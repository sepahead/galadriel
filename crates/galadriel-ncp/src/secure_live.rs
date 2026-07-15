//! Single-load validation for every Galadriel-owned secure Zenoh client.
//!
//! Zenoh 1.9 requires connector-side `enable_mtls = true` before it will present
//! configured client credentials. Galadriel validates its complete v1 client
//! profile and opens the same parsed [`ZenohConfig`], avoiding a validate/reload
//! path race.

use ncp_core::Keys;
use ncp_zenoh::{ZenohBus, ZenohConfig, ZenohError, NCP_ZENOH_CONFIG_ENV};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::{config_identity::ConfigurationIdentityBuilder, ConfigurationIdentity};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Required receive-side Zenoh defragmentation ceiling for the v1 deployment
/// profile. Application envelope gates remain 64 KiB.
pub const SECURE_TRANSPORT_MAX_MESSAGE_BYTES: usize = 128 * 1_024;

/// Maximum bytes read from the standalone secure Zenoh client document.
pub const MAX_SECURE_CONFIG_BYTES: u64 = 256 * 1_024;

/// One-byte-over read ceiling used to detect growth after the metadata check.
const MAX_SECURE_CONFIG_READ_BYTES: u64 = 262_145;

/// Maximum bytes admitted for each CA, certificate, or private-key file.
pub const MAX_SECURE_CREDENTIAL_BYTES: u64 = 1_024 * 1_024;

/// Maximum JSON values visited while extracting one endpoint setting.
pub const MAX_SECURE_ENDPOINT_TRAVERSAL_NODES: usize = 256;

/// Maximum container nesting visited while extracting one endpoint setting.
pub const MAX_SECURE_ENDPOINT_TRAVERSAL_DEPTH: usize = 16;

/// Pinned Zenoh 1.9 protocol + address + suffix byte ceiling.
const MAX_SECURE_ENDPOINT_BYTES: usize = 255;

/// Closed credential role controlling local file-permission requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMaterialKind {
    /// Router trust anchor; public material.
    TrustAnchor,
    /// Client certificate; public material.
    PublicCertificate,
    /// Client private key; owner-only material on Unix.
    PrivateKey,
}

impl CredentialMaterialKind {
    const fn requires_private_permissions(self) -> bool {
        matches!(self, Self::PrivateKey)
    }
}

/// Opaque proof that one parsed Zenoh configuration passed Galadriel's complete
/// local secure-client validation gate.
///
/// The capability cannot be constructed outside this module and is intentionally
/// separate from [`ZenohConfig`], which can represent insecure configurations.
#[derive(Clone, PartialEq, Eq)]
pub struct SecureZenohCapability {
    identity: ConfigurationIdentity,
    credential_snapshots: Vec<CredentialSnapshot>,
}

impl std::fmt::Debug for SecureZenohCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecureZenohCapability")
            .field("identity", &self.identity)
            .field("credential_count", &self.credential_snapshots.len())
            .finish()
    }
}

impl SecureZenohCapability {
    /// Canonical identity of the validated endpoint, allocation ceiling, and
    /// canonical credential **path strings**.
    ///
    /// Credential files, aliases, types, and permissions are checked when the
    /// capability is created, but this digest does not bind credential contents
    /// or later filesystem state.
    #[must_use]
    pub const fn identity(&self) -> ConfigurationIdentity {
        self.identity
    }

    /// Reopen and compare every bounded credential snapshot.
    ///
    /// This catches persistent identity, byte, size, or permission changes. It
    /// cannot eliminate a swap-load-restore race in Zenoh 1.9 because that API
    /// reopens path strings rather than consuming Galadriel's file handles.
    /// Credential paths must therefore remain immutable to untrusted writers for
    /// the process lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`SecureConfigError`] when a credential can no longer be read or
    /// differs from the validated snapshot.
    pub fn revalidate_credential_files(&self) -> Result<(), SecureConfigError> {
        for expected in &self.credential_snapshots {
            let configured =
                expected
                    .path
                    .to_str()
                    .ok_or(SecureConfigError::CredentialChanged {
                        setting: expected.setting,
                    })?;
            let current =
                validate_credential_file(expected.setting, configured, expected.material)?;
            if &current != expected {
                return Err(SecureConfigError::CredentialChanged {
                    setting: expected.setting,
                });
            }
        }
        Ok(())
    }
}

/// Closed failure taxonomy for Galadriel's local secure Zenoh configuration gate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecureConfigError {
    /// The secure configuration document could not be opened.
    #[error("cannot open secure Zenoh config {}: {source}", path.display())]
    OpenConfig {
        /// Configured document path.
        path: PathBuf,
        /// Typed filesystem source.
        #[source]
        source: std::io::Error,
    },
    /// The opened configuration document could not be inspected.
    #[error("cannot inspect secure Zenoh config {}: {source}", path.display())]
    InspectConfig {
        /// Configured document path.
        path: PathBuf,
        /// Typed filesystem source.
        #[source]
        source: std::io::Error,
    },
    /// The configuration path did not identify a regular file.
    #[error("secure Zenoh config must name a regular file")]
    ConfigNotFile,
    /// The configuration document exceeded its pre-parse byte ceiling.
    #[error(
        "secure Zenoh config observed size {observed} bytes exceeds {MAX_SECURE_CONFIG_BYTES} bytes"
    )]
    ConfigTooLarge {
        /// Size reported by metadata or the bounded read.
        observed: u64,
    },
    /// The bounded configuration document read failed.
    #[error("cannot read secure Zenoh config {}: {source}", path.display())]
    ReadConfig {
        /// Configured document path.
        path: PathBuf,
        /// Typed filesystem source.
        #[source]
        source: std::io::Error,
    },
    /// The configuration document was not UTF-8.
    #[error("secure Zenoh config is not UTF-8: {source}")]
    InvalidConfigUtf8 {
        /// Typed UTF-8 conversion source.
        #[source]
        source: std::string::FromUtf8Error,
    },
    /// The configuration document was not strict JSON.
    #[error("secure Zenoh config is not strict JSON: {source}")]
    InvalidConfigDocument {
        /// Typed JSON parser source.
        #[source]
        source: serde_json::Error,
    },
    /// Zenoh's external include mechanism was requested.
    #[error("secure Zenoh config must be standalone and must not use __config__ includes")]
    ExternalConfigInclude,
    /// Zenoh rejected the bounded standalone document.
    #[error("secure Zenoh config is invalid: {reason}")]
    InvalidZenohConfig {
        /// Foreign Zenoh parser diagnostic retained at the boundary.
        reason: String,
    },
    /// Zenoh could not materialize a required configuration path.
    #[error("secure config missing {path}: {reason}")]
    MissingConfig {
        /// Required Zenoh path.
        path: &'static str,
        /// Foreign configuration diagnostic retained as text at the boundary.
        reason: String,
    },
    /// A required Zenoh path did not contain valid JSON.
    #[error("secure config {path} is not valid JSON: {source}")]
    InvalidJson {
        /// Required Zenoh path.
        path: &'static str,
        /// Typed JSON parser source.
        #[source]
        source: serde_json::Error,
    },
    /// The deployment mode was not the required client role.
    #[error("secure Galadriel config requires mode=\"client\"")]
    InvalidMode,
    /// A discovery mechanism remained enabled.
    #[error("secure Galadriel config requires {path}=false")]
    DiscoveryEnabled {
        /// Unsafe discovery flag.
        path: &'static str,
    },
    /// Connect endpoint cardinality, scheme, authority, or endpoint-local suffix was invalid.
    #[error(
        "secure Galadriel config requires exactly one bare tls/host:port connect endpoint with a concrete DNS or IP host"
    )]
    InvalidConnectEndpoints,
    /// At least one listener endpoint was configured.
    #[error("secure Galadriel config must not expose listen endpoints")]
    ListenEndpoints,
    /// A credential setting was absent or blank.
    #[error("secure client config requires a non-empty {setting}")]
    MissingCredentialPath {
        /// Credential configuration path.
        setting: &'static str,
    },
    /// A credential setting used a relative filesystem path.
    #[error("secure client config requires {setting} to be an absolute path")]
    RelativeCredentialPath {
        /// Credential configuration path.
        setting: &'static str,
    },
    /// Credential canonicalization failed.
    #[error("secure client config cannot resolve {setting} {}: {source}", path.display())]
    ResolveCredential {
        /// Credential configuration path.
        setting: &'static str,
        /// Configured filesystem path.
        path: PathBuf,
        /// Typed filesystem source.
        #[source]
        source: std::io::Error,
    },
    /// Configured and canonical credential paths differed.
    #[error(
        "secure client config requires {setting} to use its canonical path {}",
        canonical.display()
    )]
    NonCanonicalCredentialPath {
        /// Credential configuration path.
        setting: &'static str,
        /// Canonical path that must be configured exactly.
        canonical: PathBuf,
    },
    /// Credential metadata inspection failed.
    #[error("secure client config cannot inspect {setting} {}: {source}", path.display())]
    InspectCredential {
        /// Credential configuration path.
        setting: &'static str,
        /// Canonical credential path.
        path: PathBuf,
        /// Typed filesystem source.
        #[source]
        source: std::io::Error,
    },
    /// A credential path did not identify a regular file.
    #[error("secure client config requires {setting} to name a regular file")]
    CredentialNotFile {
        /// Credential configuration path.
        setting: &'static str,
    },
    /// A credential file exceeded its pre-open byte ceiling.
    #[error(
        "secure client config requires {setting} to be at most {MAX_SECURE_CREDENTIAL_BYTES} bytes; observed {observed}"
    )]
    CredentialTooLarge {
        /// Credential configuration path.
        setting: &'static str,
        /// File size observed during validation.
        observed: u64,
    },
    /// Credential identity, bytes, or protected metadata changed after validation.
    #[error("secure client credential {setting} changed after validation")]
    CredentialChanged {
        /// Credential configuration path.
        setting: &'static str,
    },
    /// Reading a bounded credential snapshot failed.
    #[error("secure client config cannot read {setting} {}: {source}", path.display())]
    ReadCredential {
        /// Credential configuration path.
        setting: &'static str,
        /// Canonical credential path.
        path: PathBuf,
        /// Typed filesystem source.
        #[source]
        source: std::io::Error,
    },
    /// Private-key permissions were not owner-readable and private.
    #[error(
        "secure client config requires {setting} to be owner-readable, non-executable, and deny group/world permissions"
    )]
    UnsafePrivateKeyPermissions {
        /// Credential configuration path.
        setting: &'static str,
    },
    /// A credential file was writable by its group or by other users.
    #[error("secure client config requires {setting} to deny group/world write permissions")]
    UnsafeCredentialWritePermissions {
        /// Credential configuration path.
        setting: &'static str,
    },
    /// Two credential roles resolved to one filesystem identity.
    #[error("secure client config requires {setting} to resolve to a distinct credential file")]
    DuplicateCredential {
        /// Later credential configuration path.
        setting: &'static str,
    },
    /// A required fail-closed boolean was not true.
    #[error("secure Galadriel config requires {path}=true")]
    RequiredFlagDisabled {
        /// Required boolean configuration path.
        path: &'static str,
    },
    /// Receive-side message allocation did not match the fixed profile.
    #[error(
        "secure Galadriel config requires transport/link/rx/max_message_size={SECURE_TRANSPORT_MAX_MESSAGE_BYTES}"
    )]
    InvalidTransportMessageSize,
}

fn config_value(
    config: &ZenohConfig,
    path: &'static str,
) -> Result<serde_json::Value, SecureConfigError> {
    let json = config
        .get_json(path)
        .map_err(|error| SecureConfigError::MissingConfig {
            path,
            reason: error.to_string(),
        })?;
    serde_json::from_str(&json).map_err(|source| SecureConfigError::InvalidJson { path, source })
}

fn require_config_path(
    config: &ZenohConfig,
    path: &'static str,
) -> Result<String, SecureConfigError> {
    match config_value(config, path)? {
        serde_json::Value::String(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(SecureConfigError::MissingCredentialPath { setting: path }),
    }
}

#[cfg(unix)]
type CredentialIdentity = (u64, u64);
#[cfg(not(unix))]
type CredentialIdentity = PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CredentialSnapshot {
    setting: &'static str,
    path: PathBuf,
    identity: CredentialIdentity,
    material: CredentialMaterialKind,
    bytes: u64,
    digest: [u8; 32],
}

fn credential_identity(_canonical: &Path, metadata: &std::fs::Metadata) -> CredentialIdentity {
    #[cfg(unix)]
    {
        (metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        _canonical.to_path_buf()
    }
}

fn owned_credential_identity(identity: &CredentialIdentity) -> CredentialIdentity {
    #[cfg(unix)]
    {
        *identity
    }
    #[cfg(not(unix))]
    {
        identity.clone()
    }
}

fn validate_credential_metadata(
    setting: &'static str,
    metadata: &std::fs::Metadata,
    material: CredentialMaterialKind,
) -> Result<(), SecureConfigError> {
    if !metadata.is_file() {
        return Err(SecureConfigError::CredentialNotFile { setting });
    }
    if metadata.len() > MAX_SECURE_CREDENTIAL_BYTES {
        return Err(SecureConfigError::CredentialTooLarge {
            setting,
            observed: metadata.len(),
        });
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(SecureConfigError::UnsafeCredentialWritePermissions { setting });
        }
        if material.requires_private_permissions()
            && (mode & 0o077 != 0 || mode & 0o400 == 0 || mode & 0o100 != 0)
        {
            return Err(SecureConfigError::UnsafePrivateKeyPermissions { setting });
        }
    }
    #[cfg(not(unix))]
    let _ = material;
    Ok(())
}

fn validate_opened_credential_metadata(
    setting: &'static str,
    canonical: &Path,
    path_identity: &CredentialIdentity,
    metadata: &std::fs::Metadata,
    material: CredentialMaterialKind,
) -> Result<CredentialIdentity, SecureConfigError> {
    validate_credential_metadata(setting, metadata, material)?;
    let identity = credential_identity(canonical, metadata);
    if &identity != path_identity {
        return Err(SecureConfigError::CredentialChanged { setting });
    }
    Ok(identity)
}

fn validate_credential_file(
    setting: &'static str,
    configured: &str,
    material: CredentialMaterialKind,
) -> Result<CredentialSnapshot, SecureConfigError> {
    let path = Path::new(configured);
    if !path.is_absolute() {
        return Err(SecureConfigError::RelativeCredentialPath { setting });
    }
    let canonical = path
        .canonicalize()
        .map_err(|source| SecureConfigError::ResolveCredential {
            setting,
            path: path.to_path_buf(),
            source,
        })?;
    if canonical != path {
        return Err(SecureConfigError::NonCanonicalCredentialPath { setting, canonical });
    }
    let path_metadata =
        std::fs::metadata(&canonical).map_err(|source| SecureConfigError::InspectCredential {
            setting,
            path: canonical.clone(),
            source,
        })?;
    validate_credential_metadata(setting, &path_metadata, material)?;
    let path_identity = credential_identity(&canonical, &path_metadata);
    let mut file =
        std::fs::File::open(&canonical).map_err(|source| SecureConfigError::ReadCredential {
            setting,
            path: canonical.clone(),
            source,
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| SecureConfigError::InspectCredential {
            setting,
            path: canonical.clone(),
            source,
        })?;
    let identity = validate_opened_credential_metadata(
        setting,
        &canonical,
        &path_identity,
        &metadata,
        material,
    )?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 8_192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| SecureConfigError::ReadCredential {
                setting,
                path: canonical.clone(),
                source,
            })?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        if bytes > MAX_SECURE_CREDENTIAL_BYTES {
            return Err(SecureConfigError::CredentialTooLarge {
                setting,
                observed: bytes,
            });
        }
        digest.update(&buffer[..read]);
    }
    Ok(CredentialSnapshot {
        setting,
        path: canonical,
        identity,
        material,
        bytes,
        digest: digest.finalize().into(),
    })
}

fn collect_endpoints<'a>(
    value: &'a serde_json::Value,
    output: &mut Vec<&'a str>,
    stop_at: usize,
) -> bool {
    let mut remaining_nodes = MAX_SECURE_ENDPOINT_TRAVERSAL_NODES;
    collect_endpoints_inner(value, output, stop_at, &mut remaining_nodes, 0)
}

fn collect_endpoints_inner<'a>(
    value: &'a serde_json::Value,
    output: &mut Vec<&'a str>,
    stop_at: usize,
    remaining_nodes: &mut usize,
    depth: usize,
) -> bool {
    if depth > MAX_SECURE_ENDPOINT_TRAVERSAL_DEPTH {
        return false;
    }
    if *remaining_nodes == 0 {
        return false;
    }
    *remaining_nodes -= 1;
    match value {
        serde_json::Value::String(endpoint) => {
            output.push(endpoint);
            output.len() < stop_at
        }
        serde_json::Value::Array(values) => {
            for value in values {
                if !collect_endpoints_inner(
                    value,
                    output,
                    stop_at,
                    remaining_nodes,
                    depth.saturating_add(1),
                ) {
                    return false;
                }
            }
            true
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                if !collect_endpoints_inner(
                    value,
                    output,
                    stop_at,
                    remaining_nodes,
                    depth.saturating_add(1),
                ) {
                    return false;
                }
            }
            true
        }
        _ => true,
    }
}

fn single_secure_client_endpoint(value: &serde_json::Value) -> Option<&str> {
    let mut endpoints = Vec::with_capacity(2);
    let complete = collect_endpoints(value, &mut endpoints, 2);
    if complete && endpoints.len() == 1 && valid_secure_client_endpoint(endpoints[0]) {
        Some(endpoints[0])
    } else {
        None
    }
}

fn secure_client_listeners_disabled(value: &serde_json::Value) -> bool {
    let mut listeners = Vec::with_capacity(1);
    collect_endpoints(value, &mut listeners, 1) && listeners.is_empty()
}

fn contains_external_config_include(value: &serde_json::Value) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            serde_json::Value::Array(values) => pending.extend(values),
            serde_json::Value::Object(values) => {
                if values.contains_key("__config__") {
                    return true;
                }
                pending.extend(values.values());
            }
            _ => {}
        }
    }
    false
}

fn valid_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_client_authority(authority: &str) -> bool {
    let (port, parsed_ip) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, port)) = bracketed.split_once("]:") else {
            return false;
        };
        let Ok(address) = host.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        (port, Some(std::net::IpAddr::V6(address)))
    } else {
        if authority.matches(':').count() != 1 {
            return false;
        }
        let Some((host, port)) = authority.rsplit_once(':') else {
            return false;
        };
        let parsed_ip = host.parse::<std::net::IpAddr>().ok();
        if parsed_ip.is_none() && !valid_dns_host(host) {
            return false;
        }
        (port, parsed_ip)
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    if port == 0 {
        return false;
    }
    parsed_ip.is_none_or(|address| !address.is_unspecified())
}

fn secure_endpoint_text_is_canonical(value: &str) -> bool {
    if value.len() > MAX_SECURE_ENDPOINT_BYTES {
        return false;
    }
    if value != value.trim() {
        return false;
    }
    for character in value.chars() {
        if character.is_control() {
            return false;
        }
        if character.is_whitespace() {
            return false;
        }
        if matches!(character, '*' | '$' | '#' | '?') {
            return false;
        }
    }
    true
}

fn valid_secure_client_endpoint(value: &str) -> bool {
    if !secure_endpoint_text_is_canonical(value) {
        return false;
    }
    let Ok(endpoint) = value.parse::<zenoh::config::EndPoint>() else {
        return false;
    };
    if endpoint.protocol().as_str() != "tls" {
        return false;
    }
    if !endpoint.metadata().is_empty() {
        return false;
    }
    if !endpoint.config().is_empty() {
        return false;
    }
    valid_client_authority(endpoint.address().as_str())
}

fn load_bounded_secure_config(path: &Path) -> Result<ZenohConfig, SecureConfigError> {
    let file = std::fs::File::open(path).map_err(|source| SecureConfigError::OpenConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| SecureConfigError::InspectConfig {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(SecureConfigError::ConfigNotFile);
    }
    if metadata.len() > MAX_SECURE_CONFIG_BYTES {
        return Err(SecureConfigError::ConfigTooLarge {
            observed: metadata.len(),
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SECURE_CONFIG_READ_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|source| SecureConfigError::ReadConfig {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_SECURE_CONFIG_BYTES {
        return Err(SecureConfigError::ConfigTooLarge {
            observed: bytes.len() as u64,
        });
    }
    let document = String::from_utf8(bytes)
        .map_err(|source| SecureConfigError::InvalidConfigUtf8 { source })?;
    let value: serde_json::Value = serde_json::from_str(&document)
        .map_err(|source| SecureConfigError::InvalidConfigDocument { source })?;
    if contains_external_config_include(&value) {
        return Err(SecureConfigError::ExternalConfigInclude);
    }
    ZenohConfig::from_json5(&document).map_err(|error| SecureConfigError::InvalidZenohConfig {
        reason: error.to_string(),
    })
}

/// Validate the local Zenoh client configuration required by every
/// Galadriel-owned secure live receiver.
///
/// This is intentionally stricter than merely naming certificate files. Zenoh
/// 1.9 only presents a configured client certificate when connector-side
/// `enable_mtls` is true, so that flag is part of the startup gate alongside
/// one TLS-only endpoint without endpoint-local configuration or metadata, no
/// listeners/discovery, hostname verification,
/// expiration closure, fail-on-connect, the fixed receive allocation bound, and
/// canonical absolute credential files. Credential roles must use distinct
/// canonical paths; Unix builds additionally compare device/inode identity and
/// require the private key to deny group/world permissions. It does not attest
/// which configuration a remote router loaded.
///
/// # Errors
///
/// Returns [`SecureConfigError`] when any required local security invariant is absent.
pub fn validate_secure_client_config(
    config: &ZenohConfig,
) -> Result<SecureZenohCapability, SecureConfigError> {
    if config_value(config, "mode")?.as_str() != Some("client") {
        return Err(SecureConfigError::InvalidMode);
    }
    for path in ["scouting/multicast/enabled", "scouting/gossip/enabled"] {
        if config_value(config, path)?.as_bool() != Some(false) {
            return Err(SecureConfigError::DiscoveryEnabled { path });
        }
    }

    let endpoints_value = config_value(config, "connect/endpoints")?;
    // Parsing and authority validation intentionally duplicate the profile
    // renderer's narrow client grammar. Zenoh's own endpoint parser accepts
    // endpoint-local suffixes and broader authorities that are outside the
    // reviewed secure profile.
    let endpoint = single_secure_client_endpoint(&endpoints_value)
        .ok_or(SecureConfigError::InvalidConnectEndpoints)?;

    let listeners_value = config_value(config, "listen/endpoints")?;
    if !secure_client_listeners_disabled(&listeners_value) {
        return Err(SecureConfigError::ListenEndpoints);
    }

    let credential_settings = [
        (
            "transport/link/tls/root_ca_certificate",
            CredentialMaterialKind::TrustAnchor,
        ),
        (
            "transport/link/tls/connect_certificate",
            CredentialMaterialKind::PublicCertificate,
        ),
        (
            "transport/link/tls/connect_private_key",
            CredentialMaterialKind::PrivateKey,
        ),
    ];
    let mut credential_identities = HashSet::new();
    let mut credential_paths = Vec::with_capacity(credential_settings.len());
    let mut credential_snapshots = Vec::with_capacity(credential_settings.len());
    for (setting, material) in credential_settings {
        let configured = require_config_path(config, setting)?;
        let snapshot = validate_credential_file(setting, &configured, material)?;
        if !credential_identities.insert(owned_credential_identity(&snapshot.identity)) {
            return Err(SecureConfigError::DuplicateCredential { setting });
        }
        credential_paths.push((setting, configured));
        credential_snapshots.push(snapshot);
    }
    for path in [
        "transport/link/tls/enable_mtls",
        "transport/link/tls/verify_name_on_connect",
        "transport/link/tls/close_link_on_expiration",
        "connect/exit_on_failure",
    ] {
        if config_value(config, path)?.as_bool() != Some(true) {
            return Err(SecureConfigError::RequiredFlagDisabled { path });
        }
    }
    if config_value(config, "transport/link/rx/max_message_size")?.as_u64()
        != Some(SECURE_TRANSPORT_MAX_MESSAGE_BYTES as u64)
    {
        return Err(SecureConfigError::InvalidTransportMessageSize);
    }
    let mut identity = ConfigurationIdentityBuilder::new("secure-zenoh-client")
        .bytes("mode", b"client")
        .bytes("connect_endpoint", endpoint.as_bytes())
        .u64(
            "transport_max_message_bytes",
            SECURE_TRANSPORT_MAX_MESSAGE_BYTES as u64,
        );
    for (setting, path) in credential_paths {
        identity = identity.bytes(setting, path.as_bytes());
    }
    Ok(SecureZenohCapability {
        identity: identity.finish(),
        credential_snapshots,
    })
}

/// Load, validate, and open the one strict client configuration named by
/// `NCP_ZENOH_CONFIG`.
///
/// # Errors
///
/// Returns [`ZenohError`] for an absent/unreadable config, a failed local
/// invariant, or Zenoh transport startup failure.
pub async fn open_secure_bus(keys: Keys) -> Result<ZenohBus, ZenohError> {
    let path = std::env::var_os(NCP_ZENOH_CONFIG_ENV).ok_or_else(|| {
        ZenohError(format!(
            "secure Galadriel receiver requires {NCP_ZENOH_CONFIG_ENV} to name its Zenoh client config"
        ))
    })?;
    let path = std::path::Path::new(&path);
    let config = load_bounded_secure_config(path).map_err(|error| {
        ZenohError(format!(
            "load secure Galadriel Zenoh config {}: {error}",
            path.display()
        ))
    })?;
    let capability =
        validate_secure_client_config(&config).map_err(|error| ZenohError(error.to_string()))?;
    capability
        .revalidate_credential_files()
        .map_err(|error| ZenohError(error.to_string()))?;
    let bus = ZenohBus::with_config(config, keys).await?;
    capability
        .revalidate_credential_files()
        .map_err(|error| ZenohError(error.to_string()))?;
    Ok(bus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static CONFIG_FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn config_fixture_path() -> PathBuf {
        let sequence = CONFIG_FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "galadriel-bounded-secure-config-{}-{sequence}.json5",
            std::process::id()
        ))
    }

    #[test]
    fn endpoint_collection_traverses_nested_config_objects() {
        let value = serde_json::json!({
            "primary": "tls/router.example.invalid:7447",
            "fallbacks": [
                { "endpoint": "tls/router2.example.invalid:7447" },
                null,
            ],
        });
        let mut endpoints = Vec::with_capacity(3);

        assert!(collect_endpoints(&value, &mut endpoints, 3));
        endpoints.sort_unstable();

        assert_eq!(
            endpoints,
            [
                "tls/router.example.invalid:7447",
                "tls/router2.example.invalid:7447",
            ]
        );
    }

    #[test]
    fn nested_connect_endpoint_collection_stops_at_two_entries() {
        let value = serde_json::json!({
            "outer": [{
                "inner": [
                    "tls/one.invalid:7447",
                    "tls/two.invalid:7447",
                    "tls/three.invalid:7447",
                ]
            }]
        });
        let mut endpoints = Vec::with_capacity(2);

        let complete = collect_endpoints(&value, &mut endpoints, 2);

        assert!(!complete);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints.capacity(), 2);
    }

    #[test]
    fn secure_endpoint_selection_requires_each_independent_invariant() {
        let valid = "tls/router.example.invalid:7447";
        assert_eq!(
            single_secure_client_endpoint(&serde_json::json!([valid])),
            Some(valid)
        );
        assert_eq!(single_secure_client_endpoint(&serde_json::json!([])), None);
        assert_eq!(
            single_secure_client_endpoint(&serde_json::json!([
                valid,
                "tls/router2.example.invalid:7447"
            ])),
            None
        );
        assert_eq!(
            single_secure_client_endpoint(&serde_json::json!(["tcp/router.invalid:7447"])),
            None
        );

        let mut incomplete = vec![serde_json::Value::Null; MAX_SECURE_ENDPOINT_TRAVERSAL_NODES];
        incomplete[0] = serde_json::Value::String(valid.to_owned());
        assert_eq!(
            single_secure_client_endpoint(&serde_json::Value::Array(incomplete)),
            None,
            "one valid string is insufficient when bounded traversal is incomplete"
        );
    }

    #[test]
    fn secure_listener_selection_requires_complete_empty_traversal() {
        assert!(secure_client_listeners_disabled(&serde_json::json!([])));
        assert!(!secure_client_listeners_disabled(&serde_json::json!([
            "tls/0.0.0.0:7448"
        ])));

        let incomplete = serde_json::Value::Array(vec![
            serde_json::Value::Null;
            MAX_SECURE_ENDPOINT_TRAVERSAL_NODES
        ]);
        assert!(!secure_client_listeners_disabled(&incomplete));
    }

    #[test]
    fn nested_listener_endpoint_collection_stops_at_one_entry() {
        let value = serde_json::json!({
            "outer": [{
                "inner": [
                    "tls/one.invalid:7447",
                    "tls/two.invalid:7447",
                ]
            }]
        });
        let mut endpoints = Vec::with_capacity(1);

        let complete = collect_endpoints(&value, &mut endpoints, 1);

        assert!(!complete);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints.capacity(), 1);
    }

    #[test]
    fn endpoint_collection_rejects_excessive_container_depth_without_strings() {
        let mut value = serde_json::Value::Null;
        for _ in 0..=MAX_SECURE_ENDPOINT_TRAVERSAL_DEPTH {
            value = serde_json::Value::Array(vec![value]);
        }
        let mut endpoints = Vec::with_capacity(2);

        let complete = collect_endpoints(&value, &mut endpoints, 2);

        assert!(!complete);
        assert!(endpoints.is_empty());
    }

    #[test]
    fn endpoint_collection_depth_ceiling_is_inclusive_and_one_more_is_rejected() {
        let endpoint = "tls/router.example.invalid:7447";
        let mut exact = serde_json::Value::String(endpoint.to_owned());
        for _ in 0..MAX_SECURE_ENDPOINT_TRAVERSAL_DEPTH {
            exact = serde_json::Value::Array(vec![exact]);
        }
        {
            let mut endpoints = Vec::with_capacity(2);
            assert!(collect_endpoints(&exact, &mut endpoints, 2));
            assert_eq!(endpoints, [endpoint]);
        }
        let one_more = serde_json::Value::Array(vec![exact]);
        let mut endpoints = Vec::with_capacity(2);
        assert!(!collect_endpoints(&one_more, &mut endpoints, 2));
        assert!(endpoints.is_empty());
    }

    #[test]
    fn endpoint_collection_rejects_many_empty_nodes_at_fixed_work_budget() {
        let value = serde_json::Value::Array(vec![
            serde_json::Value::Null;
            MAX_SECURE_ENDPOINT_TRAVERSAL_NODES
        ]);
        let mut endpoints = Vec::with_capacity(2);

        let complete = collect_endpoints(&value, &mut endpoints, 2);

        assert!(!complete);
        assert!(endpoints.is_empty());
    }

    #[test]
    fn secure_config_byte_ceiling_accepts_exact_boundary_and_rejects_one_more() {
        assert_eq!(
            SECURE_TRANSPORT_MAX_MESSAGE_BYTES,
            128_usize
                .checked_mul(1_024)
                .expect("the platform represents the transport byte ceiling")
        );
        assert_eq!(
            MAX_SECURE_CONFIG_BYTES,
            256_u64
                .checked_mul(1_024)
                .expect("the platform represents the config byte ceiling")
        );
        assert_eq!(
            MAX_SECURE_CONFIG_READ_BYTES,
            MAX_SECURE_CONFIG_BYTES
                .checked_add(1)
                .expect("the config read sentinel is representable")
        );
        assert_eq!(
            MAX_SECURE_CREDENTIAL_BYTES,
            1_024_u64
                .checked_mul(1_024)
                .expect("the platform represents the credential byte ceiling")
        );
        let path = config_fixture_path();
        let mut exact = vec![b' '; MAX_SECURE_CONFIG_BYTES as usize];
        exact[..2].copy_from_slice(b"{}");
        std::fs::write(&path, exact).expect("exact-boundary config fixture writes");

        load_bounded_secure_config(&path).expect("exact config byte ceiling is inclusive");

        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("config fixture reopens")
            .set_len(MAX_SECURE_CONFIG_BYTES + 1)
            .expect("config fixture grows by one byte");
        let error = load_bounded_secure_config(&path)
            .expect_err("one byte beyond the config ceiling must fail before parse");
        assert!(matches!(
            error,
            SecureConfigError::ConfigTooLarge { observed }
                if observed == MAX_SECURE_CONFIG_BYTES + 1
        ));

        std::fs::remove_file(path).expect("config fixture cleans up");
    }

    #[test]
    fn secure_config_loader_rejects_external_includes() {
        let path = config_fixture_path();
        std::fs::write(
            &path,
            br#"{"transport":{"__config__":"unbounded-external.json5"}}"#,
        )
        .expect("include fixture writes");

        assert!(matches!(
            load_bounded_secure_config(&path),
            Err(SecureConfigError::ExternalConfigInclude)
        ));

        std::fs::remove_file(path).expect("include fixture cleans up");
    }

    #[test]
    fn external_include_detection_traverses_arrays_and_ignores_clean_values() {
        let nested = serde_json::json!([
            null,
            {"transport": [{"__config__": "external.json5"}]}
        ]);
        assert!(contains_external_config_include(&nested));

        let clean = serde_json::json!([
            null,
            {"transport": [{"config": "inline"}, true, 7]}
        ]);
        assert!(!contains_external_config_include(&clean));
    }

    #[test]
    fn endpoint_text_gate_checks_each_canonicality_rule() {
        let valid = "tls/router.example.invalid:7447";
        assert!(secure_endpoint_text_is_canonical(valid));
        assert!(!secure_endpoint_text_is_canonical(
            &"x".repeat(MAX_SECURE_ENDPOINT_BYTES + 1)
        ));
        assert!(!secure_endpoint_text_is_canonical(&format!(" {valid}")));
        assert!(!secure_endpoint_text_is_canonical(&format!("{valid} ")));
        assert!(!secure_endpoint_text_is_canonical(
            "tls/router\0.example.invalid:7447"
        ));
        assert!(!secure_endpoint_text_is_canonical(
            "tls/router\u{00a0}.example.invalid:7447"
        ));
        for prohibited in ['*', '$', '#', '?'] {
            assert!(!secure_endpoint_text_is_canonical(&format!(
                "tls/router{prohibited}.example.invalid:7447"
            )));
        }
    }

    #[test]
    fn authority_gate_rejects_each_invalid_host_and_port_family() {
        for authority in [
            "router.example.invalid:7447",
            "router-1:1",
            "127.0.0.1:65535",
            "[2001:db8::1]:7447",
        ] {
            assert!(valid_client_authority(authority), "{authority:?}");
        }
        for authority in [
            "",
            ":7447",
            "router.example.invalid:",
            "router.example.invalid:notaport",
            "router.example.invalid:0",
            "router.example.invalid:65536",
            "router..example.invalid:7447",
            "-router.example.invalid:7447",
            "0.0.0.0:7447",
            "[::]:7447",
            "[127.0.0.1]:7447",
            "[2001:db8::1]:7447:extra",
            "2001:db8::1:7447",
        ] {
            assert!(!valid_client_authority(authority), "{authority:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn opened_credential_identity_must_match_the_preopen_stat() {
        let first = config_fixture_path();
        let second = config_fixture_path();
        std::fs::write(&first, b"first").expect("first identity fixture writes");
        std::fs::write(&second, b"second").expect("second identity fixture writes");
        for path in [&first, &second] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
                .expect("identity fixture mode is safe");
        }
        let first_metadata = std::fs::metadata(&first).expect("first fixture metadata reads");
        let first_identity = credential_identity(&first, &first_metadata);
        let second_file = std::fs::File::open(&second).expect("second fixture opens");
        let second_metadata = second_file
            .metadata()
            .expect("second handle metadata reads");

        assert!(matches!(
            validate_opened_credential_metadata(
                "test/credential",
                &first,
                &first_identity,
                &second_metadata,
                CredentialMaterialKind::PublicCertificate,
            ),
            Err(SecureConfigError::CredentialChanged {
                setting: "test/credential"
            })
        ));

        std::fs::remove_file(first).expect("first identity fixture cleans up");
        std::fs::remove_file(second).expect("second identity fixture cleans up");
    }

    #[test]
    fn secure_endpoint_validator_matches_the_shared_deployment_corpus() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../deploy/secure-client-endpoint-corpus.json"
        ))
        .expect("shared endpoint corpus is strict JSON");
        for endpoint in corpus["valid"]
            .as_array()
            .expect("valid endpoint corpus is an array")
        {
            let endpoint = endpoint
                .as_str()
                .expect("valid endpoint corpus contains strings");
            assert!(
                valid_secure_client_endpoint(endpoint),
                "shared valid endpoint was rejected: {endpoint:?}"
            );
        }
        for endpoint in corpus["invalid"]
            .as_array()
            .expect("invalid endpoint corpus is an array")
        {
            let endpoint = endpoint
                .as_str()
                .expect("invalid endpoint corpus contains strings");
            assert!(
                !valid_secure_client_endpoint(endpoint),
                "shared invalid endpoint was accepted: {endpoint:?}"
            );
        }
    }
}
