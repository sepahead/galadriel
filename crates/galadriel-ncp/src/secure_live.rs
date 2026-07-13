//! Single-load validation for every Galadriel-owned secure Zenoh client.
//!
//! Zenoh 1.9 requires connector-side `enable_mtls = true` before it will present
//! configured client credentials. Galadriel validates its complete v1 client
//! profile and opens the same parsed [`ZenohConfig`], avoiding a validate/reload
//! path race.

use ncp_core::Keys;
use ncp_zenoh::{ZenohBus, ZenohConfig, ZenohError, NCP_ZENOH_CONFIG_ENV};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

/// Required receive-side Zenoh defragmentation ceiling for the v1 deployment
/// profile. Application envelope gates remain 64 KiB.
pub const SECURE_TRANSPORT_MAX_MESSAGE_BYTES: usize = 128 * 1_024;

fn config_value(config: &ZenohConfig, path: &str) -> Result<serde_json::Value, ZenohError> {
    let json = config
        .get_json(path)
        .map_err(|error| ZenohError(format!("secure config missing {path}: {error}")))?;
    serde_json::from_str(&json)
        .map_err(|error| ZenohError(format!("secure config {path} is not valid JSON: {error}")))
}

fn require_config_path(config: &ZenohConfig, path: &str) -> Result<String, ZenohError> {
    match config_value(config, path)? {
        serde_json::Value::String(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(ZenohError(format!(
            "secure client config requires a non-empty {path}"
        ))),
    }
}

#[cfg(unix)]
type CredentialIdentity = (u64, u64);
#[cfg(not(unix))]
type CredentialIdentity = PathBuf;

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

fn validate_credential_file(
    setting: &'static str,
    configured: &str,
    require_private_mode: bool,
) -> Result<(PathBuf, CredentialIdentity), ZenohError> {
    let path = Path::new(configured);
    if !path.is_absolute() {
        return Err(ZenohError(format!(
            "secure client config requires {setting} to be an absolute path"
        )));
    }
    let canonical = path.canonicalize().map_err(|error| {
        ZenohError(format!(
            "secure client config cannot resolve {setting} {}: {error}",
            path.display()
        ))
    })?;
    if canonical != path {
        return Err(ZenohError(format!(
            "secure client config requires {setting} to use its canonical path {}",
            canonical.display()
        )));
    }
    let metadata = canonical.metadata().map_err(|error| {
        ZenohError(format!(
            "secure client config cannot inspect {setting} {}: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(ZenohError(format!(
            "secure client config requires {setting} to name a regular file"
        )));
    }
    #[cfg(unix)]
    if require_private_mode {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 || mode & 0o400 == 0 || mode & 0o100 != 0 {
            return Err(ZenohError(format!(
                "secure client config requires {setting} to be owner-readable, non-executable, and deny group/world permissions"
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = require_private_mode;
    let identity = credential_identity(&canonical, &metadata);
    Ok((canonical, identity))
}

fn collect_endpoints<'a>(value: &'a serde_json::Value, output: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(endpoint) => output.push(endpoint),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_endpoints(value, output);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_endpoints(value, output);
            }
        }
        _ => {}
    }
}

/// Validate the local Zenoh client configuration required by every
/// Galadriel-owned secure live receiver.
///
/// This is intentionally stricter than merely naming certificate files. Zenoh
/// 1.9 only presents a configured client certificate when connector-side
/// `enable_mtls` is true, so that flag is part of the startup gate alongside
/// TLS-only endpoints, no listeners/discovery, hostname verification,
/// expiration closure, fail-on-connect, the fixed receive allocation bound, and
/// canonical absolute credential files. Credential roles must use distinct
/// canonical paths; Unix builds additionally compare device/inode identity and
/// require the private key to deny group/world permissions. It does not attest
/// which configuration a remote router loaded.
///
/// # Errors
///
/// Returns [`ZenohError`] when any required local security invariant is absent.
pub fn validate_secure_client_config(config: &ZenohConfig) -> Result<(), ZenohError> {
    if config_value(config, "mode")?.as_str() != Some("client") {
        return Err(ZenohError(
            "secure Galadriel config requires mode=\"client\"".into(),
        ));
    }
    for path in ["scouting/multicast/enabled", "scouting/gossip/enabled"] {
        if config_value(config, path)?.as_bool() != Some(false) {
            return Err(ZenohError(format!(
                "secure Galadriel config requires {path}=false"
            )));
        }
    }

    let endpoints_value = config_value(config, "connect/endpoints")?;
    let mut endpoints = Vec::new();
    collect_endpoints(&endpoints_value, &mut endpoints);
    if endpoints.len() != 1 || !endpoints[0].starts_with("tls/") {
        return Err(ZenohError(
            "secure Galadriel config requires exactly one tls/ connect endpoint".into(),
        ));
    }

    let listeners_value = config_value(config, "listen/endpoints")?;
    let mut listeners = Vec::new();
    collect_endpoints(&listeners_value, &mut listeners);
    if !listeners.is_empty() {
        return Err(ZenohError(
            "secure Galadriel config must not expose listen endpoints".into(),
        ));
    }

    let credential_settings = [
        ("transport/link/tls/root_ca_certificate", false),
        ("transport/link/tls/connect_certificate", false),
        ("transport/link/tls/connect_private_key", true),
    ];
    let mut credential_identities = HashSet::new();
    for (setting, require_private_mode) in credential_settings {
        let configured = require_config_path(config, setting)?;
        let (_, identity) = validate_credential_file(setting, &configured, require_private_mode)?;
        if !credential_identities.insert(identity) {
            return Err(ZenohError(format!(
                "secure client config requires {setting} to resolve to a distinct credential file"
            )));
        }
    }
    for path in [
        "transport/link/tls/enable_mtls",
        "transport/link/tls/verify_name_on_connect",
        "transport/link/tls/close_link_on_expiration",
        "connect/exit_on_failure",
    ] {
        if config_value(config, path)?.as_bool() != Some(true) {
            return Err(ZenohError(format!(
                "secure Galadriel config requires {path}=true"
            )));
        }
    }
    if config_value(config, "transport/link/rx/max_message_size")?.as_u64()
        != Some(SECURE_TRANSPORT_MAX_MESSAGE_BYTES as u64)
    {
        return Err(ZenohError(format!(
            "secure Galadriel config requires transport/link/rx/max_message_size={}",
            SECURE_TRANSPORT_MAX_MESSAGE_BYTES
        )));
    }
    Ok(())
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
    let config = ZenohConfig::from_file(path).map_err(|error| {
        ZenohError(format!(
            "load secure Galadriel Zenoh config {}: {error}",
            path.display()
        ))
    })?;
    validate_secure_client_config(&config)?;
    ZenohBus::with_config(config, keys).await
}
