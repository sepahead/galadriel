#![forbid(unsafe_code)]
//! Ensure the committed security references load through the pinned Zenoh parser.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use galadriel_ncp::secure_live::validate_secure_client_config;
use ncp_zenoh::ZenohConfig;

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct CredentialFixture {
    directory: PathBuf,
    root_ca: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
}

impl CredentialFixture {
    fn new() -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "galadriel-secure-config-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("credential fixture directory is unique");
        let paths = [
            directory.join("root-ca.pem"),
            directory.join("client.pem"),
            directory.join("client-key.pem"),
        ];
        for path in &paths {
            fs::write(path, b"test credential material")
                .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        }
        #[cfg(unix)]
        fs::set_permissions(&paths[2], fs::Permissions::from_mode(0o600))
            .expect("test private key mode is restricted");
        Self {
            directory,
            root_ca: paths[0]
                .canonicalize()
                .expect("root CA fixture canonicalizes"),
            certificate: paths[1]
                .canonicalize()
                .expect("certificate fixture canonicalizes"),
            private_key: paths[2]
                .canonicalize()
                .expect("private-key fixture canonicalizes"),
        }
    }

    fn apply(&self, config: &mut ZenohConfig) {
        for (setting, path) in [
            ("transport/link/tls/root_ca_certificate", &self.root_ca),
            ("transport/link/tls/connect_certificate", &self.certificate),
            ("transport/link/tls/connect_private_key", &self.private_key),
        ] {
            let encoded =
                serde_json::to_string(path.to_str().expect("credential fixture path is UTF-8"))
                    .expect("credential fixture path encodes");
            config
                .insert_json5(setting, &encoded)
                .unwrap_or_else(|error| panic!("cannot set {setting}: {error}"));
        }
    }
}

impl Drop for CredentialFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn exact_epoch_reference_configs_parse_with_pinned_zenoh() {
    let reference = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("deploy/reference");

    for name in ["zenoh-producer.json5", "zenoh-observer.json5"] {
        let path = reference.join(name);
        let mut config = ZenohConfig::from_file(&path)
            .unwrap_or_else(|error| panic!("{} must load: {error}", path.display()));
        let credentials = CredentialFixture::new();
        credentials.apply(&mut config);
        validate_secure_client_config(&config)
            .unwrap_or_else(|error| panic!("{} must be strict: {error}", path.display()));
    }

    let router_path = reference.join("zenoh-router.json5");
    let router = ZenohConfig::from_file(&router_path)
        .unwrap_or_else(|error| panic!("{} must load: {error}", router_path.display()));
    assert!(
        validate_secure_client_config(&router).is_err(),
        "the router config must never pass the client startup gate"
    );
}

#[test]
fn live_startup_rejects_each_strict_profile_regression() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("deploy/reference/zenoh-observer.json5");
    let mut config = ZenohConfig::from_file(&path)
        .unwrap_or_else(|error| panic!("{} must load: {error}", path.display()));
    let credentials = CredentialFixture::new();
    credentials.apply(&mut config);

    let mutations = [
        ("mode", r#""router""#),
        ("scouting/multicast/enabled", "true"),
        ("scouting/gossip/enabled", "true"),
        (
            "connect/endpoints",
            r#"["tcp/router.example.invalid:7447"]"#,
        ),
        (
            "connect/endpoints",
            r#"["tls/router.example.invalid:7447", "tls/router2.example.invalid:7447"]"#,
        ),
        ("listen/endpoints", r#"["tls/0.0.0.0:7448"]"#),
        ("listen/endpoints", r#"{ client: ["tls/0.0.0.0:7448"] }"#),
        ("transport/link/tls/root_ca_certificate", "null"),
        ("transport/link/tls/connect_certificate", "null"),
        ("transport/link/tls/connect_private_key", "null"),
        ("transport/link/tls/enable_mtls", "false"),
        ("transport/link/tls/verify_name_on_connect", "false"),
        ("transport/link/tls/close_link_on_expiration", "false"),
        ("connect/exit_on_failure", "false"),
        ("transport/link/rx/max_message_size", "1073741824"),
    ];
    for (setting, value) in mutations {
        let mut candidate = config.clone();
        candidate
            .insert_json5(setting, value)
            .unwrap_or_else(|error| panic!("mutation {setting} must parse: {error}"));
        assert!(
            validate_secure_client_config(&candidate).is_err(),
            "startup gate accepted {setting}={value}"
        );
    }

    let mut whitespace_path = config.clone();
    whitespace_path
        .insert_json5("transport/link/tls/connect_private_key", r#""   ""#)
        .expect("whitespace credential-path mutation parses");
    let error = validate_secure_client_config(&whitespace_path)
        .expect_err("whitespace-only credential paths must fail the non-empty gate");
    assert!(
        error.to_string().contains("requires a non-empty"),
        "whitespace path reached a later validation stage: {error}"
    );
}

#[test]
fn live_startup_rejects_unsafe_credential_filesystem_boundaries() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("deploy/reference/zenoh-observer.json5");
    let mut config = ZenohConfig::from_file(&path)
        .unwrap_or_else(|error| panic!("{} must load: {error}", path.display()));
    let credentials = CredentialFixture::new();
    credentials.apply(&mut config);
    validate_secure_client_config(&config).expect("fixture baseline is strict");

    let mut relative = config.clone();
    relative
        .insert_json5(
            "transport/link/tls/connect_private_key",
            r#""relative-key.pem""#,
        )
        .expect("relative-path mutation parses");
    assert!(validate_secure_client_config(&relative).is_err());

    let mut missing = config.clone();
    let missing_path = credentials.directory.join("missing-key.pem");
    missing
        .insert_json5(
            "transport/link/tls/connect_private_key",
            &serde_json::to_string(
                missing_path
                    .to_str()
                    .expect("missing fixture path is UTF-8"),
            )
            .expect("missing fixture path encodes"),
        )
        .expect("missing-path mutation parses");
    assert!(validate_secure_client_config(&missing).is_err());

    let mut aliased = config.clone();
    aliased
        .insert_json5(
            "transport/link/tls/connect_private_key",
            &serde_json::to_string(
                credentials
                    .certificate
                    .to_str()
                    .expect("alias fixture path is UTF-8"),
            )
            .expect("alias fixture path encodes"),
        )
        .expect("alias mutation parses");
    assert!(validate_secure_client_config(&aliased).is_err());

    #[cfg(unix)]
    {
        fs::set_permissions(&credentials.private_key, fs::Permissions::from_mode(0o644))
            .expect("private-key fixture becomes group/world readable");
        assert!(validate_secure_client_config(&config).is_err());

        for (mode, description) in [(0o200, "not owner-readable"), (0o700, "owner-executable")] {
            fs::set_permissions(&credentials.private_key, fs::Permissions::from_mode(mode))
                .unwrap_or_else(|error| {
                    panic!("private-key fixture cannot become {description}: {error}")
                });
            let error = validate_secure_client_config(&config)
                .expect_err("unsafe private-key mode must fail startup");
            assert!(
                error.to_string().contains("owner-readable, non-executable"),
                "{description} private key failed for the wrong reason: {error}"
            );
        }
    }
}

#[test]
fn handoff_binds_application_and_transport_identity() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("deploy/reference/galadriel-handoff.json");
    let handoff: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{} must be JSON: {error}", path.display()));
    let object = handoff
        .as_object()
        .unwrap_or_else(|| panic!("{} must contain an object", path.display()));
    let actual_fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_fields = [
        "epoch",
        "observer_cert_common_name",
        "producer_cert_common_name",
        "producer_id",
        "profile_version",
        "realm",
        "registry_canonical_sha256",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(actual_fields, expected_fields);
    assert_eq!(object["profile_version"], "1");
    assert_eq!(object["realm"], "engram/ncp");
    assert_eq!(object["producer_id"], "crebain-galadriel-producer");
    assert_eq!(
        object["registry_canonical_sha256"],
        "7644ec2bbf0e400303aaad62c647eea36bd919913f1a28a81c52c13e00dd45ba"
    );
}
