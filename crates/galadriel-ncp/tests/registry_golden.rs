#![forbid(unsafe_code)]
//! Cross-repository golden for Crebain's deployment-pinned registry contract.

use galadriel_core::Modality;
use galadriel_ncp::registry::{DeploymentRegistry, ProjectionIdentity};
use sha2::{Digest, Sha256};

const RAW_FIXTURE_FILE: &[u8] = include_bytes!("fixtures/crebain_registry_v1.json");
const RAW_FIXTURE_FILE_BYTES: usize = 3_053;
const RAW_FIXTURE_FILE_SHA256: &str =
    "506ce1437acc20ee5d36fd1e3551dd020095cc4d30d22d959c5df3cca81715a6";
const CANONICAL_REGISTRY_BYTES: usize = 3_052;
const CANONICAL_REGISTRY_SHA256: &str =
    "7644ec2bbf0e400303aaad62c647eea36bd919913f1a28a81c52c13e00dd45ba";

fn canonical_fixture_bytes() -> &'static [u8] {
    RAW_FIXTURE_FILE
        .strip_suffix(b"\n")
        .unwrap_or(RAW_FIXTURE_FILE)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[test]
fn raw_fixture_file_hash_is_distinct_from_the_canonical_registry_digest() {
    assert_eq!(RAW_FIXTURE_FILE.len(), RAW_FIXTURE_FILE_BYTES);
    assert_eq!(sha256_hex(RAW_FIXTURE_FILE), RAW_FIXTURE_FILE_SHA256);
    assert_ne!(RAW_FIXTURE_FILE_SHA256, CANONICAL_REGISTRY_SHA256);
}

#[test]
fn crebain_registry_canonical_bytes_and_digest_are_frozen() {
    let registry =
        DeploymentRegistry::from_json(RAW_FIXTURE_FILE).expect("golden registry validates");

    assert_eq!(registry.canonical_json(), canonical_fixture_bytes());
    assert_eq!(registry.canonical_json().len(), CANONICAL_REGISTRY_BYTES);
    assert_eq!(registry.digest(), CANONICAL_REGISTRY_SHA256);
}

#[test]
fn crebain_registry_accepts_the_exact_deployment_pin() {
    let registry =
        DeploymentRegistry::from_json_pinned(RAW_FIXTURE_FILE, CANONICAL_REGISTRY_SHA256)
            .expect("golden registry and canonical pin agree");

    assert_eq!(registry.registry_version(), "deployment-2026.07.13");
}

#[test]
fn crebain_registry_exposes_the_expected_projection_binding() {
    let registry =
        DeploymentRegistry::from_json_pinned(RAW_FIXTURE_FILE, CANONICAL_REGISTRY_SHA256)
            .expect("golden registry and canonical pin agree");
    let binding = registry
        .projection_binding(ProjectionIdentity {
            frame_id: 17,
            context_id: 23,
            modality: Modality::Radar,
            source_frame: "radar_front",
            timestamp_ms: 1_500,
        })
        .expect("golden radar binding is registered and applicable");

    assert_eq!(binding.frame().canonical_enu_frame(), "map_enu");
    assert_eq!(
        binding.modality().calibration().identifier(),
        "radar_calibration_v5"
    );
    assert_eq!(
        binding
            .context()
            .expected_modality_ids()
            .collect::<Vec<_>>(),
        vec![Modality::Visual, Modality::Radar]
    );
}
