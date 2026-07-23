#![forbid(unsafe_code)]
#![cfg(feature = "ncp-live")]

use std::process::{Command, Output};

const CANONICAL_REGISTRY_SHA256: &str =
    "7644ec2bbf0e400303aaad62c647eea36bd919913f1a28a81c52c13e00dd45ba";

fn run_observe(epoch: &str, producer_id: &str) -> Output {
    let registry = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/observe-registry-must-not-exist.json");
    assert!(
        !registry.exists(),
        "the identity-order test requires an absent registry path"
    );
    Command::new(env!("CARGO_BIN_EXE_galadriel"))
        .args([
            "observe",
            "--realm",
            "engram/ncp",
            "--epoch",
            epoch,
            "--producer-id",
            producer_id,
            "--registry",
        ])
        .arg(registry)
        .args(["--registry-sha256", CANONICAL_REGISTRY_SHA256])
        .output()
        .expect("run the built galadriel binary")
}

fn assert_no_registry_or_receiver_effect(stderr: &str) {
    assert!(!stderr.contains("cannot open registry"));
    assert!(!stderr.contains("cannot start the live receiver runtime"));
    assert!(!stderr.contains("cannot open the strict two-route receiver"));
}

#[test]
fn noncanonical_epoch_fails_before_registry_or_receiver_start() {
    let output = run_observe("uav+3", "crebain");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("CLI stderr is UTF-8");
    assert!(stderr.contains("invalid Galadriel epoch identity"));
    assert!(!stderr.contains("uav+3"));
    assert_no_registry_or_receiver_effect(&stderr);
}

#[test]
fn noncanonical_producer_fails_before_registry_or_receiver_start() {
    let output = run_observe("uav3", "crebain+1");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("CLI stderr is UTF-8");
    assert!(stderr.contains("invalid Galadriel producer identity"));
    assert!(!stderr.contains("crebain+1"));
    assert_no_registry_or_receiver_effect(&stderr);
}

#[test]
fn oversized_identity_is_not_printed_or_used() {
    let oversized = "sensitive-invalid-identity".repeat(512);
    let output = run_observe(&oversized, "crebain");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("CLI stderr is UTF-8");
    assert!(stderr.contains("invalid Galadriel epoch identity"));
    assert!(!stderr.contains(&oversized));
    assert!(stderr.len() < 512);
    assert_no_registry_or_receiver_effect(&stderr);
}
