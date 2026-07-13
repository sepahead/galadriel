#![forbid(unsafe_code)]
#![cfg(feature = "ncp-live")]

use std::process::Command;

const CANONICAL_REGISTRY_SHA256: &str =
    "7644ec2bbf0e400303aaad62c647eea36bd919913f1a28a81c52c13e00dd45ba";

#[test]
fn invalid_epoch_propagates_through_observe_and_process_main() {
    let registry = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../galadriel-ncp/tests/fixtures/crebain_registry_v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_galadriel"))
        .args([
            "observe",
            "--realm",
            "engram/ncp",
            "--epoch",
            "invalid/epoch",
            "--producer-id",
            "crebain",
            "--registry",
        ])
        .arg(registry)
        .args(["--registry-sha256", CANONICAL_REGISTRY_SHA256])
        .output()
        .expect("run the built galadriel binary");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("CLI stderr is UTF-8");
    assert!(stderr.contains("cannot open the strict two-route receiver"));
    assert!(stderr.contains("invalid NCP session id key segment: \"invalid/epoch\""));
}
