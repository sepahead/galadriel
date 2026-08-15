#![forbid(unsafe_code)]

use std::process::Command;

fn section_between<'a>(stdout: &'a str, start: &str, end: &str) -> &'a str {
    stdout
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section heading {start:?}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing following section heading {end:?}"))
        .0
}

#[test]
fn fixed_seed_demo_exercises_the_real_cli_and_semantic_scenarios() {
    let output = Command::new(env!("CARGO_BIN_EXE_galadriel"))
        .args(["demo", "--frames", "128", "--seed", "7"])
        .output()
        .expect("run the built galadriel binary");

    assert!(
        output.status.success(),
        "demo failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("CLI stdout is UTF-8");

    assert!(stdout.contains("═══ GALADRIEL'S MIRROR · cross-sensor consistency monitor ═══"));
    assert!(stdout.contains("┌─ CLEAN — corroborated airspace picture"));
    assert!(stdout.contains("└▷ VERDICT: NOMINAL"));

    let phantom = section_between(
        &stdout,
        "┌─ PHANTOM DOA — targeted single-channel spoof (acoustic)",
        "┌─ BROADBAND JAM — correlated all-channel denial",
    );
    let acoustic = phantom
        .lines()
        .find(|line| line.contains("│  acoustic"))
        .expect("phantom section contains the acoustic channel row");
    assert!(
        acoustic.contains("● ANOMALOUS"),
        "unexpected row: {acoustic}"
    );
    assert!(phantom.contains("ATTRIBUTED-INCONSISTENCY"));
    assert!(phantom.contains("[acoustic]"));

    let broadband = section_between(
        &stdout,
        "┌─ BROADBAND JAM — correlated all-channel denial",
        "┌─ SYNTHETIC MOMENT-MATCHED SPOOF",
    );
    assert_eq!(broadband.matches("● ANOMALOUS").count(), 3);
    assert!(broadband.contains("VERDICT: BROAD-DEGRADATION"));

    const STEALTH_HEADING: &str =
        "┌─ SYNTHETIC MOMENT-MATCHED SPOOF — correlation response under the modeled assumptions";
    #[cfg(feature = "dependence")]
    const STEALTH_END: &str =
        "┌─ FIXED-LAW STEALTHY SPOOF with an MI companion (feature `dependence`)";
    #[cfg(not(feature = "dependence"))]
    const STEALTH_END: &str = "build with `--features dependence`";

    let stealth_default = section_between(&stdout, STEALTH_HEADING, STEALTH_END);
    assert!(stealth_default
        .contains("baseline (NIS χ²):      NOMINAL — blind (NIS stays in-covariance)"));
    assert!(stealth_default.contains("correlation default:   VERDICT: ATTRIBUTED-INCONSISTENCY"));
    assert!(stealth_default.contains("[acoustic]"));

    #[cfg(feature = "dependence")]
    {
        let dependence = section_between(&stdout, STEALTH_END, "advisory only");
        assert!(dependence.contains("authoritative default: VERDICT: ATTRIBUTED-INCONSISTENCY"));
        assert!(dependence.contains("strongest pair KSG-MI="));
        assert!(dependence.contains("● SEPARATED"));
        assert!(dependence.contains("uncalibrated companion evidence, not PID"));
    }

    assert!(stdout.contains(
        "advisory only · calibrated_posterior=false · optional MI evidence cannot alter the default verdict"
    ));
    assert!(!stdout.contains("multi-axis fused PID"));
}
