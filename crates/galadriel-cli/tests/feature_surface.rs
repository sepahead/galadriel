#![forbid(unsafe_code)]

use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_galadriel"))
        .args(arguments)
        .output()
        .expect("run the built galadriel binary")
}

fn successful_stdout(arguments: &[&str]) -> String {
    let output = run(arguments);
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("CLI stdout is UTF-8")
}

#[test]
fn command_surface_matches_the_selected_feature_profile() {
    let help = successful_stdout(&["--help"]);
    assert!(help.contains(
        "Galadriel's Mirror is an experimental, fail-closed advisory cross-sensor consistency monitor."
    ));
    assert!(help.contains("  demo"));

    #[cfg(feature = "ncp")]
    assert!(help.contains("  replay"));
    #[cfg(not(feature = "ncp"))]
    {
        assert!(!help.contains("  replay"));
        assert_eq!(run(&["replay"]).status.code(), Some(2));
    }

    #[cfg(feature = "ncp-live")]
    assert!(help.contains("  observe"));
    #[cfg(not(feature = "ncp-live"))]
    {
        assert!(!help.contains("  observe"));
        assert_eq!(run(&["observe"]).status.code(), Some(2));
    }
}

#[cfg(feature = "ncp")]
#[test]
fn replay_options_match_the_pid_feature_profile() {
    let help = successful_stdout(&["replay", "--help"]);
    assert!(help.contains("--max-report-tracks"));

    #[cfg(feature = "pid")]
    assert!(help.contains("--max-pid-tracks"));
    #[cfg(not(feature = "pid"))]
    assert!(!help.contains("--max-pid-tracks"));
}
