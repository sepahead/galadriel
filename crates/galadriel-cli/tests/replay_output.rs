#![forbid(unsafe_code)]
#![cfg(feature = "ncp")]

use std::process::Command;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/replay_three_tracks.jsonl"
);

fn replay_stdout(max_report_tracks: &str, max_pid_tracks: &str) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_galadriel"));
    command.args(["replay", FIXTURE, "--max-report-tracks", max_report_tracks]);
    #[cfg(feature = "pid")]
    command.args(["--max-pid-tracks", max_pid_tracks]);
    #[cfg(not(feature = "pid"))]
    let _ = max_pid_tracks;

    let output = command.output().expect("run the built galadriel binary");
    assert!(
        output.status.success(),
        "replay failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("CLI stdout is UTF-8")
}

fn reported_track_ids(stdout: &str, marker: &str) -> Vec<u64> {
    stdout
        .lines()
        .filter_map(|line| {
            let suffix = line.strip_prefix(marker)?;
            let (track_id, _) = suffix.split_once(':')?;
            track_id.parse().ok()
        })
        .collect()
}

#[test]
fn replay_reports_suppressed_histories_and_exact_limit_boundaries() {
    let suppressed = replay_stdout("1", "2");

    assert!(suppressed.contains("— 10 obs, 3 track(s)"));
    assert_eq!(
        reported_track_ids(&suppressed, "│  baseline · track "),
        [10]
    );
    assert_eq!(
        reported_track_ids(&suppressed, "│  default  · track "),
        [10]
    );
    #[cfg(feature = "pid")]
    assert_eq!(
        reported_track_ids(&suppressed, "│  PID      · track "),
        [10]
    );
    #[cfg(not(feature = "pid"))]
    assert!(reported_track_ids(&suppressed, "│  PID      · track ").is_empty());
    assert!(suppressed.contains("too-few-modalities 2 frame(s), first seq 1, last seq 2"));
    assert!(suppressed.contains(
        "suppressed 2 per-track report(s); among them, 0 had baseline alarms and 0 had default-fused alarms"
    ));
    assert!(suppressed.contains(
        "historical insufficiency affected 2 baseline track(s) and 2 default track(s); consistency input was rejected or missing on 2 track(s)"
    ));
    assert!(suppressed.contains(
        "baseline history across suppressed tracks: no positive alarm frames; insufficient-evidence 4 frame(s), first seq 1, last seq 2"
    ));
    assert!(suppressed.contains(
        "default history across suppressed tracks: no positive alarm frames; insufficient-evidence 4 frame(s), first seq 1, last seq 2; missing-projection 4 frame(s), first seq 1, last seq 2"
    ));
    #[cfg(feature = "pid")]
    assert!(suppressed
        .contains("PID terminal analysis skipped for 1 track(s); bounded by --max-pid-tracks=2"));
    assert!(suppressed.contains("└▷ replay complete"));

    #[cfg(feature = "pid")]
    {
        let asymmetric = replay_stdout("3", "2");
        assert_eq!(
            reported_track_ids(&asymmetric, "│  baseline · track "),
            [10, 20, 30]
        );
        assert_eq!(
            reported_track_ids(&asymmetric, "│  default  · track "),
            [10, 20, 30]
        );
        assert_eq!(
            reported_track_ids(&asymmetric, "│  PID      · track "),
            [10, 20]
        );
        assert!(!asymmetric.contains("suppressed"));
        assert!(asymmetric.contains(
            "PID terminal analysis skipped for 1 track(s); bounded by --max-pid-tracks=2"
        ));

        let equal_limits = replay_stdout("3", "3");
        assert_eq!(
            reported_track_ids(&equal_limits, "│  baseline · track "),
            [10, 20, 30]
        );
        assert_eq!(
            reported_track_ids(&equal_limits, "│  default  · track "),
            [10, 20, 30]
        );
        assert_eq!(
            reported_track_ids(&equal_limits, "│  PID      · track "),
            [10, 20, 30]
        );
        assert!(!equal_limits.contains("suppressed"));
        assert!(!equal_limits.contains("PID terminal analysis skipped"));
        assert!(equal_limits.contains("└▷ replay complete"));
    }

    #[cfg(not(feature = "pid"))]
    {
        let all_visible = replay_stdout("3", "3");
        assert_eq!(
            reported_track_ids(&all_visible, "│  baseline · track "),
            [10, 20, 30]
        );
        assert_eq!(
            reported_track_ids(&all_visible, "│  default  · track "),
            [10, 20, 30]
        );
        assert!(reported_track_ids(&all_visible, "│  PID      · track ").is_empty());
        assert!(!all_visible.contains("suppressed"));
        assert!(all_visible.contains("└▷ replay complete"));
    }
}
