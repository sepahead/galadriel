#![forbid(unsafe_code)]
//! `galadriel-eval` — run the Monte-Carlo evaluation and print the report.
//!
//! Usage: `galadriel-eval [trials]` (default 200 trials per regime). Prints the
//! detection/AUC report, then a detection-latency (time-to-detect) study.

use galadriel_eval::{format_latency, format_report, measure_latency, run, EvalConfig};

fn main() {
    let trials = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200usize);
    let cfg = EvalConfig {
        trials,
        ..Default::default()
    };

    let results = run(&cfg);
    print!("{}", format_report(&results));

    // Latency study: lighter (fewer trials, coarse prefix step) — re-running each detector
    // on every prefix is quadratic, so it uses a capped trial count and a 4-frame step.
    let lat_trials = trials.min(50);
    let step = 4;
    println!();
    print!(
        "{}",
        format_latency(&measure_latency(&cfg, lat_trials, step), lat_trials, step)
    );
}
