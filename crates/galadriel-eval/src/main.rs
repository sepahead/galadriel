#![forbid(unsafe_code)]
//! `galadriel-eval` — run the Monte-Carlo evaluation and print the report.
//!
//! Usage: `galadriel-eval [trials]` (default 200 trials per regime). Prints the
//! detection/AUC report, a detection-latency study, and bootstrap 95% CIs.

use galadriel_eval::{
    collusion_study, decoupling_sweep, format_ci, format_collusion, format_latency, format_report,
    format_sweep, measure_latency, run, stealthy_ci_study, EvalConfig,
};

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

    // Bootstrap 95% CIs on the stealthy-spoof AUCs + the paired corr−PID difference.
    let n_boot = 2000;
    let (rows, diff) = stealthy_ci_study(&cfg, n_boot);
    println!();
    print!("{}", format_ci(&rows, diff, n_boot));

    // Decoupling-strength sweep: the detection boundary (does PID hold on longer than
    // correlation as the spoof weakens? — on linear-Gaussian data it should not).
    let grid = [1.0, 0.8, 0.6, 0.4, 0.3, 0.2, 0.1, 0.05];
    println!();
    print!("{}", format_sweep(&decoupling_sweep(&cfg, &grid, n_boot)));

    // Colluding compromise: the honest-majority failure mode.
    println!();
    print!("{}", format_collusion(&collusion_study(&cfg, trials)));
}
