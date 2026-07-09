#![forbid(unsafe_code)]
//! `galadriel-eval` — run the Monte-Carlo evaluation and print the report.
//!
//! Usage: `galadriel-eval [trials]` (default 200 trials per regime).

use galadriel_eval::{format_report, run, EvalConfig};

fn main() {
    let trials = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200usize);
    let results = run(&EvalConfig {
        trials,
        ..Default::default()
    });
    print!("{}", format_report(&results));
}
