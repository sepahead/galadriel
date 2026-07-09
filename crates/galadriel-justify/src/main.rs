#![forbid(unsafe_code)]
//! `galadriel-justify` — run the "is PID justified over correlation?" study.
//!
//! Usage: `galadriel-justify [trials]` (default 300 trials per class).

use galadriel_justify::{format_report, run};

fn main() {
    let trials = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300usize);
    print!("{}", format_report(&run(trials, 400, 0.5, 7)));
}
