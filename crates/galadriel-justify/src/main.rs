#![forbid(unsafe_code)]
//! `galadriel-justify` — run the "is PID justified over correlation?" study.
//!
//! Usage: `galadriel-justify [trials]` (default 300 trials per class).

use galadriel_justify::{
    format_report, format_seq, format_synergy, format_synergy_continuous, run, run_seq,
    run_synergy, run_synergy_continuous, Coupling,
};

fn main() {
    let trials = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300usize);
    print!("{}", format_report(&run(trials, 400, 0.5, 7)));
    print!("{}", format_synergy(&run_synergy(trials.min(250), 600, 7)));
    print!(
        "{}",
        format_synergy_continuous(&run_synergy_continuous(trials.min(250), 600, 7))
    );
    for coupling in Coupling::ALL {
        print!(
            "{}",
            format_seq(&run_seq(coupling, trials.min(100), 0.5, 7))
        );
    }
}
