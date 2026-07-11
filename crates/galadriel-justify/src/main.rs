#![forbid(unsafe_code)]
//! `galadriel-justify` — run the "is PID justified over correlation?" study.
//!
//! Usage: `galadriel-justify [trials]` (default 300 trials per class).

use galadriel_justify::{
    format_autocorrelation_null, format_report, format_seq, format_synergy,
    format_synergy_continuous, preflight_default_suite, run, run_autocorrelation_null, run_seq,
    run_synergy, run_synergy_continuous, Coupling, MAX_TRIALS, MIN_TRIALS,
};

/// Root seed shared by every study invocation below and printed in the banner, so the
/// banner cannot silently drift from the studies it describes.
const STUDY_SEED: u64 = 7;

fn trials_arg(default: usize) -> Result<usize, String> {
    let mut args = std::env::args().skip(1);
    let Some(raw) = args.next() else {
        return Ok(default);
    };
    if args.next().is_some() {
        return Err("usage: galadriel-justify [trials]".into());
    }
    let trials = raw.parse::<usize>().map_err(|_| {
        format!("trials must be an integer in {MIN_TRIALS}..={MAX_TRIALS} (got {raw:?})")
    })?;
    if !(MIN_TRIALS..=MAX_TRIALS).contains(&trials) {
        return Err(format!(
            "trials must be in {MIN_TRIALS}..={MAX_TRIALS} (got {trials})"
        ));
    }
    Ok(trials)
}

/// Print the mandatory synthetic-evidence banner (docs/EVALUATION.md §7) to stdout, so a
/// copied report always carries its non-operational label and provenance reminder.
fn print_synthetic_banner(seed: u64) {
    let rule = "=".repeat(78);
    println!(
        "{rule}\n\
         SYNTHETIC study evidence — NOT operational detection or false-alarm rates. These\n\
         numbers characterize explicitly generated models, not a deployed detector or field\n\
         prevalence. Before citing a value, record the commit, Rust toolchain, build profile,\n\
         and hardware (docs/JUSTIFICATION.md, docs/EVALUATION.md). seed={seed}\n\
         {rule}"
    );
}

fn run_main() -> Result<(), String> {
    let trials = trials_arg(300)?;
    preflight_default_suite(trials).map_err(|error| error.to_string())?;
    print_synthetic_banner(STUDY_SEED);
    let study = run(trials, 400, 0.5, STUDY_SEED).map_err(|error| error.to_string())?;
    print!("{}", format_report(&study));
    let synergy =
        run_synergy(trials.min(250), 600, STUDY_SEED).map_err(|error| error.to_string())?;
    print!("{}", format_synergy(&synergy));
    let continuous = run_synergy_continuous(trials.min(250), 600, STUDY_SEED)
        .map_err(|error| error.to_string())?;
    print!("{}", format_synergy_continuous(&continuous));
    for coupling in Coupling::ALL {
        let sequential = run_seq(coupling, trials.min(100), 0.5, STUDY_SEED)
            .map_err(|error| error.to_string())?;
        print!("{}", format_seq(&sequential));
    }
    let autocorrelation =
        run_autocorrelation_null(trials, STUDY_SEED).map_err(|error| error.to_string())?;
    print!("{}", format_autocorrelation_null(&autocorrelation));
    Ok(())
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
