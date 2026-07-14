#![forbid(unsafe_code)]
//! `galadriel-eval` — run the Monte-Carlo evaluation and print the report.
//!
//! Usage: `galadriel-eval [trials]` (default 20 trials per regime). Prints the
//! detection/AUC report, a detection-latency study, and bootstrap 95% CIs.

use galadriel_eval::{
    adaptive_adversary, attacker_gain, collusion_study, decoupling_sweep, format_adaptive,
    format_attacker_gain, format_ci, format_collusion, format_latency, format_maneuver,
    format_report, format_sweep, maneuver_far, measure_latency, run, stealthy_ci_study,
    validate_report_suite, EvalConfig, EvaluationResearchProfile, MIN_INFERENCE_TRIALS,
};

const MAX_TRIALS: usize = 1_000;

fn trials_arg(default: usize) -> Result<usize, String> {
    let mut args = std::env::args().skip(1);
    let Some(raw) = args.next() else {
        return Ok(default);
    };
    if args.next().is_some() {
        return Err("usage: galadriel-eval [trials]".into());
    }
    let trials = raw.parse::<usize>().map_err(|_| {
        format!("trials must be an integer in {MIN_INFERENCE_TRIALS}..={MAX_TRIALS} (got {raw:?})")
    })?;
    if !(MIN_INFERENCE_TRIALS..=MAX_TRIALS).contains(&trials) {
        return Err(format!(
            "trials must be in {MIN_INFERENCE_TRIALS}..={MAX_TRIALS} (got {trials})"
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
         SYNTHETIC Monte-Carlo evidence — NOT operational detection or false-alarm rates. These\n\
         numbers characterize explicitly generated models, not a deployed detector or field\n\
         prevalence. Before citing a value, record the commit, Rust toolchain, build profile,\n\
         and hardware (docs/EVALUATION.md §4/§7). seed={seed}\n\
         {rule}"
    );
}

fn run_main() -> Result<(), String> {
    let trials = trials_arg(MIN_INFERENCE_TRIALS)?;
    let mut params = EvaluationResearchProfile::SyntheticV0_9.params();
    params.trials = trials;
    let cfg = EvalConfig::try_new(params).map_err(|error| error.to_string())?;

    let lat_trials = trials.min(20);
    let step = 10;
    let n_boot = 200;
    let grid = [1.0, 0.8, 0.6, 0.4, 0.3, 0.2, 0.1, 0.05];
    let lags = [0, 8, 16, 24, 32];
    let suite = validate_report_suite(&cfg, &grid, &lags, n_boot, lat_trials, step)
        .map_err(|error| error.to_string())?;
    let cfg = suite.eval();
    print_synthetic_banner(cfg.base_seed());

    let results = run(cfg).map_err(|error| error.to_string())?;
    print!("{}", format_report(&results));

    // Latency study: lighter (fewer trials, coarse prefix step) — re-running each detector
    // on every prefix is quadratic, so it uses a capped trial count and a coarse step.
    println!();
    let latency = measure_latency(cfg, suite.latency_trials(), suite.latency_step())
        .map_err(|error| error.to_string())?;
    print!("{}", format_latency(&latency, lat_trials, step));

    // Bootstrap 95% CIs on the stealthy-spoof AUCs + the paired corr−PID difference.
    let (rows, diff) =
        stealthy_ci_study(cfg, suite.bootstrap_resamples()).map_err(|error| error.to_string())?;
    println!();
    print!("{}", format_ci(&rows, diff, n_boot));

    // Decoupling-strength sweep: the detection boundary (does PID hold on longer than
    // correlation as the spoof weakens? — on linear-Gaussian data it should not).
    println!();
    let sweep = decoupling_sweep(cfg, suite.decouplings(), suite.bootstrap_resamples())
        .map_err(|error| error.to_string())?;
    print!("{}", format_sweep(&sweep));

    // Colluding compromise: the honest-majority failure mode.
    println!();
    let collusion = collusion_study(cfg, trials).map_err(|error| error.to_string())?;
    print!("{}", format_collusion(&collusion));

    // Adaptive threshold-hugging adversary at a target 5% clean upper-tail quantile;
    // the independently seeded holdout arm reports the observed FAR.
    println!();
    let adaptive =
        adaptive_adversary(cfg, suite.decouplings(), 0.05).map_err(|error| error.to_string())?;
    print!("{}", format_adaptive(&adaptive, 0.5));

    // Non-stationary FAR: a benign maneuver, swept over per-channel lag.
    let (mag, dur) = (12.0, 90);
    println!();
    let maneuver =
        maneuver_far(cfg, suite.lag_steps(), mag, dur).map_err(|error| error.to_string())?;
    print!("{}", format_maneuver(&maneuver, mag, dur));

    // Attacker success: the undetected fused-innovation bias vs decoupling.
    println!();
    let gain = attacker_gain(cfg, suite.decouplings()).map_err(|error| error.to_string())?;
    print!("{}", format_attacker_gain(&gain, 0.5));
    Ok(())
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
