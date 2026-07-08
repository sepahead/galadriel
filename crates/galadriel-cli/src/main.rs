#![forbid(unsafe_code)]
//! `galadriel` — command-line demo and driver for Galadriel's Mirror.
//!
//! `galadriel demo` runs three synthetic scenarios — clean, a targeted acoustic
//! spoof, and a broadband jam — through the NIS χ² baseline and prints the
//! per-channel consistency traces and the fail-closed verdict for each.

use std::collections::HashMap;
use std::io::IsTerminal;

use clap::{Parser, Subcommand};
use galadriel_core::{DetectorConfig, Mirror, Modality, PidObservation, Verdict};
use galadriel_sim::injection::{inject, BroadbandJam, PhantomAcousticDoa};
use galadriel_sim::scenario::{generate, ScenarioConfig};

#[derive(Parser)]
#[command(
    name = "galadriel",
    version,
    about = "Galadriel's Mirror — a cross-sensor spoof/jam detector (MVP: NIS χ² baseline)."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the synthetic demo: clean vs targeted-spoof vs broadband-jam.
    Demo {
        /// Number of fusion frames to simulate.
        #[arg(long, default_value_t = 220)]
        frames: usize,
        /// RNG seed for the scenarios.
        #[arg(long, default_value_t = 7)]
        seed: u64,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Demo { frames, seed } => run_demo(frames, seed),
    }
    Ok(())
}

fn run_demo(frames: usize, seed: u64) {
    let color = std::io::stdout().is_terminal();
    let mods = vec![Modality::Visual, Modality::Radar, Modality::Acoustic];
    let base = ScenarioConfig {
        track_id: 1,
        frames,
        modalities: mods.clone(),
        sigma: 1.0,
        dt_ms: 100,
        seed,
    };
    let start = (frames as u64) / 2;

    banner(color);

    let clean = generate(&base);
    run_case(
        "CLEAN — corroborated airspace picture",
        &clean,
        &mods,
        color,
    );

    let mut spoof = generate(&base);
    inject(
        &mut spoof,
        &PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: start,
            bias: 8.0,
        },
    );
    run_case(
        "PHANTOM DOA — targeted single-channel spoof (acoustic)",
        &spoof,
        &mods,
        color,
    );

    let mut jam = generate(&base);
    inject(
        &mut jam,
        &BroadbandJam {
            start_frame: start,
            inflation: 3.0,
        },
    );
    run_case(
        "BROADBAND JAM — correlated all-channel denial",
        &jam,
        &mods,
        color,
    );

    println!();
    println!(
        "  {}",
        dim(
            "advisory only · calibrated_posterior=false · the PID engine (feature `pid`) must beat this",
            color
        )
    );
    println!();
}

fn run_case(title: &str, stream: &[PidObservation], mods: &[Modality], color: bool) {
    let mut mirror = Mirror::new(DetectorConfig::default());
    let track = stream[0].track_id;
    let mut history: HashMap<Modality, Vec<f64>> = HashMap::new();
    let mut report = None;

    for chunk in stream.chunks(mods.len()) {
        for o in chunk {
            mirror.ingest(o);
        }
        let r = mirror.assess(track, chunk[0].seq);
        for ch in &r.channels {
            history.entry(ch.modality).or_default().push(ch.mean_nis);
        }
        report = Some(r);
    }
    let report = report.expect("non-empty stream");

    println!();
    println!("{}", cyan(&format!("┌─ {title}"), color));
    for &m in mods {
        let hist = history.get(&m).cloned().unwrap_or_default();
        let ch = report.channels.iter().find(|c| c.modality == m);
        let (mean, anomalous, ready) = ch.map_or((0.0, false, false), |c| {
            (c.mean_nis, c.anomalous(), c.ready)
        });
        let spark = sparkline(&hist, 0.0, 30.0);
        let tag = if !ready {
            dim("… warming", color)
        } else if anomalous {
            red("● ANOMALOUS", color)
        } else {
            green("● consistent", color)
        };
        println!("│  {:<15} {}  μ={:>6.2}  {}", m.label(), spark, mean, tag);
    }
    let v = verdict_str(&report.verdict);
    let vc = match report.verdict {
        Verdict::Nominal => green(&v, color),
        Verdict::Spoof { .. } | Verdict::Jam => red(&v, color),
        Verdict::InsufficientEvidence => dim(&v, color),
    };
    println!("└▷ {}   {}", vc, dim(&report.note, color));
}

/// Render a series as a Unicode block sparkline, downsampled to ~48 columns and
/// clamped to `[lo, hi]`.
fn sparkline(data: &[f64], lo: f64, hi: f64) -> String {
    const TICKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if data.is_empty() {
        return String::new();
    }
    let cols = 48usize;
    let n = data.len();
    let span = (hi - lo).max(f64::EPSILON);
    let mut s = String::with_capacity(cols);
    for c in 0..cols {
        let idx = (c * n / cols).min(n - 1);
        let t = ((data[idx] - lo) / span).clamp(0.0, 1.0);
        let k = (t * (TICKS.len() - 1) as f64).round() as usize;
        s.push(TICKS[k.min(TICKS.len() - 1)]);
    }
    s
}

fn verdict_str(v: &Verdict) -> String {
    match v {
        Verdict::Nominal => "VERDICT: NOMINAL".into(),
        Verdict::Spoof { channels } => format!(
            "VERDICT: SPOOF [{}]",
            channels
                .iter()
                .map(|m| m.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Verdict::Jam => "VERDICT: JAM".into(),
        Verdict::InsufficientEvidence => "VERDICT: INSUFFICIENT-EVIDENCE".into(),
    }
}

fn banner(color: bool) {
    println!();
    println!(
        "{}",
        cyan(
            "═══ GALADRIEL'S MIRROR · cross-sensor consistency monitor ═══",
            color
        )
    );
    println!(
        "{}",
        dim(
            "    NIS χ² baseline — the cheap yardstick the PID engine must beat",
            color
        )
    );
}

fn wrap(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}
fn red(s: &str, color: bool) -> String {
    wrap(s, "1;31", color)
}
fn green(s: &str, color: bool) -> String {
    wrap(s, "1;32", color)
}
fn cyan(s: &str, color: bool) -> String {
    wrap(s, "1;36", color)
}
fn dim(s: &str, color: bool) -> String {
    wrap(s, "2", color)
}
