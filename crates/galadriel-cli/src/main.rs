#![forbid(unsafe_code)]
//! `galadriel` — command-line demo and driver for Galadriel's Mirror.
//!
//! `galadriel demo` runs four synthetic scenarios — clean, a targeted acoustic spoof, a
//! broadband jam, and a moment-matched stealthy spoof — through the pure default detector
//! (NIS χ² magnitude ⊕ `|ρ|` cross-sensor consistency) and prints the per-channel traces
//! and the fused verdict for each. With `--features pid` it adds the KSG-MI escalation view.

use std::collections::HashMap;
use std::io::IsTerminal;

use clap::{Parser, Subcommand};
use galadriel_core::{DetectorConfig, FusedVerdict, Mirror, Modality, PidObservation, Verdict};
use galadriel_sim::injection::{inject, BroadbandJam, PhantomAcousticDoa};
use galadriel_sim::scenario::{generate, ScenarioConfig};

#[derive(Parser)]
#[command(
    name = "galadriel",
    version,
    about = "Galadriel's Mirror — a cross-sensor spoof/jam detector (pure default: NIS χ² ⊕ |ρ| consistency)."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the synthetic demo: clean vs targeted spoof vs jam vs moment-matched stealthy spoof.
    Demo {
        /// Number of fusion frames to simulate.
        #[arg(long, default_value_t = 220)]
        frames: usize,
        /// RNG seed for the scenarios.
        #[arg(long, default_value_t = 7)]
        seed: u64,
    },
    /// Replay a JSONL capture of PidObservations through the detector(s).
    #[cfg(feature = "ncp")]
    Replay {
        /// Path to a `.jsonl` file (one PidObservation per line).
        path: String,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Demo { frames, seed } => run_demo(frames, seed),
        #[cfg(feature = "ncp")]
        Cmd::Replay { path } => run_replay(&path)?,
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
        rho: 0.0,
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

    // The stealthy spoof the magnitude baseline is blind to — caught by the pure
    // correlation default (no pid-core). This scene needs correlated honest channels.
    run_stealthy_default_demo(frames, seed, color);

    #[cfg(feature = "pid")]
    run_pid_demo(frames, seed, color);
    #[cfg(not(feature = "pid"))]
    println!(
        "\n  {}",
        dim(
            "build with `--features pid` to add the KSG-MI escalation (for nonlinear / synergistic couplings)",
            color
        )
    );

    println!();
    println!(
        "  {}",
        dim(
            "advisory only · calibrated_posterior=false · PID (feature `pid`) escalates where correlation cannot",
            color
        )
    );
    println!();
}

fn run_case(title: &str, stream: &[PidObservation], mods: &[Modality], color: bool) {
    if stream.is_empty() {
        println!("\n{}", cyan(&format!("┌─ {title}"), color));
        println!("└▷ {}", dim("(no observations — nothing to assess)", color));
        return;
    }
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

fn fused_verdict_str(v: &FusedVerdict) -> String {
    match v {
        FusedVerdict::Nominal => "VERDICT: NOMINAL".into(),
        FusedVerdict::Spoof { channels, stealthy } => format!(
            "VERDICT: SPOOF{} [{}]",
            if *stealthy { " (stealthy)" } else { "" },
            channels
                .iter()
                .map(|m| m.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        FusedVerdict::Jam => "VERDICT: JAM".into(),
        FusedVerdict::InsufficientEvidence => "VERDICT: INSUFFICIENT-EVIDENCE".into(),
    }
}

/// The pure stealthy-spoof scene: on a moment-matched spoof the magnitude baseline is
/// blind (NIS stays in-covariance) while the cheap correlation default — shipped in the
/// pure build with no `pid-core` — catches the decoupled channel by its broken
/// cross-sensor `|ρ|` agreement. Needs correlated honest channels (`ρ = 0.7`).
fn run_stealthy_default_demo(frames: usize, seed: u64, color: bool) {
    use galadriel_core::{assess_default, CorrConfig};
    use galadriel_sim::scenario::{generate_spoofed, StealthySpoof};

    let mods = vec![Modality::Visual, Modality::Radar, Modality::Acoustic];
    let cfg = ScenarioConfig {
        track_id: 1,
        frames,
        modalities: mods.clone(),
        sigma: 1.0,
        rho: 0.7,
        dt_ms: 100,
        seed,
    };
    let stream = generate_spoofed(
        &cfg,
        StealthySpoof {
            target: Modality::Acoustic,
            start_frame: (frames as u64) / 3,
        },
    );

    let report = assess_default(
        &stream,
        &mods,
        &DetectorConfig::default(),
        &CorrConfig::default(),
    );

    println!();
    println!(
        "{}",
        cyan(
            "┌─ MOMENT-MATCHED STEALTHY SPOOF (acoustic) — baseline blind, correlation default catches it",
            color
        )
    );
    for c in &report.correlation.channels {
        let tag = if c.decoupled {
            red("● DECOUPLED", color)
        } else {
            green("● corroborates", color)
        };
        let rho = c
            .corroboration
            .map_or_else(|| "  —  ".to_string(), |v| format!("{v:>5.3}"));
        println!(
            "│  {:<15} |ρ| corroboration={}  {}",
            c.modality.label(),
            rho,
            tag
        );
    }
    let bl = match report.baseline.verdict {
        Verdict::Nominal => green("NOMINAL — blind (NIS stays in-covariance)", color),
        _ => red(&verdict_str(&report.baseline.verdict), color),
    };
    let fused = fused_verdict_str(&report.verdict);
    let fc = match report.verdict {
        FusedVerdict::Nominal => green(&fused, color),
        FusedVerdict::InsufficientEvidence => dim(&fused, color),
        _ => red(&fused, color),
    };
    println!("│  baseline (NIS χ²):      {}", bl);
    println!(
        "└▷ correlation default:   {}   {}",
        fc,
        dim(&report.note, color)
    );
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
            "    NIS χ² magnitude ⊕ |ρ| cross-sensor consistency — the pure default detector",
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

/// Replay a JSONL capture of `PidObservation`s through the baseline (and the PID
/// engine when built with `--features pid,ncp`).
#[cfg(feature = "ncp")]
fn run_replay(path: &str) -> anyhow::Result<()> {
    let color = std::io::stdout().is_terminal();
    let obs = galadriel_ncp::read_jsonl(path)?;
    if obs.is_empty() {
        anyhow::bail!("no observations parsed from {path}");
    }
    let mut tracks: Vec<u64> = obs.iter().map(|o| o.track_id).collect();
    tracks.sort_unstable();
    tracks.dedup();

    println!();
    println!(
        "{}",
        cyan(
            &format!(
                "┌─ REPLAY {path} — {} obs, {} track(s)",
                obs.len(),
                tracks.len()
            ),
            color
        )
    );

    let mut mirror = Mirror::new(DetectorConfig::default());
    for o in &obs {
        mirror.ingest(o);
    }
    for t in &tracks {
        let last_seq = obs
            .iter()
            .filter(|o| o.track_id == *t)
            .map(|o| o.seq)
            .max()
            .unwrap_or(0);
        let rep = mirror.assess(*t, last_seq);
        let v = verdict_str(&rep.verdict);
        let vc = match rep.verdict {
            Verdict::Nominal => green(&v, color),
            Verdict::Spoof { .. } | Verdict::Jam => red(&v, color),
            Verdict::InsufficientEvidence => dim(&v, color),
        };
        println!("│  baseline · track {t}: {}  {}", vc, dim(&rep.note, color));
    }

    #[cfg(feature = "pid")]
    {
        use galadriel_pid::{analyze, scalar_channels, PidConfig};
        let mut mods: Vec<Modality> = obs.iter().map(|o| o.modality).collect();
        mods.sort_by_key(|m| *m as u8);
        mods.dedup();
        let rep = analyze(&scalar_channels(&obs, &mods, 0), &PidConfig::default());
        println!("│  PID · {:?}  {}", rep.verdict, dim(&rep.note, color));
    }

    println!("└▷ replay complete");
    Ok(())
}

/// The `pid` feature demo: on a moment-matched stealthy spoof the magnitude
/// baseline is blind (NIS stays in-covariance) while the cross-sensor PID engine
/// catches the decoupled channel.
#[cfg(feature = "pid")]
fn run_pid_demo(frames: usize, seed: u64, color: bool) {
    use galadriel_pid::{analyze, scalar_channels, PidConfig, PidVerdict};
    use galadriel_sim::scenario::{generate_spoofed, StealthySpoof};

    let mods = vec![Modality::Visual, Modality::Radar, Modality::Acoustic];
    let cfg = ScenarioConfig {
        track_id: 1,
        frames,
        modalities: mods.clone(),
        sigma: 1.0,
        rho: 0.7,
        dt_ms: 100,
        seed,
    };
    let stream = generate_spoofed(
        &cfg,
        StealthySpoof {
            target: Modality::Acoustic,
            start_frame: (frames as u64) / 3,
        },
    );

    // The KSG-MI escalation on the same stream: it should agree with the correlation
    // default above — on a linear-Gaussian spoof MI and |ρ| see the same structure.
    let pid = analyze(&scalar_channels(&stream, &mods, 0), &PidConfig::default());

    println!();
    println!(
        "{}",
        cyan(
            "┌─ …SAME STEALTHY SPOOF through the KSG-MI escalation (feature `pid`)",
            color
        )
    );
    for c in &pid.channels {
        let tag = if c.decoupled {
            red("● DECOUPLED", color)
        } else {
            green("● corroborates", color)
        };
        let mi = c
            .corroboration
            .map_or_else(|| "  —  ".to_string(), |v| format!("{v:>5.3}"));
        println!(
            "│  {:<15} KSG-MI corroboration={}  {}",
            c.modality.label(),
            mi,
            tag
        );
    }
    let pv = match pid.verdict {
        PidVerdict::Spoof(_) => red("SPOOF", color),
        PidVerdict::Nominal => green("NOMINAL", color),
        PidVerdict::InsufficientEvidence => dim("INSUFFICIENT-EVIDENCE", color),
    };
    println!(
        "└▷ PID engine:        {}   {}   {}",
        pv,
        dim(&pid.note, color),
        dim(
            "(confirms the correlation default — MI is forced here, not justified)",
            color
        )
    );
}
