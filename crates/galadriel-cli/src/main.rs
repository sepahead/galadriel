#![forbid(unsafe_code)]
//! `galadriel` — command-line demo and driver for Galadriel's Mirror.
//!
//! `galadriel demo` runs four synthetic scenarios — clean, a targeted acoustic spoof, a
//! broadband jam, and a moment-matched stealthy spoof — through the pure default detector
//! (NIS χ² magnitude ⊕ signed `ρ` cross-sensor consistency) and prints the per-channel traces
//! and the fused verdict for each. With `--features pid` it adds the KSG-MI escalation view.

use std::collections::HashMap;
#[cfg(feature = "ncp")]
use std::collections::VecDeque;
use std::io::IsTerminal;

use clap::{Parser, Subcommand};
use galadriel_core::{
    DetectorConfig, FusedVerdict, MagnitudeEvidence, Mirror, Modality, PidObservation, Verdict,
};
use galadriel_sim::injection::{inject, BroadbandJam, PhantomAcousticDoa};
use galadriel_sim::scenario::{generate, ScenarioConfig};

const MIN_DEMO_FRAMES: usize = 128;
const MAX_DEMO_FRAMES: usize = 10_000;

#[derive(Parser)]
#[command(
    name = "galadriel",
    version,
    about = "Galadriel's Mirror — a cross-sensor spoof/jam detector (pure default: NIS χ² ⊕ signed-ρ consistency)."
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
        /// Maximum number of per-track reports to print; all tracks are still assessed.
        #[arg(long, default_value_t = 100)]
        max_report_tracks: usize,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Demo { frames, seed } => run_demo(frames, seed)?,
        #[cfg(feature = "ncp")]
        Cmd::Replay {
            path,
            max_report_tracks,
        } => run_replay(&path, max_report_tracks)?,
    }
    Ok(())
}

fn run_demo(frames: usize, seed: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        (MIN_DEMO_FRAMES..=MAX_DEMO_FRAMES).contains(&frames),
        "demo frames must be in {MIN_DEMO_FRAMES}..={MAX_DEMO_FRAMES} so all detectors can warm up"
    );
    let color = std::io::stdout().is_terminal();
    let mods = vec![Modality::Visual, Modality::Radar, Modality::Acoustic];
    let base = ScenarioConfig {
        track_id: 1,
        frames,
        modalities: mods.clone(),
        sigma: 1.0,
        rho: 0.7,
        dt_ms: 100,
        seed,
    };
    let start = (frames as u64) / 2;

    banner(color);

    {
        let clean = generate(&base)?;
        run_case(
            "CLEAN — corroborated airspace picture",
            &clean,
            &mods,
            color,
        )?;
    }

    {
        let mut spoof = generate(&base)?;
        inject(
            &mut spoof,
            &PhantomAcousticDoa {
                target: Modality::Acoustic,
                start_frame: start,
                bias: 8.0,
            },
        )?;
        run_case(
            "PHANTOM DOA — targeted single-channel spoof (acoustic)",
            &spoof,
            &mods,
            color,
        )?;
    }

    {
        let mut jam = generate(&base)?;
        inject(
            &mut jam,
            &BroadbandJam {
                start_frame: start,
                inflation: 3.0,
            },
        )?;
        run_case(
            "BROADBAND JAM — correlated all-channel denial",
            &jam,
            &mods,
            color,
        )?;
    }

    // The stealthy spoof the magnitude baseline is blind to — caught by the pure
    // correlation default (no pid-core). This scene needs correlated honest channels.
    run_stealthy_default_demo(frames, seed, color)?;

    #[cfg(feature = "pid")]
    run_pid_demo(frames, seed, color)?;
    #[cfg(not(feature = "pid"))]
    println!(
        "\n  {}",
        dim(
            "build with `--features pid` to add nonlinear pairwise-MI diagnostics (PID atoms are report-only)",
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
    Ok(())
}

fn run_case(
    title: &str,
    stream: &[PidObservation],
    mods: &[Modality],
    color: bool,
) -> anyhow::Result<()> {
    if stream.is_empty() {
        println!("\n{}", cyan(&format!("┌─ {title}"), color));
        println!("└▷ {}", dim("(no observations — nothing to assess)", color));
        return Ok(());
    }
    anyhow::ensure!(!mods.is_empty(), "demo modalities must not be empty");
    anyhow::ensure!(
        stream.len() % mods.len() == 0,
        "demo stream has an incomplete fusion frame"
    );
    let mut mirror = Mirror::with_modalities(DetectorConfig::default(), mods)?;
    let track = stream[0].track_id;
    let mut history: HashMap<Modality, Vec<f64>> = HashMap::new();
    let mut report = None;

    for chunk in stream.chunks(mods.len()) {
        anyhow::ensure!(
            chunk
                .iter()
                .all(|observation| observation.track_id == track && observation.seq == chunk[0].seq),
            "demo stream is not grouped into one track and sequence per fusion frame"
        );
        for o in chunk {
            mirror.ingest(o)?;
        }
        let r = mirror.assess(track, chunk[0].seq)?;
        for ch in &r.channels {
            history.entry(ch.modality).or_default().push(ch.mean_nis);
        }
        report = Some(r);
    }
    let report = report.ok_or_else(|| anyhow::anyhow!("no complete fusion frame"))?;

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
        Verdict::Spoof { .. } | Verdict::Jam | Verdict::Anomaly { .. } => red(&v, color),
        Verdict::InsufficientEvidence => dim(&v, color),
    };
    println!("└▷ {}   {}", vc, dim(&report.note, color));
    Ok(())
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
        Verdict::Anomaly { channels } => format!(
            "VERDICT: ANOMALY [{}]",
            channels
                .iter()
                .map(|modality| modality.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Verdict::InsufficientEvidence => "VERDICT: INSUFFICIENT-EVIDENCE".into(),
    }
}

fn fused_verdict_str(v: &FusedVerdict) -> String {
    match v {
        FusedVerdict::Nominal => "VERDICT: NOMINAL".into(),
        FusedVerdict::Spoof {
            channels,
            magnitude,
        } => format!(
            "VERDICT: SPOOF ({}) [{}]",
            match magnitude {
                MagnitudeEvidence::InCovariance => "in-covariance magnitude",
                MagnitudeEvidence::Elevated => "elevated magnitude",
                MagnitudeEvidence::Mixed => "mixed magnitude",
                MagnitudeEvidence::Insufficient => "magnitude insufficient",
            },
            channels
                .iter()
                .map(|m| m.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        FusedVerdict::Jam => "VERDICT: JAM".into(),
        FusedVerdict::Anomaly { channels } => format!(
            "VERDICT: ANOMALY [{}]",
            channels
                .iter()
                .map(|modality| modality.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        FusedVerdict::InsufficientEvidence => "VERDICT: INSUFFICIENT-EVIDENCE".into(),
    }
}

/// The pure stealthy-spoof scene: on a moment-matched spoof the magnitude baseline is
/// blind (NIS stays in-covariance) while the cheap correlation default can flag
/// the modeled decoupling. This synthetic scene needs correlated honest channels
/// (`ρ = 0.7`) and is not field-performance evidence.
fn run_stealthy_default_demo(frames: usize, seed: u64, color: bool) -> anyhow::Result<()> {
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
    )?;

    let report = assess_default(
        &stream,
        &mods,
        &DetectorConfig::default(),
        &CorrConfig::default(),
    )?;

    println!();
    println!(
        "{}",
        cyan(
            "┌─ SYNTHETIC MOMENT-MATCHED SPOOF — correlation response under the modeled assumptions",
            color
        )
    );
    for axis in &report.correlations {
        for c in &axis.report.channels {
            let tag = if c.decoupled {
                red("● DECOUPLED", color)
            } else {
                green("● corroborates", color)
            };
            let rho = c
                .corroboration
                .map_or_else(|| "  —  ".to_string(), |v| format!("{v:>5.3}"));
            println!(
                "│  axis {} {:<15} ρ corroboration={}  {}",
                axis.axis,
                c.modality.label(),
                rho,
                tag
            );
        }
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
    println!("│  baseline (NIS χ²):      {bl}");
    println!(
        "└▷ correlation default:   {}   {}",
        fc,
        dim(&report.note, color)
    );
    Ok(())
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
            "    NIS χ² magnitude ⊕ signed-ρ cross-sensor consistency — the pure default detector",
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

#[cfg(feature = "ncp")]
#[derive(Debug, Default)]
struct FrameSpan {
    first_seq: Option<u64>,
    last_seq: Option<u64>,
    frames: usize,
}

#[cfg(feature = "ncp")]
impl FrameSpan {
    fn observe(&mut self, seq: u64) {
        self.first_seq.get_or_insert(seq);
        self.last_seq = Some(seq);
        self.frames = self.frames.saturating_add(1);
    }

    fn merge(&mut self, other: &Self) {
        if other.frames == 0 {
            return;
        }
        self.first_seq = match (self.first_seq, other.first_seq) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        };
        self.last_seq = match (self.last_seq, other.last_seq) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
        self.frames = self.frames.saturating_add(other.frames);
    }

    fn describe(&self, label: &str) -> Option<String> {
        Some(format!(
            "{label} {} frame(s), first seq {}, last seq {}",
            self.frames, self.first_seq?, self.last_seq?
        ))
    }
}

#[cfg(feature = "ncp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsistencyFrameStatus {
    Assessed { insufficient: bool },
    TooFewModalities,
    MissingProjection,
    ExtractionError,
    AnalysisError,
}

#[cfg(feature = "ncp")]
impl ConsistencyFrameStatus {
    fn insufficient(self) -> bool {
        !matches!(
            self,
            Self::Assessed {
                insufficient: false
            }
        )
    }
}

#[cfg(feature = "ncp")]
#[derive(Debug, Default)]
struct ReplayHistory {
    alarms: FrameSpan,
    insufficient: FrameSpan,
    too_few_modalities: FrameSpan,
    missing_projection: FrameSpan,
    extraction_errors: FrameSpan,
    analysis_errors: FrameSpan,
}

#[cfg(feature = "ncp")]
impl ReplayHistory {
    fn observe(
        &mut self,
        seq: u64,
        alarm: bool,
        verdict_insufficient: bool,
        consistency: Option<ConsistencyFrameStatus>,
    ) {
        if alarm {
            self.alarms.observe(seq);
        }
        if verdict_insufficient || consistency.is_some_and(ConsistencyFrameStatus::insufficient) {
            self.insufficient.observe(seq);
        }
        match consistency {
            Some(ConsistencyFrameStatus::TooFewModalities) => self.too_few_modalities.observe(seq),
            Some(ConsistencyFrameStatus::MissingProjection) => self.missing_projection.observe(seq),
            Some(ConsistencyFrameStatus::ExtractionError) => self.extraction_errors.observe(seq),
            Some(ConsistencyFrameStatus::AnalysisError) => self.analysis_errors.observe(seq),
            Some(ConsistencyFrameStatus::Assessed { .. }) | None => {}
        }
    }

    fn merge(&mut self, other: &Self) {
        self.alarms.merge(&other.alarms);
        self.insufficient.merge(&other.insufficient);
        self.too_few_modalities.merge(&other.too_few_modalities);
        self.missing_projection.merge(&other.missing_projection);
        self.extraction_errors.merge(&other.extraction_errors);
        self.analysis_errors.merge(&other.analysis_errors);
    }

    fn has_consistency_issue(&self) -> bool {
        self.too_few_modalities.frames > 0
            || self.missing_projection.frames > 0
            || self.extraction_errors.frames > 0
            || self.analysis_errors.frames > 0
    }

    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(value) = self.alarms.describe("alarm") {
            parts.push(value);
        } else {
            parts.push("no positive alarm frames".to_string());
        }
        for (span, label) in [
            (&self.insufficient, "insufficient-evidence"),
            (&self.too_few_modalities, "too-few-modalities"),
            (&self.missing_projection, "missing-projection"),
            (&self.extraction_errors, "projection-extraction-error"),
            (&self.analysis_errors, "correlation-analysis-error"),
        ] {
            if let Some(value) = span.describe(label) {
                parts.push(value);
            }
        }
        parts.join("; ")
    }
}

#[cfg(feature = "ncp")]
fn baseline_alarm(verdict: &Verdict) -> bool {
    matches!(
        verdict,
        Verdict::Spoof { .. } | Verdict::Jam | Verdict::Anomaly { .. }
    )
}

#[cfg(feature = "ncp")]
fn fused_alarm(verdict: &FusedVerdict) -> bool {
    matches!(
        verdict,
        FusedVerdict::Spoof { .. } | FusedVerdict::Jam | FusedVerdict::Anomaly { .. }
    )
}

/// Replay a JSONL capture of `PidObservation`s through the baseline (and the PID
/// engine when built with `--features pid,ncp`).
#[cfg(feature = "ncp")]
fn run_replay(path: &str, max_report_tracks: usize) -> anyhow::Result<()> {
    use galadriel_core::{
        combine_correlation_axes, consistency_channels_with_temporal_limits, correlation,
        AxisCorrelationReport, CorrConfig, CorrVerdict,
    };

    let color = std::io::stdout().is_terminal();
    let detector_cfg = DetectorConfig::default();
    anyhow::ensure!(
        (1..=detector_cfg.max_tracks).contains(&max_report_tracks),
        "max-report-tracks must be in 1..={}",
        detector_cfg.max_tracks
    );
    let mut obs = galadriel_ncp::read_jsonl(path)?;
    if obs.is_empty() {
        anyhow::bail!("no observations parsed from {path}");
    }
    // One global sort turns the previous per-track rescans/clones into O(n log n)
    // preprocessing plus a single linear replay pass.
    obs.sort_by_key(|observation| {
        (
            observation.track_id,
            observation.seq,
            observation.modality as u8,
        )
    });
    let track_count = 1 + obs
        .windows(2)
        .filter(|pair| pair[0].track_id != pair[1].track_id)
        .count();
    anyhow::ensure!(
        track_count <= detector_cfg.max_tracks,
        "capture contains {track_count} tracks; detector maximum is {}",
        detector_cfg.max_tracks
    );

    println!();
    println!(
        "{}",
        cyan(
            &format!(
                "┌─ REPLAY {path} — {} obs, {} track(s)",
                obs.len(),
                track_count
            ),
            color
        )
    );

    let mut track_start = 0usize;
    let mut track_index = 0usize;
    let mut suppressed_baseline_alarm_tracks = 0usize;
    let mut suppressed_default_alarm_tracks = 0usize;
    let mut suppressed_baseline_insufficient_tracks = 0usize;
    let mut suppressed_default_insufficient_tracks = 0usize;
    let mut suppressed_default_issue_tracks = 0usize;
    let mut suppressed_baseline_history = ReplayHistory::default();
    let mut suppressed_default_history = ReplayHistory::default();
    while track_start < obs.len() {
        let track_id = obs[track_start].track_id;
        let mut track_end = track_start + 1;
        while track_end < obs.len() && obs[track_end].track_id == track_id {
            track_end += 1;
        }
        let track_obs = &obs[track_start..track_end];
        let mut mods: Vec<Modality> = track_obs.iter().map(|o| o.modality).collect();
        mods.sort_by_key(|modality| *modality as u8);
        mods.dedup();

        let mut mirror = if mods.len() >= detector_cfg.min_channels {
            Mirror::with_modalities(detector_cfg.clone(), &mods)?
        } else {
            Mirror::new(detector_cfg.clone())?
        };
        let corr_cfg = CorrConfig::default();
        let mut frame_starts = VecDeque::with_capacity(corr_cfg.window.saturating_add(1));
        let mut baseline_history = ReplayHistory::default();
        let mut default_history = ReplayHistory::default();
        let mut baseline_terminal = None;
        let mut default_terminal: Option<(FusedVerdict, String)> = None;

        let mut frame_start = 0usize;
        while frame_start < track_obs.len() {
            let seq = track_obs[frame_start].seq;
            let mut frame_end = frame_start + 1;
            while frame_end < track_obs.len() && track_obs[frame_end].seq == seq {
                frame_end += 1;
            }
            for observation in &track_obs[frame_start..frame_end] {
                mirror.ingest(observation)?;
            }
            let baseline = mirror.assess(track_id, seq)?;
            baseline_history.observe(
                seq,
                baseline_alarm(&baseline.verdict),
                matches!(&baseline.verdict, Verdict::InsufficientEvidence),
                None,
            );

            frame_starts.push_back(frame_start);
            if frame_starts.len() > corr_cfg.window {
                frame_starts.pop_front();
            }
            let tail_start = frame_starts.front().copied().unwrap_or(frame_start);
            let (correlations, consistency_status, consistency_note) = if mods.len()
                < detector_cfg.min_channels
            {
                (
                    Vec::new(),
                    ConsistencyFrameStatus::TooFewModalities,
                    "fewer than the configured minimum modalities".to_string(),
                )
            } else {
                match consistency_channels_with_temporal_limits(
                    &track_obs[tail_start..frame_end],
                    &mods,
                    detector_cfg.max_seq_gap,
                    detector_cfg.max_timestamp_skew_ms,
                    detector_cfg.max_inter_sample_gap_ms,
                ) {
                    Ok(Some(projection)) => {
                        let axis_count = projection.axes.len();
                        let reports = projection
                            .axes
                            .iter()
                            .enumerate()
                            .map(|(axis, channels)| {
                                let mut adjusted = corr_cfg.clone();
                                adjusted.family_alpha /= axis_count as f64;
                                correlation::analyze(channels, &adjusted)
                                    .map(|report| AxisCorrelationReport { axis, report })
                            })
                            .collect::<galadriel_core::Result<Vec<_>>>();
                        match reports {
                            Ok(reports) => {
                                let insufficient = reports.is_empty()
                                    || reports.iter().any(|axis| {
                                        matches!(
                                            axis.report.verdict,
                                            CorrVerdict::InsufficientEvidence
                                        )
                                    });
                                let note = reports
                                    .iter()
                                    .map(|axis| format!("axis {}: {}", axis.axis, axis.report.note))
                                    .collect::<Vec<_>>()
                                    .join(" | ");
                                (
                                    reports,
                                    ConsistencyFrameStatus::Assessed { insufficient },
                                    note,
                                )
                            }
                            Err(error) => (
                                Vec::new(),
                                ConsistencyFrameStatus::AnalysisError,
                                format!("consistency input not assessable: {error}"),
                            ),
                        }
                    }
                    Ok(None) => (
                        Vec::new(),
                        ConsistencyFrameStatus::MissingProjection,
                        "no producer-attested common consistency projection".to_string(),
                    ),
                    Err(error) => (
                        Vec::new(),
                        ConsistencyFrameStatus::ExtractionError,
                        format!("consistency input not assessable: {error}"),
                    ),
                }
            };
            let (fused, fusion_note) = combine_correlation_axes(&baseline, &correlations);
            default_history.observe(
                seq,
                fused_alarm(&fused),
                matches!(&fused, FusedVerdict::InsufficientEvidence),
                Some(consistency_status),
            );
            baseline_terminal = Some(baseline);
            default_terminal = Some((
                fused,
                format!("{fusion_note}; consistency: {consistency_note}"),
            ));
            frame_start = frame_end;
        }

        let baseline = baseline_terminal
            .ok_or_else(|| anyhow::anyhow!("track {track_id} has no assessment frame"))?;
        let (default_verdict, default_note) = default_terminal
            .ok_or_else(|| anyhow::anyhow!("track {track_id} has no fused assessment"))?;
        let verbose = track_index < max_report_tracks;
        if verbose {
            let verdict = verdict_str(&baseline.verdict);
            let colored = match baseline.verdict {
                Verdict::Nominal => green(&verdict, color),
                Verdict::Spoof { .. } | Verdict::Jam | Verdict::Anomaly { .. } => {
                    red(&verdict, color)
                }
                Verdict::InsufficientEvidence => dim(&verdict, color),
            };
            println!(
                "│  baseline · track {track_id}: terminal {}  {}",
                colored,
                dim(&baseline_history.summary(), color)
            );
            println!("│             {}", dim(&baseline.note, color));

            let fused = fused_verdict_str(&default_verdict);
            let colored = match default_verdict {
                FusedVerdict::Nominal => green(&fused, color),
                FusedVerdict::InsufficientEvidence => dim(&fused, color),
                FusedVerdict::Spoof { .. } | FusedVerdict::Jam | FusedVerdict::Anomaly { .. } => {
                    red(&fused, color)
                }
            };
            println!(
                "│  default  · track {track_id}: terminal {}  {}",
                colored,
                dim(&default_history.summary(), color)
            );
            println!("│             {}", dim(&default_note, color));

            #[cfg(feature = "pid")]
            {
                use galadriel_pid::{assess_stream, PidConfig};
                match assess_stream(track_obs, &mods, &detector_cfg, &PidConfig::default()) {
                    Ok(report) => {
                        println!(
                            "│  PID      · track {track_id}: terminal-only fused {:?}  {}",
                            report.verdict,
                            dim(&report.note, color)
                        );
                        for axis in &report.pids {
                            println!(
                                "│             axis {} {:?}  {}",
                                axis.axis,
                                axis.report.verdict,
                                dim(&axis.report.note, color)
                            );
                        }
                    }
                    Err(error) => println!(
                        "│  PID      · track {track_id}: {}  {}",
                        dim("terminal-only INSUFFICIENT-EVIDENCE", color),
                        dim(&format!("estimator input rejected: {error}"), color)
                    ),
                }
            }
        }

        if !verbose {
            suppressed_baseline_alarm_tracks += usize::from(baseline_history.alarms.frames > 0);
            suppressed_default_alarm_tracks += usize::from(default_history.alarms.frames > 0);
            suppressed_baseline_insufficient_tracks +=
                usize::from(baseline_history.insufficient.frames > 0);
            suppressed_default_insufficient_tracks +=
                usize::from(default_history.insufficient.frames > 0);
            suppressed_default_issue_tracks += usize::from(default_history.has_consistency_issue());
            suppressed_baseline_history.merge(&baseline_history);
            suppressed_default_history.merge(&default_history);
        }
        track_index += 1;
        track_start = track_end;
    }

    if track_count > max_report_tracks {
        println!(
            "│  suppressed {} per-track report(s); among them, {} had baseline alarms and {} had default-fused alarms",
            track_count - max_report_tracks,
            suppressed_baseline_alarm_tracks,
            suppressed_default_alarm_tracks,
        );
        println!(
            "│    historical insufficiency affected {suppressed_baseline_insufficient_tracks} baseline track(s) and {suppressed_default_insufficient_tracks} default track(s); consistency input was rejected or missing on {suppressed_default_issue_tracks} track(s)",
        );
        println!(
            "│    baseline history across suppressed tracks: {}",
            dim(&suppressed_baseline_history.summary(), color)
        );
        println!(
            "│    default history across suppressed tracks: {}",
            dim(&suppressed_default_history.summary(), color)
        );
    }
    println!("└▷ replay complete");
    Ok(())
}

/// The `pid` feature demo: on a moment-matched stealthy spoof the magnitude
/// baseline is blind (NIS stays in-covariance) while the pairwise-MI engine is
/// evaluated on the same synthetic decoupling.
#[cfg(feature = "pid")]
fn run_pid_demo(frames: usize, seed: u64, color: bool) -> anyhow::Result<()> {
    use galadriel_pid::{assess_stream, PidConfig};
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
    )?;

    // Compare the KSG-MI escalation on every attested projection axis. Agreement
    // is an observed finite-sample result, not an equivalence guarantee.
    let report = assess_stream(
        &stream,
        &mods,
        &DetectorConfig::default(),
        &PidConfig::default(),
    )?;

    println!();
    println!(
        "{}",
        cyan(
            "┌─ …SAME STEALTHY SPOOF through the KSG-MI escalation (feature `pid`)",
            color
        )
    );
    for axis in &report.pids {
        for c in &axis.report.channels {
            let tag = if c.decoupled {
                red("● DECOUPLED", color)
            } else {
                green("● corroborates", color)
            };
            let mi = c
                .corroboration
                .map_or_else(|| "  —  ".to_string(), |v| format!("{v:>5.3}"));
            println!(
                "│  axis {} {:<15} KSG-MI corroboration={}  {}",
                axis.axis,
                c.modality.label(),
                mi,
                tag
            );
        }
    }
    let fused = fused_verdict_str(&report.verdict);
    let pv = match report.verdict {
        FusedVerdict::Nominal => green(&fused, color),
        FusedVerdict::InsufficientEvidence => dim(&fused, color),
        FusedVerdict::Spoof { .. } | FusedVerdict::Jam | FusedVerdict::Anomaly { .. } => {
            red(&fused, color)
        }
    };
    println!(
        "└▷ multi-axis fused PID: {}   {}   {}",
        pv,
        dim(&report.note, color),
        dim(
            "(synthetic linear-Gaussian comparison; PID atoms are diagnostic only)",
            color
        )
    );
    Ok(())
}

#[cfg(all(test, feature = "ncp"))]
mod replay_history_tests {
    use super::*;

    #[test]
    fn history_preserves_recovered_alarm_and_failure_ranges() {
        let mut history = ReplayHistory::default();

        history.observe(
            10,
            false,
            false,
            Some(ConsistencyFrameStatus::ExtractionError),
        );
        history.observe(
            11,
            true,
            false,
            Some(ConsistencyFrameStatus::Assessed {
                insufficient: false,
            }),
        );
        history.observe(
            12,
            false,
            false,
            Some(ConsistencyFrameStatus::Assessed {
                insufficient: false,
            }),
        );

        assert_eq!(history.alarms.frames, 1);
        assert_eq!(history.alarms.first_seq, Some(11));
        assert_eq!(history.alarms.last_seq, Some(11));
        assert_eq!(history.insufficient.frames, 1);
        assert_eq!(history.insufficient.first_seq, Some(10));
        assert_eq!(history.insufficient.last_seq, Some(10));
        assert_eq!(history.extraction_errors.frames, 1);
        assert!(history
            .summary()
            .contains("projection-extraction-error 1 frame(s), first seq 10, last seq 10"));
    }

    #[test]
    fn history_distinguishes_every_consistency_failure_cause() {
        let mut history = ReplayHistory::default();
        for (seq, status) in [
            (1, ConsistencyFrameStatus::TooFewModalities),
            (2, ConsistencyFrameStatus::MissingProjection),
            (3, ConsistencyFrameStatus::ExtractionError),
            (4, ConsistencyFrameStatus::AnalysisError),
            (5, ConsistencyFrameStatus::Assessed { insufficient: true }),
        ] {
            history.observe(seq, false, false, Some(status));
        }

        assert_eq!(history.insufficient.frames, 5);
        assert_eq!(history.insufficient.first_seq, Some(1));
        assert_eq!(history.insufficient.last_seq, Some(5));
        assert_eq!(history.too_few_modalities.frames, 1);
        assert_eq!(history.missing_projection.frames, 1);
        assert_eq!(history.extraction_errors.frames, 1);
        assert_eq!(history.analysis_errors.frames, 1);
        assert!(history.has_consistency_issue());
    }

    #[test]
    fn merged_suppressed_history_retains_counts_and_outer_sequence_range() {
        let mut first = ReplayHistory::default();
        first.observe(
            20,
            true,
            false,
            Some(ConsistencyFrameStatus::MissingProjection),
        );
        let mut second = ReplayHistory::default();
        second.observe(7, true, true, Some(ConsistencyFrameStatus::AnalysisError));

        let mut merged = ReplayHistory::default();
        merged.merge(&first);
        merged.merge(&second);

        assert_eq!(merged.alarms.frames, 2);
        assert_eq!(merged.alarms.first_seq, Some(7));
        assert_eq!(merged.alarms.last_seq, Some(20));
        assert_eq!(merged.insufficient.frames, 2);
        assert!(merged
            .summary()
            .contains("alarm 2 frame(s), first seq 7, last seq 20"));
    }
}
