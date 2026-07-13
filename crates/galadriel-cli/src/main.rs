#![forbid(unsafe_code)]
//! `galadriel` — demo, replay, and secure observer for Galadriel's Mirror.
//!
//! `galadriel demo` runs four synthetic scenarios — clean, a targeted acoustic spoof, a
//! broadband jam, and a moment-matched stealthy spoof — through the pure default detector
//! (NIS χ² magnitude ⊕ signed `ρ` cross-sensor consistency) and prints the per-channel traces
//! and the fused verdict for each. With `--features pid` it adds the KSG-MI escalation view.
//! `galadriel observe` (feature `ncp-live`) runs the bounded, fail-stop two-route receiver.

use std::collections::HashMap;
#[cfg(feature = "ncp")]
use std::collections::VecDeque;
use std::io::IsTerminal;
#[cfg(feature = "ncp-live")]
use std::path::PathBuf;

#[cfg(feature = "ncp-live")]
use anyhow::Context as _;
use clap::{Parser, Subcommand};
use galadriel_core::{
    DetectorConfig, FusedVerdict, MagnitudeEvidence, Mirror, Modality, PidObservation, Verdict,
};
use galadriel_sim::injection::{inject, BroadbandJam, PhantomAcousticDoa};
use galadriel_sim::scenario::{generate, ScenarioConfig};
#[cfg(feature = "ncp-live")]
use std::io::Read as _;

const MIN_DEMO_FRAMES: usize = 128;
const MAX_DEMO_FRAMES: usize = 10_000;
#[cfg(all(feature = "ncp", feature = "pid"))]
const MAX_REPLAY_PID_TRACKS: usize = 8;

#[derive(Parser)]
#[command(
    name = "galadriel",
    version,
    about = "Galadriel's Mirror — a cross-sensor statistical-consistency monitor (pure default: NIS χ² ⊕ signed-ρ consistency)."
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
        /// Maximum tracks receiving the expensive terminal PID analysis (0 disables it).
        #[cfg(feature = "pid")]
        #[arg(long, default_value_t = 4)]
        max_pid_tracks: usize,
    },
    /// Observe one exact producer epoch over the secure two-route Zenoh profile.
    #[cfg(feature = "ncp-live")]
    Observe {
        /// Exact NCP realm configured in the secure Zenoh profile.
        #[arg(long)]
        realm: String,
        /// Deployment-supplied, never-reused producer process epoch.
        #[arg(long)]
        epoch: String,
        /// Producer identity required inside both strict envelopes.
        #[arg(long)]
        producer_id: String,
        /// Deployment registry JSON shared with the producer.
        #[arg(long)]
        registry: PathBuf,
        /// Externally pinned lowercase SHA-256 of canonical registry JSON.
        #[arg(long)]
        registry_sha256: String,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Demo { frames, seed } => run_demo(frames, seed)?,
        #[cfg(feature = "ncp")]
        Cmd::Replay {
            path,
            max_report_tracks,
            #[cfg(feature = "pid")]
            max_pid_tracks,
        } => {
            #[cfg(feature = "pid")]
            run_replay(&path, max_report_tracks, max_pid_tracks)?;
            #[cfg(not(feature = "pid"))]
            run_replay(&path, max_report_tracks)?;
        }
        #[cfg(feature = "ncp-live")]
        Cmd::Observe {
            realm,
            epoch,
            producer_id,
            registry,
            registry_sha256,
        } => run_observe(&realm, &epoch, &producer_id, &registry, &registry_sha256)?,
    }
    Ok(())
}

#[cfg(feature = "ncp-live")]
fn run_observe(
    realm: &str,
    epoch: &str,
    producer_id: &str,
    registry_path: &std::path::Path,
    registry_sha256: &str,
) -> anyhow::Result<()> {
    // Read through the registry's wire ceiling instead of allocating according
    // to an untrusted file length before the strict parser can enforce it.
    let registry_file = std::fs::File::open(registry_path)
        .with_context(|| format!("cannot open registry {}", registry_path.display()))?;
    let mut registry_bytes = Vec::with_capacity(galadriel_ncp::registry::MAX_REGISTRY_BYTES + 1);
    registry_file
        .take((galadriel_ncp::registry::MAX_REGISTRY_BYTES as u64) + 1)
        .read_to_end(&mut registry_bytes)
        .with_context(|| format!("cannot read registry {}", registry_path.display()))?;
    let registry = galadriel_ncp::registry::DeploymentRegistry::from_json_pinned(
        &registry_bytes,
        registry_sha256,
    )
    .context("deployment registry or external digest pin is invalid")?;
    let keys = galadriel_ncp::ncp_core::Keys::try_new(realm)
        .map_err(|error| anyhow::anyhow!("invalid NCP realm {realm:?}: {error}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the live receiver runtime")?;

    runtime.block_on(observe_epoch(keys, epoch, producer_id, registry))
}

#[cfg(feature = "ncp-live")]
async fn observe_epoch(
    keys: galadriel_ncp::ncp_core::Keys,
    epoch: &str,
    producer_id: &str,
    registry: galadriel_ncp::registry::DeploymentRegistry,
) -> anyhow::Result<()> {
    use galadriel_ncp::assembler::{AssemblerLimits, AssemblyEvent};
    use galadriel_ncp::lifecycle::{LifecycleAssessment, LifecycleDetector};
    use galadriel_ncp::operational_live::OperationalLiveReceiver;

    // Validate the immutable statistical policy before acquiring transport
    // resources. A configuration failure must not leave a live subscription
    // waiting for drop-based cleanup.
    let mut detector = LifecycleDetector::new(DetectorConfig::default(), Default::default())
        .context("default lifecycle detector policy is invalid")?;
    let mut receiver = OperationalLiveReceiver::open_secure(
        keys,
        epoch,
        producer_id,
        registry,
        AssemblerLimits::default(),
    )
    .await
    .context("cannot open the strict two-route receiver; verify NCP_ZENOH_CONFIG")?;
    let mut interrupt = std::pin::pin!(tokio::signal::ctrl_c());

    eprintln!(
        "observing realm={} epoch={} producer={} · advisory evidence · calibrated_posterior=false",
        receiver.realm(),
        receiver.session_id(),
        receiver.producer_id()
    );

    let loop_result = 'events: loop {
        let event = tokio::select! {
            biased;
            signal = &mut interrupt => {
                match signal {
                    Ok(()) => break Ok(()),
                    Err(error) => break Err(anyhow::Error::new(error).context("Ctrl-C listener failed")),
                }
            }
            result = receiver.recv() => result.map_err(anyhow::Error::new),
        };
        let event = match event {
            Ok(event) => event,
            Err(error) => break Err(error.context("operational receiver terminated")),
        };

        match event {
            AssemblyEvent::FrameReady(frame) => {
                let assessments = match detector.assess_frame(&frame) {
                    Ok(assessments) => assessments,
                    Err(error) => {
                        break 'events Err(anyhow::Error::new(error)
                            .context("lifecycle-complete frame violated detector invariants"));
                    }
                };
                for assessment in assessments {
                    match assessment {
                        LifecycleAssessment::Evaluated {
                            track_id,
                            fusion_seq,
                            history_reset,
                            report,
                        } => println!(
                            "frame={fusion_seq} track={track_id} history_reset={history_reset} evidence={:?} calibrated_posterior=false",
                            report.verdict
                        ),
                        LifecycleAssessment::Abstained {
                            track_id,
                            fusion_seq,
                            unavailable_modalities,
                        } => println!(
                            "frame={fusion_seq} track={track_id} evidence=InsufficientEvidence lifecycle_complete=true assessable=false unavailable={unavailable_modalities:?} calibrated_posterior=false"
                        ),
                        _ => {}
                    }
                }
            }
            AssemblyEvent::HeartbeatAccepted { event_seq, .. } => {
                let assembler = receiver.assembler();
                let limits = assembler.limits();
                eprintln!(
                    "heartbeat event_seq={event_seq} prior_identities={}/{} observation_streams={}/{} open_frames={}/{} buffered_bytes={}/{}",
                    assembler.prior_identities(),
                    limits.max_prior_identities,
                    assembler.observation_streams(),
                    limits.max_observation_streams,
                    assembler.open_frames(),
                    limits.max_open_frames,
                    assembler.buffered_bytes(),
                    limits.max_buffered_bytes,
                );
            }
            AssemblyEvent::ContractHashMismatch { route } => {
                eprintln!("advisory contract-hash mismatch on {route:?} route");
            }
            AssemblyEvent::Fault(fault) => {
                break 'events Err(anyhow::anyhow!(
                    "operational receiver unexpectedly returned assembly fault: {fault:?}"
                ));
            }
            _ => {}
        }
    };

    // Always tear down both exact selectors. On Ctrl-C, a fault that won the
    // callback race but not the select race remains visible in health and must
    // not be converted into a successful exit.
    let close_result = receiver
        .close()
        .await
        .context("receiver stopped but exact subscription cleanup failed");
    let health = receiver.health().snapshot();
    let assembler = receiver.assembler();
    let limits = assembler.limits();
    eprintln!(
        "receiver stopped: frames={} heartbeats={} processed={} rejected={} post_fault={} terminal_faults={} queued_discarded={} events_staged={} events_delivered={} events_discarded={} ingress_queue={}/{} open_frames={}/{} buffered_bytes={}/{} pending_monitor={}/{} prior_identities={}/{} observation_streams={}/{} next_event_seq={} last_heartbeat_receipt={:?}",
        health.frames_delivered,
        health.heartbeats_delivered,
        health.payloads_processed,
        health.payloads_rejected,
        health.post_fault_payloads,
        health.terminal_faults,
        health.queued_payloads_discarded,
        health.assembly_events_staged,
        health.assembly_events_delivered,
        health.assembly_events_discarded,
        health.ingress_queue_depth,
        health.ingress_capacity,
        assembler.open_frames(),
        limits.max_open_frames,
        assembler.buffered_bytes(),
        limits.max_buffered_bytes,
        assembler.pending_monitor_events(),
        limits.max_reorder_events,
        assembler.prior_identities(),
        limits.max_prior_identities,
        assembler.observation_streams(),
        limits.max_observation_streams,
        assembler.next_expected_monitor_event_seq(),
        assembler.last_heartbeat_receipt(),
    );
    let loop_result = match (loop_result, health.first_fault) {
        (Ok(()), Some(fault)) => Err(anyhow::Error::new(fault)
            .context("operational receiver faulted concurrently with shutdown")),
        (result, _) => result,
    };
    loop_result?;
    close_result?;
    Ok(())
}

#[cfg(all(test, feature = "ncp-live"))]
mod observe_cli_tests {
    use super::*;

    #[test]
    fn observe_requires_every_epoch_and_registry_pin() {
        let result = Cli::try_parse_from([
            "galadriel",
            "observe",
            "--realm",
            "engram/ncp",
            "--epoch",
            "epoch-1",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn observe_parses_explicit_secure_handoff() {
        let cli = Cli::try_parse_from([
            "galadriel",
            "observe",
            "--realm",
            "engram/ncp",
            "--epoch",
            "epoch-1",
            "--producer-id",
            "crebain",
            "--registry",
            "registry.json",
            "--registry-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .expect("complete observe handoff parses");

        let Cmd::Observe {
            realm,
            epoch,
            producer_id,
            registry,
            registry_sha256,
        } = cli.cmd
        else {
            panic!("observe command must select the live variant")
        };
        assert_eq!(realm, "engram/ncp");
        assert_eq!(epoch, "epoch-1");
        assert_eq!(producer_id, "crebain");
        assert_eq!(registry, PathBuf::from("registry.json"));
        assert_eq!(registry_sha256.len(), 64);
    }
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

    // The magnitude baseline is blind to this synthetic stealthy-spoof scenario;
    // the pure correlation default flags its modeled decoupling (no pid-core).
    // This scene needs correlated honest channels.
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
        stream.len().is_multiple_of(mods.len()),
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
        Verdict::AttributedInconsistency { .. }
        | Verdict::BroadDegradation
        | Verdict::UnclassifiedAnomaly { .. } => red(&v, color),
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
        Verdict::AttributedInconsistency { channels } => format!(
            "VERDICT: ATTRIBUTED-INCONSISTENCY (spoof-like evidence; cause unclassified) [{}]",
            channels
                .iter()
                .map(|m| m.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Verdict::BroadDegradation => {
            "VERDICT: BROAD-DEGRADATION (jam-like evidence; cause unclassified)".into()
        }
        Verdict::UnclassifiedAnomaly { channels } => format!(
            "VERDICT: UNCLASSIFIED-ANOMALY [{}]",
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
        FusedVerdict::AttributedInconsistency {
            channels,
            magnitude,
        } => format!(
            "VERDICT: ATTRIBUTED-INCONSISTENCY (spoof-like evidence; cause unclassified; {}) [{}]",
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
        FusedVerdict::BroadDegradation => {
            "VERDICT: BROAD-DEGRADATION (jam-like evidence; cause unclassified)".into()
        }
        FusedVerdict::UnclassifiedAnomaly { channels } => format!(
            "VERDICT: UNCLASSIFIED-ANOMALY [{}]",
            channels
                .iter()
                .map(|modality| modality.label())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        FusedVerdict::InsufficientEvidence => "VERDICT: INSUFFICIENT-EVIDENCE".into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelEvidenceLabel {
    Decoupled,
    Corroborates,
    Insufficient,
}

fn channel_evidence_label(
    decoupled: bool,
    assessable: bool,
    axis_insufficient: bool,
) -> ChannelEvidenceLabel {
    if axis_insufficient || !assessable {
        ChannelEvidenceLabel::Insufficient
    } else if decoupled {
        ChannelEvidenceLabel::Decoupled
    } else {
        ChannelEvidenceLabel::Corroborates
    }
}

fn channel_evidence_tag(label: ChannelEvidenceLabel, color: bool) -> String {
    match label {
        ChannelEvidenceLabel::Decoupled => red("● DECOUPLED", color),
        ChannelEvidenceLabel::Corroborates => green("● corroborates", color),
        ChannelEvidenceLabel::Insufficient => dim("● INSUFFICIENT", color),
    }
}

#[cfg(feature = "pid")]
fn pid_channel_is_assessable(gate_ok: bool, corroboration: Option<f64>) -> bool {
    gate_ok && corroboration.is_some()
}

#[cfg(test)]
mod verdict_label_tests {
    use super::*;

    #[test]
    fn baseline_labels_use_neutral_verdict_names() {
        let attributed = verdict_str(&Verdict::AttributedInconsistency {
            channels: vec![Modality::Radar],
        });
        assert!(attributed.contains("ATTRIBUTED-INCONSISTENCY"));
        assert!(attributed.contains("spoof-like evidence; cause unclassified"));
        assert!(!attributed.contains("VERDICT: SPOOF"));

        let broad = verdict_str(&Verdict::BroadDegradation);
        assert!(broad.contains("BROAD-DEGRADATION"));
        assert!(broad.contains("jam-like evidence; cause unclassified"));
        assert!(!broad.contains("VERDICT: JAM"));
    }

    #[test]
    fn fused_labels_use_neutral_verdict_names() {
        let attributed = fused_verdict_str(&FusedVerdict::AttributedInconsistency {
            channels: vec![Modality::Acoustic],
            magnitude: MagnitudeEvidence::InCovariance,
        });
        assert!(attributed.contains("ATTRIBUTED-INCONSISTENCY"));
        assert!(attributed.contains("spoof-like evidence; cause unclassified"));
        assert!(!attributed.contains("VERDICT: SPOOF"));

        let broad = fused_verdict_str(&FusedVerdict::BroadDegradation);
        assert!(broad.contains("BROAD-DEGRADATION"));
        assert!(broad.contains("jam-like evidence; cause unclassified"));
        assert!(!broad.contains("VERDICT: JAM"));
    }

    #[test]
    fn insufficient_axis_never_renders_a_channel_as_corroborating() {
        assert_eq!(
            channel_evidence_label(false, true, true,),
            ChannelEvidenceLabel::Insufficient
        );
        assert_eq!(
            channel_evidence_label(false, false, false,),
            ChannelEvidenceLabel::Insufficient
        );
    }

    #[test]
    fn decoupled_channel_tag_has_the_expected_plain_text() {
        assert_eq!(
            channel_evidence_tag(ChannelEvidenceLabel::Decoupled, false),
            "● DECOUPLED"
        );
    }

    #[test]
    fn corroborating_channel_tag_has_the_expected_plain_text() {
        assert_eq!(
            channel_evidence_tag(ChannelEvidenceLabel::Corroborates, false),
            "● corroborates"
        );
    }

    #[test]
    fn insufficient_channel_tag_has_the_expected_plain_text() {
        assert_eq!(
            channel_evidence_tag(ChannelEvidenceLabel::Insufficient, false),
            "● INSUFFICIENT"
        );
    }

    #[cfg(feature = "pid")]
    #[test]
    fn pid_channel_with_a_failed_gate_is_not_assessable() {
        assert!(!pid_channel_is_assessable(false, Some(0.5)));
    }

    #[cfg(feature = "pid")]
    #[test]
    fn pid_channel_with_a_passing_gate_and_score_is_assessable() {
        assert!(pid_channel_is_assessable(true, Some(0.5)));
    }
}

#[cfg(test)]
mod demo_output_tests {
    use std::process::Command;

    use super::*;

    const CHILD_DEMO_ENV: &str = "GALADRIEL_CLI_CHILD_DEMO";
    const FAST_DEMO_FRAMES: usize = 8;

    fn child_test_stdout(test_name: &str, child_demo: &str) -> String {
        let output = Command::new(std::env::current_exe().expect("test executable path is known"))
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_DEMO_ENV, child_demo)
            .output()
            .expect("child test process starts");
        assert!(
            output.status.success(),
            "child test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("test output is UTF-8")
    }

    #[test]
    fn stealthy_default_demo_emits_its_semantic_heading() {
        let stdout = child_test_stdout(
            "demo_output_tests::stealthy_default_demo_child",
            "stealthy-default",
        );

        assert!(stdout.contains("SYNTHETIC MOMENT-MATCHED SPOOF"));
    }

    #[test]
    fn stealthy_default_demo_child() {
        if std::env::var(CHILD_DEMO_ENV).as_deref() != Ok("stealthy-default") {
            return;
        }

        run_stealthy_default_demo(FAST_DEMO_FRAMES, 7, false)
            .expect("fixed-seed default demo succeeds");
    }

    #[cfg(feature = "pid")]
    #[test]
    fn pid_demo_emits_its_semantic_heading() {
        let stdout = child_test_stdout("demo_output_tests::pid_demo_child", "pid");

        assert!(stdout.contains("KSG-MI escalation"));
    }

    #[cfg(feature = "pid")]
    #[test]
    fn pid_demo_child() {
        if std::env::var(CHILD_DEMO_ENV).as_deref() != Ok("pid") {
            return;
        }

        run_pid_demo(FAST_DEMO_FRAMES, 7, false).expect("fixed-seed PID demo succeeds");
    }
}

/// The pure stealthy-spoof scene: on a moment-matched spoof the magnitude baseline is
/// blind (NIS stays in-covariance) while the cheap correlation default can flag
/// the modeled decoupling. This synthetic scene needs correlated honest channels
/// (`ρ = 0.7`) and is not field-performance evidence.
fn run_stealthy_default_demo(frames: usize, seed: u64, color: bool) -> anyhow::Result<()> {
    use galadriel_core::{assess_default, CorrConfig, CorrVerdict};
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
        let axis_insufficient = matches!(axis.report.verdict, CorrVerdict::InsufficientEvidence);
        for c in &axis.report.channels {
            let tag = channel_evidence_tag(
                channel_evidence_label(c.decoupled, c.corroboration.is_some(), axis_insufficient),
                color,
            );
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
        Verdict::AttributedInconsistency { .. }
            | Verdict::BroadDegradation
            | Verdict::UnclassifiedAnomaly { .. }
    )
}

#[cfg(feature = "ncp")]
fn fused_alarm(verdict: &FusedVerdict) -> bool {
    matches!(
        verdict,
        FusedVerdict::AttributedInconsistency { .. }
            | FusedVerdict::BroadDegradation
            | FusedVerdict::UnclassifiedAnomaly { .. }
    )
}

#[cfg(feature = "ncp")]
fn replay_track_is_verbose(track_index: usize, max_report_tracks: usize) -> bool {
    track_index < max_report_tracks
}

#[cfg(all(feature = "ncp", feature = "pid"))]
fn replay_track_uses_pid(track_index: usize, max_pid_tracks: usize) -> bool {
    track_index < max_pid_tracks
}

/// Replay a JSONL capture of `PidObservation`s through the baseline (and the PID
/// engine when built with `--features pid,ncp`).
#[cfg(feature = "ncp")]
fn run_replay(
    path: &str,
    max_report_tracks: usize,
    #[cfg(feature = "pid")] max_pid_tracks: usize,
) -> anyhow::Result<()> {
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
    #[cfg(feature = "pid")]
    anyhow::ensure!(
        max_pid_tracks <= MAX_REPLAY_PID_TRACKS,
        "max-pid-tracks must be in 0..={MAX_REPLAY_PID_TRACKS}"
    );
    let mut obs = galadriel_ncp::read_jsonl(path)?;
    if obs.is_empty() {
        anyhow::bail!("no observations parsed from {path:?}");
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
                "┌─ REPLAY {path:?} — {} obs, {} track(s)",
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
    #[cfg(feature = "pid")]
    let mut pid_tracks_analyzed = 0usize;
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
        let verbose = replay_track_is_verbose(track_index, max_report_tracks);
        if verbose {
            let verdict = verdict_str(&baseline.verdict);
            let colored = match baseline.verdict {
                Verdict::Nominal => green(&verdict, color),
                Verdict::AttributedInconsistency { .. }
                | Verdict::BroadDegradation
                | Verdict::UnclassifiedAnomaly { .. } => red(&verdict, color),
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
                FusedVerdict::AttributedInconsistency { .. }
                | FusedVerdict::BroadDegradation
                | FusedVerdict::UnclassifiedAnomaly { .. } => red(&fused, color),
            };
            println!(
                "│  default  · track {track_id}: terminal {}  {}",
                colored,
                dim(&default_history.summary(), color)
            );
            println!("│             {}", dim(&default_note, color));
        }

        #[cfg(feature = "pid")]
        if replay_track_uses_pid(track_index, max_pid_tracks) {
            use galadriel_pid::{assess_stream, PidConfig};

            pid_tracks_analyzed += 1;
            let report = assess_stream(track_obs, &mods, &detector_cfg, &PidConfig::default());
            if verbose {
                match report {
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
    #[cfg(feature = "pid")]
    if track_count > pid_tracks_analyzed {
        println!(
            "│  PID terminal analysis skipped for {} track(s); bounded by --max-pid-tracks={max_pid_tracks}",
            track_count - pid_tracks_analyzed
        );
    }
    println!(
        "│  {}",
        dim(
            "advisory only · calibrated_posterior=false · consistency evidence, not truth or an enforcement command",
            color
        )
    );
    println!("└▷ replay complete");
    Ok(())
}

/// The `pid` feature demo: on a moment-matched stealthy spoof the magnitude
/// baseline is blind (NIS stays in-covariance) while the pairwise-MI engine is
/// evaluated on the same synthetic decoupling.
#[cfg(feature = "pid")]
fn run_pid_demo(frames: usize, seed: u64, color: bool) -> anyhow::Result<()> {
    use galadriel_pid::{assess_stream, PidConfig, PidVerdict};
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
        let axis_insufficient = matches!(axis.report.verdict, PidVerdict::InsufficientEvidence);
        for c in &axis.report.channels {
            let tag = channel_evidence_tag(
                channel_evidence_label(
                    c.decoupled,
                    pid_channel_is_assessable(c.gate_ok, c.corroboration),
                    axis_insufficient,
                ),
                color,
            );
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
        FusedVerdict::AttributedInconsistency { .. }
        | FusedVerdict::BroadDegradation
        | FusedVerdict::UnclassifiedAnomaly { .. } => red(&fused, color),
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

    #[cfg(feature = "pid")]
    #[test]
    fn pid_selection_is_independent_of_report_visibility() {
        assert_eq!(
            (replay_track_is_verbose(1, 1), replay_track_uses_pid(1, 4)),
            (false, true)
        );
    }

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
