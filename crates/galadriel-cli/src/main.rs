#![forbid(unsafe_code)]
//! `galadriel` — demo, replay, and secure observer for Galadriel's Mirror.
//!
//! `galadriel demo` runs four synthetic scenarios — clean, a targeted acoustic spoof, a
//! broadband jam, and a moment-matched stealthy spoof — through the pure default detector
//! (NIS χ² magnitude ⊕ signed `ρ` cross-sensor consistency) and prints the per-channel traces
//! and the fused verdict for each. With `--features pid` it adds the KSG-MI escalation view.
//! `galadriel observe` (feature `ncp-live`) runs the bounded, fail-stop two-route receiver.

use std::collections::HashMap;
use std::io::IsTerminal;
#[cfg(feature = "ncp-live")]
use std::path::PathBuf;
#[cfg(feature = "ncp")]
use std::{num::NonZeroUsize, ops::Range};

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

fn attack_start_frame(frames: usize, divisor: usize) -> u64 {
    debug_assert!(divisor > 0, "attack start divisor must be nonzero");
    u64::try_from(frames / divisor).expect("supported frame counts fit in u64")
}

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
    let registry = load_deployment_registry(registry_path, registry_sha256)?;
    let keys = galadriel_ncp::ncp_core::Keys::try_new(realm)
        .map_err(|error| anyhow::anyhow!("invalid NCP realm {realm:?}: {error}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the live receiver runtime")?;

    runtime.block_on(observe_epoch(keys, epoch, producer_id, registry))
}

#[cfg(feature = "ncp-live")]
fn load_deployment_registry(
    registry_path: &std::path::Path,
    registry_sha256: &str,
) -> anyhow::Result<galadriel_ncp::registry::DeploymentRegistry> {
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
    Ok(registry)
}

#[cfg(feature = "ncp-live")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObserveTelemetry {
    prior_identities: usize,
    max_prior_identities: usize,
    observation_streams: usize,
    max_observation_streams: usize,
    open_frames: usize,
    max_open_frames: usize,
    buffered_bytes: usize,
    max_buffered_bytes: usize,
}

#[cfg(feature = "ncp-live")]
impl ObserveTelemetry {
    fn from_assembler<R: galadriel_ncp::assembler::RegistryVerifier>(
        assembler: &galadriel_ncp::assembler::CrossRouteAssembler<R>,
    ) -> Self {
        let limits = assembler.limits();
        Self {
            prior_identities: assembler.prior_identities(),
            max_prior_identities: limits.max_prior_identities,
            observation_streams: assembler.observation_streams(),
            max_observation_streams: limits.max_observation_streams,
            open_frames: assembler.open_frames(),
            max_open_frames: limits.max_open_frames,
            buffered_bytes: assembler.buffered_bytes(),
            max_buffered_bytes: limits.max_buffered_bytes,
        }
    }
}

#[cfg(feature = "ncp-live")]
#[derive(Debug, Default, PartialEq, Eq)]
struct ObserveOutput {
    stdout: Vec<String>,
    stderr: Vec<String>,
}

#[cfg(feature = "ncp-live")]
fn render_lifecycle_assessment(
    assessment: galadriel_ncp::lifecycle::LifecycleAssessment,
) -> anyhow::Result<String> {
    use galadriel_ncp::lifecycle::LifecycleAssessment;

    match assessment {
        LifecycleAssessment::Evaluated {
            track_id,
            fusion_seq,
            history_reset,
            report,
        } => Ok(format!(
            "frame={fusion_seq} track={track_id} history_reset={history_reset} evidence={:?} calibrated_posterior=false",
            report.verdict
        )),
        LifecycleAssessment::Abstained {
            track_id,
            fusion_seq,
            unavailable_modalities,
        } => Ok(format!(
            "frame={fusion_seq} track={track_id} evidence=InsufficientEvidence lifecycle_complete=true assessable=false unavailable={unavailable_modalities:?} calibrated_posterior=false"
        )),
        other => Err(anyhow::anyhow!(
            "unsupported lifecycle assessment variant: {other:?}"
        )),
    }
}

#[cfg(feature = "ncp-live")]
fn handle_observe_event(
    event: galadriel_ncp::assembler::AssemblyEvent,
    detector: &mut galadriel_ncp::lifecycle::LifecycleDetector,
    telemetry: ObserveTelemetry,
) -> anyhow::Result<ObserveOutput> {
    use galadriel_ncp::assembler::AssemblyEvent;

    let mut output = ObserveOutput::default();
    match event {
        AssemblyEvent::FrameReady(frame) => {
            let assessments = detector.assess_frame(&frame).map_err(|error| {
                anyhow::Error::new(error)
                    .context("lifecycle-complete frame violated detector invariants")
            })?;
            for assessment in assessments {
                output.stdout.push(render_lifecycle_assessment(assessment)?);
            }
        }
        AssemblyEvent::HeartbeatAccepted { event_seq, .. } => {
            output.stderr.push(format!(
                "heartbeat event_seq={event_seq} prior_identities={}/{} observation_streams={}/{} open_frames={}/{} buffered_bytes={}/{}",
                telemetry.prior_identities,
                telemetry.max_prior_identities,
                telemetry.observation_streams,
                telemetry.max_observation_streams,
                telemetry.open_frames,
                telemetry.max_open_frames,
                telemetry.buffered_bytes,
                telemetry.max_buffered_bytes,
            ));
        }
        AssemblyEvent::ContractHashMismatch { route } => {
            output.stderr.push(format!(
                "advisory contract-hash mismatch on {route:?} route"
            ));
        }
        AssemblyEvent::Fault(fault) => {
            return Err(anyhow::anyhow!(
                "operational receiver unexpectedly returned assembly fault: {fault:?}"
            ));
        }
        other => {
            return Err(anyhow::anyhow!(
                "unsupported assembly event variant: {other:?}"
            ));
        }
    }
    Ok(output)
}

#[cfg(feature = "ncp-live")]
async fn observe_epoch(
    keys: galadriel_ncp::ncp_core::Keys,
    epoch: &str,
    producer_id: &str,
    registry: galadriel_ncp::registry::DeploymentRegistry,
) -> anyhow::Result<()> {
    use galadriel_ncp::assembler::AssemblerLimits;
    use galadriel_ncp::lifecycle::LifecycleDetector;
    use galadriel_ncp::operational_live::OperationalLiveReceiver;

    // Validate the immutable statistical policy before acquiring transport
    // resources. A configuration failure must not leave a live subscription
    // waiting for drop-based cleanup.
    let detector_config = DetectorConfig::standalone_advisory_v0_9()
        .context("standalone-advisory lifecycle detector policy is invalid")?;
    let mut detector = LifecycleDetector::new(detector_config, Default::default())
        .context("standalone-advisory lifecycle detector policy is invalid")?;
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

        let telemetry = ObserveTelemetry::from_assembler(receiver.assembler());
        let output = match handle_observe_event(event, &mut detector, telemetry) {
            Ok(output) => output,
            Err(error) => break 'events Err(error),
        };
        for line in output.stdout {
            println!("{line}");
        }
        for line in output.stderr {
            eprintln!("{line}");
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
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use galadriel_core::ConsistencyProjection;
    use galadriel_ncp::assembler::{
        AssemblerLimits, AssemblyEvent, AssemblyFault, AssemblyFaultKind, CrossRouteAssembler,
        EvidenceRoute, FrameIdentity, RegistryOpportunityPolicy, RegistryVerifier,
        RegistryViolation,
    };
    use galadriel_ncp::lifecycle::{LifecycleAssessment, LifecycleDetector};
    use galadriel_ncp::monitor::{
        FrameSummary, GateEvidence, GateMethod, ModalityOutcome, ModalityOutcomeKind,
        MonitorEnvelope, ProducerEvent,
    };
    use galadriel_ncp::SidecarEnvelope;

    const TEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Clone, Copy)]
    struct TestRegistry;

    impl RegistryVerifier for TestRegistry {
        fn opportunity_policy(&self) -> Result<RegistryOpportunityPolicy, RegistryViolation> {
            Ok(RegistryOpportunityPolicy {
                max_active_tracks: 32,
                max_frame_inputs: 128,
                max_attempts_per_track_modality: 128,
                max_outcomes_per_frame: 128,
                max_monitor_queue_events: 128,
            })
        }

        fn verify_summary(
            &self,
            _identity: FrameIdentity,
            registry_digest: &str,
            expected_modalities: &[Modality],
        ) -> Result<(), RegistryViolation> {
            if registry_digest == TEST_DIGEST
                && expected_modalities == [Modality::Visual, Modality::Radar]
            {
                Ok(())
            } else {
                Err(RegistryViolation::UnexpectedModalities)
            }
        }

        fn verify_projection(
            &self,
            _identity: FrameIdentity,
            _modality: Modality,
            _projection: &ConsistencyProjection,
        ) -> Result<(), RegistryViolation> {
            Ok(())
        }
    }

    #[test]
    fn test_registry_rejects_each_independent_summary_mismatch() {
        let identity = FrameIdentity {
            fusion_seq: 1,
            fusion_timestamp_ms: 1_001,
            frame_id: 10,
            context_id: 20,
            prior_id: 101,
        };
        let expected = [Modality::Visual, Modality::Radar];

        assert!(TestRegistry
            .verify_summary(identity, TEST_DIGEST, &expected)
            .is_ok());
        assert!(matches!(
            TestRegistry.verify_summary(identity, &"b".repeat(64), &expected),
            Err(RegistryViolation::UnexpectedModalities)
        ));
        assert!(matches!(
            TestRegistry.verify_summary(
                identity,
                TEST_DIGEST,
                &[Modality::Visual, Modality::Acoustic]
            ),
            Err(RegistryViolation::UnexpectedModalities)
        ));
    }

    fn projection(prior_id: u64) -> ConsistencyProjection {
        ConsistencyProjection::try_new_raw([1.0, 2.0, 3.0], 3, 10, 20, prior_id)
            .expect("test projection provenance is valid")
    }

    fn observation(modality: Modality) -> PidObservation {
        PidObservation::try_scalar_raw(7, 1_001, 1, modality, 1.0, 3)
            .expect("test observation coordinates are valid")
            .with_consistency_projection(projection(101))
    }

    fn outcome(modality: Modality, measurement_index: u32) -> ModalityOutcome {
        ModalityOutcome {
            fusion_seq: 1,
            fusion_timestamp_ms: 1_001,
            frame_id: 10,
            context_id: 20,
            prior_id: 101,
            track_id: 7,
            modality,
            attempt_index: 0,
            measurement_index: Some(measurement_index),
            outcome: ModalityOutcomeKind::Updated,
            v1_expected: true,
            candidate_count: 1,
            in_gate_count: 1,
            gate_evidence: Some(GateEvidence {
                method: GateMethod::Mahalanobis,
                d2: 1.0,
                threshold: 7.815,
            }),
            consistency_projection: Some(projection(101)),
        }
    }

    fn assembled_frame_event() -> AssemblyEvent {
        let now = Instant::now();
        let mut assembler = CrossRouteAssembler::new(
            "epoch-1",
            "crebain",
            TestRegistry,
            AssemblerLimits::default(),
            now,
        )
        .expect("CLI handler fixture assembler is valid");
        for modality in [Modality::Visual, Modality::Radar] {
            let envelope = SidecarEnvelope::try_new("epoch-1", "crebain", observation(modality))
                .expect("CLI handler fixture observation is valid");
            assert!(assembler
                .ingest_observation_envelope(envelope, now)
                .is_empty());
        }
        for (event_seq, (modality, measurement_index)) in
            [(1, (Modality::Visual, 0)), (2, (Modality::Radar, 1))]
        {
            let envelope = MonitorEnvelope::try_new(
                "epoch-1",
                "crebain",
                event_seq,
                ProducerEvent::ModalityOutcome(outcome(modality, measurement_index)),
            )
            .expect("CLI handler fixture outcome is valid");
            assert!(assembler.ingest_monitor_envelope(envelope, now).is_empty());
        }
        let closure = FrameSummary {
            fusion_seq: 1,
            fusion_timestamp_ms: 1_001,
            frame_id: 10,
            context_id: 20,
            prior_id: 101,
            registry_digest: TEST_DIGEST.to_owned(),
            expected_modalities: vec![Modality::Visual, Modality::Radar],
            active_track_count: 1,
            input_count: 2,
            outcome_count: 2,
            v1_expected_count: 2,
            degraded: false,
            truncated: false,
        };
        let envelope = MonitorEnvelope::try_new(
            "epoch-1",
            "crebain",
            3,
            ProducerEvent::FrameSummary(closure),
        )
        .expect("CLI handler fixture summary is valid");
        assembler
            .ingest_monitor_envelope(envelope, now)
            .into_iter()
            .find(|event| matches!(event, AssemblyEvent::FrameReady(_)))
            .expect("CLI handler fixture completes one frame")
    }

    fn telemetry() -> ObserveTelemetry {
        ObserveTelemetry {
            prior_identities: 2,
            max_prior_identities: 3,
            observation_streams: 4,
            max_observation_streams: 5,
            open_frames: 6,
            max_open_frames: 7,
            buffered_bytes: 8,
            max_buffered_bytes: 9,
        }
    }

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

    #[test]
    fn bounded_registry_loader_reports_the_exact_overflow_byte() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "galadriel-oversized-registry-{}-{unique}.json",
            std::process::id()
        ));
        let file = std::fs::File::create(&path).expect("create sparse oversized registry");
        file.set_len((galadriel_ncp::registry::MAX_REGISTRY_BYTES as u64) + 1)
            .expect("size sparse oversized registry");
        drop(file);

        let error = load_deployment_registry(&path, TEST_DIGEST)
            .expect_err("one byte beyond the registry ceiling is rejected");
        std::fs::remove_file(&path).expect("remove oversized registry fixture");
        assert!(matches!(
            error.downcast_ref::<galadriel_ncp::registry::RegistryError>(),
            Some(galadriel_ncp::registry::RegistryError::DocumentSize {
                actual,
                maximum,
            }) if *actual == galadriel_ncp::registry::MAX_REGISTRY_BYTES + 1
                && *maximum == galadriel_ncp::registry::MAX_REGISTRY_BYTES
        ));
    }

    #[test]
    fn observe_event_handler_renders_frame_and_both_assessment_shapes() {
        let detector_config = DetectorConfig::standalone_advisory_v0_9()
            .expect("standalone-advisory detector config is valid");
        let mut detector = LifecycleDetector::new(detector_config, Default::default())
            .expect("standalone-advisory lifecycle detector is valid");
        let output = handle_observe_event(assembled_frame_event(), &mut detector, telemetry())
            .expect("complete frame is assessed");
        assert_eq!(output.stderr, Vec::<String>::new());
        assert_eq!(output.stdout.len(), 1);
        assert!(output.stdout[0].contains("frame=1 track=7 history_reset=true evidence="));
        assert!(output.stdout[0].ends_with("calibrated_posterior=false"));

        let abstained = render_lifecycle_assessment(LifecycleAssessment::Abstained {
            track_id: 9,
            fusion_seq: 12,
            unavailable_modalities: vec![Modality::Radar],
        })
        .expect("abstention has one CLI record");
        assert_eq!(
            abstained,
            "frame=12 track=9 evidence=InsufficientEvidence lifecycle_complete=true assessable=false unavailable=[Radar] calibrated_posterior=false"
        );
    }

    #[test]
    fn observe_event_handler_reports_exact_heartbeat_and_contract_advisory() {
        let detector_config = DetectorConfig::standalone_advisory_v0_9()
            .expect("standalone-advisory detector config is valid");
        let mut detector = LifecycleDetector::new(detector_config, Default::default())
            .expect("standalone-advisory lifecycle detector is valid");
        let heartbeat = handle_observe_event(
            AssemblyEvent::HeartbeatAccepted {
                event_seq: 11,
                received_at: Instant::now(),
            },
            &mut detector,
            telemetry(),
        )
        .expect("heartbeat is advisory");
        assert_eq!(heartbeat.stdout, Vec::<String>::new());
        assert_eq!(
            heartbeat.stderr,
            ["heartbeat event_seq=11 prior_identities=2/3 observation_streams=4/5 open_frames=6/7 buffered_bytes=8/9"]
        );

        let mismatch = handle_observe_event(
            AssemblyEvent::ContractHashMismatch {
                route: EvidenceRoute::Monitor,
            },
            &mut detector,
            telemetry(),
        )
        .expect("contract mismatch remains advisory");
        assert_eq!(
            mismatch.stderr,
            ["advisory contract-hash mismatch on Monitor route"]
        );
    }

    #[test]
    fn observe_event_handler_fails_closed_if_receiver_fault_lifting_regresses() {
        let detector_config = DetectorConfig::standalone_advisory_v0_9()
            .expect("standalone-advisory detector config is valid");
        let mut detector = LifecycleDetector::new(detector_config, Default::default())
            .expect("standalone-advisory lifecycle detector is valid");
        let error = handle_observe_event(
            AssemblyEvent::Fault(AssemblyFault {
                kind: AssemblyFaultKind::HeartbeatDeadlineExpired,
                invalidate_from_fusion_seq: None,
                detected_at: Instant::now(),
            }),
            &mut detector,
            telemetry(),
        )
        .expect_err("an unexpectedly delivered terminal fault cannot be ignored");
        assert!(error
            .to_string()
            .contains("operational receiver unexpectedly returned assembly fault"));
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
    let start = attack_start_frame(frames, 2);

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
    let detector_config = DetectorConfig::standalone_advisory_v0_9()?;
    let mut mirror = Mirror::with_modalities(detector_config, mods)?;
    let track = stream[0].track_id();
    let mut history: HashMap<Modality, Vec<f64>> = HashMap::new();
    let mut report = None;

    for chunk in stream.chunks(mods.len()) {
        anyhow::ensure!(
            chunk.iter().all(|observation| {
                observation.track_id() == track && observation.sequence() == chunk[0].sequence()
            }),
            "demo stream is not grouped into one track and sequence per fusion frame"
        );
        for o in chunk {
            mirror.ingest(o)?;
        }
        let r = mirror.assess(track, chunk[0].sequence())?;
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
    let vc = color_for_tone(&v, verdict_tone(&report.verdict), color);
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
        // `c < cols`, so this downsampled index is always strictly below `n`.
        let idx = c * n / cols;
        let t = ((data[idx] - lo) / span).clamp(0.0, 1.0);
        let k = (t * (TICKS.len() - 1) as f64).round() as usize;
        // Clamping `t` to `[0, 1]` guarantees a valid tick index after rounding.
        s.push(TICKS[k]);
    }
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerdictTone {
    Good,
    Alarm,
    Insufficient,
}

fn verdict_tone(verdict: &Verdict) -> VerdictTone {
    match verdict {
        Verdict::Nominal => VerdictTone::Good,
        Verdict::InsufficientEvidence => VerdictTone::Insufficient,
        Verdict::AttributedInconsistency { .. }
        | Verdict::BroadDegradation
        | Verdict::UnclassifiedAnomaly { .. } => VerdictTone::Alarm,
    }
}

fn fused_verdict_tone(verdict: &FusedVerdict) -> VerdictTone {
    match verdict {
        FusedVerdict::Nominal => VerdictTone::Good,
        FusedVerdict::InsufficientEvidence => VerdictTone::Insufficient,
        FusedVerdict::AttributedInconsistency { .. }
        | FusedVerdict::BroadDegradation
        | FusedVerdict::UnclassifiedAnomaly { .. } => VerdictTone::Alarm,
    }
}

fn color_for_tone(text: &str, tone: VerdictTone, color: bool) -> String {
    match tone {
        VerdictTone::Good => green(text, color),
        VerdictTone::Alarm => red(text, color),
        VerdictTone::Insufficient => dim(text, color),
    }
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
            start_frame: attack_start_frame(frames, 3),
        },
    )?;

    let report = assess_default(
        &stream,
        &mods,
        &DetectorConfig::standalone_advisory_v0_9()?,
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
    let fc = color_for_tone(&fused, fused_verdict_tone(&report.verdict), color);
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

    fn has_frames(&self) -> bool {
        self.frames != 0
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
        self.too_few_modalities.has_frames()
            || self.missing_projection.has_frames()
            || self.extraction_errors.has_frames()
            || self.analysis_errors.has_frames()
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
#[derive(Debug, Default)]
struct SuppressedReplayStats {
    baseline_alarm_tracks: usize,
    default_alarm_tracks: usize,
    baseline_insufficient_tracks: usize,
    default_insufficient_tracks: usize,
    default_issue_tracks: usize,
    baseline_history: ReplayHistory,
    default_history: ReplayHistory,
}

#[cfg(feature = "ncp")]
impl SuppressedReplayStats {
    fn record(&mut self, baseline: &ReplayHistory, default: &ReplayHistory) {
        self.baseline_alarm_tracks = self
            .baseline_alarm_tracks
            .saturating_add(usize::from(baseline.alarms.has_frames()));
        self.default_alarm_tracks = self
            .default_alarm_tracks
            .saturating_add(usize::from(default.alarms.has_frames()));
        self.baseline_insufficient_tracks = self
            .baseline_insufficient_tracks
            .saturating_add(usize::from(baseline.insufficient.has_frames()));
        self.default_insufficient_tracks = self
            .default_insufficient_tracks
            .saturating_add(usize::from(default.insufficient.has_frames()));
        self.default_issue_tracks = self
            .default_issue_tracks
            .saturating_add(usize::from(default.has_consistency_issue()));
        self.baseline_history.merge(baseline);
        self.default_history.merge(default);
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

#[cfg(feature = "ncp")]
fn contiguous_ranges_by_key<T, K: PartialEq>(
    items: &[T],
    key: impl Fn(&T) -> K,
) -> Vec<Range<usize>> {
    if items.is_empty() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    let mut start = 0;
    for (end, pair) in (1..items.len()).zip(items.windows(2)) {
        if key(&pair[0]) != key(&pair[1]) {
            ranges.push(start..end);
            start = end;
        }
    }
    ranges.push(start..items.len());
    ranges
}

#[cfg(feature = "ncp")]
fn replay_window_observation_range(
    frame_ranges: &[Range<usize>],
    frame_index: usize,
    window: usize,
) -> Range<usize> {
    debug_assert!(window > 0, "correlation window must be nonzero");
    debug_assert!(frame_index < frame_ranges.len(), "frame index must exist");
    let start_frame = frame_index.saturating_add(1).saturating_sub(window);
    frame_ranges[start_frame].start..frame_ranges[frame_index].end
}

#[cfg(feature = "ncp")]
fn has_required_modalities(modality_count: usize, minimum: usize) -> bool {
    modality_count >= minimum
}

#[cfg(feature = "ncp")]
fn correlation_config_for_axes(
    base: &galadriel_core::CorrConfig,
    axis_count: usize,
) -> galadriel_core::CorrConfig {
    debug_assert!(
        axis_count > 0,
        "a validated projection has at least one axis"
    );
    let mut adjusted = base.clone();
    adjusted.family_alpha /= axis_count as f64;
    adjusted
}

#[cfg(feature = "ncp")]
fn correlation_reports_are_insufficient(reports: &[galadriel_core::AxisCorrelationReport]) -> bool {
    use galadriel_core::CorrVerdict;

    reports.is_empty()
        || reports
            .iter()
            .any(|axis| matches!(axis.report.verdict, CorrVerdict::InsufficientEvidence))
}

#[cfg(feature = "ncp")]
fn omitted_track_count(total: usize, included: usize) -> Option<NonZeroUsize> {
    NonZeroUsize::new(total.saturating_sub(included))
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
        AxisCorrelationReport, CorrConfig,
    };

    let color = std::io::stdout().is_terminal();
    let detector_cfg = DetectorConfig::standalone_advisory_v0_9()?;
    anyhow::ensure!(
        (1..=detector_cfg.max_tracks()).contains(&max_report_tracks),
        "max-report-tracks must be in 1..={}",
        detector_cfg.max_tracks()
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
            observation.track_id(),
            observation.sequence(),
            observation.modality() as u8,
        )
    });
    let track_ranges = contiguous_ranges_by_key(&obs, PidObservation::track_id);
    let track_count = track_ranges.len();
    anyhow::ensure!(
        track_count <= detector_cfg.max_tracks(),
        "capture contains {track_count} tracks; detector maximum is {}",
        detector_cfg.max_tracks()
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

    let mut suppressed = SuppressedReplayStats::default();
    for (track_index, track_range) in track_ranges.iter().enumerate() {
        let track_obs = &obs[track_range.clone()];
        let track_id = track_obs[0].track_id();
        let mut mods: Vec<Modality> = track_obs.iter().map(PidObservation::modality).collect();
        mods.sort_by_key(|modality| *modality as u8);
        mods.dedup();

        let modalities_ready = has_required_modalities(mods.len(), detector_cfg.min_channels());
        let mut mirror = if modalities_ready {
            Mirror::with_modalities(detector_cfg.clone(), &mods)?
        } else {
            Mirror::new(detector_cfg.clone())?
        };
        let corr_cfg = CorrConfig::default();
        let mut baseline_history = ReplayHistory::default();
        let mut default_history = ReplayHistory::default();
        let mut baseline_terminal = None;
        let mut default_terminal: Option<(FusedVerdict, String)> = None;

        let frame_ranges = contiguous_ranges_by_key(track_obs, PidObservation::sequence);
        for (frame_index, frame_range) in frame_ranges.iter().enumerate() {
            let seq = track_obs[frame_range.start].sequence();
            for observation in &track_obs[frame_range.clone()] {
                mirror.ingest(observation)?;
            }
            let baseline = mirror.assess(track_id, seq)?;
            baseline_history.observe(
                seq.get(),
                baseline_alarm(&baseline.verdict),
                matches!(&baseline.verdict, Verdict::InsufficientEvidence),
                None,
            );

            let window_range =
                replay_window_observation_range(&frame_ranges, frame_index, corr_cfg.window);
            let (correlations, consistency_status, consistency_note) = if modalities_ready {
                match consistency_channels_with_temporal_limits(
                    &track_obs[window_range],
                    &mods,
                    detector_cfg.max_seq_gap(),
                    detector_cfg.max_timestamp_skew_ms(),
                    detector_cfg.max_inter_sample_gap_ms(),
                ) {
                    Ok(Some(projection)) => {
                        let axis_count = projection.axes.len();
                        let reports = projection
                            .axes
                            .iter()
                            .enumerate()
                            .map(|(axis, channels)| {
                                let adjusted = correlation_config_for_axes(&corr_cfg, axis_count);
                                correlation::analyze(channels, &adjusted)
                                    .map(|report| AxisCorrelationReport { axis, report })
                            })
                            .collect::<galadriel_core::Result<Vec<_>>>();
                        match reports {
                            Ok(reports) => {
                                let insufficient = correlation_reports_are_insufficient(&reports);
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
            } else {
                (
                    Vec::new(),
                    ConsistencyFrameStatus::TooFewModalities,
                    "fewer than the configured minimum modalities".to_string(),
                )
            };
            let (fused, fusion_note) = combine_correlation_axes(&baseline, &correlations);
            default_history.observe(
                seq.get(),
                fused_alarm(&fused),
                matches!(&fused, FusedVerdict::InsufficientEvidence),
                Some(consistency_status),
            );
            baseline_terminal = Some(baseline);
            default_terminal = Some((
                fused,
                format!("{fusion_note}; consistency: {consistency_note}"),
            ));
        }

        let baseline = baseline_terminal
            .ok_or_else(|| anyhow::anyhow!("track {track_id} has no assessment frame"))?;
        let (default_verdict, default_note) = default_terminal
            .ok_or_else(|| anyhow::anyhow!("track {track_id} has no fused assessment"))?;
        let verbose = replay_track_is_verbose(track_index, max_report_tracks);
        if verbose {
            let verdict = verdict_str(&baseline.verdict);
            let colored = color_for_tone(&verdict, verdict_tone(&baseline.verdict), color);
            println!(
                "│  baseline · track {track_id}: terminal {}  {}",
                colored,
                dim(&baseline_history.summary(), color)
            );
            println!("│             {}", dim(&baseline.note, color));

            let fused = fused_verdict_str(&default_verdict);
            let colored = color_for_tone(&fused, fused_verdict_tone(&default_verdict), color);
            println!(
                "│  default  · track {track_id}: terminal {}  {}",
                colored,
                dim(&default_history.summary(), color)
            );
            println!("│             {}", dim(&default_note, color));
        } else {
            suppressed.record(&baseline_history, &default_history);
        }

        #[cfg(feature = "pid")]
        if replay_track_uses_pid(track_index, max_pid_tracks) {
            use galadriel_pid::{assess_stream, PidConfig};

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
    }

    if let Some(omitted) = omitted_track_count(track_count, max_report_tracks) {
        println!(
            "│  suppressed {} per-track report(s); among them, {} had baseline alarms and {} had default-fused alarms",
            omitted.get(),
            suppressed.baseline_alarm_tracks,
            suppressed.default_alarm_tracks,
        );
        println!(
            "│    historical insufficiency affected {} baseline track(s) and {} default track(s); consistency input was rejected or missing on {} track(s)",
            suppressed.baseline_insufficient_tracks,
            suppressed.default_insufficient_tracks,
            suppressed.default_issue_tracks,
        );
        println!(
            "│    baseline history across suppressed tracks: {}",
            dim(&suppressed.baseline_history.summary(), color)
        );
        println!(
            "│    default history across suppressed tracks: {}",
            dim(&suppressed.default_history.summary(), color)
        );
    }
    #[cfg(feature = "pid")]
    if let Some(omitted) = omitted_track_count(track_count, max_pid_tracks) {
        println!(
            "│  PID terminal analysis skipped for {} track(s); bounded by --max-pid-tracks={max_pid_tracks}",
            omitted.get()
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
            start_frame: attack_start_frame(frames, 3),
        },
    )?;

    // Compare the KSG-MI escalation on every attested projection axis. Agreement
    // is an observed finite-sample result, not an equivalence guarantee.
    let report = assess_stream(
        &stream,
        &mods,
        &DetectorConfig::standalone_advisory_v0_9()?,
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

    fn axis_report(verdict: galadriel_core::CorrVerdict) -> galadriel_core::AxisCorrelationReport {
        galadriel_core::AxisCorrelationReport {
            axis: 0,
            report: galadriel_core::CorrReport {
                channels: Vec::new(),
                verdict,
                note: String::new(),
            },
        }
    }

    #[test]
    fn contiguous_ranges_cover_empty_singleton_and_uneven_groups() {
        assert_eq!(
            contiguous_ranges_by_key::<u64, u64>(&[], |value| *value),
            Vec::<Range<usize>>::new()
        );
        let singleton = contiguous_ranges_by_key(&[7_u64], |value| *value);
        assert_eq!(singleton.len(), 1);
        assert_eq!(singleton[0], 0..1);
        assert_eq!(
            contiguous_ranges_by_key(&[1_u64, 1, 2, 2, 2, 4], |value| *value),
            [0..2, 2..5, 5..6]
        );
    }

    #[test]
    fn replay_window_observation_range_preserves_nonuniform_128_frame_boundary() {
        let mut frame_ranges = Vec::with_capacity(129);
        frame_ranges.push(0..2);
        frame_ranges.extend((1..=126).map(|frame| (frame + 1)..(frame + 2)));
        frame_ranges.push(128..131);
        frame_ranges.push(131..135);

        assert_eq!(frame_ranges.len(), 129);
        assert_eq!(
            replay_window_observation_range(&frame_ranges, 126, 128),
            0..128
        );
        assert_eq!(
            replay_window_observation_range(&frame_ranges, 127, 128),
            0..131
        );
        assert_eq!(
            replay_window_observation_range(&frame_ranges, 128, 128),
            2..135
        );
    }

    #[test]
    fn required_modality_boundary_is_inclusive() {
        assert!(!has_required_modalities(1, 2));
        assert!(has_required_modalities(2, 2));
        assert!(has_required_modalities(3, 2));
    }

    #[test]
    fn correlation_family_alpha_is_split_across_projection_axes() {
        let base = galadriel_core::CorrConfig::default();
        let adjusted = correlation_config_for_axes(&base, 3);

        assert!((adjusted.family_alpha - base.family_alpha / 3.0).abs() < f64::EPSILON);
        assert_eq!(adjusted.window, base.window);
        assert_eq!(adjusted.min_samples, base.min_samples);
    }

    #[test]
    fn correlation_report_insufficiency_covers_empty_ready_and_mixed_inputs() {
        let nominal = axis_report(galadriel_core::CorrVerdict::Nominal);
        let insufficient = axis_report(galadriel_core::CorrVerdict::InsufficientEvidence);

        assert!(correlation_reports_are_insufficient(&[]));
        assert!(!correlation_reports_are_insufficient(&[nominal]));
        assert!(correlation_reports_are_insufficient(&[
            axis_report(galadriel_core::CorrVerdict::Nominal),
            insufficient,
        ]));
    }

    #[test]
    fn omitted_track_count_distinguishes_positive_equal_and_overprovisioned_limits() {
        assert_eq!(omitted_track_count(3, 1).map(NonZeroUsize::get), Some(2));
        assert_eq!(omitted_track_count(3, 3), None);
        assert_eq!(omitted_track_count(1, 3), None);
    }

    #[test]
    fn report_visibility_covers_both_sides_of_the_limit() {
        assert!(replay_track_is_verbose(0, 1));
        assert!(!replay_track_is_verbose(1, 1));
    }

    #[cfg(feature = "pid")]
    #[test]
    fn pid_selection_covers_the_exact_limit_and_is_independent_of_visibility() {
        assert!(replay_track_uses_pid(0, 1));
        assert!(!replay_track_uses_pid(1, 1));
        assert_eq!(
            (replay_track_is_verbose(1, 1), replay_track_uses_pid(1, 4)),
            (false, true)
        );
    }

    #[test]
    fn alarm_classification_covers_every_baseline_verdict() {
        assert!(!baseline_alarm(&Verdict::Nominal));
        assert!(!baseline_alarm(&Verdict::InsufficientEvidence));
        assert!(baseline_alarm(&Verdict::AttributedInconsistency {
            channels: vec![Modality::Visual],
        }));
        assert!(baseline_alarm(&Verdict::BroadDegradation));
        assert!(baseline_alarm(&Verdict::UnclassifiedAnomaly {
            channels: vec![Modality::Radar],
        }));
    }

    #[test]
    fn alarm_classification_covers_every_fused_verdict() {
        assert!(!fused_alarm(&FusedVerdict::Nominal));
        assert!(!fused_alarm(&FusedVerdict::InsufficientEvidence));
        assert!(fused_alarm(&FusedVerdict::AttributedInconsistency {
            channels: vec![Modality::Visual],
            magnitude: MagnitudeEvidence::InCovariance,
        }));
        assert!(fused_alarm(&FusedVerdict::BroadDegradation));
        assert!(fused_alarm(&FusedVerdict::UnclassifiedAnomaly {
            channels: vec![Modality::Radar],
        }));
    }

    #[test]
    fn frame_span_presence_distinguishes_zero_and_positive_counts() {
        let mut span = FrameSpan::default();
        assert!(!span.has_frames());
        span.observe(5);
        assert!(span.has_frames());
    }

    #[test]
    fn consistency_issue_truth_table_covers_each_independent_cause() {
        assert!(!ReplayHistory::default().has_consistency_issue());

        for status in [
            ConsistencyFrameStatus::TooFewModalities,
            ConsistencyFrameStatus::MissingProjection,
            ConsistencyFrameStatus::ExtractionError,
            ConsistencyFrameStatus::AnalysisError,
        ] {
            let mut history = ReplayHistory::default();
            history.observe(1, false, false, Some(status));
            assert!(history.has_consistency_issue(), "status {status:?}");
        }

        let mut insufficient_only = ReplayHistory::default();
        insufficient_only.observe(
            1,
            false,
            false,
            Some(ConsistencyFrameStatus::Assessed { insufficient: true }),
        );
        assert!(!insufficient_only.has_consistency_issue());

        let mut alarm_only = ReplayHistory::default();
        alarm_only.observe(1, true, false, None);
        assert!(!alarm_only.has_consistency_issue());
    }

    #[test]
    fn suppressed_stats_record_zero_positive_and_repeated_histories() {
        let mut empty_stats = SuppressedReplayStats::default();
        empty_stats.record(&ReplayHistory::default(), &ReplayHistory::default());
        assert_eq!(empty_stats.baseline_alarm_tracks, 0);
        assert_eq!(empty_stats.default_alarm_tracks, 0);
        assert_eq!(empty_stats.baseline_insufficient_tracks, 0);
        assert_eq!(empty_stats.default_insufficient_tracks, 0);
        assert_eq!(empty_stats.default_issue_tracks, 0);

        let mut baseline = ReplayHistory::default();
        baseline.observe(5, true, true, None);
        let mut default = ReplayHistory::default();
        default.observe(
            7,
            true,
            true,
            Some(ConsistencyFrameStatus::MissingProjection),
        );

        let mut stats = SuppressedReplayStats::default();
        stats.record(&baseline, &default);
        assert_eq!(stats.baseline_alarm_tracks, 1);
        assert_eq!(stats.default_alarm_tracks, 1);
        assert_eq!(stats.baseline_insufficient_tracks, 1);
        assert_eq!(stats.default_insufficient_tracks, 1);
        assert_eq!(stats.default_issue_tracks, 1);

        stats.record(&baseline, &default);
        assert_eq!(stats.baseline_alarm_tracks, 2);
        assert_eq!(stats.default_alarm_tracks, 2);
        assert_eq!(stats.baseline_insufficient_tracks, 2);
        assert_eq!(stats.default_insufficient_tracks, 2);
        assert_eq!(stats.default_issue_tracks, 2);
        assert_eq!(stats.baseline_history.alarms.frames, 2);
        assert_eq!(stats.default_history.missing_projection.frames, 2);
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

#[cfg(test)]
mod verdict_label_tests {
    use super::*;

    #[test]
    fn attack_start_uses_floor_division_at_supported_boundaries() {
        assert_eq!(attack_start_frame(128, 2), 64);
        assert_eq!(attack_start_frame(128, 3), 42);
        assert_eq!(attack_start_frame(129, 3), 43);
    }

    #[test]
    fn sparkline_maps_a_nonzero_range_to_all_expected_quartile_ticks() {
        assert_eq!(sparkline(&[], 10.0, 20.0), "");

        let rendered = sparkline(&[10.0, 12.0, 15.0, 20.0], 10.0, 20.0);
        let expected = [
            "▁".repeat(12),
            "▂".repeat(12),
            "▅".repeat(12),
            "█".repeat(12),
        ]
        .concat();

        assert_eq!(rendered, expected);
        assert_eq!(rendered.chars().count(), 48);
    }

    #[test]
    fn baseline_verdict_tones_cover_every_variant() {
        assert_eq!(verdict_tone(&Verdict::Nominal), VerdictTone::Good);
        assert_eq!(
            verdict_tone(&Verdict::InsufficientEvidence),
            VerdictTone::Insufficient
        );
        for verdict in [
            Verdict::AttributedInconsistency {
                channels: vec![Modality::Visual],
            },
            Verdict::BroadDegradation,
            Verdict::UnclassifiedAnomaly {
                channels: vec![Modality::Radar],
            },
        ] {
            assert_eq!(verdict_tone(&verdict), VerdictTone::Alarm);
        }
    }

    #[test]
    fn fused_verdict_tones_cover_every_variant() {
        assert_eq!(
            fused_verdict_tone(&FusedVerdict::Nominal),
            VerdictTone::Good
        );
        assert_eq!(
            fused_verdict_tone(&FusedVerdict::InsufficientEvidence),
            VerdictTone::Insufficient
        );
        for verdict in [
            FusedVerdict::AttributedInconsistency {
                channels: vec![Modality::Visual],
                magnitude: MagnitudeEvidence::InCovariance,
            },
            FusedVerdict::BroadDegradation,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Radar],
            },
        ] {
            assert_eq!(fused_verdict_tone(&verdict), VerdictTone::Alarm);
        }
    }

    #[test]
    fn verdict_tone_coloring_covers_every_ansi_branch() {
        assert_eq!(
            color_for_tone("status", VerdictTone::Good, true),
            "\x1b[1;32mstatus\x1b[0m"
        );
        assert_eq!(
            color_for_tone("status", VerdictTone::Alarm, true),
            "\x1b[1;31mstatus\x1b[0m"
        );
        assert_eq!(
            color_for_tone("status", VerdictTone::Insufficient, true),
            "\x1b[2mstatus\x1b[0m"
        );
    }

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
