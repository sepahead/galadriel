#![forbid(unsafe_code)]
//! Structured, bounded fuzz drivers shared by fuzz targets and seed canaries.

use std::time::{Duration, Instant};

use galadriel_core::{
    assess_default, consistency_channels_with_temporal_limits, AssessmentScope, ClockDomain,
    ConsistencyProjection, DetectorConfig, DetectorParams, Mirror, Modality, PidObservation,
    ProducerId, ReleaseSuite, StreamPosition,
};
use galadriel_ncp::assembler::{
    AssemblerProfile, AssemblyEvent, AssemblyFaultKind, CrossRouteAssembler, FrameIdentity,
    RegistryOpportunityParams, RegistryOpportunityPolicy, RegistryVerifier, RegistryViolation,
};
use galadriel_ncp::lifecycle::LifecycleDetector;
use galadriel_ncp::monitor::{
    FrameSummary, GateEvidence, GateMethod, Heartbeat, ModalityMiss, ModalityMissReason,
    ModalityOutcome, ModalityOutcomeKind, MonitorEnvelope, ProducerEvent, QueueHealth,
};
use galadriel_ncp::{
    parse_jsonl_with_limits, registry::DeploymentRegistry, JsonlLimits, SidecarEnvelope,
    DEFAULT_MAX_JSONL_LINE_BYTES,
};
use serde::Deserialize;

const MAX_FUZZ_INPUT_BYTES: usize = 128 * 1024;
const MAX_OPERATIONS: usize = 256;
const MAX_FUZZ_OBSERVATIONS: usize = 1_024;
const MAX_STEP_MILLIS: u64 = 60_000;
const MAX_ELAPSED_MILLIS: u64 = 10 * 60_000;
const SESSION_ID: &str = "fuzz-epoch";
const PRODUCER_ID: &str = "fuzz-producer";
const REGISTRY_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EXPECTED_MODALITIES: [Modality; 2] = [Modality::Visual, Modality::Radar];

/// Semantic parser coverage reached by one bounded NCP input.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NcpDecodeCoverage {
    /// The input decoded as a sidecar observation envelope.
    pub sidecar_decoded: bool,
    /// The decoded sidecar envelope passed both identity validators.
    pub sidecar_validated: bool,
    /// The input decoded as a monitor envelope.
    pub monitor_decoded: bool,
    /// The decoded monitor envelope passed both identity validators.
    pub monitor_validated: bool,
    /// The input decoded as a deployment registry.
    pub registry_decoded: bool,
    /// Number of observations admitted by the bounded JSONL parser.
    pub jsonl_observations: usize,
}

/// Coarse semantic coverage reached by one detector-boundary input.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DetectorBoundaryCoverage {
    /// The byte-derived detector parameters passed public validation.
    pub detector_config_accepted: bool,
    /// The input decoded as a strict observation vector.
    pub observations_decoded: bool,
    /// Number of observations retained after the fuzz bound.
    pub observations_retained: usize,
    /// Number of observations accepted by the stateful mirror.
    pub mirror_ingests: usize,
    /// Number of mirror assessments that returned a report.
    pub mirror_assessments: usize,
    /// The temporal consistency-channel extractor was invoked.
    pub temporal_channels_attempted: bool,
    /// The fused default assessment was invoked with an exact scope.
    pub default_assessment_attempted: bool,
    /// The fused default assessment returned a report.
    pub default_assessment_accepted: bool,
}

/// Coarse semantic coverage reached by one structured lifecycle input.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LifecycleCoverage {
    /// The bounded input decoded as one strict scenario.
    pub scenario_decoded: bool,
    /// Number of bounded operations visited.
    pub operations: usize,
    /// Number of observation-route payloads passed to the assembler.
    pub observation_payloads: usize,
    /// Number of monitor-route payloads passed to the assembler.
    pub monitor_payloads: usize,
    /// Inputs rejected before either route accepted bytes.
    pub construction_rejections: usize,
    /// Assembly events emitted across both routes and clock advances.
    pub assembly_events: usize,
    /// Lifecycle-complete frames emitted by the assembler.
    pub frames_ready: usize,
    /// Complete frames committed by the lifecycle detector.
    pub lifecycle_commits: usize,
    /// Complete frames rejected by the lifecycle detector.
    pub lifecycle_rejections: usize,
    /// Terminal fail-closed assembler faults.
    pub assembler_faults: usize,
    /// First exact terminal assembler fault, when present.
    pub first_assembler_fault: Option<AssemblyFaultKind>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    operations: Vec<Operation>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Observation {
        track_id: u64,
        fusion_seq: u64,
        fusion_timestamp_ms: u64,
        frame_id: u64,
        context_id: u64,
        prior_id: u64,
        modality: Modality,
        projection: [f64; 3],
        dimensions: u8,
        nis: f64,
        dof: u8,
        #[serde(default)]
        receipt_delta_ms: u64,
    },
    Outcome {
        event_seq: u64,
        fusion_seq: u64,
        fusion_timestamp_ms: u64,
        frame_id: u64,
        context_id: u64,
        prior_id: u64,
        track_id: u64,
        modality: Modality,
        attempt_index: u32,
        measurement_index: Option<u32>,
        outcome: ModalityOutcomeKind,
        v1_expected: bool,
        candidate_count: u32,
        in_gate_count: u32,
        gate_d2: Option<f64>,
        gate_threshold: Option<f64>,
        projection: Option<[f64; 3]>,
        projection_dimensions: Option<u8>,
        #[serde(default)]
        receipt_delta_ms: u64,
    },
    Miss {
        event_seq: u64,
        fusion_seq: u64,
        fusion_timestamp_ms: u64,
        frame_id: u64,
        context_id: u64,
        prior_id: u64,
        track_id: u64,
        modality: Modality,
        reason: ModalityMissReason,
        #[serde(default)]
        receipt_delta_ms: u64,
    },
    Summary {
        event_seq: u64,
        fusion_seq: u64,
        fusion_timestamp_ms: u64,
        frame_id: u64,
        context_id: u64,
        prior_id: u64,
        registry_digest: String,
        expected_modalities: Vec<Modality>,
        active_track_count: u32,
        input_count: u32,
        outcome_count: u32,
        v1_expected_count: u32,
        degraded: bool,
        truncated: bool,
        #[serde(default)]
        receipt_delta_ms: u64,
    },
    Heartbeat {
        event_seq: u64,
        producer_timestamp_ms: u64,
        uptime_ms: u64,
        declared_interval_ms: u64,
        declared_deadline_ms: u64,
        last_fusion_seq: Option<u64>,
        active_track_count: u32,
        degraded: bool,
        queue_capacity: u32,
        queue_depth: u32,
        dropped_event_count: u64,
        published_event_count: u64,
        #[serde(default)]
        receipt_delta_ms: u64,
    },
    AdvanceTime {
        delta_ms: u64,
    },
}

#[derive(Clone, Copy)]
struct FuzzRegistry {
    policy: RegistryOpportunityPolicy,
}

impl FuzzRegistry {
    fn try_new() -> Option<Self> {
        RegistryOpportunityPolicy::try_new(RegistryOpportunityParams {
            max_active_tracks: 64,
            max_frame_inputs: 1_024,
            max_attempts_per_track_modality: 1_024,
            max_outcomes_per_frame: 1_024,
            max_monitor_queue_events: 1_024,
        })
        .ok()
        .map(|policy| Self { policy })
    }
}

impl RegistryVerifier for FuzzRegistry {
    fn opportunity_policy(&self) -> Result<RegistryOpportunityPolicy, RegistryViolation> {
        Ok(self.policy)
    }

    fn verify_summary(
        &self,
        _identity: FrameIdentity,
        registry_digest: &str,
        expected_modalities: &[Modality],
    ) -> Result<(), RegistryViolation> {
        if registry_digest != REGISTRY_DIGEST {
            return Err(RegistryViolation::DigestMismatch);
        }
        if expected_modalities != EXPECTED_MODALITIES {
            return Err(RegistryViolation::UnexpectedModalities);
        }
        Ok(())
    }

    fn verify_projection(
        &self,
        identity: FrameIdentity,
        modality: Modality,
        projection: &ConsistencyProjection,
    ) -> Result<(), RegistryViolation> {
        let projection_identity = projection.identity();
        let received_frame_id = projection_identity.frame_id().get();
        let received_context_id = projection_identity.context_id().get();
        let received_prior_id = projection_identity.frozen_prior_id().get();
        if (received_frame_id, received_context_id, received_prior_id)
            != (identity.frame_id, identity.context_id, identity.prior_id)
        {
            return Err(RegistryViolation::ProjectionIdentityMismatch {
                expected_frame_id: identity.frame_id,
                received_frame_id,
                expected_context_id: identity.context_id,
                received_context_id,
                expected_prior_id: identity.prior_id,
                received_prior_id,
            });
        }
        if !EXPECTED_MODALITIES.contains(&modality) {
            return Err(RegistryViolation::UnexpectedProjectionModality {
                context_id: identity.context_id,
                modality,
            });
        }
        if projection.dimensions() != 3 {
            return Err(RegistryViolation::ProjectionDimensionMismatch {
                context_id: identity.context_id,
                expected: 3,
                received: projection.dimensions(),
            });
        }
        Ok(())
    }
}

/// Exercise bounded NCP, monitor, registry, and JSONL decoding.
#[must_use]
pub fn exercise_ncp_decode(data: &[u8]) -> NcpDecodeCoverage {
    let mut coverage = NcpDecodeCoverage::default();
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return coverage;
    }

    if let Ok(envelope) = serde_json::from_slice::<SidecarEnvelope>(data) {
        coverage.sidecar_decoded = true;
        coverage.sidecar_validated = envelope.validate().is_ok()
            && envelope
                .validate_for(envelope.session_id(), envelope.producer_id())
                .is_ok();
        let _ = serde_json::to_vec(&envelope);
    }

    if let Ok(envelope) = MonitorEnvelope::decode(data) {
        coverage.monitor_decoded = true;
        coverage.monitor_validated = envelope.validate().is_ok()
            && envelope
                .validate_for(envelope.session_id(), envelope.producer_id())
                .is_ok();
        let _ = envelope.encode();
    }

    coverage.registry_decoded = DeploymentRegistry::from_json(data).is_ok();

    let limits =
        JsonlLimits::with_total_bytes(DEFAULT_MAX_JSONL_LINE_BYTES, 256, MAX_FUZZ_INPUT_BYTES)
            .expect("fixed fuzz limits are valid");
    let text = String::from_utf8_lossy(data);
    if let Ok(observations) = parse_jsonl_with_limits(&text, limits) {
        coverage.jsonl_observations = observations.len();
    }
    coverage
}

fn u64_prefix(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    let tail = data.get(offset..).unwrap_or_default();
    let available = tail.len().min(bytes.len());
    bytes[..available].copy_from_slice(&tail[..available]);
    u64::from_le_bytes(bytes)
}

/// Exercise detector configuration, state, temporal, and projection boundaries.
#[must_use]
pub fn exercise_detector_boundaries(data: &[u8]) -> DetectorBoundaryCoverage {
    let mut coverage = DetectorBoundaryCoverage::default();
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return coverage;
    }
    let max_seq_gap = u64_prefix(data, 0);
    let max_timestamp_skew_ms = u64_prefix(data, 8);
    let max_inter_sample_gap_ms = u64_prefix(data, 16);

    let mut parameters = DetectorParams::standalone_advisory_v0_9();
    // The canonical seed starts with an odd `[`. A leading even-valued byte,
    // including valid JSON whitespace, selects the raw config branch.
    if data.first().is_some_and(|byte| byte & 1 == 0) {
        parameters.max_seq_gap = max_seq_gap;
        parameters.max_timestamp_skew_ms = max_timestamp_skew_ms;
        parameters.max_inter_sample_gap_ms = max_inter_sample_gap_ms;
    }
    coverage.detector_config_accepted = DetectorConfig::try_new(parameters).is_ok();

    let Ok(mut observations) = serde_json::from_slice::<Vec<PidObservation>>(data) else {
        return coverage;
    };
    coverage.observations_decoded = true;
    observations.truncate(MAX_FUZZ_OBSERVATIONS);
    coverage.observations_retained = observations.len();

    let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
    let Ok(suite) = ReleaseSuite::standalone_advisory_v0_9(&modalities) else {
        return coverage;
    };
    let mut mirror = Mirror::from_release_suite(&suite);
    for observation in &observations {
        if mirror.ingest(observation).is_ok() {
            coverage.mirror_ingests += 1;
        }
        if mirror
            .assess(observation.track_id(), observation.sequence())
            .is_ok()
        {
            coverage.mirror_assessments += 1;
        }
    }

    coverage.temporal_channels_attempted = true;
    let _ = consistency_channels_with_temporal_limits(
        &observations,
        &modalities,
        max_seq_gap,
        max_timestamp_skew_ms,
        max_inter_sample_gap_ms,
    );

    let terminal_sequence = observations
        .iter()
        .map(|observation| observation.sequence().get())
        .max()
        .unwrap_or(0);
    let terminal_timestamp = observations
        .iter()
        .filter(|observation| observation.sequence().get() == terminal_sequence)
        .map(|observation| observation.timestamp_ms().get())
        .max()
        .unwrap_or(0);
    let Ok(producer_id) = ProducerId::new("fuzz-harness") else {
        return coverage;
    };
    let Ok(position) = StreamPosition::try_new(
        "fuzz-session",
        "fuzz-epoch",
        "detector-boundaries",
        0,
        terminal_sequence,
        terminal_timestamp,
        ClockDomain::SimulationTime,
    ) else {
        return coverage;
    };
    coverage.default_assessment_attempted = true;
    let scope = AssessmentScope::new(producer_id, position);
    coverage.default_assessment_accepted = assess_default(&scope, &observations, &suite).is_ok();
    coverage
}

/// Exercise the transport-free two-route assembler and lifecycle detector.
///
/// The driver bounds bytes, operation count, and monotonic time. It constructs
/// wire payloads through public validators before it sends their encoded bytes to
/// the runtime assembler. Existing raw-byte targets cover malformed JSON.
#[must_use]
pub fn exercise_lifecycle_state(data: &[u8]) -> LifecycleCoverage {
    let mut coverage = LifecycleCoverage::default();
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return coverage;
    }
    let Ok(mut scenario) = serde_json::from_slice::<Scenario>(data) else {
        return coverage;
    };
    coverage.scenario_decoded = true;
    scenario.operations.truncate(MAX_OPERATIONS);

    let Some(registry) = FuzzRegistry::try_new() else {
        coverage.construction_rejections += 1;
        return coverage;
    };
    let Ok(limits) = AssemblerProfile::BoundedV0_9.try_limits() else {
        coverage.construction_rejections += 1;
        return coverage;
    };
    let start = Instant::now();
    let Ok(mut assembler) =
        CrossRouteAssembler::new(SESSION_ID, PRODUCER_ID, registry, limits, start)
    else {
        coverage.construction_rejections += 1;
        return coverage;
    };
    let Ok(suite) = ReleaseSuite::standalone_advisory_v0_9(&EXPECTED_MODALITIES) else {
        coverage.construction_rejections += 1;
        return coverage;
    };
    let Ok(mut lifecycle) = LifecycleDetector::from_release_suite(suite) else {
        coverage.construction_rejections += 1;
        return coverage;
    };

    let mut elapsed_ms = 0_u64;
    for operation in scenario.operations {
        coverage.operations += 1;
        let events = match operation {
            Operation::Observation {
                track_id,
                fusion_seq,
                fusion_timestamp_ms,
                frame_id,
                context_id,
                prior_id,
                modality,
                projection,
                dimensions,
                nis,
                dof,
                receipt_delta_ms,
            } => {
                let received_at = advance_clock(start, &mut elapsed_ms, receipt_delta_ms);
                let Ok(projection) = ConsistencyProjection::try_new_raw(
                    projection, dimensions, frame_id, context_id, prior_id,
                ) else {
                    coverage.construction_rejections += 1;
                    continue;
                };
                let Ok(observation) = PidObservation::try_scalar_raw(
                    track_id,
                    fusion_timestamp_ms,
                    fusion_seq,
                    modality,
                    nis,
                    dof,
                ) else {
                    coverage.construction_rejections += 1;
                    continue;
                };
                let Ok(envelope) = SidecarEnvelope::try_new(
                    SESSION_ID,
                    PRODUCER_ID,
                    observation.with_consistency_projection(projection),
                ) else {
                    coverage.construction_rejections += 1;
                    continue;
                };
                let Ok(encoded) = serde_json::to_vec(&envelope) else {
                    coverage.construction_rejections += 1;
                    continue;
                };
                coverage.observation_payloads += 1;
                assembler.ingest_observation_bytes(&encoded, received_at)
            }
            Operation::Outcome {
                event_seq,
                fusion_seq,
                fusion_timestamp_ms,
                frame_id,
                context_id,
                prior_id,
                track_id,
                modality,
                attempt_index,
                measurement_index,
                outcome,
                v1_expected,
                candidate_count,
                in_gate_count,
                gate_d2,
                gate_threshold,
                projection,
                projection_dimensions,
                receipt_delta_ms,
            } => {
                let received_at = advance_clock(start, &mut elapsed_ms, receipt_delta_ms);
                let consistency_projection = match (projection, projection_dimensions) {
                    (Some(values), Some(dimensions)) => {
                        let Ok(value) = ConsistencyProjection::try_new_raw(
                            values, dimensions, frame_id, context_id, prior_id,
                        ) else {
                            coverage.construction_rejections += 1;
                            continue;
                        };
                        Some(value)
                    }
                    (None, None) => None,
                    _ => {
                        coverage.construction_rejections += 1;
                        continue;
                    }
                };
                let gate_evidence = match (gate_d2, gate_threshold) {
                    (Some(d2), Some(threshold)) => Some(GateEvidence {
                        method: GateMethod::Mahalanobis,
                        d2,
                        threshold,
                    }),
                    (None, None) => None,
                    _ => {
                        coverage.construction_rejections += 1;
                        continue;
                    }
                };
                let event = ProducerEvent::ModalityOutcome(ModalityOutcome {
                    fusion_seq,
                    fusion_timestamp_ms,
                    frame_id,
                    context_id,
                    prior_id,
                    track_id,
                    modality,
                    attempt_index,
                    measurement_index,
                    outcome,
                    v1_expected,
                    candidate_count,
                    in_gate_count,
                    gate_evidence,
                    consistency_projection,
                });
                let Some(encoded) = encode_monitor(event_seq, event) else {
                    coverage.construction_rejections += 1;
                    continue;
                };
                coverage.monitor_payloads += 1;
                assembler.ingest_monitor_bytes(&encoded, received_at)
            }
            Operation::Miss {
                event_seq,
                fusion_seq,
                fusion_timestamp_ms,
                frame_id,
                context_id,
                prior_id,
                track_id,
                modality,
                reason,
                receipt_delta_ms,
            } => {
                let received_at = advance_clock(start, &mut elapsed_ms, receipt_delta_ms);
                let event = ProducerEvent::ModalityMiss(ModalityMiss {
                    fusion_seq,
                    fusion_timestamp_ms,
                    frame_id,
                    context_id,
                    prior_id,
                    track_id,
                    modality,
                    reason,
                });
                let Some(encoded) = encode_monitor(event_seq, event) else {
                    coverage.construction_rejections += 1;
                    continue;
                };
                coverage.monitor_payloads += 1;
                assembler.ingest_monitor_bytes(&encoded, received_at)
            }
            Operation::Summary {
                event_seq,
                fusion_seq,
                fusion_timestamp_ms,
                frame_id,
                context_id,
                prior_id,
                registry_digest,
                expected_modalities,
                active_track_count,
                input_count,
                outcome_count,
                v1_expected_count,
                degraded,
                truncated,
                receipt_delta_ms,
            } => {
                let received_at = advance_clock(start, &mut elapsed_ms, receipt_delta_ms);
                let event = ProducerEvent::FrameSummary(FrameSummary {
                    fusion_seq,
                    fusion_timestamp_ms,
                    frame_id,
                    context_id,
                    prior_id,
                    registry_digest,
                    expected_modalities,
                    active_track_count,
                    input_count,
                    outcome_count,
                    v1_expected_count,
                    degraded,
                    truncated,
                });
                let Some(encoded) = encode_monitor(event_seq, event) else {
                    coverage.construction_rejections += 1;
                    continue;
                };
                coverage.monitor_payloads += 1;
                assembler.ingest_monitor_bytes(&encoded, received_at)
            }
            Operation::Heartbeat {
                event_seq,
                producer_timestamp_ms,
                uptime_ms,
                declared_interval_ms,
                declared_deadline_ms,
                last_fusion_seq,
                active_track_count,
                degraded,
                queue_capacity,
                queue_depth,
                dropped_event_count,
                published_event_count,
                receipt_delta_ms,
            } => {
                let received_at = advance_clock(start, &mut elapsed_ms, receipt_delta_ms);
                let event = ProducerEvent::Heartbeat(Heartbeat {
                    producer_timestamp_ms,
                    uptime_ms,
                    declared_interval_ms,
                    declared_deadline_ms,
                    last_fusion_seq,
                    active_track_count,
                    degraded,
                    queue_health: QueueHealth {
                        capacity: queue_capacity,
                        depth: queue_depth,
                        dropped_event_count,
                        published_event_count,
                    },
                });
                let Some(encoded) = encode_monitor(event_seq, event) else {
                    coverage.construction_rejections += 1;
                    continue;
                };
                coverage.monitor_payloads += 1;
                assembler.ingest_monitor_bytes(&encoded, received_at)
            }
            Operation::AdvanceTime { delta_ms } => {
                let now = advance_clock(start, &mut elapsed_ms, delta_ms);
                assembler.advance_time(now)
            }
        };
        record_events(events, &mut lifecycle, &mut coverage);
    }
    coverage
}

fn encode_monitor(event_seq: u64, event: ProducerEvent) -> Option<Vec<u8>> {
    MonitorEnvelope::try_new(SESSION_ID, PRODUCER_ID, event_seq, event)
        .and_then(|envelope| envelope.encode())
        .ok()
}

fn advance_clock(start: Instant, elapsed_ms: &mut u64, delta_ms: u64) -> Instant {
    *elapsed_ms = elapsed_ms
        .saturating_add(delta_ms.min(MAX_STEP_MILLIS))
        .min(MAX_ELAPSED_MILLIS);
    start
        .checked_add(Duration::from_millis(*elapsed_ms))
        .unwrap_or(start)
}

fn record_events(
    events: Vec<AssemblyEvent>,
    lifecycle: &mut LifecycleDetector,
    coverage: &mut LifecycleCoverage,
) {
    coverage.assembly_events += events.len();
    for event in events {
        match event {
            AssemblyEvent::FrameReady(frame) => {
                coverage.frames_ready += 1;
                if lifecycle.assess_frame_transition(&frame).is_ok() {
                    coverage.lifecycle_commits += 1;
                } else {
                    coverage.lifecycle_rejections += 1;
                }
            }
            AssemblyEvent::Fault(fault) => {
                coverage.assembler_faults += 1;
                if coverage.first_assembler_fault.is_none() {
                    coverage.first_assembler_fault = Some(fault.kind);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ncp_seed_corpus_reaches_each_declared_decoder() {
        let sidecar = exercise_ncp_decode(include_bytes!(
            "../seeds/ncp_decode/sidecar_observation.json"
        ));
        assert!(sidecar.sidecar_decoded);
        assert!(sidecar.sidecar_validated);

        let monitor = exercise_ncp_decode(include_bytes!(
            "../seeds/ncp_decode/monitor_outcome.json"
        ));
        assert!(monitor.monitor_decoded);
        assert!(monitor.monitor_validated);

        let registry = exercise_ncp_decode(include_bytes!(
            "../seeds/ncp_decode/deployment_registry.json"
        ));
        assert!(registry.registry_decoded);

        let jsonl = exercise_ncp_decode(include_bytes!(
            "../seeds/ncp_decode/diagnostic.jsonl"
        ));
        assert_eq!(jsonl.jsonl_observations, 2);
    }

    #[test]
    fn detector_seed_reaches_state_temporal_and_fused_paths() {
        let coverage = exercise_detector_boundaries(include_bytes!(
            "../seeds/detector_boundaries/projected_stream.json"
        ));

        assert!(coverage.detector_config_accepted);
        assert!(coverage.observations_decoded);
        assert_eq!(coverage.observations_retained, 6);
        assert_eq!(coverage.mirror_ingests, 6);
        assert!(coverage.mirror_assessments > 0);
        assert!(coverage.temporal_channels_attempted);
        assert!(coverage.default_assessment_attempted);
        assert!(coverage.default_assessment_accepted);
    }

    #[test]
    fn detector_rejects_frozen_prior_reuse_across_sequences() {
        let valid = std::str::from_utf8(include_bytes!(
            "../seeds/detector_boundaries/projected_stream.json"
        ))
        .expect("tracked detector seed is UTF-8");
        assert_eq!(valid.matches("\"prior_id\":30").count(), 3);
        let reused_prior = valid.replace("\"prior_id\":30", "\"prior_id\":29");
        let coverage = exercise_detector_boundaries(reused_prior.as_bytes());

        assert!(coverage.observations_decoded);
        assert!(coverage.default_assessment_attempted);
        assert!(!coverage.default_assessment_accepted);
    }

    #[test]
    fn detector_seed_reaches_invalid_config_and_valid_stream_paths() {
        let mut prefixed = Vec::from(b" ".as_slice());
        prefixed.extend_from_slice(include_bytes!(
            "../seeds/detector_boundaries/projected_stream.json"
        ));
        let coverage = exercise_detector_boundaries(&prefixed);

        assert!(!coverage.detector_config_accepted);
        assert!(coverage.observations_decoded);
        assert!(coverage.default_assessment_accepted);
    }

    #[test]
    fn raw_byte_drivers_reject_valid_but_oversize_prefixes() {
        let mut ncp =
            include_bytes!("../seeds/ncp_decode/sidecar_observation.json").to_vec();
        ncp.resize(MAX_FUZZ_INPUT_BYTES + 1, b' ');
        assert_eq!(exercise_ncp_decode(&ncp), NcpDecodeCoverage::default());

        let mut detector = include_bytes!(
            "../seeds/detector_boundaries/projected_stream.json"
        )
        .to_vec();
        detector.resize(MAX_FUZZ_INPUT_BYTES + 1, b' ');
        assert_eq!(
            exercise_detector_boundaries(&detector),
            DetectorBoundaryCoverage::default()
        );
    }

    #[test]
    fn valid_seed_reaches_assembly_and_lifecycle_commit() {
        let coverage = exercise_lifecycle_state(include_bytes!(
            "../seeds/lifecycle_state/valid_two_route_frame.json"
        ));

        assert!(coverage.scenario_decoded);
        assert_eq!(coverage.operations, 5);
        assert_eq!(coverage.observation_payloads, 2);
        assert_eq!(coverage.monitor_payloads, 3);
        assert_eq!(coverage.construction_rejections, 0);
        assert_eq!(coverage.frames_ready, 1);
        assert_eq!(coverage.lifecycle_commits, 1);
        assert_eq!(coverage.lifecycle_rejections, 0);
        assert_eq!(coverage.assembler_faults, 0);
    }

    #[test]
    fn duplicate_observation_seed_fails_closed() {
        let coverage = exercise_lifecycle_state(include_bytes!(
            "../seeds/lifecycle_state/duplicate_observation.json"
        ));

        assert!(coverage.scenario_decoded);
        assert_eq!(coverage.observation_payloads, 2);
        assert_eq!(coverage.frames_ready, 0);
        assert_eq!(coverage.lifecycle_commits, 0);
        assert_eq!(coverage.assembler_faults, 1);
        assert_eq!(
            coverage.first_assembler_fault,
            Some(AssemblyFaultKind::DuplicateOrRegressedObservation {
                track_id: 7,
                modality: Modality::Visual,
                previous: 1,
                received: 1,
            })
        );
    }

    #[test]
    fn reorder_gap_seed_reaches_deadline_fault() {
        let coverage = exercise_lifecycle_state(include_bytes!(
            "../seeds/lifecycle_state/reorder_gap_deadline.json"
        ));

        assert!(coverage.scenario_decoded);
        assert_eq!(coverage.monitor_payloads, 1);
        assert_eq!(coverage.frames_ready, 0);
        assert_eq!(coverage.lifecycle_commits, 0);
        assert_eq!(coverage.assembler_faults, 1);
        assert_eq!(
            coverage.first_assembler_fault,
            Some(AssemblyFaultKind::MonitorSequenceGap {
                expected: 1,
                next_received: 2,
            })
        );
    }

    #[test]
    fn malformed_and_valid_but_oversize_scenarios_do_not_enter_state_machine() {
        let malformed = exercise_lifecycle_state(b"{not-json");
        assert_eq!(malformed, LifecycleCoverage::default());

        let mut oversized =
            include_bytes!("../seeds/lifecycle_state/valid_two_route_frame.json").to_vec();
        oversized.resize(MAX_FUZZ_INPUT_BYTES + 1, b' ');
        assert_eq!(
            exercise_lifecycle_state(&oversized),
            LifecycleCoverage::default()
        );
    }
}
