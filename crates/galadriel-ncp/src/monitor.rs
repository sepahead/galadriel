//! Strict, transport-neutral producer-monitor wire types.
//!
//! These events complement the frozen PID observation sidecar. They describe
//! producer liveness and measurement disposition without pretending that a
//! rejected or missing measurement has a valid NIS value. Transport setup and
//! subscription lifecycle deliberately live outside this module.

use galadriel_core::observation::{ConsistencyProjection, Modality};
use ncp_core::{
    contract_status, valid_id_segment, ContractStatus, Keys, CONTRACT_HASH, DEFAULT_REALM,
    JSON_SAFE_INTEGER_MAX, NCP_VERSION,
};
use serde::{Deserialize, Serialize};

use crate::MAX_ID_SEGMENT_BYTES;

/// Stable named-perception entity carrying producer-monitor envelopes.
pub const MONITOR_SENSOR_NAME: &str = "galadriel-monitor";

/// Producer-monitor payload discriminator.
pub const MONITOR_KIND: &str = "galadriel_producer_event";

/// Current Galadriel producer-monitor schema version.
pub const MONITOR_SCHEMA_VERSION: &str = "1.0";

/// Machine-readable JSON Schema for [`MONITOR_SCHEMA_VERSION`].
pub const MONITOR_SCHEMA_JSON: &str =
    include_str!("../schemas/galadriel-monitor-envelope-v1.schema.json");

/// Largest declared heartbeat interval or deadline, in milliseconds.
pub const MAX_HEARTBEAT_DURATION_MS: u64 = 300_000;

/// Largest bounded publisher queue represented on the wire.
pub const MAX_MONITOR_QUEUE_EVENTS: u32 = 8_192;

/// Largest active-track count represented by one producer event.
pub const MAX_ACTIVE_TRACKS: u32 = 1_024;

/// Largest per-frame input, outcome, or candidate count represented on the wire.
pub const MAX_FRAME_ITEMS: u32 = 8_192;

/// Largest encoded monitor envelope accepted after transport framing.
pub const MAX_MONITOR_EVENT_BYTES: usize = 64 * 1_024;

/// SHA-256 registry digest length in lowercase hexadecimal characters.
pub const REGISTRY_DIGEST_HEX_LEN: usize = 64;

/// A validated producer-monitor envelope.
///
/// `event_seq` is global across all event variants within one producer session.
/// It starts at one and must strictly increase. A gap is a valid encoding of
/// producer/transport loss, but operational consumers must surface it as a fault
/// via [`MonitorEnvelope::validate_next`]. A producer that resets the counter must
/// mint a fresh `session_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorEnvelope {
    /// Stable discriminator, [`MONITOR_KIND`].
    pub kind: String,
    /// Galadriel-owned monitor schema, [`MONITOR_SCHEMA_VERSION`].
    pub schema_version: String,
    /// NCP wire version governing the named-perception route.
    pub ncp_version: String,
    /// Advisory identity of the NCP contract revision used by the producer.
    pub contract_hash: String,
    /// NCP session and producer epoch.
    pub session_id: String,
    /// Concrete producer identifier.
    pub producer_id: String,
    /// Globally monotonic event sequence within this producer session.
    pub event_seq: u64,
    /// Typed producer event.
    pub event: ProducerEvent,
}

/// One producer-monitor event, adjacent-tagged as `{ "type", "data" }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProducerEvent {
    /// Periodic producer and publisher health declaration.
    Heartbeat(Heartbeat),
    /// Disposition of a measurement or association attempt.
    ModalityOutcome(ModalityOutcome),
    /// Explicit absence of a modality result for an active track.
    ModalityMiss(ModalityMiss),
    /// Bounded whole-frame accounting record.
    FrameSummary(FrameSummary),
}

/// Periodic producer liveness and bounded publisher health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heartbeat {
    /// Producer wall-clock timestamp in milliseconds.
    pub producer_timestamp_ms: u64,
    /// Monotonic producer uptime in milliseconds for restart diagnosis.
    pub uptime_ms: u64,
    /// Declared heartbeat emission interval in milliseconds.
    pub declared_interval_ms: u64,
    /// Declared receiver deadline in milliseconds.
    pub declared_deadline_ms: u64,
    /// Most recent fusion sequence observed by the publisher, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_fusion_seq: Option<u64>,
    /// Number of currently active tracks.
    pub active_track_count: u32,
    /// Whether any loss or publication fault has degraded this epoch.
    pub degraded: bool,
    /// Current publisher queue state and cumulative counters.
    pub queue_health: QueueHealth,
}

/// Bounded publisher queue state and cumulative health counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueHealth {
    /// Configured event capacity of the publisher queue.
    pub capacity: u32,
    /// Events currently waiting in the publisher queue.
    pub depth: u32,
    /// Cumulative events dropped during this producer session.
    pub dropped_event_count: u64,
    /// Cumulative events successfully published during this producer session.
    pub published_event_count: u64,
}

/// Disposition of a modality measurement or association attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModalityOutcome {
    /// Fusion frame sequence assigned by the producer.
    pub fusion_seq: u64,
    /// Fusion frame timestamp in milliseconds.
    pub fusion_timestamp_ms: u64,
    /// Registered common physical frame for this fusion frame.
    pub frame_id: u64,
    /// Registered projection/calibration context for this fusion frame.
    pub context_id: u64,
    /// Globally unique frozen-prior identifier for this fusion frame.
    pub prior_id: u64,
    /// Numeric track identifier.
    pub track_id: u64,
    /// Sensor modality being accounted for.
    pub modality: Modality,
    /// Deterministic opportunity index for this track/modality/frame.
    pub attempt_index: u32,
    /// Zero-based index into the producer's bounded frame input, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_index: Option<u32>,
    /// Typed disposition.
    pub outcome: ModalityOutcomeKind,
    /// Whether exactly one matching frozen-v1 observation must be published.
    pub v1_expected: bool,
    /// Aggregate candidate measurements considered for this track and modality.
    /// This pair-level count is repeated on every attempt outcome.
    pub candidate_count: u32,
    /// Aggregate candidates for this track and modality that passed the producer's
    /// gate. This may be nonzero on one `gate_rejected` attempt when a different
    /// candidate in the same pair passed.
    pub in_gate_count: u32,
    /// Gate score for the selected or nearest candidate. Required whenever the
    /// typed outcome claims that candidate gating was performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_evidence: Option<GateEvidence>,
    /// Common frozen-prior residual projection, when the producer can attest it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_projection: Option<ConsistencyProjection>,
}

/// Measurement or association disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModalityOutcomeKind {
    /// The associated measurement updated the track.
    Updated,
    /// Candidate measurements existed, but none passed the gate.
    GateRejected,
    /// At least one candidate passed the gate, but assignment selected none.
    AssignmentRejected,
    /// Assignment succeeded, but the filter rejected the update.
    UpdateRejected,
    /// An unassigned measurement created this track.
    TrackBirth,
    /// The track/filter combination cannot consume this modality.
    UnsupportedFilter,
    /// The measurement updated the baseline path but could not be projected into
    /// the registered common frame.
    IncomparableProjection,
}

/// Numeric evidence used by a producer's measurement gate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateEvidence {
    /// Gate computation used by the producer.
    pub method: GateMethod,
    /// Squared distance or normalized-Euclidean fallback score.
    pub d2: f64,
    /// Acceptance threshold in the same score space as `d2`.
    pub threshold: f64,
}

/// Producer gate computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateMethod {
    /// Covariance-aware squared Mahalanobis distance.
    Mahalanobis,
    /// Normalized-Euclidean fallback when covariance gating is unavailable.
    NormalizedEuclideanFallback,
}

/// Explicit absence of a modality result for an active track.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModalityMiss {
    /// Fusion frame sequence assigned by the producer.
    pub fusion_seq: u64,
    /// Fusion frame timestamp in milliseconds.
    pub fusion_timestamp_ms: u64,
    /// Registered common physical frame for this fusion frame.
    pub frame_id: u64,
    /// Registered projection/calibration context for this fusion frame.
    pub context_id: u64,
    /// Globally unique frozen-prior identifier for this fusion frame.
    pub prior_id: u64,
    /// Numeric track identifier.
    pub track_id: u64,
    /// Missing sensor modality.
    pub modality: Modality,
    /// Typed explanation for the missing result.
    pub reason: ModalityMissReason,
}

/// Reason that an expected track/modality pair produced no outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModalityMissReason {
    /// The frame contained no measurement for this modality.
    NoMeasurement,
    /// Measurements existed, but none were candidates for this track.
    NoCandidate,
    /// Candidates existed, but none passed the gate.
    NoInGateCandidate,
    /// In-gate candidates existed, but assignment selected another track.
    NotAssigned,
    /// The track was not eligible for this modality in the current frame.
    TrackNotEligible,
}

/// Bounded accounting summary for one fusion frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameSummary {
    /// Fusion frame sequence assigned by the producer.
    pub fusion_seq: u64,
    /// Fusion frame timestamp in milliseconds.
    pub fusion_timestamp_ms: u64,
    /// Registered common physical frame for this fusion frame.
    pub frame_id: u64,
    /// Registered projection/calibration context for this fusion frame.
    pub context_id: u64,
    /// Globally unique frozen-prior identifier for this fusion frame.
    pub prior_id: u64,
    /// Lowercase SHA-256 digest of the pinned frame/context registry.
    pub registry_digest: String,
    /// Unique modalities configured as expected for this frame.
    pub expected_modalities: Vec<Modality>,
    /// Number of active tracks after processing this frame.
    pub active_track_count: u32,
    /// Number of input measurements accepted into bounded frame processing.
    pub input_count: u32,
    /// Number of outcome and miss events represented for this frame.
    pub outcome_count: u32,
    /// Number of outcome events requiring a matching frozen-v1 observation.
    pub v1_expected_count: u32,
    /// Whether any producer loss or accounting fault degraded this frame.
    pub degraded: bool,
    /// Whether producer-side bounds prevented complete frame accounting.
    pub truncated: bool,
}

/// Semantic failure in a decoded [`MonitorEnvelope`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MonitorError {
    /// The payload discriminator does not identify the monitor sidecar.
    #[error("invalid monitor kind: got {received:?}, want {MONITOR_KIND:?}")]
    InvalidKind { received: String },
    /// The Galadriel-owned monitor schema is not supported.
    #[error(
        "unsupported monitor schema version: got {received:?}, want {MONITOR_SCHEMA_VERSION:?}"
    )]
    UnsupportedSchemaVersion { received: String },
    /// The NCP wire version is malformed or incompatible.
    #[error("incompatible NCP version in monitor envelope: {0}")]
    IncompatibleNcpVersion(String),
    /// The advertised contract hash is not canonical lowercase 64-bit hex.
    #[error("invalid NCP contract hash in monitor envelope: {0:?}")]
    InvalidContractHash(String),
    /// The declared session is unsafe as an NCP key segment.
    #[error("invalid monitor session_id: {0:?}")]
    InvalidSessionId(String),
    /// The declared producer is unsafe as an NCP key segment.
    #[error("invalid monitor producer_id: {0:?}")]
    InvalidProducerId(String),
    /// The payload declares different provenance from the subscribed stream.
    #[error("monitor {field} mismatch: got {received:?}, expected {expected:?}")]
    ProvenanceMismatch {
        /// Identity field that differs.
        field: &'static str,
        /// Value bound by the consumer.
        expected: String,
        /// Value claimed by the payload.
        received: String,
    },
    /// A numeric value cannot round-trip through every NCP JSON peer.
    #[error("monitor {field} exceeds the NCP exact JSON integer range: {value}")]
    IntegerOutOfRange {
        /// Invalid field.
        field: &'static str,
        /// Invalid value.
        value: u64,
    },
    /// A registry/provenance identifier that must be positive was zero.
    #[error("monitor {field} must be greater than zero")]
    ZeroIdentifier {
        /// Invalid field.
        field: &'static str,
    },
    /// The registry digest is not canonical lowercase SHA-256 hexadecimal.
    #[error("invalid monitor registry digest: {0:?}")]
    InvalidRegistryDigest(String),
    /// The encoded event exceeds the application contract bound.
    #[error("monitor event has {actual} bytes, maximum {maximum}")]
    EncodedEventTooLarge {
        /// Encoded byte length.
        actual: usize,
        /// Contract ceiling.
        maximum: usize,
    },
    /// JSON decoding or encoding failed.
    #[error("invalid monitor JSON: {0}")]
    Json(String),
    /// An event sequence must start at one.
    #[error("monitor event_seq must be at least 1")]
    ZeroEventSequence,
    /// An event sequence did not advance globally within the producer session.
    #[error("monitor event_seq {received} is not newer than {previous}")]
    NonMonotonicEventSequence {
        /// Previously accepted event sequence.
        previous: u64,
        /// Candidate event sequence.
        received: u64,
    },
    /// An operational stream skipped one or more assigned event sequences.
    #[error("monitor event_seq gap: got {received}, expected {expected}")]
    EventSequenceGap {
        /// Next contiguous sequence.
        expected: u64,
        /// Candidate event sequence.
        received: u64,
    },
    /// A heartbeat interval or deadline is zero or exceeds its fixed ceiling.
    #[error("monitor {field} must be in 1..={MAX_HEARTBEAT_DURATION_MS} ms, got {value}")]
    HeartbeatDurationOutOfRange {
        /// Invalid duration field.
        field: &'static str,
        /// Invalid duration.
        value: u64,
    },
    /// A heartbeat deadline is shorter than its declared interval.
    #[error(
        "monitor heartbeat deadline {deadline_ms} ms is shorter than interval {interval_ms} ms"
    )]
    HeartbeatDeadlineBeforeInterval {
        /// Declared interval.
        interval_ms: u64,
        /// Declared deadline.
        deadline_ms: u64,
    },
    /// A bounded count exceeds its contract ceiling.
    #[error("monitor {field} exceeds maximum {maximum}: {value}")]
    CountOutOfRange {
        /// Invalid count field.
        field: &'static str,
        /// Invalid count.
        value: u64,
        /// Contract ceiling.
        maximum: u64,
    },
    /// Queue depth exceeds the declared queue capacity.
    #[error("monitor queue depth {depth} exceeds capacity {capacity}")]
    QueueDepthExceedsCapacity {
        /// Declared capacity.
        capacity: u32,
        /// Observed depth.
        depth: u32,
    },
    /// Gate evidence is non-finite or negative.
    #[error("monitor gate field {field} must be finite and nonnegative")]
    InvalidGateValue {
        /// Invalid gate field.
        field: &'static str,
    },
    /// Event fields disagree with the typed outcome.
    #[error("incoherent monitor event: {0}")]
    EventCoherence(&'static str),
    /// A common-prior residual projection is invalid.
    #[error("invalid monitor consistency projection: {0}")]
    InvalidConsistencyProjection(String),
    /// A frame summary declares no expected modalities.
    #[error("monitor frame summary must declare at least one expected modality")]
    EmptyExpectedModalities,
    /// A frame summary repeats an expected modality.
    #[error("monitor frame summary repeats expected modality {modality:?}")]
    DuplicateExpectedModality {
        /// Repeated modality.
        modality: Modality,
    },
}

impl MonitorEnvelope {
    /// Construct and validate an envelope stamped with local NCP identities.
    pub fn try_new(
        session_id: impl Into<String>,
        producer_id: impl Into<String>,
        event_seq: u64,
        event: ProducerEvent,
    ) -> Result<Self, MonitorError> {
        let envelope = Self {
            kind: MONITOR_KIND.to_string(),
            schema_version: MONITOR_SCHEMA_VERSION.to_string(),
            ncp_version: NCP_VERSION.to_string(),
            contract_hash: CONTRACT_HASH.to_string(),
            session_id: session_id.into(),
            producer_id: producer_id.into(),
            event_seq,
            event,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validate identity, NCP compatibility, JSON-safe integers, and event semantics.
    ///
    /// A well-formed but different `contract_hash` remains advisory, matching the
    /// existing sidecar and NCP handshake policy.
    pub fn validate(&self) -> Result<ContractStatus, MonitorError> {
        if self.kind != MONITOR_KIND {
            return Err(MonitorError::InvalidKind {
                received: self.kind.clone(),
            });
        }
        if self.schema_version != MONITOR_SCHEMA_VERSION {
            return Err(MonitorError::UnsupportedSchemaVersion {
                received: self.schema_version.clone(),
            });
        }
        if self.ncp_version != NCP_VERSION {
            return Err(MonitorError::IncompatibleNcpVersion(format!(
                "noncanonical ncp_version {:?}; expected {NCP_VERSION:?}",
                self.ncp_version
            )));
        }
        ncp_core::check_version(&self.ncp_version, true)
            .map_err(|error| MonitorError::IncompatibleNcpVersion(error.to_string()))?;
        validate_contract_hash(&self.contract_hash)?;
        validate_identity(&self.session_id, true)?;
        validate_identity(&self.producer_id, false)?;
        if self.event_seq == 0 {
            return Err(MonitorError::ZeroEventSequence);
        }
        validate_json_integer("event_seq", self.event_seq)?;
        self.event.validate()?;
        Ok(contract_status(Some(&self.contract_hash)))
    }

    /// Validate and bind claimed provenance to a concrete subscription.
    pub fn validate_for(
        &self,
        expected_session_id: &str,
        expected_producer_id: &str,
    ) -> Result<ContractStatus, MonitorError> {
        let status = self.validate()?;
        if self.session_id != expected_session_id {
            return Err(MonitorError::ProvenanceMismatch {
                field: "session_id",
                expected: expected_session_id.to_string(),
                received: self.session_id.clone(),
            });
        }
        if self.producer_id != expected_producer_id {
            return Err(MonitorError::ProvenanceMismatch {
                field: "producer_id",
                expected: expected_producer_id.to_string(),
                received: self.producer_id.clone(),
            });
        }
        Ok(status)
    }

    /// Validate that this event is newer than the last accepted global sequence.
    ///
    /// Pass zero before accepting the first event in a fresh producer session.
    pub fn validate_after(&self, previous_event_seq: u64) -> Result<ContractStatus, MonitorError> {
        validate_json_integer("previous_event_seq", previous_event_seq)?;
        let status = self.validate()?;
        if self.event_seq <= previous_event_seq {
            return Err(MonitorError::NonMonotonicEventSequence {
                previous: previous_event_seq,
                received: self.event_seq,
            });
        }
        Ok(status)
    }

    /// Validate the exact next event in a loss-intolerant operational stream.
    ///
    /// Pass zero for the first event of a fresh epoch. Unlike [`Self::validate_after`],
    /// this rejects gaps so bounded queue loss cannot masquerade as completeness.
    pub fn validate_next(&self, previous_event_seq: u64) -> Result<ContractStatus, MonitorError> {
        let status = self.validate_after(previous_event_seq)?;
        let expected =
            previous_event_seq
                .checked_add(1)
                .ok_or(MonitorError::IntegerOutOfRange {
                    field: "previous_event_seq",
                    value: previous_event_seq,
                })?;
        if self.event_seq != expected {
            return Err(MonitorError::EventSequenceGap {
                expected,
                received: self.event_seq,
            });
        }
        Ok(status)
    }

    /// Serialize a semantically valid envelope under the fixed encoded-size cap.
    pub fn encode(&self) -> Result<Vec<u8>, MonitorError> {
        self.validate()?;
        let encoded =
            serde_json::to_vec(self).map_err(|error| MonitorError::Json(error.to_string()))?;
        validate_encoded_size(encoded.len())?;
        Ok(encoded)
    }

    /// Decode and semantically validate one bounded envelope.
    pub fn decode(encoded: &[u8]) -> Result<Self, MonitorError> {
        validate_encoded_size(encoded.len())?;
        let envelope: Self = serde_json::from_slice(encoded)
            .map_err(|error| MonitorError::Json(error.to_string()))?;
        envelope.validate()?;
        Ok(envelope)
    }
}

impl ProducerEvent {
    /// Validate all semantic invariants of this event payload.
    pub fn validate(&self) -> Result<(), MonitorError> {
        match self {
            Self::Heartbeat(heartbeat) => heartbeat.validate(),
            Self::ModalityOutcome(outcome) => outcome.validate(),
            Self::ModalityMiss(miss) => miss.validate(),
            Self::FrameSummary(summary) => summary.validate(),
        }
    }
}

impl Heartbeat {
    /// Validate liveness durations, counters, and bounded queue state.
    pub fn validate(&self) -> Result<(), MonitorError> {
        validate_json_integer("event.producer_timestamp_ms", self.producer_timestamp_ms)?;
        validate_json_integer("event.uptime_ms", self.uptime_ms)?;
        validate_heartbeat_duration("event.declared_interval_ms", self.declared_interval_ms)?;
        validate_heartbeat_duration("event.declared_deadline_ms", self.declared_deadline_ms)?;
        if self.declared_deadline_ms < self.declared_interval_ms {
            return Err(MonitorError::HeartbeatDeadlineBeforeInterval {
                interval_ms: self.declared_interval_ms,
                deadline_ms: self.declared_deadline_ms,
            });
        }
        if let Some(last_fusion_seq) = self.last_fusion_seq {
            validate_json_integer("event.last_fusion_seq", last_fusion_seq)?;
        }
        validate_count(
            "event.active_track_count",
            self.active_track_count,
            MAX_ACTIVE_TRACKS,
        )?;
        self.queue_health.validate()?;
        if self.queue_health.dropped_event_count > 0 && !self.degraded {
            return Err(MonitorError::EventCoherence(
                "heartbeat with dropped events must be degraded",
            ));
        }
        Ok(())
    }
}

impl QueueHealth {
    /// Validate bounded queue occupancy and cumulative counters.
    pub fn validate(&self) -> Result<(), MonitorError> {
        if self.capacity == 0 || self.capacity > MAX_MONITOR_QUEUE_EVENTS {
            return Err(MonitorError::CountOutOfRange {
                field: "event.queue_health.capacity",
                value: u64::from(self.capacity),
                maximum: u64::from(MAX_MONITOR_QUEUE_EVENTS),
            });
        }
        if self.depth > self.capacity {
            return Err(MonitorError::QueueDepthExceedsCapacity {
                capacity: self.capacity,
                depth: self.depth,
            });
        }
        validate_json_integer(
            "event.queue_health.dropped_event_count",
            self.dropped_event_count,
        )?;
        validate_json_integer(
            "event.queue_health.published_event_count",
            self.published_event_count,
        )
    }
}

impl ModalityOutcome {
    /// Validate frame identities, bounded counts, gate evidence, and outcome coherence.
    pub fn validate(&self) -> Result<(), MonitorError> {
        validate_frame_identity(
            self.fusion_seq,
            self.fusion_timestamp_ms,
            self.frame_id,
            self.context_id,
            self.prior_id,
            Some(self.track_id),
        )?;
        if self.attempt_index >= MAX_FRAME_ITEMS {
            return Err(MonitorError::CountOutOfRange {
                field: "event.attempt_index",
                value: u64::from(self.attempt_index),
                maximum: u64::from(MAX_FRAME_ITEMS - 1),
            });
        }
        if let Some(measurement_index) = self.measurement_index {
            if measurement_index >= MAX_FRAME_ITEMS {
                return Err(MonitorError::CountOutOfRange {
                    field: "event.measurement_index",
                    value: u64::from(measurement_index),
                    maximum: u64::from(MAX_FRAME_ITEMS - 1),
                });
            }
        }
        validate_count(
            "event.candidate_count",
            self.candidate_count,
            MAX_FRAME_ITEMS,
        )?;
        validate_count("event.in_gate_count", self.in_gate_count, MAX_FRAME_ITEMS)?;
        if self.in_gate_count > self.candidate_count {
            return Err(MonitorError::EventCoherence(
                "in_gate_count cannot exceed candidate_count",
            ));
        }
        if let Some(evidence) = self.gate_evidence {
            evidence.validate()?;
        }
        if let Some(projection) = self.consistency_projection {
            validate_projection(&projection)?;
            if projection.frame_id != self.frame_id
                || projection.context_id != self.context_id
                || projection.prior_id != self.prior_id
            {
                return Err(MonitorError::EventCoherence(
                    "consistency projection provenance must match the outcome frame",
                ));
            }
        }
        if self.v1_expected
            && !matches!(
                self.outcome,
                ModalityOutcomeKind::Updated | ModalityOutcomeKind::IncomparableProjection
            )
        {
            return Err(MonitorError::EventCoherence(
                "only an updated or incomparable-projection outcome may require v1",
            ));
        }
        if self.outcome == ModalityOutcomeKind::Updated && !self.v1_expected {
            return Err(MonitorError::EventCoherence(
                "updated outcomes must require their matching v1 observation",
            ));
        }

        match self.outcome {
            ModalityOutcomeKind::Updated | ModalityOutcomeKind::UpdateRejected => {
                require_measurement_index(self.measurement_index, self.outcome)?;
                require_candidates(self.candidate_count, self.in_gate_count, self.outcome)?;
                require_accepted_gate(self.gate_evidence)?;
                if matches!(self.outcome, ModalityOutcomeKind::Updated)
                    && self.consistency_projection.is_none()
                {
                    return Err(MonitorError::EventCoherence(
                        "updated requires a consistency projection",
                    ));
                }
            }
            ModalityOutcomeKind::GateRejected => {
                if self.candidate_count == 0 {
                    return Err(MonitorError::EventCoherence(
                        "gate_rejected requires at least one pair-level candidate",
                    ));
                }
                let evidence = self.gate_evidence.ok_or(MonitorError::EventCoherence(
                    "gate_rejected requires gate_evidence",
                ))?;
                if evidence.d2 < evidence.threshold {
                    return Err(MonitorError::EventCoherence(
                        "gate_rejected evidence must meet or exceed its threshold",
                    ));
                }
            }
            ModalityOutcomeKind::AssignmentRejected => {
                if self.in_gate_count == 0 {
                    return Err(MonitorError::EventCoherence(
                        "assignment_rejected requires at least one in-gate candidate",
                    ));
                }
                require_accepted_gate(self.gate_evidence)?;
            }
            ModalityOutcomeKind::TrackBirth => {
                require_measurement_index(self.measurement_index, self.outcome)?;
                if self.candidate_count != 0
                    || self.in_gate_count != 0
                    || self.gate_evidence.is_some()
                    || self.consistency_projection.is_some()
                {
                    return Err(MonitorError::EventCoherence(
                        "track_birth requires zero gate counts and no gate or prior evidence",
                    ));
                }
            }
            ModalityOutcomeKind::UnsupportedFilter => {
                require_measurement_index(self.measurement_index, self.outcome)?;
                if self.gate_evidence.is_some() {
                    return Err(MonitorError::EventCoherence(
                        "unsupported_filter cannot claim gate evidence",
                    ));
                }
            }
            ModalityOutcomeKind::IncomparableProjection => {
                require_measurement_index(self.measurement_index, self.outcome)?;
                require_candidates(self.candidate_count, self.in_gate_count, self.outcome)?;
                require_accepted_gate(self.gate_evidence)?;
                if self.consistency_projection.is_some() {
                    return Err(MonitorError::EventCoherence(
                        "incomparable_projection cannot carry a consistency projection",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl GateEvidence {
    /// Validate finite, nonnegative gate values.
    pub fn validate(self) -> Result<(), MonitorError> {
        validate_gate_value("event.gate_evidence.d2", self.d2)?;
        validate_gate_value("event.gate_evidence.threshold", self.threshold)
    }
}

impl ModalityMiss {
    /// Validate frame identities carried by a miss event.
    pub fn validate(&self) -> Result<(), MonitorError> {
        validate_frame_identity(
            self.fusion_seq,
            self.fusion_timestamp_ms,
            self.frame_id,
            self.context_id,
            self.prior_id,
            Some(self.track_id),
        )
    }
}

impl FrameSummary {
    /// Validate frame identities, bounded accounting, and modality uniqueness.
    pub fn validate(&self) -> Result<(), MonitorError> {
        validate_frame_identity(
            self.fusion_seq,
            self.fusion_timestamp_ms,
            self.frame_id,
            self.context_id,
            self.prior_id,
            None,
        )?;
        validate_registry_digest(&self.registry_digest)?;
        validate_count(
            "event.active_track_count",
            self.active_track_count,
            MAX_ACTIVE_TRACKS,
        )?;
        validate_count("event.input_count", self.input_count, MAX_FRAME_ITEMS)?;
        validate_count("event.outcome_count", self.outcome_count, MAX_FRAME_ITEMS)?;
        validate_count(
            "event.v1_expected_count",
            self.v1_expected_count,
            MAX_FRAME_ITEMS,
        )?;
        if self.v1_expected_count > self.outcome_count {
            return Err(MonitorError::EventCoherence(
                "v1_expected_count cannot exceed outcome_count",
            ));
        }
        if self.truncated && !self.degraded {
            return Err(MonitorError::EventCoherence(
                "a truncated frame summary must be degraded",
            ));
        }
        if self.expected_modalities.is_empty() {
            return Err(MonitorError::EmptyExpectedModalities);
        }
        let mut seen = [false; Modality::ALL.len()];
        for modality in &self.expected_modalities {
            let index = modality_index(*modality);
            if seen[index] {
                return Err(MonitorError::DuplicateExpectedModality {
                    modality: *modality,
                });
            }
            seen[index] = true;
        }
        Ok(())
    }
}

/// The named perception-plane monitor route:
/// `{realm}/session/{id}/sensor/galadriel-monitor`.
pub fn monitor_key(realm: &str, session_id: &str) -> Option<String> {
    if !valid_id_segment(session_id) || session_id.len() > MAX_ID_SEGMENT_BYTES {
        return None;
    }
    Keys::try_new(realm)
        .ok()?
        .try_sensor_named(session_id, MONITOR_SENSOR_NAME)
        .ok()
}

/// [`monitor_key`] on the default NCP realm.
pub fn default_monitor_key(session_id: &str) -> Option<String> {
    monitor_key(DEFAULT_REALM, session_id)
}

fn validate_contract_hash(contract_hash: &str) -> Result<(), MonitorError> {
    if contract_hash.len() != CONTRACT_HASH.len()
        || !contract_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MonitorError::InvalidContractHash(contract_hash.to_string()));
    }
    Ok(())
}

fn validate_identity(identity: &str, session: bool) -> Result<(), MonitorError> {
    if valid_id_segment(identity) && identity.len() <= MAX_ID_SEGMENT_BYTES {
        return Ok(());
    }
    if session {
        Err(MonitorError::InvalidSessionId(identity.to_string()))
    } else {
        Err(MonitorError::InvalidProducerId(identity.to_string()))
    }
}

fn validate_json_integer(field: &'static str, value: u64) -> Result<(), MonitorError> {
    if value > JSON_SAFE_INTEGER_MAX as u64 {
        return Err(MonitorError::IntegerOutOfRange { field, value });
    }
    Ok(())
}

fn validate_positive_json_integer(field: &'static str, value: u64) -> Result<(), MonitorError> {
    if value == 0 {
        return Err(MonitorError::ZeroIdentifier { field });
    }
    validate_json_integer(field, value)
}

fn validate_encoded_size(actual: usize) -> Result<(), MonitorError> {
    if actual > MAX_MONITOR_EVENT_BYTES {
        return Err(MonitorError::EncodedEventTooLarge {
            actual,
            maximum: MAX_MONITOR_EVENT_BYTES,
        });
    }
    Ok(())
}

fn validate_registry_digest(digest: &str) -> Result<(), MonitorError> {
    if digest.len() != REGISTRY_DIGEST_HEX_LEN
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MonitorError::InvalidRegistryDigest(digest.to_string()));
    }
    Ok(())
}

fn validate_heartbeat_duration(field: &'static str, value: u64) -> Result<(), MonitorError> {
    if value == 0 || value > MAX_HEARTBEAT_DURATION_MS {
        return Err(MonitorError::HeartbeatDurationOutOfRange { field, value });
    }
    Ok(())
}

fn validate_count(field: &'static str, value: u32, maximum: u32) -> Result<(), MonitorError> {
    if value > maximum {
        return Err(MonitorError::CountOutOfRange {
            field,
            value: u64::from(value),
            maximum: u64::from(maximum),
        });
    }
    Ok(())
}

fn validate_frame_identity(
    fusion_seq: u64,
    fusion_timestamp_ms: u64,
    frame_id: u64,
    context_id: u64,
    prior_id: u64,
    track_id: Option<u64>,
) -> Result<(), MonitorError> {
    validate_json_integer("event.fusion_seq", fusion_seq)?;
    validate_json_integer("event.fusion_timestamp_ms", fusion_timestamp_ms)?;
    validate_positive_json_integer("event.frame_id", frame_id)?;
    validate_positive_json_integer("event.context_id", context_id)?;
    validate_positive_json_integer("event.prior_id", prior_id)?;
    if let Some(track_id) = track_id {
        validate_positive_json_integer("event.track_id", track_id)?;
    }
    Ok(())
}

fn validate_projection(projection: &ConsistencyProjection) -> Result<(), MonitorError> {
    projection
        .validate()
        .map_err(|error| MonitorError::InvalidConsistencyProjection(error.to_string()))?;
    validate_json_integer("event.consistency_projection.frame_id", projection.frame_id)?;
    validate_json_integer(
        "event.consistency_projection.context_id",
        projection.context_id,
    )?;
    validate_json_integer("event.consistency_projection.prior_id", projection.prior_id)
}

fn validate_gate_value(field: &'static str, value: f64) -> Result<(), MonitorError> {
    if !value.is_finite() || value < 0.0 {
        return Err(MonitorError::InvalidGateValue { field });
    }
    Ok(())
}

fn require_measurement_index(
    measurement_index: Option<u32>,
    outcome: ModalityOutcomeKind,
) -> Result<(), MonitorError> {
    if measurement_index.is_none() {
        return Err(MonitorError::EventCoherence(match outcome {
            ModalityOutcomeKind::Updated => "updated requires measurement_index",
            ModalityOutcomeKind::UpdateRejected => "update_rejected requires measurement_index",
            ModalityOutcomeKind::TrackBirth => "track_birth requires measurement_index",
            ModalityOutcomeKind::UnsupportedFilter => {
                "unsupported_filter requires measurement_index"
            }
            ModalityOutcomeKind::IncomparableProjection => {
                "incomparable_projection requires measurement_index"
            }
            ModalityOutcomeKind::GateRejected | ModalityOutcomeKind::AssignmentRejected => {
                "outcome requires measurement_index"
            }
        }));
    }
    Ok(())
}

fn require_candidates(
    candidate_count: u32,
    in_gate_count: u32,
    outcome: ModalityOutcomeKind,
) -> Result<(), MonitorError> {
    if candidate_count == 0 || in_gate_count == 0 {
        return Err(MonitorError::EventCoherence(match outcome {
            ModalityOutcomeKind::Updated => {
                "updated requires at least one candidate and in-gate candidate"
            }
            ModalityOutcomeKind::UpdateRejected => {
                "update_rejected requires at least one candidate and in-gate candidate"
            }
            ModalityOutcomeKind::GateRejected
            | ModalityOutcomeKind::AssignmentRejected
            | ModalityOutcomeKind::TrackBirth
            | ModalityOutcomeKind::UnsupportedFilter
            | ModalityOutcomeKind::IncomparableProjection => {
                "outcome requires at least one candidate and in-gate candidate"
            }
        }));
    }
    Ok(())
}

fn require_accepted_gate(gate_evidence: Option<GateEvidence>) -> Result<(), MonitorError> {
    let evidence = gate_evidence.ok_or(MonitorError::EventCoherence(
        "gate-dependent outcome requires gate_evidence",
    ))?;
    if evidence.d2 >= evidence.threshold {
        return Err(MonitorError::EventCoherence(
            "accepted gate evidence must be below its threshold",
        ));
    }
    Ok(())
}

fn modality_index(modality: Modality) -> usize {
    match modality {
        Modality::Visual => 0,
        Modality::Thermal => 1,
        Modality::Acoustic => 2,
        Modality::Radar => 3,
        Modality::Lidar => 4,
        Modality::RadioFrequency => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue_health() -> QueueHealth {
        QueueHealth {
            capacity: 2,
            depth: 1,
            dropped_event_count: 3,
            published_event_count: 7,
        }
    }

    fn heartbeat() -> Heartbeat {
        Heartbeat {
            producer_timestamp_ms: 1_700_000_000_000,
            uptime_ms: 12_345,
            declared_interval_ms: 1_000,
            declared_deadline_ms: 3_000,
            last_fusion_seq: Some(41),
            active_track_count: 2,
            degraded: true,
            queue_health: queue_health(),
        }
    }

    fn registry_digest() -> String {
        "a".repeat(REGISTRY_DIGEST_HEX_LEN)
    }

    fn gate_evidence() -> GateEvidence {
        GateEvidence {
            method: GateMethod::Mahalanobis,
            d2: 2.5,
            threshold: 7.815,
        }
    }

    fn projection() -> ConsistencyProjection {
        ConsistencyProjection {
            values: [1.0, -2.0, 0.0],
            dimensions: 2,
            frame_id: 17,
            context_id: 23,
            prior_id: 29,
        }
    }

    fn outcome(kind: ModalityOutcomeKind) -> ModalityOutcome {
        ModalityOutcome {
            fusion_seq: 41,
            fusion_timestamp_ms: 1_700_000_000_000,
            frame_id: 17,
            context_id: 23,
            prior_id: 29,
            track_id: 42,
            modality: Modality::Radar,
            attempt_index: 0,
            measurement_index: Some(3),
            outcome: kind,
            v1_expected: matches!(kind, ModalityOutcomeKind::Updated),
            candidate_count: 2,
            in_gate_count: 1,
            gate_evidence: Some(gate_evidence()),
            consistency_projection: Some(projection()),
        }
    }

    fn valid_outcome(kind: ModalityOutcomeKind) -> ModalityOutcome {
        let mut value = outcome(kind);
        value.v1_expected = matches!(
            kind,
            ModalityOutcomeKind::Updated | ModalityOutcomeKind::IncomparableProjection
        );
        match kind {
            ModalityOutcomeKind::Updated
            | ModalityOutcomeKind::AssignmentRejected
            | ModalityOutcomeKind::UpdateRejected => {}
            ModalityOutcomeKind::GateRejected => {
                value.in_gate_count = 0;
                value.gate_evidence = Some(GateEvidence {
                    d2: 3.0,
                    threshold: 3.0,
                    ..gate_evidence()
                });
            }
            ModalityOutcomeKind::TrackBirth => {
                value.candidate_count = 0;
                value.in_gate_count = 0;
                value.gate_evidence = None;
                value.consistency_projection = None;
            }
            ModalityOutcomeKind::UnsupportedFilter => {
                value.gate_evidence = None;
            }
            ModalityOutcomeKind::IncomparableProjection => {
                value.consistency_projection = None;
            }
        }
        value
    }

    #[test]
    fn monitor_envelope_golden_contract_is_frozen() {
        let envelope = MonitorEnvelope::try_new(
            "uav3",
            "crebain",
            8,
            ProducerEvent::ModalityOutcome(outcome(ModalityOutcomeKind::Updated)),
        )
        .unwrap();
        let expected = concat!(
            r#"{"kind":"galadriel_producer_event","schema_version":"1.0","#,
            r#""ncp_version":"0.8","contract_hash":"d1b50a2d8a265276","#,
            r#""session_id":"uav3","producer_id":"crebain","event_seq":8,"#,
            r#""event":{"type":"modality_outcome","data":{"fusion_seq":41,"#,
            r#""fusion_timestamp_ms":1700000000000,"frame_id":17,"context_id":23,"#,
            r#""prior_id":29,"track_id":42,"modality":"radar","attempt_index":0,"#,
            r#""measurement_index":3,"outcome":"updated","v1_expected":true,"candidate_count":2,"#,
            r#""in_gate_count":1,"gate_evidence":{"method":"mahalanobis","d2":2.5,"#,
            r#""threshold":7.815},"consistency_projection":{"values":[1.0,-2.0,0.0],"#,
            r#""dimensions":2,"frame_id":17,"context_id":23,"prior_id":29}}}}"#
        );

        assert_eq!(serde_json::to_string(&envelope).unwrap(), expected);
    }

    #[test]
    fn all_event_variants_roundtrip() {
        let events = [
            ProducerEvent::Heartbeat(heartbeat()),
            ProducerEvent::ModalityOutcome(outcome(ModalityOutcomeKind::Updated)),
            ProducerEvent::ModalityMiss(ModalityMiss {
                fusion_seq: 41,
                fusion_timestamp_ms: 1_700_000_000_000,
                frame_id: 17,
                context_id: 23,
                prior_id: 29,
                track_id: 42,
                modality: Modality::Visual,
                reason: ModalityMissReason::NoMeasurement,
            }),
            ProducerEvent::FrameSummary(FrameSummary {
                fusion_seq: 41,
                fusion_timestamp_ms: 1_700_000_000_000,
                frame_id: 17,
                context_id: 23,
                prior_id: 29,
                registry_digest: registry_digest(),
                expected_modalities: vec![Modality::Visual, Modality::Radar],
                active_track_count: 2,
                input_count: 3,
                outcome_count: 4,
                v1_expected_count: 1,
                degraded: false,
                truncated: false,
            }),
        ];

        for (index, event) in events.into_iter().enumerate() {
            let envelope =
                MonitorEnvelope::try_new("uav3", "crebain", index as u64 + 1, event).unwrap();
            let encoded = envelope.encode().unwrap();
            let decoded = MonitorEnvelope::decode(&encoded).unwrap();
            assert_eq!(decoded, envelope);
        }
    }

    #[test]
    fn every_outcome_conditional_has_a_valid_canonical_roundtrip() {
        let kinds = [
            ModalityOutcomeKind::Updated,
            ModalityOutcomeKind::GateRejected,
            ModalityOutcomeKind::AssignmentRejected,
            ModalityOutcomeKind::UpdateRejected,
            ModalityOutcomeKind::TrackBirth,
            ModalityOutcomeKind::UnsupportedFilter,
            ModalityOutcomeKind::IncomparableProjection,
        ];

        for (index, kind) in kinds.into_iter().enumerate() {
            let envelope = MonitorEnvelope::try_new(
                "uav3",
                "crebain",
                index as u64 + 1,
                ProducerEvent::ModalityOutcome(valid_outcome(kind)),
            )
            .unwrap();
            let encoded = envelope.encode().unwrap();

            assert_eq!(MonitorEnvelope::decode(&encoded).unwrap(), envelope);
        }
    }

    #[test]
    fn unknown_envelope_and_event_fields_are_rejected() {
        let envelope =
            MonitorEnvelope::try_new("uav3", "crebain", 1, ProducerEvent::Heartbeat(heartbeat()))
                .unwrap();
        let mut root = serde_json::to_value(&envelope).unwrap();
        root["future"] = serde_json::json!(true);
        let mut wrapper = serde_json::to_value(&envelope).unwrap();
        wrapper["event"]["future"] = serde_json::json!(true);
        let mut payload = serde_json::to_value(envelope).unwrap();
        payload["event"]["data"]["future"] = serde_json::json!(true);

        assert!(serde_json::from_value::<MonitorEnvelope>(root).is_err());
        assert!(serde_json::from_value::<MonitorEnvelope>(wrapper).is_err());
        assert!(serde_json::from_value::<MonitorEnvelope>(payload).is_err());
    }

    #[test]
    fn event_sequence_must_be_json_safe_and_globally_newer() {
        let event = ProducerEvent::Heartbeat(heartbeat());
        let zero = MonitorEnvelope::try_new("uav3", "crebain", 0, event.clone()).unwrap_err();
        let unsafe_seq =
            MonitorEnvelope::try_new("uav3", "crebain", JSON_SAFE_INTEGER_MAX as u64 + 1, event)
                .unwrap_err();
        let envelope =
            MonitorEnvelope::try_new("uav3", "crebain", 8, ProducerEvent::Heartbeat(heartbeat()))
                .unwrap();

        assert_eq!(zero, MonitorError::ZeroEventSequence);
        assert!(matches!(
            unsafe_seq,
            MonitorError::IntegerOutOfRange {
                field: "event_seq",
                ..
            }
        ));
        assert!(matches!(
            envelope.validate_after(8),
            Err(MonitorError::NonMonotonicEventSequence { .. })
        ));
        assert!(envelope.validate_after(7).is_ok());
        assert!(envelope.validate_next(7).is_ok());
        assert_eq!(
            envelope.validate_next(6),
            Err(MonitorError::EventSequenceGap {
                expected: 7,
                received: 8,
            })
        );
    }

    #[test]
    fn ncp_version_spelling_must_match_the_frozen_schema() {
        let mut envelope =
            MonitorEnvelope::try_new("uav3", "crebain", 1, ProducerEvent::Heartbeat(heartbeat()))
                .unwrap();
        envelope.ncp_version = "00.08".to_string();

        assert!(matches!(
            envelope.validate(),
            Err(MonitorError::IncompatibleNcpVersion(_))
        ));
    }

    #[test]
    fn identities_use_utf8_byte_ceiling_and_provenance_binding() {
        let at_bound = "é".repeat(MAX_ID_SEGMENT_BYTES / 2);
        let oversized = format!("{at_bound}é");
        let event = ProducerEvent::Heartbeat(heartbeat());
        let envelope = MonitorEnvelope::try_new(at_bound.clone(), at_bound, 1, event.clone())
            .expect("exactly 64 UTF-8 bytes is valid");

        assert!(MonitorEnvelope::try_new(oversized, "crebain", 1, event).is_err());
        assert!(matches!(
            envelope.validate_for("other", &envelope.producer_id),
            Err(MonitorError::ProvenanceMismatch {
                field: "session_id",
                ..
            })
        ));
        assert!(matches!(
            envelope.validate_for(&envelope.session_id, "other"),
            Err(MonitorError::ProvenanceMismatch {
                field: "producer_id",
                ..
            })
        ));
    }

    #[test]
    fn inclusive_wire_limits_remain_valid() {
        assert_eq!(MAX_MONITOR_EVENT_BYTES, 65_536);
        assert!(validate_json_integer("test", JSON_SAFE_INTEGER_MAX as u64).is_ok());
        assert!(validate_encoded_size(MAX_MONITOR_EVENT_BYTES).is_ok());
        assert!(validate_heartbeat_duration("test", MAX_HEARTBEAT_DURATION_MS).is_ok());
        assert!(validate_count("test", MAX_FRAME_ITEMS, MAX_FRAME_ITEMS).is_ok());
        assert!(validate_gate_value("test", 0.0).is_ok());

        let queue = QueueHealth {
            capacity: MAX_MONITOR_QUEUE_EVENTS,
            depth: MAX_MONITOR_QUEUE_EVENTS,
            dropped_event_count: 0,
            published_event_count: JSON_SAFE_INTEGER_MAX as u64,
        };
        assert!(queue.validate().is_ok());

        let mut heartbeat = heartbeat();
        heartbeat.declared_deadline_ms = heartbeat.declared_interval_ms;
        heartbeat.degraded = false;
        heartbeat.queue_health = queue;
        assert!(heartbeat.validate().is_ok());
    }

    #[test]
    fn compound_wire_guards_reject_each_invalid_arm() {
        let invalid_capacities = [0, MAX_MONITOR_QUEUE_EVENTS + 1];
        for capacity in invalid_capacities {
            let queue = QueueHealth {
                capacity,
                depth: 0,
                dropped_event_count: 0,
                published_event_count: 0,
            };
            assert!(matches!(
                queue.validate(),
                Err(MonitorError::CountOutOfRange { .. })
            ));
        }

        let queue = QueueHealth {
            capacity: 2,
            depth: 2,
            dropped_event_count: 0,
            published_event_count: 0,
        };
        assert!(queue.validate().is_ok());

        assert!(validate_contract_hash(&"0".repeat(CONTRACT_HASH.len() - 1)).is_err());
        assert!(validate_contract_hash(&"g".repeat(CONTRACT_HASH.len())).is_err());
    }

    #[test]
    fn heartbeat_requires_bounded_ordered_durations() {
        let mut value = heartbeat();
        value.declared_interval_ms = 0;
        assert!(matches!(
            value.validate(),
            Err(MonitorError::HeartbeatDurationOutOfRange { .. })
        ));

        assert!(matches!(
            ProducerEvent::Heartbeat(value.clone()).validate(),
            Err(MonitorError::HeartbeatDurationOutOfRange { .. })
        ));

        value.declared_interval_ms = 2_000;
        value.declared_deadline_ms = 1_000;
        assert!(matches!(
            value.validate(),
            Err(MonitorError::HeartbeatDeadlineBeforeInterval { .. })
        ));

        value.declared_deadline_ms = MAX_HEARTBEAT_DURATION_MS + 1;
        assert!(matches!(
            value.validate(),
            Err(MonitorError::HeartbeatDurationOutOfRange { .. })
        ));
    }

    #[test]
    fn heartbeat_rejects_incoherent_queue_and_unsafe_counters() {
        let mut value = heartbeat();
        value.queue_health.depth = value.queue_health.capacity + 1;
        assert!(matches!(
            value.validate(),
            Err(MonitorError::QueueDepthExceedsCapacity { .. })
        ));

        value.queue_health.depth = 0;
        value.queue_health.dropped_event_count = JSON_SAFE_INTEGER_MAX as u64 + 1;
        assert!(matches!(
            value.validate(),
            Err(MonitorError::IntegerOutOfRange { .. })
        ));

        value.queue_health.dropped_event_count = 1;
        value.degraded = false;
        assert_eq!(
            value.validate(),
            Err(MonitorError::EventCoherence(
                "heartbeat with dropped events must be degraded"
            ))
        );
    }

    #[test]
    fn gate_evidence_requires_finite_nonnegative_values() {
        let negative = GateEvidence {
            d2: -0.1,
            ..gate_evidence()
        };
        let non_finite = GateEvidence {
            threshold: f64::INFINITY,
            ..gate_evidence()
        };

        assert!(matches!(
            negative.validate(),
            Err(MonitorError::InvalidGateValue {
                field: "event.gate_evidence.d2"
            })
        ));
        assert!(matches!(
            non_finite.validate(),
            Err(MonitorError::InvalidGateValue {
                field: "event.gate_evidence.threshold"
            })
        ));
    }

    #[test]
    fn outcome_rejects_counts_and_gate_evidence_that_disagree() {
        let mut updated = outcome(ModalityOutcomeKind::Updated);
        updated.in_gate_count = updated.candidate_count + 1;
        assert!(matches!(
            updated.validate(),
            Err(MonitorError::EventCoherence(_))
        ));

        let mut rejected = outcome(ModalityOutcomeKind::GateRejected);
        rejected.in_gate_count = 0;
        rejected.gate_evidence = Some(GateEvidence {
            d2: 2.0,
            threshold: 3.0,
            ..gate_evidence()
        });
        assert!(matches!(
            rejected.validate(),
            Err(MonitorError::EventCoherence(_))
        ));

        rejected.gate_evidence = Some(GateEvidence {
            d2: 3.0,
            threshold: 3.0,
            ..gate_evidence()
        });
        assert!(rejected.validate().is_ok(), "the producer gate is strict <");

        rejected.gate_evidence = None;
        assert_eq!(
            rejected.validate(),
            Err(MonitorError::EventCoherence(
                "gate_rejected requires gate_evidence"
            ))
        );

        let mut equality = outcome(ModalityOutcomeKind::Updated);
        equality.gate_evidence = Some(GateEvidence {
            d2: 3.0,
            threshold: 3.0,
            ..gate_evidence()
        });
        assert!(matches!(
            equality.validate(),
            Err(MonitorError::EventCoherence(_))
        ));

        let mut no_candidates = outcome(ModalityOutcomeKind::GateRejected);
        no_candidates.candidate_count = 0;
        no_candidates.in_gate_count = 0;
        no_candidates.gate_evidence = Some(GateEvidence {
            d2: 3.0,
            threshold: 3.0,
            ..gate_evidence()
        });
        assert_eq!(
            no_candidates.validate(),
            Err(MonitorError::EventCoherence(
                "gate_rejected requires at least one pair-level candidate"
            ))
        );

        // Counts describe the whole track/modality pair, while gate_evidence
        // describes this attempt. A sibling candidate may be in-gate even when
        // this candidate is correctly rejected.
        let mut in_gate_rejection = outcome(ModalityOutcomeKind::GateRejected);
        in_gate_rejection.in_gate_count = 1;
        in_gate_rejection.gate_evidence = Some(GateEvidence {
            d2: 3.0,
            threshold: 3.0,
            ..gate_evidence()
        });
        assert!(in_gate_rejection.validate().is_ok());

        let mut impossible_counts = outcome(ModalityOutcomeKind::AssignmentRejected);
        impossible_counts.candidate_count = 0;
        impossible_counts.in_gate_count = 1;
        assert_eq!(
            impossible_counts.validate(),
            Err(MonitorError::EventCoherence(
                "in_gate_count cannot exceed candidate_count"
            ))
        );

        let mut no_assignment = outcome(ModalityOutcomeKind::AssignmentRejected);
        no_assignment.in_gate_count = 0;
        assert_eq!(
            no_assignment.validate(),
            Err(MonitorError::EventCoherence(
                "assignment_rejected requires at least one in-gate candidate"
            ))
        );
    }

    #[test]
    fn outcome_requires_fields_specific_to_update_birth_and_unsupported_filter() {
        let mut censored_update = outcome(ModalityOutcomeKind::Updated);
        censored_update.v1_expected = false;
        assert_eq!(
            censored_update.validate(),
            Err(MonitorError::EventCoherence(
                "updated outcomes must require their matching v1 observation"
            ))
        );

        let mut updated = outcome(ModalityOutcomeKind::Updated);
        updated.measurement_index = None;
        assert!(matches!(
            updated.validate(),
            Err(MonitorError::EventCoherence(
                "updated requires measurement_index"
            ))
        ));

        for (candidate_count, in_gate_count) in [(0, 1), (1, 0)] {
            let mut invalid_candidates = outcome(ModalityOutcomeKind::Updated);
            invalid_candidates.candidate_count = candidate_count;
            invalid_candidates.in_gate_count = in_gate_count;
            assert!(matches!(
                invalid_candidates.validate(),
                Err(MonitorError::EventCoherence(_))
            ));
        }

        let mut missing_gate = outcome(ModalityOutcomeKind::Updated);
        missing_gate.gate_evidence = None;
        assert_eq!(
            missing_gate.validate(),
            Err(MonitorError::EventCoherence(
                "gate-dependent outcome requires gate_evidence"
            ))
        );

        let mut missing_projection = outcome(ModalityOutcomeKind::Updated);
        missing_projection.consistency_projection = None;
        assert_eq!(
            missing_projection.validate(),
            Err(MonitorError::EventCoherence(
                "updated requires a consistency projection"
            ))
        );

        let mut birth = outcome(ModalityOutcomeKind::TrackBirth);
        birth.candidate_count = 0;
        birth.in_gate_count = 0;
        birth.gate_evidence = None;
        birth.consistency_projection = None;
        assert!(birth.validate().is_ok());

        for invalid_birth in [
            ModalityOutcome {
                candidate_count: 1,
                ..birth.clone()
            },
            ModalityOutcome {
                in_gate_count: 1,
                ..birth.clone()
            },
            ModalityOutcome {
                gate_evidence: Some(gate_evidence()),
                ..birth.clone()
            },
            ModalityOutcome {
                consistency_projection: Some(projection()),
                ..birth.clone()
            },
        ] {
            assert!(matches!(
                invalid_birth.validate(),
                Err(MonitorError::EventCoherence(_))
            ));
        }

        let mut unsupported = outcome(ModalityOutcomeKind::UnsupportedFilter);
        unsupported.gate_evidence = None;
        assert!(unsupported.validate().is_ok());

        unsupported.v1_expected = true;
        assert!(matches!(
            unsupported.validate(),
            Err(MonitorError::EventCoherence(_))
        ));
    }

    #[test]
    fn outcome_rejects_invalid_or_unsafe_projection() {
        let mut invalid = outcome(ModalityOutcomeKind::Updated);
        invalid.consistency_projection.as_mut().unwrap().dimensions = 0;
        assert!(matches!(
            invalid.validate(),
            Err(MonitorError::InvalidConsistencyProjection(_))
        ));

        let mut unsafe_id = outcome(ModalityOutcomeKind::Updated);
        unsafe_id.consistency_projection.as_mut().unwrap().prior_id =
            JSON_SAFE_INTEGER_MAX as u64 + 1;
        assert!(matches!(
            unsafe_id.validate(),
            Err(MonitorError::IntegerOutOfRange {
                field: "event.consistency_projection.prior_id",
                ..
            })
        ));

        let mut wrong_frame = outcome(ModalityOutcomeKind::Updated);
        wrong_frame
            .consistency_projection
            .as_mut()
            .unwrap()
            .frame_id += 1;
        assert_eq!(
            wrong_frame.validate(),
            Err(MonitorError::EventCoherence(
                "consistency projection provenance must match the outcome frame"
            ))
        );

        let mut wrong_context = outcome(ModalityOutcomeKind::Updated);
        wrong_context
            .consistency_projection
            .as_mut()
            .unwrap()
            .context_id += 1;
        assert_eq!(
            wrong_context.validate(),
            Err(MonitorError::EventCoherence(
                "consistency projection provenance must match the outcome frame"
            ))
        );

        let mut wrong_prior = outcome(ModalityOutcomeKind::Updated);
        wrong_prior
            .consistency_projection
            .as_mut()
            .unwrap()
            .prior_id += 1;
        assert_eq!(
            wrong_prior.validate(),
            Err(MonitorError::EventCoherence(
                "consistency projection provenance must match the outcome frame"
            ))
        );

        let mut unexpected_v1 = outcome(ModalityOutcomeKind::GateRejected);
        unexpected_v1.in_gate_count = 0;
        unexpected_v1.v1_expected = true;
        assert!(matches!(
            unexpected_v1.validate(),
            Err(MonitorError::EventCoherence(_))
        ));

        let mut incomparable = outcome(ModalityOutcomeKind::IncomparableProjection);
        incomparable.consistency_projection = None;
        incomparable.v1_expected = true;
        assert!(incomparable.validate().is_ok());

        let mut zero_prior = outcome(ModalityOutcomeKind::Updated);
        zero_prior.prior_id = 0;
        assert_eq!(
            zero_prior.validate(),
            Err(MonitorError::ZeroIdentifier {
                field: "event.prior_id"
            })
        );

        let mut excessive_attempt = outcome(ModalityOutcomeKind::Updated);
        excessive_attempt.attempt_index = MAX_FRAME_ITEMS;
        assert_eq!(
            excessive_attempt.validate(),
            Err(MonitorError::CountOutOfRange {
                field: "event.attempt_index",
                value: u64::from(MAX_FRAME_ITEMS),
                maximum: u64::from(MAX_FRAME_ITEMS - 1),
            })
        );

        let mut excessive_measurement = outcome(ModalityOutcomeKind::Updated);
        excessive_measurement.measurement_index = Some(MAX_FRAME_ITEMS);
        assert_eq!(
            excessive_measurement.validate(),
            Err(MonitorError::CountOutOfRange {
                field: "event.measurement_index",
                value: u64::from(MAX_FRAME_ITEMS),
                maximum: u64::from(MAX_FRAME_ITEMS - 1),
            })
        );
    }

    #[test]
    fn modality_miss_validates_frame_and_track_identity() {
        let miss = ModalityMiss {
            fusion_seq: 1,
            fusion_timestamp_ms: 2,
            frame_id: 3,
            context_id: 4,
            prior_id: 5,
            track_id: 0,
            modality: Modality::Radar,
            reason: ModalityMissReason::NoMeasurement,
        };

        assert_eq!(
            miss.validate(),
            Err(MonitorError::ZeroIdentifier {
                field: "event.track_id"
            })
        );
    }

    #[test]
    fn frame_summary_requires_nonempty_unique_modalities_and_bounded_counts() {
        let mut summary = FrameSummary {
            fusion_seq: 1,
            fusion_timestamp_ms: 2,
            frame_id: 17,
            context_id: 23,
            prior_id: 29,
            registry_digest: registry_digest(),
            expected_modalities: Vec::new(),
            active_track_count: 1,
            input_count: 2,
            outcome_count: 3,
            v1_expected_count: 1,
            degraded: false,
            truncated: false,
        };
        assert_eq!(
            summary.validate(),
            Err(MonitorError::EmptyExpectedModalities)
        );

        summary.expected_modalities = vec![Modality::Radar, Modality::Radar];
        assert!(matches!(
            summary.validate(),
            Err(MonitorError::DuplicateExpectedModality {
                modality: Modality::Radar
            })
        ));

        summary.expected_modalities = vec![Modality::Radar];
        summary.outcome_count = MAX_FRAME_ITEMS + 1;
        assert!(matches!(
            summary.validate(),
            Err(MonitorError::CountOutOfRange {
                field: "event.outcome_count",
                ..
            })
        ));

        summary.outcome_count = 3;
        summary.v1_expected_count = 4;
        assert!(matches!(
            summary.validate(),
            Err(MonitorError::EventCoherence(_))
        ));

        summary.v1_expected_count = 1;
        summary.registry_digest = "A".repeat(REGISTRY_DIGEST_HEX_LEN);
        assert!(matches!(
            summary.validate(),
            Err(MonitorError::InvalidRegistryDigest(_))
        ));

        summary.registry_digest = registry_digest();
        summary.truncated = true;
        assert!(matches!(
            summary.validate(),
            Err(MonitorError::EventCoherence(_))
        ));

        summary.degraded = true;
        assert!(summary.validate().is_ok());

        summary.truncated = false;
        summary.degraded = false;
        summary.v1_expected_count = summary.outcome_count;
        assert!(summary.validate().is_ok());
    }

    #[test]
    fn bounded_decoder_rejects_oversized_input_before_json_parsing() {
        let oversized = vec![b' '; MAX_MONITOR_EVENT_BYTES + 1];

        assert_eq!(
            MonitorEnvelope::decode(&oversized),
            Err(MonitorError::EncodedEventTooLarge {
                actual: MAX_MONITOR_EVENT_BYTES + 1,
                maximum: MAX_MONITOR_EVENT_BYTES,
            })
        );
    }

    #[test]
    fn monitor_schema_identity_and_enums_match_runtime_contract() {
        let schema: serde_json::Value =
            serde_json::from_str(MONITOR_SCHEMA_JSON).expect("embedded monitor schema is JSON");
        let outcome_values = serde_json::to_value([
            ModalityOutcomeKind::Updated,
            ModalityOutcomeKind::GateRejected,
            ModalityOutcomeKind::AssignmentRejected,
            ModalityOutcomeKind::UpdateRejected,
            ModalityOutcomeKind::TrackBirth,
            ModalityOutcomeKind::UnsupportedFilter,
            ModalityOutcomeKind::IncomparableProjection,
        ])
        .unwrap();
        let miss_values = serde_json::to_value([
            ModalityMissReason::NoMeasurement,
            ModalityMissReason::NoCandidate,
            ModalityMissReason::NoInGateCandidate,
            ModalityMissReason::NotAssigned,
            ModalityMissReason::TrackNotEligible,
        ])
        .unwrap();

        assert_eq!(schema["properties"]["kind"]["const"], MONITOR_KIND);
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            MONITOR_SCHEMA_VERSION
        );
        assert_eq!(schema["properties"]["ncp_version"]["const"], NCP_VERSION);
        assert_eq!(
            schema["properties"]["contract_hash"]["minLength"],
            CONTRACT_HASH.len()
        );
        assert_eq!(
            schema["properties"]["contract_hash"]["maxLength"],
            CONTRACT_HASH.len()
        );
        assert_eq!(
            schema["$defs"]["ncpKeySegment"]["not"]["pattern"],
            r"[\r\n]"
        );
        assert_eq!(
            schema["$defs"]["safeUnsignedInteger"]["maximum"],
            JSON_SAFE_INTEGER_MAX
        );
        assert_eq!(
            schema["$defs"]["heartbeatDuration"]["maximum"],
            MAX_HEARTBEAT_DURATION_MS
        );
        assert_eq!(
            schema["$defs"]["boundedQueueCount"]["maximum"],
            MAX_MONITOR_QUEUE_EVENTS
        );
        assert_eq!(
            schema["$defs"]["activeTrackCount"]["maximum"],
            MAX_ACTIVE_TRACKS
        );
        assert_eq!(
            schema["$defs"]["frameItemCount"]["maximum"],
            MAX_FRAME_ITEMS
        );
        assert_eq!(
            schema["$defs"]["registryDigest"]["pattern"],
            format!("^[0-9a-f]{{{REGISTRY_DIGEST_HEX_LEN}}}$")
        );
        assert_eq!(
            schema["$defs"]["registryDigest"]["minLength"],
            REGISTRY_DIGEST_HEX_LEN
        );
        assert_eq!(
            schema["$defs"]["registryDigest"]["maxLength"],
            REGISTRY_DIGEST_HEX_LEN
        );
        assert_eq!(
            schema["$defs"]["modalityOutcome"]["properties"]["outcome"]["enum"],
            outcome_values
        );
        assert_eq!(
            schema["$defs"]["modalityMiss"]["properties"]["reason"]["enum"],
            miss_values
        );

        let rules = schema["$defs"]["modalityOutcome"]["allOf"]
            .as_array()
            .unwrap();
        let required = |rule: &serde_json::Value, field: &str| {
            rule["then"]["required"]
                .as_array()
                .is_some_and(|fields| fields.iter().any(|value| value.as_str() == Some(field)))
        };
        let rule_for = |outcome: &str| {
            rules
                .iter()
                .find(|rule| rule["if"]["properties"]["outcome"]["const"].as_str() == Some(outcome))
                .unwrap()
        };
        let update_rule = rules
            .iter()
            .find(|rule| {
                rule["if"]["properties"]["outcome"]["enum"]
                    .as_array()
                    .is_some_and(|values| {
                        values.iter().any(|value| value.as_str() == Some("updated"))
                            && values
                                .iter()
                                .any(|value| value.as_str() == Some("update_rejected"))
                    })
            })
            .unwrap();

        assert!(required(update_rule, "gate_evidence"));
        assert!(required(rule_for("updated"), "consistency_projection"));
        assert!(required(rule_for("gate_rejected"), "gate_evidence"));
        assert!(required(rule_for("assignment_rejected"), "gate_evidence"));
        assert!(required(
            rule_for("incomparable_projection"),
            "gate_evidence"
        ));
    }

    #[test]
    fn monitor_key_follows_named_sensor_scheme() {
        assert_eq!(
            monitor_key("engram/ncp", "uav3").as_deref(),
            Some("engram/ncp/session/uav3/sensor/galadriel-monitor")
        );
        assert!(monitor_key("ncp/**", "uav3").is_none());
        assert!(monitor_key("ncp", "bad id").is_none());
        assert_eq!(
            default_monitor_key("uav3").as_deref(),
            Some("ncp/session/uav3/sensor/galadriel-monitor")
        );
        assert!(default_monitor_key(&"a".repeat(MAX_ID_SEGMENT_BYTES)).is_some());
        assert!(default_monitor_key(&"a".repeat(MAX_ID_SEGMENT_BYTES + 1)).is_none());
    }
}
