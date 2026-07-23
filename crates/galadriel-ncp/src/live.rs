//! The live Zenoh tap (feature `zenoh`; reached via galadriel's `ncp-live`).
//!
//! This is the streaming counterpart to the JSONL ingest: the *same*
//! [`PidObservation`] records, delivered live over the NCP bus instead of read from a
//! file. Galadriel subscribes to the named perception route
//! `{realm}/session/{id}/sensor/galadriel-pid` (see [`crate::sidecar_key`]). Each
//! payload is a versioned [`crate::SidecarEnvelope`], not an NCP normative message.
//!
//! It is a strictly **read-only observer**: [`SidecarTap`] only *subscribes*. It opens
//! (or shares) a Zenoh transport session, but never opens an NCP control session,
//! publishes to a control plane, or touches the safety-gated action plane — galadriel
//! is instrumentation on top of the bus, not a participant in the loop.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use galadriel_ncp::live::{HandoffProfile, SidecarTap, TransportMode};
//! let tap = SidecarTap::open(TransportMode::Secure).await?;
//! let handoff = HandoffProfile::BoundedV0_9.try_config()?;
//! let (health, mut observations) = tap
//!     .subscribe_channel("uav3", "crebain", handoff)
//!     .await?;
//! assert_eq!(health.payloads_received(), 0);
//! if let Some(obs) = observations.recv().await {
//!     let _ = obs.nis();
//! }
//! # Ok(()) }
//! ```

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use galadriel_core::{Modality, PidObservation, Sequence, TrackId};
use ncp_core::{ContractStatus, Keys, DEFAULT_REALM, JSON_SAFE_INTEGER_MAX};
use ncp_zenoh::{ZenohBus, ZenohError};
use tokio::sync::mpsc;

use crate::{
    config_identity::ConfigurationIdentityBuilder, sidecar_key, valid_producer_identity,
    valid_realm, ConfigurationIdentity, SidecarDecodeError, SidecarEnvelope, SidecarEnvelopeError,
};

/// Maximum live sidecar payload accepted under the bounded 0.9 profile.
///
/// This bounds galadriel's **decode** work only. The transport copies the full
/// received message before this gate runs, and Zenoh's own `max_message_size`
/// defaults to 1 GiB — a deployment that must bound peak receive memory sets
/// `transport/link/rx/max_message_size` in its Zenoh config as well.
pub const DEFAULT_MAX_LIVE_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum `(track, modality)` sequence streams retained by a live subscription.
pub const DEFAULT_MAX_LIVE_SEQUENCE_STREAMS: usize = 6 * 1024;

/// Maximum forward sequence advance after a stream's first accepted observation.
pub const DEFAULT_MAX_LIVE_SEQUENCE_ADVANCE: u64 = 1_000_000;

/// Default number of decoded observations retained by a bounded live handoff.
pub const DEFAULT_LIVE_HANDOFF_CAPACITY: usize = 1_024;

/// Hard upper bound for a live observation handoff queue.
pub const MAX_LIVE_HANDOFF_CAPACITY: usize = 4_096;
/// Maximum aggregate encoded-byte exposure represented by a handoff queue.
pub const MAX_LIVE_HANDOFF_STATE_BYTES: usize =
    MAX_LIVE_HANDOFF_CAPACITY * DEFAULT_MAX_LIVE_PAYLOAD_BYTES;
/// Hard ceiling for a live sidecar payload.
pub const MAX_LIVE_PAYLOAD_BYTES: usize = 64 * 1024;
/// Hard ceiling for retained live replay streams.
pub const MAX_LIVE_SEQUENCE_STREAMS: usize = 64 * 1024;
/// Hard ceiling for forward sequence distance.
pub const MAX_LIVE_SEQUENCE_ADVANCE: u64 = JSON_SAFE_INTEGER_MAX as u64;
/// Conservative fixed work units charged to each retained replay stream.
const LIVE_SEQUENCE_STATE_WORK_UNITS: usize = 64;
/// Hard ceiling for aggregate decode and replay-state work units.
pub const MAX_LIVE_CONFIGURED_WORK_UNITS: usize = 4 * 1024 * 1024;

/// Fixed overflow behavior for bounded live observation handoffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandoffOverflowPolicy {
    /// Preserve queued observations and discard the newly accepted observation.
    DropNewest,
}

/// Untrusted raw bounded-handoff parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffParams {
    /// Maximum decoded observations queued for a consumer.
    pub capacity: usize,
}

/// Named, reviewed live-handoff profiles for release 0.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandoffProfile {
    /// Bounded drop-newest handoff shipped in 0.9.
    BoundedV0_9,
}

impl HandoffProfile {
    /// Return this profile's frozen raw parameters.
    #[must_use]
    pub const fn params(self) -> HandoffParams {
        match self {
            Self::BoundedV0_9 => HandoffParams {
                capacity: DEFAULT_LIVE_HANDOFF_CAPACITY,
            },
        }
    }

    /// Validate this profile and return its immutable capability.
    pub fn try_config(self) -> Result<HandoffConfig, HandoffConfigError> {
        HandoffConfig::try_from(self.params())
    }
}

/// Validated configuration for a bounded live observation handoff.
///
/// ```compile_fail
/// use galadriel_ncp::live::HandoffConfig;
/// let _ = HandoffConfig::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffConfig {
    capacity: usize,
    identity: ConfigurationIdentity,
}

impl HandoffConfig {
    /// Validate a nonzero queue capacity no larger than
    /// [`MAX_LIVE_HANDOFF_CAPACITY`].
    ///
    /// # Errors
    ///
    /// Returns [`HandoffConfigError`] when `capacity` is zero or exceeds the hard
    /// process-memory bound.
    pub fn new(capacity: usize) -> Result<Self, HandoffConfigError> {
        Self::try_from(HandoffParams { capacity })
    }

    /// Maximum number of decoded observations waiting for the consumer.
    pub fn capacity(self) -> usize {
        self.capacity
    }

    /// Overflow policy used by this handoff.
    pub fn overflow_policy(self) -> HandoffOverflowPolicy {
        HandoffOverflowPolicy::DropNewest
    }

    /// Canonical identity of this validated handoff configuration.
    #[must_use]
    pub const fn identity(self) -> ConfigurationIdentity {
        self.identity
    }
}

impl TryFrom<HandoffParams> for HandoffConfig {
    type Error = HandoffConfigError;

    fn try_from(params: HandoffParams) -> Result<Self, Self::Error> {
        if params.capacity == 0 {
            return Err(HandoffConfigError::ZeroCapacity);
        }
        if params.capacity > MAX_LIVE_HANDOFF_CAPACITY {
            return Err(HandoffConfigError::CapacityTooLarge {
                capacity: params.capacity,
                maximum: MAX_LIVE_HANDOFF_CAPACITY,
            });
        }
        let aggregate_bytes = params
            .capacity
            .checked_mul(DEFAULT_MAX_LIVE_PAYLOAD_BYTES)
            .ok_or(HandoffConfigError::AggregateStateTooLarge {
                bytes: usize::MAX,
                maximum: MAX_LIVE_HANDOFF_STATE_BYTES,
            })?;
        if aggregate_bytes > MAX_LIVE_HANDOFF_STATE_BYTES {
            return Err(HandoffConfigError::AggregateStateTooLarge {
                bytes: aggregate_bytes,
                maximum: MAX_LIVE_HANDOFF_STATE_BYTES,
            });
        }
        Ok(Self {
            capacity: params.capacity,
            identity: ConfigurationIdentityBuilder::new("live-handoff")
                .u64("capacity", params.capacity as u64)
                .finish(),
        })
    }
}

#[cfg(test)]
impl Default for HandoffConfig {
    fn default() -> Self {
        HandoffProfile::BoundedV0_9
            .try_config()
            .expect("the compiled handoff test profile is valid")
    }
}

/// Invalid bounded-handoff configuration.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandoffConfigError {
    /// A bounded channel cannot have zero capacity.
    #[error("live handoff capacity must be greater than zero")]
    ZeroCapacity,
    /// The requested capacity exceeded [`MAX_LIVE_HANDOFF_CAPACITY`].
    #[error("live handoff capacity {capacity} exceeds maximum {maximum}")]
    CapacityTooLarge { capacity: usize, maximum: usize },
    /// Aggregate represented state exceeded its hard cap.
    #[error("live handoff represented bytes {bytes} exceed maximum {maximum}")]
    AggregateStateTooLarge { bytes: usize, maximum: usize },
}

/// Untrusted raw live-ingest parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveLimitsParams {
    /// Maximum encoded sidecar payload bytes.
    pub max_payload_bytes: usize,
    /// Maximum retained replay streams.
    pub max_sequence_streams: usize,
    /// Maximum forward advance after a stream baseline.
    pub max_sequence_advance: u64,
}

/// Named, reviewed live-ingest profiles for release 0.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveLimitsProfile {
    /// Bounded sidecar ingest profile shipped in 0.9.
    BoundedV0_9,
}

impl LiveLimitsProfile {
    /// Return this profile's frozen raw parameters.
    #[must_use]
    pub const fn params(self) -> LiveLimitsParams {
        match self {
            Self::BoundedV0_9 => LiveLimitsParams {
                max_payload_bytes: DEFAULT_MAX_LIVE_PAYLOAD_BYTES,
                max_sequence_streams: DEFAULT_MAX_LIVE_SEQUENCE_STREAMS,
                max_sequence_advance: DEFAULT_MAX_LIVE_SEQUENCE_ADVANCE,
            },
        }
    }

    /// Validate this profile and return its immutable capability.
    pub fn try_limits(self) -> Result<LiveLimits, LiveLimitsError> {
        LiveLimits::try_from(self.params())
    }
}

/// Invalid live sidecar resource parameters.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveLimitsError {
    /// A required limit was zero.
    #[error("live limit {field} must be greater than zero")]
    Zero { field: &'static str },
    /// A limit exceeded its hard maximum.
    #[error("live limit {field} is {value}, exceeding maximum {maximum}")]
    ExceedsHardMaximum {
        field: &'static str,
        value: u64,
        maximum: u64,
    },
    /// Combined payload and replay-state work exceeded its hard cap.
    #[error("live configured work {value} exceeds maximum {maximum}")]
    AggregateWorkTooLarge { value: usize, maximum: usize },
}

/// Validated resource limits for live sidecar ingest.
///
/// ```compile_fail
/// use galadriel_ncp::live::LiveLimits;
/// let _ = LiveLimits::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveLimits {
    max_payload_bytes: usize,
    max_sequence_streams: usize,
    max_sequence_advance: u64,
    identity: ConfigurationIdentity,
}

impl LiveLimits {
    /// Build a nonzero live-payload limit with the default sequence-stream bound.
    pub fn new(max_payload_bytes: usize) -> Result<Self, LiveLimitsError> {
        Self::with_sequence_stream_limit(max_payload_bytes, DEFAULT_MAX_LIVE_SEQUENCE_STREAMS)
    }

    /// Build nonzero live-payload and sequence-stream limits.
    pub fn with_sequence_stream_limit(
        max_payload_bytes: usize,
        max_sequence_streams: usize,
    ) -> Result<Self, LiveLimitsError> {
        Self::with_sequence_policy(
            max_payload_bytes,
            max_sequence_streams,
            DEFAULT_MAX_LIVE_SEQUENCE_ADVANCE,
        )
    }

    /// Build nonzero payload, retained-stream, and forward-sequence limits.
    ///
    /// A stream's first valid observation establishes its sequence baseline so a
    /// healthy late subscriber can join at any sequence. `max_sequence_advance`
    /// applies only to later observations. Producers should use a new NCP
    /// `session_id` for every process epoch rather than resetting a sequence in an
    /// existing session. Because the first sequence is necessarily trusted as a
    /// baseline, an unauthenticated first payload could pin that stream at a hostile
    /// value; authenticated ACLs and explicit session epochs remain required.
    pub fn with_sequence_policy(
        max_payload_bytes: usize,
        max_sequence_streams: usize,
        max_sequence_advance: u64,
    ) -> Result<Self, LiveLimitsError> {
        Self::try_from(LiveLimitsParams {
            max_payload_bytes,
            max_sequence_streams,
            max_sequence_advance,
        })
    }

    /// Maximum encoded bytes accepted for one sidecar payload.
    pub fn max_payload_bytes(self) -> usize {
        self.max_payload_bytes
    }

    /// Maximum retained `(track, modality)` sequence streams per subscription.
    pub fn max_sequence_streams(self) -> usize {
        self.max_sequence_streams
    }

    /// Maximum accepted forward advance after one stream establishes its baseline.
    pub fn max_sequence_advance(self) -> u64 {
        self.max_sequence_advance
    }

    /// Canonical identity of this validated live-ingest policy.
    #[must_use]
    pub const fn identity(self) -> ConfigurationIdentity {
        self.identity
    }
}

impl TryFrom<LiveLimitsParams> for LiveLimits {
    type Error = LiveLimitsError;

    fn try_from(params: LiveLimitsParams) -> Result<Self, Self::Error> {
        let scalar_limits = [
            (
                "max_payload_bytes",
                params.max_payload_bytes as u64,
                MAX_LIVE_PAYLOAD_BYTES as u64,
            ),
            (
                "max_sequence_streams",
                params.max_sequence_streams as u64,
                MAX_LIVE_SEQUENCE_STREAMS as u64,
            ),
            (
                "max_sequence_advance",
                params.max_sequence_advance,
                MAX_LIVE_SEQUENCE_ADVANCE,
            ),
        ];
        for (field, value, maximum) in scalar_limits {
            if value == 0 {
                return Err(LiveLimitsError::Zero { field });
            }
            if value > maximum {
                return Err(LiveLimitsError::ExceedsHardMaximum {
                    field,
                    value,
                    maximum,
                });
            }
        }
        let work = params
            .max_sequence_streams
            .checked_mul(LIVE_SEQUENCE_STATE_WORK_UNITS)
            .and_then(|value| value.checked_add(params.max_payload_bytes))
            .ok_or(LiveLimitsError::AggregateWorkTooLarge {
                value: usize::MAX,
                maximum: MAX_LIVE_CONFIGURED_WORK_UNITS,
            })?;
        if work > MAX_LIVE_CONFIGURED_WORK_UNITS {
            return Err(LiveLimitsError::AggregateWorkTooLarge {
                value: work,
                maximum: MAX_LIVE_CONFIGURED_WORK_UNITS,
            });
        }
        Ok(Self {
            max_payload_bytes: params.max_payload_bytes,
            max_sequence_streams: params.max_sequence_streams,
            max_sequence_advance: params.max_sequence_advance,
            identity: ConfigurationIdentityBuilder::new("live-limits")
                .u64("max_payload_bytes", params.max_payload_bytes as u64)
                .u64("max_sequence_streams", params.max_sequence_streams as u64)
                .u64("max_sequence_advance", params.max_sequence_advance)
                .finish(),
        })
    }
}

#[cfg(test)]
impl Default for LiveLimits {
    fn default() -> Self {
        LiveLimitsProfile::BoundedV0_9
            .try_limits()
            .expect("the compiled live-limit test profile is valid")
    }
}

fn bounded_live_limits() -> Result<LiveLimits, ZenohError> {
    LiveLimitsProfile::BoundedV0_9
        .try_limits()
        .map_err(|error| ZenohError(error.to_string()))
}

/// A reason a live payload was rejected before callback delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectionReason {
    /// The encoded payload exceeded [`LiveLimits::max_payload_bytes`].
    PayloadTooLarge,
    /// The payload was not valid JSON for a [`SidecarEnvelope`].
    MalformedJson,
    /// The envelope discriminator, schema, hash shape, or identity segments were invalid.
    InvalidEnvelope,
    /// The envelope carried an incompatible NCP wire version.
    IncompatibleNcpVersion,
    /// The envelope's session or producer did not match the subscription.
    ProvenanceMismatch,
    /// The decoded observation failed semantic validation.
    InvalidObservation,
    /// The sequence duplicated or regressed within its retained stream.
    DuplicateOrRegressedSequence,
    /// A later sequence advanced farther than [`LiveLimits::max_sequence_advance`].
    ExcessiveForwardSequenceGap,
    /// A new `(track, modality)` stream arrived after sequence state reached its
    /// configured capacity. Existing replay high-water marks are retained.
    SequenceCapacityExceeded,
    /// Internal live state failed, including allocation failure or terminal mutex
    /// poison. Inspect [`SubscriptionHealth::internal_fault`] for the typed cause.
    SequenceStateFailure,
}

/// Typed terminal internal failure for one live-tap epoch.
///
/// Once any variant is observed, the tap fails closed: later payloads are rejected,
/// callbacks are not invoked, and bounded receivers quarantine queued observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LiveInternalFault {
    /// Per-stream replay high-water state was poisoned.
    SequenceStatePoisoned,
    /// Callback/reset delivery-boundary state was poisoned.
    DeliveryBoundaryPoisoned,
    /// Bounded-handoff metadata state was poisoned.
    HandoffStatePoisoned,
    /// Last-accepted-observation telemetry was poisoned.
    LastAcceptedTelemetryPoisoned,
    /// Callback-latency telemetry was poisoned.
    CallbackLatencyTelemetryPoisoned,
    /// A user callback panicked after sequence admission; the subscription is terminal.
    CallbackPanicked,
}

impl LiveInternalFault {
    const fn code(self) -> u8 {
        match self {
            Self::SequenceStatePoisoned => 1,
            Self::DeliveryBoundaryPoisoned => 2,
            Self::HandoffStatePoisoned => 3,
            Self::LastAcceptedTelemetryPoisoned => 4,
            Self::CallbackLatencyTelemetryPoisoned => 5,
            Self::CallbackPanicked => 6,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::SequenceStatePoisoned),
            2 => Some(Self::DeliveryBoundaryPoisoned),
            3 => Some(Self::HandoffStatePoisoned),
            4 => Some(Self::LastAcceptedTelemetryPoisoned),
            5 => Some(Self::CallbackLatencyTelemetryPoisoned),
            6 => Some(Self::CallbackPanicked),
            _ => None,
        }
    }
}

/// Snapshot of typed live-payload rejection counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RejectionCounts {
    /// Payloads rejected for encoded size.
    pub payload_too_large: u64,
    /// Payloads rejected because JSON decoding failed.
    pub malformed_json: u64,
    /// Decoded envelopes rejected for invalid sidecar metadata.
    pub invalid_envelope: u64,
    /// Envelopes rejected for an incompatible NCP wire version.
    pub incompatible_ncp_version: u64,
    /// Envelopes rejected because claimed provenance did not match the subscription.
    pub provenance_mismatch: u64,
    /// Decoded observations rejected by semantic validation.
    pub invalid_observation: u64,
    /// Duplicate or regressed sequences.
    pub duplicate_or_regressed_sequence: u64,
    /// Established streams rejected for an excessive forward sequence gap.
    pub excessive_forward_sequence_gap: u64,
    /// New streams rejected because sequence state was at capacity.
    pub sequence_capacity_exceeded: u64,
    /// Internal live-state failures, including terminal mutex poison.
    pub sequence_state_failure: u64,
}

impl RejectionCounts {
    /// Counter value for one typed rejection reason.
    pub fn count(self, reason: RejectionReason) -> u64 {
        match reason {
            RejectionReason::PayloadTooLarge => self.payload_too_large,
            RejectionReason::MalformedJson => self.malformed_json,
            RejectionReason::InvalidEnvelope => self.invalid_envelope,
            RejectionReason::IncompatibleNcpVersion => self.incompatible_ncp_version,
            RejectionReason::ProvenanceMismatch => self.provenance_mismatch,
            RejectionReason::InvalidObservation => self.invalid_observation,
            RejectionReason::DuplicateOrRegressedSequence => self.duplicate_or_regressed_sequence,
            RejectionReason::ExcessiveForwardSequenceGap => self.excessive_forward_sequence_gap,
            RejectionReason::SequenceCapacityExceeded => self.sequence_capacity_exceeded,
            RejectionReason::SequenceStateFailure => self.sequence_state_failure,
        }
    }

    /// Saturating sum of all typed rejection counters.
    pub fn total(self) -> u64 {
        self.payload_too_large
            .saturating_add(self.malformed_json)
            .saturating_add(self.invalid_envelope)
            .saturating_add(self.incompatible_ncp_version)
            .saturating_add(self.provenance_mismatch)
            .saturating_add(self.invalid_observation)
            .saturating_add(self.duplicate_or_regressed_sequence)
            .saturating_add(self.excessive_forward_sequence_gap)
            .saturating_add(self.sequence_capacity_exceeded)
            .saturating_add(self.sequence_state_failure)
    }
}

/// Identity and producer timestamp of the last observation accepted by ingest.
///
/// Acceptance precedes the inline callback or bounded-handoff attempt, so callback
/// failure and handoff overflow do not roll back this diagnostic high-water mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LastAcceptedObservation {
    /// Producer track identifier.
    pub track_id: u64,
    /// Sensor modality for the retained sequence stream.
    pub modality: Modality,
    /// Producer sequence accepted for that stream.
    pub sequence: u64,
    /// Producer-supplied observation timestamp, not local wall-clock receive time.
    pub timestamp_ms: u64,
}

impl From<&PidObservation> for LastAcceptedObservation {
    fn from(observation: &PidObservation) -> Self {
        Self {
            track_id: observation.track_id().get(),
            modality: observation.modality(),
            sequence: observation.sequence().get(),
            timestamp_ms: observation.timestamp_ms().get(),
        }
    }
}

/// Point-in-time metrics for one bounded live observation handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HandoffMetrics {
    /// Configured channel capacity.
    pub capacity: usize,
    /// Fixed behavior when the channel reaches `capacity`.
    pub overflow_policy: HandoffOverflowPolicy,
    /// Current sequence/reset generation attached to new queue entries.
    pub generation: u64,
    /// Observations currently occupying queue capacity, including stale-generation
    /// entries that have not yet been drained by the consumer.
    pub queue_depth: usize,
    /// Largest queue depth observed since subscription creation.
    pub max_queue_depth: usize,
    /// Identity of the next queued observation, if any.
    pub oldest_queued: Option<LastAcceptedObservation>,
    /// Delivery generation attached to the next queued observation.
    pub oldest_queued_generation: Option<u64>,
    /// Monotonic age of the next queued observation at snapshot time.
    pub oldest_enqueue_age: Option<Duration>,
    /// Successful bounded-channel enqueues.
    pub enqueued: u64,
    /// Current-generation observations returned to the consumer.
    pub delivered: u64,
    /// Accepted observations dropped because the queue was full.
    pub full_drops: u64,
    /// Accepted observations dropped because the receiver was closed.
    pub closed_drops: u64,
    /// Queued observations discarded after an explicit sequence reset.
    pub stale_generation_drops: u64,
    /// Queued observations discarded when the receiver was dropped.
    pub abandoned_drops: u64,
    /// Duration of the most recent metadata-lock plus nonblocking enqueue attempt.
    pub last_enqueue_latency: Option<Duration>,
    /// Largest metadata-lock plus nonblocking enqueue duration observed so far.
    pub max_enqueue_latency: Option<Duration>,
    /// Enqueue-to-dequeue latency for the most recently drained entry.
    pub last_dequeue_latency: Option<Duration>,
    /// Largest enqueue-to-dequeue latency observed so far.
    pub max_dequeue_latency: Option<Duration>,
}

impl HandoffMetrics {
    /// Saturating sum of full, closed, stale-generation, and abandoned drops.
    pub fn total_drops(self) -> u64 {
        self.full_drops
            .saturating_add(self.closed_drops)
            .saturating_add(self.stale_generation_drops)
            .saturating_add(self.abandoned_drops)
    }
}

/// Monotonic execution-time metrics for accepted observation callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallbackLatencyMetrics {
    /// Accepted callbacks whose duration has been recorded.
    pub samples: u64,
    /// Duration of the most recently completed callback.
    pub last: Option<Duration>,
    /// Largest completed callback duration observed so far.
    pub maximum: Option<Duration>,
}

#[derive(Debug, Default)]
struct CallbackLatencyState {
    samples: u64,
    last: Option<Duration>,
    maximum: Option<Duration>,
    last_completed_at: Option<Instant>,
}

#[derive(Debug, Default)]
struct IngestCounters {
    payloads_received: AtomicU64,
    observations_accepted: AtomicU64,
    decode_failures: AtomicU64,
    callback_panics: AtomicU64,
    sequence_evictions: AtomicU64,
    sequence_resets: AtomicU64,
    contract_hash_mismatches: AtomicU64,
    payload_too_large: AtomicU64,
    malformed_json: AtomicU64,
    invalid_envelope: AtomicU64,
    incompatible_ncp_version: AtomicU64,
    provenance_mismatch: AtomicU64,
    invalid_observation: AtomicU64,
    duplicate_or_regressed_sequence: AtomicU64,
    excessive_forward_sequence_gap: AtomicU64,
    sequence_capacity_exceeded: AtomicU64,
    sequence_state_failure: AtomicU64,
    first_internal_fault: AtomicU8,
    internal_faults: AtomicU64,
    handoff_enqueued: AtomicU64,
    handoff_delivered: AtomicU64,
    handoff_full_drops: AtomicU64,
    handoff_closed_drops: AtomicU64,
    handoff_stale_generation_drops: AtomicU64,
    handoff_abandoned_drops: AtomicU64,
    callback_latency: Mutex<CallbackLatencyState>,
    last_accepted: Mutex<Option<LastAcceptedObservation>>,
}

impl IngestCounters {
    fn rejection_count(&self, reason: RejectionReason) -> u64 {
        match reason {
            RejectionReason::PayloadTooLarge => self.payload_too_large.load(Ordering::Relaxed),
            RejectionReason::MalformedJson => self.malformed_json.load(Ordering::Relaxed),
            RejectionReason::InvalidEnvelope => self.invalid_envelope.load(Ordering::Relaxed),
            RejectionReason::IncompatibleNcpVersion => {
                self.incompatible_ncp_version.load(Ordering::Relaxed)
            }
            RejectionReason::ProvenanceMismatch => self.provenance_mismatch.load(Ordering::Relaxed),
            RejectionReason::InvalidObservation => self.invalid_observation.load(Ordering::Relaxed),
            RejectionReason::DuplicateOrRegressedSequence => {
                self.duplicate_or_regressed_sequence.load(Ordering::Relaxed)
            }
            RejectionReason::ExcessiveForwardSequenceGap => {
                self.excessive_forward_sequence_gap.load(Ordering::Relaxed)
            }
            RejectionReason::SequenceCapacityExceeded => {
                self.sequence_capacity_exceeded.load(Ordering::Relaxed)
            }
            RejectionReason::SequenceStateFailure => {
                self.sequence_state_failure.load(Ordering::Relaxed)
            }
        }
    }

    fn rejection_counts(&self) -> RejectionCounts {
        RejectionCounts {
            payload_too_large: self.rejection_count(RejectionReason::PayloadTooLarge),
            malformed_json: self.rejection_count(RejectionReason::MalformedJson),
            invalid_envelope: self.rejection_count(RejectionReason::InvalidEnvelope),
            incompatible_ncp_version: self.rejection_count(RejectionReason::IncompatibleNcpVersion),
            provenance_mismatch: self.rejection_count(RejectionReason::ProvenanceMismatch),
            invalid_observation: self.rejection_count(RejectionReason::InvalidObservation),
            duplicate_or_regressed_sequence: self
                .rejection_count(RejectionReason::DuplicateOrRegressedSequence),
            excessive_forward_sequence_gap: self
                .rejection_count(RejectionReason::ExcessiveForwardSequenceGap),
            sequence_capacity_exceeded: self
                .rejection_count(RejectionReason::SequenceCapacityExceeded),
            sequence_state_failure: self.rejection_count(RejectionReason::SequenceStateFailure),
        }
    }

    fn internal_fault(&self) -> Option<LiveInternalFault> {
        LiveInternalFault::from_code(self.first_internal_fault.load(Ordering::Acquire))
    }
}

fn latch_internal_fault(counters: &IngestCounters, fault: LiveInternalFault) -> bool {
    if counters
        .first_internal_fault
        .compare_exchange(0, fault.code(), Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        counters.internal_faults.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

fn latch_internal_fault_pair(
    tap: &IngestCounters,
    subscription: &IngestCounters,
    fault: LiveInternalFault,
) {
    latch_internal_fault(tap, fault);
    latch_internal_fault(subscription, fault);
}

fn internal_fault_pair(
    tap: &IngestCounters,
    subscription: &IngestCounters,
) -> Option<LiveInternalFault> {
    tap.internal_fault()
        .or_else(|| subscription.internal_fault())
}

fn snapshot_last_accepted(
    counters: &IngestCounters,
) -> Result<Option<LastAcceptedObservation>, LiveInternalFault> {
    match counters.last_accepted.lock() {
        Ok(last) => Ok(*last),
        Err(poisoned) => {
            let mut last = poisoned.into_inner();
            *last = None;
            counters.last_accepted.clear_poison();
            Err(LiveInternalFault::LastAcceptedTelemetryPoisoned)
        }
    }
}

fn snapshot_callback_latency(
    counters: &IngestCounters,
) -> Result<CallbackLatencyMetrics, LiveInternalFault> {
    match counters.callback_latency.lock() {
        Ok(latency) => Ok(CallbackLatencyMetrics {
            samples: latency.samples,
            last: latency.last,
            maximum: latency.maximum,
        }),
        Err(poisoned) => {
            let mut latency = poisoned.into_inner();
            *latency = CallbackLatencyState::default();
            counters.callback_latency.clear_poison();
            Err(LiveInternalFault::CallbackLatencyTelemetryPoisoned)
        }
    }
}

fn preflight_telemetry_pair(tap: &IngestCounters, subscription: &IngestCounters) -> bool {
    for counters in [tap, subscription] {
        if counters.last_accepted.is_poisoned() {
            if let Err(fault) = snapshot_last_accepted(counters) {
                latch_internal_fault_pair(tap, subscription, fault);
                return false;
            }
        }
        if counters.callback_latency.is_poisoned() {
            if let Err(fault) = snapshot_callback_latency(counters) {
                latch_internal_fault_pair(tap, subscription, fault);
                return false;
            }
        }
    }
    true
}

#[derive(Debug)]
struct QueuedObservation {
    observation: PidObservation,
    generation: u64,
    enqueued_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct QueuedObservationMetadata {
    observation: LastAcceptedObservation,
    generation: u64,
    enqueued_at: Instant,
}

#[derive(Debug)]
struct HandoffQueueState {
    entries: VecDeque<QueuedObservationMetadata>,
    max_queue_depth: usize,
    last_enqueue_latency: Option<Duration>,
    max_enqueue_latency: Option<Duration>,
    last_dequeue_latency: Option<Duration>,
    max_dequeue_latency: Option<Duration>,
}

impl HandoffQueueState {
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            max_queue_depth: 0,
            last_enqueue_latency: None,
            max_enqueue_latency: None,
            last_dequeue_latency: None,
            max_dequeue_latency: None,
        }
    }
}

#[derive(Debug)]
struct HandoffState {
    config: HandoffConfig,
    queue: Mutex<HandoffQueueState>,
    tap_counters: Arc<IngestCounters>,
    subscription_counters: Arc<IngestCounters>,
    sequences: Arc<Mutex<LiveSequenceTracker>>,
}

impl HandoffState {
    fn new(
        config: HandoffConfig,
        tap_counters: Arc<IngestCounters>,
        subscription_counters: Arc<IngestCounters>,
        sequences: Arc<Mutex<LiveSequenceTracker>>,
    ) -> Self {
        Self {
            config,
            queue: Mutex::new(HandoffQueueState::new(config.capacity())),
            tap_counters,
            subscription_counters,
            sequences,
        }
    }

    fn lock_queue(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HandoffQueueState>, LiveInternalFault> {
        if self.sequences.is_poisoned() {
            drop(lock_sequence_state(
                &self.sequences,
                &self.tap_counters,
                &self.subscription_counters,
            ));
        }
        preflight_telemetry_pair(&self.tap_counters, &self.subscription_counters);
        if let Some(fault) = internal_fault_pair(&self.tap_counters, &self.subscription_counters) {
            return Err(fault);
        }
        match self.queue.lock() {
            Ok(queue) => Ok(queue),
            Err(poisoned) => {
                let mut queue = poisoned.into_inner();
                *queue = HandoffQueueState::new(self.config.capacity());
                self.queue.clear_poison();
                let fault = LiveInternalFault::HandoffStatePoisoned;
                latch_internal_fault_pair(&self.tap_counters, &self.subscription_counters, fault);
                Err(fault)
            }
        }
    }

    fn preflight(&self) -> bool {
        self.lock_queue().is_ok()
    }

    fn quarantine_receiver(&self, receiver: &mut mpsc::Receiver<QueuedObservation>) -> u64 {
        receiver.close();
        let mut discarded = 0_u64;
        while receiver.try_recv().is_ok() {
            discarded = discarded.saturating_add(1);
        }
        if let Ok(mut queue) = self.queue.lock() {
            queue.entries.clear();
        }
        increment_pair_by(
            &self.tap_counters.handoff_abandoned_drops,
            &self.subscription_counters.handoff_abandoned_drops,
            discarded,
        );
        discarded
    }

    fn record_dequeue(
        queue: &mut HandoffQueueState,
        queued: &QueuedObservation,
        dequeued_at: Instant,
    ) {
        let latency = dequeued_at.saturating_duration_since(queued.enqueued_at);
        let metadata = queue.entries.pop_front();
        debug_assert_eq!(
            metadata.map(|entry| (entry.observation, entry.generation, entry.enqueued_at)),
            Some((
                LastAcceptedObservation::from(&queued.observation),
                queued.generation,
                queued.enqueued_at,
            )),
            "Tokio handoff and mirror metadata must remain FIFO-aligned"
        );
        queue.last_dequeue_latency = Some(latency);
        queue.max_dequeue_latency = Some(
            queue
                .max_dequeue_latency
                .map_or(latency, |maximum| maximum.max(latency)),
        );
    }

    fn poll_dequeue(
        &self,
        receiver: &mut mpsc::Receiver<QueuedObservation>,
        context: &mut Context<'_>,
    ) -> Poll<Option<QueuedObservation>> {
        let Ok(mut queue) = self.lock_queue() else {
            self.quarantine_receiver(receiver);
            return Poll::Ready(None);
        };
        match receiver.poll_recv(context) {
            Poll::Ready(Some(queued)) => {
                Self::record_dequeue(&mut queue, &queued, Instant::now());
                Poll::Ready(Some(queued))
            }
            other => other,
        }
    }

    fn try_dequeue(
        &self,
        receiver: &mut mpsc::Receiver<QueuedObservation>,
    ) -> Result<QueuedObservation, mpsc::error::TryRecvError> {
        let Ok(mut queue) = self.lock_queue() else {
            self.quarantine_receiver(receiver);
            return Err(mpsc::error::TryRecvError::Disconnected);
        };
        let queued = receiver.try_recv()?;
        Self::record_dequeue(&mut queue, &queued, Instant::now());
        Ok(queued)
    }

    fn snapshot(&self, counters: &IngestCounters, generation: u64) -> Option<HandoffMetrics> {
        let now = Instant::now();
        let queue = self.lock_queue().ok()?;
        let oldest_queued = queue.entries.front().map(|entry| entry.observation);
        let oldest_queued_generation = queue.entries.front().map(|entry| entry.generation);
        let oldest_enqueue_age = queue
            .entries
            .front()
            .map(|entry| now.saturating_duration_since(entry.enqueued_at));
        Some(HandoffMetrics {
            capacity: self.config.capacity(),
            overflow_policy: self.config.overflow_policy(),
            generation,
            queue_depth: queue.entries.len(),
            max_queue_depth: queue.max_queue_depth,
            oldest_queued,
            oldest_queued_generation,
            oldest_enqueue_age,
            enqueued: counters.handoff_enqueued.load(Ordering::Relaxed),
            delivered: counters.handoff_delivered.load(Ordering::Relaxed),
            full_drops: counters.handoff_full_drops.load(Ordering::Relaxed),
            closed_drops: counters.handoff_closed_drops.load(Ordering::Relaxed),
            stale_generation_drops: counters
                .handoff_stale_generation_drops
                .load(Ordering::Relaxed),
            abandoned_drops: counters.handoff_abandoned_drops.load(Ordering::Relaxed),
            last_enqueue_latency: queue.last_enqueue_latency,
            max_enqueue_latency: queue.max_enqueue_latency,
            last_dequeue_latency: queue.last_dequeue_latency,
            max_dequeue_latency: queue.max_dequeue_latency,
        })
    }
}

#[derive(Clone, Debug)]
struct ObservationHandoff {
    sender: mpsc::Sender<QueuedObservation>,
    state: Arc<HandoffState>,
    delivery_boundary: Arc<DeliveryBoundary>,
    tap_counters: Arc<IngestCounters>,
    subscription_counters: Arc<IngestCounters>,
}

impl ObservationHandoff {
    fn preflight(&self) -> bool {
        self.state.preflight()
    }

    fn enqueue(&self, observation: PidObservation) {
        let enqueued_at = Instant::now();
        let generation = self.delivery_boundary.generation();
        let metadata = QueuedObservationMetadata {
            observation: LastAcceptedObservation::from(&observation),
            generation,
            enqueued_at,
        };
        let queued = QueuedObservation {
            observation,
            generation,
            enqueued_at,
        };
        let enqueue_started = Instant::now();

        // Synchronize the mirror metadata with try_send so depth and oldest-entry
        // snapshots cannot race ahead of, or behind, the actual channel operation.
        let Ok(mut queue) = self.state.lock_queue() else {
            return;
        };
        match self.sender.try_send(queued) {
            Ok(()) => {
                queue.entries.push_back(metadata);
                queue.max_queue_depth = queue.max_queue_depth.max(queue.entries.len());
                increment_pair(
                    &self.tap_counters.handoff_enqueued,
                    &self.subscription_counters.handoff_enqueued,
                );
            }
            Err(mpsc::error::TrySendError::Full(_)) => increment_pair(
                &self.tap_counters.handoff_full_drops,
                &self.subscription_counters.handoff_full_drops,
            ),
            Err(mpsc::error::TrySendError::Closed(_)) => increment_pair(
                &self.tap_counters.handoff_closed_drops,
                &self.subscription_counters.handoff_closed_drops,
            ),
        }
        let enqueue_latency = Instant::now().saturating_duration_since(enqueue_started);
        queue.last_enqueue_latency = Some(enqueue_latency);
        queue.max_enqueue_latency = Some(
            queue
                .max_enqueue_latency
                .map_or(enqueue_latency, |maximum| maximum.max(enqueue_latency)),
        );
    }
}

/// Consumer for a bounded, FIFO live observation handoff.
///
/// The receive side discards observations from sequence generations superseded by
/// [`SubscriptionHealth::reset_sequence_state`]. Queue-full behavior is always
/// [`HandoffOverflowPolicy::DropNewest`]; replay high-water state has already
/// advanced before an observation reaches this channel.
///
/// Generation filtering ends when [`Self::recv`] or [`Self::try_recv`] returns.
/// A later reset cannot revoke an observation already returned to application code
/// or wait for its detector work to finish. Before resetting, a caller with a
/// separate consumer task must pause that task, wait for all previously returned
/// observations to finish, reset the downstream detector and sequence state while
/// the task remains paused, and only then resume receiving.
///
/// Closing or dropping this receiver does not undeclare the upstream NCP
/// subscriber; later accepted observations are counted as closed drops. Close the
/// owning [`SidecarTap`] when the subscription should stop at the transport —
/// unless the tap wraps a host-owned bus ([`SidecarTap::from_bus`]), in which case
/// only the host can stop it by closing its own session.
pub struct LiveObservationReceiver {
    receiver: mpsc::Receiver<QueuedObservation>,
    state: Arc<HandoffState>,
    delivery_boundary: Arc<DeliveryBoundary>,
    tap_counters: Arc<IngestCounters>,
    subscription_counters: Arc<IngestCounters>,
}

impl LiveObservationReceiver {
    /// Wait for the next current-generation observation.
    ///
    /// Stale entries left by a reset are drained and counted internally. Returns
    /// `None` after the channel closes and all queued entries have been drained.
    pub async fn recv(&mut self) -> Option<PidObservation> {
        loop {
            let queued =
                poll_fn(|context| self.state.poll_dequeue(&mut self.receiver, context)).await?;
            if let Some(observation) = self.finish_dequeue(queued) {
                return Some(observation);
            }
        }
    }

    /// Attempt to receive the next current-generation observation without waiting.
    ///
    /// Stale entries are drained before returning [`mpsc::error::TryRecvError::Empty`]
    /// or [`mpsc::error::TryRecvError::Disconnected`].
    pub fn try_recv(&mut self) -> Result<PidObservation, mpsc::error::TryRecvError> {
        loop {
            let queued = self.state.try_dequeue(&mut self.receiver)?;
            if let Some(observation) = self.finish_dequeue(queued) {
                return Ok(observation);
            }
        }
    }

    /// Prevent future enqueues while allowing already queued observations to drain.
    /// The upstream transport subscription remains active until its tap is closed.
    pub fn close(&mut self) {
        self.receiver.close();
    }

    /// Whether the receive half has been closed.
    pub fn is_closed(&self) -> bool {
        self.receiver.is_closed()
    }

    fn finish_dequeue(&self, queued: QueuedObservation) -> Option<PidObservation> {
        let Ok(_delivery) = self.delivery_boundary.begin_delivery() else {
            increment_pair(
                &self.tap_counters.handoff_abandoned_drops,
                &self.subscription_counters.handoff_abandoned_drops,
            );
            return None;
        };
        if queued.generation != self.delivery_boundary.generation() {
            increment_pair(
                &self.tap_counters.handoff_stale_generation_drops,
                &self.subscription_counters.handoff_stale_generation_drops,
            );
            return None;
        }
        increment_pair(
            &self.tap_counters.handoff_delivered,
            &self.subscription_counters.handoff_delivered,
        );
        Some(queued.observation)
    }
}

impl Drop for LiveObservationReceiver {
    fn drop(&mut self) {
        let _delivery = self.delivery_boundary.begin_delivery().ok();
        self.state.quarantine_receiver(&mut self.receiver);
    }
}

fn bounded_handoff(
    config: HandoffConfig,
    delivery_boundary: Arc<DeliveryBoundary>,
    sequences: Arc<Mutex<LiveSequenceTracker>>,
    tap_counters: Arc<IngestCounters>,
    subscription_counters: Arc<IngestCounters>,
) -> (
    ObservationHandoff,
    LiveObservationReceiver,
    Arc<HandoffState>,
) {
    let state = Arc::new(HandoffState::new(
        config,
        Arc::clone(&tap_counters),
        Arc::clone(&subscription_counters),
        sequences,
    ));
    let (sender, receiver) = mpsc::channel(config.capacity());
    let handoff = ObservationHandoff {
        sender,
        state: Arc::clone(&state),
        delivery_boundary: Arc::clone(&delivery_boundary),
        tap_counters: Arc::clone(&tap_counters),
        subscription_counters: Arc::clone(&subscription_counters),
    };
    let receiver = LiveObservationReceiver {
        receiver,
        state: Arc::clone(&state),
        delivery_boundary,
        tap_counters,
        subscription_counters,
    };
    (handoff, receiver, state)
}

/// Failure to establish an explicit live sequence-reset boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SequenceResetError {
    /// Reset was requested from any live observation callback on this thread.
    CalledFromCallback,
    /// The target subscription is currently decoding or delivering a payload.
    /// Retry after that delivery returns.
    DeliveryInProgress,
    /// The pending-reset counter could not represent another concurrent request.
    TooManyPendingResets,
    /// The monotonic delivery generation cannot represent another reset.
    GenerationExhausted,
    /// A mutex-protected live state was poisoned and the epoch is terminal.
    InternalStateFault { fault: LiveInternalFault },
}

impl std::fmt::Display for SequenceResetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CalledFromCallback => {
                formatter.write_str("sequence reset cannot run from inside on_obs")
            }
            Self::DeliveryInProgress => {
                formatter.write_str("sequence reset cannot run while delivery is in progress")
            }
            Self::TooManyPendingResets => {
                formatter.write_str("too many concurrent sequence reset requests")
            }
            Self::GenerationExhausted => {
                formatter.write_str("live delivery generation is exhausted")
            }
            Self::InternalStateFault { fault } => {
                write!(
                    formatter,
                    "live epoch has terminal internal fault {fault:?}"
                )
            }
        }
    }
}

impl std::error::Error for SequenceResetError {}

#[derive(Debug, Default)]
struct DeliveryBoundaryState {
    delivery_active: bool,
    reset_active: bool,
    pending_resets: usize,
}

impl DeliveryBoundaryState {
    fn blocks_delivery(&self) -> bool {
        self.delivery_active || self.reset_active || self.pending_resets != 0
    }
}

#[derive(Debug)]
struct DeliveryBoundary {
    state: Mutex<DeliveryBoundaryState>,
    changed: Condvar,
    generation: AtomicU64,
    tap_counters: Arc<IngestCounters>,
    subscription_counters: Arc<IngestCounters>,
}

impl DeliveryBoundary {
    fn new(tap_counters: Arc<IngestCounters>, subscription_counters: Arc<IngestCounters>) -> Self {
        Self {
            state: Mutex::new(DeliveryBoundaryState::default()),
            changed: Condvar::new(),
            generation: AtomicU64::new(0),
            tap_counters,
            subscription_counters,
        }
    }

    fn latch_poison(&self) -> LiveInternalFault {
        let fault = LiveInternalFault::DeliveryBoundaryPoisoned;
        latch_internal_fault_pair(&self.tap_counters, &self.subscription_counters, fault);
        self.changed.notify_all();
        fault
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, DeliveryBoundaryState>, LiveInternalFault> {
        if let Some(fault) = internal_fault_pair(&self.tap_counters, &self.subscription_counters) {
            return Err(fault);
        }
        match self.state.lock() {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                *state = DeliveryBoundaryState::default();
                self.state.clear_poison();
                Err(self.latch_poison())
            }
        }
    }

    fn wait_for_change<'a>(
        &'a self,
        state: std::sync::MutexGuard<'a, DeliveryBoundaryState>,
    ) -> Result<std::sync::MutexGuard<'a, DeliveryBoundaryState>, LiveInternalFault> {
        match self.changed.wait(state) {
            Ok(state) => Ok(state),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                *state = DeliveryBoundaryState::default();
                self.state.clear_poison();
                Err(self.latch_poison())
            }
        }
    }

    fn begin_delivery(&self) -> Result<DeliveryGuard<'_>, LiveInternalFault> {
        let mut state = self.lock_state()?;
        while state.blocks_delivery() {
            state = self.wait_for_change(state)?;
        }
        state.delivery_active = true;
        Ok(DeliveryGuard { boundary: self })
    }

    fn begin_reset(&self) -> Result<ResetGuard<'_>, SequenceResetError> {
        if callback_active() {
            return Err(SequenceResetError::CalledFromCallback);
        }
        let mut state = self
            .lock_state()
            .map_err(|fault| SequenceResetError::InternalStateFault { fault })?;
        if state.delivery_active {
            return Err(SequenceResetError::DeliveryInProgress);
        }
        state.pending_resets = state
            .pending_resets
            .checked_add(1)
            .ok_or(SequenceResetError::TooManyPendingResets)?;
        self.changed.notify_all();
        while state.reset_active {
            state = self
                .wait_for_change(state)
                .map_err(|fault| SequenceResetError::InternalStateFault { fault })?;
        }
        state.pending_resets -= 1;
        state.reset_active = true;
        Ok(ResetGuard { boundary: self })
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn advance_generation(&self) -> Result<u64, SequenceResetError> {
        if let Some(fault) = internal_fault_pair(&self.tap_counters, &self.subscription_counters) {
            return Err(SequenceResetError::InternalStateFault { fault });
        }
        self.generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| SequenceResetError::GenerationExhausted)
    }
}

#[cfg(test)]
impl Default for DeliveryBoundary {
    fn default() -> Self {
        Self::new(
            Arc::new(IngestCounters::default()),
            Arc::new(IngestCounters::default()),
        )
    }
}

struct DeliveryGuard<'a> {
    boundary: &'a DeliveryBoundary,
}

impl Drop for DeliveryGuard<'_> {
    fn drop(&mut self) {
        match self.boundary.state.lock() {
            Ok(mut state) => {
                state.delivery_active = false;
                self.boundary.changed.notify_all();
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                *state = DeliveryBoundaryState::default();
                self.boundary.state.clear_poison();
                self.boundary.latch_poison();
            }
        }
    }
}

struct ResetGuard<'a> {
    boundary: &'a DeliveryBoundary,
}

impl Drop for ResetGuard<'_> {
    fn drop(&mut self) {
        match self.boundary.state.lock() {
            Ok(mut state) => {
                state.reset_active = false;
                self.boundary.changed.notify_all();
            }
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                *state = DeliveryBoundaryState::default();
                self.boundary.state.clear_poison();
                self.boundary.latch_poison();
            }
        }
    }
}

thread_local! {
    /// A callback may synchronously trigger another subscription's receive path on
    /// the same thread. Remember the previous value so nested callback scopes restore
    /// the outer scope instead of clearing it prematurely.
    static CALLBACK_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

fn callback_active() -> bool {
    CALLBACK_ACTIVE.get()
}

struct CallbackGuard {
    previous: bool,
}

impl CallbackGuard {
    fn enter() -> Self {
        let previous = CALLBACK_ACTIVE.replace(true);
        Self { previous }
    }
}

impl Drop for CallbackGuard {
    fn drop(&mut self) {
        CALLBACK_ACTIVE.set(self.previous);
    }
}

type SequenceKey = (TrackId, Modality);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceRejection {
    DuplicateOrRegressed,
    ExcessiveForwardGap,
    CapacityExceeded,
    StateFailure,
}

impl From<SequenceRejection> for RejectionReason {
    fn from(reason: SequenceRejection) -> Self {
        match reason {
            SequenceRejection::DuplicateOrRegressed => Self::DuplicateOrRegressedSequence,
            SequenceRejection::ExcessiveForwardGap => Self::ExcessiveForwardSequenceGap,
            SequenceRejection::CapacityExceeded => Self::SequenceCapacityExceeded,
            SequenceRejection::StateFailure => Self::SequenceStateFailure,
        }
    }
}

#[derive(Debug, Default)]
struct LiveSequenceTracker {
    states: HashMap<SequenceKey, Sequence>,
}

impl LiveSequenceTracker {
    /// Accept a live observation under bounded stream-count and forward-advance
    /// policies. Capacity fails closed: a new stream is rejected without forgetting
    /// any retained replay high-water mark.
    fn accept(
        &mut self,
        observation: &PidObservation,
        max_streams: usize,
        max_forward_gap: u64,
    ) -> Result<(), SequenceRejection> {
        if max_streams == 0 {
            return Err(SequenceRejection::StateFailure);
        }
        if max_forward_gap == 0 {
            return Err(SequenceRejection::StateFailure);
        }

        let key = (observation.track_id(), observation.modality());
        let sequence = observation.sequence();
        if let Some(last) = self.states.get(&key).copied() {
            if sequence <= last {
                return Err(SequenceRejection::DuplicateOrRegressed);
            }
            let gap = sequence
                .get()
                .checked_sub(last.get())
                .ok_or(SequenceRejection::DuplicateOrRegressed)?;
            if gap > max_forward_gap {
                return Err(SequenceRejection::ExcessiveForwardGap);
            }
            self.states.insert(key, sequence);
            return Ok(());
        }

        if self.states.len() >= max_streams {
            return Err(SequenceRejection::CapacityExceeded);
        }
        self.states
            .try_reserve(1)
            .map_err(|_| SequenceRejection::StateFailure)?;
        self.states.insert(key, sequence);
        Ok(())
    }

    fn clear(&mut self) -> usize {
        let removed = self.states.len();
        self.states.clear();
        removed
    }

    fn len(&self) -> usize {
        self.states.len()
    }
}

fn lock_sequence_state<'a>(
    sequences: &'a Mutex<LiveSequenceTracker>,
    tap_counters: &IngestCounters,
    subscription_counters: &IngestCounters,
) -> Result<std::sync::MutexGuard<'a, LiveSequenceTracker>, LiveInternalFault> {
    if let Some(fault) = internal_fault_pair(tap_counters, subscription_counters) {
        return Err(fault);
    }
    match sequences.lock() {
        Ok(state) => Ok(state),
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            *state = LiveSequenceTracker::default();
            drop(state);
            sequences.clear_poison();
            let fault = LiveInternalFault::SequenceStatePoisoned;
            latch_internal_fault_pair(tap_counters, subscription_counters, fault);
            Err(fault)
        }
    }
}

/// Per-subscription ingest health and explicit sequence-epoch recovery.
///
/// Clones share the same counters and sequence state. New streams fail closed at
/// capacity, preserving every retained replay high-water mark. The sidecar key must
/// still be protected by an authenticated, least-privilege NCP ACL.
#[derive(Clone, Debug)]
pub struct SubscriptionHealth {
    counters: Arc<IngestCounters>,
    tap_counters: Arc<IngestCounters>,
    sequences: Arc<Mutex<LiveSequenceTracker>>,
    delivery_boundary: Arc<DeliveryBoundary>,
    handoff: Option<Arc<HandoffState>>,
}

impl SubscriptionHealth {
    /// Payloads received for this subscription, including rejected payloads.
    pub fn payloads_received(&self) -> u64 {
        self.counters.payloads_received.load(Ordering::Relaxed)
    }

    /// Observations that passed decoding, validation, and sequence checks.
    pub fn observations_accepted(&self) -> u64 {
        self.counters.observations_accepted.load(Ordering::Relaxed)
    }

    /// Payloads rejected before the user callback. Use [`Self::rejections`] for the
    /// reason-specific breakdown.
    pub fn decode_failures(&self) -> u64 {
        self.counters.decode_failures.load(Ordering::Relaxed)
    }

    /// Snapshot all typed rejection counters for this subscription.
    pub fn rejections(&self) -> RejectionCounts {
        self.counters.rejection_counts()
    }

    /// Counter value for one typed rejection reason in this subscription.
    pub fn rejection_count(&self, reason: RejectionReason) -> u64 {
        self.counters.rejection_count(reason)
    }

    /// Last observation accepted in this subscription's serialized ingest order.
    /// Returns `None` before the first acceptance and immediately after a reset.
    pub fn last_accepted(&self) -> Option<LastAcceptedObservation> {
        match snapshot_last_accepted(&self.counters) {
            Ok(last) => last,
            Err(fault) => {
                latch_internal_fault_pair(&self.tap_counters, &self.counters, fault);
                None
            }
        }
    }

    /// User callback panics contained at the subscription boundary.
    pub fn callback_panics(&self) -> u64 {
        self.counters.callback_panics.load(Ordering::Relaxed)
    }

    /// Last and maximum execution time for this subscription's accepted callbacks.
    /// Inline subscriptions measure user code; bounded handoffs measure the internal
    /// nonblocking enqueue callback. Decode and validation time are excluded.
    pub fn callback_latency(&self) -> CallbackLatencyMetrics {
        match snapshot_callback_latency(&self.counters) {
            Ok(metrics) => metrics,
            Err(fault) => {
                latch_internal_fault_pair(&self.tap_counters, &self.counters, fault);
                CallbackLatencyMetrics {
                    samples: 0,
                    last: None,
                    maximum: None,
                }
            }
        }
    }

    /// Retained terminal internal fault for this subscription or its parent tap.
    pub fn internal_fault(&self) -> Option<LiveInternalFault> {
        internal_fault_pair(&self.tap_counters, &self.counters)
    }

    /// Number of terminal internal-fault transitions visible to this subscription.
    /// This is zero before failure and one after failure.
    pub fn internal_faults(&self) -> u64 {
        u64::from(self.internal_fault().is_some())
    }

    /// Legacy eviction counter, retained for API compatibility. The fail-closed
    /// capacity policy never evicts sequence state, so this remains zero.
    pub fn sequence_evictions(&self) -> u64 {
        self.counters.sequence_evictions.load(Ordering::Relaxed)
    }

    /// Explicit sequence-state resets requested through this handle.
    pub fn sequence_resets(&self) -> u64 {
        self.counters.sequence_resets.load(Ordering::Relaxed)
    }

    /// Accepted envelopes whose well-formed advisory NCP contract hash differed
    /// from this build. NCP version compatibility remains the hard gate.
    pub fn contract_hash_mismatches(&self) -> u64 {
        self.counters
            .contract_hash_mismatches
            .load(Ordering::Relaxed)
    }

    /// Observations successfully enqueued by this subscription's bounded handoff.
    /// Inline callback subscriptions always report zero.
    pub fn handoff_enqueued(&self) -> u64 {
        self.counters.handoff_enqueued.load(Ordering::Relaxed)
    }

    /// Current-generation observations returned by the bounded receiver.
    pub fn handoff_delivered(&self) -> u64 {
        self.counters.handoff_delivered.load(Ordering::Relaxed)
    }

    /// Accepted observations discarded under the `DropNewest` full-queue policy.
    pub fn handoff_full_drops(&self) -> u64 {
        self.counters.handoff_full_drops.load(Ordering::Relaxed)
    }

    /// Accepted observations discarded because the bounded receiver was closed.
    pub fn handoff_closed_drops(&self) -> u64 {
        self.counters.handoff_closed_drops.load(Ordering::Relaxed)
    }

    /// Queued observations discarded because a reset superseded their generation.
    pub fn handoff_stale_generation_drops(&self) -> u64 {
        self.counters
            .handoff_stale_generation_drops
            .load(Ordering::Relaxed)
    }

    /// Queued observations discarded when the bounded receiver was dropped.
    pub fn handoff_abandoned_drops(&self) -> u64 {
        self.counters
            .handoff_abandoned_drops
            .load(Ordering::Relaxed)
    }

    /// Total full, closed, stale-generation, and abandoned handoff drops.
    pub fn handoff_drops(&self) -> u64 {
        self.handoff_full_drops()
            .saturating_add(self.handoff_closed_drops())
            .saturating_add(self.handoff_stale_generation_drops())
            .saturating_add(self.handoff_abandoned_drops())
    }

    /// Queue depth, oldest observation, drop counts, and consumer-lag metrics for
    /// this subscription's bounded handoff. The snapshot is serialized with enqueue,
    /// dequeue, and reset, so it may wait briefly for current bounded callback work.
    /// Returns `None` for inline callbacks and when a terminal
    /// [`LiveInternalFault`] makes the snapshot unavailable.
    pub fn handoff_metrics(&self) -> Option<HandoffMetrics> {
        let handoff = self.handoff.as_ref()?;
        let _delivery = self.delivery_boundary.begin_delivery().ok()?;
        handoff.snapshot(&self.counters, self.delivery_boundary.generation())
    }

    /// Number of `(track, modality)` sequence streams currently retained.
    pub fn retained_sequence_streams(&self) -> usize {
        lock_sequence_state(&self.sequences, &self.tap_counters, &self.counters)
            .map_or(0, |sequences| sequences.len())
    }

    /// Clear sequence replay state and return the number of removed streams.
    ///
    /// Prefer a fresh `session_id` when the producer restarts. This escape hatch is
    /// for an authenticated, externally confirmed producer epoch change; callers
    /// must reset the downstream detector at the same boundary. Calling it for
    /// ordinary regressions would make replayed observations eligible again.
    ///
    /// Reset and callback delivery share a serialized boundary. A reset acquired
    /// while the subscription is idle prevents a later callback from starting until
    /// it completes. If decoding or callback delivery is already active, this method
    /// fails fast with [`SequenceResetError::DeliveryInProgress`]; callers may retry
    /// after delivery returns. It never waits for an active callback, so a callback
    /// that spawns and joins a reset thread cannot deadlock the receive path.
    ///
    /// This method must not be called directly from **any** live `on_obs` callback,
    /// including a callback for another subscription. Such attempts return
    /// [`SequenceResetError::CalledFromCallback`] without changing state.
    /// Bounded-handoff entries already queued are tagged with the old generation;
    /// the receiver drains and counts them without delivery. Until drained, those
    /// stale entries still occupy bounded capacity and may cause `DropNewest` events.
    /// An observation already returned by the receiver is no longer inside this
    /// boundary and cannot be revoked. A separate consumer must therefore be paused
    /// and acknowledged idle before this method is called, then have its detector
    /// reset before receiving resumes.
    /// This local boundary cannot label or drain bytes already queued inside the
    /// transport; a fresh session ID remains the only unambiguous wire-level epoch.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceResetError`] for a callback-context reset, an active target
    /// delivery, exhausted counters/generation, or terminal poisoned internal state.
    pub fn reset_sequence_state(&self) -> Result<usize, SequenceResetError> {
        let _reset = self.delivery_boundary.begin_reset()?;
        self.delivery_boundary.advance_generation()?;
        let removed = lock_sequence_state(&self.sequences, &self.tap_counters, &self.counters)
            .map_err(|fault| SequenceResetError::InternalStateFault { fault })?
            .clear();
        match self.counters.last_accepted.lock() {
            Ok(mut last) => *last = None,
            Err(poisoned) => {
                let mut last = poisoned.into_inner();
                *last = None;
                self.counters.last_accepted.clear_poison();
                let fault = LiveInternalFault::LastAcceptedTelemetryPoisoned;
                latch_internal_fault_pair(&self.tap_counters, &self.counters, fault);
                return Err(SequenceResetError::InternalStateFault { fault });
            }
        }
        self.counters
            .sequence_resets
            .fetch_add(1, Ordering::Relaxed);
        self.tap_counters
            .sequence_resets
            .fetch_add(1, Ordering::Relaxed);
        Ok(removed)
    }
}

/// Required transport-security intent for opening a live tap.
///
/// There is deliberately no default: production must request [`Self::Secure`],
/// while local work must acknowledge that [`Self::QuietDevelopment`] validates no
/// TLS identity or ACL policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Require Galadriel's single-load strict mTLS client configuration and fail
    /// closed if any local security invariant is absent.
    Secure,
    /// NCP's hardened default config — multicast scouting disabled — without proving
    /// authentication/authorization. If the `NCP_ZENOH_CONFIG` environment variable is
    /// set, ncp-zenoh loads that file **instead** of the hardened default, so the
    /// scouting-off property then depends entirely on the named config.
    QuietDevelopment,
}

/// Explicit lifecycle ownership of a shared Zenoh bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusOwnership {
    /// This component opened the bus and may close it.
    Owned,
    /// A host supplied the bus and retains exclusive close authority.
    HostOwned,
}

/// A live, read-only tap on Galadriel's named perception route over Zenoh.
pub struct SidecarTap {
    bus: ZenohBus,
    realm: String,
    limits: LiveLimits,
    counters: Arc<IngestCounters>,
    /// Whether this tap opened (and therefore owns) its Zenoh session. `from_bus`
    /// taps wrap a host-owned bus and must never close it: `ZenohBus` clones share
    /// one session and one retained-subscriber registry, so closing from the tap
    /// would tear down the host's entire transport.
    ownership: BusOwnership,
}

impl SidecarTap {
    /// Open a tap on the default NCP realm with explicit transport-security intent.
    pub async fn open(mode: TransportMode) -> Result<Self, ZenohError> {
        Self::open_with_limits(mode, bounded_live_limits()?).await
    }

    /// Open a default-realm tap with explicit intent and caller-supplied limits.
    pub async fn open_with_limits(
        mode: TransportMode,
        limits: LiveLimits,
    ) -> Result<Self, ZenohError> {
        let keys = Keys::default();
        let bus = match mode {
            TransportMode::Secure => crate::secure_live::open_secure_bus(keys).await?,
            TransportMode::QuietDevelopment => ZenohBus::open_realm(keys).await?,
        };
        Self::from_parts(bus, DEFAULT_REALM.to_string(), limits, BusOwnership::Owned)
    }

    fn from_parts(
        bus: ZenohBus,
        realm: String,
        limits: LiveLimits,
        ownership: BusOwnership,
    ) -> Result<Self, ZenohError> {
        if !valid_realm(&realm) {
            return Err(ZenohError(format!(
                "invalid NCP realm: expected concrete key segments, got {realm:?}"
            )));
        }
        Ok(Self {
            bus,
            realm,
            limits,
            counters: Arc::new(IngestCounters::default()),
            ownership,
        })
    }

    /// Open a tap on an explicit realm with explicit transport-security intent.
    pub async fn open_realm(
        realm: impl Into<String>,
        mode: TransportMode,
    ) -> Result<Self, ZenohError> {
        Self::open_realm_with_limits(realm, mode, bounded_live_limits()?).await
    }

    /// Open an explicit-realm tap with explicit intent and caller-supplied limits.
    pub async fn open_realm_with_limits(
        realm: impl Into<String>,
        mode: TransportMode,
        limits: LiveLimits,
    ) -> Result<Self, ZenohError> {
        let realm = realm.into();
        if !valid_realm(&realm) {
            return Err(ZenohError(format!(
                "invalid NCP realm: expected concrete key segments, got {realm:?}"
            )));
        }
        let keys = Keys::try_new(&realm)
            .map_err(|error| ZenohError(format!("invalid NCP realm: {error}")))?;
        let bus = match mode {
            TransportMode::Secure => crate::secure_live::open_secure_bus(keys).await?,
            TransportMode::QuietDevelopment => ZenohBus::open_realm(keys).await?,
        };
        Self::from_parts(bus, realm, limits, BusOwnership::Owned)
    }

    /// Wrap an already-open bus, so a host app can share one Zenoh session across its
    /// own traffic and galadriel's observer tap. The realm is derived from the bus,
    /// eliminating a caller-supplied realm that could silently subscribe to the wrong
    /// keyspace. This constructor inherits the host's transport-security choice and
    /// cannot prove that the existing session used strict mTLS; the host remains
    /// responsible for that deployment invariant.
    ///
    /// A shared tap does **not** own the session: [`Self::close`] refuses with a typed
    /// error, and the tap's subscriptions remain declared on the host session until
    /// the host closes its own `ZenohBus`. The host owns the transport lifecycle.
    pub fn from_bus(bus: ZenohBus) -> Result<Self, ZenohError> {
        Self::from_bus_with_limits(bus, bounded_live_limits()?)
    }

    /// Wrap an already-open bus with caller-supplied payload limits.
    /// See [`Self::from_bus`] for the shared-session close semantics.
    pub fn from_bus_with_limits(bus: ZenohBus, limits: LiveLimits) -> Result<Self, ZenohError> {
        let realm = bus.keys().realm().to_owned();
        Self::from_parts(bus, realm, limits, BusOwnership::HostOwned)
    }

    /// Payloads rejected for excessive size, malformed JSON, invalid observation
    /// values, duplicate/regressed sequence numbers, or excessive sequence advances,
    /// across all subscriptions. Use [`Self::rejections`] for the typed breakdown.
    /// Rejected input is dropped before the callback but never silently.
    pub fn decode_failures(&self) -> u64 {
        self.counters.decode_failures.load(Ordering::Relaxed)
    }

    /// Snapshot typed rejection counters across all subscriptions.
    pub fn rejections(&self) -> RejectionCounts {
        self.counters.rejection_counts()
    }

    /// Counter value for one typed rejection reason across all subscriptions.
    pub fn rejection_count(&self, reason: RejectionReason) -> u64 {
        self.counters.rejection_count(reason)
    }

    /// Last observation accepted by any subscription on this tap before callback or
    /// bounded-handoff outcome.
    /// Concurrent subscriptions have independent delivery order, so this is a
    /// diagnostic snapshot rather than a global causal ordering. A per-subscription
    /// sequence reset does **not** clear this tap-level snapshot, so it may still
    /// report an observation from before the reset.
    pub fn last_accepted(&self) -> Option<LastAcceptedObservation> {
        match snapshot_last_accepted(&self.counters) {
            Ok(last) => last,
            Err(fault) => {
                latch_internal_fault(&self.counters, fault);
                None
            }
        }
    }

    /// User callback panics caught at the receive boundary. The first panic latches
    /// a terminal fault so no later payload is decoded or delivered.
    pub fn callback_panics(&self) -> u64 {
        self.counters.callback_panics.load(Ordering::Relaxed)
    }

    /// Last and maximum callback execution time across this tap's subscriptions.
    /// The `last` value is the most recently completed callback across independent
    /// subscriptions; `maximum` is their aggregate high-water mark.
    pub fn callback_latency(&self) -> CallbackLatencyMetrics {
        match snapshot_callback_latency(&self.counters) {
            Ok(metrics) => metrics,
            Err(fault) => {
                latch_internal_fault(&self.counters, fault);
                CallbackLatencyMetrics {
                    samples: 0,
                    last: None,
                    maximum: None,
                }
            }
        }
    }

    /// Retained tap-wide terminal internal fault, if any subscription state or
    /// tap telemetry was poisoned.
    pub fn internal_fault(&self) -> Option<LiveInternalFault> {
        self.counters.internal_fault()
    }

    /// Number of tap-wide terminal internal-fault transitions (zero or one).
    pub fn internal_faults(&self) -> u64 {
        self.counters.internal_faults.load(Ordering::Relaxed)
    }

    /// Total payloads seen on the sidecar key (decoded **or** dropped), across all
    /// subscriptions of this tap. This is the tap's **liveness signal**: brokered
    /// pub/sub fails *silent* — a realm mismatch (producer on `"engram/ncp"`, tap on
    /// another realm), a key typo, or an ACL denial all look identical to "no traffic".
    /// [`Self::decode_failures`] only catches drift in payloads that *arrive*; a stuck
    /// zero **here**, while the producer's session is known to be active, is the
    /// symptom of a mis-wired feed. Operators should alarm on it — the detector itself
    /// already fails closed (starved windows yield `InsufficientEvidence`, never a
    /// clean `Nominal`), so this counter is about *diagnosing* the starvation, not
    /// about safety.
    pub fn payloads_received(&self) -> u64 {
        self.counters.payloads_received.load(Ordering::Relaxed)
    }

    /// Observations accepted across all subscriptions before invoking callbacks.
    pub fn observations_accepted(&self) -> u64 {
        self.counters.observations_accepted.load(Ordering::Relaxed)
    }

    /// Legacy aggregate eviction counter. The fail-closed capacity policy never
    /// evicts sequence state, so this remains zero.
    pub fn sequence_evictions(&self) -> u64 {
        self.counters.sequence_evictions.load(Ordering::Relaxed)
    }

    /// Explicit sequence-state resets across all subscription health handles.
    pub fn sequence_resets(&self) -> u64 {
        self.counters.sequence_resets.load(Ordering::Relaxed)
    }

    /// Accepted envelopes with an advisory NCP contract-hash mismatch across all
    /// subscriptions.
    pub fn contract_hash_mismatches(&self) -> u64 {
        self.counters
            .contract_hash_mismatches
            .load(Ordering::Relaxed)
    }

    /// Successful bounded-channel enqueues across all subscriptions on this tap.
    pub fn handoff_enqueued(&self) -> u64 {
        self.counters.handoff_enqueued.load(Ordering::Relaxed)
    }

    /// Current-generation observations returned by bounded receivers on this tap.
    pub fn handoff_delivered(&self) -> u64 {
        self.counters.handoff_delivered.load(Ordering::Relaxed)
    }

    /// Accepted observations dropped because a bounded handoff was full.
    pub fn handoff_full_drops(&self) -> u64 {
        self.counters.handoff_full_drops.load(Ordering::Relaxed)
    }

    /// Accepted observations dropped because a bounded receiver was closed.
    pub fn handoff_closed_drops(&self) -> u64 {
        self.counters.handoff_closed_drops.load(Ordering::Relaxed)
    }

    /// Queued observations discarded after a sequence-generation reset.
    pub fn handoff_stale_generation_drops(&self) -> u64 {
        self.counters
            .handoff_stale_generation_drops
            .load(Ordering::Relaxed)
    }

    /// Queued observations discarded when bounded receivers were dropped.
    pub fn handoff_abandoned_drops(&self) -> u64 {
        self.counters
            .handoff_abandoned_drops
            .load(Ordering::Relaxed)
    }

    /// Total bounded-handoff drops across all subscriptions on this tap.
    pub fn handoff_drops(&self) -> u64 {
        self.handoff_full_drops()
            .saturating_add(self.handoff_closed_drops())
            .saturating_add(self.handoff_stale_generation_drops())
            .saturating_add(self.handoff_abandoned_drops())
    }

    /// The underlying bus (e.g. to close it, or share the session).
    pub fn bus(&self) -> &ZenohBus {
        &self.bus
    }

    /// Subscribe to a session's `sensor/galadriel-pid` route. `on_obs` runs **inline
    /// on Zenoh's receive task** for each decoded observation, so keep it cheap
    /// (decode + hand off). Each envelope must declare the same `session_id` and
    /// `producer_id` supplied here; this is payload provenance, while mTLS/ACL is
    /// responsible for authenticating the publisher.
    ///
    /// Oversized, malformed, invalid, misattributed, duplicate, regressed, and
    /// excessive-forward-gap payloads are dropped and counted by
    /// [`Self::decode_failures`]. A callback panic is caught, counted by
    /// [`Self::callback_panics`], and latched as a terminal internal fault so it
    /// cannot unwind Zenoh's receive task or permit later delivery.
    pub async fn subscribe<F>(
        &self,
        session_id: &str,
        producer_id: &str,
        on_obs: F,
    ) -> Result<(), ZenohError>
    where
        F: Fn(PidObservation) + Send + Sync + 'static,
    {
        self.subscribe_with_health(session_id, producer_id, on_obs)
            .await
            .map(|_| ())
    }

    /// Subscribe and return counters scoped to this one session subscription.
    ///
    /// The returned handle also exposes an explicit sequence-state reset for a
    /// confirmed producer restart. Prefer a fresh session ID so replay epochs are
    /// separated by construction.
    pub async fn subscribe_with_health<F>(
        &self,
        session_id: &str,
        producer_id: &str,
        on_obs: F,
    ) -> Result<SubscriptionHealth, ZenohError>
    where
        F: Fn(PidObservation) + Send + Sync + 'static,
    {
        let key = sidecar_key(&self.realm, session_id)
            .ok_or_else(|| ZenohError("invalid Galadriel session identity".to_string()))?;
        if !valid_producer_identity(producer_id) {
            return Err(ZenohError(
                "invalid Galadriel producer identity".to_string(),
            ));
        }
        let expected_session_id = session_id.to_owned();
        let expected_producer_id = producer_id.to_owned();
        let tap_counters = Arc::clone(&self.counters);
        let subscription_counters = Arc::new(IngestCounters::default());
        let limits = self.limits;
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let delivery_boundary = Arc::new(DeliveryBoundary::new(
            Arc::clone(&tap_counters),
            Arc::clone(&subscription_counters),
        ));
        let health = SubscriptionHealth {
            counters: Arc::clone(&subscription_counters),
            tap_counters: Arc::clone(&tap_counters),
            sequences: Arc::clone(&sequences),
            delivery_boundary: Arc::clone(&delivery_boundary),
            handoff: None,
        };
        self.bus
            .subscribe(&key, move |_key, bytes| {
                process_payload(
                    &bytes,
                    PayloadContext {
                        expected_session_id: &expected_session_id,
                        expected_producer_id: &expected_producer_id,
                        limits,
                        delivery_boundary: &delivery_boundary,
                        sequences: &sequences,
                        tap_counters: &tap_counters,
                        subscription_counters: &subscription_counters,
                    },
                    &on_obs,
                );
            })
            .await?;
        Ok(health)
    }

    /// Subscribe with a bounded FIFO handoff instead of a user callback on Zenoh's
    /// receive task.
    ///
    /// Decode, validation, and sequence admission still execute inline, followed by
    /// one nonblocking `try_send`. When the queue is full, the newly accepted
    /// observation is dropped and counted while its replay high-water mark remains
    /// advanced. This prevents slow detector work from blocking the receive task and
    /// prevents a queue overflow from reopening replay eligibility.
    ///
    /// [`SubscriptionHealth::reset_sequence_state`] advances a delivery generation;
    /// the receiver drains and counts entries from older generations without exposing
    /// them to the consumer.
    pub async fn subscribe_channel(
        &self,
        session_id: &str,
        producer_id: &str,
        config: HandoffConfig,
    ) -> Result<(SubscriptionHealth, LiveObservationReceiver), ZenohError> {
        let key = sidecar_key(&self.realm, session_id)
            .ok_or_else(|| ZenohError("invalid Galadriel session identity".to_string()))?;
        if !valid_producer_identity(producer_id) {
            return Err(ZenohError(
                "invalid Galadriel producer identity".to_string(),
            ));
        }
        let expected_session_id = session_id.to_owned();
        let expected_producer_id = producer_id.to_owned();
        let tap_counters = Arc::clone(&self.counters);
        let subscription_counters = Arc::new(IngestCounters::default());
        let limits = self.limits;
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let delivery_boundary = Arc::new(DeliveryBoundary::new(
            Arc::clone(&tap_counters),
            Arc::clone(&subscription_counters),
        ));
        let (handoff, receiver, handoff_state) = bounded_handoff(
            config,
            Arc::clone(&delivery_boundary),
            Arc::clone(&sequences),
            Arc::clone(&tap_counters),
            Arc::clone(&subscription_counters),
        );
        let health = SubscriptionHealth {
            counters: Arc::clone(&subscription_counters),
            tap_counters: Arc::clone(&tap_counters),
            sequences: Arc::clone(&sequences),
            delivery_boundary: Arc::clone(&delivery_boundary),
            handoff: Some(handoff_state),
        };
        self.bus
            .subscribe(&key, move |_key, bytes| {
                handoff.preflight();
                process_payload(
                    &bytes,
                    PayloadContext {
                        expected_session_id: &expected_session_id,
                        expected_producer_id: &expected_producer_id,
                        limits,
                        delivery_boundary: &delivery_boundary,
                        sequences: &sequences,
                        tap_counters: &tap_counters,
                        subscription_counters: &subscription_counters,
                    },
                    &|observation| handoff.enqueue(observation),
                );
            })
            .await?;
        Ok((health, receiver))
    }

    /// Gracefully close the underlying Zenoh session (undeclare subscribers and flush).
    ///
    /// Only a tap that opened its own session (the `open*` constructors) may close it.
    /// A tap created with [`Self::from_bus`] wraps a **host-owned** bus whose clones
    /// share one Zenoh session and one retained-subscriber registry; closing from the
    /// tap would silently tear down the host's entire transport — every subscription,
    /// not just galadriel's. That call therefore fails with a typed error and changes
    /// nothing; the host closes the session through its own `ZenohBus` handle.
    pub async fn close(&self) -> Result<(), ZenohError> {
        if self.ownership != BusOwnership::Owned {
            return Err(ZenohError(
                "refusing to close a host-owned bus: this tap was created with \
                 from_bus, and closing would tear down the host's shared Zenoh \
                 session; the host application owns that lifecycle"
                    .to_string(),
            ));
        }
        self.bus.close().await
    }
}

#[derive(Clone, Copy)]
struct PayloadContext<'a> {
    expected_session_id: &'a str,
    expected_producer_id: &'a str,
    limits: LiveLimits,
    delivery_boundary: &'a DeliveryBoundary,
    sequences: &'a Mutex<LiveSequenceTracker>,
    tap_counters: &'a IngestCounters,
    subscription_counters: &'a IngestCounters,
}

fn process_payload<F>(bytes: &[u8], context: PayloadContext<'_>, on_obs: &F)
where
    F: Fn(PidObservation),
{
    increment_pair(
        &context.tap_counters.payloads_received,
        &context.subscription_counters.payloads_received,
    );
    // Detect a poison event that predates this callback before parsing attacker-
    // controlled bytes. A poison that races after this boundary is still caught by
    // the mandatory sequence lock before admission; mutex poison cannot be observed
    // asynchronously at the instant another thread panics.
    if context.sequences.is_poisoned() {
        drop(lock_sequence_state(
            context.sequences,
            context.tap_counters,
            context.subscription_counters,
        ));
    }
    if internal_fault_pair(context.tap_counters, context.subscription_counters).is_some()
        || !preflight_telemetry_pair(context.tap_counters, context.subscription_counters)
    {
        reject_pair(
            context.tap_counters,
            context.subscription_counters,
            RejectionReason::SequenceStateFailure,
        );
        return;
    }
    let Ok(_delivery) = context.delivery_boundary.begin_delivery() else {
        reject_pair(
            context.tap_counters,
            context.subscription_counters,
            RejectionReason::SequenceStateFailure,
        );
        return;
    };
    if bytes.len() > context.limits.max_payload_bytes {
        reject_pair(
            context.tap_counters,
            context.subscription_counters,
            RejectionReason::PayloadTooLarge,
        );
        return;
    }

    // Parse straight into the strict raw DTO, then perform typed semantic conversion.
    // A `serde_json::Value` intermediate would collapse duplicate JSON keys (last
    // occurrence wins) before `deny_unknown_fields` could reject them — a parser
    // differential with first-wins JSON consumers on a security boundary. Keeping
    // conversion separate also preserves typed compatibility rejection.
    let envelope = match SidecarEnvelope::decode(bytes) {
        Ok(envelope) => envelope,
        Err(SidecarDecodeError::MalformedJson) => {
            reject_pair(
                context.tap_counters,
                context.subscription_counters,
                RejectionReason::MalformedJson,
            );
            return;
        }
        Err(SidecarDecodeError::InvalidEnvelope) => {
            reject_pair(
                context.tap_counters,
                context.subscription_counters,
                RejectionReason::InvalidEnvelope,
            );
            return;
        }
        Err(SidecarDecodeError::Semantic(error)) => {
            reject_pair(
                context.tap_counters,
                context.subscription_counters,
                rejection_reason_for_envelope_error(&error),
            );
            return;
        }
    };
    let contract_hash_mismatch =
        match envelope.validate_for(context.expected_session_id, context.expected_producer_id) {
            Ok(ContractStatus::Mismatch { .. }) => true,
            Ok(ContractStatus::Match | ContractStatus::NotAdvertised) => false,
            Err(error) => {
                reject_pair(
                    context.tap_counters,
                    context.subscription_counters,
                    rejection_reason_for_envelope_error(&error),
                );
                return;
            }
        };
    let observation = envelope.observation;
    {
        let mut sequences = match lock_sequence_state(
            context.sequences,
            context.tap_counters,
            context.subscription_counters,
        ) {
            Ok(sequences) => sequences,
            Err(_) => {
                reject_pair(
                    context.tap_counters,
                    context.subscription_counters,
                    RejectionReason::SequenceStateFailure,
                );
                return;
            }
        };
        match sequences.accept(
            &observation,
            context.limits.max_sequence_streams,
            context.limits.max_sequence_advance,
        ) {
            Ok(()) => {}
            Err(reason) => {
                reject_pair(
                    context.tap_counters,
                    context.subscription_counters,
                    reason.into(),
                );
                return;
            }
        }
    }
    if contract_hash_mismatch {
        increment_pair(
            &context.tap_counters.contract_hash_mismatches,
            &context.subscription_counters.contract_hash_mismatches,
        );
    }
    if record_acceptance_pair(
        context.tap_counters,
        context.subscription_counters,
        &observation,
    )
    .is_err()
    {
        return;
    }

    let callback_started = Instant::now();
    let callback_panicked = {
        let _callback = CallbackGuard::enter();
        catch_unwind(AssertUnwindSafe(|| on_obs(observation))).is_err()
    };
    let callback_completed_at = Instant::now();
    if callback_panicked {
        increment_pair(
            &context.tap_counters.callback_panics,
            &context.subscription_counters.callback_panics,
        );
        latch_internal_fault_pair(
            context.tap_counters,
            context.subscription_counters,
            LiveInternalFault::CallbackPanicked,
        );
    }
    if let Err(fault) = record_callback_latency_pair(
        context.tap_counters,
        context.subscription_counters,
        callback_completed_at.saturating_duration_since(callback_started),
        callback_completed_at,
    ) {
        latch_internal_fault_pair(context.tap_counters, context.subscription_counters, fault);
    }
}

fn increment_pair(tap: &AtomicU64, subscription: &AtomicU64) {
    increment_pair_by(tap, subscription, 1);
}

fn increment_pair_by(tap: &AtomicU64, subscription: &AtomicU64, amount: u64) {
    tap.fetch_add(amount, Ordering::Relaxed);
    subscription.fetch_add(amount, Ordering::Relaxed);
}

fn record_callback_latency_pair(
    tap: &IngestCounters,
    subscription: &IngestCounters,
    latency: Duration,
    completed_at: Instant,
) -> Result<(), LiveInternalFault> {
    record_callback_latency(tap, latency, completed_at)?;
    record_callback_latency(subscription, latency, completed_at)
}

fn record_callback_latency(
    counters: &IngestCounters,
    latency: Duration,
    completed_at: Instant,
) -> Result<(), LiveInternalFault> {
    let mut state = match counters.callback_latency.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            *state = CallbackLatencyState::default();
            counters.callback_latency.clear_poison();
            return Err(LiveInternalFault::CallbackLatencyTelemetryPoisoned);
        }
    };
    state.samples = state.samples.saturating_add(1);
    state.maximum = Some(
        state
            .maximum
            .map_or(latency, |maximum| maximum.max(latency)),
    );
    if state
        .last_completed_at
        .is_none_or(|previous| completed_at >= previous)
    {
        state.last = Some(latency);
        state.last_completed_at = Some(completed_at);
    }
    Ok(())
}

fn rejection_counter(counters: &IngestCounters, reason: RejectionReason) -> &AtomicU64 {
    match reason {
        RejectionReason::PayloadTooLarge => &counters.payload_too_large,
        RejectionReason::MalformedJson => &counters.malformed_json,
        RejectionReason::InvalidEnvelope => &counters.invalid_envelope,
        RejectionReason::IncompatibleNcpVersion => &counters.incompatible_ncp_version,
        RejectionReason::ProvenanceMismatch => &counters.provenance_mismatch,
        RejectionReason::InvalidObservation => &counters.invalid_observation,
        RejectionReason::DuplicateOrRegressedSequence => &counters.duplicate_or_regressed_sequence,
        RejectionReason::ExcessiveForwardSequenceGap => &counters.excessive_forward_sequence_gap,
        RejectionReason::SequenceCapacityExceeded => &counters.sequence_capacity_exceeded,
        RejectionReason::SequenceStateFailure => &counters.sequence_state_failure,
    }
}

fn rejection_reason_for_envelope_error(error: &SidecarEnvelopeError) -> RejectionReason {
    match error {
        SidecarEnvelopeError::IncompatibleNcpVersion(_) => RejectionReason::IncompatibleNcpVersion,
        SidecarEnvelopeError::ProvenanceMismatch { .. } => RejectionReason::ProvenanceMismatch,
        SidecarEnvelopeError::InvalidObservation(_)
        | SidecarEnvelopeError::IntegerOutOfRange { .. } => RejectionReason::InvalidObservation,
        _ => RejectionReason::InvalidEnvelope,
    }
}

fn reject_pair(tap: &IngestCounters, subscription: &IngestCounters, reason: RejectionReason) {
    increment_pair(&tap.decode_failures, &subscription.decode_failures);
    increment_pair(
        rejection_counter(tap, reason),
        rejection_counter(subscription, reason),
    );
}

fn record_acceptance_pair(
    tap: &IngestCounters,
    subscription: &IngestCounters,
    observation: &PidObservation,
) -> Result<(), LiveInternalFault> {
    let last = Some(LastAcceptedObservation::from(observation));
    match tap.last_accepted.lock() {
        Ok(mut accepted) => *accepted = last,
        Err(poisoned) => {
            let mut accepted = poisoned.into_inner();
            *accepted = None;
            tap.last_accepted.clear_poison();
            let fault = LiveInternalFault::LastAcceptedTelemetryPoisoned;
            latch_internal_fault_pair(tap, subscription, fault);
            return Err(fault);
        }
    }
    match subscription.last_accepted.lock() {
        Ok(mut accepted) => *accepted = last,
        Err(poisoned) => {
            let mut accepted = poisoned.into_inner();
            *accepted = None;
            subscription.last_accepted.clear_poison();
            let fault = LiveInternalFault::LastAcceptedTelemetryPoisoned;
            latch_internal_fault_pair(tap, subscription, fault);
            return Err(fault);
        }
    }
    increment_pair(
        &tap.observations_accepted,
        &subscription.observations_accepted,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use galadriel_core::Modality;
    use std::sync::{mpsc, Barrier};
    use std::thread;
    use std::time::Duration;

    const TEST_SESSION_ID: &str = "session-1";
    const TEST_PRODUCER_ID: &str = "crebain";

    fn envelope(observation: PidObservation) -> SidecarEnvelope {
        SidecarEnvelope {
            kind: crate::SIDECAR_KIND.to_string(),
            schema_version: crate::SIDECAR_SCHEMA_VERSION.to_string(),
            ncp_version: ncp_core::NCP_VERSION.to_string(),
            contract_hash: ncp_core::CONTRACT_HASH.to_string(),
            session_id: TEST_SESSION_ID.to_string(),
            producer_id: TEST_PRODUCER_ID.to_string(),
            observation,
        }
    }

    fn test_observation(
        track_id: u64,
        timestamp_ms: u64,
        sequence: u64,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> PidObservation {
        PidObservation::try_scalar_raw(track_id, timestamp_ms, sequence, modality, nis, dof)
            .expect("test observation is valid")
    }

    fn encoded(track_id: u64, sequence: u64) -> Vec<u8> {
        serde_json::to_vec(&envelope(test_observation(
            track_id,
            sequence,
            sequence,
            Modality::Radar,
            3.0,
            3,
        )))
        .unwrap()
    }

    fn process_payload<F>(
        bytes: &[u8],
        limits: LiveLimits,
        delivery_boundary: &DeliveryBoundary,
        sequences: &Mutex<LiveSequenceTracker>,
        tap_counters: &IngestCounters,
        subscription_counters: &IngestCounters,
        on_obs: &F,
    ) where
        F: Fn(PidObservation),
    {
        super::process_payload(
            bytes,
            PayloadContext {
                expected_session_id: TEST_SESSION_ID,
                expected_producer_id: TEST_PRODUCER_ID,
                limits,
                delivery_boundary,
                sequences,
                tap_counters,
                subscription_counters,
            },
            on_obs,
        );
    }

    struct HandoffHarness {
        delivery_boundary: Arc<DeliveryBoundary>,
        sequences: Arc<Mutex<LiveSequenceTracker>>,
        tap_counters: Arc<IngestCounters>,
        subscription_counters: Arc<IngestCounters>,
        health: SubscriptionHealth,
        handoff: ObservationHandoff,
        receiver: Option<LiveObservationReceiver>,
    }

    impl HandoffHarness {
        fn new(capacity: usize) -> Self {
            let config = HandoffConfig::new(capacity).unwrap();
            let tap_counters = Arc::new(IngestCounters::default());
            let subscription_counters = Arc::new(IngestCounters::default());
            let delivery_boundary = Arc::new(DeliveryBoundary::new(
                Arc::clone(&tap_counters),
                Arc::clone(&subscription_counters),
            ));
            let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
            let (handoff, receiver, state) = bounded_handoff(
                config,
                Arc::clone(&delivery_boundary),
                Arc::clone(&sequences),
                Arc::clone(&tap_counters),
                Arc::clone(&subscription_counters),
            );
            let health = SubscriptionHealth {
                counters: Arc::clone(&subscription_counters),
                tap_counters: Arc::clone(&tap_counters),
                sequences: Arc::clone(&sequences),
                delivery_boundary: Arc::clone(&delivery_boundary),
                handoff: Some(state),
            };
            Self {
                delivery_boundary,
                sequences,
                tap_counters,
                subscription_counters,
                health,
                handoff,
                receiver: Some(receiver),
            }
        }

        fn push(&self, track_id: u64, sequence: u64) {
            self.handoff.preflight();
            process_payload(
                &encoded(track_id, sequence),
                LiveLimits::default(),
                &self.delivery_boundary,
                &self.sequences,
                &self.tap_counters,
                &self.subscription_counters,
                &|observation| self.handoff.enqueue(observation),
            );
        }

        fn receiver(&mut self) -> &mut LiveObservationReceiver {
            self.receiver.as_mut().unwrap()
        }
    }

    #[test]
    fn handoff_config_rejects_zero_capacity() {
        assert_eq!(HandoffConfig::new(0), Err(HandoffConfigError::ZeroCapacity));
    }

    #[test]
    fn handoff_config_rejects_capacity_above_hard_limit() {
        assert_eq!(
            HandoffConfig::new(MAX_LIVE_HANDOFF_CAPACITY + 1),
            Err(HandoffConfigError::CapacityTooLarge {
                capacity: MAX_LIVE_HANDOFF_CAPACITY + 1,
                maximum: MAX_LIVE_HANDOFF_CAPACITY,
            })
        );
    }

    #[test]
    fn handoff_config_accepts_the_exact_capacity_and_aggregate_byte_boundaries() {
        let config = HandoffConfig::new(MAX_LIVE_HANDOFF_CAPACITY)
            .expect("the exact handoff capacity ceiling is inclusive");

        assert_eq!(config.capacity(), MAX_LIVE_HANDOFF_CAPACITY);
        assert_eq!(
            config.capacity() * DEFAULT_MAX_LIVE_PAYLOAD_BYTES,
            MAX_LIVE_HANDOFF_STATE_BYTES
        );
        assert_eq!(config.overflow_policy(), HandoffOverflowPolicy::DropNewest);
    }

    #[test]
    fn release_live_profiles_have_stable_identities() {
        let handoff = HandoffProfile::BoundedV0_9.try_config().unwrap();
        let limits = LiveLimitsProfile::BoundedV0_9.try_limits().unwrap();

        assert_eq!(MAX_LIVE_CONFIGURED_WORK_UNITS, 4_194_304);
        assert_eq!(
            handoff.identity().to_hex(),
            "8102d551625d24f8cae73f7e467c8bf8bb5c5e1a3b8747c50b1a4ef6aaed70b3"
        );
        assert_eq!(
            limits.identity().to_hex(),
            "c7f6f6b6446415c5610d313ec0465093597e76cb5b2be2bc16b2818a4939fdcb"
        );
    }

    #[test]
    fn live_limits_reject_scalar_and_aggregate_boundaries() {
        assert!(matches!(
            LiveLimits::with_sequence_policy(0, 1, 1),
            Err(LiveLimitsError::Zero {
                field: "max_payload_bytes"
            })
        ));
        assert!(matches!(
            LiveLimits::with_sequence_policy(MAX_LIVE_PAYLOAD_BYTES + 1, 1, 1),
            Err(LiveLimitsError::ExceedsHardMaximum {
                field: "max_payload_bytes",
                ..
            })
        ));
        assert!(matches!(
            LiveLimits::with_sequence_policy(MAX_LIVE_PAYLOAD_BYTES, MAX_LIVE_SEQUENCE_STREAMS, 1,),
            Err(LiveLimitsError::AggregateWorkTooLarge { .. })
        ));

        let streams_at_exact_work_ceiling = (MAX_LIVE_CONFIGURED_WORK_UNITS
            - MAX_LIVE_PAYLOAD_BYTES)
            / LIVE_SEQUENCE_STATE_WORK_UNITS;
        let exact = LiveLimits::with_sequence_policy(
            MAX_LIVE_PAYLOAD_BYTES,
            streams_at_exact_work_ceiling,
            1,
        )
        .expect("the exact configured-work ceiling is inclusive");
        assert_eq!(
            exact.max_sequence_streams() * LIVE_SEQUENCE_STATE_WORK_UNITS
                + exact.max_payload_bytes(),
            MAX_LIVE_CONFIGURED_WORK_UNITS
        );
        assert!(matches!(
            LiveLimits::with_sequence_policy(
                MAX_LIVE_PAYLOAD_BYTES,
                streams_at_exact_work_ceiling + 1,
                1,
            ),
            Err(LiveLimitsError::AggregateWorkTooLarge {
                value,
                maximum: MAX_LIVE_CONFIGURED_WORK_UNITS,
            }) if value == MAX_LIVE_CONFIGURED_WORK_UNITS + LIVE_SEQUENCE_STATE_WORK_UNITS
        ));

        let mut changed = LiveLimitsProfile::BoundedV0_9.params();
        changed.max_sequence_advance += 1;
        assert_ne!(
            LiveLimits::try_from(changed).unwrap().identity(),
            LiveLimitsProfile::BoundedV0_9
                .try_limits()
                .unwrap()
                .identity()
        );
    }

    #[test]
    fn bounded_handoff_drops_newest_at_capacity_and_reports_queue_metrics() {
        let mut harness = HandoffHarness::new(1);

        harness.push(1, 1);
        harness.push(1, 2);

        let full = harness.health.handoff_metrics().unwrap();
        assert_eq!(full.queue_depth, 1);
        assert_eq!(full.max_queue_depth, 1);
        assert_eq!(full.enqueued, 1);
        assert_eq!(full.full_drops, 1);
        assert_eq!(full.total_drops(), 1);
        assert_eq!(full.oldest_queued.unwrap().sequence, 1);
        assert!(full.oldest_enqueue_age.is_some());
        assert!(full.last_enqueue_latency.is_some());
        assert!(full.max_enqueue_latency.is_some());
        let callbacks = harness.health.callback_latency();
        assert_eq!(callbacks.samples, 2);
        assert!(callbacks.last.is_some());
        assert!(callbacks.maximum.is_some());
        assert!(callbacks.maximum >= callbacks.last);
        assert_eq!(
            snapshot_callback_latency(&harness.tap_counters)
                .expect("test callback telemetry is healthy")
                .samples,
            2
        );

        let delivered = harness.receiver().try_recv().unwrap();
        assert_eq!(delivered.sequence().get(), 1);
        let drained = harness.health.handoff_metrics().unwrap();
        assert_eq!(drained.queue_depth, 0);
        assert_eq!(drained.delivered, 1);
        assert!(drained.last_dequeue_latency.is_some());
        assert!(drained.max_dequeue_latency.is_some());
    }

    #[test]
    fn bounded_handoff_is_fifo_and_full_drop_does_not_reopen_replay() {
        let mut harness = HandoffHarness::new(2);
        harness.push(1, 1);
        harness.push(1, 2);
        harness.push(1, 3);

        let first = harness.receiver().try_recv().unwrap();
        let second = harness.receiver().try_recv().unwrap();
        assert_eq!((first.sequence().get(), second.sequence().get()), (1, 2));

        harness.push(1, 3);

        assert_eq!(harness.health.observations_accepted(), 3);
        assert_eq!(harness.health.handoff_full_drops(), 1);
        assert_eq!(
            harness
                .health
                .rejection_count(RejectionReason::DuplicateOrRegressedSequence),
            1
        );
        assert!(matches!(
            harness.receiver().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn concurrent_dequeue_and_enqueue_keep_channel_metadata_capacity_bounded() {
        let mut harness = HandoffHarness::new(1);
        harness.push(1, 1);

        // Hold the dequeued item before its generation/delivery accounting. The
        // actual Tokio removal and mirror pop must already be one atomic queue
        // operation so a concurrent producer can reuse the slot without leaving
        // stale metadata or inflating the depth above capacity.
        let queued = {
            let receiver = harness.receiver();
            let state = Arc::clone(&receiver.state);
            state.try_dequeue(&mut receiver.receiver).unwrap()
        };
        let handoff = harness.handoff.clone();
        let delivery_boundary = Arc::clone(&harness.delivery_boundary);
        thread::spawn(move || {
            let _delivery = delivery_boundary
                .begin_delivery()
                .expect("test delivery boundary is healthy");
            handoff.enqueue(test_observation(1, 2, 2, Modality::Radar, 3.0, 3));
        })
        .join()
        .unwrap();

        let metrics = harness.health.handoff_metrics().unwrap();
        assert_eq!(metrics.queue_depth, 1);
        assert_eq!(metrics.max_queue_depth, 1);
        assert_eq!(metrics.oldest_queued.unwrap().sequence, 2);

        let first = harness.receiver().finish_dequeue(queued).unwrap();
        let second = harness.receiver().try_recv().unwrap();
        assert_eq!((first.sequence().get(), second.sequence().get()), (1, 2));
    }

    #[test]
    fn bounded_handoff_counts_delivery_after_receiver_close() {
        let mut harness = HandoffHarness::new(1);
        harness.receiver().close();

        harness.push(1, 1);

        assert_eq!(harness.health.handoff_enqueued(), 0);
        assert_eq!(harness.health.handoff_closed_drops(), 1);
        assert_eq!(harness.health.handoff_drops(), 1);
        assert_eq!(harness.health.handoff_metrics().unwrap().queue_depth, 0);
    }

    #[test]
    fn bounded_handoff_reset_discards_stale_generation_before_delivery() {
        let mut harness = HandoffHarness::new(2);
        harness.push(1, 1);
        assert_eq!(harness.health.reset_sequence_state().unwrap(), 1);
        harness.push(1, 1);
        let reset_metrics = harness.health.handoff_metrics().unwrap();
        assert_eq!(reset_metrics.generation, 1);
        assert_eq!(reset_metrics.oldest_queued_generation, Some(0));

        let delivered = harness.receiver().try_recv().unwrap();

        assert_eq!(delivered.sequence().get(), 1);
        assert_eq!(harness.health.handoff_stale_generation_drops(), 1);
        assert_eq!(harness.health.handoff_delivered(), 1);
        assert_eq!(harness.health.handoff_metrics().unwrap().generation, 1);
        assert!(matches!(
            harness.receiver().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn reset_cannot_revoke_an_observation_already_returned_to_the_consumer() {
        let mut harness = HandoffHarness::new(1);
        harness.push(1, 1);
        let already_returned = harness.receiver().try_recv().unwrap();

        assert_eq!(harness.health.reset_sequence_state().unwrap(), 1);

        // The caller owns this value now. This is why a cross-task reset must
        // first pause the consumer and wait for its downstream work to finish.
        assert_eq!(already_returned.sequence().get(), 1);
        assert_eq!(harness.health.handoff_delivered(), 1);
        assert_eq!(harness.health.handoff_stale_generation_drops(), 0);
    }

    #[test]
    fn concurrent_callback_records_publish_one_coherent_completion_ordered_snapshot() {
        let counters = Arc::new(IngestCounters::default());
        let origin = Instant::now();
        let (newer_recorded_tx, newer_recorded_rx) = mpsc::channel();

        let newer_counters = Arc::clone(&counters);
        let newer = thread::spawn(move || {
            record_callback_latency(
                &newer_counters,
                Duration::from_millis(7),
                origin + Duration::from_millis(2),
            )
            .expect("test telemetry mutex is healthy");
            newer_recorded_tx.send(()).unwrap();
        });
        let older_counters = Arc::clone(&counters);
        let older = thread::spawn(move || {
            newer_recorded_rx.recv().unwrap();
            // This longer callback completed first but records second. It must
            // update the maximum without overwriting the latest completion.
            record_callback_latency(
                &older_counters,
                Duration::from_millis(20),
                origin + Duration::from_millis(1),
            )
            .expect("test telemetry mutex remains healthy");
        });
        newer.join().unwrap();
        older.join().unwrap();

        assert_eq!(
            snapshot_callback_latency(&counters).expect("test telemetry snapshot is healthy"),
            CallbackLatencyMetrics {
                samples: 2,
                last: Some(Duration::from_millis(7)),
                maximum: Some(Duration::from_millis(20)),
            }
        );
    }

    #[test]
    fn dropping_bounded_receiver_counts_abandoned_entries_and_closes_handoff() {
        let mut harness = HandoffHarness::new(2);
        harness.push(1, 1);
        drop(harness.receiver.take().unwrap());

        assert_eq!(harness.health.handoff_abandoned_drops(), 1);
        assert_eq!(harness.health.handoff_metrics().unwrap().queue_depth, 0);

        harness.push(1, 2);
        assert_eq!(harness.health.handoff_closed_drops(), 1);
        assert_eq!(harness.health.handoff_drops(), 2);
    }

    #[test]
    fn process_payload_rejects_oversize_and_duplicate_input() {
        let first = encoded(1, 1);
        let limits = LiveLimits::new(first.len()).unwrap();
        let delivery_boundary = DeliveryBoundary::default();
        let sequences = Mutex::new(LiveSequenceTracker::default());
        let tap = IngestCounters::default();
        let subscription = IngestCounters::default();
        let callbacks = AtomicU64::new(0);
        let on_obs = |_| {
            callbacks.fetch_add(1, Ordering::Relaxed);
        };

        process_payload(
            &first,
            limits,
            &delivery_boundary,
            &sequences,
            &tap,
            &subscription,
            &on_obs,
        );
        process_payload(
            &first,
            limits,
            &delivery_boundary,
            &sequences,
            &tap,
            &subscription,
            &on_obs,
        );
        let mut oversized = first;
        oversized.push(b' ');
        process_payload(
            &oversized,
            limits,
            &delivery_boundary,
            &sequences,
            &tap,
            &subscription,
            &on_obs,
        );

        assert_eq!(tap.payloads_received.load(Ordering::Relaxed), 3);
        assert_eq!(subscription.decode_failures.load(Ordering::Relaxed), 2);
        assert_eq!(
            subscription.rejection_count(RejectionReason::DuplicateOrRegressedSequence),
            1
        );
        assert_eq!(
            subscription.rejection_count(RejectionReason::PayloadTooLarge),
            1
        );
        assert_eq!(subscription.rejection_counts().total(), 2);
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            1
        );
        assert_eq!(callbacks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn process_payload_rejects_invalid_observation_during_typed_envelope_decode() {
        let mut invalid =
            serde_json::to_value(envelope(test_observation(1, 0, 1, Modality::Radar, 1.0, 3)))
                .unwrap();
        invalid["observation"]["nis"] = serde_json::json!(-0.1);
        let invalid = serde_json::to_vec(&invalid).unwrap();
        let delivery_boundary = DeliveryBoundary::default();
        let sequences = Mutex::new(LiveSequenceTracker::default());
        let tap = IngestCounters::default();
        let subscription = IngestCounters::default();
        let callbacks = AtomicU64::new(0);

        process_payload(
            &invalid,
            LiveLimits::default(),
            &delivery_boundary,
            &sequences,
            &tap,
            &subscription,
            &|_| {
                callbacks.fetch_add(1, Ordering::Relaxed);
            },
        );

        assert_eq!(subscription.decode_failures.load(Ordering::Relaxed), 1);
        assert_eq!(
            subscription.rejection_count(RejectionReason::InvalidEnvelope),
            1
        );
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn process_payload_rejects_unversioned_legacy_payload_and_wrong_provenance() {
        let legacy =
            serde_json::to_vec(&test_observation(1, 0, 1, Modality::Radar, 3.0, 3)).unwrap();
        let mut wrong_provenance = envelope(test_observation(1, 0, 2, Modality::Radar, 3.0, 3));
        wrong_provenance.session_id = "other-session".to_string();
        let wrong_provenance = serde_json::to_vec(&wrong_provenance).unwrap();
        let delivery_boundary = DeliveryBoundary::default();
        let sequences = Mutex::new(LiveSequenceTracker::default());
        let tap = IngestCounters::default();
        let subscription = IngestCounters::default();

        for payload in [legacy, wrong_provenance] {
            process_payload(
                &payload,
                LiveLimits::default(),
                &delivery_boundary,
                &sequences,
                &tap,
                &subscription,
                &|_| {},
            );
        }

        assert_eq!(
            subscription.rejection_count(RejectionReason::InvalidEnvelope),
            1
        );
        assert_eq!(
            subscription.rejection_count(RejectionReason::ProvenanceMismatch),
            1
        );
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn process_payload_rejects_incompatible_version_and_surfaces_hash_advisory() {
        let mut wrong_version = envelope(test_observation(1, 0, 1, Modality::Radar, 3.0, 3));
        wrong_version.ncp_version = "0.6".to_string();
        let wrong_version = serde_json::to_vec(&wrong_version).unwrap();
        let mut drifted = envelope(test_observation(1, 0, 2, Modality::Radar, 3.0, 3));
        drifted.contract_hash = "deadbeefdeadbeef".to_string();
        let drifted = serde_json::to_vec(&drifted).unwrap();
        let delivery_boundary = DeliveryBoundary::default();
        let sequences = Mutex::new(LiveSequenceTracker::default());
        let tap = IngestCounters::default();
        let subscription = IngestCounters::default();

        for payload in [&wrong_version, &drifted] {
            process_payload(
                payload,
                LiveLimits::default(),
                &delivery_boundary,
                &sequences,
                &tap,
                &subscription,
                &|_| {},
            );
        }
        process_payload(
            &drifted,
            LiveLimits::default(),
            &delivery_boundary,
            &sequences,
            &tap,
            &subscription,
            &|_| {},
        );

        assert_eq!(
            subscription.rejection_count(RejectionReason::IncompatibleNcpVersion),
            1
        );
        assert_eq!(
            subscription
                .contract_hash_mismatches
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            subscription.rejection_count(RejectionReason::DuplicateOrRegressedSequence),
            1
        );
    }

    #[test]
    fn process_payload_callback_panic_is_terminal_before_later_decode() {
        let delivery_boundary = DeliveryBoundary::default();
        let sequences = Mutex::new(LiveSequenceTracker::default());
        let tap = IngestCounters::default();
        let subscription = IngestCounters::default();
        let callbacks = AtomicU64::new(0);
        let on_obs = |_| {
            if callbacks.fetch_add(1, Ordering::Relaxed) == 0 {
                panic!("simulated user callback failure");
            }
        };

        for payload in [encoded(1, 1), encoded(1, 2)] {
            process_payload(
                &payload,
                LiveLimits::default(),
                &delivery_boundary,
                &sequences,
                &tap,
                &subscription,
                &on_obs,
            );
        }

        assert_eq!(callbacks.load(Ordering::Relaxed), 1);
        assert_eq!(subscription.callback_panics.load(Ordering::Relaxed), 1);
        assert_eq!(subscription.decode_failures.load(Ordering::Relaxed), 1);
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            internal_fault_pair(&tap, &subscription),
            Some(LiveInternalFault::CallbackPanicked)
        );
        let callback_latency =
            snapshot_callback_latency(&subscription).expect("test callback telemetry is healthy");
        assert_eq!(callback_latency.samples, 1);
        assert!(callback_latency.last.is_some());
        assert!(callback_latency.maximum.is_some());
        assert!(callback_latency.maximum >= callback_latency.last);
    }

    #[test]
    fn process_payload_allows_late_baseline_but_rejects_later_forward_poisoning() {
        let limits = LiveLimits::with_sequence_policy(DEFAULT_MAX_LIVE_PAYLOAD_BYTES, 4, 10)
            .expect("valid limits");
        let delivery_boundary = DeliveryBoundary::default();
        let sequences = Mutex::new(LiveSequenceTracker::default());
        let tap = IngestCounters::default();
        let subscription = IngestCounters::default();
        let callbacks = AtomicU64::new(0);
        let on_obs = |_| {
            callbacks.fetch_add(1, Ordering::Relaxed);
        };

        for payload in [encoded(1, 0), encoded(1, 100), encoded(1, 1), encoded(2, 9)] {
            process_payload(
                &payload,
                limits,
                &delivery_boundary,
                &sequences,
                &tap,
                &subscription,
                &on_obs,
            );
        }

        assert_eq!(callbacks.load(Ordering::Relaxed), 3);
        assert_eq!(subscription.decode_failures.load(Ordering::Relaxed), 1);
        assert_eq!(
            subscription.rejection_count(RejectionReason::ExcessiveForwardSequenceGap),
            1
        );
        assert_eq!(sequences.lock().unwrap().len(), 2);
        assert_eq!(
            snapshot_last_accepted(&subscription).expect("test acceptance telemetry is healthy"),
            Some(LastAcceptedObservation {
                track_id: 2,
                modality: Modality::Radar,
                sequence: 9,
                timestamp_ms: 9,
            })
        );
    }

    #[test]
    fn forward_gap_is_relative_to_the_retained_nonzero_high_water_mark() {
        let limits = LiveLimits::with_sequence_policy(DEFAULT_MAX_LIVE_PAYLOAD_BYTES, 1, 10)
            .expect("valid limits");
        let delivery_boundary = DeliveryBoundary::default();
        let sequences = Mutex::new(LiveSequenceTracker::default());
        let tap = IngestCounters::default();
        let subscription = IngestCounters::default();
        let callbacks = AtomicU64::new(0);

        for payload in [encoded(1, 50), encoded(1, 60), encoded(1, 71)] {
            process_payload(
                &payload,
                limits,
                &delivery_boundary,
                &sequences,
                &tap,
                &subscription,
                &|_| {
                    callbacks.fetch_add(1, Ordering::Relaxed);
                },
            );
        }

        assert_eq!(callbacks.load(Ordering::Relaxed), 2);
        assert_eq!(
            subscription.rejection_count(RejectionReason::ExcessiveForwardSequenceGap),
            1
        );
        let retained = sequences.lock().unwrap();
        assert_eq!(retained.states.values().next().unwrap().get(), 60);
    }

    #[test]
    fn process_payload_rejects_new_stream_at_capacity_without_forgetting_replay_state() {
        let limits = LiveLimits::with_sequence_policy(DEFAULT_MAX_LIVE_PAYLOAD_BYTES, 2, 10)
            .expect("valid limits");
        let delivery_boundary = DeliveryBoundary::default();
        let sequences = Mutex::new(LiveSequenceTracker::default());
        let tap = IngestCounters::default();
        let subscription = IngestCounters::default();
        let callbacks = AtomicU64::new(0);
        let on_obs = |_| {
            callbacks.fetch_add(1, Ordering::Relaxed);
        };

        for payload in [
            encoded(1, 0),
            encoded(2, 0),
            encoded(1, 1),
            encoded(3, 0),
            encoded(2, 0),
        ] {
            process_payload(
                &payload,
                limits,
                &delivery_boundary,
                &sequences,
                &tap,
                &subscription,
                &on_obs,
            );
        }

        assert_eq!(callbacks.load(Ordering::Relaxed), 3);
        assert_eq!(subscription.decode_failures.load(Ordering::Relaxed), 2);
        assert_eq!(subscription.malformed_json.load(Ordering::Relaxed), 0);
        assert_eq!(
            subscription.rejection_count(RejectionReason::SequenceCapacityExceeded),
            1
        );
        assert_eq!(
            subscription.rejection_count(RejectionReason::DuplicateOrRegressedSequence),
            1
        );
        assert_eq!(subscription.sequence_evictions.load(Ordering::Relaxed), 0);
        assert_eq!(tap.sequence_evictions.load(Ordering::Relaxed), 0);
        assert_eq!(sequences.lock().unwrap().len(), 2);
    }

    #[test]
    fn subscription_counters_are_isolated_while_tap_counter_aggregates() {
        let limits = LiveLimits::default();
        let tap = IngestCounters::default();
        let first_subscription = IngestCounters::default();
        let second_subscription = IngestCounters::default();
        let first_delivery_boundary = DeliveryBoundary::default();
        let second_delivery_boundary = DeliveryBoundary::default();
        let first_sequences = Mutex::new(LiveSequenceTracker::default());
        let second_sequences = Mutex::new(LiveSequenceTracker::default());

        process_payload(
            &encoded(1, 0),
            limits,
            &first_delivery_boundary,
            &first_sequences,
            &tap,
            &first_subscription,
            &|_| {},
        );
        process_payload(
            b"not json",
            limits,
            &second_delivery_boundary,
            &second_sequences,
            &tap,
            &second_subscription,
            &|_| {},
        );

        assert_eq!(tap.payloads_received.load(Ordering::Relaxed), 2);
        assert_eq!(
            first_subscription.payloads_received.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            first_subscription.decode_failures.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            second_subscription
                .payloads_received
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            second_subscription.decode_failures.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            second_subscription.rejection_count(RejectionReason::MalformedJson),
            1
        );
    }

    #[test]
    fn subscription_health_reset_clears_sequence_epoch_and_counts_it() {
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        sequences
            .lock()
            .unwrap()
            .accept(&test_observation(1, 0, 1, Modality::Radar, 3.0, 3), 2, 10)
            .unwrap();
        let counters = Arc::new(IngestCounters::default());
        *counters.last_accepted.lock().unwrap() = Some(LastAcceptedObservation {
            track_id: 1,
            modality: Modality::Radar,
            sequence: 1,
            timestamp_ms: 0,
        });
        let tap_counters = Arc::new(IngestCounters::default());
        let health = SubscriptionHealth {
            counters,
            tap_counters: Arc::clone(&tap_counters),
            sequences,
            delivery_boundary: Arc::new(DeliveryBoundary::default()),
            handoff: None,
        };

        let removed = health.reset_sequence_state().unwrap();

        assert_eq!(removed, 1);
        assert_eq!(health.retained_sequence_streams(), 0);
        assert_eq!(health.sequence_resets(), 1);
        assert_eq!(health.last_accepted(), None);
        assert_eq!(tap_counters.sequence_resets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn reset_from_callback_returns_typed_error_without_deadlocking() {
        let delivery_boundary = Arc::new(DeliveryBoundary::default());
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let counters = Arc::new(IngestCounters::default());
        let tap_counters = Arc::new(IngestCounters::default());
        let health = SubscriptionHealth {
            counters: Arc::clone(&counters),
            tap_counters: Arc::clone(&tap_counters),
            sequences: Arc::clone(&sequences),
            delivery_boundary: Arc::clone(&delivery_boundary),
            handoff: None,
        };
        let (error_tx, error_rx) = mpsc::channel();

        process_payload(
            &encoded(1, 1),
            LiveLimits::default(),
            &delivery_boundary,
            &sequences,
            &tap_counters,
            &counters,
            &|_| {
                error_tx
                    .send(health.reset_sequence_state().unwrap_err())
                    .unwrap();
            },
        );

        assert_eq!(
            error_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            SequenceResetError::CalledFromCallback
        );
        assert_eq!(health.retained_sequence_streams(), 1);
        assert_eq!(health.sequence_resets(), 0);
    }

    #[test]
    fn sequence_reset_errors_have_exact_operator_diagnostics() {
        let cases = [
            (
                SequenceResetError::CalledFromCallback,
                "sequence reset cannot run from inside on_obs",
            ),
            (
                SequenceResetError::DeliveryInProgress,
                "sequence reset cannot run while delivery is in progress",
            ),
            (
                SequenceResetError::TooManyPendingResets,
                "too many concurrent sequence reset requests",
            ),
            (
                SequenceResetError::GenerationExhausted,
                "live delivery generation is exhausted",
            ),
            (
                SequenceResetError::InternalStateFault {
                    fault: LiveInternalFault::SequenceStatePoisoned,
                },
                "live epoch has terminal internal fault SequenceStatePoisoned",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn subscription_health_accessors_preserve_every_counter_and_snapshot() {
        let counters = Arc::new(IngestCounters::default());
        let tap_counters = Arc::new(IngestCounters::default());
        counters.payloads_received.store(2, Ordering::Relaxed);
        counters.observations_accepted.store(3, Ordering::Relaxed);
        counters.decode_failures.store(4, Ordering::Relaxed);
        counters.callback_panics.store(5, Ordering::Relaxed);
        counters.sequence_evictions.store(6, Ordering::Relaxed);
        counters.sequence_resets.store(7, Ordering::Relaxed);
        counters
            .contract_hash_mismatches
            .store(8, Ordering::Relaxed);
        counters.handoff_enqueued.store(9, Ordering::Relaxed);
        counters.handoff_delivered.store(10, Ordering::Relaxed);
        counters.handoff_full_drops.store(11, Ordering::Relaxed);
        counters.handoff_closed_drops.store(12, Ordering::Relaxed);
        counters
            .handoff_stale_generation_drops
            .store(13, Ordering::Relaxed);
        counters
            .handoff_abandoned_drops
            .store(14, Ordering::Relaxed);
        *counters.last_accepted.lock().unwrap() = Some(LastAcceptedObservation {
            track_id: 17,
            modality: Modality::Thermal,
            sequence: 19,
            timestamp_ms: 23,
        });

        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let delivery_boundary = Arc::new(DeliveryBoundary::new(
            Arc::clone(&tap_counters),
            Arc::clone(&counters),
        ));
        let health = SubscriptionHealth {
            counters: Arc::clone(&counters),
            tap_counters: Arc::clone(&tap_counters),
            sequences,
            delivery_boundary,
            handoff: None,
        };

        assert_eq!(health.payloads_received(), 2);
        assert_eq!(health.observations_accepted(), 3);
        assert_eq!(health.decode_failures(), 4);
        assert_eq!(health.callback_panics(), 5);
        assert_eq!(
            health.last_accepted(),
            Some(LastAcceptedObservation {
                track_id: 17,
                modality: Modality::Thermal,
                sequence: 19,
                timestamp_ms: 23,
            })
        );
        assert_eq!(health.sequence_evictions(), 6);
        assert_eq!(health.sequence_resets(), 7);
        assert_eq!(health.contract_hash_mismatches(), 8);
        assert_eq!(health.handoff_enqueued(), 9);
        assert_eq!(health.handoff_delivered(), 10);
        assert_eq!(health.handoff_full_drops(), 11);
        assert_eq!(health.handoff_closed_drops(), 12);
        assert_eq!(health.handoff_stale_generation_drops(), 13);
        assert_eq!(health.handoff_abandoned_drops(), 14);
        assert_eq!(health.handoff_drops(), 50);
        assert_eq!(health.handoff_metrics(), None);
        assert_eq!(health.retained_sequence_streams(), 0);
        assert_eq!(health.internal_fault(), None);
        assert_eq!(health.internal_faults(), 0);

        latch_internal_fault_pair(
            &tap_counters,
            &counters,
            LiveInternalFault::CallbackPanicked,
        );
        assert_eq!(
            health.internal_fault(),
            Some(LiveInternalFault::CallbackPanicked)
        );
        assert_eq!(health.internal_faults(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn sidecar_tap_fault_accessors_preserve_the_latched_terminal_fault() {
        let realm = format!("galadriel/test/tap-health-{}", std::process::id());
        let tap = SidecarTap::open_realm(realm, TransportMode::QuietDevelopment)
            .await
            .expect("the isolated quiet-development tap opens");

        assert_eq!(tap.internal_fault(), None);
        assert_eq!(tap.internal_faults(), 0);
        latch_internal_fault(&tap.counters, LiveInternalFault::CallbackPanicked);
        assert_eq!(
            tap.internal_fault(),
            Some(LiveInternalFault::CallbackPanicked)
        );
        assert_eq!(tap.internal_faults(), 1);

        tap.close().await.expect("the owned test tap closes");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn subscribe_with_health_rejects_identities_before_retaining_a_subscription() {
        let realm = format!(
            "galadriel/test/invalid-callback-identity-{}",
            std::process::id()
        );
        let tap = SidecarTap::open_realm(realm, TransportMode::QuietDevelopment)
            .await
            .expect("the isolated quiet-development tap opens");
        let oversized = "a".repeat(crate::MAX_ID_SEGMENT_BYTES + 1);

        for (session_id, producer_id, expected_error) in [
            ("*", TEST_PRODUCER_ID, "invalid Galadriel session identity"),
            (
                oversized.as_str(),
                TEST_PRODUCER_ID,
                "invalid Galadriel session identity",
            ),
            (TEST_SESSION_ID, "*", "invalid Galadriel producer identity"),
            (
                TEST_SESSION_ID,
                oversized.as_str(),
                "invalid Galadriel producer identity",
            ),
        ] {
            let result = tap
                .subscribe_with_health(session_id, producer_id, |_| {})
                .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("an invalid identity created a callback subscription"),
            };
            assert_eq!(error.to_string(), expected_error);
        }

        assert_eq!(
            tap.bus()
                .unsubscribe_session(TEST_SESSION_ID)
                .expect("the valid session lookup succeeds"),
            0
        );
        assert_eq!(tap.payloads_received(), 0);
        assert_eq!(tap.observations_accepted(), 0);
        assert_eq!(tap.rejections().total(), 0);

        tap.close().await.expect("the owned test tap closes");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn subscribe_channel_rejects_identities_before_handoff_or_subscription_effects() {
        let realm = format!(
            "galadriel/test/invalid-handoff-identity-{}",
            std::process::id()
        );
        let tap = SidecarTap::open_realm(realm, TransportMode::QuietDevelopment)
            .await
            .expect("the isolated quiet-development tap opens");
        let handoff = HandoffConfig::new(1).expect("the test handoff is valid");
        let oversized = "a".repeat(crate::MAX_ID_SEGMENT_BYTES + 1);

        for (session_id, producer_id, expected_error) in [
            ("*", TEST_PRODUCER_ID, "invalid Galadriel session identity"),
            (
                oversized.as_str(),
                TEST_PRODUCER_ID,
                "invalid Galadriel session identity",
            ),
            (TEST_SESSION_ID, "*", "invalid Galadriel producer identity"),
            (
                TEST_SESSION_ID,
                oversized.as_str(),
                "invalid Galadriel producer identity",
            ),
        ] {
            let result = tap
                .subscribe_channel(session_id, producer_id, handoff)
                .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("an invalid identity created a handoff subscription"),
            };
            assert_eq!(error.to_string(), expected_error);
        }

        assert_eq!(
            tap.bus()
                .unsubscribe_session(TEST_SESSION_ID)
                .expect("the valid session lookup succeeds"),
            0
        );
        assert_eq!(tap.handoff_enqueued(), 0);
        assert_eq!(tap.handoff_delivered(), 0);
        assert_eq!(tap.handoff_drops(), 0);
        assert_eq!(tap.payloads_received(), 0);

        tap.close().await.expect("the owned test tap closes");
    }

    #[test]
    fn each_delivery_boundary_state_independently_blocks_delivery() {
        let open = DeliveryBoundaryState::default();
        assert!(!open.blocks_delivery());

        let delivery = DeliveryBoundaryState {
            delivery_active: true,
            ..DeliveryBoundaryState::default()
        };
        assert!(delivery.blocks_delivery());

        let reset = DeliveryBoundaryState {
            reset_active: true,
            ..DeliveryBoundaryState::default()
        };
        assert!(reset.blocks_delivery());

        let pending = DeliveryBoundaryState {
            pending_resets: 1,
            ..DeliveryBoundaryState::default()
        };
        assert!(pending.blocks_delivery());
    }

    #[test]
    fn delivery_and_reset_guards_release_their_exact_boundary_state() {
        let delivery_boundary = DeliveryBoundary::default();
        {
            let _delivery = delivery_boundary.begin_delivery().unwrap();
            let state = delivery_boundary.state.lock().unwrap();
            assert!(state.delivery_active);
            assert!(!state.reset_active);
            assert_eq!(state.pending_resets, 0);
        }
        {
            let state = delivery_boundary.state.lock().unwrap();
            assert!(!state.delivery_active);
            assert!(!state.reset_active);
            assert_eq!(state.pending_resets, 0);
        }

        let reset_boundary = DeliveryBoundary::default();
        {
            let _reset = reset_boundary.begin_reset().unwrap();
            let state = reset_boundary.state.lock().unwrap();
            assert!(!state.delivery_active);
            assert!(state.reset_active);
            assert_eq!(state.pending_resets, 0);
        }
        let state = reset_boundary.state.lock().unwrap();
        assert!(!state.delivery_active);
        assert!(!state.reset_active);
        assert_eq!(state.pending_resets, 0);
    }

    #[test]
    fn callback_cannot_reset_a_different_idle_subscription() {
        let source_boundary = DeliveryBoundary::default();
        let source_sequences = Mutex::new(LiveSequenceTracker::default());
        let source_counters = IngestCounters::default();
        let source_tap_counters = IngestCounters::default();
        let target_health = SubscriptionHealth {
            counters: Arc::new(IngestCounters::default()),
            tap_counters: Arc::new(IngestCounters::default()),
            sequences: Arc::new(Mutex::new(LiveSequenceTracker::default())),
            delivery_boundary: Arc::new(DeliveryBoundary::default()),
            handoff: None,
        };
        let (error_tx, error_rx) = mpsc::channel();

        process_payload(
            &encoded(1, 1),
            LiveLimits::default(),
            &source_boundary,
            &source_sequences,
            &source_tap_counters,
            &source_counters,
            &|_| {
                error_tx
                    .send(target_health.reset_sequence_state().unwrap_err())
                    .unwrap();
            },
        );

        assert_eq!(
            error_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            SequenceResetError::CalledFromCallback
        );
        assert_eq!(target_health.sequence_resets(), 0);
    }

    #[test]
    fn callback_spawn_and_join_reset_fails_fast_without_deadlock() {
        let delivery_boundary = Arc::new(DeliveryBoundary::default());
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let counters = Arc::new(IngestCounters::default());
        let tap_counters = Arc::new(IngestCounters::default());
        let health = SubscriptionHealth {
            counters: Arc::clone(&counters),
            tap_counters: Arc::clone(&tap_counters),
            sequences: Arc::clone(&sequences),
            delivery_boundary: Arc::clone(&delivery_boundary),
            handoff: None,
        };
        let (error_tx, error_rx) = mpsc::channel();

        process_payload(
            &encoded(1, 1),
            LiveLimits::default(),
            &delivery_boundary,
            &sequences,
            &tap_counters,
            &counters,
            &|_| {
                let health = health.clone();
                let error = thread::spawn(move || health.reset_sequence_state().unwrap_err())
                    .join()
                    .unwrap();
                error_tx.send(error).unwrap();
            },
        );

        assert_eq!(
            error_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            SequenceResetError::DeliveryInProgress
        );
        assert_eq!(health.sequence_resets(), 0);
    }

    #[test]
    fn reset_fails_fast_during_delivery_then_succeeds_after_callback() {
        let delivery_boundary = Arc::new(DeliveryBoundary::default());
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let counters = Arc::new(IngestCounters::default());
        let tap_counters = Arc::new(IngestCounters::default());
        let health = SubscriptionHealth {
            counters: Arc::clone(&counters),
            tap_counters: Arc::clone(&tap_counters),
            sequences: Arc::clone(&sequences),
            delivery_boundary: Arc::clone(&delivery_boundary),
            handoff: None,
        };
        let callback_release = Arc::new(Barrier::new(2));
        let (entered_tx, entered_rx) = mpsc::channel();

        let process_thread = {
            let callback_release = Arc::clone(&callback_release);
            let delivery_boundary = Arc::clone(&delivery_boundary);
            let sequences = Arc::clone(&sequences);
            let counters = Arc::clone(&counters);
            let tap_counters = Arc::clone(&tap_counters);
            thread::spawn(move || {
                process_payload(
                    &encoded(1, 1),
                    LiveLimits::default(),
                    &delivery_boundary,
                    &sequences,
                    &tap_counters,
                    &counters,
                    &|_| {
                        entered_tx.send(()).unwrap();
                        callback_release.wait();
                    },
                );
            })
        };
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("callback entered serialized delivery boundary");

        assert_eq!(
            health.reset_sequence_state(),
            Err(SequenceResetError::DeliveryInProgress)
        );
        assert_eq!(health.sequence_resets(), 0);
        callback_release.wait();
        process_thread.join().unwrap();
        assert_eq!(health.reset_sequence_state().unwrap(), 1);
        assert_eq!(health.sequence_resets(), 1);
        assert_eq!(health.last_accepted(), None);
    }

    #[test]
    fn acquired_reset_boundary_prevents_later_delivery_barging() {
        let delivery_boundary = Arc::new(DeliveryBoundary::default());
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let counters = Arc::new(IngestCounters::default());
        let tap_counters = Arc::new(IngestCounters::default());
        let reset = delivery_boundary.begin_reset().unwrap();
        let (callback_tx, callback_rx) = mpsc::channel();

        let delivery_thread = {
            let delivery_boundary = Arc::clone(&delivery_boundary);
            let sequences = Arc::clone(&sequences);
            let counters = Arc::clone(&counters);
            let tap_counters = Arc::clone(&tap_counters);
            thread::spawn(move || {
                process_payload(
                    &encoded(1, 1),
                    LiveLimits::default(),
                    &delivery_boundary,
                    &sequences,
                    &tap_counters,
                    &counters,
                    &|_| callback_tx.send(()).unwrap(),
                );
            })
        };

        assert_eq!(
            callback_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        drop(reset);
        callback_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        delivery_thread.join().unwrap();
    }

    #[test]
    fn live_limits_reject_zero_sequence_advance() {
        let error = LiveLimits::with_sequence_policy(1, 1, 0).unwrap_err();

        assert_eq!(
            error,
            LiveLimitsError::Zero {
                field: "max_sequence_advance"
            }
        );
    }

    type FaultParts = (
        Arc<IngestCounters>,
        Arc<IngestCounters>,
        Arc<DeliveryBoundary>,
        Arc<Mutex<LiveSequenceTracker>>,
    );

    fn fault_parts() -> FaultParts {
        let tap = Arc::new(IngestCounters::default());
        let subscription = Arc::new(IngestCounters::default());
        let boundary = Arc::new(DeliveryBoundary::new(
            Arc::clone(&tap),
            Arc::clone(&subscription),
        ));
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        (tap, subscription, boundary, sequences)
    }

    fn poison_sequence_state(sequences: &Arc<Mutex<LiveSequenceTracker>>) {
        let sequences = Arc::clone(sequences);
        assert!(thread::spawn(move || {
            let _state = sequences
                .lock()
                .expect("test sequence state starts healthy");
            panic!("deterministic live sequence poison");
        })
        .join()
        .is_err());
    }

    fn poison_delivery_boundary(boundary: &Arc<DeliveryBoundary>) {
        let boundary = Arc::clone(boundary);
        assert!(thread::spawn(move || {
            let _state = boundary
                .state
                .lock()
                .expect("test delivery boundary starts healthy");
            panic!("deterministic live delivery-boundary poison");
        })
        .join()
        .is_err());
    }

    fn poison_last_accepted(counters: &Arc<IngestCounters>) {
        let counters = Arc::clone(counters);
        assert!(thread::spawn(move || {
            let _last = counters
                .last_accepted
                .lock()
                .expect("test last-accepted telemetry starts healthy");
            panic!("deterministic last-accepted telemetry poison");
        })
        .join()
        .is_err());
    }

    fn poison_callback_latency(counters: &Arc<IngestCounters>) {
        let counters = Arc::clone(counters);
        assert!(thread::spawn(move || {
            let _latency = counters
                .callback_latency
                .lock()
                .expect("test callback telemetry starts healthy");
            panic!("deterministic callback-latency telemetry poison");
        })
        .join()
        .is_err());
    }

    #[test]
    fn poisoned_sequence_state_rejects_current_and_later_payloads() {
        let (tap, subscription, boundary, sequences) = fault_parts();
        poison_sequence_state(&sequences);
        let callbacks = AtomicU64::new(0);

        for payload in [encoded(1, 1), encoded(1, 2)] {
            process_payload(
                &payload,
                LiveLimits::default(),
                &boundary,
                &sequences,
                &tap,
                &subscription,
                &|_| {
                    callbacks.fetch_add(1, Ordering::Relaxed);
                },
            );
        }

        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            0
        );
        assert_eq!(subscription.decode_failures.load(Ordering::Relaxed), 2);
        assert_eq!(
            internal_fault_pair(&tap, &subscription),
            Some(LiveInternalFault::SequenceStatePoisoned)
        );
        assert_eq!(sequences.lock().expect("poison is quarantined").len(), 0);
    }

    #[test]
    fn poisoned_delivery_boundary_fences_callback_before_sequence_admission() {
        let (tap, subscription, boundary, sequences) = fault_parts();
        poison_delivery_boundary(&boundary);
        let callbacks = AtomicU64::new(0);

        process_payload(
            &encoded(1, 1),
            LiveLimits::default(),
            &boundary,
            &sequences,
            &tap,
            &subscription,
            &|_| {
                callbacks.fetch_add(1, Ordering::Relaxed);
            },
        );

        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            sequences.lock().expect("sequence state is healthy").len(),
            0
        );
        assert_eq!(
            internal_fault_pair(&tap, &subscription),
            Some(LiveInternalFault::DeliveryBoundaryPoisoned)
        );
    }

    #[test]
    fn poisoned_last_accepted_telemetry_fails_before_decoding() {
        let (tap, subscription, boundary, sequences) = fault_parts();
        poison_last_accepted(&subscription);
        let callbacks = AtomicU64::new(0);

        process_payload(
            &encoded(1, 1),
            LiveLimits::default(),
            &boundary,
            &sequences,
            &tap,
            &subscription,
            &|_| {
                callbacks.fetch_add(1, Ordering::Relaxed);
            },
        );

        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            internal_fault_pair(&tap, &subscription),
            Some(LiveInternalFault::LastAcceptedTelemetryPoisoned)
        );
        assert_eq!(snapshot_last_accepted(&subscription), Ok(None));
    }

    #[test]
    fn poisoned_callback_latency_telemetry_fails_before_decoding() {
        let (tap, subscription, boundary, sequences) = fault_parts();
        poison_callback_latency(&subscription);
        let callbacks = AtomicU64::new(0);

        process_payload(
            &encoded(1, 1),
            LiveLimits::default(),
            &boundary,
            &sequences,
            &tap,
            &subscription,
            &|_| {
                callbacks.fetch_add(1, Ordering::Relaxed);
            },
        );

        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            internal_fault_pair(&tap, &subscription),
            Some(LiveInternalFault::CallbackLatencyTelemetryPoisoned)
        );
        assert_eq!(
            snapshot_callback_latency(&subscription),
            Ok(CallbackLatencyMetrics {
                samples: 0,
                last: None,
                maximum: None,
            })
        );
    }

    #[test]
    fn poisoned_handoff_state_quarantines_queued_observation() {
        let mut harness = HandoffHarness::new(2);
        harness.push(1, 1);
        let state = Arc::clone(&harness.handoff.state);
        assert!(thread::spawn(move || {
            let _queue = state
                .queue
                .lock()
                .expect("test handoff state starts healthy");
            panic!("deterministic handoff-state poison");
        })
        .join()
        .is_err());

        harness.push(1, 2);

        assert_eq!(
            harness.receiver().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        );
        assert_eq!(harness.health.observations_accepted(), 1);
        assert_eq!(harness.health.handoff_delivered(), 0);
        assert_eq!(harness.health.handoff_abandoned_drops(), 1);
        assert_eq!(
            harness.health.internal_fault(),
            Some(LiveInternalFault::HandoffStatePoisoned)
        );
    }

    #[test]
    fn poisoned_sequence_state_quarantines_previously_queued_observation() {
        let mut harness = HandoffHarness::new(2);
        harness.push(1, 1);
        poison_sequence_state(&harness.sequences);

        assert_eq!(
            harness.receiver().try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        );
        assert_eq!(harness.health.handoff_delivered(), 0);
        assert_eq!(harness.health.handoff_abandoned_drops(), 1);
        assert_eq!(
            harness.health.internal_fault(),
            Some(LiveInternalFault::SequenceStatePoisoned)
        );
    }

    #[test]
    fn internal_poison_preserves_prior_callback_panic_evidence() {
        let (tap, subscription, boundary, sequences) = fault_parts();
        process_payload(
            &encoded(1, 1),
            LiveLimits::default(),
            &boundary,
            &sequences,
            &tap,
            &subscription,
            &|_| panic!("contained callback panic"),
        );
        poison_sequence_state(&sequences);

        process_payload(
            &encoded(1, 2),
            LiveLimits::default(),
            &boundary,
            &sequences,
            &tap,
            &subscription,
            &|_| {},
        );

        assert_eq!(subscription.callback_panics.load(Ordering::Relaxed), 1);
        assert_eq!(
            subscription.observations_accepted.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            internal_fault_pair(&tap, &subscription),
            Some(LiveInternalFault::CallbackPanicked)
        );
    }
}
