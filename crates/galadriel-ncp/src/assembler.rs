//! Bounded, transport-neutral assembly of Galadriel's observation and monitor routes.
//!
//! The assembler owns exactly one producer epoch. Callers provide raw payload bytes
//! and a local monotonic receipt [`Instant`]; no transport, wall clock, thread, or
//! async runtime is used here. A fresh epoch requires a fresh assembler.
//!
//! Version 1 can prove exact joins for every event and observation it receives. It
//! cannot independently reconstruct a producer's frozen pre-association track set or
//! input-class Cartesian ledger because those values are not present on the v1 wire.
//! It therefore verifies the Cartesian product of the track identities represented
//! by monitor events, while treating the producer's complete frozen-ledger claim as
//! producer-asserted evidence. It is authenticated only when the caller or transport
//! independently binds the producer identity. A future wire version is required for
//! independent receiver re-derivation of that cardinality.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use galadriel_core::observation::{ConsistencyProjection, Modality, PidObservation};
use ncp_core::{ContractStatus, JSON_SAFE_INTEGER_MAX};

use crate::monitor::{
    FrameSummary, Heartbeat, ModalityMiss, ModalityMissReason, ModalityOutcome,
    ModalityOutcomeKind, MonitorEnvelope, MonitorError, ProducerEvent, MAX_ACTIVE_TRACKS,
    MAX_FRAME_ITEMS, MAX_HEARTBEAT_DURATION_MS, MAX_MONITOR_EVENT_BYTES,
};
use crate::{
    config_identity::ConfigurationIdentityBuilder, valid_producer_identity, valid_session_identity,
    ConfigurationIdentity, SidecarDecodeError, SidecarEnvelope, SidecarEnvelopeError,
};

/// Maximum sidecar bytes admitted by the pure assembler before JSON decoding.
pub const MAX_ASSEMBLER_SIDECAR_BYTES: usize = 64 * 1024;
/// Hard ceiling for monitor events waiting for global sequence reordering.
pub const MAX_ASSEMBLER_REORDER_EVENTS: usize = 8_192;
/// Hard ceiling for simultaneously open fusion frames in one epoch.
pub const MAX_ASSEMBLER_OPEN_FRAMES: usize = 1_024;
/// Hard ceiling for aggregate encoded bytes represented by buffered evidence.
pub const MAX_ASSEMBLER_BUFFERED_BYTES: usize = 64 * 1024 * 1024;
/// Hard ceiling for retained epoch-global prior identities.
pub const MAX_ASSEMBLER_PRIOR_IDENTITIES: usize = 1_000_000;
/// Hard ceiling for retained `(track, modality)` observation replay streams.
pub const MAX_ASSEMBLER_OBSERVATION_STREAMS: usize = 64 * 1024;
/// Hard ceiling for the aggregate number of per-frame state slots.
pub const MAX_ASSEMBLER_FRAME_STATE_SLOTS: usize = 16 * 1024 * 1024;
/// Hard ceiling for aggregate frame, reorder, and replay-index slots.
pub const MAX_ASSEMBLER_TOTAL_STATE_SLOTS: usize = MAX_ASSEMBLER_FRAME_STATE_SLOTS
    + MAX_ASSEMBLER_REORDER_EVENTS
    + MAX_ASSEMBLER_PRIOR_IDENTITIES
    + MAX_ASSEMBLER_OBSERVATION_STREAMS;
/// Hard ceiling for sequence-window distances admitted by a configuration.
pub const MAX_ASSEMBLER_SEQUENCE_DISTANCE: u64 = JSON_SAFE_INTEGER_MAX as u64;

/// Route on which an assembly fault or advisory was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceRoute {
    /// Frozen `galadriel-pid` observation route.
    Observation,
    /// `galadriel-monitor` lifecycle route.
    Monitor,
}

/// Immutable frame identity shared by every monitor event in one fusion frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameIdentity {
    /// Producer fusion sequence.
    pub fusion_seq: u64,
    /// Producer fusion timestamp.
    pub fusion_timestamp_ms: u64,
    /// Registered physical frame.
    pub frame_id: u64,
    /// Registered projection context.
    pub context_id: u64,
    /// Epoch-global frozen-prior identity.
    pub prior_id: u64,
}

impl FrameIdentity {
    fn from_observation(observation: &PidObservation) -> Option<Self> {
        observation.consistency_projection().map(|projection| {
            let identity = projection.identity();
            Self {
                fusion_seq: observation.sequence().get(),
                fusion_timestamp_ms: observation.timestamp_ms().get(),
                frame_id: identity.frame_id().get(),
                context_id: identity.context_id().get(),
                prior_id: identity.frozen_prior_id().get(),
            }
        })
    }

    fn from_outcome(outcome: &ModalityOutcome) -> Self {
        Self {
            fusion_seq: outcome.fusion_seq,
            fusion_timestamp_ms: outcome.fusion_timestamp_ms,
            frame_id: outcome.frame_id,
            context_id: outcome.context_id,
            prior_id: outcome.prior_id,
        }
    }

    fn from_miss(miss: &ModalityMiss) -> Self {
        Self {
            fusion_seq: miss.fusion_seq,
            fusion_timestamp_ms: miss.fusion_timestamp_ms,
            frame_id: miss.frame_id,
            context_id: miss.context_id,
            prior_id: miss.prior_id,
        }
    }

    fn from_summary(summary: &FrameSummary) -> Self {
        Self {
            fusion_seq: summary.fusion_seq,
            fusion_timestamp_ms: summary.fusion_timestamp_ms,
            frame_id: summary.frame_id,
            context_id: summary.context_id,
            prior_id: summary.prior_id,
        }
    }
}

/// Typed registry rejection returned through [`RegistryVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryViolation {
    /// A verifier implementation could not establish its external deployment pin.
    RegistryNotPinned,
    /// A supposedly validated registry could not produce a bounded typed policy.
    InvalidOpportunityPolicy,
    /// Summary digest differs from the deployment pin.
    DigestMismatch,
    /// Frame identifier is unknown.
    UnknownFrame { frame_id: u64 },
    /// Projection-context identifier is unknown.
    UnknownContext { context_id: u64 },
    /// The context is not bound to the declared frame.
    FrameContextMismatch { frame_id: u64, context_id: u64 },
    /// Frame or context is not applicable at the fusion timestamp.
    NotApplicable { timestamp_ms: u64 },
    /// Summary modality set differs from the registered context.
    UnexpectedModalities,
    /// Projection provenance differs from the enclosing frame identity.
    ProjectionIdentityMismatch {
        expected_frame_id: u64,
        received_frame_id: u64,
        expected_context_id: u64,
        received_context_id: u64,
        expected_prior_id: u64,
        received_prior_id: u64,
    },
    /// A projection modality is absent from the registered context.
    UnexpectedProjectionModality { context_id: u64, modality: Modality },
    /// Projection dimensionality differs from the registered context.
    ProjectionDimensionMismatch {
        context_id: u64,
        expected: u8,
        received: u8,
    },
    /// Producer evidence exceeded an opportunity bound pinned by the registry.
    OpportunityLimitExceeded {
        limit: RegistryPolicyLimit,
        maximum: u32,
        received: u32,
    },
}

/// Untrusted raw producer-opportunity parameters from a registry document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryOpportunityParams {
    /// Maximum frozen or post-processing active tracks.
    pub max_active_tracks: u32,
    /// Maximum bounded inputs represented by one frame.
    pub max_frame_inputs: u32,
    /// Maximum attempts represented for one track/modality pair.
    pub max_attempts_per_track_modality: u32,
    /// Maximum outcome/miss events represented by one frame.
    pub max_outcomes_per_frame: u32,
    /// Maximum producer monitor-queue capacity.
    pub max_monitor_queue_events: u32,
}

/// Invalid producer-opportunity policy from a registry document.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryOpportunityPolicyError {
    /// A required bound was zero or exceeded its wire hard maximum.
    #[error("invalid registry opportunity limit {field}: {value}, maximum {maximum}")]
    InvalidLimit {
        /// Invalid field.
        field: &'static str,
        /// Received value.
        value: u32,
        /// Compiled wire maximum.
        maximum: u32,
    },
}

/// Validated, immutable deployment-pinned producer bounds.
///
/// ```compile_fail
/// use galadriel_ncp::assembler::RegistryOpportunityPolicy;
/// let _ = RegistryOpportunityPolicy {
///     max_active_tracks: 1,
///     max_frame_inputs: 1,
///     max_attempts_per_track_modality: 1,
///     max_outcomes_per_frame: 1,
///     max_monitor_queue_events: 1,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryOpportunityPolicy {
    max_active_tracks: u32,
    max_frame_inputs: u32,
    max_attempts_per_track_modality: u32,
    max_outcomes_per_frame: u32,
    max_monitor_queue_events: u32,
    identity: ConfigurationIdentity,
}

impl RegistryOpportunityPolicy {
    /// Validate raw opportunity parameters.
    pub fn try_new(
        params: RegistryOpportunityParams,
    ) -> Result<Self, RegistryOpportunityPolicyError> {
        Self::try_from(params)
    }

    /// Maximum frozen or post-processing active tracks.
    #[must_use]
    pub const fn max_active_tracks(self) -> u32 {
        self.max_active_tracks
    }

    /// Maximum bounded inputs represented by one frame.
    #[must_use]
    pub const fn max_frame_inputs(self) -> u32 {
        self.max_frame_inputs
    }

    /// Maximum attempts represented for one track/modality pair.
    #[must_use]
    pub const fn max_attempts_per_track_modality(self) -> u32 {
        self.max_attempts_per_track_modality
    }

    /// Maximum outcome/miss events represented by one frame.
    #[must_use]
    pub const fn max_outcomes_per_frame(self) -> u32 {
        self.max_outcomes_per_frame
    }

    /// Maximum producer monitor-queue capacity.
    #[must_use]
    pub const fn max_monitor_queue_events(self) -> u32 {
        self.max_monitor_queue_events
    }

    /// Canonical identity of this validated registry policy.
    #[must_use]
    pub const fn identity(self) -> ConfigurationIdentity {
        self.identity
    }
}

impl TryFrom<RegistryOpportunityParams> for RegistryOpportunityPolicy {
    type Error = RegistryOpportunityPolicyError;

    fn try_from(params: RegistryOpportunityParams) -> Result<Self, Self::Error> {
        for (field, value, maximum) in [
            (
                "max_active_tracks",
                params.max_active_tracks,
                MAX_ACTIVE_TRACKS,
            ),
            ("max_frame_inputs", params.max_frame_inputs, MAX_FRAME_ITEMS),
            (
                "max_attempts_per_track_modality",
                params.max_attempts_per_track_modality,
                MAX_FRAME_ITEMS,
            ),
            (
                "max_outcomes_per_frame",
                params.max_outcomes_per_frame,
                MAX_FRAME_ITEMS,
            ),
            (
                "max_monitor_queue_events",
                params.max_monitor_queue_events,
                crate::monitor::MAX_MONITOR_QUEUE_EVENTS,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(RegistryOpportunityPolicyError::InvalidLimit {
                    field,
                    value,
                    maximum,
                });
            }
        }
        let identity = ConfigurationIdentityBuilder::new("registry-opportunity-policy")
            .u64("max_active_tracks", u64::from(params.max_active_tracks))
            .u64("max_frame_inputs", u64::from(params.max_frame_inputs))
            .u64(
                "max_attempts_per_track_modality",
                u64::from(params.max_attempts_per_track_modality),
            )
            .u64(
                "max_outcomes_per_frame",
                u64::from(params.max_outcomes_per_frame),
            )
            .u64(
                "max_monitor_queue_events",
                u64::from(params.max_monitor_queue_events),
            )
            .finish();
        Ok(Self {
            max_active_tracks: params.max_active_tracks,
            max_frame_inputs: params.max_frame_inputs,
            max_attempts_per_track_modality: params.max_attempts_per_track_modality,
            max_outcomes_per_frame: params.max_outcomes_per_frame,
            max_monitor_queue_events: params.max_monitor_queue_events,
            identity,
        })
    }
}

/// Read-only boundary between the assembler and a deployment-pinned registry.
///
/// Implementations must be externally deployment-pinned, compare
/// `registry_digest`, validate the frame/context binding and timestamp
/// applicability, require the exact registered canonical modality order, and
/// bind every common projection to that context's modality and dimensionality.
/// Keeping this as a static-dispatch trait lets the registry parser evolve without
/// weakening the assembly core.
pub trait RegistryVerifier {
    /// Return the externally pinned opportunity and producer-queue bounds.
    fn opportunity_policy(&self) -> Result<RegistryOpportunityPolicy, RegistryViolation>;

    /// Verify one completed summary against immutable deployment registry state.
    fn verify_summary(
        &self,
        identity: FrameIdentity,
        registry_digest: &str,
        expected_modalities: &[Modality],
    ) -> Result<(), RegistryViolation>;

    /// Verify one common projection against immutable deployment registry state.
    fn verify_projection(
        &self,
        identity: FrameIdentity,
        modality: Modality,
        projection: &ConsistencyProjection,
    ) -> Result<(), RegistryViolation>;
}

/// Untrusted raw assembler resource and deadline parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblerParams {
    /// Maximum open frames, including observation-first frames.
    pub max_open_frames: usize,
    /// Maximum outcome/miss records retained for one frame.
    pub max_events_per_frame: usize,
    /// Maximum observations retained for one frame.
    pub max_observations_per_frame: usize,
    /// Maximum distinct track identities retained for one frame.
    pub max_tracks_per_frame: usize,
    /// Maximum monitor events waiting for a missing global event sequence.
    pub max_reorder_events: usize,
    /// Maximum forward distance from the next required monitor sequence.
    pub max_reorder_distance: u64,
    /// Maximum aggregate encoded bytes represented by all buffers.
    pub max_buffered_bytes: usize,
    /// Maximum epoch-global prior identities retained without eviction.
    pub max_prior_identities: usize,
    /// Maximum observation replay streams retained without eviction.
    pub max_observation_streams: usize,
    /// Maximum forward observation sequence advance after a stream baseline.
    pub max_observation_advance: u64,
    /// Fixed deadline from the first route receipt for one frame.
    pub frame_deadline: Duration,
    /// Fixed time allowed for a missing monitor sequence to arrive.
    pub reorder_deadline: Duration,
    /// Required producer heartbeat cadence.
    pub heartbeat_interval: Duration,
    /// Receiver-owned receipt deadline after at least one heartbeat was accepted.
    pub heartbeat_deadline: Duration,
    /// Receiver-owned grace period for the first heartbeat after transport activation.
    pub initial_heartbeat_deadline: Duration,
}

/// Named, reviewed assembler profiles for release 0.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssemblerProfile {
    /// Bounded cross-route assembly profile shipped in 0.9.
    BoundedV0_9,
}

impl AssemblerProfile {
    /// Return this profile's frozen raw parameters.
    #[must_use]
    pub const fn params(self) -> AssemblerParams {
        match self {
            Self::BoundedV0_9 => AssemblerParams {
                max_open_frames: 64,
                max_events_per_frame: MAX_FRAME_ITEMS as usize,
                max_observations_per_frame: MAX_FRAME_ITEMS as usize,
                max_tracks_per_frame: 2 * MAX_ACTIVE_TRACKS as usize,
                max_reorder_events: 1_024,
                max_reorder_distance: MAX_FRAME_ITEMS as u64,
                max_buffered_bytes: 8 * 1024 * 1024,
                max_prior_identities: MAX_ASSEMBLER_PRIOR_IDENTITIES,
                max_observation_streams: MAX_ASSEMBLER_OBSERVATION_STREAMS,
                max_observation_advance: 1_000_000,
                frame_deadline: Duration::from_secs(5),
                reorder_deadline: Duration::from_secs(1),
                heartbeat_interval: Duration::from_secs(1),
                heartbeat_deadline: Duration::from_secs(3),
                initial_heartbeat_deadline: Duration::from_secs(30),
            },
        }
    }

    /// Validate this profile and return its immutable capability.
    pub fn try_limits(self) -> Result<AssemblerLimits, AssemblerConfigError> {
        AssemblerLimits::try_from(self.params())
    }
}

/// Finite, validated resource and deadline policy for one assembler epoch.
///
/// ```compile_fail
/// use galadriel_ncp::assembler::AssemblerLimits;
/// let _ = AssemblerLimits::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblerLimits {
    max_open_frames: usize,
    max_events_per_frame: usize,
    max_observations_per_frame: usize,
    max_tracks_per_frame: usize,
    max_reorder_events: usize,
    max_reorder_distance: u64,
    max_buffered_bytes: usize,
    max_prior_identities: usize,
    max_observation_streams: usize,
    max_observation_advance: u64,
    frame_deadline: Duration,
    reorder_deadline: Duration,
    heartbeat_interval: Duration,
    heartbeat_deadline: Duration,
    initial_heartbeat_deadline: Duration,
    identity: ConfigurationIdentity,
}

impl AssemblerLimits {
    /// Maximum open frames, including observation-first frames.
    #[must_use]
    pub const fn max_open_frames(self) -> usize {
        self.max_open_frames
    }

    /// Maximum outcome/miss records retained for one frame.
    #[must_use]
    pub const fn max_events_per_frame(self) -> usize {
        self.max_events_per_frame
    }

    /// Maximum observations retained for one frame.
    #[must_use]
    pub const fn max_observations_per_frame(self) -> usize {
        self.max_observations_per_frame
    }

    /// Maximum track identities retained for one frame.
    #[must_use]
    pub const fn max_tracks_per_frame(self) -> usize {
        self.max_tracks_per_frame
    }

    /// Maximum monitor events waiting for reordering.
    #[must_use]
    pub const fn max_reorder_events(self) -> usize {
        self.max_reorder_events
    }

    /// Maximum forward monitor sequence distance.
    #[must_use]
    pub const fn max_reorder_distance(self) -> u64 {
        self.max_reorder_distance
    }

    /// Aggregate encoded-byte budget.
    #[must_use]
    pub const fn max_buffered_bytes(self) -> usize {
        self.max_buffered_bytes
    }

    /// Maximum retained frozen-prior identities.
    #[must_use]
    pub const fn max_prior_identities(self) -> usize {
        self.max_prior_identities
    }

    /// Maximum retained observation replay streams.
    #[must_use]
    pub const fn max_observation_streams(self) -> usize {
        self.max_observation_streams
    }

    /// Maximum forward observation sequence advance.
    #[must_use]
    pub const fn max_observation_advance(self) -> u64 {
        self.max_observation_advance
    }

    /// Fixed frame-completion deadline.
    #[must_use]
    pub const fn frame_deadline(self) -> Duration {
        self.frame_deadline
    }

    /// Fixed monitor reorder-gap deadline.
    #[must_use]
    pub const fn reorder_deadline(self) -> Duration {
        self.reorder_deadline
    }

    /// Required producer heartbeat interval.
    #[must_use]
    pub const fn heartbeat_interval(self) -> Duration {
        self.heartbeat_interval
    }

    /// Steady-state receiver heartbeat deadline.
    #[must_use]
    pub const fn heartbeat_deadline(self) -> Duration {
        self.heartbeat_deadline
    }

    /// Initial receiver heartbeat grace period.
    #[must_use]
    pub const fn initial_heartbeat_deadline(self) -> Duration {
        self.initial_heartbeat_deadline
    }

    /// Canonical SHA-256 identity of this validated policy.
    #[must_use]
    pub const fn identity(self) -> ConfigurationIdentity {
        self.identity
    }

    const fn as_params(self) -> AssemblerParams {
        AssemblerParams {
            max_open_frames: self.max_open_frames,
            max_events_per_frame: self.max_events_per_frame,
            max_observations_per_frame: self.max_observations_per_frame,
            max_tracks_per_frame: self.max_tracks_per_frame,
            max_reorder_events: self.max_reorder_events,
            max_reorder_distance: self.max_reorder_distance,
            max_buffered_bytes: self.max_buffered_bytes,
            max_prior_identities: self.max_prior_identities,
            max_observation_streams: self.max_observation_streams,
            max_observation_advance: self.max_observation_advance,
            frame_deadline: self.frame_deadline,
            reorder_deadline: self.reorder_deadline,
            heartbeat_interval: self.heartbeat_interval,
            heartbeat_deadline: self.heartbeat_deadline,
            initial_heartbeat_deadline: self.initial_heartbeat_deadline,
        }
    }
}

impl TryFrom<AssemblerParams> for AssemblerLimits {
    type Error = AssemblerConfigError;

    fn try_from(params: AssemblerParams) -> Result<Self, Self::Error> {
        validate_assembler_params(params, None)?;
        let duration_value = |field, duration| {
            duration_ms(duration).ok_or(AssemblerConfigError::InvalidDuration {
                field,
                violation: AssemblerDurationViolation::NotExactMilliseconds,
            })
        };
        let identity = ConfigurationIdentityBuilder::new("assembler-limits")
            .u64("max_open_frames", params.max_open_frames as u64)
            .u64("max_events_per_frame", params.max_events_per_frame as u64)
            .u64(
                "max_observations_per_frame",
                params.max_observations_per_frame as u64,
            )
            .u64("max_tracks_per_frame", params.max_tracks_per_frame as u64)
            .u64("max_reorder_events", params.max_reorder_events as u64)
            .u64("max_reorder_distance", params.max_reorder_distance)
            .u64("max_buffered_bytes", params.max_buffered_bytes as u64)
            .u64("max_prior_identities", params.max_prior_identities as u64)
            .u64(
                "max_observation_streams",
                params.max_observation_streams as u64,
            )
            .u64("max_observation_advance", params.max_observation_advance)
            .u64(
                "frame_deadline_ms",
                duration_value("frame_deadline", params.frame_deadline)?,
            )
            .u64(
                "reorder_deadline_ms",
                duration_value("reorder_deadline", params.reorder_deadline)?,
            )
            .u64(
                "heartbeat_interval_ms",
                duration_value("heartbeat_interval", params.heartbeat_interval)?,
            )
            .u64(
                "heartbeat_deadline_ms",
                duration_value("heartbeat_deadline", params.heartbeat_deadline)?,
            )
            .u64(
                "initial_heartbeat_deadline_ms",
                duration_value(
                    "initial_heartbeat_deadline",
                    params.initial_heartbeat_deadline,
                )?,
            )
            .finish();
        Ok(Self {
            max_open_frames: params.max_open_frames,
            max_events_per_frame: params.max_events_per_frame,
            max_observations_per_frame: params.max_observations_per_frame,
            max_tracks_per_frame: params.max_tracks_per_frame,
            max_reorder_events: params.max_reorder_events,
            max_reorder_distance: params.max_reorder_distance,
            max_buffered_bytes: params.max_buffered_bytes,
            max_prior_identities: params.max_prior_identities,
            max_observation_streams: params.max_observation_streams,
            max_observation_advance: params.max_observation_advance,
            frame_deadline: params.frame_deadline,
            reorder_deadline: params.reorder_deadline,
            heartbeat_interval: params.heartbeat_interval,
            heartbeat_deadline: params.heartbeat_deadline,
            initial_heartbeat_deadline: params.initial_heartbeat_deadline,
            identity,
        })
    }
}

#[cfg(test)]
impl Default for AssemblerLimits {
    fn default() -> Self {
        AssemblerProfile::BoundedV0_9
            .try_limits()
            .expect("the compiled assembler test profile is valid")
    }
}

/// Why a duration policy was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssemblerDurationViolation {
    /// Duration was zero.
    Zero,
    /// Duration cannot be represented as an exact `u64` millisecond count.
    NotExactMilliseconds,
    /// Duration exceeded the compiled hard maximum.
    ExceedsHardMaximum,
    /// Steady deadline was shorter than the declared heartbeat interval.
    DeadlineShorterThanInterval,
    /// Initial grace was shorter than the steady heartbeat deadline.
    InitialShorterThanSteady,
    /// Deadline cannot be represented at the supplied monotonic anchor.
    AnchorOverflow,
}

/// Invalid immutable assembler configuration.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssemblerConfigError {
    /// Session or producer is not a canonical Galadriel core identity.
    #[error("invalid assembler {field}")]
    InvalidIdentity {
        /// Invalid field.
        field: &'static str,
    },
    /// A resource limit is zero or exceeds its hard ceiling.
    #[error("invalid assembler limit {field}: {value}, maximum {maximum}")]
    InvalidLimit {
        /// Invalid field.
        field: &'static str,
        /// Invalid value.
        value: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// A sequence-distance bound is zero or exceeds its hard ceiling.
    #[error("invalid assembler sequence limit {field}: {value}, maximum {maximum}")]
    InvalidSequenceLimit {
        /// Invalid field.
        field: &'static str,
        /// Invalid value.
        value: u64,
        /// Compiled hard maximum.
        maximum: u64,
    },
    /// Aggregate configured state exceeded the compiled ceiling.
    #[error("assembler aggregate state {value} exceeds maximum {maximum}")]
    AggregateStateTooLarge {
        /// Computed applicable state slots, or `usize::MAX` on arithmetic overflow.
        value: usize,
        /// Applicable compiled state-slot maximum.
        maximum: usize,
    },
    /// The aggregate byte budget cannot admit one maximum route payload.
    #[error("assembler buffered-byte budget {value} is smaller than required minimum {minimum}")]
    BufferBudgetTooSmall {
        /// Configured aggregate budget.
        value: usize,
        /// Minimum capable of admitting one bounded route payload.
        minimum: usize,
    },
    /// A duration is invalid or violates ordering.
    #[error("invalid assembler duration {field}: {violation:?}")]
    InvalidDuration {
        /// Invalid duration field or relationship.
        field: &'static str,
        /// Typed reason for rejection.
        violation: AssemblerDurationViolation,
    },
    /// Registry was not externally pinned or could not expose trusted policy.
    #[error("invalid assembler registry policy: {0:?}")]
    Registry(RegistryViolation),
}

/// Expected evidence still absent when a frame deadline expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MissingFrameEvidence {
    /// No frame summary arrived.
    Summary,
    /// One or more summary-declared observations did not arrive.
    Observation { missing: u32 },
}

/// Capacity whose exhaustion invalidated the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssemblyCapacity {
    /// Open-frame table.
    Frames,
    /// Per-frame outcome/miss table.
    FrameEvents,
    /// Per-frame observation table.
    FrameObservations,
    /// Per-frame track identity table.
    FrameTracks,
    /// Global monitor reorder table.
    MonitorReorder,
    /// Aggregate encoded-byte accounting.
    BufferedBytes,
    /// Epoch-global frozen-prior index.
    PriorIdentities,
    /// Epoch-global observation replay index.
    ObservationStreams,
}

/// Deployment-pinned opportunity bound exceeded by producer evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryPolicyLimit {
    /// Frozen or post-processing active tracks.
    ActiveTracks,
    /// Inputs represented by one frame.
    FrameInputs,
    /// Attempts represented for one track/modality pair.
    AttemptsPerTrackModality,
    /// Outcome and miss events represented by one frame.
    OutcomesPerFrame,
    /// Producer monitor-queue capacity.
    MonitorQueueEvents,
}

/// Fail-closed protocol, availability, or resource violation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssemblyFaultKind {
    /// An internal bounded-state invariant failed without panicking.
    InternalState,
    /// Local monotonic timestamps regressed across serialized calls.
    MonotonicClockRegressed,
    /// A configured monotonic deadline could not be represented at its receipt anchor.
    MonotonicDeadlineOverflow,
    /// Payload exceeded the pre-decode route bound.
    PayloadTooLarge { route: EvidenceRoute },
    /// Payload was not strict JSON for the route envelope.
    MalformedPayload { route: EvidenceRoute },
    /// Decoded envelope failed strict semantic validation.
    InvalidEnvelope { route: EvidenceRoute },
    /// Payload session or producer differs from the exact subscription.
    ProvenanceMismatch { route: EvidenceRoute },
    /// A bounded state table or byte budget was exhausted.
    CapacityExceeded { capacity: AssemblyCapacity },
    /// Monitor event sequence duplicated or regressed.
    DuplicateOrRegressedMonitorSequence { expected: u64, received: u64 },
    /// Monitor event arrived farther ahead than the configured reorder window.
    MonitorReorderDistanceExceeded { expected: u64, received: u64 },
    /// Missing monitor sequence did not arrive before its receipt-time deadline.
    MonitorSequenceGap { expected: u64, next_received: u64 },
    /// JSON-safe monitor event sequence was exhausted.
    MonitorSequenceExhausted,
    /// Fusion sequences regressed in globally ordered monitor evidence.
    FusionSequenceRegressed { previous: u64, received: u64 },
    /// A later frame began before the preceding frame summary.
    MissingSummaryBeforeNextFrame { previous: u64, received: u64 },
    /// Outcome, miss, or second summary followed a frame summary.
    EventAfterFrameSummary { fusion_seq: u64 },
    /// Monitor records for one fusion sequence disagree on immutable identity.
    FrameIdentityMismatch { fusion_seq: u64 },
    /// A prior identity was reused at another fusion sequence.
    PriorReuse {
        prior_id: u64,
        previous_fusion_seq: u64,
        received_fusion_seq: u64,
    },
    /// Registry rejected pinned policy or the summary's digest, binding, time, or modalities.
    Registry(RegistryViolation),
    /// Summary declared producer loss or truncation.
    ProducerDegradedFrame { fusion_seq: u64, truncated: bool },
    /// Summary outcome/miss count differs from received monitor records.
    OutcomeCountMismatch { declared: u32, received: u32 },
    /// Summary v1 count differs from v1-expected outcomes.
    V1ExpectedCountMismatch { declared: u32, received: u32 },
    /// Event ordering/cardinality violates the documented v1 ledger.
    InvalidFrameLedger { fusion_seq: u64 },
    /// Observation is replayed or regressed within a track/modality stream.
    DuplicateOrRegressedObservation {
        track_id: u64,
        modality: Modality,
        previous: u64,
        received: u64,
    },
    /// Observation sequence advanced beyond the configured bound.
    ObservationAdvanceExceeded {
        track_id: u64,
        modality: Modality,
        previous: u64,
        received: u64,
    },
    /// Observation refers to a frame already finalized and evicted.
    ObservationForFinalizedFrame { fusion_seq: u64 },
    /// No v1-expected outcome matches the observation key.
    UnexpectedObservation {
        fusion_seq: u64,
        track_id: u64,
        modality: Modality,
    },
    /// Matching observation has a different fusion timestamp.
    ObservationTimestampMismatch {
        fusion_seq: u64,
        track_id: u64,
        modality: Modality,
    },
    /// Matching observation and outcome carry different projection attestations.
    ObservationProjectionMismatch {
        fusion_seq: u64,
        track_id: u64,
        modality: Modality,
    },
    /// Frame could not become complete before its fixed deadline.
    FrameDeadlineExpired {
        fusion_seq: u64,
        missing: MissingFrameEvidence,
    },
    /// Heartbeat declaration differs from the receiver-owned operational profile.
    HeartbeatProfileMismatch,
    /// Heartbeat uptime or cumulative counters regressed within one epoch.
    HeartbeatStateRegressed,
    /// Heartbeat completion cursor differs from summaries preceding it in event order.
    HeartbeatLastFusionMismatch {
        expected: Option<u64>,
        received: Option<u64>,
    },
    /// Heartbeat or cumulative drop counters declared epoch loss.
    ProducerDeclaredLoss,
    /// No accepted heartbeat arrived before the local receipt deadline.
    HeartbeatDeadlineExpired,
}

/// The first terminal fault for an assembler epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyFault {
    /// Typed failure.
    pub kind: AssemblyFaultKind,
    /// Earliest fusion sequence whose downstream correlation suffix must reset.
    pub invalidate_from_fusion_seq: Option<u64>,
    /// Local monotonic time at which the fault became known.
    pub detected_at: Instant,
}

/// Outcome or miss retained in producer event-sequence order.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FrameMonitorEvent {
    /// Per-attempt disposition.
    Outcome(ModalityOutcome),
    /// Aggregate track/modality miss.
    Miss(ModalityMiss),
}

/// Opaque lifecycle-complete proof object constructed only by the assembler.
/// Statistical detectors may still return insufficient evidence (for example,
/// for incomparable projections); readiness is not `Nominal`.
#[derive(Debug, Clone)]
pub struct AssembledFrame {
    /// Exact producer session proven across both evidence routes.
    pub(crate) session_id: String,
    /// Exact producer identity proven across both evidence routes.
    pub(crate) producer_id: String,
    /// Immutable frame identity.
    pub(crate) identity: FrameIdentity,
    /// Producer-ordered outcome and miss records.
    pub(crate) monitor_events: Vec<FrameMonitorEvent>,
    /// Exact v1 observations, sorted by track and stable modality rank.
    pub(crate) observations: Vec<PidObservation>,
    /// Sole healthy closure record.
    pub(crate) summary: FrameSummary,
}

impl AssembledFrame {
    /// Exact producer session and statistical-history epoch.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Exact producer identity bound to this frame.
    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    /// Immutable identity proven across both evidence routes.
    pub fn identity(&self) -> FrameIdentity {
        self.identity
    }

    /// Producer-ordered, lifecycle-complete outcome and miss ledger.
    pub fn monitor_events(&self) -> &[FrameMonitorEvent] {
        &self.monitor_events
    }

    /// Exact joined observations, ordered by track and stable modality rank.
    pub fn observations(&self) -> &[PidObservation] {
        &self.observations
    }

    /// Sole healthy producer closure record for this frame.
    pub fn summary(&self) -> &FrameSummary {
        &self.summary
    }
}

/// Observable state change produced by an ingest or time-advance call.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AssemblyEvent {
    /// One lifecycle-complete, healthy frame.
    FrameReady(AssembledFrame),
    /// Advisory NCP contract-hash mismatch; frozen schema compatibility is unchanged.
    ContractHashMismatch { route: EvidenceRoute },
    /// Contiguous heartbeat accepted and local receipt deadline advanced.
    HeartbeatAccepted {
        event_seq: u64,
        received_at: Instant,
    },
    /// Terminal epoch fault. No later input can produce [`Self::FrameReady`].
    Fault(AssemblyFault),
}

#[derive(Debug)]
struct PendingMonitor {
    envelope: MonitorEnvelope,
    encoded_bytes: usize,
    received_at: Instant,
}

#[derive(Debug)]
struct StoredObservation {
    observation: PidObservation,
}

#[derive(Debug)]
struct PartialFrame {
    first_seen_at: Instant,
    identity: Option<FrameIdentity>,
    monitor_events: Vec<FrameMonitorEvent>,
    observations: HashMap<(u64, Modality), StoredObservation>,
    track_ids: HashSet<u64>,
    summary: Option<FrameSummary>,
    expected_observations: Option<HashMap<(u64, Modality), Option<ConsistencyProjection>>>,
    buffered_bytes: usize,
    ready: bool,
}

impl PartialFrame {
    fn new(first_seen_at: Instant) -> Self {
        Self {
            first_seen_at,
            identity: None,
            monitor_events: Vec::new(),
            observations: HashMap::new(),
            track_ids: HashSet::new(),
            summary: None,
            expected_observations: None,
            buffered_bytes: 0,
            ready: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HeartbeatSnapshot {
    uptime_ms: u64,
    published_event_count: u64,
}

/// Pure, bounded cross-route assembler for one exact producer epoch.
pub struct CrossRouteAssembler<R> {
    session_id: String,
    producer_id: String,
    registry: R,
    registry_policy: RegistryOpportunityPolicy,
    limits: AssemblerLimits,
    last_now: Instant,
    next_event_seq: u64,
    pending_monitor: BTreeMap<u64, PendingMonitor>,
    monitor_gap_started_at: Option<Instant>,
    frames: BTreeMap<u64, PartialFrame>,
    buffered_bytes: usize,
    prior_sequences: HashMap<u64, u64>,
    observation_high_water: HashMap<(u64, Modality), u64>,
    last_monitor_fusion_seq: Option<u64>,
    last_summary_fusion_seq: Option<u64>,
    last_finalized_fusion_seq: Option<u64>,
    heartbeat: Option<HeartbeatSnapshot>,
    last_heartbeat_receipt: Option<Instant>,
    started_at: Instant,
    fault: Option<AssemblyFault>,
}

impl<R: RegistryVerifier> CrossRouteAssembler<R> {
    /// Create a one-epoch assembler with immutable provenance, registry, and bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AssemblerConfigError`] for invalid identities, zero bounds,
    /// excessive hard limits, a non-millisecond/invalid deadline profile, or a
    /// registry that cannot expose externally pinned opportunity policy.
    pub fn new(
        session_id: impl AsRef<str>,
        producer_id: impl AsRef<str>,
        registry: R,
        limits: AssemblerLimits,
        started_at: Instant,
    ) -> Result<Self, AssemblerConfigError> {
        let session_id = session_id.as_ref();
        let producer_id = producer_id.as_ref();
        if !valid_session_identity(session_id) {
            return Err(AssemblerConfigError::InvalidIdentity {
                field: "session_id",
            });
        }
        if !valid_producer_identity(producer_id) {
            return Err(AssemblerConfigError::InvalidIdentity {
                field: "producer_id",
            });
        }
        validate_limits(limits, started_at)?;
        let registry_policy = registry
            .opportunity_policy()
            .map_err(AssemblerConfigError::Registry)?;
        Ok(Self {
            session_id: session_id.to_owned(),
            producer_id: producer_id.to_owned(),
            registry,
            registry_policy,
            limits,
            last_now: started_at,
            next_event_seq: 1,
            pending_monitor: BTreeMap::new(),
            monitor_gap_started_at: None,
            frames: BTreeMap::new(),
            buffered_bytes: 0,
            prior_sequences: HashMap::new(),
            observation_high_water: HashMap::new(),
            last_monitor_fusion_seq: None,
            last_summary_fusion_seq: None,
            last_finalized_fusion_seq: None,
            heartbeat: None,
            last_heartbeat_receipt: None,
            started_at,
            fault: None,
        })
    }

    /// Re-anchor a newly constructed assembler at the transport activation boundary.
    ///
    /// The operational receiver validates configuration before creating external
    /// subscriptions, then invokes this exactly once before admitting any evidence.
    #[cfg(any(feature = "zenoh", test))]
    pub(crate) fn reanchor_initial_clock(
        &mut self,
        started_at: Instant,
    ) -> Result<(), AssemblerConfigError> {
        debug_assert!(self.pending_monitor.is_empty());
        debug_assert!(self.frames.is_empty());
        debug_assert!(self.fault.is_none());
        debug_assert_eq!(self.last_now, self.started_at);
        validate_deadline_anchor(self.limits, started_at)?;
        self.started_at = started_at;
        self.last_now = started_at;
        Ok(())
    }

    /// First terminal fault, if the epoch has failed closed.
    pub fn fault(&self) -> Option<&AssemblyFault> {
        self.fault.as_ref()
    }

    /// Number of frames currently consuming bounded assembly state.
    pub fn open_frames(&self) -> usize {
        self.frames.len()
    }

    /// Monitor events currently waiting behind the next required global sequence.
    pub fn pending_monitor_events(&self) -> usize {
        self.pending_monitor.len()
    }

    /// Next contiguous monitor `event_seq` required by this epoch.
    pub fn next_expected_monitor_event_seq(&self) -> u64 {
        self.next_event_seq
    }

    /// Local monotonic receipt time of the last accepted contiguous heartbeat.
    pub fn last_heartbeat_receipt(&self) -> Option<Instant> {
        self.last_heartbeat_receipt
    }

    /// Aggregate encoded bytes represented by current buffers.
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Epoch-global frozen-prior identities retained for replay rejection.
    pub fn prior_identities(&self) -> usize {
        self.prior_sequences.len()
    }

    /// Epoch-global `(track, modality)` streams retained for replay rejection.
    pub fn observation_streams(&self) -> usize {
        self.observation_high_water.len()
    }

    /// Immutable resource and deadline policy for this epoch.
    pub fn limits(&self) -> AssemblerLimits {
        self.limits
    }

    /// Earliest reorder-gap, incomplete-frame, or heartbeat deadline.
    ///
    /// Callers may sleep until this instant and then call [`Self::advance_time`].
    /// A terminal epoch has no further deadline work.
    pub fn next_deadline_at(&self) -> Option<Instant> {
        if self.fault.is_some() {
            return None;
        }

        let reorder = self
            .monitor_gap_started_at
            .map(|started| conservative_deadline_at(started, self.limits.reorder_deadline));
        let frame = self
            .frames
            .values()
            .filter(|frame| !frame.ready)
            .map(|frame| conservative_deadline_at(frame.first_seen_at, self.limits.frame_deadline))
            .min();
        let (heartbeat_base, heartbeat_window) = self.heartbeat_deadline_base_and_window();
        let heartbeat = conservative_deadline_at(heartbeat_base, heartbeat_window);

        [reorder, frame, Some(heartbeat)]
            .into_iter()
            .flatten()
            .min()
    }

    /// Decode and ingest one raw monitor-route payload.
    pub fn ingest_monitor_bytes(
        &mut self,
        encoded: &[u8],
        received_at: Instant,
    ) -> Vec<AssemblyEvent> {
        let mut events = self.begin_call(received_at);
        if self.fault.is_some() {
            return events;
        }
        let envelope = match MonitorEnvelope::decode(encoded) {
            Ok(envelope) => envelope,
            Err(error) => {
                let kind = monitor_decode_fault(&error);
                events.push(self.fail(kind, None, received_at));
                return events;
            }
        };
        events.extend(self.ingest_monitor_envelope_sized(envelope, encoded.len(), received_at));
        events
    }

    /// Ingest an already decoded monitor envelope using its canonical encoded size.
    pub fn ingest_monitor_envelope(
        &mut self,
        envelope: MonitorEnvelope,
        received_at: Instant,
    ) -> Vec<AssemblyEvent> {
        let encoded_bytes = match serde_json::to_vec(&envelope) {
            Ok(encoded) => encoded.len(),
            Err(_) => {
                let mut events = self.begin_call(received_at);
                if self.fault.is_none() {
                    events.push(self.fail(
                        AssemblyFaultKind::InvalidEnvelope {
                            route: EvidenceRoute::Monitor,
                        },
                        event_fusion_seq(&envelope.event),
                        received_at,
                    ));
                }
                return events;
            }
        };
        self.ingest_monitor_envelope_sized(envelope, encoded_bytes, received_at)
    }

    fn ingest_monitor_envelope_sized(
        &mut self,
        envelope: MonitorEnvelope,
        encoded_bytes: usize,
        received_at: Instant,
    ) -> Vec<AssemblyEvent> {
        let mut events = self.begin_call(received_at);
        if self.fault.is_some() {
            return events;
        }
        if encoded_bytes > MAX_MONITOR_EVENT_BYTES {
            events.push(self.fail(
                AssemblyFaultKind::PayloadTooLarge {
                    route: EvidenceRoute::Monitor,
                },
                event_fusion_seq(&envelope.event),
                received_at,
            ));
            return events;
        }
        let status = match envelope.validate_for(&self.session_id, &self.producer_id) {
            Ok(status) => status,
            Err(error) => {
                events.push(self.fail(monitor_validation_fault(&error), None, received_at));
                return events;
            }
        };
        if let ProducerEvent::ModalityOutcome(outcome) = &envelope.event {
            if let Some(projection) = &outcome.consistency_projection {
                if let Err(error) = self.registry.verify_projection(
                    FrameIdentity::from_outcome(outcome),
                    outcome.modality,
                    projection,
                ) {
                    events.push(self.fail(
                        AssemblyFaultKind::Registry(error),
                        Some(outcome.fusion_seq),
                        received_at,
                    ));
                    return events;
                }
            }
        }
        if matches!(status, ContractStatus::Mismatch { .. }) {
            events.push(AssemblyEvent::ContractHashMismatch {
                route: EvidenceRoute::Monitor,
            });
        }
        let fusion_seq = event_fusion_seq(&envelope.event);
        if envelope.event_seq < self.next_event_seq
            || self.pending_monitor.contains_key(&envelope.event_seq)
        {
            events.push(self.fail(
                AssemblyFaultKind::DuplicateOrRegressedMonitorSequence {
                    expected: self.next_event_seq,
                    received: envelope.event_seq,
                },
                fusion_seq,
                received_at,
            ));
            return events;
        }
        if envelope.event_seq.saturating_sub(self.next_event_seq) > self.limits.max_reorder_distance
        {
            events.push(self.fail(
                AssemblyFaultKind::MonitorReorderDistanceExceeded {
                    expected: self.next_event_seq,
                    received: envelope.event_seq,
                },
                fusion_seq,
                received_at,
            ));
            return events;
        }
        if self.pending_monitor.len() >= self.limits.max_reorder_events {
            events.push(self.fail(
                AssemblyFaultKind::CapacityExceeded {
                    capacity: AssemblyCapacity::MonitorReorder,
                },
                fusion_seq,
                received_at,
            ));
            return events;
        }
        if let Some(fusion_seq) = fusion_seq {
            if let Err(kind) = self.ensure_frame(fusion_seq, received_at) {
                events.push(self.fail(kind, Some(fusion_seq), received_at));
                return events;
            }
        }
        if !self.reserve_bytes(encoded_bytes) {
            events.push(self.fail(
                AssemblyFaultKind::CapacityExceeded {
                    capacity: AssemblyCapacity::BufferedBytes,
                },
                fusion_seq,
                received_at,
            ));
            return events;
        }
        self.pending_monitor.insert(
            envelope.event_seq,
            PendingMonitor {
                envelope,
                encoded_bytes,
                received_at,
            },
        );
        events.extend(self.drain_monitor(received_at));
        events
    }

    /// Decode and ingest one raw frozen-observation-route payload.
    pub fn ingest_observation_bytes(
        &mut self,
        encoded: &[u8],
        received_at: Instant,
    ) -> Vec<AssemblyEvent> {
        let mut events = self.begin_call(received_at);
        if self.fault.is_some() {
            return events;
        }
        if encoded.len() > MAX_ASSEMBLER_SIDECAR_BYTES {
            events.push(self.fail(
                AssemblyFaultKind::PayloadTooLarge {
                    route: EvidenceRoute::Observation,
                },
                None,
                received_at,
            ));
            return events;
        }
        let envelope = match SidecarEnvelope::decode(encoded) {
            Ok(envelope) => envelope,
            Err(SidecarDecodeError::MalformedJson) => {
                events.push(self.fail(
                    AssemblyFaultKind::MalformedPayload {
                        route: EvidenceRoute::Observation,
                    },
                    None,
                    received_at,
                ));
                return events;
            }
            Err(SidecarDecodeError::InvalidEnvelope | SidecarDecodeError::Semantic(_)) => {
                events.push(self.fail(
                    AssemblyFaultKind::InvalidEnvelope {
                        route: EvidenceRoute::Observation,
                    },
                    None,
                    received_at,
                ));
                return events;
            }
        };
        events.extend(self.ingest_observation_envelope_sized(envelope, encoded.len(), received_at));
        events
    }

    /// Ingest an already decoded sidecar envelope using its canonical encoded size.
    pub fn ingest_observation_envelope(
        &mut self,
        envelope: SidecarEnvelope,
        received_at: Instant,
    ) -> Vec<AssemblyEvent> {
        let encoded_bytes = match serde_json::to_vec(&envelope) {
            Ok(encoded) => encoded.len(),
            Err(_) => {
                let mut events = self.begin_call(received_at);
                if self.fault.is_none() {
                    events.push(self.fail(
                        AssemblyFaultKind::InvalidEnvelope {
                            route: EvidenceRoute::Observation,
                        },
                        Some(envelope.observation.sequence().get()),
                        received_at,
                    ));
                }
                return events;
            }
        };
        self.ingest_observation_envelope_sized(envelope, encoded_bytes, received_at)
    }

    fn ingest_observation_envelope_sized(
        &mut self,
        envelope: SidecarEnvelope,
        encoded_bytes: usize,
        received_at: Instant,
    ) -> Vec<AssemblyEvent> {
        let mut events = self.begin_call(received_at);
        if self.fault.is_some() {
            return events;
        }
        if encoded_bytes > MAX_ASSEMBLER_SIDECAR_BYTES {
            events.push(self.fail(
                AssemblyFaultKind::PayloadTooLarge {
                    route: EvidenceRoute::Observation,
                },
                Some(envelope.observation.sequence().get()),
                received_at,
            ));
            return events;
        }
        let status = match envelope.validate_for(&self.session_id, &self.producer_id) {
            Ok(status) => status,
            Err(error) => {
                events.push(self.fail(sidecar_validation_fault(&error), None, received_at));
                return events;
            }
        };
        if matches!(status, ContractStatus::Mismatch { .. }) {
            events.push(AssemblyEvent::ContractHashMismatch {
                route: EvidenceRoute::Observation,
            });
        }
        let observation = envelope.observation;
        let fusion_seq = observation.sequence().get();
        if let Some(projection) = observation.consistency_projection() {
            let projection_identity = projection.identity();
            let identity = FrameIdentity {
                fusion_seq,
                fusion_timestamp_ms: observation.timestamp_ms().get(),
                frame_id: projection_identity.frame_id().get(),
                context_id: projection_identity.context_id().get(),
                prior_id: projection_identity.frozen_prior_id().get(),
            };
            if let Err(error) =
                self.registry
                    .verify_projection(identity, observation.modality(), projection)
            {
                events.push(self.fail(
                    AssemblyFaultKind::Registry(error),
                    Some(fusion_seq),
                    received_at,
                ));
                return events;
            }
        }
        if self
            .last_finalized_fusion_seq
            .is_some_and(|last| fusion_seq <= last)
        {
            events.push(self.fail(
                AssemblyFaultKind::ObservationForFinalizedFrame { fusion_seq },
                Some(fusion_seq),
                received_at,
            ));
            return events;
        }
        let stream = (observation.track_id().get(), observation.modality());
        if let Some(previous) = self.observation_high_water.get(&stream).copied() {
            if fusion_seq <= previous {
                events.push(self.fail(
                    AssemblyFaultKind::DuplicateOrRegressedObservation {
                        track_id: stream.0,
                        modality: stream.1,
                        previous,
                        received: fusion_seq,
                    },
                    Some(fusion_seq),
                    received_at,
                ));
                return events;
            }
            if fusion_seq - previous > self.limits.max_observation_advance {
                events.push(self.fail(
                    AssemblyFaultKind::ObservationAdvanceExceeded {
                        track_id: stream.0,
                        modality: stream.1,
                        previous,
                        received: fusion_seq,
                    },
                    Some(fusion_seq),
                    received_at,
                ));
                return events;
            }
        } else if self.observation_high_water.len() >= self.limits.max_observation_streams {
            events.push(self.fail(
                AssemblyFaultKind::CapacityExceeded {
                    capacity: AssemblyCapacity::ObservationStreams,
                },
                Some(fusion_seq),
                received_at,
            ));
            return events;
        }
        if let Err(kind) = self.ensure_frame(fusion_seq, received_at) {
            events.push(self.fail(kind, Some(fusion_seq), received_at));
            return events;
        }
        if let Some(identity) = FrameIdentity::from_observation(&observation) {
            if let Err(kind) = self.establish_identity(identity) {
                events.push(self.fail(kind, Some(fusion_seq), received_at));
                return events;
            }
        }
        let Some(frame) = self.frames.get(&fusion_seq) else {
            events.push(self.fail(
                AssemblyFaultKind::InternalState,
                Some(fusion_seq),
                received_at,
            ));
            return events;
        };
        if frame.observations.len() >= self.limits.max_observations_per_frame {
            events.push(self.fail(
                AssemblyFaultKind::CapacityExceeded {
                    capacity: AssemblyCapacity::FrameObservations,
                },
                Some(fusion_seq),
                received_at,
            ));
            return events;
        }
        if !frame.track_ids.contains(&observation.track_id().get())
            && frame.track_ids.len() >= self.limits.max_tracks_per_frame
        {
            events.push(self.fail(
                AssemblyFaultKind::CapacityExceeded {
                    capacity: AssemblyCapacity::FrameTracks,
                },
                Some(fusion_seq),
                received_at,
            ));
            return events;
        }
        if let Some(expected) = frame.expected_observations.as_ref() {
            let Some(identity) = frame.identity else {
                events.push(self.fail(
                    AssemblyFaultKind::InternalState,
                    Some(fusion_seq),
                    received_at,
                ));
                return events;
            };
            if let Err(kind) = validate_observation_join(identity, expected, &observation) {
                events.push(self.fail(kind, Some(fusion_seq), received_at));
                return events;
            }
        }
        if !self.reserve_bytes(encoded_bytes) {
            events.push(self.fail(
                AssemblyFaultKind::CapacityExceeded {
                    capacity: AssemblyCapacity::BufferedBytes,
                },
                Some(fusion_seq),
                received_at,
            ));
            return events;
        }
        self.observation_high_water.insert(stream, fusion_seq);
        let Some(frame) = self.frames.get_mut(&fusion_seq) else {
            events.push(self.fail(
                AssemblyFaultKind::InternalState,
                Some(fusion_seq),
                received_at,
            ));
            return events;
        };
        frame.track_ids.insert(observation.track_id().get());
        frame.buffered_bytes = frame.buffered_bytes.saturating_add(encoded_bytes);
        frame
            .observations
            .insert(stream, StoredObservation { observation });
        if let Err(kind) = self.refresh_frame_readiness(fusion_seq) {
            events.push(self.fail(kind, Some(fusion_seq), received_at));
            return events;
        }
        match self.drain_ready_frames() {
            Ok(mut ready) => events.append(&mut ready),
            Err(kind) => events.push(self.fail(kind, Some(fusion_seq), received_at)),
        }
        events
    }

    /// Advance local monotonic time and expire monitor gaps, frames, or heartbeat.
    pub fn advance_time(&mut self, now: Instant) -> Vec<AssemblyEvent> {
        self.begin_call(now)
    }

    fn begin_call(&mut self, now: Instant) -> Vec<AssemblyEvent> {
        if self.fault.is_some() {
            return Vec::new();
        }
        if now < self.last_now {
            return vec![self.fail(
                AssemblyFaultKind::MonotonicClockRegressed,
                None,
                self.last_now,
            )];
        }
        self.last_now = now;
        if [
            self.limits.frame_deadline,
            self.limits.reorder_deadline,
            self.limits.heartbeat_deadline,
        ]
        .into_iter()
        .any(|duration| now.checked_add(duration).is_none())
        {
            return vec![self.fail(
                AssemblyFaultKind::MonotonicDeadlineOverflow,
                self.oldest_open_frame(),
                now,
            )];
        }
        if let Some(started) = self.monitor_gap_started_at {
            if elapsed_at_least(started, now, self.limits.reorder_deadline) {
                let next_received = self
                    .pending_monitor
                    .keys()
                    .next()
                    .copied()
                    .unwrap_or(self.next_event_seq);
                let invalidate_from_fusion_seq = self
                    .pending_monitor
                    .values()
                    .filter_map(|pending| event_fusion_seq(&pending.envelope.event))
                    .chain(self.oldest_open_frame())
                    .min();
                return vec![self.fail(
                    AssemblyFaultKind::MonitorSequenceGap {
                        expected: self.next_event_seq,
                        next_received,
                    },
                    invalidate_from_fusion_seq,
                    now,
                )];
            }
        }
        if let Some((&fusion_seq, frame)) = self.frames.iter().find(|(_, frame)| {
            !frame.ready && elapsed_at_least(frame.first_seen_at, now, self.limits.frame_deadline)
        }) {
            let missing = if let Some(summary) = &frame.summary {
                let expected = summary.v1_expected_count;
                let received = u32::try_from(frame.observations.len()).unwrap_or(u32::MAX);
                MissingFrameEvidence::Observation {
                    missing: expected.saturating_sub(received).max(1),
                }
            } else {
                MissingFrameEvidence::Summary
            };
            return vec![self.fail(
                AssemblyFaultKind::FrameDeadlineExpired {
                    fusion_seq,
                    missing,
                },
                Some(fusion_seq),
                now,
            )];
        }
        let (heartbeat_base, heartbeat_window) = self.heartbeat_deadline_base_and_window();
        if elapsed_at_least(heartbeat_base, now, heartbeat_window) {
            return vec![self.fail(
                AssemblyFaultKind::HeartbeatDeadlineExpired,
                self.oldest_open_frame(),
                now,
            )];
        }
        Vec::new()
    }

    fn heartbeat_deadline_base_and_window(&self) -> (Instant, Duration) {
        self.last_heartbeat_receipt.map_or(
            (self.started_at, self.limits.initial_heartbeat_deadline),
            |receipt| (receipt, self.limits.heartbeat_deadline),
        )
    }

    fn drain_monitor(&mut self, now: Instant) -> Vec<AssemblyEvent> {
        let mut events = Vec::new();
        let mut staged_ready = Vec::new();
        while let Some(pending) = self.pending_monitor.remove(&self.next_event_seq) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(pending.encoded_bytes);
            let event_seq = pending.envelope.event_seq;
            match self.process_ordered_monitor(pending) {
                Ok(produced) => {
                    for event in produced {
                        if matches!(&event, AssemblyEvent::FrameReady(_)) {
                            staged_ready.push(event);
                        } else {
                            events.push(event);
                        }
                    }
                }
                Err((kind, fusion_seq)) => {
                    events.push(self.fail(kind, fusion_seq, now));
                    return events;
                }
            }
            if self.next_event_seq == JSON_SAFE_INTEGER_MAX as u64 {
                events.push(self.fail(
                    AssemblyFaultKind::MonitorSequenceExhausted,
                    self.oldest_open_frame(),
                    now,
                ));
                return events;
            }
            self.next_event_seq = event_seq + 1;
        }
        self.monitor_gap_started_at = self
            .pending_monitor
            .values()
            .map(|pending| pending.received_at)
            .min();
        events.append(&mut staged_ready);
        events
    }

    fn process_ordered_monitor(
        &mut self,
        pending: PendingMonitor,
    ) -> Result<Vec<AssemblyEvent>, (AssemblyFaultKind, Option<u64>)> {
        let event_seq = pending.envelope.event_seq;
        match pending.envelope.event {
            ProducerEvent::Heartbeat(heartbeat) => {
                self.process_heartbeat(&heartbeat)
                    .map_err(|kind| (kind, self.oldest_open_frame()))?;
                self.last_heartbeat_receipt = Some(pending.received_at);
                Ok(vec![AssemblyEvent::HeartbeatAccepted {
                    event_seq,
                    received_at: pending.received_at,
                }])
            }
            ProducerEvent::ModalityOutcome(outcome) => {
                let fusion_seq = outcome.fusion_seq;
                self.process_frame_event(
                    FrameIdentity::from_outcome(&outcome),
                    FrameMonitorEvent::Outcome(outcome),
                    pending.encoded_bytes,
                    pending.received_at,
                )
                .map_err(|kind| (kind, Some(fusion_seq)))?;
                self.refresh_frame_readiness(fusion_seq)
                    .map_err(|kind| (kind, Some(fusion_seq)))?;
                self.drain_ready_frames()
                    .map_err(|kind| (kind, Some(fusion_seq)))
            }
            ProducerEvent::ModalityMiss(miss) => {
                let fusion_seq = miss.fusion_seq;
                self.process_frame_event(
                    FrameIdentity::from_miss(&miss),
                    FrameMonitorEvent::Miss(miss),
                    pending.encoded_bytes,
                    pending.received_at,
                )
                .map_err(|kind| (kind, Some(fusion_seq)))?;
                self.refresh_frame_readiness(fusion_seq)
                    .map_err(|kind| (kind, Some(fusion_seq)))?;
                self.drain_ready_frames()
                    .map_err(|kind| (kind, Some(fusion_seq)))
            }
            ProducerEvent::FrameSummary(summary) => {
                let fusion_seq = summary.fusion_seq;
                self.process_summary(summary, pending.encoded_bytes, pending.received_at)
                    .map_err(|kind| (kind, Some(fusion_seq)))?;
                self.refresh_frame_readiness(fusion_seq)
                    .map_err(|kind| (kind, Some(fusion_seq)))?;
                self.drain_ready_frames()
                    .map_err(|kind| (kind, Some(fusion_seq)))
            }
        }
    }

    fn process_frame_event(
        &mut self,
        identity: FrameIdentity,
        event: FrameMonitorEvent,
        encoded_bytes: usize,
        received_at: Instant,
    ) -> Result<(), AssemblyFaultKind> {
        self.check_monitor_frame_order(identity.fusion_seq)?;
        self.ensure_frame(identity.fusion_seq, received_at)?;
        self.establish_identity(identity)?;
        let frame = self
            .frames
            .get(&identity.fusion_seq)
            .ok_or(AssemblyFaultKind::InternalState)?;
        if frame.summary.is_some() {
            return Err(AssemblyFaultKind::EventAfterFrameSummary {
                fusion_seq: identity.fusion_seq,
            });
        }
        let next_event_count = u32::try_from(frame.monitor_events.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        enforce_registry_max(
            RegistryPolicyLimit::OutcomesPerFrame,
            self.registry_policy.max_outcomes_per_frame,
            next_event_count,
        )?;
        if let FrameMonitorEvent::Outcome(outcome) = &event {
            if let Some(measurement_index) = outcome.measurement_index {
                enforce_registry_max(
                    RegistryPolicyLimit::FrameInputs,
                    self.registry_policy.max_frame_inputs,
                    measurement_index.saturating_add(1),
                )?;
            }
            if outcome.outcome != ModalityOutcomeKind::TrackBirth {
                enforce_registry_max(
                    RegistryPolicyLimit::AttemptsPerTrackModality,
                    self.registry_policy.max_attempts_per_track_modality,
                    outcome.attempt_index.saturating_add(1),
                )?;
                enforce_registry_max(
                    RegistryPolicyLimit::AttemptsPerTrackModality,
                    self.registry_policy.max_attempts_per_track_modality,
                    outcome.candidate_count,
                )?;
            }
        }
        if frame.monitor_events.len() >= self.limits.max_events_per_frame {
            return Err(AssemblyFaultKind::CapacityExceeded {
                capacity: AssemblyCapacity::FrameEvents,
            });
        }
        let track_id = match &event {
            FrameMonitorEvent::Outcome(outcome) => outcome.track_id,
            FrameMonitorEvent::Miss(miss) => miss.track_id,
        };
        if !frame.track_ids.contains(&track_id)
            && frame.track_ids.len() >= self.limits.max_tracks_per_frame
        {
            return Err(AssemblyFaultKind::CapacityExceeded {
                capacity: AssemblyCapacity::FrameTracks,
            });
        }
        let frame = self
            .frames
            .get_mut(&identity.fusion_seq)
            .ok_or(AssemblyFaultKind::InternalState)?;
        frame.track_ids.insert(track_id);
        frame.monitor_events.push(event);
        frame.buffered_bytes = frame.buffered_bytes.saturating_add(encoded_bytes);
        self.buffered_bytes = self.buffered_bytes.saturating_add(encoded_bytes);
        Ok(())
    }

    fn process_summary(
        &mut self,
        summary: FrameSummary,
        encoded_bytes: usize,
        received_at: Instant,
    ) -> Result<(), AssemblyFaultKind> {
        let identity = FrameIdentity::from_summary(&summary);
        self.check_monitor_frame_order(identity.fusion_seq)?;
        self.ensure_frame(identity.fusion_seq, received_at)?;
        self.establish_identity(identity)?;
        if self
            .frames
            .get(&identity.fusion_seq)
            .is_some_and(|frame| frame.summary.is_some())
        {
            return Err(AssemblyFaultKind::EventAfterFrameSummary {
                fusion_seq: identity.fusion_seq,
            });
        }
        self.registry
            .verify_summary(
                identity,
                &summary.registry_digest,
                &summary.expected_modalities,
            )
            .map_err(AssemblyFaultKind::Registry)?;
        enforce_registry_max(
            RegistryPolicyLimit::ActiveTracks,
            self.registry_policy.max_active_tracks,
            summary.active_track_count,
        )?;
        enforce_registry_max(
            RegistryPolicyLimit::FrameInputs,
            self.registry_policy.max_frame_inputs,
            summary.input_count,
        )?;
        enforce_registry_max(
            RegistryPolicyLimit::OutcomesPerFrame,
            self.registry_policy.max_outcomes_per_frame,
            summary.outcome_count,
        )?;
        // FrameSummary::validate guarantees truncated => degraded, so one
        // validated flag is the complete downstream rejection predicate.
        if summary.degraded {
            return Err(AssemblyFaultKind::ProducerDegradedFrame {
                fusion_seq: summary.fusion_seq,
                truncated: summary.truncated,
            });
        }
        let expected_observations = {
            let frame = self
                .frames
                .get(&identity.fusion_seq)
                .ok_or(AssemblyFaultKind::InternalState)?;
            validate_frame_at_summary(frame, &summary, self.registry_policy)?
        };
        let frame = self
            .frames
            .get_mut(&identity.fusion_seq)
            .ok_or(AssemblyFaultKind::InternalState)?;
        frame.summary = Some(summary);
        frame.expected_observations = Some(expected_observations);
        frame.buffered_bytes = frame.buffered_bytes.saturating_add(encoded_bytes);
        self.buffered_bytes = self.buffered_bytes.saturating_add(encoded_bytes);
        self.last_summary_fusion_seq = Some(identity.fusion_seq);
        Ok(())
    }

    fn check_monitor_frame_order(&mut self, fusion_seq: u64) -> Result<(), AssemblyFaultKind> {
        match self.last_monitor_fusion_seq {
            None => self.last_monitor_fusion_seq = Some(fusion_seq),
            Some(previous) if fusion_seq < previous => {
                return Err(AssemblyFaultKind::FusionSequenceRegressed {
                    previous,
                    received: fusion_seq,
                });
            }
            Some(previous) if fusion_seq > previous => {
                if self.last_summary_fusion_seq != Some(previous) {
                    return Err(AssemblyFaultKind::MissingSummaryBeforeNextFrame {
                        previous,
                        received: fusion_seq,
                    });
                }
                self.last_monitor_fusion_seq = Some(fusion_seq);
            }
            Some(_) => {}
        }
        if self.last_summary_fusion_seq == Some(fusion_seq) {
            return Err(AssemblyFaultKind::EventAfterFrameSummary { fusion_seq });
        }
        Ok(())
    }

    fn establish_identity(&mut self, identity: FrameIdentity) -> Result<(), AssemblyFaultKind> {
        if let Some(previous) = self.prior_sequences.get(&identity.prior_id).copied() {
            if previous != identity.fusion_seq {
                return Err(AssemblyFaultKind::PriorReuse {
                    prior_id: identity.prior_id,
                    previous_fusion_seq: previous,
                    received_fusion_seq: identity.fusion_seq,
                });
            }
        } else {
            if self.prior_sequences.len() >= self.limits.max_prior_identities {
                return Err(AssemblyFaultKind::CapacityExceeded {
                    capacity: AssemblyCapacity::PriorIdentities,
                });
            }
            self.prior_sequences
                .insert(identity.prior_id, identity.fusion_seq);
        }
        let frame = self
            .frames
            .get_mut(&identity.fusion_seq)
            .ok_or(AssemblyFaultKind::InternalState)?;
        match frame.identity {
            Some(previous) if previous != identity => {
                Err(AssemblyFaultKind::FrameIdentityMismatch {
                    fusion_seq: identity.fusion_seq,
                })
            }
            Some(_) => Ok(()),
            None => {
                frame.identity = Some(identity);
                Ok(())
            }
        }
    }

    fn ensure_frame(
        &mut self,
        fusion_seq: u64,
        received_at: Instant,
    ) -> Result<(), AssemblyFaultKind> {
        if self.frames.contains_key(&fusion_seq) {
            return Ok(());
        }
        if self.frames.len() >= self.limits.max_open_frames {
            return Err(AssemblyFaultKind::CapacityExceeded {
                capacity: AssemblyCapacity::Frames,
            });
        }
        self.frames
            .insert(fusion_seq, PartialFrame::new(received_at));
        Ok(())
    }

    fn refresh_frame_readiness(&mut self, fusion_seq: u64) -> Result<(), AssemblyFaultKind> {
        let ready = {
            let frame = self
                .frames
                .get(&fusion_seq)
                .ok_or(AssemblyFaultKind::InternalState)?;
            match (&frame.summary, &frame.expected_observations) {
                (None, None) => false,
                (Some(_), Some(expected)) => frame.observations.len() == expected.len(),
                _ => return Err(AssemblyFaultKind::InternalState),
            }
        };
        self.frames
            .get_mut(&fusion_seq)
            .ok_or(AssemblyFaultKind::InternalState)?
            .ready = ready;
        Ok(())
    }

    fn drain_ready_frames(&mut self) -> Result<Vec<AssemblyEvent>, AssemblyFaultKind> {
        let mut events = Vec::new();
        while let Some((&fusion_seq, frame)) = self.frames.first_key_value() {
            if !frame.ready {
                break;
            }
            let frame = self
                .frames
                .remove(&fusion_seq)
                .ok_or(AssemblyFaultKind::InternalState)?;
            self.buffered_bytes = self.buffered_bytes.saturating_sub(frame.buffered_bytes);
            let identity = frame.identity.ok_or(AssemblyFaultKind::InternalState)?;
            let summary = frame.summary.ok_or(AssemblyFaultKind::InternalState)?;
            let mut observations = frame
                .observations
                .into_values()
                .map(|stored| stored.observation)
                .collect::<Vec<_>>();
            observations.sort_by_key(|observation| {
                (
                    observation.track_id().get(),
                    modality_rank(observation.modality()),
                )
            });
            self.last_finalized_fusion_seq = Some(fusion_seq);
            events.push(AssemblyEvent::FrameReady(AssembledFrame {
                session_id: self.session_id.clone(),
                producer_id: self.producer_id.clone(),
                identity,
                monitor_events: frame.monitor_events,
                observations,
                summary,
            }));
        }
        Ok(events)
    }

    fn process_heartbeat(&mut self, heartbeat: &Heartbeat) -> Result<(), AssemblyFaultKind> {
        let interval_ms = duration_ms(self.limits.heartbeat_interval)
            .ok_or(AssemblyFaultKind::HeartbeatProfileMismatch)?;
        let deadline_ms = duration_ms(self.limits.heartbeat_deadline)
            .ok_or(AssemblyFaultKind::HeartbeatProfileMismatch)?;
        if heartbeat.declared_interval_ms != interval_ms
            || heartbeat.declared_deadline_ms != deadline_ms
        {
            return Err(AssemblyFaultKind::HeartbeatProfileMismatch);
        }
        enforce_registry_max(
            RegistryPolicyLimit::MonitorQueueEvents,
            self.registry_policy.max_monitor_queue_events,
            heartbeat.queue_health.capacity,
        )?;
        enforce_registry_max(
            RegistryPolicyLimit::ActiveTracks,
            self.registry_policy.max_active_tracks,
            heartbeat.active_track_count,
        )?;
        // Heartbeat::validate guarantees dropped_event_count > 0 => degraded.
        if heartbeat.degraded {
            return Err(AssemblyFaultKind::ProducerDeclaredLoss);
        }
        if heartbeat.last_fusion_seq != self.last_summary_fusion_seq {
            return Err(AssemblyFaultKind::HeartbeatLastFusionMismatch {
                expected: self.last_summary_fusion_seq,
                received: heartbeat.last_fusion_seq,
            });
        }
        if let Some(previous) = self.heartbeat {
            if heartbeat.uptime_ms <= previous.uptime_ms
                || heartbeat.queue_health.published_event_count < previous.published_event_count
            {
                return Err(AssemblyFaultKind::HeartbeatStateRegressed);
            }
        }
        self.heartbeat = Some(HeartbeatSnapshot {
            uptime_ms: heartbeat.uptime_ms,
            published_event_count: heartbeat.queue_health.published_event_count,
        });
        Ok(())
    }

    fn reserve_bytes(&mut self, amount: usize) -> bool {
        self.buffered_bytes
            .checked_add(amount)
            .filter(|total| *total <= self.limits.max_buffered_bytes)
            .is_some_and(|total| {
                self.buffered_bytes = total;
                true
            })
    }

    fn oldest_open_frame(&self) -> Option<u64> {
        self.frames.keys().next().copied()
    }

    fn fail(
        &mut self,
        kind: AssemblyFaultKind,
        mut invalidate_from_fusion_seq: Option<u64>,
        detected_at: Instant,
    ) -> AssemblyEvent {
        match &kind {
            AssemblyFaultKind::PriorReuse {
                previous_fusion_seq,
                received_fusion_seq,
                ..
            }
            | AssemblyFaultKind::MissingSummaryBeforeNextFrame {
                previous: previous_fusion_seq,
                received: received_fusion_seq,
            } => {
                invalidate_from_fusion_seq = Some((*previous_fusion_seq).min(*received_fusion_seq));
            }
            _ => {}
        }
        let fault = AssemblyFault {
            kind,
            invalidate_from_fusion_seq,
            detected_at,
        };
        self.pending_monitor.clear();
        self.frames.clear();
        self.prior_sequences.clear();
        self.observation_high_water.clear();
        self.buffered_bytes = 0;
        self.fault = Some(fault.clone());
        AssemblyEvent::Fault(fault)
    }
}

fn enforce_registry_max(
    limit: RegistryPolicyLimit,
    maximum: u32,
    received: u32,
) -> Result<(), AssemblyFaultKind> {
    if received > maximum {
        return Err(AssemblyFaultKind::Registry(
            RegistryViolation::OpportunityLimitExceeded {
                limit,
                maximum,
                received,
            },
        ));
    }
    Ok(())
}

fn validate_frame_at_summary(
    frame: &PartialFrame,
    summary: &FrameSummary,
    registry_policy: RegistryOpportunityPolicy,
) -> Result<HashMap<(u64, Modality), Option<ConsistencyProjection>>, AssemblyFaultKind> {
    let identity = frame
        .identity
        .ok_or(AssemblyFaultKind::InvalidFrameLedger {
            fusion_seq: summary.fusion_seq,
        })?;
    let received = u32::try_from(frame.monitor_events.len()).unwrap_or(u32::MAX);
    if received != summary.outcome_count {
        return Err(AssemblyFaultKind::OutcomeCountMismatch {
            declared: summary.outcome_count,
            received,
        });
    }
    let expected = validate_frame_ledger(frame, summary, registry_policy)?;
    let declared_v1 = u32::try_from(expected.len()).unwrap_or(u32::MAX);
    if declared_v1 != summary.v1_expected_count {
        return Err(AssemblyFaultKind::V1ExpectedCountMismatch {
            declared: summary.v1_expected_count,
            received: declared_v1,
        });
    }
    for stored in frame.observations.values() {
        validate_observation_join(identity, &expected, &stored.observation)?;
    }
    Ok(expected)
}

fn validate_observation_join(
    identity: FrameIdentity,
    expected: &HashMap<(u64, Modality), Option<ConsistencyProjection>>,
    observation: &PidObservation,
) -> Result<(), AssemblyFaultKind> {
    let track_id = observation.track_id().get();
    let modality = observation.modality();
    let Some(expected_projection) = expected.get(&(track_id, modality)) else {
        return Err(AssemblyFaultKind::UnexpectedObservation {
            fusion_seq: identity.fusion_seq,
            track_id,
            modality,
        });
    };
    if observation.timestamp_ms().get() != identity.fusion_timestamp_ms {
        return Err(AssemblyFaultKind::ObservationTimestampMismatch {
            fusion_seq: identity.fusion_seq,
            track_id,
            modality,
        });
    }
    if observation.consistency_projection() != expected_projection.as_ref() {
        return Err(AssemblyFaultKind::ObservationProjectionMismatch {
            fusion_seq: identity.fusion_seq,
            track_id,
            modality,
        });
    }
    Ok(())
}

#[derive(Default)]
struct PairLedger {
    next_attempt: u32,
    last_measurement_index: Option<u32>,
    candidate_count: Option<u32>,
    in_gate_count: Option<u32>,
    observed_in_gate_count: u32,
    in_gate_count_unverifiable: bool,
    terminal_count: u32,
    miss: Option<ModalityMissReason>,
}

fn validate_frame_ledger(
    frame: &PartialFrame,
    summary: &FrameSummary,
    registry_policy: RegistryOpportunityPolicy,
) -> Result<HashMap<(u64, Modality), Option<ConsistencyProjection>>, AssemblyFaultKind> {
    let invalid = || AssemblyFaultKind::InvalidFrameLedger {
        fusion_seq: summary.fusion_seq,
    };
    let modality_positions = summary
        .expected_modalities
        .iter()
        .copied()
        .enumerate()
        .map(|(index, modality)| (modality, index))
        .collect::<HashMap<_, _>>();
    let mut pairs: HashMap<(u64, Modality), PairLedger> = HashMap::new();
    let mut frozen_tracks = HashSet::new();
    let mut expected_observations = HashMap::new();
    let mut last_pair_rank: Option<(u64, usize)> = None;
    let mut birth_phase = false;
    let mut birth_tracks = HashSet::new();
    let mut birth_measurements = HashSet::new();
    let mut last_birth_rank: Option<(u32, u64, usize)> = None;

    for event in &frame.monitor_events {
        match event {
            FrameMonitorEvent::Outcome(outcome) => {
                let modality_rank = *modality_positions
                    .get(&outcome.modality)
                    .ok_or_else(invalid)?;
                if outcome.outcome == ModalityOutcomeKind::TrackBirth {
                    birth_phase = true;
                    let measurement_index = outcome.measurement_index.ok_or_else(invalid)?;
                    let rank = (measurement_index, outcome.track_id, modality_rank);
                    if outcome.attempt_index != 0
                        || !birth_tracks.insert(outcome.track_id)
                        || !birth_measurements.insert(measurement_index)
                        || last_birth_rank.is_some_and(|previous| rank <= previous)
                        || measurement_index >= summary.input_count
                    {
                        return Err(invalid());
                    }
                    last_birth_rank = Some(rank);
                    continue;
                }
                if birth_phase {
                    return Err(invalid());
                }
                let rank = (outcome.track_id, modality_rank);
                if last_pair_rank.is_some_and(|previous| rank < previous) {
                    return Err(invalid());
                }
                last_pair_rank = Some(rank);
                frozen_tracks.insert(outcome.track_id);
                let ledger = pairs
                    .entry((outcome.track_id, outcome.modality))
                    .or_default();
                if ledger.miss.is_some() || outcome.attempt_index != ledger.next_attempt {
                    return Err(invalid());
                }
                let measurement_index = outcome.measurement_index.ok_or_else(invalid)?;
                if measurement_index >= summary.input_count
                    || ledger
                        .last_measurement_index
                        .is_some_and(|previous| measurement_index <= previous)
                {
                    return Err(invalid());
                }
                ledger.last_measurement_index = Some(measurement_index);
                ledger.next_attempt = ledger.next_attempt.checked_add(1).ok_or_else(invalid)?;
                enforce_registry_max(
                    RegistryPolicyLimit::AttemptsPerTrackModality,
                    registry_policy.max_attempts_per_track_modality,
                    ledger.next_attempt,
                )?;
                match (ledger.candidate_count, ledger.in_gate_count) {
                    (None, None) => {
                        ledger.candidate_count = Some(outcome.candidate_count);
                        ledger.in_gate_count = Some(outcome.in_gate_count);
                    }
                    (Some(candidates), Some(in_gate))
                        if candidates == outcome.candidate_count
                            && in_gate == outcome.in_gate_count => {}
                    _ => return Err(invalid()),
                }
                if let Some(evidence) = outcome.gate_evidence {
                    if evidence.d2 < evidence.threshold {
                        ledger.observed_in_gate_count = ledger
                            .observed_in_gate_count
                            .checked_add(1)
                            .ok_or_else(invalid)?;
                    }
                } else {
                    ledger.in_gate_count_unverifiable = true;
                }
                if matches!(
                    outcome.outcome,
                    ModalityOutcomeKind::Updated
                        | ModalityOutcomeKind::UpdateRejected
                        | ModalityOutcomeKind::UnsupportedFilter
                        | ModalityOutcomeKind::IncomparableProjection
                ) {
                    ledger.terminal_count =
                        ledger.terminal_count.checked_add(1).ok_or_else(invalid)?;
                }
                if outcome.v1_expected
                    && expected_observations
                        .insert(
                            (outcome.track_id, outcome.modality),
                            outcome.consistency_projection.clone(),
                        )
                        .is_some()
                {
                    return Err(invalid());
                }
            }
            FrameMonitorEvent::Miss(miss) => {
                if birth_phase {
                    return Err(invalid());
                }
                let modality_rank = *modality_positions.get(&miss.modality).ok_or_else(invalid)?;
                let rank = (miss.track_id, modality_rank);
                if last_pair_rank.is_some_and(|previous| rank < previous) {
                    return Err(invalid());
                }
                last_pair_rank = Some(rank);
                frozen_tracks.insert(miss.track_id);
                let ledger = pairs.entry((miss.track_id, miss.modality)).or_default();
                if ledger.miss.replace(miss.reason).is_some() {
                    return Err(invalid());
                }
            }
        }
    }

    if birth_tracks
        .iter()
        .any(|track_id| frozen_tracks.contains(track_id))
    {
        return Err(invalid());
    }
    enforce_registry_max(
        RegistryPolicyLimit::ActiveTracks,
        registry_policy.max_active_tracks,
        u32::try_from(birth_tracks.len()).unwrap_or(u32::MAX),
    )?;
    enforce_registry_max(
        RegistryPolicyLimit::ActiveTracks,
        registry_policy.max_active_tracks,
        u32::try_from(frozen_tracks.len()).unwrap_or(u32::MAX),
    )?;
    let represented_tracks = frozen_tracks
        .len()
        .checked_add(birth_tracks.len())
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(invalid)?;
    if summary.active_track_count > represented_tracks {
        return Err(invalid());
    }
    for track_id in frozen_tracks {
        for modality in &summary.expected_modalities {
            if !pairs.contains_key(&(track_id, *modality)) {
                return Err(invalid());
            }
        }
    }
    for ledger in pairs.values() {
        let candidates = ledger.candidate_count.unwrap_or(0);
        let in_gate = ledger.in_gate_count.unwrap_or(0);
        if candidates != ledger.next_attempt
            || (!ledger.in_gate_count_unverifiable && in_gate != ledger.observed_in_gate_count)
        {
            return Err(invalid());
        }
        match (ledger.terminal_count, ledger.miss) {
            (1, None) => {}
            (0, Some(ModalityMissReason::NoMeasurement | ModalityMissReason::TrackNotEligible))
                if candidates == 0 => {}
            (0, Some(ModalityMissReason::NoCandidate))
                if candidates == 0 && summary.input_count > 0 => {}
            (0, Some(ModalityMissReason::NoInGateCandidate)) if candidates > 0 && in_gate == 0 => {}
            (0, Some(ModalityMissReason::NotAssigned)) if in_gate > 0 => {}
            _ => return Err(invalid()),
        }
    }
    Ok(expected_observations)
}

fn validate_limits(
    limits: AssemblerLimits,
    started_at: Instant,
) -> Result<(), AssemblerConfigError> {
    validate_assembler_params(limits.as_params(), Some(started_at))
}

fn validate_assembler_params(
    limits: AssemblerParams,
    anchor: Option<Instant>,
) -> Result<(), AssemblerConfigError> {
    for (field, value, maximum) in [
        (
            "max_open_frames",
            limits.max_open_frames,
            MAX_ASSEMBLER_OPEN_FRAMES,
        ),
        (
            "max_events_per_frame",
            limits.max_events_per_frame,
            MAX_FRAME_ITEMS as usize,
        ),
        (
            "max_observations_per_frame",
            limits.max_observations_per_frame,
            MAX_FRAME_ITEMS as usize,
        ),
        (
            "max_tracks_per_frame",
            limits.max_tracks_per_frame,
            MAX_FRAME_ITEMS as usize,
        ),
        (
            "max_reorder_events",
            limits.max_reorder_events,
            MAX_ASSEMBLER_REORDER_EVENTS,
        ),
        (
            "max_buffered_bytes",
            limits.max_buffered_bytes,
            MAX_ASSEMBLER_BUFFERED_BYTES,
        ),
        (
            "max_prior_identities",
            limits.max_prior_identities,
            MAX_ASSEMBLER_PRIOR_IDENTITIES,
        ),
        (
            "max_observation_streams",
            limits.max_observation_streams,
            MAX_ASSEMBLER_OBSERVATION_STREAMS,
        ),
    ] {
        if value == 0 || value > maximum {
            return Err(AssemblerConfigError::InvalidLimit {
                field,
                value,
                maximum,
            });
        }
    }
    for (field, value) in [
        ("max_reorder_distance", limits.max_reorder_distance),
        ("max_observation_advance", limits.max_observation_advance),
    ] {
        if value == 0 || value > MAX_ASSEMBLER_SEQUENCE_DISTANCE {
            return Err(AssemblerConfigError::InvalidSequenceLimit {
                field,
                value,
                maximum: MAX_ASSEMBLER_SEQUENCE_DISTANCE,
            });
        }
    }
    let minimum_buffer = MAX_ASSEMBLER_SIDECAR_BYTES.max(MAX_MONITOR_EVENT_BYTES);
    if limits.max_buffered_bytes < minimum_buffer {
        return Err(AssemblerConfigError::BufferBudgetTooSmall {
            value: limits.max_buffered_bytes,
            minimum: minimum_buffer,
        });
    }
    let per_frame_slots = limits
        .max_events_per_frame
        .checked_add(limits.max_observations_per_frame)
        .and_then(|value| value.checked_add(limits.max_tracks_per_frame));
    let frame_slots = per_frame_slots.and_then(|value| value.checked_mul(limits.max_open_frames));
    let total_slots = frame_slots
        .and_then(|value| value.checked_add(limits.max_reorder_events))
        .and_then(|value| value.checked_add(limits.max_prior_identities))
        .and_then(|value| value.checked_add(limits.max_observation_streams));
    let Some((frame_slots, _)) = frame_slots.zip(total_slots) else {
        return Err(AssemblerConfigError::AggregateStateTooLarge {
            value: usize::MAX,
            maximum: MAX_ASSEMBLER_TOTAL_STATE_SLOTS,
        });
    };
    // The non-frame terms were independently capped above, and the total ceiling
    // is exactly the frame ceiling plus those component caps.
    if frame_slots > MAX_ASSEMBLER_FRAME_STATE_SLOTS {
        return Err(AssemblerConfigError::AggregateStateTooLarge {
            value: frame_slots,
            maximum: MAX_ASSEMBLER_FRAME_STATE_SLOTS,
        });
    }

    for (field, duration) in [
        ("frame_deadline", limits.frame_deadline),
        ("reorder_deadline", limits.reorder_deadline),
        ("heartbeat_interval", limits.heartbeat_interval),
        ("heartbeat_deadline", limits.heartbeat_deadline),
        (
            "initial_heartbeat_deadline",
            limits.initial_heartbeat_deadline,
        ),
    ] {
        if duration.is_zero() {
            return Err(AssemblerConfigError::InvalidDuration {
                field,
                violation: AssemblerDurationViolation::Zero,
            });
        }
        let Some(millis) = duration_ms(duration) else {
            return Err(AssemblerConfigError::InvalidDuration {
                field,
                violation: AssemblerDurationViolation::NotExactMilliseconds,
            });
        };
        if duration.subsec_nanos() % 1_000_000 != 0 {
            return Err(AssemblerConfigError::InvalidDuration {
                field,
                violation: AssemblerDurationViolation::NotExactMilliseconds,
            });
        }
        if millis > MAX_HEARTBEAT_DURATION_MS {
            return Err(AssemblerConfigError::InvalidDuration {
                field,
                violation: AssemblerDurationViolation::ExceedsHardMaximum,
            });
        }
    }
    if limits.heartbeat_deadline < limits.heartbeat_interval {
        return Err(AssemblerConfigError::InvalidDuration {
            field: "heartbeat_deadline",
            violation: AssemblerDurationViolation::DeadlineShorterThanInterval,
        });
    }
    if limits.initial_heartbeat_deadline < limits.heartbeat_deadline {
        return Err(AssemblerConfigError::InvalidDuration {
            field: "initial_heartbeat_deadline",
            violation: AssemblerDurationViolation::InitialShorterThanSteady,
        });
    }
    if let Some(anchor) = anchor {
        validate_deadline_anchor_params(limits, anchor)?;
    }
    Ok(())
}

#[cfg(any(feature = "zenoh", test))]
fn validate_deadline_anchor(
    limits: AssemblerLimits,
    anchor: Instant,
) -> Result<(), AssemblerConfigError> {
    validate_deadline_anchor_params(limits.as_params(), anchor)
}

fn validate_deadline_anchor_params(
    limits: AssemblerParams,
    anchor: Instant,
) -> Result<(), AssemblerConfigError> {
    for (field, duration) in [
        ("frame_deadline", limits.frame_deadline),
        ("reorder_deadline", limits.reorder_deadline),
        ("heartbeat_deadline", limits.heartbeat_deadline),
        (
            "initial_heartbeat_deadline",
            limits.initial_heartbeat_deadline,
        ),
    ] {
        if anchor.checked_add(duration).is_none() {
            return Err(AssemblerConfigError::InvalidDuration {
                field,
                violation: AssemblerDurationViolation::AnchorOverflow,
            });
        }
    }
    Ok(())
}

fn monitor_decode_fault(error: &MonitorError) -> AssemblyFaultKind {
    match error {
        MonitorError::EncodedEventTooLarge { .. } => AssemblyFaultKind::PayloadTooLarge {
            route: EvidenceRoute::Monitor,
        },
        MonitorError::Json(_) => AssemblyFaultKind::MalformedPayload {
            route: EvidenceRoute::Monitor,
        },
        _ => AssemblyFaultKind::InvalidEnvelope {
            route: EvidenceRoute::Monitor,
        },
    }
}

fn monitor_validation_fault(error: &MonitorError) -> AssemblyFaultKind {
    if matches!(error, MonitorError::ProvenanceMismatch { .. }) {
        AssemblyFaultKind::ProvenanceMismatch {
            route: EvidenceRoute::Monitor,
        }
    } else {
        AssemblyFaultKind::InvalidEnvelope {
            route: EvidenceRoute::Monitor,
        }
    }
}

fn sidecar_validation_fault(error: &SidecarEnvelopeError) -> AssemblyFaultKind {
    if matches!(error, SidecarEnvelopeError::ProvenanceMismatch { .. }) {
        AssemblyFaultKind::ProvenanceMismatch {
            route: EvidenceRoute::Observation,
        }
    } else {
        AssemblyFaultKind::InvalidEnvelope {
            route: EvidenceRoute::Observation,
        }
    }
}

fn event_fusion_seq(event: &ProducerEvent) -> Option<u64> {
    match event {
        ProducerEvent::Heartbeat(_) => None,
        ProducerEvent::ModalityOutcome(outcome) => Some(outcome.fusion_seq),
        ProducerEvent::ModalityMiss(miss) => Some(miss.fusion_seq),
        ProducerEvent::FrameSummary(summary) => Some(summary.fusion_seq),
    }
}

fn elapsed_at_least(start: Instant, now: Instant, duration: Duration) -> bool {
    now.checked_duration_since(start)
        .is_some_and(|elapsed| elapsed >= duration)
}

fn conservative_deadline_at(start: Instant, duration: Duration) -> Instant {
    start.checked_add(duration).unwrap_or(start)
}

fn duration_ms(duration: Duration) -> Option<u64> {
    u64::try_from(duration.as_millis()).ok()
}

fn modality_rank(modality: Modality) -> u8 {
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
    use crate::monitor::{GateEvidence, GateMethod, QueueHealth};
    use crate::registry::{DeploymentRegistry, PinnedDeploymentRegistry};

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FIXTURE_REGISTRY_DIGEST: &str =
        "7644ec2bbf0e400303aaad62c647eea36bd919913f1a28a81c52c13e00dd45ba";

    #[derive(Clone, Copy)]
    struct TestRegistry;

    fn wire_policy() -> RegistryOpportunityPolicy {
        RegistryOpportunityPolicy::try_new(RegistryOpportunityParams {
            max_active_tracks: MAX_ACTIVE_TRACKS,
            max_frame_inputs: MAX_FRAME_ITEMS,
            max_attempts_per_track_modality: MAX_FRAME_ITEMS,
            max_outcomes_per_frame: MAX_FRAME_ITEMS,
            max_monitor_queue_events: crate::monitor::MAX_MONITOR_QUEUE_EVENTS,
        })
        .expect("wire policy is bounded")
    }

    fn verify_test_projection(
        identity: FrameIdentity,
        modality: Modality,
        projection: &ConsistencyProjection,
        expected_modalities: &[Modality],
    ) -> Result<(), RegistryViolation> {
        let projection_identity = projection.identity();
        let frame_id = projection_identity.frame_id().get();
        let context_id = projection_identity.context_id().get();
        let prior_id = projection_identity.frozen_prior_id().get();
        if (frame_id, context_id, prior_id)
            != (identity.frame_id, identity.context_id, identity.prior_id)
        {
            return Err(RegistryViolation::ProjectionIdentityMismatch {
                expected_frame_id: identity.frame_id,
                received_frame_id: frame_id,
                expected_context_id: identity.context_id,
                received_context_id: context_id,
                expected_prior_id: identity.prior_id,
                received_prior_id: prior_id,
            });
        }
        if !expected_modalities.contains(&modality) {
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

    impl RegistryVerifier for TestRegistry {
        fn opportunity_policy(&self) -> Result<RegistryOpportunityPolicy, RegistryViolation> {
            Ok(wire_policy())
        }

        fn verify_summary(
            &self,
            identity: FrameIdentity,
            registry_digest: &str,
            expected_modalities: &[Modality],
        ) -> Result<(), RegistryViolation> {
            if registry_digest != DIGEST {
                return Err(RegistryViolation::DigestMismatch);
            }
            if identity.frame_id != 10 {
                return Err(RegistryViolation::UnknownFrame {
                    frame_id: identity.frame_id,
                });
            }
            if identity.context_id != 20 {
                return Err(RegistryViolation::UnknownContext {
                    context_id: identity.context_id,
                });
            }
            if expected_modalities != [Modality::Visual] {
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
            verify_test_projection(identity, modality, projection, &[Modality::Visual])
        }
    }

    #[derive(Clone, Copy)]
    struct PolicyRegistry {
        policy: RegistryOpportunityPolicy,
        expected_modalities: &'static [Modality],
    }

    impl RegistryVerifier for PolicyRegistry {
        fn opportunity_policy(&self) -> Result<RegistryOpportunityPolicy, RegistryViolation> {
            Ok(self.policy)
        }

        fn verify_summary(
            &self,
            identity: FrameIdentity,
            registry_digest: &str,
            expected_modalities: &[Modality],
        ) -> Result<(), RegistryViolation> {
            if registry_digest != DIGEST {
                return Err(RegistryViolation::DigestMismatch);
            }
            if identity.frame_id != 10 || identity.context_id != 20 {
                return Err(RegistryViolation::FrameContextMismatch {
                    frame_id: identity.frame_id,
                    context_id: identity.context_id,
                });
            }
            if expected_modalities != self.expected_modalities {
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
            verify_test_projection(identity, modality, projection, self.expected_modalities)
        }
    }

    #[derive(Clone, Copy)]
    struct UnpinnedRegistry;

    impl RegistryVerifier for UnpinnedRegistry {
        fn opportunity_policy(&self) -> Result<RegistryOpportunityPolicy, RegistryViolation> {
            Err(RegistryViolation::RegistryNotPinned)
        }

        fn verify_summary(
            &self,
            _identity: FrameIdentity,
            _registry_digest: &str,
            _expected_modalities: &[Modality],
        ) -> Result<(), RegistryViolation> {
            Err(RegistryViolation::RegistryNotPinned)
        }

        fn verify_projection(
            &self,
            _identity: FrameIdentity,
            _modality: Modality,
            _projection: &ConsistencyProjection,
        ) -> Result<(), RegistryViolation> {
            Err(RegistryViolation::RegistryNotPinned)
        }
    }

    fn projection(prior_id: u64) -> ConsistencyProjection {
        ConsistencyProjection::try_new_raw([1.0, 2.0, 3.0], 3, 10, 20, prior_id)
            .expect("test projection is valid")
    }

    fn outcome(seq: u64, prior_id: u64) -> ModalityOutcome {
        ModalityOutcome {
            fusion_seq: seq,
            fusion_timestamp_ms: 1_000 + seq,
            frame_id: 10,
            context_id: 20,
            prior_id,
            track_id: 7,
            modality: Modality::Visual,
            attempt_index: 0,
            measurement_index: Some(0),
            outcome: ModalityOutcomeKind::Updated,
            v1_expected: true,
            candidate_count: 1,
            in_gate_count: 1,
            gate_evidence: Some(GateEvidence {
                method: GateMethod::Mahalanobis,
                d2: 1.0,
                threshold: 7.815,
            }),
            consistency_projection: Some(projection(prior_id)),
        }
    }

    fn summary(seq: u64, prior_id: u64) -> FrameSummary {
        FrameSummary {
            fusion_seq: seq,
            fusion_timestamp_ms: 1_000 + seq,
            frame_id: 10,
            context_id: 20,
            prior_id,
            registry_digest: DIGEST.to_owned(),
            expected_modalities: vec![Modality::Visual],
            active_track_count: 1,
            input_count: 1,
            outcome_count: 1,
            v1_expected_count: 1,
            degraded: false,
            truncated: false,
        }
    }

    fn empty_summary(seq: u64, prior_id: u64) -> FrameSummary {
        let mut value = summary(seq, prior_id);
        value.active_track_count = 0;
        value.input_count = 0;
        value.outcome_count = 0;
        value.v1_expected_count = 0;
        value
    }

    fn ledger_summary(active_track_count: u32, input_count: u32) -> FrameSummary {
        let mut value = summary(1, 101);
        value.active_track_count = active_track_count;
        value.input_count = input_count;
        value.outcome_count = 0;
        value.v1_expected_count = 0;
        value
    }

    fn ledger_outcome(
        track_id: u64,
        attempt_index: u32,
        measurement_index: u32,
        outcome_kind: ModalityOutcomeKind,
        candidate_count: u32,
        in_gate_count: u32,
        gate_score: Option<(f64, f64)>,
    ) -> FrameMonitorEvent {
        let mut value = outcome(1, 101);
        value.track_id = track_id;
        value.attempt_index = attempt_index;
        value.measurement_index = Some(measurement_index);
        value.outcome = outcome_kind;
        value.v1_expected = false;
        value.candidate_count = candidate_count;
        value.in_gate_count = in_gate_count;
        value.gate_evidence = gate_score.map(|(d2, threshold)| GateEvidence {
            method: GateMethod::Mahalanobis,
            d2,
            threshold,
        });
        value.consistency_projection = None;
        FrameMonitorEvent::Outcome(value)
    }

    fn ledger_miss(track_id: u64, reason: ModalityMissReason) -> FrameMonitorEvent {
        FrameMonitorEvent::Miss(ModalityMiss {
            fusion_seq: 1,
            fusion_timestamp_ms: 1_001,
            frame_id: 10,
            context_id: 20,
            prior_id: 101,
            track_id,
            modality: Modality::Visual,
            reason,
        })
    }

    fn validate_test_ledger(
        monitor_events: Vec<FrameMonitorEvent>,
        summary: &FrameSummary,
    ) -> Result<HashMap<(u64, Modality), Option<ConsistencyProjection>>, AssemblyFaultKind> {
        for event in &monitor_events {
            let result = match event {
                FrameMonitorEvent::Outcome(outcome) => outcome.validate(),
                FrameMonitorEvent::Miss(miss) => miss.validate(),
            };
            result.expect("ledger fixture must satisfy the public monitor wire invariants");
        }
        let mut summary = summary.clone();
        summary.outcome_count = u32::try_from(monitor_events.len()).expect("small ledger fixture");
        summary.v1_expected_count = monitor_events
            .iter()
            .filter(
                |event| matches!(event, FrameMonitorEvent::Outcome(outcome) if outcome.v1_expected),
            )
            .count()
            .try_into()
            .expect("small ledger fixture");
        summary
            .validate()
            .expect("ledger closure fixture must satisfy the public monitor wire invariants");
        let mut frame = PartialFrame::new(Instant::now());
        frame.monitor_events = monitor_events;
        validate_frame_ledger(&frame, &summary, wire_policy())
    }

    fn valid_two_attempt_ledger() -> Vec<FrameMonitorEvent> {
        vec![
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::GateRejected,
                2,
                1,
                Some((9.0, 7.815)),
            ),
            ledger_outcome(
                7,
                1,
                1,
                ModalityOutcomeKind::UpdateRejected,
                2,
                1,
                Some((1.0, 7.815)),
            ),
        ]
    }

    fn heartbeat(last_fusion_seq: Option<u64>, uptime_ms: u64, capacity: u32) -> Heartbeat {
        Heartbeat {
            producer_timestamp_ms: 1,
            uptime_ms,
            declared_interval_ms: 1_000,
            declared_deadline_ms: 30_000,
            last_fusion_seq,
            active_track_count: 0,
            degraded: false,
            queue_health: QueueHealth {
                capacity,
                depth: 0,
                dropped_event_count: 0,
                published_event_count: 0,
            },
        }
    }

    fn observation(seq: u64, prior_id: u64) -> PidObservation {
        test_observation(
            7,
            1_000 + seq,
            seq,
            Modality::Visual,
            1.0,
            Some(projection(prior_id)),
        )
    }

    fn test_observation(
        track_id: u64,
        timestamp_ms: u64,
        sequence: u64,
        modality: Modality,
        nis: f64,
        projection: Option<ConsistencyProjection>,
    ) -> PidObservation {
        let observation =
            PidObservation::try_scalar_raw(track_id, timestamp_ms, sequence, modality, nis, 3)
                .expect("test observation is valid");
        match projection {
            Some(projection) => observation.with_consistency_projection(projection),
            None => observation,
        }
    }

    fn one_dimensional_registry_observation() -> PidObservation {
        let projection = ConsistencyProjection::try_new_raw([1.0, 0.0, 0.0], 1, 17, 23, 101)
            .expect("one-dimensional test projection is valid");
        test_observation(7, 1_100, 1, Modality::Visual, 1.0, Some(projection))
    }

    fn one_dimensional_registry_outcome() -> ModalityOutcome {
        ModalityOutcome {
            fusion_seq: 1,
            fusion_timestamp_ms: 1_100,
            frame_id: 17,
            context_id: 23,
            prior_id: 101,
            track_id: 7,
            modality: Modality::Visual,
            attempt_index: 0,
            measurement_index: Some(0),
            outcome: ModalityOutcomeKind::Updated,
            v1_expected: true,
            candidate_count: 1,
            in_gate_count: 1,
            gate_evidence: Some(GateEvidence {
                method: GateMethod::Mahalanobis,
                d2: 1.0,
                threshold: 7.815,
            }),
            consistency_projection: one_dimensional_registry_observation()
                .consistency_projection()
                .cloned(),
        }
    }

    fn pinned_fixture_registry() -> PinnedDeploymentRegistry {
        DeploymentRegistry::from_json_pinned(
            include_bytes!("../tests/fixtures/crebain_registry_v1.json"),
            FIXTURE_REGISTRY_DIGEST,
        )
        .expect("shared registry fixture and deployment pin are valid")
    }

    fn monitor_bytes(event_seq: u64, event: ProducerEvent) -> Vec<u8> {
        MonitorEnvelope::try_new("epoch-1", "crebain", event_seq, event)
            .and_then(|envelope| envelope.encode())
            .expect("test monitor envelope is valid")
    }

    fn observation_bytes(observation: PidObservation) -> Vec<u8> {
        serde_json::to_vec(
            &SidecarEnvelope::try_new("epoch-1", "crebain", observation)
                .expect("test sidecar is valid"),
        )
        .expect("test sidecar encodes")
    }

    fn assembler(start: Instant) -> CrossRouteAssembler<TestRegistry> {
        let limits = AssemblerLimits {
            heartbeat_deadline: Duration::from_secs(30),
            ..AssemblerLimits::default()
        };
        CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
            .expect("test assembler config is valid")
    }

    fn assembler_with_registry<R: RegistryVerifier>(
        start: Instant,
        registry: R,
    ) -> CrossRouteAssembler<R> {
        let limits = AssemblerLimits {
            heartbeat_deadline: Duration::from_secs(30),
            ..AssemblerLimits::default()
        };
        CrossRouteAssembler::new("epoch-1", "crebain", registry, limits, start)
            .expect("test assembler config is valid")
    }

    fn ready(events: &[AssemblyEvent]) -> Option<&AssembledFrame> {
        events.iter().find_map(|event| match event {
            AssemblyEvent::FrameReady(frame) => Some(frame),
            _ => None,
        })
    }

    fn fault_kind(events: &[AssemblyEvent]) -> Option<&AssemblyFaultKind> {
        events.iter().find_map(|event| match event {
            AssemblyEvent::Fault(fault) => Some(&fault.kind),
            _ => None,
        })
    }

    fn fault(events: &[AssemblyEvent]) -> Option<&AssemblyFault> {
        events.iter().find_map(|event| match event {
            AssemblyEvent::Fault(fault) => Some(fault),
            _ => None,
        })
    }

    #[test]
    fn pristine_reanchor_starts_heartbeat_deadline_at_transport_activation() {
        let construction = Instant::now();
        let activation = construction + Duration::from_secs(45);
        let mut assembler = assembler(construction);

        assembler
            .reanchor_initial_clock(activation)
            .expect("activation anchor remains representable");

        assert_eq!(
            assembler.next_deadline_at(),
            Some(activation + Duration::from_secs(30))
        );
    }

    #[test]
    fn deadline_anchor_validation_rejects_the_platform_boundary() {
        let start = Instant::now();
        let mut accepted_seconds = 0_u64;
        let mut rejected_seconds = u64::MAX;
        while accepted_seconds < rejected_seconds {
            let midpoint = accepted_seconds
                + (rejected_seconds - accepted_seconds) / 2
                + (rejected_seconds - accepted_seconds) % 2;
            if start.checked_add(Duration::from_secs(midpoint)).is_some() {
                accepted_seconds = midpoint;
            } else {
                rejected_seconds = midpoint - 1;
            }
        }
        let terminal_anchor = start
            .checked_add(Duration::from_secs(accepted_seconds))
            .expect("binary search retains the largest whole-second anchor");

        assert!(matches!(
            validate_deadline_anchor(AssemblerLimits::default(), terminal_anchor),
            Err(AssemblerConfigError::InvalidDuration {
                field: "frame_deadline",
                violation: AssemblerDurationViolation::AnchorOverflow,
            })
        ));
    }

    #[test]
    fn initial_heartbeat_grace_expires_exactly_and_then_uses_steady_deadline() {
        let start = Instant::now();
        let limits = AssemblerLimits::default();
        let mut silent =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("default assembler config is valid");
        assert_eq!(
            silent.next_deadline_at(),
            Some(start + limits.initial_heartbeat_deadline)
        );
        assert!(silent
            .advance_time(start + limits.initial_heartbeat_deadline - Duration::from_millis(1))
            .is_empty());
        assert!(matches!(
            fault_kind(&silent.advance_time(start + limits.initial_heartbeat_deadline)),
            Some(AssemblyFaultKind::HeartbeatDeadlineExpired)
        ));

        let mut active =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("default assembler config is valid");
        let receipt = start + Duration::from_secs(10);
        let mut first = heartbeat(None, 1, 1);
        first.declared_deadline_ms = 3_000;
        assert!(active
            .ingest_monitor_bytes(&monitor_bytes(1, ProducerEvent::Heartbeat(first)), receipt,)
            .iter()
            .any(|event| matches!(event, AssemblyEvent::HeartbeatAccepted { .. })));
        assert_eq!(
            active.next_deadline_at(),
            Some(receipt + limits.heartbeat_deadline)
        );
        assert!(matches!(
            fault_kind(&active.advance_time(receipt + limits.heartbeat_deadline)),
            Some(AssemblyFaultKind::HeartbeatDeadlineExpired)
        ));
    }

    #[test]
    fn default_track_capacity_covers_full_frozen_set_replacement_by_births() {
        assert_eq!(
            AssemblerLimits::default().max_tracks_per_frame,
            2 * MAX_ACTIVE_TRACKS as usize
        );
        assert_eq!(
            AssemblerLimits::default().max_prior_identities,
            MAX_ASSEMBLER_PRIOR_IDENTITIES
        );
        assert_eq!(
            AssemblerLimits::default().max_observation_streams,
            MAX_ASSEMBLER_OBSERVATION_STREAMS
        );
    }

    #[test]
    fn hard_bounds_and_state_accessors_preserve_exact_values() {
        assert_eq!(MAX_ASSEMBLER_SIDECAR_BYTES, 65_536);
        assert_eq!(MAX_ASSEMBLER_OBSERVATION_STREAMS, 65_536);

        let start = Instant::now();
        let limits = AssemblerLimits {
            max_open_frames: 7,
            heartbeat_deadline: Duration::from_secs(30),
            ..AssemblerLimits::default()
        };
        let mut assembler =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("nondefault test limits validate");
        assembler.frames.insert(1, PartialFrame::new(start));
        assembler.frames.insert(2, PartialFrame::new(start));
        assembler.buffered_bytes = 7;
        assembler.prior_sequences.insert(11, 1);
        assembler.prior_sequences.insert(12, 2);
        assembler
            .observation_high_water
            .insert((11, Modality::Visual), 1);
        assembler
            .observation_high_water
            .insert((12, Modality::Radar), 2);

        assert_eq!(
            (
                assembler.open_frames(),
                assembler.buffered_bytes(),
                assembler.prior_identities(),
                assembler.observation_streams(),
                assembler.limits(),
            ),
            (2, 7, 2, 2, limits)
        );
    }

    #[test]
    fn identity_validation_covers_character_and_byte_boundaries() {
        let exact = "a".repeat(crate::MAX_ID_SEGMENT_BYTES);
        let oversized = "a".repeat(crate::MAX_ID_SEGMENT_BYTES + 1);
        assert!(valid_session_identity(&exact));
        assert!(valid_producer_identity(&exact));
        for invalid in ["", "bad*", "uav+3", "époch1", "-uav3", "uav3-"] {
            assert!(!valid_session_identity(invalid));
            assert!(!valid_producer_identity(invalid));
        }
        assert!(!valid_session_identity(&oversized));
        assert!(!valid_producer_identity(&oversized));

        let limits = AssemblerProfile::BoundedV0_9.try_limits().unwrap();
        assert!(matches!(
            CrossRouteAssembler::new("uav+3", "crebain", TestRegistry, limits, Instant::now()),
            Err(AssemblerConfigError::InvalidIdentity {
                field: "session_id",
                ..
            })
        ));
        assert!(matches!(
            CrossRouteAssembler::new("uav3", "crebain+1", TestRegistry, limits, Instant::now()),
            Err(AssemblerConfigError::InvalidIdentity {
                field: "producer_id",
                ..
            })
        ));
    }

    #[test]
    fn release_profiles_have_stable_architecture_independent_identities() {
        let limits = AssemblerProfile::BoundedV0_9.try_limits().unwrap();
        let params = AssemblerProfile::BoundedV0_9.params();
        let policy = wire_policy();

        assert_eq!(limits.max_open_frames(), params.max_open_frames);
        assert_eq!(limits.max_events_per_frame(), params.max_events_per_frame);
        assert_eq!(
            limits.max_observations_per_frame(),
            params.max_observations_per_frame
        );
        assert_eq!(limits.max_tracks_per_frame(), params.max_tracks_per_frame);
        assert_eq!(limits.max_reorder_events(), params.max_reorder_events);
        assert_eq!(limits.max_reorder_distance(), params.max_reorder_distance);
        assert_eq!(limits.max_buffered_bytes(), params.max_buffered_bytes);
        assert_eq!(limits.max_prior_identities(), params.max_prior_identities);
        assert_eq!(
            limits.max_observation_streams(),
            params.max_observation_streams
        );
        assert_eq!(
            limits.max_observation_advance(),
            params.max_observation_advance
        );
        assert_eq!(limits.frame_deadline(), params.frame_deadline);
        assert_eq!(limits.reorder_deadline(), params.reorder_deadline);
        assert_eq!(limits.heartbeat_interval(), params.heartbeat_interval);
        assert_eq!(limits.heartbeat_deadline(), params.heartbeat_deadline);
        assert_eq!(
            limits.initial_heartbeat_deadline(),
            params.initial_heartbeat_deadline
        );

        assert_eq!(
            limits.identity().to_hex(),
            "de32762c3262bef5424bbe66ae96a698173f5b35bbae5f5b1c06955594cd6b13"
        );
        assert_eq!(
            policy.identity().to_hex(),
            "0efa70a37ea0bbf937a580d19294fe65a5970d7a18d3497b280c3a55725d5b9f"
        );
    }

    #[test]
    fn typed_construction_rejects_buffer_aggregate_and_registry_boundaries() {
        let mut too_small_buffer = AssemblerProfile::BoundedV0_9.params();
        too_small_buffer.max_buffered_bytes = MAX_ASSEMBLER_SIDECAR_BYTES - 1;
        assert!(matches!(
            AssemblerLimits::try_from(too_small_buffer),
            Err(AssemblerConfigError::BufferBudgetTooSmall { .. })
        ));

        let mut excessive_aggregate = AssemblerProfile::BoundedV0_9.params();
        excessive_aggregate.max_open_frames = MAX_ASSEMBLER_OPEN_FRAMES;
        excessive_aggregate.max_tracks_per_frame = MAX_FRAME_ITEMS as usize;
        assert!(matches!(
            AssemblerLimits::try_from(excessive_aggregate),
            Err(AssemblerConfigError::AggregateStateTooLarge { .. })
        ));

        let exact_aggregate = AssemblerLimits {
            max_open_frames: MAX_ASSEMBLER_OPEN_FRAMES,
            max_events_per_frame: MAX_FRAME_ITEMS as usize,
            max_observations_per_frame: MAX_FRAME_ITEMS as usize - 1,
            max_tracks_per_frame: 1,
            max_reorder_events: MAX_ASSEMBLER_REORDER_EVENTS,
            max_prior_identities: MAX_ASSEMBLER_PRIOR_IDENTITIES,
            max_observation_streams: MAX_ASSEMBLER_OBSERVATION_STREAMS,
            ..AssemblerLimits::default()
        };
        assert!(validate_limits(exact_aggregate, Instant::now()).is_ok());
        assert_eq!(
            MAX_ASSEMBLER_TOTAL_STATE_SLOTS,
            MAX_ASSEMBLER_FRAME_STATE_SLOTS
                + MAX_ASSEMBLER_REORDER_EVENTS
                + MAX_ASSEMBLER_PRIOR_IDENTITIES
                + MAX_ASSEMBLER_OBSERVATION_STREAMS
        );

        let one_frame_slot_over = AssemblerLimits {
            max_observations_per_frame: MAX_FRAME_ITEMS as usize,
            max_reorder_events: 1,
            max_prior_identities: 1,
            max_observation_streams: 1,
            ..exact_aggregate
        };
        assert_eq!(
            validate_limits(one_frame_slot_over, Instant::now()),
            Err(AssemblerConfigError::AggregateStateTooLarge {
                value: MAX_ASSEMBLER_FRAME_STATE_SLOTS + MAX_ASSEMBLER_OPEN_FRAMES,
                maximum: MAX_ASSEMBLER_FRAME_STATE_SLOTS,
            })
        );

        let mut invalid_policy = RegistryOpportunityParams {
            max_active_tracks: MAX_ACTIVE_TRACKS,
            max_frame_inputs: MAX_FRAME_ITEMS,
            max_attempts_per_track_modality: MAX_FRAME_ITEMS,
            max_outcomes_per_frame: MAX_FRAME_ITEMS,
            max_monitor_queue_events: crate::monitor::MAX_MONITOR_QUEUE_EVENTS,
        };
        invalid_policy.max_active_tracks = 0;
        assert!(matches!(
            RegistryOpportunityPolicy::try_new(invalid_policy),
            Err(RegistryOpportunityPolicyError::InvalidLimit {
                field: "max_active_tracks",
                ..
            })
        ));
    }

    #[test]
    fn registry_opportunity_policy_preserves_every_pinned_bound() {
        let params = RegistryOpportunityParams {
            max_active_tracks: 2,
            max_frame_inputs: 3,
            max_attempts_per_track_modality: 4,
            max_outcomes_per_frame: 5,
            max_monitor_queue_events: 6,
        };
        let policy = RegistryOpportunityPolicy::try_new(params).unwrap();

        assert_eq!(policy.max_active_tracks(), 2);
        assert_eq!(policy.max_frame_inputs(), 3);
        assert_eq!(policy.max_attempts_per_track_modality(), 4);
        assert_eq!(policy.max_outcomes_per_frame(), 5);
        assert_eq!(policy.max_monitor_queue_events(), 6);
        assert_ne!(policy.identity().as_bytes(), &[0; 32]);
    }

    #[test]
    fn resource_and_duration_validation_isolation_covers_each_predicate() {
        let start = Instant::now();
        let defaults = AssemblerLimits::default();

        for invalid in [
            AssemblerLimits {
                max_open_frames: 0,
                ..defaults
            },
            AssemblerLimits {
                max_open_frames: MAX_ASSEMBLER_OPEN_FRAMES + 1,
                ..defaults
            },
        ] {
            assert!(matches!(
                validate_limits(invalid, start),
                Err(AssemblerConfigError::InvalidLimit { .. })
            ));
        }
        for invalid in [
            AssemblerLimits {
                max_reorder_distance: 0,
                ..defaults
            },
            AssemblerLimits {
                max_observation_advance: 0,
                ..defaults
            },
        ] {
            assert!(matches!(
                validate_limits(invalid, start),
                Err(AssemblerConfigError::InvalidSequenceLimit { value: 0, .. })
            ));
        }

        for field in ["max_reorder_distance", "max_observation_advance"] {
            let exact_ceiling = match field {
                "max_reorder_distance" => AssemblerLimits {
                    max_reorder_distance: MAX_ASSEMBLER_SEQUENCE_DISTANCE,
                    ..defaults
                },
                "max_observation_advance" => AssemblerLimits {
                    max_observation_advance: MAX_ASSEMBLER_SEQUENCE_DISTANCE,
                    ..defaults
                },
                _ => unreachable!("the test enumerates every sequence limit"),
            };
            assert!(
                validate_limits(exact_ceiling, start).is_ok(),
                "{field} accepts the documented exact ceiling"
            );

            let one_over = match field {
                "max_reorder_distance" => AssemblerLimits {
                    max_reorder_distance: MAX_ASSEMBLER_SEQUENCE_DISTANCE + 1,
                    ..defaults
                },
                "max_observation_advance" => AssemblerLimits {
                    max_observation_advance: MAX_ASSEMBLER_SEQUENCE_DISTANCE + 1,
                    ..defaults
                },
                _ => unreachable!("the test enumerates every sequence limit"),
            };
            assert!(matches!(
                validate_limits(one_over, start),
                Err(AssemblerConfigError::InvalidSequenceLimit {
                    field: rejected,
                    value,
                    maximum: MAX_ASSEMBLER_SEQUENCE_DISTANCE,
                }) if rejected == field && value == MAX_ASSEMBLER_SEQUENCE_DISTANCE + 1
            ));
        }

        let zero = AssemblerLimits {
            frame_deadline: Duration::ZERO,
            ..defaults
        };
        let fractional = AssemblerLimits {
            frame_deadline: Duration::from_nanos(1),
            ..defaults
        };
        assert!(matches!(
            validate_limits(zero, start),
            Err(AssemblerConfigError::InvalidDuration {
                field: "frame_deadline",
                violation: AssemblerDurationViolation::Zero,
            })
        ));
        assert!(matches!(
            validate_limits(fractional, start),
            Err(AssemblerConfigError::InvalidDuration {
                field: "frame_deadline",
                violation: AssemblerDurationViolation::NotExactMilliseconds,
            })
        ));

        let unrepresentable = AssemblerLimits {
            frame_deadline: Duration::from_millis(u64::MAX),
            ..defaults
        };
        assert!(matches!(
            validate_limits(unrepresentable, start),
            Err(AssemblerConfigError::InvalidDuration {
                field: "frame_deadline",
                violation: AssemblerDurationViolation::ExceedsHardMaximum,
            })
        ));
    }

    #[test]
    fn decode_fault_fusion_sequence_and_modality_rank_are_exact() {
        assert_eq!(
            monitor_decode_fault(&MonitorError::EncodedEventTooLarge {
                actual: MAX_MONITOR_EVENT_BYTES + 1,
                maximum: MAX_MONITOR_EVENT_BYTES,
            }),
            AssemblyFaultKind::PayloadTooLarge {
                route: EvidenceRoute::Monitor,
            }
        );
        assert_eq!(
            monitor_decode_fault(&MonitorError::Json("malformed".to_owned())),
            AssemblyFaultKind::MalformedPayload {
                route: EvidenceRoute::Monitor,
            }
        );
        let FrameMonitorEvent::Miss(miss) = ledger_miss(7, ModalityMissReason::NoMeasurement)
        else {
            unreachable!();
        };
        assert_eq!(
            [
                event_fusion_seq(&ProducerEvent::Heartbeat(heartbeat(None, 1, 1))),
                event_fusion_seq(&ProducerEvent::ModalityOutcome(outcome(7, 107))),
                event_fusion_seq(&ProducerEvent::ModalityMiss(miss)),
                event_fusion_seq(&ProducerEvent::FrameSummary(summary(7, 107))),
            ],
            [None, Some(7), Some(1), Some(7)]
        );
        assert_eq!(
            [
                Modality::Visual,
                Modality::Thermal,
                Modality::Acoustic,
                Modality::Radar,
                Modality::Lidar,
                Modality::RadioFrequency,
            ]
            .map(modality_rank),
            [0, 1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn frame_ledger_repeated_attempts_enforce_sequence_measurements_counts_and_gate_boundary() {
        let closure = ledger_summary(1, 2);
        let valid = valid_two_attempt_ledger();
        assert!(validate_test_ledger(valid.clone(), &closure).is_ok());

        let mut skipped_attempt = valid.clone();
        let FrameMonitorEvent::Outcome(value) = &mut skipped_attempt[0] else {
            unreachable!();
        };
        value.attempt_index = 1;
        assert!(validate_test_ledger(skipped_attempt, &closure).is_err());

        let mut out_of_range = valid.clone();
        let FrameMonitorEvent::Outcome(value) = &mut out_of_range[0] else {
            unreachable!();
        };
        value.measurement_index = Some(closure.input_count);
        assert!(validate_test_ledger(out_of_range, &closure).is_err());

        let mut duplicate_measurement = valid.clone();
        let FrameMonitorEvent::Outcome(value) = &mut duplicate_measurement[1] else {
            unreachable!();
        };
        value.measurement_index = Some(0);
        assert!(validate_test_ledger(duplicate_measurement, &closure).is_err());

        let mut candidate_drift = valid.clone();
        let FrameMonitorEvent::Outcome(value) = &mut candidate_drift[1] else {
            unreachable!();
        };
        value.candidate_count = 3;
        assert!(validate_test_ledger(candidate_drift, &closure).is_err());

        let mut in_gate_drift = valid;
        let FrameMonitorEvent::Outcome(value) = &mut in_gate_drift[1] else {
            unreachable!();
        };
        value.in_gate_count = 2;
        assert!(validate_test_ledger(in_gate_drift, &closure).is_err());

        let boundary = vec![
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::GateRejected,
                1,
                0,
                Some((7.815, 7.815)),
            ),
            ledger_miss(7, ModalityMissReason::NoInGateCandidate),
        ];
        assert!(validate_test_ledger(boundary, &ledger_summary(1, 1)).is_ok());
    }

    #[test]
    fn frame_ledger_enforces_pair_ordering_and_attempt_miss_exclusion() {
        let ordered_outcomes = vec![
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::UpdateRejected,
                1,
                1,
                Some((1.0, 7.815)),
            ),
            ledger_outcome(
                8,
                0,
                0,
                ModalityOutcomeKind::UpdateRejected,
                1,
                1,
                Some((1.0, 7.815)),
            ),
        ];
        assert!(validate_test_ledger(ordered_outcomes.clone(), &ledger_summary(2, 1)).is_ok());

        let mut reversed_outcomes = ordered_outcomes;
        reversed_outcomes.reverse();
        assert!(validate_test_ledger(reversed_outcomes, &ledger_summary(2, 1)).is_err());

        let ordered_misses = vec![
            ledger_miss(7, ModalityMissReason::NoMeasurement),
            ledger_miss(8, ModalityMissReason::NoMeasurement),
        ];
        assert!(validate_test_ledger(ordered_misses.clone(), &ledger_summary(2, 0)).is_ok());

        let mut reversed_misses = ordered_misses;
        reversed_misses.reverse();
        assert!(validate_test_ledger(reversed_misses, &ledger_summary(2, 0)).is_err());

        let attempt_after_miss = vec![
            ledger_miss(7, ModalityMissReason::NoMeasurement),
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::UpdateRejected,
                1,
                1,
                Some((1.0, 7.815)),
            ),
        ];
        assert!(validate_test_ledger(attempt_after_miss, &ledger_summary(1, 1)).is_err());

        let miss_after_attempt = vec![
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::AssignmentRejected,
                1,
                1,
                Some((1.0, 7.815)),
            ),
            ledger_miss(7, ModalityMissReason::NotAssigned),
        ];
        assert!(validate_test_ledger(miss_after_attempt, &ledger_summary(1, 1)).is_ok());
    }

    #[test]
    fn frame_ledger_births_require_unique_ordered_tracks_and_measurements() {
        let ordered = vec![
            ledger_outcome(7, 0, 0, ModalityOutcomeKind::TrackBirth, 0, 0, None),
            ledger_outcome(8, 0, 1, ModalityOutcomeKind::TrackBirth, 0, 0, None),
        ];
        assert!(validate_test_ledger(ordered.clone(), &ledger_summary(2, 2)).is_ok());

        let mut nonzero_attempt = vec![ordered[0].clone()];
        let FrameMonitorEvent::Outcome(value) = &mut nonzero_attempt[0] else {
            unreachable!();
        };
        value.attempt_index = 1;
        assert!(validate_test_ledger(nonzero_attempt, &ledger_summary(1, 1)).is_err());

        let duplicate_track = vec![
            ordered[0].clone(),
            ledger_outcome(7, 0, 1, ModalityOutcomeKind::TrackBirth, 0, 0, None),
        ];
        assert!(validate_test_ledger(duplicate_track, &ledger_summary(2, 2)).is_err());

        let duplicate_measurement = vec![
            ordered[0].clone(),
            ledger_outcome(8, 0, 0, ModalityOutcomeKind::TrackBirth, 0, 0, None),
        ];
        assert!(validate_test_ledger(duplicate_measurement, &ledger_summary(2, 2)).is_err());

        let mut reversed = ordered.clone();
        reversed.reverse();
        assert!(validate_test_ledger(reversed, &ledger_summary(2, 2)).is_err());

        let out_of_range = vec![ledger_outcome(
            7,
            0,
            1,
            ModalityOutcomeKind::TrackBirth,
            0,
            0,
            None,
        )];
        assert!(validate_test_ledger(out_of_range, &ledger_summary(1, 1)).is_err());
    }

    #[test]
    fn frame_ledger_miss_reasons_follow_candidate_and_gate_truth_table() {
        for (reason, input_count) in [
            (ModalityMissReason::NoMeasurement, 0),
            (ModalityMissReason::NoCandidate, 1),
            (ModalityMissReason::TrackNotEligible, 0),
        ] {
            assert!(validate_test_ledger(
                vec![ledger_miss(7, reason)],
                &ledger_summary(1, input_count),
            )
            .is_ok());
        }
        assert!(validate_test_ledger(
            vec![ledger_miss(7, ModalityMissReason::NoCandidate)],
            &ledger_summary(1, 0),
        )
        .is_err());

        assert!(validate_test_ledger(
            vec![ledger_miss(7, ModalityMissReason::NotAssigned)],
            &ledger_summary(1, 0),
        )
        .is_err());
        assert!(validate_test_ledger(
            vec![ledger_miss(7, ModalityMissReason::NoInGateCandidate)],
            &ledger_summary(1, 0),
        )
        .is_err());

        let pair = |in_gate_count, d2, reason| {
            let outcome_kind = if in_gate_count == 0 {
                ModalityOutcomeKind::GateRejected
            } else {
                ModalityOutcomeKind::AssignmentRejected
            };
            vec![
                ledger_outcome(7, 0, 0, outcome_kind, 1, in_gate_count, Some((d2, 7.815))),
                ledger_miss(7, reason),
            ]
        };

        assert!(validate_test_ledger(
            pair(0, 9.0, ModalityMissReason::NoCandidate),
            &ledger_summary(1, 1),
        )
        .is_err());
        assert!(validate_test_ledger(
            pair(0, 9.0, ModalityMissReason::NoInGateCandidate),
            &ledger_summary(1, 1),
        )
        .is_ok());
        assert!(validate_test_ledger(
            pair(1, 1.0, ModalityMissReason::NoInGateCandidate),
            &ledger_summary(1, 1),
        )
        .is_err());
        assert!(validate_test_ledger(
            pair(1, 1.0, ModalityMissReason::NotAssigned),
            &ledger_summary(1, 1),
        )
        .is_ok());
        assert!(validate_test_ledger(
            pair(0, 9.0, ModalityMissReason::NotAssigned),
            &ledger_summary(1, 1),
        )
        .is_err());
    }

    #[test]
    fn frame_ledger_rejects_no_measurement_when_candidates_exist() {
        let monitor_events = vec![
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::GateRejected,
                1,
                0,
                Some((9.0, 7.815)),
            ),
            ledger_miss(7, ModalityMissReason::NoMeasurement),
        ];

        let error = validate_test_ledger(monitor_events, &ledger_summary(1, 1))
            .expect_err("NoMeasurement must not close a ledger with candidates");

        assert_eq!(
            error,
            AssemblyFaultKind::InvalidFrameLedger { fusion_seq: 1 }
        );
    }

    #[test]
    fn frame_ledger_rejects_track_not_eligible_when_candidates_exist() {
        let monitor_events = vec![
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::GateRejected,
                1,
                0,
                Some((9.0, 7.815)),
            ),
            ledger_miss(7, ModalityMissReason::TrackNotEligible),
        ];

        let error = validate_test_ledger(monitor_events, &ledger_summary(1, 1))
            .expect_err("TrackNotEligible must not close a ledger with candidates");

        assert_eq!(
            error,
            AssemblyFaultKind::InvalidFrameLedger { fusion_seq: 1 }
        );
    }

    #[test]
    fn frame_ledger_reconciles_candidate_gate_and_terminal_totals_independently() {
        let valid_terminal = vec![ledger_outcome(
            7,
            0,
            0,
            ModalityOutcomeKind::UpdateRejected,
            1,
            1,
            Some((1.0, 7.815)),
        )];
        assert!(validate_test_ledger(valid_terminal.clone(), &ledger_summary(1, 1)).is_ok());

        let mut candidate_mismatch = valid_terminal.clone();
        let FrameMonitorEvent::Outcome(value) = &mut candidate_mismatch[0] else {
            unreachable!();
        };
        value.candidate_count = 2;
        assert!(validate_test_ledger(candidate_mismatch, &ledger_summary(1, 1)).is_err());

        let gate_mismatch = vec![
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::GateRejected,
                2,
                2,
                Some((9.0, 7.815)),
            ),
            ledger_outcome(
                7,
                1,
                1,
                ModalityOutcomeKind::AssignmentRejected,
                2,
                2,
                Some((1.0, 7.815)),
            ),
            ledger_miss(7, ModalityMissReason::NotAssigned),
        ];
        assert!(validate_test_ledger(gate_mismatch, &ledger_summary(1, 2)).is_err());

        let two_terminals = vec![
            ledger_outcome(
                7,
                0,
                0,
                ModalityOutcomeKind::UpdateRejected,
                2,
                2,
                Some((1.0, 7.815)),
            ),
            ledger_outcome(
                7,
                1,
                1,
                ModalityOutcomeKind::UpdateRejected,
                2,
                2,
                Some((1.0, 7.815)),
            ),
        ];
        assert!(validate_test_ledger(two_terminals, &ledger_summary(1, 2)).is_err());

        let unterminated = vec![ledger_outcome(
            7,
            0,
            0,
            ModalityOutcomeKind::GateRejected,
            1,
            0,
            Some((9.0, 7.815)),
        )];
        assert!(validate_test_ledger(unterminated, &ledger_summary(1, 1)).is_err());
    }

    #[test]
    fn heartbeat_configuration_matches_the_monitor_wire_duration_domain() {
        let start = Instant::now();
        let wire_maximum = Duration::from_millis(MAX_HEARTBEAT_DURATION_MS);
        let inclusive = AssemblerLimits {
            heartbeat_interval: wire_maximum,
            heartbeat_deadline: wire_maximum,
            initial_heartbeat_deadline: wire_maximum,
            ..AssemblerLimits::default()
        };
        CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, inclusive, start)
            .expect("inclusive monitor duration boundary is constructible");

        for invalid in [
            AssemblerLimits {
                heartbeat_interval: wire_maximum + Duration::from_millis(1),
                heartbeat_deadline: wire_maximum + Duration::from_millis(1),
                initial_heartbeat_deadline: wire_maximum + Duration::from_millis(1),
                ..AssemblerLimits::default()
            },
            AssemblerLimits {
                heartbeat_interval: wire_maximum,
                heartbeat_deadline: wire_maximum + Duration::from_millis(1),
                initial_heartbeat_deadline: wire_maximum + Duration::from_millis(1),
                ..AssemblerLimits::default()
            },
        ] {
            assert!(matches!(
                CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, invalid, start),
                Err(AssemblerConfigError::InvalidDuration { .. })
            ));
        }
    }

    #[test]
    fn assembler_completes_when_observation_arrives_before_monitor_closure() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assert!(ready(
            &assembler.ingest_observation_bytes(&observation_bytes(observation(1, 101)), start)
        )
        .is_none());
        assert!(ready(&assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start
        ))
        .is_none());
        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
            start,
        );
        let frame = ready(&events).expect("summary closes exact joined frame");
        assert_eq!(frame.session_id(), "epoch-1");
        assert_eq!(frame.producer_id(), "crebain");
        assert_eq!(frame.identity.fusion_seq, 1);
        assert_eq!(frame.observations.len(), 1);
    }

    #[test]
    fn pinned_registry_rejects_one_dimensional_projection_on_observation_first_ingress() {
        let start = Instant::now();
        let mut assembler = assembler_with_registry(start, pinned_fixture_registry());

        let events = assembler.ingest_observation_bytes(
            &observation_bytes(one_dimensional_registry_observation()),
            start,
        );

        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::ProjectionDimensionMismatch {
                    context_id: 23,
                    expected: 3,
                    received: 1,
                }
            ))
        ));
    }

    #[test]
    fn pinned_registry_rejects_one_dimensional_projection_on_monitor_first_ingress() {
        let start = Instant::now();
        let mut assembler = assembler_with_registry(start, pinned_fixture_registry());

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(
                1,
                ProducerEvent::ModalityOutcome(one_dimensional_registry_outcome()),
            ),
            start,
        );

        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::ProjectionDimensionMismatch {
                    context_id: 23,
                    expected: 3,
                    received: 1,
                }
            ))
        ));
    }

    #[test]
    fn assembler_reorders_monitor_events_within_bounded_window() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let later = assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
            start,
        );
        assert!(fault_kind(&later).is_none());
        assert_eq!(assembler.pending_monitor_events(), 1);
        assert_eq!(assembler.next_expected_monitor_event_seq(), 1);
        let earlier = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        assert!(fault_kind(&earlier).is_none());
        assert_eq!(assembler.pending_monitor_events(), 0);
        assert_eq!(assembler.next_expected_monitor_event_seq(), 3);
        let events =
            assembler.ingest_observation_bytes(&observation_bytes(observation(1, 101)), start);
        assert!(ready(&events).is_some());
    }

    #[test]
    fn assembler_fails_closed_when_monitor_gap_deadline_expires() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
            start,
        );
        let events = assembler.advance_time(start + Duration::from_secs(1));
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::MonitorSequenceGap {
                expected: 1,
                next_received: 2
            })
        ));
    }

    #[test]
    fn assembler_monitor_gap_invalidates_from_the_oldest_open_frame() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_observation_bytes(&observation_bytes(observation(1, 101)), start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(2, 102))),
            start,
        );

        let events = assembler.advance_time(start + Duration::from_secs(1));

        assert_eq!(
            fault(&events)
                .expect("the monitor gap is terminal")
                .invalidate_from_fusion_seq,
            Some(1)
        );
    }

    #[test]
    fn assembler_monitor_gap_before_heartbeat_invalidates_the_oldest_open_frame() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_observation_bytes(&observation_bytes(observation(4, 104)), start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::Heartbeat(heartbeat(None, 1, 1))),
            start,
        );

        let events = assembler.advance_time(start + Duration::from_secs(1));

        assert_eq!(
            fault(&events)
                .expect("the monitor gap is terminal")
                .invalidate_from_fusion_seq,
            Some(4)
        );
    }

    #[test]
    fn assembler_rejects_duplicate_global_monitor_sequence() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::DuplicateOrRegressedMonitorSequence { .. })
        ));
    }

    #[test]
    fn assembler_establishes_observation_projection_identity_before_monitor() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let bad = test_observation(7, 1_001, 1, Modality::Visual, 1.0, Some(projection(999)));
        assembler.ingest_observation_bytes(&observation_bytes(bad), start);
        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::FrameIdentityMismatch { fusion_seq: 1 })
        ));
    }

    #[test]
    fn assembler_retains_prior_identity_after_completed_frame() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_observation_bytes(&observation_bytes(observation(1, 101)), start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
            start,
        );
        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(3, ProducerEvent::ModalityOutcome(outcome(2, 101))),
            start,
        );
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::PriorReuse { .. })
        ));
    }

    #[test]
    fn assembler_missing_summary_invalidates_from_the_unclosed_frame() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::ModalityOutcome(outcome(2, 102))),
            start,
        );

        let fault = fault(&events).expect("starting a later frame before closure is terminal");
        assert!(matches!(
            fault.kind,
            AssemblyFaultKind::MissingSummaryBeforeNextFrame {
                previous: 1,
                received: 2,
            }
        ));
        assert_eq!(fault.invalidate_from_fusion_seq, Some(1));
    }

    #[test]
    fn assembler_expires_frame_missing_v1_observation() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
            start,
        );
        let events = assembler.advance_time(start + Duration::from_secs(5));
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::FrameDeadlineExpired {
                missing: MissingFrameEvidence::Observation { missing: 1 },
                ..
            })
        ));
    }

    #[test]
    fn assembler_rejects_summary_outcome_count_disagreement() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        let mut bad_summary = summary(1, 101);
        bad_summary.outcome_count = 2;
        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(bad_summary)),
            start,
        );
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::OutcomeCountMismatch {
                declared: 2,
                received: 1
            })
        ));
    }

    #[test]
    fn assembler_rejects_active_tracks_absent_from_the_visible_lifecycle_ledger() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let mut impossible = empty_summary(1, 101);
        impossible.active_track_count = 1;

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::FrameSummary(impossible)),
            start,
        );
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::InvalidFrameLedger { fusion_seq: 1 })
        ));
    }

    #[test]
    fn summary_caches_immutable_join_ledger_and_post_summary_join_is_constant_time() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
            start,
        );
        assert!(fault_kind(&events).is_none());
        let partial = assembler
            .frames
            .get(&1)
            .expect("incomplete frame is retained");
        assert_eq!(
            partial
                .expected_observations
                .as_ref()
                .expect("summary validates and caches the immutable ledger")
                .len(),
            1
        );
        assert!(!partial.ready);

        let unexpected =
            test_observation(8, 1_001, 1, Modality::Visual, 1.0, Some(projection(101)));
        let events = assembler.ingest_observation_bytes(&observation_bytes(unexpected), start);
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::UnexpectedObservation {
                track_id: 8,
                modality: Modality::Visual,
                ..
            })
        ));
    }

    #[test]
    fn assembler_rejects_observation_without_v1_expected_key() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let unexpected =
            test_observation(8, 1_001, 1, Modality::Visual, 1.0, Some(projection(101)));
        assembler.ingest_observation_bytes(&observation_bytes(unexpected), start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );
        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
            start,
        );
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::UnexpectedObservation {
                track_id: 8,
                modality: Modality::Visual,
                ..
            })
        ));
    }

    #[test]
    fn assembler_rejects_an_updated_outcome_that_censors_its_v1_join() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let encoded = String::from_utf8(monitor_bytes(
            1,
            ProducerEvent::ModalityOutcome(outcome(1, 101)),
        ))
        .expect("test envelope is UTF-8 JSON");
        let needle = r#""v1_expected":true"#;
        assert_eq!(encoded.matches(needle).count(), 1);
        let mutated = encoded.replacen(needle, r#""v1_expected":false"#, 1);

        let events = assembler.ingest_monitor_bytes(mutated.as_bytes(), start);
        assert!(
            matches!(
                fault_kind(&events),
                Some(AssemblyFaultKind::InvalidEnvelope {
                    route: EvidenceRoute::Monitor
                })
            ),
            "unexpected events: {events:?}"
        );
    }

    #[test]
    fn assembler_open_frame_capacity_fails_without_eviction() {
        let start = Instant::now();
        let limits = AssemblerLimits {
            max_open_frames: 1,
            heartbeat_deadline: Duration::from_secs(30),
            ..AssemblerLimits::default()
        };
        let mut assembler =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("test assembler config is valid");
        assembler.ingest_observation_bytes(&observation_bytes(observation(1, 101)), start);
        let events =
            assembler.ingest_observation_bytes(&observation_bytes(observation(2, 102)), start);
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::CapacityExceeded {
                capacity: AssemblyCapacity::Frames
            })
        ));
    }

    #[test]
    fn assembler_rejects_observation_prior_reuse_at_the_earliest_sequence() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_observation_bytes(&observation_bytes(observation(2, 101)), start);

        let earlier = test_observation(8, 1_001, 1, Modality::Visual, 1.0, Some(projection(101)));
        let events = assembler.ingest_observation_bytes(&observation_bytes(earlier), start);

        let fault = fault(&events).expect("observation prior reuse faults immediately");
        assert!(matches!(
            fault.kind,
            AssemblyFaultKind::PriorReuse {
                prior_id: 101,
                previous_fusion_seq: 2,
                received_fusion_seq: 1,
            }
        ));
        assert_eq!(fault.invalidate_from_fusion_seq, Some(1));
    }

    #[test]
    fn assembler_discards_staged_ready_when_buffered_event_invalidates_frame() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::ModalityOutcome(outcome(1, 101))),
            start,
        );

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::FrameSummary(empty_summary(1, 101))),
            start,
        );

        assert!(ready(&events).is_none());
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::EventAfterFrameSummary { fusion_seq: 1 })
        ));
    }

    #[test]
    fn assembler_reconciles_declared_and_observed_in_gate_counts() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let mut rejected = outcome(1, 101);
        rejected.outcome = ModalityOutcomeKind::GateRejected;
        rejected.v1_expected = false;
        rejected.in_gate_count = 1;
        rejected.gate_evidence = Some(GateEvidence {
            method: GateMethod::Mahalanobis,
            d2: 9.0,
            threshold: 7.815,
        });
        rejected.consistency_projection = None;
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(rejected)),
            start,
        );
        assembler.ingest_monitor_bytes(
            &monitor_bytes(
                2,
                ProducerEvent::ModalityMiss(ModalityMiss {
                    fusion_seq: 1,
                    fusion_timestamp_ms: 1_001,
                    frame_id: 10,
                    context_id: 20,
                    prior_id: 101,
                    track_id: 7,
                    modality: Modality::Visual,
                    reason: ModalityMissReason::NotAssigned,
                }),
            ),
            start,
        );
        let mut closure = summary(1, 101);
        closure.outcome_count = 2;
        closure.v1_expected_count = 0;

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(3, ProducerEvent::FrameSummary(closure)),
            start,
        );

        assert!(ready(&events).is_none());
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::InvalidFrameLedger { fusion_seq: 1 })
        ));
    }

    #[test]
    fn assembler_preserves_unverifiable_gate_count_for_unsupported_filter() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let mut unsupported = outcome(1, 101);
        unsupported.outcome = ModalityOutcomeKind::UnsupportedFilter;
        unsupported.v1_expected = false;
        unsupported.gate_evidence = None;
        unsupported.consistency_projection = None;
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(unsupported)),
            start,
        );
        let mut closure = summary(1, 101);
        closure.v1_expected_count = 0;

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(closure)),
            start,
        );

        assert!(ready(&events).is_some());
        assert!(fault_kind(&events).is_none());
    }

    #[test]
    fn decoded_envelopes_fit_the_required_single_payload_buffer_floor() {
        let start = Instant::now();
        let limits = AssemblerLimits {
            max_buffered_bytes: MAX_ASSEMBLER_SIDECAR_BYTES.max(MAX_MONITOR_EVENT_BYTES),
            heartbeat_deadline: Duration::from_secs(30),
            ..AssemblerLimits::default()
        };
        let mut assembler =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("test assembler config is valid");
        let envelope = SidecarEnvelope::try_new("epoch-1", "crebain", observation(1, 101))
            .expect("test envelope is valid");

        let events = assembler.ingest_observation_envelope(envelope, start);

        assert!(fault_kind(&events).is_none());
        assert!(assembler.buffered_bytes() > 0);
        assert!(assembler.buffered_bytes() <= limits.max_buffered_bytes());

        let mut assembler =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("test assembler config is valid");
        let envelope = MonitorEnvelope::try_new(
            "epoch-1",
            "crebain",
            1,
            ProducerEvent::Heartbeat(heartbeat(None, 1, 1)),
        )
        .expect("test envelope is valid");

        let events = assembler.ingest_monitor_envelope(envelope, start);

        assert!(fault_kind(&events).is_none());
        assert_eq!(assembler.buffered_bytes(), 0);
    }

    #[test]
    fn exact_route_payload_ceilings_are_accepted_before_semantic_processing() {
        let start = Instant::now();

        let mut raw_monitor = monitor_bytes(1, ProducerEvent::Heartbeat(heartbeat(None, 1, 1)));
        raw_monitor.resize(MAX_MONITOR_EVENT_BYTES, b' ');
        let mut monitor_assembler = assembler(start);
        let events = monitor_assembler.ingest_monitor_bytes(&raw_monitor, start);
        assert!(events
            .iter()
            .any(|event| matches!(event, AssemblyEvent::HeartbeatAccepted { event_seq: 1, .. })));
        assert!(fault_kind(&events).is_none());

        let monitor_envelope = MonitorEnvelope::try_new(
            "epoch-1",
            "crebain",
            1,
            ProducerEvent::Heartbeat(heartbeat(None, 1, 1)),
        )
        .expect("test monitor envelope validates");
        let mut monitor_assembler = assembler(start);
        let events = monitor_assembler.ingest_monitor_envelope_sized(
            monitor_envelope,
            MAX_MONITOR_EVENT_BYTES,
            start,
        );
        assert!(events
            .iter()
            .any(|event| matches!(event, AssemblyEvent::HeartbeatAccepted { event_seq: 1, .. })));
        assert!(fault_kind(&events).is_none());

        let mut raw_observation = observation_bytes(observation(1, 101));
        raw_observation.resize(MAX_ASSEMBLER_SIDECAR_BYTES, b' ');
        let mut observation_assembler = assembler(start);
        let events = observation_assembler.ingest_observation_bytes(&raw_observation, start);
        assert!(fault_kind(&events).is_none());
        assert_eq!(observation_assembler.open_frames(), 1);

        let observation_envelope =
            SidecarEnvelope::try_new("epoch-1", "crebain", observation(1, 101))
                .expect("test observation envelope validates");
        let mut observation_assembler = assembler(start);
        let events = observation_assembler.ingest_observation_envelope_sized(
            observation_envelope,
            MAX_ASSEMBLER_SIDECAR_BYTES,
            start,
        );
        assert!(fault_kind(&events).is_none());
        assert_eq!(observation_assembler.open_frames(), 1);
    }

    #[test]
    fn oversized_and_malformed_route_payloads_keep_distinct_fault_taxonomy() {
        let start = Instant::now();

        let mut monitor = assembler(start);
        let events = monitor.ingest_monitor_bytes(&vec![b' '; MAX_MONITOR_EVENT_BYTES + 1], start);
        assert_eq!(
            fault_kind(&events),
            Some(&AssemblyFaultKind::PayloadTooLarge {
                route: EvidenceRoute::Monitor,
            })
        );

        let mut monitor = assembler(start);
        let events = monitor.ingest_monitor_bytes(b"{", start);
        assert_eq!(
            fault_kind(&events),
            Some(&AssemblyFaultKind::MalformedPayload {
                route: EvidenceRoute::Monitor,
            })
        );

        let mut observation_assembler = assembler(start);
        let events = observation_assembler.ingest_observation_bytes(b"{", start);
        assert_eq!(
            fault_kind(&events),
            Some(&AssemblyFaultKind::MalformedPayload {
                route: EvidenceRoute::Observation,
            })
        );

        let envelope = SidecarEnvelope::try_new("epoch-1", "crebain", observation(1, 101))
            .expect("test observation envelope validates");
        let mut invalid = serde_json::to_value(envelope).expect("test envelope serializes");
        invalid["session_id"] = serde_json::json!("epoch+1");
        let invalid = serde_json::to_vec(&invalid).expect("test envelope encodes");
        let mut observation_assembler = assembler(start);
        let events = observation_assembler.ingest_observation_bytes(&invalid, start);
        assert_eq!(
            fault_kind(&events),
            Some(&AssemblyFaultKind::InvalidEnvelope {
                route: EvidenceRoute::Observation,
            })
        );

        let monitor_envelope = MonitorEnvelope::try_new(
            "epoch-1",
            "crebain",
            1,
            ProducerEvent::Heartbeat(heartbeat(None, 1, 1)),
        )
        .expect("test monitor envelope validates");
        let mut monitor = assembler(start);
        let events = monitor.ingest_monitor_envelope_sized(
            monitor_envelope,
            MAX_MONITOR_EVENT_BYTES + 1,
            start,
        );
        assert_eq!(
            fault_kind(&events),
            Some(&AssemblyFaultKind::PayloadTooLarge {
                route: EvidenceRoute::Monitor,
            })
        );

        let observation_envelope =
            SidecarEnvelope::try_new("epoch-1", "crebain", observation(1, 101))
                .expect("test observation envelope validates");
        let mut observation_assembler = assembler(start);
        let events = observation_assembler.ingest_observation_envelope_sized(
            observation_envelope,
            MAX_ASSEMBLER_SIDECAR_BYTES + 1,
            start,
        );
        assert_eq!(
            fault_kind(&events),
            Some(&AssemblyFaultKind::PayloadTooLarge {
                route: EvidenceRoute::Observation,
            })
        );
    }

    #[test]
    fn exact_sequence_advance_boundaries_are_accepted() {
        let start = Instant::now();
        let limits = AssemblerLimits {
            max_reorder_distance: 2,
            max_observation_advance: 2,
            heartbeat_deadline: Duration::from_secs(30),
            ..AssemblerLimits::default()
        };

        let mut monitor_assembler =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("test limits validate");
        let pending = MonitorEnvelope::try_new(
            "epoch-1",
            "crebain",
            3,
            ProducerEvent::Heartbeat(heartbeat(None, 1, 1)),
        )
        .expect("test monitor envelope validates");
        let events = monitor_assembler.ingest_monitor_envelope_sized(pending, 1, start);
        assert!(fault_kind(&events).is_none());
        assert_eq!(monitor_assembler.pending_monitor_events(), 1);

        let mut observation_assembler =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("test limits validate");
        observation_assembler
            .observation_high_water
            .insert((7, Modality::Visual), 1);
        let envelope = SidecarEnvelope::try_new("epoch-1", "crebain", observation(3, 103))
            .expect("test observation envelope validates");
        let events = observation_assembler.ingest_observation_envelope_sized(envelope, 1, start);
        assert!(fault_kind(&events).is_none());
        assert_eq!(
            observation_assembler
                .observation_high_water
                .get(&(7, Modality::Visual)),
            Some(&3)
        );
    }

    #[test]
    fn a_new_track_fails_at_capacity_while_an_existing_track_remains_admissible() {
        let start = Instant::now();
        let limits = AssemblerLimits {
            max_tracks_per_frame: 1,
            heartbeat_deadline: Duration::from_secs(30),
            ..AssemblerLimits::default()
        };
        let mut assembler =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("test limits validate");
        let identity = FrameIdentity::from_outcome(&outcome(1, 101));

        assembler
            .process_frame_event(
                identity,
                FrameMonitorEvent::Outcome(outcome(1, 101)),
                1,
                start,
            )
            .expect("first track is admitted");
        assembler
            .process_frame_event(
                identity,
                FrameMonitorEvent::Outcome(outcome(1, 101)),
                1,
                start,
            )
            .expect("existing track remains admissible at capacity");
        let mut second_track = outcome(1, 101);
        second_track.track_id = 8;

        assert_eq!(
            assembler.process_frame_event(
                identity,
                FrameMonitorEvent::Outcome(second_track),
                1,
                start,
            ),
            Err(AssemblyFaultKind::CapacityExceeded {
                capacity: AssemblyCapacity::FrameTracks,
            })
        );
    }

    #[test]
    fn observation_route_rejects_a_new_track_at_exact_capacity() {
        let start = Instant::now();
        let limits = AssemblerLimits {
            max_tracks_per_frame: 1,
            heartbeat_deadline: Duration::from_secs(30),
            ..AssemblerLimits::default()
        };
        let mut assembler =
            CrossRouteAssembler::new("epoch-1", "crebain", TestRegistry, limits, start)
                .expect("test limits validate");
        assert!(fault_kind(
            &assembler.ingest_observation_bytes(&observation_bytes(observation(1, 101)), start,)
        )
        .is_none());
        let second_track =
            test_observation(8, 1_001, 1, Modality::Visual, 1.0, Some(projection(101)));

        let events = assembler.ingest_observation_bytes(&observation_bytes(second_track), start);

        assert_eq!(
            fault_kind(&events),
            Some(&AssemblyFaultKind::CapacityExceeded {
                capacity: AssemblyCapacity::FrameTracks,
            })
        );
    }

    #[test]
    fn finalized_frame_rejects_equal_sequence_observation_replay() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::FrameSummary(empty_summary(1, 101))),
            start,
        );
        assert!(ready(&events).is_some());
        let replay = observation(1, 202);

        let events = assembler.ingest_observation_bytes(&observation_bytes(replay), start);

        assert_eq!(
            fault_kind(&events),
            Some(&AssemblyFaultKind::ObservationForFinalizedFrame { fusion_seq: 1 })
        );
    }

    #[test]
    fn summary_flags_and_monitor_order_fail_independently() {
        let start = Instant::now();

        for truncated in [false, true] {
            let mut assembler = assembler(start);
            let mut closure = empty_summary(1, 101);
            closure.degraded = true;
            closure.truncated = truncated;
            closure
                .validate()
                .expect("degraded summary fixture satisfies wire invariants");
            assert_eq!(
                fault_kind(&assembler.ingest_monitor_bytes(
                    &monitor_bytes(1, ProducerEvent::FrameSummary(closure)),
                    start,
                )),
                Some(&AssemblyFaultKind::ProducerDegradedFrame {
                    fusion_seq: 1,
                    truncated,
                })
            );
        }

        let mut assembler = assembler(start);
        assembler.last_monitor_fusion_seq = Some(2);
        assert_eq!(
            assembler.check_monitor_frame_order(1),
            Err(AssemblyFaultKind::FusionSequenceRegressed {
                previous: 2,
                received: 1,
            })
        );
    }

    #[test]
    fn heartbeat_profile_loss_and_regression_boundaries_are_reachable() {
        let start = Instant::now();

        let mut wrong_interval = heartbeat(None, 1, 1);
        wrong_interval.declared_interval_ms += 1;
        assert_eq!(
            assembler(start).process_heartbeat(&wrong_interval),
            Err(AssemblyFaultKind::HeartbeatProfileMismatch)
        );
        let mut wrong_deadline = heartbeat(None, 1, 1);
        wrong_deadline.declared_deadline_ms += 1;
        assert_eq!(
            assembler(start).process_heartbeat(&wrong_deadline),
            Err(AssemblyFaultKind::HeartbeatProfileMismatch)
        );

        let mut degraded = heartbeat(None, 1, 1);
        degraded.degraded = true;
        assert_eq!(
            assembler(start).process_heartbeat(&degraded),
            Err(AssemblyFaultKind::ProducerDeclaredLoss)
        );
        let mut dropped = heartbeat(None, 1, 1);
        dropped.degraded = true;
        dropped.queue_health.dropped_event_count = 1;
        dropped
            .validate()
            .expect("degraded loss declaration satisfies wire invariants");
        assert_eq!(
            assembler(start).process_heartbeat(&dropped),
            Err(AssemblyFaultKind::ProducerDeclaredLoss)
        );

        let mut uptime_regressed = assembler(start);
        let mut first = heartbeat(None, 2, 1);
        first.queue_health.published_event_count = 5;
        uptime_regressed
            .process_heartbeat(&first)
            .expect("first heartbeat establishes snapshot");
        let mut second = heartbeat(None, 2, 1);
        second.queue_health.published_event_count = 5;
        assert_eq!(
            uptime_regressed.process_heartbeat(&second),
            Err(AssemblyFaultKind::HeartbeatStateRegressed)
        );

        let mut published_regressed = assembler(start);
        published_regressed
            .process_heartbeat(&first)
            .expect("first heartbeat establishes snapshot");
        let mut second = heartbeat(None, 3, 1);
        second.queue_health.published_event_count = 4;
        assert_eq!(
            published_regressed.process_heartbeat(&second),
            Err(AssemblyFaultKind::HeartbeatStateRegressed)
        );

        let mut unchanged_published = assembler(start);
        unchanged_published
            .process_heartbeat(&first)
            .expect("first heartbeat establishes snapshot");
        let mut second = heartbeat(None, 3, 1);
        second.queue_health.published_event_count = 5;
        assert_eq!(unchanged_published.process_heartbeat(&second), Ok(()));
    }

    #[test]
    fn assembler_rejects_unpinned_registry_at_construction() {
        let start = Instant::now();
        let result = CrossRouteAssembler::new(
            "epoch-1",
            "crebain",
            UnpinnedRegistry,
            AssemblerLimits::default(),
            start,
        );

        assert!(matches!(
            result,
            Err(AssemblerConfigError::Registry(
                RegistryViolation::RegistryNotPinned
            ))
        ));
    }

    #[test]
    fn assembler_rejects_noncanonical_registry_modality_order() {
        const CANONICAL: &[Modality] = &[Modality::Visual, Modality::Radar];
        let start = Instant::now();
        let registry = PolicyRegistry {
            policy: wire_policy(),
            expected_modalities: CANONICAL,
        };
        let mut assembler = assembler_with_registry(start, registry);
        let mut closure = empty_summary(1, 101);
        closure.expected_modalities = vec![Modality::Radar, Modality::Visual];

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::FrameSummary(closure)),
            start,
        );

        assert!(ready(&events).is_none());
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::UnexpectedModalities
            ))
        ));
    }

    #[test]
    fn assembler_enforces_registry_attempt_limit_before_closure() {
        let start = Instant::now();
        let registry = PolicyRegistry {
            policy: RegistryOpportunityPolicy {
                max_attempts_per_track_modality: 1,
                ..wire_policy()
            },
            expected_modalities: &[Modality::Visual],
        };
        let mut assembler = assembler_with_registry(start, registry);
        let mut first = outcome(1, 101);
        first.outcome = ModalityOutcomeKind::GateRejected;
        first.v1_expected = false;
        first.in_gate_count = 0;
        first.gate_evidence = Some(GateEvidence {
            method: GateMethod::Mahalanobis,
            d2: 9.0,
            threshold: 7.815,
        });
        first.consistency_projection = None;
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(first)),
            start,
        );
        let mut second = outcome(1, 101);
        second.attempt_index = 1;

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::ModalityOutcome(second)),
            start,
        );

        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::OpportunityLimitExceeded {
                    limit: RegistryPolicyLimit::AttemptsPerTrackModality,
                    maximum: 1,
                    received: 2,
                }
            ))
        ));
    }

    #[test]
    fn assembler_enforces_registry_summary_and_queue_limits() {
        let start = Instant::now();
        let registry = PolicyRegistry {
            policy: RegistryOpportunityPolicy {
                max_frame_inputs: 1,
                max_monitor_queue_events: 1,
                ..wire_policy()
            },
            expected_modalities: &[Modality::Visual],
        };
        let mut summary_assembler = assembler_with_registry(start, registry);
        let mut closure = empty_summary(1, 101);
        closure.input_count = 2;
        let summary_events = summary_assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::FrameSummary(closure)),
            start,
        );
        assert!(matches!(
            fault_kind(&summary_events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::OpportunityLimitExceeded {
                    limit: RegistryPolicyLimit::FrameInputs,
                    maximum: 1,
                    received: 2,
                }
            ))
        ));

        let mut heartbeat_assembler = assembler_with_registry(start, registry);
        let heartbeat_events = heartbeat_assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::Heartbeat(heartbeat(None, 1, 2))),
            start,
        );
        assert!(matches!(
            fault_kind(&heartbeat_events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::OpportunityLimitExceeded {
                    limit: RegistryPolicyLimit::MonitorQueueEvents,
                    maximum: 1,
                    received: 2,
                }
            ))
        ));
    }

    #[test]
    fn assembler_enforces_registry_active_track_and_outcome_limits() {
        let start = Instant::now();
        let registry = PolicyRegistry {
            policy: RegistryOpportunityPolicy {
                max_active_tracks: 1,
                max_outcomes_per_frame: 1,
                ..wire_policy()
            },
            expected_modalities: &[Modality::Visual],
        };

        let mut summary_assembler = assembler_with_registry(start, registry);
        let mut closure = empty_summary(1, 101);
        closure.active_track_count = 2;
        let summary_events = summary_assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::FrameSummary(closure)),
            start,
        );
        assert!(matches!(
            fault_kind(&summary_events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::OpportunityLimitExceeded {
                    limit: RegistryPolicyLimit::ActiveTracks,
                    maximum: 1,
                    received: 2,
                }
            ))
        ));

        let mut outcome_assembler = assembler_with_registry(start, registry);
        let mut rejected = outcome(1, 101);
        rejected.outcome = ModalityOutcomeKind::GateRejected;
        rejected.v1_expected = false;
        rejected.in_gate_count = 0;
        rejected.gate_evidence = Some(GateEvidence {
            method: GateMethod::Mahalanobis,
            d2: 9.0,
            threshold: 7.815,
        });
        rejected.consistency_projection = None;
        outcome_assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(rejected)),
            start,
        );
        let outcome_events = outcome_assembler.ingest_monitor_bytes(
            &monitor_bytes(
                2,
                ProducerEvent::ModalityMiss(ModalityMiss {
                    fusion_seq: 1,
                    fusion_timestamp_ms: 1_001,
                    frame_id: 10,
                    context_id: 20,
                    prior_id: 101,
                    track_id: 7,
                    modality: Modality::Visual,
                    reason: ModalityMissReason::NoInGateCandidate,
                }),
            ),
            start,
        );
        assert!(matches!(
            fault_kind(&outcome_events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::OpportunityLimitExceeded {
                    limit: RegistryPolicyLimit::OutcomesPerFrame,
                    maximum: 1,
                    received: 2,
                }
            ))
        ));

        let mut heartbeat_assembler = assembler_with_registry(start, registry);
        let mut oversized_heartbeat = heartbeat(None, 1, 1);
        oversized_heartbeat.active_track_count = 2;
        let heartbeat_events = heartbeat_assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::Heartbeat(oversized_heartbeat)),
            start,
        );
        assert!(matches!(
            fault_kind(&heartbeat_events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::OpportunityLimitExceeded {
                    limit: RegistryPolicyLimit::ActiveTracks,
                    maximum: 1,
                    received: 2,
                }
            ))
        ));
    }

    #[test]
    fn assembler_enforces_registry_cap_on_reconstructed_frozen_tracks() {
        let start = Instant::now();
        let registry = PolicyRegistry {
            policy: RegistryOpportunityPolicy {
                max_active_tracks: 1,
                ..wire_policy()
            },
            expected_modalities: &[Modality::Visual],
        };
        let mut assembler = assembler_with_registry(start, registry);
        let mut first = outcome(1, 101);
        first.outcome = ModalityOutcomeKind::UpdateRejected;
        first.v1_expected = false;
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(first)),
            start,
        );
        let mut second = outcome(1, 101);
        second.track_id = 8;
        second.outcome = ModalityOutcomeKind::UpdateRejected;
        second.v1_expected = false;
        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::ModalityOutcome(second)),
            start,
        );
        let mut closure = summary(1, 101);
        closure.outcome_count = 2;
        closure.v1_expected_count = 0;

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(3, ProducerEvent::FrameSummary(closure)),
            start,
        );

        assert!(ready(&events).is_none());
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::OpportunityLimitExceeded {
                    limit: RegistryPolicyLimit::ActiveTracks,
                    maximum: 1,
                    received: 2,
                }
            ))
        ));
    }

    #[test]
    fn assembler_enforces_registry_cap_on_transient_track_births() {
        let start = Instant::now();
        let registry = PolicyRegistry {
            policy: RegistryOpportunityPolicy {
                max_active_tracks: 1,
                ..wire_policy()
            },
            expected_modalities: &[Modality::Visual],
        };
        let mut assembler = assembler_with_registry(start, registry);
        let mut first = outcome(1, 101);
        first.outcome = ModalityOutcomeKind::TrackBirth;
        first.v1_expected = false;
        first.candidate_count = 0;
        first.in_gate_count = 0;
        first.gate_evidence = None;
        first.consistency_projection = None;
        assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::ModalityOutcome(first)),
            start,
        );
        let mut second = outcome(1, 101);
        second.track_id = 8;
        second.measurement_index = Some(1);
        second.outcome = ModalityOutcomeKind::TrackBirth;
        second.v1_expected = false;
        second.candidate_count = 0;
        second.in_gate_count = 0;
        second.gate_evidence = None;
        second.consistency_projection = None;
        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::ModalityOutcome(second)),
            start,
        );
        let mut closure = empty_summary(1, 101);
        closure.active_track_count = 1;
        closure.input_count = 2;
        closure.outcome_count = 2;

        let events = assembler.ingest_monitor_bytes(
            &monitor_bytes(3, ProducerEvent::FrameSummary(closure)),
            start,
        );

        assert!(ready(&events).is_none());
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::Registry(
                RegistryViolation::OpportunityLimitExceeded {
                    limit: RegistryPolicyLimit::ActiveTracks,
                    maximum: 1,
                    received: 2,
                }
            ))
        ));
    }

    #[test]
    fn assembler_heartbeat_cursor_must_equal_last_observable_summary() {
        let start = Instant::now();
        let mut mismatched = assembler(start);
        let events = mismatched.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::Heartbeat(heartbeat(Some(1), 1, 1))),
            start,
        );
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::HeartbeatLastFusionMismatch {
                expected: None,
                received: Some(1),
            })
        ));

        let mut exact = assembler(start);
        exact.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::FrameSummary(empty_summary(1, 101))),
            start,
        );
        let accepted = exact.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::Heartbeat(heartbeat(Some(1), 1, 1))),
            start,
        );
        assert!(accepted
            .iter()
            .any(|event| matches!(event, AssemblyEvent::HeartbeatAccepted { .. })));
    }

    #[test]
    fn assembler_next_deadline_is_earliest_fixed_boundary_and_none_after_fault() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        assert_eq!(
            assembler.next_deadline_at(),
            Some(start + Duration::from_secs(30))
        );

        assembler.ingest_observation_bytes(
            &observation_bytes(observation(1, 101)),
            start + Duration::from_secs(1),
        );
        assert_eq!(
            assembler.next_deadline_at(),
            Some(start + Duration::from_secs(6))
        );

        assembler.ingest_monitor_bytes(
            &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
            start + Duration::from_secs(2),
        );
        let gap_deadline = start + Duration::from_secs(3);
        assert_eq!(assembler.next_deadline_at(), Some(gap_deadline));
        assert!(assembler
            .advance_time(gap_deadline - Duration::from_millis(1))
            .is_empty());
        let events = assembler.advance_time(gap_deadline);
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::MonitorSequenceGap { .. })
        ));
        assert_eq!(assembler.next_deadline_at(), None);
    }

    #[test]
    fn assembler_heartbeat_uses_local_receipt_deadline() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let heartbeat = Heartbeat {
            producer_timestamp_ms: 9_999_999,
            uptime_ms: 5_000,
            declared_interval_ms: 1_000,
            declared_deadline_ms: 30_000,
            last_fusion_seq: None,
            active_track_count: 0,
            degraded: false,
            queue_health: QueueHealth {
                capacity: 1,
                depth: 0,
                dropped_event_count: 0,
                published_event_count: 0,
            },
        };
        let accepted = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::Heartbeat(heartbeat)),
            start + Duration::from_secs(5),
        );
        assert!(accepted
            .iter()
            .any(|event| matches!(event, AssemblyEvent::HeartbeatAccepted { .. })));
        assert_eq!(
            assembler.last_heartbeat_receipt(),
            Some(start + Duration::from_secs(5))
        );
        assert!(assembler
            .advance_time(start + Duration::from_secs(34))
            .is_empty());
        let expired = assembler.advance_time(start + Duration::from_secs(35));
        assert!(matches!(
            fault_kind(&expired),
            Some(AssemblyFaultKind::HeartbeatDeadlineExpired)
        ));
    }

    #[test]
    fn assembler_heartbeat_silence_is_terminal_and_late_input_cannot_repair_it() {
        let start = Instant::now();
        let mut assembler = assembler(start);
        let events = assembler.advance_time(start + Duration::from_secs(30));
        assert!(matches!(
            fault_kind(&events),
            Some(AssemblyFaultKind::HeartbeatDeadlineExpired)
        ));
        let heartbeat = Heartbeat {
            producer_timestamp_ms: 1,
            uptime_ms: 1,
            declared_interval_ms: 1_000,
            declared_deadline_ms: 30_000,
            last_fusion_seq: None,
            active_track_count: 0,
            degraded: false,
            queue_health: QueueHealth {
                capacity: 1,
                depth: 0,
                dropped_event_count: 0,
                published_event_count: 0,
            },
        };
        let later = assembler.ingest_monitor_bytes(
            &monitor_bytes(1, ProducerEvent::Heartbeat(heartbeat)),
            start + Duration::from_secs(30),
        );
        assert!(later.is_empty());
        assert!(assembler.fault().is_some());
    }
}
