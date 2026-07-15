//! Coherent assessment outcomes and typed failures.
//!
//! A completed assessment is either nominal, anomalous, or insufficient. Only
//! nominal and anomalous assessments imply [`StreamState::Ready`]. Authentication,
//! compatibility, ordering, reset, terminal-state, resource, backend, and internal
//! faults are [`AssessmentFailure`] values rather than successful outcomes.

use std::fmt;

use thiserror::Error;

use crate::Modality;

const MAX_DIAGNOSTIC_BYTES: usize = 256;

/// Construction failure for a bounded assessment value.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutcomeError {
    /// An attribution requires at least one modality.
    #[error("attributed evidence requires at least one modality")]
    EmptyModalitySet,
    /// One modality occurred more than once.
    #[error("modality {modality:?} occurs more than once")]
    DuplicateModality {
        /// Repeated modality.
        modality: Modality,
    },
    /// A modality collection exceeded the closed modality vocabulary.
    /// This takes precedence after every distinct modality has been retained.
    #[error("modality set has more than {maximum} entries")]
    TooManyModalities {
        /// Inclusive collection bound.
        maximum: usize,
    },
    /// An unclassified anomaly requires at least one anomaly reason.
    #[error("anomaly-reason set must not be empty")]
    EmptyAnomalyReasons,
    /// One anomaly reason occurred more than once.
    #[error("anomaly reason {reason:?} occurs more than once")]
    DuplicateAnomalyReason {
        /// Repeated reason.
        reason: AnomalyReason,
    },
    /// An anomaly-reason collection exceeded the closed vocabulary.
    /// This takes precedence after every distinct anomaly reason has been retained.
    #[error("anomaly-reason set has more than {maximum} entries")]
    TooManyAnomalyReasons {
        /// Inclusive collection bound.
        maximum: usize,
    },
    /// Unavailability requires at least one unavailability reason.
    #[error("unavailability-reason set must not be empty")]
    EmptyUnavailabilityReasons,
    /// One unavailability reason occurred more than once.
    #[error("unavailability reason {reason:?} occurs more than once")]
    DuplicateUnavailabilityReason {
        /// Repeated reason.
        reason: UnavailabilityReason,
    },
    /// An unavailability-reason collection exceeded the closed vocabulary.
    /// This takes precedence after every distinct unavailability reason is retained.
    #[error("unavailability-reason set has more than {maximum} entries")]
    TooManyUnavailabilityReasons {
        /// Inclusive collection bound.
        maximum: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanonicalSetError<T> {
    Duplicate(T),
    TooMany,
}

fn canonical_unique<T>(
    values: impl IntoIterator<Item = T>,
    maximum: usize,
    rank: impl Fn(T) -> u8,
) -> Result<Vec<T>, CanonicalSetError<T>>
where
    T: Copy + Eq,
{
    let mut canonical = Vec::with_capacity(maximum);
    for value in values {
        if canonical.len() == maximum {
            return Err(CanonicalSetError::TooMany);
        }
        if canonical.contains(&value) {
            return Err(CanonicalSetError::Duplicate(value));
        }
        canonical.push(value);
    }
    canonical.sort_unstable_by_key(|value| rank(*value));
    Ok(canonical)
}

const fn modality_rank(modality: Modality) -> u8 {
    match modality {
        Modality::Visual => 0,
        Modality::Thermal => 1,
        Modality::Acoustic => 2,
        Modality::Radar => 3,
        Modality::Lidar => 4,
        Modality::RadioFrequency => 5,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModalitySet(Vec<Modality>);

impl ModalitySet {
    fn try_new(modalities: impl IntoIterator<Item = Modality>) -> Result<Self, OutcomeError> {
        canonical_unique(modalities, Modality::ALL.len(), modality_rank)
            .map(Self)
            .map_err(|error| match error {
                CanonicalSetError::Duplicate(modality) => {
                    OutcomeError::DuplicateModality { modality }
                }
                CanonicalSetError::TooMany => OutcomeError::TooManyModalities {
                    maximum: Modality::ALL.len(),
                },
            })
    }

    fn as_slice(&self) -> &[Modality] {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Canonically ordered modality collection that cannot be empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonEmptyModalitySet(ModalitySet);

impl NonEmptyModalitySet {
    /// Constructs a nonempty, bounded, unique modality set.
    ///
    /// Input order is not semantic. The retained order is the frozen order
    /// `visual`, `thermal`, `acoustic`, `radar`, `lidar`, `radiofrequency`.
    ///
    /// # Errors
    ///
    /// Returns [`OutcomeError::EmptyModalitySet`] for empty input and a typed
    /// construction error for duplicate or oversized input.
    pub fn try_new(modalities: impl IntoIterator<Item = Modality>) -> Result<Self, OutcomeError> {
        let modalities = ModalitySet::try_new(modalities)?;
        if modalities.is_empty() {
            return Err(OutcomeError::EmptyModalitySet);
        }
        Ok(Self(modalities))
    }

    /// Returns the canonical nonempty modality slice.
    pub fn as_slice(&self) -> &[Modality] {
        self.0.as_slice()
    }
}

/// Exact statistical state of one stream generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamState {
    /// No complete frame is retained in the current generation.
    Empty,
    /// Valid complete frames are accumulating below the readiness minimum.
    Collecting,
    /// Every enabled detector has enough complete contiguous evidence.
    Ready,
    /// The latest committed position explicitly lacks assessable evidence.
    Unavailable,
    /// A receiver-owned deadline expired and the epoch requires rollover.
    TimedOut,
}

/// Closed reason for an empty statistical suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmptyReason {
    /// No complete frame has been accepted in the current generation.
    NoCompleteFrame,
}

/// Closed reason for evidence that is still collecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CollectingReason {
    /// Fewer complete contiguous samples than the readiness minimum are retained.
    InsufficientSamples,
}

/// Closed reason for a receiver-owned timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeoutReason {
    /// The authenticated heartbeat deadline expired.
    HeartbeatDeadlineExpired,
    /// The bounded source-reorder deadline expired.
    ReorderDeadlineExpired,
    /// The deadline for completing a staged fusion frame expired.
    IncompleteFrameDeadlineExpired,
}

/// Closed evidence reason for an anomaly that could not be localized more narrowly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyReason {
    /// Independent enabled detectors produced conflicting positive evidence.
    ConflictingEvidence,
    /// Evidence indicates a low-side distributional shift.
    LowSideShift,
    /// Positive evidence exists but does not support a unique attribution.
    AmbiguousAttribution,
}

impl AnomalyReason {
    const ALL: [Self; 3] = [
        Self::ConflictingEvidence,
        Self::LowSideShift,
        Self::AmbiguousAttribution,
    ];

    const fn canonical_rank(self) -> u8 {
        match self {
            Self::ConflictingEvidence => 0,
            Self::LowSideShift => 1,
            Self::AmbiguousAttribution => 2,
        }
    }
}

/// Closed reason for an explicitly unavailable statistical suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnavailabilityReason {
    /// One or more expected modalities did not complete the fusion frame.
    MissingModalities,
    /// An authenticated, compatible evidence prerequisite reported no evidence.
    /// Backend execution faults are [`AssessmentFailure`] values instead.
    UnavailablePrerequisite,
    /// Previously retained evidence exceeded its admissible freshness window.
    StaleRetainedEvidence,
    /// Lifecycle closure proved that a required measurement was missed.
    MeasurementMiss,
    /// Authenticated lifecycle closure proved that a statistical measurement
    /// opportunity yielded no assessable evidence. Authorization and protocol
    /// rejections are [`AssessmentFailure`] values instead.
    OpportunityRejected,
}

impl UnavailabilityReason {
    const ALL: [Self; 5] = [
        Self::MissingModalities,
        Self::UnavailablePrerequisite,
        Self::StaleRetainedEvidence,
        Self::MeasurementMiss,
        Self::OpportunityRejected,
    ];

    const fn canonical_rank(self) -> u8 {
        match self {
            Self::MissingModalities => 0,
            Self::UnavailablePrerequisite => 1,
            Self::StaleRetainedEvidence => 2,
            Self::MeasurementMiss => 3,
            Self::OpportunityRejected => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AnomalyReasons(Vec<AnomalyReason>);

impl AnomalyReasons {
    fn try_new(reasons: impl IntoIterator<Item = AnomalyReason>) -> Result<Self, OutcomeError> {
        let canonical = canonical_unique(
            reasons,
            AnomalyReason::ALL.len(),
            AnomalyReason::canonical_rank,
        )
        .map_err(|error| match error {
            CanonicalSetError::Duplicate(reason) => OutcomeError::DuplicateAnomalyReason { reason },
            CanonicalSetError::TooMany => OutcomeError::TooManyAnomalyReasons {
                maximum: AnomalyReason::ALL.len(),
            },
        })?;
        if canonical.is_empty() {
            return Err(OutcomeError::EmptyAnomalyReasons);
        }
        Ok(Self(canonical))
    }

    fn as_slice(&self) -> &[AnomalyReason] {
        &self.0
    }
}

/// Canonically ordered, nonempty reasons for explicit unavailability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnavailabilityReasons(Vec<UnavailabilityReason>);

impl UnavailabilityReasons {
    pub(crate) fn unavailable_prerequisite() -> Self {
        Self(vec![UnavailabilityReason::UnavailablePrerequisite])
    }

    /// Constructs a bounded, unique, nonempty unavailability-reason set.
    ///
    /// Input order is not semantic. The returned slice follows the frozen rank
    /// declared by [`UnavailabilityReason`].
    ///
    /// # Errors
    ///
    /// Returns a typed construction error for empty, duplicate, or oversized input.
    pub fn try_new(
        reasons: impl IntoIterator<Item = UnavailabilityReason>,
    ) -> Result<Self, OutcomeError> {
        let canonical = canonical_unique(
            reasons,
            UnavailabilityReason::ALL.len(),
            UnavailabilityReason::canonical_rank,
        )
        .map_err(|error| match error {
            CanonicalSetError::Duplicate(reason) => {
                OutcomeError::DuplicateUnavailabilityReason { reason }
            }
            CanonicalSetError::TooMany => OutcomeError::TooManyUnavailabilityReasons {
                maximum: UnavailabilityReason::ALL.len(),
            },
        })?;
        if canonical.is_empty() {
            return Err(OutcomeError::EmptyUnavailabilityReasons);
        }
        Ok(Self(canonical))
    }

    /// Returns the canonical nonempty reason slice.
    pub fn as_slice(&self) -> &[UnavailabilityReason] {
        &self.0
    }
}

/// Validated payload for an anomaly that cannot be attributed more narrowly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnclassifiedAnomaly {
    channels: ModalitySet,
    reasons: AnomalyReasons,
}

impl UnclassifiedAnomaly {
    /// Constructs bounded unclassified anomaly evidence.
    ///
    /// The modality set may be empty when localization failed. The anomaly-reason
    /// set must be nonempty. Both collections reject duplicates and are retained in
    /// their explicit frozen canonical order.
    ///
    /// # Errors
    ///
    /// Returns a typed construction error for a duplicate or oversized modality
    /// set, or an empty, duplicate, or oversized anomaly-reason set.
    pub fn try_new(
        channels: impl IntoIterator<Item = Modality>,
        reasons: impl IntoIterator<Item = AnomalyReason>,
    ) -> Result<Self, OutcomeError> {
        Ok(Self {
            channels: ModalitySet::try_new(channels)?,
            reasons: AnomalyReasons::try_new(reasons)?,
        })
    }

    /// Returns canonically ordered affected modalities, possibly empty.
    pub fn affected_modalities(&self) -> &[Modality] {
        self.channels.as_slice()
    }

    /// Returns canonically ordered, nonempty anomaly reasons.
    pub fn reasons(&self) -> &[AnomalyReason] {
        self.reasons.as_slice()
    }
}

/// Positive anomaly evidence. Every variant implies [`StreamState::Ready`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnomalyEvidence {
    /// A nonempty subset has localized inconsistency evidence.
    Attributed(NonEmptyModalitySet),
    /// Multiple modalities show broad degradation evidence.
    BroadDegradation,
    /// Positive evidence exists but cannot be classified more narrowly.
    Unclassified(UnclassifiedAnomaly),
}

/// Successful but non-ready assessment result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Insufficiency {
    /// No complete frame is retained in the current generation.
    Empty(EmptyReason),
    /// Valid evidence is accumulating below readiness.
    Collecting(CollectingReason),
    /// The latest committed position explicitly lacks assessable evidence.
    Unavailable(UnavailabilityReasons),
    /// A receiver-owned deadline expired.
    TimedOut(TimeoutReason),
}

impl Insufficiency {
    /// Returns the one non-ready state encoded by this insufficiency payload.
    pub const fn state(&self) -> StreamState {
        match self {
            Self::Empty(_) => StreamState::Empty,
            Self::Collecting(_) => StreamState::Collecting,
            Self::Unavailable(_) => StreamState::Unavailable,
            Self::TimedOut(_) => StreamState::TimedOut,
        }
    }
}

/// A coherent completed assessment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AssessmentOutcome {
    /// All enabled checks were within their documented acceptance regions.
    Nominal,
    /// Positive anomaly evidence from a ready stream.
    Anomaly(AnomalyEvidence),
    /// A successful fail-closed assessment from a non-ready stream.
    Insufficient(Insufficiency),
}

impl AssessmentOutcome {
    /// Returns the exact statistical state implied by this outcome.
    pub const fn state(&self) -> StreamState {
        match self {
            Self::Nominal | Self::Anomaly(_) => StreamState::Ready,
            Self::Insufficient(insufficiency) => insufficiency.state(),
        }
    }
}

/// Stable category of a detector failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureKind {
    /// Caller-controlled data or configuration was invalid.
    InvalidInput,
    /// Producer identity could not be authenticated.
    Unauthenticated,
    /// An authenticated principal lacked authority for the operation.
    Unauthorized,
    /// Required versioned semantics were not supported.
    Incompatible,
    /// Input violated stream identity or accepted temporal order.
    TemporalOrIdentity,
    /// A validated discontinuity requires an explicit reset receipt.
    RequiresReset,
    /// The epoch or adapter is terminal and requires epoch rollover.
    Terminal,
    /// A declared finite resource bound was reached.
    ResourceExhausted,
    /// A selected external numerical or statistical backend failed.
    BackendFault,
    /// An implementation invariant failed independently of caller input.
    InternalFault,
}

macro_rules! define_failure_codes {
    ($( $(#[$variant_meta:meta])* $variant:ident ),+ $(,)?) => {
        /// Version-scoped machine code for a failed detector operation.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum FailureCode {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl FailureCode {
            #[cfg(test)]
            const ALL: &[Self] = &[$(Self::$variant),+];
        }
    };
}

define_failure_codes! {
    /// Detector configuration was outside its accepted domain.
    InvalidConfiguration,
    /// Observation structure or values were invalid.
    InvalidObservation,
    /// A caller supplied a non-finite numeric input.
    NonFiniteInput,
    /// Producer authentication was absent or invalid.
    UnauthenticatedProducer,
    /// Producer or caller was not authorized for the requested transition.
    UnauthorizedOperation,
    /// Report schema semantics were unsupported.
    UnsupportedSchema,
    /// Protocol semantics were unsupported.
    UnsupportedProtocol,
    /// Evidence was older than the accepted high-water mark.
    StaleInput,
    /// An already accepted input was repeated.
    DuplicateInput,
    /// Input order regressed or skipped an unauthorized position.
    ReorderedInput,
    /// Previously accepted evidence was replayed.
    ReplayedInput,
    /// Input named a different session.
    WrongSession,
    /// Input named a different or closed epoch.
    WrongEpoch,
    /// Input named a different stream.
    WrongStream,
    /// Input named a different state generation.
    WrongGeneration,
    /// The accepted discontinuity requires an explicit reset before more data.
    ResetRequired,
    /// The epoch reached a terminal statistical state.
    EpochTerminal,
    /// The transport adapter reached its orthogonal terminal fault state.
    AdapterFaulted,
    /// The configured track bound was reached.
    TrackCapacity,
    /// The configured payload byte bound was reached.
    PayloadCapacity,
    /// A fallible bounded allocation failed.
    AllocationFailure,
    /// A JSON-safe counter had no representable successor.
    CounterExhausted,
    /// A numerical or statistical backend failed on validated input.
    NumericBackendFailure,
    /// Versioned serialization failed on validated report material.
    SerializationFailure,
    /// Internal state violated an invariant after validated input.
    InvariantViolation,
}

impl FailureCode {
    /// Returns the stable failure category implied by this code.
    pub const fn kind(self) -> FailureKind {
        match self {
            Self::InvalidConfiguration | Self::InvalidObservation | Self::NonFiniteInput => {
                FailureKind::InvalidInput
            }
            Self::UnauthenticatedProducer => FailureKind::Unauthenticated,
            Self::UnauthorizedOperation => FailureKind::Unauthorized,
            Self::UnsupportedSchema | Self::UnsupportedProtocol => FailureKind::Incompatible,
            Self::StaleInput
            | Self::DuplicateInput
            | Self::ReorderedInput
            | Self::ReplayedInput
            | Self::WrongSession
            | Self::WrongEpoch
            | Self::WrongStream
            | Self::WrongGeneration => FailureKind::TemporalOrIdentity,
            Self::ResetRequired => FailureKind::RequiresReset,
            Self::EpochTerminal | Self::AdapterFaulted => FailureKind::Terminal,
            Self::TrackCapacity
            | Self::PayloadCapacity
            | Self::AllocationFailure
            | Self::CounterExhausted => FailureKind::ResourceExhausted,
            Self::NumericBackendFailure => FailureKind::BackendFault,
            Self::SerializationFailure | Self::InvariantViolation => FailureKind::InternalFault,
        }
    }
}

impl fmt::Display for FailureCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::InvalidObservation => "invalid_observation",
            Self::NonFiniteInput => "non_finite_input",
            Self::UnauthenticatedProducer => "unauthenticated_producer",
            Self::UnauthorizedOperation => "unauthorized_operation",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::StaleInput => "stale_input",
            Self::DuplicateInput => "duplicate_input",
            Self::ReorderedInput => "reordered_input",
            Self::ReplayedInput => "replayed_input",
            Self::WrongSession => "wrong_session",
            Self::WrongEpoch => "wrong_epoch",
            Self::WrongStream => "wrong_stream",
            Self::WrongGeneration => "wrong_generation",
            Self::ResetRequired => "reset_required",
            Self::EpochTerminal => "epoch_terminal",
            Self::AdapterFaulted => "adapter_faulted",
            Self::TrackCapacity => "track_capacity",
            Self::PayloadCapacity => "payload_capacity",
            Self::AllocationFailure => "allocation_failure",
            Self::CounterExhausted => "counter_exhausted",
            Self::NumericBackendFailure => "numeric_backend_failure",
            Self::SerializationFailure => "serialization_failure",
            Self::InvariantViolation => "invariant_violation",
        };
        formatter.write_str(value)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Diagnostic(String);

impl Diagnostic {
    fn sanitized(input: &str) -> Self {
        let mut value = String::with_capacity(input.len().min(MAX_DIAGNOSTIC_BYTES));
        let mut previous_was_space = true;

        for character in input.chars().take(MAX_DIAGNOSTIC_BYTES) {
            let sanitized = if character.is_ascii_graphic() {
                character
            } else if character.is_whitespace() || character.is_control() {
                ' '
            } else {
                '?'
            };

            if sanitized == ' ' {
                if previous_was_space {
                    continue;
                }
                previous_was_space = true;
            } else {
                previous_was_space = false;
            }

            if value.len() >= MAX_DIAGNOSTIC_BYTES {
                break;
            }
            value.push(sanitized);
        }

        if value.ends_with(' ') {
            value.pop();
        }
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed failure returned when no coherent assessment outcome can be produced.
///
/// Equality and display use only the closed machine code. A crate-private
/// diagnostic may be attached for debugging, but is sanitized, bounded, and is
/// intentionally absent from display, equality, and canonical assessment material.
/// The diagnostic is visible only through the explicit [`fmt::Debug`] representation.
#[derive(Clone, Error)]
#[error("{code}")]
pub struct AssessmentFailure {
    code: FailureCode,
    diagnostic: Diagnostic,
}

impl AssessmentFailure {
    /// Constructs a failure with no diagnostic detail.
    pub fn new(code: FailureCode) -> Self {
        Self::with_diagnostic(code, "")
    }

    pub(crate) fn with_diagnostic(code: FailureCode, diagnostic: &str) -> Self {
        Self {
            code,
            diagnostic: Diagnostic::sanitized(diagnostic),
        }
    }

    /// Returns the stable machine failure code.
    pub const fn code(&self) -> FailureCode {
        self.code
    }

    /// Returns the stable high-level failure category.
    pub const fn kind(&self) -> FailureKind {
        self.code.kind()
    }
}

impl fmt::Debug for AssessmentFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssessmentFailure")
            .field("code", &self.code)
            .field("diagnostic", &self.diagnostic.as_str())
            .finish()
    }
}

impl PartialEq for AssessmentFailure {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl Eq for AssessmentFailure {}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn unavailability_reasons() -> UnavailabilityReasons {
        UnavailabilityReasons::try_new([UnavailabilityReason::MissingModalities]).unwrap()
    }

    fn all_failure_cases() -> [(FailureCode, FailureKind, &'static str); 25] {
        [
            (
                FailureCode::InvalidConfiguration,
                FailureKind::InvalidInput,
                "invalid_configuration",
            ),
            (
                FailureCode::InvalidObservation,
                FailureKind::InvalidInput,
                "invalid_observation",
            ),
            (
                FailureCode::NonFiniteInput,
                FailureKind::InvalidInput,
                "non_finite_input",
            ),
            (
                FailureCode::UnauthenticatedProducer,
                FailureKind::Unauthenticated,
                "unauthenticated_producer",
            ),
            (
                FailureCode::UnauthorizedOperation,
                FailureKind::Unauthorized,
                "unauthorized_operation",
            ),
            (
                FailureCode::UnsupportedSchema,
                FailureKind::Incompatible,
                "unsupported_schema",
            ),
            (
                FailureCode::UnsupportedProtocol,
                FailureKind::Incompatible,
                "unsupported_protocol",
            ),
            (
                FailureCode::StaleInput,
                FailureKind::TemporalOrIdentity,
                "stale_input",
            ),
            (
                FailureCode::DuplicateInput,
                FailureKind::TemporalOrIdentity,
                "duplicate_input",
            ),
            (
                FailureCode::ReorderedInput,
                FailureKind::TemporalOrIdentity,
                "reordered_input",
            ),
            (
                FailureCode::ReplayedInput,
                FailureKind::TemporalOrIdentity,
                "replayed_input",
            ),
            (
                FailureCode::WrongSession,
                FailureKind::TemporalOrIdentity,
                "wrong_session",
            ),
            (
                FailureCode::WrongEpoch,
                FailureKind::TemporalOrIdentity,
                "wrong_epoch",
            ),
            (
                FailureCode::WrongStream,
                FailureKind::TemporalOrIdentity,
                "wrong_stream",
            ),
            (
                FailureCode::WrongGeneration,
                FailureKind::TemporalOrIdentity,
                "wrong_generation",
            ),
            (
                FailureCode::ResetRequired,
                FailureKind::RequiresReset,
                "reset_required",
            ),
            (
                FailureCode::EpochTerminal,
                FailureKind::Terminal,
                "epoch_terminal",
            ),
            (
                FailureCode::AdapterFaulted,
                FailureKind::Terminal,
                "adapter_faulted",
            ),
            (
                FailureCode::TrackCapacity,
                FailureKind::ResourceExhausted,
                "track_capacity",
            ),
            (
                FailureCode::PayloadCapacity,
                FailureKind::ResourceExhausted,
                "payload_capacity",
            ),
            (
                FailureCode::AllocationFailure,
                FailureKind::ResourceExhausted,
                "allocation_failure",
            ),
            (
                FailureCode::CounterExhausted,
                FailureKind::ResourceExhausted,
                "counter_exhausted",
            ),
            (
                FailureCode::NumericBackendFailure,
                FailureKind::BackendFault,
                "numeric_backend_failure",
            ),
            (
                FailureCode::SerializationFailure,
                FailureKind::InternalFault,
                "serialization_failure",
            ),
            (
                FailureCode::InvariantViolation,
                FailureKind::InternalFault,
                "invariant_violation",
            ),
        ]
    }

    #[test]
    fn nominal_outcome_implies_ready() {
        assert_eq!(AssessmentOutcome::Nominal.state(), StreamState::Ready);
    }

    #[test]
    fn every_anomaly_variant_implies_ready() {
        let cases = [
            AssessmentOutcome::Anomaly(AnomalyEvidence::Attributed(
                NonEmptyModalitySet::try_new([Modality::Radar]).unwrap(),
            )),
            AssessmentOutcome::Anomaly(AnomalyEvidence::BroadDegradation),
            AssessmentOutcome::Anomaly(AnomalyEvidence::Unclassified(
                UnclassifiedAnomaly::try_new([], [AnomalyReason::AmbiguousAttribution]).unwrap(),
            )),
        ];

        assert!(cases
            .iter()
            .all(|outcome| outcome.state() == StreamState::Ready));
    }

    #[test]
    fn every_insufficiency_variant_implies_its_exact_nonready_state() {
        let cases = [
            (
                Insufficiency::Empty(EmptyReason::NoCompleteFrame),
                StreamState::Empty,
            ),
            (
                Insufficiency::Collecting(CollectingReason::InsufficientSamples),
                StreamState::Collecting,
            ),
            (
                Insufficiency::Unavailable(unavailability_reasons()),
                StreamState::Unavailable,
            ),
            (
                Insufficiency::TimedOut(TimeoutReason::HeartbeatDeadlineExpired),
                StreamState::TimedOut,
            ),
        ];

        assert!(cases.iter().all(|(insufficiency, expected)| {
            AssessmentOutcome::Insufficient(insufficiency.clone()).state() == *expected
                && *expected != StreamState::Ready
        }));
    }

    #[test]
    fn attributed_evidence_rejects_empty_modalities() {
        assert_eq!(
            NonEmptyModalitySet::try_new([]),
            Err(OutcomeError::EmptyModalitySet)
        );
    }

    #[test]
    fn modality_sets_reject_duplicates_before_the_vocabulary_bound() {
        assert_eq!(
            NonEmptyModalitySet::try_new([Modality::Radar, Modality::Radar]),
            Err(OutcomeError::DuplicateModality {
                modality: Modality::Radar,
            })
        );
    }

    #[test]
    fn modality_sets_reject_input_beyond_the_closed_vocabulary() {
        let mut modalities = Modality::ALL.to_vec();
        modalities.push(Modality::Visual);

        assert_eq!(
            NonEmptyModalitySet::try_new(modalities),
            Err(OutcomeError::TooManyModalities {
                maximum: Modality::ALL.len(),
            })
        );
    }

    #[test]
    fn modality_sets_use_the_explicit_frozen_rank() {
        let modalities = NonEmptyModalitySet::try_new([
            Modality::RadioFrequency,
            Modality::Lidar,
            Modality::Radar,
            Modality::Acoustic,
            Modality::Thermal,
            Modality::Visual,
        ])
        .unwrap();

        assert_eq!(modalities.as_slice(), &Modality::ALL);
    }

    #[test]
    fn unclassified_anomaly_allows_an_empty_localization_set() {
        let evidence =
            UnclassifiedAnomaly::try_new([], [AnomalyReason::AmbiguousAttribution]).unwrap();

        assert!(evidence.affected_modalities().is_empty());
    }

    #[test]
    fn unclassified_anomaly_exposes_nonempty_modalities_in_canonical_order() {
        let evidence = UnclassifiedAnomaly::try_new(
            [Modality::Radar, Modality::Visual],
            [AnomalyReason::AmbiguousAttribution],
        )
        .unwrap();

        assert_eq!(
            evidence.affected_modalities(),
            &[Modality::Visual, Modality::Radar]
        );
    }

    #[test]
    fn unclassified_anomaly_rejects_empty_reasons() {
        assert_eq!(
            UnclassifiedAnomaly::try_new([Modality::Visual], []),
            Err(OutcomeError::EmptyAnomalyReasons)
        );
    }

    #[test]
    fn anomaly_reasons_reject_duplicates_before_the_vocabulary_bound() {
        assert_eq!(
            UnclassifiedAnomaly::try_new(
                [],
                [
                    AnomalyReason::ConflictingEvidence,
                    AnomalyReason::ConflictingEvidence,
                ],
            ),
            Err(OutcomeError::DuplicateAnomalyReason {
                reason: AnomalyReason::ConflictingEvidence,
            })
        );
    }

    #[test]
    fn anomaly_reasons_reject_input_beyond_the_closed_vocabulary() {
        let mut reasons = AnomalyReason::ALL.to_vec();
        reasons.push(AnomalyReason::ConflictingEvidence);

        assert_eq!(
            UnclassifiedAnomaly::try_new([], reasons),
            Err(OutcomeError::TooManyAnomalyReasons {
                maximum: AnomalyReason::ALL.len(),
            })
        );
    }

    #[test]
    fn anomaly_reasons_use_the_explicit_frozen_rank() {
        let evidence = UnclassifiedAnomaly::try_new(
            [],
            [
                AnomalyReason::AmbiguousAttribution,
                AnomalyReason::LowSideShift,
                AnomalyReason::ConflictingEvidence,
            ],
        )
        .unwrap();

        assert_eq!(evidence.reasons(), &AnomalyReason::ALL);
    }

    #[test]
    fn unavailability_reasons_reject_empty_input() {
        assert_eq!(
            UnavailabilityReasons::try_new([]),
            Err(OutcomeError::EmptyUnavailabilityReasons)
        );
    }

    #[test]
    fn unavailability_reasons_reject_duplicates_before_the_vocabulary_bound() {
        assert_eq!(
            UnavailabilityReasons::try_new([
                UnavailabilityReason::MeasurementMiss,
                UnavailabilityReason::MeasurementMiss,
            ]),
            Err(OutcomeError::DuplicateUnavailabilityReason {
                reason: UnavailabilityReason::MeasurementMiss,
            })
        );
    }

    #[test]
    fn unavailability_reasons_reject_input_beyond_the_closed_vocabulary() {
        let mut reasons = UnavailabilityReason::ALL.to_vec();
        reasons.push(UnavailabilityReason::MissingModalities);

        assert_eq!(
            UnavailabilityReasons::try_new(reasons),
            Err(OutcomeError::TooManyUnavailabilityReasons {
                maximum: UnavailabilityReason::ALL.len(),
            })
        );
    }

    #[test]
    fn unavailability_reasons_use_the_explicit_frozen_rank() {
        let reasons = UnavailabilityReasons::try_new([
            UnavailabilityReason::OpportunityRejected,
            UnavailabilityReason::MeasurementMiss,
            UnavailabilityReason::StaleRetainedEvidence,
            UnavailabilityReason::UnavailablePrerequisite,
            UnavailabilityReason::MissingModalities,
        ])
        .unwrap();

        assert_eq!(reasons.as_slice(), &UnavailabilityReason::ALL);
    }

    #[test]
    fn every_failure_code_has_the_expected_kind_and_machine_label() {
        let cases = all_failure_cases();
        assert_eq!(cases.len(), FailureCode::ALL.len());

        for (index, (code, expected_kind, expected_label)) in cases.into_iter().enumerate() {
            assert_eq!(code, FailureCode::ALL[index]);
            assert!(!FailureCode::ALL[..index].contains(&code));
            assert_eq!(code.kind(), expected_kind, "unexpected kind for {code:?}");
            assert_eq!(
                code.to_string(),
                expected_label,
                "unexpected label for {code:?}"
            );
        }
    }

    #[test]
    fn failure_diagnostics_are_bounded_and_sanitized() {
        let input = format!("  line one\nβ\t\u{1b}[31m{}  ", "x".repeat(300));
        let failure = AssessmentFailure::with_diagnostic(FailureCode::InvalidObservation, &input);
        let diagnostic = failure.diagnostic.as_str();

        assert!(diagnostic.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(!diagnostic.contains(['\n', '\r', '\t', '\u{1b}', 'β']));
        assert!(!diagnostic.starts_with(' '));
        assert!(!diagnostic.ends_with(' '));
    }

    #[test]
    fn failure_diagnostic_sanitization_has_exact_character_and_length_semantics() {
        assert_eq!(Diagnostic::sanitized("alpha").as_str(), "alpha");
        assert_eq!(Diagnostic::sanitized("a\u{00a0}b").as_str(), "a b");
        assert_eq!(Diagnostic::sanitized("a\u{1b}b").as_str(), "a b");
        assert_eq!(Diagnostic::sanitized("a\u{03b2}b").as_str(), "a?b");

        let oversized = "x".repeat(MAX_DIAGNOSTIC_BYTES + 17);
        let bounded = Diagnostic::sanitized(&oversized);
        assert_eq!(bounded.as_str().len(), MAX_DIAGNOSTIC_BYTES);
        assert!(bounded.as_str().bytes().all(|byte| byte == b'x'));
    }

    #[test]
    fn failure_diagnostics_do_not_change_machine_equality_or_display() {
        let left = AssessmentFailure::with_diagnostic(
            FailureCode::UnsupportedProtocol,
            "attacker-controlled detail",
        );
        let right = AssessmentFailure::new(FailureCode::UnsupportedProtocol);

        assert_eq!(left, right);
        assert_eq!(left.to_string(), "unsupported_protocol");
    }

    #[test]
    fn failure_equality_and_debug_expose_the_exact_machine_contract() {
        let failure = AssessmentFailure::with_diagnostic(FailureCode::InvalidObservation, "alpha");
        let other = AssessmentFailure::new(FailureCode::UnsupportedProtocol);

        assert_ne!(failure, other);
        assert_eq!(
            format!("{failure:?}"),
            "AssessmentFailure { code: InvalidObservation, diagnostic: \"alpha\" }"
        );
    }

    #[test]
    fn successful_reason_vocabularies_are_exact() {
        assert_eq!(
            AnomalyReason::ALL,
            [
                AnomalyReason::ConflictingEvidence,
                AnomalyReason::LowSideShift,
                AnomalyReason::AmbiguousAttribution,
            ]
        );
        assert_eq!(
            UnavailabilityReason::ALL,
            [
                UnavailabilityReason::MissingModalities,
                UnavailabilityReason::UnavailablePrerequisite,
                UnavailabilityReason::StaleRetainedEvidence,
                UnavailabilityReason::MeasurementMiss,
                UnavailabilityReason::OpportunityRejected,
            ]
        );
    }

    proptest! {
        #[test]
        fn modality_canonicalization_is_permutation_invariant(
            indices in prop::collection::vec(0usize..Modality::ALL.len(), 1..=Modality::ALL.len())
        ) {
            let mut modalities = Vec::new();
            for index in indices {
                let modality = Modality::ALL[index];
                if !modalities.contains(&modality) {
                    modalities.push(modality);
                }
            }
            let mut reversed = modalities.clone();
            reversed.reverse();

            let left = NonEmptyModalitySet::try_new(modalities)?;
            let right = NonEmptyModalitySet::try_new(reversed)?;
            prop_assert_eq!(left, right);
        }

        #[test]
        fn anomaly_reason_canonicalization_is_permutation_invariant(
            indices in prop::collection::vec(0usize..AnomalyReason::ALL.len(), 1..=AnomalyReason::ALL.len())
        ) {
            let mut reasons = Vec::new();
            for index in indices {
                let reason = AnomalyReason::ALL[index];
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
            }
            let mut reversed = reasons.clone();
            reversed.reverse();

            let left = UnclassifiedAnomaly::try_new([], reasons)?;
            let right = UnclassifiedAnomaly::try_new([], reversed)?;
            prop_assert_eq!(left, right);
        }

        #[test]
        fn unavailability_reason_canonicalization_is_permutation_invariant(
            indices in prop::collection::vec(
                0usize..UnavailabilityReason::ALL.len(),
                1..=UnavailabilityReason::ALL.len(),
            )
        ) {
            let mut reasons = Vec::new();
            for index in indices {
                let reason = UnavailabilityReason::ALL[index];
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
            }
            let mut reversed = reasons.clone();
            reversed.reverse();

            let left = UnavailabilityReasons::try_new(reasons)?;
            let right = UnavailabilityReasons::try_new(reversed)?;
            prop_assert_eq!(left, right);
        }

        #[test]
        fn arbitrary_diagnostics_remain_bounded_single_line_ascii(
            characters in prop::collection::vec(any::<char>(), 0..1_024)
        ) {
            let input: String = characters.into_iter().collect();
            let failure = AssessmentFailure::with_diagnostic(
                FailureCode::InvalidObservation,
                &input,
            );
            let diagnostic = failure.diagnostic.as_str();
            let is_single_line_ascii = diagnostic
                .chars()
                .all(|character| character.is_ascii_graphic() || character == ' ');

            prop_assert!(diagnostic.len() <= MAX_DIAGNOSTIC_BYTES);
            prop_assert!(is_single_line_ascii);
            prop_assert!(!diagnostic.starts_with(' '));
            prop_assert!(!diagnostic.ends_with(' '));
            prop_assert!(!diagnostic.contains("  "));
        }
    }
}
