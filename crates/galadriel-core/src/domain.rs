//! Validated identities and stream coordinates used at Galadriel boundaries.
//!
//! Numeric values are deliberately limited to [`JSON_SAFE_INTEGER_MAX`] so every
//! accepted value is represented exactly by common JSON implementations. Textual
//! identities use a bounded ASCII grammar to avoid path injection, control
//! characters, and Unicode-normalization ambiguity. All fields remain private so
//! invalid values cannot be assembled through the public API.
//!
//! The identity types are intentionally non-interchangeable:
//!
//! ```compile_fail
//! use galadriel_core::{ProjectionFrameId, TrackId};
//!
//! fn accept_track(_: TrackId) {}
//!
//! let frame = ProjectionFrameId::new(7).unwrap();
//! accept_track(frame);
//! ```
//!
//! Raw integers must also cross the appropriate fallible boundary:
//!
//! ```compile_fail
//! use galadriel_core::TrackId;
//!
//! fn accept_track(_: TrackId) {}
//!
//! accept_track(7_u64);
//! ```

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Largest integer represented exactly by both `u64` and an IEEE-754 binary64.
pub const JSON_SAFE_INTEGER_MAX: u64 = (1_u64 << 53) - 1;

/// Maximum encoded length of a textual domain identifier.
pub const MAX_IDENTIFIER_BYTES: usize = 64;

/// Failure to construct or advance a validated domain value.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainError {
    /// A semantic identity used the reserved zero value.
    #[error("{kind} must be greater than zero")]
    ZeroIdentifier {
        /// Name of the rejected domain type.
        kind: &'static str,
    },

    /// A numeric value cannot be represented exactly by every supported JSON peer.
    #[error("{kind} value {value} exceeds the exact JSON integer maximum {maximum}")]
    IntegerOutOfRange {
        /// Name of the rejected domain type.
        kind: &'static str,
        /// Rejected value.
        value: u64,
        /// Inclusive upper bound.
        maximum: u64,
    },

    /// A textual identity was empty.
    #[error("{kind} must not be empty")]
    EmptyIdentifier {
        /// Name of the rejected domain type.
        kind: &'static str,
    },

    /// A textual identity exceeded its encoded byte ceiling.
    #[error("{kind} is {length} bytes; maximum is {maximum}")]
    IdentifierTooLong {
        /// Name of the rejected domain type.
        kind: &'static str,
        /// Actual UTF-8 byte length.
        length: usize,
        /// Inclusive byte ceiling.
        maximum: usize,
    },

    /// A textual identity did not begin and end with an ASCII alphanumeric.
    #[error("{kind} must begin and end with an ASCII alphanumeric character")]
    InvalidIdentifierBoundary {
        /// Name of the rejected domain type.
        kind: &'static str,
    },

    /// A textual identity contained a character outside its canonical grammar.
    #[error("{kind} contains invalid character {character:?} at byte {index}")]
    InvalidIdentifierCharacter {
        /// Name of the rejected domain type.
        kind: &'static str,
        /// UTF-8 byte offset of the rejected character.
        index: usize,
        /// Rejected character.
        character: char,
    },

    /// A timestamp declared a clock interpretation outside the closed contract.
    #[error("unknown clock_domain")]
    UnknownClockDomain,

    /// A bounded ordinal cannot advance without rollover.
    #[error("{kind} is exhausted at {maximum}; epoch rollover is required")]
    ValueExhausted {
        /// Name of the exhausted domain type.
        kind: &'static str,
        /// Inclusive terminal value.
        maximum: u64,
    },

    /// Epoch rollover attempted to reuse the current epoch identity.
    #[error("epoch_id rollover requires a fresh identity")]
    ReusedEpochId,

    /// A stream successor did not advance its timestamp.
    #[error("timestamp_ms must increase: previous {previous}, proposed {proposed}")]
    NonIncreasingTimestamp {
        /// Current timestamp.
        previous: u64,
        /// Rejected successor timestamp.
        proposed: u64,
    },
}

fn validate_text_identifier(kind: &'static str, value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::EmptyIdentifier { kind });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(DomainError::IdentifierTooLong {
            kind,
            length: value.len(),
            maximum: MAX_IDENTIFIER_BYTES,
        });
    }

    let begins_with_alphanumeric = value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric());
    let ends_with_alphanumeric = value
        .chars()
        .next_back()
        .is_some_and(|character| character.is_ascii_alphanumeric());
    if !begins_with_alphanumeric || !ends_with_alphanumeric {
        return Err(DomainError::InvalidIdentifierBoundary { kind });
    }

    for (index, character) in value.char_indices() {
        if !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')) {
            return Err(DomainError::InvalidIdentifierCharacter {
                kind,
                index,
                character,
            });
        }
    }
    Ok(())
}

macro_rules! bounded_numeric_identifier {
    ($name:ident, $kind:literal, $minimum:literal, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Smallest accepted identity.
            pub const MIN: u64 = $minimum;

            /// Largest accepted identity.
            pub const MAX: u64 = JSON_SAFE_INTEGER_MAX;

            /// Constructs a validated identity.
            ///
            /// # Errors
            ///
            /// Returns [`DomainError::ZeroIdentifier`] below [`Self::MIN`] and
            /// [`DomainError::IntegerOutOfRange`] above [`Self::MAX`].
            pub const fn new(value: u64) -> Result<Self, DomainError> {
                if value < Self::MIN {
                    return Err(DomainError::ZeroIdentifier { kind: $kind });
                }
                if value > Self::MAX {
                    return Err(DomainError::IntegerOutOfRange {
                        kind: $kind,
                        value,
                        maximum: Self::MAX,
                    });
                }
                Ok(Self(value))
            }

            /// Returns the validated integer value.
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl TryFrom<u64> for $name {
            type Error = DomainError;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u64(self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = u64::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! bounded_ordinal {
    ($name:ident, $kind:literal, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Smallest accepted value.
            pub const MIN: u64 = 0;

            /// Largest accepted value.
            pub const MAX: u64 = JSON_SAFE_INTEGER_MAX;

            /// Constructs a validated ordinal.
            ///
            /// # Errors
            ///
            /// Returns [`DomainError::IntegerOutOfRange`] above [`Self::MAX`].
            pub const fn new(value: u64) -> Result<Self, DomainError> {
                if value > Self::MAX {
                    return Err(DomainError::IntegerOutOfRange {
                        kind: $kind,
                        value,
                        maximum: Self::MAX,
                    });
                }
                Ok(Self(value))
            }

            /// Returns the validated integer value.
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Returns the next value without wrapping or saturating.
            ///
            /// # Errors
            ///
            /// Returns [`DomainError::ValueExhausted`] at [`Self::MAX`].
            pub const fn checked_successor(self) -> Result<Self, DomainError> {
                if self.0 == Self::MAX {
                    return Err(DomainError::ValueExhausted {
                        kind: $kind,
                        maximum: Self::MAX,
                    });
                }
                Ok(Self(self.0 + 1))
            }
        }

        impl TryFrom<u64> for $name {
            type Error = DomainError;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u64(self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = u64::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! textual_identifier {
    ($name:ident, $kind:literal, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Largest accepted UTF-8 byte length.
            pub const MAX_BYTES: usize = MAX_IDENTIFIER_BYTES;

            /// Constructs a validated textual identity.
            ///
            /// The grammar is `[A-Za-z0-9][A-Za-z0-9._:-]{0,62}[A-Za-z0-9]`,
            /// with the single-character ASCII-alphanumeric case also accepted.
            ///
            /// # Errors
            ///
            /// Returns a [`DomainError`] when the value is empty, oversized, has
            /// a non-alphanumeric boundary, or contains a non-canonical character.
            pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                validate_text_identifier($kind, &value)?;
                Ok(Self(value))
            }

            /// Returns the validated identifier text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = DomainError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = DomainError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

bounded_numeric_identifier!(
    TrackId,
    "track_id",
    0,
    "A frozen-v1 track identity, including zero, with an exact cross-language JSON representation."
);
bounded_numeric_identifier!(
    ProjectionFrameId,
    "projection_frame_id",
    1,
    "A nonzero physical coordinate-frame identity for a consistency projection."
);
bounded_numeric_identifier!(
    ProjectionContextId,
    "projection_context_id",
    1,
    "A nonzero calibration and projection-definition identity."
);
bounded_numeric_identifier!(
    FrozenPriorId,
    "frozen_prior_id",
    1,
    "A nonzero identity for an immutable predicted-state snapshot."
);

bounded_ordinal!(
    Sequence,
    "sequence",
    "A zero-based, bounded position in one producer stream and epoch."
);
bounded_ordinal!(
    StateGeneration,
    "state_generation",
    "A zero-based, bounded generation distinguishing explicit detector-state resets within one epoch."
);
bounded_ordinal!(
    TimestampMillis,
    "timestamp_ms",
    "A non-negative millisecond reading interpreted only within its clock domain."
);

impl TimestampMillis {
    /// Adds a millisecond delta without wrapping or saturating.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::ValueExhausted`] if the sum would exceed
    /// [`Self::MAX`].
    pub const fn checked_add(self, delta_ms: u64) -> Result<Self, DomainError> {
        if delta_ms > Self::MAX - self.0 {
            return Err(DomainError::ValueExhausted {
                kind: "timestamp_ms",
                maximum: Self::MAX,
            });
        }
        Ok(Self(self.0 + delta_ms))
    }
}

textual_identifier!(
    SessionId,
    "session_id",
    "A bounded session identity with a canonical, path-safe ASCII representation."
);
textual_identifier!(
    EpochId,
    "epoch_id",
    "A freshly minted textual identity for one producer-process epoch."
);
textual_identifier!(
    StreamId,
    "stream_id",
    "A bounded identity for one ordered stream within an epoch."
);
textual_identifier!(
    ProducerId,
    "producer_id",
    "A bounded identity naming the producer responsible for a stream."
);

/// Closed interpretation and origin contract for a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockDomain {
    /// Milliseconds since the Unix epoch in Coordinated Universal Time.
    UnixUtc,
    /// Milliseconds from a process-local monotonic origin.
    MonotonicProcess,
    /// Milliseconds in an explicitly managed simulation timeline.
    SimulationTime,
    /// Milliseconds since the TAI epoch in International Atomic Time.
    Tai,
}

impl ClockDomain {
    /// Parses the exact snake-case wire name of a supported clock domain.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::UnknownClockDomain`] for every value outside the
    /// four closed variants.
    pub fn new(value: impl AsRef<str>) -> Result<Self, DomainError> {
        match value.as_ref() {
            "unix_utc" => Ok(Self::UnixUtc),
            "monotonic_process" => Ok(Self::MonotonicProcess),
            "simulation_time" => Ok(Self::SimulationTime),
            "tai" => Ok(Self::Tai),
            _ => Err(DomainError::UnknownClockDomain),
        }
    }

    /// Returns the exact snake-case wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnixUtc => "unix_utc",
            Self::MonotonicProcess => "monotonic_process",
            Self::SimulationTime => "simulation_time",
            Self::Tai => "tai",
        }
    }
}

impl FromStr for ClockDomain {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl fmt::Display for ClockDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

/// Immutable provenance tying a projection to its frame, context, and prior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionIdentity {
    frame_id: ProjectionFrameId,
    context_id: ProjectionContextId,
    frozen_prior_id: FrozenPriorId,
}

impl ProjectionIdentity {
    /// Constructs validated projection provenance from wire-level integers.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for a zero or non-JSON-safe component.
    pub fn try_new(
        frame_id: u64,
        context_id: u64,
        frozen_prior_id: u64,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            frame_id: ProjectionFrameId::new(frame_id)?,
            context_id: ProjectionContextId::new(context_id)?,
            frozen_prior_id: FrozenPriorId::new(frozen_prior_id)?,
        })
    }

    /// Returns the physical projection-frame identity.
    pub const fn frame_id(self) -> ProjectionFrameId {
        self.frame_id
    }

    /// Returns the projection/calibration-context identity.
    pub const fn context_id(self) -> ProjectionContextId {
        self.context_id
    }

    /// Returns the immutable prior-snapshot identity.
    pub const fn frozen_prior_id(self) -> FrozenPriorId {
        self.frozen_prior_id
    }
}

/// Immutable session and producer-epoch identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochIdentity {
    session_id: SessionId,
    epoch_id: EpochId,
}

impl EpochIdentity {
    /// Constructs a validated epoch identity from boundary values.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for an invalid textual identity.
    pub fn try_new(
        session_id: impl Into<String>,
        epoch_id: impl Into<String>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            session_id: SessionId::new(session_id)?,
            epoch_id: EpochId::new(epoch_id)?,
        })
    }

    /// Returns the enclosing session identity.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the producer-epoch identity.
    pub fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }

    /// Creates a fresh epoch identity in the same session.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::ReusedEpochId`] if `epoch_id` is unchanged or a
    /// textual validation error for the proposed identity.
    pub fn checked_rollover(&self, epoch_id: impl Into<String>) -> Result<Self, DomainError> {
        let epoch_id = EpochId::new(epoch_id)?;
        if epoch_id == self.epoch_id {
            return Err(DomainError::ReusedEpochId);
        }
        Ok(Self {
            session_id: self.session_id.clone(),
            epoch_id,
        })
    }
}

/// Identity of one ordered stream within an epoch.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamIdentity {
    epoch: EpochIdentity,
    stream_id: StreamId,
}

impl StreamIdentity {
    /// Constructs a validated stream identity from boundary values.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for an invalid epoch or stream component.
    pub fn try_new(
        session_id: impl Into<String>,
        epoch_id: impl Into<String>,
        stream_id: impl Into<String>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            epoch: EpochIdentity::try_new(session_id, epoch_id)?,
            stream_id: StreamId::new(stream_id)?,
        })
    }

    /// Returns the enclosing epoch identity.
    pub fn epoch(&self) -> &EpochIdentity {
        &self.epoch
    }

    /// Returns this stream's identity within the epoch.
    pub fn stream_id(&self) -> &StreamId {
        &self.stream_id
    }
}

/// Immutable coordinate of an event in one epoch-scoped stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamPosition {
    identity: StreamIdentity,
    state_generation: StateGeneration,
    sequence: Sequence,
    timestamp_ms: TimestampMillis,
    clock_domain: ClockDomain,
}

impl StreamPosition {
    /// Constructs a validated stream coordinate from boundary values.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for any invalid identity, state generation,
    /// sequence, or timestamp component. `clock_domain` is already closed and
    /// validated by its enum type.
    pub fn try_new(
        session_id: impl Into<String>,
        epoch_id: impl Into<String>,
        stream_id: impl Into<String>,
        state_generation: u64,
        sequence: u64,
        timestamp_ms: u64,
        clock_domain: ClockDomain,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            identity: StreamIdentity::try_new(session_id, epoch_id, stream_id)?,
            state_generation: StateGeneration::new(state_generation)?,
            sequence: Sequence::new(sequence)?,
            timestamp_ms: TimestampMillis::new(timestamp_ms)?,
            clock_domain,
        })
    }

    /// Returns the epoch-scoped stream identity.
    pub fn identity(&self) -> &StreamIdentity {
        &self.identity
    }

    /// Returns the detector-state generation within the current epoch.
    pub const fn state_generation(&self) -> StateGeneration {
        self.state_generation
    }

    /// Returns the sequence coordinate.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Returns the timestamp coordinate.
    pub const fn timestamp_ms(&self) -> TimestampMillis {
        self.timestamp_ms
    }

    /// Returns the clock domain in which the timestamp is meaningful.
    pub const fn clock_domain(&self) -> ClockDomain {
        self.clock_domain
    }

    /// Returns the next contiguous position at a strictly newer timestamp.
    ///
    /// The original position is not mutated. Counter exhaustion requires a new
    /// epoch; this method never wraps or saturates.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::IntegerOutOfRange`] for a non-JSON-safe timestamp,
    /// [`DomainError::NonIncreasingTimestamp`] for a frozen or regressing clock,
    /// or [`DomainError::ValueExhausted`] when the sequence is exhausted.
    pub fn checked_successor(&self, timestamp_ms: u64) -> Result<Self, DomainError> {
        let timestamp_ms = TimestampMillis::new(timestamp_ms)?;
        if timestamp_ms <= self.timestamp_ms {
            return Err(DomainError::NonIncreasingTimestamp {
                previous: self.timestamp_ms.get(),
                proposed: timestamp_ms.get(),
            });
        }
        Ok(Self {
            identity: self.identity.clone(),
            state_generation: self.state_generation,
            sequence: self.sequence.checked_successor()?,
            timestamp_ms,
            clock_domain: self.clock_domain,
        })
    }

    /// Records an explicit state reset at the next contiguous stream position.
    ///
    /// A reset advances both sequence and state generation. It never restarts the
    /// sequence within an epoch and does not mutate the previous position.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::IntegerOutOfRange`] for a non-JSON-safe timestamp,
    /// [`DomainError::NonIncreasingTimestamp`] for a frozen or regressing clock,
    /// or [`DomainError::ValueExhausted`] when sequence or state generation is
    /// exhausted.
    pub fn checked_reset(&self, timestamp_ms: u64) -> Result<Self, DomainError> {
        let timestamp_ms = TimestampMillis::new(timestamp_ms)?;
        if timestamp_ms <= self.timestamp_ms {
            return Err(DomainError::NonIncreasingTimestamp {
                previous: self.timestamp_ms.get(),
                proposed: timestamp_ms.get(),
            });
        }
        Ok(Self {
            identity: self.identity.clone(),
            state_generation: self.state_generation.checked_successor()?,
            sequence: self.sequence.checked_successor()?,
            timestamp_ms,
            clock_domain: self.clock_domain,
        })
    }

    /// Starts a fresh epoch for this session and stream.
    ///
    /// Epoch rollover is the only operation here that restarts sequence and state
    /// generation at zero. Timestamp ordering is not compared across epochs
    /// because process-local and simulation clock origins may also restart.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::ReusedEpochId`] for the active epoch, a textual
    /// validation error for the proposed epoch, or
    /// [`DomainError::IntegerOutOfRange`] for a non-JSON-safe timestamp.
    pub fn checked_epoch_rollover(
        &self,
        epoch_id: impl Into<String>,
        timestamp_ms: u64,
    ) -> Result<Self, DomainError> {
        let epoch = self.identity.epoch.checked_rollover(epoch_id)?;
        let timestamp_ms = TimestampMillis::new(timestamp_ms)?;
        Ok(Self {
            identity: StreamIdentity {
                epoch,
                stream_id: self.identity.stream_id.clone(),
            },
            state_generation: StateGeneration::new(0)?,
            sequence: Sequence::new(0)?,
            timestamp_ms,
            clock_domain: self.clock_domain,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn position(state_generation: u64, sequence: u64, timestamp_ms: u64) -> StreamPosition {
        StreamPosition::try_new(
            "session-1",
            "epoch-1",
            "radar",
            state_generation,
            sequence,
            timestamp_ms,
            ClockDomain::UnixUtc,
        )
        .unwrap()
    }

    #[test]
    fn json_safe_integer_max_matches_binary64_exact_integer_boundary() {
        assert_eq!(JSON_SAFE_INTEGER_MAX, 9_007_199_254_740_991);
    }

    #[test]
    fn numeric_identities_accept_the_inclusive_upper_boundary() {
        assert!(TrackId::new(JSON_SAFE_INTEGER_MAX).is_ok());
        assert!(ProjectionFrameId::new(JSON_SAFE_INTEGER_MAX).is_ok());
        assert!(ProjectionContextId::new(JSON_SAFE_INTEGER_MAX).is_ok());
        assert!(FrozenPriorId::new(JSON_SAFE_INTEGER_MAX).is_ok());
    }

    #[test]
    fn frozen_v1_track_identity_accepts_zero_but_projection_identities_do_not() {
        assert_eq!(TrackId::new(0).unwrap().get(), 0);
        assert_eq!(
            ProjectionFrameId::new(0),
            Err(DomainError::ZeroIdentifier {
                kind: "projection_frame_id"
            })
        );
        assert_eq!(
            ProjectionContextId::new(0),
            Err(DomainError::ZeroIdentifier {
                kind: "projection_context_id"
            })
        );
        assert_eq!(
            FrozenPriorId::new(0),
            Err(DomainError::ZeroIdentifier {
                kind: "frozen_prior_id"
            })
        );
    }

    #[test]
    fn numeric_identities_reject_first_unsafe_json_integer() {
        assert!(matches!(
            ProjectionFrameId::new(JSON_SAFE_INTEGER_MAX + 1),
            Err(DomainError::IntegerOutOfRange {
                kind: "projection_frame_id",
                value,
                maximum: JSON_SAFE_INTEGER_MAX,
            }) if value == JSON_SAFE_INTEGER_MAX + 1
        ));
    }

    #[test]
    fn ordinals_accept_zero() {
        assert_eq!(Sequence::new(0).unwrap().get(), 0);
    }

    #[test]
    fn sequence_successor_rejects_exhaustion_without_wrapping() {
        assert_eq!(
            Sequence::new(Sequence::MAX).unwrap().checked_successor(),
            Err(DomainError::ValueExhausted {
                kind: "sequence",
                maximum: Sequence::MAX,
            })
        );
    }

    #[test]
    fn timestamp_checked_add_accepts_exact_upper_boundary() {
        let timestamp = TimestampMillis::new(TimestampMillis::MAX - 7).unwrap();

        assert_eq!(
            timestamp.checked_add(7).unwrap().get(),
            TimestampMillis::MAX
        );
    }

    #[test]
    fn timestamp_checked_add_rejects_overflow_without_saturating() {
        let timestamp = TimestampMillis::new(TimestampMillis::MAX).unwrap();

        assert!(matches!(
            timestamp.checked_add(1),
            Err(DomainError::ValueExhausted {
                kind: "timestamp_ms",
                maximum: TimestampMillis::MAX,
            })
        ));
    }

    #[test]
    fn textual_identifiers_accept_canonical_separators() {
        let identity = SessionId::new("session-7.core:alpha_2").unwrap();

        assert_eq!(identity.as_str(), "session-7.core:alpha_2");
    }

    #[test]
    fn textual_identifiers_accept_exact_byte_ceiling() {
        let value = "a".repeat(MAX_IDENTIFIER_BYTES);

        assert_eq!(EpochId::new(&value).unwrap().as_str(), value);
    }

    #[test]
    fn textual_identifiers_reject_empty_input() {
        assert_eq!(
            StreamId::new(""),
            Err(DomainError::EmptyIdentifier { kind: "stream_id" })
        );
    }

    #[test]
    fn textual_identifiers_reject_oversized_input() {
        let value = "a".repeat(MAX_IDENTIFIER_BYTES + 1);

        assert!(matches!(
            ProducerId::new(value),
            Err(DomainError::IdentifierTooLong {
                kind: "producer_id",
                length,
                maximum: MAX_IDENTIFIER_BYTES,
            }) if length == MAX_IDENTIFIER_BYTES + 1
        ));
    }

    #[test]
    fn textual_identifiers_reject_non_alphanumeric_boundaries() {
        assert_eq!(
            SessionId::new("-session"),
            Err(DomainError::InvalidIdentifierBoundary { kind: "session_id" })
        );
    }

    #[test]
    fn textual_identifiers_reject_path_and_wildcard_injection() {
        for value in [
            "session/command",
            "session*all",
            "session$all",
            "session?all",
        ] {
            assert!(SessionId::new(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn textual_identifiers_reject_whitespace_and_controls() {
        for value in [
            "session one",
            "session\tone",
            "session\none",
            "session\0one",
        ] {
            assert!(SessionId::new(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn textual_identifiers_reject_unicode_normalization_ambiguity() {
        assert!(EpochId::new("café").is_err());
        assert!(EpochId::new("cafe\u{301}").is_err());
    }

    #[test]
    fn numeric_serde_representation_is_a_scalar_integer() {
        let identity = TrackId::new(7).unwrap();

        assert_eq!(serde_json::to_string(&identity).unwrap(), "7");
    }

    #[test]
    fn frozen_v1_zero_track_identity_roundtrips_as_a_scalar_integer() {
        let identity = TrackId::new(0).unwrap();
        let encoded = serde_json::to_string(&identity).unwrap();

        assert_eq!(encoded, "0");
        assert_eq!(serde_json::from_str::<TrackId>(&encoded).unwrap(), identity);
    }

    #[test]
    fn textual_newtype_serde_representation_is_a_scalar_string() {
        let identity = ProducerId::new("crebain").unwrap();

        assert_eq!(serde_json::to_string(&identity).unwrap(), "\"crebain\"");
    }

    #[test]
    fn clock_domain_uses_closed_snake_case_wire_names() {
        let variants = [
            (ClockDomain::UnixUtc, "unix_utc"),
            (ClockDomain::MonotonicProcess, "monotonic_process"),
            (ClockDomain::SimulationTime, "simulation_time"),
            (ClockDomain::Tai, "tai"),
        ];

        for (domain, wire_name) in variants {
            assert_eq!(domain.to_string(), wire_name);
            assert_eq!(ClockDomain::new(wire_name).unwrap(), domain);
            assert_eq!(
                serde_json::to_string(&domain).unwrap(),
                format!("\"{wire_name}\"")
            );
            assert_eq!(
                serde_json::from_str::<ClockDomain>(&format!("\"{wire_name}\"")).unwrap(),
                domain
            );
        }
    }

    #[test]
    fn clock_domain_constructor_rejects_unknown_value() {
        assert_eq!(
            ClockDomain::new("producer_monotonic"),
            Err(DomainError::UnknownClockDomain)
        );
    }

    #[test]
    fn unknown_clock_domain_error_does_not_retain_attacker_text() {
        let oversized = "x".repeat(MAX_IDENTIFIER_BYTES * 1_024);

        assert_eq!(
            ClockDomain::new(oversized),
            Err(DomainError::UnknownClockDomain)
        );
    }

    #[test]
    fn clock_domain_deserialization_rejects_unknown_value() {
        assert!(serde_json::from_str::<ClockDomain>("\"producer_monotonic\"").is_err());
    }

    #[test]
    fn numeric_deserialization_revalidates_json_safe_boundary() {
        let encoded = (JSON_SAFE_INTEGER_MAX + 1).to_string();

        assert!(serde_json::from_str::<Sequence>(&encoded).is_err());
    }

    #[test]
    fn numeric_deserialization_rejects_ambiguous_json_forms() {
        for encoded in ["1.0", "1e0", "\"1\"", "-1", "null"] {
            assert!(
                serde_json::from_str::<Sequence>(encoded).is_err(),
                "accepted {encoded}"
            );
        }
    }

    #[test]
    fn textual_deserialization_revalidates_identifier_grammar() {
        assert!(serde_json::from_str::<SessionId>("\"session/*\"").is_err());
    }

    #[test]
    fn projection_identity_exposes_only_validated_components() {
        let identity = ProjectionIdentity::try_new(11, 12, 13).unwrap();

        assert_eq!(
            (
                identity.frame_id().get(),
                identity.context_id().get(),
                identity.frozen_prior_id().get(),
            ),
            (11, 12, 13)
        );
    }

    #[test]
    fn projection_identity_rejects_zero_component() {
        assert_eq!(
            ProjectionIdentity::try_new(1, 2, 0),
            Err(DomainError::ZeroIdentifier {
                kind: "frozen_prior_id",
            })
        );
    }

    #[test]
    fn closed_projection_deserialization_rejects_unknown_fields() {
        let encoded = r#"{
            "frame_id": 1,
            "context_id": 2,
            "frozen_prior_id": 3,
            "extension": false
        }"#;

        assert!(serde_json::from_str::<ProjectionIdentity>(encoded).is_err());
    }

    #[test]
    fn epoch_rollover_preserves_session_and_changes_epoch_identity() {
        let current = EpochIdentity::try_new("session-1", "epoch-1").unwrap();
        let next = current.checked_rollover("epoch-2").unwrap();

        assert_eq!(
            (next.session_id().as_str(), next.epoch_id().as_str()),
            ("session-1", "epoch-2")
        );
    }

    #[test]
    fn epoch_rollover_rejects_identity_reuse() {
        let current = EpochIdentity::try_new("session-1", "epoch-1").unwrap();

        assert_eq!(
            current.checked_rollover("epoch-1"),
            Err(DomainError::ReusedEpochId)
        );
    }

    #[test]
    fn stream_position_successor_is_contiguous_and_immutable() {
        let current = position(4, 9, 1_000);
        let next = current.checked_successor(1_001).unwrap();

        assert_eq!(
            (
                current.state_generation().get(),
                current.sequence().get(),
                current.timestamp_ms().get(),
                next.state_generation().get(),
                next.sequence().get(),
                next.timestamp_ms().get(),
            ),
            (4, 9, 1_000, 4, 10, 1_001)
        );
    }

    #[test]
    fn stream_position_successor_rejects_frozen_timestamp() {
        let current = position(0, 9, 1_000);

        assert_eq!(
            current.checked_successor(1_000),
            Err(DomainError::NonIncreasingTimestamp {
                previous: 1_000,
                proposed: 1_000,
            })
        );
    }

    #[test]
    fn stream_position_successor_rejects_regressing_timestamp() {
        let current = position(0, 9, 1_000);

        assert!(matches!(
            current.checked_successor(999),
            Err(DomainError::NonIncreasingTimestamp {
                previous: 1_000,
                proposed: 999,
            })
        ));
    }

    #[test]
    fn stream_position_successor_rejects_sequence_exhaustion() {
        let current = position(0, Sequence::MAX, 1_000);

        assert!(matches!(
            current.checked_successor(1_001),
            Err(DomainError::ValueExhausted {
                kind: "sequence",
                maximum: Sequence::MAX,
            })
        ));
    }

    #[test]
    fn explicit_reset_advances_state_generation_without_restarting_sequence() {
        let current = position(4, 9, 1_000);
        let reset = current.checked_reset(1_001).unwrap();

        assert_eq!(
            (reset.state_generation().get(), reset.sequence().get()),
            (5, 10)
        );
    }

    #[test]
    fn explicit_reset_rejects_state_generation_exhaustion() {
        let current = position(StateGeneration::MAX, 9, 1_000);

        assert!(matches!(
            current.checked_reset(1_001),
            Err(DomainError::ValueExhausted {
                kind: "state_generation",
                maximum: StateGeneration::MAX,
            })
        ));
    }

    #[test]
    fn explicit_reset_rejects_sequence_exhaustion() {
        let current = position(4, Sequence::MAX, 1_000);

        assert!(matches!(
            current.checked_reset(1_001),
            Err(DomainError::ValueExhausted {
                kind: "sequence",
                maximum: Sequence::MAX,
            })
        ));
    }

    #[test]
    fn epoch_rollover_restarts_sequence_and_state_generation_at_zero() {
        let current = position(8, 91, 1_000);
        let rolled = current.checked_epoch_rollover("epoch-2", 7).unwrap();

        assert_eq!(
            (
                rolled.identity().epoch().session_id().as_str(),
                rolled.identity().epoch().epoch_id().as_str(),
                rolled.state_generation().get(),
                rolled.sequence().get(),
                rolled.timestamp_ms().get(),
            ),
            ("session-1", "epoch-2", 0, 0, 7)
        );
    }

    #[test]
    fn stream_epoch_rollover_rejects_current_epoch_identity() {
        let current = position(8, 91, 1_000);

        assert_eq!(
            current.checked_epoch_rollover("epoch-1", 7),
            Err(DomainError::ReusedEpochId)
        );
    }

    #[test]
    fn closed_stream_position_deserialization_rejects_unknown_fields() {
        let position = position(0, 9, 1_000);
        let mut encoded = serde_json::to_value(position).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("extension".to_string(), serde_json::Value::Null);

        assert!(serde_json::from_value::<StreamPosition>(encoded).is_err());
    }

    proptest! {
        #[test]
        fn safe_positive_integer_round_trips_through_every_identity(
            value in 1_u64..=JSON_SAFE_INTEGER_MAX,
        ) {
            prop_assert_eq!(TrackId::new(value)?.get(), value);
            prop_assert_eq!(ProjectionFrameId::new(value)?.get(), value);
            prop_assert_eq!(ProjectionContextId::new(value)?.get(), value);
            prop_assert_eq!(FrozenPriorId::new(value)?.get(), value);
        }

        #[test]
        fn unsafe_integer_is_rejected_by_every_numeric_type(
            value in (JSON_SAFE_INTEGER_MAX + 1)..=u64::MAX,
        ) {
            prop_assert!(TrackId::new(value).is_err());
            prop_assert!(Sequence::new(value).is_err());
            prop_assert!(StateGeneration::new(value).is_err());
            prop_assert!(TimestampMillis::new(value).is_err());
        }

        #[test]
        fn sequence_successor_is_exactly_one_for_every_nonterminal_value(
            value in 0_u64..JSON_SAFE_INTEGER_MAX,
        ) {
            let current = Sequence::new(value)?;

            prop_assert_eq!(current.checked_successor()?.get(), value + 1);
        }

        #[test]
        fn valid_ascii_identifier_round_trips_as_a_json_string(
            value in "[A-Za-z0-9]{1,64}",
        ) {
            let identity = StreamId::new(value.clone())?;
            let encoded = serde_json::to_string(&identity)?;
            let decoded: StreamId = serde_json::from_str(&encoded)?;

            prop_assert_eq!(decoded.as_str(), value);
        }

        #[test]
        fn stream_successor_preserves_all_identity_components(
            sequence in 0_u64..JSON_SAFE_INTEGER_MAX,
            timestamp in 0_u64..JSON_SAFE_INTEGER_MAX,
        ) {
            let current = StreamPosition::try_new(
                "session-1",
                "epoch-1",
                "stream-1",
                3,
                sequence,
                timestamp,
                ClockDomain::MonotonicProcess,
            )?;
            let next = current.checked_successor(timestamp + 1)?;

            prop_assert_eq!(next.identity(), current.identity());
            prop_assert_eq!(next.clock_domain(), current.clock_domain());
            prop_assert_eq!(next.state_generation(), current.state_generation());
        }

        #[test]
        fn explicit_reset_advances_both_bounded_generations_exactly_once(
            state_generation in 0_u64..JSON_SAFE_INTEGER_MAX,
            sequence in 0_u64..JSON_SAFE_INTEGER_MAX,
            timestamp in 0_u64..JSON_SAFE_INTEGER_MAX,
        ) {
            let current = StreamPosition::try_new(
                "session-1",
                "epoch-1",
                "stream-1",
                state_generation,
                sequence,
                timestamp,
                ClockDomain::MonotonicProcess,
            )?;
            let reset = current.checked_reset(timestamp + 1)?;

            prop_assert_eq!(reset.state_generation().get(), state_generation + 1);
            prop_assert_eq!(reset.sequence().get(), sequence + 1);
            prop_assert_eq!(reset.identity(), current.identity());
        }

        #[test]
        fn epoch_rollover_resets_both_generations_for_every_valid_position(
            state_generation in 0_u64..=JSON_SAFE_INTEGER_MAX,
            sequence in 0_u64..=JSON_SAFE_INTEGER_MAX,
            timestamp in 0_u64..=JSON_SAFE_INTEGER_MAX,
            rollover_timestamp in 0_u64..=JSON_SAFE_INTEGER_MAX,
        ) {
            let current = StreamPosition::try_new(
                "session-1",
                "epoch-1",
                "stream-1",
                state_generation,
                sequence,
                timestamp,
                ClockDomain::SimulationTime,
            )?;
            let rolled = current.checked_epoch_rollover("epoch-2", rollover_timestamp)?;

            prop_assert_eq!(rolled.state_generation().get(), 0);
            prop_assert_eq!(rolled.sequence().get(), 0);
            prop_assert_eq!(rolled.timestamp_ms().get(), rollover_timestamp);
        }
    }
}
