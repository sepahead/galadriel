//! Conservative statistical assessment of lifecycle-complete assembled frames.
//!
//! [`CrossRouteAssembler`](crate::assembler::CrossRouteAssembler) proves that the
//! two producer routes agree and that every declared observation arrived. That
//! does not imply that every expected modality produced an assessable update: a
//! healthy frame may explicitly contain a gate miss, update rejection, or an
//! incomparable projection. [`LifecycleDetector`] converts those explicit
//! absences into an immediate abstention and clears the affected track history so
//! samples on either side of a censored frame or excessive forward-time gap cannot
//! form one apparently clean statistical window.
//!
//! A returned detector report remains advisory, synthetic-calibration-limited
//! evidence. Lifecycle completeness is not physical truth or a calibrated
//! posterior.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;

use galadriel_core::{
    assess_default, ClockDomain, CorrConfig, DefaultReport, DetectorConfig, EpochId, Modality,
    ProducerAxisFamilyPolicy, ProducerId, ReleaseSuite, ReleaseSuiteParams, SessionId, StreamId,
    StreamPosition,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::assembler::{AssembledFrame, FrameMonitorEvent};
use crate::monitor::{ModalityOutcomeKind, MAX_FRAME_ITEMS, REGISTRY_DIGEST_HEX_LEN};

/// Aggregate ceiling for common-projection observations retained by one
/// lifecycle adapter across every track, modality, and history frame.
pub const MAX_LIFECYCLE_RETAINED_OBSERVATIONS: usize = 960 * 1_024;

/// Hard ceiling for independently keyed lifecycle streams in one detector.
pub const MAX_LIFECYCLE_STREAMS: usize = 64;

/// Hard ceiling for fresh epochs retained for one logical stream.
///
/// The set is never evicted. Reaching the ceiling faults the detector instead of
/// forgetting an old epoch and making `A -> B -> A` reuse admissible.
pub const MAX_LIFECYCLE_EPOCHS_PER_STREAM: usize = 1_024;

/// Hard ceiling for recent accepted frame positions retained per logical stream.
pub const MAX_LIFECYCLE_RECENT_FRAMES: usize = 4_096;

/// Number of hash-linked receipts retained in memory by one detector.
///
/// Older receipts may be evicted while their final digest remains available as
/// [`LifecycleDetector::receipt_anchor`]. This is an in-memory audit aid, not a
/// durable journal or persistence guarantee.
pub const MAX_LIFECYCLE_RECEIPTS: usize = 65_536;

/// Maximum standalone JSON receipt size accepted by
/// [`LifecycleReceipt::decode_and_verify`].
pub const MAX_LIFECYCLE_RECEIPT_BYTES: usize = 16 * 1_024;

const LEGACY_LOCAL_STREAM_ID: &str = "galadriel-fusion";

/// SHA-256 digest used by lifecycle transition receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LifecycleDigest([u8; 32]);

impl LifecycleDigest {
    /// Digest containing only zero bytes, used before the first receipt.
    pub const ZERO: Self = Self([0; 32]);

    /// Return the raw SHA-256 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the canonical lowercase hexadecimal form.
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }
}

impl fmt::Display for LifecycleDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for LifecycleDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for LifecycleDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "lifecycle digest must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(Self(bytes))
    }
}

/// Typed reason that a detector-state generation advanced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum LifecycleResetReason {
    /// A caller explicitly requested a state reset.
    Explicit,
    /// A caller recorded an explicit timeout transition.
    Timeout,
    /// The registered physical frame changed.
    ProjectionFrameChanged,
    /// The registered projection/calibration context changed.
    ProjectionContextChanged,
    /// The pinned projection-registry digest changed.
    ProjectionRegistryChanged,
    /// The canonical expected-modality set changed.
    ExpectedModalitiesChanged,
    /// A contiguous frame arrived beyond the configured data-time deadline.
    InterSampleDeadlineExceeded {
        /// Observed timestamp distance in milliseconds.
        gap_ms: u64,
        /// Inclusive configured maximum in milliseconds.
        maximum_ms: u64,
    },
}

/// Opaque, non-empty, canonically ordered reset-reason set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LifecycleResetReasons(Vec<LifecycleResetReason>);

impl LifecycleResetReasons {
    fn new(reasons: Vec<LifecycleResetReason>) -> Self {
        debug_assert!(!reasons.is_empty());
        debug_assert!(reasons.len() <= 5);
        Self(reasons)
    }

    /// Borrow the bounded reason sequence.
    pub fn as_slice(&self) -> &[LifecycleResetReason] {
        &self.0
    }

    /// Number of reasons, always in `1..=5` for detector-created values.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return whether the set is empty.
    ///
    /// Detector-created values are never empty; this method supports generic
    /// collection inspection without exposing construction.
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl<'de> Deserialize<'de> for LifecycleResetReasons {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let reasons = Vec::<LifecycleResetReason>::deserialize(deserializer)?;
        let valid = match reasons.as_slice() {
            [LifecycleResetReason::Explicit] | [LifecycleResetReason::Timeout] => true,
            reasons if (1..=5).contains(&reasons.len()) => {
                reasons.iter().map(reset_reason_rank).all(|rank| rank >= 2)
                    && reasons
                        .windows(2)
                        .all(|pair| reset_reason_rank(&pair[0]) < reset_reason_rank(&pair[1]))
            }
            _ => false,
        };
        if !valid {
            return Err(serde::de::Error::custom(
                "lifecycle reset reasons are empty, noncanonical, duplicated, or out of bounds",
            ));
        }
        Ok(Self(reasons))
    }
}

fn reset_reason_rank(reason: &LifecycleResetReason) -> u8 {
    match reason {
        LifecycleResetReason::Explicit => 0,
        LifecycleResetReason::Timeout => 1,
        LifecycleResetReason::ProjectionFrameChanged => 2,
        LifecycleResetReason::ProjectionContextChanged => 3,
        LifecycleResetReason::ProjectionRegistryChanged => 4,
        LifecycleResetReason::ExpectedModalitiesChanged => 5,
        LifecycleResetReason::InterSampleDeadlineExceeded { .. } => 6,
    }
}

/// Strict classification for an event rejected by lifecycle ordering.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum LifecycleIngressRejection {
    /// The most recent accepted frame was submitted again byte-for-byte.
    #[error("duplicate frame at sequence {sequence}")]
    Duplicate {
        /// Repeated sequence.
        sequence: u64,
    },
    /// An older retained frame was submitted again byte-for-byte.
    #[error("replayed frame at sequence {sequence}; current sequence is {current}")]
    Replay {
        /// Replayed sequence.
        sequence: u64,
        /// Current accepted sequence.
        current: u64,
    },
    /// An older position fell outside retained fingerprints, so equality cannot
    /// be established and the event is conservatively classified as reordered.
    #[error("reordered frame at sequence {sequence}; current sequence is {current}")]
    Reordered {
        /// Older sequence.
        sequence: u64,
        /// Current accepted sequence.
        current: u64,
    },
    /// A retained position was reused with different frame evidence.
    #[error("conflicting replay at sequence {sequence}; current sequence is {current}")]
    ConflictingReplay {
        /// Reused sequence.
        sequence: u64,
        /// Current accepted sequence.
        current: u64,
    },
    /// One or more positions were skipped without an explicit control transition.
    #[error("forward sequence gap: expected {expected}, received {received}")]
    ForwardSequenceGap {
        /// Exact next sequence.
        expected: u64,
        /// Received sequence.
        received: u64,
    },
    /// A position did not advance the timestamp within one clock domain.
    #[error("timestamp did not increase: previous {previous}, received {received}")]
    NonIncreasingTimestamp {
        /// Previously accepted timestamp.
        previous: u64,
        /// Received timestamp.
        received: u64,
    },
    /// The clock interpretation changed without starting a new logical stream.
    #[error("clock domain changed within one logical stream")]
    ClockDomainChanged,
    /// The position did not carry the state generation required by the frame.
    #[error(
        "state generation mismatch: current {current}, received {received}, required {required}"
    )]
    StateGenerationMismatch {
        /// Current accepted generation.
        current: u64,
        /// Received generation.
        received: u64,
        /// Exact required generation.
        required: u64,
    },
    /// A continuity boundary was presented without advancing state generation.
    #[error("frame requires an explicit reset transition")]
    MissingReset {
        /// Canonically ordered reasons requiring the reset.
        reasons: LifecycleResetReasons,
    },
    /// Rollover reused any epoch retained for the logical stream.
    #[error("epoch {epoch_id:?} was already used by this logical stream")]
    ReusedEpoch {
        /// Reused epoch identifier.
        epoch_id: EpochId,
    },
    /// Rollover did not begin at sequence and state generation zero.
    #[error(
        "epoch rollover must start at sequence 0 and generation 0; got sequence {sequence}, generation {state_generation}"
    )]
    InvalidRolloverOrigin {
        /// Received sequence.
        sequence: u64,
        /// Received state generation.
        state_generation: u64,
    },
    /// The non-evicting epoch-retention set reached its hard ceiling.
    #[error("epoch retention capacity {maximum} is exhausted")]
    EpochCapacity {
        /// Hard epoch-retention ceiling.
        maximum: usize,
    },
    /// The bounded logical-stream map reached its validated ceiling.
    #[error("lifecycle stream capacity {maximum} is exhausted")]
    StreamCapacity {
        /// Validated stream ceiling for this detector configuration.
        maximum: usize,
    },
    /// A control transition did not identify an active logical stream and epoch.
    #[error("control transition does not match an active lifecycle stream")]
    UnknownStream,
    /// A reset/timeout control position was not the exact checked reset successor.
    #[error("reset or timeout position is not the exact checked reset successor")]
    InvalidResetSuccessor,
}

/// State-machine transition bound into a [`LifecycleReceipt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum LifecycleTransition {
    /// First accepted position for one logical stream.
    Initialized,
    /// Exact successor accepted without resetting detector state.
    Advanced,
    /// State generation advanced for the listed canonical reasons.
    Reset {
        /// Non-empty reset-reason set.
        reasons: LifecycleResetReasons,
    },
    /// A fresh epoch replaced the active epoch at generation and sequence zero.
    EpochRolledOver {
        /// Previously active epoch.
        previous_epoch_id: EpochId,
    },
    /// Input was rejected before statistical assessment.
    Rejected {
        /// Exact ordering/lifecycle classification.
        reason: LifecycleIngressRejection,
    },
    /// Structurally valid admission reached a terminal detector or adapter fault.
    Faulted {
        /// Exact display reason returned and retained by the detector.
        reason: String,
    },
}

impl LifecycleTransition {
    fn resets_history(&self) -> bool {
        matches!(
            self,
            Self::Initialized | Self::Reset { .. } | Self::EpochRolledOver { .. }
        )
    }
}

/// Deterministic, hash-linked receipt for one lifecycle state-machine decision.
///
/// The frame digest binds the complete assembled frame. The optional assessment
/// digest binds the accepted suite and every field in the serialized assessment
/// vector, including exact numeric report details. A caller retaining the frame
/// history and immutable suite can recompute those reports and compare the
/// digest. Receipts are held in memory only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleReceipt {
    index: u64,
    previous_digest: LifecycleDigest,
    digest: LifecycleDigest,
    producer_id: ProducerId,
    position: StreamPosition,
    transition: LifecycleTransition,
    frame_digest: Option<LifecycleDigest>,
    assessment_digest: Option<LifecycleDigest>,
}

/// Strict standalone receipt decode or integrity-verification failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LifecycleReceiptDecodeError {
    /// The JSON artifact exceeded its pre-parse ceiling.
    #[error("lifecycle receipt has {actual} bytes; maximum is {MAX_LIFECYCLE_RECEIPT_BYTES}")]
    TooLarge {
        /// Encoded byte count.
        actual: usize,
    },
    /// The receipt was not valid strict JSON for the frozen shape.
    #[error("invalid lifecycle receipt JSON: {source}")]
    InvalidJson {
        /// Typed JSON source.
        #[source]
        source: serde_json::Error,
    },
    /// The decoded fields could not have been emitted by the detector.
    #[error("lifecycle receipt violates the frozen detector shape")]
    InvalidShape,
    /// The embedded digest did not match the canonical receipt preimage.
    #[error("lifecycle receipt digest verification failed")]
    DigestMismatch,
}

impl LifecycleReceipt {
    /// Decode one bounded strict-JSON receipt and verify its embedded digest.
    ///
    /// This establishes internal integrity under the frozen encoding. It does
    /// not authenticate the writer, provide durability, or replace an external
    /// signature/MAC and trusted retention channel.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleReceiptDecodeError`] for oversize, malformed,
    /// structurally invalid, or digest-mismatched input. Ordinary JSON whitespace
    /// and object-member ordering are accepted before canonical recomputation.
    pub fn decode_and_verify(encoded: &[u8]) -> Result<Self, LifecycleReceiptDecodeError> {
        if encoded.len() > MAX_LIFECYCLE_RECEIPT_BYTES {
            return Err(LifecycleReceiptDecodeError::TooLarge {
                actual: encoded.len(),
            });
        }
        let receipt = serde_json::from_slice::<Self>(encoded)
            .map_err(|source| LifecycleReceiptDecodeError::InvalidJson { source })?;
        if !receipt.has_valid_detector_shape() {
            return Err(LifecycleReceiptDecodeError::InvalidShape);
        }
        if !receipt.verifies() {
            return Err(LifecycleReceiptDecodeError::DigestMismatch);
        }
        Ok(receipt)
    }

    /// Zero-based receipt index in this detector's global chain.
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Digest of the immediately preceding receipt, or all zeroes for index zero.
    pub const fn previous_digest(&self) -> LifecycleDigest {
        self.previous_digest
    }

    /// Digest of this receipt's canonical preimage.
    pub const fn digest(&self) -> LifecycleDigest {
        self.digest
    }

    /// Validated producer identity bound to the decision.
    pub const fn producer_id(&self) -> &ProducerId {
        &self.producer_id
    }

    /// Exact typed stream position presented to the state machine.
    pub const fn position(&self) -> &StreamPosition {
        &self.position
    }

    /// Typed transition outcome.
    pub const fn transition(&self) -> &LifecycleTransition {
        &self.transition
    }

    /// Digest of the complete assembled frame, when the event carried one.
    pub const fn frame_digest(&self) -> Option<LifecycleDigest> {
        self.frame_digest
    }

    /// Digest of assessment dispositions, when assessment completed.
    pub const fn assessment_digest(&self) -> Option<LifecycleDigest> {
        self.assessment_digest
    }

    /// Verify this receipt's canonical digest without consulting detector state.
    pub fn verifies(&self) -> bool {
        receipt_digest(
            self.index,
            self.previous_digest,
            &self.producer_id,
            &self.position,
            &self.transition,
            self.frame_digest,
            self.assessment_digest,
        )
        .is_ok_and(|digest| digest == self.digest)
    }

    /// Recompute and compare the exact serialized assessment evidence.
    ///
    /// The digest covers the release-suite identity and every serialized field
    /// of every assessment, including numeric baseline/correlation report
    /// fields. This remains an integrity/recomputation check, not authentication.
    pub fn verifies_assessments(
        &self,
        release_suite: &ReleaseSuite,
        assessments: &[LifecycleAssessment],
    ) -> bool {
        self.assessment_digest.is_some_and(|expected| {
            assessment_digest(release_suite, assessments).is_ok_and(|actual| actual == expected)
        })
    }

    /// Return whether this receipt is the exact hash-chain successor of `previous`.
    pub fn follows(&self, previous: &Self) -> bool {
        previous.index.checked_add(1) == Some(self.index)
            && self.previous_digest == previous.digest
            && self.verifies()
            && previous.verifies()
    }

    fn has_valid_detector_shape(&self) -> bool {
        if self.index > galadriel_core::JSON_SAFE_INTEGER_MAX
            || (self.index == 0 && self.previous_digest != LifecycleDigest::ZERO)
            || (self.assessment_digest.is_some() && self.frame_digest.is_none())
        {
            return false;
        }
        match &self.transition {
            LifecycleTransition::Initialized | LifecycleTransition::Advanced => {
                self.frame_digest.is_some() && self.assessment_digest.is_some()
            }
            LifecycleTransition::Reset { .. } | LifecycleTransition::EpochRolledOver { .. } => {
                self.frame_digest.is_some() == self.assessment_digest.is_some()
            }
            LifecycleTransition::Rejected { .. } => self.assessment_digest.is_none(),
            LifecycleTransition::Faulted { reason } => {
                !reason.is_empty()
                    && self.frame_digest.is_some()
                    && self.assessment_digest.is_none()
            }
        }
    }
}

/// Accepted frame transition and the assessments produced inside it.
#[derive(Debug, Clone)]
pub struct LifecycleTransitionOutcome {
    receipt: LifecycleReceipt,
    assessments: Vec<LifecycleAssessment>,
}

impl LifecycleTransitionOutcome {
    /// Receipt committed after every assessment completed successfully.
    pub const fn receipt(&self) -> &LifecycleReceipt {
        &self.receipt
    }

    /// Track assessments bound to the committed receipt.
    pub fn assessments(&self) -> &[LifecycleAssessment] {
        &self.assessments
    }

    /// Consume the outcome into its receipt and assessment vector.
    pub fn into_parts(self) -> (LifecycleReceipt, Vec<LifecycleAssessment>) {
        (self.receipt, self.assessments)
    }
}

/// One track-level result at a lifecycle-complete fusion frame.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum LifecycleAssessment {
    /// Every expected modality supplied a common-projection observation, so the
    /// bounded contiguous suffix was evaluated by the default detector.
    Evaluated {
        /// Numeric producer track identity.
        track_id: u64,
        /// Fusion frame being assessed.
        fusion_seq: u64,
        /// Whether this frame began a new statistical suffix.
        history_reset: bool,
        /// Advisory NIS/CUSUM and signed-correlation result.
        report: Box<DefaultReport>,
    },
    /// At least one expected modality lacked an assessable common projection.
    /// The track's retained suffix was discarded before this result was emitted.
    Abstained {
        /// Numeric producer track identity.
        track_id: u64,
        /// Fusion frame being assessed.
        fusion_seq: u64,
        /// Canonically ordered expected modalities without an assessable common
        /// projection in this frame.
        unavailable_modalities: Vec<Modality>,
    },
}

/// Terminal lifecycle-to-detector integration fault.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleDetectorError {
    /// Immutable detector configuration was invalid.
    #[error("invalid lifecycle detector configuration: {0}")]
    InvalidConfiguration(String),
    /// An assembled frame contradicted invariants required by this adapter.
    #[error("invalid assembled frame: {0}")]
    InvalidFrame(String),
    /// The frozen track set exceeded the detector's explicit state limit.
    #[error("assembled frame has {actual} frozen tracks; detector maximum is {maximum}")]
    TrackCapacity {
        /// Frozen tracks represented by the frame ledger.
        actual: usize,
        /// Configured detector track ceiling.
        maximum: usize,
    },
    /// The pure detector rejected evidence that had crossed the assembly boundary.
    #[error("detector rejected track {track_id} frame {fusion_seq}: {reason}")]
    Assessment {
        /// Track being evaluated.
        track_id: u64,
        /// Frame being evaluated.
        fusion_seq: u64,
        /// Underlying fail-closed detector error.
        reason: String,
    },
    /// A typed stream position or producer identity was invalid or contradicted
    /// the lifecycle-complete frame.
    #[error("invalid lifecycle position: {0}")]
    InvalidPosition(String),
    /// Strict ordering rejected a duplicate, replay, reorder, gap, reset, or
    /// rollover transition.
    #[error("lifecycle ingress rejected: {0}")]
    Ingress(#[from] LifecycleIngressRejection),
    /// Canonical receipt evidence could not be encoded.
    #[error("cannot encode lifecycle receipt evidence: {0}")]
    ReceiptEncoding(String),
    /// The JSON-safe global receipt ordinal cannot advance.
    #[error("lifecycle receipt index is exhausted")]
    ReceiptIndexExhausted,
}

#[derive(Debug, Clone)]
struct TrackHistory {
    frames: VecDeque<Vec<galadriel_core::PidObservation>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LogicalStreamKey {
    producer_id: ProducerId,
    session_id: SessionId,
    stream_id: StreamId,
}

impl LogicalStreamKey {
    fn from_position(producer_id: ProducerId, position: &StreamPosition) -> Self {
        Self {
            producer_id,
            session_id: position.identity().epoch().session_id().clone(),
            stream_id: position.identity().stream_id().clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct FrameContinuity {
    frame_id: u64,
    context_id: u64,
    registry_digest: String,
    modalities: Vec<Modality>,
}

impl FrameContinuity {
    fn from_frame(frame: &AssembledFrame) -> Self {
        Self {
            frame_id: frame.identity.frame_id,
            context_id: frame.identity.context_id,
            registry_digest: frame.summary.registry_digest.clone(),
            modalities: frame.summary.expected_modalities.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct RecentFrame {
    sequence: u64,
    digest: LifecycleDigest,
}

#[derive(Debug, Clone)]
struct LifecycleLane {
    position: StreamPosition,
    used_epochs: HashSet<EpochId>,
    tracks: HashMap<u64, TrackHistory>,
    last_frame: Option<FrameContinuity>,
    recent_frames: VecDeque<RecentFrame>,
}

impl LifecycleLane {
    fn new(position: StreamPosition) -> Self {
        let mut used_epochs = HashSet::with_capacity(1);
        used_epochs.insert(position.identity().epoch().epoch_id().clone());
        Self {
            position,
            used_epochs,
            tracks: HashMap::new(),
            last_frame: None,
            recent_frames: VecDeque::new(),
        }
    }

    fn remember_frame(&mut self, position: &StreamPosition, digest: LifecycleDigest) {
        if self.recent_frames.len() >= MAX_LIFECYCLE_RECENT_FRAMES {
            self.recent_frames.pop_front();
        }
        self.recent_frames.push_back(RecentFrame {
            sequence: position.sequence().get(),
            digest,
        });
    }
}

#[derive(Debug, Clone)]
enum Admission {
    Initialize,
    Advance,
    Reset(LifecycleResetReasons),
    Rollover { previous_epoch_id: EpochId },
}

impl Admission {
    fn transition(&self) -> LifecycleTransition {
        match self {
            Self::Initialize => LifecycleTransition::Initialized,
            Self::Advance => LifecycleTransition::Advanced,
            Self::Reset(reasons) => LifecycleTransition::Reset {
                reasons: reasons.clone(),
            },
            Self::Rollover { previous_epoch_id } => LifecycleTransition::EpochRolledOver {
                previous_epoch_id: previous_epoch_id.clone(),
            },
        }
    }
}

/// Bounded bridge from lifecycle-complete frames to Galadriel's pure default
/// detector.
///
/// The bridge owns no transport or wall clock. It retains at most the larger of
/// the configured NIS and correlation windows for at most
/// [`DetectorConfig::max_tracks`] tracks. The exact producer/session pair carried
/// by each assembled frame is an automatic history boundary. Any terminal adapter
/// error clears all history and is returned unchanged on later calls.
#[derive(Debug)]
pub struct LifecycleDetector {
    detector_config: DetectorConfig,
    correlation_config: CorrConfig,
    fixed_release_suite: Option<ReleaseSuite>,
    history_frames: usize,
    max_streams: usize,
    lanes: HashMap<LogicalStreamKey, LifecycleLane>,
    receipts: VecDeque<LifecycleReceipt>,
    receipt_anchor: LifecycleDigest,
    last_receipt_digest: LifecycleDigest,
    next_receipt_index: u64,
    evicted_receipts: u64,
    fault: Option<LifecycleDetectorError>,
}

impl LifecycleDetector {
    /// Construct a bounded lifecycle detector with immutable statistical policy.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleDetectorError::InvalidConfiguration`] when either
    /// detector configuration is invalid.
    pub fn new(
        detector_config: DetectorConfig,
        correlation_config: CorrConfig,
    ) -> Result<Self, LifecycleDetectorError> {
        Self::from_components(detector_config, correlation_config, None)
    }

    /// Construct from an already accepted release suite.
    ///
    /// Named-suite provenance remains named in every report. The suite's expected
    /// modality set is fixed for this detector instance; a frame declaring a
    /// different set is an explicit terminal configuration boundary rather than a
    /// silently reconstructed custom suite.
    pub fn from_release_suite(release_suite: ReleaseSuite) -> Result<Self, LifecycleDetectorError> {
        Self::from_components(
            release_suite.detector().clone(),
            release_suite.correlation().clone(),
            Some(release_suite),
        )
    }

    fn from_components(
        detector_config: DetectorConfig,
        correlation_config: CorrConfig,
        fixed_release_suite: Option<ReleaseSuite>,
    ) -> Result<Self, LifecycleDetectorError> {
        let history_frames = detector_config
            .window_len()
            .max(correlation_config.window());
        let retained_observations_per_stream = history_frames
            .checked_mul(detector_config.max_tracks())
            .and_then(|samples| samples.checked_mul(Modality::ALL.len()))
            .ok_or_else(|| {
                LifecycleDetectorError::InvalidConfiguration(
                    "history frames × max tracks × modalities overflows usize".to_owned(),
                )
            })?;
        if retained_observations_per_stream > MAX_LIFECYCLE_RETAINED_OBSERVATIONS {
            return Err(LifecycleDetectorError::InvalidConfiguration(format!(
                "one lifecycle stream may retain {retained_observations_per_stream} observations; maximum is \
                 {MAX_LIFECYCLE_RETAINED_OBSERVATIONS}"
            )));
        }
        let max_streams = MAX_LIFECYCLE_STREAMS.min(
            MAX_LIFECYCLE_RETAINED_OBSERVATIONS
                .checked_div(retained_observations_per_stream.max(1))
                .unwrap_or(1)
                .max(1),
        );
        Ok(Self {
            detector_config,
            correlation_config,
            fixed_release_suite,
            history_frames,
            max_streams,
            lanes: HashMap::new(),
            receipts: VecDeque::new(),
            receipt_anchor: LifecycleDigest::ZERO,
            last_receipt_digest: LifecycleDigest::ZERO,
            next_receipt_index: 0,
            evicted_receipts: 0,
            fault: None,
        })
    }

    /// Retained first terminal adapter fault, if any.
    pub fn fault(&self) -> Option<&LifecycleDetectorError> {
        self.fault.as_ref()
    }

    /// Number of track suffixes currently retained.
    pub fn retained_tracks(&self) -> usize {
        self.lanes.values().map(|lane| lane.tracks.len()).sum()
    }

    /// Number of logical streams currently retained.
    pub fn retained_streams(&self) -> usize {
        self.lanes.len()
    }

    /// Validated stream ceiling derived from the aggregate observation bound.
    pub const fn max_streams(&self) -> usize {
        self.max_streams
    }

    /// Hash-linked receipts currently retained in memory, oldest first.
    pub fn receipts(&self) -> &VecDeque<LifecycleReceipt> {
        &self.receipts
    }

    /// Digest immediately preceding the oldest retained receipt.
    ///
    /// This is all zeroes until receipt eviction occurs.
    pub const fn receipt_anchor(&self) -> LifecycleDigest {
        self.receipt_anchor
    }

    /// Number of oldest receipts evicted from bounded in-memory retention.
    pub const fn evicted_receipts(&self) -> u64 {
        self.evicted_receipts
    }

    /// Most recently committed receipt, if any.
    pub fn last_receipt(&self) -> Option<&LifecycleReceipt> {
        self.receipts.back()
    }

    /// Discard statistical suffixes as a diagnostic operation.
    ///
    /// This operation has no producer position and therefore cannot represent a
    /// protocol reset. Accepted operational flows should call [`Self::reset_at`]
    /// or [`Self::timeout_at`] instead so the boundary advances generation and is
    /// recorded in the receipt chain.
    #[deprecated(
        since = "0.9.0",
        note = "diagnostic only; use reset_at or timeout_at for accepted lifecycle state"
    )]
    pub fn clear_histories(&mut self) {
        for lane in self.lanes.values_mut() {
            lane.tracks.clear();
        }
    }

    /// Assess every frozen track represented by one assembled frame.
    ///
    /// A track is evaluated only when this exact frame contains one observation
    /// with a common projection for every summary-declared modality. Otherwise it
    /// immediately returns [`LifecycleAssessment::Abstained`] and its suffix is
    /// cleared. Track births are outside the frozen Cartesian ledger and begin
    /// participating on a later frame.
    ///
    /// # Errors
    ///
    /// Any structural, capacity, or detector error permanently faults this
    /// instance. No partial result is returned.
    pub fn assess_frame(
        &mut self,
        frame: &AssembledFrame,
    ) -> Result<Vec<LifecycleAssessment>, LifecycleDetectorError> {
        self.assess_frame_transition(frame)
            .map(LifecycleTransitionOutcome::into_parts)
            .map(|(_, assessments)| assessments)
    }

    /// Assess one v1 sidecar frame through the typed lifecycle state machine and
    /// return its committed receipt.
    ///
    /// The frozen v1 sidecar carries a producer ID and an epoch-scoped
    /// `session_id`, but it has no distinct core session, epoch, stream,
    /// generation, or clock-domain fields. This compatibility adapter therefore
    /// constructs a **project-local** [`StreamPosition`]: producer ID is the core
    /// session, sidecar session is the epoch, stream is
    /// `"galadriel-fusion"`, and the producer fusion timestamp is treated as a
    /// process-monotonic millisecond coordinate. This mapping does not add fields
    /// to Galadriel's sidecar schema v1 and is not a claim of NCP wire-1.0 reset or
    /// rollover support.
    /// Call [`Self::assess_positioned_frame`] when those identities are available
    /// from an authenticated external control plane.
    pub fn assess_frame_transition(
        &mut self,
        frame: &AssembledFrame,
    ) -> Result<LifecycleTransitionOutcome, LifecycleDetectorError> {
        if let Some(fault) = &self.fault {
            return Err(fault.clone());
        }
        if let Err(error) = validate_frame_cardinality(frame, self.detector_config.max_tracks()) {
            return Err(self.latch(error));
        }
        let position = match self.legacy_local_position(frame) {
            Ok(position) => position,
            Err(error) => return Err(self.latch(error)),
        };
        self.assess_positioned_frame(position, frame)
    }

    /// Assess a lifecycle-complete frame at an explicit typed stream position.
    ///
    /// The position epoch must equal the frame's sidecar `session_id`; the frame
    /// itself does not carry the position's enclosing core session, stream ID,
    /// state generation, or clock domain, so those remain caller-provided control
    /// provenance. Producer identity is parsed from and bound to the assembled
    /// frame. Every successful report is produced only after state admission and
    /// is committed with the returned hash-linked receipt.
    ///
    /// # Errors
    ///
    /// Returns and latches the first invalid frame, identity mismatch, strict
    /// ordering rejection, receipt failure, or detector failure.
    pub fn assess_positioned_frame(
        &mut self,
        position: StreamPosition,
        frame: &AssembledFrame,
    ) -> Result<LifecycleTransitionOutcome, LifecycleDetectorError> {
        if let Some(fault) = &self.fault {
            return Err(fault.clone());
        }
        if let Err(error) = validate_frame_cardinality(frame, self.detector_config.max_tracks()) {
            return Err(self.latch(error));
        }
        let producer_id = ProducerId::new(frame.producer_id()).map_err(|error| {
            self.latch(LifecycleDetectorError::InvalidPosition(error.to_string()))
        })?;
        let frame_digest = frame_digest(frame).map_err(|error| self.latch(error))?;
        if let Err(error) = validate_frame_identity(frame) {
            return Err(self.fault_with_receipt(producer_id, position, Some(frame_digest), error));
        }
        if position.identity().epoch().epoch_id().as_str() != frame.session_id() {
            let error = LifecycleDetectorError::InvalidPosition(format!(
                "position epoch_id {:?} differs from assembled sidecar session_id {:?}",
                position.identity().epoch().epoch_id().as_str(),
                frame.session_id()
            ));
            return Err(self.fault_with_receipt(producer_id, position, Some(frame_digest), error));
        }
        if position.sequence().get() != frame.identity.fusion_seq
            || position.timestamp_ms().get() != frame.identity.fusion_timestamp_ms
        {
            let error = LifecycleDetectorError::InvalidPosition(format!(
                "position sequence/timestamp ({}, {}) differs from assembled frame ({}, {})",
                position.sequence().get(),
                position.timestamp_ms().get(),
                frame.identity.fusion_seq,
                frame.identity.fusion_timestamp_ms
            ));
            return Err(self.fault_with_receipt(producer_id, position, Some(frame_digest), error));
        }

        let modalities = &frame.summary.expected_modalities;
        if let Err(error) = validate_canonical_modalities(modalities) {
            return Err(self.fault_with_receipt(producer_id, position, Some(frame_digest), error));
        }
        if modalities.len() < self.detector_config.min_channels() {
            let error = LifecycleDetectorError::InvalidFrame(format!(
                "{} expected modalities cannot satisfy detector min_channels {}",
                modalities.len(),
                self.detector_config.min_channels()
            ));
            return Err(self.fault_with_receipt(producer_id, position, Some(frame_digest), error));
        }
        let release_suite = match self.release_suite_for(modalities) {
            Ok(suite) => suite,
            Err(error) => {
                return Err(self.fault_with_receipt(
                    producer_id,
                    position,
                    Some(frame_digest),
                    error,
                ));
            }
        };

        let frozen_tracks = frozen_track_ids(frame);
        if frozen_tracks.len() > self.detector_config.max_tracks() {
            let error = LifecycleDetectorError::TrackCapacity {
                actual: frozen_tracks.len(),
                maximum: self.detector_config.max_tracks(),
            };
            return Err(self.fault_with_receipt(producer_id, position, Some(frame_digest), error));
        }
        if let Err(error) = validate_observation_ledger(frame, &frozen_tracks, modalities) {
            return Err(self.fault_with_receipt(producer_id, position, Some(frame_digest), error));
        }

        let key = LogicalStreamKey::from_position(producer_id.clone(), &position);
        let admission = match self.classify_admission(&key, &position, frame, frame_digest) {
            Ok(admission) => admission,
            Err(reason) => {
                return Err(self.reject_with_receipt(
                    producer_id,
                    position,
                    Some(frame_digest),
                    reason,
                ));
            }
        };
        let transition = admission.transition();
        self.apply_admission(&key, position.clone(), &admission);
        let assessments = {
            let lane = self.lanes.get_mut(&key).ok_or_else(|| {
                LifecycleDetectorError::InvalidPosition(
                    "admitted lifecycle lane is unavailable".to_owned(),
                )
            })?;
            assess_lane(
                &self.detector_config,
                &release_suite,
                self.history_frames,
                lane,
                frame,
                transition.resets_history(),
            )
        };
        let assessments = match assessments {
            Ok(assessments) => assessments,
            Err(error) => {
                return Err(self.fault_with_receipt(
                    producer_id,
                    position,
                    Some(frame_digest),
                    error,
                ));
            }
        };
        let assessment_digest = match assessment_digest(&release_suite, &assessments) {
            Ok(digest) => digest,
            Err(error) => {
                return Err(self.fault_with_receipt(
                    producer_id,
                    position,
                    Some(frame_digest),
                    error,
                ));
            }
        };
        if let Some(lane) = self.lanes.get_mut(&key) {
            lane.position = position.clone();
            lane.last_frame = Some(FrameContinuity::from_frame(frame));
            lane.remember_frame(&position, frame_digest);
        }
        let receipt = match self.commit_receipt(
            producer_id,
            position,
            transition,
            Some(frame_digest),
            Some(assessment_digest),
        ) {
            Ok(receipt) => receipt,
            Err(error) => return Err(self.latch(error)),
        };
        Ok(LifecycleTransitionOutcome {
            receipt,
            assessments,
        })
    }

    /// Record an explicit detector-state reset at the exact checked successor.
    ///
    /// The position must equal [`StreamPosition::checked_reset`] applied to the
    /// active position. It consumes one stream position, clears statistical
    /// suffixes, and commits a receipt without producing assessments.
    pub fn reset_at(
        &mut self,
        producer_id: impl AsRef<str>,
        position: StreamPosition,
    ) -> Result<LifecycleReceipt, LifecycleDetectorError> {
        self.control_reset(
            producer_id.as_ref(),
            position,
            LifecycleResetReason::Explicit,
        )
    }

    /// Record an explicit timeout at the exact checked reset successor.
    ///
    /// This method has no wall clock and does not infer transport silence. The
    /// caller supplies a position already established by its external deadline
    /// authority; the detector validates and receipts that transition.
    pub fn timeout_at(
        &mut self,
        producer_id: impl AsRef<str>,
        position: StreamPosition,
    ) -> Result<LifecycleReceipt, LifecycleDetectorError> {
        self.control_reset(
            producer_id.as_ref(),
            position,
            LifecycleResetReason::Timeout,
        )
    }

    /// Record a fresh epoch rollover without assessing a frame.
    ///
    /// The new position must preserve producer, core session, stream, and clock
    /// domain while using an unseen epoch at sequence and generation zero.
    pub fn rollover_at(
        &mut self,
        producer_id: impl AsRef<str>,
        position: StreamPosition,
    ) -> Result<LifecycleReceipt, LifecycleDetectorError> {
        if let Some(fault) = &self.fault {
            return Err(fault.clone());
        }
        let producer_id = ProducerId::new(producer_id.as_ref()).map_err(|error| {
            self.latch(LifecycleDetectorError::InvalidPosition(error.to_string()))
        })?;
        let key = LogicalStreamKey::from_position(producer_id.clone(), &position);
        let admission = match self.classify_rollover(&key, &position) {
            Ok(admission) => admission,
            Err(reason) => {
                return Err(self.reject_with_receipt(producer_id, position, None, reason));
            }
        };
        let transition = admission.transition();
        self.apply_admission(&key, position.clone(), &admission);
        self.commit_receipt(producer_id, position, transition, None, None)
            .map_err(|error| self.latch(error))
    }

    fn control_reset(
        &mut self,
        producer_id: &str,
        position: StreamPosition,
        reason: LifecycleResetReason,
    ) -> Result<LifecycleReceipt, LifecycleDetectorError> {
        if let Some(fault) = &self.fault {
            return Err(fault.clone());
        }
        let producer_id = ProducerId::new(producer_id).map_err(|error| {
            self.latch(LifecycleDetectorError::InvalidPosition(error.to_string()))
        })?;
        let key = LogicalStreamKey::from_position(producer_id.clone(), &position);
        let valid = self.lanes.get(&key).is_some_and(|lane| {
            lane.position
                .checked_reset(position.timestamp_ms().get())
                .is_ok_and(|expected| expected == position)
        });
        if !valid {
            return Err(self.reject_with_receipt(
                producer_id,
                position,
                None,
                LifecycleIngressRejection::InvalidResetSuccessor,
            ));
        }
        if let Some(lane) = self.lanes.get_mut(&key) {
            lane.position = position.clone();
            lane.tracks.clear();
            lane.last_frame = None;
        }
        self.commit_receipt(
            producer_id,
            position,
            LifecycleTransition::Reset {
                reasons: LifecycleResetReasons::new(vec![reason]),
            },
            None,
            None,
        )
        .map_err(|error| self.latch(error))
    }

    fn release_suite_for(
        &self,
        modalities: &[Modality],
    ) -> Result<ReleaseSuite, LifecycleDetectorError> {
        if let Some(suite) = &self.fixed_release_suite {
            if suite.expected_modalities() != modalities {
                return Err(LifecycleDetectorError::InvalidFrame(format!(
                    "frame expected modalities differ from fixed release suite {:?}",
                    suite.expected_modalities()
                )));
            }
            Ok(suite.clone())
        } else {
            ReleaseSuite::try_new(ReleaseSuiteParams {
                detector: self.detector_config.clone(),
                correlation: self.correlation_config.clone(),
                expected_modalities: modalities.to_vec(),
                axis_policy: ProducerAxisFamilyPolicy::AttestedCommonProjectionBonferroniV1,
            })
            .map_err(|error| {
                LifecycleDetectorError::InvalidFrame(format!(
                    "expected modalities cannot form an accepted custom detector suite: {error}"
                ))
            })
        }
    }

    fn legacy_local_position(
        &self,
        frame: &AssembledFrame,
    ) -> Result<StreamPosition, LifecycleDetectorError> {
        let producer_id = ProducerId::new(frame.producer_id())
            .map_err(|error| LifecycleDetectorError::InvalidPosition(error.to_string()))?;
        let session_id = SessionId::new(frame.producer_id())
            .map_err(|error| LifecycleDetectorError::InvalidPosition(error.to_string()))?;
        let stream_id = StreamId::new(LEGACY_LOCAL_STREAM_ID)
            .map_err(|error| LifecycleDetectorError::InvalidPosition(error.to_string()))?;
        let key = LogicalStreamKey {
            producer_id,
            session_id,
            stream_id,
        };
        let state_generation = self.lanes.get(&key).map_or(0, |lane| {
            if lane.position.identity().epoch().epoch_id().as_str() != frame.session_id() {
                0
            } else if continuity_reset_reasons(
                lane,
                frame,
                self.detector_config.max_inter_sample_gap_ms(),
            )
            .is_empty()
            {
                lane.position.state_generation().get()
            } else {
                lane.position.state_generation().get().saturating_add(1)
            }
        });
        StreamPosition::try_new(
            frame.producer_id(),
            frame.session_id(),
            LEGACY_LOCAL_STREAM_ID,
            state_generation,
            frame.identity.fusion_seq,
            frame.identity.fusion_timestamp_ms,
            ClockDomain::MonotonicProcess,
        )
        .map_err(|error| LifecycleDetectorError::InvalidPosition(error.to_string()))
    }

    fn classify_admission(
        &self,
        key: &LogicalStreamKey,
        position: &StreamPosition,
        frame: &AssembledFrame,
        frame_digest: LifecycleDigest,
    ) -> Result<Admission, LifecycleIngressRejection> {
        let Some(lane) = self.lanes.get(key) else {
            if self.lanes.len() >= self.max_streams {
                return Err(LifecycleIngressRejection::StreamCapacity {
                    maximum: self.max_streams,
                });
            }
            if position.state_generation().get() != 0 {
                return Err(LifecycleIngressRejection::StateGenerationMismatch {
                    current: 0,
                    received: position.state_generation().get(),
                    required: 0,
                });
            }
            return Ok(Admission::Initialize);
        };

        let current_epoch = lane.position.identity().epoch().epoch_id();
        let received_epoch = position.identity().epoch().epoch_id();
        if received_epoch != current_epoch {
            return self.classify_rollover(key, position);
        }
        if position.clock_domain() != lane.position.clock_domain() {
            return Err(LifecycleIngressRejection::ClockDomainChanged);
        }

        let current_sequence = lane.position.sequence().get();
        let received_sequence = position.sequence().get();
        if received_sequence <= current_sequence {
            let retained = lane
                .recent_frames
                .iter()
                .rev()
                .find(|recent| recent.sequence == position.sequence().get());
            return Err(match retained {
                Some(recent) if recent.digest != frame_digest => {
                    LifecycleIngressRejection::ConflictingReplay {
                        sequence: received_sequence,
                        current: current_sequence,
                    }
                }
                Some(_) if received_sequence == current_sequence => {
                    LifecycleIngressRejection::Duplicate {
                        sequence: received_sequence,
                    }
                }
                Some(_) => LifecycleIngressRejection::Replay {
                    sequence: received_sequence,
                    current: current_sequence,
                },
                None => LifecycleIngressRejection::Reordered {
                    sequence: received_sequence,
                    current: current_sequence,
                },
            });
        }

        let expected_sequence = current_sequence.checked_add(1).ok_or(
            LifecycleIngressRejection::ForwardSequenceGap {
                expected: current_sequence,
                received: received_sequence,
            },
        )?;
        if received_sequence != expected_sequence {
            return Err(LifecycleIngressRejection::ForwardSequenceGap {
                expected: expected_sequence,
                received: received_sequence,
            });
        }
        if position.timestamp_ms().get() <= lane.position.timestamp_ms().get() {
            return Err(LifecycleIngressRejection::NonIncreasingTimestamp {
                previous: lane.position.timestamp_ms().get(),
                received: position.timestamp_ms().get(),
            });
        }

        let reset_reasons =
            continuity_reset_reasons(lane, frame, self.detector_config.max_inter_sample_gap_ms());
        let current_generation = lane.position.state_generation().get();
        let received_generation = position.state_generation().get();
        if reset_reasons.is_empty() {
            if received_generation == current_generation {
                return Ok(Admission::Advance);
            }
            let reset_generation = current_generation
                .checked_add(1)
                .unwrap_or(current_generation);
            if received_generation == reset_generation && reset_generation != current_generation {
                return Ok(Admission::Reset(LifecycleResetReasons::new(vec![
                    LifecycleResetReason::Explicit,
                ])));
            }
            return Err(LifecycleIngressRejection::StateGenerationMismatch {
                current: current_generation,
                received: received_generation,
                required: current_generation,
            });
        }

        let required_generation = current_generation
            .checked_add(1)
            .unwrap_or(current_generation);
        if received_generation == current_generation {
            return Err(LifecycleIngressRejection::MissingReset {
                reasons: LifecycleResetReasons::new(reset_reasons),
            });
        }
        if required_generation == current_generation || received_generation != required_generation {
            return Err(LifecycleIngressRejection::StateGenerationMismatch {
                current: current_generation,
                received: received_generation,
                required: required_generation,
            });
        }
        Ok(Admission::Reset(LifecycleResetReasons::new(reset_reasons)))
    }

    fn classify_rollover(
        &self,
        key: &LogicalStreamKey,
        position: &StreamPosition,
    ) -> Result<Admission, LifecycleIngressRejection> {
        let lane = self
            .lanes
            .get(key)
            .ok_or(LifecycleIngressRejection::UnknownStream)?;
        let received_epoch = position.identity().epoch().epoch_id();
        if received_epoch == lane.position.identity().epoch().epoch_id() {
            return Err(LifecycleIngressRejection::ReusedEpoch {
                epoch_id: received_epoch.clone(),
            });
        }
        if lane.used_epochs.contains(received_epoch) {
            return Err(LifecycleIngressRejection::ReusedEpoch {
                epoch_id: received_epoch.clone(),
            });
        }
        if lane.used_epochs.len() >= MAX_LIFECYCLE_EPOCHS_PER_STREAM {
            return Err(LifecycleIngressRejection::EpochCapacity {
                maximum: MAX_LIFECYCLE_EPOCHS_PER_STREAM,
            });
        }
        if position.sequence().get() != 0 || position.state_generation().get() != 0 {
            return Err(LifecycleIngressRejection::InvalidRolloverOrigin {
                sequence: position.sequence().get(),
                state_generation: position.state_generation().get(),
            });
        }
        if position.clock_domain() != lane.position.clock_domain() {
            return Err(LifecycleIngressRejection::ClockDomainChanged);
        }
        Ok(Admission::Rollover {
            previous_epoch_id: lane.position.identity().epoch().epoch_id().clone(),
        })
    }

    fn apply_admission(
        &mut self,
        key: &LogicalStreamKey,
        position: StreamPosition,
        admission: &Admission,
    ) {
        match admission {
            Admission::Initialize => {
                self.lanes.insert(key.clone(), LifecycleLane::new(position));
            }
            Admission::Advance => {}
            Admission::Reset(_) => {
                if let Some(lane) = self.lanes.get_mut(key) {
                    lane.tracks.clear();
                }
            }
            Admission::Rollover { .. } => {
                if let Some(lane) = self.lanes.get_mut(key) {
                    lane.used_epochs
                        .insert(position.identity().epoch().epoch_id().clone());
                    lane.position = position;
                    lane.tracks.clear();
                    lane.last_frame = None;
                    lane.recent_frames.clear();
                }
            }
        }
    }

    fn commit_receipt(
        &mut self,
        producer_id: ProducerId,
        position: StreamPosition,
        transition: LifecycleTransition,
        frame_digest: Option<LifecycleDigest>,
        assessment_digest: Option<LifecycleDigest>,
    ) -> Result<LifecycleReceipt, LifecycleDetectorError> {
        if self.next_receipt_index > galadriel_core::JSON_SAFE_INTEGER_MAX {
            return Err(LifecycleDetectorError::ReceiptIndexExhausted);
        }
        let digest = receipt_digest(
            self.next_receipt_index,
            self.last_receipt_digest,
            &producer_id,
            &position,
            &transition,
            frame_digest,
            assessment_digest,
        )?;
        let receipt = LifecycleReceipt {
            index: self.next_receipt_index,
            previous_digest: self.last_receipt_digest,
            digest,
            producer_id,
            position,
            transition,
            frame_digest,
            assessment_digest,
        };
        self.next_receipt_index = self
            .next_receipt_index
            .checked_add(1)
            .ok_or(LifecycleDetectorError::ReceiptIndexExhausted)?;
        self.last_receipt_digest = digest;
        if self.receipts.len() >= MAX_LIFECYCLE_RECEIPTS {
            if let Some(evicted) = self.receipts.pop_front() {
                self.receipt_anchor = evicted.digest;
                self.evicted_receipts = self.evicted_receipts.saturating_add(1);
            }
        }
        self.receipts.push_back(receipt.clone());
        Ok(receipt)
    }

    fn reject_with_receipt(
        &mut self,
        producer_id: ProducerId,
        position: StreamPosition,
        frame_digest: Option<LifecycleDigest>,
        reason: LifecycleIngressRejection,
    ) -> LifecycleDetectorError {
        let error = LifecycleDetectorError::Ingress(reason.clone());
        if let Err(receipt_error) = self.commit_receipt(
            producer_id,
            position,
            LifecycleTransition::Rejected { reason },
            frame_digest,
            None,
        ) {
            return self.latch(receipt_error);
        }
        self.latch(error)
    }

    fn fault_with_receipt(
        &mut self,
        producer_id: ProducerId,
        position: StreamPosition,
        frame_digest: Option<LifecycleDigest>,
        error: LifecycleDetectorError,
    ) -> LifecycleDetectorError {
        if let Err(receipt_error) = self.commit_receipt(
            producer_id,
            position,
            LifecycleTransition::Faulted {
                reason: error.to_string(),
            },
            frame_digest,
            None,
        ) {
            return self.latch(receipt_error);
        }
        self.latch(error)
    }

    fn latch(&mut self, error: LifecycleDetectorError) -> LifecycleDetectorError {
        for lane in self.lanes.values_mut() {
            lane.tracks.clear();
        }
        self.fault = Some(error.clone());
        error
    }
}

fn validate_frame_cardinality(
    frame: &AssembledFrame,
    max_tracks: usize,
) -> Result<(), LifecycleDetectorError> {
    if !crate::valid_session_identity(frame.session_id())
        || !crate::valid_producer_identity(frame.producer_id())
    {
        return Err(LifecycleDetectorError::InvalidFrame(
            "assembled producer/session identity is outside the canonical sidecar domain"
                .to_owned(),
        ));
    }
    if frame.summary.registry_digest.len() != REGISTRY_DIGEST_HEX_LEN {
        return Err(LifecycleDetectorError::InvalidFrame(format!(
            "registry digest length {} differs from {REGISTRY_DIGEST_HEX_LEN}",
            frame.summary.registry_digest.len()
        )));
    }
    if frame.summary.expected_modalities.len() > Modality::ALL.len() {
        return Err(LifecycleDetectorError::InvalidFrame(format!(
            "frame declares {} modalities; closed maximum is {}",
            frame.summary.expected_modalities.len(),
            Modality::ALL.len()
        )));
    }
    let maximum_monitor_events = MAX_FRAME_ITEMS as usize;
    if frame.monitor_events.len() > maximum_monitor_events {
        return Err(LifecycleDetectorError::InvalidFrame(format!(
            "frame has {} monitor events; maximum is {maximum_monitor_events}",
            frame.monitor_events.len()
        )));
    }
    let maximum_observations = max_tracks.checked_mul(Modality::ALL.len()).ok_or_else(|| {
        LifecycleDetectorError::InvalidConfiguration(
            "max tracks × closed modalities overflows usize".to_owned(),
        )
    })?;
    if frame.observations.len() > maximum_observations {
        return Err(LifecycleDetectorError::InvalidFrame(format!(
            "frame has {} observations; lifecycle maximum is {maximum_observations}",
            frame.observations.len()
        )));
    }
    Ok(())
}

fn continuity_reset_reasons(
    lane: &LifecycleLane,
    frame: &AssembledFrame,
    maximum_gap_ms: u64,
) -> Vec<LifecycleResetReason> {
    let Some(previous) = &lane.last_frame else {
        return Vec::new();
    };
    let mut reasons = Vec::with_capacity(5);
    if previous.frame_id != frame.identity.frame_id {
        reasons.push(LifecycleResetReason::ProjectionFrameChanged);
    }
    if previous.context_id != frame.identity.context_id {
        reasons.push(LifecycleResetReason::ProjectionContextChanged);
    }
    if previous.registry_digest != frame.summary.registry_digest {
        reasons.push(LifecycleResetReason::ProjectionRegistryChanged);
    }
    if previous.modalities != frame.summary.expected_modalities {
        reasons.push(LifecycleResetReason::ExpectedModalitiesChanged);
    }
    if let Some(gap_ms) = frame
        .identity
        .fusion_timestamp_ms
        .checked_sub(lane.position.timestamp_ms().get())
        .filter(|gap_ms| *gap_ms > maximum_gap_ms)
    {
        reasons.push(LifecycleResetReason::InterSampleDeadlineExceeded {
            gap_ms,
            maximum_ms: maximum_gap_ms,
        });
    }
    reasons
}

fn assess_lane(
    detector_config: &DetectorConfig,
    release_suite: &ReleaseSuite,
    history_frames: usize,
    lane: &mut LifecycleLane,
    frame: &AssembledFrame,
    stream_reset: bool,
) -> Result<Vec<LifecycleAssessment>, LifecycleDetectorError> {
    let modalities = &frame.summary.expected_modalities;
    let frozen_tracks = frozen_track_ids(frame);
    let mut observations_by_track = validate_observation_ledger(frame, &frozen_tracks, modalities)?;
    lane.tracks
        .retain(|track_id, _| frozen_tracks.contains(track_id));

    let mut assessments = Vec::with_capacity(frozen_tracks.len());
    for track_id in frozen_tracks {
        let observations = observations_by_track.remove(&track_id).unwrap_or_default();
        let unavailable_modalities = modalities
            .iter()
            .copied()
            .filter(|modality| {
                !observations.iter().any(|observation| {
                    observation.modality() == *modality
                        && observation.consistency_projection().is_some()
                })
            })
            .collect::<Vec<_>>();
        if !unavailable_modalities.is_empty() {
            lane.tracks.remove(&track_id);
            assessments.push(LifecycleAssessment::Abstained {
                track_id,
                fusion_seq: frame.identity.fusion_seq,
                unavailable_modalities,
            });
            continue;
        }
        if observations.len() != modalities.len() {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "track {track_id} frame {} has {} observations for {} expected modalities",
                frame.identity.fusion_seq,
                observations.len(),
                modalities.len()
            )));
        }

        let history_reset = stream_reset || !lane.tracks.contains_key(&track_id);
        let history = lane.tracks.entry(track_id).or_insert_with(|| TrackHistory {
            frames: VecDeque::new(),
        });
        history.frames.push_back(observations);
        if history.frames.len() > history_frames {
            history.frames.pop_front();
        }
        let observation_count = history
            .frames
            .len()
            .checked_mul(modalities.len())
            .ok_or_else(|| {
                LifecycleDetectorError::InvalidFrame(
                    "bounded history observation count overflow".to_owned(),
                )
            })?;
        let mut stream = Vec::with_capacity(observation_count);
        for observations in &history.frames {
            stream.extend(observations.iter().cloned());
        }
        let report = assess_default(&stream, release_suite).map_err(|error| {
            LifecycleDetectorError::Assessment {
                track_id,
                fusion_seq: frame.identity.fusion_seq,
                reason: error.to_string(),
            }
        })?;
        assessments.push(LifecycleAssessment::Evaluated {
            track_id,
            fusion_seq: frame.identity.fusion_seq,
            history_reset,
            report: Box::new(report),
        });
    }
    if lane.tracks.len() > detector_config.max_tracks() {
        return Err(LifecycleDetectorError::TrackCapacity {
            actual: lane.tracks.len(),
            maximum: detector_config.max_tracks(),
        });
    }
    Ok(assessments)
}

fn frame_digest(frame: &AssembledFrame) -> Result<LifecycleDigest, LifecycleDetectorError> {
    let mut digest = Sha256::new();
    digest.update(b"galadriel-ncp/lifecycle-frame/v0.9\0");
    append_digest_bytes(&mut digest, frame.session_id().as_bytes());
    append_digest_bytes(&mut digest, frame.producer_id().as_bytes());
    for value in [
        frame.identity.fusion_seq,
        frame.identity.fusion_timestamp_ms,
        frame.identity.frame_id,
        frame.identity.context_id,
        frame.identity.prior_id,
    ] {
        digest.update(value.to_be_bytes());
    }
    digest.update((frame.monitor_events.len() as u128).to_be_bytes());
    for event in &frame.monitor_events {
        let (tag, encoded) = match event {
            FrameMonitorEvent::Outcome(outcome) => (
                0_u8,
                serde_json::to_vec(outcome)
                    .map_err(|error| LifecycleDetectorError::ReceiptEncoding(error.to_string()))?,
            ),
            FrameMonitorEvent::Miss(miss) => (
                1_u8,
                serde_json::to_vec(miss)
                    .map_err(|error| LifecycleDetectorError::ReceiptEncoding(error.to_string()))?,
            ),
        };
        digest.update([tag]);
        append_digest_bytes(&mut digest, &encoded);
    }
    digest.update((frame.observations.len() as u128).to_be_bytes());
    for observation in &frame.observations {
        let encoded = serde_json::to_vec(observation)
            .map_err(|error| LifecycleDetectorError::ReceiptEncoding(error.to_string()))?;
        append_digest_bytes(&mut digest, &encoded);
    }
    let summary = serde_json::to_vec(&frame.summary)
        .map_err(|error| LifecycleDetectorError::ReceiptEncoding(error.to_string()))?;
    append_digest_bytes(&mut digest, &summary);
    Ok(LifecycleDigest(digest.finalize().into()))
}

fn assessment_digest(
    release_suite: &ReleaseSuite,
    assessments: &[LifecycleAssessment],
) -> Result<LifecycleDigest, LifecycleDetectorError> {
    let encoded = serde_json::to_vec(assessments)
        .map_err(|error| LifecycleDetectorError::ReceiptEncoding(error.to_string()))?;
    Ok(assessment_digest_from_encoded(release_suite, &encoded))
}

fn assessment_digest_from_encoded(
    release_suite: &ReleaseSuite,
    encoded_assessments: &[u8],
) -> LifecycleDigest {
    let mut digest = Sha256::new();
    digest.update(b"galadriel-ncp/lifecycle-assessment/v0.9\0");
    digest.update(release_suite.identity().as_bytes());
    append_digest_bytes(&mut digest, encoded_assessments);
    LifecycleDigest(digest.finalize().into())
}

fn receipt_digest(
    index: u64,
    previous_digest: LifecycleDigest,
    producer_id: &ProducerId,
    position: &StreamPosition,
    transition: &LifecycleTransition,
    frame_digest: Option<LifecycleDigest>,
    assessment_digest: Option<LifecycleDigest>,
) -> Result<LifecycleDigest, LifecycleDetectorError> {
    let mut digest = Sha256::new();
    digest.update(b"galadriel-ncp/lifecycle-receipt/v0.9\0");
    digest.update(index.to_be_bytes());
    digest.update(previous_digest.as_bytes());
    append_digest_bytes(&mut digest, producer_id.as_str().as_bytes());
    let position = serde_json::to_vec(position)
        .map_err(|error| LifecycleDetectorError::ReceiptEncoding(error.to_string()))?;
    append_digest_bytes(&mut digest, &position);
    let transition = serde_json::to_vec(transition)
        .map_err(|error| LifecycleDetectorError::ReceiptEncoding(error.to_string()))?;
    append_digest_bytes(&mut digest, &transition);
    append_optional_digest(&mut digest, frame_digest);
    append_optional_digest(&mut digest, assessment_digest);
    Ok(LifecycleDigest(digest.finalize().into()))
}

fn append_optional_digest(digest: &mut Sha256, value: Option<LifecycleDigest>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn append_digest_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u128).to_be_bytes());
    digest.update(bytes);
}

fn validate_frame_identity(frame: &AssembledFrame) -> Result<(), LifecycleDetectorError> {
    let summary = &frame.summary;
    if summary.fusion_seq != frame.identity.fusion_seq
        || summary.fusion_timestamp_ms != frame.identity.fusion_timestamp_ms
        || summary.frame_id != frame.identity.frame_id
        || summary.context_id != frame.identity.context_id
        || summary.prior_id != frame.identity.prior_id
    {
        return Err(LifecycleDetectorError::InvalidFrame(
            "summary identity differs from assembled identity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_canonical_modalities(modalities: &[Modality]) -> Result<(), LifecycleDetectorError> {
    if modalities.is_empty()
        || modalities
            .windows(2)
            .any(|pair| modality_rank(pair[0]) >= modality_rank(pair[1]))
    {
        return Err(LifecycleDetectorError::InvalidFrame(
            "expected modalities must be nonempty, unique, and in canonical order".to_owned(),
        ));
    }
    Ok(())
}

fn frozen_track_ids(frame: &AssembledFrame) -> BTreeSet<u64> {
    frame
        .monitor_events
        .iter()
        .filter_map(|event| match event {
            FrameMonitorEvent::Outcome(outcome)
                if outcome.outcome != ModalityOutcomeKind::TrackBirth =>
            {
                Some(outcome.track_id)
            }
            FrameMonitorEvent::Outcome(_) => None,
            FrameMonitorEvent::Miss(miss) => Some(miss.track_id),
        })
        .collect()
}

fn validate_observation_ledger(
    frame: &AssembledFrame,
    frozen_tracks: &BTreeSet<u64>,
    modalities: &[Modality],
) -> Result<HashMap<u64, Vec<galadriel_core::PidObservation>>, LifecycleDetectorError> {
    let maximum_observations = frozen_tracks
        .len()
        .checked_mul(modalities.len())
        .ok_or_else(|| {
            LifecycleDetectorError::InvalidFrame(
                "frozen track × modality observation bound overflows usize".to_owned(),
            )
        })?;
    if frame.observations.len() > maximum_observations {
        return Err(LifecycleDetectorError::InvalidFrame(format!(
            "frame {} has {} observations; frozen Cartesian maximum is {maximum_observations}",
            frame.identity.fusion_seq,
            frame.observations.len(),
        )));
    }

    let mut pairs = HashSet::with_capacity(frame.observations.len());
    let mut by_track: HashMap<u64, Vec<galadriel_core::PidObservation>> =
        HashMap::with_capacity(frozen_tracks.len());
    for observation in &frame.observations {
        let track_id = observation.track_id().get();
        let modality = observation.modality();
        if !frozen_tracks.contains(&track_id) {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "observation track {} is absent from the frozen frame ledger",
                track_id,
            )));
        }
        if !modalities.contains(&modality) {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "track {} has observation for unexpected modality {:?}",
                track_id, modality,
            )));
        }
        if !pairs.insert((track_id, modality)) {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "duplicate observation for track {} / {:?}",
                track_id, modality,
            )));
        }
        if observation.sequence().get() != frame.identity.fusion_seq
            || observation.timestamp_ms().get() != frame.identity.fusion_timestamp_ms
        {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "track {} / {:?} observation sequence or timestamp differs from frame {}",
                track_id, modality, frame.identity.fusion_seq,
            )));
        }
        if let Some(projection) = observation.consistency_projection() {
            let identity = projection.identity();
            if identity.frame_id().get() != frame.identity.frame_id
                || identity.context_id().get() != frame.identity.context_id
                || identity.frozen_prior_id().get() != frame.identity.prior_id
            {
                return Err(LifecycleDetectorError::InvalidFrame(format!(
                    "track {} / {:?} projection provenance differs from frame {}",
                    track_id, modality, frame.identity.fusion_seq,
                )));
            }
        }
        by_track
            .entry(track_id)
            .or_default()
            .push(observation.clone());
    }
    for observations in by_track.values_mut() {
        observations.sort_by_key(|observation| modality_rank(observation.modality()));
    }
    Ok(by_track)
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
    use galadriel_core::{
        AssessmentClassification, ConsistencyProjection, CorrParams, DetectorParams, FusedVerdict,
        PidObservation, ReleaseProfile,
    };

    use super::*;
    use crate::assembler::FrameIdentity;
    use crate::monitor::{
        FrameSummary, GateEvidence, GateMethod, ModalityMiss, ModalityMissReason, ModalityOutcome,
    };

    const REGISTRY_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn correlation(window: usize, min_samples: usize) -> CorrConfig {
        CorrConfig::try_new(CorrParams {
            window,
            min_samples,
            ..CorrParams::standalone_advisory_v0_9()
        })
        .expect("test correlation config is valid")
    }

    fn detector() -> LifecycleDetector {
        detector_with_nis_alpha(0.01)
    }

    fn detector_with_nis_alpha(nis_alpha: f64) -> LifecycleDetector {
        LifecycleDetector::new(
            DetectorConfig::try_new(DetectorParams {
                window_len: 4,
                min_samples: 4,
                min_channels: 2,
                nis_alpha,
                ..DetectorParams::standalone_advisory_v0_9()
            })
            .expect("test detector config is valid"),
            correlation(4, 4),
        )
        .expect("test detector config validates")
    }

    #[test]
    fn aggregate_history_bound_rejects_cross_config_state_explosion() {
        let exact = LifecycleDetector::new(
            DetectorConfig::try_new(DetectorParams {
                window_len: 40,
                min_samples: 1,
                min_channels: 2,
                max_tracks: galadriel_core::config::MAX_DETECTOR_TRACKS,
                ..DetectorParams::standalone_advisory_v0_9()
            })
            .expect("exact aggregate-bound detector config is valid"),
            correlation(40, 4),
        )
        .expect("the exact lifecycle aggregate ceiling is inclusive");
        assert_eq!(exact.max_streams(), 1);
        assert_eq!(
            40 * galadriel_core::config::MAX_DETECTOR_TRACKS * Modality::ALL.len(),
            MAX_LIFECYCLE_RETAINED_OBSERVATIONS
        );

        let error = LifecycleDetector::new(
            DetectorConfig::try_new(DetectorParams {
                window_len: 1,
                min_samples: 1,
                min_channels: 2,
                max_tracks: 4,
                ..DetectorParams::standalone_advisory_v0_9()
            })
            .expect("test detector config is valid"),
            correlation(galadriel_core::correlation::MAX_CORRELATION_WINDOW, 4),
        )
        .expect_err("combined lifecycle retention must be bounded");

        assert!(matches!(
            error,
            LifecycleDetectorError::InvalidConfiguration(reason)
                if reason.contains("may retain")
        ));
    }

    #[test]
    fn lifecycle_stream_ceiling_is_exposed_exactly() {
        let detector = detector();

        assert_eq!(detector.max_streams(), 40);
        assert!(detector.max_streams() < MAX_LIFECYCLE_STREAMS);
        assert!(detector.max_streams() > 1);
    }

    #[test]
    fn lifecycle_eviction_counter_is_exposed_exactly() {
        let mut detector = detector();
        detector.evicted_receipts = 7;

        assert_eq!(detector.evicted_receipts(), 7);
    }

    #[test]
    fn lifecycle_receipt_index_accepts_the_json_safe_boundary_only() {
        let mut detector = detector();
        let frame = complete_frame(1, 11);
        detector.next_receipt_index = galadriel_core::JSON_SAFE_INTEGER_MAX;
        let receipt = detector
            .commit_receipt(
                ProducerId::new("crebain").expect("test producer is valid"),
                positioned(&frame, 0),
                LifecycleTransition::Rejected {
                    reason: LifecycleIngressRejection::UnknownStream,
                },
                None,
                None,
            )
            .expect("the exact JSON-safe receipt index is inclusive");
        assert_eq!(receipt.index(), galadriel_core::JSON_SAFE_INTEGER_MAX);
        let encoded = serde_json::to_vec(&receipt).expect("boundary receipt serializes");
        assert_eq!(
            LifecycleReceipt::decode_and_verify(&encoded)
                .expect("the exact JSON-safe receipt index decodes")
                .index(),
            galadriel_core::JSON_SAFE_INTEGER_MAX
        );
        assert_eq!(
            detector
                .commit_receipt(
                    ProducerId::new("crebain").expect("test producer is valid"),
                    positioned(&frame, 0),
                    LifecycleTransition::Initialized,
                    None,
                    None,
                )
                .unwrap_err(),
            LifecycleDetectorError::ReceiptIndexExhausted
        );
    }

    #[test]
    fn frame_sidecar_cardinality_rejects_each_identity_bound_independently() {
        let cases = [
            (String::new(), "crebain".to_owned()),
            (
                "s".repeat(crate::MAX_ID_SEGMENT_BYTES + 1),
                "crebain".to_owned(),
            ),
            ("epoch-1".to_owned(), String::new()),
            (
                "epoch-1".to_owned(),
                "p".repeat(crate::MAX_ID_SEGMENT_BYTES + 1),
            ),
            ("uav+3".to_owned(), "crebain".to_owned()),
            ("époch1".to_owned(), "crebain".to_owned()),
            ("-uav3".to_owned(), "crebain".to_owned()),
            ("uav3".to_owned(), "crebain-".to_owned()),
        ];

        for (session_id, producer_id) in cases {
            let mut frame = complete_frame(1, 11);
            frame.session_id = session_id;
            frame.producer_id = producer_id;
            assert!(matches!(
                validate_frame_cardinality(&frame, 1),
                Err(LifecycleDetectorError::InvalidFrame(reason))
                    if reason.contains("canonical sidecar domain")
            ));
        }
    }

    #[test]
    fn frame_cardinality_bounds_are_inclusive_and_reject_one_more_directly() {
        let mut exact = complete_frame(1, 11);
        exact.session_id = "s".repeat(crate::MAX_ID_SEGMENT_BYTES);
        exact.producer_id = "p".repeat(crate::MAX_ID_SEGMENT_BYTES);
        exact.summary.expected_modalities = Modality::ALL.to_vec();
        exact.monitor_events = vec![exact.monitor_events[0].clone(); MAX_FRAME_ITEMS as usize];
        assert!(validate_frame_cardinality(&exact, 1).is_ok());

        let mut too_many_modalities = complete_frame(1, 11);
        too_many_modalities.summary.expected_modalities = Modality::ALL.to_vec();
        too_many_modalities
            .summary
            .expected_modalities
            .push(Modality::Visual);
        assert!(validate_frame_cardinality(&too_many_modalities, 1).is_err());

        let mut too_many_events = complete_frame(1, 11);
        too_many_events.monitor_events =
            vec![too_many_events.monitor_events[0].clone(); MAX_FRAME_ITEMS as usize + 1];
        assert!(validate_frame_cardinality(&too_many_events, 1).is_err());

        let mut exact_observations = complete_frame(1, 11);
        exact_observations.observations =
            vec![exact_observations.observations[0].clone(); Modality::ALL.len()];
        assert!(validate_frame_cardinality(&exact_observations, 1).is_ok());

        let mut too_many_observations = exact_observations;
        too_many_observations
            .observations
            .push(too_many_observations.observations[0].clone());
        assert!(validate_frame_cardinality(&too_many_observations, 1).is_err());
    }

    fn identity(fusion_seq: u64, context_id: u64) -> FrameIdentity {
        FrameIdentity {
            fusion_seq,
            fusion_timestamp_ms: (fusion_seq + 1) * 100,
            frame_id: 7,
            context_id,
            prior_id: fusion_seq + 1,
        }
    }

    fn observation(identity: FrameIdentity, modality: Modality) -> PidObservation {
        let offset = match modality {
            Modality::Visual => 0.0,
            Modality::Radar => 0.1,
            _ => 0.2,
        };
        let projection = ConsistencyProjection::try_new_raw(
            [identity.fusion_seq as f64 + offset, 0.0, 0.0],
            1,
            identity.frame_id,
            identity.context_id,
            identity.prior_id,
        )
        .expect("test projection is valid");
        test_observation(
            1,
            identity.fusion_timestamp_ms,
            identity.fusion_seq,
            modality,
            3.0,
            Some(projection),
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

    fn outcome(identity: FrameIdentity, modality: Modality) -> FrameMonitorEvent {
        FrameMonitorEvent::Outcome(ModalityOutcome {
            fusion_seq: identity.fusion_seq,
            fusion_timestamp_ms: identity.fusion_timestamp_ms,
            frame_id: identity.frame_id,
            context_id: identity.context_id,
            prior_id: identity.prior_id,
            track_id: 1,
            modality,
            attempt_index: 0,
            measurement_index: Some(0),
            outcome: ModalityOutcomeKind::Updated,
            v1_expected: true,
            candidate_count: 1,
            in_gate_count: 1,
            gate_evidence: Some(GateEvidence {
                method: GateMethod::Mahalanobis,
                d2: 1.0,
                threshold: 7.0,
            }),
            consistency_projection: observation(identity, modality)
                .consistency_projection()
                .cloned(),
        })
    }

    fn complete_frame(fusion_seq: u64, context_id: u64) -> AssembledFrame {
        let identity = identity(fusion_seq, context_id);
        let modalities = vec![Modality::Visual, Modality::Radar];
        AssembledFrame {
            session_id: "epoch-1".to_owned(),
            producer_id: "crebain".to_owned(),
            identity,
            monitor_events: modalities
                .iter()
                .copied()
                .map(|modality| outcome(identity, modality))
                .collect(),
            observations: modalities
                .iter()
                .copied()
                .map(|modality| observation(identity, modality))
                .collect(),
            summary: FrameSummary {
                fusion_seq: identity.fusion_seq,
                fusion_timestamp_ms: identity.fusion_timestamp_ms,
                frame_id: identity.frame_id,
                context_id: identity.context_id,
                prior_id: identity.prior_id,
                registry_digest: REGISTRY_DIGEST.to_owned(),
                expected_modalities: modalities,
                active_track_count: 1,
                input_count: 2,
                outcome_count: 2,
                v1_expected_count: 2,
                degraded: false,
                truncated: false,
            },
        }
    }

    fn miss_frame(fusion_seq: u64) -> AssembledFrame {
        let mut frame = complete_frame(fusion_seq, 11);
        frame.monitor_events.pop();
        frame
            .monitor_events
            .push(FrameMonitorEvent::Miss(ModalityMiss {
                fusion_seq,
                fusion_timestamp_ms: frame.identity.fusion_timestamp_ms,
                frame_id: frame.identity.frame_id,
                context_id: frame.identity.context_id,
                prior_id: frame.identity.prior_id,
                track_id: 1,
                modality: Modality::Radar,
                reason: ModalityMissReason::NoMeasurement,
            }));
        frame.observations.pop();
        frame.summary.v1_expected_count = 1;
        frame
    }

    fn birth_frame(fusion_seq: u64) -> AssembledFrame {
        let mut frame = complete_frame(fusion_seq, 11);
        let FrameMonitorEvent::Outcome(mut birth) = frame.monitor_events.remove(0) else {
            panic!("complete fixture begins with an outcome")
        };
        birth.outcome = ModalityOutcomeKind::TrackBirth;
        birth.v1_expected = false;
        birth.candidate_count = 0;
        birth.in_gate_count = 0;
        birth.gate_evidence = None;
        birth.consistency_projection = None;
        frame.monitor_events = vec![FrameMonitorEvent::Outcome(birth)];
        frame.observations.clear();
        frame.summary.active_track_count = 1;
        frame.summary.input_count = 1;
        frame.summary.outcome_count = 1;
        frame.summary.v1_expected_count = 0;
        frame
    }

    fn set_fusion_timestamp(frame: &mut AssembledFrame, timestamp_ms: u64) {
        frame.identity.fusion_timestamp_ms = timestamp_ms;
        frame.summary.fusion_timestamp_ms = timestamp_ms;
        for observation in &mut frame.observations {
            *observation = test_observation(
                observation.track_id().get(),
                timestamp_ms,
                observation.sequence().get(),
                observation.modality(),
                observation.nis(),
                observation.consistency_projection().cloned(),
            );
        }
        for event in &mut frame.monitor_events {
            match event {
                FrameMonitorEvent::Outcome(outcome) => {
                    outcome.fusion_timestamp_ms = timestamp_ms;
                }
                FrameMonitorEvent::Miss(miss) => {
                    miss.fusion_timestamp_ms = timestamp_ms;
                }
            }
        }
    }

    fn set_epoch(frame: &mut AssembledFrame, session_id: &str, producer_id: &str) {
        frame.session_id = session_id.to_owned();
        frame.producer_id = producer_id.to_owned();
    }

    fn positioned(frame: &AssembledFrame, state_generation: u64) -> StreamPosition {
        StreamPosition::try_new(
            "mission-1",
            frame.session_id(),
            "fusion",
            state_generation,
            frame.identity.fusion_seq,
            frame.identity.fusion_timestamp_ms,
            ClockDomain::MonotonicProcess,
        )
        .expect("test position is valid")
    }

    fn assert_invalid_frame(frame: AssembledFrame, expected_reason: &str) {
        let mut detector = detector();
        let error = detector
            .assess_frame(&frame)
            .expect_err("fabricated frame must fail closed");
        assert!(matches!(
            &error,
            LifecycleDetectorError::InvalidFrame(reason) if reason.contains(expected_reason)
        ));
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn observation_count_above_frozen_cartesian_bound_is_terminal() {
        let mut frame = complete_frame(1, 11);
        frame.observations.push(frame.observations[0].clone());

        assert_invalid_frame(frame, "frozen Cartesian maximum");
    }

    #[test]
    fn oversized_monitor_ledger_is_rejected_before_fingerprint_or_set_allocation() {
        let mut detector = detector();
        let mut frame = complete_frame(1, 11);
        frame.monitor_events =
            vec![frame.monitor_events[0].clone(); (MAX_FRAME_ITEMS as usize) + 1];

        let error = detector
            .assess_frame(&frame)
            .expect_err("oversized forged monitor ledger must fail at cardinality gate");

        assert!(matches!(
            error,
            LifecycleDetectorError::InvalidFrame(reason)
                if reason.contains("monitor events; maximum")
        ));
        assert!(detector.receipts().is_empty());
        assert_eq!(detector.retained_streams(), 0);
    }

    #[test]
    fn oversized_observation_ledger_is_rejected_before_hash_set_allocation() {
        let mut detector = detector();
        let mut frame = complete_frame(1, 11);
        let maximum = detector.detector_config.max_tracks() * Modality::ALL.len();
        frame.observations = vec![frame.observations[0].clone(); maximum + 1];

        let error = detector
            .assess_frame(&frame)
            .expect_err("oversized forged observation ledger must fail at cardinality gate");

        assert!(matches!(
            error,
            LifecycleDetectorError::InvalidFrame(reason)
                if reason.contains("observations; lifecycle maximum")
        ));
        assert!(detector.receipts().is_empty());
        assert_eq!(detector.retained_streams(), 0);
    }

    #[test]
    fn observation_for_track_outside_frozen_ledger_is_terminal() {
        let mut frame = complete_frame(1, 11);
        let previous = &frame.observations[1];
        frame.observations[1] = test_observation(
            2,
            previous.timestamp_ms().get(),
            previous.sequence().get(),
            previous.modality(),
            previous.nis(),
            previous.consistency_projection().cloned(),
        );

        assert_invalid_frame(frame, "absent from the frozen frame ledger");
    }

    #[test]
    fn duplicate_or_unexpected_observation_modality_is_terminal() {
        let mut duplicate = complete_frame(1, 11);
        duplicate.observations[1] = observation(duplicate.identity, Modality::Visual);
        assert_invalid_frame(duplicate, "duplicate observation");

        let mut unexpected = complete_frame(1, 11);
        unexpected.observations[1] = observation(unexpected.identity, Modality::Thermal);
        assert_invalid_frame(unexpected, "unexpected modality");
    }

    #[test]
    fn observation_identity_or_projection_provenance_mismatch_is_terminal() {
        let mut wrong_sequence = complete_frame(1, 11);
        let previous = &wrong_sequence.observations[0];
        wrong_sequence.observations[0] = test_observation(
            previous.track_id().get(),
            previous.timestamp_ms().get(),
            2,
            previous.modality(),
            previous.nis(),
            previous.consistency_projection().cloned(),
        );
        assert_invalid_frame(wrong_sequence, "sequence or timestamp differs");

        let mut wrong_timestamp = complete_frame(1, 11);
        let previous = &wrong_timestamp.observations[0];
        wrong_timestamp.observations[0] = test_observation(
            previous.track_id().get(),
            previous.timestamp_ms().get() + 1,
            previous.sequence().get(),
            previous.modality(),
            previous.nis(),
            previous.consistency_projection().cloned(),
        );
        assert_invalid_frame(wrong_timestamp, "sequence or timestamp differs");

        let mut wrong_projection_frame = complete_frame(1, 11);
        wrong_projection_frame.observations[0] = test_observation(
            1,
            wrong_projection_frame.identity.fusion_timestamp_ms,
            wrong_projection_frame.identity.fusion_seq,
            Modality::Visual,
            3.0,
            Some(
                ConsistencyProjection::try_new_raw(
                    [1.0, 0.0, 0.0],
                    1,
                    wrong_projection_frame.identity.frame_id + 1,
                    wrong_projection_frame.identity.context_id,
                    wrong_projection_frame.identity.prior_id,
                )
                .expect("mismatched projection remains structurally valid"),
            ),
        );
        assert_invalid_frame(wrong_projection_frame, "projection provenance differs");

        let mut wrong_projection_context = complete_frame(1, 11);
        wrong_projection_context.observations[0] = test_observation(
            1,
            wrong_projection_context.identity.fusion_timestamp_ms,
            wrong_projection_context.identity.fusion_seq,
            Modality::Visual,
            3.0,
            Some(
                ConsistencyProjection::try_new_raw(
                    [1.0, 0.0, 0.0],
                    1,
                    wrong_projection_context.identity.frame_id,
                    wrong_projection_context.identity.context_id + 1,
                    wrong_projection_context.identity.prior_id,
                )
                .expect("mismatched projection remains structurally valid"),
            ),
        );
        assert_invalid_frame(wrong_projection_context, "projection provenance differs");

        let mut wrong_projection_prior = complete_frame(1, 11);
        wrong_projection_prior.observations[0] = test_observation(
            1,
            wrong_projection_prior.identity.fusion_timestamp_ms,
            wrong_projection_prior.identity.fusion_seq,
            Modality::Visual,
            3.0,
            Some(
                ConsistencyProjection::try_new_raw(
                    [1.0, 0.0, 0.0],
                    1,
                    wrong_projection_prior.identity.frame_id,
                    wrong_projection_prior.identity.context_id,
                    wrong_projection_prior.identity.prior_id + 1,
                )
                .expect("mismatched projection remains structurally valid"),
            ),
        );
        assert_invalid_frame(wrong_projection_prior, "projection provenance differs");
    }

    #[test]
    fn every_summary_identity_field_must_match_the_assembled_identity() {
        let mut wrong_sequence = complete_frame(1, 11);
        wrong_sequence.summary.fusion_seq += 1;
        assert_invalid_frame(wrong_sequence, "summary identity differs");

        let mut wrong_timestamp = complete_frame(1, 11);
        wrong_timestamp.summary.fusion_timestamp_ms += 1;
        assert_invalid_frame(wrong_timestamp, "summary identity differs");

        let mut wrong_frame = complete_frame(1, 11);
        wrong_frame.summary.frame_id += 1;
        assert_invalid_frame(wrong_frame, "summary identity differs");

        let mut wrong_context = complete_frame(1, 11);
        wrong_context.summary.context_id += 1;
        assert_invalid_frame(wrong_context, "summary identity differs");

        let mut wrong_prior = complete_frame(1, 11);
        wrong_prior.summary.prior_id += 1;
        assert_invalid_frame(wrong_prior, "summary identity differs");
    }

    #[test]
    fn individually_invalid_observation_cannot_cross_construction_boundary() {
        assert!(PidObservation::try_scalar_raw(1, 100, 1, Modality::Visual, f64::NAN, 3,).is_err());
    }

    #[test]
    fn complete_suffix_is_bounded_and_eventually_evaluated() {
        let mut detector = detector();
        for fusion_seq in 1..=4 {
            let assessments = detector
                .assess_frame(&complete_frame(fusion_seq, 11))
                .expect("complete frame evaluates");
            let LifecycleAssessment::Evaluated {
                history_reset,
                report,
                ..
            } = &assessments[0]
            else {
                panic!("complete frame must be evaluated")
            };
            assert_eq!(*history_reset, fusion_seq == 1);
            if fusion_seq == 4 {
                assert!(report
                    .baseline()
                    .channels()
                    .iter()
                    .all(|channel| channel.ready()));
            }
        }
        assert_eq!(detector.retained_tracks(), 1);
    }

    #[test]
    fn accepted_frames_commit_deterministic_hash_linked_receipts() {
        let mut left = detector();
        let mut right = detector();

        let left_first = left
            .assess_frame_transition(&complete_frame(1, 11))
            .expect("first frame commits");
        let left_second = left
            .assess_frame_transition(&complete_frame(2, 11))
            .expect("second frame commits");
        let right_first = right
            .assess_frame_transition(&complete_frame(1, 11))
            .expect("same first frame commits deterministically");
        let right_second = right
            .assess_frame_transition(&complete_frame(2, 11))
            .expect("same second frame commits deterministically");

        assert_eq!(
            left_first.receipt().digest(),
            right_first.receipt().digest()
        );
        assert_eq!(
            left_second.receipt().digest(),
            right_second.receipt().digest()
        );
        assert!(left_first.receipt().verifies());
        assert!(left_second.receipt().follows(left_first.receipt()));
        assert_eq!(left_second.receipt().index(), 1);
        assert_eq!(
            left_second.receipt().previous_digest(),
            left_first.receipt().digest()
        );
        assert_eq!(left_second.receipt().producer_id().as_str(), "crebain");
        assert_eq!(left_second.receipt().position().sequence().get(), 2);
        assert!(matches!(
            left_second.receipt().transition(),
            LifecycleTransition::Advanced
        ));
        assert!(left_second.receipt().frame_digest().is_some());
        assert!(left_second.receipt().assessment_digest().is_some());
        let encoded_second = serde_json::to_vec(left_second.receipt())
            .expect("non-origin lifecycle receipt serializes");
        assert_eq!(
            LifecycleReceipt::decode_and_verify(&encoded_second)
                .expect("non-origin lifecycle receipt decodes")
                .digest(),
            left_second.receipt().digest()
        );
        assert_eq!(left.retained_streams(), 1);
        assert_eq!(left.receipts().len(), 2);
        assert_eq!(left.last_receipt(), Some(left_second.receipt()));
        assert_eq!(left.receipt_anchor(), LifecycleDigest::ZERO);
        assert_eq!(left.evicted_receipts(), 0);
    }

    #[test]
    fn frozen_receipt_golden_vector_decodes_and_verifies_independently() {
        let encoded = include_bytes!("../tests/fixtures/lifecycle-receipt-v0.9.json");
        assert_eq!(
            MAX_LIFECYCLE_RECEIPT_BYTES,
            16_usize
                .checked_mul(1_024)
                .expect("the platform represents the receipt byte ceiling")
        );
        let receipt = LifecycleReceipt::decode_and_verify(encoded)
            .expect("frozen receipt vector must decode and verify");

        assert_eq!(receipt.index(), 0);
        assert_eq!(receipt.producer_id().as_str(), "crebain");
        assert!(matches!(
            receipt.transition(),
            LifecycleTransition::Initialized
        ));
        assert_eq!(
            receipt.digest().to_hex(),
            "7ff603b62f4b775e2a438608ba60eec9c4226d39f78849257100b9b2e648d429"
        );
        let canonical = serde_json::to_vec(&receipt).expect("decoded receipt reserializes");
        assert_eq!(encoded.strip_suffix(b"\n").unwrap_or(encoded), canonical);

        let mut invalid_chain_origin = receipt.clone();
        invalid_chain_origin.previous_digest = LifecycleDigest([1; 32]);
        assert!(!invalid_chain_origin.has_valid_detector_shape());

        let mut initialized_without_assessment = receipt.clone();
        initialized_without_assessment.assessment_digest = None;
        assert!(!initialized_without_assessment.has_valid_detector_shape());

        let mut valid_reset = receipt.clone();
        valid_reset.transition = LifecycleTransition::Reset {
            reasons: LifecycleResetReasons::new(vec![LifecycleResetReason::Explicit]),
        };
        assert!(valid_reset.has_valid_detector_shape());

        let mut empty_fault_reason = receipt.clone();
        empty_fault_reason.transition = LifecycleTransition::Faulted {
            reason: String::new(),
        };
        empty_fault_reason.assessment_digest = None;
        assert!(!empty_fault_reason.has_valid_detector_shape());

        let mut missing_fault_frame = receipt.clone();
        missing_fault_frame.transition = LifecycleTransition::Faulted {
            reason: "exact fault".to_owned(),
        };
        missing_fault_frame.frame_digest = None;
        missing_fault_frame.assessment_digest = None;
        assert!(!missing_fault_frame.has_valid_detector_shape());

        let mut valid_fault = receipt.clone();
        valid_fault.transition = LifecycleTransition::Faulted {
            reason: "exact fault".to_owned(),
        };
        valid_fault.assessment_digest = None;
        assert!(valid_fault.has_valid_detector_shape());

        let mut exact_ceiling = canonical.clone();
        exact_ceiling.resize(MAX_LIFECYCLE_RECEIPT_BYTES, b' ');
        assert!(LifecycleReceipt::decode_and_verify(&exact_ceiling).is_ok());
        let mut one_over = exact_ceiling;
        one_over.push(b' ');
        assert!(matches!(
            LifecycleReceipt::decode_and_verify(&one_over),
            Err(LifecycleReceiptDecodeError::TooLarge { actual })
                if actual == MAX_LIFECYCLE_RECEIPT_BYTES + 1
        ));
    }

    #[test]
    fn lifecycle_transition_history_semantics_cover_every_variant() {
        assert!(LifecycleTransition::Initialized.resets_history());
        assert!(LifecycleTransition::Reset {
            reasons: LifecycleResetReasons::new(vec![LifecycleResetReason::Explicit]),
        }
        .resets_history());
        assert!(LifecycleTransition::EpochRolledOver {
            previous_epoch_id: EpochId::new("epoch-1").unwrap(),
        }
        .resets_history());
        assert!(!LifecycleTransition::Advanced.resets_history());
        assert!(!LifecycleTransition::Rejected {
            reason: LifecycleIngressRejection::UnknownStream,
        }
        .resets_history());
        assert!(!LifecycleTransition::Faulted {
            reason: "exact fault".to_owned(),
        }
        .resets_history());
    }

    #[test]
    fn lifecycle_digest_shape_rejects_length_and_alphabet_independently() {
        let short_lowercase = format!("\"{}\"", "a".repeat(63));
        let exact_length_nonhex = format!("\"{}g\"", "a".repeat(63));
        let exact_length_uppercase = format!("\"{}A\"", "a".repeat(63));

        assert!(serde_json::from_str::<LifecycleDigest>(&short_lowercase).is_err());
        assert!(serde_json::from_str::<LifecycleDigest>(&exact_length_nonhex).is_err());
        assert!(serde_json::from_str::<LifecycleDigest>(&exact_length_uppercase).is_err());
    }

    #[test]
    fn lifecycle_reset_reason_accessors_preserve_multiple_reasons() {
        let reasons = LifecycleResetReasons::new(vec![
            LifecycleResetReason::Explicit,
            LifecycleResetReason::Timeout,
        ]);

        assert_eq!(reasons.len(), 2);
        assert!(!reasons.is_empty());
        assert_eq!(
            reasons.as_slice(),
            &[
                LifecycleResetReason::Explicit,
                LifecycleResetReason::Timeout,
            ]
        );

        let explicit = serde_json::from_str::<LifecycleResetReasons>(r#"[{"kind":"explicit"}]"#)
            .expect("the explicit singleton is a canonical reset-reason set");
        assert_eq!(explicit.len(), 1);
        assert_eq!(explicit.as_slice(), &[LifecycleResetReason::Explicit]);
        assert!(serde_json::from_str::<LifecycleResetReasons>("[]").is_err());

        let canonical_multi = serde_json::from_str::<LifecycleResetReasons>(
            r#"[{"kind":"projection_frame_changed"},{"kind":"projection_context_changed"}]"#,
        )
        .expect("ordered structural reasons form a canonical set");
        assert_eq!(canonical_multi.len(), 2);
        assert!(serde_json::from_str::<LifecycleResetReasons>(
            r#"[{"kind":"explicit"},{"kind":"projection_frame_changed"}]"#,
        )
        .is_err());
        assert!(serde_json::from_str::<LifecycleResetReasons>(
            r#"[{"kind":"projection_frame_changed"},{"kind":"projection_frame_changed"}]"#,
        )
        .is_err());
    }

    #[test]
    fn receipt_successor_check_does_not_saturate_at_u64_max() {
        let encoded = include_bytes!("../tests/fixtures/lifecycle-receipt-v0.9.json");
        let mut previous = serde_json::from_slice::<LifecycleReceipt>(encoded)
            .expect("frozen receipt vector decodes");
        previous.index = u64::MAX;
        previous.digest = receipt_digest(
            previous.index,
            previous.previous_digest,
            &previous.producer_id,
            &previous.position,
            &previous.transition,
            previous.frame_digest,
            previous.assessment_digest,
        )
        .expect("mutated predecessor digest recomputes");

        let mut candidate = previous.clone();
        candidate.previous_digest = previous.digest;
        candidate.digest = receipt_digest(
            candidate.index,
            candidate.previous_digest,
            &candidate.producer_id,
            &candidate.position,
            &candidate.transition,
            candidate.frame_digest,
            candidate.assessment_digest,
        )
        .expect("mutated candidate digest recomputes");

        assert!(previous.verifies());
        assert!(candidate.verifies());
        assert!(!candidate.follows(&previous));
        let previous = serde_json::to_vec(&previous).expect("mutated predecessor serializes");
        assert!(matches!(
            LifecycleReceipt::decode_and_verify(&previous),
            Err(LifecycleReceiptDecodeError::InvalidShape)
        ));
    }

    #[test]
    fn serialized_numeric_report_field_is_bound_into_the_assessment_digest() {
        let mut detector = detector();
        let release_suite = detector
            .release_suite_for(&[Modality::Visual, Modality::Radar])
            .expect("fixture modalities form the detector's release suite");
        let outcome = detector
            .assess_frame_transition(&complete_frame(1, 11))
            .expect("complete frame commits");
        assert!(outcome
            .receipt()
            .verifies_assessments(&release_suite, outcome.assessments()));
        let alternate_suite = detector_with_nis_alpha(0.02)
            .release_suite_for(&[Modality::Visual, Modality::Radar])
            .expect("alternate fixture modalities form a release suite");
        assert!(!outcome
            .receipt()
            .verifies_assessments(&alternate_suite, outcome.assessments()));
        assert!(!outcome.receipt().verifies_assessments(&release_suite, &[]));

        let encoded = serde_json::to_vec(outcome.assessments())
            .expect("detector-created assessments serialize");
        let expected = outcome
            .receipt()
            .assessment_digest()
            .expect("accepted frame carries assessment evidence");
        assert_eq!(
            assessment_digest_from_encoded(&release_suite, &encoded),
            expected
        );

        let needle = br#""sum_nis":3.0"#;
        let start = encoded
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("serialized baseline exposes the exact numeric sum_nis field");
        let mut mutated = encoded;
        let numeric_offset = start + needle.len() - 3;
        assert_eq!(mutated[numeric_offset], b'3');
        mutated[numeric_offset] = b'4';

        assert_ne!(
            assessment_digest_from_encoded(&release_suite, &mutated),
            expected,
            "changing one serialized numeric report field must change the evidence digest"
        );
    }

    #[test]
    fn fault_receipt_binds_the_exact_reason_and_rejects_one_field_mutation() {
        let mut detector = detector();
        let mut invalid = complete_frame(1, 11);
        invalid.summary.expected_modalities.reverse();

        let error = detector
            .assess_frame(&invalid)
            .expect_err("noncanonical modalities fault the detector");
        let receipt = detector
            .last_receipt()
            .expect("positioned structural fault commits a receipt");
        assert!(matches!(
            receipt.transition(),
            LifecycleTransition::Faulted { reason } if reason == &error.to_string()
        ));
        assert!(receipt.verifies());

        let mut encoded = serde_json::to_value(receipt).expect("receipt serializes");
        let reason = encoded
            .pointer_mut("/transition/reason")
            .and_then(|value| value.as_str())
            .expect("fault receipt serializes its exact reason")
            .to_owned();
        encoded["transition"]["reason"] = serde_json::Value::String(format!("{reason}."));
        let encoded = serde_json::to_vec(&encoded).expect("mutated receipt serializes");

        assert!(matches!(
            LifecycleReceipt::decode_and_verify(&encoded),
            Err(LifecycleReceiptDecodeError::DigestMismatch)
        ));
    }

    #[test]
    fn abstained_assessment_receipt_binds_the_accepted_release_suite() {
        let frame = miss_frame(1);
        let mut left = detector_with_nis_alpha(0.01);
        let mut right = detector_with_nis_alpha(0.02);

        let left = left
            .assess_frame_transition(&frame)
            .expect("left suite abstains explicitly");
        let right = right
            .assess_frame_transition(&frame)
            .expect("right suite abstains explicitly");

        assert!(matches!(
            left.assessments(),
            [LifecycleAssessment::Abstained { .. }]
        ));
        assert!(matches!(
            right.assessments(),
            [LifecycleAssessment::Abstained { .. }]
        ));
        assert_eq!(
            left.receipt().frame_digest(),
            right.receipt().frame_digest()
        );
        assert_ne!(
            left.receipt().assessment_digest(),
            right.receipt().assessment_digest()
        );
        assert_ne!(left.receipt().digest(), right.receipt().digest());
    }

    #[test]
    fn empty_assessment_receipt_binds_the_accepted_release_suite() {
        let mut frame = complete_frame(1, 11);
        frame.monitor_events.clear();
        frame.observations.clear();
        frame.summary.active_track_count = 0;
        frame.summary.input_count = 0;
        frame.summary.outcome_count = 0;
        frame.summary.v1_expected_count = 0;
        let mut left = detector_with_nis_alpha(0.01);
        let mut right = detector_with_nis_alpha(0.02);

        let left = left
            .assess_frame_transition(&frame)
            .expect("left suite accepts the empty closure");
        let right = right
            .assess_frame_transition(&frame)
            .expect("right suite accepts the empty closure");

        assert!(left.assessments().is_empty());
        assert!(right.assessments().is_empty());
        assert_eq!(
            left.receipt().frame_digest(),
            right.receipt().frame_digest()
        );
        assert_ne!(
            left.receipt().assessment_digest(),
            right.receipt().assessment_digest()
        );
        assert_ne!(left.receipt().digest(), right.receipt().digest());
    }

    #[test]
    fn exact_duplicate_is_rejected_and_receipted_without_reassessment() {
        let mut detector = detector();
        let frame = complete_frame(1, 11);
        detector
            .assess_frame_transition(&frame)
            .expect("first frame commits");

        let error = detector
            .assess_frame_transition(&frame)
            .expect_err("exact duplicate must be rejected");

        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::Duplicate { sequence: 1 })
        ));
        assert!(matches!(
            detector.last_receipt().map(LifecycleReceipt::transition),
            Some(LifecycleTransition::Rejected {
                reason: LifecycleIngressRejection::Duplicate { sequence: 1 }
            })
        ));
        assert_eq!(detector.receipts().len(), 2);
    }

    #[test]
    fn same_position_with_different_evidence_is_conflicting_replay() {
        let mut detector = detector();
        let frame = complete_frame(1, 11);
        detector
            .assess_frame_transition(&frame)
            .expect("first frame commits");
        let mut conflicting = frame.clone();
        let previous = &conflicting.observations[0];
        conflicting.observations[0] = test_observation(
            previous.track_id().get(),
            previous.timestamp_ms().get(),
            previous.sequence().get(),
            previous.modality(),
            previous.nis() + 1.0,
            previous.consistency_projection().cloned(),
        );

        let error = detector
            .assess_frame_transition(&conflicting)
            .expect_err("conflicting evidence at an accepted position must fail");

        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::ConflictingReplay {
                sequence: 1,
                current: 1
            })
        ));
    }

    #[test]
    fn older_retained_frame_is_classified_as_replay() {
        let mut detector = detector();
        let first = complete_frame(1, 11);
        detector
            .assess_frame_transition(&first)
            .expect("first frame commits");
        detector
            .assess_frame_transition(&complete_frame(2, 11))
            .expect("second frame commits");

        let error = detector
            .assess_frame_transition(&first)
            .expect_err("older retained frame must be rejected as replay");

        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::Replay {
                sequence: 1,
                current: 2
            })
        ));
    }

    #[test]
    fn older_unretained_position_is_classified_as_reordered() {
        let mut detector = detector();
        let first = complete_frame(1, 11);
        detector
            .assess_frame_transition(&first)
            .expect("first frame commits");
        detector
            .assess_frame_transition(&complete_frame(2, 11))
            .expect("second frame commits");
        detector
            .lanes
            .values_mut()
            .next()
            .expect("one test lane exists")
            .recent_frames
            .clear();

        let error = detector
            .assess_frame_transition(&first)
            .expect_err("an older position without a retained fingerprint is reordered");

        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::Reordered {
                sequence: 1,
                current: 2
            })
        ));
    }

    #[test]
    fn explicit_reset_consumes_exact_position_and_next_frame_starts_fresh() {
        let mut detector = detector();
        let first = complete_frame(1, 11);
        let first_position = positioned(&first, 0);
        detector
            .assess_positioned_frame(first_position.clone(), &first)
            .expect("first positioned frame commits");
        let reset_position = first_position
            .checked_reset(first.identity.fusion_timestamp_ms + 1)
            .expect("exact reset successor is valid");

        let reset = detector
            .reset_at("crebain", reset_position)
            .expect("explicit reset commits");
        let next = complete_frame(3, 11);
        let next_outcome = detector
            .assess_positioned_frame(positioned(&next, 1), &next)
            .expect("post-reset exact successor evaluates");

        assert!(matches!(
            reset.transition(),
            LifecycleTransition::Reset { reasons }
                if reasons.as_slice() == [LifecycleResetReason::Explicit]
        ));
        assert!(matches!(
            next_outcome.assessments(),
            [LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }]
        ));
        assert!(next_outcome.receipt().follows(&reset));
    }

    #[test]
    fn positioned_admission_enforces_exact_explicit_and_required_generations() {
        let first = complete_frame(1, 11);

        let mut explicit = detector();
        explicit
            .assess_positioned_frame(positioned(&first, 0), &first)
            .expect("first explicit-reset fixture frame commits");
        let next = complete_frame(2, 11);
        let reset = explicit
            .assess_positioned_frame(positioned(&next, 1), &next)
            .expect("exact successor generation is an explicit reset");
        assert!(matches!(
            reset.receipt().transition(),
            LifecycleTransition::Reset { reasons }
                if reasons.as_slice() == [LifecycleResetReason::Explicit]
        ));

        let mut skipped = detector();
        skipped
            .assess_positioned_frame(positioned(&first, 0), &first)
            .expect("first skipped-generation fixture frame commits");
        let error = skipped
            .assess_positioned_frame(positioned(&next, 2), &next)
            .expect_err("an unrequired generation skip must fail closed");
        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::StateGenerationMismatch {
                current: 0,
                received: 2,
                required: 0
            })
        ));

        let mut required = detector();
        required
            .assess_positioned_frame(positioned(&first, 0), &first)
            .expect("first required-reset fixture frame commits");
        let changed_context = complete_frame(2, 12);
        let error = required
            .assess_positioned_frame(positioned(&changed_context, 2), &changed_context)
            .expect_err("a continuity reset requires exactly the next generation");
        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::StateGenerationMismatch {
                current: 0,
                received: 2,
                required: 1
            })
        ));
    }

    #[test]
    fn explicit_timeout_is_receipted_without_claiming_a_wall_clock() {
        let mut detector = detector();
        let first = complete_frame(1, 11);
        let first_position = positioned(&first, 0);
        detector
            .assess_positioned_frame(first_position.clone(), &first)
            .expect("first positioned frame commits");
        let timeout_position = first_position
            .checked_reset(first.identity.fusion_timestamp_ms + 1)
            .expect("exact timeout successor is valid");

        let timeout = detector
            .timeout_at("crebain", timeout_position)
            .expect("caller-authorized timeout commits");

        assert!(matches!(
            timeout.transition(),
            LifecycleTransition::Reset { reasons }
                if reasons.as_slice() == [LifecycleResetReason::Timeout]
        ));
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn epoch_rollover_is_zero_origin_and_prevents_a_to_b_to_a_reuse() {
        let mut detector = detector();
        let first = complete_frame(1, 11);
        let first_position = positioned(&first, 0);
        detector
            .assess_positioned_frame(first_position.clone(), &first)
            .expect("first positioned frame commits");
        let epoch_b = first_position
            .checked_epoch_rollover("epoch-2", 10)
            .expect("fresh epoch B is valid");
        let rollover = detector
            .rollover_at("crebain", epoch_b.clone())
            .expect("fresh epoch B commits");
        let reused_epoch_a = epoch_b
            .checked_epoch_rollover("epoch-1", 20)
            .expect("core helper only compares with the active epoch");

        let error = detector
            .rollover_at("crebain", reused_epoch_a)
            .expect_err("retained epoch A must not be reusable");

        assert!(matches!(
            rollover.transition(),
            LifecycleTransition::EpochRolledOver { previous_epoch_id }
                if previous_epoch_id.as_str() == "epoch-1"
        ));
        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::ReusedEpoch {
                epoch_id
            }) if epoch_id.as_str() == "epoch-1"
        ));
    }

    #[test]
    fn epoch_rollover_rejects_each_nonzero_origin_coordinate_independently() {
        for (sequence, state_generation) in [(1, 0), (0, 1)] {
            let mut detector = detector();
            let first = complete_frame(1, 11);
            detector
                .assess_positioned_frame(positioned(&first, 0), &first)
                .expect("first rollover-boundary fixture frame commits");
            let rollover = StreamPosition::try_new(
                "mission-1",
                "epoch-2",
                "fusion",
                state_generation,
                sequence,
                first.identity.fusion_timestamp_ms + 1,
                ClockDomain::MonotonicProcess,
            )
            .expect("nonzero-origin rollover fixture is structurally valid");

            let error = detector
                .rollover_at("crebain", rollover)
                .expect_err("either nonzero origin coordinate must fail closed");
            assert!(matches!(
                error,
                LifecycleDetectorError::Ingress(
                    LifecycleIngressRejection::InvalidRolloverOrigin {
                        sequence: observed_sequence,
                        state_generation: observed_generation,
                    }
                ) if observed_sequence == sequence && observed_generation == state_generation
            ));
        }
    }

    #[test]
    fn positioned_rollover_frame_is_assessed_inside_the_rollover_transition() {
        let mut detector = detector();
        let first = complete_frame(1, 11);
        detector
            .assess_positioned_frame(positioned(&first, 0), &first)
            .expect("first positioned frame commits");
        let mut rollover_frame = complete_frame(0, 11);
        set_epoch(&mut rollover_frame, "epoch-2", "crebain");
        let rollover_position = positioned(&rollover_frame, 0);

        let outcome = detector
            .assess_positioned_frame(rollover_position, &rollover_frame)
            .expect("zero-origin fresh epoch frame commits");

        assert!(matches!(
            outcome.receipt().transition(),
            LifecycleTransition::EpochRolledOver { previous_epoch_id }
                if previous_epoch_id.as_str() == "epoch-1"
        ));
        assert!(matches!(
            outcome.assessments(),
            [LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }]
        ));
    }

    #[test]
    fn positioned_frame_rejects_each_coordinate_mismatch_independently() {
        let frame = complete_frame(1, 11);
        let cases = [
            StreamPosition::try_new(
                "mission-1",
                frame.session_id(),
                "fusion",
                0,
                frame.identity.fusion_seq + 1,
                frame.identity.fusion_timestamp_ms,
                ClockDomain::MonotonicProcess,
            )
            .expect("sequence-mismatch position is structurally valid"),
            StreamPosition::try_new(
                "mission-1",
                frame.session_id(),
                "fusion",
                0,
                frame.identity.fusion_seq,
                frame.identity.fusion_timestamp_ms + 1,
                ClockDomain::MonotonicProcess,
            )
            .expect("timestamp-mismatch position is structurally valid"),
        ];

        for position in cases {
            let mut detector = detector();
            let error = detector
                .assess_positioned_frame(position, &frame)
                .expect_err("either coordinate mismatch must fail closed");
            assert!(matches!(
                &error,
                LifecycleDetectorError::InvalidPosition(reason)
                    if reason.contains("differs from assembled frame")
            ));
            assert_eq!(detector.fault(), Some(&error));
        }
    }

    #[test]
    fn named_release_suite_provenance_survives_lifecycle_assessment() {
        let suite = ReleaseSuite::standalone_advisory_v0_9(&[Modality::Visual, Modality::Radar])
            .expect("named test release suite is valid");
        let expected_identity = suite.identity();
        let mut detector =
            LifecycleDetector::from_release_suite(suite).expect("named release suite is accepted");

        let assessments = detector
            .assess_frame(&complete_frame(1, 11))
            .expect("complete named-suite frame evaluates");
        let LifecycleAssessment::Evaluated { report, .. } = &assessments[0] else {
            panic!("complete named-suite frame must be evaluated")
        };

        assert_eq!(report.suite_identity(), expected_identity);
        assert_eq!(
            report.classification(),
            AssessmentClassification::NamedRelease(ReleaseProfile::StandaloneAdvisoryV0_9)
        );
    }

    #[test]
    #[allow(deprecated)]
    fn explicit_history_clear_discards_the_suffix_without_clearing_health() {
        let mut detector = detector();
        for fusion_seq in 1..=3 {
            detector
                .assess_frame(&complete_frame(fusion_seq, 11))
                .expect("warm-up frame evaluates");
        }
        assert_eq!(detector.retained_tracks(), 1);

        detector.clear_histories();

        assert_eq!(detector.retained_tracks(), 0);
        assert_eq!(detector.fault(), None);
        let assessment = detector
            .assess_frame(&complete_frame(4, 11))
            .expect("post-clear frame starts a new suffix");
        assert!(matches!(
            &assessment[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                report,
                ..
            } if *report.verdict() == FusedVerdict::InsufficientEvidence
        ));
    }

    #[test]
    fn expected_modalities_below_the_detector_minimum_are_terminal() {
        let mut detector = LifecycleDetector::new(
            DetectorConfig::try_new(DetectorParams {
                window_len: 4,
                min_samples: 4,
                min_channels: 3,
                ..DetectorParams::standalone_advisory_v0_9()
            })
            .expect("test detector config is valid"),
            correlation(4, 4),
        )
        .expect("three-channel detector config validates");

        let error = detector
            .assess_frame(&complete_frame(1, 11))
            .expect_err("a two-modality frame cannot satisfy a three-channel detector");

        assert!(matches!(
            &error,
            LifecycleDetectorError::InvalidFrame(reason)
                if reason.contains("cannot satisfy detector min_channels 3")
        ));
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn track_capacity_boundary_is_inclusive() {
        let mut detector = LifecycleDetector::new(
            DetectorConfig::try_new(DetectorParams {
                window_len: 4,
                min_samples: 4,
                min_channels: 2,
                max_tracks: 1,
                ..DetectorParams::standalone_advisory_v0_9()
            })
            .expect("test detector config is valid"),
            correlation(4, 4),
        )
        .expect("one-track detector config validates");

        let assessment = detector
            .assess_frame(&complete_frame(1, 11))
            .expect("exactly max_tracks frozen tracks remain admissible");

        assert!(matches!(
            assessment.as_slice(),
            [LifecycleAssessment::Evaluated {
                track_id: 1,
                history_reset: true,
                ..
            }]
        ));
        assert_eq!(detector.retained_tracks(), 1);
        assert_eq!(detector.fault(), None);
    }

    #[test]
    fn explicit_miss_abstains_immediately_and_breaks_the_suffix() {
        let mut detector = detector();
        for fusion_seq in 1..=3 {
            detector
                .assess_frame(&complete_frame(fusion_seq, 11))
                .expect("warm-up frame evaluates");
        }

        let assessments = detector
            .assess_frame(&miss_frame(4))
            .expect("a valid miss is an abstention, not an adapter fault");
        assert!(matches!(
            assessments.as_slice(),
            [LifecycleAssessment::Abstained {
                unavailable_modalities,
                ..
            }] if unavailable_modalities == &[Modality::Radar]
        ));
        assert_eq!(detector.retained_tracks(), 0);

        let next = detector
            .assess_frame(&complete_frame(5, 11))
            .expect("post-miss frame starts a new suffix");
        assert!(matches!(
            &next[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                report,
                ..
            } if *report.verdict() == FusedVerdict::InsufficientEvidence
        ));
    }

    #[test]
    fn context_change_resets_but_forward_sequence_gap_is_rejected() {
        let mut detector = detector();
        detector
            .assess_frame(&complete_frame(1, 11))
            .expect("first frame evaluates");
        let changed = detector
            .assess_frame(&complete_frame(2, 12))
            .expect("context change starts a new suffix");
        assert!(matches!(
            changed[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }
        ));
        let error = detector
            .assess_frame(&complete_frame(4, 12))
            .expect_err("an unreceipted sequence gap must fail closed");
        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::ForwardSequenceGap {
                expected: 3,
                received: 4
            })
        ));
        assert!(matches!(
            detector.last_receipt().map(LifecycleReceipt::transition),
            Some(LifecycleTransition::Rejected {
                reason: LifecycleIngressRejection::ForwardSequenceGap { .. }
            })
        ));
    }

    #[test]
    fn projection_registry_change_resets_the_statistical_suffix() {
        let mut detector = detector();
        detector
            .assess_frame_transition(&complete_frame(1, 11))
            .expect("first registry frame commits");
        let mut changed = complete_frame(2, 11);
        changed.summary.registry_digest =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();

        let outcome = detector
            .assess_frame_transition(&changed)
            .expect("legacy mapping advances generation for a registry boundary");

        assert!(matches!(
            outcome.receipt().transition(),
            LifecycleTransition::Reset { reasons }
                if reasons.as_slice() == [LifecycleResetReason::ProjectionRegistryChanged]
        ));
        assert!(matches!(
            outcome.assessments(),
            [LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }]
        ));
    }

    #[test]
    fn session_or_producer_change_cannot_share_a_consecutive_history_suffix() {
        let mut detector = detector();
        for fusion_seq in 1..=3 {
            detector
                .assess_frame(&complete_frame(fusion_seq, 11))
                .expect("first epoch warm-up frame evaluates");
        }

        let mut new_session = complete_frame(0, 11);
        set_epoch(&mut new_session, "epoch-2", "crebain");
        let session_assessments = detector
            .assess_frame(&new_session)
            .expect("consecutive frame in a new session starts a new suffix");
        assert!(matches!(
            &session_assessments[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                report,
                ..
            } if *report.verdict() == FusedVerdict::InsufficientEvidence
        ));

        let mut new_producer = complete_frame(1, 11);
        set_epoch(&mut new_producer, "epoch-2", "other-producer");
        let producer_assessments = detector
            .assess_frame(&new_producer)
            .expect("consecutive frame from a different producer starts a new suffix");
        assert!(matches!(
            &producer_assessments[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                report,
                ..
            } if *report.verdict() == FusedVerdict::InsufficientEvidence
        ));
    }

    #[test]
    fn forward_timestamp_gap_resets_only_above_the_configured_boundary() {
        let mut detector = detector();
        let maximum_gap = detector.detector_config.max_inter_sample_gap_ms();
        let first_timestamp = 100_u64;
        let boundary_timestamp = first_timestamp
            .checked_add(maximum_gap)
            .expect("test timestamp remains representable");
        let reset_timestamp = boundary_timestamp
            .checked_add(maximum_gap)
            .and_then(|timestamp| timestamp.checked_add(1))
            .expect("test timestamp remains representable");

        let mut first = complete_frame(1, 11);
        set_fusion_timestamp(&mut first, first_timestamp);
        detector
            .assess_frame(&first)
            .expect("first frame evaluates");

        let mut boundary = complete_frame(2, 11);
        set_fusion_timestamp(&mut boundary, boundary_timestamp);
        let boundary_assessment = detector
            .assess_frame(&boundary)
            .expect("the inclusive timestamp gap evaluates");
        assert!(matches!(
            boundary_assessment[0],
            LifecycleAssessment::Evaluated {
                history_reset: false,
                ..
            }
        ));

        let mut above = complete_frame(3, 11);
        set_fusion_timestamp(&mut above, reset_timestamp);
        let above_assessment = detector
            .assess_frame(&above)
            .expect("a forward gap starts a new valid suffix");
        assert!(matches!(
            above_assessment[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }
        ));
    }

    #[test]
    fn regressing_timestamp_remains_a_terminal_detector_error() {
        let mut detector = detector();
        let mut first = complete_frame(1, 11);
        set_fusion_timestamp(&mut first, 100);
        detector
            .assess_frame(&first)
            .expect("first frame evaluates");
        let mut regressed = complete_frame(2, 11);
        set_fusion_timestamp(&mut regressed, 99);

        let error = detector
            .assess_frame(&regressed)
            .expect_err("timestamp regression must not be converted into a reset");

        assert!(matches!(
            error,
            LifecycleDetectorError::Ingress(LifecycleIngressRejection::NonIncreasingTimestamp {
                previous: 100,
                received: 99
            })
        ));
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn exact_timestamp_boundary_is_valid_and_larger_values_cannot_be_constructed() {
        let mut detector = detector();
        let maximum = galadriel_core::TimestampMillis::MAX;
        let mut first = complete_frame(1, 11);
        set_fusion_timestamp(&mut first, maximum - 1);
        detector
            .assess_frame(&first)
            .expect("timestamp immediately below the domain maximum evaluates");
        let mut terminal = complete_frame(2, 11);
        set_fusion_timestamp(&mut terminal, maximum);

        detector
            .assess_frame(&terminal)
            .expect("the exact timestamp domain maximum evaluates");

        assert!(
            PidObservation::try_scalar_raw(1, maximum + 1, 3, Modality::Visual, 1.0, 3,).is_err()
        );
        assert_eq!(detector.fault(), None);
    }

    #[test]
    fn zero_track_frame_retires_absent_history() {
        let mut detector = detector();
        detector
            .assess_frame(&complete_frame(1, 11))
            .expect("first frame evaluates");
        let mut empty = complete_frame(2, 11);
        empty.monitor_events.clear();
        empty.observations.clear();
        empty.summary.active_track_count = 0;
        empty.summary.input_count = 0;
        empty.summary.outcome_count = 0;
        empty.summary.v1_expected_count = 0;

        assert!(detector
            .assess_frame(&empty)
            .expect("zero-track closure is valid")
            .is_empty());
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn track_birth_is_excluded_and_clears_any_reused_track_suffix() {
        let mut detector = detector();
        detector
            .assess_frame(&complete_frame(1, 11))
            .expect("first frozen frame evaluates");

        assert!(detector
            .assess_frame(&birth_frame(2))
            .expect("birth-only frame is valid")
            .is_empty());
        assert_eq!(detector.retained_tracks(), 0);

        let next = detector
            .assess_frame(&complete_frame(3, 11))
            .expect("track participates only when later frozen");
        assert!(matches!(
            next[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }
        ));
    }

    #[test]
    fn structural_fault_latches_and_clears_history() {
        let mut detector = detector();
        detector
            .assess_frame(&complete_frame(1, 11))
            .expect("first frame evaluates");
        let mut invalid = complete_frame(2, 11);
        invalid.summary.expected_modalities.reverse();

        let error = detector
            .assess_frame(&invalid)
            .expect_err("noncanonical modalities must fault");
        assert!(matches!(error, LifecycleDetectorError::InvalidFrame(_)));
        assert_eq!(detector.retained_tracks(), 0);
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(
            detector
                .assess_frame(&complete_frame(3, 11))
                .expect_err("fault is permanent"),
            error
        );
    }
}
