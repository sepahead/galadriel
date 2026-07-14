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
//! use galadriel_ncp::live::{HandoffConfig, SidecarTap, TransportMode};
//! let tap = SidecarTap::open(TransportMode::Secure).await?;
//! let (health, mut observations) = tap
//!     .subscribe_channel("uav3", "crebain", HandoffConfig::default())
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use galadriel_core::{Modality, PidObservation, Sequence, TrackId};
use ncp_core::{ContractStatus, Keys, DEFAULT_REALM};
use ncp_zenoh::{ZenohBus, ZenohError};
use tokio::sync::mpsc;

use crate::{sidecar_key, valid_realm, SidecarEnvelope, SidecarEnvelopeError};

/// Maximum live sidecar payload accepted under [`LiveLimits::default`].
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

/// Fixed overflow behavior for bounded live observation handoffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandoffOverflowPolicy {
    /// Preserve queued observations and discard the newly accepted observation.
    DropNewest,
}

/// Validated configuration for a bounded live observation handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffConfig {
    capacity: usize,
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
        if capacity == 0 {
            return Err(HandoffConfigError::ZeroCapacity);
        }
        if capacity > MAX_LIVE_HANDOFF_CAPACITY {
            return Err(HandoffConfigError::CapacityTooLarge {
                capacity,
                maximum: MAX_LIVE_HANDOFF_CAPACITY,
            });
        }
        Ok(Self { capacity })
    }

    /// Maximum number of decoded observations waiting for the consumer.
    pub fn capacity(self) -> usize {
        self.capacity
    }

    /// Overflow policy used by this handoff.
    pub fn overflow_policy(self) -> HandoffOverflowPolicy {
        HandoffOverflowPolicy::DropNewest
    }
}

impl Default for HandoffConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_LIVE_HANDOFF_CAPACITY,
        }
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
}

/// Resource limits for live sidecar ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveLimits {
    max_payload_bytes: usize,
    max_sequence_streams: usize,
    max_sequence_advance: u64,
}

impl LiveLimits {
    /// Build a nonzero live-payload limit with the default sequence-stream bound.
    pub fn new(max_payload_bytes: usize) -> Result<Self, ZenohError> {
        Self::with_sequence_stream_limit(max_payload_bytes, DEFAULT_MAX_LIVE_SEQUENCE_STREAMS)
    }

    /// Build nonzero live-payload and sequence-stream limits.
    pub fn with_sequence_stream_limit(
        max_payload_bytes: usize,
        max_sequence_streams: usize,
    ) -> Result<Self, ZenohError> {
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
    ) -> Result<Self, ZenohError> {
        if max_payload_bytes == 0 {
            return Err(ZenohError(
                "max live payload bytes must be greater than zero".to_string(),
            ));
        }
        if max_sequence_streams == 0 {
            return Err(ZenohError(
                "max live sequence streams must be greater than zero".to_string(),
            ));
        }
        if max_sequence_advance == 0 {
            return Err(ZenohError(
                "max live sequence advance must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
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
}

impl Default for LiveLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_LIVE_PAYLOAD_BYTES,
            max_sequence_streams: DEFAULT_MAX_LIVE_SEQUENCE_STREAMS,
            max_sequence_advance: DEFAULT_MAX_LIVE_SEQUENCE_ADVANCE,
        }
    }
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
    /// Internal bounded sequence state could not be reserved or remained inconsistent.
    SequenceStateFailure,
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
    /// Internal sequence-state failures.
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

    fn last_accepted(&self) -> Option<LastAcceptedObservation> {
        *self
            .last_accepted
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn callback_latency(&self) -> CallbackLatencyMetrics {
        let latency = self
            .callback_latency
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        CallbackLatencyMetrics {
            samples: latency.samples,
            last: latency.last,
            maximum: latency.maximum,
        }
    }
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
}

impl HandoffState {
    fn new(config: HandoffConfig) -> Self {
        Self {
            config,
            queue: Mutex::new(HandoffQueueState::new(config.capacity())),
        }
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
        let mut queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
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
        let mut queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
        let queued = receiver.try_recv()?;
        Self::record_dequeue(&mut queue, &queued, Instant::now());
        Ok(queued)
    }

    fn abandon_all(&self) -> usize {
        let mut queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
        let abandoned = queue.entries.len();
        queue.entries.clear();
        abandoned
    }

    fn snapshot(&self, counters: &IngestCounters, generation: u64) -> HandoffMetrics {
        let now = Instant::now();
        let queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
        let oldest_queued = queue.entries.front().map(|entry| entry.observation);
        let oldest_queued_generation = queue.entries.front().map(|entry| entry.generation);
        let oldest_enqueue_age = queue
            .entries
            .front()
            .map(|entry| now.saturating_duration_since(entry.enqueued_at));
        HandoffMetrics {
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
        }
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
        let mut queue = self
            .state
            .queue
            .lock()
            .unwrap_or_else(|error| error.into_inner());
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
        let _delivery = self.delivery_boundary.begin_delivery();
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
        let _delivery = self.delivery_boundary.begin_delivery();
        self.receiver.close();
        let abandoned = self.state.abandon_all() as u64;
        increment_pair_by(
            &self.tap_counters.handoff_abandoned_drops,
            &self.subscription_counters.handoff_abandoned_drops,
            abandoned,
        );
    }
}

fn bounded_handoff(
    config: HandoffConfig,
    delivery_boundary: Arc<DeliveryBoundary>,
    tap_counters: Arc<IngestCounters>,
    subscription_counters: Arc<IngestCounters>,
) -> (
    ObservationHandoff,
    LiveObservationReceiver,
    Arc<HandoffState>,
) {
    let state = Arc::new(HandoffState::new(config));
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

#[derive(Debug, Default)]
struct DeliveryBoundary {
    state: Mutex<DeliveryBoundaryState>,
    changed: Condvar,
    generation: AtomicU64,
}

impl DeliveryBoundary {
    fn begin_delivery(&self) -> DeliveryGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        while state.delivery_active || state.reset_active || state.pending_resets > 0 {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
        state.delivery_active = true;
        DeliveryGuard { boundary: self }
    }

    fn begin_reset(&self) -> Result<ResetGuard<'_>, SequenceResetError> {
        if callback_active() {
            return Err(SequenceResetError::CalledFromCallback);
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
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
                .changed
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
        state.pending_resets -= 1;
        state.reset_active = true;
        Ok(ResetGuard { boundary: self })
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn advance_generation(&self) -> Result<u64, SequenceResetError> {
        self.generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map(|previous| previous + 1)
            .map_err(|_| SequenceResetError::GenerationExhausted)
    }
}

struct DeliveryGuard<'a> {
    boundary: &'a DeliveryBoundary,
}

impl Drop for DeliveryGuard<'_> {
    fn drop(&mut self) {
        let mut state = self
            .boundary
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.delivery_active = false;
        self.boundary.changed.notify_all();
    }
}

struct ResetGuard<'a> {
    boundary: &'a DeliveryBoundary,
}

impl Drop for ResetGuard<'_> {
    fn drop(&mut self) {
        let mut state = self
            .boundary
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.reset_active = false;
        self.boundary.changed.notify_all();
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
            let gap = sequence.get() - last.get();
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
        self.counters.last_accepted()
    }

    /// User callback panics contained at the subscription boundary.
    pub fn callback_panics(&self) -> u64 {
        self.counters.callback_panics.load(Ordering::Relaxed)
    }

    /// Last and maximum execution time for this subscription's accepted callbacks.
    /// Inline subscriptions measure user code; bounded handoffs measure the internal
    /// nonblocking enqueue callback. Decode and validation time are excluded.
    pub fn callback_latency(&self) -> CallbackLatencyMetrics {
        self.counters.callback_latency()
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
    /// Returns `None` for inline callbacks.
    pub fn handoff_metrics(&self) -> Option<HandoffMetrics> {
        let handoff = self.handoff.as_ref()?;
        let _delivery = self.delivery_boundary.begin_delivery();
        Some(handoff.snapshot(&self.counters, self.delivery_boundary.generation()))
    }

    /// Number of `(track, modality)` sequence streams currently retained.
    pub fn retained_sequence_streams(&self) -> usize {
        self.sequences
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
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
    /// delivery, an exhausted pending-reset counter, or an exhausted generation.
    pub fn reset_sequence_state(&self) -> Result<usize, SequenceResetError> {
        let _reset = self.delivery_boundary.begin_reset()?;
        self.delivery_boundary.advance_generation()?;
        let removed = self
            .sequences
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        *self
            .counters
            .last_accepted
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
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
    owns_bus: bool,
}

impl SidecarTap {
    /// Open a tap on the default NCP realm with explicit transport-security intent.
    pub async fn open(mode: TransportMode) -> Result<Self, ZenohError> {
        Self::open_with_limits(mode, LiveLimits::default()).await
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
        Self::from_parts(bus, DEFAULT_REALM.to_string(), limits, true)
    }

    fn from_parts(
        bus: ZenohBus,
        realm: String,
        limits: LiveLimits,
        owns_bus: bool,
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
            owns_bus,
        })
    }

    /// Open a tap on an explicit realm with explicit transport-security intent.
    pub async fn open_realm(
        realm: impl Into<String>,
        mode: TransportMode,
    ) -> Result<Self, ZenohError> {
        Self::open_realm_with_limits(realm, mode, LiveLimits::default()).await
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
        Self::from_parts(bus, realm, limits, true)
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
        Self::from_bus_with_limits(bus, LiveLimits::default())
    }

    /// Wrap an already-open bus with caller-supplied payload limits.
    /// See [`Self::from_bus`] for the shared-session close semantics.
    pub fn from_bus_with_limits(bus: ZenohBus, limits: LiveLimits) -> Result<Self, ZenohError> {
        let realm = bus.keys().realm().to_owned();
        Self::from_parts(bus, realm, limits, false)
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
        self.counters.last_accepted()
    }

    /// User callback panics caught at the receive boundary. The panicking payload is
    /// dropped, while Zenoh's receive task remains alive for later observations.
    pub fn callback_panics(&self) -> u64 {
        self.counters.callback_panics.load(Ordering::Relaxed)
    }

    /// Last and maximum callback execution time across this tap's subscriptions.
    /// The `last` value is the most recently completed callback across independent
    /// subscriptions; `maximum` is their aggregate high-water mark.
    pub fn callback_latency(&self) -> CallbackLatencyMetrics {
        self.counters.callback_latency()
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
    /// [`Self::decode_failures`]. Callback panics are caught and counted by
    /// [`Self::callback_panics`] so they cannot unwind Zenoh's receive task.
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
            .ok_or_else(|| ZenohError(format!("invalid NCP session id segment: {session_id:?}")))?;
        if !ncp_core::valid_id_segment(producer_id) {
            return Err(ZenohError(format!(
                "invalid sidecar producer id segment: {producer_id:?}"
            )));
        }
        let expected_session_id = session_id.to_owned();
        let expected_producer_id = producer_id.to_owned();
        let tap_counters = Arc::clone(&self.counters);
        let subscription_counters = Arc::new(IngestCounters::default());
        let limits = self.limits;
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let delivery_boundary = Arc::new(DeliveryBoundary::default());
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
            .ok_or_else(|| ZenohError(format!("invalid NCP session id segment: {session_id:?}")))?;
        if !ncp_core::valid_id_segment(producer_id) {
            return Err(ZenohError(format!(
                "invalid sidecar producer id segment: {producer_id:?}"
            )));
        }
        let expected_session_id = session_id.to_owned();
        let expected_producer_id = producer_id.to_owned();
        let tap_counters = Arc::clone(&self.counters);
        let subscription_counters = Arc::new(IngestCounters::default());
        let limits = self.limits;
        let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
        let delivery_boundary = Arc::new(DeliveryBoundary::default());
        let (handoff, receiver, handoff_state) = bounded_handoff(
            config,
            Arc::clone(&delivery_boundary),
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
        if !self.owns_bus {
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
    let _delivery = context.delivery_boundary.begin_delivery();
    if bytes.len() > context.limits.max_payload_bytes {
        reject_pair(
            context.tap_counters,
            context.subscription_counters,
            RejectionReason::PayloadTooLarge,
        );
        return;
    }

    // Parse straight into the typed envelope. A `serde_json::Value` intermediate would
    // collapse duplicate JSON keys (last occurrence wins) before `deny_unknown_fields`
    // could reject them — a parser differential with first-wins JSON consumers on a
    // security boundary. `classify()` preserves the malformed-vs-invalid counter split.
    let envelope = match serde_json::from_slice::<SidecarEnvelope>(bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            let reason = if error.classify() == serde_json::error::Category::Data {
                RejectionReason::InvalidEnvelope
            } else {
                RejectionReason::MalformedJson
            };
            reject_pair(context.tap_counters, context.subscription_counters, reason);
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
        let mut sequences = context
            .sequences
            .lock()
            .unwrap_or_else(|error| error.into_inner());
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
    record_acceptance_pair(
        context.tap_counters,
        context.subscription_counters,
        &observation,
    );

    let callback_started = Instant::now();
    let callback_panicked = {
        let _callback = CallbackGuard::enter();
        catch_unwind(AssertUnwindSafe(|| on_obs(observation))).is_err()
    };
    let callback_completed_at = Instant::now();
    record_callback_latency_pair(
        context.tap_counters,
        context.subscription_counters,
        callback_completed_at.saturating_duration_since(callback_started),
        callback_completed_at,
    );
    if callback_panicked {
        increment_pair(
            &context.tap_counters.callback_panics,
            &context.subscription_counters.callback_panics,
        );
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
) {
    record_callback_latency(tap, latency, completed_at);
    record_callback_latency(subscription, latency, completed_at);
}

fn record_callback_latency(counters: &IngestCounters, latency: Duration, completed_at: Instant) {
    let mut state = counters
        .callback_latency
        .lock()
        .unwrap_or_else(|error| error.into_inner());
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
) {
    increment_pair(
        &tap.observations_accepted,
        &subscription.observations_accepted,
    );
    let last = Some(LastAcceptedObservation::from(observation));
    *tap.last_accepted
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = last;
    *subscription
        .last_accepted
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = last;
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
            let delivery_boundary = Arc::new(DeliveryBoundary::default());
            let sequences = Arc::new(Mutex::new(LiveSequenceTracker::default()));
            let tap_counters = Arc::new(IngestCounters::default());
            let subscription_counters = Arc::new(IngestCounters::default());
            let (handoff, receiver, state) = bounded_handoff(
                config,
                Arc::clone(&delivery_boundary),
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
        assert_eq!(harness.tap_counters.callback_latency().samples, 2);

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
            let _delivery = delivery_boundary.begin_delivery();
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
            );
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
            );
        });
        newer.join().unwrap();
        older.join().unwrap();

        assert_eq!(
            counters.callback_latency(),
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
    fn process_payload_catches_callback_panic_and_accepts_later_input() {
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

        assert_eq!(callbacks.load(Ordering::Relaxed), 2);
        assert_eq!(subscription.callback_panics.load(Ordering::Relaxed), 1);
        assert_eq!(subscription.decode_failures.load(Ordering::Relaxed), 0);
        let callback_latency = subscription.callback_latency();
        assert_eq!(callback_latency.samples, 2);
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
            subscription.last_accepted(),
            Some(LastAcceptedObservation {
                track_id: 2,
                modality: Modality::Radar,
                sequence: 9,
                timestamp_ms: 9,
            })
        );
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

        assert!(error.to_string().contains("sequence advance"));
    }
}
