//! Bounded live ingress for producer-monitor events.
//!
//! [`MonitorTap`] subscribes to the exact `sensor/galadriel-monitor` route, binds
//! every payload to the configured producer epoch, and emits only a contiguous
//! `event_seq` stream. A bounded reorder map tolerates limited transport reorder.
//! Every open gap owns a positive bounded monotonic deadline, including when no
//! later payload arrives to trigger another callback.
//! Any decode, provenance, sequence, capacity, or handoff failure latches the
//! first [`MonitorIngressFault`] and permanently stops delivery for that epoch.
//! Each receiver owns the raw Zenoh subscriber guard for its exact selector;
//! closing or dropping the receiver undeclares only that selector, cancels its
//! timer, and releases all retained ingress state even on a host-owned bus.
//! The application size gate runs after Zenoh materializes the payload; bounding
//! transport allocation therefore also requires the deployment receive-size cap.
//! Opening and receiving require a Tokio runtime with the time driver enabled;
//! that owning runtime must remain alive for the receiver's full lifetime.
//!
//! This module deliberately does not assemble monitor events with frozen-v1
//! observations. A clean ingress stream is necessary, but not sufficient, for a
//! lifecycle-complete operational assessment.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use ncp_core::{ContractStatus, Keys, DEFAULT_REALM};
use ncp_zenoh::{ZenohBus, ZenohError};
use tokio::sync::{mpsc, watch};

use crate::live::TransportMode;
use crate::monitor::{
    monitor_key, MonitorEnvelope, MonitorError, MAX_MONITOR_EVENT_BYTES, MAX_MONITOR_QUEUE_EVENTS,
};
use crate::{valid_realm, MAX_ID_SEGMENT_BYTES};

/// Default number of contiguous monitor receipts retained for a consumer.
pub const DEFAULT_MONITOR_HANDOFF_CAPACITY: usize = 1_024;

/// Default number of out-of-order monitor receipts retained before a gap closes.
pub const DEFAULT_MONITOR_REORDER_CAPACITY: usize = 128;

/// Default largest accepted forward distance from the next monitor sequence.
pub const DEFAULT_MONITOR_REORDER_DISTANCE: u64 = 1_024;

/// Default time allowed for a missing monitor sequence to arrive.
pub const DEFAULT_MONITOR_REORDER_DEADLINE: Duration = Duration::from_secs(1);

/// Hard ceiling for either monitor handoff or reorder item capacity.
pub const MAX_MONITOR_INGRESS_ITEMS: usize = MAX_MONITOR_QUEUE_EVENTS as usize;

/// Hard ceiling for forward monitor sequence reordering.
pub const MAX_MONITOR_REORDER_DISTANCE: u64 = MAX_MONITOR_QUEUE_EVENTS as u64;

/// Hard ceiling for a monitor sequence gap to remain unresolved.
pub const MAX_MONITOR_REORDER_DEADLINE: Duration = Duration::from_secs(60);

/// Bounded monitor-ingress configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorLiveConfig {
    handoff_capacity: usize,
    reorder_capacity: usize,
    max_reorder_distance: u64,
    reorder_deadline: Duration,
}

impl MonitorLiveConfig {
    /// Validate all monitor-ingress memory and sequence bounds.
    ///
    /// # Errors
    ///
    /// Returns [`MonitorLiveConfigError`] when any bound is zero or exceeds its
    /// fixed process ceiling.
    pub fn new(
        handoff_capacity: usize,
        reorder_capacity: usize,
        max_reorder_distance: u64,
    ) -> Result<Self, MonitorLiveConfigError> {
        validate_item_capacity("handoff", handoff_capacity)?;
        validate_item_capacity("reorder", reorder_capacity)?;
        if max_reorder_distance == 0 {
            return Err(MonitorLiveConfigError::ZeroReorderDistance);
        }
        if max_reorder_distance > MAX_MONITOR_REORDER_DISTANCE {
            return Err(MonitorLiveConfigError::ReorderDistanceTooLarge {
                distance: max_reorder_distance,
                maximum: MAX_MONITOR_REORDER_DISTANCE,
            });
        }
        validate_capacity_relationship(handoff_capacity, reorder_capacity)?;
        Ok(Self {
            handoff_capacity,
            reorder_capacity,
            max_reorder_distance,
            reorder_deadline: DEFAULT_MONITOR_REORDER_DEADLINE,
        })
    }

    /// Override the finite deadline for a missing monitor sequence.
    ///
    /// # Errors
    ///
    /// Returns [`MonitorLiveConfigError`] when `reorder_deadline` is zero or
    /// exceeds [`MAX_MONITOR_REORDER_DEADLINE`].
    pub fn with_reorder_deadline(
        mut self,
        reorder_deadline: Duration,
    ) -> Result<Self, MonitorLiveConfigError> {
        validate_reorder_deadline(reorder_deadline)?;
        self.reorder_deadline = reorder_deadline;
        Ok(self)
    }

    /// Maximum contiguous receipts waiting for the consumer.
    pub fn handoff_capacity(self) -> usize {
        self.handoff_capacity
    }

    /// Maximum receipts held while earlier event sequences are missing.
    pub fn reorder_capacity(self) -> usize {
        self.reorder_capacity
    }

    /// Maximum forward distance from the next required event sequence.
    pub fn max_reorder_distance(self) -> u64 {
        self.max_reorder_distance
    }

    /// Maximum monotonic time an event-sequence gap may remain unresolved.
    pub fn reorder_deadline(self) -> Duration {
        self.reorder_deadline
    }
}

impl Default for MonitorLiveConfig {
    fn default() -> Self {
        Self {
            handoff_capacity: DEFAULT_MONITOR_HANDOFF_CAPACITY,
            reorder_capacity: DEFAULT_MONITOR_REORDER_CAPACITY,
            max_reorder_distance: DEFAULT_MONITOR_REORDER_DISTANCE,
            reorder_deadline: DEFAULT_MONITOR_REORDER_DEADLINE,
        }
    }
}

fn validate_capacity_relationship(
    handoff_capacity: usize,
    reorder_capacity: usize,
) -> Result<(), MonitorLiveConfigError> {
    let minimum = reorder_capacity.saturating_add(1);
    if handoff_capacity < minimum {
        return Err(MonitorLiveConfigError::HandoffTooSmallForReorder {
            handoff_capacity,
            minimum,
        });
    }
    Ok(())
}

fn validate_reorder_deadline(deadline: Duration) -> Result<(), MonitorLiveConfigError> {
    if deadline.is_zero() {
        return Err(MonitorLiveConfigError::ZeroReorderDeadline);
    }
    if deadline > MAX_MONITOR_REORDER_DEADLINE {
        return Err(MonitorLiveConfigError::ReorderDeadlineTooLarge {
            deadline,
            maximum: MAX_MONITOR_REORDER_DEADLINE,
        });
    }
    Ok(())
}

fn validate_item_capacity(
    field: &'static str,
    capacity: usize,
) -> Result<(), MonitorLiveConfigError> {
    if capacity == 0 {
        return Err(MonitorLiveConfigError::ZeroCapacity { field });
    }
    if capacity > MAX_MONITOR_INGRESS_ITEMS {
        return Err(MonitorLiveConfigError::CapacityTooLarge {
            field,
            capacity,
            maximum: MAX_MONITOR_INGRESS_ITEMS,
        });
    }
    Ok(())
}

/// Invalid monitor-ingress configuration.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MonitorLiveConfigError {
    /// A bounded item capacity was zero.
    #[error("monitor {field} capacity must be greater than zero")]
    ZeroCapacity { field: &'static str },
    /// A bounded item capacity exceeded the fixed ceiling.
    #[error("monitor {field} capacity {capacity} exceeds maximum {maximum}")]
    CapacityTooLarge {
        field: &'static str,
        capacity: usize,
        maximum: usize,
    },
    /// The handoff cannot contain a full reorder burst plus its missing head.
    #[error(
        "monitor handoff capacity {handoff_capacity} is smaller than required reorder burst capacity {minimum}"
    )]
    HandoffTooSmallForReorder {
        handoff_capacity: usize,
        minimum: usize,
    },
    /// Forward reorder distance was zero.
    #[error("monitor reorder distance must be greater than zero")]
    ZeroReorderDistance,
    /// Forward reorder distance exceeded the fixed ceiling.
    #[error("monitor reorder distance {distance} exceeds maximum {maximum}")]
    ReorderDistanceTooLarge { distance: u64, maximum: u64 },
    /// The reorder deadline was zero.
    #[error("monitor reorder deadline must be greater than zero")]
    ZeroReorderDeadline,
    /// The reorder deadline exceeded the fixed ceiling.
    #[error("monitor reorder deadline {deadline:?} exceeds maximum {maximum:?}")]
    ReorderDeadlineTooLarge {
        deadline: Duration,
        maximum: Duration,
    },
}

/// Stable category for one terminal monitor-ingress fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MonitorIngressFaultKind {
    /// Payload exceeded the strict monitor wire ceiling.
    PayloadTooLarge,
    /// Payload was not syntactically valid JSON.
    MalformedJson,
    /// Payload decoded as JSON but violated the monitor envelope contract.
    InvalidEnvelope,
    /// Payload declared an incompatible NCP version.
    IncompatibleNcpVersion,
    /// Payload identity differed from the exact subscription provenance.
    ProvenanceMismatch,
    /// Event sequence duplicated or preceded the next required sequence.
    DuplicateOrRegressedSequence,
    /// Event sequence was farther ahead than the configured reorder window.
    ReorderDistanceExceeded,
    /// The bounded reorder map was full.
    ReorderCapacityExceeded,
    /// A missing event sequence did not arrive before the finite deadline.
    SequenceGapDeadlineExceeded,
    /// The bounded consumer handoff was full.
    HandoffFull,
    /// The bounded consumer handoff was closed.
    HandoffClosed,
    /// Internal sequence state could not advance safely.
    InternalSequenceFailure,
    /// The owned monotonic gap-deadline task terminated unexpectedly.
    TimerTaskFailed,
}

/// First terminal failure of one monitor subscription.
///
/// The first value is retained for the epoch. Later payloads cannot replace it or
/// resume delivery.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MonitorIngressFault {
    /// Payload exceeded the strict monitor wire ceiling.
    #[error("monitor payload has {actual} bytes, maximum {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    /// Payload was not syntactically valid JSON.
    #[error("monitor payload is malformed JSON")]
    MalformedJson,
    /// Payload decoded as JSON but violated the strict envelope contract.
    #[error("monitor payload violates the envelope contract")]
    InvalidEnvelope,
    /// Payload declared an incompatible NCP version.
    #[error("monitor payload declares an incompatible NCP version")]
    IncompatibleNcpVersion,
    /// Payload identity differed from the exact subscription provenance.
    #[error("monitor payload provenance does not match the subscription")]
    ProvenanceMismatch,
    /// Event sequence duplicated or preceded the next required sequence.
    #[error("monitor event_seq {received} duplicates or precedes required sequence {expected}")]
    DuplicateOrRegressedSequence { expected: u64, received: u64 },
    /// Event sequence was farther ahead than the configured reorder window.
    #[error(
        "monitor event_seq {received} is too far ahead of required sequence {expected}; maximum distance {maximum}"
    )]
    ReorderDistanceExceeded {
        expected: u64,
        received: u64,
        maximum: u64,
    },
    /// The bounded reorder map was full.
    #[error("monitor reorder capacity {capacity} is exhausted")]
    ReorderCapacityExceeded { capacity: usize },
    /// A missing event sequence did not arrive before the finite deadline.
    #[error("monitor event_seq gap at {expected} before {next_received} exceeded {deadline:?}")]
    SequenceGapDeadlineExceeded {
        expected: u64,
        next_received: u64,
        deadline: Duration,
    },
    /// The bounded consumer handoff was full.
    #[error("monitor handoff capacity {capacity} is exhausted at event_seq {event_seq}")]
    HandoffFull { capacity: usize, event_seq: u64 },
    /// The bounded consumer handoff was closed.
    #[error("monitor handoff is closed at event_seq {event_seq}")]
    HandoffClosed { event_seq: u64 },
    /// Internal sequence state could not advance safely.
    #[error("monitor sequence state cannot advance safely")]
    InternalSequenceFailure,
    /// The owned monotonic gap-deadline task terminated unexpectedly.
    #[error("monitor gap-deadline task terminated unexpectedly")]
    TimerTaskFailed,
}

impl MonitorIngressFault {
    /// Stable counter category for this fault.
    pub fn kind(&self) -> MonitorIngressFaultKind {
        match self {
            Self::PayloadTooLarge { .. } => MonitorIngressFaultKind::PayloadTooLarge,
            Self::MalformedJson => MonitorIngressFaultKind::MalformedJson,
            Self::InvalidEnvelope => MonitorIngressFaultKind::InvalidEnvelope,
            Self::IncompatibleNcpVersion => MonitorIngressFaultKind::IncompatibleNcpVersion,
            Self::ProvenanceMismatch => MonitorIngressFaultKind::ProvenanceMismatch,
            Self::DuplicateOrRegressedSequence { .. } => {
                MonitorIngressFaultKind::DuplicateOrRegressedSequence
            }
            Self::ReorderDistanceExceeded { .. } => {
                MonitorIngressFaultKind::ReorderDistanceExceeded
            }
            Self::ReorderCapacityExceeded { .. } => {
                MonitorIngressFaultKind::ReorderCapacityExceeded
            }
            Self::SequenceGapDeadlineExceeded { .. } => {
                MonitorIngressFaultKind::SequenceGapDeadlineExceeded
            }
            Self::HandoffFull { .. } => MonitorIngressFaultKind::HandoffFull,
            Self::HandoffClosed { .. } => MonitorIngressFaultKind::HandoffClosed,
            Self::InternalSequenceFailure => MonitorIngressFaultKind::InternalSequenceFailure,
            Self::TimerTaskFailed => MonitorIngressFaultKind::TimerTaskFailed,
        }
    }
}

/// Snapshot of terminal fault counts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MonitorIngressFaultCounts {
    /// Oversized payload faults.
    pub payload_too_large: u64,
    /// Malformed JSON faults.
    pub malformed_json: u64,
    /// Invalid envelope faults.
    pub invalid_envelope: u64,
    /// Incompatible NCP version faults.
    pub incompatible_ncp_version: u64,
    /// Provenance mismatch faults.
    pub provenance_mismatch: u64,
    /// Duplicate or regressed sequence faults.
    pub duplicate_or_regressed_sequence: u64,
    /// Excessive reorder-distance faults.
    pub reorder_distance_exceeded: u64,
    /// Reorder-capacity faults.
    pub reorder_capacity_exceeded: u64,
    /// Missing-sequence deadline faults.
    pub sequence_gap_deadline_exceeded: u64,
    /// Full handoff faults.
    pub handoff_full: u64,
    /// Closed handoff faults.
    pub handoff_closed: u64,
    /// Internal sequence-state faults.
    pub internal_sequence_failure: u64,
    /// Unexpected deadline-task termination faults.
    pub timer_task_failed: u64,
}

impl MonitorIngressFaultCounts {
    /// Count for one stable fault category.
    pub fn count(self, kind: MonitorIngressFaultKind) -> u64 {
        match kind {
            MonitorIngressFaultKind::PayloadTooLarge => self.payload_too_large,
            MonitorIngressFaultKind::MalformedJson => self.malformed_json,
            MonitorIngressFaultKind::InvalidEnvelope => self.invalid_envelope,
            MonitorIngressFaultKind::IncompatibleNcpVersion => self.incompatible_ncp_version,
            MonitorIngressFaultKind::ProvenanceMismatch => self.provenance_mismatch,
            MonitorIngressFaultKind::DuplicateOrRegressedSequence => {
                self.duplicate_or_regressed_sequence
            }
            MonitorIngressFaultKind::ReorderDistanceExceeded => self.reorder_distance_exceeded,
            MonitorIngressFaultKind::ReorderCapacityExceeded => self.reorder_capacity_exceeded,
            MonitorIngressFaultKind::SequenceGapDeadlineExceeded => {
                self.sequence_gap_deadline_exceeded
            }
            MonitorIngressFaultKind::HandoffFull => self.handoff_full,
            MonitorIngressFaultKind::HandoffClosed => self.handoff_closed,
            MonitorIngressFaultKind::InternalSequenceFailure => self.internal_sequence_failure,
            MonitorIngressFaultKind::TimerTaskFailed => self.timer_task_failed,
        }
    }

    /// Total terminal faults represented by this snapshot.
    pub fn total(self) -> u64 {
        self.payload_too_large
            .saturating_add(self.malformed_json)
            .saturating_add(self.invalid_envelope)
            .saturating_add(self.incompatible_ncp_version)
            .saturating_add(self.provenance_mismatch)
            .saturating_add(self.duplicate_or_regressed_sequence)
            .saturating_add(self.reorder_distance_exceeded)
            .saturating_add(self.reorder_capacity_exceeded)
            .saturating_add(self.sequence_gap_deadline_exceeded)
            .saturating_add(self.handoff_full)
            .saturating_add(self.handoff_closed)
            .saturating_add(self.internal_sequence_failure)
            .saturating_add(self.timer_task_failed)
    }
}

/// A validated monitor envelope paired with its local monotonic receipt time.
#[derive(Debug, Clone, PartialEq)]
pub struct MonitorReceipt {
    /// Strict validated producer-monitor envelope.
    pub envelope: MonitorEnvelope,
    /// Local monotonic time captured at serialized ingress admission.
    pub received_at: Instant,
    /// Nondecreasing ingress-order time suitable for serialized assembler calls.
    ///
    /// Reordering preserves [`Self::received_at`] exactly. This value is clamped
    /// forward when a later-arriving missing sequence releases earlier receipts.
    pub ordered_at: Instant,
}

#[derive(Debug, Default)]
struct IngressCounters {
    payloads_received: AtomicU64,
    payloads_after_fault: AtomicU64,
    events_validated: AtomicU64,
    events_reordered: AtomicU64,
    events_enqueued: AtomicU64,
    events_delivered: AtomicU64,
    contract_hash_mismatches: AtomicU64,
    last_contiguous_event_seq: AtomicU64,
    pending_reorder_events: AtomicU64,
    payload_too_large: AtomicU64,
    malformed_json: AtomicU64,
    invalid_envelope: AtomicU64,
    incompatible_ncp_version: AtomicU64,
    provenance_mismatch: AtomicU64,
    duplicate_or_regressed_sequence: AtomicU64,
    reorder_distance_exceeded: AtomicU64,
    reorder_capacity_exceeded: AtomicU64,
    sequence_gap_deadline_exceeded: AtomicU64,
    handoff_full: AtomicU64,
    handoff_closed: AtomicU64,
    internal_sequence_failure: AtomicU64,
    timer_task_failed: AtomicU64,
    last_payload_received_at: Mutex<Option<Instant>>,
}

impl IngressCounters {
    fn fault_count(&self, kind: MonitorIngressFaultKind) -> u64 {
        fault_counter(self, kind).load(Ordering::Relaxed)
    }

    fn fault_counts(&self) -> MonitorIngressFaultCounts {
        MonitorIngressFaultCounts {
            payload_too_large: self.payload_too_large.load(Ordering::Relaxed),
            malformed_json: self.malformed_json.load(Ordering::Relaxed),
            invalid_envelope: self.invalid_envelope.load(Ordering::Relaxed),
            incompatible_ncp_version: self.incompatible_ncp_version.load(Ordering::Relaxed),
            provenance_mismatch: self.provenance_mismatch.load(Ordering::Relaxed),
            duplicate_or_regressed_sequence: self
                .duplicate_or_regressed_sequence
                .load(Ordering::Relaxed),
            reorder_distance_exceeded: self.reorder_distance_exceeded.load(Ordering::Relaxed),
            reorder_capacity_exceeded: self.reorder_capacity_exceeded.load(Ordering::Relaxed),
            sequence_gap_deadline_exceeded: self
                .sequence_gap_deadline_exceeded
                .load(Ordering::Relaxed),
            handoff_full: self.handoff_full.load(Ordering::Relaxed),
            handoff_closed: self.handoff_closed.load(Ordering::Relaxed),
            internal_sequence_failure: self.internal_sequence_failure.load(Ordering::Relaxed),
            timer_task_failed: self.timer_task_failed.load(Ordering::Relaxed),
        }
    }

    fn last_payload_received_at(&self) -> Option<Instant> {
        *self
            .last_payload_received_at
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

fn fault_counter(counters: &IngressCounters, kind: MonitorIngressFaultKind) -> &AtomicU64 {
    match kind {
        MonitorIngressFaultKind::PayloadTooLarge => &counters.payload_too_large,
        MonitorIngressFaultKind::MalformedJson => &counters.malformed_json,
        MonitorIngressFaultKind::InvalidEnvelope => &counters.invalid_envelope,
        MonitorIngressFaultKind::IncompatibleNcpVersion => &counters.incompatible_ncp_version,
        MonitorIngressFaultKind::ProvenanceMismatch => &counters.provenance_mismatch,
        MonitorIngressFaultKind::DuplicateOrRegressedSequence => {
            &counters.duplicate_or_regressed_sequence
        }
        MonitorIngressFaultKind::ReorderDistanceExceeded => &counters.reorder_distance_exceeded,
        MonitorIngressFaultKind::ReorderCapacityExceeded => &counters.reorder_capacity_exceeded,
        MonitorIngressFaultKind::SequenceGapDeadlineExceeded => {
            &counters.sequence_gap_deadline_exceeded
        }
        MonitorIngressFaultKind::HandoffFull => &counters.handoff_full,
        MonitorIngressFaultKind::HandoffClosed => &counters.handoff_closed,
        MonitorIngressFaultKind::InternalSequenceFailure => &counters.internal_sequence_failure,
        MonitorIngressFaultKind::TimerTaskFailed => &counters.timer_task_failed,
    }
}

#[derive(Debug)]
struct ReorderState {
    next_event_seq: u64,
    pending: BTreeMap<u64, MonitorReceipt>,
}

impl Default for ReorderState {
    fn default() -> Self {
        Self {
            next_event_seq: 1,
            pending: BTreeMap::new(),
        }
    }
}

impl ReorderState {
    fn admit(
        &mut self,
        receipt: MonitorReceipt,
        config: MonitorLiveConfig,
    ) -> Result<(Vec<MonitorReceipt>, bool), MonitorIngressFault> {
        let received = receipt.envelope.event_seq;
        if received < self.next_event_seq || self.pending.contains_key(&received) {
            return Err(MonitorIngressFault::DuplicateOrRegressedSequence {
                expected: self.next_event_seq,
                received,
            });
        }
        let distance = received - self.next_event_seq;
        if distance > config.max_reorder_distance {
            return Err(MonitorIngressFault::ReorderDistanceExceeded {
                expected: self.next_event_seq,
                received,
                maximum: config.max_reorder_distance,
            });
        }
        if distance > 0 {
            if self.pending.len() >= config.reorder_capacity {
                return Err(MonitorIngressFault::ReorderCapacityExceeded {
                    capacity: config.reorder_capacity,
                });
            }
            self.pending.insert(received, receipt);
            return Ok((Vec::new(), true));
        }

        let mut contiguous = Vec::with_capacity(self.pending.len().saturating_add(1));
        contiguous.push(receipt);
        self.next_event_seq = self
            .next_event_seq
            .checked_add(1)
            .ok_or(MonitorIngressFault::InternalSequenceFailure)?;
        while let Some(receipt) = self.pending.remove(&self.next_event_seq) {
            contiguous.push(receipt);
            self.next_event_seq = self
                .next_event_seq
                .checked_add(1)
                .ok_or(MonitorIngressFault::InternalSequenceFailure)?;
        }
        Ok((contiguous, false))
    }

    fn last_contiguous_event_seq(&self) -> Option<u64> {
        self.next_event_seq
            .checked_sub(1)
            .and_then(NonZeroU64::new)
            .map(NonZeroU64::get)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GapTimerCommand {
    Idle,
    Arm {
        generation: u64,
        deadline_at: Instant,
    },
    Stop,
}

#[derive(Debug, Clone, Copy)]
struct ActiveGap {
    expected: u64,
    generation: u64,
    deadline_at: Instant,
}

#[derive(Debug, Default)]
struct IngressState {
    cancelled: bool,
    terminal_fault: Option<MonitorIngressFault>,
    reorder: ReorderState,
    active_gap: Option<ActiveGap>,
    gap_generation: u64,
    last_ordered_at: Option<Instant>,
}

struct IngressEpoch {
    expected_session_id: String,
    expected_producer_id: String,
    config: MonitorLiveConfig,
    tap_counters: Arc<IngressCounters>,
    subscription_counters: Arc<IngressCounters>,
    state: Arc<Mutex<IngressState>>,
    sender: mpsc::Sender<MonitorReceipt>,
    fault_sender: watch::Sender<Option<MonitorIngressFault>>,
    gap_timer: watch::Sender<GapTimerCommand>,
}

impl IngressEpoch {
    fn process_payload(&self, bytes: &[u8]) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        // The mutex acquisition is the callback's serialized admission point.
        // Timestamping before it would let a callback wait behind another
        // transition, then retroactively anchor a new gap in the past.
        let received_at = Instant::now();
        if state.cancelled {
            return;
        }
        increment_pair(
            &self.tap_counters.payloads_received,
            &self.subscription_counters.payloads_received,
        );
        record_last_received(&self.tap_counters, received_at);
        record_last_received(&self.subscription_counters, received_at);

        if state.terminal_fault.is_some() {
            increment_pair(
                &self.tap_counters.payloads_after_fault,
                &self.subscription_counters.payloads_after_fault,
            );
            return;
        }
        if self.expire_overdue_gap_locked(&mut state, received_at) {
            return;
        }
        if bytes.len() > MAX_MONITOR_EVENT_BYTES {
            self.latch_fault_locked(
                &mut state,
                MonitorIngressFault::PayloadTooLarge {
                    actual: bytes.len(),
                    maximum: MAX_MONITOR_EVENT_BYTES,
                },
            );
            return;
        }

        let envelope = match serde_json::from_slice::<MonitorEnvelope>(bytes) {
            Ok(envelope) => envelope,
            Err(error) => {
                let fault = if error.classify() == serde_json::error::Category::Data {
                    MonitorIngressFault::InvalidEnvelope
                } else {
                    MonitorIngressFault::MalformedJson
                };
                self.latch_fault_locked(&mut state, fault);
                return;
            }
        };
        let contract_hash_mismatch =
            match envelope.validate_for(&self.expected_session_id, &self.expected_producer_id) {
                Ok(ContractStatus::Mismatch { .. }) => true,
                Ok(ContractStatus::Match | ContractStatus::NotAdvertised) => false,
                Err(error) => {
                    self.latch_fault_locked(&mut state, fault_for_monitor_error(&error));
                    return;
                }
            };
        increment_pair(
            &self.tap_counters.events_validated,
            &self.subscription_counters.events_validated,
        );
        if contract_hash_mismatch {
            increment_pair(
                &self.tap_counters.contract_hash_mismatches,
                &self.subscription_counters.contract_hash_mismatches,
            );
        }

        let receipt = MonitorReceipt {
            envelope,
            received_at,
            ordered_at: received_at,
        };
        let (mut contiguous, reordered) = match state.reorder.admit(receipt, self.config) {
            Ok(admitted) => admitted,
            Err(fault) => {
                self.latch_fault_locked(&mut state, fault);
                return;
            }
        };
        if reordered {
            increment_pair(
                &self.tap_counters.events_reordered,
                &self.subscription_counters.events_reordered,
            );
        }

        if self.refresh_gap_deadline_locked(&mut state, received_at) {
            return;
        }

        store_pair(
            &self.tap_counters.pending_reorder_events,
            &self.subscription_counters.pending_reorder_events,
            usize_to_u64(state.reorder.pending.len()),
        );
        if let Some(sequence) = state.reorder.last_contiguous_event_seq() {
            store_pair(
                &self.tap_counters.last_contiguous_event_seq,
                &self.subscription_counters.last_contiguous_event_seq,
                sequence,
            );
        }

        for receipt in &mut contiguous {
            let ordered_at = state
                .last_ordered_at
                .map_or(receipt.received_at, |previous| {
                    previous.max(receipt.received_at)
                });
            receipt.ordered_at = ordered_at;
            state.last_ordered_at = Some(ordered_at);
        }
        for receipt in contiguous {
            let event_seq = receipt.envelope.event_seq;
            match self.sender.try_send(receipt) {
                Ok(()) => increment_pair(
                    &self.tap_counters.events_enqueued,
                    &self.subscription_counters.events_enqueued,
                ),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.latch_fault_locked(
                        &mut state,
                        MonitorIngressFault::HandoffFull {
                            capacity: self.config.handoff_capacity,
                            event_seq,
                        },
                    );
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.latch_fault_locked(
                        &mut state,
                        MonitorIngressFault::HandoffClosed { event_seq },
                    );
                    return;
                }
            }
        }
    }

    fn latch_timer_task_failure(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.cancelled {
            return;
        }
        self.latch_fault_locked(&mut state, MonitorIngressFault::TimerTaskFailed);
    }

    fn arm_gap_locked(
        &self,
        state: &mut IngressState,
        expected: u64,
        started_at: Instant,
    ) -> Result<(), MonitorIngressFault> {
        let generation = state
            .gap_generation
            .checked_add(1)
            .ok_or(MonitorIngressFault::InternalSequenceFailure)?;
        let deadline_at = started_at
            .checked_add(self.config.reorder_deadline)
            .ok_or(MonitorIngressFault::InternalSequenceFailure)?;
        state.gap_generation = generation;
        state.active_gap = Some(ActiveGap {
            expected,
            generation,
            deadline_at,
        });
        self.gap_timer.send_replace(GapTimerCommand::Arm {
            generation,
            deadline_at,
        });
        Ok(())
    }

    fn refresh_gap_deadline_locked(&self, state: &mut IngressState, now: Instant) -> bool {
        if state.reorder.pending.is_empty() {
            if state.active_gap.take().is_some() {
                self.gap_timer.send_replace(GapTimerCommand::Idle);
            }
            return false;
        }

        let expected = state.reorder.next_event_seq;
        if state
            .active_gap
            .is_none_or(|active_gap| active_gap.expected != expected)
        {
            // Every pending receipt proves that `expected` is absent. Sequence
            // order is not arrival order, so use the oldest proof rather than the
            // lowest pending sequence; otherwise nearer late arrivals can extend
            // an already-established gap beyond its configured temporal bound.
            let started_at = state
                .reorder
                .pending
                .values()
                .map(|receipt| receipt.received_at)
                .min()
                .unwrap_or(now);
            if let Err(fault) = self.arm_gap_locked(state, expected, started_at) {
                self.latch_fault_locked(state, fault);
                return true;
            }
        }
        self.expire_overdue_gap_locked(state, now)
    }

    fn expire_overdue_gap_locked(&self, state: &mut IngressState, now: Instant) -> bool {
        let Some(active_gap) = state.active_gap else {
            return false;
        };
        if now < active_gap.deadline_at {
            return false;
        }
        let fault = sequence_gap_fault(state, self.config.reorder_deadline);
        self.latch_fault_locked(state, fault)
    }

    fn expire_gap(&self, generation: u64, now: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.cancelled {
            return true;
        }
        if state.terminal_fault.is_some() {
            return true;
        }
        let Some(active_gap) = state.active_gap else {
            return false;
        };
        if active_gap.generation != generation || now < active_gap.deadline_at {
            return false;
        }
        let fault = sequence_gap_fault(&state, self.config.reorder_deadline);
        self.latch_fault_locked(&mut state, fault)
    }

    fn cancel(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.cancelled {
            return;
        }
        state.cancelled = true;
        state.reorder.pending.clear();
        state.active_gap = None;
        store_pair(
            &self.tap_counters.pending_reorder_events,
            &self.subscription_counters.pending_reorder_events,
            0,
        );
        self.gap_timer.send_replace(GapTimerCommand::Stop);
    }

    fn latch_fault_locked(&self, state: &mut IngressState, fault: MonitorIngressFault) -> bool {
        if state.terminal_fault.is_some() {
            return false;
        }
        let kind = fault.kind();
        state.reorder.pending.clear();
        state.active_gap = None;
        store_pair(
            &self.tap_counters.pending_reorder_events,
            &self.subscription_counters.pending_reorder_events,
            0,
        );
        increment_pair(
            fault_counter(&self.tap_counters, kind),
            fault_counter(&self.subscription_counters, kind),
        );
        state.terminal_fault = Some(fault.clone());
        self.gap_timer.send_replace(GapTimerCommand::Stop);
        self.fault_sender.send_replace(Some(fault));
        true
    }
}

fn sequence_gap_fault(state: &IngressState, deadline: Duration) -> MonitorIngressFault {
    let next_received = state
        .reorder
        .pending
        .first_key_value()
        .map_or(state.reorder.next_event_seq, |(sequence, _)| *sequence);
    MonitorIngressFault::SequenceGapDeadlineExceeded {
        expected: state.reorder.next_event_seq,
        next_received,
        deadline,
    }
}

async fn run_gap_timer(
    mut commands: watch::Receiver<GapTimerCommand>,
    ingress: Weak<IngressEpoch>,
) {
    loop {
        let command = *commands.borrow_and_update();
        match command {
            GapTimerCommand::Idle => {
                if commands.changed().await.is_err() {
                    return;
                }
            }
            GapTimerCommand::Stop => return,
            GapTimerCommand::Arm {
                generation,
                deadline_at,
            } => {
                tokio::select! {
                    biased;
                    changed = commands.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline_at)) => {
                        let Some(ingress) = ingress.upgrade() else {
                            return;
                        };
                        if ingress.expire_gap(generation, deadline_at) {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Subscription-scoped monitor ingress health and the retained first fault.
#[derive(Clone)]
pub struct MonitorSubscriptionHealth {
    counters: Arc<IngressCounters>,
    first_fault: watch::Receiver<Option<MonitorIngressFault>>,
}

impl MonitorSubscriptionHealth {
    /// Payloads observed on the exact monitor route, including rejected input.
    pub fn payloads_received(&self) -> u64 {
        self.counters.payloads_received.load(Ordering::Relaxed)
    }

    /// Payloads ignored after the epoch entered its terminal fault state.
    pub fn payloads_after_fault(&self) -> u64 {
        self.counters.payloads_after_fault.load(Ordering::Relaxed)
    }

    /// Strict envelopes accepted before ordering and handoff.
    pub fn events_validated(&self) -> u64 {
        self.counters.events_validated.load(Ordering::Relaxed)
    }

    /// Valid envelopes that arrived ahead of the next required event sequence.
    pub fn events_reordered(&self) -> u64 {
        self.counters.events_reordered.load(Ordering::Relaxed)
    }

    /// Contiguous receipts admitted to the bounded consumer handoff.
    pub fn events_enqueued(&self) -> u64 {
        self.counters.events_enqueued.load(Ordering::Relaxed)
    }

    /// Receipts returned to the consumer before the terminal boundary.
    pub fn events_delivered(&self) -> u64 {
        self.counters.events_delivered.load(Ordering::Relaxed)
    }

    /// Accepted envelopes carrying an advisory NCP contract-hash mismatch.
    pub fn contract_hash_mismatches(&self) -> u64 {
        self.counters
            .contract_hash_mismatches
            .load(Ordering::Relaxed)
    }

    /// Most recent contiguous event sequence accepted at ingress.
    pub fn last_contiguous_event_seq(&self) -> Option<u64> {
        let sequence = self
            .counters
            .last_contiguous_event_seq
            .load(Ordering::Relaxed);
        NonZeroU64::new(sequence).map(NonZeroU64::get)
    }

    /// Number of validated receipts currently waiting for an earlier sequence.
    pub fn pending_reorder_events(&self) -> u64 {
        self.counters.pending_reorder_events.load(Ordering::Relaxed)
    }

    /// Local monotonic time of the most recent serialized ingress admission.
    pub fn last_payload_received_at(&self) -> Option<Instant> {
        self.counters.last_payload_received_at()
    }

    /// Retained first terminal ingress fault, if any.
    pub fn first_fault(&self) -> Option<MonitorIngressFault> {
        self.first_fault.borrow().clone()
    }

    /// Snapshot terminal fault counts for this subscription.
    pub fn fault_counts(&self) -> MonitorIngressFaultCounts {
        self.counters.fault_counts()
    }

    /// Count for one terminal fault category.
    pub fn fault_count(&self, kind: MonitorIngressFaultKind) -> u64 {
        self.counters.fault_count(kind)
    }
}

/// Nonblocking receive failure for [`LiveMonitorReceiver::try_recv`].
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MonitorTryRecvError {
    /// The epoch has a terminal ingress fault.
    #[error(transparent)]
    Fault(#[from] MonitorIngressFault),
    /// No receipt is currently available.
    #[error("monitor handoff is empty")]
    Empty,
    /// The receipt channel is closed and drained.
    #[error("monitor handoff is closed")]
    Closed,
}

enum MonitorTerminalState {
    Healthy,
    Fault(MonitorIngressFault),
}

/// Bounded, fail-stop receiver for contiguous monitor receipts.
pub struct LiveMonitorReceiver {
    receiver: mpsc::Receiver<MonitorReceipt>,
    first_fault: watch::Receiver<Option<MonitorIngressFault>>,
    fault_channel_closed: bool,
    tap_counters: Arc<IngressCounters>,
    counters: Arc<IngressCounters>,
    state: Arc<Mutex<IngressState>>,
    ingress_owner: Option<Arc<IngressEpoch>>,
    subscriber: Option<zenoh::pubsub::Subscriber<()>>,
    gap_timer_task: Option<tokio::task::JoinHandle<()>>,
    lifecycle_lease: Option<MonitorReceiverLease>,
}

impl LiveMonitorReceiver {
    /// Receive one contiguous monitor receipt.
    ///
    /// Once the first ingress fault is latched, this returns that fault forever
    /// and no queued receipt can cross the terminal boundary. `Ok(None)` means the
    /// handoff was closed and drained without an ingress fault.
    pub async fn recv(&mut self) -> Result<Option<MonitorReceipt>, MonitorIngressFault> {
        loop {
            self.supervise_finished_gap_timer();
            if let MonitorTerminalState::Fault(fault) = self.terminal_state() {
                return Err(fault);
            }
            tokio::select! {
                biased;
                changed = self.first_fault.changed(), if !self.fault_channel_closed => {
                    if changed.is_err() {
                        self.fault_channel_closed = true;
                    }
                }
                receipt = self.receiver.recv() => {
                    let Some(receipt) = receipt else {
                        if let MonitorTerminalState::Fault(fault) = self.terminal_state() {
                            return Err(fault);
                        }
                        return Ok(None);
                    };
                    let state = Arc::clone(&self.state);
                    let state = state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    if let Some(fault) = &state.terminal_fault {
                        return Err(fault.clone());
                    }
                    increment_pair(
                        &self.tap_counters.events_delivered,
                        &self.counters.events_delivered,
                    );
                    return Ok(Some(receipt));
                }
                _ = async {
                    let Some(task) = self.gap_timer_task.as_mut() else {
                        return;
                    };
                    let _ = task.await;
                }, if self.gap_timer_task.is_some() => {
                    self.gap_timer_task.take();
                    if let Some(ingress) = &self.ingress_owner {
                        ingress.latch_timer_task_failure();
                    }
                }
            }
        }
    }

    /// Try to receive one contiguous monitor receipt without waiting.
    pub fn try_recv(&mut self) -> Result<MonitorReceipt, MonitorTryRecvError> {
        self.supervise_finished_gap_timer();
        if let MonitorTerminalState::Fault(fault) = self.terminal_state() {
            return Err(fault.into());
        }
        let receipt = match self.receiver.try_recv() {
            Ok(receipt) => receipt,
            Err(mpsc::error::TryRecvError::Empty) => return Err(MonitorTryRecvError::Empty),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                if let MonitorTerminalState::Fault(fault) = self.terminal_state() {
                    return Err(fault.into());
                }
                return Err(MonitorTryRecvError::Closed);
            }
        };
        let state = Arc::clone(&self.state);
        let state = state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(fault) = &state.terminal_fault {
            return Err(fault.clone().into());
        }
        increment_pair(
            &self.tap_counters.events_delivered,
            &self.counters.events_delivered,
        );
        Ok(receipt)
    }

    /// Cancel this exact subscription while allowing queued receipts to drain.
    ///
    /// This undeclares only this receiver's selector, stops its gap timer, clears
    /// pending reorder state, and never closes or broadly unsubscribes a shared
    /// host-owned bus. Dropping the receiver performs the same cancellation.
    pub fn close(&mut self) {
        self.cancel_subscription();
        self.receiver.close();
    }

    /// Whether the consumer side has been closed.
    pub fn is_closed(&self) -> bool {
        self.receiver.is_closed()
    }

    fn terminal_state(&self) -> MonitorTerminalState {
        match self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .terminal_fault
            .clone()
        {
            Some(fault) => MonitorTerminalState::Fault(fault),
            None => MonitorTerminalState::Healthy,
        }
    }

    fn cancel_subscription(&mut self) {
        self.supervise_finished_gap_timer();
        if let Some(ingress) = self.ingress_owner.take() {
            ingress.cancel();
        }
        if let Some(task) = self.gap_timer_task.take() {
            task.abort();
        }
        drop(self.subscriber.take());
        drop(self.lifecycle_lease.take());
    }

    fn supervise_finished_gap_timer(&mut self) {
        if self
            .gap_timer_task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
        {
            self.gap_timer_task.take();
            if let Some(ingress) = &self.ingress_owner {
                ingress.latch_timer_task_failure();
            }
        }
    }
}

impl Drop for LiveMonitorReceiver {
    fn drop(&mut self) {
        self.cancel_subscription();
    }
}

#[derive(Debug, Default)]
struct MonitorTapLifecycle {
    active_receivers: usize,
    close_started: bool,
    close_complete: bool,
}

struct MonitorReceiverLease {
    lifecycle: Arc<Mutex<MonitorTapLifecycle>>,
}

impl Drop for MonitorReceiverLease {
    fn drop(&mut self) {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        lifecycle.active_receivers = lifecycle.active_receivers.saturating_sub(1);
    }
}

fn reserve_monitor_receiver(
    lifecycle: &Arc<Mutex<MonitorTapLifecycle>>,
) -> Result<MonitorReceiverLease, ZenohError> {
    let mut state = lifecycle.lock().unwrap_or_else(|error| error.into_inner());
    if state.close_started {
        return Err(ZenohError(
            "cannot subscribe after monitor tap close has started".to_owned(),
        ));
    }
    state.active_receivers = state
        .active_receivers
        .checked_add(1)
        .ok_or_else(|| ZenohError("monitor receiver count overflow".to_owned()))?;
    drop(state);
    Ok(MonitorReceiverLease {
        lifecycle: Arc::clone(lifecycle),
    })
}

/// A read-only Zenoh tap on the producer-monitor route.
pub struct MonitorTap {
    bus: ZenohBus,
    realm: String,
    config: MonitorLiveConfig,
    counters: Arc<IngressCounters>,
    owns_bus: bool,
    lifecycle: Arc<Mutex<MonitorTapLifecycle>>,
}

impl MonitorTap {
    /// Open a default-realm tap with explicit transport-security intent.
    pub async fn open(mode: TransportMode) -> Result<Self, ZenohError> {
        Self::open_with_config(mode, MonitorLiveConfig::default()).await
    }

    /// Open a default-realm tap with explicit security intent and ingress bounds.
    pub async fn open_with_config(
        mode: TransportMode,
        config: MonitorLiveConfig,
    ) -> Result<Self, ZenohError> {
        let keys = Keys::default();
        let bus = open_bus(keys, mode).await?;
        Self::from_parts(bus, DEFAULT_REALM.to_string(), config, true)
    }

    /// Open an explicit-realm tap with explicit transport-security intent.
    pub async fn open_realm(
        realm: impl Into<String>,
        mode: TransportMode,
    ) -> Result<Self, ZenohError> {
        Self::open_realm_with_config(realm, mode, MonitorLiveConfig::default()).await
    }

    /// Open an explicit-realm tap with explicit security intent and ingress bounds.
    pub async fn open_realm_with_config(
        realm: impl Into<String>,
        mode: TransportMode,
        config: MonitorLiveConfig,
    ) -> Result<Self, ZenohError> {
        let realm = realm.into();
        let keys = Keys::try_new(&realm)
            .map_err(|error| ZenohError(format!("invalid NCP realm: {error}")))?;
        let bus = open_bus(keys, mode).await?;
        Self::from_parts(bus, realm, config, true)
    }

    /// Wrap a host-owned bus and derive the exact realm from it.
    ///
    /// This inherits the host's security and allocation posture. It cannot prove
    /// that the shared session used mTLS, the required read-only ACL, or a bounded
    /// transport receive-size limit before payload materialization.
    pub fn from_bus(bus: ZenohBus) -> Result<Self, ZenohError> {
        Self::from_bus_with_config(bus, MonitorLiveConfig::default())
    }

    /// Wrap a host-owned bus with caller-supplied ingress bounds.
    pub fn from_bus_with_config(
        bus: ZenohBus,
        config: MonitorLiveConfig,
    ) -> Result<Self, ZenohError> {
        let realm = bus.keys().realm().to_owned();
        Self::from_parts(bus, realm, config, false)
    }

    fn from_parts(
        bus: ZenohBus,
        realm: String,
        config: MonitorLiveConfig,
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
            config,
            counters: Arc::new(IngressCounters::default()),
            owns_bus,
            lifecycle: Arc::new(Mutex::new(MonitorTapLifecycle::default())),
        })
    }

    /// Subscribe to one exact producer epoch with bounded fail-stop delivery.
    ///
    /// # Panics
    ///
    /// Panics when polled outside a Tokio runtime. The runtime must enable its
    /// time driver because each subscription owns a monotonic gap-deadline task.
    pub async fn subscribe_channel(
        &self,
        session_id: &str,
        producer_id: &str,
    ) -> Result<(MonitorSubscriptionHealth, LiveMonitorReceiver), ZenohError> {
        let key = monitor_key(&self.realm, session_id)
            .ok_or_else(|| ZenohError(format!("invalid NCP session id segment: {session_id:?}")))?;
        validate_monitor_producer_id(producer_id)?;
        let lifecycle_lease = reserve_monitor_receiver(&self.lifecycle)?;

        let (sender, receiver) = mpsc::channel(self.config.handoff_capacity);
        let (fault_sender, fault_receiver) = watch::channel(None);
        let (gap_timer, gap_commands) = watch::channel(GapTimerCommand::Idle);
        let subscription_counters = Arc::new(IngressCounters::default());
        let state = Arc::new(Mutex::new(IngressState::default()));
        let health = MonitorSubscriptionHealth {
            counters: Arc::clone(&subscription_counters),
            first_fault: fault_receiver.clone(),
        };
        let ingress = Arc::new(IngressEpoch {
            expected_session_id: session_id.to_owned(),
            expected_producer_id: producer_id.to_owned(),
            config: self.config,
            tap_counters: Arc::clone(&self.counters),
            subscription_counters: Arc::clone(&subscription_counters),
            state: Arc::clone(&state),
            sender,
            fault_sender,
            gap_timer,
        });
        let gap_timer_task = tokio::spawn(run_gap_timer(gap_commands, Arc::downgrade(&ingress)));
        let callback_ingress = Arc::downgrade(&ingress);
        let subscriber = self
            .bus
            .session()
            .declare_subscriber(key.clone())
            .callback(move |sample| {
                let Some(ingress) = callback_ingress.upgrade() else {
                    return;
                };
                let bytes = sample.payload().to_bytes();
                ingress.process_payload(&bytes);
            })
            .await
            .map_err(|error| {
                ZenohError(format!(
                    "declare exact monitor subscriber for {key:?}: {error}"
                ))
            })?;
        let live_receiver = LiveMonitorReceiver {
            receiver,
            first_fault: fault_receiver,
            fault_channel_closed: false,
            tap_counters: Arc::clone(&self.counters),
            counters: Arc::clone(&subscription_counters),
            state: Arc::clone(&state),
            ingress_owner: Some(ingress),
            subscriber: Some(subscriber),
            gap_timer_task: Some(gap_timer_task),
            lifecycle_lease: Some(lifecycle_lease),
        };
        Ok((health, live_receiver))
    }

    /// Payloads observed across this tap's subscriptions.
    pub fn payloads_received(&self) -> u64 {
        self.counters.payloads_received.load(Ordering::Relaxed)
    }

    /// Strict envelopes validated across this tap's subscriptions.
    pub fn events_validated(&self) -> u64 {
        self.counters.events_validated.load(Ordering::Relaxed)
    }

    /// Contiguous receipts enqueued across this tap's subscriptions.
    pub fn events_enqueued(&self) -> u64 {
        self.counters.events_enqueued.load(Ordering::Relaxed)
    }

    /// Receipts delivered across this tap's subscriptions.
    pub fn events_delivered(&self) -> u64 {
        self.counters.events_delivered.load(Ordering::Relaxed)
    }

    /// Accepted advisory contract-hash mismatches across subscriptions.
    pub fn contract_hash_mismatches(&self) -> u64 {
        self.counters
            .contract_hash_mismatches
            .load(Ordering::Relaxed)
    }

    /// Snapshot terminal faults across subscriptions.
    pub fn fault_counts(&self) -> MonitorIngressFaultCounts {
        self.counters.fault_counts()
    }

    /// Underlying bus for a host that owns or shares the transport lifecycle.
    pub fn bus(&self) -> &ZenohBus {
        &self.bus
    }

    /// Close a bus opened by this tap after every scoped receiver is closed.
    ///
    /// # Errors
    ///
    /// A tap created with [`Self::from_bus`] refuses to close the host-owned
    /// session. An owned tap refuses while a returned [`LiveMonitorReceiver`] is
    /// active, preventing that receiver from being stranded on an idle ingress
    /// epoch after transport shutdown. Close or drop every receiver, then retry.
    /// Once owned-session close starts, later subscription attempts are rejected,
    /// including when close is cancelled or returns an error and must be retried.
    /// Owned-session close errors are propagated from `ncp-zenoh`.
    pub async fn close(&self) -> Result<(), ZenohError> {
        if !self.owns_bus {
            return Err(ZenohError(
                "refusing to close a host-owned bus: this monitor tap was created with from_bus"
                    .to_string(),
            ));
        }
        {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if lifecycle.close_complete {
                return Ok(());
            }
            if !lifecycle.close_started {
                if lifecycle.active_receivers > 0 {
                    return Err(ZenohError(format!(
                        "refusing to close monitor tap with {} active receiver(s)",
                        lifecycle.active_receivers
                    )));
                }
                lifecycle.close_started = true;
            }
        }
        self.bus.close().await?;
        self.lifecycle
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .close_complete = true;
        Ok(())
    }
}

async fn open_bus(keys: Keys, mode: TransportMode) -> Result<ZenohBus, ZenohError> {
    match mode {
        TransportMode::Secure => crate::secure_live::open_secure_bus(keys).await,
        TransportMode::QuietDevelopment => ZenohBus::open_realm(keys).await,
    }
}

fn fault_for_monitor_error(error: &MonitorError) -> MonitorIngressFault {
    match error {
        MonitorError::IncompatibleNcpVersion(_) => MonitorIngressFault::IncompatibleNcpVersion,
        MonitorError::ProvenanceMismatch { .. } => MonitorIngressFault::ProvenanceMismatch,
        _ => MonitorIngressFault::InvalidEnvelope,
    }
}

fn validate_monitor_producer_id(producer_id: &str) -> Result<(), ZenohError> {
    if !ncp_core::valid_id_segment(producer_id) {
        return Err(ZenohError(format!(
            "invalid monitor producer id segment: {producer_id:?}"
        )));
    }
    if producer_id.len() > MAX_ID_SEGMENT_BYTES {
        return Err(ZenohError(format!(
            "invalid monitor producer id segment: {producer_id:?}"
        )));
    }
    Ok(())
}

fn record_last_received(counters: &IngressCounters, received_at: Instant) {
    let mut last = counters
        .last_payload_received_at
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if last.is_none_or(|previous| received_at >= previous) {
        *last = Some(received_at);
    }
}

fn increment_pair(tap: &AtomicU64, subscription: &AtomicU64) {
    tap.fetch_add(1, Ordering::Relaxed);
    subscription.fetch_add(1, Ordering::Relaxed);
}

fn store_pair(tap: &AtomicU64, subscription: &AtomicU64, value: u64) {
    tap.store(value, Ordering::Relaxed);
    subscription.store(value, Ordering::Relaxed);
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::{
        AssemblerLimits, AssemblyEvent, CrossRouteAssembler, FrameIdentity,
        RegistryOpportunityPolicy, RegistryVerifier, RegistryViolation,
    };
    use crate::monitor::{
        Heartbeat, ProducerEvent, QueueHealth, MAX_ACTIVE_TRACKS, MAX_FRAME_ITEMS,
    };
    use galadriel_core::observation::{ConsistencyProjection, Modality};

    const SESSION_ID: &str = "epoch-1";
    const PRODUCER_ID: &str = "crebain";

    struct TimestampTestRegistry;

    impl RegistryVerifier for TimestampTestRegistry {
        fn opportunity_policy(&self) -> Result<RegistryOpportunityPolicy, RegistryViolation> {
            Ok(RegistryOpportunityPolicy {
                max_active_tracks: MAX_ACTIVE_TRACKS,
                max_frame_inputs: MAX_FRAME_ITEMS,
                max_attempts_per_track_modality: MAX_FRAME_ITEMS,
                max_outcomes_per_frame: MAX_FRAME_ITEMS,
                max_monitor_queue_events: MAX_MONITOR_QUEUE_EVENTS,
            })
        }

        fn verify_summary(
            &self,
            _identity: FrameIdentity,
            _registry_digest: &str,
            _expected_modalities: &[Modality],
        ) -> Result<(), RegistryViolation> {
            Ok(())
        }

        fn verify_projection(
            &self,
            identity: FrameIdentity,
            modality: Modality,
            projection: &ConsistencyProjection,
        ) -> Result<(), RegistryViolation> {
            if projection.frame_id != identity.frame_id
                || projection.context_id != identity.context_id
                || projection.prior_id != identity.prior_id
            {
                return Err(RegistryViolation::ProjectionIdentityMismatch {
                    expected_frame_id: identity.frame_id,
                    received_frame_id: projection.frame_id,
                    expected_context_id: identity.context_id,
                    received_context_id: projection.context_id,
                    expected_prior_id: identity.prior_id,
                    received_prior_id: projection.prior_id,
                });
            }
            if modality != Modality::Visual {
                return Err(RegistryViolation::UnexpectedProjectionModality {
                    context_id: identity.context_id,
                    modality,
                });
            }
            if projection.dimensions != 3 {
                return Err(RegistryViolation::ProjectionDimensionMismatch {
                    context_id: identity.context_id,
                    expected: 3,
                    received: projection.dimensions,
                });
            }
            Ok(())
        }
    }

    struct Harness {
        ingress: Arc<IngressEpoch>,
        counters: Arc<IngressCounters>,
        receiver: LiveMonitorReceiver,
        fault_receiver: watch::Receiver<Option<MonitorIngressFault>>,
        gap_commands: Option<watch::Receiver<GapTimerCommand>>,
    }

    impl Harness {
        fn new(config: MonitorLiveConfig) -> Self {
            let (sender, receiver) = mpsc::channel(config.handoff_capacity());
            let (fault_sender, fault_receiver) = watch::channel(None);
            let (gap_timer, gap_commands) = watch::channel(GapTimerCommand::Idle);
            let tap_counters = Arc::new(IngressCounters::default());
            let counters = Arc::new(IngressCounters::default());
            let state = Arc::new(Mutex::new(IngressState::default()));
            let ingress = Arc::new(IngressEpoch {
                expected_session_id: SESSION_ID.to_string(),
                expected_producer_id: PRODUCER_ID.to_string(),
                config,
                tap_counters: Arc::clone(&tap_counters),
                subscription_counters: Arc::clone(&counters),
                state: Arc::clone(&state),
                sender,
                fault_sender,
                gap_timer,
            });
            let live_receiver = LiveMonitorReceiver {
                receiver,
                first_fault: fault_receiver.clone(),
                fault_channel_closed: false,
                tap_counters,
                counters: Arc::clone(&counters),
                state,
                ingress_owner: Some(Arc::clone(&ingress)),
                subscriber: None,
                gap_timer_task: None,
                lifecycle_lease: None,
            };
            Self {
                ingress,
                counters,
                receiver: live_receiver,
                fault_receiver,
                gap_commands: Some(gap_commands),
            }
        }

        fn process(&self, bytes: &[u8]) {
            self.ingress.process_payload(bytes);
        }

        fn first_fault(&self) -> Option<MonitorIngressFault> {
            self.fault_receiver.borrow().clone()
        }

        fn spawn_gap_timer(&mut self) -> tokio::task::JoinHandle<()> {
            let commands = self
                .gap_commands
                .take()
                .expect("test gap timer starts only once");
            tokio::spawn(run_gap_timer(commands, Arc::downgrade(&self.ingress)))
        }
    }

    fn encoded(event_seq: u64) -> Vec<u8> {
        MonitorEnvelope::try_new(
            SESSION_ID,
            PRODUCER_ID,
            event_seq,
            ProducerEvent::Heartbeat(Heartbeat {
                producer_timestamp_ms: event_seq,
                uptime_ms: event_seq,
                declared_interval_ms: 1_000,
                declared_deadline_ms: 3_000,
                last_fusion_seq: None,
                active_track_count: 0,
                degraded: false,
                queue_health: QueueHealth {
                    capacity: 8,
                    depth: 0,
                    dropped_event_count: 0,
                    published_event_count: event_seq,
                },
            }),
        )
        .expect("test monitor envelope is valid")
        .encode()
        .expect("test monitor envelope encodes")
    }

    #[test]
    fn config_rejects_zero_and_excessive_bounds() {
        assert!(matches!(
            MonitorLiveConfig::new(0, 1, 1),
            Err(MonitorLiveConfigError::ZeroCapacity { field: "handoff" })
        ));
        assert!(matches!(
            MonitorLiveConfig::new(1, MAX_MONITOR_INGRESS_ITEMS + 1, 1),
            Err(MonitorLiveConfigError::CapacityTooLarge {
                field: "reorder",
                ..
            })
        ));
        assert!(matches!(
            MonitorLiveConfig::new(1, 1, MAX_MONITOR_REORDER_DISTANCE + 1),
            Err(MonitorLiveConfigError::ReorderDistanceTooLarge { .. })
        ));
        assert!(matches!(
            MonitorLiveConfig::new(2, 2, 2),
            Err(MonitorLiveConfigError::HandoffTooSmallForReorder {
                handoff_capacity: 2,
                minimum: 3
            })
        ));
        assert!(matches!(
            MonitorLiveConfig::default().with_reorder_deadline(Duration::ZERO),
            Err(MonitorLiveConfigError::ZeroReorderDeadline)
        ));
        assert!(matches!(
            MonitorLiveConfig::default()
                .with_reorder_deadline(MAX_MONITOR_REORDER_DEADLINE + Duration::from_millis(1)),
            Err(MonitorLiveConfigError::ReorderDeadlineTooLarge { .. })
        ));
    }

    #[test]
    fn config_preserves_nondefault_values_and_accepts_exact_ceilings() {
        let deadline = Duration::from_millis(37);
        let config = MonitorLiveConfig::new(17, 7, 13)
            .expect("nondefault bounds are valid")
            .with_reorder_deadline(deadline)
            .expect("nondefault deadline is valid");
        assert_eq!(
            (
                config.handoff_capacity(),
                config.reorder_capacity(),
                config.max_reorder_distance(),
                config.reorder_deadline(),
            ),
            (17, 7, 13, deadline)
        );
        assert!(validate_item_capacity("handoff", MAX_MONITOR_INGRESS_ITEMS).is_ok());
        assert!(MonitorLiveConfig::default()
            .with_reorder_deadline(MAX_MONITOR_REORDER_DEADLINE)
            .is_ok());
    }

    #[test]
    fn fault_count_snapshot_maps_every_category_and_total() {
        let counts = MonitorIngressFaultCounts {
            payload_too_large: 2,
            malformed_json: 3,
            invalid_envelope: 4,
            incompatible_ncp_version: 5,
            provenance_mismatch: 6,
            duplicate_or_regressed_sequence: 7,
            reorder_distance_exceeded: 8,
            reorder_capacity_exceeded: 9,
            sequence_gap_deadline_exceeded: 10,
            handoff_full: 11,
            handoff_closed: 12,
            internal_sequence_failure: 13,
            timer_task_failed: 14,
        };
        for (kind, expected) in [
            (MonitorIngressFaultKind::PayloadTooLarge, 2),
            (MonitorIngressFaultKind::MalformedJson, 3),
            (MonitorIngressFaultKind::InvalidEnvelope, 4),
            (MonitorIngressFaultKind::IncompatibleNcpVersion, 5),
            (MonitorIngressFaultKind::ProvenanceMismatch, 6),
            (MonitorIngressFaultKind::DuplicateOrRegressedSequence, 7),
            (MonitorIngressFaultKind::ReorderDistanceExceeded, 8),
            (MonitorIngressFaultKind::ReorderCapacityExceeded, 9),
            (MonitorIngressFaultKind::SequenceGapDeadlineExceeded, 10),
            (MonitorIngressFaultKind::HandoffFull, 11),
            (MonitorIngressFaultKind::HandoffClosed, 12),
            (MonitorIngressFaultKind::InternalSequenceFailure, 13),
            (MonitorIngressFaultKind::TimerTaskFailed, 14),
        ] {
            assert_eq!(counts.count(kind), expected);
        }
        assert_eq!(counts.total(), 104);
    }

    #[test]
    fn subscription_health_reports_distinct_counter_values() {
        let counters = Arc::new(IngressCounters::default());
        counters.payloads_received.store(2, Ordering::Relaxed);
        counters.payloads_after_fault.store(3, Ordering::Relaxed);
        counters.events_validated.store(4, Ordering::Relaxed);
        counters.events_reordered.store(5, Ordering::Relaxed);
        counters.events_enqueued.store(6, Ordering::Relaxed);
        counters.events_delivered.store(7, Ordering::Relaxed);
        counters
            .contract_hash_mismatches
            .store(8, Ordering::Relaxed);
        counters
            .last_contiguous_event_seq
            .store(9, Ordering::Relaxed);
        counters.pending_reorder_events.store(10, Ordering::Relaxed);
        counters.payload_too_large.store(11, Ordering::Relaxed);
        counters.provenance_mismatch.store(12, Ordering::Relaxed);
        let received_at = Instant::now();
        *counters
            .last_payload_received_at
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(received_at);
        let (_fault_sender, first_fault) = watch::channel(Some(MonitorIngressFault::MalformedJson));
        let health = MonitorSubscriptionHealth {
            counters: Arc::clone(&counters),
            first_fault,
        };

        assert_eq!(
            (
                health.payloads_received(),
                health.payloads_after_fault(),
                health.events_validated(),
                health.events_reordered(),
                health.events_enqueued(),
                health.events_delivered(),
                health.contract_hash_mismatches(),
                health.last_contiguous_event_seq(),
                health.pending_reorder_events(),
                health.last_payload_received_at(),
            ),
            (2, 3, 4, 5, 6, 7, 8, Some(9), 10, Some(received_at),)
        );
        assert_eq!(
            health.first_fault(),
            Some(MonitorIngressFault::MalformedJson)
        );
        assert_eq!(health.fault_counts().payload_too_large, 11);
        assert_eq!(health.fault_counts().provenance_mismatch, 12);
        assert_eq!(
            health.fault_count(MonitorIngressFaultKind::ProvenanceMismatch),
            12
        );

        counters
            .last_contiguous_event_seq
            .store(0, Ordering::Relaxed);
        assert_eq!(health.last_contiguous_event_seq(), None);
    }

    #[test]
    fn timestamp_and_size_conversion_helpers_preserve_exact_values() {
        let counters = IngressCounters::default();
        let earlier = Instant::now();
        let later = earlier + Duration::from_millis(1);
        record_last_received(&counters, later);
        assert_eq!(counters.last_payload_received_at(), Some(later));
        record_last_received(&counters, earlier);
        assert_eq!(counters.last_payload_received_at(), Some(later));
        assert_eq!(usize_to_u64(2), 2);
    }

    #[test]
    fn default_reorder_state_has_no_contiguous_sequence() {
        assert_eq!(ReorderState::default().last_contiguous_event_seq(), None);
    }

    #[test]
    fn monitor_producer_id_validation_covers_character_and_byte_boundaries() {
        let exact = "a".repeat(MAX_ID_SEGMENT_BYTES);
        let oversized = "a".repeat(MAX_ID_SEGMENT_BYTES + 1);
        assert!(validate_monitor_producer_id(&exact).is_ok());
        assert!(validate_monitor_producer_id(&oversized).is_err());
        assert!(validate_monitor_producer_id("*").is_err());
    }

    #[test]
    fn bounded_reorder_emits_only_contiguous_sequence() {
        let config = MonitorLiveConfig::new(5, 4, 4).expect("valid bounds");
        let mut harness = Harness::new(config);

        harness.process(&encoded(2));
        assert!(matches!(
            harness.receiver.try_recv(),
            Err(MonitorTryRecvError::Empty)
        ));
        std::thread::sleep(Duration::from_millis(2));
        harness.process(&encoded(1));

        let first = harness.receiver.try_recv().expect("event one is ready");
        let second = harness.receiver.try_recv().expect("event two is ready");
        assert_eq!(
            (first.envelope.event_seq, second.envelope.event_seq),
            (1, 2)
        );
        assert!(first.received_at > second.received_at);
        assert!(first.ordered_at <= second.ordered_at);
        assert!(first.ordered_at >= first.received_at);
        assert!(second.ordered_at >= second.received_at);
        assert!(harness.first_fault().is_none());
    }

    #[test]
    fn serialized_admission_timestamp_excludes_callback_mutex_wait() {
        let deadline = Duration::from_millis(10);
        let config = MonitorLiveConfig::new(3, 2, 2)
            .expect("valid bounds")
            .with_reorder_deadline(deadline)
            .expect("valid deadline");
        let mut harness = Harness::new(config);
        let locked_ingress = Arc::clone(&harness.ingress);
        let callback_ingress = Arc::clone(&harness.ingress);
        let state_guard = locked_ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(0);

        let callback = std::thread::spawn(move || {
            started_sender
                .send(())
                .expect("test callback start is observed");
            callback_ingress.process_payload(&encoded(2));
        });
        started_receiver
            .recv()
            .expect("test callback starts while ingress is locked");
        std::thread::sleep(deadline.saturating_mul(5));
        let released_at = Instant::now();
        drop(state_guard);
        callback.join().expect("test callback completes");

        let receipt = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .reorder
            .pending
            .get(&2)
            .cloned()
            .expect("out-of-order event remains pending");
        assert!(receipt.received_at >= released_at);
        assert!(harness.first_fault().is_none());
        assert!(matches!(
            harness.receiver.try_recv(),
            Err(MonitorTryRecvError::Empty)
        ));
    }

    #[test]
    fn ordered_receipts_compose_directly_with_the_assembler_clock() {
        let config = MonitorLiveConfig::new(3, 2, 2).expect("valid bounds");
        let mut harness = Harness::new(config);
        harness.process(&encoded(2));
        std::thread::sleep(Duration::from_millis(2));
        harness.process(&encoded(1));
        let receipts = [
            harness.receiver.try_recv().expect("event one is ready"),
            harness.receiver.try_recv().expect("event two is ready"),
        ];
        let mut assembler = CrossRouteAssembler::new(
            SESSION_ID,
            PRODUCER_ID,
            TimestampTestRegistry,
            AssemblerLimits::default(),
            receipts[0].ordered_at,
        )
        .expect("test assembler config is valid");

        for receipt in receipts {
            let events = assembler.ingest_monitor_envelope(receipt.envelope, receipt.ordered_at);
            assert!(events
                .iter()
                .any(|event| matches!(event, AssemblyEvent::HeartbeatAccepted { .. })));
            assert!(!events
                .iter()
                .any(|event| matches!(event, AssemblyEvent::Fault(_))));
        }
        assert!(assembler.fault().is_none());
    }

    #[test]
    fn full_reorder_burst_fits_an_empty_validated_handoff() {
        let config = MonitorLiveConfig::new(3, 2, 2).expect("burst fits handoff");
        let mut harness = Harness::new(config);

        harness.process(&encoded(2));
        harness.process(&encoded(3));
        harness.process(&encoded(1));

        let sequences = (0..3)
            .map(|_| {
                harness
                    .receiver
                    .try_recv()
                    .expect("full reorder burst is retained")
                    .envelope
                    .event_seq
            })
            .collect::<Vec<_>>();
        assert_eq!(sequences, vec![1, 2, 3]);
        assert!(harness.first_fault().is_none());
    }

    #[tokio::test]
    async fn unexpected_gap_timer_termination_faults_the_subscription() {
        let config = MonitorLiveConfig::new(3, 2, 2).expect("valid bounds");
        let mut harness = Harness::new(config);
        let timer = harness.spawn_gap_timer();
        timer.abort();
        harness.receiver.gap_timer_task = Some(timer);

        let error = tokio::time::timeout(Duration::from_secs(1), harness.receiver.recv())
            .await
            .expect("timer failure is supervised")
            .expect_err("timer failure must fail closed");
        assert_eq!(error, MonitorIngressFault::TimerTaskFailed);
        assert_eq!(
            harness
                .counters
                .fault_count(MonitorIngressFaultKind::TimerTaskFailed),
            1
        );
    }

    #[test]
    fn exact_gap_deadline_expires_but_earlier_and_stale_timer_wakes_do_not() {
        let deadline = Duration::from_secs(1);
        let config = MonitorLiveConfig::new(3, 2, 2)
            .expect("valid bounds")
            .with_reorder_deadline(deadline)
            .expect("valid deadline");
        let harness = Harness::new(config);
        harness.process(&encoded(2));
        let active_gap = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active_gap
            .expect("event two opens a gap");

        assert!(!harness.ingress.expire_gap(
            active_gap.generation,
            active_gap.deadline_at - Duration::from_nanos(1),
        ));
        assert!(!harness
            .ingress
            .expire_gap(active_gap.generation + 1, active_gap.deadline_at,));
        assert!(harness
            .ingress
            .expire_gap(active_gap.generation, active_gap.deadline_at));
        assert!(matches!(
            harness.first_fault(),
            Some(MonitorIngressFault::SequenceGapDeadlineExceeded { .. })
        ));
    }

    #[test]
    fn overdue_gap_locked_expires_at_the_exact_boundary() {
        let config = MonitorLiveConfig::new(3, 2, 2).expect("valid bounds");
        let harness = Harness::new(config);
        harness.process(&encoded(2));
        let mut state = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let deadline_at = state.active_gap.expect("event two opens a gap").deadline_at;

        assert!(harness
            .ingress
            .expire_overdue_gap_locked(&mut state, deadline_at));
        drop(state);
        assert!(matches!(
            harness.first_fault(),
            Some(MonitorIngressFault::SequenceGapDeadlineExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn close_records_a_gap_timer_that_already_failed() {
        let config = MonitorLiveConfig::new(3, 2, 2).expect("valid bounds");
        let mut harness = Harness::new(config);
        let timer = harness.spawn_gap_timer();
        timer.abort();
        while !timer.is_finished() {
            tokio::task::yield_now().await;
        }
        harness.receiver.gap_timer_task = Some(timer);

        harness.receiver.close();

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::TimerTaskFailed)
        );
        assert_eq!(
            harness
                .counters
                .fault_count(MonitorIngressFaultKind::TimerTaskFailed),
            1
        );
    }

    #[tokio::test]
    async fn persistent_small_gap_faults_without_another_payload() {
        let config = MonitorLiveConfig::new(3, 2, 2)
            .expect("valid bounds")
            .with_reorder_deadline(Duration::from_millis(20))
            .expect("valid deadline");
        let mut harness = Harness::new(config);
        let timer = harness.spawn_gap_timer();
        let mut fault_updates = harness.fault_receiver.clone();

        harness.process(&encoded(2));
        tokio::time::timeout(Duration::from_secs(1), fault_updates.changed())
            .await
            .expect("gap faults before outer deadline")
            .expect("fault publisher remains live");

        let expected = MonitorIngressFault::SequenceGapDeadlineExceeded {
            expected: 1,
            next_received: 2,
            deadline: Duration::from_millis(20),
        };
        assert_eq!(harness.first_fault(), Some(expected.clone()));
        assert_eq!(
            harness
                .counters
                .fault_count(MonitorIngressFaultKind::SequenceGapDeadlineExceeded),
            1
        );
        assert_eq!(
            harness
                .counters
                .pending_reorder_events
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(harness.receiver.recv().await, Err(expected));
        timer.await.expect("gap timer exits after terminal fault");
    }

    #[tokio::test]
    async fn closing_a_gap_cancels_its_deadline() {
        let config = MonitorLiveConfig::new(3, 2, 2)
            .expect("valid bounds")
            .with_reorder_deadline(Duration::from_millis(30))
            .expect("valid deadline");
        let mut harness = Harness::new(config);
        let timer = harness.spawn_gap_timer();

        harness.process(&encoded(2));
        tokio::time::sleep(Duration::from_millis(5)).await;
        harness.process(&encoded(1));
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(harness.first_fault().is_none());
        assert_eq!(
            harness
                .receiver
                .try_recv()
                .expect("event one is delivered")
                .envelope
                .event_seq,
            1
        );
        assert_eq!(
            harness
                .receiver
                .try_recv()
                .expect("event two is delivered")
                .envelope
                .event_seq,
            2
        );

        drop(harness);
        tokio::time::timeout(Duration::from_secs(1), timer)
            .await
            .expect("timer observes ingress cancellation")
            .expect("gap timer task exits cleanly");
    }

    #[test]
    fn advancing_the_expected_sequence_reanchors_the_remaining_gap() {
        let deadline = Duration::from_millis(100);
        let config = MonitorLiveConfig::new(4, 3, 4)
            .expect("valid bounds")
            .with_reorder_deadline(deadline)
            .expect("valid deadline");
        let harness = Harness::new(config);

        harness.process(&encoded(2));
        std::thread::sleep(Duration::from_millis(2));
        harness.process(&encoded(4));
        let fourth_received_at = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .reorder
            .pending
            .get(&4)
            .expect("event four remains pending")
            .received_at;
        std::thread::sleep(Duration::from_millis(2));

        harness.process(&encoded(1));

        let state = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let active_gap = state
            .active_gap
            .expect("gap before event four remains active");
        assert_eq!(active_gap.expected, 3);
        assert_eq!(
            active_gap.deadline_at,
            fourth_received_at
                .checked_add(deadline)
                .expect("short test deadline fits")
        );
        assert!(harness.first_fault().is_none());
    }

    #[test]
    fn advancing_a_gap_keeps_the_oldest_pending_arrival_as_its_bound() {
        let deadline = Duration::from_millis(100);
        let config = MonitorLiveConfig::new(5, 4, 4)
            .expect("valid bounds")
            .with_reorder_deadline(deadline)
            .expect("valid deadline");
        let harness = Harness::new(config);

        harness.process(&encoded(5));
        let fifth_received_at = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .reorder
            .pending
            .get(&5)
            .expect("event five remains pending")
            .received_at;
        std::thread::sleep(Duration::from_millis(2));
        harness.process(&encoded(4));
        let fourth_received_at = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .reorder
            .pending
            .get(&4)
            .expect("event four remains pending")
            .received_at;
        assert!(fourth_received_at > fifth_received_at);
        std::thread::sleep(Duration::from_millis(2));

        harness.process(&encoded(1));

        let state = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let active_gap = state
            .active_gap
            .expect("gap before events four and five remains active");
        assert_eq!(active_gap.expected, 2);
        assert_eq!(
            active_gap.deadline_at,
            fifth_received_at
                .checked_add(deadline)
                .expect("short test deadline fits")
        );
        assert_ne!(
            active_gap.deadline_at,
            fourth_received_at
                .checked_add(deadline)
                .expect("short test deadline fits")
        );
    }

    #[test]
    fn concurrent_callbacks_emit_one_contiguous_sequence() {
        const EVENT_COUNT: u64 = 32;
        let config = MonitorLiveConfig::new(64, 32, 32).expect("valid concurrency bounds");
        let mut harness = Harness::new(config);
        let barrier = Arc::new(std::sync::Barrier::new(EVENT_COUNT as usize));
        let mut workers = Vec::new();

        for event_seq in (1..=EVENT_COUNT).rev() {
            let ingress = Arc::clone(&harness.ingress);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let bytes = encoded(event_seq);
                barrier.wait();
                ingress.process_payload(&bytes);
            }));
        }
        for worker in workers {
            worker.join().expect("callback worker does not panic");
        }

        let delivered = (1..=EVENT_COUNT)
            .map(|_| {
                harness
                    .receiver
                    .try_recv()
                    .expect("every concurrent event reaches the handoff")
                    .envelope
                    .event_seq
            })
            .collect::<Vec<_>>();
        assert_eq!(delivered, (1..=EVENT_COUNT).collect::<Vec<_>>());
        assert!(harness.first_fault().is_none());
    }

    #[test]
    fn receiver_delivery_and_fault_are_linearizable() {
        for _ in 0..32 {
            let mut harness = Harness::new(MonitorLiveConfig::default());
            harness.process(&encoded(1));
            let ingress = Arc::clone(&harness.ingress);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let fault_barrier = Arc::clone(&barrier);
            let fault_worker = std::thread::spawn(move || {
                fault_barrier.wait();
                ingress.process_payload(b"{not-json");
            });

            barrier.wait();
            let delivered = harness.receiver.try_recv();
            fault_worker.join().expect("fault callback does not panic");

            match delivered {
                Ok(receipt) => {
                    assert_eq!(receipt.envelope.event_seq, 1);
                    assert_eq!(harness.counters.events_delivered.load(Ordering::Relaxed), 1);
                }
                Err(MonitorTryRecvError::Fault(MonitorIngressFault::MalformedJson)) => {
                    assert_eq!(harness.counters.events_delivered.load(Ordering::Relaxed), 0);
                }
                other => panic!("delivery/fault race returned impossible outcome: {other:?}"),
            }
            assert_eq!(
                harness.first_fault(),
                Some(MonitorIngressFault::MalformedJson)
            );
            assert_eq!(
                harness.receiver.try_recv(),
                Err(MonitorTryRecvError::Fault(
                    MonitorIngressFault::MalformedJson
                ))
            );
        }
    }

    #[test]
    fn callbacks_after_terminal_fault_cannot_mutate_ingress_state() {
        const AFTER_FAULT: usize = 16;
        let harness = Harness::new(MonitorLiveConfig::default());
        harness.process(b"{not-json");
        let barrier = Arc::new(std::sync::Barrier::new(AFTER_FAULT));
        let mut workers = Vec::new();

        for event_seq in 1..=AFTER_FAULT as u64 {
            let ingress = Arc::clone(&harness.ingress);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let bytes = encoded(event_seq);
                barrier.wait();
                ingress.process_payload(&bytes);
            }));
        }
        for worker in workers {
            worker.join().expect("post-fault callback does not panic");
        }

        let state = harness
            .ingress
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            state.terminal_fault,
            Some(MonitorIngressFault::MalformedJson)
        );
        assert!(state.reorder.pending.is_empty());
        assert_eq!(state.reorder.next_event_seq, 1);
        assert!(state.last_ordered_at.is_none());
        drop(state);
        assert_eq!(
            harness
                .counters
                .payloads_after_fault
                .load(Ordering::Relaxed),
            AFTER_FAULT as u64
        );
        assert_eq!(harness.counters.events_enqueued.load(Ordering::Relaxed), 0);
        assert_eq!(harness.counters.fault_counts().total(), 1);
    }

    #[test]
    fn duplicate_sequence_latches_terminal_fault() {
        let mut harness = Harness::new(MonitorLiveConfig::default());
        harness.process(&encoded(1));
        harness.receiver.try_recv().expect("first event is ready");

        harness.process(&encoded(1));

        assert!(matches!(
            harness.first_fault(),
            Some(MonitorIngressFault::DuplicateOrRegressedSequence {
                expected: 2,
                received: 1
            })
        ));
    }

    #[test]
    fn reorder_capacity_latches_terminal_fault() {
        let config = MonitorLiveConfig::new(4, 1, 4).expect("valid bounds");
        let harness = Harness::new(config);
        harness.process(&encoded(2));

        harness.process(&encoded(3));

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::ReorderCapacityExceeded { capacity: 1 })
        );
    }

    #[test]
    fn handoff_capacity_fault_cannot_hide_behind_full_queue() {
        let config = MonitorLiveConfig::new(2, 1, 2).expect("valid bounds");
        let harness = Harness::new(config);
        harness.process(&encoded(1));

        harness.process(&encoded(2));
        harness.process(&encoded(3));

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::HandoffFull {
                capacity: 2,
                event_seq: 3
            })
        );
    }

    #[test]
    fn malformed_json_remains_the_first_fault() {
        let harness = Harness::new(MonitorLiveConfig::default());
        harness.process(b"{not-json");

        harness.process(&vec![b'x'; MAX_MONITOR_EVENT_BYTES + 1]);

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::MalformedJson)
        );
        assert_eq!(
            harness
                .counters
                .payloads_after_fault
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn payload_size_gate_runs_before_json_decode() {
        let harness = Harness::new(MonitorLiveConfig::default());

        harness.process(&vec![b'x'; MAX_MONITOR_EVENT_BYTES + 1]);

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::PayloadTooLarge {
                actual: MAX_MONITOR_EVENT_BYTES + 1,
                maximum: MAX_MONITOR_EVENT_BYTES
            })
        );
        assert_eq!(
            harness
                .counters
                .fault_count(MonitorIngressFaultKind::MalformedJson),
            0
        );
    }

    #[test]
    fn payload_at_the_exact_wire_ceiling_reaches_json_decode() {
        let harness = Harness::new(MonitorLiveConfig::default());

        harness.process(&vec![b' '; MAX_MONITOR_EVENT_BYTES]);

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::MalformedJson)
        );
        assert_eq!(
            harness
                .counters
                .fault_count(MonitorIngressFaultKind::PayloadTooLarge),
            0
        );
    }

    #[test]
    fn duplicate_json_key_latches_invalid_envelope_fault() {
        let harness = Harness::new(MonitorLiveConfig::default());
        let json = String::from_utf8(encoded(1)).expect("test envelope is UTF-8 JSON");
        let duplicated = json.replacen(
            "\"kind\":\"galadriel_producer_event\"",
            "\"kind\":\"other\",\"kind\":\"galadriel_producer_event\"",
            1,
        );

        harness.process(duplicated.as_bytes());

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::InvalidEnvelope)
        );
    }

    #[test]
    fn reorder_distance_latches_terminal_fault() {
        let config = MonitorLiveConfig::new(5, 4, 1).expect("valid bounds");
        let harness = Harness::new(config);

        harness.process(&encoded(3));

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::ReorderDistanceExceeded {
                expected: 1,
                received: 3,
                maximum: 1
            })
        );
    }

    #[test]
    fn closing_receiver_cancels_without_fault_and_clears_pending_state() {
        let mut harness = Harness::new(MonitorLiveConfig::default());
        assert!(!harness.receiver.is_closed());
        harness.process(&encoded(2));
        assert_eq!(
            harness
                .counters
                .pending_reorder_events
                .load(Ordering::Relaxed),
            1
        );

        harness.receiver.close();
        harness.process(&encoded(1));

        assert!(harness.receiver.is_closed());
        assert!(harness.first_fault().is_none());
        assert_eq!(
            harness
                .counters
                .pending_reorder_events
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            harness.counters.payloads_received.load(Ordering::Relaxed),
            1
        );
        harness.ingress.latch_timer_task_failure();
        assert!(harness.first_fault().is_none());
    }

    #[test]
    fn dropping_receiver_cancels_owned_ingress_and_clears_pending_state() {
        let Harness {
            ingress,
            counters,
            receiver,
            ..
        } = Harness::new(MonitorLiveConfig::default());
        ingress.process_payload(&encoded(2));
        assert_eq!(counters.pending_reorder_events.load(Ordering::Relaxed), 1);

        drop(receiver);
        assert!(
            ingress
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .cancelled
        );
        assert_eq!(counters.pending_reorder_events.load(Ordering::Relaxed), 0);
        ingress.process_payload(&encoded(1));
        assert_eq!(counters.payloads_received.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn incompatible_ncp_version_latches_typed_fault() {
        let harness = Harness::new(MonitorLiveConfig::default());
        let mut value: serde_json::Value =
            serde_json::from_slice(&encoded(1)).expect("test envelope is JSON");
        value["ncp_version"] = serde_json::json!("0.7");

        harness.process(&serde_json::to_vec(&value).expect("modified envelope encodes"));

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::IncompatibleNcpVersion)
        );
    }

    #[test]
    fn wrong_producer_latches_provenance_fault() {
        let harness = Harness::new(MonitorLiveConfig::default());
        let mut value: serde_json::Value =
            serde_json::from_slice(&encoded(1)).expect("test envelope is JSON");
        value["producer_id"] = serde_json::json!("other");

        harness.process(&serde_json::to_vec(&value).expect("modified envelope encodes"));

        assert_eq!(
            harness.first_fault(),
            Some(MonitorIngressFault::ProvenanceMismatch)
        );
    }
}
