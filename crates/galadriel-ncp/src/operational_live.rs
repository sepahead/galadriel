//! Bounded live assembly across the observation and producer-monitor routes.
//!
//! One [`OperationalLiveReceiver`] owns one [`CrossRouteAssembler`] and subscribes
//! one [`ZenohBus`] to the two exact named-sensor keys for a producer epoch. Both
//! Zenoh callbacks serialize through one ingress lock, capture receipt time while
//! holding that lock, and move accepted payloads through one bounded, nonblocking
//! channel. The first ingress or assembler fault permanently terminates delivery.
//!
//! This is an integration boundary, not proof of a deployment's authentication or
//! ACL policy. [`OperationalLiveReceiver::open_secure`] validates one parsed strict
//! client configuration and opens that same value through `ncp-zenoh`.
//! [`OperationalLiveReceiver::from_bus`] necessarily inherits an existing session's
//! security posture without verifying it.
//! Opening and receiving require a Tokio runtime with the time driver enabled.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ncp_core::Keys;
use ncp_zenoh::{ZenohBus, ZenohError};
use tokio::sync::{mpsc, Notify};
use zenoh::pubsub::Subscriber;

use crate::assembler::{
    AssemblerConfigError, AssemblerLimits, AssemblyEvent, AssemblyFault, CrossRouteAssembler,
    EvidenceRoute, RegistryVerifier, MAX_ASSEMBLER_SIDECAR_BYTES,
};
use crate::monitor::{MAX_MONITOR_EVENT_BYTES, MONITOR_SENSOR_NAME};
use crate::SIDECAR_SENSOR_NAME;

/// Default number of raw cross-route payloads waiting for the assembler.
pub const DEFAULT_OPERATIONAL_INGRESS_CAPACITY: usize = 1_024;

/// Hard ceiling for the raw cross-route handoff.
pub const MAX_OPERATIONAL_INGRESS_CAPACITY: usize = 8_192;

const INGRESS_STARTING: u8 = 0;
const INGRESS_ACTIVATING: u8 = 1;
const INGRESS_ACTIVE: u8 = 2;
const INGRESS_CLOSED: u8 = 3;

/// Bounded configuration for one operational receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationalLiveConfig {
    ingress_capacity: usize,
}

impl OperationalLiveConfig {
    /// Construct a configuration with a finite raw-ingress capacity.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalLiveConfigError`] when `ingress_capacity` is zero or
    /// exceeds [`MAX_OPERATIONAL_INGRESS_CAPACITY`].
    pub fn new(ingress_capacity: usize) -> Result<Self, OperationalLiveConfigError> {
        if ingress_capacity == 0 {
            return Err(OperationalLiveConfigError::ZeroIngressCapacity);
        }
        if ingress_capacity > MAX_OPERATIONAL_INGRESS_CAPACITY {
            return Err(OperationalLiveConfigError::IngressCapacityTooLarge {
                capacity: ingress_capacity,
                maximum: MAX_OPERATIONAL_INGRESS_CAPACITY,
            });
        }
        Ok(Self { ingress_capacity })
    }

    /// Maximum raw payloads waiting for the assembler.
    pub fn ingress_capacity(self) -> usize {
        self.ingress_capacity
    }
}

impl Default for OperationalLiveConfig {
    fn default() -> Self {
        Self {
            ingress_capacity: DEFAULT_OPERATIONAL_INGRESS_CAPACITY,
        }
    }
}

/// Invalid operational-live resource configuration.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationalLiveConfigError {
    /// A zero-capacity handoff cannot admit evidence.
    #[error("operational ingress capacity must be greater than zero")]
    ZeroIngressCapacity,
    /// The requested handoff exceeded its process ceiling.
    #[error("operational ingress capacity {capacity} exceeds maximum {maximum}")]
    IngressCapacityTooLarge { capacity: usize, maximum: usize },
}

/// What the receiver itself can establish about its transport setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationalTransportSecurity {
    /// The receiver opened a bus from one locally validated secure configuration.
    ///
    /// This proves local strict-config validation, not remote deployment policy.
    OwnedSecureConfigValidated,
    /// A host supplied the bus; transport security is inherited and unverified.
    InheritedUnverified,
}

/// Terminal failure detected before raw evidence reached the assembler.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationalIngressFault {
    /// Evidence arrived before both exact route subscriptions were active.
    #[error("{route:?} payload arrived before the operational epoch was active")]
    EvidenceBeforeReady {
        route: EvidenceRoute,
        detected_at: Instant,
    },
    /// The exact subscription unexpectedly reported a different key.
    #[error("{route:?} subscription received unexpected key {received:?}; expected {expected:?}")]
    UnexpectedKey {
        route: EvidenceRoute,
        expected: String,
        received: String,
        detected_at: Instant,
    },
    /// Payload size exceeded the route's pre-assembly bound.
    #[error("{route:?} payload has {actual} bytes, maximum {maximum}")]
    PayloadTooLarge {
        route: EvidenceRoute,
        actual: usize,
        maximum: usize,
        detected_at: Instant,
    },
    /// The single bounded handoff was full.
    #[error("operational ingress is full at capacity {capacity} for {route:?}")]
    HandoffFull {
        route: EvidenceRoute,
        capacity: usize,
        detected_at: Instant,
    },
    /// The single bounded handoff was closed.
    #[error("operational ingress is closed for {route:?}")]
    HandoffClosed {
        route: EvidenceRoute,
        detected_at: Instant,
    },
    /// The receiver observed that all handoff senders had closed.
    #[error("operational ingress channel closed")]
    IngressClosed { detected_at: Instant },
}

impl OperationalIngressFault {
    /// Local monotonic instant at which the fault became known.
    pub fn detected_at(&self) -> Instant {
        match self {
            Self::EvidenceBeforeReady { detected_at, .. }
            | Self::UnexpectedKey { detected_at, .. }
            | Self::PayloadTooLarge { detected_at, .. }
            | Self::HandoffFull { detected_at, .. }
            | Self::HandoffClosed { detected_at, .. }
            | Self::IngressClosed { detected_at } => *detected_at,
        }
    }
}

/// Terminal receive outcome for one operational receiver epoch.
///
/// Ingress and assembly variants are retained as the first terminal fault in
/// health. [`Self::Closed`] is an expected caller-initiated lifecycle boundary and
/// is never recorded as a fault.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OperationalLiveFault {
    /// Raw ingress failed before assembly.
    #[error(transparent)]
    Ingress(#[from] OperationalIngressFault),
    /// The cross-route assembler failed closed.
    #[error("cross-route assembler fault: {0:?}")]
    Assembly(AssemblyFault),
    /// The caller explicitly closed the receiver.
    #[error("operational receiver is closed")]
    Closed { closed_at: Instant },
}

impl OperationalLiveFault {
    /// Local monotonic instant at which the fault or closure became known.
    pub fn detected_at(&self) -> Instant {
        match self {
            Self::Ingress(fault) => fault.detected_at(),
            Self::Assembly(fault) => fault.detected_at,
            Self::Closed { closed_at } => *closed_at,
        }
    }
}

/// Startup failure while constructing an operational receiver.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OperationalLiveOpenError {
    /// Immutable assembler configuration was invalid.
    #[error(transparent)]
    Assembler(#[from] AssemblerConfigError),
    /// An exact named-sensor key could not be constructed.
    #[error("cannot construct operational route: {0}")]
    Route(String),
    /// Zenoh open or subscription declaration failed.
    #[error(transparent)]
    Transport(#[from] ZenohError),
    /// Evidence arrived during the non-atomic two-subscription startup window.
    #[error("evidence arrived before both exact operational subscriptions were active")]
    EvidenceBeforeReady,
}

/// Coherent point-in-time counters for one operational receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalLiveHealthSnapshot {
    /// Security posture established by the receiver constructor.
    pub transport_security: OperationalTransportSecurity,
    /// Configured capacity of the single raw cross-route handoff.
    pub ingress_capacity: usize,
    /// Current number of raw payloads waiting in that handoff.
    pub ingress_queue_depth: usize,
    /// Observation-route callbacks invoked, including terminal/post-fault input.
    pub observation_payloads_received: u64,
    /// Monitor-route callbacks invoked, including terminal/post-fault input.
    pub monitor_payloads_received: u64,
    /// Aggregate callback payload bytes, saturating at `u64::MAX`.
    pub payload_bytes_received: u64,
    /// Observation payloads admitted to the single bounded handoff.
    pub observation_payloads_enqueued: u64,
    /// Monitor payloads admitted to the single bounded handoff.
    pub monitor_payloads_enqueued: u64,
    /// Raw payloads fed into the assembler.
    pub payloads_processed: u64,
    /// Payloads rejected by the callback that established the terminal fault.
    pub payloads_rejected: u64,
    /// Callback payloads observed after the first terminal fault.
    pub post_fault_payloads: u64,
    /// Previously enqueued payloads discarded after a fault or close boundary.
    pub queued_payloads_discarded: u64,
    /// Nonterminal assembler events staged for callers.
    pub assembly_events_staged: u64,
    /// Assembly events returned to callers.
    pub assembly_events_delivered: u64,
    /// Staged or transaction-local events invalidated by a fault or close boundary.
    pub assembly_events_discarded: u64,
    /// Delivered lifecycle-complete frames.
    pub frames_delivered: u64,
    /// Delivered heartbeat acknowledgements.
    pub heartbeats_delivered: u64,
    /// Delivered contract-hash advisories.
    pub contract_advisories_delivered: u64,
    /// Assembler terminal faults observed, whether or not ingress faulted first.
    pub assembly_faults_observed: u64,
    /// Zero before failure and one after the retained first fault.
    pub terminal_faults: u64,
    /// Latest monotonic receipt captured under callback serialization.
    pub last_receipt_at: Option<Instant>,
    /// Retained first terminal fault.
    pub first_fault: Option<OperationalLiveFault>,
}

impl OperationalLiveHealthSnapshot {
    fn new(transport_security: OperationalTransportSecurity, ingress_capacity: usize) -> Self {
        Self {
            transport_security,
            ingress_capacity,
            ingress_queue_depth: 0,
            observation_payloads_received: 0,
            monitor_payloads_received: 0,
            payload_bytes_received: 0,
            observation_payloads_enqueued: 0,
            monitor_payloads_enqueued: 0,
            payloads_processed: 0,
            payloads_rejected: 0,
            post_fault_payloads: 0,
            queued_payloads_discarded: 0,
            assembly_events_staged: 0,
            assembly_events_delivered: 0,
            assembly_events_discarded: 0,
            frames_delivered: 0,
            heartbeats_delivered: 0,
            contract_advisories_delivered: 0,
            assembly_faults_observed: 0,
            terminal_faults: 0,
            last_receipt_at: None,
            first_fault: None,
        }
    }
}

/// Read-only health handle retained independently from the receiver.
#[derive(Clone)]
pub struct OperationalLiveHealth {
    shared: Arc<SharedIngress>,
}

impl OperationalLiveHealth {
    /// Return a coherent snapshot taken under the shared ingress lock.
    pub fn snapshot(&self) -> OperationalLiveHealthSnapshot {
        let state = lock_state(&self.shared);
        let mut snapshot = state.health.clone();
        snapshot.ingress_queue_depth = state.capacity.saturating_sub(state.sender.capacity());
        snapshot
    }

    /// Return the retained first terminal fault, if any.
    pub fn first_fault(&self) -> Option<OperationalLiveFault> {
        lock_state(&self.shared).health.first_fault.clone()
    }
}

#[derive(Debug)]
struct RawIngress {
    route: EvidenceRoute,
    payload: Vec<u8>,
    received_at: Instant,
}

struct SharedIngress {
    state: Mutex<IngressState>,
    terminal_notify: Notify,
    startup_notify: Notify,
    startup_inflight: AtomicUsize,
    phase: AtomicU8,
}

struct IngressState {
    sender: mpsc::Sender<RawIngress>,
    health: OperationalLiveHealthSnapshot,
    capacity: usize,
}

impl IngressState {
    fn latch_first(&mut self, fault: OperationalLiveFault) -> bool {
        if self.health.first_fault.is_some() {
            return false;
        }
        self.health.first_fault = Some(fault);
        self.health.terminal_faults = 1;
        true
    }

    fn note_received(&mut self, route: EvidenceRoute, payload_bytes: usize, received_at: Instant) {
        match route {
            EvidenceRoute::Observation => {
                increment(&mut self.health.observation_payloads_received);
            }
            EvidenceRoute::Monitor => {
                increment(&mut self.health.monitor_payloads_received);
            }
        }
        self.health.payload_bytes_received = self
            .health
            .payload_bytes_received
            .saturating_add(usize_to_u64(payload_bytes));
        self.health.last_receipt_at = Some(received_at);
    }

    fn note_enqueued(&mut self, route: EvidenceRoute) {
        match route {
            EvidenceRoute::Observation => {
                increment(&mut self.health.observation_payloads_enqueued);
            }
            EvidenceRoute::Monitor => {
                increment(&mut self.health.monitor_payloads_enqueued);
            }
        }
    }
}

fn lock_state(shared: &SharedIngress) -> MutexGuard<'_, IngressState> {
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn increment(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn route_payload_limit(route: EvidenceRoute) -> usize {
    match route {
        EvidenceRoute::Observation => MAX_ASSEMBLER_SIDECAR_BYTES,
        EvidenceRoute::Monitor => MAX_MONITOR_EVENT_BYTES,
    }
}

fn receipt_precedes_deadline(received_at: Instant, deadline: Instant) -> bool {
    received_at < deadline
}

struct StartupCallbackPermit<'a> {
    shared: &'a SharedIngress,
}

struct StartupActivationGuard {
    shared: Arc<SharedIngress>,
    armed: bool,
}

impl StartupActivationGuard {
    fn new(shared: Arc<SharedIngress>) -> Self {
        Self {
            shared,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartupActivationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.shared.phase.store(INGRESS_CLOSED, Ordering::Release);
            self.shared.startup_notify.notify_waiters();
        }
    }
}

impl Drop for StartupCallbackPermit<'_> {
    fn drop(&mut self) {
        self.shared.startup_inflight.fetch_sub(1, Ordering::AcqRel);
        self.shared.startup_notify.notify_one();
    }
}

fn enter_callback(shared: &SharedIngress) -> (u8, Option<StartupCallbackPermit<'_>>) {
    loop {
        let phase = shared.phase.load(Ordering::Acquire);
        match phase {
            INGRESS_STARTING => {
                shared.startup_inflight.fetch_add(1, Ordering::AcqRel);
                if shared.phase.load(Ordering::Acquire) == INGRESS_STARTING {
                    return (phase, Some(StartupCallbackPermit { shared }));
                }
                shared.startup_inflight.fetch_sub(1, Ordering::AcqRel);
                shared.startup_notify.notify_one();
            }
            INGRESS_ACTIVATING => std::thread::yield_now(),
            _ => return (phase, None),
        }
    }
}

struct CallbackPayload<'a, F> {
    route: EvidenceRoute,
    expected_key: &'a str,
    received_key: String,
    payload_len: usize,
    materialize: F,
}

fn accept_payload<F>(
    shared: &Arc<SharedIngress>,
    callback: CallbackPayload<'_, F>,
    entered_phase: u8,
    _startup_permit: Option<StartupCallbackPermit<'_>>,
) where
    F: FnOnce() -> Vec<u8>,
{
    let CallbackPayload {
        route,
        expected_key,
        received_key,
        payload_len,
        materialize: materialize_payload,
    } = callback;
    // Capture startup/lifecycle state at callback entry. A callback that began
    // before both subscriptions were live must not be reclassified as epoch input
    // merely because it waited for the cross-route serialization lock.
    if entered_phase == INGRESS_CLOSED {
        return;
    }
    let mut state = lock_state(shared);
    if shared.phase.load(Ordering::Acquire) == INGRESS_CLOSED {
        return;
    }
    // Receipt is sampled only after both route callbacks enter the same critical
    // section, so channel order and assembler time order have one linearization.
    let received_at = Instant::now();
    state.note_received(route, payload_len, received_at);

    if state.health.first_fault.is_some() {
        increment(&mut state.health.post_fault_payloads);
        return;
    }

    if entered_phase != INGRESS_ACTIVE {
        increment(&mut state.health.payloads_rejected);
        let latched = state.latch_first(
            OperationalIngressFault::EvidenceBeforeReady {
                route,
                detected_at: received_at,
            }
            .into(),
        );
        drop(state);
        if latched {
            shared.terminal_notify.notify_one();
        }
        return;
    }

    let fault = if received_key != expected_key {
        Some(OperationalIngressFault::UnexpectedKey {
            route,
            expected: expected_key.to_owned(),
            received: received_key,
            detected_at: received_at,
        })
    } else {
        let maximum = route_payload_limit(route);
        (payload_len > maximum).then_some(OperationalIngressFault::PayloadTooLarge {
            route,
            actual: payload_len,
            maximum,
            detected_at: received_at,
        })
    };

    if let Some(fault) = fault {
        increment(&mut state.health.payloads_rejected);
        let latched = state.latch_first(fault.into());
        drop(state);
        if latched {
            shared.terminal_notify.notify_one();
        }
        return;
    }

    // Materialize exactly one application-owned copy only after provenance and
    // the route-specific size bound succeed. An inherited transport may have a
    // much larger allocation ceiling, so pre-checking `ZBytes::len` is mandatory.
    let payload = materialize_payload();
    debug_assert_eq!(payload.len(), payload_len);
    let ingress = RawIngress {
        route,
        payload,
        received_at,
    };
    match state.sender.try_send(ingress) {
        Ok(()) => state.note_enqueued(route),
        Err(mpsc::error::TrySendError::Full(_)) => {
            increment(&mut state.health.payloads_rejected);
            let capacity = state.capacity;
            let latched = state.latch_first(
                OperationalIngressFault::HandoffFull {
                    route,
                    capacity,
                    detected_at: received_at,
                }
                .into(),
            );
            drop(state);
            if latched {
                shared.terminal_notify.notify_one();
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            increment(&mut state.health.payloads_rejected);
            let latched = state.latch_first(
                OperationalIngressFault::HandoffClosed {
                    route,
                    detected_at: received_at,
                }
                .into(),
            );
            drop(state);
            if latched {
                shared.terminal_notify.notify_one();
            }
        }
    }
}

async fn subscribe_exact(
    bus: &ZenohBus,
    key: &str,
    route: EvidenceRoute,
    shared: Arc<SharedIngress>,
) -> Result<Subscriber<()>, ZenohError> {
    let selector = key.to_owned();
    let expected_key = selector.clone();
    bus.session()
        .declare_subscriber(selector)
        .callback(move |sample| {
            let (entered_phase, startup_permit) = enter_callback(&shared);
            if entered_phase == INGRESS_CLOSED {
                return;
            }
            let payload_len = sample.payload().len();
            accept_payload(
                &shared,
                CallbackPayload {
                    route,
                    expected_key: &expected_key,
                    received_key: sample.key_expr().as_str().to_owned(),
                    payload_len,
                    materialize: || sample.payload().to_bytes().to_vec(),
                },
                entered_phase,
                startup_permit,
            );
        })
        .await
        .map_err(|error| ZenohError(format!("declare operational {route:?} subscriber: {error}")))
}

/// Live, fail-stop receiver joining one exact observation/monitor producer epoch.
pub struct OperationalLiveReceiver<R> {
    observation_subscription: Option<Subscriber<()>>,
    monitor_subscription: Option<Subscriber<()>>,
    bus: ZenohBus,
    assembler: CrossRouteAssembler<R>,
    receiver: mpsc::Receiver<RawIngress>,
    shared: Arc<SharedIngress>,
    pending_events: VecDeque<AssemblyEvent>,
    config: OperationalLiveConfig,
    realm: String,
    session_id: String,
    producer_id: String,
    observation_key: String,
    monitor_key: String,
    transport_security: OperationalTransportSecurity,
    closed_at: Option<Instant>,
}

struct PreparedOperational<R> {
    assembler: CrossRouteAssembler<R>,
    realm: String,
    session_id: String,
    producer_id: String,
    observation_key: String,
    monitor_key: String,
}

impl<R: RegistryVerifier> OperationalLiveReceiver<R> {
    /// Open an owned Zenoh bus using its strict client configuration.
    ///
    /// `keys` fixes the realm. This constructor loads and validates the local
    /// secure client configuration once, then passes that same parsed value to
    /// Zenoh so a path replacement cannot swap the checked configuration before
    /// open. It does not prove remote router policy or end-to-end deployment
    /// security.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalLiveOpenError`] for transport setup, route construction,
    /// subscription declaration, or assembler-configuration failure.
    pub async fn open_secure(
        keys: Keys,
        session_id: impl Into<String>,
        producer_id: impl Into<String>,
        registry: R,
        assembler_limits: AssemblerLimits,
    ) -> Result<Self, OperationalLiveOpenError> {
        Self::open_secure_with_config(
            keys,
            session_id,
            producer_id,
            registry,
            assembler_limits,
            OperationalLiveConfig::default(),
        )
        .await
    }

    /// Open an owned secure bus with a caller-supplied ingress bound.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalLiveOpenError`] for transport setup, route construction,
    /// subscription declaration, or assembler-configuration failure.
    pub async fn open_secure_with_config(
        keys: Keys,
        session_id: impl Into<String>,
        producer_id: impl Into<String>,
        registry: R,
        assembler_limits: AssemblerLimits,
        config: OperationalLiveConfig,
    ) -> Result<Self, OperationalLiveOpenError> {
        let prepared = Self::prepare(
            &keys,
            session_id.into(),
            producer_id.into(),
            registry,
            assembler_limits,
        )?;
        let bus = crate::secure_live::open_secure_bus(keys).await?;
        Self::from_prepared(
            bus,
            prepared,
            config,
            OperationalTransportSecurity::OwnedSecureConfigValidated,
        )
        .await
    }

    /// Subscribe through a host-supplied shared bus.
    ///
    /// The realm is derived from `bus`; both exact subscriptions use that one bus.
    /// Transport authentication, encryption, ACLs, and bus lifecycle are inherited
    /// from the host and remain unverified by this integration seam.
    ///
    /// # Errors
    ///
    /// Returns [`OperationalLiveOpenError`] for route construction, subscription
    /// declaration, or assembler-configuration failure.
    pub async fn from_bus(
        bus: ZenohBus,
        session_id: impl Into<String>,
        producer_id: impl Into<String>,
        registry: R,
        assembler_limits: AssemblerLimits,
    ) -> Result<Self, OperationalLiveOpenError> {
        Self::from_bus_with_config(
            bus,
            session_id,
            producer_id,
            registry,
            assembler_limits,
            OperationalLiveConfig::default(),
        )
        .await
    }

    /// Subscribe through a host-supplied bus with a caller-supplied ingress bound.
    ///
    /// Security and lifecycle remain inherited and unverified; see [`Self::from_bus`].
    ///
    /// # Errors
    ///
    /// Returns [`OperationalLiveOpenError`] for route construction, subscription
    /// declaration, or assembler-configuration failure.
    pub async fn from_bus_with_config(
        bus: ZenohBus,
        session_id: impl Into<String>,
        producer_id: impl Into<String>,
        registry: R,
        assembler_limits: AssemblerLimits,
        config: OperationalLiveConfig,
    ) -> Result<Self, OperationalLiveOpenError> {
        Self::from_parts(
            bus,
            session_id.into(),
            producer_id.into(),
            registry,
            assembler_limits,
            config,
            OperationalTransportSecurity::InheritedUnverified,
        )
        .await
    }

    async fn from_parts(
        bus: ZenohBus,
        session_id: String,
        producer_id: String,
        registry: R,
        assembler_limits: AssemblerLimits,
        config: OperationalLiveConfig,
        transport_security: OperationalTransportSecurity,
    ) -> Result<Self, OperationalLiveOpenError> {
        let prepared = Self::prepare(
            bus.keys(),
            session_id,
            producer_id,
            registry,
            assembler_limits,
        )?;
        Self::from_prepared(bus, prepared, config, transport_security).await
    }

    fn prepare(
        keys: &Keys,
        session_id: String,
        producer_id: String,
        registry: R,
        assembler_limits: AssemblerLimits,
    ) -> Result<PreparedOperational<R>, OperationalLiveOpenError> {
        let observation_key = keys
            .try_sensor_named(&session_id, SIDECAR_SENSOR_NAME)
            .map_err(|error| OperationalLiveOpenError::Route(error.to_string()))?;
        let monitor_key = keys
            .try_sensor_named(&session_id, MONITOR_SENSOR_NAME)
            .map_err(|error| OperationalLiveOpenError::Route(error.to_string()))?;
        let realm = keys.realm().to_owned();
        let assembler = CrossRouteAssembler::new(
            session_id.clone(),
            producer_id.clone(),
            registry,
            assembler_limits,
            Instant::now(),
        )?;
        Ok(PreparedOperational {
            assembler,
            realm,
            session_id,
            producer_id,
            observation_key,
            monitor_key,
        })
    }

    async fn from_prepared(
        bus: ZenohBus,
        prepared: PreparedOperational<R>,
        config: OperationalLiveConfig,
        transport_security: OperationalTransportSecurity,
    ) -> Result<Self, OperationalLiveOpenError> {
        let PreparedOperational {
            mut assembler,
            realm,
            session_id,
            producer_id,
            observation_key,
            monitor_key,
        } = prepared;
        let (sender, receiver) = mpsc::channel(config.ingress_capacity);
        let shared = Arc::new(SharedIngress {
            state: Mutex::new(IngressState {
                sender,
                health: OperationalLiveHealthSnapshot::new(
                    transport_security,
                    config.ingress_capacity,
                ),
                capacity: config.ingress_capacity,
            }),
            terminal_notify: Notify::new(),
            startup_notify: Notify::new(),
            startup_inflight: AtomicUsize::new(0),
            phase: AtomicU8::new(INGRESS_STARTING),
        });

        // Keep the raw subscriber guards local until both declarations and the
        // assembler succeed. Every early-return path drops any completed guard, so
        // a shared host bus cannot retain an orphaned partial subscription.
        let observation_subscription = subscribe_exact(
            &bus,
            &observation_key,
            EvidenceRoute::Observation,
            shared.clone(),
        )
        .await?;
        let monitor_subscription =
            subscribe_exact(&bus, &monitor_key, EvidenceRoute::Monitor, shared.clone()).await?;
        let mut activation_guard = StartupActivationGuard::new(shared.clone());

        shared.phase.store(INGRESS_ACTIVATING, Ordering::Release);
        loop {
            let notified = shared.startup_notify.notified();
            if shared.startup_inflight.load(Ordering::Acquire) == 0 {
                break;
            }
            notified.await;
        }
        {
            let state = lock_state(&shared);
            if matches!(
                state.health.first_fault,
                Some(OperationalLiveFault::Ingress(
                    OperationalIngressFault::EvidenceBeforeReady { .. }
                ))
            ) {
                shared.phase.store(INGRESS_CLOSED, Ordering::Release);
                return Err(OperationalLiveOpenError::EvidenceBeforeReady);
            }
            // Anchor heartbeat and monotonic-order enforcement at the same
            // serialized boundary that first admits callback evidence.
            assembler.reanchor_initial_clock(Instant::now())?;
            shared.phase.store(INGRESS_ACTIVE, Ordering::Release);
        }
        activation_guard.disarm();

        Ok(Self {
            observation_subscription: Some(observation_subscription),
            monitor_subscription: Some(monitor_subscription),
            bus,
            assembler,
            receiver,
            shared,
            pending_events: VecDeque::new(),
            config,
            realm,
            session_id,
            producer_id,
            observation_key,
            monitor_key,
            transport_security,
            closed_at: None,
        })
    }

    /// Wait for the next nonterminal assembly event or the retained first fault.
    ///
    /// Calls after termination return the same fault. Events already queued at an
    /// ingress or assembler terminal boundary are discarded, so a `FrameReady`
    /// cannot cross that boundary.
    ///
    /// # Panics
    ///
    /// Panics if the current Tokio runtime has no time driver. Deadline
    /// enforcement depends on Tokio monotonic timers.
    pub async fn recv(&mut self) -> Result<AssemblyEvent, OperationalLiveFault> {
        // Give the bounded queue snapshot that existed at call entry priority
        // over already staged events. New arrivals cannot extend this budget, so
        // an authenticated producer cannot starve delivery indefinitely.
        let mut priority_ingress = {
            // Serialize the snapshot with callback admission. Payloads accepted
            // after this lock boundary belong to a later receive call.
            let _state = lock_state(&self.shared);
            self.receiver.len()
        };
        loop {
            if let Some(fault) = self.terminal_fault_and_discard() {
                return Err(fault);
            }
            if let Some(closed_at) = self.closed_at {
                return Err(OperationalLiveFault::Closed { closed_at });
            }

            let deadline = self.assembler.next_deadline_at();
            if let Some(deadline) = deadline.filter(|deadline| Instant::now() >= *deadline) {
                // Drain every receipt captured strictly before an already-due
                // boundary before expiring it. Staged events remain provisional
                // until this exact liveness boundary is resolved.
                if let Some(ingress) = self.ingress_at_deadline_boundary(deadline) {
                    self.process_ingress(ingress);
                } else {
                    let events = self.assembler.advance_time(deadline);
                    self.stage_assembly_events(events);
                }
                continue;
            }

            if priority_ingress > 0 {
                match self.receiver.try_recv() {
                    Ok(ingress) => {
                        priority_ingress -= 1;
                        self.process_ingress_or_expire(ingress, deadline);
                        continue;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => priority_ingress = 0,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.latch_receiver_fault(
                            OperationalIngressFault::IngressClosed {
                                detected_at: Instant::now(),
                            }
                            .into(),
                        );
                        continue;
                    }
                }
            }
            if let Some(event) = self.take_pending_event()? {
                return Ok(event);
            }

            let wake = if let Some(deadline) = deadline {
                let notified = self.shared.terminal_notify.notified();
                let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
                tokio::pin!(notified);
                tokio::pin!(sleep);
                tokio::select! {
                    biased;
                    () = &mut notified => ReceiverWake::Terminal,
                    ingress = self.receiver.recv() => ReceiverWake::Ingress {
                        ingress,
                        deadline: Some(deadline),
                    },
                    () = &mut sleep => ReceiverWake::Deadline(deadline),
                }
            } else {
                let notified = self.shared.terminal_notify.notified();
                tokio::pin!(notified);
                tokio::select! {
                    biased;
                    () = &mut notified => ReceiverWake::Terminal,
                    ingress = self.receiver.recv() => ReceiverWake::Ingress {
                        ingress,
                        deadline: None,
                    },
                }
            };

            match wake {
                ReceiverWake::Terminal => {}
                ReceiverWake::Ingress {
                    ingress: Some(ingress),
                    deadline,
                } => self.process_ingress_or_expire(ingress, deadline),
                ReceiverWake::Ingress { ingress: None, .. } => self.latch_receiver_fault(
                    OperationalIngressFault::IngressClosed {
                        detected_at: Instant::now(),
                    }
                    .into(),
                ),
                ReceiverWake::Deadline(deadline) => {
                    // Establish a boundary with both callbacks before expiring the
                    // exact assembler deadline. Only evidence captured strictly
                    // before the deadline is processed first; equality expires.
                    if let Some(ingress) = self.ingress_at_deadline_boundary(deadline) {
                        self.process_ingress(ingress);
                    } else {
                        let events = self.assembler.advance_time(deadline);
                        self.stage_assembly_events(events);
                    }
                }
            }
        }
    }

    fn process_ingress(&mut self, ingress: RawIngress) {
        let events = match ingress.route {
            EvidenceRoute::Observation => self
                .assembler
                .ingest_observation_bytes(&ingress.payload, ingress.received_at),
            EvidenceRoute::Monitor => self
                .assembler
                .ingest_monitor_bytes(&ingress.payload, ingress.received_at),
        };
        {
            let mut state = lock_state(&self.shared);
            increment(&mut state.health.payloads_processed);
        }
        self.stage_assembly_events(events);
    }

    fn process_ingress_or_expire(&mut self, ingress: RawIngress, deadline: Option<Instant>) {
        if let Some(deadline) = deadline {
            if !receipt_precedes_deadline(ingress.received_at, deadline) {
                self.note_dequeued_payload_discarded();
                let events = self.assembler.advance_time(deadline);
                self.stage_assembly_events(events);
                return;
            }
        }
        self.process_ingress(ingress);
    }

    fn ingress_at_deadline_boundary(&mut self, deadline: Instant) -> Option<RawIngress> {
        let mut state = lock_state(&self.shared);
        if state.health.first_fault.is_some() {
            return None;
        }
        match self.receiver.try_recv() {
            Ok(ingress) if receipt_precedes_deadline(ingress.received_at, deadline) => {
                Some(ingress)
            }
            Ok(_) => {
                increment(&mut state.health.queued_payloads_discarded);
                None
            }
            Err(mpsc::error::TryRecvError::Empty) => None,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                let latched = state.latch_first(
                    OperationalIngressFault::IngressClosed {
                        detected_at: Instant::now(),
                    }
                    .into(),
                );
                drop(state);
                if latched {
                    self.shared.terminal_notify.notify_one();
                }
                None
            }
        }
    }

    fn note_dequeued_payload_discarded(&self) {
        increment(&mut lock_state(&self.shared).health.queued_payloads_discarded);
    }

    fn stage_assembly_events(&mut self, events: Vec<AssemblyEvent>) {
        let assembly_fault = events.iter().find_map(|event| match event {
            AssemblyEvent::Fault(fault) => Some(fault.clone()),
            _ => None,
        });
        let mut state = lock_state(&self.shared);

        if assembly_fault.is_some() {
            increment(&mut state.health.assembly_faults_observed);
        }
        if state.health.first_fault.is_some() {
            state.health.assembly_events_discarded = state
                .health
                .assembly_events_discarded
                .saturating_add(usize_to_u64(events.len()));
            return;
        }
        if let Some(fault) = assembly_fault {
            let pending = self.pending_events.len();
            self.pending_events.clear();
            state.health.assembly_events_discarded = state
                .health
                .assembly_events_discarded
                .saturating_add(usize_to_u64(events.len().saturating_sub(1)))
                .saturating_add(usize_to_u64(pending));
            let latched = state.latch_first(OperationalLiveFault::Assembly(fault));
            drop(state);
            if latched {
                self.shared.terminal_notify.notify_one();
            }
            return;
        }

        state.health.assembly_events_staged = state
            .health
            .assembly_events_staged
            .saturating_add(usize_to_u64(events.len()));
        self.pending_events.extend(events);
    }

    fn take_pending_event(&mut self) -> Result<Option<AssemblyEvent>, OperationalLiveFault> {
        let mut state = lock_state(&self.shared);
        if let Some(fault) = &state.health.first_fault {
            return Err(fault.clone());
        }
        let Some(event) = self.pending_events.pop_front() else {
            return Ok(None);
        };
        increment(&mut state.health.assembly_events_delivered);
        match &event {
            AssemblyEvent::FrameReady(_) => increment(&mut state.health.frames_delivered),
            AssemblyEvent::ContractHashMismatch { .. } => {
                increment(&mut state.health.contract_advisories_delivered);
            }
            AssemblyEvent::HeartbeatAccepted { .. } => {
                increment(&mut state.health.heartbeats_delivered);
            }
            AssemblyEvent::Fault(_) => {
                // Fault events are lifted into `OperationalLiveFault` transactionally.
            }
        }
        Ok(Some(event))
    }

    fn terminal_fault_and_discard(&mut self) -> Option<OperationalLiveFault> {
        let mut state = lock_state(&self.shared);
        let fault = state.health.first_fault.clone()?;
        let pending = self.pending_events.len();
        self.pending_events.clear();
        let mut queued = 0_u64;
        while self.receiver.try_recv().is_ok() {
            queued = queued.saturating_add(1);
        }
        state.health.queued_payloads_discarded = state
            .health
            .queued_payloads_discarded
            .saturating_add(queued);
        state.health.assembly_events_discarded = state
            .health
            .assembly_events_discarded
            .saturating_add(usize_to_u64(pending));
        Some(fault)
    }

    fn discard_buffered_for_close(&mut self) {
        // Serialize with any callback that crossed the phase check just before
        // close. Once this lock is held, CLOSED prevents every later callback from
        // enqueueing, so the drain is a complete lifecycle boundary.
        let mut state = lock_state(&self.shared);
        let pending = self.pending_events.len();
        self.pending_events.clear();
        let mut queued = 0_u64;
        while self.receiver.try_recv().is_ok() {
            queued = queued.saturating_add(1);
        }
        state.health.queued_payloads_discarded = state
            .health
            .queued_payloads_discarded
            .saturating_add(queued);
        state.health.assembly_events_discarded = state
            .health
            .assembly_events_discarded
            .saturating_add(usize_to_u64(pending));
    }

    fn latch_receiver_fault(&self, fault: OperationalLiveFault) {
        let mut state = lock_state(&self.shared);
        let latched = state.latch_first(fault);
        drop(state);
        if latched {
            self.shared.terminal_notify.notify_one();
        }
    }

    /// Clone a read-only health handle.
    pub fn health(&self) -> OperationalLiveHealth {
        OperationalLiveHealth {
            shared: self.shared.clone(),
        }
    }

    /// Borrow the owned assembler for bounded-state diagnostics.
    pub fn assembler(&self) -> &CrossRouteAssembler<R> {
        &self.assembler
    }

    /// Raw-ingress configuration used by this receiver.
    pub fn config(&self) -> OperationalLiveConfig {
        self.config
    }

    /// Realm derived from the owned or shared bus.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Exact producer epoch path segment.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Producer identity enforced by the assembler.
    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    /// Exact raw observation-route subscription key.
    pub fn observation_key(&self) -> &str {
        &self.observation_key
    }

    /// Exact raw monitor-route subscription key.
    pub fn monitor_key(&self) -> &str {
        &self.monitor_key
    }

    /// Security posture established by the selected constructor.
    pub fn transport_security(&self) -> OperationalTransportSecurity {
        self.transport_security
    }

    /// Idempotently undeclare only this receiver's two exact subscriptions.
    ///
    /// A bus supplied through [`Self::from_bus`] remains open for its host. A bus
    /// opened through [`Self::open_secure`] is also closed after both selectors are
    /// undeclared. Dropping the receiver without calling this method still drops the
    /// two scoped subscriber guards, but cannot report undeclaration errors.
    ///
    /// # Errors
    ///
    /// Returns the first Zenoh undeclaration or owned-session close error after
    /// attempting all lifecycle cleanup.
    pub async fn close(&mut self) -> Result<(), ZenohError> {
        if self.closed_at.is_some() {
            return Ok(());
        }
        self.closed_at = Some(Instant::now());
        self.shared.phase.store(INGRESS_CLOSED, Ordering::Release);
        let mut first_error = None;

        if let Some(subscription) = self.observation_subscription.take() {
            if let Err(error) = subscription.undeclare().await {
                first_error = Some(ZenohError(format!(
                    "undeclare operational observation subscriber: {error}"
                )));
            }
        }
        if let Some(subscription) = self.monitor_subscription.take() {
            if let Err(error) = subscription.undeclare().await {
                first_error.get_or_insert_with(|| {
                    ZenohError(format!("undeclare operational monitor subscriber: {error}"))
                });
            }
        }
        if self.transport_security == OperationalTransportSecurity::OwnedSecureConfigValidated {
            if let Err(error) = self.bus.close().await {
                first_error.get_or_insert(error);
            }
        }
        self.discard_buffered_for_close();

        first_error.map_or(Ok(()), Err)
    }

    /// Borrow the shared Zenoh bus.
    ///
    /// For [`Self::from_bus`], the host retains transport-security and lifecycle
    /// responsibility. Closing this handle would close the host's shared session.
    pub fn bus(&self) -> &ZenohBus {
        &self.bus
    }
}

impl<R> Drop for OperationalLiveReceiver<R> {
    fn drop(&mut self) {
        self.shared.phase.store(INGRESS_CLOSED, Ordering::Release);
    }
}

enum ReceiverWake {
    Terminal,
    Ingress {
        ingress: Option<RawIngress>,
        deadline: Option<Instant>,
    },
    Deadline(Instant),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::{mpsc, Notify};

    use super::{
        accept_payload, lock_state, receipt_precedes_deadline, CallbackPayload, IngressState,
        OperationalLiveConfig, OperationalLiveHealthSnapshot, OperationalTransportSecurity,
        SharedIngress, INGRESS_ACTIVE, INGRESS_CLOSED,
    };
    use crate::assembler::EvidenceRoute;

    #[test]
    fn receipt_strictly_before_deadline_is_admissible() {
        let start = std::time::Instant::now();
        assert!(receipt_precedes_deadline(
            start + Duration::from_millis(9),
            start + Duration::from_millis(10),
        ));
    }

    #[test]
    fn receipt_equal_to_deadline_is_not_admissible() {
        let deadline = std::time::Instant::now();
        assert!(!receipt_precedes_deadline(deadline, deadline));
    }

    #[test]
    fn receipt_after_deadline_is_not_admissible() {
        let start = std::time::Instant::now();
        assert!(!receipt_precedes_deadline(
            start + Duration::from_millis(11),
            start + Duration::from_millis(10),
        ));
    }

    #[test]
    fn callback_waiting_for_ingress_lock_cannot_enqueue_after_close() {
        let config = OperationalLiveConfig::new(1).expect("test capacity is valid");
        let (sender, mut receiver) = mpsc::channel(config.ingress_capacity());
        let shared = Arc::new(SharedIngress {
            state: Mutex::new(IngressState {
                sender,
                health: OperationalLiveHealthSnapshot::new(
                    OperationalTransportSecurity::InheritedUnverified,
                    config.ingress_capacity(),
                ),
                capacity: config.ingress_capacity(),
            }),
            terminal_notify: Notify::new(),
            startup_notify: Notify::new(),
            startup_inflight: AtomicUsize::new(0),
            phase: AtomicU8::new(INGRESS_ACTIVE),
        });
        let state_guard = lock_state(&shared);
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let callback_shared = shared.clone();
        let callback = std::thread::spawn(move || {
            started_sender.send(()).expect("signal callback entry");
            accept_payload(
                &callback_shared,
                CallbackPayload {
                    route: EvidenceRoute::Observation,
                    expected_key: "expected/key",
                    received_key: "expected/key".to_owned(),
                    payload_len: 2,
                    materialize: || b"{}".to_vec(),
                },
                INGRESS_ACTIVE,
                None,
            );
        });
        started_receiver.recv().expect("callback began");
        shared.phase.store(INGRESS_CLOSED, Ordering::Release);
        drop(state_guard);
        callback.join().expect("callback exits after close");

        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(lock_state(&shared).health.observation_payloads_received, 0);
    }

    #[test]
    fn oversized_callback_faults_before_materializing_an_application_copy() {
        let config = OperationalLiveConfig::new(1).expect("test capacity is valid");
        let (sender, _receiver) = mpsc::channel(config.ingress_capacity());
        let shared = Arc::new(SharedIngress {
            state: Mutex::new(IngressState {
                sender,
                health: OperationalLiveHealthSnapshot::new(
                    OperationalTransportSecurity::InheritedUnverified,
                    config.ingress_capacity(),
                ),
                capacity: config.ingress_capacity(),
            }),
            terminal_notify: Notify::new(),
            startup_notify: Notify::new(),
            startup_inflight: AtomicUsize::new(0),
            phase: AtomicU8::new(INGRESS_ACTIVE),
        });
        let materialized = Arc::new(AtomicBool::new(false));
        let materialized_by_callback = materialized.clone();

        accept_payload(
            &shared,
            CallbackPayload {
                route: EvidenceRoute::Observation,
                expected_key: "expected/key",
                received_key: "expected/key".to_owned(),
                payload_len: crate::assembler::MAX_ASSEMBLER_SIDECAR_BYTES + 1,
                materialize: move || {
                    materialized_by_callback.store(true, Ordering::Relaxed);
                    Vec::new()
                },
            },
            INGRESS_ACTIVE,
            None,
        );

        assert!(!materialized.load(Ordering::Relaxed));
        assert!(matches!(
            lock_state(&shared).health.first_fault,
            Some(super::OperationalLiveFault::Ingress(
                super::OperationalIngressFault::PayloadTooLarge { .. }
            ))
        ));
    }
}
