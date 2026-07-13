#![forbid(unsafe_code)]
#![cfg(feature = "zenoh")]
//! In-process coverage for the bounded cross-route operational receiver.
//!
//! These tests deliberately use a quiet, discovery-disabled loopback session.
//! That makes transport local and deterministic; it is not a secure-deployment test.

use std::time::Duration;

use galadriel_core::observation::{ConsistencyProjection, Modality, PidObservation};
use galadriel_ncp::assembler::{
    AssemblerLimits, AssemblyEvent, AssemblyFaultKind, EvidenceRoute, FrameIdentity,
    RegistryOpportunityPolicy, RegistryVerifier, RegistryViolation,
};
use galadriel_ncp::monitor::{
    FrameSummary, GateEvidence, GateMethod, ModalityOutcome, ModalityOutcomeKind, MonitorEnvelope,
    ProducerEvent, MONITOR_SENSOR_NAME,
};
use galadriel_ncp::operational_live::{
    OperationalIngressFault, OperationalLiveConfig, OperationalLiveFault, OperationalLiveHealth,
    OperationalLiveReceiver, OperationalTransportSecurity,
};
use galadriel_ncp::{SidecarEnvelope, SIDECAR_SENSOR_NAME};
use ncp_core::Keys;
use ncp_zenoh::{Plane, ZenohBus, ZenohConfig};
use tokio::time::{sleep, timeout};

const REALM: &str = "engram/ncp";
const SESSION_ID: &str = "crebain-epoch-1";
const PRODUCER_ID: &str = "crebain";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy)]
struct TestRegistry;

impl RegistryVerifier for TestRegistry {
    fn opportunity_policy(&self) -> Result<RegistryOpportunityPolicy, RegistryViolation> {
        Ok(RegistryOpportunityPolicy {
            max_active_tracks: 32,
            max_frame_inputs: 128,
            max_attempts_per_track_modality: 128,
            max_outcomes_per_frame: 128,
            max_monitor_queue_events: 128,
        })
    }

    fn verify_summary(
        &self,
        identity: FrameIdentity,
        registry_digest: &str,
        expected_modalities: &[Modality],
    ) -> Result<(), RegistryViolation> {
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
        if registry_digest != DIGEST {
            return Err(RegistryViolation::DigestMismatch);
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

fn quiet_loopback_config_for_tests() -> ZenohConfig {
    let mut config = ZenohConfig::default();
    for (path, value) in [
        ("scouting/multicast/enabled", "false"),
        ("scouting/gossip/enabled", "false"),
        ("transport/shared_memory/enabled", "false"),
    ] {
        config
            .insert_json5(path, value)
            .unwrap_or_else(|error| panic!("quiet test transport {path}: {error}"));
    }
    config
}

async fn quiet_loopback_bus_for_tests() -> ZenohBus {
    let keys = Keys::try_new(REALM).expect("test realm is valid");
    ZenohBus::with_config(quiet_loopback_config_for_tests(), keys)
        .await
        .expect("open quiet in-process Zenoh session")
}

fn limits(heartbeat_interval: Duration, heartbeat_deadline: Duration) -> AssemblerLimits {
    AssemblerLimits {
        frame_deadline: Duration::from_secs(2),
        reorder_deadline: Duration::from_millis(250),
        heartbeat_interval,
        heartbeat_deadline,
        initial_heartbeat_deadline: heartbeat_deadline,
        ..AssemblerLimits::default()
    }
}

async fn receiver_with(
    capacity: usize,
    heartbeat_interval: Duration,
    heartbeat_deadline: Duration,
) -> (ZenohBus, OperationalLiveReceiver<TestRegistry>) {
    let bus = quiet_loopback_bus_for_tests().await;
    let publisher = bus.clone();
    let receiver = OperationalLiveReceiver::from_bus_with_config(
        bus,
        SESSION_ID,
        PRODUCER_ID,
        TestRegistry,
        limits(heartbeat_interval, heartbeat_deadline),
        OperationalLiveConfig::new(capacity).expect("test ingress capacity is valid"),
    )
    .await
    .expect("subscribe operational receiver");
    (publisher, receiver)
}

fn projection(prior_id: u64) -> ConsistencyProjection {
    ConsistencyProjection {
        values: [1.0, 2.0, 3.0],
        dimensions: 3,
        frame_id: 10,
        context_id: 20,
        prior_id,
    }
}

fn observation(fusion_seq: u64, prior_id: u64) -> PidObservation {
    PidObservation {
        track_id: 7,
        timestamp_ms: 1_000 + fusion_seq,
        seq: fusion_seq,
        modality: Modality::Visual,
        nis: 1.0,
        dof: 3,
        innovation: None,
        innovation_cov: None,
        consistency_projection: Some(projection(prior_id)),
    }
}

fn outcome(fusion_seq: u64, prior_id: u64) -> ModalityOutcome {
    ModalityOutcome {
        fusion_seq,
        fusion_timestamp_ms: 1_000 + fusion_seq,
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

fn summary(fusion_seq: u64, prior_id: u64) -> FrameSummary {
    FrameSummary {
        fusion_seq,
        fusion_timestamp_ms: 1_000 + fusion_seq,
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

fn observation_bytes(producer_id: &str, fusion_seq: u64, prior_id: u64) -> Vec<u8> {
    serde_json::to_vec(
        &SidecarEnvelope::try_new(SESSION_ID, producer_id, observation(fusion_seq, prior_id))
            .expect("test sidecar envelope is valid"),
    )
    .expect("test sidecar envelope encodes")
}

fn monitor_bytes(event_seq: u64, event: ProducerEvent) -> Vec<u8> {
    MonitorEnvelope::try_new(SESSION_ID, PRODUCER_ID, event_seq, event)
        .and_then(|envelope| envelope.encode())
        .expect("test monitor envelope is valid")
}

fn monitor_contract_mismatch_bytes(event_seq: u64, event: ProducerEvent) -> Vec<u8> {
    let mut envelope = MonitorEnvelope::try_new(SESSION_ID, PRODUCER_ID, event_seq, event)
        .expect("test monitor envelope is valid");
    envelope.contract_hash = "deadbeefdeadbeef".to_owned();
    envelope
        .encode()
        .expect("contract mismatch is an advisory, not an encoding failure")
}

async fn publish(bus: &ZenohBus, key: &str, payload: &[u8]) {
    bus.put(key, payload, Plane::Perception)
        .await
        .expect("publish raw named-sensor payload")
}

async fn wait_for_fault(health: &OperationalLiveHealth) -> OperationalLiveFault {
    timeout(TEST_TIMEOUT, async {
        loop {
            if let Some(fault) = health.first_fault() {
                return fault;
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("terminal fault arrives")
}

async fn wait_for_post_fault_payload(health: &OperationalLiveHealth) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if health.snapshot().post_fault_payloads > 0 {
                return;
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("post-fault callback is counted")
}

async fn wait_for_observation_enqueued(health: &OperationalLiveHealth, expected: u64) {
    timeout(TEST_TIMEOUT, async {
        loop {
            if health.snapshot().observation_payloads_enqueued >= expected {
                return;
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("observation payload reaches bounded ingress")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observation_and_monitor_routes_assemble_one_ready_frame() {
    let (publisher, mut receiver) =
        receiver_with(8, Duration::from_secs(1), Duration::from_secs(4)).await;
    let observation_key = receiver.observation_key().to_owned();
    let monitor_key = receiver.monitor_key().to_owned();

    publish(
        &publisher,
        &observation_key,
        &observation_bytes(PRODUCER_ID, 1, 101),
    )
    .await;
    publish(
        &publisher,
        &monitor_key,
        &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
    )
    .await;
    publish(
        &publisher,
        &monitor_key,
        &monitor_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
    )
    .await;

    let event = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("assembly completes before timeout")
        .expect("epoch remains healthy");
    let AssemblyEvent::FrameReady(frame) = event else {
        panic!("expected FrameReady")
    };
    assert_eq!(
        (
            frame.identity().fusion_seq,
            frame.monitor_events().len(),
            frame.observations().len(),
            receiver.health().snapshot().frames_delivered,
        ),
        (1, 1, 1, 1)
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_silence_expires_the_exact_assembler_heartbeat_deadline() {
    let (publisher, mut receiver) =
        receiver_with(4, Duration::from_millis(20), Duration::from_millis(40)).await;

    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("silence deadline is bounded")
        .expect_err("all-silence epoch must fail closed");
    assert!(matches!(
        fault,
        OperationalLiveFault::Assembly(galadriel_ncp::assembler::AssemblyFault {
            kind: AssemblyFaultKind::HeartbeatDeadlineExpired,
            ..
        })
    ));

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_deadline_ingress_expires_at_exact_deadline_before_decode() {
    let (publisher, mut receiver) =
        receiver_with(4, Duration::from_millis(20), Duration::from_millis(40)).await;
    let health = receiver.health();
    let key = receiver.observation_key().to_owned();
    let deadline = receiver
        .assembler()
        .next_deadline_at()
        .expect("healthy receiver has a heartbeat deadline");
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        deadline + Duration::from_millis(10),
    ))
    .await;
    publish(&publisher, &key, b"{").await;
    wait_for_observation_enqueued(&health, 1).await;

    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("late ingress is ordered against the deadline")
        .expect_err("deadline wins before late payload decoding");
    let snapshot = health.snapshot();
    assert!(matches!(
        fault,
        OperationalLiveFault::Assembly(galadriel_ncp::assembler::AssemblyFault {
            kind: AssemblyFaultKind::HeartbeatDeadlineExpired,
            detected_at,
            ..
        }) if detected_at == deadline
    ));
    assert_eq!(
        (
            snapshot.payloads_processed,
            snapshot.queued_payloads_discarded,
            snapshot.ingress_queue_depth,
        ),
        (0, 1, 0)
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_queue_latches_first_fault_and_blocks_previously_queued_delivery() {
    let (publisher, mut receiver) =
        receiver_with(1, Duration::from_secs(1), Duration::from_secs(4)).await;
    let health = receiver.health();
    let key = receiver.observation_key().to_owned();

    publish(&publisher, &key, b"{}").await;
    publish(&publisher, &key, b"{}").await;
    let first_fault = wait_for_fault(&health).await;
    publish(&publisher, &key, b"{}").await;
    wait_for_post_fault_payload(&health).await;

    let returned = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("receiver observes out-of-band terminal wake")
        .expect_err("queued payload cannot cross the terminal boundary");
    let snapshot = health.snapshot();
    assert!(matches!(
        (&first_fault, &returned),
        (
            OperationalLiveFault::Ingress(OperationalIngressFault::HandoffFull {
                route: EvidenceRoute::Observation,
                capacity: 1,
                ..
            }),
            OperationalLiveFault::Ingress(OperationalIngressFault::HandoffFull {
                route: EvidenceRoute::Observation,
                capacity: 1,
                ..
            })
        )
    ));
    assert_eq!(
        (
            snapshot.observation_payloads_enqueued,
            snapshot.payloads_rejected,
            snapshot.post_fault_payloads,
            snapshot.queued_payloads_discarded,
            snapshot.assembly_events_delivered,
        ),
        (1, 1, 1, 1, 0)
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_producer_is_rejected_by_the_cross_route_assembler() {
    let (publisher, mut receiver) =
        receiver_with(4, Duration::from_secs(1), Duration::from_secs(4)).await;
    let key = receiver.observation_key().to_owned();
    publish(
        &publisher,
        &key,
        &observation_bytes("other-producer", 1, 101),
    )
    .await;

    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("wrong provenance is processed")
        .expect_err("wrong producer terminates the epoch");
    assert!(matches!(
        fault,
        OperationalLiveFault::Assembly(galadriel_ncp::assembler::AssemblyFault {
            kind: AssemblyFaultKind::ProvenanceMismatch {
                route: EvidenceRoute::Observation
            },
            ..
        })
    ));

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_epoch_is_rejected_by_the_cross_route_assembler() {
    let (publisher, mut receiver) =
        receiver_with(4, Duration::from_secs(1), Duration::from_secs(4)).await;
    let key = receiver.observation_key().to_owned();
    let bytes = serde_json::to_vec(
        &SidecarEnvelope::try_new("different-epoch", PRODUCER_ID, observation(1, 101))
            .expect("wrong-epoch envelope is otherwise valid"),
    )
    .expect("wrong-epoch envelope encodes");
    publish(&publisher, &key, &bytes).await;

    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("wrong epoch is processed")
        .expect_err("wrong epoch terminates the receiver");
    assert!(matches!(
        fault,
        OperationalLiveFault::Assembly(galadriel_ncp::assembler::AssemblyFault {
            kind: AssemblyFaultKind::ProvenanceMismatch {
                route: EvidenceRoute::Observation
            },
            ..
        })
    ));

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_raw_payload_latches_the_assembler_decode_fault() {
    let (publisher, mut receiver) =
        receiver_with(4, Duration::from_secs(1), Duration::from_secs(4)).await;
    let key = receiver.observation_key().to_owned();
    publish(&publisher, &key, b"{").await;

    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("malformed payload is processed")
        .expect_err("decode failure terminates the epoch");
    assert!(matches!(
        fault,
        OperationalLiveFault::Assembly(galadriel_ncp::assembler::AssemblyFault {
            kind: AssemblyFaultKind::MalformedPayload {
                route: EvidenceRoute::Observation
            },
            ..
        })
    ));

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_payload_faults_before_the_bounded_handoff() {
    let (publisher, mut receiver) =
        receiver_with(4, Duration::from_secs(1), Duration::from_secs(4)).await;
    let key = receiver.monitor_key().to_owned();
    let oversized = vec![b'x'; galadriel_ncp::monitor::MAX_MONITOR_EVENT_BYTES + 1];
    publish(&publisher, &key, &oversized).await;

    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("oversize callback wakes receiver")
        .expect_err("oversize payload terminates the epoch");
    let snapshot = receiver.health().snapshot();
    assert!(matches!(
        fault,
        OperationalLiveFault::Ingress(OperationalIngressFault::PayloadTooLarge {
            route: EvidenceRoute::Monitor,
            ..
        })
    ));
    assert_eq!(
        (
            snapshot.monitor_payloads_received,
            snapshot.monitor_payloads_enqueued,
            snapshot.payloads_rejected,
        ),
        (1, 0, 1)
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_frame_ready_is_discarded_when_ingress_faults() {
    let (publisher, mut receiver) =
        receiver_with(8, Duration::from_secs(1), Duration::from_secs(4)).await;
    let observation_key = receiver.observation_key().to_owned();
    let monitor_key = receiver.monitor_key().to_owned();

    publish(
        &publisher,
        &observation_key,
        &observation_bytes(PRODUCER_ID, 1, 101),
    )
    .await;
    publish(
        &publisher,
        &monitor_key,
        &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
    )
    .await;
    publish(
        &publisher,
        &monitor_key,
        &monitor_contract_mismatch_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
    )
    .await;

    let advisory = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("advisory arrives")
        .expect("advisory is nonterminal");
    assert!(matches!(
        advisory,
        AssemblyEvent::ContractHashMismatch {
            route: EvidenceRoute::Monitor
        }
    ));

    let oversized = vec![b'x'; galadriel_ncp::assembler::MAX_ASSEMBLER_SIDECAR_BYTES + 1];
    publish(&publisher, &observation_key, &oversized).await;
    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("terminal callback wakes receiver")
        .expect_err("pending frame cannot cross ingress terminal boundary");
    let snapshot = receiver.health().snapshot();
    assert!(matches!(
        fault,
        OperationalLiveFault::Ingress(OperationalIngressFault::PayloadTooLarge {
            route: EvidenceRoute::Observation,
            ..
        })
    ));
    assert_eq!(
        (
            snapshot.frames_delivered,
            snapshot.assembly_events_discarded,
            snapshot.terminal_faults,
        ),
        (0, 1, 1)
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_decode_fault_preempts_a_pending_frame_ready() {
    let (publisher, mut receiver) =
        receiver_with(8, Duration::from_secs(1), Duration::from_secs(4)).await;
    let health = receiver.health();
    let observation_key = receiver.observation_key().to_owned();
    let monitor_key = receiver.monitor_key().to_owned();

    publish(
        &publisher,
        &observation_key,
        &observation_bytes(PRODUCER_ID, 1, 101),
    )
    .await;
    publish(
        &publisher,
        &monitor_key,
        &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
    )
    .await;
    publish(
        &publisher,
        &monitor_key,
        &monitor_contract_mismatch_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
    )
    .await;
    assert!(matches!(
        timeout(TEST_TIMEOUT, receiver.recv())
            .await
            .expect("advisory arrives")
            .expect("advisory is nonterminal"),
        AssemblyEvent::ContractHashMismatch { .. }
    ));

    publish(&publisher, &observation_key, b"{").await;
    wait_for_observation_enqueued(&health, 2).await;
    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("queued decode is serviced")
        .expect_err("decode fault preempts pending frame delivery");
    let snapshot = health.snapshot();
    assert!(matches!(
        fault,
        OperationalLiveFault::Assembly(galadriel_ncp::assembler::AssemblyFault {
            kind: AssemblyFaultKind::MalformedPayload {
                route: EvidenceRoute::Observation
            },
            ..
        })
    ));
    assert_eq!(
        (
            snapshot.frames_delivered,
            snapshot.assembly_events_discarded
        ),
        (0, 1)
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn due_heartbeat_deadline_preempts_a_pending_frame_ready() {
    let (publisher, mut receiver) =
        receiver_with(8, Duration::from_millis(50), Duration::from_millis(200)).await;
    let observation_key = receiver.observation_key().to_owned();
    let monitor_key = receiver.monitor_key().to_owned();

    publish(
        &publisher,
        &observation_key,
        &observation_bytes(PRODUCER_ID, 1, 101),
    )
    .await;
    publish(
        &publisher,
        &monitor_key,
        &monitor_bytes(1, ProducerEvent::ModalityOutcome(outcome(1, 101))),
    )
    .await;
    publish(
        &publisher,
        &monitor_key,
        &monitor_contract_mismatch_bytes(2, ProducerEvent::FrameSummary(summary(1, 101))),
    )
    .await;
    assert!(matches!(
        timeout(TEST_TIMEOUT, receiver.recv())
            .await
            .expect("advisory arrives")
            .expect("advisory is nonterminal"),
        AssemblyEvent::ContractHashMismatch { .. }
    ));

    let deadline = receiver
        .assembler()
        .next_deadline_at()
        .expect("healthy receiver has a deadline");
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        deadline + Duration::from_millis(10),
    ))
    .await;
    let fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("due deadline is serviced")
        .expect_err("deadline fault preempts pending frame delivery");
    let snapshot = receiver.health().snapshot();
    assert!(matches!(
        fault,
        OperationalLiveFault::Assembly(galadriel_ncp::assembler::AssemblyFault {
            kind: AssemblyFaultKind::HeartbeatDeadlineExpired,
            ..
        })
    ));
    assert_eq!(
        (
            snapshot.frames_delivered,
            snapshot.assembly_events_discarded
        ),
        (0, 1)
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriptions_use_only_the_two_exact_named_sensor_keys() {
    let (publisher, receiver) =
        receiver_with(4, Duration::from_secs(1), Duration::from_secs(4)).await;
    let wrong_key = publisher
        .keys()
        .try_sensor_named(SESSION_ID, "galadriel-pid-shadow")
        .expect("adjacent test key is valid");
    publish(&publisher, &wrong_key, b"{}").await;
    sleep(Duration::from_millis(50)).await;

    let snapshot = receiver.health().snapshot();
    assert_eq!(
        (
            receiver.observation_key(),
            receiver.monitor_key(),
            receiver.transport_security(),
            snapshot.observation_payloads_received,
            snapshot.monitor_payloads_received,
        ),
        (
            format!("{REALM}/session/{SESSION_ID}/sensor/{SIDECAR_SENSOR_NAME}").as_str(),
            format!("{REALM}/session/{SESSION_ID}/sensor/{MONITOR_SENSOR_NAME}").as_str(),
            OperationalTransportSecurity::InheritedUnverified,
            0,
            0,
        )
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_configured_capacity_and_current_queue_depth() {
    let (publisher, mut receiver) =
        receiver_with(2, Duration::from_secs(1), Duration::from_secs(4)).await;
    let health = receiver.health();
    let key = receiver.observation_key().to_owned();

    publish(&publisher, &key, b"{}").await;
    wait_for_observation_enqueued(&health, 1).await;
    let queued = health.snapshot();
    assert_eq!(
        (queued.ingress_capacity, queued.ingress_queue_depth),
        (2, 1)
    );

    let _ = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("queued payload is processed")
        .expect_err("minimal object is not a sidecar envelope");
    assert_eq!(health.snapshot().ingress_queue_depth, 0);

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_receiver_undeclares_only_its_scoped_subscriptions() {
    let (publisher, receiver) =
        receiver_with(4, Duration::from_secs(1), Duration::from_secs(4)).await;
    let health = receiver.health();
    let observation_key = receiver.observation_key().to_owned();
    let monitor_key = receiver.monitor_key().to_owned();
    drop(receiver);

    publish(&publisher, &observation_key, b"{}").await;
    publish(&publisher, &monitor_key, b"{}").await;
    sleep(Duration::from_millis(50)).await;

    let snapshot = health.snapshot();
    assert_eq!(
        (
            snapshot.observation_payloads_received,
            snapshot.monitor_payloads_received,
            snapshot.ingress_queue_depth,
        ),
        (0, 0, 0)
    );

    publisher.close().await.expect("close quiet test session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_close_undeclares_receivers_but_keeps_inherited_bus_open() {
    let (publisher, mut receiver) =
        receiver_with(4, Duration::from_secs(1), Duration::from_secs(4)).await;
    let health = receiver.health();
    let observation_key = receiver.observation_key().to_owned();
    let monitor_key = receiver.monitor_key().to_owned();
    publish(&publisher, &observation_key, b"{}").await;
    wait_for_observation_enqueued(&health, 1).await;
    receiver
        .close()
        .await
        .expect("undeclare exact subscriptions");
    receiver.close().await.expect("second close is a no-op");
    let closed_fault = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .expect("closed receiver responds immediately")
        .expect_err("closed receiver cannot deliver assembly events");
    assert!(matches!(closed_fault, OperationalLiveFault::Closed { .. }));

    publish(&publisher, &observation_key, b"{}").await;
    publish(&publisher, &monitor_key, b"{}").await;
    sleep(Duration::from_millis(50)).await;

    let snapshot = health.snapshot();
    assert_eq!(
        (
            snapshot.observation_payloads_received,
            snapshot.monitor_payloads_received,
            snapshot.ingress_queue_depth,
            snapshot.queued_payloads_discarded,
            snapshot.terminal_faults,
            snapshot.first_fault,
        ),
        (1, 0, 0, 1, 0, None)
    );

    publisher.close().await.expect("close quiet test session");
}
