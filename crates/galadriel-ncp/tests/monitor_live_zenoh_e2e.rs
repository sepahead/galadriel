#![forbid(unsafe_code)]
#![cfg(feature = "zenoh")]
//! In-process Zenoh coverage for bounded producer-monitor ingress.

use std::time::Duration;

use galadriel_ncp::monitor::{Heartbeat, MonitorEnvelope, ProducerEvent, QueueHealth};
use galadriel_ncp::monitor_live::{
    MonitorIngressFault, MonitorIngressFaultKind, MonitorLiveConfig, MonitorSubscriptionHealth,
    MonitorTap,
};
use ncp_core::keys::Keys;
use ncp_zenoh::{Plane, ZenohBus, ZenohConfig};
use tokio::time::{timeout, Instant};

const REALM: &str = "engram/ncp";
const SESSION_ID: &str = "crebain-epoch-1";
const PRODUCER_ID: &str = "crebain";
const DEADLINE: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

fn loopback_config() -> ZenohConfig {
    let mut config = ZenohConfig::default();
    for (path, value) in [
        ("scouting/multicast/enabled", "false"),
        ("scouting/gossip/enabled", "false"),
        ("transport/shared_memory/enabled", "false"),
    ] {
        config
            .insert_json5(path, value)
            .unwrap_or_else(|error| panic!("loopback config {path}: {error}"));
    }
    config
}

async fn loopback_bus() -> ZenohBus {
    let keys = Keys::try_new(REALM).expect("test realm is valid");
    ZenohBus::with_config(loopback_config(), keys)
        .await
        .expect("open hermetic Zenoh session")
}

fn envelope(event_seq: u64) -> MonitorEnvelope {
    MonitorEnvelope::try_new(
        SESSION_ID,
        PRODUCER_ID,
        event_seq,
        ProducerEvent::Heartbeat(Heartbeat {
            producer_timestamp_ms: 1_000 + event_seq,
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
}

fn encoded(event_seq: u64) -> Vec<u8> {
    envelope(event_seq)
        .encode()
        .expect("test monitor envelope encodes")
}

async fn publish(bus: &ZenohBus, bytes: &[u8]) {
    let key =
        galadriel_ncp::monitor::monitor_key(REALM, SESSION_ID).expect("test monitor key is valid");
    bus.put(&key, bytes, Plane::Perception)
        .await
        .expect("publish monitor envelope");
}

async fn wait_for_fault(health: &MonitorSubscriptionHealth) -> MonitorIngressFault {
    timeout(DEADLINE, async {
        loop {
            if let Some(fault) = health.first_fault() {
                return fault;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("monitor fault arrives before deadline")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_monitor_tap_reorders_and_delivers_ordered_receipts() {
    let bus = loopback_bus().await;
    let publisher = bus.clone();
    let tap = MonitorTap::from_bus(bus).expect("wrap shared bus");
    let (health, mut receiver) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID)
        .await
        .expect("subscribe monitor channel");
    let started = Instant::now().into_std();

    publish(&publisher, &encoded(2)).await;
    tokio::time::sleep(POLL_INTERVAL).await;
    publish(&publisher, &encoded(1)).await;

    let first = timeout(DEADLINE, receiver.recv())
        .await
        .expect("first receipt before deadline")
        .expect("monitor stream stays healthy")
        .expect("first receipt exists");
    let second = timeout(DEADLINE, receiver.recv())
        .await
        .expect("second receipt before deadline")
        .expect("monitor stream stays healthy")
        .expect("second receipt exists");
    let completed = Instant::now().into_std();

    assert_eq!(
        (first.envelope.event_seq, second.envelope.event_seq),
        (1, 2)
    );
    assert!(first.received_at >= started && first.received_at <= completed);
    assert!(second.received_at >= started && second.received_at <= completed);
    assert!(first.received_at > second.received_at);
    assert!(first.ordered_at <= second.ordered_at);
    assert!(first.ordered_at >= first.received_at);
    assert!(second.ordered_at >= second.received_at);
    assert_eq!(health.events_reordered(), 1);
    assert_eq!(health.events_delivered(), 2);
    assert_eq!(health.last_contiguous_event_seq(), Some(2));
    assert!(health.first_fault().is_none());

    tap.close()
        .await
        .expect_err("shared tap must not close its host bus");
    publisher.close().await.expect("host closes shared session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provenance_mismatch_faults_the_epoch_and_delivers_nothing() {
    let bus = loopback_bus().await;
    let publisher = bus.clone();
    let tap = MonitorTap::from_bus(bus).expect("wrap shared bus");
    let (health, mut receiver) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID)
        .await
        .expect("subscribe monitor channel");
    let mut wrong = envelope(1);
    wrong.producer_id = "other-producer".to_string();

    publish(
        &publisher,
        &serde_json::to_vec(&wrong).expect("wrong-provenance envelope encodes"),
    )
    .await;

    let fault = wait_for_fault(&health).await;
    assert_eq!(fault, MonitorIngressFault::ProvenanceMismatch);
    assert_eq!(
        health.fault_count(MonitorIngressFaultKind::ProvenanceMismatch),
        1
    );
    assert_eq!(
        timeout(DEADLINE, receiver.recv())
            .await
            .expect("receiver reports fault before deadline"),
        Err(MonitorIngressFault::ProvenanceMismatch)
    );
    assert_eq!(health.events_delivered(), 0);

    publisher.close().await.expect("host closes shared session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_handoff_surfaces_terminal_fault_out_of_band() {
    let bus = loopback_bus().await;
    let publisher = bus.clone();
    let config = MonitorLiveConfig::new(2, 1, 2).expect("small valid bounds");
    let tap = MonitorTap::from_bus_with_config(bus, config).expect("wrap shared bus");
    let (health, mut receiver) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID)
        .await
        .expect("subscribe monitor channel");

    publish(&publisher, &encoded(1)).await;
    publish(&publisher, &encoded(2)).await;
    publish(&publisher, &encoded(3)).await;

    let fault = wait_for_fault(&health).await;
    assert_eq!(
        fault,
        MonitorIngressFault::HandoffFull {
            capacity: 2,
            event_seq: 3
        }
    );
    assert_eq!(health.events_enqueued(), 2);
    assert_eq!(
        timeout(DEADLINE, receiver.recv())
            .await
            .expect("fault bypasses the full handoff"),
        Err(fault)
    );
    assert_eq!(health.events_delivered(), 0);

    publisher.close().await.expect("host closes shared session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_small_gap_faults_without_a_followup_sample() {
    let bus = loopback_bus().await;
    let publisher = bus.clone();
    let config = MonitorLiveConfig::new(3, 2, 2)
        .expect("small valid bounds")
        .with_reorder_deadline(Duration::from_millis(50))
        .expect("short positive deadline");
    let tap = MonitorTap::from_bus_with_config(bus, config).expect("wrap shared bus");
    let (health, mut receiver) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID)
        .await
        .expect("subscribe monitor channel");

    publish(&publisher, &encoded(2)).await;

    let fault = wait_for_fault(&health).await;
    assert_eq!(
        fault,
        MonitorIngressFault::SequenceGapDeadlineExceeded {
            expected: 1,
            next_received: 2,
            deadline: Duration::from_millis(50),
        }
    );
    assert_eq!(
        health.fault_count(MonitorIngressFaultKind::SequenceGapDeadlineExceeded),
        1
    );
    assert_eq!(health.pending_reorder_events(), 0);
    assert_eq!(
        timeout(DEADLINE, receiver.recv())
            .await
            .expect("receiver reports gap fault before deadline"),
        Err(fault)
    );

    publisher.close().await.expect("host closes shared session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receiver_close_undeclares_only_its_selector_and_stops_its_gap_timer() {
    let bus = loopback_bus().await;
    let publisher = bus.clone();
    let config = MonitorLiveConfig::new(3, 2, 2)
        .expect("small valid bounds")
        .with_reorder_deadline(Duration::from_millis(50))
        .expect("short positive deadline");
    let tap = MonitorTap::from_bus_with_config(bus, config).expect("wrap shared bus");
    let (health, mut receiver) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID)
        .await
        .expect("subscribe monitor channel");

    publish(&publisher, &encoded(2)).await;
    timeout(DEADLINE, async {
        while health.pending_reorder_events() != 1 {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("out-of-order event reaches the live subscription");

    receiver.close();
    assert!(receiver.is_closed());
    assert_eq!(
        timeout(DEADLINE, receiver.recv())
            .await
            .expect("cancelled handoff closes promptly"),
        Ok(None)
    );
    assert_eq!(health.pending_reorder_events(), 0);

    tokio::time::sleep(Duration::from_millis(100)).await;
    publish(&publisher, &encoded(1)).await;
    tokio::time::sleep(POLL_INTERVAL).await;
    assert!(health.first_fault().is_none());
    assert_eq!(
        health.fault_count(MonitorIngressFaultKind::SequenceGapDeadlineExceeded),
        0
    );
    assert_eq!(health.payloads_received(), 1);

    let (restarted_health, mut restarted_receiver) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID)
        .await
        .expect("exact selector can be subscribed again after scoped cancellation");
    publish(&publisher, &encoded(1)).await;
    let restarted = timeout(DEADLINE, restarted_receiver.recv())
        .await
        .expect("restarted receipt before deadline")
        .expect("restarted monitor stream stays healthy")
        .expect("restarted receipt exists");
    assert_eq!(restarted.envelope.event_seq, 1);
    assert_eq!(restarted_health.payloads_received(), 1);
    assert_eq!(health.payloads_received(), 1);

    restarted_receiver.close();
    publisher.close().await.expect("host closes shared session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advisory_contract_hash_mismatch_is_counted_and_delivered() {
    let bus = loopback_bus().await;
    let publisher = bus.clone();
    let tap = MonitorTap::from_bus(bus).expect("wrap shared bus");
    let (health, mut receiver) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID)
        .await
        .expect("subscribe monitor channel");
    let mut drifted = envelope(1);
    drifted.contract_hash = "deadbeefdeadbeef".to_string();
    let bytes = drifted.encode().expect("advisory mismatch remains valid");

    publish(&publisher, &bytes).await;

    let receipt = timeout(DEADLINE, receiver.recv())
        .await
        .expect("receipt before deadline")
        .expect("advisory drift does not fault")
        .expect("receipt exists");
    assert_eq!(receipt.envelope.event_seq, 1);
    assert_eq!(health.contract_hash_mismatches(), 1);
    assert!(health.first_fault().is_none());

    publisher.close().await.expect("host closes shared session");
}
