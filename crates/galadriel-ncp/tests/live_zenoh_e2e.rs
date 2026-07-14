#![forbid(unsafe_code)]
#![cfg(feature = "zenoh")]
//! End-to-end runtime proof of the NCP **live leg** (feature `zenoh`): a real
//! in-process Zenoh session carries a [`SidecarEnvelope`] from a publisher to a
//! [`SidecarTap`] subscription — actual `ZenohBus` round trip, not synthetic
//! payload delivery into `process_payload`.
//!
//! Loopback model (mirrors NCP's own `ncp-zenoh/tests/loopback.rs`): Zenoh
//! delivers a session's own publications to that session's subscribers, so one
//! in-process session with discovery disabled is a hermetic, deterministic bus.
//! No external router, no LAN scouting, no other process.
//!
//! Producer surface note: `ZenohBus::put_sensor_named` gates payloads as NCP
//! `SensorFrame`s and rejects a sidecar envelope, so a real producer (and this
//! test) publishes the envelope with the raw `ZenohBus::put(key, bytes,
//! Plane::Perception)` primitive — or the raw shared `zenoh::Session` — on the
//! exact sidecar key.
//!
//! Run with:
//! ```text
//! cargo test -p galadriel-ncp --features zenoh --test live_zenoh_e2e --locked
//! ```
//! CI already runs it via `cargo test --workspace --all-features --locked`.

use std::time::Duration;

use galadriel_core::observation::{Modality, PidObservation};
use galadriel_ncp::live::{
    HandoffConfig, HandoffProfile, LastAcceptedObservation, LiveLimits, RejectionReason,
    SidecarTap, SubscriptionHealth, TransportMode,
};
use galadriel_ncp::{sidecar_key, SidecarEnvelope};
use ncp_core::keys::Keys;
use ncp_zenoh::{Plane, ZenohBus, ZenohConfig, NCP_ZENOH_CONFIG_ENV};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::time::{timeout, Instant};

/// The deployment realm shared with the Crebain producer (multi-segment,
/// exercising `from_bus` realm derivation beyond the `"ncp"` default).
const REALM: &str = "engram/ncp";
const SESSION_ID: &str = "uav3";
const PRODUCER_ID: &str = "crebain";

/// Every await in this file is bounded: nothing here can hang CI.
const RECV_DEADLINE: Duration = Duration::from_secs(10);
const COUNTER_DEADLINE: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

fn handoff() -> HandoffConfig {
    HandoffProfile::BoundedV0_9
        .try_config()
        .expect("compiled test handoff profile is valid")
}

/// Hermetic in-process loopback config, byte-for-byte the knobs NCP's own
/// runtime test uses: no multicast scouting, no gossip, no shared-memory —
/// the test never depends on the environment or the network.
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

async fn loopback_bus(realm: &str) -> ZenohBus {
    let keys = Keys::try_new(realm).expect("test realm is a valid NCP realm");
    ZenohBus::with_config(loopback_config(), keys)
        .await
        .expect("open in-process loopback Zenoh session")
}

/// A crebain-shaped baseline observation (radar, dof 3, χ²-plausible NIS).
fn observation(seq: u64) -> PidObservation {
    PidObservation::try_scalar_raw(42, 1_000 + seq, seq, Modality::Radar, 2.5, 3)
        .expect("test observation is valid")
}

fn envelope_for(session_id: &str, observation: PidObservation) -> SidecarEnvelope {
    SidecarEnvelope::try_new(session_id, PRODUCER_ID, observation)
        .expect("test envelope passes sidecar validation")
}

fn envelope_bytes(session_id: &str, seq: u64) -> Vec<u8> {
    serde_json::to_vec(&envelope_for(session_id, observation(seq)))
        .expect("envelope serializes to JSON")
}

fn subscribed_key() -> String {
    sidecar_key(REALM, SESSION_ID).expect("sidecar key for a valid realm/session")
}

/// Bounded poll for a counter transition driven by Zenoh's receive task.
async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + COUNTER_DEADLINE;
    while !done() {
        assert!(
            Instant::now() < deadline,
            "timed out after {COUNTER_DEADLINE:?} waiting for {what}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Bounded receive with a clear diagnostic on starvation.
async fn recv_one(
    observations: &mut galadriel_ncp::live::LiveObservationReceiver,
    what: &str,
) -> PidObservation {
    timeout(RECV_DEADLINE, observations.recv())
        .await
        .unwrap_or_else(|_| panic!("live leg delivered nothing within {RECV_DEADLINE:?}: {what}"))
        .expect("bounded handoff channel closed unexpectedly")
}

fn assert_nothing_delivered(
    observations: &mut galadriel_ncp::live::LiveObservationReceiver,
    health: &SubscriptionHealth,
    context: &str,
) {
    assert_eq!(health.observations_accepted(), 0, "{context}");
    assert_eq!(health.handoff_enqueued(), 0, "{context}");
    assert!(
        matches!(observations.try_recv(), Err(TryRecvError::Empty)),
        "{context}: rejected payload must not reach the consumer"
    );
}

/// (1)(2)(3)(4)(5) — the positive path: one shared in-process session, a
/// `from_bus` tap on the `engram/ncp` realm, `subscribe_channel`, one valid
/// envelope published on the exact sidecar key, decoded observation delivered
/// with exact field fidelity and health counters advanced.
///
/// Also proves the *realm derivation* claim of `from_bus`: a byte-identical
/// envelope published on the **default-realm** key first is never seen by the
/// `engram/ncp` subscription (its key cannot match), so `payloads_received`
/// ends at exactly 1 — brokered pub/sub realm mismatch is silent, which is
/// precisely why `payloads_received` is the documented liveness signal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_bus_live_leg_delivers_valid_envelope_end_to_end() {
    let bus = loopback_bus(REALM).await;
    let publisher = bus.clone(); // clone shares the same Arc<zenoh::Session>
    let tap = SidecarTap::from_bus(bus).expect("wrap the shared bus");

    let key = subscribed_key();
    assert_eq!(key, "engram/ncp/session/uav3/sensor/galadriel-pid");

    let (health, mut observations) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID, handoff())
        .await
        .expect("subscribe to the sidecar channel");
    assert_eq!(health.payloads_received(), 0);

    // Research-mode observation: assert full field fidelity through the wire.
    let published = observation(7)
        .try_with_research(
            [0.5, -0.25, 0.125],
            [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
        )
        .expect("test research fields are valid");
    let bytes = serde_json::to_vec(&envelope_for(SESSION_ID, published.clone()))
        .expect("envelope serializes");

    // Realm-mismatch control: same payload on the DEFAULT realm's key. The
    // subscription key is derived from the bus realm, so this can never match.
    let default_realm_key = sidecar_key(ncp_core::DEFAULT_REALM, SESSION_ID).expect("default key");
    assert_ne!(default_realm_key, key);
    publisher
        .put(&default_realm_key, &bytes, Plane::Perception)
        .await
        .expect("publish on the wrong-realm key");

    // The real publish, on the exact sidecar key, over the shared session.
    publisher
        .put(&key, &bytes, Plane::Perception)
        .await
        .expect("publish sidecar envelope");

    let received = recv_one(&mut observations, "valid envelope on the subscribed key").await;
    assert_eq!(received.track_id(), published.track_id());
    assert_eq!(received.timestamp_ms(), published.timestamp_ms());
    assert_eq!(received.sequence(), published.sequence());
    assert_eq!(received.modality(), published.modality());
    assert_eq!(received.nis(), published.nis());
    assert_eq!(received.dof(), published.dof());
    assert_eq!(received.innovation(), published.innovation());
    assert_eq!(
        received.innovation_covariance(),
        published.innovation_covariance()
    );
    assert!(received.consistency_projection().is_none());

    // Subscription-scoped health counters.
    assert_eq!(
        health.payloads_received(),
        1,
        "wrong-realm publish must not arrive"
    );
    assert_eq!(health.observations_accepted(), 1);
    assert_eq!(health.decode_failures(), 0);
    assert_eq!(health.rejections().total(), 0);
    assert_eq!(health.handoff_enqueued(), 1);
    assert_eq!(health.handoff_delivered(), 1);
    assert_eq!(health.handoff_drops(), 0);
    assert_eq!(health.contract_hash_mismatches(), 0);

    // Tap-scoped aggregates and the diagnostic high-water mark.
    assert_eq!(tap.payloads_received(), 1);
    assert_eq!(tap.observations_accepted(), 1);
    assert_eq!(tap.decode_failures(), 0);
    // `LastAcceptedObservation` is #[non_exhaustive]; compare field-by-field.
    let last: LastAcceptedObservation = tap.last_accepted().expect("an observation was accepted");
    assert_eq!(last.track_id, published.track_id().get());
    assert_eq!(last.modality, published.modality());
    assert_eq!(last.sequence, published.sequence().get());
    assert_eq!(last.timestamp_ms, published.timestamp_ms().get());

    // A shared-bus tap must refuse to close the HOST's session — and the refusal
    // must change nothing: the host's transport keeps working afterwards.
    let refused = tap
        .close()
        .await
        .expect_err("a from_bus tap must refuse to close the host-owned session");
    assert!(
        refused.to_string().contains("host-owned"),
        "close refusal names the host-owned bus: {refused}"
    );
    publisher
        .put(&key, &envelope_bytes(SESSION_ID, 8), Plane::Perception)
        .await
        .expect("host session must survive the refused tap close");
    let survived = recv_one(&mut observations, "delivery after refused close").await;
    assert_eq!(survived.sequence().get(), 8);

    // The HOST closes the shared session through its own handle — that is the
    // documented lifecycle owner, and it still works.
    publisher.close().await.expect("host-owned close succeeds");
}

/// (1) via the public constructor: `TransportMode::QuietDevelopment` maps to
/// `ZenohBus::open_realm` (live.rs), i.e. NCP's hardened default config with
/// multicast scouting disabled. Publishes through the raw shared
/// `zenoh::Session` handle (`tap.bus().session()`), the second documented
/// producer surface.
///
/// Skipped when `NCP_ZENOH_CONFIG` is set: NCP's default open path loads that
/// file instead of the hardened default, so the test would no longer be
/// hermetic. CI never sets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiet_development_open_realm_round_trip() {
    if std::env::var_os(NCP_ZENOH_CONFIG_ENV).is_some() {
        eprintln!("skipping: {NCP_ZENOH_CONFIG_ENV} overrides the hermetic default config");
        return;
    }

    let tap = SidecarTap::open_realm(REALM, TransportMode::QuietDevelopment)
        .await
        .expect("QuietDevelopment opens the hardened default (scouting-off) session");
    let (health, mut observations) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID, handoff())
        .await
        .expect("subscribe to the sidecar channel");

    // Publish over the same session via the raw shared-session accessor.
    let key = subscribed_key();
    tap.bus()
        .session()
        .put(key.as_str(), envelope_bytes(SESSION_ID, 3))
        .await
        .expect("publish via the raw shared zenoh session");

    let received = recv_one(&mut observations, "QuietDevelopment loopback").await;
    assert_eq!(received.track_id().get(), 42);
    assert_eq!(received.sequence().get(), 3);
    assert_eq!(received.modality(), Modality::Radar);
    assert_eq!(health.payloads_received(), 1);
    assert_eq!(health.observations_accepted(), 1);
    assert_eq!(health.decode_failures(), 0);

    tap.close().await.expect("graceful close");
}

/// (6a) Wrong-session provenance: a fully valid envelope claiming `uav9`
/// arriving on `uav3`'s key is rejected, counted as `ProvenanceMismatch`, and
/// never delivered — then a valid envelope proves the subscription survived.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_session_envelope_is_rejected_counted_and_not_delivered() {
    let bus = loopback_bus(REALM).await;
    let publisher = bus.clone();
    let tap = SidecarTap::from_bus(bus).expect("wrap the shared bus");
    let (health, mut observations) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID, handoff())
        .await
        .expect("subscribe to the sidecar channel");

    let key = subscribed_key();
    // Valid envelope, wrong session claim, published on uav3's key.
    publisher
        .put(&key, &envelope_bytes("uav9", 1), Plane::Perception)
        .await
        .expect("publish wrong-session envelope");

    wait_until("provenance_mismatch counter", || {
        health.rejection_count(RejectionReason::ProvenanceMismatch) >= 1
    })
    .await;
    assert_eq!(
        health.rejection_count(RejectionReason::ProvenanceMismatch),
        1
    );
    assert_eq!(health.decode_failures(), 1);
    assert_nothing_delivered(&mut observations, &health, "wrong-session envelope");

    // The subscription is still alive after the rejection.
    publisher
        .put(&key, &envelope_bytes(SESSION_ID, 2), Plane::Perception)
        .await
        .expect("publish valid envelope after rejection");
    let received = recv_one(&mut observations, "valid envelope after rejection").await;
    assert_eq!(received.sequence().get(), 2);
    assert_eq!(health.payloads_received(), 2);
    assert_eq!(health.observations_accepted(), 1);

    tap.close()
        .await
        .expect_err("a from_bus tap must refuse to close the host-owned session");
    publisher.close().await.expect("host-owned close succeeds");
}

/// (6b) Duplicate-JSON-key payload: `{"kind":…,"kind":…}` must be rejected at
/// the typed-envelope parse (serde data error → `InvalidEnvelope`), never
/// collapsed last-key-wins — the parser-differential boundary live.rs defends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_json_key_payload_is_counted_invalid_envelope() {
    let bus = loopback_bus(REALM).await;
    let publisher = bus.clone();
    let tap = SidecarTap::from_bus(bus).expect("wrap the shared bus");
    let (health, mut observations) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID, handoff())
        .await
        .expect("subscribe to the sidecar channel");

    // Take a byte-valid envelope and inject a duplicate leading "kind" key.
    let valid = serde_json::to_string(&envelope_for(SESSION_ID, observation(1)))
        .expect("envelope serializes");
    assert!(
        valid.starts_with("{\"kind\":"),
        "envelope field order changed; update the duplicate-key surgery"
    );
    let duplicated = format!("{{\"kind\":\"galadriel_pid_observation\",{}", &valid[1..]);

    let key = subscribed_key();
    publisher
        .put(&key, duplicated.as_bytes(), Plane::Perception)
        .await
        .expect("publish duplicate-key payload");

    wait_until("invalid_envelope counter", || {
        health.rejection_count(RejectionReason::InvalidEnvelope) >= 1
    })
    .await;
    assert_eq!(health.rejection_count(RejectionReason::InvalidEnvelope), 1);
    assert_eq!(
        health.rejection_count(RejectionReason::MalformedJson),
        0,
        "duplicate key is a data error at the typed parse, not a syntax error"
    );
    assert_eq!(health.decode_failures(), 1);
    assert_nothing_delivered(&mut observations, &health, "duplicate-key payload");

    tap.close()
        .await
        .expect_err("a from_bus tap must refuse to close the host-owned session");
    publisher.close().await.expect("host-owned close succeeds");
}

/// (6c) Oversized payload: rejected by the size gate BEFORE any parse
/// (`PayloadTooLarge`, `malformed_json` stays 0), and a small valid envelope
/// still flows afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_payload_is_rejected_before_parse() {
    let bus = loopback_bus(REALM).await;
    let publisher = bus.clone();
    let limits = LiveLimits::new(2_048).expect("nonzero payload limit");
    let tap = SidecarTap::from_bus_with_limits(bus, limits).expect("wrap the shared bus");
    let (health, mut observations) = tap
        .subscribe_channel(SESSION_ID, PRODUCER_ID, handoff())
        .await
        .expect("subscribe to the sidecar channel");

    let key = subscribed_key();
    // 4096 junk bytes: over the limit AND not JSON — proves the size gate
    // fires first (malformed_json must stay 0).
    publisher
        .put(&key, &vec![b'x'; 4_096], Plane::Perception)
        .await
        .expect("publish oversized payload");

    wait_until("payload_too_large counter", || {
        health.rejection_count(RejectionReason::PayloadTooLarge) >= 1
    })
    .await;
    assert_eq!(health.rejection_count(RejectionReason::PayloadTooLarge), 1);
    assert_eq!(
        health.rejection_count(RejectionReason::MalformedJson),
        0,
        "size gate must precede JSON parsing"
    );
    assert_eq!(health.decode_failures(), 1);
    assert_nothing_delivered(&mut observations, &health, "oversized payload");

    // A small valid envelope still fits the 2 KiB limit and is delivered.
    publisher
        .put(&key, &envelope_bytes(SESSION_ID, 9), Plane::Perception)
        .await
        .expect("publish valid envelope after oversize rejection");
    let received = recv_one(&mut observations, "valid envelope after oversize rejection").await;
    assert_eq!(received.sequence().get(), 9);
    assert_eq!(health.observations_accepted(), 1);

    tap.close()
        .await
        .expect_err("a from_bus tap must refuse to close the host-owned session");
    publisher.close().await.expect("host-owned close succeeds");
}
