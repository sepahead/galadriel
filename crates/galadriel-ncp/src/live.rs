//! The live Zenoh tap (feature `zenoh`; reached via galadriel's `ncp-live`).
//!
//! This is the streaming counterpart to the JSONL ingest: the *same*
//! [`PidObservation`] records, delivered live over the NCP bus instead of read from a
//! file. galadriel subscribes to its **non-wire sidecar key**
//! `{realm}/session/{id}/galadriel/pid` (see [`crate::sidecar_key`]) — additive under
//! the session, never a proto/wire message, so it can never touch NCP's `CONTRACT_HASH`.
//!
//! It is a strictly **read-only observer**: [`SidecarTap`] only *subscribes*. It never
//! publishes to a control plane, never opens a session, never touches the safety-gated
//! action plane — galadriel is instrumentation on top of the bus, not a participant in
//! the loop.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use galadriel_ncp::live::SidecarTap;
//! let tap = SidecarTap::open().await?;
//! tap.subscribe("uav3", |obs| {
//!     // hand each observation to a galadriel detector (cheap: decode + enqueue)
//!     let _ = obs.nis;
//! })
//! .await?;
//! # Ok(()) }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use galadriel_core::observation::PidObservation;
use ncp_core::{Keys, DEFAULT_REALM};
use ncp_zenoh::{ZenohBus, ZenohError};

use crate::sidecar_key;

/// A live, read-only tap on galadriel's sidecar observation key over Zenoh.
pub struct SidecarTap {
    bus: ZenohBus,
    realm: String,
    decode_failures: Arc<AtomicU64>,
}

impl SidecarTap {
    /// Open a tap on the default NCP realm with the hardened default Zenoh config.
    pub async fn open() -> Result<Self, ZenohError> {
        Ok(Self {
            bus: ZenohBus::open().await?,
            realm: DEFAULT_REALM.to_string(),
            decode_failures: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Open a tap on an explicit realm.
    pub async fn open_realm(realm: impl Into<String>) -> Result<Self, ZenohError> {
        let realm = realm.into();
        let bus = ZenohBus::open_realm(Keys::new(&realm)).await?;
        Ok(Self {
            bus,
            realm,
            decode_failures: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Wrap an already-open bus, so a host app can share one Zenoh session across its
    /// own traffic and galadriel's observer tap.
    pub fn from_bus(bus: ZenohBus, realm: impl Into<String>) -> Self {
        Self {
            bus,
            realm: realm.into(),
            decode_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Payloads on the sidecar key that failed to decode as a [`PidObservation`],
    /// across all subscriptions of this tap. Malformed input is *dropped* (the
    /// callback must never see adversarial bytes) but **never silently**: a rising
    /// counter here is the first symptom of sidecar-contract drift (a producer
    /// serializing a different shape — see `sidecar_payload_contract_is_frozen`)
    /// or of garbage injected on the key, and a monitor must be able to see its
    /// own feed rotting.
    pub fn decode_failures(&self) -> u64 {
        self.decode_failures.load(Ordering::Relaxed)
    }

    /// The underlying bus (e.g. to close it, or share the session).
    pub fn bus(&self) -> &ZenohBus {
        &self.bus
    }

    /// Subscribe to a session's galadriel sidecar key. `on_obs` runs **inline on Zenoh's
    /// receive task** for each decoded observation, so keep it cheap (decode + hand off).
    /// Malformed payloads are dropped — the callback must never see adversarial bytes,
    /// and must never panic, because a panic unwinds Zenoh's task (see
    /// `ZenohBus::subscribe`) — but each drop is **counted** ([`Self::decode_failures`]),
    /// so contract drift shows up as a rising counter rather than as silence.
    /// Errors if `session_id` is not a valid NCP id segment.
    pub async fn subscribe<F>(&self, session_id: &str, on_obs: F) -> Result<(), ZenohError>
    where
        F: Fn(PidObservation) + Send + Sync + 'static,
    {
        let key = sidecar_key(&self.realm, session_id)
            .ok_or_else(|| ZenohError(format!("invalid NCP session id segment: {session_id:?}")))?;
        let failures = Arc::clone(&self.decode_failures);
        self.bus
            .subscribe(&key, move |_key, bytes| {
                match serde_json::from_slice::<PidObservation>(&bytes) {
                    Ok(obs) => on_obs(obs),
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
            .await
    }

    /// Gracefully close the underlying Zenoh session (undeclare subscribers and flush).
    pub async fn close(&self) -> Result<(), ZenohError> {
        self.bus.close().await
    }
}
