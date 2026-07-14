#![forbid(unsafe_code)]
//! # galadriel-ncp
//!
//! Versioned NCP sidecar ingest for Galadriel's Mirror (feature `ncp`).
//!
//! galadriel is a **read-only** consumer of per-measurement records. Native
//! innovations may be carried for diagnostics, but consistency uses only the
//! optional producer-attested `consistency_projection` field.
//! In the ecosystem those ride the NCP observation plane; this crate is the seam
//! that turns them into [`galadriel_core::PidObservation`]s.
//! Producer lifecycle, frame closure, and liveness use the separate strict
//! [`monitor::MonitorEnvelope`] contract on `sensor/galadriel-monitor`; they are
//! never fabricated as observations on the frozen `galadriel-pid` route.
//!
//! ## Transport, honestly scoped
//!
//! - **The MVP path is transport-free JSONL** — no Zenoh, no tokio, no network —
//!   which is a first-class NCP flow (`ncp-observe` and the reference UAV loop both
//!   emit JSONL). [`read_jsonl`] / [`parse_jsonl`] / [`write_jsonl`] cover it with
//!   independent per-record, record-count, and aggregate-byte limits.
//! - `PidObservation` is **not** an NCP wire message. Live records ride the named
//!   perception route `Keys::sensor_named(session_id, "galadriel-pid")` inside a
//!   versioned [`SidecarEnvelope`]. The sidecar remains outside the normative proto
//!   and `CONTRACT_HASH`, while its envelope declares both the sidecar schema and the
//!   NCP contract revision used for transport addressing.
//! - The live Zenoh tap (`live::SidecarTap`, `ncp-zenoh`) is a separate, heavier
//!   concern behind the `zenoh` feature (reached via galadriel's `ncp-live`) — it is not
//!   pulled by the default JSONL path.
//! - The same feature exposes `operational_live::OperationalLiveReceiver`, which
//!   joins the observation and monitor routes through one serialized, bounded,
//!   deadline-driven ingress before [`lifecycle::LifecycleDetector`] admits evidence.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::path::Path;

use galadriel_core::{Modality, PidObservation, Sequence, TrackId};
use ncp_core::{
    contract_status, valid_id_segment, ContractStatus, Keys, CONTRACT_HASH, DEFAULT_REALM,
    JSON_SAFE_INTEGER_MAX, NCP_VERSION,
};
use serde::{Deserialize, Deserializer, Serialize};

pub mod assembler;
mod config_identity;
pub mod lifecycle;
#[cfg(feature = "zenoh")]
pub mod live;
pub mod monitor;
#[cfg(feature = "zenoh")]
pub mod monitor_live;
#[cfg(feature = "zenoh")]
pub mod operational_live;
pub mod registry;
#[cfg(feature = "zenoh")]
pub mod secure_live;

pub use config_identity::ConfigurationIdentity;

/// The exact pinned `ncp-core`, re-exported so hosts reuse galadriel's revision
/// (constants, `Keys`, validators) instead of re-resolving the git dependency and
/// risking a second, diverging pin in one process.
pub use ncp_core;

/// The exact pinned `ncp-zenoh` (feature `zenoh`), re-exported so a host that
/// builds a shared bus for [`live::SidecarTap::from_bus`] uses the same crate
/// version as the tap itself.
#[cfg(feature = "zenoh")]
pub use ncp_zenoh;

/// Maximum bytes accepted for the sidecar `session_id` / `producer_id` segments.
///
/// NCP 0.8 bounds a transport-neutral session identifier to 1..=64 bytes
/// (`ncp-core` `validate_session_id_str`); the sidecar mirrors that ceiling so an
/// envelope can never carry an identity the NCP control plane itself would reject.
pub const MAX_ID_SEGMENT_BYTES: usize = 64;

/// Stable named-perception entity carrying Galadriel sidecar envelopes.
///
/// The `-pid` suffix is **historical**: it predates the current layering, in which the
/// primary cross-sensor signal is NIS/CUSUM plus signed (sign-preserving) correlation and
/// PID is only an optional additive research diagnostic. The route and payload kind keep
/// the name because it is a *frozen* on-the-wire contract shared with the Crebain producer
/// and the JSON Schema; renaming it is a breaking change deliberately deferred to the next
/// sidecar-schema version bump (see [`SIDECAR_SCHEMA_VERSION`]), never done ad hoc.
pub const SIDECAR_SENSOR_NAME: &str = "galadriel-pid";

/// Sidecar payload discriminator. This is deliberately not an NCP normative
/// message kind; the envelope is project-owned and versioned independently.
pub const SIDECAR_KIND: &str = "galadriel_pid_observation";

/// Current Galadriel sidecar schema. An incompatible shape requires a new value
/// and coordinated producer/consumer update.
pub const SIDECAR_SCHEMA_VERSION: &str = "1.0";

/// Machine-readable JSON Schema for [`SIDECAR_SCHEMA_VERSION`]. Semantic checks
/// that JSON Schema cannot express (paired research fields, covariance positive
/// definiteness, and inactive projection axes) are enforced while constructing or
/// decoding the typed observation; [`SidecarEnvelope::validate_for`] additionally
/// binds the envelope's transport provenance.
pub const SIDECAR_SCHEMA_JSON: &str =
    include_str!("../schemas/galadriel-pid-envelope-v1.schema.json");

/// A validated live-sidecar envelope.
///
/// The payload-level `producer_id` is an authenticated *claim* only when the
/// transport identity/ACL binds the publisher. It is not a signature. A fresh NCP
/// `session_id` is the producer epoch boundary; producers must not reuse it after a
/// restart that resets observation sequences.
///
/// This epoch discipline is **sidecar-owned** and deliberately simpler than NCP 0.8's
/// control-plane sessions, whose server-issued `generation` distinguishes incarnations
/// of one `session_id`. The sidecar has no session server to issue generations, so a
/// producer restart must mint a *new* `session_id` (subscribers key on the exact path
/// segment); carrying a generation field would claim a lifecycle authority this
/// observation-plane contract does not have.
#[derive(Debug, Clone, Serialize)]
pub struct SidecarEnvelope {
    /// Stable discriminator, [`SIDECAR_KIND`].
    kind: String,
    /// Galadriel-owned envelope schema, [`SIDECAR_SCHEMA_VERSION`].
    schema_version: String,
    /// NCP wire version governing the named-perception route.
    ncp_version: String,
    /// Advisory identity of the NCP contract revision used by the producer.
    contract_hash: String,
    /// NCP session/producer epoch. Must equal the subscribed path segment.
    session_id: String,
    /// Concrete producer identifier, for example `"crebain"`.
    producer_id: String,
    /// The existing, frozen Crebain/Galadriel observation contract.
    observation: PidObservation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSidecarEnvelope {
    kind: String,
    schema_version: String,
    ncp_version: String,
    contract_hash: String,
    session_id: String,
    producer_id: String,
    observation: PidObservation,
}

/// Semantic failure in a decoded [`SidecarEnvelope`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SidecarEnvelopeError {
    /// The payload discriminator does not identify this sidecar.
    #[error("invalid sidecar kind: got {received:?}, want {SIDECAR_KIND:?}")]
    InvalidKind { received: String },
    /// The Galadriel-owned schema is not supported.
    #[error(
        "unsupported sidecar schema version: got {received:?}, want {SIDECAR_SCHEMA_VERSION:?}"
    )]
    UnsupportedSchemaVersion { received: String },
    /// The NCP wire version is malformed or incompatible.
    #[error("incompatible NCP version in sidecar envelope: {0}")]
    IncompatibleNcpVersion(String),
    /// The advertised contract hash is not a canonical 64-bit lowercase hex value.
    #[error("invalid NCP contract hash in sidecar envelope: {0:?}")]
    InvalidContractHash(String),
    /// The declared session is unsafe as an NCP key segment.
    #[error("invalid sidecar session_id: {0:?}")]
    InvalidSessionId(String),
    /// The declared producer is unsafe as an NCP key segment.
    #[error("invalid sidecar producer_id: {0:?}")]
    InvalidProducerId(String),
    /// The payload declares different provenance from the subscribed stream.
    #[error("sidecar {field} mismatch: got {received:?}, expected {expected:?}")]
    ProvenanceMismatch {
        field: &'static str,
        expected: String,
        received: String,
    },
    /// A numeric identity cannot round-trip through every NCP JSON peer.
    #[error("sidecar {field} exceeds the NCP exact JSON integer range: {value}")]
    IntegerOutOfRange { field: &'static str, value: u64 },
    /// The nested observation violates Galadriel's semantic contract.
    #[error("invalid sidecar observation: {0}")]
    InvalidObservation(String),
}

impl SidecarEnvelope {
    /// Construct and validate an envelope stamped with the local NCP and sidecar
    /// contract identities.
    pub fn try_new(
        session_id: impl Into<String>,
        producer_id: impl Into<String>,
        observation: PidObservation,
    ) -> Result<Self, SidecarEnvelopeError> {
        Self::try_from(RawSidecarEnvelope {
            kind: SIDECAR_KIND.to_string(),
            schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
            ncp_version: NCP_VERSION.to_string(),
            contract_hash: CONTRACT_HASH.to_string(),
            session_id: session_id.into(),
            producer_id: producer_id.into(),
            observation,
        })
    }

    /// Return the stable sidecar payload discriminator.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Return the Galadriel-owned sidecar schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Return the NCP wire version declared by the producer.
    pub fn ncp_version(&self) -> &str {
        &self.ncp_version
    }

    /// Return the producer-advertised NCP contract hash.
    pub fn contract_hash(&self) -> &str {
        &self.contract_hash
    }

    /// Return the producer epoch bound to the sidecar route.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Return the producer identity claimed by the envelope.
    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    /// Borrow the validated observation payload.
    pub fn observation(&self) -> &PidObservation {
        &self.observation
    }

    /// Consume the envelope and return its validated observation payload.
    pub fn into_observation(self) -> PidObservation {
        self.observation
    }

    /// Validate envelope identity, NCP compatibility, concrete provenance
    /// segments, cross-language integer bounds, and the nested observation.
    ///
    /// A well-formed but different `contract_hash` is advisory, matching NCP's
    /// handshake policy; the returned [`ContractStatus`] lets callers surface it.
    pub fn validate(&self) -> Result<ContractStatus, SidecarEnvelopeError> {
        if self.kind != SIDECAR_KIND {
            return Err(SidecarEnvelopeError::InvalidKind {
                received: self.kind.clone(),
            });
        }
        if self.schema_version != SIDECAR_SCHEMA_VERSION {
            return Err(SidecarEnvelopeError::UnsupportedSchemaVersion {
                received: self.schema_version.clone(),
            });
        }
        if self.ncp_version != NCP_VERSION {
            return Err(SidecarEnvelopeError::IncompatibleNcpVersion(format!(
                "noncanonical ncp_version {:?}; expected {NCP_VERSION:?}",
                self.ncp_version
            )));
        }
        ncp_core::check_version(&self.ncp_version, true)
            .map_err(|error| SidecarEnvelopeError::IncompatibleNcpVersion(error.to_string()))?;
        if self.contract_hash.len() != CONTRACT_HASH.len()
            || !self
                .contract_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SidecarEnvelopeError::InvalidContractHash(
                self.contract_hash.clone(),
            ));
        }
        if !valid_id_segment(&self.session_id) || self.session_id.len() > MAX_ID_SEGMENT_BYTES {
            return Err(SidecarEnvelopeError::InvalidSessionId(
                self.session_id.clone(),
            ));
        }
        if !valid_id_segment(&self.producer_id) || self.producer_id.len() > MAX_ID_SEGMENT_BYTES {
            return Err(SidecarEnvelopeError::InvalidProducerId(
                self.producer_id.clone(),
            ));
        }
        self.validate_json_integer("observation.track_id", self.observation.track_id().get())?;
        self.validate_json_integer(
            "observation.timestamp_ms",
            self.observation.timestamp_ms().get(),
        )?;
        self.validate_json_integer("observation.seq", self.observation.sequence().get())?;
        if let Some(projection) = self.observation.consistency_projection() {
            let identity = projection.identity();
            self.validate_json_integer(
                "observation.consistency_projection.frame_id",
                identity.frame_id().get(),
            )?;
            self.validate_json_integer(
                "observation.consistency_projection.context_id",
                identity.context_id().get(),
            )?;
            self.validate_json_integer(
                "observation.consistency_projection.prior_id",
                identity.frozen_prior_id().get(),
            )?;
        }
        Ok(contract_status(Some(&self.contract_hash)))
    }

    /// Validate the envelope and bind its claimed provenance to a concrete
    /// subscription. This prevents a valid payload for another session/producer
    /// from being accepted merely because it arrived on this callback.
    pub fn validate_for(
        &self,
        expected_session_id: &str,
        expected_producer_id: &str,
    ) -> Result<ContractStatus, SidecarEnvelopeError> {
        let status = self.validate()?;
        if self.session_id != expected_session_id {
            return Err(SidecarEnvelopeError::ProvenanceMismatch {
                field: "session_id",
                expected: expected_session_id.to_string(),
                received: self.session_id.clone(),
            });
        }
        if self.producer_id != expected_producer_id {
            return Err(SidecarEnvelopeError::ProvenanceMismatch {
                field: "producer_id",
                expected: expected_producer_id.to_string(),
                received: self.producer_id.clone(),
            });
        }
        Ok(status)
    }

    fn validate_json_integer(
        &self,
        field: &'static str,
        value: u64,
    ) -> Result<(), SidecarEnvelopeError> {
        if value > JSON_SAFE_INTEGER_MAX as u64 {
            return Err(SidecarEnvelopeError::IntegerOutOfRange { field, value });
        }
        Ok(())
    }
}

impl TryFrom<RawSidecarEnvelope> for SidecarEnvelope {
    type Error = SidecarEnvelopeError;

    fn try_from(raw: RawSidecarEnvelope) -> Result<Self, Self::Error> {
        let envelope = Self {
            kind: raw.kind,
            schema_version: raw.schema_version,
            ncp_version: raw.ncp_version,
            contract_hash: raw.contract_hash,
            session_id: raw.session_id,
            producer_id: raw.producer_id,
            observation: raw.observation,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

impl<'de> Deserialize<'de> for SidecarEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawSidecarEnvelope::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// Maximum encoded bytes in one JSONL record under the bounded 0.9 profile.
pub const DEFAULT_MAX_JSONL_LINE_BYTES: usize = 64 * 1024;

/// Maximum observations accepted by one JSONL operation under the bounded 0.9 profile.
pub const DEFAULT_MAX_JSONL_RECORDS: usize = 100_000;

/// Maximum aggregate encoded bytes accepted or produced by one JSONL operation.
pub const DEFAULT_MAX_JSONL_BYTES: usize = 64 * 1024 * 1024;

/// Absolute per-record ceiling accepted by [`JsonlLimits`].
pub const MAX_JSONL_LINE_BYTES: usize = 1024 * 1024;
/// Absolute record-count ceiling accepted by [`JsonlLimits`].
pub const MAX_JSONL_RECORDS: usize = 1_000_000;
/// Absolute aggregate-byte ceiling accepted by [`JsonlLimits`].
pub const MAX_JSONL_BYTES: usize = 256 * 1024 * 1024;

/// Untrusted raw JSONL limit parameters.
///
/// The fields are intentionally easy to deserialize or populate at a CLI
/// boundary. Convert them to [`JsonlLimits`] before allocating or processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonlParams {
    /// Maximum encoded bytes in one record, excluding its line ending.
    pub max_line_bytes: usize,
    /// Maximum nonblank records in one operation.
    pub max_records: usize,
    /// Maximum aggregate encoded bytes in one operation.
    pub max_total_bytes: usize,
}

/// Named, reviewed JSONL resource profiles for release 0.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonlProfile {
    /// Bounded local-file and transport-free ingest profile shipped in 0.9.
    BoundedV0_9,
}

impl JsonlProfile {
    /// Return the frozen raw parameters for this named profile.
    #[must_use]
    pub const fn params(self) -> JsonlParams {
        match self {
            Self::BoundedV0_9 => JsonlParams {
                max_line_bytes: DEFAULT_MAX_JSONL_LINE_BYTES,
                max_records: DEFAULT_MAX_JSONL_RECORDS,
                max_total_bytes: DEFAULT_MAX_JSONL_BYTES,
            },
        }
    }

    /// Validate this profile and return an immutable limit capability.
    pub fn try_limits(self) -> Result<JsonlLimits, JsonlLimitsError> {
        JsonlLimits::try_from(self.params())
    }
}

/// Invalid raw JSONL resource limits.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonlLimitsError {
    /// A required ceiling was zero.
    #[error("JSONL limit {field} must be greater than zero")]
    Zero {
        /// Invalid field.
        field: &'static str,
    },
    /// A ceiling exceeded its compiled hard maximum.
    #[error("JSONL limit {field} is {value}, exceeding hard maximum {maximum}")]
    ExceedsHardMaximum {
        /// Invalid field.
        field: &'static str,
        /// Received value.
        value: usize,
        /// Compiled hard maximum.
        maximum: usize,
    },
    /// A record could not fit inside the aggregate byte budget.
    #[error("JSONL max_line_bytes {line_bytes} exceeds max_total_bytes {total_bytes}")]
    LineExceedsTotal {
        /// Per-record ceiling.
        line_bytes: usize,
        /// Aggregate ceiling.
        total_bytes: usize,
    },
}

/// Validated, immutable resource limits for JSONL ingest and serialization.
///
/// Raw values cannot bypass validation:
///
/// ```compile_fail
/// use galadriel_ncp::JsonlLimits;
/// let _ = JsonlLimits { max_line_bytes: 1, max_records: 1, max_total_bytes: 1 };
/// ```
///
/// Production code must select a named profile or validate explicit parameters:
///
/// ```compile_fail
/// use galadriel_ncp::JsonlLimits;
/// let _ = JsonlLimits::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonlLimits {
    max_line_bytes: usize,
    max_records: usize,
    max_total_bytes: usize,
    identity: ConfigurationIdentity,
}

impl JsonlLimits {
    /// Validate line and record limits with [`DEFAULT_MAX_JSONL_BYTES`] as the
    /// aggregate input/output ceiling.
    pub fn new(max_line_bytes: usize, max_records: usize) -> Result<Self, JsonlLimitsError> {
        Self::with_total_bytes(max_line_bytes, max_records, DEFAULT_MAX_JSONL_BYTES)
    }

    /// Validate line, record, and aggregate-byte limits.
    pub fn with_total_bytes(
        max_line_bytes: usize,
        max_records: usize,
        max_total_bytes: usize,
    ) -> Result<Self, JsonlLimitsError> {
        Self::try_from(JsonlParams {
            max_line_bytes,
            max_records,
            max_total_bytes,
        })
    }

    /// Maximum encoded bytes in one record, excluding a CR/LF line ending.
    pub fn max_line_bytes(self) -> usize {
        self.max_line_bytes
    }

    /// Maximum nonblank observation records in one operation.
    pub fn max_records(self) -> usize {
        self.max_records
    }

    /// Maximum aggregate encoded bytes read or written by one operation.
    pub fn max_total_bytes(self) -> usize {
        self.max_total_bytes
    }

    /// Canonical SHA-256 identity of these validated limits.
    #[must_use]
    pub const fn identity(self) -> ConfigurationIdentity {
        self.identity
    }
}

impl TryFrom<JsonlParams> for JsonlLimits {
    type Error = JsonlLimitsError;

    fn try_from(params: JsonlParams) -> Result<Self, Self::Error> {
        for (field, value, maximum) in [
            (
                "max_line_bytes",
                params.max_line_bytes,
                MAX_JSONL_LINE_BYTES,
            ),
            ("max_records", params.max_records, MAX_JSONL_RECORDS),
            ("max_total_bytes", params.max_total_bytes, MAX_JSONL_BYTES),
        ] {
            if value == 0 {
                return Err(JsonlLimitsError::Zero { field });
            }
            if value > maximum {
                return Err(JsonlLimitsError::ExceedsHardMaximum {
                    field,
                    value,
                    maximum,
                });
            }
        }
        if params.max_line_bytes > params.max_total_bytes {
            return Err(JsonlLimitsError::LineExceedsTotal {
                line_bytes: params.max_line_bytes,
                total_bytes: params.max_total_bytes,
            });
        }
        let identity = config_identity::ConfigurationIdentityBuilder::new("jsonl-limits")
            .u64("max_line_bytes", params.max_line_bytes as u64)
            .u64("max_records", params.max_records as u64)
            .u64("max_total_bytes", params.max_total_bytes as u64)
            .finish();
        Ok(Self {
            max_line_bytes: params.max_line_bytes,
            max_records: params.max_records,
            max_total_bytes: params.max_total_bytes,
            identity,
        })
    }
}

#[cfg(test)]
impl Default for JsonlLimits {
    fn default() -> Self {
        JsonlProfile::BoundedV0_9
            .try_limits()
            .expect("the compiled JSONL test profile is valid")
    }
}

fn bounded_jsonl_limits() -> io::Result<JsonlLimits> {
    JsonlProfile::BoundedV0_9
        .try_limits()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

/// Whether a realm is a concrete, non-wildcard Zenoh key prefix.
///
/// Multi-segment realms such as `"engram/ncp"` are accepted, but every segment
/// must satisfy NCP's single-segment rules. Empty segments, whitespace, and key
/// expression delimiters are rejected.
pub fn valid_realm(realm: &str) -> bool {
    ncp_core::keys::valid_realm(realm)
}

/// The canonical NCP observation-plane key for a session:
/// `{realm}/session/{id}/observation` — the read-only tap galadriel subscribes to.
/// Returns `None` if the realm is not concrete or `session_id` is not a valid
/// NCP id segment.
pub fn observation_key(realm: &str, session_id: &str) -> Option<String> {
    Keys::try_new(realm).ok()?.try_observation(session_id).ok()
}

/// The named perception-plane sidecar route:
/// `{realm}/session/{id}/sensor/galadriel-pid`.
///
/// The route is built by NCP's fallible key API, so an invalid realm or session ID
/// returns `None` rather than panicking or widening a subscription.
pub fn sidecar_key(realm: &str, session_id: &str) -> Option<String> {
    Keys::try_new(realm)
        .ok()?
        .try_sensor_named(session_id, SIDECAR_SENSOR_NAME)
        .ok()
}

/// [`sidecar_key`] on the default realm.
pub fn default_sidecar_key(session_id: &str) -> Option<String> {
    sidecar_key(DEFAULT_REALM, session_id)
}

#[derive(Debug, Default)]
pub(crate) struct SequenceTracker {
    last: HashMap<(TrackId, Modality), Sequence>,
}

impl SequenceTracker {
    pub(crate) fn accept(
        &mut self,
        observation: &PidObservation,
        max_streams: usize,
    ) -> Result<(), String> {
        let key = (observation.track_id(), observation.modality());
        match self.last.get(&key).copied() {
            Some(last) if observation.sequence() <= last => {
                return Err(format!(
                    "sequence {} is not newer than {} for track {} / {}",
                    observation.sequence(),
                    last,
                    observation.track_id(),
                    observation.modality().label()
                ));
            }
            _ => {}
        }
        if !self.last.contains_key(&key) && self.last.len() >= max_streams {
            return Err(format!(
                "sequence stream count exceeds configured maximum {max_streams}"
            ));
        }
        if !self.last.contains_key(&key) {
            self.last
                .try_reserve(1)
                .map_err(|error| format!("cannot reserve sequence state: {error}"))?;
        }
        self.last.insert(key, observation.sequence());
        Ok(())
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn parse_jsonl_reader<R: BufRead>(
    mut reader: R,
    limits: JsonlLimits,
) -> io::Result<Vec<PidObservation>> {
    let line_read_limit = limits.max_line_bytes.checked_add(2).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "max JSONL line bytes is too large",
        )
    })?;
    let aggregate_probe_limit = limits.max_total_bytes.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "max total JSONL bytes is too large",
        )
    })?;
    let mut line = Vec::with_capacity(limits.max_line_bytes.min(4096));
    let mut out = Vec::new();
    let mut sequences = SequenceTracker::default();
    let mut line_number = 0_usize;
    let mut blank_lines = 0_usize;
    let mut total_bytes = 0_usize;

    loop {
        line.clear();
        let remaining_probe_bytes = aggregate_probe_limit.saturating_sub(total_bytes);
        let read_limit =
            u64::try_from(line_read_limit.min(remaining_probe_bytes)).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "JSONL read limit cannot be represented by this reader",
                )
            })?;
        let bytes_read = (&mut reader)
            .take(read_limit)
            .read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            break;
        }
        line_number = line_number
            .checked_add(1)
            .ok_or_else(|| invalid_data("JSONL line number overflow"))?;
        total_bytes = total_bytes
            .checked_add(bytes_read)
            .ok_or_else(|| invalid_data("total JSONL byte count overflow"))?;
        if total_bytes > limits.max_total_bytes {
            return Err(invalid_data(format!(
                "line {line_number}: total JSONL bytes exceed {}",
                limits.max_total_bytes
            )));
        }

        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.len() > limits.max_line_bytes {
            return Err(invalid_data(format!(
                "line {line_number}: encoded record exceeds {} bytes",
                limits.max_line_bytes
            )));
        }

        let text = std::str::from_utf8(&line)
            .map_err(|error| invalid_data(format!("line {line_number}: invalid UTF-8: {error}")))?
            .trim();
        if text.is_empty() {
            if blank_lines >= limits.max_records {
                return Err(invalid_data(format!(
                    "line {line_number}: blank line count exceeds {}",
                    limits.max_records
                )));
            }
            blank_lines += 1;
            continue;
        }
        if out.len() >= limits.max_records {
            return Err(invalid_data(format!(
                "line {line_number}: record count exceeds {}",
                limits.max_records
            )));
        }

        let observation: PidObservation = serde_json::from_str(text)
            .map_err(|error| invalid_data(format!("line {line_number}: {error}")))?;
        sequences
            .accept(&observation, limits.max_records)
            .map_err(|error| invalid_data(format!("line {line_number}: {error}")))?;
        out.push(observation);
    }

    Ok(out)
}

/// Parse JSONL text (one `PidObservation` JSON object per line) into observations.
/// Blank lines are skipped; malformed, invalid, duplicate, or out-of-order records
/// error with their 1-based line number. Default resource limits apply.
pub fn parse_jsonl(text: &str) -> io::Result<Vec<PidObservation>> {
    parse_jsonl_with_limits(text, bounded_jsonl_limits()?)
}

/// Parse JSONL text with caller-supplied resource limits.
pub fn parse_jsonl_with_limits(text: &str, limits: JsonlLimits) -> io::Result<Vec<PidObservation>> {
    parse_jsonl_reader(Cursor::new(text.as_bytes()), limits)
}

/// Read a JSONL file of `PidObservation` records with bounded streaming I/O.
pub fn read_jsonl(path: impl AsRef<Path>) -> io::Result<Vec<PidObservation>> {
    read_jsonl_with_limits(path, bounded_jsonl_limits()?)
}

/// Read a JSONL file with caller-supplied resource limits.
pub fn read_jsonl_with_limits(
    path: impl AsRef<Path>,
    limits: JsonlLimits,
) -> io::Result<Vec<PidObservation>> {
    parse_jsonl_reader(BufReader::new(File::open(path)?), limits)
}

fn serialize_record(
    observation: &PidObservation,
    record_number: usize,
    line: &mut Vec<u8>,
) -> io::Result<()> {
    line.clear();
    serde_json::to_writer(line, observation)
        .map_err(|error| invalid_data(format!("record {record_number}: {error}")))
}

fn validate_serialization(
    observations: &[PidObservation],
    limits: JsonlLimits,
) -> io::Result<usize> {
    if observations.len() > limits.max_records {
        return Err(invalid_data(format!(
            "record count {} exceeds {}",
            observations.len(),
            limits.max_records
        )));
    }

    let mut sequences = SequenceTracker::default();
    let mut line = Vec::new();
    let mut total_bytes = 0_usize;
    for (index, observation) in observations.iter().enumerate() {
        let record_number = index + 1;
        sequences
            .accept(observation, limits.max_records)
            .map_err(|error| invalid_data(format!("record {record_number}: {error}")))?;
        serialize_record(observation, record_number, &mut line)?;
        if line.len() > limits.max_line_bytes {
            return Err(invalid_data(format!(
                "record {record_number}: encoded record exceeds {} bytes",
                limits.max_line_bytes
            )));
        }
        total_bytes = total_bytes
            .checked_add(usize::from(index > 0))
            .and_then(|total| total.checked_add(line.len()))
            .ok_or_else(|| invalid_data("total serialized JSONL byte count overflow"))?;
        if total_bytes > limits.max_total_bytes {
            return Err(invalid_data(format!(
                "record {record_number}: total serialized JSONL bytes exceed {}",
                limits.max_total_bytes
            )));
        }
    }
    Ok(total_bytes)
}

fn write_jsonl_records<W: Write>(mut writer: W, observations: &[PidObservation]) -> io::Result<()> {
    let mut line = Vec::new();
    for (index, observation) in observations.iter().enumerate() {
        serialize_record(observation, index + 1, &mut line)?;
        if index > 0 {
            writer.write_all(b"\n")?;
        }
        writer.write_all(&line)?;
    }
    writer.flush()
}

/// Serialize validated observations to JSONL text using default resource limits.
pub fn to_jsonl(observations: &[PidObservation]) -> io::Result<String> {
    to_jsonl_with_limits(observations, bounded_jsonl_limits()?)
}

/// Serialize validated observations to JSONL text with caller-supplied limits.
pub fn to_jsonl_with_limits(
    observations: &[PidObservation],
    limits: JsonlLimits,
) -> io::Result<String> {
    let encoded_bytes = validate_serialization(observations, limits)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_bytes)
        .map_err(|error| io::Error::other(format!("cannot reserve JSONL output: {error}")))?;
    write_jsonl_records(&mut bytes, observations)?;
    String::from_utf8(bytes).map_err(|error| invalid_data(error.to_string()))
}

/// Write validated observations to a JSONL file using bounded, streaming output.
pub fn write_jsonl(path: impl AsRef<Path>, observations: &[PidObservation]) -> io::Result<()> {
    write_jsonl_with_limits(path, observations, bounded_jsonl_limits()?)
}

/// Write validated observations to a JSONL file with caller-supplied limits.
/// Validation completes before the destination is created or truncated.
pub fn write_jsonl_with_limits(
    path: impl AsRef<Path>,
    observations: &[PidObservation],
    limits: JsonlLimits,
) -> io::Result<()> {
    validate_serialization(observations, limits)?;
    write_jsonl_records(io::BufWriter::new(File::create(path)?), observations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use galadriel_core::observation::{ConsistencyProjection, Modality};
    use std::{fs, process, thread};

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

    #[test]
    fn jsonl_roundtrips() {
        let obs = vec![
            test_observation(1, 0, 0, Modality::Radar, 3.1, 3),
            test_observation(1, 100, 1, Modality::Acoustic, 4.2, 3),
        ];
        let encoded = to_jsonl(&obs).unwrap();
        let back = parse_jsonl(&encoded).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[1].modality(), Modality::Acoustic);
        assert!((back[0].nis() - 3.1).abs() < 1e-12);
    }

    #[test]
    fn parse_jsonl_skips_blanks_and_reports_bad_lines() {
        let good = to_jsonl(&[test_observation(1, 0, 0, Modality::Visual, 2.0, 3)]).unwrap();
        assert_eq!(parse_jsonl(&format!("\n{good}\n\n")).unwrap().len(), 1);
        let err = parse_jsonl("{not valid json}").unwrap_err();
        assert!(err.to_string().contains("line 1"));
    }

    #[test]
    fn parse_jsonl_rejects_invalid_observation_values() {
        let encoded =
            r#"{"track_id":1,"timestamp_ms":0,"seq":0,"modality":"visual","nis":-0.1,"dof":3}"#;

        let error = parse_jsonl(encoded).unwrap_err();

        assert!(error.to_string().contains("nis must be >= 0"));
    }

    #[test]
    fn parse_jsonl_rejects_duplicate_sequences() {
        let observations = [
            test_observation(1, 0, 4, Modality::Visual, 2.0, 3),
            test_observation(1, 1, 4, Modality::Visual, 2.0, 3),
        ];
        let encoded = observations
            .iter()
            .map(|observation| serde_json::to_string(observation).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let error = parse_jsonl(&encoded).unwrap_err();

        assert!(error.to_string().contains("is not newer"));
    }

    #[test]
    fn parse_jsonl_rejects_regressed_sequences() {
        let observations = [
            test_observation(1, 0, 4, Modality::Visual, 2.0, 3),
            test_observation(1, 1, 3, Modality::Visual, 2.0, 3),
        ];
        let encoded = observations
            .iter()
            .map(|observation| serde_json::to_string(observation).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let error = parse_jsonl(&encoded).unwrap_err();

        assert!(error.to_string().contains("sequence 3 is not newer than 4"));
    }

    #[test]
    fn parse_jsonl_enforces_line_and_record_limits() {
        let observations = [
            test_observation(1, 0, 0, Modality::Visual, 2.0, 3),
            test_observation(1, 1, 1, Modality::Visual, 2.0, 3),
        ];
        let encoded = observations
            .iter()
            .map(|observation| serde_json::to_string(observation).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let line_limit = JsonlLimits::new(8, 2).unwrap();
        let record_limit = JsonlLimits::new(DEFAULT_MAX_JSONL_LINE_BYTES, 1).unwrap();

        let line_error = parse_jsonl_with_limits(&encoded, line_limit).unwrap_err();
        let record_error = parse_jsonl_with_limits(&encoded, record_limit).unwrap_err();

        assert!(line_error.to_string().contains("exceeds 8 bytes"));
        assert!(record_error.to_string().contains("record count exceeds 1"));
    }

    #[test]
    fn parse_jsonl_enforces_aggregate_byte_limit_including_blank_lines() {
        let observation = test_observation(1, 0, 0, Modality::Visual, 2.0, 3);
        let record = serde_json::to_string(&observation).unwrap();
        let encoded = format!("\n\n{record}");
        let limits = JsonlLimits::with_total_bytes(
            record.len(),
            DEFAULT_MAX_JSONL_RECORDS,
            encoded.len() - 1,
        )
        .unwrap();

        let error = parse_jsonl_with_limits(&encoded, limits).unwrap_err();

        assert!(error.to_string().contains("total JSONL bytes exceed"));
    }

    #[test]
    fn serialization_enforces_aggregate_byte_limit() {
        let observations = [
            test_observation(1, 0, 0, Modality::Visual, 2.0, 3),
            test_observation(1, 1, 1, Modality::Visual, 2.0, 3),
        ];
        let encoded = observations
            .iter()
            .map(|observation| serde_json::to_string(observation).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let limits = JsonlLimits::with_total_bytes(
            encoded.lines().map(str::len).max().unwrap(),
            DEFAULT_MAX_JSONL_RECORDS,
            encoded.len() - 1,
        )
        .unwrap();

        let error = to_jsonl_with_limits(&observations, limits).unwrap_err();

        assert!(error
            .to_string()
            .contains("total serialized JSONL bytes exceed"));
    }

    #[test]
    fn aggregate_byte_limit_is_inclusive() {
        let observations = [test_observation(1, 0, 0, Modality::Visual, 2.0, 3)];
        let encoded = serde_json::to_string(&observations[0]).unwrap();
        let limits =
            JsonlLimits::with_total_bytes(encoded.len(), DEFAULT_MAX_JSONL_RECORDS, encoded.len())
                .unwrap();

        let parsed = parse_jsonl_with_limits(&encoded, limits).unwrap();
        let serialized = to_jsonl_with_limits(&observations, limits).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].sequence(), observations[0].sequence());
        assert_eq!(serialized, encoded);
    }

    #[test]
    fn aggregate_serialization_failure_does_not_truncate_destination() {
        let path = std::env::temp_dir().join(format!(
            "galadriel-ncp-aggregate-limit-{}-{:?}.jsonl",
            process::id(),
            thread::current().id()
        ));
        fs::write(&path, b"sentinel").unwrap();
        let observations = [test_observation(1, 0, 0, Modality::Visual, 2.0, 3)];
        let limits = JsonlLimits::with_total_bytes(1, DEFAULT_MAX_JSONL_RECORDS, 1).unwrap();

        write_jsonl_with_limits(&path, &observations, limits).unwrap_err();
        let contents = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();

        assert_eq!(contents, b"sentinel");
    }

    #[test]
    fn jsonl_limits_reject_zero_or_overflowing_aggregate_limit() {
        let zero = JsonlLimits::with_total_bytes(1, 1, 0).unwrap_err();
        let overflow = JsonlLimits::with_total_bytes(1, 1, usize::MAX).unwrap_err();

        assert_eq!(
            zero,
            JsonlLimitsError::Zero {
                field: "max_total_bytes"
            }
        );
        assert_eq!(
            overflow,
            JsonlLimitsError::ExceedsHardMaximum {
                field: "max_total_bytes",
                value: usize::MAX,
                maximum: MAX_JSONL_BYTES,
            }
        );
    }

    #[test]
    fn bounded_jsonl_profile_has_a_stable_identity() {
        let limits = JsonlProfile::BoundedV0_9.try_limits().unwrap();

        assert_eq!(
            limits.identity().to_hex(),
            "3a2901ecb749cc732abab144296b577e8fd846920d3341f420fe0465f411d081"
        );
    }

    #[test]
    fn invalid_observation_cannot_cross_construction_boundary() {
        let invalid = PidObservation::try_scalar_raw(1, 0, 0, Modality::Visual, f64::INFINITY, 3);

        assert!(invalid.is_err());
    }

    #[test]
    fn serialization_rejects_out_of_order_records() {
        let observations = [
            test_observation(1, 0, 2, Modality::Radar, 3.0, 3),
            test_observation(1, 1, 1, Modality::Radar, 3.0, 3),
        ];

        let error = to_jsonl(&observations).unwrap_err();

        assert!(error.to_string().contains("sequence 1 is not newer than 2"));
    }

    /// The **frozen sidecar payload contract** for a producer that opts into every
    /// research field. Baseline-only producers may omit the optional fields, as the
    /// minimal case below demonstrates. The live tap rejects and counts payloads it
    /// cannot decode; if a `galadriel-core` change alters either supported shape,
    /// this test fails and the sidecar contract must be re-versioned deliberately
    /// (and every affected producer updated), never by accident.
    #[test]
    fn sidecar_payload_contract_is_frozen() {
        let projection = ConsistencyProjection::try_new_raw([1.0, -2.5, 0.25], 3, 17, 23, 29)
            .expect("test projection is valid");
        let full = test_observation(42, 1_700_000_000_000, 7, Modality::Radar, 2.75, 3)
            .try_with_research(
                [1.0, -2.5, 0.25],
                [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
            )
            .expect("test research fields are valid")
            .with_consistency_projection(projection);
        let expect_full = concat!(
            r#"{"track_id":42,"timestamp_ms":1700000000000,"seq":7,"#,
            r#""modality":"radar","nis":2.75,"dof":3,"#,
            r#""innovation":[1.0,-2.5,0.25],"#,
            r#""innovation_cov":[[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]],"#,
            r#""consistency_projection":{"values":[1.0,-2.5,0.25],"dimensions":3,"#,
            r#""frame_id":17,"context_id":23,"prior_id":29}}"#
        );
        assert_eq!(serde_json::to_string(&full).unwrap(), expect_full);

        // The baseline-only shape also preserves the frozen v1 zero track identity.
        let minimal =
            r#"{"track_id":0,"timestamp_ms":0,"seq":0,"modality":"acoustic","nis":3.1,"dof":3}"#;
        let obs: PidObservation = serde_json::from_str(minimal).expect("minimal contract parses");
        assert_eq!(obs.track_id().get(), 0);
        assert_eq!(obs.modality(), Modality::Acoustic);
        assert!(obs.innovation().is_none() && obs.innovation_covariance().is_none());
        // And byte-for-byte back out (skip_serializing_if drops the None fields):
        assert_eq!(serde_json::to_string(&obs).unwrap(), minimal);
    }

    #[test]
    fn sidecar_envelope_contract_is_frozen_and_bound_to_provenance() {
        let observation = test_observation(42, 1_700_000_000_000, 7, Modality::Radar, 2.75, 3);
        let envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        let expected = concat!(
            r#"{"kind":"galadriel_pid_observation","schema_version":"1.0","#,
            r#""ncp_version":"0.8","contract_hash":"d1b50a2d8a265276","#,
            r#""session_id":"uav3","producer_id":"crebain","observation":{"#,
            r#""track_id":42,"timestamp_ms":1700000000000,"seq":7,"#,
            r#""modality":"radar","nis":2.75,"dof":3}}"#
        );

        assert_eq!(serde_json::to_string(&envelope).unwrap(), expected);
        assert_eq!(
            envelope.validate_for("uav3", "crebain").unwrap(),
            ContractStatus::Match
        );
    }

    #[test]
    fn sidecar_envelope_deserialization_roundtrips_a_validated_value() {
        let envelope = SidecarEnvelope::try_new(
            "uav3",
            "crebain",
            test_observation(42, 1_700_000_000_000, 7, Modality::Radar, 2.75, 3),
        )
        .unwrap();
        let encoded = serde_json::to_vec(&envelope).unwrap();

        let decoded = serde_json::from_slice::<SidecarEnvelope>(&encoded).unwrap();

        assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
        assert_eq!(decoded.kind(), SIDECAR_KIND);
        assert_eq!(decoded.schema_version(), SIDECAR_SCHEMA_VERSION);
        assert_eq!(decoded.ncp_version(), NCP_VERSION);
        assert_eq!(decoded.contract_hash(), CONTRACT_HASH);
        assert_eq!(decoded.session_id(), "uav3");
        assert_eq!(decoded.producer_id(), "crebain");
        assert_eq!(decoded.observation().sequence().get(), 7);
    }

    #[test]
    fn sidecar_envelope_rejects_unversioned_nested_projection_identity() {
        let projection = ConsistencyProjection::try_new_raw([1.0, -2.5, 0.25], 3, 17, 23, 29)
            .expect("test projection is valid");
        let observation = test_observation(42, 1_700_000_000_000, 7, Modality::Radar, 2.75, 3)
            .with_consistency_projection(projection);
        let envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        let mut raw = serde_json::to_value(envelope).unwrap();
        raw["observation"]["consistency_projection"] = serde_json::json!({
            "values": [1.0, -2.5, 0.25],
            "dimensions": 3,
            "identity": {
                "frame_id": 17,
                "context_id": 23,
                "frozen_prior_id": 29
            }
        });

        assert!(serde_json::from_value::<SidecarEnvelope>(raw).is_err());
    }

    #[test]
    fn sidecar_envelope_deserialization_rejects_semantically_invalid_kind() {
        let envelope = SidecarEnvelope::try_new(
            "uav3",
            "crebain",
            test_observation(1, 1, 1, Modality::Visual, 1.0, 3),
        )
        .unwrap();
        let mut raw = serde_json::to_value(envelope).unwrap();
        raw["kind"] = serde_json::json!("accepted-looking-but-invalid");

        let error = serde_json::from_value::<SidecarEnvelope>(raw).unwrap_err();

        assert!(error.to_string().contains("invalid sidecar kind"));
    }

    #[test]
    fn sidecar_json_schema_identity_matches_the_runtime_contract() {
        let schema: serde_json::Value =
            serde_json::from_str(SIDECAR_SCHEMA_JSON).expect("embedded sidecar schema is JSON");

        assert_eq!(schema["properties"]["kind"]["const"], SIDECAR_KIND);
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            SIDECAR_SCHEMA_VERSION
        );
        assert_eq!(schema["properties"]["ncp_version"]["const"], NCP_VERSION);
        assert_eq!(
            schema["$defs"]["safeUnsignedInteger"]["maximum"],
            JSON_SAFE_INTEGER_MAX
        );
        assert_eq!(
            schema["$defs"]["ncpKeySegment"]["maxLength"],
            MAX_ID_SEGMENT_BYTES
        );
        assert_eq!(
            schema["$defs"]["ncpKeySegment"]["pattern"],
            r"^[^/\*\$#\?\s\u0000-\u001F\u007F-\u009F\uFEFF]+$"
        );
        assert_eq!(
            schema["$defs"]["pidObservation"]["properties"]["track_id"]["$ref"],
            "#/$defs/safeUnsignedInteger"
        );
        assert_eq!(
            schema["$defs"]["consistencyProjection"]["required"],
            serde_json::json!(["values", "dimensions", "frame_id", "context_id", "prior_id"])
        );
        for field in ["frame_id", "context_id", "prior_id"] {
            assert_eq!(
                schema["$defs"]["consistencyProjection"]["properties"][field]["$ref"],
                "#/$defs/safeUnsignedInteger"
            );
        }
        assert!(schema["$defs"].get("projectionIdentity").is_none());
    }

    #[test]
    fn sidecar_envelope_rejects_oversized_identity_segments() {
        let observation = test_observation(1, 1, 1, Modality::Visual, 1.0, 3);
        let oversized = "x".repeat(MAX_ID_SEGMENT_BYTES + 1);
        let at_bound = "x".repeat(MAX_ID_SEGMENT_BYTES);

        // NCP 0.8 bounds session identifiers to 1..=64 bytes; the envelope mirrors it.
        assert!(matches!(
            SidecarEnvelope::try_new(oversized.clone(), "crebain", observation.clone()),
            Err(SidecarEnvelopeError::InvalidSessionId(_))
        ));
        assert!(matches!(
            SidecarEnvelope::try_new("uav3", oversized, observation.clone()),
            Err(SidecarEnvelopeError::InvalidProducerId(_))
        ));
        // Exactly 64 bytes remains valid on both segments.
        assert!(SidecarEnvelope::try_new(at_bound.clone(), at_bound, observation).is_ok());
    }

    #[test]
    fn sidecar_envelope_rejects_unknown_nested_observation_fields() {
        let observation = test_observation(1, 1, 1, Modality::Visual, 1.0, 3);
        let envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        let mut value = serde_json::to_value(envelope).unwrap();
        value["observation"]["undeclared_future_meaning"] = serde_json::json!(true);

        assert!(serde_json::from_value::<SidecarEnvelope>(value).is_err());
    }

    #[test]
    fn sidecar_envelope_rejects_wrong_version_and_provenance() {
        let observation = test_observation(1, 1, 1, Modality::Visual, 1.0, 3);
        let envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        let mut wrong_version = serde_json::to_value(&envelope).unwrap();
        wrong_version["ncp_version"] = serde_json::json!("0.6");
        assert!(serde_json::from_value::<SidecarEnvelope>(wrong_version).is_err());

        let mut noncanonical_version = serde_json::to_value(&envelope).unwrap();
        noncanonical_version["ncp_version"] = serde_json::json!("00.08");
        assert!(serde_json::from_value::<SidecarEnvelope>(noncanonical_version).is_err());

        assert!(matches!(
            envelope.validate_for("uav4", "crebain"),
            Err(SidecarEnvelopeError::ProvenanceMismatch {
                field: "session_id",
                ..
            })
        ));
        assert!(matches!(
            envelope.validate_for("uav3", "other-producer"),
            Err(SidecarEnvelopeError::ProvenanceMismatch {
                field: "producer_id",
                ..
            })
        ));
    }

    #[test]
    fn sidecar_envelope_surfaces_contract_drift_but_rejects_unsafe_integers() {
        let observation = test_observation(1, 1, 1, Modality::Visual, 1.0, 3);
        let envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        let mut drifted = serde_json::to_value(envelope).unwrap();
        drifted["contract_hash"] = serde_json::json!("deadbeefdeadbeef");
        let envelope = serde_json::from_value::<SidecarEnvelope>(drifted).unwrap();
        assert!(matches!(
            envelope.validate().unwrap(),
            ContractStatus::Mismatch { .. }
        ));

        let mut unsafe_envelope = serde_json::to_value(&envelope).unwrap();
        unsafe_envelope["observation"]["track_id"] =
            serde_json::json!(JSON_SAFE_INTEGER_MAX as u64 + 1);
        assert!(serde_json::from_value::<SidecarEnvelope>(unsafe_envelope).is_err());
    }

    #[test]
    fn keys_follow_the_ncp_scheme() {
        assert_eq!(
            sidecar_key("ncp", "uav3").unwrap(),
            "ncp/session/uav3/sensor/galadriel-pid"
        );
        assert!(observation_key("ncp", "uav3")
            .unwrap()
            .contains("session/uav3/observation"));
        // Invalid id segments are rejected.
        assert!(sidecar_key("ncp", "bad id!").is_none());
        assert_eq!(
            sidecar_key("engram/ncp", "uav3").as_deref(),
            Some("engram/ncp/session/uav3/sensor/galadriel-pid")
        );
        assert!(sidecar_key("ncp/**", "uav3").is_none());
        assert!(sidecar_key("ncp//fleet", "uav3").is_none());
        assert!(sidecar_key("/ncp", "uav3").is_none());
        assert!(sidecar_key("ncp/\0fleet", "uav3").is_none());
        assert!(default_sidecar_key("uav3").is_some());
    }

    #[test]
    fn duplicate_json_keys_are_rejected_not_last_wins() {
        // A `serde_json::Value` intermediate collapses duplicate keys (last occurrence
        // wins) BEFORE `deny_unknown_fields` can see them, so a payload carrying an
        // identity field twice could smuggle a first-wins/last-wins parser differential
        // past the provenance gate. The live tap therefore deserializes payloads
        // directly into the typed envelope, which rejects duplicates as a Data error
        // (counted as an invalid envelope, not malformed JSON).
        let envelope = SidecarEnvelope::try_new(
            "uav3",
            "crebain",
            test_observation(1, 100, 0, Modality::Radar, 3.2, 3),
        )
        .expect("valid envelope");
        let json = serde_json::to_string(&envelope).expect("serializable envelope");
        let duplicated = json.replacen(
            "\"session_id\":\"uav3\"",
            "\"session_id\":\"mallory\",\"session_id\":\"uav3\"",
            1,
        );
        assert_ne!(
            json, duplicated,
            "the duplicate key must actually be injected"
        );

        let error = serde_json::from_slice::<SidecarEnvelope>(duplicated.as_bytes())
            .expect_err("typed parse must reject duplicate keys");
        assert_eq!(error.classify(), serde_json::error::Category::Data);

        // The differential this guards against: a Value round-trip accepts silently.
        let value: serde_json::Value =
            serde_json::from_str(&duplicated).expect("plain JSON parse succeeds");
        assert!(
            serde_json::from_value::<SidecarEnvelope>(value).is_ok(),
            "the Value route would have accepted the duplicated payload (last key wins)"
        );
    }
}
