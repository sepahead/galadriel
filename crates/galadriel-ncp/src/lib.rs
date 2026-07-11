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
//! - The live Zenoh tap ([`live::SidecarTap`], `ncp-zenoh`) is a separate, heavier
//!   concern behind the `zenoh` feature (reached via galadriel's `ncp-live`) — it is not
//!   pulled by the default JSONL path.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::path::Path;

use galadriel_core::observation::{Modality, PidObservation};
use ncp_core::{
    contract_status, valid_id_segment, ContractStatus, Keys, CONTRACT_HASH, DEFAULT_REALM,
    JSON_SAFE_INTEGER_MAX, NCP_VERSION,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "zenoh")]
pub mod live;

/// Stable named-perception entity carrying Galadriel sidecar envelopes.
pub const SIDECAR_SENSOR_NAME: &str = "galadriel-pid";

/// Sidecar payload discriminator. This is deliberately not an NCP normative
/// message kind; the envelope is project-owned and versioned independently.
pub const SIDECAR_KIND: &str = "galadriel_pid_observation";

/// Current Galadriel sidecar schema. An incompatible shape requires a new value
/// and coordinated producer/consumer update.
pub const SIDECAR_SCHEMA_VERSION: &str = "1.0";

/// Machine-readable JSON Schema for [`SIDECAR_SCHEMA_VERSION`]. Semantic checks
/// that JSON Schema cannot express (paired research fields, covariance positive
/// definiteness, inactive projection axes, and provenance binding) remain enforced
/// by [`SidecarEnvelope::validate_for`].
pub const SIDECAR_SCHEMA_JSON: &str =
    include_str!("../schemas/galadriel-pid-envelope-v1.schema.json");

/// A validated live-sidecar envelope.
///
/// The payload-level `producer_id` is an authenticated *claim* only when the
/// transport identity/ACL binds the publisher. It is not a signature. A fresh NCP
/// `session_id` is the producer epoch boundary; producers must not reuse it after a
/// restart that resets observation sequences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SidecarEnvelope {
    /// Stable discriminator, [`SIDECAR_KIND`].
    pub kind: String,
    /// Galadriel-owned envelope schema, [`SIDECAR_SCHEMA_VERSION`].
    pub schema_version: String,
    /// NCP wire version governing the named-perception route.
    pub ncp_version: String,
    /// Advisory identity of the NCP contract revision used by the producer.
    pub contract_hash: String,
    /// NCP session/producer epoch. Must equal the subscribed path segment.
    pub session_id: String,
    /// Concrete producer identifier, for example `"crebain"`.
    pub producer_id: String,
    /// The existing, frozen Crebain/Galadriel observation contract.
    pub observation: PidObservation,
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
        let envelope = Self {
            kind: SIDECAR_KIND.to_string(),
            schema_version: SIDECAR_SCHEMA_VERSION.to_string(),
            ncp_version: NCP_VERSION.to_string(),
            contract_hash: CONTRACT_HASH.to_string(),
            session_id: session_id.into(),
            producer_id: producer_id.into(),
            observation,
        };
        envelope.validate()?;
        Ok(envelope)
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
        if !valid_id_segment(&self.session_id) {
            return Err(SidecarEnvelopeError::InvalidSessionId(
                self.session_id.clone(),
            ));
        }
        if !valid_id_segment(&self.producer_id) {
            return Err(SidecarEnvelopeError::InvalidProducerId(
                self.producer_id.clone(),
            ));
        }
        self.observation
            .validate()
            .map_err(|error| SidecarEnvelopeError::InvalidObservation(error.to_string()))?;
        self.validate_json_integer("observation.track_id", self.observation.track_id)?;
        self.validate_json_integer("observation.timestamp_ms", self.observation.timestamp_ms)?;
        self.validate_json_integer("observation.seq", self.observation.seq)?;
        if let Some(projection) = self.observation.consistency_projection {
            self.validate_json_integer(
                "observation.consistency_projection.frame_id",
                projection.frame_id,
            )?;
            self.validate_json_integer(
                "observation.consistency_projection.context_id",
                projection.context_id,
            )?;
            self.validate_json_integer(
                "observation.consistency_projection.prior_id",
                projection.prior_id,
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

/// Maximum encoded bytes in one JSONL record under [`JsonlLimits::default`].
pub const DEFAULT_MAX_JSONL_LINE_BYTES: usize = 64 * 1024;

/// Maximum observations accepted by one JSONL operation under [`JsonlLimits::default`].
pub const DEFAULT_MAX_JSONL_RECORDS: usize = 100_000;

/// Maximum aggregate encoded bytes accepted or produced by one JSONL operation.
pub const DEFAULT_MAX_JSONL_BYTES: usize = 64 * 1024 * 1024;

/// Resource limits for JSONL ingest and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonlLimits {
    max_line_bytes: usize,
    max_records: usize,
    max_total_bytes: usize,
}

impl JsonlLimits {
    /// Build nonzero line and record limits with [`DEFAULT_MAX_JSONL_BYTES`] as the
    /// aggregate input/output ceiling.
    pub fn new(max_line_bytes: usize, max_records: usize) -> io::Result<Self> {
        Self::with_total_bytes(max_line_bytes, max_records, DEFAULT_MAX_JSONL_BYTES)
    }

    /// Build nonzero line, record, and aggregate-byte limits.
    pub fn with_total_bytes(
        max_line_bytes: usize,
        max_records: usize,
        max_total_bytes: usize,
    ) -> io::Result<Self> {
        if max_line_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max JSONL line bytes must be greater than zero",
            ));
        }
        if max_records == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max JSONL records must be greater than zero",
            ));
        }
        if max_total_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max total JSONL bytes must be greater than zero",
            ));
        }
        max_line_bytes.checked_add(2).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "max JSONL line bytes is too large",
            )
        })?;
        max_total_bytes.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "max total JSONL bytes is too large",
            )
        })?;
        Ok(Self {
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
}

impl Default for JsonlLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: DEFAULT_MAX_JSONL_LINE_BYTES,
            max_records: DEFAULT_MAX_JSONL_RECORDS,
            max_total_bytes: DEFAULT_MAX_JSONL_BYTES,
        }
    }
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
    last: HashMap<(u64, Modality), u64>,
}

impl SequenceTracker {
    pub(crate) fn accept(
        &mut self,
        observation: &PidObservation,
        max_streams: usize,
    ) -> Result<(), String> {
        let key = (observation.track_id, observation.modality);
        match self.last.get(&key).copied() {
            Some(last) if observation.seq <= last => {
                return Err(format!(
                    "sequence {} is not newer than {} for track {} / {}",
                    observation.seq,
                    last,
                    observation.track_id,
                    observation.modality.label()
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
        self.last.insert(key, observation.seq);
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
        observation
            .validate()
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
    parse_jsonl_with_limits(text, JsonlLimits::default())
}

/// Parse JSONL text with caller-supplied resource limits.
pub fn parse_jsonl_with_limits(text: &str, limits: JsonlLimits) -> io::Result<Vec<PidObservation>> {
    parse_jsonl_reader(Cursor::new(text.as_bytes()), limits)
}

/// Read a JSONL file of `PidObservation` records with bounded streaming I/O.
pub fn read_jsonl(path: impl AsRef<Path>) -> io::Result<Vec<PidObservation>> {
    read_jsonl_with_limits(path, JsonlLimits::default())
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
        observation
            .validate()
            .map_err(|error| invalid_data(format!("record {record_number}: {error}")))?;
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
    to_jsonl_with_limits(observations, JsonlLimits::default())
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
    write_jsonl_with_limits(path, observations, JsonlLimits::default())
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

    #[test]
    fn jsonl_roundtrips() {
        let obs = vec![
            PidObservation::scalar(1, 0, 0, Modality::Radar, 3.1, 3),
            PidObservation::scalar(1, 100, 1, Modality::Acoustic, 4.2, 3),
        ];
        let encoded = to_jsonl(&obs).unwrap();
        let back = parse_jsonl(&encoded).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[1].modality, Modality::Acoustic);
        assert!((back[0].nis - 3.1).abs() < 1e-12);
    }

    #[test]
    fn parse_jsonl_skips_blanks_and_reports_bad_lines() {
        let good = to_jsonl(&[PidObservation::scalar(1, 0, 0, Modality::Visual, 2.0, 3)]).unwrap();
        assert_eq!(parse_jsonl(&format!("\n{good}\n\n")).unwrap().len(), 1);
        let err = parse_jsonl("{not valid json}").unwrap_err();
        assert!(err.to_string().contains("line 1"));
    }

    #[test]
    fn parse_jsonl_rejects_invalid_observation_values() {
        let invalid = PidObservation::scalar(1, 0, 0, Modality::Visual, -0.1, 3);
        let encoded = serde_json::to_string(&invalid).unwrap();

        let error = parse_jsonl(&encoded).unwrap_err();

        assert!(error.to_string().contains("nis must be >= 0"));
    }

    #[test]
    fn parse_jsonl_rejects_duplicate_sequences() {
        let observations = [
            PidObservation::scalar(1, 0, 4, Modality::Visual, 2.0, 3),
            PidObservation::scalar(1, 1, 4, Modality::Visual, 2.0, 3),
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
            PidObservation::scalar(1, 0, 4, Modality::Visual, 2.0, 3),
            PidObservation::scalar(1, 1, 3, Modality::Visual, 2.0, 3),
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
            PidObservation::scalar(1, 0, 0, Modality::Visual, 2.0, 3),
            PidObservation::scalar(1, 1, 1, Modality::Visual, 2.0, 3),
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
        let observation = PidObservation::scalar(1, 0, 0, Modality::Visual, 2.0, 3);
        let encoded = format!("\n\n{}", serde_json::to_string(&observation).unwrap());
        let limits = JsonlLimits::with_total_bytes(
            DEFAULT_MAX_JSONL_LINE_BYTES,
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
            PidObservation::scalar(1, 0, 0, Modality::Visual, 2.0, 3),
            PidObservation::scalar(1, 1, 1, Modality::Visual, 2.0, 3),
        ];
        let encoded = observations
            .iter()
            .map(|observation| serde_json::to_string(observation).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let limits = JsonlLimits::with_total_bytes(
            DEFAULT_MAX_JSONL_LINE_BYTES,
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
        let observations = [PidObservation::scalar(1, 0, 0, Modality::Visual, 2.0, 3)];
        let encoded = serde_json::to_string(&observations[0]).unwrap();
        let limits = JsonlLimits::with_total_bytes(
            DEFAULT_MAX_JSONL_LINE_BYTES,
            DEFAULT_MAX_JSONL_RECORDS,
            encoded.len(),
        )
        .unwrap();

        let parsed = parse_jsonl_with_limits(&encoded, limits).unwrap();
        let serialized = to_jsonl_with_limits(&observations, limits).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].seq, observations[0].seq);
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
        let observations = [PidObservation::scalar(1, 0, 0, Modality::Visual, 2.0, 3)];
        let limits = JsonlLimits::with_total_bytes(
            DEFAULT_MAX_JSONL_LINE_BYTES,
            DEFAULT_MAX_JSONL_RECORDS,
            1,
        )
        .unwrap();

        write_jsonl_with_limits(&path, &observations, limits).unwrap_err();
        let contents = fs::read(&path).unwrap();
        fs::remove_file(path).unwrap();

        assert_eq!(contents, b"sentinel");
    }

    #[test]
    fn jsonl_limits_reject_zero_or_overflowing_aggregate_limit() {
        let zero = JsonlLimits::with_total_bytes(1, 1, 0).unwrap_err();
        let overflow = JsonlLimits::with_total_bytes(1, 1, usize::MAX).unwrap_err();

        assert_eq!(zero.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(overflow.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn serialization_is_fallible_and_validated() {
        let invalid = [PidObservation::scalar(
            1,
            0,
            0,
            Modality::Visual,
            f64::INFINITY,
            3,
        )];

        let error = to_jsonl(&invalid).unwrap_err();

        assert!(error.to_string().contains("non-finite"));
    }

    #[test]
    fn serialization_rejects_out_of_order_records() {
        let observations = [
            PidObservation::scalar(1, 0, 2, Modality::Radar, 3.0, 3),
            PidObservation::scalar(1, 1, 1, Modality::Radar, 3.0, 3),
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
        let full = PidObservation {
            track_id: 42,
            timestamp_ms: 1_700_000_000_000,
            seq: 7,
            modality: Modality::Radar,
            nis: 2.75,
            dof: 3,
            innovation: Some([1.0, -2.5, 0.25]),
            innovation_cov: Some([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]]),
            consistency_projection: Some(ConsistencyProjection {
                values: [1.0, -2.5, 0.25],
                dimensions: 3,
                frame_id: 17,
                context_id: 23,
                prior_id: 29,
            }),
        };
        let expect_full = concat!(
            r#"{"track_id":42,"timestamp_ms":1700000000000,"seq":7,"#,
            r#""modality":"radar","nis":2.75,"dof":3,"#,
            r#""innovation":[1.0,-2.5,0.25],"#,
            r#""innovation_cov":[[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]],"#,
            r#""consistency_projection":{"values":[1.0,-2.5,0.25],"dimensions":3,"#,
            r#""frame_id":17,"context_id":23,"prior_id":29}}"#
        );
        assert_eq!(serde_json::to_string(&full).unwrap(), expect_full);

        // The baseline-only (research fields omitted) shape, as a consumer:
        let minimal =
            r#"{"track_id":1,"timestamp_ms":0,"seq":0,"modality":"acoustic","nis":3.1,"dof":3}"#;
        let obs: PidObservation = serde_json::from_str(minimal).expect("minimal contract parses");
        assert_eq!(obs.modality, Modality::Acoustic);
        assert!(obs.innovation.is_none() && obs.innovation_cov.is_none());
        // And byte-for-byte back out (skip_serializing_if drops the None fields):
        assert_eq!(serde_json::to_string(&obs).unwrap(), minimal);
    }

    #[test]
    fn sidecar_envelope_contract_is_frozen_and_bound_to_provenance() {
        let observation =
            PidObservation::scalar(42, 1_700_000_000_000, 7, Modality::Radar, 2.75, 3);
        let envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        let expected = concat!(
            r#"{"kind":"galadriel_pid_observation","schema_version":"1.0","#,
            r#""ncp_version":"0.7","contract_hash":"f05e328cad20959d","#,
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
            schema["$defs"]["ncpKeySegment"]["pattern"],
            r"^[^/\*\$#\?\s\u0000-\u001F\u007F-\u009F\uFEFF]+$"
        );
    }

    #[test]
    fn sidecar_envelope_rejects_unknown_nested_observation_fields() {
        let observation = PidObservation::scalar(1, 1, 1, Modality::Visual, 1.0, 3);
        let envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        let mut value = serde_json::to_value(envelope).unwrap();
        value["observation"]["undeclared_future_meaning"] = serde_json::json!(true);

        assert!(serde_json::from_value::<SidecarEnvelope>(value).is_err());
    }

    #[test]
    fn sidecar_envelope_rejects_wrong_version_and_provenance() {
        let observation = PidObservation::scalar(1, 1, 1, Modality::Visual, 1.0, 3);
        let mut envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        envelope.ncp_version = "0.6".to_string();
        assert!(matches!(
            envelope.validate(),
            Err(SidecarEnvelopeError::IncompatibleNcpVersion(_))
        ));

        envelope.ncp_version = NCP_VERSION.to_string();
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
        let observation = PidObservation::scalar(1, 1, 1, Modality::Visual, 1.0, 3);
        let mut envelope = SidecarEnvelope::try_new("uav3", "crebain", observation).unwrap();
        envelope.contract_hash = "deadbeefdeadbeef".to_string();
        assert!(matches!(
            envelope.validate().unwrap(),
            ContractStatus::Mismatch { .. }
        ));

        envelope.observation.track_id = JSON_SAFE_INTEGER_MAX as u64 + 1;
        assert!(matches!(
            envelope.validate(),
            Err(SidecarEnvelopeError::IntegerOutOfRange {
                field: "observation.track_id",
                ..
            })
        ));
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
            galadriel_core::PidObservation::scalar(
                1,
                100,
                0,
                galadriel_core::Modality::Radar,
                3.2,
                3,
            ),
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
