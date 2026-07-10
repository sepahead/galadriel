#![forbid(unsafe_code)]
//! # galadriel-ncp
//!
//! NCP observation-plane ingest for Galadriel's Mirror (feature `ncp`).
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
//! - `PidObservation` is **not** an NCP wire message: it rides a **non-wire sidecar
//!   key** additively under the session, so it never touches the normative proto or
//!   `CONTRACT_HASH`. [`sidecar_key`] builds it from the NCP key scheme (`ncp-core`
//!   [`Keys`]), and [`observation_key`] gives the canonical read-only observation key
//!   galadriel would subscribe to.
//! - The live Zenoh tap ([`live::SidecarTap`], `ncp-zenoh`) is a separate, heavier
//!   concern behind the `zenoh` feature (reached via galadriel's `ncp-live`) — it is not
//!   pulled by the default JSONL path.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::path::Path;

use galadriel_core::observation::{Modality, PidObservation};
use ncp_core::{valid_id_segment, Keys, DEFAULT_REALM};

#[cfg(feature = "zenoh")]
pub mod live;

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
    realm
        .split('/')
        .all(|segment| valid_id_segment(segment) && !segment.chars().any(char::is_control))
}

/// The canonical NCP observation-plane key for a session:
/// `{realm}/session/{id}/observation` — the read-only tap galadriel subscribes to.
/// Returns `None` if the realm is not concrete or `session_id` is not a valid
/// NCP id segment.
pub fn observation_key(realm: &str, session_id: &str) -> Option<String> {
    (valid_realm(realm) && valid_id_segment(session_id))
        .then(|| Keys::new(realm).observation(session_id))
}

/// The non-wire **sidecar key** galadriel's `PidObservation` rides — additive under
/// the session (`{realm}/session/{id}/galadriel/pid`), so it never touches NCP's
/// normative wire / `CONTRACT_HASH`. Returns `None` for an invalid realm or id
/// segment.
pub fn sidecar_key(realm: &str, session_id: &str) -> Option<String> {
    (valid_realm(realm) && valid_id_segment(session_id))
        .then(|| format!("{realm}/session/{session_id}/galadriel/pid"))
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
    fn keys_follow_the_ncp_scheme() {
        assert_eq!(
            sidecar_key("ncp", "uav3").unwrap(),
            "ncp/session/uav3/galadriel/pid"
        );
        assert!(observation_key("ncp", "uav3")
            .unwrap()
            .contains("session/uav3/observation"));
        // Invalid id segments are rejected.
        assert!(sidecar_key("ncp", "bad id!").is_none());
        assert_eq!(
            sidecar_key("engram/ncp", "uav3").as_deref(),
            Some("engram/ncp/session/uav3/galadriel/pid")
        );
        assert!(sidecar_key("ncp/**", "uav3").is_none());
        assert!(sidecar_key("ncp//fleet", "uav3").is_none());
        assert!(sidecar_key("/ncp", "uav3").is_none());
        assert!(sidecar_key("ncp/\0fleet", "uav3").is_none());
        assert!(default_sidecar_key("uav3").is_some());
    }
}
