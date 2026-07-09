#![forbid(unsafe_code)]
//! # galadriel-ncp
//!
//! NCP observation-plane ingest for Galadriel's Mirror (feature `ncp`).
//!
//! galadriel is a **read-only** consumer of per-measurement innovation records.
//! In the ecosystem those ride the NCP observation plane; this crate is the seam
//! that turns them into [`galadriel_core::PidObservation`]s.
//!
//! ## Transport, honestly scoped
//!
//! - **The MVP path is transport-free JSONL** — no Zenoh, no tokio, no network —
//!   which is a first-class NCP flow (`ncp-observe` and the reference UAV loop both
//!   emit JSONL). [`read_jsonl`] / [`parse_jsonl`] / [`write_jsonl`] cover it.
//! - `PidObservation` is **not** an NCP wire message: it rides a **non-wire sidecar
//!   key** additively under the session, so it never touches the normative proto or
//!   `CONTRACT_HASH`. [`sidecar_key`] builds it from the NCP key scheme (`ncp-core`
//!   [`Keys`]), and [`observation_key`] gives the canonical read-only observation key
//!   galadriel would subscribe to.
//! - The live Zenoh tap ([`live::SidecarTap`], `ncp-zenoh`) is a separate, heavier
//!   concern behind the `zenoh` feature (reached via galadriel's `ncp-live`) — it is not
//!   pulled by the default JSONL path.

use std::fs;
use std::io;
use std::path::Path;

use galadriel_core::observation::PidObservation;
use ncp_core::{valid_id_segment, Keys, DEFAULT_REALM};

#[cfg(feature = "zenoh")]
pub mod live;

/// The canonical NCP observation-plane key for a session:
/// `{realm}/session/{id}/observation` — the read-only tap galadriel subscribes to.
/// Returns `None` if `session_id` is not a valid NCP id segment.
pub fn observation_key(realm: &str, session_id: &str) -> Option<String> {
    valid_id_segment(session_id).then(|| Keys::new(realm).observation(session_id))
}

/// The non-wire **sidecar key** galadriel's `PidObservation` rides — additive under
/// the session (`{realm}/session/{id}/galadriel/pid`), so it never touches NCP's
/// normative wire / `CONTRACT_HASH`. Returns `None` for an invalid id segment.
pub fn sidecar_key(realm: &str, session_id: &str) -> Option<String> {
    valid_id_segment(session_id).then(|| format!("{realm}/session/{session_id}/galadriel/pid"))
}

/// [`sidecar_key`] on the default realm.
pub fn default_sidecar_key(session_id: &str) -> Option<String> {
    sidecar_key(DEFAULT_REALM, session_id)
}

/// Parse JSONL text (one `PidObservation` JSON object per line) into observations.
/// Blank lines are skipped; a malformed line errors with its 1-based line number.
pub fn parse_jsonl(text: &str) -> io::Result<Vec<PidObservation>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obs: PidObservation = serde_json::from_str(line).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("line {}: {e}", i + 1))
        })?;
        out.push(obs);
    }
    Ok(out)
}

/// Read a JSONL file of `PidObservation` records.
pub fn read_jsonl(path: impl AsRef<Path>) -> io::Result<Vec<PidObservation>> {
    parse_jsonl(&fs::read_to_string(path)?)
}

/// Serialize observations to JSONL text (one compact JSON object per line).
pub fn to_jsonl(observations: &[PidObservation]) -> String {
    observations
        .iter()
        .map(|o| serde_json::to_string(o).expect("PidObservation serializes"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write observations to a JSONL file (the sidecar capture format).
pub fn write_jsonl(path: impl AsRef<Path>, observations: &[PidObservation]) -> io::Result<()> {
    fs::write(path, to_jsonl(observations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use galadriel_core::observation::Modality;

    #[test]
    fn jsonl_roundtrips() {
        let obs = vec![
            PidObservation::scalar(1, 0, 0, Modality::Radar, 3.1, 3),
            PidObservation::scalar(1, 100, 1, Modality::Acoustic, 4.2, 3),
        ];
        let back = parse_jsonl(&to_jsonl(&obs)).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[1].modality, Modality::Acoustic);
        assert!((back[0].nis - 3.1).abs() < 1e-12);
    }

    #[test]
    fn parse_jsonl_skips_blanks_and_reports_bad_lines() {
        let good = to_jsonl(&[PidObservation::scalar(1, 0, 0, Modality::Visual, 2.0, 3)]);
        assert_eq!(parse_jsonl(&format!("\n{good}\n\n")).unwrap().len(), 1);
        let err = parse_jsonl("{not valid json}").unwrap_err();
        assert!(err.to_string().contains("line 1"));
    }

    /// The **frozen sidecar payload contract**. Any producer — crebain's Rust
    /// emitter, a TS publisher — writes exactly this JSON shape onto
    /// `{realm}/session/{id}/galadriel/pid`; the live tap *silently drops* what it
    /// cannot decode, so an unnoticed wire change would surface as "no data", the
    /// worst failure mode for a monitor. If a `galadriel-core` change alters this
    /// serialization, this test fails and the sidecar contract must be re-versioned
    /// deliberately (and every producer updated), never by accident.
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
        };
        let expect_full = concat!(
            r#"{"track_id":42,"timestamp_ms":1700000000000,"seq":7,"#,
            r#""modality":"radar","nis":2.75,"dof":3,"#,
            r#""innovation":[1.0,-2.5,0.25],"#,
            r#""innovation_cov":[[1.0,0.0,0.0],[0.0,1.0,0.0],[0.0,0.0,1.0]]}"#
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
        assert!(default_sidecar_key("uav3").is_some());
    }
}
