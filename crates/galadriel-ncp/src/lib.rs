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
