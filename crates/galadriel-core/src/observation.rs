//! The wire types galadriel ingests: [`Modality`] and [`PidObservation`].

use serde::{Deserialize, Serialize};

/// Sensor modality — galadriel-owned. Variants and lowercase serde tags mirror
/// crebain `sensor_fusion::SensorModality` byte-for-byte (`"visual"` …
/// `"radiofrequency"`), so a `PidObservation` serialized by crebain deserializes
/// here with no mapping table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Modality {
    Visual,
    Thermal,
    Acoustic,
    Radar,
    Lidar,
    /// serde tag `"radiofrequency"` (NOT `"rf"`), matching crebain.
    RadioFrequency,
}

impl Modality {
    /// All modalities, in a stable order (their discriminant order).
    pub const ALL: [Modality; 6] = [
        Modality::Visual,
        Modality::Thermal,
        Modality::Acoustic,
        Modality::Radar,
        Modality::Lidar,
        Modality::RadioFrequency,
    ];

    /// A short, stable label for display.
    pub fn label(self) -> &'static str {
        match self {
            Modality::Visual => "visual",
            Modality::Thermal => "thermal",
            Modality::Acoustic => "acoustic",
            Modality::Radar => "radar",
            Modality::Lidar => "lidar",
            Modality::RadioFrequency => "radiofrequency",
        }
    }
}

/// One per-measurement filter-innovation record: emitted by crebain fusion
/// `update_track` (one per associated measurement) and consumed by galadriel.
///
/// `nis` is the Normalized Innovation Squared formed against the **a priori**
/// (predicted, pre-update) track state:
///
/// ```text
///   y   = z - H x̂⁻      (3-vector; radar: polar residual, az wrapped to [-π,π])
///   S   = H P⁻ Hᵀ + R    (3×3)
///   NIS = yᵀ S⁻¹ y        (scalar) ~ χ²(dof),  dof = 3 for this fusion core.
/// ```
///
/// The baseline consumes only `nis` + `dof`; `innovation` / `innovation_cov`
/// feed the optional PID engine's per-channel columns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PidObservation {
    /// Numeric track id — the `u64` behind crebain's `"TRK-%05u"` label.
    pub track_id: u64,
    /// Measurement time, ms since epoch (`SensorMeasurement.timestamp_ms`).
    pub timestamp_ms: u64,
    /// Monotonic fusion frame counter at emit time (`MultiSensorFusion.frame_count`).
    pub seq: u64,
    /// Modality of the measurement that produced this residual.
    pub modality: Modality,
    /// Scalar whitened innovation: `NIS = yᵀ S⁻¹ y ~ χ²(dof)`.
    pub nis: f64,
    /// Innovation dimension / χ² degrees of freedom (3 for this fusion core).
    pub dof: u8,

    // ── Research mode (optional; omitted from the wire when None) ────────────
    /// Raw innovation `y = z - H x̂⁻`. Cartesian `[x,y,z]` m for visual/thermal/
    /// acoustic/lidar; radar polar `[range m, az rad, el rad]`, az wrapped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub innovation: Option<[f64; 3]>,
    /// Innovation covariance `S = H P⁻ Hᵀ + R`, row-major 3×3, same frame as `innovation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub innovation_cov: Option<[[f64; 3]; 3]>,
}

impl PidObservation {
    /// Construct a baseline-only observation (no research-mode innovation).
    pub fn scalar(
        track_id: u64,
        timestamp_ms: u64,
        seq: u64,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> Self {
        Self {
            track_id,
            timestamp_ms,
            seq,
            modality,
            nis,
            dof,
            innovation: None,
            innovation_cov: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modality_serde_tags_match_crebain() {
        assert_eq!(
            serde_json::to_string(&Modality::RadioFrequency).unwrap(),
            "\"radiofrequency\""
        );
        assert_eq!(
            serde_json::to_string(&Modality::Acoustic).unwrap(),
            "\"acoustic\""
        );
        let m: Modality = serde_json::from_str("\"radar\"").unwrap();
        assert_eq!(m, Modality::Radar);
    }

    #[test]
    fn scalar_observation_omits_research_fields() {
        let o = PidObservation::scalar(1, 100, 0, Modality::Radar, 3.2, 3);
        let j = serde_json::to_string(&o).unwrap();
        assert!(
            !j.contains("innovation"),
            "research fields must be omitted when None: {j}"
        );
        let back: PidObservation = serde_json::from_str(&j).unwrap();
        assert_eq!(back.track_id, 1);
        assert_eq!(back.modality, Modality::Radar);
    }
}
