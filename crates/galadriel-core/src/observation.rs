//! The wire types galadriel ingests: [`Modality`] and [`PidObservation`].

use serde::{Deserialize, Serialize};

/// Relative covariance-symmetry tolerance, measured against
/// `sqrt(S[i][i] * S[j][j])` for each off-diagonal pair.
pub const COVARIANCE_SYMMETRY_RELATIVE_TOLERANCE: f64 = 1e-9;

/// Maximum number of axes carried by a producer-attested consistency projection.
pub const MAX_CONSISTENCY_PROJECTION_AXES: usize = 3;

/// A bounded residual projection that is explicitly comparable across modalities.
///
/// This is distinct from [`PidObservation::innovation`]. A raw filter innovation may
/// be expressed in a modality-specific measurement space (for example, radar polar
/// coordinates versus camera Cartesian coordinates) and may have been computed
/// after another modality already updated the track. Such values are never valid
/// cross-sensor consistency inputs.
///
/// Presence of this object is a producer attestation that:
///
/// - `values[..dimensions]` use the same physical `frame_id` and projection/basis
///   definition (`context_id`) for every requested modality;
/// - every modality at one fusion sequence was projected from the same frozen,
///   pre-update state snapshot (`prior_id`); and
/// - `prior_id` identifies only that snapshot and is not reused at another sequence.
///
/// The identifiers are provenance labels, not authentication. The transport must
/// still authenticate and authorize the producer.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyProjection {
    /// Projected signed residual values. Only `[..dimensions]` is active.
    pub values: [f64; MAX_CONSISTENCY_PROJECTION_AXES],
    /// Number of active axes, in `1..=MAX_CONSISTENCY_PROJECTION_AXES`.
    pub dimensions: u8,
    /// Producer-defined identifier for the common physical coordinate frame.
    pub frame_id: u64,
    /// Producer-defined identifier for the projection basis and calibration context.
    pub context_id: u64,
    /// Producer-defined identifier for the common frozen prior snapshot.
    pub prior_id: u64,
}

impl ConsistencyProjection {
    /// Validate the bounded payload and provenance identifiers.
    pub fn validate(&self) -> crate::Result<()> {
        use crate::GaladrielError::{InvalidObservation, NonFinite};

        if !(1..=MAX_CONSISTENCY_PROJECTION_AXES as u8).contains(&self.dimensions) {
            return Err(InvalidObservation(format!(
                "consistency projection dimensions must be in 1..={MAX_CONSISTENCY_PROJECTION_AXES}"
            )));
        }
        if self.frame_id == 0 || self.context_id == 0 || self.prior_id == 0 {
            return Err(InvalidObservation(
                "consistency projection frame_id, context_id, and prior_id must be non-zero".into(),
            ));
        }
        if !self.values.iter().all(|value| value.is_finite()) {
            return Err(NonFinite("PidObservation::consistency_projection"));
        }
        if self.values[self.dimensions as usize..]
            .iter()
            .any(|value| *value != 0.0)
        {
            return Err(InvalidObservation(
                "inactive consistency projection axes must be zero".into(),
            ));
        }
        Ok(())
    }
}

fn covariance_pair_scale(left_diagonal: f64, right_diagonal: f64) -> f64 {
    if left_diagonal == right_diagonal {
        return left_diagonal;
    }
    let scale = left_diagonal.sqrt() * right_diagonal.sqrt();
    if scale.is_finite() {
        scale
    } else {
        // The exact geometric mean lies between the two finite positive inputs.
        // Overflow is only a rounding artifact near f64::MAX; the larger diagonal
        // is a conservative finite normalization for the symmetry check.
        left_diagonal.max(right_diagonal)
    }
}

/// Validate a 3×3 innovation covariance and return its symmetric representation.
///
/// Wire-format covariance can contain tiny asymmetric roundoff from matrix
/// arithmetic. Differences are judged relative to the per-pair covariance scale,
/// then accepted pairs are averaged before the positive-definiteness test. Callers
/// performing a Cholesky solve should use the returned matrix rather than either
/// original triangle.
pub fn validate_and_symmetrize_covariance(
    mut covariance: [[f64; 3]; 3],
) -> crate::Result<[[f64; 3]; 3]> {
    use crate::GaladrielError::{InvalidObservation, NonFinite};

    if !covariance.iter().flatten().all(|value| value.is_finite()) {
        return Err(NonFinite("PidObservation::innovation_cov"));
    }
    if covariance.iter().enumerate().any(|(i, row)| row[i] <= 0.0) {
        return Err(InvalidObservation(
            "innovation_cov diagonal must be strictly positive".into(),
        ));
    }
    for i in 0..3 {
        for j in (i + 1)..3 {
            let pair_scale = covariance_pair_scale(covariance[i][i], covariance[j][j]);
            let normalized_difference =
                covariance[i][j] / pair_scale - covariance[j][i] / pair_scale;
            if !normalized_difference.is_finite()
                || normalized_difference.abs() > COVARIANCE_SYMMETRY_RELATIVE_TOLERANCE
            {
                return Err(InvalidObservation(
                    "innovation_cov must be symmetric within its per-pair covariance scale".into(),
                ));
            }
            let symmetric = covariance[i][j] / 2.0 + covariance[j][i] / 2.0;
            covariance[i][j] = symmetric;
            covariance[j][i] = symmetric;
        }
    }

    // Positive diagonal entries are not enough: a symmetric covariance can still
    // be indefinite. Scale first to avoid overflow, then apply Sylvester's
    // criterion to the symmetrized 3x3 matrix.
    let scale = covariance
        .iter()
        .flatten()
        .map(|value| value.abs())
        .fold(0.0_f64, f64::max);
    let a = covariance[0][0] / scale;
    let b = covariance[0][1] / scale;
    let c = covariance[0][2] / scale;
    let d = covariance[1][1] / scale;
    let e = covariance[1][2] / scale;
    let f = covariance[2][2] / scale;
    let det2 = a * d - b * b;
    let det3 = a * (d * f - e * e) - b * (b * f - c * e) + c * (b * e - c * d);
    if !(a > 0.0 && det2 > 0.0 && det3 > 0.0) {
        return Err(InvalidObservation(
            "innovation_cov must be positive definite".into(),
        ));
    }
    Ok(covariance)
}

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
/// The baseline consumes only `nis` + `dof`. `innovation` / `innovation_cov` are
/// modality-native diagnostic fields. Cross-sensor consistency detectors consume
/// only [`ConsistencyProjection`], never those raw innovations.
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
    /// Optional producer-attested common consistency projection. Existing captures
    /// without this metadata remain valid for the NIS baseline, but consistency
    /// assessment fails closed as insufficient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_projection: Option<ConsistencyProjection>,
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
            consistency_projection: None,
        }
    }

    /// Validate the numeric and research-field invariants required by every detector.
    ///
    /// This deliberately does not authenticate the producer or prove that `nis` was
    /// computed from the supplied innovation. It only rejects values that would make
    /// statistical processing undefined or make the optional research payload
    /// internally incomplete.
    pub fn validate(&self) -> crate::Result<()> {
        use crate::GaladrielError::{InvalidObservation, NonFinite};

        if self.seq == u64::MAX {
            return Err(InvalidObservation(
                "seq must be less than u64::MAX so a newer observation remains representable"
                    .into(),
            ));
        }
        if self.timestamp_ms == u64::MAX {
            return Err(InvalidObservation(
                "timestamp_ms must be less than u64::MAX so a newer timestamp remains representable"
                    .into(),
            ));
        }
        if !self.nis.is_finite() {
            return Err(NonFinite("PidObservation::nis"));
        }
        if self.nis < 0.0 {
            return Err(InvalidObservation("nis must be >= 0".into()));
        }
        if self.dof == 0 {
            return Err(InvalidObservation("dof must be > 0".into()));
        }
        if self.innovation.is_some() != self.innovation_cov.is_some() {
            return Err(InvalidObservation(
                "innovation and innovation_cov must either both be present or both be absent"
                    .into(),
            ));
        }
        if let Some(innovation) = self.innovation {
            if self.dof != 3 {
                return Err(InvalidObservation(
                    "research-mode [f64; 3] innovations require dof == 3".into(),
                ));
            }
            if !innovation.iter().all(|value| value.is_finite()) {
                return Err(NonFinite("PidObservation::innovation"));
            }
        }
        if let Some(covariance) = self.innovation_cov {
            validate_and_symmetrize_covariance(covariance)?;
        }
        if let Some(projection) = self.consistency_projection {
            projection.validate()?;
        }
        Ok(())
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
        assert!(back.validate().is_ok());
    }

    #[test]
    fn validation_rejects_values_that_can_poison_numeric_state() {
        let mut observation = PidObservation::scalar(1, 100, 0, Modality::Radar, f64::NAN, 3);
        assert!(observation.validate().is_err());

        observation.nis = -1.0;
        assert!(observation.validate().is_err());

        observation.nis = 3.0;
        observation.dof = 0;
        assert!(observation.validate().is_err());

        observation.dof = 3;
        observation.innovation = Some([0.0; 3]);
        assert!(
            observation.validate().is_err(),
            "research fields must be paired"
        );

        observation.innovation_cov =
            Some([[1e-12, 0.0, 0.0], [1e-10, 1e-12, 0.0], [0.0, 0.0, 1e-12]]);
        assert!(
            observation.validate().is_err(),
            "symmetry tolerance must be relative even for small covariances"
        );
    }

    #[test]
    fn covariance_validation_accepts_roundoff_and_returns_a_symmetric_matrix() {
        let covariance = [
            [
                1.588_373_458_602_466_3,
                8.673_617_379_884_035e-19,
                -4.336_808_689_942_018e-19,
            ],
            [
                0.0,
                0.001_170_253_521_333_416_1,
                -3.388_131_789_017_201_4e-21,
            ],
            [
                -4.336_808_689_942_018e-19,
                -3.388_131_789_017_201_4e-21,
                0.001_153_509_640_919_248_5,
            ],
        ];
        let symmetric = validate_and_symmetrize_covariance(covariance)
            .expect("fixture-scale floating-point roundoff must be accepted");
        assert_eq!(symmetric[0][1], symmetric[1][0]);
    }

    #[test]
    fn covariance_validation_rejects_material_asymmetry_at_tiny_scale() {
        let covariance = [[1e-12, 0.0, 0.0], [1e-18, 1e-12, 0.0], [0.0, 0.0, 1e-12]];
        assert!(validate_and_symmetrize_covariance(covariance).is_err());
    }

    #[test]
    fn validation_rejects_terminal_sequence_and_timestamp_values() {
        let mut observation = PidObservation::scalar(1, 100, u64::MAX, Modality::Radar, 3.0, 3);
        assert!(observation.validate().is_err());

        observation.seq = 1;
        observation.timestamp_ms = u64::MAX;
        assert!(observation.validate().is_err());
    }

    #[test]
    fn consistency_projection_requires_bounded_active_axes_and_provenance() {
        let mut projection = ConsistencyProjection {
            values: [1.0, 0.0, 0.0],
            dimensions: 1,
            frame_id: 1,
            context_id: 2,
            prior_id: 3,
        };
        assert!(projection.validate().is_ok());

        projection.values[2] = 1.0;
        assert!(projection.validate().is_err());
        projection.values[2] = 0.0;
        projection.prior_id = 0;
        assert!(projection.validate().is_err());
        projection.prior_id = 3;
        projection.dimensions = 0;
        assert!(projection.validate().is_err());
    }
}
