//! The wire types galadriel ingests: [`Modality`] and [`PidObservation`].

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::domain::{DomainError, ProjectionIdentity, Sequence, TimestampMillis, TrackId};

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
/// - [`Self::values`] use the same physical frame and projection/basis definition
///   in [`Self::identity`] for every requested modality;
/// - every modality at one fusion sequence was projected from the same frozen,
///   pre-update state snapshot; and
/// - the frozen-prior identity names only that snapshot and is not reused at
///   another sequence.
///
/// The producer attests global frozen-prior identity uniqueness; galadriel rejects
/// reuse at another sequence anywhere in each bounded consistency extraction,
/// including across physical-frame and projection-context changes.
///
/// The identifiers are provenance labels, not authentication. The transport must
/// still authenticate and authorize the producer.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsistencyProjection {
    /// Projected signed residual values. Only `[..dimensions]` is active internally.
    values: [f64; MAX_CONSISTENCY_PROJECTION_AXES],
    /// Number of active axes, in `1..=MAX_CONSISTENCY_PROJECTION_AXES`.
    dimensions: u8,
    /// Typed provenance for the common frame, projection context, and frozen prior.
    identity: ProjectionIdentity,
}

impl ConsistencyProjection {
    /// Constructs a bounded projection with already-validated provenance.
    ///
    /// Zero-valued axes, including negative zero, are normalized to positive zero
    /// so equivalent projections have one representation.
    ///
    /// # Errors
    ///
    /// Returns an error when the active-axis count is outside `1..=3`, any value
    /// is non-finite, or an inactive axis is non-zero.
    pub fn try_new(
        mut values: [f64; MAX_CONSISTENCY_PROJECTION_AXES],
        dimensions: u8,
        identity: ProjectionIdentity,
    ) -> crate::Result<Self> {
        use crate::GaladrielError::{InvalidObservation, NonFinite};

        if !(1..=MAX_CONSISTENCY_PROJECTION_AXES as u8).contains(&dimensions) {
            return Err(InvalidObservation(format!(
                "consistency projection dimensions must be in 1..={MAX_CONSISTENCY_PROJECTION_AXES}"
            )));
        }
        if !values.iter().all(|value| value.is_finite()) {
            return Err(NonFinite("PidObservation::consistency_projection"));
        }
        if values[dimensions as usize..]
            .iter()
            .any(|value| *value != 0.0)
        {
            return Err(InvalidObservation(
                "inactive consistency projection axes must be zero".into(),
            ));
        }
        for value in &mut values {
            if *value == 0.0 {
                *value = 0.0;
            }
        }
        Ok(Self {
            values,
            dimensions,
            identity,
        })
    }

    /// Constructs a projection directly from untrusted integer provenance.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid projection values, zero identifiers, or
    /// identifiers above the exact JSON-integer boundary.
    pub fn try_new_raw(
        values: [f64; MAX_CONSISTENCY_PROJECTION_AXES],
        dimensions: u8,
        frame_id: u64,
        context_id: u64,
        frozen_prior_id: u64,
    ) -> crate::Result<Self> {
        let identity = ProjectionIdentity::try_new(frame_id, context_id, frozen_prior_id)
            .map_err(invalid_domain_value)?;
        Self::try_new(values, dimensions, identity)
    }

    /// Returns the active projected residual axes.
    pub fn values(&self) -> &[f64] {
        &self.values[..usize::from(self.dimensions)]
    }

    /// Returns the fixed-width representation, including canonical zero padding.
    pub const fn padded_values(&self) -> [f64; MAX_CONSISTENCY_PROJECTION_AXES] {
        self.values
    }

    /// Returns the number of active projected residual axes.
    pub const fn dimensions(&self) -> u8 {
        self.dimensions
    }

    /// Returns the validated projection provenance.
    pub const fn identity(&self) -> ProjectionIdentity {
        self.identity
    }
}

// This private DTO deliberately freezes the established v1 field names while the
// public value keeps its provenance grouped in a typed `ProjectionIdentity`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsistencyProjectionWire {
    values: [f64; MAX_CONSISTENCY_PROJECTION_AXES],
    dimensions: u8,
    frame_id: u64,
    context_id: u64,
    prior_id: u64,
}

impl Serialize for ConsistencyProjection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ConsistencyProjectionWire {
            values: self.values,
            dimensions: self.dimensions,
            frame_id: self.identity.frame_id().get(),
            context_id: self.identity.context_id().get(),
            prior_id: self.identity.frozen_prior_id().get(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConsistencyProjection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConsistencyProjectionWire::deserialize(deserializer)?;
        Self::try_new_raw(
            wire.values,
            wire.dimensions,
            wire.frame_id,
            wire.context_id,
            wire.prior_id,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn invalid_domain_value(error: DomainError) -> crate::GaladrielError {
    crate::GaladrielError::InvalidObservation(error.to_string())
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
    /// All modalities, in stable canonical-code order.
    pub const ALL: [Modality; 6] = [
        Modality::Visual,
        Modality::Thermal,
        Modality::Acoustic,
        Modality::Radar,
        Modality::Lidar,
        Modality::RadioFrequency,
    ];

    /// Stable numeric code for deterministic ordering and cross-crate identities.
    ///
    /// This mapping is explicit and does not depend on Rust enum layout.
    pub const fn stable_code(self) -> u8 {
        match self {
            Modality::Visual => 0,
            Modality::Thermal => 1,
            Modality::Acoustic => 2,
            Modality::Radar => 3,
            Modality::Lidar => 4,
            Modality::RadioFrequency => 5,
        }
    }

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
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PidObservation {
    /// Validated track identity.
    track_id: TrackId,
    /// Measurement time, ms since epoch (`SensorMeasurement.timestamp_ms`).
    timestamp_ms: TimestampMillis,
    /// Monotonic fusion frame counter at emit time (`MultiSensorFusion.frame_count`).
    #[serde(rename = "seq")]
    sequence: Sequence,
    /// Modality of the measurement that produced this residual.
    modality: Modality,
    /// Scalar whitened innovation: `NIS = yᵀ S⁻¹ y ~ χ²(dof)`.
    nis: f64,
    /// Innovation dimension / χ² degrees of freedom (3 for this fusion core).
    dof: u8,

    /// Raw innovation `y = z - H x̂⁻`. Cartesian `[x,y,z]` m for visual/thermal/
    /// acoustic/lidar; radar polar `[range m, az rad, el rad]`, az wrapped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    innovation: Option<[f64; 3]>,
    /// Innovation covariance `S = H P⁻ Hᵀ + R`, row-major 3×3, same frame as `innovation`.
    #[serde(
        rename = "innovation_cov",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    innovation_covariance: Option<[[f64; 3]; 3]>,
    /// Optional producer-attested common consistency projection. Existing captures
    /// without this metadata remain valid for the NIS baseline, but consistency
    /// assessment fails closed as insufficient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consistency_projection: Option<ConsistencyProjection>,
}

impl PidObservation {
    /// Constructs a baseline-only observation from validated domain coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error when `nis` is negative or non-finite, or when `dof` is
    /// zero.
    pub fn try_scalar(
        track_id: TrackId,
        timestamp_ms: TimestampMillis,
        sequence: Sequence,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> crate::Result<Self> {
        use crate::GaladrielError::{InvalidObservation, NonFinite};

        if !nis.is_finite() {
            return Err(NonFinite("PidObservation::nis"));
        }
        if nis < 0.0 {
            return Err(InvalidObservation("nis must be >= 0".into()));
        }
        if dof == 0 {
            return Err(InvalidObservation("dof must be > 0".into()));
        }
        let nis = if nis == 0.0 { 0.0 } else { nis };
        Ok(Self {
            track_id,
            timestamp_ms,
            sequence,
            modality,
            nis,
            dof,
            innovation: None,
            innovation_covariance: None,
            consistency_projection: None,
        })
    }

    /// Constructs a baseline-only observation from untrusted integer coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error when any coordinate is outside its JSON-safe domain, `nis`
    /// is negative or non-finite, or `dof` is zero. The frozen v1 `track_id` range
    /// includes zero.
    pub fn try_scalar_raw(
        track_id: u64,
        timestamp_ms: u64,
        sequence: u64,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> crate::Result<Self> {
        Self::try_scalar(
            TrackId::new(track_id).map_err(invalid_domain_value)?,
            TimestampMillis::new(timestamp_ms).map_err(invalid_domain_value)?,
            Sequence::new(sequence).map_err(invalid_domain_value)?,
            modality,
            nis,
            dof,
        )
    }

    /// Adds a validated, paired research innovation without mutating this value.
    ///
    /// The stored covariance is the symmetric matrix returned by
    /// [`validate_and_symmetrize_covariance`].
    ///
    /// # Errors
    ///
    /// Returns an error unless `dof == 3`, all innovation values are finite, and
    /// the covariance is finite, symmetric within tolerance, and positive definite.
    pub fn try_with_research(
        mut self,
        innovation: [f64; 3],
        innovation_covariance: [[f64; 3]; 3],
    ) -> crate::Result<Self> {
        use crate::GaladrielError::{InvalidObservation, NonFinite};

        if self.dof != 3 {
            return Err(InvalidObservation(
                "research-mode [f64; 3] innovations require dof == 3".into(),
            ));
        }
        if !innovation.iter().all(|value| value.is_finite()) {
            return Err(NonFinite("PidObservation::innovation"));
        }
        self.innovation = Some(innovation.map(|value| if value == 0.0 { 0.0 } else { value }));
        self.innovation_covariance =
            Some(validate_and_symmetrize_covariance(innovation_covariance)?);
        Ok(self)
    }

    /// Adds an already-validated consistency projection without mutating this value.
    #[must_use]
    pub fn with_consistency_projection(mut self, projection: ConsistencyProjection) -> Self {
        self.consistency_projection = Some(projection);
        self
    }

    /// Returns the validated track identity.
    pub const fn track_id(&self) -> TrackId {
        self.track_id
    }

    /// Returns the validated measurement timestamp.
    pub const fn timestamp_ms(&self) -> TimestampMillis {
        self.timestamp_ms
    }

    /// Returns the validated stream sequence.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Returns the closed sensor modality.
    pub const fn modality(&self) -> Modality {
        self.modality
    }

    /// Returns the normalized innovation squared.
    pub const fn nis(&self) -> f64 {
        self.nis
    }

    /// Returns the innovation degrees of freedom.
    pub const fn dof(&self) -> u8 {
        self.dof
    }

    /// Returns the optional raw research innovation.
    pub const fn innovation(&self) -> Option<[f64; 3]> {
        self.innovation
    }

    /// Returns the optional validated, symmetrized innovation covariance.
    pub const fn innovation_covariance(&self) -> Option<[[f64; 3]; 3]> {
        self.innovation_covariance
    }

    /// Returns the optional producer-attested consistency projection.
    pub const fn consistency_projection(&self) -> Option<&ConsistencyProjection> {
        self.consistency_projection.as_ref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PidObservationWire {
    track_id: u64,
    timestamp_ms: u64,
    #[serde(rename = "seq")]
    sequence: u64,
    modality: Modality,
    nis: f64,
    dof: u8,
    #[serde(default)]
    innovation: Option<[f64; 3]>,
    #[serde(rename = "innovation_cov", default)]
    innovation_covariance: Option<[[f64; 3]; 3]>,
    #[serde(default)]
    consistency_projection: Option<ConsistencyProjection>,
}

impl<'de> Deserialize<'de> for PidObservation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PidObservationWire::deserialize(deserializer)?;
        let mut observation = Self::try_scalar_raw(
            wire.track_id,
            wire.timestamp_ms,
            wire.sequence,
            wire.modality,
            wire.nis,
            wire.dof,
        )
        .map_err(serde::de::Error::custom)?;
        observation = match (wire.innovation, wire.innovation_covariance) {
            (None, None) => observation,
            (Some(innovation), Some(covariance)) => observation
                .try_with_research(innovation, covariance)
                .map_err(serde::de::Error::custom)?,
            _ => {
                return Err(serde::de::Error::custom(
                    "innovation and innovation_cov must either both be present or both be absent",
                ));
            }
        };
        if let Some(projection) = wire.consistency_projection {
            observation = observation.with_consistency_projection(projection);
        }
        Ok(observation)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use crate::domain::JSON_SAFE_INTEGER_MAX;

    use super::*;

    const IDENTITY_COVARIANCE: [[f64; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];

    fn scalar() -> PidObservation {
        PidObservation::try_scalar_raw(1, 100, 0, Modality::Radar, 3.2, 3).unwrap()
    }

    #[test]
    fn modality_wire_vocabulary_is_closed_and_stable() {
        let labels = Modality::ALL.map(Modality::label);
        let codes = Modality::ALL.map(Modality::stable_code);

        assert_eq!(
            labels,
            [
                "visual",
                "thermal",
                "acoustic",
                "radar",
                "lidar",
                "radiofrequency"
            ]
        );
        assert_eq!(codes, [0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn scalar_nis_has_one_signed_zero_representation() {
        let positive = PidObservation::try_scalar_raw(1, 0, 0, Modality::Visual, 0.0, 1)
            .expect("positive zero NIS is valid");
        let negative = PidObservation::try_scalar_raw(1, 0, 0, Modality::Visual, -0.0, 1)
            .expect("negative zero NIS is valid and canonicalized");

        assert_eq!(positive, negative);
        assert_eq!(negative.nis().to_bits(), 0.0_f64.to_bits());
        assert_eq!(
            serde_json::to_string(&negative).expect("observation serializes"),
            serde_json::to_string(&positive).expect("observation serializes")
        );
    }

    #[test]
    fn modality_deserialization_rejects_out_of_vocabulary_values() {
        assert!(serde_json::from_str::<Modality>("\"rf\"").is_err());
    }

    #[test]
    fn typed_scalar_exposes_only_validated_coordinates() {
        let observation = PidObservation::try_scalar(
            TrackId::new(7).unwrap(),
            TimestampMillis::new(101).unwrap(),
            Sequence::new(3).unwrap(),
            Modality::Thermal,
            2.5,
            3,
        )
        .unwrap();

        assert_eq!(
            (
                observation.track_id().get(),
                observation.timestamp_ms().get(),
                observation.sequence().get(),
                observation.modality(),
                observation.nis(),
                observation.dof(),
            ),
            (7, 101, 3, Modality::Thermal, 2.5, 3)
        );
    }

    #[test]
    fn scalar_wire_shape_preserves_coordinate_names_and_omits_research_fields() {
        assert_eq!(
            serde_json::to_value(scalar()).unwrap(),
            json!({
                "track_id": 1,
                "timestamp_ms": 100,
                "seq": 0,
                "modality": "radar",
                "nis": 3.2,
                "dof": 3
            })
        );
    }

    #[test]
    fn raw_scalar_accepts_exact_json_integer_boundaries() {
        let observation = PidObservation::try_scalar_raw(
            JSON_SAFE_INTEGER_MAX,
            JSON_SAFE_INTEGER_MAX,
            JSON_SAFE_INTEGER_MAX,
            Modality::Visual,
            0.0,
            u8::MAX,
        )
        .unwrap();

        assert_eq!(observation.track_id().get(), JSON_SAFE_INTEGER_MAX);
    }

    #[test]
    fn raw_scalar_rejects_every_invalid_coordinate_boundary() {
        let first_unsafe = JSON_SAFE_INTEGER_MAX + 1;
        let attempts = [
            PidObservation::try_scalar_raw(first_unsafe, 0, 0, Modality::Visual, 1.0, 1),
            PidObservation::try_scalar_raw(1, first_unsafe, 0, Modality::Visual, 1.0, 1),
            PidObservation::try_scalar_raw(1, 0, first_unsafe, Modality::Visual, 1.0, 1),
        ];

        assert!(attempts.into_iter().all(|attempt| attempt.is_err()));
    }

    #[test]
    fn scalar_constructor_rejects_numeric_poisoning() {
        let attempts = [
            PidObservation::try_scalar_raw(1, 0, 0, Modality::Visual, f64::NAN, 1),
            PidObservation::try_scalar_raw(1, 0, 0, Modality::Visual, f64::INFINITY, 1),
            PidObservation::try_scalar_raw(1, 0, 0, Modality::Visual, -1.0, 1),
            PidObservation::try_scalar_raw(1, 0, 0, Modality::Visual, 1.0, 0),
        ];

        assert!(attempts.into_iter().all(|attempt| attempt.is_err()));
    }

    #[test]
    fn observation_deserialization_enforces_domain_boundaries() {
        let first_unsafe = JSON_SAFE_INTEGER_MAX + 1;
        let payloads = [
            json!({"track_id": first_unsafe, "timestamp_ms": 0, "seq": 0, "modality": "radar", "nis": 1.0, "dof": 1}),
            json!({"track_id": 1, "timestamp_ms": first_unsafe, "seq": 0, "modality": "radar", "nis": 1.0, "dof": 1}),
            json!({"track_id": 1, "timestamp_ms": 0, "seq": first_unsafe, "modality": "radar", "nis": 1.0, "dof": 1}),
        ];

        assert!(payloads
            .into_iter()
            .all(|payload| serde_json::from_value::<PidObservation>(payload).is_err()));
    }

    #[test]
    fn frozen_v1_zero_track_observation_roundtrips_exactly() {
        let wire =
            r#"{"track_id":0,"timestamp_ms":0,"seq":0,"modality":"radar","nis":1.0,"dof":1}"#;

        let observation = serde_json::from_str::<PidObservation>(wire).unwrap();

        assert_eq!(observation.track_id().get(), 0);
        assert_eq!(serde_json::to_string(&observation).unwrap(), wire);
    }

    #[test]
    fn observation_deserialization_rejects_unknown_and_duplicate_fields() {
        let unknown = r#"{"track_id":1,"timestamp_ms":0,"seq":0,"modality":"radar","nis":1.0,"dof":1,"admin":true}"#;
        let duplicate = r#"{"track_id":1,"track_id":2,"timestamp_ms":0,"seq":0,"modality":"radar","nis":1.0,"dof":1}"#;

        assert!(serde_json::from_str::<PidObservation>(unknown).is_err());
        assert!(serde_json::from_str::<PidObservation>(duplicate).is_err());
    }

    #[test]
    fn research_payload_must_be_complete_at_deserialization() {
        let innovation_only = json!({
            "track_id": 1,
            "timestamp_ms": 0,
            "seq": 0,
            "modality": "radar",
            "nis": 1.0,
            "dof": 3,
            "innovation": [0.0, 0.0, 0.0]
        });
        let covariance_only = json!({
            "track_id": 1,
            "timestamp_ms": 0,
            "seq": 0,
            "modality": "radar",
            "nis": 1.0,
            "dof": 3,
            "innovation_cov": IDENTITY_COVARIANCE
        });

        assert!(serde_json::from_value::<PidObservation>(innovation_only).is_err());
        assert!(serde_json::from_value::<PidObservation>(covariance_only).is_err());
    }

    #[test]
    fn research_constructor_symmetrizes_accepted_roundoff() {
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
        let observation = scalar()
            .try_with_research([0.0, 1.0, -1.0], covariance)
            .unwrap();
        let symmetric = observation.innovation_covariance().unwrap();

        assert_eq!(symmetric[0][1], symmetric[1][0]);
    }

    #[test]
    fn research_constructor_rejects_material_covariance_asymmetry() {
        let covariance = [[1e-12, 0.0, 0.0], [1e-18, 1e-12, 0.0], [0.0, 0.0, 1e-12]];

        assert!(scalar().try_with_research([0.0; 3], covariance).is_err());
    }

    #[test]
    fn projection_uses_typed_identity_and_active_axis_view() {
        let identity = ProjectionIdentity::try_new(1, 2, 3).unwrap();
        let projection = ConsistencyProjection::try_new([1.0, -2.0, 0.0], 2, identity).unwrap();

        assert_eq!(
            (
                projection.values(),
                projection.dimensions(),
                projection.identity()
            ),
            (&[1.0, -2.0][..], 2, identity)
        );
    }

    #[test]
    fn projection_v1_wire_shape_is_flat_and_roundtrips_exactly() {
        let projection = ConsistencyProjection::try_new_raw([1.0, 0.0, 0.0], 1, 1, 2, 3).unwrap();
        let wire =
            r#"{"values":[1.0,0.0,0.0],"dimensions":1,"frame_id":1,"context_id":2,"prior_id":3}"#;
        let encoded = serde_json::to_string(&projection).unwrap();

        assert_eq!(encoded, wire);
        assert_eq!(
            serde_json::from_str::<ConsistencyProjection>(wire).unwrap(),
            projection
        );
    }

    #[test]
    fn projection_rejects_invalid_axes_and_raw_provenance() {
        let identity = ProjectionIdentity::try_new(1, 2, 3).unwrap();
        let first_unsafe = JSON_SAFE_INTEGER_MAX + 1;
        let attempts = [
            ConsistencyProjection::try_new([1.0, 0.0, 0.0], 0, identity),
            ConsistencyProjection::try_new([1.0, 0.0, 0.0], 4, identity),
            ConsistencyProjection::try_new([1.0, 0.0, 1.0], 1, identity),
            ConsistencyProjection::try_new([f64::NAN, 0.0, 0.0], 1, identity),
            ConsistencyProjection::try_new_raw([1.0, 0.0, 0.0], 1, 0, 2, 3),
            ConsistencyProjection::try_new_raw([1.0, 0.0, 0.0], 1, 1, first_unsafe, 3),
        ];

        assert!(attempts.into_iter().all(|attempt| attempt.is_err()));
    }

    #[test]
    fn projection_deserialization_rejects_unversioned_nested_identity() {
        let payload = json!({
            "values": [1.0, 0.0, 0.0],
            "dimensions": 1,
            "identity": {
                "frame_id": 1,
                "context_id": 2,
                "frozen_prior_id": 3
            }
        });

        assert!(serde_json::from_value::<ConsistencyProjection>(payload).is_err());
    }

    #[test]
    fn projection_deserialization_rejects_zero_v1_provenance() {
        let payload = json!({
            "values": [1.0, 0.0, 0.0],
            "dimensions": 1,
            "frame_id": 1,
            "context_id": 2,
            "prior_id": 0
        });

        assert!(serde_json::from_value::<ConsistencyProjection>(payload).is_err());
    }

    #[test]
    fn equivalent_signed_zero_inputs_have_one_projection_representation() {
        let positive = ConsistencyProjection::try_new_raw([0.0, 0.0, 0.0], 1, 1, 2, 3).unwrap();
        let negative = ConsistencyProjection::try_new_raw([-0.0, -0.0, -0.0], 1, 1, 2, 3).unwrap();

        assert_eq!(positive, negative);
        assert!(negative
            .padded_values()
            .iter()
            .all(|value| value.to_bits() == 0));
    }

    #[test]
    fn complete_observation_roundtrip_preserves_validated_value() {
        let projection = ConsistencyProjection::try_new_raw([1.0, 2.0, 0.0], 2, 4, 5, 6).unwrap();
        let observation = scalar()
            .try_with_research([1.0, 2.0, 3.0], IDENTITY_COVARIANCE)
            .unwrap()
            .with_consistency_projection(projection);
        let encoded = serde_json::to_vec(&observation).unwrap();
        let decoded = serde_json::from_slice::<PidObservation>(&encoded).unwrap();

        assert_eq!(decoded, observation);
    }

    proptest! {
        #[test]
        fn raw_and_typed_construction_are_metamorphically_equivalent(
            track_id in 0_u64..=JSON_SAFE_INTEGER_MAX,
            timestamp_ms in 0_u64..=JSON_SAFE_INTEGER_MAX,
            sequence in 0_u64..=JSON_SAFE_INTEGER_MAX,
            integer_nis in 0_u32..1_000_000_u32,
            dof in 1_u8..=u8::MAX,
        ) {
            let nis = f64::from(integer_nis);
            let raw = PidObservation::try_scalar_raw(
                track_id,
                timestamp_ms,
                sequence,
                Modality::Acoustic,
                nis,
                dof,
            ).unwrap();
            let typed = PidObservation::try_scalar(
                TrackId::new(track_id).unwrap(),
                TimestampMillis::new(timestamp_ms).unwrap(),
                Sequence::new(sequence).unwrap(),
                Modality::Acoustic,
                nis,
                dof,
            ).unwrap();
            let encoded = serde_json::to_vec(&raw).unwrap();
            let roundtrip = serde_json::from_slice::<PidObservation>(&encoded).unwrap();

            prop_assert_eq!(&raw, &typed);
            prop_assert_eq!(roundtrip, raw);
        }
    }
}
