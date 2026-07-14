//! Canonical identities for accepted configurations and report provenance.

use std::fmt;

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{PidObservation, ReleaseSuite};

const _: () = assert!(
    usize::BITS <= u64::BITS,
    "canonical identity encoding requires lossless usize-to-u64 conversion",
);

/// A domain-separated SHA-256 digest of one complete accepted configuration.
///
/// The bytes are architecture-independent. Integer fields use big-endian fixed
/// widths, collections carry explicit lengths, and admitted negative zero is
/// canonicalized to positive zero before its IEEE-754 bits are written.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConfigDigest([u8; 32]);

impl ConfigDigest {
    /// Returns the raw SHA-256 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the lowercase hexadecimal representation.
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(64);
        for byte in self.0 {
            let _ = write!(output, "{byte:02x}");
        }
        output
    }
}

impl fmt::Debug for ConfigDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ConfigDigest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for ConfigDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for ConfigDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

/// A domain-separated SHA-256 digest of one exact whole-stream assessment input.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssessmentDigest([u8; 32]);

impl AssessmentDigest {
    fn from_config_digest(digest: ConfigDigest) -> Self {
        Self(*digest.as_bytes())
    }

    /// Returns the raw SHA-256 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the lowercase hexadecimal representation.
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(64);
        for byte in self.0 {
            let _ = write!(output, "{byte:02x}");
        }
        output
    }
}

impl fmt::Debug for AssessmentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AssessmentDigest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for AssessmentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for AssessmentDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

/// Opaque canonical binding between one accepted release suite and its exact
/// ordered observation input.
///
/// Only whole-stream assessment preparation can mint this value. Callers may
/// compare or verify it, but cannot construct one from arbitrary component
/// reports. The binding covers every field currently carried by
/// [`PidObservation`], including optional native research data and producer-
/// attested consistency projections.
///
/// ```compile_fail
/// use galadriel_core::AssessmentBinding;
/// let _ = AssessmentBinding {};
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AssessmentBinding {
    digest: AssessmentDigest,
    suite_identity: ConfigDigest,
    observation_count: usize,
}

impl AssessmentBinding {
    /// Canonical domain-separated digest of the suite and ordered observations.
    pub const fn digest(&self) -> AssessmentDigest {
        self.digest
    }

    /// Complete accepted release-suite identity included in the binding.
    pub const fn suite_identity(&self) -> ConfigDigest {
        self.suite_identity
    }

    /// Number of exact observations included in the binding.
    pub const fn observation_count(&self) -> usize {
        self.observation_count
    }

    /// Verify this binding against an exact ordered stream and release suite.
    pub fn verifies(&self, stream: &[PidObservation], suite: &ReleaseSuite) -> bool {
        self == &Self::for_release_stream(stream, suite)
    }

    pub(crate) fn for_release_stream(stream: &[PidObservation], suite: &ReleaseSuite) -> Self {
        let mut identity = IdentityBuilder::new(b"galadriel-assessment-binding-v1");
        identity.digest(b"release_suite", suite.identity());
        identity.usize(b"observation_count", stream.len());
        for observation in stream {
            identity.digest(b"observation", observation_identity(observation));
        }
        Self {
            digest: AssessmentDigest::from_config_digest(identity.finish()),
            suite_identity: suite.identity(),
            observation_count: stream.len(),
        }
    }
}

impl fmt::Debug for AssessmentBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssessmentBinding")
            .field("digest", &self.digest)
            .field("suite_identity", &self.suite_identity)
            .field("observation_count", &self.observation_count)
            .finish()
    }
}

impl Serialize for AssessmentBinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self.digest)
    }
}

fn observation_identity(observation: &PidObservation) -> ConfigDigest {
    let mut identity = IdentityBuilder::new(b"galadriel-assessment-observation-v1");
    identity.u64(b"track_id", observation.track_id().get());
    identity.u64(b"timestamp_ms", observation.timestamp_ms().get());
    identity.u64(b"sequence", observation.sequence().get());
    // Preserve the frozen one-based assessment tag while deriving it from the
    // explicit layout-independent modality code.
    identity.u8(b"modality", observation.modality().stable_code() + 1);
    identity.f64(b"nis", observation.nis());
    identity.u8(b"dof", observation.dof());

    match observation.innovation() {
        Some(innovation) => {
            identity.u8(b"innovation_present", 1);
            for value in innovation {
                identity.f64(b"innovation_value", value);
            }
        }
        None => identity.u8(b"innovation_present", 0),
    }
    match observation.innovation_covariance() {
        Some(covariance) => {
            identity.u8(b"covariance_present", 1);
            for value in covariance.into_iter().flatten() {
                identity.f64(b"covariance_value", value);
            }
        }
        None => identity.u8(b"covariance_present", 0),
    }
    match observation.consistency_projection() {
        Some(projection) => {
            let projection_identity = projection.identity();
            identity.u8(b"projection_present", 1);
            identity.u8(b"projection_dimensions", projection.dimensions());
            for value in projection.padded_values() {
                identity.f64(b"projection_value", value);
            }
            identity.u64(b"projection_frame", projection_identity.frame_id().get());
            identity.u64(
                b"projection_context",
                projection_identity.context_id().get(),
            );
            identity.u64(
                b"projection_prior",
                projection_identity.frozen_prior_id().get(),
            );
        }
        None => identity.u8(b"projection_present", 0),
    }
    identity.finish()
}

/// Canonical SHA-256 preimage writer used by accepted configuration types.
pub(crate) struct IdentityBuilder(Sha256);

impl IdentityBuilder {
    pub(crate) fn new(domain: &'static [u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"galadriel-config-identity\0");
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain);
        Self(hasher)
    }

    fn field_prefix(&mut self, name: &'static [u8], type_tag: u8, length: u64) {
        self.0.update((name.len() as u64).to_be_bytes());
        self.0.update(name);
        self.0.update([type_tag]);
        self.0.update(length.to_be_bytes());
    }

    pub(crate) fn u8(&mut self, name: &'static [u8], value: u8) {
        self.field_prefix(name, 1, 1);
        self.0.update([value]);
    }

    pub(crate) fn u64(&mut self, name: &'static [u8], value: u64) {
        self.field_prefix(name, 2, 8);
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn usize(&mut self, name: &'static [u8], value: usize) {
        self.u64(name, value as u64);
    }

    pub(crate) fn f64(&mut self, name: &'static [u8], value: f64) {
        let canonical = if value == 0.0 { 0.0 } else { value };
        self.field_prefix(name, 3, 8);
        self.0.update(canonical.to_bits().to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, name: &'static [u8], value: &[u8]) {
        self.field_prefix(name, 4, value.len() as u64);
        self.0.update(value);
    }

    pub(crate) fn digest(&mut self, name: &'static [u8], value: ConfigDigest) {
        self.field_prefix(name, 5, 32);
        self.0.update(value.0);
    }

    pub(crate) fn finish(self) -> ConfigDigest {
        ConfigDigest(self.0.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        ConsistencyProjection, Modality, ProjectionIdentity, Sequence, TimestampMillis, TrackId,
    };

    #[test]
    fn negative_zero_has_the_same_canonical_identity_as_positive_zero() {
        let mut left = IdentityBuilder::new(b"zero-test-v1");
        left.f64(b"value", -0.0);
        let mut right = IdentityBuilder::new(b"zero-test-v1");
        right.f64(b"value", 0.0);

        assert_eq!(left.finish(), right.finish());
    }

    #[test]
    fn domains_separate_equal_field_material() {
        let mut left = IdentityBuilder::new(b"left-v1");
        left.u64(b"value", 7);
        let mut right = IdentityBuilder::new(b"right-v1");
        right.u64(b"value", 7);

        assert_ne!(left.finish(), right.finish());
    }

    fn suite() -> ReleaseSuite {
        ReleaseSuite::standalone_advisory_v0_9(&[
            Modality::Visual,
            Modality::Radar,
            Modality::Acoustic,
        ])
        .expect("test suite")
    }

    fn scalar(
        track: u64,
        timestamp: u64,
        sequence: u64,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> PidObservation {
        PidObservation::try_scalar(
            TrackId::new(track).expect("test track"),
            TimestampMillis::new(timestamp).expect("test timestamp"),
            Sequence::new(sequence).expect("test sequence"),
            modality,
            nis,
            dof,
        )
        .expect("test observation")
    }

    fn projection(
        values: [f64; 3],
        dimensions: u8,
        frame: u64,
        context: u64,
        prior: u64,
    ) -> ConsistencyProjection {
        ConsistencyProjection::try_new(
            values,
            dimensions,
            ProjectionIdentity::try_new(frame, context, prior).expect("test projection identity"),
        )
        .expect("test projection")
    }

    #[test]
    fn assessment_binding_covers_every_scalar_coordinate_and_input_order() {
        let suite = suite();
        let base = scalar(1, 100, 7, Modality::Visual, 3.0, 3);
        let base_binding =
            AssessmentBinding::for_release_stream(std::slice::from_ref(&base), &suite);
        let mutations = [
            scalar(2, 100, 7, Modality::Visual, 3.0, 3),
            scalar(1, 101, 7, Modality::Visual, 3.0, 3),
            scalar(1, 100, 8, Modality::Visual, 3.0, 3),
            scalar(1, 100, 7, Modality::Radar, 3.0, 3),
            scalar(1, 100, 7, Modality::Visual, 3.125, 3),
            scalar(1, 100, 7, Modality::Visual, 3.0, 2),
        ];

        assert!(mutations.iter().all(|mutation| {
            AssessmentBinding::for_release_stream(std::slice::from_ref(mutation), &suite)
                != base_binding
        }));
        let radar = scalar(1, 100, 7, Modality::Radar, 3.0, 3);
        assert_ne!(
            AssessmentBinding::for_release_stream(&[base.clone(), radar.clone()], &suite),
            AssessmentBinding::for_release_stream(&[radar, base], &suite)
        );
    }

    #[test]
    fn assessment_binding_covers_native_research_and_projection_fields() {
        let suite = suite();
        let scalar = scalar(1, 100, 7, Modality::Visual, 3.0, 3);
        let covariance = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let complete = scalar
            .clone()
            .try_with_research([0.1, 0.2, 0.3], covariance)
            .expect("test research input")
            .with_consistency_projection(projection([0.4, 0.5, 0.6], 3, 1, 2, 3));
        let complete_binding =
            AssessmentBinding::for_release_stream(std::slice::from_ref(&complete), &suite);
        let covariance_changed = [[1.125, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let mutations = [
            scalar.clone(),
            scalar
                .clone()
                .try_with_research([0.125, 0.2, 0.3], covariance)
                .expect("test research input")
                .with_consistency_projection(projection([0.4, 0.5, 0.6], 3, 1, 2, 3)),
            scalar
                .clone()
                .try_with_research([0.1, 0.2, 0.3], covariance_changed)
                .expect("test research input")
                .with_consistency_projection(projection([0.4, 0.5, 0.6], 3, 1, 2, 3)),
            scalar
                .clone()
                .try_with_research([0.1, 0.2, 0.3], covariance)
                .expect("test research input")
                .with_consistency_projection(projection([0.425, 0.5, 0.6], 3, 1, 2, 3)),
            scalar
                .clone()
                .try_with_research([0.1, 0.2, 0.3], covariance)
                .expect("test research input")
                .with_consistency_projection(projection([0.4, 0.5, 0.0], 2, 1, 2, 3)),
            scalar
                .clone()
                .try_with_research([0.1, 0.2, 0.3], covariance)
                .expect("test research input")
                .with_consistency_projection(projection([0.4, 0.5, 0.6], 3, 4, 2, 3)),
            scalar
                .clone()
                .try_with_research([0.1, 0.2, 0.3], covariance)
                .expect("test research input")
                .with_consistency_projection(projection([0.4, 0.5, 0.6], 3, 1, 4, 3)),
            scalar
                .try_with_research([0.1, 0.2, 0.3], covariance)
                .expect("test research input")
                .with_consistency_projection(projection([0.4, 0.5, 0.6], 3, 1, 2, 4)),
        ];

        assert!(mutations.iter().all(|mutation| {
            AssessmentBinding::for_release_stream(std::slice::from_ref(mutation), &suite)
                != complete_binding
        }));
        assert!(complete_binding.verifies(&[complete], &suite));
    }

    #[test]
    fn assessment_binding_distinguishes_each_optional_presence_boundary() {
        let suite = suite();
        let covariance = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let scalar = scalar(1, 100, 7, Modality::Visual, 3.0, 3);
        let research = scalar
            .clone()
            .try_with_research([0.1, 0.2, 0.3], covariance)
            .expect("test research input");
        let projected_scalar =
            scalar
                .clone()
                .with_consistency_projection(projection([0.4, 0.5, 0.6], 3, 1, 2, 3));
        let projected_research =
            research
                .clone()
                .with_consistency_projection(projection([0.4, 0.5, 0.6], 3, 1, 2, 3));

        let bindings =
            [scalar, research, projected_scalar, projected_research].map(|observation| {
                AssessmentBinding::for_release_stream(std::slice::from_ref(&observation), &suite)
            });
        for (index, binding) in bindings.iter().enumerate() {
            assert!(bindings[index + 1..].iter().all(|other| binding != other));
        }
    }
}
