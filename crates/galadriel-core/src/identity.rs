//! Canonical identities for accepted configurations and report provenance.

use std::fmt;

use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{PidObservation, ProducerId, ReleaseSuite, StreamPosition};

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

/// Validated lifecycle labels for one accepted whole-stream assessment.
///
/// The scope names one producer and one exact lifecycle position. The position
/// contains session, epoch, stream, state generation, sequence, timestamp, and
/// clock domain. Core compares the terminal sequence and timestamp with the
/// assessed stream. The other values are validated caller declarations. The
/// scope does not authenticate the producer. It does not prove observation
/// origin.
///
/// ```
/// use galadriel_core::{AssessmentScope, ClockDomain, ProducerId, StreamPosition};
///
/// let scope = AssessmentScope::new(
///     ProducerId::new("producer-1")?,
///     StreamPosition::try_new(
///         "session-1",
///         "epoch-1",
///         "fusion",
///         0,
///         17,
///         1_700,
///         ClockDomain::MonotonicProcess,
///     )?,
/// );
/// assert_eq!(scope.position().sequence().get(), 17);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ```compile_fail
/// use galadriel_core::AssessmentScope;
/// let _ = AssessmentScope {};
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentScope {
    producer_id: ProducerId,
    position: StreamPosition,
}

impl AssessmentScope {
    /// Constructs a scope from validated producer and lifecycle values.
    pub const fn new(producer_id: ProducerId, position: StreamPosition) -> Self {
        Self {
            producer_id,
            position,
        }
    }

    /// Returns the validated producer label.
    pub const fn producer_id(&self) -> &ProducerId {
        &self.producer_id
    }

    /// Returns the exact lifecycle position for this assessment.
    pub const fn position(&self) -> &StreamPosition {
        &self.position
    }
}

/// Opaque canonical binding for one scope, release suite, and ordered stream.
///
/// Only whole-stream assessment preparation can mint this value. Callers may
/// compare or verify it, but cannot construct one from arbitrary component
/// reports. The binding covers every field currently carried by
/// [`PidObservation`], including optional native research data and producer-
/// attested consistency projections. It also covers the complete
/// [`AssessmentScope`]. The digest domain is
/// `galadriel-assessment-binding-v2`.
///
/// The binding identifies the submitted input. Different bindings can carry
/// equal detector verdicts. The binding does not require each observation to
/// change an estimator or verdict.
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
    scope: AssessmentScope,
}

impl AssessmentBinding {
    /// Canonical digest of the scope, suite, and ordered observations.
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

    /// Validated lifecycle labels included in this binding.
    pub const fn scope(&self) -> &AssessmentScope {
        &self.scope
    }

    /// Verify this binding against one exact scope, ordered stream, and suite.
    ///
    /// The method rejects cheap identity and size mismatches before it hashes the
    /// stream. A successful result proves internal digest agreement. It does not
    /// authenticate the producer or the caller.
    pub fn verifies(
        &self,
        scope: &AssessmentScope,
        stream: &[PidObservation],
        suite: &ReleaseSuite,
    ) -> bool {
        if scope != &self.scope {
            return false;
        }
        if stream.len() != self.observation_count {
            return false;
        }
        if suite.identity() != self.suite_identity {
            return false;
        }
        if crate::validate_consistency_input_len(stream.len()).is_err() {
            return false;
        }
        self.digest == Self::for_release_stream(scope, stream, suite).digest
    }

    pub(crate) fn for_release_stream(
        scope: &AssessmentScope,
        stream: &[PidObservation],
        suite: &ReleaseSuite,
    ) -> Self {
        let mut identity = IdentityBuilder::new(b"galadriel-assessment-binding-v2");
        append_assessment_scope(&mut identity, scope);
        identity.digest(b"release_suite", suite.identity());
        identity.usize(b"observation_count", stream.len());
        for observation in stream {
            identity.digest(b"observation", observation_identity(observation));
        }
        Self {
            digest: AssessmentDigest::from_config_digest(identity.finish()),
            suite_identity: suite.identity(),
            observation_count: stream.len(),
            scope: scope.clone(),
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
            .field("scope", &self.scope)
            .finish()
    }
}

fn append_assessment_scope(identity: &mut IdentityBuilder, scope: &AssessmentScope) {
    let position = scope.position();
    let stream = position.identity();
    let epoch = stream.epoch();
    identity.bytes(b"producer_id", scope.producer_id().as_str().as_bytes());
    identity.bytes(b"session_id", epoch.session_id().as_str().as_bytes());
    identity.bytes(b"epoch_id", epoch.epoch_id().as_str().as_bytes());
    identity.bytes(b"stream_id", stream.stream_id().as_str().as_bytes());
    identity.u64(b"state_generation", position.state_generation().get());
    identity.u64(b"terminal_sequence", position.sequence().get());
    identity.u64(b"terminal_timestamp_ms", position.timestamp_ms().get());
    identity.bytes(b"clock_domain", position.clock_domain().as_str().as_bytes());
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
        ClockDomain, ConsistencyProjection, Modality, ProducerId, ProjectionIdentity, Sequence,
        StreamPosition, TimestampMillis, TrackId, JSON_SAFE_INTEGER_MAX,
    };

    #[expect(
        clippy::too_many_arguments,
        reason = "the scope fixture names every bound identity coordinate"
    )]
    fn scope_with(
        producer_id: &str,
        session_id: &str,
        epoch_id: &str,
        stream_id: &str,
        state_generation: u64,
        sequence: u64,
        timestamp_ms: u64,
        clock_domain: ClockDomain,
    ) -> AssessmentScope {
        AssessmentScope::new(
            ProducerId::new(producer_id).expect("test producer"),
            StreamPosition::try_new(
                session_id,
                epoch_id,
                stream_id,
                state_generation,
                sequence,
                timestamp_ms,
                clock_domain,
            )
            .expect("test position"),
        )
    }

    fn scope(sequence: u64, timestamp_ms: u64) -> AssessmentScope {
        scope_with(
            "test-producer",
            "test-session",
            "test-epoch",
            "test-stream",
            0,
            sequence,
            timestamp_ms,
            ClockDomain::SimulationTime,
        )
    }

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

    #[test]
    fn digest_and_binding_observables_have_exact_canonical_forms() {
        let bytes = std::array::from_fn(|index| index as u8);
        let expected = "000102030405060708090a0b0c0d0e0f\
                        101112131415161718191a1b1c1d1e1f";
        let config = ConfigDigest(bytes);
        let assessment = AssessmentDigest(bytes);

        assert_eq!(config.as_bytes(), &bytes);
        assert_eq!(config.to_hex(), expected);
        assert_eq!(format!("{config}"), expected);
        assert_eq!(
            format!("{config:?}"),
            format!("ConfigDigest(\"{expected}\")")
        );
        assert_eq!(
            serde_json::to_string(&config).expect("serialize config digest"),
            format!("\"{expected}\"")
        );

        assert_eq!(assessment.as_bytes(), &bytes);
        assert_eq!(assessment.to_hex(), expected);
        assert_eq!(format!("{assessment}"), expected);
        assert_eq!(
            format!("{assessment:?}"),
            format!("AssessmentDigest(\"{expected}\")")
        );
        assert_eq!(
            serde_json::to_string(&assessment).expect("serialize assessment digest"),
            format!("\"{expected}\"")
        );

        let scope = scope(7, 100);
        let binding = AssessmentBinding {
            digest: assessment,
            suite_identity: config,
            observation_count: 7,
            scope: scope.clone(),
        };
        assert_eq!(binding.digest(), assessment);
        assert_eq!(binding.suite_identity(), config);
        assert_eq!(binding.observation_count(), 7);
        assert_eq!(binding.scope(), &scope);
        let debug = format!("{binding:?}");
        assert!(debug.contains(&format!("AssessmentDigest(\"{expected}\")")));
        assert!(debug.contains("producer_id: ProducerId(\"test-producer\")"));
        assert_eq!(
            serde_json::to_string(&binding).expect("serialize assessment binding"),
            format!("\"{expected}\"")
        );
    }

    #[test]
    fn assessment_scope_json_roundtrip_preserves_every_validated_label() {
        let scope = scope(7, 100);
        let encoded = serde_json::to_vec(&scope).expect("scope serializes");

        let decoded = serde_json::from_slice::<AssessmentScope>(&encoded)
            .expect("scope deserializes through validated fields");

        assert_eq!(decoded, scope);
    }

    #[test]
    fn assessment_scope_json_rejects_an_unknown_field() {
        let mut value = serde_json::to_value(scope(7, 100)).expect("scope serializes");
        value["unexpected"] = serde_json::json!(true);

        assert!(serde_json::from_value::<AssessmentScope>(value).is_err());
    }

    #[test]
    fn assessment_scope_json_revalidates_the_producer_grammar() {
        let mut value = serde_json::to_value(scope(7, 100)).expect("scope serializes");
        value["producer_id"] = serde_json::json!("../invalid");

        assert!(serde_json::from_value::<AssessmentScope>(value).is_err());
    }

    #[test]
    fn assessment_scope_json_rejects_an_unsafe_terminal_integer() {
        let mut value = serde_json::to_value(scope(7, 100)).expect("scope serializes");
        value["position"]["sequence"] = serde_json::json!(JSON_SAFE_INTEGER_MAX + 1);

        assert!(serde_json::from_value::<AssessmentScope>(value).is_err());
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
        let scope = scope(7, 100);
        let base_binding =
            AssessmentBinding::for_release_stream(&scope, std::slice::from_ref(&base), &suite);
        assert_eq!(
            base_binding.digest().to_hex(),
            "25b3a35232c6643536f83768653171428430980981b033e6d28be717637e4236"
        );
        let mutations = [
            scalar(2, 100, 7, Modality::Visual, 3.0, 3),
            scalar(1, 101, 7, Modality::Visual, 3.0, 3),
            scalar(1, 100, 8, Modality::Visual, 3.0, 3),
            scalar(1, 100, 7, Modality::Radar, 3.0, 3),
            scalar(1, 100, 7, Modality::Visual, 3.125, 3),
            scalar(1, 100, 7, Modality::Visual, 3.0, 2),
        ];

        assert!(mutations.iter().all(|mutation| {
            AssessmentBinding::for_release_stream(&scope, std::slice::from_ref(mutation), &suite)
                != base_binding
        }));
        let radar = scalar(1, 100, 7, Modality::Radar, 3.0, 3);
        assert_ne!(
            AssessmentBinding::for_release_stream(&scope, &[base.clone(), radar.clone()], &suite,),
            AssessmentBinding::for_release_stream(&scope, &[radar, base], &suite)
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
        let scope = scope(7, 100);
        let complete_binding =
            AssessmentBinding::for_release_stream(&scope, std::slice::from_ref(&complete), &suite);
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
            AssessmentBinding::for_release_stream(&scope, std::slice::from_ref(mutation), &suite)
                != complete_binding
        }));
        assert!(complete_binding.verifies(&scope, &[complete], &suite));
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

        let scope = scope(7, 100);
        let bindings =
            [scalar, research, projected_scalar, projected_research].map(|observation| {
                AssessmentBinding::for_release_stream(
                    &scope,
                    std::slice::from_ref(&observation),
                    &suite,
                )
            });
        for (index, binding) in bindings.iter().enumerate() {
            assert!(bindings[index + 1..].iter().all(|other| binding != other));
        }
    }

    #[test]
    fn assessment_binding_covers_every_scope_coordinate() {
        let suite = suite();
        let observation = scalar(1, 100, 7, Modality::Visual, 3.0, 3);
        let base_scope = scope(7, 100);
        let base = AssessmentBinding::for_release_stream(
            &base_scope,
            std::slice::from_ref(&observation),
            &suite,
        );
        let mutations = [
            scope_with(
                "other-producer",
                "test-session",
                "test-epoch",
                "test-stream",
                0,
                7,
                100,
                ClockDomain::SimulationTime,
            ),
            scope_with(
                "test-producer",
                "other-session",
                "test-epoch",
                "test-stream",
                0,
                7,
                100,
                ClockDomain::SimulationTime,
            ),
            scope_with(
                "test-producer",
                "test-session",
                "other-epoch",
                "test-stream",
                0,
                7,
                100,
                ClockDomain::SimulationTime,
            ),
            scope_with(
                "test-producer",
                "test-session",
                "test-epoch",
                "other-stream",
                0,
                7,
                100,
                ClockDomain::SimulationTime,
            ),
            scope_with(
                "test-producer",
                "test-session",
                "test-epoch",
                "test-stream",
                1,
                7,
                100,
                ClockDomain::SimulationTime,
            ),
            scope_with(
                "test-producer",
                "test-session",
                "test-epoch",
                "test-stream",
                0,
                8,
                100,
                ClockDomain::SimulationTime,
            ),
            scope_with(
                "test-producer",
                "test-session",
                "test-epoch",
                "test-stream",
                0,
                7,
                101,
                ClockDomain::SimulationTime,
            ),
            scope_with(
                "test-producer",
                "test-session",
                "test-epoch",
                "test-stream",
                0,
                7,
                100,
                ClockDomain::MonotonicProcess,
            ),
        ];

        for mutation in mutations {
            assert_ne!(
                AssessmentBinding::for_release_stream(
                    &mutation,
                    std::slice::from_ref(&observation),
                    &suite,
                ),
                base
            );
            assert!(!base.verifies(&mutation, std::slice::from_ref(&observation), &suite,));
        }
        assert!(base.verifies(&base_scope, std::slice::from_ref(&observation), &suite,));
    }

    #[test]
    fn assessment_scope_fields_have_unambiguous_variable_length_boundaries() {
        let suite = suite();
        let observation = scalar(1, 100, 7, Modality::Visual, 3.0, 3);
        let pairs = [
            (
                scope_with(
                    "ab",
                    "c",
                    "epoch",
                    "stream",
                    0,
                    7,
                    100,
                    ClockDomain::SimulationTime,
                ),
                scope_with(
                    "a",
                    "bc",
                    "epoch",
                    "stream",
                    0,
                    7,
                    100,
                    ClockDomain::SimulationTime,
                ),
            ),
            (
                scope_with(
                    "producer",
                    "ab",
                    "c",
                    "stream",
                    0,
                    7,
                    100,
                    ClockDomain::SimulationTime,
                ),
                scope_with(
                    "producer",
                    "a",
                    "bc",
                    "stream",
                    0,
                    7,
                    100,
                    ClockDomain::SimulationTime,
                ),
            ),
            (
                scope_with(
                    "producer",
                    "session",
                    "ab",
                    "c",
                    0,
                    7,
                    100,
                    ClockDomain::SimulationTime,
                ),
                scope_with(
                    "producer",
                    "session",
                    "a",
                    "bc",
                    0,
                    7,
                    100,
                    ClockDomain::SimulationTime,
                ),
            ),
        ];

        for (left, right) in pairs {
            assert_ne!(
                AssessmentBinding::for_release_stream(
                    &left,
                    std::slice::from_ref(&observation),
                    &suite,
                ),
                AssessmentBinding::for_release_stream(
                    &right,
                    std::slice::from_ref(&observation),
                    &suite,
                )
            );
        }
    }
}
