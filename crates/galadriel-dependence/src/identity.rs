//! Canonical identities for accepted dependence configurations and research suites.

use std::fmt;

use galadriel_core::{AssessmentBinding, AssessmentScope, PidObservation};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

const _: () = assert!(
    usize::BITS <= u64::BITS,
    "canonical dependence identity encoding requires lossless usize-to-u64 conversion",
);

/// Whether an accepted dependence configuration or suite came from a named profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DependenceResearchClassification {
    /// Closed, versioned exploratory research profile.
    NamedResearchProfile,
    /// Accepted custom values that are never relabeled as a named profile.
    CustomAcceptedResearch,
}

macro_rules! digest_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
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

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.to_hex())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }
    };
}

digest_type!(
    MiConsensusConfigDigest,
    "A domain-separated SHA-256 digest of one complete accepted MI-consensus configuration."
);
digest_type!(
    DependenceResearchSuiteDigest,
    "A domain-separated SHA-256 digest of one complete accepted dependence research suite."
);
digest_type!(
    DependenceAssessmentDigest,
    "A domain-separated SHA-256 digest binding an exact core release input to one complete dependence research suite."
);
digest_type!(
    ProjectionAxisDigest,
    "A domain-separated SHA-256 digest binding one producer-attested projection axis to its core assessment."
);

/// Opaque binding between one exact core assessment and one dependence research suite.
///
/// The nested core binding covers the assessment scope, release suite, and every
/// ordered observation. This layer adds the complete dependence-suite identity.
/// It proves internal byte-level agreement, not producer authenticity or the truth
/// of a declared population law.
///
/// ```compile_fail
/// use galadriel_dependence::DependenceAssessmentBinding;
/// let _ = DependenceAssessmentBinding {};
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct DependenceAssessmentBinding {
    digest: DependenceAssessmentDigest,
    release_binding: AssessmentBinding,
    suite_identity: DependenceResearchSuiteDigest,
}

impl DependenceAssessmentBinding {
    pub(crate) fn new(
        release_binding: &AssessmentBinding,
        suite_identity: DependenceResearchSuiteDigest,
    ) -> Self {
        let mut identity = IdentityBuilder::new(b"galadriel-dependence-assessment-binding-v1");
        identity.bytes(b"release_assessment", release_binding.digest().as_bytes());
        identity.bytes(b"dependence_research_suite", suite_identity.as_bytes());
        Self {
            digest: DependenceAssessmentDigest::from_bytes(identity.finish()),
            release_binding: release_binding.clone(),
            suite_identity,
        }
    }

    /// Canonical digest of the nested release binding and dependence suite.
    pub const fn digest(&self) -> DependenceAssessmentDigest {
        self.digest
    }

    /// Exact scope, suite, and observation binding from core preparation.
    pub const fn release_binding(&self) -> &AssessmentBinding {
        &self.release_binding
    }

    /// Complete dependence research-suite identity.
    pub const fn suite_identity(&self) -> DependenceResearchSuiteDigest {
        self.suite_identity
    }

    /// Verify the nested core input and the complete dependence-suite identity.
    ///
    /// A successful result proves internal digest agreement. It does not prove
    /// the population-law declaration, producer authenticity, or physical truth.
    pub fn verifies(
        &self,
        scope: &AssessmentScope,
        stream: &[PidObservation],
        suite: &crate::DependenceResearchSuite,
    ) -> bool {
        if self.suite_identity != suite.identity()
            || !self
                .release_binding
                .verifies(scope, stream, suite.release_suite())
        {
            return false;
        }
        self == &Self::new(&self.release_binding, suite.identity())
    }
}

/// Architecture-independent canonical SHA-256 preimage writer.
pub(crate) struct IdentityBuilder(Sha256);

impl IdentityBuilder {
    pub(crate) fn new(domain: &'static [u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"galadriel-dependence-identity\0");
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

    pub(crate) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floating_zero_is_canonical_and_domains_are_distinct() {
        let mut negative = IdentityBuilder::new(b"zero-v1");
        negative.f64(b"value", -0.0);
        let mut positive = IdentityBuilder::new(b"zero-v1");
        positive.f64(b"value", 0.0);
        let mut other_domain = IdentityBuilder::new(b"other-v1");
        other_domain.f64(b"value", 0.0);

        let negative = negative.finish();
        let positive = positive.finish();
        let other_domain = other_domain.finish();
        assert_eq!(negative, positive);
        assert_ne!(positive, other_domain);
    }

    #[test]
    fn identity_preimage_encoding_has_an_independent_known_answer() {
        let mut identity = IdentityBuilder::new(b"kat-v1");
        identity.u8(b"u8", 0xa5);
        identity.u64(b"u64", 0x0102_0304_0506_0708);
        identity.usize(b"usize", 42);
        identity.f64(b"f64", 1.5);
        identity.bytes(b"bytes", b"\0abc");

        // Independently reconstructed from the documented length-prefixed
        // big-endian preimage, then SHA-256 hashed outside this implementation.
        assert_eq!(
            identity.finish(),
            [
                0x29, 0x44, 0x02, 0xbd, 0x01, 0xf6, 0xff, 0x5a, 0x60, 0xfb, 0xf4, 0x93, 0xdc, 0xbe,
                0x75, 0x55, 0x10, 0x8f, 0xd3, 0x93, 0x1a, 0xac, 0x59, 0x53, 0x8e, 0x2e, 0x01, 0x2e,
                0xea, 0xe7, 0xc2, 0xba,
            ]
        );
    }
}
