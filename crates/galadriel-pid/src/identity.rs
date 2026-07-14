//! Canonical identities for accepted PID configurations and research suites.

use std::fmt;

use galadriel_core::AssessmentBinding;
use sha2::{Digest, Sha256};

const _: () = assert!(
    usize::BITS <= u64::BITS,
    "canonical PID identity encoding requires lossless usize-to-u64 conversion",
);

/// Whether an accepted PID configuration or suite came from a named profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidResearchClassification {
    /// Closed, versioned PID research profile.
    NamedResearchProfile,
    /// Accepted custom research values; never relabelled as a named profile.
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
    };
}

digest_type!(
    PidConfigDigest,
    "A domain-separated SHA-256 digest of one complete accepted PID configuration."
);
digest_type!(
    PidResearchSuiteDigest,
    "A domain-separated SHA-256 digest of one complete accepted PID research suite."
);
digest_type!(
    PidAssessmentDigest,
    "A domain-separated SHA-256 digest binding an exact release input to one complete PID research suite."
);

/// Opaque binding between an exact core release assessment and one complete PID
/// research suite.
///
/// The nested core binding covers every ordered observation and the complete
/// [`galadriel_core::ReleaseSuite`]. This layer additionally binds the named or
/// custom PID research-suite identity, preventing equal component values from
/// being relabelled under a different suite.
///
/// ```compile_fail
/// use galadriel_pid::PidAssessmentBinding;
/// let _ = PidAssessmentBinding {};
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PidAssessmentBinding {
    digest: PidAssessmentDigest,
    release_binding: AssessmentBinding,
    suite_identity: PidResearchSuiteDigest,
}

impl PidAssessmentBinding {
    pub(crate) fn new(
        release_binding: &AssessmentBinding,
        suite_identity: PidResearchSuiteDigest,
    ) -> Self {
        let mut identity = IdentityBuilder::new(b"galadriel-pid-assessment-binding-v1");
        identity.bytes(b"release_assessment", release_binding.digest().as_bytes());
        identity.bytes(b"pid_research_suite", suite_identity.as_bytes());
        Self {
            digest: PidAssessmentDigest::from_bytes(identity.finish()),
            release_binding: release_binding.clone(),
            suite_identity,
        }
    }

    /// Canonical digest of the nested release binding and complete PID suite.
    pub const fn digest(&self) -> PidAssessmentDigest {
        self.digest
    }

    /// Exact suite-and-observation binding produced by the core preparation.
    pub const fn release_binding(&self) -> &AssessmentBinding {
        &self.release_binding
    }

    /// Complete named or custom PID research-suite identity.
    pub const fn suite_identity(&self) -> PidResearchSuiteDigest {
        self.suite_identity
    }
}

/// Architecture-independent canonical SHA-256 preimage writer.
pub(crate) struct IdentityBuilder(Sha256);

impl IdentityBuilder {
    pub(crate) fn new(domain: &'static [u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"galadriel-pid-config-identity\0");
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
}
