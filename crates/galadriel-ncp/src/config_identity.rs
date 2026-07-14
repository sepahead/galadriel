//! Architecture-independent identities for validated NCP configuration.

use sha2::{Digest, Sha256};
use std::fmt;

/// A canonical SHA-256 identity for one fully validated NCP configuration.
///
/// Identities are derived from a domain-separated, length-prefixed byte stream
/// containing fixed-width integers. They therefore do not depend on the host's
/// pointer width, native endianness, or serializer implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConfigurationIdentity([u8; 32]);

impl ConfigurationIdentity {
    /// Return the raw SHA-256 digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the canonical lowercase hexadecimal representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}

impl fmt::Display for ConfigurationIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Canonical field encoder used only after a configuration has validated.
pub(crate) struct ConfigurationIdentityBuilder(Sha256);

impl ConfigurationIdentityBuilder {
    pub(crate) fn new(domain: &'static str) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"galadriel-ncp/configuration-identity/v0.9\0");
        append_bytes(&mut digest, domain.as_bytes());
        Self(digest)
    }

    pub(crate) fn u64(mut self, name: &'static str, value: u64) -> Self {
        append_bytes(&mut self.0, name.as_bytes());
        append_bytes(&mut self.0, &value.to_be_bytes());
        self
    }

    #[cfg(any(feature = "zenoh", test))]
    pub(crate) fn bytes(mut self, name: &'static str, value: &[u8]) -> Self {
        append_bytes(&mut self.0, name.as_bytes());
        append_bytes(&mut self.0, value);
        self
    }

    pub(crate) fn finish(self) -> ConfigurationIdentity {
        ConfigurationIdentity(self.0.finalize().into())
    }
}

fn append_bytes(digest: &mut Sha256, bytes: &[u8]) {
    // A fixed-width u128 prefix covers every Rust target's `usize` without a
    // host-width-dependent encoding or a fallible production path.
    digest.update((bytes.len() as u128).to_be_bytes());
    digest.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_encoding_is_domain_separated_and_unambiguous() {
        let left = ConfigurationIdentityBuilder::new("left")
            .u64("a", 1)
            .bytes("b", b"23")
            .finish();
        let right = ConfigurationIdentityBuilder::new("right")
            .u64("a", 1)
            .bytes("b", b"23")
            .finish();
        let repartitioned = ConfigurationIdentityBuilder::new("left")
            .u64("a", 12)
            .bytes("b", b"3")
            .finish();

        assert_ne!(left, right);
        assert_ne!(left, repartitioned);
        assert_eq!(left.to_hex().len(), 64);
        assert_eq!(left.to_string(), left.to_hex());
    }
}
