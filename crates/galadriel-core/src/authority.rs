//! Machine-testable downstream authority invariants.
//!
//! Galadriel does not apply policy. A consumer can use this pure validator to
//! prove that a proposed advisory effect is record-only or monotonically
//! restrictive. The check is verdict-independent: `Nominal` receives no special
//! ability to grant or widen authority.

use crate::{GaladrielError, Result};

/// Whether an independently authorized action is currently admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// Independent policy denies the action.
    Deny,
    /// Independent policy permits the action within the accompanying bounds.
    Allow,
}

/// The only two Galadriel consumer modes admitted by the 0.9 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryPolicy {
    /// Evidence is archived but changes no policy field.
    RecordOnly,
    /// Independently admitted evidence may reduce, but never widen, authority.
    RestrictOnly,
}

/// A bounded, consumer-owned policy snapshot before or after advisory handling.
///
/// Numeric limits use integer deployment units chosen by the consumer. This
/// avoids NaN, rounding, and unit-conversion ambiguity in the monotonicity check.
/// The capability digest binds the full action/capability set not represented by
/// the scalar limits; it must never change in an advisory transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    authorization: Authorization,
    velocity_limit_units: u64,
    slew_limit_units: u64,
    command_ttl_ms: u64,
    lease_expiry_ms: u64,
    watchdog_epoch: u64,
    capability_digest: [u8; 32],
}

impl AuthoritySnapshot {
    /// Construct one consumer policy snapshot.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        authorization: Authorization,
        velocity_limit_units: u64,
        slew_limit_units: u64,
        command_ttl_ms: u64,
        lease_expiry_ms: u64,
        watchdog_epoch: u64,
        capability_digest: [u8; 32],
    ) -> Self {
        Self {
            authorization,
            velocity_limit_units,
            slew_limit_units,
            command_ttl_ms,
            lease_expiry_ms,
            watchdog_epoch,
            capability_digest,
        }
    }

    /// Independent allow/deny result.
    pub const fn authorization(&self) -> Authorization {
        self.authorization
    }

    /// Consumer-defined velocity cap in fixed integer units.
    pub const fn velocity_limit_units(&self) -> u64 {
        self.velocity_limit_units
    }

    /// Consumer-defined slew cap in fixed integer units.
    pub const fn slew_limit_units(&self) -> u64 {
        self.slew_limit_units
    }

    /// Maximum command lifetime in milliseconds.
    pub const fn command_ttl_ms(&self) -> u64 {
        self.command_ttl_ms
    }

    /// Absolute expiry of the independently issued lease.
    pub const fn lease_expiry_ms(&self) -> u64 {
        self.lease_expiry_ms
    }

    /// Independent plant-watchdog epoch; advisory handling cannot refresh it.
    pub const fn watchdog_epoch(&self) -> u64 {
        self.watchdog_epoch
    }

    /// Digest binding every capability outside the explicit scalar fields.
    pub const fn capability_digest(&self) -> &[u8; 32] {
        &self.capability_digest
    }
}

/// Validate a proposed consumer policy transition caused by advisory handling.
///
/// `RecordOnly` requires byte-for-byte semantic equality. `RestrictOnly` permits
/// `Allow -> Deny` and non-increasing scalar limits/expiries, while capability and
/// watchdog identities remain unchanged. The function is intentionally not given
/// a verdict: the same rules apply to every Galadriel finding, including nominal.
pub fn validate_advisory_effect(
    policy: AdvisoryPolicy,
    before: &AuthoritySnapshot,
    after: &AuthoritySnapshot,
) -> Result<()> {
    if policy == AdvisoryPolicy::RecordOnly {
        return if before == after {
            Ok(())
        } else {
            Err(GaladrielError::AuthorityViolation(
                "record-only advisory changed policy",
            ))
        };
    }

    if before.capability_digest != after.capability_digest {
        return Err(GaladrielError::AuthorityViolation(
            "advisory changed the capability set",
        ));
    }
    if before.watchdog_epoch != after.watchdog_epoch {
        return Err(GaladrielError::AuthorityViolation(
            "advisory changed or refreshed the plant watchdog",
        ));
    }
    if before.authorization == Authorization::Deny && after.authorization == Authorization::Allow {
        return Err(GaladrielError::AuthorityViolation(
            "advisory changed DENY to ALLOW",
        ));
    }
    if after.velocity_limit_units > before.velocity_limit_units {
        return Err(GaladrielError::AuthorityViolation(
            "advisory increased the velocity limit",
        ));
    }
    if after.slew_limit_units > before.slew_limit_units {
        return Err(GaladrielError::AuthorityViolation(
            "advisory increased the slew limit",
        ));
    }
    if after.command_ttl_ms > before.command_ttl_ms {
        return Err(GaladrielError::AuthorityViolation(
            "advisory extended the command TTL",
        ));
    }
    if after.lease_expiry_ms > before.lease_expiry_ms {
        return Err(GaladrielError::AuthorityViolation(
            "advisory extended or restored the lease",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const DIGEST: [u8; 32] = [0x5a; 32];

    fn snapshot(authorization: Authorization, value: u64) -> AuthoritySnapshot {
        AuthoritySnapshot::new(authorization, value, value, value, value, 7, DIGEST)
    }

    #[test]
    fn record_only_accepts_exactly_unchanged_policy() {
        let before = snapshot(Authorization::Allow, 10);
        assert_eq!(
            validate_advisory_effect(AdvisoryPolicy::RecordOnly, &before, &before),
            Ok(())
        );
    }

    #[test]
    fn record_only_rejects_even_a_restriction() {
        let before = snapshot(Authorization::Allow, 10);
        let after = snapshot(Authorization::Deny, 9);
        assert!(matches!(
            validate_advisory_effect(AdvisoryPolicy::RecordOnly, &before, &after),
            Err(GaladrielError::AuthorityViolation(_))
        ));
    }

    #[test]
    fn restrict_only_accepts_monotonic_reduction_and_zero_boundary() {
        let before = snapshot(Authorization::Allow, u64::MAX);
        let after = snapshot(Authorization::Deny, 0);
        assert_eq!(
            validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after),
            Ok(())
        );
    }

    #[test]
    fn nominal_cannot_turn_deny_into_allow_or_widen_each_limit() {
        // The validator is deliberately independent of the finding; this is the
        // exact transition a consumer might otherwise attempt on `Nominal`.
        let before = snapshot(Authorization::Deny, 10);
        let allow = snapshot(Authorization::Allow, 10);
        assert!(validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &allow).is_err());

        for after in [
            AuthoritySnapshot::new(Authorization::Deny, 11, 10, 10, 10, 7, DIGEST),
            AuthoritySnapshot::new(Authorization::Deny, 10, 11, 10, 10, 7, DIGEST),
            AuthoritySnapshot::new(Authorization::Deny, 10, 10, 11, 10, 7, DIGEST),
            AuthoritySnapshot::new(Authorization::Deny, 10, 10, 10, 11, 7, DIGEST),
        ] {
            assert!(
                validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after).is_err()
            );
        }
    }

    #[test]
    fn restrict_only_rejects_capability_substitution_and_watchdog_refresh() {
        let before = snapshot(Authorization::Allow, 10);
        let changed_capability =
            AuthoritySnapshot::new(Authorization::Allow, 10, 10, 10, 10, 7, [0xa5; 32]);
        let refreshed_watchdog =
            AuthoritySnapshot::new(Authorization::Allow, 10, 10, 10, 10, 8, DIGEST);
        assert!(validate_advisory_effect(
            AdvisoryPolicy::RestrictOnly,
            &before,
            &changed_capability
        )
        .is_err());
        assert!(validate_advisory_effect(
            AdvisoryPolicy::RestrictOnly,
            &before,
            &refreshed_watchdog
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn arbitrary_non_increasing_limits_are_accepted(
            velocity in 0u64..=u64::MAX,
            slew in 0u64..=u64::MAX,
            ttl in 0u64..=u64::MAX,
            lease in 0u64..=u64::MAX,
        ) {
            let before = AuthoritySnapshot::new(
                Authorization::Allow,
                velocity,
                slew,
                ttl,
                lease,
                7,
                DIGEST,
            );
            let after = AuthoritySnapshot::new(
                Authorization::Deny,
                velocity / 2,
                slew / 2,
                ttl / 2,
                lease / 2,
                7,
                DIGEST,
            );
            prop_assert_eq!(
                validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after),
                Ok(())
            );
        }

        #[test]
        fn any_single_limit_increase_is_rejected(
            base in 0u64..u64::MAX,
            field in 0usize..4,
        ) {
            let before = snapshot(Authorization::Allow, base);
            let mut values = [base; 4];
            values[field] = base + 1;
            let after = AuthoritySnapshot::new(
                Authorization::Allow,
                values[0],
                values[1],
                values[2],
                values[3],
                7,
                DIGEST,
            );
            prop_assert!(
                validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after).is_err()
            );
        }
    }
}
