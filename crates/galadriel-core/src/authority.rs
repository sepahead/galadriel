//! Machine-testable downstream authority invariants.
//!
//! Galadriel does not apply policy. A consumer can use this pure validator to
//! check that a proposed advisory effect is record-only or monotonically
//! restrictive. The check is verdict-independent. `Nominal` receives no special
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

/// A velocity cap in the consumer's bound integer unit and scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VelocityLimit(u64);

impl VelocityLimit {
    /// Constructs a velocity cap from the consumer's integer representation.
    pub const fn new(units: u64) -> Self {
        Self(units)
    }

    /// Returns the consumer's integer representation.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A slew cap in the consumer's bound integer unit and scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlewLimit(u64);

impl SlewLimit {
    /// Constructs a slew cap from the consumer's integer representation.
    pub const fn new(units: u64) -> Self {
        Self(units)
    }

    /// Returns the consumer's integer representation.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A maximum command lifetime in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandTtlMillis(u64);

impl CommandTtlMillis {
    /// Constructs a maximum command lifetime in milliseconds.
    pub const fn new(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    /// Returns the maximum command lifetime in milliseconds.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An absolute lease expiry in the bound clock domain and epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseExpiryMillis(u64);

impl LeaseExpiryMillis {
    /// Constructs an absolute lease expiry in milliseconds.
    pub const fn new(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    /// Returns the absolute lease expiry in milliseconds.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An independent plant-watchdog epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WatchdogEpoch(u64);

impl WatchdogEpoch {
    /// Constructs a watchdog epoch from the consumer's integer identity.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the consumer's integer identity.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Opaque identity for one exact authority interpretation.
///
/// The consumer derives this identity from a canonical description. That
/// description binds the velocity unit and scale, slew unit and scale, lease
/// clock domain and epoch, and interpretation profile. The identity MUST change
/// when any bound semantic value changes. Galadriel compares the identity but
/// does not authenticate the declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthoritySemanticsId([u8; 32]);

impl AuthoritySemanticsId {
    /// Constructs an identity from the consumer's canonical 32-byte digest.
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Returns the consumer's canonical digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Named, type-safe values for one bound authority snapshot.
///
/// The distinct scalar types prevent accidental field swaps.
/// They do not define a global ordering. The validator compares their integer
/// values only after both snapshots have the same semantics identity.
///
/// ```compile_fail
/// use galadriel_core::{
///     Authorization, AuthoritySemanticsId, AuthoritySnapshot,
///     AuthoritySnapshotParams, CommandTtlMillis, LeaseExpiryMillis, SlewLimit,
///     VelocityLimit, WatchdogEpoch,
/// };
///
/// let _ = AuthoritySnapshot::new_strict(AuthoritySnapshotParams {
///     authorization: Authorization::Allow,
///     semantics_id: AuthoritySemanticsId::new([0x11; 32]),
///     velocity_limit: SlewLimit::new(10),
///     slew_limit: VelocityLimit::new(20),
///     command_ttl: CommandTtlMillis::new(100),
///     lease_expiry: LeaseExpiryMillis::new(1_000),
///     watchdog_epoch: WatchdogEpoch::new(7),
///     capability_digest: [0x22; 32],
/// });
/// ```
///
/// ```compile_fail
/// use galadriel_core::{
///     Authorization, AuthoritySemanticsId, AuthoritySnapshot,
///     AuthoritySnapshotParams, CommandTtlMillis, LeaseExpiryMillis, SlewLimit,
///     VelocityLimit, WatchdogEpoch,
/// };
///
/// let command_ttl = CommandTtlMillis::new(100);
/// let lease_expiry = LeaseExpiryMillis::new(1_000);
/// let _ = AuthoritySnapshot::new_strict(AuthoritySnapshotParams {
///     authorization: Authorization::Allow,
///     semantics_id: AuthoritySemanticsId::new([0x11; 32]),
///     velocity_limit: VelocityLimit::new(10),
///     slew_limit: SlewLimit::new(20),
///     command_ttl: lease_expiry,
///     lease_expiry: command_ttl,
///     watchdog_epoch: WatchdogEpoch::new(7),
///     capability_digest: [0x22; 32],
/// });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshotParams {
    /// Independent allow/deny result.
    pub authorization: Authorization,
    /// Exact unit, clock, and profile interpretation identity.
    pub semantics_id: AuthoritySemanticsId,
    /// Velocity cap in the semantics-bound integer unit and scale.
    pub velocity_limit: VelocityLimit,
    /// Slew cap in the semantics-bound integer unit and scale.
    pub slew_limit: SlewLimit,
    /// Maximum command lifetime in milliseconds.
    pub command_ttl: CommandTtlMillis,
    /// Absolute lease expiry in the semantics-bound clock domain and epoch.
    pub lease_expiry: LeaseExpiryMillis,
    /// Independent plant-watchdog epoch.
    pub watchdog_epoch: WatchdogEpoch,
    /// Digest of every capability outside the explicit scalar fields.
    pub capability_digest: [u8; 32],
}

/// A bounded, consumer-owned policy snapshot before or after advisory handling.
///
/// Strict snapshots bind every scalar interpretation with an
/// [`AuthoritySemanticsId`]. Legacy unbound snapshots support unchanged
/// [`AdvisoryPolicy::RecordOnly`] comparisons only. The capability digest binds
/// the full action and capability set not represented by the scalar limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    authorization: Authorization,
    semantics_id: Option<AuthoritySemanticsId>,
    velocity_limit: VelocityLimit,
    slew_limit: SlewLimit,
    command_ttl: CommandTtlMillis,
    lease_expiry: LeaseExpiryMillis,
    watchdog_epoch: WatchdogEpoch,
    capability_digest: [u8; 32],
}

impl AuthoritySnapshot {
    /// Constructs one bound consumer policy snapshot.
    ///
    /// # Examples
    ///
    /// ```
    /// use galadriel_core::{
    ///     validate_advisory_effect, AdvisoryPolicy, Authorization,
    ///     AuthoritySemanticsId, AuthoritySnapshot, AuthoritySnapshotParams,
    ///     CommandTtlMillis, LeaseExpiryMillis, SlewLimit, VelocityLimit,
    ///     WatchdogEpoch,
    /// };
    ///
    /// let semantics_id = AuthoritySemanticsId::new([0x11; 32]);
    /// let capability_digest = [0x22; 32];
    /// let before = AuthoritySnapshot::new_strict(AuthoritySnapshotParams {
    ///     authorization: Authorization::Allow,
    ///     semantics_id,
    ///     velocity_limit: VelocityLimit::new(100),
    ///     slew_limit: SlewLimit::new(50),
    ///     command_ttl: CommandTtlMillis::new(1_000),
    ///     lease_expiry: LeaseExpiryMillis::new(10_000),
    ///     watchdog_epoch: WatchdogEpoch::new(7),
    ///     capability_digest,
    /// });
    /// let after = AuthoritySnapshot::new_strict(AuthoritySnapshotParams {
    ///     authorization: Authorization::Deny,
    ///     semantics_id,
    ///     velocity_limit: VelocityLimit::new(90),
    ///     slew_limit: SlewLimit::new(40),
    ///     command_ttl: CommandTtlMillis::new(900),
    ///     lease_expiry: LeaseExpiryMillis::new(9_000),
    ///     watchdog_epoch: WatchdogEpoch::new(7),
    ///     capability_digest,
    /// });
    ///
    /// assert_eq!(
    ///     validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after),
    ///     Ok(())
    /// );
    /// ```
    pub const fn new_strict(params: AuthoritySnapshotParams) -> Self {
        Self {
            authorization: params.authorization,
            semantics_id: Some(params.semantics_id),
            velocity_limit: params.velocity_limit,
            slew_limit: params.slew_limit,
            command_ttl: params.command_ttl,
            lease_expiry: params.lease_expiry,
            watchdog_epoch: params.watchdog_epoch,
            capability_digest: params.capability_digest,
        }
    }

    /// Constructs one legacy unbound consumer policy snapshot.
    ///
    /// An unbound snapshot supports exact record-only equality. Restrict-only
    /// validation rejects it because its unit, clock, and profile semantics are
    /// not bound.
    #[deprecated(
        since = "0.9.0",
        note = "use AuthoritySnapshot::new_strict because legacy snapshots are unbound and record-only"
    )]
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
            semantics_id: None,
            velocity_limit: VelocityLimit::new(velocity_limit_units),
            slew_limit: SlewLimit::new(slew_limit_units),
            command_ttl: CommandTtlMillis::new(command_ttl_ms),
            lease_expiry: LeaseExpiryMillis::new(lease_expiry_ms),
            watchdog_epoch: WatchdogEpoch::new(watchdog_epoch),
            capability_digest,
        }
    }

    /// Independent allow/deny result.
    pub const fn authorization(&self) -> Authorization {
        self.authorization
    }

    /// Returns the exact bound semantics identity.
    ///
    /// A legacy snapshot returns `None`.
    pub const fn semantics_id(&self) -> Option<&AuthoritySemanticsId> {
        self.semantics_id.as_ref()
    }

    /// Returns the typed velocity cap.
    pub const fn velocity_limit(&self) -> VelocityLimit {
        self.velocity_limit
    }

    /// Consumer-defined velocity cap in fixed integer units.
    pub const fn velocity_limit_units(&self) -> u64 {
        self.velocity_limit.get()
    }

    /// Returns the typed slew cap.
    pub const fn slew_limit(&self) -> SlewLimit {
        self.slew_limit
    }

    /// Consumer-defined slew cap in fixed integer units.
    pub const fn slew_limit_units(&self) -> u64 {
        self.slew_limit.get()
    }

    /// Returns the typed maximum command lifetime.
    pub const fn command_ttl(&self) -> CommandTtlMillis {
        self.command_ttl
    }

    /// Maximum command lifetime in milliseconds.
    pub const fn command_ttl_ms(&self) -> u64 {
        self.command_ttl.get()
    }

    /// Returns the typed absolute lease expiry.
    pub const fn lease_expiry(&self) -> LeaseExpiryMillis {
        self.lease_expiry
    }

    /// Absolute expiry of the independently issued lease.
    pub const fn lease_expiry_ms(&self) -> u64 {
        self.lease_expiry.get()
    }

    /// Returns the typed independent plant-watchdog epoch.
    pub const fn watchdog(&self) -> WatchdogEpoch {
        self.watchdog_epoch
    }

    /// Independent plant-watchdog epoch. Advisory handling cannot refresh it.
    pub const fn watchdog_epoch(&self) -> u64 {
        self.watchdog_epoch.get()
    }

    /// Digest binding every capability outside the explicit scalar fields.
    pub const fn capability_digest(&self) -> &[u8; 32] {
        &self.capability_digest
    }
}

/// Validate a proposed consumer policy transition caused by advisory handling.
///
/// `RecordOnly` requires exact semantic equality. `RestrictOnly` first requires
/// two bound snapshots with the same semantics identity. It then permits
/// `Allow -> Deny` and non-increasing scalar limits or expiries. Capability and
/// watchdog identities MUST remain unchanged. The function receives no verdict.
/// The same rules apply to every Galadriel finding, including nominal.
///
/// # Errors
///
/// Returns [`GaladrielError::AuthorityViolation`] when the proposed effect is not
/// exactly record-only or cannot prove a semantics-bound monotonic restriction.
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

    let (Some(before_semantics), Some(after_semantics)) =
        (before.semantics_id.as_ref(), after.semantics_id.as_ref())
    else {
        return Err(GaladrielError::AuthorityViolation(
            "restrict-only advisory requires bound authority semantics",
        ));
    };
    if before_semantics != after_semantics {
        return Err(GaladrielError::AuthorityViolation(
            "advisory changed authority semantics",
        ));
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
    if after.velocity_limit.get() > before.velocity_limit.get() {
        return Err(GaladrielError::AuthorityViolation(
            "advisory increased the velocity limit",
        ));
    }
    if after.slew_limit.get() > before.slew_limit.get() {
        return Err(GaladrielError::AuthorityViolation(
            "advisory increased the slew limit",
        ));
    }
    if after.command_ttl.get() > before.command_ttl.get() {
        return Err(GaladrielError::AuthorityViolation(
            "advisory extended the command TTL",
        ));
    }
    if after.lease_expiry.get() > before.lease_expiry.get() {
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
    const OTHER_DIGEST: [u8; 32] = [0xa5; 32];
    const UNIT_CLOCK_PROFILE_A: AuthoritySemanticsId = AuthoritySemanticsId::new([0x3c; 32]);
    const UNIT_CLOCK_PROFILE_B: AuthoritySemanticsId = AuthoritySemanticsId::new([0xc3; 32]);

    fn strict_snapshot(authorization: Authorization, value: u64) -> AuthoritySnapshot {
        strict_snapshot_with(authorization, [value; 4], 7, UNIT_CLOCK_PROFILE_A, DIGEST)
    }

    fn strict_snapshot_with(
        authorization: Authorization,
        values: [u64; 4],
        watchdog_epoch: u64,
        semantics_id: AuthoritySemanticsId,
        capability_digest: [u8; 32],
    ) -> AuthoritySnapshot {
        AuthoritySnapshot::new_strict(AuthoritySnapshotParams {
            authorization,
            semantics_id,
            velocity_limit: VelocityLimit::new(values[0]),
            slew_limit: SlewLimit::new(values[1]),
            command_ttl: CommandTtlMillis::new(values[2]),
            lease_expiry: LeaseExpiryMillis::new(values[3]),
            watchdog_epoch: WatchdogEpoch::new(watchdog_epoch),
            capability_digest,
        })
    }

    #[allow(deprecated)]
    fn legacy_snapshot(authorization: Authorization, value: u64) -> AuthoritySnapshot {
        AuthoritySnapshot::new(authorization, value, value, value, value, 7, DIGEST)
    }

    #[test]
    fn strict_snapshot_getters_preserve_every_constructor_field() {
        let snapshot = strict_snapshot_with(
            Authorization::Deny,
            [2, 3, 4, 5],
            6,
            UNIT_CLOCK_PROFILE_A,
            DIGEST,
        );
        assert_eq!(snapshot.authorization(), Authorization::Deny);
        assert_eq!(snapshot.semantics_id(), Some(&UNIT_CLOCK_PROFILE_A));
        assert_eq!(snapshot.velocity_limit(), VelocityLimit::new(2));
        assert_eq!(snapshot.velocity_limit_units(), 2);
        assert_eq!(snapshot.slew_limit(), SlewLimit::new(3));
        assert_eq!(snapshot.slew_limit_units(), 3);
        assert_eq!(snapshot.command_ttl(), CommandTtlMillis::new(4));
        assert_eq!(snapshot.command_ttl_ms(), 4);
        assert_eq!(snapshot.lease_expiry(), LeaseExpiryMillis::new(5));
        assert_eq!(snapshot.lease_expiry_ms(), 5);
        assert_eq!(snapshot.watchdog(), WatchdogEpoch::new(6));
        assert_eq!(snapshot.watchdog_epoch(), 6);
        assert_eq!(snapshot.capability_digest(), &DIGEST);
    }

    #[test]
    fn record_only_accepts_exactly_unchanged_legacy_policy() {
        let before = legacy_snapshot(Authorization::Allow, 10);
        assert_eq!(before.semantics_id(), None);
        assert_eq!(
            validate_advisory_effect(AdvisoryPolicy::RecordOnly, &before, &before),
            Ok(())
        );
    }

    #[test]
    fn record_only_rejects_even_a_restriction() {
        let before = strict_snapshot(Authorization::Allow, 10);
        let after = strict_snapshot(Authorization::Deny, 9);
        assert!(matches!(
            validate_advisory_effect(AdvisoryPolicy::RecordOnly, &before, &after),
            Err(GaladrielError::AuthorityViolation(_))
        ));
    }

    #[test]
    fn restrict_only_accepts_bound_monotonic_reduction_and_zero_boundary() {
        let before = strict_snapshot(Authorization::Allow, u64::MAX);
        let after = strict_snapshot(Authorization::Deny, 0);
        assert_eq!(
            validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after),
            Ok(())
        );
    }

    #[test]
    fn restrict_only_accepts_equality_for_both_authorization_states() {
        for authorization in [Authorization::Deny, Authorization::Allow] {
            let snapshot =
                strict_snapshot_with(authorization, [2, 3, 4, 5], 6, UNIT_CLOCK_PROFILE_A, DIGEST);
            assert_eq!(
                validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &snapshot, &snapshot,),
                Ok(())
            );
        }
    }

    #[test]
    fn restrict_only_rejects_mismatched_unit_clock_profile_identity() {
        let before = strict_snapshot_with(
            Authorization::Allow,
            [10; 4],
            7,
            UNIT_CLOCK_PROFILE_A,
            DIGEST,
        );
        let after =
            strict_snapshot_with(Authorization::Deny, [9; 4], 7, UNIT_CLOCK_PROFILE_B, DIGEST);
        assert_eq!(
            validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after),
            Err(GaladrielError::AuthorityViolation(
                "advisory changed authority semantics"
            ))
        );
    }

    #[test]
    fn restrict_only_rejects_every_pair_with_a_legacy_unbound_snapshot() {
        let legacy = legacy_snapshot(Authorization::Deny, 0);
        let strict = strict_snapshot(Authorization::Deny, 0);
        for (before, after) in [(legacy, legacy), (legacy, strict), (strict, legacy)] {
            assert_eq!(
                validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after),
                Err(GaladrielError::AuthorityViolation(
                    "restrict-only advisory requires bound authority semantics"
                ))
            );
        }
    }

    #[test]
    fn nominal_cannot_turn_deny_into_allow_or_widen_each_limit() {
        // The validator is deliberately independent of the finding. This is the
        // exact transition a consumer might otherwise attempt on `Nominal`.
        let before = strict_snapshot(Authorization::Deny, 10);
        let allow = strict_snapshot(Authorization::Allow, 10);
        assert!(validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &allow).is_err());

        for after in [
            strict_snapshot_with(
                Authorization::Deny,
                [11, 10, 10, 10],
                7,
                UNIT_CLOCK_PROFILE_A,
                DIGEST,
            ),
            strict_snapshot_with(
                Authorization::Deny,
                [10, 11, 10, 10],
                7,
                UNIT_CLOCK_PROFILE_A,
                DIGEST,
            ),
            strict_snapshot_with(
                Authorization::Deny,
                [10, 10, 11, 10],
                7,
                UNIT_CLOCK_PROFILE_A,
                DIGEST,
            ),
            strict_snapshot_with(
                Authorization::Deny,
                [10, 10, 10, 11],
                7,
                UNIT_CLOCK_PROFILE_A,
                DIGEST,
            ),
        ] {
            assert!(
                validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after).is_err()
            );
        }
    }

    #[test]
    fn restrict_only_rejects_capability_substitution_and_watchdog_refresh() {
        let before = strict_snapshot(Authorization::Allow, 10);
        let changed_capability = strict_snapshot_with(
            Authorization::Allow,
            [10; 4],
            7,
            UNIT_CLOCK_PROFILE_A,
            OTHER_DIGEST,
        );
        let refreshed_watchdog = strict_snapshot_with(
            Authorization::Allow,
            [10; 4],
            8,
            UNIT_CLOCK_PROFILE_A,
            DIGEST,
        );
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
            let before = strict_snapshot_with(
                Authorization::Allow,
                [velocity, slew, ttl, lease],
                7,
                UNIT_CLOCK_PROFILE_A,
                DIGEST,
            );
            let after = strict_snapshot_with(
                Authorization::Deny,
                [velocity / 2, slew / 2, ttl / 2, lease / 2],
                7,
                UNIT_CLOCK_PROFILE_A,
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
            let before = strict_snapshot(Authorization::Allow, base);
            let mut values = [base; 4];
            values[field] = base + 1;
            let after = strict_snapshot_with(
                Authorization::Allow,
                values,
                7,
                UNIT_CLOCK_PROFILE_A,
                DIGEST,
            );
            prop_assert!(
                validate_advisory_effect(AdvisoryPolicy::RestrictOnly, &before, &after).is_err()
            );
        }
    }
}
