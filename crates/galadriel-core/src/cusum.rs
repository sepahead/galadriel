//! A two-sided CUSUM change detector.
//!
//! The tabular CUSUM accumulates deviations from a configured target beyond a
//! slack `k`, and alarms when either the upper or lower cumulative sum reaches
//! the threshold `h`. It can catch a sustained mean shift (which spoofing,
//! jamming, faults, or drift may cause) faster than a single-window test. The
//! slack band suppresses per-sample deviations no larger than `k`; a sufficiently
//! large single sample can still alarm immediately.
//!
//! [`crate::Mirror`] scales NIS and its null mean by `sqrt(2*dof)` before
//! calling this generic accumulator, so detector-level slack and threshold
//! parameters have comparable null-standard-deviation units across dimensions.
//! If an arm's exact update exceeds `f64::MAX`, that arm is terminally saturated
//! and remains in alarm until [`Cusum::reset`]; finite storage cannot retain the
//! otherwise unbounded excess needed to evaluate a later opposing update safely.

use crate::numeric::ExactMagnitude;

/// Two-sided tabular CUSUM.
#[derive(Debug, Clone)]
pub struct Cusum {
    target: f64,
    slack: f64,
    threshold: f64,
    hi: f64,
    lo: f64,
    hi_saturated: bool,
    lo_saturated: bool,
}

impl Cusum {
    /// Add a short signed expression exactly in binary64 units, then round once,
    /// saturating only when the mathematical result is outside the finite range.
    fn saturating_sum_with_overflow(terms: &[f64]) -> (f64, bool) {
        let mut positive = ExactMagnitude::default();
        let mut negative = ExactMagnitude::default();
        for &term in terms {
            debug_assert!(term.is_finite());
            if term.is_sign_negative() {
                negative.add_finite(term.abs());
            } else {
                positive.add_finite(term);
            }
        }
        match positive.cmp(&negative) {
            std::cmp::Ordering::Greater => {
                let magnitude = positive.subtract(&negative);
                (magnitude.saturating_f64(), magnitude.exceeds_f64_max())
            }
            std::cmp::Ordering::Less => (-negative.subtract(&positive).saturating_f64(), false),
            std::cmp::Ordering::Equal => (0.0, false),
        }
    }

    #[cfg(test)]
    fn saturating_sum(terms: &[f64]) -> f64 {
        Self::saturating_sum_with_overflow(terms).0
    }

    /// New detector targeting `target`, with slack `k` and alarm threshold `h`
    /// expressed in the same units as the input series.
    pub fn new(target: f64, slack: f64, threshold: f64) -> crate::Result<Self> {
        use crate::GaladrielError::InvalidConfig;
        if !target.is_finite() || target <= 0.0 {
            return Err(InvalidConfig("CUSUM target must be finite and > 0".into()));
        }
        if !slack.is_finite() || slack < 0.0 {
            return Err(InvalidConfig("CUSUM slack must be finite and >= 0".into()));
        }
        if !threshold.is_finite() || threshold <= 0.0 {
            return Err(InvalidConfig(
                "CUSUM threshold must be finite and > 0".into(),
            ));
        }
        Ok(Self {
            target,
            slack,
            threshold,
            hi: 0.0,
            lo: 0.0,
            hi_saturated: false,
            lo_saturated: false,
        })
    }

    /// Feed one finite sample in the same units as `target`; returns whether the
    /// detector is currently in alarm. [`crate::Mirror`] supplies scaled NIS.
    pub fn update(&mut self, x: f64) -> crate::Result<bool> {
        if !x.is_finite() {
            return Err(crate::GaladrielError::NonFinite("Cusum::update"));
        }
        if !self.hi_saturated {
            let (hi, saturated) =
                Self::saturating_sum_with_overflow(&[self.hi, x, -self.target, -self.slack]);
            self.hi = hi.max(0.0);
            self.hi_saturated = saturated;
        }
        if !self.lo_saturated {
            let (lo, saturated) =
                Self::saturating_sum_with_overflow(&[self.lo, self.target, -x, -self.slack]);
            self.lo = lo.max(0.0);
            self.lo_saturated = saturated;
        }
        Ok(self.alarm())
    }

    /// Whether either cumulative sum has crossed the threshold.
    pub fn alarm(&self) -> bool {
        self.high_alarm() || self.low_alarm()
    }

    /// Whether the above-target arm has crossed the threshold.
    pub fn high_alarm(&self) -> bool {
        self.hi >= self.threshold
    }

    /// Whether the below-target arm has crossed the threshold.
    pub fn low_alarm(&self) -> bool {
        self.lo >= self.threshold
    }

    /// Current upper cumulative sum (drift above target).
    pub fn hi(&self) -> f64 {
        self.hi
    }

    /// Current lower cumulative sum (drift below target).
    pub fn lo(&self) -> f64 {
        self.lo
    }

    /// Reset both cumulative sums to zero, including terminal saturation latches.
    pub fn reset(&mut self) {
        self.hi = 0.0;
        self.lo = 0.0;
        self.hi_saturated = false;
        self.lo_saturated = false;
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn stays_quiet_on_target() {
        let mut c = Cusum::new(3.0, 2.0, 12.0).unwrap();
        for _ in 0..1000 {
            assert!(!c.update(3.0).unwrap());
        }
    }

    #[test]
    fn fires_quickly_on_step_up() {
        let mut c = Cusum::new(3.0, 2.0, 12.0).unwrap();
        let mut fired_at = None;
        for i in 0..20 {
            if c.update(15.0).unwrap() {
                fired_at = Some(i);
                break;
            }
        }
        let at = fired_at.expect("CUSUM never fired on a large step");
        assert!(at <= 3, "CUSUM too slow: fired at frame {at}");
    }

    #[test]
    fn fires_on_sustained_step_down_via_the_lower_arm() {
        // The lower arm is active only when slack < target; with slack 1.0 < target 3.0 a
        // sustained below-target NIS accrues on `lo` and alarms.
        let mut c = Cusum::new(3.0, 1.0, 5.0).unwrap();
        let mut fired = None;
        for i in 0..20 {
            if c.update(0.0).unwrap() {
                fired = Some(i);
                break;
            }
        }
        let at = fired.expect("lower arm never fired on a sustained drop");
        assert!(
            c.lo() > 0.0 && c.hi() == 0.0,
            "the LOWER arm should drive the alarm (hi={}, lo={})",
            c.hi(),
            c.lo()
        );
        assert!(at <= 4, "lower CUSUM too slow: fired at {at}");
    }

    #[test]
    fn reset_clears_both_arms() {
        let mut high = Cusum::new(3.0, 1.0, 5.0).unwrap();
        high.update(20.0).unwrap();
        assert!(high.high_alarm());
        high.reset();
        assert_eq!((high.hi(), high.lo()), (0.0, 0.0));
        assert!(!high.alarm());

        let mut low = Cusum::new(3.0, 1.0, 5.0).unwrap();
        for _ in 0..3 {
            low.update(0.0).unwrap();
        }
        assert!(low.low_alarm());
        low.reset();
        assert_eq!((low.hi(), low.lo()), (0.0, 0.0));
        assert!(!low.alarm());
    }

    #[test]
    fn invalid_values_do_not_poison_state() {
        for target in [f64::NEG_INFINITY, -1.0, 0.0, f64::INFINITY, f64::NAN] {
            assert!(Cusum::new(target, 1.0, 5.0).is_err());
        }
        for slack in [f64::NEG_INFINITY, -1.0, f64::INFINITY, f64::NAN] {
            assert!(Cusum::new(3.0, slack, 5.0).is_err());
        }
        for threshold in [f64::NEG_INFINITY, -1.0, 0.0, f64::INFINITY, f64::NAN] {
            assert!(Cusum::new(3.0, 1.0, threshold).is_err());
        }

        let mut c = Cusum::new(3.0, 1.0, 5.0).unwrap();
        c.update(6.0).unwrap();
        let before = (c.hi(), c.lo());
        for value in [f64::NEG_INFINITY, f64::INFINITY, f64::NAN] {
            assert!(c.update(value).is_err());
            assert_eq!((c.hi(), c.lo()), before);
        }
    }

    #[test]
    fn finite_extreme_updates_saturate_into_alarm_instead_of_erroring() {
        let mut c = Cusum::new(3.0, 1.0, 5.0).unwrap();

        assert!(c.update(f64::MAX).unwrap());
        assert!(c.update(f64::MAX).unwrap());
        assert_eq!(c.hi(), f64::MAX);
        assert!(c.lo().is_finite());
    }

    #[test]
    fn arithmetic_saturation_is_terminal_until_reset_for_both_arms() {
        let threshold = f64::MAX / 2.0;

        let mut high = Cusum::new(1.0, 0.0, threshold).unwrap();
        assert!(high.update(f64::MAX).unwrap());
        assert!(high.update(f64::MAX).unwrap());
        assert_eq!(high.hi(), f64::MAX);
        assert!(high.update(-f64::MAX).unwrap());
        assert_eq!(high.hi(), f64::MAX);
        high.reset();
        assert!(!high.update(1.0).unwrap());

        let mut low = Cusum::new(1.0, 0.0, threshold).unwrap();
        assert!(low.update(-f64::MAX).unwrap());
        assert!(low.update(-f64::MAX).unwrap());
        assert_eq!(low.lo(), f64::MAX);
        assert!(low.update(f64::MAX).unwrap());
        assert_eq!(low.lo(), f64::MAX);
        low.reset();
        assert!(!low.update(1.0).unwrap());
    }

    #[test]
    fn exact_accumulation_preserves_cancellation_residuals_and_saturates_true_overflow() {
        let smallest = f64::from_bits(1);
        assert_eq!(
            Cusum::saturating_sum(&[f64::MAX, -f64::MAX, smallest, 0.0]),
            smallest
        );
        assert_eq!(
            Cusum::saturating_sum(&[f64::MAX, f64::MAX, -f64::MAX, -f64::MAX]),
            0.0
        );
        assert_eq!(Cusum::saturating_sum(&[f64::MAX, f64::MAX]), f64::MAX);
        assert_eq!(Cusum::saturating_sum(&[-f64::MAX, -f64::MAX]), -f64::MAX);
    }

    #[test]
    fn cancellation_at_an_admitted_tiny_threshold_does_not_hide_an_alarm() {
        // These are the exact binary64 coordinates produced by a valid dof=1
        // detector operating point. Their exact-real residual is 2^-51 even
        // though ordinary left-to-right binary64 subtraction rounds to zero.
        let target = 0.707_106_781_186_547_5;
        let slack = 11.529_210_410_948_265;
        let x = 12.236_317_192_134_813;
        let exact_residual = 2.0 * f64::EPSILON;
        assert_eq!(x - target - slack, 0.0);

        let mut c = Cusum::new(target, slack, 1.0e-16).unwrap();
        assert!(c.update(x).unwrap());
        assert_eq!(c.hi(), exact_residual);
        assert!(c.high_alarm());
    }

    #[test]
    fn alarm_boundary_is_inclusive_for_both_arms() {
        let mut high = Cusum::new(3.0, 1.0, 5.0).unwrap();
        assert!(high.update(9.0).unwrap());
        assert_eq!(high.hi(), 5.0);
        assert!(high.high_alarm());

        let mut low = Cusum::new(6.0, 1.0, 5.0).unwrap();
        assert!(low.update(0.0).unwrap());
        assert_eq!(low.lo(), 5.0);
        assert!(low.low_alarm());
    }

    #[test]
    fn one_large_sample_can_cross_the_threshold() {
        let mut c = Cusum::new(3.0, 2.0, 12.0).unwrap();
        assert!(c.update(17.0).unwrap());
        assert_eq!(c.hi(), 12.0);
    }

    proptest! {
        #[test]
        fn integer_sequences_match_an_independent_exact_recurrence(
            target in 1_i64..50,
            slack in 0_i64..25,
            threshold in 1_i64..500,
            samples in prop::collection::vec(-100_i64..200, 0..128),
        ) {
            let mut detector = Cusum::new(target as f64, slack as f64, threshold as f64).unwrap();
            let (mut expected_hi, mut expected_lo) = (0_i64, 0_i64);
            for sample in samples {
                expected_hi = (expected_hi + sample - target - slack).max(0);
                expected_lo = (expected_lo + target - sample - slack).max(0);
                let alarm = detector.update(sample as f64).unwrap();
                prop_assert_eq!(detector.hi(), expected_hi as f64);
                prop_assert_eq!(detector.lo(), expected_lo as f64);
                prop_assert_eq!(
                    alarm,
                    expected_hi >= threshold || expected_lo >= threshold
                );
            }
        }
    }
}
