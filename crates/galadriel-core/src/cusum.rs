//! A two-sided CUSUM change detector.
//!
//! The tabular CUSUM accumulates deviations from a configured target beyond a
//! slack `k`, and alarms when either the upper or lower
//! cumulative sum exceeds the threshold `h`. It catches a *sustained* mean shift
//! (which spoofing, jamming, faults, or drift may cause) faster than a single-window test,
//! while a slack band
//! rejects transient benign spikes.
//!
//! [`crate::Mirror`] scales NIS and its null mean by `sqrt(2*dof)` before
//! calling this generic accumulator, so detector-level slack and threshold
//! parameters have comparable null-standard-deviation units across dimensions.

/// Two-sided tabular CUSUM.
#[derive(Debug, Clone)]
pub struct Cusum {
    target: f64,
    slack: f64,
    threshold: f64,
    hi: f64,
    lo: f64,
}

impl Cusum {
    /// Add a short signed expression after normalizing its terms, saturating only
    /// when the mathematical result itself is outside the finite `f64` range.
    fn saturating_sum(terms: &[f64]) -> f64 {
        let scale = terms.iter().map(|term| term.abs()).fold(0.0_f64, f64::max);
        if scale == 0.0 {
            return 0.0;
        }
        let scaled = terms.iter().map(|term| term / scale).sum::<f64>();
        let value = scale * scaled;
        if value.is_finite() {
            value
        } else {
            value.signum() * f64::MAX
        }
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
        })
    }

    /// Feed one NIS sample; returns whether the detector is currently in alarm.
    pub fn update(&mut self, x: f64) -> crate::Result<bool> {
        if !x.is_finite() {
            return Err(crate::GaladrielError::NonFinite("Cusum::update"));
        }
        let hi = Self::saturating_sum(&[self.hi, x, -self.target, -self.slack]).max(0.0);
        let lo = Self::saturating_sum(&[self.lo, self.target, -x, -self.slack]).max(0.0);
        self.hi = hi;
        self.lo = lo;
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

    /// Reset both cumulative sums to zero.
    pub fn reset(&mut self) {
        self.hi = 0.0;
        self.lo = 0.0;
    }
}

#[cfg(test)]
mod tests {
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
        let mut c = Cusum::new(3.0, 1.0, 5.0).unwrap();
        for _ in 0..10 {
            c.update(20.0).unwrap();
        }
        assert!(c.alarm());
        c.reset();
        assert!(!c.alarm() && c.hi() == 0.0 && c.lo() == 0.0);
    }

    #[test]
    fn invalid_values_do_not_poison_state() {
        assert!(Cusum::new(0.0, 1.0, 5.0).is_err());
        assert!(Cusum::new(3.0, f64::NAN, 5.0).is_err());
        let mut c = Cusum::new(3.0, 1.0, 5.0).unwrap();
        assert!(c.update(f64::INFINITY).is_err());
        assert_eq!((c.hi(), c.lo()), (0.0, 0.0));
    }

    #[test]
    fn finite_extreme_updates_saturate_into_alarm_instead_of_erroring() {
        let mut c = Cusum::new(3.0, 1.0, 5.0).unwrap();

        assert!(c.update(f64::MAX).unwrap());
        assert!(c.update(f64::MAX).unwrap());
        assert_eq!(c.hi(), f64::MAX);
        assert!(c.lo().is_finite());
    }
}
