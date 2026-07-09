//! A two-sided CUSUM change detector on a per-channel NIS stream.
//!
//! The tabular CUSUM accumulates deviations of the NIS from its expected mean
//! (`dof`) beyond a slack `k`, and alarms when either the upper or lower
//! cumulative sum exceeds the threshold `h`. It catches a *sustained* mean shift
//! (a persistent spoof/jam) faster than a single-window test, while a slack band
//! rejects transient benign spikes.
//!
//! Note: the lower arm accrues only when `x < target − slack`, so with the default
//! configuration (`cusum_slack == dof`) it is inert for a non-negative NIS — the detector
//! is effectively one-sided there, watching only for *inflation*. A configuration with
//! `slack < target` activates the below-target arm.

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
    /// New detector targeting `target` (the null NIS mean, i.e. `dof`), with the
    /// given slack `k` and alarm threshold `h`.
    pub fn new(target: f64, slack: f64, threshold: f64) -> Self {
        Self {
            target,
            slack,
            threshold,
            hi: 0.0,
            lo: 0.0,
        }
    }

    /// Feed one NIS sample; returns whether the detector is currently in alarm.
    pub fn update(&mut self, x: f64) -> bool {
        self.hi = (self.hi + x - self.target - self.slack).max(0.0);
        self.lo = (self.lo + self.target - x - self.slack).max(0.0);
        self.alarm()
    }

    /// Whether either cumulative sum has crossed the threshold.
    pub fn alarm(&self) -> bool {
        self.hi > self.threshold || self.lo > self.threshold
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
        let mut c = Cusum::new(3.0, 2.0, 12.0);
        for _ in 0..1000 {
            assert!(!c.update(3.0));
        }
    }

    #[test]
    fn fires_quickly_on_step_up() {
        let mut c = Cusum::new(3.0, 2.0, 12.0);
        let mut fired_at = None;
        for i in 0..20 {
            if c.update(15.0) {
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
        let mut c = Cusum::new(3.0, 1.0, 5.0);
        let mut fired = None;
        for i in 0..20 {
            if c.update(0.0) {
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
        let mut c = Cusum::new(3.0, 1.0, 5.0);
        for _ in 0..10 {
            c.update(20.0);
        }
        assert!(c.alarm());
        c.reset();
        assert!(!c.alarm() && c.hi() == 0.0 && c.lo() == 0.0);
    }
}
