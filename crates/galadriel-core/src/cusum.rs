//! A two-sided CUSUM change detector on a per-channel NIS stream.
//!
//! The tabular CUSUM accumulates deviations of the NIS from its expected mean
//! (`dof`) beyond a slack `k`, and alarms when either the upper or lower
//! cumulative sum exceeds the threshold `h`. It catches a *sustained* mean shift
//! (a persistent spoof/jam) faster than a single-window test, while a slack band
//! rejects transient benign spikes.

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
}
