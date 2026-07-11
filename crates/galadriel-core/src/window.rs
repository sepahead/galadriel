//! A fixed-capacity sliding window of NIS samples for one `(track, modality)` channel.

use std::collections::VecDeque;

/// Hard allocation bound for one channel window.
pub const MAX_WINDOW_LEN: usize = 65_536;

/// A ring buffer of the most recent NIS samples for a single channel.
#[derive(Debug, Clone)]
pub struct NisWindow {
    dof: u8,
    cap: usize,
    buf: VecDeque<f64>,
    /// Representable rolling total. `None` means the mathematical finite-input
    /// total currently exceeds `f64::MAX` and must use the scaled fallback.
    cached_sum: Option<f64>,
    updates_since_rebuild: usize,
}

impl NisWindow {
    /// Return a representable sum and an overflow-safe mean.
    ///
    /// NIS samples are non-negative, so scaling by the largest sample avoids
    /// intermediate overflow without cancellation. If the mathematical sum is
    /// larger than `f64::MAX`, the returned sum saturates at `f64::MAX`; such a
    /// value is already in the extreme right tail of every supported chi-squared
    /// reference distribution. The mean remains representable because it cannot
    /// exceed the largest sample.
    fn scaled_summary(&self) -> (f64, f64, bool) {
        let Some(scale) = self.buf.iter().copied().reduce(f64::max) else {
            return (0.0, 0.0, false);
        };
        if scale == 0.0 {
            return (0.0, 0.0, false);
        }

        let scaled_sum = self.buf.iter().map(|value| value / scale).sum::<f64>();
        let raw_sum = scale * scaled_sum;
        let overflowed = !raw_sum.is_finite();
        let sum = raw_sum.min(f64::MAX);
        let scaled_mean = (scaled_sum / self.buf.len() as f64).min(1.0);
        let mean = scale * scaled_mean;
        (sum, mean, overflowed)
    }

    fn rebuild_cache(&mut self) {
        let (sum, _, overflowed) = self.scaled_summary();
        self.cached_sum = (!overflowed).then_some(sum);
        self.updates_since_rebuild = 0;
    }

    pub(crate) fn summary(&self) -> (f64, f64) {
        if self.buf.is_empty() {
            return (0.0, 0.0);
        }
        if let Some(sum) = self.cached_sum {
            return (sum, sum / self.buf.len() as f64);
        }
        let (sum, mean, _) = self.scaled_summary();
        (sum, mean)
    }

    /// Create an empty window of the given capacity and χ² degrees of freedom.
    pub fn new(cap: usize, dof: u8) -> crate::Result<Self> {
        use crate::GaladrielError::{InvalidConfig, InvalidObservation};
        if cap == 0 || cap > MAX_WINDOW_LEN {
            return Err(InvalidConfig(format!(
                "window capacity must be in 1..={MAX_WINDOW_LEN}"
            )));
        }
        if dof == 0 {
            return Err(InvalidObservation("window dof must be > 0".into()));
        }
        let mut buf = VecDeque::new();
        buf.try_reserve_exact(cap).map_err(|_| {
            InvalidConfig(format!(
                "could not reserve storage for a {cap}-sample NIS window"
            ))
        })?;
        Ok(Self {
            dof,
            cap,
            buf,
            cached_sum: Some(0.0),
            updates_since_rebuild: 0,
        })
    }

    /// Push a NIS sample, evicting the oldest if at capacity.
    pub fn push(&mut self, nis: f64) -> crate::Result<()> {
        use crate::GaladrielError::{InvalidObservation, NonFinite};
        if !nis.is_finite() {
            return Err(NonFinite("NisWindow::push"));
        }
        if nis < 0.0 {
            return Err(InvalidObservation("NIS sample must be >= 0".into()));
        }
        let evicted = (self.buf.len() >= self.cap)
            .then(|| self.buf.pop_front())
            .flatten();
        let dominant_eviction = evicted.is_some_and(|oldest| {
            self.cached_sum
                .is_some_and(|sum| sum > 0.0 && oldest >= sum / 2.0)
        });
        self.buf.push_back(nis);
        if let Some(sum) = self.cached_sum {
            let retained = (sum - evicted.unwrap_or(0.0)).max(0.0);
            let next = retained + nis;
            self.cached_sum = next.is_finite().then_some(next);
        }
        self.updates_since_rebuild = self.updates_since_rebuild.saturating_add(1);
        // A dominant eviction can expose small values lost beside the old scale.
        // Periodic rebuilding bounds ordinary rolling-roundoff while keeping the
        // common ingest-and-assess path amortized O(1).
        if dominant_eviction || self.updates_since_rebuild >= self.cap.max(1_024) {
            self.rebuild_cache();
        }
        Ok(())
    }

    /// Number of samples currently held.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the window holds no samples.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether the window is at capacity.
    pub fn is_full(&self) -> bool {
        self.buf.len() >= self.cap
    }

    /// χ² degrees of freedom for this channel's NIS.
    pub fn dof(&self) -> u8 {
        self.dof
    }

    /// Window capacity.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Sum of the held NIS samples, saturated at `f64::MAX` if the exact finite-input
    /// total is not representable.
    pub fn sum(&self) -> crate::Result<f64> {
        Ok(self.summary().0)
    }

    /// Mean of the held NIS samples (0.0 if empty).
    pub fn mean(&self) -> crate::Result<f64> {
        Ok(self.summary().1)
    }

    /// Iterator over the held samples, oldest first.
    pub fn values(&self) -> impl Iterator<Item = f64> + '_ {
        self.buf.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_at_capacity() {
        let mut w = NisWindow::new(3, 3).unwrap();
        for v in [1.0, 2.0, 3.0, 4.0] {
            w.push(v).unwrap();
        }
        assert_eq!(w.len(), 3);
        assert!(w.is_full());
        assert_eq!(w.values().collect::<Vec<_>>(), vec![2.0, 3.0, 4.0]);
        assert!((w.mean().unwrap() - 3.0).abs() < 1e-12);
    }

    #[test]
    fn rejects_invalid_samples_and_allocations() {
        assert!(NisWindow::new(0, 3).is_err());
        assert!(NisWindow::new(MAX_WINDOW_LEN + 1, 3).is_err());
        assert!(NisWindow::new(1, 0).is_err());

        let mut window = NisWindow::new(2, 3).unwrap();
        assert!(window.push(f64::INFINITY).is_err());
        assert!(window.push(-1.0).is_err());
    }

    #[test]
    fn finite_extreme_samples_have_a_saturated_sum_and_finite_mean() {
        let mut window = NisWindow::new(2, 3).unwrap();
        window.push(f64::MAX).unwrap();
        window.push(f64::MAX).unwrap();

        assert_eq!(window.sum().unwrap(), f64::MAX);
        assert_eq!(window.mean().unwrap(), f64::MAX);
    }

    #[test]
    fn rolling_summary_recovers_small_values_after_a_dominant_eviction() {
        let mut window = NisWindow::new(3, 3).unwrap();
        for value in [f64::MAX, 1.0, 1.0, 1.0] {
            window.push(value).unwrap();
        }

        assert_eq!(window.sum().unwrap(), 3.0);
        assert_eq!(window.mean().unwrap(), 1.0);
        assert_eq!(window.values().collect::<Vec<_>>(), vec![1.0, 1.0, 1.0]);
    }

    #[test]
    fn rolling_summary_stays_close_to_the_retained_values() {
        let mut window = NisWindow::new(64, 3).unwrap();
        for index in 0..10_000 {
            window.push((index % 17) as f64 / 3.0).unwrap();
        }
        let expected = window.values().sum::<f64>();

        assert!((window.sum().unwrap() - expected).abs() < 1e-10);
        assert!((window.mean().unwrap() - expected / window.len() as f64).abs() < 1e-12);
    }
}
