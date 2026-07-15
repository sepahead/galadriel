//! A fixed-capacity sliding window of NIS samples for one `(track, modality)` channel.

use std::collections::VecDeque;

use crate::numeric::ExactMagnitude;

/// Hard allocation bound for one channel window.
pub const MAX_WINDOW_LEN: usize = 65_536;

/// Fixed bytes retained by each exact 34-limb binary64 superaccumulator.
pub const NIS_WINDOW_EXACT_CACHE_BYTES: usize = 34 * std::mem::size_of::<u64>();

const _: () = assert!(
    std::mem::size_of::<ExactMagnitude>() == NIS_WINDOW_EXACT_CACHE_BYTES,
    "detector state budgeting must match the exact-sum cache layout",
);

/// A ring buffer of the most recent NIS samples for a single channel.
///
/// In addition to storage reserved for `capacity` binary64 samples, each window
/// retains a fixed 34-limb (272-byte) exact-sum cache. Normal sum/mean queries are
/// constant-time and independent of the insertion and eviction history.
#[derive(Debug, Clone)]
pub struct NisWindow {
    dof: u8,
    cap: usize,
    buf: VecDeque<f64>,
    // Exact integer sum in binary64's 2^-1074 units. This 34-limb (272-byte)
    // cache makes representable summaries independent of update/eviction history.
    exact_sum: ExactMagnitude,
}

impl NisWindow {
    /// Return a correctly rounded representable sum and an overflow-safe mean.
    ///
    /// NIS samples are non-negative, so a fixed superaccumulator can form their
    /// exact real sum without cancellation or history-dependent rounding. If the
    /// mathematical sum is larger than `f64::MAX`, the returned sum saturates at
    /// `f64::MAX`; such a value is already in the extreme right tail of every
    /// supported chi-squared reference distribution. Only that overflow case
    /// computes the mean by scaling samples by their maximum. The mean remains
    /// representable because it cannot exceed the largest sample.
    pub(crate) fn summary(&self) -> (f64, f64) {
        if self.buf.is_empty() {
            return (0.0, 0.0);
        }

        // Exact add/subtract updates make the cached integer a function only of
        // the retained multiset. It rounds once here, never during ingestion.
        let sum = self.exact_sum.saturating_f64();
        if !self.exact_sum.exceeds_f64_max() {
            return (sum, sum / self.buf.len() as f64);
        }

        let scale = self.buf.iter().copied().reduce(f64::max).unwrap_or(0.0);
        if scale == 0.0 {
            return (sum, 0.0);
        }
        let scaled_sum = self.buf.iter().map(|value| value / scale).sum::<f64>();
        let scaled_mean = (scaled_sum / self.buf.len() as f64).min(1.0);
        (sum, scale * scaled_mean)
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
            exact_sum: ExactMagnitude::default(),
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
        if self.buf.len() >= self.cap {
            if let Some(evicted) = self.buf.pop_front() {
                self.exact_sum.subtract_finite(evicted);
            }
        }
        self.buf.push_back(nis);
        self.exact_sum.add_finite(nis);
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

    /// Correctly rounded sum of the held NIS samples, saturated at `f64::MAX` if
    /// the exact finite-input total is not representable. Runs in `O(1)` time.
    pub fn sum(&self) -> crate::Result<f64> {
        Ok(self.summary().0)
    }

    /// Mean of the held NIS samples (0.0 if empty). Runs in `O(1)` time unless
    /// the exact sum exceeds `f64::MAX`, when an `O(len)` scaled fallback keeps
    /// the mean finite.
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
    use proptest::prelude::*;

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
        assert_eq!(
            NisWindow::new(MAX_WINDOW_LEN, u8::MAX).unwrap().capacity(),
            MAX_WINDOW_LEN
        );

        let mut window = NisWindow::new(2, 3).unwrap();
        window.push(2.0).unwrap();
        let before = window.values().collect::<Vec<_>>();
        for invalid in [f64::NEG_INFINITY, -1.0, f64::INFINITY, f64::NAN] {
            assert!(window.push(invalid).is_err());
            assert_eq!(window.values().collect::<Vec<_>>(), before);
        }
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
    fn overflow_fallback_preserves_an_unequal_extreme_mean_exactly() {
        let mut window = NisWindow::new(2, 3).unwrap();
        window.push(f64::MAX).unwrap();
        window.push(f64::MAX / 2.0).unwrap();

        assert_eq!(window.sum().unwrap(), f64::MAX);
        assert_eq!(window.mean().unwrap(), f64::MAX * 0.75);
    }

    #[test]
    fn rolling_summary_recovers_immediately_after_overflowing_values_are_evicted() {
        let mut window = NisWindow::new(2, 3).unwrap();
        for value in [f64::MAX, f64::MAX, 1.0, 1.0] {
            window.push(value).unwrap();
        }

        assert_eq!(window.sum().unwrap(), 2.0);
        assert_eq!(window.mean().unwrap(), 1.0);
        assert_eq!(window.values().collect::<Vec<_>>(), vec![1.0, 1.0]);
    }

    #[test]
    fn rolling_summary_is_exact_for_the_retained_estimand_and_history_independent() {
        let mut through_history = NisWindow::new(64, 3).unwrap();
        for index in 0..10_000 {
            through_history.push((index % 17) as f64 / 3.0).unwrap();
        }
        let retained = through_history.values().collect::<Vec<_>>();
        let mut direct = NisWindow::new(64, 3).unwrap();
        for value in retained {
            direct.push(value).unwrap();
        }

        // The exact-real sum of the retained binary64 values rounds to 174.0.
        // The former binary64 add/subtract cache drifted one ULP below it, which
        // was enough to reverse a strict p-value comparison at that boundary.
        assert_eq!(through_history.sum().unwrap(), 174.0);
        assert_eq!(
            through_history.sum().unwrap().to_bits(),
            direct.sum().unwrap().to_bits()
        );
        assert_eq!(
            through_history.mean().unwrap().to_bits(),
            direct.mean().unwrap().to_bits()
        );
    }

    #[test]
    fn empty_summary_is_zero_and_window_metadata_is_stable() {
        let window = NisWindow::new(3, 7).unwrap();
        assert!(window.is_empty());
        assert!(!window.is_full());
        assert_eq!(window.len(), 0);
        assert_eq!(window.dof(), 7);
        assert_eq!(window.capacity(), 3);
        assert_eq!(window.sum().unwrap(), 0.0);
        assert_eq!(window.mean().unwrap(), 0.0);
        assert_eq!(window.values().count(), 0);
    }

    proptest! {
        #[test]
        fn bounded_integer_windows_match_the_exact_retained_suffix(
            capacity in 1_usize..128,
            samples in prop::collection::vec(0_u32..10_000, 0..512),
        ) {
            let mut window = NisWindow::new(capacity, 3).unwrap();
            for &sample in &samples {
                window.push(f64::from(sample)).unwrap();
            }

            let retained = &samples[samples.len().saturating_sub(capacity)..];
            let expected_sum = retained.iter().map(|&value| u64::from(value)).sum::<u64>();
            let expected_values = retained.iter().map(|&value| f64::from(value)).collect::<Vec<_>>();
            prop_assert_eq!(window.values().collect::<Vec<_>>(), expected_values);
            prop_assert_eq!(window.sum().unwrap(), expected_sum as f64);
            let expected_mean = if retained.is_empty() {
                0.0
            } else {
                expected_sum as f64 / retained.len() as f64
            };
            prop_assert_eq!(window.mean().unwrap(), expected_mean);
        }
    }
}
