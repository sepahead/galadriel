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
}

impl NisWindow {
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
        Ok(Self { dof, cap, buf })
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
            self.buf.pop_front();
        }
        self.buf.push_back(nis);
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

    /// Sum of the held NIS samples.
    pub fn sum(&self) -> crate::Result<f64> {
        let sum = self.buf.iter().try_fold(0.0_f64, |sum, value| {
            let next = sum + value;
            next.is_finite().then_some(next)
        });
        sum.ok_or(crate::GaladrielError::NonFinite("NisWindow::sum"))
    }

    /// Mean of the held NIS samples (0.0 if empty).
    pub fn mean(&self) -> crate::Result<f64> {
        if self.buf.is_empty() {
            Ok(0.0)
        } else {
            Ok(self.sum()? / self.buf.len() as f64)
        }
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
}
