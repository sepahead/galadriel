//! A fixed-capacity sliding window of NIS samples for one `(track, modality)` channel.

use std::collections::VecDeque;

/// A ring buffer of the most recent NIS samples for a single channel.
#[derive(Debug, Clone)]
pub struct NisWindow {
    dof: u8,
    cap: usize,
    buf: VecDeque<f64>,
}

impl NisWindow {
    /// Create an empty window of the given capacity and χ² degrees of freedom.
    pub fn new(cap: usize, dof: u8) -> Self {
        let cap = cap.max(1);
        Self {
            dof,
            cap,
            buf: VecDeque::with_capacity(cap),
        }
    }

    /// Push a NIS sample, evicting the oldest if at capacity.
    pub fn push(&mut self, nis: f64) {
        if self.buf.len() >= self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(nis);
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
    pub fn sum(&self) -> f64 {
        self.buf.iter().sum()
    }

    /// Mean of the held NIS samples (0.0 if empty).
    pub fn mean(&self) -> f64 {
        if self.buf.is_empty() {
            0.0
        } else {
            self.sum() / self.buf.len() as f64
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
        let mut w = NisWindow::new(3, 3);
        for v in [1.0, 2.0, 3.0, 4.0] {
            w.push(v);
        }
        assert_eq!(w.len(), 3);
        assert!(w.is_full());
        assert_eq!(w.values().collect::<Vec<_>>(), vec![2.0, 3.0, 4.0]);
        assert!((w.mean() - 3.0).abs() < 1e-12);
    }
}
