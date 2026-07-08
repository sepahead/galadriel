//! The cheap yardstick: a windowed **NIS χ² consistency test** per channel.
//!
//! Under the null hypothesis each `NIS ~ χ²(dof)` i.i.d., so a window of `n`
//! samples has sum `~ χ²(n·dof)`. The right-tail p-value flags an improbably
//! **high** sum — the signature of inflated innovations, i.e. a spoof or jam.
//! This is the statistic the optional PID engine must add value over.

use crate::chi2;
use crate::window::NisWindow;

/// Result of the windowed NIS consistency test for one channel.
#[derive(Debug, Clone, PartialEq)]
pub struct NisStat {
    /// Samples in the window.
    pub n: usize,
    /// χ² degrees of freedom per sample.
    pub dof: u8,
    /// Mean NIS over the window (≈ `dof` under the null).
    pub mean_nis: f64,
    /// Sum of NIS over the window (`~ χ²(n·dof)` under the null).
    pub sum_nis: f64,
    /// Right-tail p-value of `sum_nis` under `χ²(n·dof)`.
    pub p_right: f64,
    /// Whether the window's NIS is improbably high at the given significance.
    pub elevated: bool,
}

/// Run the NIS χ² consistency test over `window` at significance `alpha`.
pub fn nis_consistency(window: &NisWindow, alpha: f64) -> NisStat {
    let n = window.len();
    let dof = window.dof();
    let sum = window.sum();
    let k = n as f64 * dof as f64;
    let p_right = if n == 0 { 1.0 } else { chi2::chi2_sf(sum, k) };
    NisStat {
        n,
        dof,
        mean_nis: if n == 0 { 0.0 } else { sum / n as f64 },
        sum_nis: sum,
        p_right,
        elevated: n > 0 && p_right < alpha,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window_of(vals: &[f64], dof: u8) -> NisWindow {
        let mut w = NisWindow::new(vals.len().max(1), dof);
        for &v in vals {
            w.push(v);
        }
        w
    }

    #[test]
    fn consistent_nis_is_not_elevated() {
        // 64 samples each equal to dof ⇒ sum == n·dof ⇒ p ≈ 0.5.
        let w = window_of(&[3.0; 64], 3);
        let s = nis_consistency(&w, 0.01);
        assert!(!s.elevated, "consistent stream flagged: p={}", s.p_right);
        assert!(s.p_right > 0.4 && s.p_right < 0.6);
    }

    #[test]
    fn inflated_nis_is_elevated() {
        // 64 samples at 5× the expected mean ⇒ vanishing right-tail p.
        let w = window_of(&[15.0; 64], 3);
        let s = nis_consistency(&w, 0.01);
        assert!(s.elevated, "inflated stream not flagged: p={}", s.p_right);
        assert!(s.p_right < 1e-6);
    }
}
