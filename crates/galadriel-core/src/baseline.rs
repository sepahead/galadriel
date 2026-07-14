//! The cheap yardstick: a windowed **NIS χ² consistency test** per channel.
//!
//! Under the null hypothesis each `NIS ~ χ²(dof)` i.i.d., so a window of `n`
//! samples has sum `~ χ²(n·dof)`. The right-tail p-value flags an improbably
//! **high** sum: evidence of inflated innovations, without identifying their cause.
//! This is the statistic the optional PID engine must add value over.

use crate::chi2;
use crate::window::NisWindow;

/// Smallest per-test significance supported by the chi-square tail implementation.
///
/// `statrs` deliberately rounds sufficiently small upper tails to zero before the
/// last representable subnormal `f64` values. Keeping the decision threshold in
/// the normal range ensures that this representational underflow cannot reverse
/// the strict `p_right < alpha` decision.
pub const MIN_NIS_TEST_ALPHA: f64 = f64::MIN_POSITIVE;

/// Output-only result of the windowed NIS consistency test for one channel.
///
/// Fields are private so callers cannot fabricate an internally contradictory
/// statistic such as `elevated = false` with a tail below the accepted alpha.
/// Only [`nis_consistency`] constructs this value.
///
/// ```compile_fail
/// use galadriel_core::baseline::NisStat;
/// let _ = NisStat { n: 1 };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NisStat {
    /// Samples in the window.
    n: usize,
    /// χ² degrees of freedom per sample.
    dof: u8,
    /// Mean NIS over the window (≈ `dof` under the null).
    mean_nis: f64,
    /// Sum of NIS over the window (`~ χ²(n·dof)` under the null).
    sum_nis: f64,
    /// Right-tail p-value of `sum_nis` under `χ²(n·dof)`.
    p_right: f64,
    /// Whether the window's NIS is improbably high at the given significance.
    elevated: bool,
}

impl NisStat {
    /// Samples represented by this statistic.
    pub const fn n(&self) -> usize {
        self.n
    }

    /// Chi-square degrees of freedom per retained sample.
    pub const fn dof(&self) -> u8 {
        self.dof
    }

    /// Mean retained NIS, saturated at `f64::MAX` when necessary.
    pub const fn mean_nis(&self) -> f64 {
        self.mean_nis
    }

    /// Correctly rounded retained NIS sum, saturated at `f64::MAX`.
    pub const fn sum_nis(&self) -> f64 {
        self.sum_nis
    }

    /// Right-tail probability under the configured chi-square null.
    pub const fn p_right(&self) -> f64 {
        self.p_right
    }

    /// Whether the right tail is strictly below the accepted alpha.
    pub const fn elevated(&self) -> bool {
        self.elevated
    }
}

/// Run the NIS χ² consistency test over `window` at significance `alpha`.
pub fn nis_consistency(window: &NisWindow, alpha: f64) -> crate::Result<NisStat> {
    if !alpha.is_finite() || !(MIN_NIS_TEST_ALPHA..1.0).contains(&alpha) {
        return Err(crate::GaladrielError::InvalidConfig(format!(
            "NIS alpha must be finite and in [{MIN_NIS_TEST_ALPHA}, 1)"
        )));
    }
    let n = window.len();
    let dof = window.dof();
    let (sum, mean) = window.summary();
    let k = n as f64 * dof as f64;
    let p_right = if n == 0 { 1.0 } else { chi2::chi2_sf(sum, k) };
    if !p_right.is_finite() {
        return Err(crate::GaladrielError::NonFinite("NIS p-value"));
    }
    Ok(NisStat {
        n,
        dof,
        mean_nis: mean,
        sum_nis: sum,
        p_right,
        elevated: n > 0 && p_right < alpha,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window_of(vals: &[f64], dof: u8) -> NisWindow {
        let mut w = NisWindow::new(vals.len().max(1), dof).unwrap();
        for &v in vals {
            w.push(v).unwrap();
        }
        w
    }

    #[test]
    fn consistent_nis_is_not_elevated() {
        // 64 samples each equal to dof ⇒ sum == n·dof ⇒ p ≈ 0.5.
        let w = window_of(&[3.0; 64], 3);
        let s = nis_consistency(&w, 0.01).unwrap();
        assert!(
            !s.elevated(),
            "consistent stream flagged: p={}",
            s.p_right()
        );
        assert!(s.p_right() > 0.4 && s.p_right() < 0.6);
    }

    #[test]
    fn inflated_nis_is_elevated() {
        // 64 samples at 5× the expected mean ⇒ vanishing right-tail p.
        let w = window_of(&[15.0; 64], 3);
        let s = nis_consistency(&w, 0.01).unwrap();
        assert!(
            s.elevated(),
            "inflated stream not flagged: p={}",
            s.p_right()
        );
        assert!(s.p_right() < 1e-6);
    }

    #[test]
    fn rejects_invalid_alpha() {
        let w = window_of(&[3.0; 4], 3);
        for alpha in [
            f64::NEG_INFINITY,
            -1.0,
            0.0,
            MIN_NIS_TEST_ALPHA / 2.0,
            1.0,
            f64::INFINITY,
            f64::NAN,
        ] {
            assert!(
                nis_consistency(&w, alpha).is_err(),
                "accepted alpha={alpha}"
            );
        }
    }

    #[test]
    fn accepts_the_exact_minimum_alpha_and_keeps_equality_non_elevated() {
        let empty = NisWindow::new(1, 3).unwrap();
        let empty_stat = nis_consistency(&empty, MIN_NIS_TEST_ALPHA).unwrap();
        assert_eq!(empty_stat.p_right(), 1.0);
        assert!(!empty_stat.elevated());

        let w = window_of(&[3.0; 4], 3);
        let p_right = nis_consistency(&w, 0.5).unwrap().p_right();
        let at_equality = nis_consistency(&w, p_right).unwrap();
        assert_eq!(at_equality.p_right(), p_right);
        assert!(!at_equality.elevated(), "p == alpha is not elevated");
    }

    #[test]
    fn admitted_alpha_keeps_a_subnormal_exact_tail_on_the_anomalous_side() {
        // For chi-square(2), SF(1440) = exp(-720), a representable subnormal.
        // statrs rounds this particular tail to zero, but the admitted alpha floor
        // remains larger than the exact tail, so the strict verdict is unchanged.
        let exact_tail = (-720.0_f64).exp();
        assert!(exact_tail > 0.0 && exact_tail < MIN_NIS_TEST_ALPHA);

        let w = window_of(&[1_440.0], 2);
        let stat = nis_consistency(&w, MIN_NIS_TEST_ALPHA).unwrap();
        assert_eq!(stat.p_right(), 0.0);
        assert!(stat.elevated());
    }

    #[test]
    fn finite_extreme_nis_is_an_anomaly_not_a_numeric_error() {
        let w = window_of(&[f64::MAX, f64::MAX], 3);
        let stat = nis_consistency(&w, 0.01).expect("finite NIS remains assessable");

        assert!(stat.elevated());
        assert_eq!(stat.p_right(), 0.0);
        assert_eq!(stat.mean_nis(), f64::MAX);
        assert_eq!(stat.sum_nis(), f64::MAX);
    }
}
