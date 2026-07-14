//! Numerically robust χ² distribution helpers.
//!
//! The original hand-rolled incomplete-gamma loop silently stopped converging at
//! larger window degrees of freedom and lost extreme upper-tail probabilities to
//! `1 - CDF` cancellation. These wrappers use `statrs`' checked regularized-gamma
//! implementation and define the distribution boundaries explicitly.

#[cfg(test)]
use statrs::function::gamma::checked_gamma_lr;
use statrs::function::gamma::checked_gamma_ur;

#[cfg(test)]
use statrs::function::gamma::ln_gamma;

/// Regularized lower incomplete gamma `P(a, x) = γ(a,x) / Γ(a)`.
///
/// Returns NaN outside `a > 0, x >= 0` or for NaN input.
#[cfg(test)]
fn gammp(a: f64, x: f64) -> f64 {
    if a.is_nan() || x.is_nan() || a <= 0.0 || x < 0.0 || a == f64::INFINITY {
        return f64::NAN;
    }
    if x == 0.0 {
        return 0.0;
    }
    if x == f64::INFINITY {
        return 1.0;
    }
    checked_gamma_lr(a, x).unwrap_or(f64::NAN)
}

/// Regularized upper incomplete gamma `Q(a, x) = Γ(a,x) / Γ(a)`.
///
/// This evaluates the upper tail directly instead of subtracting the CDF.
/// Returns NaN outside `a > 0, x >= 0` or for NaN input.
fn gammq(a: f64, x: f64) -> f64 {
    if a.is_nan() || x.is_nan() || a <= 0.0 || x < 0.0 || a == f64::INFINITY {
        return f64::NAN;
    }
    if x == 0.0 {
        return 1.0;
    }
    if x == f64::INFINITY {
        return 0.0;
    }
    checked_gamma_ur(a, x).unwrap_or(f64::NAN)
}

/// CDF of the χ² distribution with `k` degrees of freedom at `x`.
#[cfg(test)]
fn chi2_cdf(x: f64, k: f64) -> f64 {
    gammp(k / 2.0, x / 2.0)
}

/// Survival function (right tail) of χ²(`k`) at `x`.
pub(crate) fn chi2_sf(x: f64, k: f64) -> f64 {
    gammq(k / 2.0, x / 2.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() < tol
    }

    #[test]
    fn ln_gamma_known_values() {
        assert!(close(ln_gamma(5.0), 24f64.ln(), 1e-12));
        assert!(close(
            ln_gamma(0.5),
            std::f64::consts::PI.sqrt().ln(),
            1e-12
        ));
        assert!(close(ln_gamma(1.0), 0.0, 1e-12));
    }

    #[test]
    fn chi2_critical_values() {
        assert!(close(chi2_sf(3.841, 1.0), 0.05, 1e-3));
        assert!(close(chi2_sf(7.815, 3.0), 0.05, 1e-3));
        assert!(close(chi2_sf(11.345, 3.0), 0.01, 1e-3));
        assert!(close(chi2_sf(5.991, 2.0), 0.05, 1e-3));
    }

    #[test]
    fn survival_function_preserves_small_upper_tail_probabilities() {
        // For χ²(2), SF(x) = exp(-x/2) exactly.
        for x in [40.0_f64, 70.0, 80.0, 100.0] {
            let expected = (-x / 2.0).exp();
            let actual = chi2_sf(x, 2.0);
            assert!(actual > 0.0);
            assert!((actual / expected - 1.0).abs() < 1e-12);
        }
    }

    #[test]
    fn remains_calibrated_at_large_degrees_of_freedom() {
        for k in [1_000.0, 100_000.0, 1_000_000.0, 16_000_000.0] {
            let at_mean = chi2_sf(k, k);
            assert!(
                (0.49..0.51).contains(&at_mean),
                "SF at the mean should approach 0.5 for k={k}, got {at_mean}"
            );
        }
    }

    #[test]
    fn distribution_boundaries_are_defined() {
        assert_eq!(chi2_cdf(0.0, 3.0), 0.0);
        assert_eq!(chi2_sf(0.0, 3.0), 1.0);
        assert_eq!(chi2_cdf(f64::INFINITY, 3.0), 1.0);
        assert_eq!(chi2_sf(f64::INFINITY, 3.0), 0.0);
        assert!(chi2_cdf(1.0, 0.0).is_nan());
        assert!(chi2_sf(f64::NAN, 3.0).is_nan());
    }

    proptest! {
        #[test]
        fn cdf_is_a_probability(x in 0.0f64..2.0e7, k in 1.0f64..2.0e7) {
            let p = chi2_cdf(x, k);
            prop_assert!(p.is_finite() && (0.0..=1.0).contains(&p));
        }

        #[test]
        fn cdf_is_monotone_in_x(x in 0.0f64..1.0e7, dx in 0.0f64..1.0e7, k in 1.0f64..2.0e7) {
            prop_assert!(chi2_cdf(x + dx, k) >= chi2_cdf(x, k) - 1e-12);
        }

        #[test]
        fn survival_complements_cdf(x in 0.0f64..2.0e7, k in 1.0f64..2.0e7) {
            prop_assert!((chi2_cdf(x, k) + chi2_sf(x, k) - 1.0).abs() < 1e-10);
        }
    }
}
