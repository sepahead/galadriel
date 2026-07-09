//! Minimal, dependency-free χ² distribution support: `ln_gamma`, the regularized
//! incomplete gamma functions, and the χ²(k) CDF / survival function.
//!
//! Used by [`crate::baseline`] to turn a windowed NIS sum into a right-tail
//! p-value. Accuracy is ~1e-10 relative, ample for a detection threshold.

/// Natural log of the gamma function, via the Lanczos approximation (g = 7).
pub fn ln_gamma(x: f64) -> f64 {
    // g = 7, n = 9 coefficients.
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        // Reflection: Γ(x)Γ(1-x) = π / sin(πx).
        let pi = std::f64::consts::PI;
        (pi / (pi * x).sin()).ln() - ln_gamma(1.0 - x)
    } else {
        let x = x - 1.0;
        let mut a = C[0];
        let t = x + 7.5;
        for (i, &c) in C.iter().enumerate().skip(1) {
            a += c / (x + i as f64);
        }
        0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
    }
}

/// Regularized lower incomplete gamma `P(a, x)` via a power series (for `x < a+1`).
fn gamma_series(a: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut ap = a;
    let mut del = 1.0 / a;
    let mut sum = del;
    for _ in 0..300 {
        ap += 1.0;
        del *= x / ap;
        sum += del;
        if del.abs() < sum.abs() * 1e-16 {
            break;
        }
    }
    (sum * (-x + a * x.ln() - ln_gamma(a)).exp()).clamp(0.0, 1.0)
}

/// Regularized upper incomplete gamma `Q(a, x)` via a continued fraction
/// (Lentz's method, for `x >= a+1`).
fn gamma_cf(a: f64, x: f64) -> f64 {
    const TINY: f64 = 1e-300;
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / TINY;
    let mut d = 1.0 / b;
    let mut h = d;
    for i in 1..300 {
        let an = -(i as f64) * (i as f64 - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < TINY {
            d = TINY;
        }
        c = b + an / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < 1e-16 {
            break;
        }
    }
    ((-x + a * x.ln() - ln_gamma(a)).exp() * h).clamp(0.0, 1.0)
}

/// Regularized lower incomplete gamma `P(a, x) = γ(a,x) / Γ(a)`.
pub fn gammp(a: f64, x: f64) -> f64 {
    if x <= 0.0 || a <= 0.0 {
        return 0.0;
    }
    if x < a + 1.0 {
        gamma_series(a, x)
    } else {
        1.0 - gamma_cf(a, x)
    }
}

/// Regularized upper incomplete gamma `Q(a, x) = 1 - P(a, x)`.
pub fn gammq(a: f64, x: f64) -> f64 {
    1.0 - gammp(a, x)
}

/// CDF of the χ² distribution with `k` degrees of freedom at `x`.
pub fn chi2_cdf(x: f64, k: f64) -> f64 {
    gammp(k / 2.0, x / 2.0)
}

/// Survival function (right-tail, `1 - CDF`) of χ²(`k`) at `x`.
pub fn chi2_sf(x: f64, k: f64) -> f64 {
    gammq(k / 2.0, x / 2.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() < tol
    }

    #[test]
    fn ln_gamma_known_values() {
        // Γ(5) = 24 ⇒ ln = ln 24
        assert!(close(ln_gamma(5.0), 24f64.ln(), 1e-9));
        // Γ(0.5) = √π
        assert!(close(ln_gamma(0.5), std::f64::consts::PI.sqrt().ln(), 1e-9));
        assert!(close(ln_gamma(1.0), 0.0, 1e-9));
    }

    #[test]
    fn chi2_critical_values() {
        // Standard χ² upper-tail critical values.
        assert!(
            close(chi2_sf(3.841, 1.0), 0.05, 1e-3),
            "χ²(1) 0.95 quantile"
        );
        assert!(
            close(chi2_sf(7.815, 3.0), 0.05, 1e-3),
            "χ²(3) 0.95 quantile"
        );
        assert!(
            close(chi2_sf(11.345, 3.0), 0.01, 1e-3),
            "χ²(3) 0.99 quantile"
        );
        assert!(
            close(chi2_sf(5.991, 2.0), 0.05, 1e-3),
            "χ²(2) 0.95 quantile"
        );
    }

    #[test]
    fn cdf_sf_complementary_and_monotone() {
        for &(x, k) in &[(1.0, 3.0), (5.0, 3.0), (12.0, 3.0), (200.0, 192.0)] {
            assert!(close(chi2_cdf(x, k) + chi2_sf(x, k), 1.0, 1e-9));
        }
        // At the mean (x = k) the CDF is near 0.5 for large k.
        assert!(chi2_cdf(192.0, 192.0) > 0.45 && chi2_cdf(192.0, 192.0) < 0.55);
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The CDF is always a valid probability.
        #[test]
        fn chi2_cdf_is_a_probability(x in 0.0f64..2000.0, k in 1.0f64..300.0) {
            let p = chi2_cdf(x, k);
            prop_assert!((-1e-9..=1.0 + 1e-9).contains(&p), "cdf {p} ∉ [0,1] at x={x} k={k}");
        }

        /// The CDF is monotone non-decreasing in x.
        #[test]
        fn chi2_cdf_is_monotone_in_x(x in 0.0f64..1000.0, dx in 0.0f64..1000.0, k in 1.0f64..300.0) {
            prop_assert!(
                chi2_cdf(x + dx, k) >= chi2_cdf(x, k) - 1e-9,
                "not monotone at x={x} dx={dx} k={k}"
            );
        }

        /// The survival function complements the CDF.
        #[test]
        fn chi2_sf_complements_cdf(x in 0.0f64..2000.0, k in 1.0f64..300.0) {
            prop_assert!((chi2_cdf(x, k) + chi2_sf(x, k) - 1.0).abs() < 1e-6);
        }
    }
}
