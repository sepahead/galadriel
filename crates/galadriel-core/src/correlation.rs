//! The cheap, pure cross-sensor consistency check: pairwise **|Pearson correlation|**.
//!
//! This is galadriel's **default** cross-channel detector. `docs/JUSTIFICATION.md`
//! shows that for the linear-Gaussian innovation-residual regime — galadriel's actual
//! input — this is *as good as* the MI/PID engine (`corr AUC = MI AUC = 1.000`) at a
//! fraction of the cost and with no heavy dependency. So it is the default, and the
//! `pid` engine is reserved as an opt-in escalation for the regimes where correlation
//! is provably weaker: nonlinear or synergistic cross-channel structure, or a
//! correlation-aware adversary.
//!
//! It mirrors the PID engine's structure exactly — a channel's corroboration is its
//! best pairwise statistic with any peer, and the outlier that shares little with
//! everyone is flagged — so the two are drop-in comparable (see `galadriel-eval`).

use crate::observation::Modality;

/// Tunables for the correlation consistency check.
#[derive(Debug, Clone)]
pub struct CorrConfig {
    /// Window length (frames) analysed, taken from each channel's tail.
    pub window: usize,
    /// Minimum aligned samples per channel before a verdict is trusted.
    pub min_samples: usize,
    /// A channel is flagged decoupled if its corroboration falls below
    /// `decouple_ratio × the strongest corroboration in the group`.
    pub decouple_ratio: f64,
    /// …and only when that strongest corroboration clears this floor (there is a
    /// genuine linear consensus to have decoupled from).
    pub corr_floor: f64,
}

impl Default for CorrConfig {
    fn default() -> Self {
        Self {
            window: 128,
            min_samples: 64,
            decouple_ratio: 0.4,
            corr_floor: 0.15,
        }
    }
}

/// Per-channel correlation detail.
#[derive(Debug, Clone)]
pub struct CorrChannel {
    /// Which modality.
    pub modality: Modality,
    /// Aligned samples used.
    pub n: usize,
    /// Corroboration: the channel's best pairwise `|ρ|` with any peer.
    pub corroboration: Option<f64>,
    /// Whether it was flagged decoupled.
    pub decoupled: bool,
}

/// The correlation verdict (same shape as the PID engine's).
#[derive(Debug, Clone, PartialEq)]
pub enum CorrVerdict {
    /// All ready channels linearly corroborate one another.
    Nominal,
    /// One or a minority of channels decoupled (low `|ρ|` with everyone).
    Spoof(Vec<Modality>),
    /// Too few channels/samples or no consensus. Fail closed.
    InsufficientEvidence,
}

/// The full report.
#[derive(Debug, Clone)]
pub struct CorrReport {
    /// Per-channel detail.
    pub channels: Vec<CorrChannel>,
    /// The verdict.
    pub verdict: CorrVerdict,
    /// Rationale.
    pub note: String,
}

/// Absolute Pearson correlation of two equal-length series (0 for a constant series).
pub fn abs_pearson(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len().min(y.len());
    if n == 0 {
        return 0.0;
    }
    let nf = n as f64;
    let mx = x[..n].iter().sum::<f64>() / nf;
    let my = y[..n].iter().sum::<f64>() / nf;
    let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
    for i in 0..n {
        let (dx, dy) = (x[i] - mx, y[i] - my);
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    if sxx <= 0.0 || syy <= 0.0 {
        0.0
    } else {
        (sxy / (sxx.sqrt() * syy.sqrt())).abs().min(1.0)
    }
}

/// Analyse aligned per-channel signed-scalar series for linear cross-sensor decoupling.
/// Requires ≥ 3 channels; the tail `window` is taken and aligned.
pub fn analyze(channels: &[(Modality, Vec<f64>)], cfg: &CorrConfig) -> CorrReport {
    let c = channels.len();
    let w = channels
        .iter()
        .map(|(_, v)| v.len())
        .min()
        .unwrap_or(0)
        .min(cfg.window);

    if c < 3 || w < cfg.min_samples {
        return CorrReport {
            channels: Vec::new(),
            verdict: CorrVerdict::InsufficientEvidence,
            note: format!(
                "need ≥3 channels and ≥{} aligned samples (have {c} channels, w={w})",
                cfg.min_samples
            ),
        };
    }

    let cols: Vec<Vec<f64>> = channels
        .iter()
        .map(|(_, v)| v[v.len() - w..].to_vec())
        .collect();

    // Pairwise |ρ| matrix.
    let mut corr = vec![vec![0.0_f64; c]; c];
    for i in 0..c {
        for j in (i + 1)..c {
            let r = abs_pearson(&cols[i], &cols[j]);
            corr[i][j] = r;
            corr[j][i] = r;
        }
    }

    let mut reports: Vec<CorrChannel> = channels
        .iter()
        .enumerate()
        .map(|(i, (m, _))| {
            let corroboration = (0..c)
                .filter(|&j| j != i)
                .map(|j| corr[i][j])
                .reduce(f64::max);
            CorrChannel {
                modality: *m,
                n: w,
                corroboration,
                decoupled: false,
            }
        })
        .collect();

    let reference = reports
        .iter()
        .filter_map(|r| r.corroboration)
        .fold(f64::MIN, f64::max);

    if reference < cfg.corr_floor {
        return CorrReport {
            verdict: CorrVerdict::InsufficientEvidence,
            note: format!(
                "no coherent linear consensus (strongest |rho| {reference:.3} < floor {:.3})",
                cfg.corr_floor
            ),
            channels: reports,
        };
    }

    let threshold = cfg.decouple_ratio * reference;
    let mut decoupled: Vec<Modality> = Vec::new();
    for r in &mut reports {
        if r.corroboration.is_some_and(|v| v < threshold) {
            r.decoupled = true;
            decoupled.push(r.modality);
        }
    }

    let (verdict, note) = if decoupled.is_empty() {
        (
            CorrVerdict::Nominal,
            format!("{c} channels linearly corroborate (strongest |rho| {reference:.3})"),
        )
    } else {
        let names: Vec<&str> = decoupled.iter().map(|m| m.label()).collect();
        (
            CorrVerdict::Spoof(decoupled.clone()),
            format!(
                "{} channel(s) linearly decoupled: {}",
                decoupled.len(),
                names.join(", ")
            ),
        )
    };

    CorrReport {
        channels: reports,
        verdict,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(n: usize, f: impl Fn(usize) -> f64) -> Vec<f64> {
        (0..n).map(f).collect()
    }

    #[test]
    fn pearson_basics() {
        let x = series(100, |i| i as f64);
        assert!((abs_pearson(&x, &x) - 1.0).abs() < 1e-9);
        let y = series(100, |i| -(i as f64));
        assert!((abs_pearson(&x, &y) - 1.0).abs() < 1e-9);
        assert!(abs_pearson(&x, &vec![1.0; 100]) < 1e-9); // constant → 0
    }

    #[test]
    fn correlated_channels_nominal_one_decoupled_is_spoof() {
        // Three channels: A and B track a shared ramp (correlated); C is decoupled noise.
        let n = 128;
        let a = series(n, |i| (i as f64).sin());
        let b = series(n, |i| (i as f64).sin() + 0.05 * (i as f64).cos());
        let c_good = series(n, |i| (i as f64).sin() - 0.05);
        let c_bad = series(n, |i| ((i * 7 % 13) as f64) - 6.0); // unrelated

        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let clean = vec![
            (mods[0], a.clone()),
            (mods[1], b.clone()),
            (mods[2], c_good),
        ];
        assert_eq!(
            analyze(&clean, &CorrConfig::default()).verdict,
            CorrVerdict::Nominal
        );

        let spoofed = vec![(mods[0], a), (mods[1], b), (mods[2], c_bad)];
        match analyze(&spoofed, &CorrConfig::default()).verdict {
            CorrVerdict::Spoof(v) => assert!(v.contains(&Modality::Acoustic)),
            other => panic!("expected Spoof(acoustic), got {other:?}"),
        }
    }

    #[test]
    fn fewer_than_three_channels_is_insufficient_evidence() {
        let n = 128;
        let a = series(n, |i| (i as f64).sin());
        let b = series(n, |i| (i as f64).sin() + 0.05);
        let two = vec![(Modality::Visual, a), (Modality::Radar, b)];
        assert_eq!(
            analyze(&two, &CorrConfig::default()).verdict,
            CorrVerdict::InsufficientEvidence
        );
    }

    #[test]
    fn no_linear_consensus_fails_closed() {
        use std::f64::consts::PI;
        // Three orthogonal sinusoids (DFT basis over a full period) — pairwise |ρ| ≈ 0, so
        // there is no coherent consensus to decouple from → fail closed, not a false Spoof.
        let n = 120;
        let s = |k: f64| series(n, |i| (2.0 * PI * k * i as f64 / n as f64).sin());
        let chans = vec![
            (Modality::Visual, s(1.0)),
            (Modality::Radar, s(2.0)),
            (Modality::Acoustic, s(3.0)),
        ];
        assert_eq!(
            analyze(&chans, &CorrConfig::default()).verdict,
            CorrVerdict::InsufficientEvidence
        );
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// `|ρ|` is always a finite value in [0, 1] and symmetric in its arguments.
        #[test]
        fn abs_pearson_is_a_unit_symmetric_magnitude(
            pairs in prop::collection::vec((-1000.0f64..1000.0, -1000.0f64..1000.0), 3..80)
        ) {
            let x: Vec<f64> = pairs.iter().map(|p| p.0).collect();
            let y: Vec<f64> = pairs.iter().map(|p| p.1).collect();
            let r = abs_pearson(&x, &y);
            prop_assert!(r.is_finite(), "abs_pearson not finite: {r}");
            prop_assert!((-1e-9..=1.0 + 1e-9).contains(&r), "abs_pearson {r} ∉ [0,1]");
            prop_assert!(
                (abs_pearson(&x, &y) - abs_pearson(&y, &x)).abs() < 1e-9,
                "abs_pearson not symmetric"
            );
        }

        /// A non-constant series correlates perfectly with itself.
        #[test]
        fn abs_pearson_self_correlation_is_one(
            v in prop::collection::vec(-1000.0f64..1000.0, 3..80)
        ) {
            prop_assume!(v.iter().any(|&a| (a - v[0]).abs() > 1e-2));
            prop_assert!((abs_pearson(&v, &v) - 1.0).abs() < 1e-4, "self-corr ≠ 1");
        }
    }
}
