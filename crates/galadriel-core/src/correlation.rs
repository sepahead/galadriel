//! The cheap, pure cross-sensor consistency check: signed pairwise **Pearson correlation**.
//!
//! This is galadriel's **default** cross-channel detector. The controlled synthetic
//! studies described in `docs/JUSTIFICATION.md` compare it with the optional MI/PID
//! engine under explicitly generated linear and nonlinear dependence. Those studies
//! do not establish equivalence, operational accuracy, or coverage of a deployed
//! residual distribution. Correlation remains the default because it is inexpensive,
//! signed, and interpretable; MI/PID is an opt-in research diagnostic.
//!
//! Like the PID engine, it builds pairwise evidence and requires a unique positive
//! strict-majority consensus before attributing an outsider. The statistics and
//! confirmation procedures differ, so their scores are comparable only within the
//! explicitly documented evaluation protocol (see `galadriel-eval`).

use crate::observation::Modality;

/// Largest tail window accepted by the correlation detector.
pub const MAX_CORRELATION_WINDOW: usize = 65_536;

/// Maximum pair-sample products evaluated in one correlation assessment.
///
/// For the current six modalities this admits the full maximum window while
/// retaining a separate work bound if the modality set grows in the future.
pub const MAX_CORRELATION_PAIR_SAMPLES: usize = 1_000_000;

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
    /// Per-assessment family-wise false-consensus bound under the approximate
    /// Fisher-z null, Bonferroni-corrected across all channel pairs.
    pub family_alpha: f64,
}

impl Default for CorrConfig {
    fn default() -> Self {
        Self {
            window: 128,
            min_samples: 64,
            decouple_ratio: 0.4,
            corr_floor: 0.15,
            family_alpha: 0.01,
        }
    }
}

impl CorrConfig {
    /// Validate estimator, allocation, and probability-domain invariants.
    pub fn validate(&self) -> crate::Result<()> {
        use crate::GaladrielError::InvalidConfig;
        if self.window < 4 {
            return Err(InvalidConfig("correlation window must be >= 4".into()));
        }
        if self.window > MAX_CORRELATION_WINDOW {
            return Err(InvalidConfig(format!(
                "correlation window must be <= {MAX_CORRELATION_WINDOW}"
            )));
        }
        if self.min_samples < 4 || self.min_samples > self.window {
            return Err(InvalidConfig(
                "correlation min_samples must be in 4..=window".into(),
            ));
        }
        if !self.decouple_ratio.is_finite()
            || self.decouple_ratio <= 0.0
            || self.decouple_ratio > 1.0
        {
            return Err(InvalidConfig(
                "correlation decouple_ratio must be finite and in (0, 1]".into(),
            ));
        }
        if !self.corr_floor.is_finite() || self.corr_floor <= 0.0 || self.corr_floor > 1.0 {
            return Err(InvalidConfig(
                "correlation corr_floor must be finite and in (0, 1]".into(),
            ));
        }
        if !self.family_alpha.is_finite() || self.family_alpha <= 0.0 || self.family_alpha >= 1.0 {
            return Err(InvalidConfig(
                "correlation family_alpha must be finite and in (0, 1)".into(),
            ));
        }
        Ok(())
    }
}

/// Per-channel correlation detail.
#[derive(Debug, Clone)]
pub struct CorrChannel {
    /// Which modality.
    pub modality: Modality,
    /// Aligned samples used.
    pub n: usize,
    /// Corroboration: the channel's best signed pairwise `ρ` with any peer.
    pub corroboration: Option<f64>,
    /// Whether it was flagged decoupled.
    pub decoupled: bool,
}

/// The correlation verdict (same shape as the PID engine's).
#[derive(Debug, Clone, PartialEq)]
pub enum CorrVerdict {
    /// All ready channels belong to one strict-majority positive-consensus clique.
    Nominal,
    /// One or a minority of channels decoupled (low signed `ρ` with every member
    /// of the positive-consensus clique).
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

/// Signed Pearson correlation of two equal-length finite series.
///
/// Each column is independently scaled before centering so large but finite input
/// cannot overflow the mean, variance, or covariance. Constant or numerically
/// degenerate columns are undefined for Pearson correlation and return an error;
/// they are never fabricated into a low edge that could accuse a channel.
pub fn pearson(x: &[f64], y: &[f64]) -> crate::Result<f64> {
    if x.len() != y.len() {
        return Err(crate::GaladrielError::InvalidChannels(format!(
            "Pearson columns must have equal length ({} != {})",
            x.len(),
            y.len()
        )));
    }
    if x.is_empty() {
        return Err(crate::GaladrielError::InvalidChannels(
            "Pearson columns must not be empty".into(),
        ));
    }
    if !x.iter().chain(y).all(|value| value.is_finite()) {
        return Err(crate::GaladrielError::NonFinite("Pearson input"));
    }
    let n = x.len();
    let bounds = |values: &[f64]| {
        values.iter().copied().fold(
            (f64::INFINITY, f64::NEG_INFINITY),
            |(minimum, maximum), value| (minimum.min(value), maximum.max(value)),
        )
    };
    let ((x_min, x_max), (y_min, y_max)) = (bounds(x), bounds(y));
    if x_min == x_max || y_min == y_max {
        return Err(crate::GaladrielError::InvalidChannels(
            "Pearson columns must be non-degenerate".into(),
        ));
    }
    // Range-center before accumulating. Unlike scaling by max(|x|), this is
    // translation invariant: a large finite offset cannot erase small but
    // representable variation. The midpoint formula cannot overflow.
    let x_center = x_min / 2.0 + x_max / 2.0;
    let y_center = y_min / 2.0 + y_max / 2.0;
    let x_scale = (x_min - x_center).abs().max((x_max - x_center).abs());
    let y_scale = (y_min - y_center).abs().max((y_max - y_center).abs());
    let nf = n as f64;
    let mx = x
        .iter()
        .map(|value| (value - x_center) / x_scale)
        .sum::<f64>()
        / nf;
    let my = y
        .iter()
        .map(|value| (value - y_center) / y_scale)
        .sum::<f64>()
        / nf;
    let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
    for i in 0..n {
        let (dx, dy) = (
            (x[i] - x_center) / x_scale - mx,
            (y[i] - y_center) / y_scale - my,
        );
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    if !sxx.is_finite() || !syy.is_finite() || sxx <= f64::EPSILON * nf || syy <= f64::EPSILON * nf
    {
        Err(crate::GaladrielError::InvalidChannels(
            "Pearson columns are numerically degenerate".into(),
        ))
    } else {
        let correlation = sxy / (sxx.sqrt() * syy.sqrt());
        if !correlation.is_finite() {
            return Err(crate::GaladrielError::NonFinite("Pearson result"));
        }
        Ok(correlation.clamp(-1.0, 1.0))
    }
}

/// Absolute Pearson magnitude, retained for evaluation code that intentionally
/// studies sign-invariant dependence. The production detector uses [`pearson`].
pub fn abs_pearson(x: &[f64], y: &[f64]) -> crate::Result<f64> {
    pearson(x, y).map(f64::abs)
}

/// Analyse aligned per-channel signed-scalar series for linear cross-sensor decoupling.
/// Requires ≥ 3 channels; the tail `window` is taken and aligned.
pub fn analyze(channels: &[(Modality, Vec<f64>)], cfg: &CorrConfig) -> crate::Result<CorrReport> {
    cfg.validate()?;
    let c = channels.len();
    let unique = channels
        .iter()
        .map(|(modality, _)| *modality)
        .collect::<std::collections::HashSet<_>>();
    if unique.len() != c {
        return Err(crate::GaladrielError::InvalidChannels(
            "correlation modalities must be unique".into(),
        ));
    }
    let lengths: std::collections::HashSet<usize> =
        channels.iter().map(|(_, values)| values.len()).collect();
    if lengths.len() > 1 {
        return Err(crate::GaladrielError::InvalidChannels(
            "correlation columns must already be sequence-aligned and equal-length".into(),
        ));
    }
    let w = channels
        .first()
        .map_or(0, |(_, values)| values.len())
        .min(cfg.window);

    let pair_count = c
        .checked_mul(c.saturating_sub(1))
        .map(|ordered_pairs| ordered_pairs / 2)
        .ok_or_else(|| {
            crate::GaladrielError::InvalidConfig(
                "correlation channel-pair count overflows usize".into(),
            )
        })?;
    let pair_samples = pair_count.checked_mul(w).ok_or_else(|| {
        crate::GaladrielError::InvalidConfig(
            "correlation pair-sample work estimate overflows usize".into(),
        )
    })?;
    if pair_samples > MAX_CORRELATION_PAIR_SAMPLES {
        return Err(crate::GaladrielError::InvalidConfig(format!(
            "correlation assessment requires {pair_samples} pair-samples; maximum is {MAX_CORRELATION_PAIR_SAMPLES}"
        )));
    }

    if c < 3 || w < cfg.min_samples {
        return Ok(CorrReport {
            channels: Vec::new(),
            verdict: CorrVerdict::InsufficientEvidence,
            note: format!(
                "need ≥3 channels and ≥{} aligned samples (have {c} channels, w={w})",
                cfg.min_samples
            ),
        });
    }

    let cols: Vec<&[f64]> = channels
        .iter()
        .map(|(_, values)| &values[values.len() - w..])
        .collect();

    // Pairwise |ρ| matrix.
    let mut corr = vec![vec![0.0_f64; c]; c];
    for i in 0..c {
        for j in (i + 1)..c {
            let r = pearson(cols[i], cols[j])?;
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
        return Ok(CorrReport {
            verdict: CorrVerdict::InsufficientEvidence,
            note: format!(
                "no coherent positive linear consensus (strongest rho {reference:.3} < floor {:.3})",
                cfg.corr_floor
            ),
            channels: reports,
        });
    }

    let pair_alpha = cfg.family_alpha / pair_count.max(1) as f64;
    let z = statrs::distribution::ContinuousCDF::inverse_cdf(
        &statrs::distribution::Normal::standard(),
        1.0 - pair_alpha,
    );
    let significance_floor = (z / (w as f64 - 3.0).sqrt()).tanh();
    let threshold = cfg
        .corr_floor
        .max(significance_floor)
        .max(cfg.decouple_ratio * reference);

    if reference < threshold {
        return Ok(CorrReport {
            verdict: CorrVerdict::InsufficientEvidence,
            note: format!(
                "no family-wise-significant positive consensus (strongest rho {reference:.3}, required {threshold:.3})"
            ),
            channels: reports,
        });
    }

    // With at most six Modality variants, exhaustively enumerate cliques. A unique
    // strict-majority clique is the minimum structure that supports attribution:
    // mere graph connectivity would let an A-B-C chain masquerade as all-pairs
    // corroboration, while equal disconnected dyads remain honestly ambiguous.
    let mut largest_cliques = Vec::<Vec<usize>>::new();
    let mut largest_size = 0;
    for mask in 1usize..(1usize << c) {
        let members: Vec<usize> = (0..c).filter(|index| mask & (1 << index) != 0).collect();
        if members.len() < largest_size {
            continue;
        }
        let is_clique = members.iter().enumerate().all(|(position, &i)| {
            members[position + 1..]
                .iter()
                .all(|&j| corr[i][j] >= threshold)
        });
        if !is_clique {
            continue;
        }
        if members.len() > largest_size {
            largest_size = members.len();
            largest_cliques.clear();
        }
        largest_cliques.push(members);
    }
    if largest_size * 2 <= c || largest_cliques.len() != 1 {
        return Ok(CorrReport {
            verdict: CorrVerdict::InsufficientEvidence,
            note: format!(
                "ambiguous positive-consensus structure (largest clique {largest_size}/{c}, {} tied); no unique strict majority",
                largest_cliques.len()
            ),
            channels: reports,
        });
    }
    let consensus = &largest_cliques[0];
    let consensus_set: std::collections::HashSet<usize> = consensus.iter().copied().collect();
    let bridged_outsider = (0..c).find(|index| {
        !consensus_set.contains(index)
            && consensus
                .iter()
                .any(|&member| corr[*index][member] >= threshold)
    });
    if let Some(index) = bridged_outsider {
        return Ok(CorrReport {
            verdict: CorrVerdict::InsufficientEvidence,
            note: format!(
                "{} remains positively connected to part of the consensus clique; attribution is ambiguous",
                channels[index].0.label()
            ),
            channels: reports,
        });
    }
    let mut decoupled = Vec::new();
    for (index, report) in reports.iter_mut().enumerate() {
        if !consensus_set.contains(&index) {
            report.decoupled = true;
            decoupled.push(report.modality);
        }
    }

    let (verdict, note) = if decoupled.is_empty() {
        (
            CorrVerdict::Nominal,
            format!(
                "{c} channels form one positive-consensus clique (strongest rho {reference:.3})"
            ),
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

    Ok(CorrReport {
        channels: reports,
        verdict,
        note,
    })
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
        assert!((pearson(&x, &x).unwrap() - 1.0).abs() < 1e-9);
        let y = series(100, |i| -(i as f64));
        assert!((pearson(&x, &y).unwrap() + 1.0).abs() < 1e-9);
        assert!(abs_pearson(&x, &y).unwrap() > 1.0 - 1e-9);
        assert!(pearson(&x, &vec![1.0; 100]).is_err());
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
            analyze(&clean, &CorrConfig::default()).unwrap().verdict,
            CorrVerdict::Nominal
        );

        let spoofed = vec![(mods[0], a), (mods[1], b), (mods[2], c_bad)];
        match analyze(&spoofed, &CorrConfig::default()).unwrap().verdict {
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
            analyze(&two, &CorrConfig::default()).unwrap().verdict,
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
            analyze(&chans, &CorrConfig::default()).unwrap().verdict,
            CorrVerdict::InsufficientEvidence
        );
    }

    #[test]
    fn sign_flip_is_a_decoupling_not_corroboration() {
        let n = 128;
        let x = series(n, |i| (i as f64 / 7.0).sin());
        let channels = vec![
            (Modality::Visual, x.clone()),
            (Modality::Radar, x.clone()),
            (Modality::Acoustic, x.iter().map(|value| -value).collect()),
        ];
        assert_eq!(
            analyze(&channels, &CorrConfig::default()).unwrap().verdict,
            CorrVerdict::Spoof(vec![Modality::Acoustic])
        );
    }

    #[test]
    fn constant_outlier_is_unassessable_not_a_spoof() {
        let n = 128;
        let x = series(n, |i| (i as f64 / 7.0).sin());
        let channels = vec![
            (Modality::Visual, x.clone()),
            (Modality::Radar, x),
            (Modality::Acoustic, vec![1.0; n]),
        ];
        assert!(matches!(
            analyze(&channels, &CorrConfig::default()),
            Err(crate::GaladrielError::InvalidChannels(_))
        ));
    }

    #[test]
    fn disconnected_equal_dyads_are_ambiguous() {
        let n = 128;
        let a = series(n, |i| (i as f64 / 5.0).sin());
        let b = series(n, |i| (i as f64 / 11.0).cos());
        let channels = vec![
            (Modality::Visual, a.clone()),
            (Modality::Radar, a),
            (Modality::Acoustic, b.clone()),
            (Modality::Lidar, b),
        ];
        assert_eq!(
            analyze(&channels, &CorrConfig::default()).unwrap().verdict,
            CorrVerdict::InsufficientEvidence
        );
    }

    #[test]
    fn outsider_bridged_to_one_consensus_member_is_ambiguous() {
        use std::f64::consts::PI;

        let n = 128;
        let common = series(n, |i| (2.0 * PI * i as f64 / n as f64).sin());
        let private = series(n, |i| (4.0 * PI * i as f64 / n as f64).sin());
        let bridge: Vec<f64> = common
            .iter()
            .zip(&private)
            .map(|(shared, private)| shared + private)
            .collect();
        let channels = vec![
            (Modality::Visual, bridge),
            (Modality::Radar, common.clone()),
            (Modality::Acoustic, common),
            (Modality::Lidar, private),
        ];

        assert_eq!(
            analyze(&channels, &CorrConfig::default()).unwrap().verdict,
            CorrVerdict::InsufficientEvidence
        );
    }

    #[test]
    fn configuration_and_actual_pair_work_are_bounded() {
        let oversized = CorrConfig {
            window: MAX_CORRELATION_WINDOW + 1,
            min_samples: 4,
            ..CorrConfig::default()
        };
        assert!(oversized.validate().is_err());

        let cfg = CorrConfig {
            window: MAX_CORRELATION_WINDOW,
            min_samples: 4,
            ..CorrConfig::default()
        };
        let values: Vec<f64> = (0..MAX_CORRELATION_WINDOW)
            .map(|index| index as f64)
            .collect();
        let channels: Vec<_> = Modality::ALL
            .iter()
            .copied()
            .map(|modality| (modality, values.clone()))
            .collect();
        assert!(analyze(&channels, &cfg).is_ok());
    }

    #[test]
    fn finite_scaling_is_stable_and_nonfinite_input_errors() {
        let x = series(128, |i| 1e200 * (i as f64 / 5.0).sin());
        let y = series(128, |i| 1e200 * (i as f64 / 11.0).cos());
        let r = pearson(&x, &y).unwrap();
        assert!(r.is_finite() && r.abs() < 0.5, "rho={r}");
        let mut poisoned = x.clone();
        poisoned[0] = f64::NAN;
        assert!(pearson(&poisoned, &y).is_err());

        let shifted = series(128, |i| 1e15 + i as f64);
        assert!(
            (pearson(&shifted, &shifted).unwrap() - 1.0).abs() < 1e-12,
            "large offsets must not erase representable variation"
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
            prop_assume!(x.iter().any(|&value| (value - x[0]).abs() > 1e-9));
            prop_assume!(y.iter().any(|&value| (value - y[0]).abs() > 1e-9));
            let r = abs_pearson(&x, &y).unwrap();
            prop_assert!(r.is_finite(), "abs_pearson not finite: {r}");
            prop_assert!((-1e-9..=1.0 + 1e-9).contains(&r), "abs_pearson {r} ∉ [0,1]");
            prop_assert!(
                (abs_pearson(&x, &y).unwrap() - abs_pearson(&y, &x).unwrap()).abs() < 1e-9,
                "abs_pearson not symmetric"
            );
        }

        /// A non-constant series correlates perfectly with itself.
        #[test]
        fn abs_pearson_self_correlation_is_one(
            v in prop::collection::vec(-1000.0f64..1000.0, 3..80)
        ) {
            prop_assume!(v.iter().any(|&a| (a - v[0]).abs() > 1e-2));
            prop_assert!((abs_pearson(&v, &v).unwrap() - 1.0).abs() < 1e-4, "self-corr ≠ 1");
        }
    }
}
