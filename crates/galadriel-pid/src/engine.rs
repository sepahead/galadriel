//! Geometry-gated mutual-information consistency analysis.
//!
//! Pairwise MI is sign-invariant, so this engine is an additive escalation over
//! the signed-correlation default rather than a replacement for it. Attribution
//! requires a unique strict-majority clique. PID atoms remain advisory diagnostics
//! and never drive the verdict.

use std::collections::HashSet;

use galadriel_core::{GaladrielError, Modality};
use pid_core::{
    distance_concentration_stats, intrinsic_dimension_levina_bickel, ksg_mi, pid2_isx_estimate,
    DistanceConcentrationConfig, IntrinsicDimConfig, Jitter, KsgConfig, MatOwned, Metric,
    Pid2Config,
};

const MIN_BOOTSTRAP_RESAMPLES: usize = 20;
const MAX_BOOTSTRAP_RESAMPLES: usize = MAX_PID_WINDOW;
const MAX_QUADRATIC_FIT_WORK: usize = 50_000_000;
const MAX_MODALITIES: usize = Modality::ALL.len();
// pair_mi runs intrinsic-dimension, distance-concentration, and MI estimators.
const ESTIMATOR_FITS_PER_PAIR: usize = 3;
const MAX_PAIR_ESTIMATOR_FITS: usize = pair_count(MAX_MODALITIES) * ESTIMATOR_FITS_PER_PAIR;
// pid2_isx_estimate performs three MI estimates plus one I^sx estimate.
const ESTIMATOR_FITS_PER_ATOM: usize = 4;
const MAX_ATOM_ESTIMATOR_FITS: usize = MAX_MODALITIES * ESTIMATOR_FITS_PER_ATOM;
const MAX_EXCLUDED_CANDIDATES: usize = (MAX_MODALITIES - 1) / 2;
const MAX_CONFIRMATION_EDGE_FITS: usize = max_confirmation_edge_fits(MAX_MODALITIES);
const CONFIRMATION_BOUND_GROUPS: usize = 2;

/// Maximum PID analysis window. The mandatory geometry and kNN estimators are
/// quadratic in the number of samples, so the much larger scalar-window bound
/// is not a safe computational bound for this engine.
pub const MAX_PID_WINDOW: usize = 512;

const ROLE_PAIR_POINT: u64 = 0x5041_4952_504f_494e;
const ROLE_PID_ATOMS: u64 = 0x5049_445f_4154_4f4d;
const ROLE_BOOT_PLAN: u64 = 0x424f_4f54_5f50_4c41;
const ROLE_BOOT_JITTER: u64 = 0x424f_4f54_5f4a_4954;

const fn pair_count(channels: usize) -> usize {
    channels.saturating_mul(channels.saturating_sub(1)) / 2
}

const fn max_confirmation_edge_fits(max_channels: usize) -> usize {
    let mut channels = 3;
    let mut maximum = 0;
    while channels <= max_channels {
        let mut consensus = channels / 2 + 1;
        while consensus < channels {
            let excluded = channels - consensus;
            let fits = pair_count(consensus) + excluded * consensus;
            if fits > maximum {
                maximum = fits;
            }
            consensus += 1;
        }
        channels += 1;
    }
    maximum
}

/// Engine tunables.
#[derive(Debug, Clone)]
pub struct PidConfig {
    /// Window length (frames) analysed, taken from each channel's tail.
    pub window: usize,
    /// Minimum aligned samples per channel before a point-estimate verdict is trusted.
    /// With bootstrap confirmation enabled, [`Self::required_samples`] also requires
    /// enough samples to construct every distinct circular resample.
    pub min_samples: usize,
    /// Seeded jitter magnitude after per-column standardisation.
    pub jitter_std: f64,
    /// Jitter/estimator seed for reproducibility.
    pub seed: u64,
    /// k for the Levina-Bickel intrinsic-dimension estimator (needs `k >= 3`).
    pub geom_k: usize,
    /// Geometry gate: reject if intrinsic dimension exceeds this.
    pub id_max: f64,
    /// Geometry gate: reject if pairwise-distance CV is below this.
    pub cv_min: f64,
    /// Geometry gate: reject if mean-nearest-neighbour / mean-pairwise distance
    /// exceeds this concentration threshold.
    pub nn_ratio_max: f64,
    /// Edge threshold relative to the strongest pairwise MI.
    pub decouple_ratio: f64,
    /// Absolute minimum MI (nats) for a consensus edge.
    pub mi_floor: f64,
    /// Confirm positive point-estimate attribution with circular delete-block intervals.
    /// Disabling this permits explicitly unconfirmed point-estimate verdicts.
    pub bootstrap: bool,
    /// Deterministic circular delete-block resamples (when `bootstrap`).
    pub n_boot: usize,
    /// Consecutive circular frames removed from each resample.
    pub block_size: usize,
    /// Nominal one-sided tail budget shared by the joint worst-consensus lower
    /// bound and joint worst-candidate upper bound in one analysis. This controls
    /// the selected empirical edge family, not post-selection error for the full
    /// clique search.
    pub family_alpha: f64,
}

impl Default for PidConfig {
    fn default() -> Self {
        Self {
            window: 128,
            min_samples: 64,
            jitter_std: 1e-4,
            seed: 1,
            geom_k: 5,
            id_max: 10.0,
            cv_min: 0.01,
            nn_ratio_max: 0.999,
            decouple_ratio: 0.4,
            mi_floor: 0.03,
            bootstrap: true,
            n_boot: 100,
            block_size: 8,
            family_alpha: 0.10,
        }
    }
}

impl PidConfig {
    /// Effective aligned-sample requirement for the configured analysis.
    ///
    /// Bootstrap confirmation needs at least `n_boot` observations because its
    /// circular delete-block plans use distinct starting positions. Applying this
    /// requirement before any estimator prevents an early nominal result in a
    /// window that cannot yet confirm a positive attribution.
    pub fn required_samples(&self) -> usize {
        if self.bootstrap {
            self.min_samples.max(self.n_boot)
        } else {
            self.min_samples
        }
    }

    /// Validate estimator, allocation, bootstrap-diversity, and worst-case work
    /// invariants for all six unique modalities.
    pub fn validate(&self) -> galadriel_core::Result<()> {
        use galadriel_core::GaladrielError::InvalidConfig;

        if !(4..=MAX_PID_WINDOW).contains(&self.window) {
            return Err(InvalidConfig(format!(
                "PID window must be in 4..={MAX_PID_WINDOW} (estimators are quadratic)"
            )));
        }
        if self.geom_k < 3 {
            return Err(InvalidConfig("PID geom_k must be >= 3".into()));
        }
        if self.min_samples <= self.geom_k || self.min_samples > self.window {
            return Err(InvalidConfig(
                "PID min_samples must be greater than geom_k and <= window".into(),
            ));
        }
        if !self.jitter_std.is_finite() || self.jitter_std <= 0.0 {
            return Err(InvalidConfig(
                "PID jitter_std must be finite and > 0".into(),
            ));
        }
        if !self.id_max.is_finite() || self.id_max <= 0.0 {
            return Err(InvalidConfig("PID id_max must be finite and > 0".into()));
        }
        if !self.cv_min.is_finite() || self.cv_min <= 0.0 {
            return Err(InvalidConfig("PID cv_min must be finite and > 0".into()));
        }
        if !self.nn_ratio_max.is_finite() || self.nn_ratio_max <= 0.0 || self.nn_ratio_max > 1.0 {
            return Err(InvalidConfig(
                "PID nn_ratio_max must be finite and in (0, 1]".into(),
            ));
        }
        if !self.decouple_ratio.is_finite()
            || self.decouple_ratio <= 0.0
            || self.decouple_ratio > 1.0
        {
            return Err(InvalidConfig(
                "PID decouple_ratio must be finite and in (0, 1]".into(),
            ));
        }
        if !self.mi_floor.is_finite() || self.mi_floor <= 0.0 {
            return Err(InvalidConfig("PID mi_floor must be finite and > 0".into()));
        }
        if !self.family_alpha.is_finite() || self.family_alpha <= 0.0 || self.family_alpha >= 1.0 {
            return Err(InvalidConfig(
                "PID family_alpha must be finite and in (0, 1)".into(),
            ));
        }
        if self.family_alpha / galadriel_core::MAX_CONSISTENCY_PROJECTION_AXES as f64 == 0.0 {
            return Err(InvalidConfig(format!(
                "PID family_alpha is too small to divide across {} projection axes",
                galadriel_core::MAX_CONSISTENCY_PROJECTION_AXES
            )));
        }
        if self.bootstrap {
            if !(MIN_BOOTSTRAP_RESAMPLES..=MAX_BOOTSTRAP_RESAMPLES).contains(&self.n_boot) {
                return Err(InvalidConfig(format!(
                    "PID n_boot must be in {MIN_BOOTSTRAP_RESAMPLES}..={MAX_BOOTSTRAP_RESAMPLES}"
                )));
            }
            if self.block_size == 0
                || self.block_size >= self.min_samples
                || self.min_samples - self.block_size <= self.geom_k
            {
                return Err(InvalidConfig(
                    "PID block_size must leave more than geom_k samples at min_samples".into(),
                ));
            }
            if self.n_boot > self.window {
                return Err(InvalidConfig(
                    "PID n_boot cannot exceed window for distinct circular delete-block plans"
                        .into(),
                ));
            }
            self.confirmation_tail_rank()?;
        }
        let mandatory_fits = MAX_PAIR_ESTIMATOR_FITS
            .checked_add(MAX_ATOM_ESTIMATOR_FITS)
            .ok_or_else(|| InvalidConfig("PID mandatory fit count overflowed".into()))?;
        let bootstrap_fits = if self.bootstrap {
            MAX_CONFIRMATION_EDGE_FITS
                .checked_mul(self.n_boot)
                .ok_or_else(|| InvalidConfig("PID bootstrap fit count overflowed".into()))?
        } else {
            0
        };
        let fit_count = mandatory_fits
            .checked_add(bootstrap_fits)
            .ok_or_else(|| InvalidConfig("PID total fit count overflowed".into()))?;
        let quadratic_work = self
            .window
            .checked_mul(self.window)
            .and_then(|distance_pairs| distance_pairs.checked_mul(fit_count))
            .ok_or_else(|| InvalidConfig("PID quadratic work estimate overflowed".into()))?;
        if quadratic_work > MAX_QUADRATIC_FIT_WORK {
            return Err(InvalidConfig(format!(
                "PID requests {quadratic_work} quadratic fit-units (including up to {MAX_PAIR_ESTIMATOR_FITS} mandatory pair-estimator, {MAX_ATOM_ESTIMATOR_FITS} atom-estimator, and {MAX_CONFIRMATION_EDGE_FITS} confirmation-edge fits per resample across as many as {MAX_EXCLUDED_CANDIDATES} excluded candidates); maximum is {MAX_QUADRATIC_FIT_WORK}"
            )));
        }
        Ok(())
    }

    fn confirmation_tail_rank(&self) -> galadriel_core::Result<usize> {
        let tail_probability = self.family_alpha / CONFIRMATION_BOUND_GROUPS as f64;
        let tail_rank = (tail_probability * self.n_boot as f64).floor() as usize;
        if tail_rank == 0 || tail_rank >= self.n_boot {
            return Err(GaladrielError::InvalidConfig(format!(
                "PID n_boot={} cannot resolve family_alpha={} across the {CONFIRMATION_BOUND_GROUPS} joint confirmation bounds; increase n_boot or family_alpha",
                self.n_boot, self.family_alpha
            )));
        }
        Ok(tail_rank)
    }
}

/// Per-channel analysis detail.
#[derive(Debug, Clone)]
pub struct ChannelPid {
    /// Which modality.
    pub modality: Modality,
    /// Aligned samples used.
    pub n: usize,
    /// Whether at least one pair was safely assessable for this channel.
    pub gate_ok: bool,
    /// Human-readable geometry/estimator status.
    pub gate_note: String,
    /// Best safely estimated pairwise MI (nats).
    pub corroboration: Option<f64>,
    /// Advisory shared-exclusions redundancy atom (nats).
    pub redundancy: Option<f64>,
    /// Advisory shared-exclusions synergy atom (nats).
    pub synergy: Option<f64>,
    /// Whether this channel was attributed as decoupled from the consensus clique.
    /// Attribution is bootstrap-confirmed unless the caller explicitly disables it.
    pub decoupled: bool,
    /// Circular delete-block interval for the worst candidate-to-consensus confirmation
    /// margin: edge MI minus the replicate-selected consensus threshold, in nats.
    /// A confirmed candidate has an upper endpoint below zero.
    pub ci: Option<(f64, f64)>,
}

/// The engine's advisory verdict. Uniform magnitude inflation is owned by the
/// baseline; this engine detects cross-channel decoupling.
#[derive(Debug, Clone, PartialEq)]
pub enum PidVerdict {
    /// Every requested channel belongs to one assessable consensus clique.
    Nominal,
    /// One or a strict minority of channels was attributed as decoupled. This
    /// identifies information-theoretic structure, not an attack cause.
    Decoupled(Vec<Modality>),
    /// The estimator or consensus structure was not sufficient for attribution.
    InsufficientEvidence,
}

/// Full PID consistency report.
#[derive(Debug, Clone)]
pub struct PidReport {
    /// Per-channel detail, in input order.
    pub channels: Vec<ChannelPid>,
    /// Advisory verdict.
    pub verdict: PidVerdict,
    /// Human-readable rationale.
    pub note: String,
}

/// Analyse already sequence-aligned signed-scalar channel series.
///
/// Duplicate modalities, unequal lengths, non-finite values, and numerically
/// degenerate raw columns are malformed inputs and return an error. Too few
/// channels/samples and estimator limitations return an explicit insufficient
/// report instead. Default positive attributions fit every selected consensus and
/// candidate-to-consensus edge, then bound the joint worst-consensus and
/// worst-candidate margins across common circular delete-block resamples. These
/// bounds are a conservative screening guard, not a post-selection calibration
/// guarantee for the clique search.
pub fn analyze(
    channels: &[(Modality, Vec<f64>)],
    cfg: &PidConfig,
) -> galadriel_core::Result<PidReport> {
    cfg.validate()?;
    let c = channels.len();

    let unique: HashSet<Modality> = channels.iter().map(|(modality, _)| *modality).collect();
    if unique.len() != c {
        return Err(GaladrielError::InvalidChannels(
            "PID modalities must be unique".into(),
        ));
    }
    let lengths: HashSet<usize> = channels.iter().map(|(_, values)| values.len()).collect();
    if lengths.len() > 1 {
        return Err(GaladrielError::InvalidChannels(
            "PID columns must already be sequence-aligned and equal-length".into(),
        ));
    }
    if channels
        .iter()
        .flat_map(|(_, values)| values)
        .any(|value| !value.is_finite())
    {
        return Err(GaladrielError::NonFinite("PID channel input"));
    }

    let w = channels
        .first()
        .map_or(0, |(_, values)| values.len())
        .min(cfg.window);
    let required_samples = cfg.required_samples();
    if c < 3 || w < required_samples {
        return Ok(PidReport {
            channels: Vec::new(),
            verdict: PidVerdict::InsufficientEvidence,
            note: format!(
                "need >=3 channels and >={required_samples} aligned samples (have {c} channels, w={w})"
            ),
        });
    }
    // KSG distances are not scale invariant when one fixed jitter amplitude is
    // added. Validate and standardise every verdict-eligible raw column.
    let mut cols = Vec::with_capacity(c);
    for (modality, values) in channels {
        cols.push(standardize(&values[values.len() - w..], modality.label())?);
    }

    let mut mi = vec![vec![None::<f64>; c]; c];
    let mut pair_failures = vec![Vec::<String>::new(); c];
    for i in 0..c {
        for j in (i + 1)..c {
            match pair_mi(cfg, channels[i].0, &cols[i], channels[j].0, &cols[j]) {
                Ok(value) => {
                    mi[i][j] = Some(value);
                    mi[j][i] = Some(value);
                }
                Err(reason) => {
                    pair_failures[i].push(format!("{}: {reason}", channels[j].0.label()));
                    pair_failures[j].push(format!("{}: {reason}", channels[i].0.label()));
                }
            }
        }
    }
    for failures in &mut pair_failures {
        failures.sort_unstable();
    }

    let mut reports = Vec::with_capacity(c);
    for (i, (modality, _)) in channels.iter().enumerate() {
        let peers: Vec<f64> = (0..c)
            .filter(|&j| j != i)
            .filter_map(|j| mi[i][j])
            .collect();
        let corroboration = peers.iter().copied().reduce(f64::max);
        let gate_ok = corroboration.is_some();
        let gate_note = if pair_failures[i].is_empty() {
            "all pair estimators ready".to_string()
        } else if gate_ok {
            format!(
                "{}/{} pairs assessable; {}",
                peers.len(),
                c - 1,
                pair_failures[i].join("; ")
            )
        } else {
            format!("no assessable pair; {}", pair_failures[i].join("; "))
        };
        let atoms = isx_atoms(cfg, channels, &cols, i, w);
        reports.push(ChannelPid {
            modality: *modality,
            n: w,
            gate_ok,
            gate_note,
            corroboration,
            redundancy: atoms.map(|atom| atom.0),
            synergy: atoms.map(|atom| atom.1),
            decoupled: false,
            ci: None,
        });
    }

    if reports.iter().any(|report| !report.gate_ok) {
        let missing = reports
            .iter()
            .filter(|report| !report.gate_ok)
            .map(|report| report.modality.label())
            .collect::<Vec<_>>()
            .join(", ");
        return Ok(PidReport {
            channels: reports,
            verdict: PidVerdict::InsufficientEvidence,
            note: format!("requested channel(s) not assessable: {missing}"),
        });
    }
    let failed_pairs = pair_failures.iter().map(Vec::len).sum::<usize>() / 2;
    if failed_pairs > 0 {
        return Ok(PidReport {
            channels: reports,
            verdict: PidVerdict::InsufficientEvidence,
            note: format!(
                "{failed_pairs} requested pair estimator(s) failed a geometry or numerical gate"
            ),
        });
    }

    let reference = reports
        .iter()
        .filter_map(|report| report.corroboration)
        .fold(0.0_f64, f64::max);
    if reference < cfg.mi_floor {
        return Ok(PidReport {
            channels: reports,
            verdict: PidVerdict::InsufficientEvidence,
            note: format!(
                "no coherent MI consensus (strongest pair {reference:.3} < floor {:.3})",
                cfg.mi_floor
            ),
        });
    }
    let threshold = cfg.mi_floor.max(cfg.decouple_ratio * reference);

    let (largest_size, largest_cliques) = largest_consensus_cliques(&mi, threshold);
    if largest_size * 2 <= c || largest_cliques.len() != 1 {
        return Ok(PidReport {
            channels: reports,
            verdict: PidVerdict::InsufficientEvidence,
            note: format!(
                "ambiguous MI-consensus structure (largest clique {largest_size}/{c}, {} tied); no unique strict majority",
                largest_cliques.len()
            ),
        });
    }

    let consensus = &largest_cliques[0];
    let consensus_set: HashSet<usize> = consensus.iter().copied().collect();
    let candidates: Vec<usize> = (0..c)
        .filter(|index| !consensus_set.contains(index))
        .collect();

    // An excluded channel is attributable only when every edge from it to the
    // consensus was successfully estimated and is below threshold. A missing
    // estimate or a partial bridge is ambiguity, never evidence against it.
    for &candidate in &candidates {
        let fully_assessed_low = consensus
            .iter()
            .all(|&peer| mi[candidate][peer].is_some_and(|value| value < threshold));
        if !fully_assessed_low {
            return Ok(PidReport {
                channels: reports,
                verdict: PidVerdict::InsufficientEvidence,
                note: format!(
                    "{} is outside the majority clique but is not uniformly assessable-and-low against it",
                    channels[candidate].0.label()
                ),
            });
        }
    }

    if candidates.is_empty() {
        return Ok(PidReport {
            channels: reports,
            verdict: PidVerdict::Nominal,
            note: format!(
                "all {c} requested channels form one assessable MI-consensus clique (strongest MI {reference:.3} nats)"
            ),
        });
    }

    if cfg.bootstrap {
        if let Err(reason) =
            confirm_attribution(cfg, channels, &cols, consensus, &candidates, &mut reports)
        {
            return Ok(PidReport {
                channels: reports,
                verdict: PidVerdict::InsufficientEvidence,
                note: format!("bootstrap did not confirm the selected attribution: {reason}"),
            });
        }
    }

    let mut decoupled = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        reports[candidate].decoupled = true;
        decoupled.push(reports[candidate].modality);
    }
    decoupled.sort_by_key(|modality| modality_key(*modality));
    let names = decoupled
        .iter()
        .map(|modality| modality.label())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(PidReport {
        channels: reports,
        verdict: PidVerdict::Decoupled(decoupled.clone()),
        note: format!(
            "{} channel(s) {} a unique {}/{} MI-consensus clique: {names}",
            decoupled.len(),
            if cfg.bootstrap {
                "bootstrap-confirmed decoupled from"
            } else {
                "point-estimate decoupled from (bootstrap disabled)"
            },
            largest_size,
            c
        ),
    })
}

fn standardize(values: &[f64], modality: &str) -> galadriel_core::Result<Vec<f64>> {
    let (minimum, maximum) = values.iter().copied().fold(
        (f64::INFINITY, f64::NEG_INFINITY),
        |(minimum, maximum), value| (minimum.min(value), maximum.max(value)),
    );
    if minimum == maximum {
        return Err(GaladrielError::InvalidChannels(format!(
            "PID {modality} column is degenerate"
        )));
    }
    let center = minimum / 2.0 + maximum / 2.0;
    let scale = (minimum - center).abs().max((maximum - center).abs());
    let n = values.len() as f64;
    let mean = values
        .iter()
        .map(|value| (value - center) / scale)
        .sum::<f64>()
        / n;
    let centered: Vec<f64> = values
        .iter()
        .map(|value| (value - center) / scale - mean)
        .collect();
    let sum_squares = centered.iter().map(|value| value * value).sum::<f64>();
    if !sum_squares.is_finite() || sum_squares <= f64::EPSILON * n {
        return Err(GaladrielError::InvalidChannels(format!(
            "PID {modality} column is numerically degenerate"
        )));
    }
    let rms = (sum_squares / n).sqrt();
    let standardized: Vec<f64> = centered.into_iter().map(|value| value / rms).collect();
    if standardized.iter().any(|value| !value.is_finite()) {
        return Err(GaladrielError::NonFinite("PID standardisation"));
    }
    Ok(standardized)
}

fn largest_consensus_cliques(mi: &[Vec<Option<f64>>], threshold: f64) -> (usize, Vec<Vec<usize>>) {
    let c = mi.len();
    let mut largest_size = 0;
    let mut largest_cliques = Vec::new();
    for mask in 1usize..(1usize << c) {
        let members: Vec<usize> = (0..c).filter(|index| mask & (1 << index) != 0).collect();
        if members.len() < largest_size {
            continue;
        }
        let is_clique = members.iter().enumerate().all(|(position, &i)| {
            members[position + 1..]
                .iter()
                .all(|&j| mi[i][j].is_some_and(|value| value >= threshold))
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
    (largest_size, largest_cliques)
}

const fn modality_key(modality: Modality) -> u64 {
    match modality {
        Modality::Visual => 0,
        Modality::Thermal => 1,
        Modality::Acoustic => 2,
        Modality::Radar => 3,
        Modality::Lidar => 4,
        Modality::RadioFrequency => 5,
    }
}

/// Geometry-gated pairwise MI. Geometry and estimator failures remain
/// distinguishable from a successfully estimated low MI through `Err`.
fn pair_mi(
    cfg: &PidConfig,
    a_modality: Modality,
    a: &[f64],
    b_modality: Modality,
    b: &[f64],
) -> Result<f64, String> {
    let (first_modality, first, second_modality, second) =
        canonical_pair(a_modality, a, b_modality, b);
    let seed = domain_seed(
        cfg.seed,
        ROLE_PAIR_POINT,
        modality_key(first_modality),
        modality_key(second_modality),
    );
    let (joint, columns) = jittered_matrix_and_columns(&[first, second], cfg.jitter_std, seed)?;
    let id = intrinsic_dimension_levina_bickel(
        joint.as_ref(),
        &IntrinsicDimConfig {
            k: cfg.geom_k,
            metric: Metric::Chebyshev,
        },
    )
    .map_err(|error| format!("intrinsic-dimension estimator failed: {error}"))?;
    if !id.is_finite() || id > cfg.id_max {
        return Err(format!(
            "intrinsic dimension {id:.3} exceeds {:.3}",
            cfg.id_max
        ));
    }
    let concentration = distance_concentration_stats(
        joint.as_ref(),
        &DistanceConcentrationConfig {
            metric: Metric::Chebyshev,
        },
    )
    .map_err(|error| format!("distance-concentration estimator failed: {error}"))?;
    if !concentration.pairwise_cv.is_finite()
        || !concentration.nn_over_pairwise_mean.is_finite()
        || concentration.pairwise_cv < cfg.cv_min
        || concentration.nn_over_pairwise_mean > cfg.nn_ratio_max
    {
        return Err(format!(
            "geometry gate failed (cv {:.4}, nn/pair {:.4})",
            concentration.pairwise_cv, concentration.nn_over_pairwise_mean
        ));
    }
    estimate_mi(&columns[0], &columns[1])
}

fn canonical_pair<'a>(
    a_modality: Modality,
    a: &'a [f64],
    b_modality: Modality,
    b: &'a [f64],
) -> (Modality, &'a [f64], Modality, &'a [f64]) {
    if modality_key(a_modality) < modality_key(b_modality) {
        (a_modality, a, b_modality, b)
    } else {
        (b_modality, b, a_modality, a)
    }
}

fn estimate_mi(a: &MatOwned, b: &MatOwned) -> Result<f64, String> {
    let value = ksg_mi(a.as_ref(), b.as_ref(), &KsgConfig::default())
        .map_err(|error| format!("KSG estimator failed: {error}"))?;
    if !value.is_finite() || value < 0.0 {
        return Err("KSG estimator returned an invalid MI".into());
    }
    Ok(value)
}

/// Build and jitter a joint matrix once, then split its columns. Jitter is i.i.d.
/// across the row-major joint matrix; no two columns can receive the identical
/// restarted PRNG sequence.
fn jittered_matrix_and_columns(
    columns: &[&[f64]],
    jitter_std: f64,
    seed: u64,
) -> Result<(MatOwned, Vec<MatOwned>), String> {
    let Some(first) = columns.first() else {
        return Err("cannot jitter an empty column set".into());
    };
    let n = first.len();
    if n == 0 || columns.iter().any(|column| column.len() != n) {
        return Err("jitter columns must be non-empty and equal-length".into());
    }
    let dimensions = columns.len();
    let mut flat = Vec::with_capacity(n.saturating_mul(dimensions));
    for row in 0..n {
        for column in columns {
            flat.push(column[row]);
        }
    }
    let raw = MatOwned::new(flat, n, dimensions)
        .map_err(|error| format!("joint matrix construction failed: {error}"))?;
    let jitter = Jitter::new(jitter_std, seed)
        .map_err(|error| format!("jitter construction failed: {error}"))?;
    let joint = jitter
        .apply(raw.as_ref())
        .map_err(|error| format!("joint jitter failed: {error}"))?;

    let view = joint.as_ref();
    let mut split = Vec::with_capacity(dimensions);
    for dimension in 0..dimensions {
        let data: Vec<f64> = (0..n).map(|row| view.row(row)[dimension]).collect();
        split.push(
            MatOwned::new(data, n, 1)
                .map_err(|error| format!("jittered column construction failed: {error}"))?,
        );
    }
    Ok((joint, split))
}

/// Advisory `I^sx` atoms for `(channel, stable designated peer, remaining consensus)`.
fn isx_atoms(
    cfg: &PidConfig,
    channels: &[(Modality, Vec<f64>)],
    cols: &[Vec<f64>],
    i: usize,
    w: usize,
) -> Option<(f64, f64)> {
    let mut others: Vec<usize> = (0..channels.len()).filter(|&index| index != i).collect();
    others.sort_by_key(|&index| modality_key(channels[index].0));
    if others.len() < 2 {
        return None;
    }
    let target = consensus(cols, &others[1..], w);
    let seed = domain_seed(
        cfg.seed,
        ROLE_PID_ATOMS,
        modality_key(channels[i].0),
        modality_key(channels[others[0]].0),
    );
    let (_, columns) =
        jittered_matrix_and_columns(&[&cols[i], &cols[others[0]], &target], cfg.jitter_std, seed)
            .ok()?;
    let estimate = pid2_isx_estimate(
        columns[0].as_ref(),
        columns[1].as_ref(),
        columns[2].as_ref(),
        &Pid2Config::default(),
    )
    .ok()?;
    let redundancy = estimate.redundancy_isx;
    let synergy = estimate.mi_s1s2_t - estimate.mi_s1_t - estimate.mi_s2_t + redundancy;
    (redundancy.is_finite() && synergy.is_finite()).then_some((redundancy, synergy))
}

fn consensus(cols: &[Vec<f64>], indices: &[usize], w: usize) -> Vec<f64> {
    (0..w)
        .map(|frame| {
            indices.iter().map(|&index| cols[index][frame]).sum::<f64>() / indices.len() as f64
        })
        .collect()
}

#[derive(Debug, Clone)]
struct EdgeBootstrap {
    left: usize,
    right: usize,
    estimates: Vec<f64>,
}

#[derive(Debug, Clone)]
struct EdgeMargins {
    left: usize,
    right: usize,
    values: Vec<f64>,
}

/// Confirm the selected clique and every candidate-to-clique low edge with
/// simultaneous one-sided circular delete-block bounds. Each resample uses one
/// common row plan across every edge and reselects the strongest consensus
/// reference. Delete-block plans avoid the duplicated rows that make a
/// replacement bootstrap pathological for nearest-neighbour MI estimators.
fn confirm_attribution(
    cfg: &PidConfig,
    channels: &[(Modality, Vec<f64>)],
    cols: &[Vec<f64>],
    consensus: &[usize],
    candidates: &[usize],
    reports: &mut [ChannelPid],
) -> Result<(), String> {
    let mut stable_consensus = consensus.to_vec();
    stable_consensus.sort_by_key(|&index| modality_key(channels[index].0));
    let mut stable_candidates = candidates.to_vec();
    stable_candidates.sort_by_key(|&index| modality_key(channels[index].0));

    let consensus_fit_count = pair_count(stable_consensus.len());
    let candidate_fit_count = stable_candidates
        .len()
        .checked_mul(stable_consensus.len())
        .ok_or_else(|| "confirmation edge count overflowed".to_string())?;
    let required_edges = consensus_fit_count
        .checked_add(candidate_fit_count)
        .ok_or_else(|| "confirmation edge count overflowed".to_string())?;
    if required_edges == 0 {
        return Err("selected attribution has no confirmable edges".into());
    }

    let plans = delete_block_plans(cfg, cols[0].len(), channels)?;
    let mut consensus_bootstraps = Vec::with_capacity(consensus_fit_count);
    for (position, &left) in stable_consensus.iter().enumerate() {
        for &right in &stable_consensus[position + 1..] {
            consensus_bootstraps.push(EdgeBootstrap {
                left,
                right,
                estimates: bootstrap_mi_series(
                    cfg,
                    channels[left].0,
                    &cols[left],
                    channels[right].0,
                    &cols[right],
                    &plans,
                )?,
            });
        }
    }

    let mut candidate_bootstraps = Vec::with_capacity(candidate_fit_count);
    for &candidate in &stable_candidates {
        for &peer in &stable_consensus {
            candidate_bootstraps.push(EdgeBootstrap {
                left: candidate,
                right: peer,
                estimates: bootstrap_mi_series(
                    cfg,
                    channels[candidate].0,
                    &cols[candidate],
                    channels[peer].0,
                    &cols[peer],
                    &plans,
                )?,
            });
        }
    }

    let thresholds: Vec<f64> = (0..cfg.n_boot)
        .map(|replicate| {
            let reference = consensus_bootstraps
                .iter()
                .map(|edge| edge.estimates[replicate])
                .fold(0.0_f64, f64::max);
            cfg.mi_floor.max(cfg.decouple_ratio * reference)
        })
        .collect();
    let consensus_margins = bootstrap_margins(consensus_bootstraps, &thresholds, cfg)?;
    let candidate_margins = bootstrap_margins(candidate_bootstraps, &thresholds, cfg)?;
    let tail_rank = cfg
        .confirmation_tail_rank()
        .map_err(|error| error.to_string())?;
    let consensus_interval = joint_margin_interval(&consensus_margins, tail_rank, false)?;
    let candidate_interval = joint_margin_interval(&candidate_margins, tail_rank, true)?;

    for &candidate in &stable_candidates {
        let candidate_edges: Vec<&EdgeMargins> = candidate_margins
            .iter()
            .filter(|edge| edge.left == candidate)
            .collect();
        reports[candidate].ci = Some(joint_margin_interval_refs(
            &candidate_edges,
            tail_rank,
            true,
        )?);
    }

    if consensus_interval.0 <= 0.0 {
        let edge = consensus_margins
            .iter()
            .min_by(|left, right| {
                margin_interval(left, tail_rank)
                    .0
                    .total_cmp(&margin_interval(right, tail_rank).0)
            })
            .ok_or_else(|| "selected consensus has no margin series".to_string())?;
        return Err(format!(
            "joint worst-consensus lower margin {:.3} is not positive (weakest diagnostic edge {}-{})",
            consensus_interval.0,
            channels[edge.left].0.label(),
            channels[edge.right].0.label(),
        ));
    }
    if candidate_interval.1 >= 0.0 {
        let edge = candidate_margins
            .iter()
            .max_by(|left, right| {
                margin_interval(left, tail_rank)
                    .1
                    .total_cmp(&margin_interval(right, tail_rank).1)
            })
            .ok_or_else(|| "selected candidates have no margin series".to_string())?;
        return Err(format!(
            "joint worst-candidate upper margin {:.3} is not negative (worst diagnostic edge {}-{})",
            candidate_interval.1,
            channels[edge.left].0.label(),
            channels[edge.right].0.label(),
        ));
    }
    Ok(())
}

fn delete_block_plans(
    cfg: &PidConfig,
    n: usize,
    channels: &[(Modality, Vec<f64>)],
) -> Result<Vec<Vec<usize>>, String> {
    if cfg.block_size == 0
        || cfg.block_size >= n
        || n - cfg.block_size <= cfg.geom_k
        || cfg.n_boot > n
    {
        return Err("invalid circular delete-block dimensions".into());
    }

    let mut modality_keys: Vec<u64> = channels
        .iter()
        .map(|(modality, _)| modality_key(*modality))
        .collect();
    modality_keys.sort_unstable();
    let set_tag = modality_keys
        .into_iter()
        .fold(0x6a09_e667_f3bc_c909_u64, |tag, key| mix64(tag ^ key));
    let mut rng = SplitMix64::new(domain_seed(cfg.seed, ROLE_BOOT_PLAN, set_tag, n as u64));
    let mut starts: Vec<usize> = (0..n).collect();
    for index in (1..starts.len()).rev() {
        let other = rng.index(index + 1);
        starts.swap(index, other);
    }
    starts.truncate(cfg.n_boot);
    let mut plans = Vec::with_capacity(cfg.n_boot);
    for start in starts {
        let plan: Vec<usize> = (0..n)
            .filter(|&index| {
                let circular_offset = (index + n - start) % n;
                circular_offset >= cfg.block_size
            })
            .collect();
        plans.push(plan);
    }
    Ok(plans)
}

/// Evaluate one edge over common deterministic circular delete-block plans. Every
/// resample must estimate successfully; point substitution would narrow the
/// eventual margin interval and is therefore prohibited.
fn bootstrap_mi_series(
    cfg: &PidConfig,
    a_modality: Modality,
    a: &[f64],
    b_modality: Modality,
    b: &[f64],
    plans: &[Vec<usize>],
) -> Result<Vec<f64>, String> {
    let (first_modality, first, second_modality, second) =
        canonical_pair(a_modality, a, b_modality, b);
    let n = first.len();
    if n != second.len()
        || plans.len() != cfg.n_boot
        || plans
            .iter()
            .any(|plan| plan.len() != n - cfg.block_size || plan.iter().any(|&index| index >= n))
    {
        return Err("invalid circular delete-block dimensions".into());
    }
    let pair_tag = (modality_key(first_modality) << 32) | modality_key(second_modality);
    let mut estimates = Vec::with_capacity(cfg.n_boot);
    for (replicate, plan) in plans.iter().enumerate() {
        let resampled_a: Vec<f64> = plan.iter().map(|&index| first[index]).collect();
        let resampled_b: Vec<f64> = plan.iter().map(|&index| second[index]).collect();

        let seed = domain_seed(cfg.seed, ROLE_BOOT_JITTER, pair_tag, replicate as u64);
        let (_, columns) =
            jittered_matrix_and_columns(&[&resampled_a, &resampled_b], cfg.jitter_std, seed)?;
        estimates.push(estimate_mi(&columns[0], &columns[1])?);
    }
    Ok(estimates)
}

fn bootstrap_margins(
    bootstraps: Vec<EdgeBootstrap>,
    thresholds: &[f64],
    cfg: &PidConfig,
) -> Result<Vec<EdgeMargins>, String> {
    if thresholds.len() != cfg.n_boot {
        return Err("bootstrap requires a complete non-empty bound family".into());
    }
    bootstraps
        .into_iter()
        .map(|edge| {
            if edge.estimates.len() != thresholds.len() {
                return Err("bootstrap edge series is incomplete".into());
            }
            let values: Vec<f64> = edge
                .estimates
                .iter()
                .zip(thresholds)
                .map(|(estimate, threshold)| estimate - threshold)
                .collect();
            Ok(EdgeMargins {
                left: edge.left,
                right: edge.right,
                values,
            })
        })
        .collect()
}

fn margin_interval(edge: &EdgeMargins, tail_rank: usize) -> (f64, f64) {
    let mut values = edge.values.clone();
    values.sort_by(f64::total_cmp);
    let upper = values.len() - tail_rank - 1;
    (values[tail_rank], values[upper])
}

fn joint_margin_interval(
    edges: &[EdgeMargins],
    tail_rank: usize,
    select_maximum: bool,
) -> Result<(f64, f64), String> {
    let references: Vec<&EdgeMargins> = edges.iter().collect();
    joint_margin_interval_refs(&references, tail_rank, select_maximum)
}

fn joint_margin_interval_refs(
    edges: &[&EdgeMargins],
    tail_rank: usize,
    select_maximum: bool,
) -> Result<(f64, f64), String> {
    let Some(first) = edges.first() else {
        return Err("cannot form a joint bound from an empty edge family".into());
    };
    let replicates = first.values.len();
    if replicates == 0
        || edges.iter().any(|edge| edge.values.len() != replicates)
        || tail_rank >= replicates
    {
        return Err("incomplete joint edge-margin family".into());
    }
    let mut extrema: Vec<f64> = (0..replicates)
        .map(|replicate| {
            edges
                .iter()
                .skip(1)
                .fold(first.values[replicate], |value, edge| {
                    if select_maximum {
                        value.max(edge.values[replicate])
                    } else {
                        value.min(edge.values[replicate])
                    }
                })
        })
        .collect();
    extrema.sort_by(f64::total_cmp);
    let upper = replicates - tail_rank - 1;
    Ok((extrema[tail_rank], extrema[upper]))
}

fn domain_seed(base: u64, role: u64, first: u64, second: u64) -> u64 {
    mix64(mix64(base ^ role) ^ mix64(first) ^ mix64(second.rotate_left(32)))
}

fn mix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mix64(self.state)
    }

    fn index(&mut self, upper: usize) -> usize {
        (((self.next_u64() as u128) * (upper as u128)) >> 64) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar_channels;
    use galadriel_sim::scenario::{generate, generate_spoofed, ScenarioConfig, StealthySpoof};

    fn scen(seed: u64) -> ScenarioConfig {
        ScenarioConfig {
            frames: 400,
            rho: 0.7,
            seed,
            ..Default::default()
        }
    }

    fn pseudo_random_series(n: usize, seed: u64) -> Vec<f64> {
        let mut rng = SplitMix64::new(seed);
        (0..n)
            .map(|_| {
                let bits = rng.next_u64() >> 11;
                2.0 * bits as f64 / ((1_u64 << 53) as f64) - 1.0
            })
            .collect()
    }

    #[test]
    fn clean_corroborated_stream_is_nominal() {
        for seed in [7, 11, 23, 42] {
            let scenario = scen(seed);
            let stream = generate(&scenario).unwrap();
            let channels = scalar_channels(&stream, &scenario.modalities, 0).unwrap();
            let report = analyze(&channels, &PidConfig::default()).unwrap();
            assert_eq!(
                report.verdict,
                PidVerdict::Nominal,
                "seed {seed}: {}",
                report.note
            );
        }
    }

    #[test]
    fn fewer_than_three_channels_is_insufficient_evidence() {
        let scenario = scen(7);
        let stream = generate(&scenario).unwrap();
        let two = [Modality::Visual, Modality::Radar];
        let channels = scalar_channels(&stream, &two, 0).unwrap();
        let report = analyze(&channels, &PidConfig::default()).unwrap();
        assert_eq!(report.verdict, PidVerdict::InsufficientEvidence);
    }

    #[test]
    fn bootstrap_readiness_precedes_nominal_or_positive_verdicts() {
        let scenario = ScenarioConfig {
            frames: PidConfig::default().min_samples,
            rho: 0.7,
            ..Default::default()
        };
        let stream = generate(&scenario).unwrap();
        let channels = scalar_channels(&stream, &scenario.modalities, 0).unwrap();
        let report = analyze(&channels, &PidConfig::default()).unwrap();

        assert_eq!(PidConfig::default().required_samples(), 100);
        assert_eq!(report.verdict, PidVerdict::InsufficientEvidence);
        assert!(report.note.contains("100 aligned samples"));
    }

    #[test]
    fn default_confirmation_never_overstates_point_decoupling_evidence() {
        let mut confirmed = 0;
        for seed in [7, 23] {
            let scenario = scen(seed);
            let stream = generate_spoofed(
                &scenario,
                StealthySpoof {
                    target: Modality::Acoustic,
                    start_frame: scenario.frames as u64 / 3,
                },
            )
            .unwrap();
            let channels = scalar_channels(&stream, &scenario.modalities, 0).unwrap();
            let point = analyze(
                &channels,
                &PidConfig {
                    bootstrap: false,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(
                matches!(
                    point.verdict,
                    PidVerdict::Decoupled(ref modalities)
                        if modalities == &[Modality::Acoustic]
                ),
                "seed {seed}: point estimate did not isolate acoustic: {}",
                point.note
            );

            let report = analyze(&channels, &PidConfig::default()).unwrap();
            match &report.verdict {
                PidVerdict::Decoupled(modalities) => {
                    assert_eq!(modalities, &[Modality::Acoustic]);
                    let acoustic = report
                        .channels
                        .iter()
                        .find(|channel| channel.modality == Modality::Acoustic)
                        .unwrap();
                    assert!(acoustic.ci.is_some_and(|interval| interval.1 < 0.0));
                    confirmed += 1;
                }
                PidVerdict::InsufficientEvidence => {
                    assert!(report.channels.iter().all(|channel| !channel.decoupled));
                }
                PidVerdict::Nominal => {
                    panic!("seed {seed}: confirmation erased a point candidate as nominal")
                }
            }
        }
        assert!(
            confirmed > 0,
            "default confirmation never accepted a clear decoupling"
        );
    }

    #[test]
    fn rejects_constant_columns_before_jitter_can_create_false_information() {
        let channels = vec![
            (Modality::Visual, vec![0.0; 128]),
            (Modality::Radar, vec![10.0; 128]),
            (Modality::Acoustic, vec![-7.0; 128]),
        ];
        assert!(matches!(
            analyze(&channels, &PidConfig::default()),
            Err(GaladrielError::InvalidChannels(_))
        ));

        let short = channels
            .iter()
            .map(|(modality, values)| (*modality, values[..16].to_vec()))
            .collect::<Vec<_>>();
        assert_eq!(
            analyze(&short, &PidConfig::default()).unwrap().verdict,
            PidVerdict::InsufficientEvidence,
            "too few samples are inconclusive, even when the observed prefix is constant"
        );
    }

    #[test]
    fn joint_jitter_does_not_reuse_one_noise_sequence_across_columns() {
        let zeros = vec![0.0; 128];
        let (_, columns) = jittered_matrix_and_columns(&[&zeros, &zeros], 1e-4, 7).unwrap();
        assert!(
            (0..128).all(|row| columns[0].as_ref().row(row)[0] != columns[1].as_ref().row(row)[0])
        );
    }

    #[test]
    fn rejects_non_finite_and_ambiguous_channel_inputs() {
        let base = pseudo_random_series(128, 1);
        let mut nan = base.clone();
        nan[17] = f64::NAN;
        let non_finite = vec![
            (Modality::Visual, base.clone()),
            (Modality::Radar, base.clone()),
            (Modality::Acoustic, nan),
        ];
        assert!(matches!(
            analyze(&non_finite, &PidConfig::default()),
            Err(GaladrielError::NonFinite(_))
        ));

        let unequal = vec![
            (Modality::Visual, base.clone()),
            (Modality::Radar, base[..127].to_vec()),
            (Modality::Acoustic, base.clone()),
        ];
        assert!(matches!(
            analyze(&unequal, &PidConfig::default()),
            Err(GaladrielError::InvalidChannels(_))
        ));

        let duplicate = vec![
            (Modality::Visual, base.clone()),
            (Modality::Visual, base.clone()),
            (Modality::Acoustic, base),
        ];
        assert!(matches!(
            analyze(&duplicate, &PidConfig::default()),
            Err(GaladrielError::InvalidChannels(_))
        ));
    }

    #[test]
    fn equal_disconnected_dyads_are_insufficient_not_nominal() {
        let first = pseudo_random_series(128, 7);
        let second = pseudo_random_series(128, 19);
        let channels = vec![
            (Modality::Visual, first.clone()),
            (Modality::Radar, first),
            (Modality::Acoustic, second.clone()),
            (Modality::Lidar, second),
        ];
        let report = analyze(&channels, &PidConfig::default()).unwrap();
        assert_eq!(
            report.verdict,
            PidVerdict::InsufficientEvidence,
            "{}",
            report.note
        );
    }

    #[test]
    fn invalid_bootstrap_configuration_is_rejected() {
        let mut config = PidConfig {
            bootstrap: true,
            n_boot: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        config.n_boot = 200;
        config.block_size = config.min_samples;
        assert!(config.validate().is_err());

        config.block_size = config.min_samples - 1;
        assert!(config.validate().is_err());

        config.window = MAX_PID_WINDOW + 1;
        assert!(config.validate().is_err());

        config.window = MAX_PID_WINDOW;
        config.min_samples = MAX_PID_WINDOW;
        config.block_size = 8;
        config.n_boot = 200;
        assert!(
            config.validate().is_err(),
            "quadratic bootstrap work must be bounded"
        );

        config = PidConfig::default();
        config.family_alpha = 0.0;
        assert!(config.validate().is_err());
        config.family_alpha = 1.0;
        assert!(config.validate().is_err());
        config.family_alpha = f64::NAN;
        assert!(config.validate().is_err());
        config.family_alpha = f64::from_bits(1);
        assert!(config.validate().is_err());

        config = PidConfig {
            n_boot: MIN_BOOTSTRAP_RESAMPLES,
            family_alpha: 0.01,
            ..Default::default()
        };
        assert!(matches!(
            config.validate(),
            Err(GaladrielError::InvalidConfig(ref message))
                if message.contains("cannot resolve family_alpha")
        ));
        let no_channels = Vec::new();
        assert!(matches!(
            analyze(&no_channels, &config),
            Err(GaladrielError::InvalidConfig(ref message))
                if message.contains("cannot resolve family_alpha")
        ));
    }

    #[test]
    fn default_resolves_six_modalities_across_three_projection_axes() {
        let config = PidConfig::default();
        assert!(config.bootstrap);
        assert!(config.validate().is_ok());
        assert_eq!(config.confirmation_tail_rank().unwrap(), 5);
        assert_eq!(pair_count(Modality::ALL.len()), 15);
        assert_eq!(MAX_EXCLUDED_CANDIDATES, 2);
        assert_eq!(MAX_CONFIRMATION_EDGE_FITS, 15);
        assert_eq!(CONFIRMATION_BOUND_GROUPS, 2);

        let mut three_axis = config;
        three_axis.family_alpha /= 3.0;
        assert!(three_axis.validate().is_ok());
        assert_eq!(three_axis.confirmation_tail_rank().unwrap(), 1);
    }

    #[test]
    fn bootstrap_never_flags_a_clean_stream() {
        let config = PidConfig {
            bootstrap: true,
            n_boot: 40,
            ..Default::default()
        };
        for seed in [7, 11, 23] {
            let scenario = scen(seed);
            let stream = generate(&scenario).unwrap();
            let channels = scalar_channels(&stream, &scenario.modalities, 0).unwrap();
            let report = analyze(&channels, &config).unwrap();
            assert_eq!(
                report.verdict,
                PidVerdict::Nominal,
                "seed {seed}: {}",
                report.note
            );
        }
    }

    #[test]
    fn bootstrap_is_a_fail_closed_subset_of_point_estimates() {
        let scenario = scen(7);
        let stream = generate_spoofed(
            &scenario,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: scenario.frames as u64 / 3,
            },
        )
        .unwrap();
        let channels = scalar_channels(&stream, &scenario.modalities, 0).unwrap();
        let point = analyze(
            &channels,
            &PidConfig {
                bootstrap: false,
                ..Default::default()
            },
        )
        .unwrap();
        let bootstrap = analyze(
            &channels,
            &PidConfig {
                bootstrap: true,
                n_boot: 40,
                ..Default::default()
            },
        )
        .unwrap();

        let point_flagged: HashSet<Modality> = point
            .channels
            .iter()
            .filter(|channel| channel.decoupled)
            .map(|channel| channel.modality)
            .collect();
        for channel in bootstrap
            .channels
            .iter()
            .filter(|channel| channel.decoupled)
        {
            assert!(point_flagged.contains(&channel.modality));
            assert!(channel.ci.is_some());
        }
        if !matches!(bootstrap.verdict, PidVerdict::Decoupled(_)) {
            assert!(bootstrap.channels.iter().all(|channel| !channel.decoupled));
        }
    }

    #[test]
    fn modality_permutation_preserves_point_atoms_and_bootstrap_intervals() {
        let scenario = scen(23);
        let stream = generate_spoofed(
            &scenario,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: scenario.frames as u64 / 3,
            },
        )
        .unwrap();
        let channels = scalar_channels(&stream, &scenario.modalities, 0).unwrap();
        let config = PidConfig {
            bootstrap: false,
            ..Default::default()
        };
        let original = analyze(&channels, &config).unwrap();
        let mut permuted = channels.clone();
        permuted.rotate_left(1);
        permuted.reverse();
        let reordered = analyze(&permuted, &config).unwrap();

        assert_eq!(original.verdict, reordered.verdict);
        assert_eq!(original.note, reordered.note);
        for (modality, _) in &channels {
            let left = original
                .channels
                .iter()
                .find(|channel| channel.modality == *modality)
                .unwrap();
            let right = reordered
                .channels
                .iter()
                .find(|channel| channel.modality == *modality)
                .unwrap();
            assert_eq!(left.gate_note, right.gate_note);
            assert_eq!(
                left.corroboration.map(f64::to_bits),
                right.corroboration.map(f64::to_bits)
            );
            assert_eq!(
                left.redundancy.map(f64::to_bits),
                right.redundancy.map(f64::to_bits)
            );
            assert_eq!(
                left.synergy.map(f64::to_bits),
                right.synergy.map(f64::to_bits)
            );
        }

        let bootstrap = PidConfig {
            n_boot: MIN_BOOTSTRAP_RESAMPLES,
            ..Default::default()
        };
        let plans = delete_block_plans(&bootstrap, channels[0].1.len(), &channels).unwrap();
        let reordered_plans =
            delete_block_plans(&bootstrap, permuted[0].1.len(), &permuted).unwrap();
        assert_eq!(plans, reordered_plans);
        let first = bootstrap_mi_series(
            &bootstrap,
            channels[0].0,
            &channels[0].1,
            channels[1].0,
            &channels[1].1,
            &plans,
        )
        .unwrap();
        let reversed = bootstrap_mi_series(
            &bootstrap,
            channels[1].0,
            &channels[1].1,
            channels[0].0,
            &channels[0].1,
            &plans,
        )
        .unwrap();
        assert_eq!(
            first
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            reversed
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>()
        );
    }
}
