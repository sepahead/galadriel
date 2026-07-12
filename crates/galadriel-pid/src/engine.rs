//! Geometry-gated mutual-information consistency analysis.
//!
//! Pairwise MI is sign-invariant, so this engine is an additive escalation over
//! the signed-correlation default rather than a replacement for it. Attribution
//! requires a unique strict-majority clique. PID atoms remain advisory diagnostics
//! and never drive the verdict.

use std::{collections::HashSet, sync::Arc};

use galadriel_core::{GaladrielError, Modality};
use pid_core::experimental::continuous::raw_scalars::ksg_mi;
use pid_core::{
    diagnostics::{
        distance_concentration_stats, intrinsic_dimension_levina_bickel,
        DistanceConcentrationConfig, IntrinsicDimConfig,
    },
    experimental::{
        continuous::{pid2_isx_estimate, Pid2Config},
        pipelines::Jitter,
    },
    stable::continuous::{
        ksg_mi_report, AssumptionLedgerEntry, EstimandIdentity, KsgConfig, KsgMethodStatus,
        KsgProvenance, KsgReportWarning, ProvenanceHashes, ScientificStatus, SupportContract,
        WarningCode,
    },
    MatOwned, Metric, ResourceEstimate,
};

const MIN_BOOTSTRAP_RESAMPLES: usize = 20;
const MAX_BOOTSTRAP_RESAMPLES: usize = MAX_PID_WINDOW;
const MAX_QUADRATIC_FIT_WORK: usize = 200_000_000;
const MAX_MODALITIES: usize = Modality::ALL.len();
/// Conservative quadratic fit units for one point-gate pair: intrinsic dimension,
/// distance concentration, and four report-first KSG distance/count scans.
pub const PID_PAIR_POINT_FIT_UNITS: usize = 6;
const MAX_PAIR_ESTIMATOR_FITS: usize = pair_count(MAX_MODALITIES) * PID_PAIR_POINT_FIT_UNITS;
/// Conservative quadratic fit units for one PID2 atom calculation: three mutual
/// information estimates plus one shared-exclusions estimate.
pub const PID_ATOM_POINT_FIT_UNITS: usize = 4;
const MAX_ATOM_ESTIMATOR_FITS: usize = MAX_MODALITIES * PID_ATOM_POINT_FIT_UNITS;
/// Conservative quadratic scan units for one raw-scalar KSG confirmation edge:
/// one joint-neighbor-radius scan, two marginal-count scans, plus one overhead unit.
pub const PID_CONFIRMATION_EDGE_FIT_UNITS: usize = 4;
const MAX_EXCLUDED_CANDIDATES: usize = (MAX_MODALITIES - 1) / 2;
const MAX_CONFIRMATION_EDGE_FITS: usize = max_confirmation_edge_fits(MAX_MODALITIES);
const CONFIRMATION_BOUND_GROUPS: usize = 2;

/// Exact upstream dependency identity used for every report from this crate.
pub const PID_RS_VERSION: &str = "1.0.0";
/// Immutable pid-rs revision selected by the workspace manifest.
pub const PID_RS_REVISION: &str = "1cd2424f7967e1752dcc8e53859e8fdad3566f51";

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
    /// Standard deviation of the seeded additive Gaussian observation-noise model
    /// after per-column standardisation. This changes the estimand; it is not a
    /// generic repair for tied samples. Keep it in sensitivity/evidence records.
    pub observation_noise_std: f64,
    /// Observation-noise/estimator seed for reproducibility.
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
            observation_noise_std: 1e-4,
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
        if !self.observation_noise_std.is_finite() || self.observation_noise_std <= 0.0 {
            return Err(InvalidConfig(
                "PID observation_noise_std must be finite and > 0".into(),
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
                .checked_mul(PID_CONFIRMATION_EDGE_FIT_UNITS)
                .and_then(|fits| fits.checked_mul(self.n_boot))
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
                "PID requests {quadratic_work} quadratic scan-equivalent fit-units (including up to {MAX_PAIR_ESTIMATOR_FITS} mandatory pair-estimator units, {MAX_ATOM_ESTIMATOR_FITS} atom-estimator units, and {MAX_CONFIRMATION_EDGE_FITS} confirmation edges × {PID_CONFIRMATION_EDGE_FIT_UNITS} units per resample across as many as {MAX_EXCLUDED_CANDIDATES} excluded candidates); maximum is {MAX_QUADRATIC_FIT_WORK}"
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

/// Machine-readable estimator/dependency evidence attached to every PID result.
#[derive(Debug, Clone, PartialEq)]
pub struct PidEstimatorEvidence {
    pub pid_rs_version: &'static str,
    pub pid_rs_revision: &'static str,
    pub pairwise_estimator: &'static str,
    pub pairwise_scientific_status: &'static str,
    pub atom_estimator: &'static str,
    pub atom_scientific_status: &'static str,
    pub support_contract: &'static str,
    pub observation_noise_model: &'static str,
    pub observation_noise_std: f64,
    pub seed: u64,
    pub geom_k: usize,
    /// Typed summaries of every successful report-first pairwise estimate used
    /// by the point gate. Bootstrap scalar fits are intentionally excluded.
    pub pairwise_reports: Vec<PairKsgEvidence>,
}

impl PidEstimatorEvidence {
    pub fn from_config(config: &PidConfig) -> Self {
        Self {
            pid_rs_version: PID_RS_VERSION,
            pid_rs_revision: PID_RS_REVISION,
            pairwise_estimator:
                "KSG MI (report-first point gate; raw-scalar circular-resample confirmation)",
            pairwise_scientific_status:
                "conditional_continuous/restricted_domain point; experimental bootstrap pipeline",
            atom_estimator: "continuous shared-exclusions PID2 (Ehrlich KSG)",
            atom_scientific_status: "experimental_restricted_domain",
            support_contract: "caller-declared regular full-dimensional continuous law",
            observation_noise_model:
                "seeded additive Gaussian noise after per-column standardisation",
            observation_noise_std: config.observation_noise_std,
            seed: config.seed,
            geom_k: config.geom_k,
            pairwise_reports: Vec::new(),
        }
    }
}

/// Report-first KSG evidence retained for one canonical modality pair.
///
/// The upstream report owns additional high-volume diagnostics. Galadriel keeps
/// the typed scientific status, assumptions, warnings, hashes, estimand, support
/// contract, and resource preflight that a downstream audit needs to interpret
/// the scalar used by the clique gate.
#[derive(Debug, Clone, PartialEq)]
pub struct PairKsgEvidence {
    pub first: Modality,
    pub second: Modality,
    pub estimate_nats: f64,
    pub n_samples: usize,
    pub k: usize,
    pub support_contract: SupportContract,
    pub method_status: KsgMethodStatus,
    pub scientific_status: ScientificStatus,
    pub estimand: EstimandIdentity,
    pub assumption_ledger: Vec<AssumptionLedgerEntry>,
    pub warnings: Vec<KsgReportWarning>,
    pub report_warnings: Vec<WarningCode>,
    pub provenance_hashes: Arc<ProvenanceHashes>,
    pub preprocessing_description: String,
    pub observation_model_description: String,
    pub sampling_model_description: Option<String>,
    pub resource_estimate: ResourceEstimate,
}

struct PairMiEstimate {
    value: f64,
    evidence: PairKsgEvidence,
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
    /// Exact dependency, estimator, support, noise, and seed classification.
    pub estimator: PidEstimatorEvidence,
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
    let mut estimator = PidEstimatorEvidence::from_config(cfg);
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
            estimator,
            channels: Vec::new(),
            verdict: PidVerdict::InsufficientEvidence,
            note: format!(
                "need >=3 channels and >={required_samples} aligned samples (have {c} channels, w={w})"
            ),
        });
    }
    // KSG distances are not scale invariant when one fixed observation-noise
    // amplitude is added. Validate and standardise every verdict-eligible column.
    let mut cols = Vec::with_capacity(c);
    for (modality, values) in channels {
        cols.push(standardize(&values[values.len() - w..], modality.label())?);
    }

    let mut mi = vec![vec![None::<f64>; c]; c];
    let mut pair_failures = vec![Vec::<String>::new(); c];
    for i in 0..c {
        for j in (i + 1)..c {
            match pair_mi(cfg, channels[i].0, &cols[i], channels[j].0, &cols[j]) {
                Ok(estimate) => {
                    mi[i][j] = Some(estimate.value);
                    mi[j][i] = Some(estimate.value);
                    estimator.pairwise_reports.push(estimate.evidence);
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
            estimator,
            channels: reports,
            verdict: PidVerdict::InsufficientEvidence,
            note: format!("requested channel(s) not assessable: {missing}"),
        });
    }
    let failed_pairs = pair_failures.iter().map(Vec::len).sum::<usize>() / 2;
    if failed_pairs > 0 {
        return Ok(PidReport {
            estimator,
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
            estimator,
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
            estimator,
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
                estimator,
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
            estimator,
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
                estimator,
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
        estimator,
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
) -> Result<PairMiEstimate, String> {
    let (first_modality, first, second_modality, second) =
        canonical_pair(a_modality, a, b_modality, b);
    let seed = domain_seed(
        cfg.seed,
        ROLE_PAIR_POINT,
        modality_key(first_modality),
        modality_key(second_modality),
    );
    let (joint, columns) =
        noised_matrix_and_columns(&[first, second], cfg.observation_noise_std, seed)?;
    let id = intrinsic_dimension_levina_bickel(
        joint.as_ref(),
        &IntrinsicDimConfig::default()
            .with_k(cfg.geom_k)
            .with_metric(Metric::Chebyshev),
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
        &DistanceConcentrationConfig::default().with_metric(Metric::Chebyshev),
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
    estimate_mi_reported(
        cfg,
        first_modality,
        second_modality,
        seed,
        &columns[0],
        &columns[1],
    )
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

fn estimate_mi_reported(
    cfg: &PidConfig,
    first: Modality,
    second: Modality,
    derived_seed: u64,
    a: &MatOwned,
    b: &MatOwned,
) -> Result<PairMiEstimate, String> {
    let provenance = KsgProvenance::new(
        format!(
            "Galadriel overflow-resistant per-column standardisation (midrange/range preconditioning, then mean centering and population-RMS scaling) of the canonical {}-{} modality pair",
            first.label(),
            second.label()
        ),
        format!(
            "seeded additive Gaussian observation noise after standardisation (std={:.17e}, root_seed={}, derived_pair_seed={derived_seed}); population support is declared separately by KsgConfig",
            cfg.observation_noise_std, cfg.seed
        ),
        None,
    )
    .and_then(|provenance| {
        provenance.with_sampling_model_and_splits(
            "one temporally ordered sequence-aligned analysis window; temporal dependence is not diagnosed by the point report, and circular delete-block confirmation is a separate experimental pipeline",
            None,
            None,
        )
    })
    .map_err(|error| format!("KSG provenance rejected: {error}"))?;
    let report = ksg_mi_report(
        a.as_ref(),
        b.as_ref(),
        &KsgConfig::assume_regular_full_dimensional(),
        &provenance,
    )
    .map_err(|error| format!("KSG estimator failed: {error}"))?;
    if report.method_status != KsgMethodStatus::RestrictedDomain
        || report.scientific_status != ScientificStatus::ConditionalContinuous
    {
        return Err("KSG report returned an unexpected scientific-status classification".into());
    }
    let value = report.signed_estimate_nats;
    // KSG's finite-sample estimate is signed. pid-rs 1.0 deliberately defaults
    // to NegativeHandling::Allow so a small negative estimate remains an
    // auditable low-dependence result rather than a numerical failure. The
    // clique threshold is positive, so retaining the sign cannot create a
    // corroborating edge.
    if !value.is_finite() {
        return Err("KSG estimator returned a non-finite MI".into());
    }
    let preprocessing_description = report.provenance.preprocessing_description().to_owned();
    let observation_model_description =
        report.provenance.observation_model_description().to_owned();
    let sampling_model_description = report
        .provenance
        .sampling_model_description()
        .map(str::to_owned);
    Ok(PairMiEstimate {
        value,
        evidence: PairKsgEvidence {
            first,
            second,
            estimate_nats: value,
            n_samples: report.n_samples,
            k: report.k,
            support_contract: report.support_contract,
            method_status: report.method_status,
            scientific_status: report.scientific_status,
            estimand: report.estimand,
            assumption_ledger: report.assumption_ledger,
            warnings: report.warnings,
            report_warnings: report.report_warnings,
            provenance_hashes: Arc::new(report.provenance_hashes),
            preprocessing_description,
            observation_model_description,
            sampling_model_description,
            resource_estimate: report.resource_estimate,
        },
    })
}

/// Inner resample scalar path. The point gate above carries pid-rs's full
/// report/status/diagnostics; bootstrap replicates reuse the same explicit
/// support contract but avoid multiplying report materialization by every
/// edge×resample. The enclosing [`PidEstimatorEvidence`] classifies this part of
/// the pipeline as experimental.
fn estimate_mi(a: &MatOwned, b: &MatOwned) -> Result<f64, String> {
    let value = ksg_mi(
        a.as_ref(),
        b.as_ref(),
        &KsgConfig::assume_regular_full_dimensional(),
    )
    .map_err(|error| format!("KSG bootstrap estimator failed: {error}"))?;
    if !value.is_finite() {
        return Err("KSG bootstrap estimator returned a non-finite MI".into());
    }
    Ok(value)
}

/// Apply the configured observation-noise model to one joint matrix, then split
/// its columns. Noise is i.i.d. across the row-major joint matrix; no two columns
/// can receive the identical restarted PRNG sequence.
fn noised_matrix_and_columns(
    columns: &[&[f64]],
    observation_noise_std: f64,
    seed: u64,
) -> Result<(MatOwned, Vec<MatOwned>), String> {
    let Some(first) = columns.first() else {
        return Err("cannot apply observation noise to an empty column set".into());
    };
    let n = first.len();
    if n == 0 || columns.iter().any(|column| column.len() != n) {
        return Err("observation-noise columns must be non-empty and equal-length".into());
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
    let jitter = Jitter::new(observation_noise_std, seed)
        .map_err(|error| format!("observation-noise construction failed: {error}"))?;
    let joint = jitter
        .apply(raw.as_ref())
        .map_err(|error| format!("joint observation-noise application failed: {error}"))?;

    let view = joint.as_ref();
    let mut split = Vec::with_capacity(dimensions);
    for dimension in 0..dimensions {
        let data: Vec<f64> = (0..n).map(|row| view.row(row)[dimension]).collect();
        split.push(
            MatOwned::new(data, n, 1)
                .map_err(|error| format!("noised column construction failed: {error}"))?,
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
    let (_, columns) = noised_matrix_and_columns(
        &[&cols[i], &cols[others[0]], &target],
        cfg.observation_noise_std,
        seed,
    )
    .ok()?;
    let estimate = pid2_isx_estimate(
        columns[0].as_ref(),
        columns[1].as_ref(),
        columns[2].as_ref(),
        &Pid2Config::assume_regular_full_dimensional(),
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
        let (_, columns) = noised_matrix_and_columns(
            &[&resampled_a, &resampled_b],
            cfg.observation_noise_std,
            seed,
        )?;
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
            let report = analyze(&channels, &PidConfig::default()).unwrap();
            assert!(
                matches!(
                    point.verdict,
                    PidVerdict::Decoupled(ref modalities)
                        if modalities == &[Modality::Acoustic]
                ),
                "seed {seed}: point estimate did not isolate acoustic: {}",
                point.note
            );
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
    fn default_bootstrap_confirms_a_strong_deterministic_decoupling() {
        let shared = pseudo_random_series(128, 0x51);
        let honest_noise = pseudo_random_series(128, 0x52);
        let weak_noise = pseudo_random_series(128, 0x53);
        let radar = shared
            .iter()
            .zip(&honest_noise)
            .map(|(&signal, &noise)| signal + 0.03 * noise)
            .collect::<Vec<_>>();
        let acoustic = shared
            .iter()
            .zip(&weak_noise)
            .map(|(&signal, &noise)| 0.5 * signal + noise)
            .collect::<Vec<_>>();
        let channels = vec![
            (Modality::Visual, shared),
            (Modality::Radar, radar),
            (Modality::Acoustic, acoustic),
        ];

        let report = analyze(&channels, &PidConfig::default()).unwrap();
        assert_eq!(
            report.verdict,
            PidVerdict::Decoupled(vec![Modality::Acoustic]),
            "{}",
            report.note
        );
        let acoustic = report
            .channels
            .iter()
            .find(|channel| channel.modality == Modality::Acoustic)
            .unwrap();
        assert!(acoustic.decoupled);
        assert!(acoustic.ci.is_some_and(|(_, upper)| upper < 0.0));

        let evidence = &report.estimator.pairwise_reports;
        assert_eq!(evidence.len(), 3);
        assert!(evidence.iter().all(|pair| {
            pair.method_status == KsgMethodStatus::RestrictedDomain
                && pair.scientific_status == ScientificStatus::ConditionalContinuous
                && !pair.assumption_ledger.is_empty()
                && !pair.warnings.is_empty()
                && pair.provenance_hashes.input_hashes_sha256.len() == 2
                && pair.sampling_model_description.is_some()
                && pair.observation_model_description.contains("root_seed=1")
        }));
    }

    #[test]
    fn rejects_constant_columns_before_noise_can_create_false_information() {
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
    fn joint_observation_noise_does_not_reuse_one_sequence_across_columns() {
        let zeros = vec![0.0; 128];
        let (_, columns) = noised_matrix_and_columns(&[&zeros, &zeros], 1e-4, 7).unwrap();
        assert!(
            (0..128).all(|row| columns[0].as_ref().row(row)[0] != columns[1].as_ref().row(row)[0])
        );
    }

    #[test]
    fn finite_negative_ksg_estimates_remain_valid_low_edges() {
        for seed in 1..=128 {
            let first = pseudo_random_series(64, seed);
            let second = pseudo_random_series(64, seed.wrapping_add(10_000));
            let (_, columns) = noised_matrix_and_columns(&[&first, &second], 1e-4, seed).unwrap();
            let raw = ksg_mi(
                columns[0].as_ref(),
                columns[1].as_ref(),
                &KsgConfig::assume_regular_full_dimensional(),
            )
            .unwrap();
            if raw < 0.0 {
                assert_eq!(estimate_mi(&columns[0], &columns[1]).unwrap(), raw);
                let reported = estimate_mi_reported(
                    &PidConfig::default(),
                    Modality::Visual,
                    Modality::Radar,
                    seed,
                    &columns[0],
                    &columns[1],
                )
                .unwrap();
                assert_eq!(reported.value, raw);
                return;
            }
        }
        panic!("fixed seed scan did not produce a signed negative KSG estimate");
    }

    #[test]
    fn pid_rs_1_0_evidence_and_upstream_status_are_locked() {
        use pid_core::experimental::continuous::{
            pid2_isx_report, Pid2Config, Pid2MethodStatus, Pid2Provenance,
        };

        let evidence: serde_json::Value =
            serde_json::from_str(include_str!("../../../evidence/pid-rs-1.0-migration.json"))
                .unwrap();
        assert_eq!(evidence["schema_version"], 3);
        assert_eq!(evidence["to"]["pid_core_version"], PID_RS_VERSION);
        assert_eq!(evidence["to"]["pid_rs_revision"], PID_RS_REVISION);
        let lock = include_str!("../../../Cargo.lock");
        let locked_identity = format!(
            "name = \"pid-core\"\nversion = \"{PID_RS_VERSION}\"\nsource = \"git+https://github.com/sepahead/pid-rs?rev={PID_RS_REVISION}#{PID_RS_REVISION}\""
        );
        assert!(
            lock.contains(&locked_identity),
            "PID report identity constants must match the resolved Cargo.lock pin"
        );
        assert_eq!(
            evidence["execution_environment"]["rustc"],
            "1.96.0 (ac68faa20)"
        );
        assert_eq!(
            evidence["reproduction"]["discrete_xor"]["from"],
            evidence["reproduction"]["discrete_xor"]["to"]
        );
        assert_eq!(
            evidence["reproduction"]["stdout_sha256"]["from"],
            evidence["reproduction"]["stdout_sha256"]["to"]
        );
        assert_eq!(
            evidence["reproduction"]["sequential"]["from"],
            evidence["reproduction"]["sequential"]["to"]
        );
        assert_eq!(
            evidence["reproduction"]["autocorrelation_null"]["from"],
            evidence["reproduction"]["autocorrelation_null"]["to"]
        );

        let first = pseudo_random_series(128, 11);
        let second = pseudo_random_series(128, 17);
        let noise = pseudo_random_series(128, 23);
        let target = first
            .iter()
            .zip(&second)
            .zip(&noise)
            .map(|((&a, &b), &epsilon)| a + b + 0.2 * epsilon)
            .collect::<Vec<_>>();
        let (_, columns) =
            noised_matrix_and_columns(&[&first, &second, &target], 1e-4, 29).unwrap();
        let provenance = Pid2Provenance::new(
            "locked synthetic source-1 preprocessing",
            "locked synthetic source-2 preprocessing",
            "locked synthetic target preprocessing",
            "locked regular full-dimensional synthetic observation model",
        )
        .unwrap();
        let report = pid2_isx_report(
            columns[0].as_ref(),
            columns[1].as_ref(),
            columns[2].as_ref(),
            &Pid2Config::assume_regular_full_dimensional(),
            &provenance,
        )
        .unwrap();
        assert_eq!(
            report.method_status,
            Pid2MethodStatus::ExperimentalRestrictedDomain
        );
        assert!(!report.warnings.is_empty());
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
    fn quadratic_preflight_counts_full_report_first_pair_work() {
        let mut config = PidConfig {
            window: 180,
            min_samples: 100,
            ..Default::default()
        };
        let fits = MAX_PAIR_ESTIMATOR_FITS
            + MAX_ATOM_ESTIMATOR_FITS
            + MAX_CONFIRMATION_EDGE_FITS * PID_CONFIRMATION_EDGE_FIT_UNITS * config.n_boot;
        assert_eq!(PID_PAIR_POINT_FIT_UNITS, 6);
        assert_eq!(PID_CONFIRMATION_EDGE_FIT_UNITS, 4);
        assert_eq!(config.window * config.window * fits, 198_093_600);
        assert!(config.validate().is_ok());

        config.window = 181;
        assert!(matches!(
            config.validate(),
            Err(GaladrielError::InvalidConfig(ref message))
                if message.contains("maximum is 200000000")
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
