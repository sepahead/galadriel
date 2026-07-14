#![forbid(unsafe_code)]
//! Monte-Carlo evaluation of Galadriel's Mirror across four regimes, comparing four
//! detectors: the cheap **NIS χ² baseline**, the signed-correlation consistency
//! component, the cross-sensor **pairwise-MI/PID research engine**, and the full
//! additive fusion.
//!
//! All regimes run on the *same* corroborated sim (`rho > 0`) so every detector sees a
//! genuine consensus. Per trial we record, for each detector, a binary alarm and a
//! continuous score; across trials we report detection rate, false-alarm rate (on the
//! clean/null regime), and alarm-ranked ROC-AUC (alarms rank above non-alarms, then the
//! continuous score; attack vs clean uses the Mann–Whitney identity
//! `AUC = P(score_attack > score_clean)`). AUCs carry percentile-bootstrap 95 % CIs
//! ([`stealthy_ci_study`], with a *paired* corr-vs-PID difference CI via [`auc_diff_ci`]).
//! A companion study ([`measure_latency`]) reports median **time-to-detect** — frames from
//! attack onset to first alarm on growing prefixes — because how *fast* a detector fires
//! matters as much as whether it does.
//!
//! Under this simulator and the stated parameter grid, the detectors show
//! complementarity: the baseline responds to magnitude attacks while cross-sensor
//! consistency can respond to the modeled moment-matched decoupling. These results
//! are an evaluation of the modeled regimes, not a claim of operational coverage.
//! Standalone correlation and PID component metrics are deliberately pre-registered to
//! producer-attested consistency-projection axis 0. The full fused verdict evaluates every
//! attested axis and applies the detector's cross-axis family control and conflict handling.
//!
//! A decoupling-strength sweep ([`decoupling_sweep`]) compares the signed-correlation
//! and pairwise-MI paths on linear-Gaussian data using pointwise intervals. It does
//! not establish equivalence, family-wise superiority, or pure-synergy detection.

use std::collections::{HashMap, HashSet};

use galadriel_core::{
    correlation, CorrConfig, CorrVerdict, GaladrielError, Mirror, Modality, PidObservation,
    ReleaseSuite, Result as CoreResult, Verdict,
};
use galadriel_pid::{
    analyze, assess_stream, scalar_channels, FusedVerdict, PidConfig, PidConfigError,
    PidConfirmation, PidResearchProfile, PidResearchSuite, PidVerdict,
};
use galadriel_pid::{
    MAX_PID_WINDOW, PID_ATOM_POINT_FIT_UNITS, PID_CONFIRMATION_EDGE_FIT_UNITS,
    PID_PAIR_POINT_FIT_UNITS,
};
use galadriel_sim::injection::{inject, BroadbandJam, Maneuver, PhantomAcousticDoa};
use galadriel_sim::scenario::{
    generate, generate_collusion, generate_spoofed, generate_spoofed_partial, ScenarioConfig,
    ScenarioConfigError, ScenarioParams, StealthySpoof,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Minimum trial count accepted by inferential reports.
pub const MIN_INFERENCE_TRIALS: usize = 20;
const MAX_BOOTSTRAP_AUC_COMPARISONS: usize = 250_000_000;
const MAX_GRID_TRIAL_COMBINATIONS: usize = 50_000;
const MAX_STUDY_OBSERVATIONS: usize = 100_000_000;
const MAX_LATENCY_PREFIX_OBSERVATIONS: usize = 100_000_000;
const EVAL_PROJECTION_AXES: usize = 3;
const MAX_SUITE_PID_QUADRATIC_WORK: u128 = 300_000_000_000;
const ADAPTIVE_CALIBRATION_DOMAIN: u64 = 0x4144_4150_5443_414c;
const ADAPTIVE_HOLDOUT_DOMAIN: u64 = 0x4144_4150_5448_4f4c;

fn pid_research_config() -> std::result::Result<PidConfig, EvalConfigError> {
    PidResearchProfile::CircularDeleteBlockV0_9
        .try_config()
        .map_err(|source| EvalConfigError::Pid { source })
}

/// The sensor channels under test.
pub const MODALITIES: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

/// Literal-friendly, untrusted evaluation parameters.
#[derive(Debug, Clone)]
pub struct EvalParams {
    /// Trials per attack regime.
    pub trials: usize,
    /// Base seed; each study derives trial seeds in a named deterministic domain.
    pub base_seed: u64,
    /// Frames per trial.
    pub frames: usize,
    /// Cross-channel correlation of the corroborated regime.
    pub rho: f64,
    /// Nominal per-axis innovation std.
    pub sigma: f64,
    /// Loud bias-spoof magnitude (σ units).
    pub spoof_bias: f64,
    /// Broadband-jam innovation inflation (×).
    pub jam_inflation: f64,
}

/// Named, bounded research evaluation profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationResearchProfile {
    /// Synthetic evaluation defaults shipped with the 0.9 source release.
    SyntheticV0_9,
}

impl EvaluationResearchProfile {
    /// Return mutable raw parameters for a custom research evaluation.
    #[must_use]
    pub const fn params(self) -> EvalParams {
        match self {
            Self::SyntheticV0_9 => EvalParams {
                trials: 200,
                base_seed: 1000,
                frames: 300,
                rho: 0.7,
                sigma: 1.0,
                spoof_bias: 8.0,
                jam_inflation: 3.0,
            },
        }
    }

    /// Resolve the exact named profile to an immutable accepted value.
    ///
    /// Construction is `O(1)`, allocates no retained collections, and proves the
    /// per-trial scenario bound. Whole-suite grid, bootstrap, latency-prefix, and
    /// PID work is accepted separately by [`EvalSuiteConfig::try_new`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalConfigError`] if the named profile ceases to satisfy the
    /// evaluation contract.
    pub fn try_config(self) -> std::result::Result<EvalConfig, EvalConfigError> {
        EvalConfig::try_new_with_origin(self.params(), EvalConfigOrigin::Named(self))
    }

    /// Stable profile identity used in canonical configuration preimages.
    #[must_use]
    pub const fn identity(self) -> &'static str {
        match self {
            Self::SyntheticV0_9 => "galadriel-eval/synthetic-v0.9",
        }
    }
}

/// Provenance and research classification of an accepted evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalConfigOrigin {
    /// Exact named research profile.
    Named(EvaluationResearchProfile),
    /// Caller-supplied custom research parameters.
    CustomResearch,
}

/// Typed evaluation configuration and preflight failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EvalConfigError {
    /// Trial count is outside inferential bounds.
    #[error("trials must be in {minimum}..={maximum} for inferential reports")]
    TrialsOutOfRange { minimum: usize, maximum: usize },
    /// Frame count is outside simulator/evaluation bounds.
    #[error("frames must be in 128..=10000")]
    FramesOutOfRange,
    /// Corroborated-regime correlation is invalid.
    #[error("rho must be finite and in (0, 1) for corroborated studies")]
    InvalidCorrelation,
    /// Nominal standard deviation or its square is invalid.
    #[error("sigma must be finite, > 0, and have a finite nonzero square")]
    InvalidSigma,
    /// Loud-spoof bias or its square is invalid.
    #[error("spoof_bias must be finite, > 0, and have a finite square")]
    InvalidSpoofBias,
    /// Jam inflation or its square is invalid.
    #[error("jam_inflation must be finite, > 1, and have a finite square")]
    InvalidJamInflation,
    /// A derived scenario did not satisfy the simulator contract.
    #[error("evaluation scenario is invalid: {source}")]
    Scenario {
        /// Typed simulator source.
        #[source]
        source: ScenarioConfigError,
    },
    /// The named PID research profile could not be accepted.
    #[error("evaluation PID profile is invalid: {source}")]
    Pid {
        /// Typed PID configuration source.
        #[source]
        source: PidConfigError,
    },
    /// A checked preflight product overflowed.
    #[error("{context} work estimate overflowed")]
    WorkOverflow { context: &'static str },
    /// A bounded work estimate exceeds its fixed maximum.
    #[error("{context} requests about {actual} work units; maximum is {maximum}")]
    WorkLimit {
        context: &'static str,
        actual: u128,
        maximum: u128,
    },
    /// A study grid has an invalid length.
    #[error("{grid} grid must contain 1..={maximum} entries")]
    GridLength { grid: &'static str, maximum: usize },
    /// A decoupling value is not finite and in range.
    #[error("decoupling value at index {index} must be finite and in [0, 1]")]
    InvalidDecoupling { index: usize },
    /// A study grid repeats an arm and would create ambiguous duplicate evidence.
    #[error("{grid} grid repeats the value at index {index}")]
    DuplicateGridValue { grid: &'static str, index: usize },
    /// Bootstrap resamples are outside inferential bounds.
    #[error("inferential bootstrap resamples must be in 200..=100000")]
    BootstrapOutOfRange,
    /// Latency step is zero or exceeds the accepted frame count.
    #[error("latency step must be in 1..=frames")]
    InvalidLatencyStep,
    /// Maneuver lag arithmetic cannot be represented.
    #[error("maneuver lag at index {index} overflows its frame window")]
    ManeuverLagOverflow { index: usize },
    /// Maneuver magnitude is not a finite, positive, representable scale.
    #[error("maneuver magnitude must be finite, > 0, and have a finite square")]
    InvalidManeuverMagnitude,
    /// A zero-frame maneuver has no study exposure.
    #[error("maneuver duration must be > 0")]
    InvalidManeuverDuration,
    /// A lagged modality's complete maneuver window is censored by the capture.
    #[error(
        "maneuver lag at index {index} requires capture end frame {required_end}; available frames are {available_frames}"
    )]
    ManeuverOutsideCapture {
        index: usize,
        required_end: u64,
        available_frames: usize,
    },
}

impl From<EvalConfigError> for GaladrielError {
    fn from(error: EvalConfigError) -> Self {
        Self::InvalidConfig(error.to_string())
    }
}

/// Immutable, fully accepted base configuration for research evaluation.
///
/// ```compile_fail
/// use galadriel_eval::EvalConfig;
/// let _forged = EvalConfig { trials: usize::MAX };
/// ```
///
/// ```compile_fail
/// use galadriel_eval::EvalConfig;
/// let _implicit = EvalConfig::default();
/// ```
#[derive(Debug, Clone)]
pub struct EvalConfig {
    trials: usize,
    base_seed: u64,
    frames: usize,
    rho: f64,
    sigma: f64,
    spoof_bias: f64,
    jam_inflation: f64,
    origin: EvalConfigOrigin,
    canonical_digest: String,
}

impl EvalConfig {
    /// Accept caller-supplied custom research parameters.
    ///
    /// Construction is `O(1)`, retains no collections, and validates all local
    /// scalar, derived-variance, per-stream allocation, timestamp, sequence, and
    /// prior-identity bounds.
    ///
    /// # Errors
    ///
    /// Returns [`EvalConfigError`] for any invalid or unrepresentable input.
    pub fn try_new(params: EvalParams) -> std::result::Result<Self, EvalConfigError> {
        Self::try_new_with_origin(params, EvalConfigOrigin::CustomResearch)
    }

    fn try_new_with_origin(
        params: EvalParams,
        origin: EvalConfigOrigin,
    ) -> std::result::Result<Self, EvalConfigError> {
        if !(MIN_INFERENCE_TRIALS..=1_000).contains(&params.trials) {
            return Err(EvalConfigError::TrialsOutOfRange {
                minimum: MIN_INFERENCE_TRIALS,
                maximum: 1_000,
            });
        }
        if !(128..=10_000).contains(&params.frames) {
            return Err(EvalConfigError::FramesOutOfRange);
        }
        if !params.rho.is_finite() || params.rho <= 0.0 || params.rho >= 1.0 {
            return Err(EvalConfigError::InvalidCorrelation);
        }
        if !params.sigma.is_finite()
            || params.sigma <= 0.0
            || !(params.sigma * params.sigma).is_finite()
            || params.sigma * params.sigma == 0.0
        {
            return Err(EvalConfigError::InvalidSigma);
        }
        if !params.spoof_bias.is_finite()
            || params.spoof_bias <= 0.0
            || !(params.spoof_bias * params.spoof_bias).is_finite()
        {
            return Err(EvalConfigError::InvalidSpoofBias);
        }
        if !params.jam_inflation.is_finite()
            || params.jam_inflation <= 1.0
            || !(params.jam_inflation * params.jam_inflation).is_finite()
        {
            return Err(EvalConfigError::InvalidJamInflation);
        }
        scenario_from_parts(&params, params.base_seed)
            .map_err(|source| EvalConfigError::Scenario { source })?;
        let canonical_digest = eval_digest(&params, origin);
        Ok(Self {
            trials: params.trials,
            base_seed: params.base_seed,
            frames: params.frames,
            rho: params.rho,
            sigma: params.sigma,
            spoof_bias: params.spoof_bias,
            jam_inflation: params.jam_inflation,
            origin,
            canonical_digest,
        })
    }

    /// Trials per attack regime.
    #[must_use]
    pub const fn trials(&self) -> usize {
        self.trials
    }
    /// Base seed for named deterministic seed domains.
    #[must_use]
    pub const fn base_seed(&self) -> u64 {
        self.base_seed
    }
    /// Frames per trial.
    #[must_use]
    pub const fn frames(&self) -> usize {
        self.frames
    }
    /// Corroborated-regime cross-channel correlation.
    #[must_use]
    pub const fn rho(&self) -> f64 {
        self.rho
    }
    /// Nominal per-axis innovation standard deviation.
    #[must_use]
    pub const fn sigma(&self) -> f64 {
        self.sigma
    }
    /// Loud-spoof bias in nominal standard deviations.
    #[must_use]
    pub const fn spoof_bias(&self) -> f64 {
        self.spoof_bias
    }
    /// Broadband-jam innovation multiplier.
    #[must_use]
    pub const fn jam_inflation(&self) -> f64 {
        self.jam_inflation
    }
    /// Named-profile or custom-research provenance.
    #[must_use]
    pub const fn origin(&self) -> EvalConfigOrigin {
        self.origin
    }
    /// SHA-256 of the domain-separated canonical accepted configuration.
    #[must_use]
    pub fn canonical_digest(&self) -> &str {
        &self.canonical_digest
    }
}

impl TryFrom<EvalParams> for EvalConfig {
    type Error = EvalConfigError;

    fn try_from(params: EvalParams) -> std::result::Result<Self, Self::Error> {
        Self::try_new(params)
    }
}

fn scenario_from_parts(
    params: &EvalParams,
    seed: u64,
) -> std::result::Result<ScenarioConfig, ScenarioConfigError> {
    ScenarioConfig::try_new(ScenarioParams {
        track_id: 1,
        frames: params.frames,
        modalities: MODALITIES.to_vec(),
        sigma: params.sigma,
        rho: params.rho,
        dt_ms: 100,
        seed,
    })
}

fn eval_digest(params: &EvalParams, origin: EvalConfigOrigin) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"galadriel-eval-config-v0.9\0");
    match origin {
        EvalConfigOrigin::Named(profile) => {
            hasher.update(b"named\0");
            hasher.update(profile.identity().as_bytes());
            hasher.update([0]);
        }
        EvalConfigOrigin::CustomResearch => hasher.update(b"custom-research\0"),
    }
    hasher.update((params.trials as u128).to_be_bytes());
    hasher.update(params.base_seed.to_be_bytes());
    hasher.update((params.frames as u128).to_be_bytes());
    hasher.update(params.rho.to_bits().to_be_bytes());
    hasher.update(params.sigma.to_bits().to_be_bytes());
    hasher.update(params.spoof_bias.to_bits().to_be_bytes());
    hasher.update(params.jam_inflation.to_bits().to_be_bytes());
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn validate_trials(trials: usize) -> std::result::Result<(), EvalConfigError> {
    if !(MIN_INFERENCE_TRIALS..=1_000).contains(&trials) {
        return Err(EvalConfigError::TrialsOutOfRange {
            minimum: MIN_INFERENCE_TRIALS,
            maximum: 1_000,
        });
    }
    Ok(())
}

fn validate_bootstrap(n_boot: usize) -> std::result::Result<(), EvalConfigError> {
    if !(200..=100_000).contains(&n_boot) {
        return Err(EvalConfigError::BootstrapOutOfRange);
    }
    Ok(())
}

fn validate_decouplings(decouplings: &[f64]) -> std::result::Result<(), EvalConfigError> {
    if decouplings.is_empty() || decouplings.len() > 10_000 {
        return Err(EvalConfigError::GridLength {
            grid: "decoupling",
            maximum: 10_000,
        });
    }
    let mut values = HashSet::with_capacity(decouplings.len());
    for (index, value) in decouplings.iter().copied().enumerate() {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(EvalConfigError::InvalidDecoupling { index });
        }
        let canonical_bits = if value == 0.0 { 0 } else { value.to_bits() };
        if !values.insert(canonical_bits) {
            return Err(EvalConfigError::DuplicateGridValue {
                grid: "decoupling",
                index,
            });
        }
    }
    Ok(())
}

fn validate_maneuver_inputs(
    cfg: &EvalConfig,
    lag_steps: &[u64],
    magnitude: f64,
    duration: u64,
) -> std::result::Result<(), EvalConfigError> {
    if lag_steps.is_empty() || lag_steps.len() > 10_000 {
        return Err(EvalConfigError::GridLength {
            grid: "maneuver lag",
            maximum: 10_000,
        });
    }
    if !magnitude.is_finite() || magnitude <= 0.0 || !(magnitude * magnitude).is_finite() {
        return Err(EvalConfigError::InvalidManeuverMagnitude);
    }
    if duration == 0 {
        return Err(EvalConfigError::InvalidManeuverDuration);
    }
    let mut unique_lags = HashSet::with_capacity(lag_steps.len());
    let maneuver_start = (cfg.frames / 3) as u64;
    let max_modality = MODALITIES
        .iter()
        .copied()
        .map(|modality| u64::from(modality.stable_code()))
        .fold(0, u64::max);
    for (index, lag_step) in lag_steps.iter().copied().enumerate() {
        if !unique_lags.insert(lag_step) {
            return Err(EvalConfigError::DuplicateGridValue {
                grid: "maneuver lag",
                index,
            });
        }
        let required_end = max_modality
            .checked_mul(lag_step)
            .and_then(|lag| maneuver_start.checked_add(lag))
            .and_then(|start| start.checked_add(duration))
            .ok_or(EvalConfigError::ManeuverLagOverflow { index })?;
        if required_end > cfg.frames as u64 {
            return Err(EvalConfigError::ManeuverOutsideCapture {
                index,
                required_end,
                available_frames: cfg.frames,
            });
        }
    }
    Ok(())
}

fn validate_grid_work(
    cfg: &EvalConfig,
    grid_len: usize,
) -> std::result::Result<(), EvalConfigError> {
    let combinations = cfg
        .trials
        .checked_mul(grid_len)
        .ok_or(EvalConfigError::WorkOverflow {
            context: "grid × trials",
        })?;
    if combinations > MAX_GRID_TRIAL_COMBINATIONS {
        return Err(EvalConfigError::WorkLimit {
            context: "grid × trials",
            actual: combinations as u128,
            maximum: MAX_GRID_TRIAL_COMBINATIONS as u128,
        });
    }
    validate_observation_work(cfg.trials, cfg.frames, grid_len)?;
    Ok(())
}

fn validate_observation_work(
    trials: usize,
    frames: usize,
    streams_per_trial: usize,
) -> std::result::Result<(), EvalConfigError> {
    let observations = trials
        .checked_mul(frames)
        .and_then(|frames| frames.checked_mul(MODALITIES.len()))
        .and_then(|observations| observations.checked_mul(streams_per_trial))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "generated observations",
        })?;
    if observations > MAX_STUDY_OBSERVATIONS {
        return Err(EvalConfigError::WorkLimit {
            context: "generated observations",
            actual: observations as u128,
            maximum: MAX_STUDY_OBSERVATIONS as u128,
        });
    }
    Ok(())
}

fn validate_bootstrap_work(
    trials: usize,
    n_boot: usize,
    interval_count: usize,
) -> std::result::Result<(), EvalConfigError> {
    let combined = trials.checked_mul(2).ok_or(EvalConfigError::WorkOverflow {
        context: "bootstrap AUC",
    })?;
    let rank_levels = usize::try_from(usize::BITS - combined.leading_zeros()).unwrap_or(usize::MAX);
    let work = combined
        .checked_mul(rank_levels)
        .and_then(|rank_work| rank_work.checked_mul(n_boot))
        .and_then(|comparisons| comparisons.checked_mul(interval_count))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "bootstrap AUC",
        })?;
    if work > MAX_BOOTSTRAP_AUC_COMPARISONS {
        return Err(EvalConfigError::WorkLimit {
            context: "bootstrap AUC rank",
            actual: work as u128,
            maximum: MAX_BOOTSTRAP_AUC_COMPARISONS as u128,
        });
    }
    Ok(())
}

fn pid_fit_count(cfg: &PidConfig) -> std::result::Result<u128, EvalConfigError> {
    let channels = MODALITIES.len();
    let pair_count = channels
        .checked_mul(channels.saturating_sub(1))
        .map(|pairs| pairs / 2)
        .ok_or(EvalConfigError::WorkOverflow {
            context: "PID pair count",
        })?;
    let point_fits = pair_count
        .checked_mul(PID_PAIR_POINT_FIT_UNITS)
        .and_then(|fits| fits.checked_add(channels.saturating_mul(PID_ATOM_POINT_FIT_UNITS)))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "PID point-fit count",
        })?;
    let confirmation_fits = match cfg.confirmation() {
        PidConfirmation::PointEstimateOnly => 0,
        PidConfirmation::CircularDeleteBlock(confirmation) => {
            let consensus = channels / 2 + 1;
            let consensus_edges = consensus
                .checked_mul(consensus.saturating_sub(1))
                .map(|edges| edges / 2)
                .ok_or(EvalConfigError::WorkOverflow {
                    context: "PID confirmation-edge count",
                })?;
            let excluded_edges = channels
                .saturating_sub(consensus)
                .checked_mul(consensus)
                .ok_or(EvalConfigError::WorkOverflow {
                    context: "PID candidate-edge count",
                })?;
            consensus_edges
                .checked_add(excluded_edges)
                .and_then(|edges| edges.checked_mul(PID_CONFIRMATION_EDGE_FIT_UNITS))
                .and_then(|edges| edges.checked_mul(confirmation.resamples()))
                .ok_or(EvalConfigError::WorkOverflow {
                    context: "PID confirmation-fit count",
                })?
        }
    };
    point_fits
        .checked_add(confirmation_fits)
        .map(|fits| fits as u128)
        .ok_or(EvalConfigError::WorkOverflow {
            context: "PID total-fit count",
        })
}

fn pid_analysis_work(
    cfg: &PidConfig,
    samples: usize,
    fit_count: u128,
) -> std::result::Result<u128, EvalConfigError> {
    if samples < cfg.required_samples() {
        return Ok(0);
    }
    let window = samples.min(cfg.window()).min(MAX_PID_WINDOW) as u128;
    window
        .checked_mul(window)
        .and_then(|distance_pairs| distance_pairs.checked_mul(fit_count))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "PID analysis",
        })
}

fn full_pid_work(cfg: &EvalConfig, calls: usize) -> std::result::Result<u128, EvalConfigError> {
    let pid_cfg = pid_research_config()?;
    let fit_count = pid_fit_count(&pid_cfg)?;
    let per_call = pid_analysis_work(&pid_cfg, cfg.frames, fit_count)?;
    checked_work_product(calls as u128, per_call, "full-stream PID")
}

fn validate_pid_work_limit(
    work: u128,
    context: &'static str,
) -> std::result::Result<(), EvalConfigError> {
    if work > MAX_SUITE_PID_QUADRATIC_WORK {
        return Err(EvalConfigError::WorkLimit {
            context,
            actual: work,
            maximum: MAX_SUITE_PID_QUADRATIC_WORK,
        });
    }
    Ok(())
}

fn validate_full_pid_calls(
    cfg: &EvalConfig,
    calls: usize,
    context: &'static str,
) -> std::result::Result<(), EvalConfigError> {
    validate_pid_work_limit(full_pid_work(cfg, calls)?, context)
}

fn latency_pid_work(
    cfg: &EvalConfig,
    trials: usize,
    step: usize,
) -> std::result::Result<u128, EvalConfigError> {
    let pid_cfg = pid_research_config()?;
    let fit_count = pid_fit_count(&pid_cfg)?;
    let onset = cfg.frames / 3;
    let work_per_stream = ttd_probe_schedule(cfg.frames, onset, step)
        .into_iter()
        .try_fold(0_u128, |work, probe| {
            let probe_work = pid_analysis_work(&pid_cfg, probe.frames, fit_count)?;
            work.checked_add(probe_work)
                .ok_or(EvalConfigError::WorkOverflow {
                    context: "latency PID",
                })
        })?;
    let streams = trials
        .checked_mul(Attack::ALL.len().saturating_sub(1))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "latency PID stream count",
        })?;
    checked_work_product(streams as u128, work_per_stream, "latency PID")
}

fn checked_work_product(
    left: u128,
    right: u128,
    context: &'static str,
) -> std::result::Result<u128, EvalConfigError> {
    left.checked_mul(right)
        .ok_or(EvalConfigError::WorkOverflow { context })
}

fn validate_suite_pid_work(
    cfg: &EvalConfig,
    grid_len: usize,
    lag_count: usize,
    latency_trials: usize,
    latency_step: usize,
) -> std::result::Result<(), EvalConfigError> {
    // Per trial: main report (axis-0 component plus every fused axis), CI study,
    // sweep, collusion, adaptive calibration/holdout/attacks, and maneuver study.
    let full_calls_per_trial = Attack::ALL
        .len()
        .checked_mul(1 + EVAL_PROJECTION_AXES)
        .and_then(|calls| calls.checked_add(2))
        .and_then(|calls| calls.checked_add(1 + grid_len))
        .and_then(|calls| calls.checked_add(1))
        .and_then(|calls| calls.checked_add(2 + grid_len))
        .and_then(|calls| calls.checked_add(lag_count))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "suite PID call count",
        })?;
    let full_calls = checked_work_product(
        cfg.trials as u128,
        full_calls_per_trial as u128,
        "full-stream",
    )?;
    let full_calls = usize::try_from(full_calls).map_err(|_| EvalConfigError::WorkOverflow {
        context: "full-stream PID call count",
    })?;
    let full_work = full_pid_work(cfg, full_calls)?;
    let latency_work = latency_pid_work(cfg, latency_trials, latency_step)?;
    let total = full_work
        .checked_add(latency_work)
        .ok_or(EvalConfigError::WorkOverflow {
            context: "suite PID",
        })?;
    validate_pid_work_limit(total, "suite PID quadratic fits")
}

/// Raw workload parameters for the complete command-line evaluation suite.
#[derive(Debug, Clone)]
pub struct EvalSuiteParams {
    /// Decoupling strengths used by sweep/adaptive/gain studies.
    pub decouplings: Vec<f64>,
    /// Per-modality maneuver lag steps.
    pub lag_steps: Vec<u64>,
    /// Bootstrap resamples for inferential intervals.
    pub bootstrap_resamples: usize,
    /// Trial count used by time-to-detect studies.
    pub latency_trials: usize,
    /// Prefix stride used by time-to-detect studies.
    pub latency_step: usize,
}

/// Immutable accepted composition for the complete synthetic evaluation suite.
///
/// A value exists only after all grid, trial, observation, bootstrap, maneuver,
/// latency-prefix, pair, estimator-fit, and multi-axis PID products have passed
/// checked arithmetic and fixed ceilings. Construction is `O(g + l + p)`, where
/// `g` and `l` are grid lengths and `p` is the number of latency probes; it retains
/// exactly the two supplied grids. The admitted work is bounded by the constants
/// documented in this crate's configuration contract.
///
/// ```compile_fail
/// use galadriel_eval::EvalSuiteConfig;
/// let _forged = EvalSuiteConfig { latency_step: 0 };
/// ```
///
/// ```compile_fail
/// use galadriel_eval::EvalSuiteConfig;
/// let _implicit = EvalSuiteConfig::default();
/// ```
#[derive(Debug, Clone)]
pub struct EvalSuiteConfig {
    eval: EvalConfig,
    decouplings: Vec<f64>,
    lag_steps: Vec<u64>,
    bootstrap_resamples: usize,
    latency_trials: usize,
    latency_step: usize,
    canonical_digest: String,
}

impl EvalSuiteConfig {
    /// Preflight and accept a complete evaluation suite before any simulation.
    ///
    /// # Errors
    ///
    /// Returns [`EvalConfigError`] on the first invalid local or aggregate bound.
    pub fn try_new(
        eval: EvalConfig,
        mut params: EvalSuiteParams,
    ) -> std::result::Result<Self, EvalConfigError> {
        validate_decouplings(&params.decouplings)?;
        for value in &mut params.decouplings {
            if *value == 0.0 {
                *value = 0.0;
            }
        }
        validate_maneuver_inputs(&eval, &params.lag_steps, 12.0, 90)?;
        validate_trials(params.latency_trials)?;
        validate_bootstrap(params.bootstrap_resamples)?;

        let stream_factor = params
            .decouplings
            .len()
            .checked_mul(4)
            .and_then(|factor| factor.checked_add(params.lag_steps.len()))
            .and_then(|factor| factor.checked_add(10))
            .ok_or(EvalConfigError::WorkOverflow {
                context: "suite stream count",
            })?;
        validate_observation_work(eval.trials, eval.frames, stream_factor)?;

        let bootstrap_intervals = params
            .decouplings
            .len()
            .checked_mul(4)
            .and_then(|intervals| intervals.checked_add(5))
            .ok_or(EvalConfigError::WorkOverflow {
                context: "suite bootstrap interval count",
            })?;
        validate_bootstrap_work(eval.trials, params.bootstrap_resamples, bootstrap_intervals)?;

        if params.latency_step == 0 || params.latency_step > eval.frames {
            return Err(EvalConfigError::InvalidLatencyStep);
        }
        validate_suite_pid_work(
            &eval,
            params.decouplings.len(),
            params.lag_steps.len(),
            params.latency_trials,
            params.latency_step,
        )?;
        validate_latency_work(&eval, params.latency_trials, params.latency_step)?;
        let canonical_digest = suite_digest(&eval, &params);
        Ok(Self {
            eval,
            decouplings: params.decouplings,
            lag_steps: params.lag_steps,
            bootstrap_resamples: params.bootstrap_resamples,
            latency_trials: params.latency_trials,
            latency_step: params.latency_step,
            canonical_digest,
        })
    }

    /// Accepted base evaluation configuration.
    #[must_use]
    pub const fn eval(&self) -> &EvalConfig {
        &self.eval
    }
    /// Accepted decoupling grid.
    #[must_use]
    pub fn decouplings(&self) -> &[f64] {
        &self.decouplings
    }
    /// Accepted maneuver-lag grid.
    #[must_use]
    pub fn lag_steps(&self) -> &[u64] {
        &self.lag_steps
    }
    /// Accepted bootstrap count.
    #[must_use]
    pub const fn bootstrap_resamples(&self) -> usize {
        self.bootstrap_resamples
    }
    /// Accepted latency trial count.
    #[must_use]
    pub const fn latency_trials(&self) -> usize {
        self.latency_trials
    }
    /// Accepted latency-prefix stride.
    #[must_use]
    pub const fn latency_step(&self) -> usize {
        self.latency_step
    }
    /// SHA-256 of the complete domain-separated suite composition.
    #[must_use]
    pub fn canonical_digest(&self) -> &str {
        &self.canonical_digest
    }
}

fn suite_digest(eval: &EvalConfig, params: &EvalSuiteParams) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"galadriel-eval-suite-config-v0.9\0");
    hasher.update(eval.canonical_digest.as_bytes());
    hasher.update([0]);
    hasher.update((params.decouplings.len() as u128).to_be_bytes());
    for value in &params.decouplings {
        hasher.update(value.to_bits().to_be_bytes());
    }
    hasher.update((params.lag_steps.len() as u128).to_be_bytes());
    for value in &params.lag_steps {
        hasher.update(value.to_be_bytes());
    }
    hasher.update((params.bootstrap_resamples as u128).to_be_bytes());
    hasher.update((params.latency_trials as u128).to_be_bytes());
    hasher.update((params.latency_step as u128).to_be_bytes());
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Preflight the complete command-line report suite before any simulation runs.
///
/// This compatibility entry point now returns the accepted composition; callers
/// should retain it and take all subsequent inputs from its getters.
pub fn validate_report_suite(
    cfg: &EvalConfig,
    decouplings: &[f64],
    lag_steps: &[u64],
    n_boot: usize,
    latency_trials: usize,
    latency_step: usize,
) -> std::result::Result<EvalSuiteConfig, EvalConfigError> {
    EvalSuiteConfig::try_new(
        cfg.clone(),
        EvalSuiteParams {
            decouplings: decouplings.to_vec(),
            lag_steps: lag_steps.to_vec(),
            bootstrap_resamples: n_boot,
            latency_trials,
            latency_step,
        },
    )
}

/// The four regimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attack {
    /// Corroborated, no attack (the negative class / false-alarm probe).
    Clean,
    /// A large constant bias on one channel — inflates NIS, preserves correlation.
    LoudSpoof,
    /// A moment-matched decoupling — NIS unchanged, correlation broken.
    Stealthy,
    /// Correlated all-channel innovation inflation.
    Jam,
}

impl Attack {
    /// All regimes.
    pub const ALL: [Attack; 4] = [
        Attack::Clean,
        Attack::LoudSpoof,
        Attack::Stealthy,
        Attack::Jam,
    ];

    /// A human label.
    pub fn label(self) -> &'static str {
        match self {
            Attack::Clean => "clean (null)",
            Attack::LoudSpoof => "loud bias spoof",
            Attack::Stealthy => "stealthy (moment-matched)",
            Attack::Jam => "broadband jam",
        }
    }
}

fn attack_seed(cfg: &EvalConfig, trial: usize, attack: Attack) -> u64 {
    let domain = match attack {
        Attack::Clean => 0x434c_4541_4e00_0001,
        Attack::LoudSpoof => 0x4c4f_5544_0000_0002,
        Attack::Stealthy => 0x5354_4541_4c54_4803,
        Attack::Jam => 0x4a41_4d00_0000_0004,
    };
    cfg.base_seed.wrapping_add(trial as u64) ^ domain
}

#[derive(Debug, Clone, Copy)]
enum AdaptiveCleanArm {
    Calibration,
    Holdout,
}

fn adaptive_clean_seed(cfg: &EvalConfig, trial: usize, arm: AdaptiveCleanArm) -> u64 {
    let domain = match arm {
        AdaptiveCleanArm::Calibration => ADAPTIVE_CALIBRATION_DOMAIN,
        AdaptiveCleanArm::Holdout => ADAPTIVE_HOLDOUT_DOMAIN,
    };
    let mut mixer = SplitMix64(
        cfg.base_seed
            .wrapping_add(trial as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ domain,
    );
    mixer.next_u64()
}

fn scenario(cfg: &EvalConfig, seed: u64) -> CoreResult<ScenarioConfig> {
    ScenarioConfig::try_new(ScenarioParams {
        track_id: 1,
        frames: cfg.frames,
        modalities: MODALITIES.to_vec(),
        sigma: cfg.sigma,
        rho: cfg.rho,
        dt_ms: 100,
        seed,
    })
    .map_err(|error| GaladrielError::InvalidConfig(error.to_string()))
}

fn build(attack: Attack, cfg: &EvalConfig, seed: u64) -> CoreResult<Vec<PidObservation>> {
    let s = scenario(cfg, seed)?;
    let start = (cfg.frames as u64) / 3;
    match attack {
        Attack::Clean => generate(&s),
        Attack::LoudSpoof => {
            let mut v = generate(&s)?;
            inject(
                &mut v,
                &PhantomAcousticDoa {
                    target: Modality::Acoustic,
                    start_frame: start,
                    bias: cfg.spoof_bias,
                },
            )?;
            Ok(v)
        }
        Attack::Stealthy => generate_spoofed(
            &s,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: start,
            },
        ),
        Attack::Jam => {
            let mut v = generate(&s)?;
            inject(
                &mut v,
                &BroadbandJam {
                    start_frame: start,
                    inflation: cfg.jam_inflation,
                },
            )?;
            Ok(v)
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DetectorEvidence {
    /// `None` means the detector explicitly lacked sufficient evidence.
    alarm: Option<bool>,
    /// A continuous score can remain estimable even when the discrete consensus
    /// graph is inconclusive. `None` means no defensible score was available.
    score: Option<f64>,
}

impl DetectorEvidence {
    fn require_score(self, detector: &str) -> CoreResult<f64> {
        self.score.ok_or_else(|| {
            GaladrielError::InvalidConfig(format!(
                "{detector} had no continuous score in a study requiring one"
            ))
        })
    }
}

/// Baseline: streaming NIS χ² Mirror. Alarm = attributed, broad, or unclassified
/// magnitude evidence; score = the strongest per-channel terminal-window surprise
/// `1 − min_c p_right`, ranked above all non-alarms when a CUSUM-only alarm fires.
fn baseline_eval(stream: &[PidObservation]) -> CoreResult<DetectorEvidence> {
    let suite = ReleaseSuite::standalone_advisory_v0_9(&MODALITIES)?;
    let mut m = Mirror::from_release_suite(&suite);
    for o in stream {
        m.ingest(o)?;
    }
    let first = stream.first().ok_or_else(|| {
        GaladrielError::InvalidObservation("baseline evaluation requires observations".into())
    })?;
    let last = stream
        .iter()
        .map(PidObservation::sequence)
        .max()
        .ok_or_else(|| {
            GaladrielError::InvalidObservation("baseline evaluation requires observations".into())
        })?;
    let rep = m.assess(first.track_id(), last)?;
    let alarm = match rep.verdict() {
        Verdict::InsufficientEvidence => None,
        Verdict::AttributedInconsistency { .. }
        | Verdict::BroadDegradation
        | Verdict::UnclassifiedAnomaly { .. } => Some(true),
        Verdict::Nominal => Some(false),
    };
    let minimum_p = rep
        .channels()
        .iter()
        .filter(|c| c.ready())
        .map(|c| c.p_right())
        .reduce(f64::min);
    Ok(DetectorEvidence {
        alarm,
        score: minimum_p.map(|p| alarm_rank(alarm == Some(true), 1.0 - p)),
    })
}

/// Decoupling depth `1 − min/max corroboration` over a channel group's best-peer
/// corroborations — the score shared by the PID engine and the correlation default so
/// the two are **directly comparable** (the whole point of `docs/JUSTIFICATION.md`).
fn decoupling_depth(corrs: &[f64]) -> Option<f64> {
    if corrs.len() < 2 {
        return None;
    }
    let mx = corrs.iter().copied().fold(f64::MIN, f64::max);
    let mn = corrs.iter().copied().fold(f64::MAX, f64::min);
    if mx > 1e-9 {
        Some((1.0 - mn / mx).clamp(0.0, 1.0))
    } else {
        Some(0.0)
    }
}

fn alarm_rank(alarm: bool, continuous_score: f64) -> f64 {
    let score = continuous_score.clamp(0.0, 1.0);
    if alarm {
        2.0 + score
    } else {
        score
    }
}

fn alarm_rank_evidence(evidence: DetectorEvidence) -> DetectorEvidence {
    DetectorEvidence {
        alarm: evidence.alarm,
        score: evidence
            .score
            .map(|score| alarm_rank(evidence.alarm == Some(true), score)),
    }
}

/// Registered projection-axis-0 PID component: alarm = `Decoupled`; score = decoupling
/// depth over KSG-MI corroborations.
fn pid_evidence(stream: &[PidObservation]) -> CoreResult<DetectorEvidence> {
    let channels = scalar_channels(stream, &MODALITIES, 0)?;
    let rep = analyze(&channels, &pid_research_config()?)?;
    let alarm = match rep.verdict() {
        PidVerdict::Decoupled(_) => Some(true),
        PidVerdict::Nominal => Some(false),
        PidVerdict::InsufficientEvidence => None,
    };
    let corrs: Vec<f64> = rep
        .channels()
        .iter()
        .filter_map(|c| c.corroboration())
        .collect();
    Ok(DetectorEvidence {
        alarm,
        score: decoupling_depth(&corrs),
    })
}

fn pid_eval(stream: &[PidObservation]) -> CoreResult<DetectorEvidence> {
    pid_evidence(stream).map(alarm_rank_evidence)
}

/// Registered projection-axis-0 signed-correlation component. Its alarm and score
/// are derived from the same report; all-axis fusion is evaluated separately.
fn corr_evidence(stream: &[PidObservation]) -> CoreResult<DetectorEvidence> {
    let channels = scalar_channels(stream, &MODALITIES, 0)?;
    let report = correlation::analyze(&channels, &CorrConfig::standalone_advisory_v0_9()?)?;
    let alarm = match report.verdict() {
        CorrVerdict::Decoupled(_) => Some(true),
        CorrVerdict::Nominal => Some(false),
        CorrVerdict::InsufficientEvidence => None,
    };
    let corrs: Vec<f64> = report
        .channels()
        .iter()
        .filter_map(|c| c.corroboration())
        .collect();
    Ok(DetectorEvidence {
        alarm,
        score: decoupling_depth(&corrs),
    })
}

fn corr_eval(stream: &[PidObservation]) -> CoreResult<DetectorEvidence> {
    corr_evidence(stream).map(alarm_rank_evidence)
}

fn component_evaluations(stream: &[PidObservation]) -> CoreResult<[DetectorEvidence; 3]> {
    Ok([
        baseline_eval(stream)?,
        corr_eval(stream)?,
        pid_eval(stream)?,
    ])
}

/// Fused detector: alarm on attributed-inconsistency, broad-degradation, or unclassified
/// evidence (NIS ⊕ PID escalation).
fn fused_eval(stream: &[PidObservation]) -> CoreResult<Option<bool>> {
    let suite = PidResearchSuite::circular_delete_block_v0_9(&MODALITIES)?;
    let r = assess_stream(stream, &suite)?;
    Ok(match r.verdict() {
        FusedVerdict::InsufficientEvidence => None,
        FusedVerdict::AttributedInconsistency { .. }
        | FusedVerdict::BroadDegradation
        | FusedVerdict::UnclassifiedAnomaly { .. } => Some(true),
        FusedVerdict::Nominal => Some(false),
    })
}

/// ROC-AUC via the Mann–Whitney identity (ties count 0.5).
pub fn auc(pos: &[f64], neg: &[f64]) -> f64 {
    if pos.is_empty() || neg.is_empty() || !pos.iter().chain(neg).all(|value| value.is_finite()) {
        return f64::NAN;
    }
    let Some(capacity) = pos.len().checked_add(neg.len()) else {
        return f64::NAN;
    };
    let mut ranked = Vec::new();
    if ranked.try_reserve_exact(capacity).is_err() {
        return f64::NAN;
    }
    ranked.extend(pos.iter().copied().map(|score| (score, true)));
    ranked.extend(neg.iter().copied().map(|score| (score, false)));
    ranked.sort_by(|left, right| left.0.total_cmp(&right.0));

    // Mann–Whitney U in O(n log n): every positive in a tie group beats all
    // earlier negatives and ties half of the negatives in its own group.
    let (mut index, mut negatives_before, mut wins) = (0usize, 0usize, 0.0_f64);
    while index < ranked.len() {
        let mut end = index + 1;
        while end < ranked.len() && ranked[end].0 == ranked[index].0 {
            end += 1;
        }
        let positives = ranked[index..end]
            .iter()
            .filter(|(_, positive)| *positive)
            .count();
        let negatives = end - index - positives;
        wins += positives as f64 * (negatives_before as f64 + 0.5 * negatives as f64);
        negatives_before += negatives;
        index = end;
    }
    wins / (pos.len() as f64 * neg.len() as f64)
}

fn auc_bootstrap_work_ok(pos: usize, neg: usize, n_boot: usize) -> bool {
    let Some(combined) = pos.checked_add(neg) else {
        return false;
    };
    let rank_levels = usize::try_from(usize::BITS - combined.leading_zeros()).unwrap_or(usize::MAX);
    combined
        .checked_mul(rank_levels)
        .and_then(|work| work.checked_mul(n_boot))
        .is_some_and(|work| work <= MAX_BOOTSTRAP_AUC_COMPARISONS)
}

// ---------------------------------------------------------------------------
// Bootstrap confidence intervals
// ---------------------------------------------------------------------------

/// A tiny deterministic SplitMix64 PRNG for bootstrap resampling — no dependency, no
/// `unsafe`, reproducible from a seed (the harness bans `Math.random`-style entropy).
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A uniform index in `0..n`.
    fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        let bound = n as u64;
        // Reject the short residue at the bottom of the u64 domain. A plain
        // modulo maps that residue onto early indices one extra time whenever
        // the resample length does not divide 2^64.
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let draw = self.next_u64();
            if draw >= threshold {
                return (draw % bound) as usize;
            }
        }
    }
}

fn percentiles(mut xs: Vec<f64>, lo: f64, hi: f64) -> (f64, f64) {
    xs.retain(|value| value.is_finite());
    if xs.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    xs.sort_by(f64::total_cmp);
    let pick = |q: f64| {
        let idx = ((q * (xs.len() as f64 - 1.0)).round() as usize).min(xs.len() - 1);
        xs[idx]
    };
    (pick(lo), pick(hi))
}

/// Percentile bootstrap 95% CI for an AUC, resampling each class with replacement.
pub fn auc_ci(pos: &[f64], neg: &[f64], n_boot: usize, seed: u64) -> (f64, f64) {
    let work_ok = auc_bootstrap_work_ok(pos.len(), neg.len(), n_boot);
    if pos.len() < 2
        || neg.len() < 2
        || !(200..=100_000).contains(&n_boot)
        || !work_ok
        || !pos.iter().chain(neg).all(|value| value.is_finite())
    {
        return (f64::NAN, f64::NAN);
    }
    let mut rng = SplitMix64(seed.wrapping_add(0x5EED));
    let mut aucs = Vec::with_capacity(n_boot);
    let (mut rp, mut rn) = (vec![0.0; pos.len()], vec![0.0; neg.len()]);
    for _ in 0..n_boot {
        for r in rp.iter_mut() {
            *r = pos[rng.below(pos.len())];
        }
        for r in rn.iter_mut() {
            *r = neg[rng.below(neg.len())];
        }
        aucs.push(auc(&rp, &rn));
    }
    percentiles(aucs, 0.025, 0.975)
}

/// Paired bootstrap 95% CI for the AUC *difference* `AUC(a) − AUC(b)`, resampling the
/// trial indices **jointly** so the two detectors share the same resamples (they are
/// scored on the same streams, so a paired bootstrap is the correct pairing).
/// `a_pos`/`b_pos` must be aligned by attack-trial; `a_neg`/`b_neg` by clean-trial.
pub fn auc_diff_ci(
    a_pos: &[f64],
    a_neg: &[f64],
    b_pos: &[f64],
    b_neg: &[f64],
    n_boot: usize,
    seed: u64,
) -> (f64, f64) {
    let (np, nn) = (a_pos.len(), a_neg.len());
    // Each paired-difference resample computes two AUCs.
    let work_ok = auc_bootstrap_work_ok(np, nn, n_boot.saturating_mul(2));
    if np < 2
        || nn < 2
        || b_pos.len() != np
        || b_neg.len() != nn
        || !(200..=100_000).contains(&n_boot)
        || !work_ok
        || !a_pos
            .iter()
            .chain(a_neg)
            .chain(b_pos)
            .chain(b_neg)
            .all(|value| value.is_finite())
    {
        return (f64::NAN, f64::NAN);
    }
    let mut rng = SplitMix64(seed.wrapping_add(0xD1FF));
    let mut diffs = Vec::with_capacity(n_boot);
    let (mut ap, mut an, mut bp, mut bn) =
        (vec![0.0; np], vec![0.0; nn], vec![0.0; np], vec![0.0; nn]);
    for _ in 0..n_boot {
        for i in 0..np {
            let j = rng.below(np);
            ap[i] = a_pos[j];
            bp[i] = b_pos[j];
        }
        for i in 0..nn {
            let j = rng.below(nn);
            an[i] = a_neg[j];
            bn[i] = b_neg[j];
        }
        diffs.push(auc(&ap, &an) - auc(&bp, &bn));
    }
    percentiles(diffs, 0.025, 0.975)
}

/// Wilson score 95% CI for a binomial proportion `k/n` (a closed-form interval, correct
/// even at the `k = n` / `k = 0` boundaries where a normal approximation degenerates).
pub fn wilson_ci(k: usize, n: usize) -> (f64, f64) {
    if n == 0 || k > n {
        return (f64::NAN, f64::NAN);
    }
    let z = 1.959_964_f64;
    let nf = n as f64;
    let p = k as f64 / nf;
    let z2 = z * z;
    let denom = 1.0 + z2 / nf;
    let center = p + z2 / (2.0 * nf);
    let margin = z * (p * (1.0 - p) / nf + z2 / (4.0 * nf * nf)).sqrt();
    (
        ((center - margin) / denom).max(0.0),
        ((center + margin) / denom).min(1.0),
    )
}

/// A bootstrap-CI row for one detector's alarm-ranked ROC-AUC on the stealthy spoof.
#[derive(Debug, Clone)]
pub struct CiRow {
    /// Detector name.
    pub name: String,
    /// Point AUC.
    pub auc: f64,
    /// 95% CI lower / upper.
    pub lo: f64,
    pub hi: f64,
    /// Assessable attack and clean score counts used by this AUC.
    pub positive_n: usize,
    pub negative_n: usize,
}

/// Bootstrap 95% CIs for the three detectors' alarm-ranked ROC-AUC on the
/// **stealthy spoof** (the statistic reported by [`run`]), plus the paired corr−PID
/// AUC-difference CI. Correlation and PID are the pre-registered axis-0 component
/// studies; the fused detector remains all-axis. Returns
/// `(rows, (diff, diff_lo, diff_hi))`. Resamples the already-computed scores — no
/// re-simulation beyond the one score pass. Clean and attack arms use
/// domain-separated independent seeds; detector scores remain paired within each arm.
pub fn stealthy_ci_study(
    cfg: &EvalConfig,
    n_boot: usize,
) -> CoreResult<(Vec<CiRow>, (f64, f64, f64))> {
    validate_observation_work(cfg.trials, cfg.frames, 2)?;
    let pid_calls = cfg
        .trials
        .checked_mul(2)
        .ok_or(EvalConfigError::WorkOverflow {
            context: "CI study PID call count",
        })?;
    validate_full_pid_calls(cfg, pid_calls, "CI study PID quadratic fits")?;
    validate_bootstrap(n_boot)?;
    // Three single-detector AUC intervals plus two AUC evaluations inside
    // each paired difference resample.
    validate_bootstrap_work(cfg.trials, n_boot, 5)?;
    let (mut cb, mut sb) = (Vec::new(), Vec::new()); // baseline clean/stealthy
    let (mut cc, mut sc) = (Vec::new(), Vec::new()); // correlation
    let (mut cp, mut sp) = (Vec::new(), Vec::new()); // PID
    for t in 0..cfg.trials {
        let clean = build(Attack::Clean, cfg, attack_seed(cfg, t, Attack::Clean))?;
        let steal = build(Attack::Stealthy, cfg, attack_seed(cfg, t, Attack::Stealthy))?;
        let [clean_baseline, clean_corr, clean_pid] = component_evaluations(&clean)?;
        let [stealthy_baseline, stealthy_corr, stealthy_pid] = component_evaluations(&steal)?;
        cb.push(clean_baseline.require_score("baseline")?);
        sb.push(stealthy_baseline.require_score("baseline")?);
        cc.push(clean_corr.require_score("correlation")?);
        sc.push(stealthy_corr.require_score("correlation")?);
        cp.push(clean_pid.require_score("PID")?);
        sp.push(stealthy_pid.require_score("PID")?);
    }
    let seed = cfg.base_seed;
    let row = |name: &str, pos: &[f64], neg: &[f64]| {
        let (lo, hi) = auc_ci(pos, neg, n_boot, seed);
        CiRow {
            name: name.to_string(),
            auc: auc(pos, neg),
            lo,
            hi,
            positive_n: pos.len(),
            negative_n: neg.len(),
        }
    };
    let rows = vec![
        row("baseline (NIS χ²)", &sb, &cb),
        row("correlation axis 0", &sc, &cc),
        row("PID axis 0 (KSG-MI)", &sp, &cp),
    ];
    let diff = auc(&sc, &cc) - auc(&sp, &cp);
    let (dlo, dhi) = auc_diff_ci(&sc, &cc, &sp, &cp, n_boot, seed);
    Ok((rows, (diff, dlo, dhi)))
}

/// Format the bootstrap-CI study as a plain-text block.
pub fn format_ci(rows: &[CiRow], diff: (f64, f64, f64), n_boot: usize) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Bootstrap 95% CIs — stealthy spoof · alarm-ranked ROC-AUC · {n_boot} resamples\n\n"
    ));
    for r in rows {
        s.push_str(&format!(
            "{:<22} AUC {:.3}  [{:.3}, {:.3}]  n={}/{} (attack/clean)\n",
            r.name, r.auc, r.lo, r.hi, r.positive_n, r.negative_n,
        ));
    }
    let (d, lo, hi) = diff;
    let includes_zero = lo <= 0.0 && hi >= 0.0;
    s.push_str(&format!(
        "{:<22} ΔAUC {:+.3}  [{:+.3}, {:+.3}]  → {}\n",
        "corr − PID (paired)",
        d,
        lo,
        hi,
        if includes_zero {
            "CI includes 0: no difference detected at this sample size"
        } else {
            "pointwise CI excludes 0"
        }
    ));
    s
}

// ---------------------------------------------------------------------------
// Decoupling-strength sweep (the detection boundary)
// ---------------------------------------------------------------------------

/// One row of the decoupling-strength sweep.
#[derive(Debug, Clone)]
pub struct SweepRow {
    /// Decoupling strength `d ∈ [0,1]` (1 = full decouple / easiest, 0 = no attack).
    pub decoupling: f64,
    /// Correlation-default consistency-score AUC and its bootstrap 95% CI.
    pub corr_auc: f64,
    pub corr_ci: (f64, f64),
    /// PID consistency-score AUC and its bootstrap 95% CI.
    pub pid_auc: f64,
    pub pid_ci: (f64, f64),
    /// Pointwise paired-bootstrap 95% CI for the AUC difference `corr − PID`.
    /// A grid-wide superiority claim requires simultaneous-error control.
    pub diff_ci: (f64, f64),
}

/// Sweep the stealthy spoof's **decoupling strength** and report, for each `d`, the AUC of
/// the pre-registered axis-0 correlation and PID consistency scores (the shared
/// decoupling-depth score → this is
/// the like-for-like comparison) with bootstrap 95% CIs. Traces the *detection boundary*:
/// how weak a decoupling each detector can still resolve. The clean/null scores are shared
/// across all `d`. Since the spoof stays moment-matched at every `d`, the NIS baseline is
/// blind throughout, so only the two consistency scores are reported.
pub fn decoupling_sweep(
    cfg: &EvalConfig,
    decouplings: &[f64],
    n_boot: usize,
) -> CoreResult<Vec<SweepRow>> {
    validate_decouplings(decouplings)?;
    validate_bootstrap(n_boot)?;
    validate_grid_work(cfg, decouplings.len())?;
    validate_observation_work(cfg.trials, cfg.frames, decouplings.len().saturating_add(1))?;
    let pid_calls = decouplings
        .len()
        .checked_add(1)
        .and_then(|streams| streams.checked_mul(cfg.trials))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "sweep PID call count",
        })?;
    validate_full_pid_calls(cfg, pid_calls, "sweep PID quadratic fits")?;
    let intervals = decouplings.len().checked_mul(4).ok_or_else(|| {
        GaladrielError::InvalidConfig("sweep bootstrap work estimate overflowed".into())
    })?;
    validate_bootstrap_work(cfg.trials, n_boot, intervals)?;
    let (mut clean_c, mut clean_p) = (
        Vec::with_capacity(cfg.trials),
        Vec::with_capacity(cfg.trials),
    );
    for t in 0..cfg.trials {
        let clean = build(Attack::Clean, cfg, attack_seed(cfg, t, Attack::Clean))?;
        clean_c.push(corr_evidence(&clean)?.require_score("correlation")?);
        clean_p.push(pid_evidence(&clean)?.require_score("PID")?);
    }
    let spoof = StealthySpoof {
        target: Modality::Acoustic,
        start_frame: (cfg.frames as u64) / 3,
    };
    let mut rows = Vec::with_capacity(decouplings.len());
    for &d in decouplings {
        let (mut sc, mut sp) = (
            Vec::with_capacity(cfg.trials),
            Vec::with_capacity(cfg.trials),
        );
        for t in 0..cfg.trials {
            let scenario = scenario(cfg, attack_seed(cfg, t, Attack::Stealthy))?;
            let stream = generate_spoofed_partial(&scenario, spoof, d)?;
            sc.push(corr_evidence(&stream)?.require_score("correlation")?);
            sp.push(pid_evidence(&stream)?.require_score("PID")?);
        }
        rows.push(SweepRow {
            decoupling: d,
            corr_auc: auc(&sc, &clean_c),
            corr_ci: auc_ci(&sc, &clean_c, n_boot, cfg.base_seed),
            pid_auc: auc(&sp, &clean_p),
            pid_ci: auc_ci(&sp, &clean_p, n_boot, cfg.base_seed ^ 0xF),
            diff_ci: auc_diff_ci(&sc, &clean_c, &sp, &clean_p, n_boot, cfg.base_seed ^ 0xAB),
        });
    }
    Ok(rows)
}

/// Format the decoupling sweep as a plain-text table, with a data-driven verdict on
/// whether the two detectors' CIs overlap at every strength.
pub fn format_sweep(rows: &[SweepRow]) -> String {
    let mut s = String::new();
    s.push_str(
        "Decoupling-strength sweep — axis-0 AUC vs decoupling (the detection boundary)\n\
         d=1 full decouple (easiest) → d→0 weak decouple (hardest); corr retained ∝ √(1−d)\n\n",
    );
    s.push_str(&format!(
        "{:>5} | {:>21} | {:>21} | {:>18}\n",
        "d", "corr AUC [95% CI]", "PID AUC [95% CI]", "Δ(corr−PID) [95% CI]"
    ));
    s.push_str(&format!("{}\n", "-".repeat(74)));
    for r in rows {
        s.push_str(&format!(
            "{:>5.2} | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}] | {:+.3} [{:+.3},{:+.3}]\n",
            r.decoupling,
            r.corr_auc,
            r.corr_ci.0,
            r.corr_ci.1,
            r.pid_auc,
            r.pid_ci.0,
            r.pid_ci.1,
            r.corr_auc - r.pid_auc,
            r.diff_ci.0,
            r.diff_ci.1,
        ));
    }
    let pointwise_band: Vec<String> = rows
        .iter()
        .filter(|r| r.diff_ci.0 > 0.0)
        .map(|r| format!("{:.2}", r.decoupling))
        .collect();
    if pointwise_band.is_empty() {
        s.push_str(
            "\nEvery pointwise paired ΔAUC interval includes 0. The sweep provides no evidence\n\
             of a difference at any sampled strength.\n",
        );
    } else {
        s.push_str(&format!(
            "\nExploratory pointwise 95% intervals exclude 0 at d ∈ {{{}}}. Because this scans\n\
             the grid without a simultaneous/max-statistic correction, it is not confirmatory\n\
             evidence that correlation strictly beats PID somewhere on the boundary.\n",
            pointwise_band.join(", ")
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// Colluding compromise (the honest-majority failure mode)
// ---------------------------------------------------------------------------

/// Result of the 2-of-3 colluding-compromise study.
#[derive(Debug, Clone)]
pub struct CollusionResult {
    /// Trials.
    pub trials: usize,
    /// Fraction of trials the correlation detector flagged the **honest** channel as decoupled.
    pub corr_accuses_honest: f64,
    /// Wilson 95% CI for `corr_accuses_honest`.
    pub corr_ci: (f64, f64),
    /// Fraction the PID detector flagged the **honest** channel.
    pub pid_accuses_honest: f64,
    /// Wilson 95% CI for `pid_accuses_honest`.
    pub pid_ci: (f64, f64),
    /// Fraction the PID detector flagged any channel.
    pub pid_fires: f64,
    /// Fraction the PID detector explicitly returned insufficient evidence.
    pub pid_insufficient: f64,
    /// Fraction the correlation detector flagged **any** channel (it fires — at the wrong one).
    pub corr_fires: f64,
}

/// The axis-0 colluding-compromise study: two channels (radar + acoustic) jointly spoof onto a
/// **shared** phantom (so they mutually corroborate), while visual stays honest. Measures how
/// often each detector flags the *honest* channel — the mis-attribution a colluding majority
/// forces. This is the honest-majority assumption failing: with the liars in the majority the
/// "consensus" is theirs, and the honest minority is the one that looks decoupled.
pub fn collusion_study(cfg: &EvalConfig, n: usize) -> CoreResult<CollusionResult> {
    validate_trials(n)?;
    validate_observation_work(n, cfg.frames, 1)?;
    validate_full_pid_calls(cfg, n, "collusion PID quadratic fits")?;
    let honest = Modality::Visual;
    let colluders = [Modality::Radar, Modality::Acoustic];
    let start = (cfg.frames as u64) / 3;
    let pid_config = pid_research_config()?;
    let (mut c_acc, mut p_acc, mut c_fire, mut p_fire, mut p_insufficient) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    for t in 0..n {
        let s = scenario(cfg, cfg.base_seed.wrapping_add(t as u64))?;
        let stream = generate_collusion(&s, &colluders, start)?;
        let chans = scalar_channels(&stream, &MODALITIES, 0)?;

        let cr = correlation::analyze(&chans, &CorrConfig::standalone_advisory_v0_9()?)?;
        if cr
            .channels()
            .iter()
            .any(|c| c.modality() == honest && c.decoupled())
        {
            c_acc += 1;
        }
        if cr.channels().iter().any(|c| c.decoupled()) {
            c_fire += 1;
        }

        let pr = analyze(&chans, &pid_config)?;
        match pr.verdict() {
            PidVerdict::Decoupled(modalities) => {
                p_fire += 1;
                p_acc += usize::from(modalities.contains(&honest));
            }
            PidVerdict::InsufficientEvidence => p_insufficient += 1,
            PidVerdict::Nominal => {}
        }
    }
    let nf = n as f64;
    Ok(CollusionResult {
        trials: n,
        corr_accuses_honest: c_acc as f64 / nf,
        corr_ci: wilson_ci(c_acc, n),
        pid_accuses_honest: p_acc as f64 / nf,
        pid_ci: wilson_ci(p_acc, n),
        pid_fires: p_fire as f64 / nf,
        pid_insufficient: p_insufficient as f64 / nf,
        corr_fires: c_fire as f64 / nf,
    })
}

/// Format the colluding-compromise study (mis-attribution rates with Wilson 95% CIs).
pub fn format_collusion(r: &CollusionResult) -> String {
    format!(
        "Colluding compromise axis 0 (2 of 3) — the honest-majority assumption FAILS ({} trials)\n\
         radar + acoustic share a phantom (mutually corroborate); visual is honest.\n\n\
         correlation flags the HONEST channel: {:.3} [{:.3},{:.3}]   (fires at all: {:.3})\n\
         PID         flags the HONEST channel: {:.3} [{:.3},{:.3}]   (fires: {:.3}; insufficient: {:.3})\n\n\
         With a colluding majority the 'consensus' is the liars' — the honest minority\n\
         decouples from it and is (mis-)accused. Cross-sensor majority attribution assumes an\n\
         honest majority. PID insufficiency is fail-closed abstention, not evidence that this\n\
         structural assumption has been escaped.\n",
        r.trials,
        r.corr_accuses_honest,
        r.corr_ci.0,
        r.corr_ci.1,
        r.corr_fires,
        r.pid_accuses_honest,
        r.pid_ci.0,
        r.pid_ci.1,
        r.pid_fires,
        r.pid_insufficient,
    )
}

// ---------------------------------------------------------------------------
// Adaptive (threshold-hugging) adversary
// ---------------------------------------------------------------------------

/// One row of the adaptive-adversary sweep: operating-point **detection rate** (the
/// fraction of attack scores exceeding the independently calibrated threshold) at
/// decoupling `d`. These are axis-0 component scores, distinct from the detectors'
/// built-in gates and from the threshold-free AUC.
#[derive(Debug, Clone)]
pub struct AdaptiveRow {
    /// Decoupling strength.
    pub decoupling: f64,
    /// Correlation axis-0 score-threshold detection proportion at `d`.
    pub corr_detect: f64,
    /// PID axis-0 score-threshold detection proportion at `d`.
    pub pid_detect: f64,
}

/// A binomial rate and its Wilson 95% interval.
#[derive(Debug, Clone, Copy)]
pub struct RateInterval {
    /// Observed rate on the fixed denominator.
    pub rate: f64,
    /// Wilson 95% confidence interval.
    pub ci: (f64, f64),
}

/// Adaptive score-threshold study with independent clean calibration and holdout arms.
#[derive(Debug, Clone)]
pub struct AdaptiveStudy {
    /// Detection proportions across the requested decoupling grid.
    pub rows: Vec<AdaptiveRow>,
    /// Requested upper-tail clean quantile used to fit each threshold.
    pub target_far: f64,
    /// Number of clean trials used only for threshold calibration.
    pub calibration_trials: usize,
    /// Number of independently seeded clean trials used only to estimate holdout FAR.
    pub holdout_trials: usize,
    /// Correlation axis-0 observed holdout FAR and Wilson interval.
    pub corr_holdout_far: RateInterval,
    /// PID axis-0 observed holdout FAR and Wilson interval.
    pub pid_holdout_far: RateInterval,
}

fn quantile(sorted_scores: &[f64], q: f64) -> f64 {
    if sorted_scores.is_empty() {
        return f64::NAN;
    }
    let idx =
        ((q * (sorted_scores.len() as f64 - 1.0)).round() as usize).min(sorted_scores.len() - 1);
    sorted_scores[idx]
}

/// Sweep decoupling strength and report each axis-0 component's detection rate at a
/// separately fitted target clean upper-tail quantile `far`. Calibration and clean
/// holdout streams use disjoint deterministic seed domains. The returned independent
/// holdout FARs and Wilson intervals show the operating points actually observed; a
/// finite calibration sample does not guarantee that either realized FAR equals `far`.
/// A threshold-hugging adversary injects the largest `d` that stays below the gate; the
/// *evasion ceiling* ([`evasion_ceiling`]) is the largest `d` a detector still misses
/// (detection ≤ τ). A lower ceiling indicates less evasion on this finite synthetic grid;
/// it is not a worst-case bound or a matched-realized-FAR comparison.
pub fn adaptive_adversary(
    cfg: &EvalConfig,
    decouplings: &[f64],
    far: f64,
) -> CoreResult<AdaptiveStudy> {
    validate_decouplings(decouplings)?;
    validate_grid_work(cfg, decouplings.len())?;
    validate_observation_work(cfg.trials, cfg.frames, decouplings.len().saturating_add(2))?;
    let pid_calls = decouplings
        .len()
        .checked_add(2)
        .and_then(|streams| streams.checked_mul(cfg.trials))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "adaptive PID call count",
        })?;
    validate_full_pid_calls(cfg, pid_calls, "adaptive PID quadratic fits")?;
    if !far.is_finite() || far <= 0.0 || far >= 1.0 {
        return Err(GaladrielError::InvalidConfig(
            "target clean upper-tail quantile must be finite and in (0, 1)".into(),
        ));
    }
    let spoof = StealthySpoof {
        target: Modality::Acoustic,
        start_frame: (cfg.frames as u64) / 3,
    };
    // Calibration and holdout are deliberately separate data arms. Reusing the
    // fitted sample would report a tautological in-sample operating point.
    let (mut cc, mut cp) = (
        Vec::with_capacity(cfg.trials),
        Vec::with_capacity(cfg.trials),
    );
    for t in 0..cfg.trials {
        let clean = build(
            Attack::Clean,
            cfg,
            adaptive_clean_seed(cfg, t, AdaptiveCleanArm::Calibration),
        )?;
        cc.push(corr_evidence(&clean)?.require_score("correlation")?);
        cp.push(pid_evidence(&clean)?.require_score("PID")?);
    }
    cc.sort_by(f64::total_cmp);
    cp.sort_by(f64::total_cmp);
    let corr_thresh = quantile(&cc, 1.0 - far);
    let pid_thresh = quantile(&cp, 1.0 - far);

    let (mut corr_holdout_alarms, mut pid_holdout_alarms) = (0usize, 0usize);
    for t in 0..cfg.trials {
        let clean = build(
            Attack::Clean,
            cfg,
            adaptive_clean_seed(cfg, t, AdaptiveCleanArm::Holdout),
        )?;
        corr_holdout_alarms +=
            usize::from(corr_evidence(&clean)?.require_score("correlation")? > corr_thresh);
        pid_holdout_alarms += usize::from(pid_evidence(&clean)?.require_score("PID")? > pid_thresh);
    }

    let mut rows = Vec::with_capacity(decouplings.len());
    for &d in decouplings {
        let (mut cd, mut pd) = (0usize, 0usize);
        for t in 0..cfg.trials {
            let scenario = scenario(cfg, attack_seed(cfg, t, Attack::Stealthy))?;
            let stream = generate_spoofed_partial(&scenario, spoof, d)?;
            if corr_evidence(&stream)?.require_score("correlation")? > corr_thresh {
                cd += 1;
            }
            if pid_evidence(&stream)?.require_score("PID")? > pid_thresh {
                pd += 1;
            }
        }
        let nf = cfg.trials as f64;
        rows.push(AdaptiveRow {
            decoupling: d,
            corr_detect: cd as f64 / nf,
            pid_detect: pd as f64 / nf,
        });
    }
    let trials = cfg.trials as f64;
    Ok(AdaptiveStudy {
        rows,
        target_far: far,
        calibration_trials: cfg.trials,
        holdout_trials: cfg.trials,
        corr_holdout_far: RateInterval {
            rate: corr_holdout_alarms as f64 / trials,
            ci: wilson_ci(corr_holdout_alarms, cfg.trials),
        },
        pid_holdout_far: RateInterval {
            rate: pid_holdout_alarms as f64 / trials,
            ci: wilson_ci(pid_holdout_alarms, cfg.trials),
        },
    })
}

/// The evasion ceiling: the largest decoupling a detector still misses (detection ≤ `tau`) —
/// i.e. the most an adaptive adversary can inject undetected. `0.0` if even the weakest
/// decoupling in the grid is caught.
pub fn evasion_ceiling(
    rows: &[AdaptiveRow],
    detect: impl Fn(&AdaptiveRow) -> f64,
    tau: f64,
) -> f64 {
    rows.iter()
        .filter(|r| detect(r) <= tau)
        .map(|r| r.decoupling)
        .fold(0.0, f64::max)
}

/// Format the adaptive-adversary study, independent holdout FARs, and sampled ceilings.
pub fn format_adaptive(study: &AdaptiveStudy, tau: f64) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Adaptive axis-0 score sweep — detection rate vs decoupling at target clean upper-tail {:.3}\n\
         thresholds fitted on {} clean trials; FAR evaluated on {} independently seeded clean trials\n\
         holdout FAR: corr {:.3} [{:.3},{:.3}] · PID {:.3} [{:.3},{:.3}] (Wilson 95%)\n\
         sampled-grid ceiling uses detection ≤ {tau:.2}\n\n",
        study.target_far,
        study.calibration_trials,
        study.holdout_trials,
        study.corr_holdout_far.rate,
        study.corr_holdout_far.ci.0,
        study.corr_holdout_far.ci.1,
        study.pid_holdout_far.rate,
        study.pid_holdout_far.ci.0,
        study.pid_holdout_far.ci.1,
    ));
    s.push_str(&format!(
        "{:>5} | {:>12} | {:>12}\n",
        "d", "corr detect", "PID detect"
    ));
    s.push_str(&format!("{}\n", "-".repeat(35)));
    for r in &study.rows {
        s.push_str(&format!(
            "{:>5.2} | {:>12.3} | {:>12.3}\n",
            r.decoupling, r.corr_detect, r.pid_detect
        ));
    }
    let corr_ceil = evasion_ceiling(&study.rows, |r| r.corr_detect, tau);
    let pid_ceil = evasion_ceiling(&study.rows, |r| r.pid_detect, tau);
    s.push_str(&format!(
        "\nObserved sampled-grid ceiling: correlation {corr_ceil:.2}   PID {pid_ceil:.2}\n"
    ));
    s.push_str(
        "Target quantiles need not yield identical realized holdout FARs. This descriptive finite\n\
         grid is not a worst-case evasion bound or an equivalence/superiority result.\n",
    );
    s
}

// ---------------------------------------------------------------------------
// Non-stationary false-alarm rate (a benign maneuvering target)
// ---------------------------------------------------------------------------

/// One row of the maneuver false-alarm study: the fraction of **honest maneuvering**
/// trials where the consistency detector flags a decoupling (a false positive), at a given
/// per-channel lag. Isolated from NIS — this is the pure cross-sensor consistency FAR.
#[derive(Debug, Clone)]
pub struct ManeuverRow {
    /// Per-channel lag step (0 = a synchronized maneuver; larger = more heterogeneous).
    pub lag_step: u64,
    /// Correlation-default false-decoupling rate under the maneuver.
    pub corr_far: f64,
    /// PID false-decoupling rate under the maneuver.
    pub pid_far: f64,
}

/// Measure the axis-0 consistency components' **false-alarm rate under a benign maneuver** (no
/// spoof), sweeping the per-channel lag. A synchronized maneuver (`lag_step = 0`) keeps
/// channels correlated and should not trip the consistency check. Heterogeneous lags are
/// measured as a possible false-positive source rather than assumed to cross a detector
/// threshold. We count a **decoupling** flag (not the broad NIS-degradation evidence a
/// coherent maneuver legitimately raises), isolating the cross-sensor false positive.
pub fn maneuver_far(
    cfg: &EvalConfig,
    lag_steps: &[u64],
    magnitude: f64,
    duration: u64,
) -> CoreResult<Vec<ManeuverRow>> {
    validate_maneuver_inputs(cfg, lag_steps, magnitude, duration)?;
    validate_grid_work(cfg, lag_steps.len())?;
    let pid_calls =
        lag_steps
            .len()
            .checked_mul(cfg.trials)
            .ok_or(EvalConfigError::WorkOverflow {
                context: "maneuver PID call count",
            })?;
    validate_full_pid_calls(cfg, pid_calls, "maneuver PID quadratic fits")?;
    let start = (cfg.frames as u64) / 3;
    let pid_config = pid_research_config()?;
    let mut rows = Vec::with_capacity(lag_steps.len());
    for &lag_step in lag_steps {
        let (mut cf, mut pf) = (0usize, 0usize);
        for t in 0..cfg.trials {
            let scenario = scenario(cfg, cfg.base_seed.wrapping_add(t as u64))?;
            let mut stream = generate(&scenario)?;
            inject(
                &mut stream,
                &Maneuver {
                    start_frame: start,
                    duration,
                    magnitude,
                    lag_step,
                },
            )?;
            let channels = scalar_channels(&stream, &MODALITIES, 0)?;
            if correlation::analyze(&channels, &CorrConfig::standalone_advisory_v0_9()?)?
                .channels()
                .iter()
                .any(|channel| channel.decoupled())
            {
                cf += 1;
            }
            if analyze(&channels, &pid_config)?
                .channels()
                .iter()
                .any(|channel| channel.is_decoupled())
            {
                pf += 1;
            }
        }
        let nf = cfg.trials as f64;
        rows.push(ManeuverRow {
            lag_step,
            corr_far: cf as f64 / nf,
            pid_far: pf as f64 / nf,
        });
    }
    Ok(rows)
}

/// Format the maneuver false-alarm study.
pub fn format_maneuver(rows: &[ManeuverRow], magnitude: f64, duration: u64) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Non-stationary FAR — axis 0 · a BENIGN {magnitude:.0}σ maneuver over {duration} frames, per-channel lag\n\
         consistency false-decoupling rate on honest maneuvering streams (isolated from broad NIS degradation)\n\n"
    ));
    s.push_str(&format!(
        "{:>8} | {:>11} | {:>11}\n",
        "lag_step", "corr FAR", "PID FAR"
    ));
    s.push_str(&format!("{}\n", "-".repeat(36)));
    for r in rows {
        s.push_str(&format!(
            "{:>8} | {:>11.3} | {:>11.3}\n",
            r.lag_step, r.corr_far, r.pid_far
        ));
    }
    if let Some(r0) = rows.iter().find(|r| r.lag_step == 0) {
        s.push_str(&format!(
            "\nObserved synchronized (lag 0) false-decoupling rates: correlation {:.3}, PID {:.3}.\n",
            r0.corr_far, r0.pid_far
        ));
        s.push_str(
            "Rows are descriptive for this maneuver model and grid. Relabeling a fused alarm as\n\
             degradation does not eliminate the operational cost of a benign false alarm.\n",
        );
    }
    s
}

// ---------------------------------------------------------------------------
// Modeled attacker impact — fused-innovation perturbation
// ---------------------------------------------------------------------------

/// The **fused innovation** per frame under the simplest sound fusion: the inverse-variance
/// weighted mean of the channels' attested common projection (axis 0). For the
/// equal-variance simulator this is the plain mean — a static model of the common
/// deviation the tracker acts on. Native modality innovations are not substituted.
fn fused_innovation(stream: &[PidObservation]) -> Vec<f64> {
    let n = MODALITIES.len();
    stream
        .chunks(n)
        .map(|frame| {
            let (sum, cnt) = frame
                .iter()
                .filter_map(|observation| {
                    observation
                        .consistency_projection()
                        .map(|projection| projection.values()[0])
                })
                .fold((0.0, 0usize), |(s, c), v| (s + v, c + 1));
            if cnt == 0 {
                0.0
            } else {
                sum / cnt as f64
            }
        })
        .collect()
}

/// One row of the attacker-impact study: at decoupling `d`, the RMS perturbation
/// (σ units) induced in a static fused innovation, alongside the detection rate.
#[derive(Debug, Clone)]
pub struct AttackerGainRow {
    /// Decoupling strength.
    pub decoupling: f64,
    /// RMS perturbation of the fused innovation over the attack window (σ units).
    /// The modeled phantom is zero-mean, so this is not a directional state bias.
    pub fused_perturbation_rms: f64,
    /// Correlation-default detection rate (matched to the default operating point).
    pub detect_rate: f64,
}

/// Measure modeled fused-innovation perturbation: for each decoupling `d`, the
/// RMS difference from the same-seed clean stream and how often correlation flags
/// it. The zero-mean phantom does not model an attacker-chosen directional bias or
/// accumulated state-estimation error.
pub fn attacker_gain(cfg: &EvalConfig, decouplings: &[f64]) -> CoreResult<Vec<AttackerGainRow>> {
    validate_decouplings(decouplings)?;
    validate_grid_work(cfg, decouplings.len())?;
    let streams = decouplings.len().checked_mul(2).ok_or_else(|| {
        GaladrielError::InvalidConfig("attacker-study work estimate overflowed".into())
    })?;
    validate_observation_work(cfg.trials, cfg.frames, streams)?;
    let onset = cfg.frames / 3;
    let spoof = StealthySpoof {
        target: Modality::Acoustic,
        start_frame: onset as u64,
    };
    let mut rows = Vec::with_capacity(decouplings.len());
    for &d in decouplings {
        let (mut bias_sq, mut count) = (0.0_f64, 0usize);
        let mut detect = 0usize;
        for t in 0..cfg.trials {
            let scenario = scenario(cfg, cfg.base_seed.wrapping_add(t as u64))?;
            let clean = generate(&scenario)?;
            let spoofed = generate_spoofed_partial(&scenario, spoof, d)?;
            let (clean_fused, spoofed_fused) =
                (fused_innovation(&clean), fused_innovation(&spoofed));
            for frame in onset..clean_fused.len().min(spoofed_fused.len()) {
                let bias = (spoofed_fused[frame] - clean_fused[frame]) / cfg.sigma;
                bias_sq += bias * bias;
                count += 1;
            }
            if corr_evidence(&spoofed)?.alarm == Some(true) {
                detect += 1;
            }
        }
        rows.push(AttackerGainRow {
            decoupling: d,
            fused_perturbation_rms: if count == 0 {
                0.0
            } else {
                (bias_sq / count as f64).sqrt()
            },
            detect_rate: detect as f64 / cfg.trials as f64,
        });
    }
    Ok(rows)
}

/// Format the modeled perturbation study.
pub fn format_attacker_gain(rows: &[AttackerGainRow], detect_tol: f64) -> String {
    let mut s = String::new();
    s.push_str(
        "Modeled impact — fused-innovation RMS perturbation vs detection (static equal-variance\n\
         fusion; perturbation in σ units; zero-mean phantom, not directional bias).\n\n",
    );
    s.push_str(&format!(
        "{:>5} | {:>16} | {:>12}\n",
        "d", "fused RMS (σ)", "corr detect"
    ));
    s.push_str(&format!("{}\n", "-".repeat(40)));
    for r in rows {
        s.push_str(&format!(
            "{:>5.2} | {:>16.3} | {:>12.3}\n",
            r.decoupling, r.fused_perturbation_rms, r.detect_rate
        ));
    }
    // Largest sampled perturbation at or below the detection tolerance.
    let undetected = rows
        .iter()
        .filter(|r| r.detect_rate <= detect_tol)
        .map(|r| r.fused_perturbation_rms)
        .fold(0.0_f64, f64::max);
    let detected_min = rows
        .iter()
        .filter(|r| r.detect_rate > detect_tol)
        .map(|r| r.fused_perturbation_rms)
        .fold(f64::INFINITY, f64::min);
    s.push_str(&format!(
        "\nLargest sampled RMS perturbation with detection ≤ {detect_tol:.2}: {undetected:.3} σ.\n\
         Smallest sampled RMS perturbation above that detection tolerance: {:.3} σ.\n\
         These are descriptive grid results, not an operational safety bound.\n",
        if detected_min.is_finite() {
            detected_min
        } else {
            undetected
        }
    ));
    s
}

/// Per-attack metrics for both detectors and their fusion.
///
/// Standalone correlation and PID fields are pre-registered projection-axis-0
/// component metrics; fused fields evaluate every attested projection axis.
#[derive(Debug, Clone)]
pub struct AttackMetrics {
    /// Which regime.
    pub attack: Attack,
    /// Baseline detection rate.
    pub baseline_rate: f64,
    /// Signed-correlation axis-0 consistency detection rate.
    pub corr_rate: f64,
    /// PID axis-0 detection rate.
    pub pid_rate: f64,
    /// Full fused (baseline ⊕ signed correlation ⊕ PID) detection rate.
    pub fused_rate: f64,
    /// Wilson 95% intervals for the four detection rates in the same order.
    pub detection_ci: FourDetectorIntervals,
    /// Explicit insufficient-evidence rates on the fixed trial denominator
    /// (baseline, signed correlation, PID, fused).
    pub insufficient_rate: (f64, f64, f64, f64),
    /// Fraction of trials contributing a continuous AUC score (baseline,
    /// signed correlation, PID).
    pub score_availability: (f64, f64, f64),
    /// Baseline ROC-AUC vs clean.
    pub baseline_auc: f64,
    /// Signed-correlation axis-0 component ROC-AUC vs clean.
    pub corr_auc: f64,
    /// PID axis-0 ROC-AUC vs clean.
    pub pid_auc: f64,
}

/// Confidence intervals ordered as baseline, correlation axis 0, PID axis 0, and fused.
pub type FourDetectorIntervals = ((f64, f64), (f64, f64), (f64, f64), (f64, f64));

/// Full evaluation results.
#[derive(Debug, Clone)]
pub struct EvalResults {
    /// The config used.
    pub cfg: EvalConfig,
    /// Baseline false-alarm rate (on clean).
    pub baseline_far: f64,
    /// Correlation axis-0 component false-alarm rate (on clean).
    pub corr_far: f64,
    /// PID axis-0 component false-alarm rate (on clean).
    pub pid_far: f64,
    /// Fused false-alarm rate (on clean).
    pub fused_far: f64,
    /// Wilson 95% intervals for the four clean false-alarm rates in the same order.
    pub far_ci: FourDetectorIntervals,
    /// Explicit insufficient-evidence rates on clean trials (baseline,
    /// signed correlation, PID, fused).
    pub clean_insufficient_rate: (f64, f64, f64, f64),
    /// Fraction of clean trials contributing a continuous AUC score (baseline,
    /// signed correlation, PID).
    pub clean_score_availability: (f64, f64, f64),
    /// Metrics for the three attack regimes.
    pub per_attack: Vec<AttackMetrics>,
}

/// Run the Monte-Carlo evaluation.
pub fn run(cfg: &EvalConfig) -> CoreResult<EvalResults> {
    validate_observation_work(cfg.trials, cfg.frames, Attack::ALL.len())?;
    let pid_calls = cfg
        .trials
        .checked_mul(Attack::ALL.len())
        .and_then(|calls| calls.checked_mul(1 + EVAL_PROJECTION_AXES))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "main evaluation PID call count",
        })?;
    validate_full_pid_calls(cfg, pid_calls, "main evaluation PID quadratic fits")?;
    let mut b_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut c_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut p_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut b_alarms: HashMap<Attack, usize> = HashMap::new();
    let mut c_alarms: HashMap<Attack, usize> = HashMap::new();
    let mut p_alarms: HashMap<Attack, usize> = HashMap::new();
    let mut f_alarms: HashMap<Attack, usize> = HashMap::new();
    let mut b_insufficient: HashMap<Attack, usize> = HashMap::new();
    let mut c_insufficient: HashMap<Attack, usize> = HashMap::new();
    let mut p_insufficient: HashMap<Attack, usize> = HashMap::new();
    let mut f_insufficient: HashMap<Attack, usize> = HashMap::new();

    for &attack in &Attack::ALL {
        let mut bs = Vec::with_capacity(cfg.trials);
        let mut cs = Vec::with_capacity(cfg.trials);
        let mut ps = Vec::with_capacity(cfg.trials);
        let (mut ba, mut ca, mut pa, mut fa) = (0usize, 0usize, 0usize, 0usize);
        let (mut bi, mut ci, mut pi, mut fi) = (0usize, 0usize, 0usize, 0usize);
        for t in 0..cfg.trials {
            let stream = build(attack, cfg, attack_seed(cfg, t, attack))?;
            let [b, c, p] = component_evaluations(&stream)?;
            if let Some(score) = b.score {
                bs.push(score);
            }
            if let Some(alarm) = b.alarm {
                ba += usize::from(alarm);
            } else {
                bi += 1;
            }
            if let Some(score) = c.score {
                cs.push(score);
            }
            if let Some(alarm) = c.alarm {
                ca += usize::from(alarm);
            } else {
                ci += 1;
            }
            if let Some(score) = p.score {
                ps.push(score);
            }
            if let Some(alarm) = p.alarm {
                pa += usize::from(alarm);
            } else {
                pi += 1;
            }
            match fused_eval(&stream)? {
                Some(alarm) => fa += usize::from(alarm),
                None => fi += 1,
            }
        }
        b_scores.insert(attack, bs);
        c_scores.insert(attack, cs);
        p_scores.insert(attack, ps);
        b_alarms.insert(attack, ba);
        c_alarms.insert(attack, ca);
        p_alarms.insert(attack, pa);
        f_alarms.insert(attack, fa);
        b_insufficient.insert(attack, bi);
        c_insufficient.insert(attack, ci);
        p_insufficient.insert(attack, pi);
        f_insufficient.insert(attack, fi);
    }

    let n = cfg.trials as f64;
    let clean_b = &b_scores[&Attack::Clean];
    let clean_c = &c_scores[&Attack::Clean];
    let clean_p = &p_scores[&Attack::Clean];
    let per_attack = Attack::ALL
        .iter()
        .filter(|a| **a != Attack::Clean)
        .map(|&a| AttackMetrics {
            attack: a,
            baseline_rate: b_alarms[&a] as f64 / n,
            corr_rate: c_alarms[&a] as f64 / n,
            pid_rate: p_alarms[&a] as f64 / n,
            fused_rate: f_alarms[&a] as f64 / n,
            detection_ci: (
                wilson_ci(b_alarms[&a], cfg.trials),
                wilson_ci(c_alarms[&a], cfg.trials),
                wilson_ci(p_alarms[&a], cfg.trials),
                wilson_ci(f_alarms[&a], cfg.trials),
            ),
            insufficient_rate: (
                b_insufficient[&a] as f64 / n,
                c_insufficient[&a] as f64 / n,
                p_insufficient[&a] as f64 / n,
                f_insufficient[&a] as f64 / n,
            ),
            score_availability: (
                b_scores[&a].len() as f64 / n,
                c_scores[&a].len() as f64 / n,
                p_scores[&a].len() as f64 / n,
            ),
            baseline_auc: auc(&b_scores[&a], clean_b),
            corr_auc: auc(&c_scores[&a], clean_c),
            pid_auc: auc(&p_scores[&a], clean_p),
        })
        .collect();

    Ok(EvalResults {
        baseline_far: b_alarms[&Attack::Clean] as f64 / n,
        corr_far: c_alarms[&Attack::Clean] as f64 / n,
        pid_far: p_alarms[&Attack::Clean] as f64 / n,
        fused_far: f_alarms[&Attack::Clean] as f64 / n,
        far_ci: (
            wilson_ci(b_alarms[&Attack::Clean], cfg.trials),
            wilson_ci(c_alarms[&Attack::Clean], cfg.trials),
            wilson_ci(p_alarms[&Attack::Clean], cfg.trials),
            wilson_ci(f_alarms[&Attack::Clean], cfg.trials),
        ),
        clean_insufficient_rate: (
            b_insufficient[&Attack::Clean] as f64 / n,
            c_insufficient[&Attack::Clean] as f64 / n,
            p_insufficient[&Attack::Clean] as f64 / n,
            f_insufficient[&Attack::Clean] as f64 / n,
        ),
        clean_score_availability: (
            clean_b.len() as f64 / n,
            clean_c.len() as f64 / n,
            clean_p.len() as f64 / n,
        ),
        per_attack,
        cfg: cfg.clone(),
    })
}

/// Format results as a plain-text report (suitable for a docs code block).
pub fn format_report(r: &EvalResults) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Galadriel evaluation — {} trials/regime · rho={} · frames={} · sigma={}\n",
        r.cfg.trials, r.cfg.rho, r.cfg.frames, r.cfg.sigma
    ));
    s.push_str(&format!(
        "False-alarm rate (clean):   baseline {:.3}   corr-ax0 {:.3}   PID-ax0 {:.3}   fused {:.3}\n\n",
        r.baseline_far, r.corr_far, r.pid_far, r.fused_far
    ));
    s.push_str(&format!(
        "Wilson 95% CI (clean):      [{:.3},{:.3}] [{:.3},{:.3}] [{:.3},{:.3}] [{:.3},{:.3}]\n\n",
        r.far_ci.0 .0,
        r.far_ci.0 .1,
        r.far_ci.1 .0,
        r.far_ci.1 .1,
        r.far_ci.2 .0,
        r.far_ci.2 .1,
        r.far_ci.3 .0,
        r.far_ci.3 .1,
    ));
    s.push_str(&format!(
        "Insufficient rate (clean):  baseline {:.3}   corr-ax0 {:.3}   PID-ax0 {:.3}   fused {:.3}\n\n",
        r.clean_insufficient_rate.0,
        r.clean_insufficient_rate.1,
        r.clean_insufficient_rate.2,
        r.clean_insufficient_rate.3,
    ));
    s.push_str(&format!(
        "AUC-score availability:     baseline {:.3}   corr-ax0 {:.3}   PID-ax0 {:.3}\n\n",
        r.clean_score_availability.0, r.clean_score_availability.1, r.clean_score_availability.2,
    ));
    s.push_str(&format!(
        "{:<28} | {:>8} | {:>8} | {:>7} | {:>9} | {:>8} | {:>8} | {:>7}\n",
        "regime", "base det", "corr det", "PID det", "fused det", "base AUC", "corr AUC", "PID AUC"
    ));
    s.push_str(&format!("{}\n", "-".repeat(104)));
    for m in &r.per_attack {
        s.push_str(&format!(
            "{:<28} | {:>8.3} | {:>8.3} | {:>7.3} | {:>9.3} | {:>8.3} | {:>8.3} | {:>7.3}\n",
            m.attack.label(),
            m.baseline_rate,
            m.corr_rate,
            m.pid_rate,
            m.fused_rate,
            m.baseline_auc,
            m.corr_auc,
            m.pid_auc,
        ));
        s.push_str(&format!(
            "  insufficient (base/corr/PID/fused): {:.3}/{:.3}/{:.3}/{:.3}\n",
            m.insufficient_rate.0,
            m.insufficient_rate.1,
            m.insufficient_rate.2,
            m.insufficient_rate.3,
        ));
        s.push_str(&format!(
            "  detection Wilson CIs: [{:.3},{:.3}] [{:.3},{:.3}] [{:.3},{:.3}] [{:.3},{:.3}]\n",
            m.detection_ci.0 .0,
            m.detection_ci.0 .1,
            m.detection_ci.1 .0,
            m.detection_ci.1 .1,
            m.detection_ci.2 .0,
            m.detection_ci.2 .1,
            m.detection_ci.3 .0,
            m.detection_ci.3 .1,
        ));
        s.push_str(&format!(
            "  score available (base/corr/PID): {:.3}/{:.3}/{:.3}\n",
            m.score_availability.0, m.score_availability.1, m.score_availability.2,
        ));
    }
    s.push_str(
        "\ncorr/PID standalone metrics = registered consistency-projection axis 0; fused = all axes.\n\
         corr = signed-correlation consistency component; PID = pairwise KSG-MI escalation.\n\
         Rates use all configured trials; insufficient-evidence rates are shown separately.\n\
         AUC alarm-ranks discrete alarms above non-alarms, then uses the continuous score.\n\
         AUC uses assessable scores only and may therefore have a smaller denominator.\n",
    );
    s
}

// ---------------------------------------------------------------------------
// Detection latency (time-to-detect)
// ---------------------------------------------------------------------------

/// Median time-to-detect per detector: frames from attack onset to the first alarm on a
/// growing prefix of the stream. A `None` TTD means the detector never alarmed within the
/// capture. `reach` is the fraction of all trials that alarmed after onset without
/// an earlier sampled false start; `false_start_rate` reports that distinct failure
/// mode instead of conflating it with a never-detected attack.
#[derive(Debug, Clone)]
pub struct AttackLatency {
    /// Which regime.
    pub attack: Attack,
    /// Median frames-to-detect for the NIS baseline.
    pub baseline_ttd: Option<f64>,
    /// Median frames-to-detect for the correlation axis-0 component.
    pub corr_ttd: Option<f64>,
    /// Median frames-to-detect for the PID axis-0 component.
    pub pid_ttd: Option<f64>,
    /// Fraction with a post-onset alarm and no sampled false start:
    /// (baseline, correlation axis 0, PID axis 0).
    pub reach: (f64, f64, f64),
    /// Fraction of trials with a sampled pre-onset alarm: (baseline,
    /// corr-default, PID).
    pub false_start_rate: (f64, f64, f64),
}

fn median(v: &mut [usize]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2] as f64
    } else {
        f64::from(u32::try_from(v[n / 2 - 1] + v[n / 2]).unwrap_or(u32::MAX)) / 2.0
    })
}

/// First alarm frame offset from `onset`, searching growing prefixes stepped by `step`
/// frames and always probing the complete capture once; `None` if the detector never
/// alarms within the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TtdOutcome {
    Detected(usize),
    FalseStart,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbePhase {
    PreOnset,
    PostOnset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TtdProbe {
    frames: usize,
    phase: ProbePhase,
}

fn push_unique_probe(probes: &mut Vec<TtdProbe>, frames: usize, phase: ProbePhase) {
    if probes.last().is_none_or(|probe| probe.frames != frames) {
        probes.push(TtdProbe { frames, phase });
    }
}

fn ttd_probe_schedule(frames: usize, onset: usize, step: usize) -> Vec<TtdProbe> {
    let step = step.max(1);
    let pre_onset_frames = onset.min(frames);
    let mut probes = Vec::new();
    if pre_onset_frames > 0 {
        let mut prefix = 1usize;
        loop {
            let probe = prefix.min(pre_onset_frames);
            push_unique_probe(&mut probes, probe, ProbePhase::PreOnset);
            if probe == pre_onset_frames {
                break;
            }
            prefix = prefix.saturating_add(step).min(pre_onset_frames);
        }
    }
    if onset < frames {
        let mut prefix = onset.saturating_add(1).max(1);
        while prefix <= frames {
            push_unique_probe(&mut probes, prefix, ProbePhase::PostOnset);
            prefix = prefix.saturating_add(step);
        }
        // A stepped schedule generally overshoots the capture boundary. Always
        // assess the complete capture once so a final-frame alarm is reachable.
        push_unique_probe(&mut probes, frames, ProbePhase::PostOnset);
    }
    probes
}

fn ttd(
    stream: &[PidObservation],
    onset: usize,
    step: usize,
    alarm: impl Fn(&[PidObservation]) -> CoreResult<bool>,
) -> CoreResult<TtdOutcome> {
    let n_mods = MODALITIES.len();
    let frames = stream.len() / n_mods;
    for probe in ttd_probe_schedule(frames, onset, step) {
        if alarm(&stream[..probe.frames * n_mods])? {
            return Ok(match probe.phase {
                // Any alarm at a pre-onset probe is a false start, not attack
                // detection. Exclude it from latency reach even if it clears.
                ProbePhase::PreOnset => TtdOutcome::FalseStart,
                ProbePhase::PostOnset => TtdOutcome::Detected(probe.frames - onset - 1),
            });
        }
    }
    Ok(TtdOutcome::Never)
}

fn validate_latency_work(
    cfg: &EvalConfig,
    trials: usize,
    step: usize,
) -> std::result::Result<(), EvalConfigError> {
    let probes = ttd_probe_schedule(cfg.frames, cfg.frames / 3, step).len();
    let observations = trials
        .checked_mul(Attack::ALL.len() - 1)
        .and_then(|work| work.checked_mul(3))
        .and_then(|work| work.checked_mul(probes))
        .and_then(|work| work.checked_mul(cfg.frames))
        .and_then(|work| work.checked_mul(MODALITIES.len()))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "latency prefix observations",
        })?;
    if observations > MAX_LATENCY_PREFIX_OBSERVATIONS {
        return Err(EvalConfigError::WorkLimit {
            context: "latency prefix observations",
            actual: observations as u128,
            maximum: MAX_LATENCY_PREFIX_OBSERVATIONS as u128,
        });
    }
    Ok(())
}

/// Measure detection latency for the three attack regimes over `trials` seeds, probing
/// prefixes every `step` frames and the final capture frame. Correlation and PID are
/// pre-registered to projection axis 0. Detectors that never fire yield `None`.
pub fn measure_latency(
    cfg: &EvalConfig,
    trials: usize,
    step: usize,
) -> CoreResult<Vec<AttackLatency>> {
    validate_trials(trials)?;
    if step == 0 || step > cfg.frames {
        return Err(EvalConfigError::InvalidLatencyStep.into());
    }
    validate_latency_work(cfg, trials, step)?;
    validate_pid_work_limit(
        latency_pid_work(cfg, trials, step)?,
        "latency PID quadratic fits",
    )?;
    let onset = cfg.frames / 3;
    let mut rows = Vec::with_capacity(Attack::ALL.len() - 1);
    for &attack in Attack::ALL
        .iter()
        .filter(|attack| **attack != Attack::Clean)
    {
        let (mut baseline_ttd, mut corr_ttd, mut pid_ttd) = (Vec::new(), Vec::new(), Vec::new());
        let (mut baseline_reach, mut corr_reach, mut pid_reach) = (0usize, 0usize, 0usize);
        let (mut baseline_false, mut corr_false, mut pid_false) = (0usize, 0usize, 0usize);
        for trial in 0..trials {
            let stream = build(attack, cfg, attack_seed(cfg, trial, attack))?;
            match ttd(&stream, onset, step, |prefix| {
                baseline_eval(prefix).map(|result| result.alarm == Some(true))
            })? {
                TtdOutcome::Detected(delay) => {
                    baseline_ttd.push(delay);
                    baseline_reach += 1;
                }
                TtdOutcome::FalseStart => baseline_false += 1,
                TtdOutcome::Never => {}
            }
            match ttd(&stream, onset, step, |prefix| {
                corr_evidence(prefix).map(|result| result.alarm == Some(true))
            })? {
                TtdOutcome::Detected(delay) => {
                    corr_ttd.push(delay);
                    corr_reach += 1;
                }
                TtdOutcome::FalseStart => corr_false += 1,
                TtdOutcome::Never => {}
            }
            match ttd(&stream, onset, step, |prefix| {
                pid_evidence(prefix).map(|result| result.alarm == Some(true))
            })? {
                TtdOutcome::Detected(delay) => {
                    pid_ttd.push(delay);
                    pid_reach += 1;
                }
                TtdOutcome::FalseStart => pid_false += 1,
                TtdOutcome::Never => {}
            }
        }
        let trial_count = trials as f64;
        rows.push(AttackLatency {
            attack,
            baseline_ttd: median(&mut baseline_ttd),
            corr_ttd: median(&mut corr_ttd),
            pid_ttd: median(&mut pid_ttd),
            reach: (
                baseline_reach as f64 / trial_count,
                corr_reach as f64 / trial_count,
                pid_reach as f64 / trial_count,
            ),
            false_start_rate: (
                baseline_false as f64 / trial_count,
                corr_false as f64 / trial_count,
                pid_false as f64 / trial_count,
            ),
        });
    }
    Ok(rows)
}

/// Format the latency study as a plain-text table (median frames + reach%).
pub fn format_latency(rows: &[AttackLatency], trials: usize, step: usize) -> String {
    let cell = |t: Option<f64>, reach: f64| match t {
        Some(v) => format!("{v:>4.0}f ({:>3.0}%)", reach * 100.0),
        None => format!("{:>5} ({:>3.0}%)", "—", reach * 100.0),
    };
    let mut s = String::new();
    s.push_str(&format!(
        "Detection latency — axis-0 consistency components · median frames from attack onset to first alarm\n\
         {trials} trials/regime · prefix step {step} frames · 100 ms/frame · '—' = no qualifying post-onset alarm\n\n"
    ));
    s.push_str(&format!(
        "{:<28} | {:>12} | {:>12} | {:>12}\n",
        "regime", "baseline", "corr default", "PID"
    ));
    s.push_str(&format!("{}\n", "-".repeat(74)));
    for r in rows {
        s.push_str(&format!(
            "{:<28} | {} | {} | {}\n",
            r.attack.label(),
            cell(r.baseline_ttd, r.reach.0),
            cell(r.corr_ttd, r.reach.1),
            cell(r.pid_ttd, r.reach.2),
        ));
        s.push_str(&format!(
            "  pre-onset false starts (base/corr/PID): {:.1}%/{:.1}%/{:.1}%\n",
            r.false_start_rate.0 * 100.0,
            r.false_start_rate.1 * 100.0,
            r.false_start_rate.2 * 100.0,
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mut update: impl FnMut(&mut EvalParams)) -> EvalConfig {
        let mut params = EvaluationResearchProfile::SyntheticV0_9.params();
        update(&mut params);
        EvalConfig::try_new(params).expect("test evaluation parameters must be valid")
    }

    fn suite_params() -> EvalSuiteParams {
        EvalSuiteParams {
            decouplings: vec![1.0, 0.6, 0.2],
            lag_steps: vec![0, 16],
            bootstrap_resamples: 200,
            latency_trials: MIN_INFERENCE_TRIALS,
            latency_step: 10,
        }
    }

    fn metrics(r: &EvalResults, a: Attack) -> AttackMetrics {
        r.per_attack
            .iter()
            .find(|m| m.attack == a)
            .cloned()
            .unwrap()
    }

    #[test]
    fn eval_config_rejects_every_scalar_boundary_with_typed_categories() {
        for trials in [0, MIN_INFERENCE_TRIALS - 1, 1_001, usize::MAX] {
            let mut params = EvaluationResearchProfile::SyntheticV0_9.params();
            params.trials = trials;
            assert!(matches!(
                EvalConfig::try_new(params),
                Err(EvalConfigError::TrialsOutOfRange { .. })
            ));
        }
        for frames in [0, 127, 10_001, usize::MAX] {
            let mut params = EvaluationResearchProfile::SyntheticV0_9.params();
            params.frames = frames;
            assert!(matches!(
                EvalConfig::try_new(params),
                Err(EvalConfigError::FramesOutOfRange)
            ));
        }
        for rho in [f64::NEG_INFINITY, -0.0, 0.0, 1.0, f64::INFINITY, f64::NAN] {
            let mut params = EvaluationResearchProfile::SyntheticV0_9.params();
            params.rho = rho;
            assert!(matches!(
                EvalConfig::try_new(params),
                Err(EvalConfigError::InvalidCorrelation)
            ));
        }
        for sigma in [
            f64::NEG_INFINITY,
            -1.0,
            0.0,
            f64::MIN_POSITIVE,
            f64::INFINITY,
            f64::NAN,
        ] {
            let mut params = EvaluationResearchProfile::SyntheticV0_9.params();
            params.sigma = sigma;
            assert!(matches!(
                EvalConfig::try_new(params),
                Err(EvalConfigError::InvalidSigma)
            ));
        }
        for spoof_bias in [
            f64::NEG_INFINITY,
            -1.0,
            0.0,
            f64::MAX,
            f64::INFINITY,
            f64::NAN,
        ] {
            let mut params = EvaluationResearchProfile::SyntheticV0_9.params();
            params.spoof_bias = spoof_bias;
            assert!(matches!(
                EvalConfig::try_new(params),
                Err(EvalConfigError::InvalidSpoofBias)
            ));
        }
        for jam_inflation in [
            f64::NEG_INFINITY,
            -1.0,
            0.0,
            1.0,
            f64::MAX,
            f64::INFINITY,
            f64::NAN,
        ] {
            let mut params = EvaluationResearchProfile::SyntheticV0_9.params();
            params.jam_inflation = jam_inflation;
            assert!(matches!(
                EvalConfig::try_new(params),
                Err(EvalConfigError::InvalidJamInflation)
            ));
        }
    }

    #[test]
    fn named_and_custom_eval_identities_are_deterministic_and_distinct() {
        let first = EvaluationResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named evaluation profile must be accepted");
        let second = EvaluationResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named evaluation profile must be accepted");
        let custom = EvalConfig::try_new(EvaluationResearchProfile::SyntheticV0_9.params())
            .expect("identical custom parameters must be accepted");

        assert_eq!(
            first.origin(),
            EvalConfigOrigin::Named(EvaluationResearchProfile::SyntheticV0_9)
        );
        assert_eq!(first.canonical_digest(), second.canonical_digest());
        assert_eq!(first.canonical_digest().len(), 64);
        assert_eq!(custom.origin(), EvalConfigOrigin::CustomResearch);
        assert_ne!(first.canonical_digest(), custom.canonical_digest());
    }

    #[test]
    fn suite_acceptance_rejects_duplicate_malformed_and_overflowing_grids() {
        let cfg = config(|params| params.trials = MIN_INFERENCE_TRIALS);

        let mut empty = suite_params();
        empty.decouplings.clear();
        assert!(matches!(
            EvalSuiteConfig::try_new(cfg.clone(), empty),
            Err(EvalConfigError::GridLength {
                grid: "decoupling",
                ..
            })
        ));

        let mut duplicate_zero = suite_params();
        duplicate_zero.decouplings = vec![0.0, -0.0];
        assert!(matches!(
            EvalSuiteConfig::try_new(cfg.clone(), duplicate_zero),
            Err(EvalConfigError::DuplicateGridValue {
                grid: "decoupling",
                index: 1
            })
        ));

        let mut nonfinite = suite_params();
        nonfinite.decouplings[1] = f64::NAN;
        assert!(matches!(
            EvalSuiteConfig::try_new(cfg.clone(), nonfinite),
            Err(EvalConfigError::InvalidDecoupling { index: 1 })
        ));

        let mut duplicate_lag = suite_params();
        duplicate_lag.lag_steps = vec![16, 16];
        assert!(matches!(
            EvalSuiteConfig::try_new(cfg.clone(), duplicate_lag),
            Err(EvalConfigError::DuplicateGridValue {
                grid: "maneuver lag",
                index: 1
            })
        ));

        let mut lag_overflow = suite_params();
        lag_overflow.lag_steps = vec![u64::MAX];
        assert!(matches!(
            EvalSuiteConfig::try_new(cfg.clone(), lag_overflow),
            Err(EvalConfigError::ManeuverLagOverflow { index: 0 })
        ));

        let mut censored_lag = suite_params();
        censored_lag.lag_steps = vec![64];
        assert!(matches!(
            EvalSuiteConfig::try_new(cfg.clone(), censored_lag),
            Err(EvalConfigError::ManeuverOutsideCapture {
                index: 0,
                required_end: 382,
                available_frames: 300,
            })
        ));

        let mut bootstrap = suite_params();
        bootstrap.bootstrap_resamples = 199;
        assert!(matches!(
            EvalSuiteConfig::try_new(cfg.clone(), bootstrap),
            Err(EvalConfigError::BootstrapOutOfRange)
        ));

        let mut latency = suite_params();
        latency.latency_step = 0;
        assert!(matches!(
            EvalSuiteConfig::try_new(cfg, latency),
            Err(EvalConfigError::InvalidLatencyStep)
        ));
    }

    #[test]
    fn accepted_suite_retains_exact_inputs_and_stable_identity() {
        let cfg = config(|params| params.trials = MIN_INFERENCE_TRIALS);
        let params = suite_params();
        let first = EvalSuiteConfig::try_new(cfg.clone(), params.clone())
            .expect("bounded suite must be accepted");
        let second =
            EvalSuiteConfig::try_new(cfg, params).expect("same bounded suite must be accepted");

        assert_eq!(first.decouplings(), [1.0, 0.6, 0.2]);
        assert_eq!(first.lag_steps(), [0, 16]);
        assert_eq!(first.bootstrap_resamples(), 200);
        assert_eq!(first.latency_trials(), MIN_INFERENCE_TRIALS);
        assert_eq!(first.latency_step(), 10);
        assert_eq!(first.canonical_digest(), second.canonical_digest());
        assert_eq!(first.canonical_digest().len(), 64);

        let mut positive_zero = suite_params();
        positive_zero.decouplings = vec![0.0, 0.6];
        let mut negative_zero = positive_zero.clone();
        negative_zero.decouplings[0] = -0.0;
        let positive_zero = EvalSuiteConfig::try_new(first.eval().clone(), positive_zero)
            .expect("positive-zero grid must be accepted");
        let negative_zero = EvalSuiteConfig::try_new(first.eval().clone(), negative_zero)
            .expect("negative-zero grid must be accepted");
        assert_eq!(negative_zero.decouplings()[0].to_bits(), 0.0_f64.to_bits());
        assert_eq!(
            negative_zero.canonical_digest(),
            positive_zero.canonical_digest()
        );
    }

    #[test]
    fn hypothesis_holds() {
        // Smaller trial count keeps the test fast but statistically clear.
        let r = run(&config(|params| params.trials = 40)).expect("valid evaluation");

        // Every detector is quiet on the null.
        assert!(r.baseline_far < 0.1, "baseline FAR {:.3}", r.baseline_far);
        assert!(r.corr_far < 0.1, "corr-default FAR {:.3}", r.corr_far);
        assert!(r.pid_far < 0.1, "PID FAR {:.3}", r.pid_far);
        assert!(r.fused_far < 0.1, "fused FAR {:.3}", r.fused_far);

        // The headline: the cross-sensor detectors catch the stealthy spoof the baseline
        // is blind to.
        let st = metrics(&r, Attack::Stealthy);
        assert!(
            st.pid_rate > 0.8,
            "PID stealthy detection {:.3}",
            st.pid_rate
        );
        assert!(
            st.baseline_rate < 0.2,
            "baseline stealthy detection {:.3}",
            st.baseline_rate
        );
        assert!(st.pid_auc > 0.85, "PID stealthy AUC {:.3}", st.pid_auc);
        assert!(
            st.baseline_auc < 0.75,
            "baseline stealthy AUC {:.3}",
            st.baseline_auc
        );

        // On this linear-Gaussian stealthy spoof the cheap axis-0 correlation component
        // is sufficient; this study does not establish a need for PID here.
        assert!(
            st.corr_rate > 0.8,
            "corr-default stealthy detection {:.3}",
            st.corr_rate
        );
        assert!(
            st.corr_auc > 0.85,
            "corr-default stealthy AUC {:.3}",
            st.corr_auc
        );

        // Complementarity: the baseline owns the magnitude attacks.
        let loud = metrics(&r, Attack::LoudSpoof);
        let jam = metrics(&r, Attack::Jam);
        assert!(
            loud.baseline_rate > 0.8,
            "baseline loud {:.3}",
            loud.baseline_rate
        );
        assert!(
            jam.baseline_rate > 0.8,
            "baseline jam {:.3}",
            jam.baseline_rate
        );

        // The fused detector covers all three attacks.
        for a in [Attack::LoudSpoof, Attack::Stealthy, Attack::Jam] {
            assert!(
                metrics(&r, a).fused_rate > 0.8,
                "{a:?} fused {:.3}",
                metrics(&r, a).fused_rate
            );
        }
    }

    #[test]
    fn auc_basics() {
        assert!((auc(&[1.0, 2.0, 3.0], &[0.0, 0.5]) - 1.0).abs() < 1e-9);
        assert!((auc(&[0.0], &[0.0]) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn ttd_probes_non_aligned_final_capture_frame_once() {
        let cfg = config(|params| {
            params.trials = MIN_INFERENCE_TRIALS;
            params.frames = 128;
        });
        let stream = build(Attack::Clean, &cfg, 7).expect("valid synthetic stream");
        let onset = cfg.frames / 3;
        let final_probes = std::cell::Cell::new(0usize);
        let outcome = ttd(&stream, onset, 6, |prefix| {
            if prefix.len() == stream.len() {
                final_probes.set(final_probes.get() + 1);
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .expect("valid TTD probe sequence");

        assert_eq!(
            (outcome, final_probes.get()),
            (TtdOutcome::Detected(cfg.frames - onset - 1), 1)
        );
    }

    #[test]
    fn latency_tracks_attack_ownership() {
        // Lean settings: enough trials for a stable median, small enough to stay fast.
        let cfg = config(|params| params.frames = 210);
        let rows = measure_latency(&cfg, 20, 6).expect("valid latency study");

        let st = rows.iter().find(|r| r.attack == Attack::Stealthy).unwrap();
        // The cross-sensor detectors detect the stealthy spoof at a finite latency…
        assert!(
            st.corr_ttd.is_some(),
            "corr should detect the stealthy spoof"
        );
        assert!(st.pid_ttd.is_some(), "PID should detect the stealthy spoof");
        assert!(st.reach.1 > 0.8, "corr reach on stealthy {:.2}", st.reach.1);
        assert!(st.reach.2 > 0.8, "PID reach on stealthy {:.2}", st.reach.2);

        // …while the magnitude baseline owns the loud spoof and never (mostly) the stealthy.
        let loud = rows.iter().find(|r| r.attack == Attack::LoudSpoof).unwrap();
        assert!(
            loud.baseline_ttd.is_some(),
            "baseline should detect the loud spoof"
        );
        assert!(
            loud.reach.0 > 0.8,
            "baseline reach on loud {:.2}",
            loud.reach.0
        );
    }

    #[test]
    fn bootstrap_cis_match_alarm_ranked_auc_and_beat_baseline() {
        let cfg = config(|params| params.trials = 80);
        let (rows, (diff, dlo, dhi)) = stealthy_ci_study(&cfg, 500).expect("valid bootstrap study");

        let corr = &rows[1];
        let pid = &rows[2];
        assert!(
            (diff - (corr.auc - pid.auc)).abs() < 1e-12 && dlo <= dhi,
            "paired ΔAUC {diff:.3} [{dlo:.3},{dhi:.3}] must match row AUCs"
        );

        // Both cross-sensor detectors' CIs sit well above the baseline's.
        let baseline = &rows[0];
        assert!(
            baseline.hi < corr.lo.min(pid.lo),
            "baseline CI [.,{:.3}] should not overlap corr/PID lower bounds {:.3}/{:.3}",
            baseline.hi,
            corr.lo,
            pid.lo,
        );
        // The baseline is not distinguishable from chance (its CI brackets 0.5).
        assert!(
            baseline.lo <= 0.5 && baseline.hi >= 0.45,
            "baseline AUC CI [{:.3},{:.3}] should be near chance",
            baseline.lo,
            baseline.hi
        );
    }

    #[test]
    fn component_auc_ranking_places_alarms_above_non_alarms() {
        let alarmed = alarm_rank_evidence(DetectorEvidence {
            alarm: Some(true),
            score: Some(0.0),
        });
        let quiet = alarm_rank_evidence(DetectorEvidence {
            alarm: Some(false),
            score: Some(1.0),
        });

        assert!(alarmed.score.expect("ranked alarm") > quiet.score.expect("ranked non-alarm"));
    }

    #[test]
    fn auc_ci_brackets_a_cleanly_separable_case() {
        let pos: Vec<f64> = (0..50).map(|i| 10.0 + i as f64).collect();
        let neg: Vec<f64> = (0..50).map(|i| i as f64 * 0.1).collect();
        let (lo, hi) = auc_ci(&pos, &neg, 500, 1);
        assert!(lo > 0.95 && hi <= 1.0, "CI [{lo:.3},{hi:.3}] near 1.0");
    }

    #[test]
    fn colluding_majority_inverts_the_detector_onto_the_honest_channel() {
        let cfg = config(|params| params.trials = 40);
        let r = collusion_study(&cfg, 40).expect("valid collusion study");
        // The detector fires (it is not silent)…
        assert!(
            r.corr_fires > 0.8,
            "correlation should fire under collusion {:.3}",
            r.corr_fires
        );
        // …but at the HONEST channel — the mis-attribution the honest-majority failure forces.
        assert!(
            r.corr_accuses_honest > 0.8,
            "correlation should mis-flag the honest channel {:.3}",
            r.corr_accuses_honest
        );
        // PID inherits the same structural failure (it is not a way out).
        assert!(
            r.pid_accuses_honest > 0.5,
            "PID should also mis-flag the honest channel {:.3} (fires {:.3}, insufficient {:.3})",
            r.pid_accuses_honest,
            r.pid_fires,
            r.pid_insufficient,
        );
    }

    #[test]
    fn decoupling_sweep_shows_correlation_dominates_the_boundary() {
        let cfg = config(|params| params.trials = 60);
        let grid = [1.0, 0.6, 0.4, 0.2, 0.1];
        let rows = decoupling_sweep(&cfg, &grid, 400).expect("valid sweep");

        // Detection degrades as the decoupling weakens: full decouple is easier than weak.
        assert!(
            rows[0].corr_auc >= rows[rows.len() - 1].corr_auc,
            "corr AUC should not increase as d shrinks: {:.3} -> {:.3}",
            rows[0].corr_auc,
            rows[rows.len() - 1].corr_auc
        );
        // Full decoupling is essentially perfect for correlation.
        assert!(
            rows[0].corr_auc > 0.95,
            "full-decouple corr AUC {:.3}",
            rows[0].corr_auc
        );
        // At these configured points correlation is not materially worse than PID.
        for r in &rows {
            assert!(
                r.corr_auc >= r.pid_auc - 0.03,
                "d={:.2}: correlation {:.3} should not trail PID {:.3}",
                r.decoupling,
                r.corr_auc,
                r.pid_auc
            );
        }
        // Pointwise intervals are descriptive only; scanning them cannot support a
        // family-wise "strictly beats somewhere" claim without max-stat correction.
        assert!(rows.iter().all(|row| row.diff_ci.0 <= row.diff_ci.1));
    }

    #[test]
    fn adaptive_detection_declines_as_decoupling_weakens() {
        let cfg = config(|params| params.trials = 50);
        let grid = [1.0, 0.6, 0.4, 0.2, 0.1, 0.05];
        let study = adaptive_adversary(&cfg, &grid, 0.05).expect("valid adaptive study");
        let rows = &study.rows;

        // Detection rate falls as the decoupling weakens (easier attacks are caught more).
        assert!(
            rows[0].corr_detect >= rows[rows.len() - 1].corr_detect,
            "corr detection should not rise as d shrinks: {:.3} -> {:.3}",
            rows[0].corr_detect,
            rows[rows.len() - 1].corr_detect
        );
        // Full decoupling is reliably caught by the correlation default.
        assert!(
            rows[0].corr_detect > 0.8,
            "full-decouple corr detect {:.3}",
            rows[0].corr_detect
        );
        // The independent holdout rates disclose whether the two fitted thresholds
        // actually landed at comparable operating points; target quantiles alone do not.
        assert!(study.corr_holdout_far.rate.is_finite() && study.pid_holdout_far.rate.is_finite());
    }

    #[test]
    fn adaptive_clean_calibration_and_holdout_seed_domains_are_disjoint() {
        let cfg = EvaluationResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named evaluation profile must be valid");
        let calibration: std::collections::HashSet<_> = (0..1_000)
            .map(|trial| adaptive_clean_seed(&cfg, trial, AdaptiveCleanArm::Calibration))
            .collect();
        let holdout: std::collections::HashSet<_> = (0..1_000)
            .map(|trial| adaptive_clean_seed(&cfg, trial, AdaptiveCleanArm::Holdout))
            .collect();

        assert!(calibration.is_disjoint(&holdout));
    }

    #[test]
    fn adaptive_formatter_discloses_independent_holdout_far_intervals() {
        let study = AdaptiveStudy {
            rows: vec![AdaptiveRow {
                decoupling: 0.5,
                corr_detect: 0.4,
                pid_detect: 0.3,
            }],
            target_far: 0.05,
            calibration_trials: 20,
            holdout_trials: 20,
            corr_holdout_far: RateInterval {
                rate: 0.05,
                ci: (0.01, 0.20),
            },
            pid_holdout_far: RateInterval {
                rate: 0.10,
                ci: (0.03, 0.30),
            },
        };

        let formatted = format_adaptive(&study, 0.5);
        assert!(formatted.contains("holdout FAR: corr 0.050 [0.010,0.200]"));
    }

    #[test]
    fn synchronized_maneuver_does_not_false_alarm() {
        let cfg = config(|params| params.trials = 40);
        let rows = maneuver_far(&cfg, &[0, 32], 12.0, 90).expect("valid maneuver study");
        // A synchronized maneuver (lag 0) keeps channels correlated → ~no consistency FAR.
        assert!(
            rows[0].corr_far < 0.1,
            "synced corr FAR {:.3}",
            rows[0].corr_far
        );
        assert!(
            rows[0].pid_far < 0.1,
            "synced pid FAR {:.3}",
            rows[0].pid_far
        );
        // A strongly heterogeneous maneuver (lag 32) does decorrelate → the FAR rises (honest limit).
        assert!(
            rows[1].corr_far + rows[1].pid_far > rows[0].corr_far + rows[0].pid_far,
            "large-lag FAR ({:.3}+{:.3}) should exceed synced ({:.3}+{:.3})",
            rows[1].corr_far,
            rows[1].pid_far,
            rows[0].corr_far,
            rows[0].pid_far
        );
    }

    #[test]
    fn maneuver_study_rejects_invalid_or_censored_inputs_before_generation() {
        let cfg = config(|params| params.trials = MIN_INFERENCE_TRIALS);
        assert!(matches!(
            validate_maneuver_inputs(&cfg, &[0], f64::NAN, 90),
            Err(EvalConfigError::InvalidManeuverMagnitude)
        ));
        assert!(matches!(
            validate_maneuver_inputs(&cfg, &[0], 12.0, 0),
            Err(EvalConfigError::InvalidManeuverDuration)
        ));
        assert!(matches!(
            validate_maneuver_inputs(&cfg, &[64], 12.0, 90),
            Err(EvalConfigError::ManeuverOutsideCapture { .. })
        ));
        assert!(maneuver_far(&cfg, &[64], 12.0, 90).is_err());
    }

    #[test]
    fn modeled_perturbation_grows_with_decoupling() {
        let cfg = config(|params| params.trials = 60);
        let rows = attacker_gain(&cfg, &[0.1, 0.4, 1.0]).expect("valid attacker study");
        // More decoupling injects more fused-innovation bias…
        assert!(
            rows[2].fused_perturbation_rms > rows[0].fused_perturbation_rms,
            "RMS perturbation should grow with d: {:.3} -> {:.3}",
            rows[0].fused_perturbation_rms,
            rows[2].fused_perturbation_rms
        );
        // …but also becomes more detectable — the security trade-off.
        assert!(
            rows[2].detect_rate >= rows[0].detect_rate,
            "detection should grow with d: {:.3} -> {:.3}",
            rows[0].detect_rate,
            rows[2].detect_rate
        );
        // A weak (near-undetectable) decoupling injects only a small bias.
        assert!(
            rows[0].fused_perturbation_rms < rows[2].fused_perturbation_rms,
            "weak decoupling should induce less RMS perturbation"
        );
    }

    #[test]
    fn wilson_ci_is_sane_at_the_boundaries() {
        // k = n: upper bound is 1.0, lower bound strictly below 1.
        let (lo, hi) = wilson_ci(200, 200);
        assert!(
            lo > 0.97 && lo < 1.0 && (hi - 1.0).abs() < 1e-9,
            "wilson(200,200)=[{lo:.3},{hi:.3}]"
        );
        // A p̂ = 0.5 interval is centered near 0.5.
        let (lo, hi) = wilson_ci(50, 100);
        assert!(lo > 0.40 && hi < 0.60, "wilson(50,100)=[{lo:.3},{hi:.3}]");
    }

    #[test]
    fn command_report_suite_preflights_before_work() {
        let cfg = config(|params| params.trials = MIN_INFERENCE_TRIALS);
        let grid = [1.0, 0.8, 0.6, 0.4, 0.3, 0.2, 0.1, 0.05];
        let lags = [0, 8, 16, 24, 32];
        validate_report_suite(&cfg, &grid, &lags, 200, MIN_INFERENCE_TRIALS, 10)
            .expect("minimum CLI suite must pass preflight");

        let documented_larger = config(|params| params.trials = 200);
        validate_report_suite(
            &documented_larger,
            &grid,
            &lags,
            200,
            MIN_INFERENCE_TRIALS,
            10,
        )
        .expect("documented 200-trial release suite must pass preflight");

        let excessive = config(|params| {
            params.trials = 1_000;
            params.frames = 10_000;
        });
        assert!(
            validate_report_suite(&excessive, &grid, &lags, 200, 1_000, 1).is_err(),
            "accepted field maxima must not imply an unbounded aggregate suite"
        );
    }

    #[test]
    fn command_preflight_rejects_pid_estimator_work_before_observation_limits() {
        let estimator_heavy = config(|params| {
            params.trials = 1_000;
            params.frames = 192;
        });
        let error =
            validate_report_suite(&estimator_heavy, &[1.0, 0.6, 0.2], &[0], 200, 1_000, 128)
                .expect_err("quadratic PID work must reject this otherwise bounded suite");

        assert!(matches!(
            error,
            EvalConfigError::WorkLimit {
                context: "suite PID quadratic fits",
                ..
            }
        ));
    }

    #[test]
    fn individual_study_rejects_aggregate_pid_work_before_execution() {
        let cfg = config(|params| {
            params.trials = 1_000;
            params.frames = 128;
        });
        let grid = (0..50).map(|index| index as f64 / 49.0).collect::<Vec<_>>();
        let error = decoupling_sweep(&cfg, &grid, 200)
            .expect_err("standalone sweep must enforce the aggregate PID ceiling");
        assert!(matches!(
            error,
            GaladrielError::InvalidConfig(message)
                if message.contains("sweep PID quadratic fits")
        ));
    }

    #[test]
    fn inferential_intervals_reject_degenerate_sample_counts() {
        assert!(auc_ci(&[1.0], &[0.0, 1.0], 200, 1).0.is_nan());
        assert!(auc_ci(&[1.0, 2.0], &[0.0, 1.0], 199, 1).0.is_nan());
        assert!(wilson_ci(2, 1).0.is_nan());
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Every point inside the documented scalar domain is accepted without
        /// normalization, and canonical identity is deterministic.
        #[test]
        fn valid_eval_params_round_trip_into_an_immutable_config(
            trials in MIN_INFERENCE_TRIALS..=1_000usize,
            base_seed in any::<u64>(),
            frames in 128usize..=10_000,
            rho in 1.0e-6f64..0.999_999,
            sigma in 1.0e-6f64..1.0e100,
            spoof_bias in 1.0e-6f64..1.0e100,
            jam_inflation in 1.000_001f64..1.0e100,
        ) {
            let params = EvalParams {
                trials,
                base_seed,
                frames,
                rho,
                sigma,
                spoof_bias,
                jam_inflation,
            };
            let first = EvalConfig::try_new(params.clone())
                .expect("generated parameters are inside every accepted scalar bound");
            let second = EvalConfig::try_new(params)
                .expect("the same generated parameters remain accepted");

            prop_assert_eq!(first.trials(), trials);
            prop_assert_eq!(first.base_seed(), base_seed);
            prop_assert_eq!(first.frames(), frames);
            prop_assert_eq!(first.rho().to_bits(), rho.to_bits());
            prop_assert_eq!(first.sigma().to_bits(), sigma.to_bits());
            prop_assert_eq!(first.spoof_bias().to_bits(), spoof_bias.to_bits());
            prop_assert_eq!(first.jam_inflation().to_bits(), jam_inflation.to_bits());
            prop_assert_eq!(first.canonical_digest(), second.canonical_digest());
        }

        /// The AUC is a probability in [0, 1] and antisymmetric: swapping the classes
        /// gives `1 − AUC`.
        #[test]
        fn auc_is_a_unit_antisymmetric_probability(
            pos in prop::collection::vec(-100.0f64..100.0, 1..40),
            neg in prop::collection::vec(-100.0f64..100.0, 1..40),
        ) {
            let a = auc(&pos, &neg);
            prop_assert!((-1e-9..=1.0 + 1e-9).contains(&a), "auc {a} ∉ [0,1]");
            prop_assert!(
                (a + auc(&neg, &pos) - 1.0).abs() < 1e-9,
                "auc not antisymmetric: {a} + {} ≠ 1",
                auc(&neg, &pos)
            );
        }

        /// The Wilson interval is a sub-interval of [0, 1] that brackets the point estimate.
        #[test]
        fn wilson_ci_brackets_the_estimate(
            (n, k) in (1usize..2000).prop_flat_map(|n| (Just(n), 0usize..=n))
        ) {
            let (lo, hi) = wilson_ci(k, n);
            let p = k as f64 / n as f64;
            prop_assert!(lo >= -1e-12 && hi <= 1.0 + 1e-12, "wilson [{lo},{hi}] ∉ [0,1]");
            prop_assert!(lo <= hi, "wilson lo {lo} > hi {hi}");
            prop_assert!(lo <= p + 1e-9 && p <= hi + 1e-9, "wilson [{lo},{hi}] misses p̂={p}");
        }

        /// A bootstrap AUC CI is ordered and within [0, 1].
        #[test]
        fn auc_ci_is_ordered_within_unit(
            pos in prop::collection::vec(-100.0f64..100.0, 2..30),
            neg in prop::collection::vec(-100.0f64..100.0, 2..30),
        ) {
            let (lo, hi) = auc_ci(&pos, &neg, 200, 7);
            prop_assert!(lo <= hi + 1e-12, "auc_ci lo {lo} > hi {hi}");
            prop_assert!(lo >= -1e-9 && hi <= 1.0 + 1e-9, "auc_ci [{lo},{hi}] ∉ [0,1]");
        }
    }
}
