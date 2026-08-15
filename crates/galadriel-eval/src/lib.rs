#![forbid(unsafe_code)]
//! Monte Carlo evaluation of Galadriel's Mirror across four modeled regimes.
//!
//! The evaluation compares the NIS baseline, signed correlation, exploratory MI
//! consensus, and the authoritative NIS-plus-correlation core default. Scoped
//! studies use [`ScenarioConfig::assessment_scope`]. That synthetic scope is not
//! operational provenance and does not authenticate a producer.
//!
//! All regimes run on the *same* corroborated sim (`rho > 0`). The baseline,
//! correlation, and core paths produce alarm outcomes. The MI companion instead
//! produces a descriptive majority-graph separation event or an unavailable state,
//! plus a complete-pair score when all edge estimates exist. MI event rates are not
//! false-alarm rates. Event-ranked attack-versus-clean AUC uses the Mann–Whitney identity
//! `AUC = P(score_attack > score_clean) + 0.5 * P(score_attack = score_clean)`.
//! MI AUC is conditional on an available graph event and score; reports therefore
//! include correlation on the identical joint-complete cases and sharp worst/best
//! bounds over arbitrary rankings of missing MI scores. AUCs carry percentile-bootstrap 95 % CIs
//! ([`stealthy_ci_study`], with a paired correlation-to-MI difference CI through
//! [`auc_diff_ci`]). A companion study ([`measure_latency`]) reports alarm latency
//! for the accepted components and, separately, an oracle-onset-segmented posthoc
//! separation-event latency for MI. These are not one calibrated endpoint.
//!
//! Under this simulator and the stated parameter grid, the detectors show
//! complementarity: the baseline responds to magnitude attacks while cross-sensor
//! consistency can respond to the modeled moment-matched decoupling. These results
//! are an evaluation of the modeled regimes, not a claim of operational coverage.
//! Standalone correlation and MI component metrics are deliberately pre-registered to
//! producer-attested consistency-projection axis 0. The core-default metric evaluates every
//! attested correlation axis. MI never enters that verdict.
//!
//! A decoupling-strength sweep ([`decoupling_sweep`]) compares the signed-correlation
//! and pairwise-MI paths on linear-Gaussian data using pointwise intervals. It does
//! not establish equivalence, family-wise superiority, or pure-synergy detection.

use std::collections::{HashMap, HashSet};

use galadriel_core::{
    assess_default, correlation, AssessmentScope, CorrConfig, CorrVerdict, FusedVerdict,
    GaladrielError, Mirror, Modality, PidObservation, ReleaseSuite, Result as CoreResult, Verdict,
};
use galadriel_dependence::{
    analyze, scalar_channels, ContinuousLawDeclaration, DeclaredMiInput, MiConsensusConfig,
    MiConsensusConfigError, MiConsensusReport, MiConsensusResearchProfile, MiGraphDisposition,
    MAX_MI_WINDOW,
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
/// Minimum capture length for the registered evaluation design.
///
/// The attack starts one third of the way through a capture. At 216 frames the
/// pre-attack phase contains the 72 rows required by the exhaustive MI profile,
/// while the post-attack phase contains at least its complete 128-row window.
/// This prevents a fixed-law MI report from spanning an attack transition or
/// comparing clean and attack arms at different configured window sizes.
pub const MIN_EVALUATION_FRAMES: usize = 216;
/// Registered clean upper-tail quantile for the adaptive-adversary study.
pub const ADAPTIVE_TARGET_FAR: f64 = 0.05;
/// Registered score-threshold tolerance used by descriptive grid summaries.
pub const DETECTION_TOLERANCE: f64 = 0.5;
/// Registered benign-maneuver magnitude in simulator standard-deviation units.
pub const MANEUVER_MAGNITUDE_SIGMA: f64 = 12.0;
/// Registered benign-maneuver duration in frames.
pub const MANEUVER_DURATION_FRAMES: u64 = 90;
const MAX_BOOTSTRAP_AUC_COMPARISONS: usize = 250_000_000;
const MAX_GRID_TRIAL_COMBINATIONS: usize = 50_000;
const MAX_STUDY_OBSERVATIONS: usize = 100_000_000;
const MAX_LATENCY_PREFIX_OBSERVATIONS: usize = 100_000_000;
const MAX_SUITE_MI_QUADRATIC_WORK: u128 = 4_000_000_000_000;
const ADAPTIVE_CALIBRATION_DOMAIN: u64 = 0x4144_4150_5443_414c;
const ADAPTIVE_HOLDOUT_DOMAIN: u64 = 0x4144_4150_5448_4f4c;
const EVALUATION_PROTOCOL_ID: &str =
    "galadriel-eval/stationary-phase+mi-selection-sensitivity-v0.9";
const MI_EVENT_PROTOCOL_ID: &str = "galadriel-eval/mi-event/separated-from-majority-graph-v0.9";
const MI_SCORE_PROTOCOL_ID: &str =
    "galadriel-eval/mi-score/positive-reference-signed-estimate-spread-v0.9";

fn mi_research_config() -> std::result::Result<MiConsensusConfig, EvalConfigError> {
    MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9
        .try_config(synthetic_continuous_law()?)
        .map_err(|source| EvalConfigError::MiConsensus { source })
}

fn synthetic_continuous_law() -> std::result::Result<ContinuousLawDeclaration, EvalConfigError> {
    ContinuousLawDeclaration::try_iid(
        "The registered simulator declares nonsingular jointly Gaussian bivariate populations with finite mutual information for every requested projection pair.",
        "Binary64 sample representation of pseudorandom draws intended from the declared continuous law; no deliberate quantization, added noise, or tie-breaking transform; exact ties abstain.",
        "Rows are independent draws within one fixed-parameter synthetic scenario episode.",
        "All registered simulator projection coordinates use the same fixed physical innovation unit and identity gauge; no sample-fitted rescaling is applied.",
    )
    .map_err(|source| EvalConfigError::MiConsensus { source })
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
    /// MI work is accepted separately by [`EvalSuiteConfig::try_new`].
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
    #[error("frames must be in {MIN_EVALUATION_FRAMES}..=10000")]
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
    /// The named MI-consensus profile could not be accepted.
    #[error("evaluation MI-consensus profile is invalid: {source}")]
    MiConsensus {
        /// Typed MI configuration source.
        #[source]
        source: MiConsensusConfigError,
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
    /// A maneuver shorter than two frames has no nonzero sampled study exposure.
    #[error("maneuver duration must be >= 2")]
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
        if !(MIN_EVALUATION_FRAMES..=10_000).contains(&params.frames) {
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
    if duration < 2 {
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

fn mi_fit_count(cfg: &MiConsensusConfig) -> std::result::Result<u128, EvalConfigError> {
    let window = cfg.window() as u128;
    let denominator = window
        .checked_mul(window)
        .ok_or(EvalConfigError::WorkOverflow {
            context: "MI configured window square",
        })?;
    Ok(cfg.quadratic_fit_work() as u128 / denominator)
}

fn mi_analysis_work(
    cfg: &MiConsensusConfig,
    samples: usize,
    fit_count: u128,
) -> std::result::Result<u128, EvalConfigError> {
    if samples < cfg.required_samples() {
        return Ok(0);
    }
    let window = samples.min(cfg.window()).min(MAX_MI_WINDOW) as u128;
    window
        .checked_mul(window)
        .and_then(|distance_pairs| distance_pairs.checked_mul(fit_count))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "MI analysis",
        })
}

fn full_mi_work(cfg: &EvalConfig, calls: usize) -> std::result::Result<u128, EvalConfigError> {
    let mi_cfg = mi_research_config()?;
    let fit_count = mi_fit_count(&mi_cfg)?;
    let per_call = mi_analysis_work(&mi_cfg, cfg.frames, fit_count)?;
    checked_work_product(calls as u128, per_call, "full-stream MI")
}

fn validate_mi_work_limit(
    work: u128,
    context: &'static str,
) -> std::result::Result<(), EvalConfigError> {
    if work > MAX_SUITE_MI_QUADRATIC_WORK {
        return Err(EvalConfigError::WorkLimit {
            context,
            actual: work,
            maximum: MAX_SUITE_MI_QUADRATIC_WORK,
        });
    }
    Ok(())
}

fn validate_full_mi_calls(
    cfg: &EvalConfig,
    calls: usize,
    context: &'static str,
) -> std::result::Result<(), EvalConfigError> {
    validate_mi_work_limit(full_mi_work(cfg, calls)?, context)
}

fn latency_mi_work(
    cfg: &EvalConfig,
    trials: usize,
    step: usize,
) -> std::result::Result<u128, EvalConfigError> {
    let mi_cfg = mi_research_config()?;
    let fit_count = mi_fit_count(&mi_cfg)?;
    let onset = cfg.frames / 3;
    let work_per_stream = ttd_probe_schedule(cfg.frames, onset, step)
        .into_iter()
        .try_fold(0_u128, |work, probe| {
            let stationary_rows = match probe.phase {
                ProbePhase::PreOnset => probe.frames,
                ProbePhase::PostOnset => probe.frames.saturating_sub(onset),
            };
            let probe_work = mi_analysis_work(&mi_cfg, stationary_rows, fit_count)?;
            work.checked_add(probe_work)
                .ok_or(EvalConfigError::WorkOverflow {
                    context: "latency MI",
                })
        })?;
    let streams = trials
        .checked_mul(Attack::ALL.len().saturating_sub(1))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "latency MI stream count",
        })?;
    checked_work_product(streams as u128, work_per_stream, "latency MI")
}

fn checked_work_product(
    left: u128,
    right: u128,
    context: &'static str,
) -> std::result::Result<u128, EvalConfigError> {
    left.checked_mul(right)
        .ok_or(EvalConfigError::WorkOverflow { context })
}

fn validate_suite_mi_work(
    cfg: &EvalConfig,
    grid_len: usize,
    latency_trials: usize,
    latency_step: usize,
) -> std::result::Result<(), EvalConfigError> {
    // Per trial: main axis-0 MI component, CI study,
    // sweep, collusion, and adaptive calibration/holdout/attacks. The
    // nonstationary maneuver study deliberately has no fixed-law MI call.
    let full_calls_per_trial = Attack::ALL
        .len()
        .checked_add(2)
        .and_then(|calls| calls.checked_add(1 + grid_len))
        .and_then(|calls| calls.checked_add(1))
        .and_then(|calls| calls.checked_add(2 + grid_len))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "suite MI call count",
        })?;
    let full_calls = checked_work_product(
        cfg.trials as u128,
        full_calls_per_trial as u128,
        "full-stream",
    )?;
    let full_calls = usize::try_from(full_calls).map_err(|_| EvalConfigError::WorkOverflow {
        context: "full-stream MI call count",
    })?;
    let full_work = full_mi_work(cfg, full_calls)?;
    let latency_work = latency_mi_work(cfg, latency_trials, latency_step)?;
    let total = full_work
        .checked_add(latency_work)
        .ok_or(EvalConfigError::WorkOverflow {
            context: "suite MI",
        })?;
    validate_mi_work_limit(total, "suite MI quadratic fits")
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
    /// Trial count used by alarm/separation-event latency studies.
    pub latency_trials: usize,
    /// Prefix stride used by alarm/separation-event latency studies.
    pub latency_step: usize,
}

/// Immutable accepted composition for the complete synthetic evaluation suite.
///
/// A value exists only after all grid, trial, observation, bootstrap, maneuver,
/// latency-prefix, pair, estimator-fit, and registered axis-0 MI products have passed
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
        validate_maneuver_inputs(
            &eval,
            &params.lag_steps,
            MANEUVER_MAGNITUDE_SIGMA,
            MANEUVER_DURATION_FRAMES,
        )?;
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
            .and_then(|intervals| intervals.checked_add(6))
            .ok_or(EvalConfigError::WorkOverflow {
                context: "suite bootstrap interval count",
            })?;
        validate_bootstrap_work(eval.trials, params.bootstrap_resamples, bootstrap_intervals)?;

        if params.latency_step == 0 || params.latency_step > eval.frames {
            return Err(EvalConfigError::InvalidLatencyStep);
        }
        validate_suite_mi_work(
            &eval,
            params.decouplings.len(),
            params.latency_trials,
            params.latency_step,
        )?;
        validate_latency_work(&eval, params.latency_trials, params.latency_step)?;
        let mi_config_identity = mi_research_config()?.identity().to_hex();
        let canonical_digest = suite_digest(&eval, &params, &mi_config_identity);
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

fn suite_digest(eval: &EvalConfig, params: &EvalSuiteParams, mi_config_identity: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"galadriel-eval-suite-config-v0.9.1\0");
    hasher.update(eval.canonical_digest.as_bytes());
    hasher.update([0]);
    hasher.update(EVALUATION_PROTOCOL_ID.as_bytes());
    hasher.update([0]);
    hasher.update(mi_config_identity.as_bytes());
    hasher.update([0]);
    hasher.update(MI_EVENT_PROTOCOL_ID.as_bytes());
    hasher.update([0]);
    hasher.update(MI_SCORE_PROTOCOL_ID.as_bytes());
    hasher.update([0]);
    hasher.update(ADAPTIVE_TARGET_FAR.to_bits().to_be_bytes());
    hasher.update(DETECTION_TOLERANCE.to_bits().to_be_bytes());
    hasher.update(MANEUVER_MAGNITUDE_SIGMA.to_bits().to_be_bytes());
    hasher.update(MANEUVER_DURATION_FRAMES.to_be_bytes());
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

    fn identity(self) -> &'static str {
        match self {
            Attack::Clean => "clean",
            Attack::LoudSpoof => "loud-spoof",
            Attack::Stealthy => "stealthy-spoof",
            Attack::Jam => "broadband-jam",
        }
    }

    fn stationary_start_frame(self, cfg: &EvalConfig) -> usize {
        match self {
            Attack::Clean => 0,
            Attack::LoudSpoof | Attack::Stealthy | Attack::Jam => cfg.frames / 3,
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

fn build_from_scenario(
    attack: Attack,
    cfg: &EvalConfig,
    scenario: &ScenarioConfig,
) -> CoreResult<Vec<PidObservation>> {
    let start = (cfg.frames as u64) / 3;
    match attack {
        Attack::Clean => generate(scenario),
        Attack::LoudSpoof => {
            let mut v = generate(scenario)?;
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
            scenario,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: start,
            },
        ),
        Attack::Jam => {
            let mut v = generate(scenario)?;
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

fn build(attack: Attack, cfg: &EvalConfig, seed: u64) -> CoreResult<Vec<PidObservation>> {
    let scenario = scenario(cfg, seed)?;
    build_from_scenario(attack, cfg, &scenario)
}

fn build_scoped(
    attack: Attack,
    cfg: &EvalConfig,
    seed: u64,
) -> CoreResult<(AssessmentScope, Vec<PidObservation>)> {
    let scenario = scenario(cfg, seed)?;
    let scope = scenario
        .assessment_scope("evaluation-fused")
        .map_err(|error| GaladrielError::InvalidConfig(error.to_string()))?;
    let stream = build_from_scenario(attack, cfg, &scenario)?;
    Ok((scope, stream))
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

/// Project-defined signed-estimate spread over a positive best-peer reference.
///
/// This normalization permits one registered ranking protocol for the correlation
/// and MI component studies. It does not make MI nats and signed correlation the
/// same estimand. Finite-sample KSG estimates can be negative even though population
/// MI is nonnegative. A negative minority-channel estimate is retained because it
/// can be part of a valid threshold-graph separation. The score is available only
/// when at least one best-peer estimate supplies a positive reference; the caller
/// separately withholds every graph below the configured MI reference floor.
fn mi_best_peer_spread(values: &[f64]) -> Option<f64> {
    if values.len() < 2 || values.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let maximum = values.iter().copied().fold(f64::MIN, f64::max);
    let minimum = values.iter().copied().fold(f64::MAX, f64::min);
    if maximum <= 1e-9 {
        return None;
    }
    Some(((maximum - minimum) / maximum).clamp(0.0, 1.0))
}

fn signed_correlation_imbalance(values: &[f64]) -> Option<f64> {
    if values.len() < 2 || values.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let maximum = values.iter().copied().fold(f64::MIN, f64::max);
    let minimum = values.iter().copied().fold(f64::MAX, f64::min);
    if maximum > 1e-9 {
        Some((1.0 - minimum / maximum).clamp(0.0, 1.0))
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
        score: match (evidence.alarm, evidence.score) {
            (Some(alarm), Some(score)) => Some(alarm_rank(alarm, score)),
            _ => None,
        },
    }
}

fn stationary_mi_report(
    stream: &[PidObservation],
    start_frame: usize,
    episode_label: &str,
) -> CoreResult<MiConsensusReport> {
    let modalities = MODALITIES.len();
    if stream.is_empty() || !stream.len().is_multiple_of(modalities) {
        return Err(GaladrielError::InvalidObservation(
            "registered MI input must contain complete frame-major modality rows".into(),
        ));
    }
    let frames = stream.len() / modalities;
    if start_frame >= frames {
        return Err(GaladrielError::InvalidObservation(format!(
            "registered MI stationary start {start_frame} must precede {frames} available frames"
        )));
    }
    for (frame, observations) in stream.chunks_exact(modalities).enumerate() {
        let sequence = observations[0].sequence();
        if observations
            .iter()
            .zip(MODALITIES)
            .any(|(observation, modality)| {
                observation.sequence() != sequence || observation.modality() != modality
            })
        {
            return Err(GaladrielError::InvalidObservation(format!(
                "registered MI input is not the expected frame-major modality sequence at frame {frame}"
            )));
        }
    }
    let start = start_frame
        .checked_mul(modalities)
        .ok_or_else(|| GaladrielError::InvalidObservation("MI frame offset overflowed".into()))?;
    let stationary = &stream[start..];
    let channels = scalar_channels(stationary, &MODALITIES, 0)?;
    let label = format!("{episode_label}:stationary-frames-{start_frame}..{frames}:axis-0");
    let input = DeclaredMiInput::try_new(channels, label)?;
    analyze(&input, &mi_research_config()?)
}

/// Registered projection-axis-0 MI graph component. A positive study event means
/// `SeparatedFromMajorityGraph`; it is not a calibrated security alarm.
fn mi_evidence(
    stream: &[PidObservation],
    start_frame: usize,
    episode_label: &str,
) -> CoreResult<DetectorEvidence> {
    let rep = stationary_mi_report(stream, start_frame, episode_label)?;
    // The binary event and continuous score are different project-defined
    // compositions. A threshold graph can be ambiguous, below its configured
    // reference floor, or unstable under deletion even though every pairwise KSG
    // report exists. In that case the graph event abstains, but the complete-graph
    // decoupling-depth score remains available. Missing pair evidence withholds both.
    let expected_pairs = MODALITIES.len() * (MODALITIES.len() - 1) / 2;
    let below_resolution = matches!(
        rep.disposition(),
        MiGraphDisposition::Unavailable(
            galadriel_dependence::MiGraphUnavailableReason::ReferenceBelowConfiguredFloor
        )
    );
    let score = if !below_resolution
        && rep.pairs().len() == expected_pairs
        && rep
            .pairs()
            .iter()
            .all(|pair| pair.estimate_nats().is_some())
        && rep.channels().len() == MODALITIES.len()
    {
        rep.channels()
            .iter()
            .map(|channel| channel.strongest_pair_mi_nats())
            .collect::<Option<Vec<_>>>()
            .and_then(|estimates| mi_best_peer_spread(&estimates))
    } else {
        None
    };
    let alarm = match rep.disposition() {
        MiGraphDisposition::SeparatedFromMajorityGraph(_) => Some(true),
        MiGraphDisposition::NoSeparationAtConfiguredThreshold => Some(false),
        MiGraphDisposition::Unavailable(_) => None,
    };
    Ok(DetectorEvidence { alarm, score })
}

fn mi_eval(
    stream: &[PidObservation],
    start_frame: usize,
    episode_label: &str,
) -> CoreResult<DetectorEvidence> {
    mi_evidence(stream, start_frame, episode_label).map(alarm_rank_evidence)
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
        score: signed_correlation_imbalance(&corrs),
    })
}

fn corr_eval(stream: &[PidObservation]) -> CoreResult<DetectorEvidence> {
    corr_evidence(stream).map(alarm_rank_evidence)
}

fn component_evaluations(
    stream: &[PidObservation],
    mi_start_frame: usize,
    episode_label: &str,
) -> CoreResult<[DetectorEvidence; 3]> {
    Ok([
        baseline_eval(stream)?,
        corr_eval(stream)?,
        mi_eval(stream, mi_start_frame, episode_label)?,
    ])
}

/// Authoritative default detector only: NIS plus signed correlation. Exploratory
/// MI never enters this verdict.
fn default_eval(scope: &AssessmentScope, stream: &[PidObservation]) -> CoreResult<Option<bool>> {
    let suite = ReleaseSuite::standalone_advisory_v0_9(&MODALITIES)?;
    let report = assess_default(scope, stream, &suite)?;
    Ok(match report.verdict() {
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

/// Sharp worst/best ROC-AUC bounds when only a subset of each fixed arm has a score.
///
/// The observed-observed Mann–Whitney contribution is fixed. Every pair containing
/// at least one missing score is assigned zero contribution for the lower bound and
/// one for the upper bound. No missing-at-random or score-order assumption is made.
fn auc_missingness_bounds(
    observed_auc: f64,
    observed_positive: usize,
    observed_negative: usize,
    total_positive: usize,
    total_negative: usize,
) -> (f64, f64) {
    if !observed_auc.is_finite()
        || observed_positive > total_positive
        || observed_negative > total_negative
        || total_positive == 0
        || total_negative == 0
    {
        return (f64::NAN, f64::NAN);
    }
    let observed_pairs = observed_positive as f64 * observed_negative as f64;
    let total_pairs = total_positive as f64 * total_negative as f64;
    let observed_contribution = observed_auc * observed_pairs;
    let unknown_pairs = total_pairs - observed_pairs;
    (
        observed_contribution / total_pairs,
        (observed_contribution + unknown_pairs) / total_pairs,
    )
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

/// A conservative floating-point enclosure of the exact rational proportion `k/n`.
///
/// Integer-to-`f64` conversion can round distinct counts to the same value above `2^53`.
/// Moving each converted count outward before division, then moving the quotient outward,
/// preserves an enclosure of the exact rational value for every valid `usize` count.
fn proportion_enclosure(k: usize, n: usize) -> (f64, f64) {
    debug_assert!(n > 0 && k <= n);
    if k == 0 {
        return (0.0, 0.0);
    }
    if k == n {
        return (1.0, 1.0);
    }

    let kf = k as f64;
    let nf = n as f64;
    let lower = (kf.next_down() / nf.next_up()).next_down().max(0.0);
    let upper = (kf.next_up() / nf.next_down()).next_up().min(1.0);
    (lower, upper)
}

/// Direct Wilson calculation for proportions no greater than one half.
fn wilson_lower_half(k: usize, n: usize) -> (f64, f64) {
    debug_assert!(n > 0 && k <= n / 2);
    let z = 1.959_964_f64;
    let nf = n as f64;
    let p = k as f64 / nf;
    let z2 = z * z;
    let denom = 1.0 + z2 / nf;
    let center = p + z2 / (2.0 * nf);
    let margin = z * (p * (1.0 - p) / nf + z2 / (4.0 * nf * nf)).sqrt();
    let (point_lower, point_upper) = proportion_enclosure(k, n);
    let lower = ((center - margin) / denom).clamp(0.0, 1.0).min(point_lower);
    let upper = ((center + margin) / denom).clamp(0.0, 1.0).max(point_upper);
    (lower, upper)
}

/// Return `1 - value` with the exact rounding residual of the subtraction.
fn one_minus_with_roundoff(value: f64) -> (f64, f64) {
    let negative = -value;
    let difference = 1.0 + negative;
    let virtual_negative = difference - 1.0;
    let residual = (1.0 - (difference - virtual_negative)) + (negative - virtual_negative);
    (difference, residual)
}

fn outward_complement_lower(value: f64) -> f64 {
    let (difference, residual) = one_minus_with_roundoff(value);
    if residual < 0.0 {
        difference.next_down()
    } else {
        difference
    }
}

fn outward_complement_upper(value: f64) -> f64 {
    let (difference, residual) = one_minus_with_roundoff(value);
    if residual > 0.0 {
        difference.next_up()
    } else {
        difference
    }
}

/// Wilson score 95% CI for a binomial proportion `k/n` (a closed-form interval, correct
/// even at the `k = n` / `k = 0` boundaries where a normal approximation degenerates).
/// The returned floating-point interval conservatively contains the exact rational point
/// estimate for every valid `usize` count, including counts beyond `f64`'s exact-integer
/// range.
pub fn wilson_ci(k: usize, n: usize) -> (f64, f64) {
    if n == 0 || k > n {
        return (f64::NAN, f64::NAN);
    }
    if k <= n / 2 {
        return wilson_lower_half(k, n);
    }

    // Reflect the numerically stable failure-proportion interval. Move a subtraction
    // outward only when its error-free residual proves that it rounded inward.
    let (failure_lower, failure_upper) = wilson_lower_half(n - k, n);
    let (point_lower, point_upper) = proportion_enclosure(k, n);
    let lower = outward_complement_lower(failure_upper)
        .max(0.0)
        .min(point_lower);
    let upper = outward_complement_upper(failure_lower)
        .min(1.0)
        .max(point_upper);
    (lower, upper)
}

#[cfg(test)]
fn compare_f64_to_proportion(value: f64, k: usize, n: usize) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    assert!(n > 0 && k <= n && value.is_finite());
    if k == 0 {
        return value.partial_cmp(&0.0).expect("finite values are ordered");
    }
    if k == n {
        return value.partial_cmp(&1.0).expect("finite values are ordered");
    }
    if value <= 0.0 {
        return Ordering::Less;
    }
    if value >= 1.0 {
        return Ordering::Greater;
    }

    let bits = value.to_bits();
    let exponent_field = ((bits >> 52) & 0x7ff) as i32;
    if exponent_field == 0 {
        // Every positive `usize` ratio is at least 1 / (2^64 - 1), far above the
        // largest subnormal `f64`, on every Rust target supported today.
        return Ordering::Less;
    }
    let significand = (1_u64 << 52) | (bits & ((1_u64 << 52) - 1));
    let exponent = exponent_field - 1023;
    let denominator_shift = (52 - exponent) as u32;
    let right_bits = 128 - (k as u128).leading_zeros();
    if right_bits + denominator_shift > 128 {
        return Ordering::Less;
    }

    let left = u128::from(significand) * n as u128;
    let right = (k as u128) << denominator_shift;
    left.cmp(&right)
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
    /// Fixed arm sizes before score-dependent exclusions.
    pub positive_total: usize,
    pub negative_total: usize,
    /// Worst/best AUC over arbitrary rankings of every missing score.
    pub missingness_bounds: (f64, f64),
}

/// Bootstrap 95% CIs for the three detectors' alarm-ranked ROC-AUC on the
/// **stealthy spoof** (the statistic reported by [`run`]), plus a fourth row that
/// recomputes correlation on exactly the MI-complete cases and the paired corr−MI
/// AUC-difference CI. Correlation and MI are the pre-registered axis-0 component
/// studies; the authoritative core default remains all-axis. Returns
/// `(rows, (diff, diff_lo, diff_hi))`. Resamples the already-computed scores — no
/// re-simulation beyond the one score pass. Clean and attack arms use
/// domain-separated independent seeds. MI AUC uses only trials with an available
/// graph event and score. The correlation-to-MI difference uses those same
/// complete cases within each arm, so unavailable MI events never become negative
/// examples and detector pairing is preserved. Each row also carries worst/best
/// AUC bounds over arbitrary rankings of its missing scores.
pub fn stealthy_ci_study(
    cfg: &EvalConfig,
    n_boot: usize,
) -> CoreResult<(Vec<CiRow>, (f64, f64, f64))> {
    validate_observation_work(cfg.trials, cfg.frames, 2)?;
    let mi_calls = cfg
        .trials
        .checked_mul(2)
        .ok_or(EvalConfigError::WorkOverflow {
            context: "CI study MI call count",
        })?;
    validate_full_mi_calls(cfg, mi_calls, "CI study MI quadratic fits")?;
    validate_bootstrap(n_boot)?;
    // Four displayed AUC intervals (including matched-case correlation) plus
    // two AUC evaluations inside each paired difference resample.
    validate_bootstrap_work(cfg.trials, n_boot, 6)?;
    let (mut cb, mut sb) = (Vec::new(), Vec::new()); // baseline clean/stealthy
    let (mut cc, mut sc) = (Vec::new(), Vec::new()); // correlation, all assessable trials
    let (mut cp, mut sp) = (Vec::new(), Vec::new()); // MI
    let (mut paired_cc, mut paired_sc) = (Vec::new(), Vec::new());
    for t in 0..cfg.trials {
        let clean = build(Attack::Clean, cfg, attack_seed(cfg, t, Attack::Clean))?;
        let steal = build(Attack::Stealthy, cfg, attack_seed(cfg, t, Attack::Stealthy))?;
        let clean_label = format!("ci-clean-trial-{t}");
        let stealthy_label = format!("ci-stealthy-trial-{t}");
        let [clean_baseline, clean_corr, clean_mi] =
            component_evaluations(&clean, 0, &clean_label)?;
        let [stealthy_baseline, stealthy_corr, stealthy_mi] =
            component_evaluations(&steal, cfg.frames / 3, &stealthy_label)?;
        cb.push(clean_baseline.require_score("baseline")?);
        sb.push(stealthy_baseline.require_score("baseline")?);
        let clean_corr_score = clean_corr.require_score("correlation")?;
        let stealthy_corr_score = stealthy_corr.require_score("correlation")?;
        cc.push(clean_corr_score);
        sc.push(stealthy_corr_score);
        if let Some(score) = clean_mi.score {
            paired_cc.push(clean_corr_score);
            cp.push(score);
        }
        if let Some(score) = stealthy_mi.score {
            paired_sc.push(stealthy_corr_score);
            sp.push(score);
        }
    }
    let seed = cfg.base_seed;
    let row =
        |name: &str, pos: &[f64], neg: &[f64], positive_total: usize, negative_total: usize| {
            let (lo, hi) = auc_ci(pos, neg, n_boot, seed);
            let point = auc(pos, neg);
            CiRow {
                name: name.to_string(),
                auc: point,
                lo,
                hi,
                positive_n: pos.len(),
                negative_n: neg.len(),
                positive_total,
                negative_total,
                missingness_bounds: auc_missingness_bounds(
                    point,
                    pos.len(),
                    neg.len(),
                    positive_total,
                    negative_total,
                ),
            }
        };
    let rows = vec![
        row("baseline (NIS χ²)", &sb, &cb, cfg.trials, cfg.trials),
        row("correlation axis 0", &sc, &cc, cfg.trials, cfg.trials),
        row(
            "corr axis 0 (MI-complete)",
            &paired_sc,
            &paired_cc,
            cfg.trials,
            cfg.trials,
        ),
        row("MI axis 0 (KSG-MI)", &sp, &cp, cfg.trials, cfg.trials),
    ];
    let diff = auc(&paired_sc, &paired_cc) - auc(&sp, &cp);
    let (dlo, dhi) = auc_diff_ci(&paired_sc, &paired_cc, &sp, &cp, n_boot, seed);
    Ok((rows, (diff, dlo, dhi)))
}

/// Format the bootstrap-CI study as a plain-text block.
pub fn format_ci(rows: &[CiRow], diff: (f64, f64, f64), n_boot: usize) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Bootstrap 95% CIs — stealthy spoof · alarm/event-ranked ROC-AUC · {n_boot} resamples\n\n"
    ));
    for r in rows {
        if r.auc.is_finite()
            && r.lo.is_finite()
            && r.hi.is_finite()
            && r.lo <= r.hi
            && (0.0..=1.0).contains(&r.auc)
            && (0.0..=1.0).contains(&r.lo)
            && (0.0..=1.0).contains(&r.hi)
        {
            s.push_str(&format!(
                "{:<26} AUC {:.3}  [{:.3}, {:.3}]  observed={}/{} of total={}/{} (attack/clean)\n",
                r.name,
                r.auc,
                r.lo,
                r.hi,
                r.positive_n,
                r.negative_n,
                r.positive_total,
                r.negative_total,
            ));
            if r.positive_n != r.positive_total || r.negative_n != r.negative_total {
                s.push_str(&format!(
                    "  arbitrary-missing-score AUC bounds: [{:.3}, {:.3}]\n",
                    r.missingness_bounds.0, r.missingness_bounds.1,
                ));
            }
        } else {
            s.push_str(&format!(
                "{:<26} unavailable: non-finite, unordered, or out-of-domain AUC interval  observed={}/{} of total={}/{} (attack/clean)\n",
                r.name,
                r.positive_n,
                r.negative_n,
                r.positive_total,
                r.negative_total,
            ));
        }
    }
    let (d, lo, hi) = diff;
    if d.is_finite() && lo.is_finite() && hi.is_finite() && lo <= hi {
        let includes_zero = lo <= 0.0 && hi >= 0.0;
        s.push_str(&format!(
            "{:<22} ΔAUC {:+.3}  [{:+.3}, {:+.3}]  → {}\n",
            "corr − MI (paired)",
            d,
            lo,
            hi,
            if includes_zero {
                "CI includes 0: no difference detected at this sample size"
            } else {
                "pointwise CI excludes 0"
            }
        ));
    } else {
        s.push_str(&format!(
            "{:<22} unavailable: non-finite or unordered paired interval\n",
            "corr − MI (paired)",
        ));
    }
    s.push_str(
        "The all-case correlation row answers a different denominator question. The MI row, the\n\
         MI-complete correlation row, and corr−MI difference use identical event-assessable cases;\n\
         unavailable MI graph outcomes are excluded, not ranked as non-events. Counts disclose the\n\
         retained arms; arbitrary-missing-score bounds require no missing-at-random assumption.\n",
    );
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
    /// MI consistency-score AUC and its bootstrap 95% CI.
    pub mi_auc: f64,
    pub mi_ci: (f64, f64),
    /// Pointwise paired-bootstrap 95% CI for the AUC difference `corr − MI`.
    /// A grid-wide superiority claim requires simultaneous-error control.
    pub diff_ci: (f64, f64),
}

/// Sweep the stealthy spoof's **decoupling strength** and report, for each `d`, the AUC of
/// the pre-registered axis-0 correlation and MI consistency scores (the shared
/// project-defined normalized ranking protocol over the same registered rows and
/// window, while remaining different estimands) with bootstrap 95% CIs. Traces the *detection boundary*:
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
    let mi_calls = decouplings
        .len()
        .checked_add(1)
        .and_then(|streams| streams.checked_mul(cfg.trials))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "sweep MI call count",
        })?;
    validate_full_mi_calls(cfg, mi_calls, "sweep MI quadratic fits")?;
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
        clean_p
            .push(mi_evidence(&clean, 0, &format!("sweep-clean-trial-{t}"))?.require_score("MI")?);
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
            sp.push(
                mi_evidence(
                    &stream,
                    cfg.frames / 3,
                    &format!("sweep-attack-d-{:016x}-trial-{t}", d.to_bits()),
                )?
                .require_score("MI")?,
            );
        }
        rows.push(SweepRow {
            decoupling: d,
            corr_auc: auc(&sc, &clean_c),
            corr_ci: auc_ci(&sc, &clean_c, n_boot, cfg.base_seed),
            mi_auc: auc(&sp, &clean_p),
            mi_ci: auc_ci(&sp, &clean_p, n_boot, cfg.base_seed ^ 0xF),
            diff_ci: auc_diff_ci(&sc, &clean_c, &sp, &clean_p, n_boot, cfg.base_seed ^ 0xAB),
        });
    }
    Ok(rows)
}

/// Format the decoupling sweep as a plain-text table, with a data-driven verdict from
/// each paired `corr - MI` confidence interval. Public rows with non-finite, out-of-domain,
/// or unordered statistical fields are disclosed and omitted from the table and verdict.
pub fn format_sweep(rows: &[SweepRow]) -> String {
    let is_unit = |value: f64| value.is_finite() && (0.0..=1.0).contains(&value);
    let is_unit_interval = |interval: (f64, f64)| {
        is_unit(interval.0) && is_unit(interval.1) && interval.0 <= interval.1
    };
    let is_difference_interval = |interval: (f64, f64)| {
        interval.0.is_finite()
            && interval.1.is_finite()
            && (-1.0..=1.0).contains(&interval.0)
            && (-1.0..=1.0).contains(&interval.1)
            && interval.0 <= interval.1
    };
    let is_valid_row = |row: &SweepRow| {
        is_unit(row.decoupling)
            && is_unit(row.corr_auc)
            && is_unit_interval(row.corr_ci)
            && is_unit(row.mi_auc)
            && is_unit_interval(row.mi_ci)
            && is_difference_interval(row.diff_ci)
    };
    let valid_rows: Vec<&SweepRow> = rows.iter().filter(|row| is_valid_row(row)).collect();
    let invalid_rows: Vec<String> = rows
        .iter()
        .enumerate()
        .filter(|(_index, row)| !is_valid_row(row))
        .map(|(index, _row)| (index + 1).to_string())
        .collect();

    let mut s = String::new();
    s.push_str(
        "Decoupling-strength sweep — axis-0 AUC vs decoupling (the detection boundary)\n\
         d=1 full decouple (easiest) → d→0 weak decouple (hardest); corr retained ∝ √(1−d)\n\n",
    );
    s.push_str(&format!(
        "{:>5} | {:>21} | {:>21} | {:>18}\n",
        "d", "corr AUC [95% CI]", "MI AUC [95% CI]", "Δ(corr−MI) [95% CI]"
    ));
    s.push_str(&format!("{}\n", "-".repeat(74)));
    for r in &valid_rows {
        s.push_str(&format!(
            "{:>5.2} | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}] | {:+.3} [{:+.3},{:+.3}]\n",
            r.decoupling,
            r.corr_auc,
            r.corr_ci.0,
            r.corr_ci.1,
            r.mi_auc,
            r.mi_ci.0,
            r.mi_ci.1,
            r.corr_auc - r.mi_auc,
            r.diff_ci.0,
            r.diff_ci.1,
        ));
    }
    if rows.is_empty() {
        s.push_str(
            "\nNo sweep rows were sampled; no pointwise interval comparison is available.\n",
        );
        return s;
    }
    if !invalid_rows.is_empty() {
        s.push_str(&format!(
            "\nInvalid sweep rows at one-based positions {{{}}} were omitted from the table\n\
             and directional comparison.\n",
            invalid_rows.join(", ")
        ));
    }
    if valid_rows.is_empty() {
        s.push_str("\nNo valid pointwise interval comparison is available.\n");
        return s;
    }
    let correlation_band: Vec<String> = valid_rows
        .iter()
        .filter(|r| r.diff_ci.0 > 0.0)
        .map(|r| r.decoupling.to_string())
        .collect();
    let mi_band: Vec<String> = valid_rows
        .iter()
        .filter(|r| r.diff_ci.1 < 0.0)
        .map(|r| r.decoupling.to_string())
        .collect();
    if correlation_band.is_empty() && mi_band.is_empty() {
        let qualifier = if invalid_rows.is_empty() {
            "Every pointwise"
        } else {
            "Every valid pointwise"
        };
        s.push_str(&format!(
            "\n{qualifier} paired ΔAUC interval includes 0. The sweep provides no evidence\n\
             of a difference at any sampled strength.\n"
        ));
    } else {
        s.push_str("\nExploratory pointwise 95% intervals exclude 0 in these directions:\n");
        if !correlation_band.is_empty() {
            s.push_str(&format!(
                "  correlation > MI at d ∈ {{{}}}\n",
                correlation_band.join(", ")
            ));
        }
        if !mi_band.is_empty() {
            s.push_str(&format!(
                "  MI > correlation at d ∈ {{{}}}\n",
                mi_band.join(", ")
            ));
        }
        s.push_str(
            "Because this scans the grid without a simultaneous/max-statistic correction,\n\
             these are not confirmatory evidence of detector superiority anywhere on the boundary.\n",
        );
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
    /// Fraction whose MI graph separated the **honest** channel.
    pub mi_accuses_honest: f64,
    /// Wilson 95% CI for `mi_accuses_honest`.
    pub mi_ci: (f64, f64),
    /// Fraction with `SeparatedFromMajorityGraph`.
    pub mi_separation_rate: f64,
    /// Fraction whose MI graph disposition was unavailable.
    pub mi_unavailable_rate: f64,
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
    validate_full_mi_calls(cfg, n, "collusion MI quadratic fits")?;
    let honest = Modality::Visual;
    let colluders = [Modality::Radar, Modality::Acoustic];
    let start_frame = cfg.frames / 3;
    let start = start_frame as u64;
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

        let report = stationary_mi_report(&stream, start_frame, &format!("collusion-trial-{t}"))?;
        match report.disposition() {
            MiGraphDisposition::SeparatedFromMajorityGraph(modalities) => {
                p_fire += 1;
                p_acc += usize::from(modalities.contains(&honest));
            }
            MiGraphDisposition::Unavailable(_) => p_insufficient += 1,
            MiGraphDisposition::NoSeparationAtConfiguredThreshold => {}
        }
    }
    let nf = n as f64;
    Ok(CollusionResult {
        trials: n,
        corr_accuses_honest: c_acc as f64 / nf,
        corr_ci: wilson_ci(c_acc, n),
        mi_accuses_honest: p_acc as f64 / nf,
        mi_ci: wilson_ci(p_acc, n),
        mi_separation_rate: p_fire as f64 / nf,
        mi_unavailable_rate: p_insufficient as f64 / nf,
        corr_fires: c_fire as f64 / nf,
    })
}

/// Format the colluding-compromise study (mis-attribution rates with Wilson 95% CIs).
pub fn format_collusion(r: &CollusionResult) -> String {
    format!(
        "Colluding compromise axis 0 (2 of 3) — the honest-majority assumption FAILS ({} trials)\n\
         radar + acoustic share a phantom (mutually corroborate); visual is honest.\n\n\
         correlation flags the HONEST channel: {:.3} [{:.3},{:.3}]   (fires at all: {:.3})\n\
         MI graph   separates the HONEST channel: {:.3} [{:.3},{:.3}]   (separation: {:.3}; unavailable: {:.3})\n\n\
         With a colluding majority the 'consensus' is the liars' — the honest minority\n\
         decouples from it and is (mis-)accused. Cross-sensor majority attribution assumes an\n\
         honest majority. MI unavailability is fail-closed abstention, not evidence that this\n\
         structural assumption has been escaped.\n",
        r.trials,
        r.corr_accuses_honest,
        r.corr_ci.0,
        r.corr_ci.1,
        r.corr_fires,
        r.mi_accuses_honest,
        r.mi_ci.0,
        r.mi_ci.1,
        r.mi_separation_rate,
        r.mi_unavailable_rate,
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
    /// MI axis-0 score-threshold detection proportion at `d`.
    pub mi_detect: f64,
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
    /// MI axis-0 observed holdout FAR and Wilson interval.
    pub mi_holdout_far: RateInterval,
}

/// Invalid public input to [`evasion_ceiling`].
#[derive(Debug, Clone, Copy, PartialEq, Error)]
#[non_exhaustive]
pub enum EvasionCeilingError {
    #[error("evasion ceiling requires a non-empty grid")]
    EmptyGrid,
    #[error("detection tolerance must be finite and lie in [0,1]")]
    InvalidTolerance,
    #[error("row {index} has a non-finite or out-of-domain decoupling")]
    InvalidDecoupling { index: usize },
    #[error("row {index} has a non-finite or out-of-domain detection rate")]
    InvalidDetectionRate { index: usize },
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
    let mi_calls = decouplings
        .len()
        .checked_add(2)
        .and_then(|streams| streams.checked_mul(cfg.trials))
        .ok_or(EvalConfigError::WorkOverflow {
            context: "adaptive MI call count",
        })?;
    validate_full_mi_calls(cfg, mi_calls, "adaptive MI quadratic fits")?;
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
        cp.push(
            mi_evidence(&clean, 0, &format!("adaptive-calibration-clean-trial-{t}"))?
                .require_score("MI")?,
        );
    }
    cc.sort_by(f64::total_cmp);
    cp.sort_by(f64::total_cmp);
    let corr_thresh = quantile(&cc, 1.0 - far);
    let mi_thresh = quantile(&cp, 1.0 - far);

    let (mut corr_holdout_alarms, mut mi_holdout_alarms) = (0usize, 0usize);
    for t in 0..cfg.trials {
        let clean = build(
            Attack::Clean,
            cfg,
            adaptive_clean_seed(cfg, t, AdaptiveCleanArm::Holdout),
        )?;
        corr_holdout_alarms +=
            usize::from(corr_evidence(&clean)?.require_score("correlation")? > corr_thresh);
        mi_holdout_alarms += usize::from(
            mi_evidence(&clean, 0, &format!("adaptive-holdout-clean-trial-{t}"))?
                .require_score("MI")?
                > mi_thresh,
        );
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
            if mi_evidence(
                &stream,
                cfg.frames / 3,
                &format!("adaptive-attack-d-{:016x}-trial-{t}", d.to_bits()),
            )?
            .require_score("MI")?
                > mi_thresh
            {
                pd += 1;
            }
        }
        let nf = cfg.trials as f64;
        rows.push(AdaptiveRow {
            decoupling: d,
            corr_detect: cd as f64 / nf,
            mi_detect: pd as f64 / nf,
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
        mi_holdout_far: RateInterval {
            rate: mi_holdout_alarms as f64 / trials,
            ci: wilson_ci(mi_holdout_alarms, cfg.trials),
        },
    })
}

/// The evasion ceiling: the largest decoupling a detector still misses (detection ≤ `tau`) —
/// i.e. the most an adaptive adversary can inject undetected. `Ok(None)` means every
/// sampled point exceeded the tolerance; `Ok(Some(0.0))` means a sampled `d=0` point
/// was missed. Invalid or empty public rows fail explicitly.
pub fn evasion_ceiling(
    rows: &[AdaptiveRow],
    detect: impl Fn(&AdaptiveRow) -> f64,
    tau: f64,
) -> std::result::Result<Option<f64>, EvasionCeilingError> {
    if rows.is_empty() {
        return Err(EvasionCeilingError::EmptyGrid);
    }
    if !tau.is_finite() || !(0.0..=1.0).contains(&tau) {
        return Err(EvasionCeilingError::InvalidTolerance);
    }
    let mut largest: Option<f64> = None;
    for (index, row) in rows.iter().enumerate() {
        if !row.decoupling.is_finite() || !(0.0..=1.0).contains(&row.decoupling) {
            return Err(EvasionCeilingError::InvalidDecoupling { index });
        }
        let detection = detect(row);
        if !detection.is_finite() || !(0.0..=1.0).contains(&detection) {
            return Err(EvasionCeilingError::InvalidDetectionRate { index });
        }
        if detection <= tau {
            largest = Some(largest.map_or(row.decoupling, |value| value.max(row.decoupling)));
        }
    }
    Ok(largest)
}

/// Format the adaptive-adversary study, independent holdout FARs, and sampled ceilings.
pub fn format_adaptive(study: &AdaptiveStudy, tau: f64) -> String {
    let valid_interval = |value: RateInterval| {
        value.rate.is_finite()
            && value.ci.0.is_finite()
            && value.ci.1.is_finite()
            && (0.0..=1.0).contains(&value.rate)
            && (0.0..=1.0).contains(&value.ci.0)
            && (0.0..=1.0).contains(&value.ci.1)
            && value.ci.0 <= value.ci.1
    };
    if !study.target_far.is_finite()
        || !(0.0..=1.0).contains(&study.target_far)
        || study.calibration_trials == 0
        || study.holdout_trials == 0
        || !valid_interval(study.corr_holdout_far)
        || !valid_interval(study.mi_holdout_far)
    {
        return "Adaptive study unavailable: invalid target, denominator, rate, or interval.\n"
            .to_owned();
    }
    let corr_ceil = match evasion_ceiling(&study.rows, |row| row.corr_detect, tau) {
        Ok(value) => value,
        Err(error) => return format!("Adaptive study unavailable: {error}.\n"),
    };
    let mi_ceil = match evasion_ceiling(&study.rows, |row| row.mi_detect, tau) {
        Ok(value) => value,
        Err(error) => return format!("Adaptive study unavailable: {error}.\n"),
    };
    let ceiling = |value: Option<f64>| match value {
        Some(value) => format!("{value:.2}"),
        None => "none (all sampled points exceeded tolerance)".to_owned(),
    };
    let mut s = String::new();
    s.push_str(&format!(
        "Adaptive axis-0 score sweep — detection rate vs decoupling at target clean upper-tail {:.3}\n\
         thresholds fitted on {} clean trials; FAR evaluated on {} independently seeded clean trials\n\
         holdout FAR: corr {:.3} [{:.3},{:.3}] · MI {:.3} [{:.3},{:.3}] (Wilson 95%)\n\
         sampled-grid ceiling uses detection ≤ {tau:.2}\n\n",
        study.target_far,
        study.calibration_trials,
        study.holdout_trials,
        study.corr_holdout_far.rate,
        study.corr_holdout_far.ci.0,
        study.corr_holdout_far.ci.1,
        study.mi_holdout_far.rate,
        study.mi_holdout_far.ci.0,
        study.mi_holdout_far.ci.1,
    ));
    s.push_str(&format!(
        "{:>5} | {:>12} | {:>12}\n",
        "d", "corr detect", "MI detect"
    ));
    s.push_str(&format!("{}\n", "-".repeat(35)));
    for r in &study.rows {
        s.push_str(&format!(
            "{:>5.2} | {:>12.3} | {:>12.3}\n",
            r.decoupling, r.corr_detect, r.mi_detect
        ));
    }
    s.push_str(&format!(
        "\nObserved sampled-grid ceiling: correlation {}   MI {}\n",
        ceiling(corr_ceil),
        ceiling(mi_ceil),
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
/// trials where signed correlation flags a decoupling (a false positive), at a
/// given per-channel lag. The time-varying maneuver is not submitted to the
/// fixed-law i.i.d. MI companion.
#[derive(Debug, Clone)]
pub struct ManeuverRow {
    /// Per-channel lag step (0 = a synchronized maneuver; larger = more heterogeneous).
    pub lag_step: u64,
    /// Correlation-default false-decoupling rate under the maneuver.
    pub corr_far: f64,
}

/// Measure the axis-0 signed-correlation **false-alarm rate under a benign
/// maneuver** (no spoof), sweeping the per-channel lag. A synchronized maneuver
/// (`lag_step = 0`) keeps channels correlated and should not trip the consistency
/// check. Heterogeneous lags are measured as a possible false-positive source
/// rather than assumed to cross a detector threshold. We count a **decoupling**
/// flag (not the broad NIS-degradation evidence a coherent maneuver legitimately
/// raises), isolating the cross-sensor false positive. MI is deliberately absent:
/// one time-varying maneuver window does not satisfy its declared fixed-law i.i.d.
/// input contract.
pub fn maneuver_far(
    cfg: &EvalConfig,
    lag_steps: &[u64],
    magnitude: f64,
    duration: u64,
) -> CoreResult<Vec<ManeuverRow>> {
    validate_maneuver_inputs(cfg, lag_steps, magnitude, duration)?;
    validate_grid_work(cfg, lag_steps.len())?;
    let start = (cfg.frames as u64) / 3;
    let mut rows = Vec::with_capacity(lag_steps.len());
    for &lag_step in lag_steps {
        let mut cf = 0usize;
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
        }
        let nf = cfg.trials as f64;
        rows.push(ManeuverRow {
            lag_step,
            corr_far: cf as f64 / nf,
        });
    }
    Ok(rows)
}

/// Format the maneuver false-alarm study.
pub fn format_maneuver(rows: &[ManeuverRow], magnitude: f64, duration: u64) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Non-stationary response — axis 0 · a BENIGN {magnitude:.0}σ maneuver over {duration} frames, per-channel lag\n\
         signed-correlation false-decoupling rate (isolated from broad NIS degradation)\n\n"
    ));
    s.push_str(&format!("{:>8} | {:>11}\n", "lag_step", "corr FAR"));
    s.push_str(&format!("{}\n", "-".repeat(23)));
    for r in rows {
        s.push_str(&format!("{:>8} | {:>11.3}\n", r.lag_step, r.corr_far));
    }
    if let Some(r0) = rows.iter().find(|r| r.lag_step == 0) {
        s.push_str(&format!(
            "\nObserved synchronized (lag 0) correlation false-decoupling rate: {:.3}.\n",
            r0.corr_far
        ));
        s.push_str(
            "Rows are descriptive for this maneuver model and grid. MI is not evaluated because\n\
             the time-varying episode does not satisfy its declared fixed-law i.i.d. contract.\n",
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

/// Format the modeled perturbation study. Public rows with non-finite or out-of-domain
/// values are disclosed and omitted from the table and threshold partitions.
pub fn format_attacker_gain(rows: &[AttackerGainRow], detect_tol: f64) -> String {
    let is_unit = |value: f64| value.is_finite() && (0.0..=1.0).contains(&value);
    let is_valid_row = |row: &AttackerGainRow| {
        is_unit(row.decoupling)
            && row.fused_perturbation_rms.is_finite()
            && row.fused_perturbation_rms >= 0.0
            && is_unit(row.detect_rate)
    };
    let valid_rows: Vec<&AttackerGainRow> = rows.iter().filter(|row| is_valid_row(row)).collect();
    let invalid_rows: Vec<String> = rows
        .iter()
        .enumerate()
        .filter(|(_index, row)| !is_valid_row(row))
        .map(|(index, _row)| (index + 1).to_string())
        .collect();

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
    for r in &valid_rows {
        s.push_str(&format!(
            "{:>5.2} | {:>16.3} | {:>12}\n",
            r.decoupling, r.fused_perturbation_rms, r.detect_rate
        ));
    }
    if !invalid_rows.is_empty() {
        s.push_str(&format!(
            "\nInvalid modeled-impact rows at one-based positions {{{}}} were omitted from\n\
             the table and threshold partitions.\n",
            invalid_rows.join(", ")
        ));
    }
    if !is_unit(detect_tol) {
        s.push_str(
            "\nDetection tolerance is not a finite probability in [0, 1]; sampled threshold\n\
             partitions are unavailable.\n\
             These are descriptive grid results, not an operational safety bound.\n",
        );
        return s;
    }
    let missing_partition = if invalid_rows.is_empty() {
        "none sampled"
    } else {
        "none sampled among valid rows"
    };
    // Largest sampled perturbation at or below the detection tolerance.
    let undetected = valid_rows
        .iter()
        .filter(|r| r.detect_rate <= detect_tol)
        .map(|r| r.fused_perturbation_rms)
        .reduce(f64::max)
        .map(|value| format!("{value:.3} σ"))
        .unwrap_or_else(|| missing_partition.to_owned());
    let detected_min = valid_rows
        .iter()
        .filter(|r| r.detect_rate > detect_tol)
        .map(|r| r.fused_perturbation_rms)
        .reduce(f64::min)
        .map(|value| format!("{value:.3} σ"))
        .unwrap_or_else(|| missing_partition.to_owned());
    s.push_str(&format!(
        "\nLargest sampled RMS perturbation with detection ≤ {detect_tol}: {undetected}.\n\
         Smallest sampled RMS perturbation above that detection tolerance: {detected_min}.\n\
         These are descriptive grid results, not an operational safety bound.\n",
    ));
    s
}

/// Per-attack metrics for the component studies and authoritative core default.
///
/// Standalone correlation and MI fields are pre-registered projection-axis-0
/// component metrics; core-default fields evaluate every attested correlation axis.
#[derive(Debug, Clone)]
pub struct AttackMetrics {
    /// Which regime.
    pub attack: Attack,
    /// Baseline detection rate.
    pub baseline_rate: f64,
    /// Signed-correlation axis-0 consistency detection rate.
    pub corr_rate: f64,
    /// MI axis-0 descriptive majority-graph separation-event rate.
    pub mi_separation_rate: f64,
    /// Authoritative core-default (baseline plus signed correlation) detection rate.
    pub default_rate: f64,
    /// Wilson 95% intervals for the four detection rates in the same order.
    pub detection_ci: FourDetectorIntervals,
    /// Explicit insufficient-evidence rates on the fixed trial denominator
    /// (baseline, signed correlation, MI, core default).
    pub insufficient_rate: (f64, f64, f64, f64),
    /// Fraction of trials contributing a continuous AUC score (baseline,
    /// signed correlation, MI).
    pub score_availability: (f64, f64, f64),
    /// Baseline ROC-AUC vs clean.
    pub baseline_auc: f64,
    /// Signed-correlation axis-0 component ROC-AUC vs clean.
    pub corr_auc: f64,
    /// MI axis-0 ROC-AUC vs clean, conditional on an available graph event and score.
    pub mi_auc: f64,
    /// Worst/best MI AUC if every unavailable attack/clean score is ranked
    /// adversarially, without a missing-at-random assumption.
    pub mi_auc_missingness_bounds: (f64, f64),
    /// Correlation AUC on trials where both correlation and MI supplied scores.
    pub corr_auc_on_mi_complete_cases: f64,
    /// MI AUC recomputed on the same joint-complete trials as the preceding field.
    pub mi_auc_on_corr_complete_cases: f64,
    /// Joint-complete attack and clean counts used by both preceding AUCs.
    pub mi_complete_case_counts: (usize, usize),
}

/// Confidence intervals ordered as baseline, correlation axis 0, MI axis 0, and core default.
pub type FourDetectorIntervals = ((f64, f64), (f64, f64), (f64, f64), (f64, f64));

/// Full evaluation results.
#[derive(Debug, Clone)]
pub struct EvalResults {
    /// The config used.
    pub cfg: EvalConfig,
    /// Versioned evaluation composition and stationary-phase protocol.
    pub evaluation_protocol_id: String,
    /// Complete accepted MI-companion configuration identity, including the
    /// pinned pid-rs revision and declared continuous law.
    pub mi_config_identity: String,
    /// Versioned graph-event composition used by MI event rates.
    pub mi_event_protocol_id: String,
    /// Versioned continuous-score composition used by MI ranking studies.
    pub mi_score_protocol_id: String,
    /// Baseline false-alarm rate (on clean).
    pub baseline_far: f64,
    /// Correlation axis-0 component false-alarm rate (on clean).
    pub corr_far: f64,
    /// MI axis-0 descriptive majority-graph separation-event rate on clean trials.
    pub mi_clean_separation_rate: f64,
    /// Authoritative core-default false-alarm rate (on clean).
    pub default_far: f64,
    /// Wilson 95% intervals for the four clean false-alarm rates in the same order.
    pub far_ci: FourDetectorIntervals,
    /// Explicit insufficient-evidence rates on clean trials (baseline,
    /// signed correlation, MI, core default).
    pub clean_insufficient_rate: (f64, f64, f64, f64),
    /// Fraction of clean trials contributing a continuous AUC score (baseline,
    /// signed correlation, MI).
    pub clean_score_availability: (f64, f64, f64),
    /// Metrics for the three attack regimes.
    pub per_attack: Vec<AttackMetrics>,
}

/// Run the Monte-Carlo evaluation.
pub fn run(cfg: &EvalConfig) -> CoreResult<EvalResults> {
    validate_observation_work(cfg.trials, cfg.frames, Attack::ALL.len())?;
    let mi_calls =
        cfg.trials
            .checked_mul(Attack::ALL.len())
            .ok_or(EvalConfigError::WorkOverflow {
                context: "main evaluation MI call count",
            })?;
    validate_full_mi_calls(cfg, mi_calls, "main evaluation MI quadratic fits")?;
    let mi_config_identity = mi_research_config()?.identity().to_hex();
    let mut b_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut c_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut p_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut c_on_p_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut p_on_c_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
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
        let mut cs_on_p = Vec::with_capacity(cfg.trials);
        let mut ps_on_c = Vec::with_capacity(cfg.trials);
        let (mut ba, mut ca, mut pa, mut fa) = (0usize, 0usize, 0usize, 0usize);
        let (mut bi, mut ci, mut pi, mut fi) = (0usize, 0usize, 0usize, 0usize);
        for t in 0..cfg.trials {
            let (scope, stream) = build_scoped(attack, cfg, attack_seed(cfg, t, attack))?;
            let episode_label = format!("main-{}-trial-{t}", attack.identity());
            let [b, c, p] =
                component_evaluations(&stream, attack.stationary_start_frame(cfg), &episode_label)?;
            if let Some(score) = b.score {
                bs.push(score);
            }
            if let Some(alarm) = b.alarm {
                ba += usize::from(alarm);
            } else {
                bi += 1;
            }
            let corr_score = c.score;
            if let Some(score) = corr_score {
                cs.push(score);
            }
            if let Some(alarm) = c.alarm {
                ca += usize::from(alarm);
            } else {
                ci += 1;
            }
            if let Some(score) = p.score {
                ps.push(score);
                if let Some(corr_score) = corr_score {
                    cs_on_p.push(corr_score);
                    ps_on_c.push(score);
                }
            }
            if let Some(alarm) = p.alarm {
                pa += usize::from(alarm);
            } else {
                pi += 1;
            }
            match default_eval(&scope, &stream)? {
                Some(alarm) => fa += usize::from(alarm),
                None => fi += 1,
            }
        }
        b_scores.insert(attack, bs);
        c_scores.insert(attack, cs);
        p_scores.insert(attack, ps);
        c_on_p_scores.insert(attack, cs_on_p);
        p_on_c_scores.insert(attack, ps_on_c);
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
    let clean_c_on_p = &c_on_p_scores[&Attack::Clean];
    let clean_p_on_c = &p_on_c_scores[&Attack::Clean];
    let per_attack = Attack::ALL
        .iter()
        .filter(|a| **a != Attack::Clean)
        .map(|&a| {
            let mi_auc = auc(&p_scores[&a], clean_p);
            AttackMetrics {
                attack: a,
                baseline_rate: b_alarms[&a] as f64 / n,
                corr_rate: c_alarms[&a] as f64 / n,
                mi_separation_rate: p_alarms[&a] as f64 / n,
                default_rate: f_alarms[&a] as f64 / n,
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
                mi_auc,
                mi_auc_missingness_bounds: auc_missingness_bounds(
                    mi_auc,
                    p_scores[&a].len(),
                    clean_p.len(),
                    cfg.trials,
                    cfg.trials,
                ),
                corr_auc_on_mi_complete_cases: auc(&c_on_p_scores[&a], clean_c_on_p),
                mi_auc_on_corr_complete_cases: auc(&p_on_c_scores[&a], clean_p_on_c),
                mi_complete_case_counts: (p_on_c_scores[&a].len(), clean_p_on_c.len()),
            }
        })
        .collect();

    Ok(EvalResults {
        evaluation_protocol_id: EVALUATION_PROTOCOL_ID.to_owned(),
        mi_config_identity,
        mi_event_protocol_id: MI_EVENT_PROTOCOL_ID.to_owned(),
        mi_score_protocol_id: MI_SCORE_PROTOCOL_ID.to_owned(),
        baseline_far: b_alarms[&Attack::Clean] as f64 / n,
        corr_far: c_alarms[&Attack::Clean] as f64 / n,
        mi_clean_separation_rate: p_alarms[&Attack::Clean] as f64 / n,
        default_far: f_alarms[&Attack::Clean] as f64 / n,
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
        "protocol={}\nMI config SHA-256={}\nMI event={}\nMI score={}\n",
        r.evaluation_protocol_id,
        r.mi_config_identity,
        r.mi_event_protocol_id,
        r.mi_score_protocol_id,
    ));
    s.push_str(&format!(
        "Clean rates: baseline FAR {:.3}   corr-ax0 FAR {:.3}   MI-ax0 graph separation {:.3}   core-default FAR {:.3}\n\n",
        r.baseline_far, r.corr_far, r.mi_clean_separation_rate, r.default_far
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
        "Insufficient rate (clean):  baseline {:.3}   corr-ax0 {:.3}   MI-ax0 {:.3}   core-default {:.3}\n\n",
        r.clean_insufficient_rate.0,
        r.clean_insufficient_rate.1,
        r.clean_insufficient_rate.2,
        r.clean_insufficient_rate.3,
    ));
    s.push_str(&format!(
        "AUC-score availability:     baseline {:.3}   corr-ax0 {:.3}   MI-ax0 {:.3}\n\n",
        r.clean_score_availability.0, r.clean_score_availability.1, r.clean_score_availability.2,
    ));
    s.push_str(&format!(
        "{:<28} | {:>8} | {:>8} | {:>7} | {:>9} | {:>8} | {:>8} | {:>7}\n",
        "regime",
        "base det",
        "corr det",
        "MI sep.",
        "core default",
        "base AUC",
        "corr AUC",
        "MI AUC"
    ));
    s.push_str(&format!("{}\n", "-".repeat(104)));
    for m in &r.per_attack {
        s.push_str(&format!(
            "{:<28} | {:>8.3} | {:>8.3} | {:>7.3} | {:>9.3} | {:>8.3} | {:>8.3} | {:>7.3}\n",
            m.attack.label(),
            m.baseline_rate,
            m.corr_rate,
            m.mi_separation_rate,
            m.default_rate,
            m.baseline_auc,
            m.corr_auc,
            m.mi_auc,
        ));
        s.push_str(&format!(
            "  unavailable (base/corr/MI/core-default): {:.3}/{:.3}/{:.3}/{:.3}\n",
            m.insufficient_rate.0,
            m.insufficient_rate.1,
            m.insufficient_rate.2,
            m.insufficient_rate.3,
        ));
        s.push_str(&format!(
            "  detection/separation Wilson CIs: [{:.3},{:.3}] [{:.3},{:.3}] [{:.3},{:.3}] [{:.3},{:.3}]\n",
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
            "  score available (base/corr/MI): {:.3}/{:.3}/{:.3}\n",
            m.score_availability.0, m.score_availability.1, m.score_availability.2,
        ));
        s.push_str(&format!(
            "  MI AUC is availability-conditional; arbitrary-missing-score bounds: [{:.3},{:.3}]\n\
             joint-complete corr/MI AUC: {:.3}/{:.3} on {}/{} attack/clean trials\n",
            m.mi_auc_missingness_bounds.0,
            m.mi_auc_missingness_bounds.1,
            m.corr_auc_on_mi_complete_cases,
            m.mi_auc_on_corr_complete_cases,
            m.mi_complete_case_counts.0,
            m.mi_complete_case_counts.1,
        ));
    }
    s.push_str(
        "\ncorr/MI standalone metrics = registered consistency-projection axis 0; core-default = baseline plus all correlation axes. MI is companion evidence only.\n\
         corr = signed-correlation consistency component; MI = pairwise KSG-MI companion.\n\
         Clean MI uses the configured stationary tail; attack MI uses only the fixed-parameter post-onset phase.\n\
         Rates use all configured trials; insufficient-evidence rates are shown separately.\n\
         MI AUC alarm-ranks only available graph events, then uses the positive-reference signed-estimate spread score.\n\
         It is a selection-conditional AUC, not a fixed-denominator classifier AUC. Each regime row\n\
         gives assumption-free worst/best missing-score bounds and both scores on their identical\n\
         joint-complete subset; the all-case correlation AUC answers a different denominator question.\n",
    );
    s
}

// ---------------------------------------------------------------------------
// Accepted-alarm latency and descriptive MI separation-event latency
// ---------------------------------------------------------------------------

/// Median latency on growing prefixes. Baseline and correlation fields measure the
/// first accepted alarm. The MI field resets at the true simulated onset and measures
/// the first uncalibrated posthoc graph-separation event; it is not an online or
/// security-detection latency.
#[derive(Debug, Clone)]
pub struct AttackLatency {
    /// Which regime.
    pub attack: Attack,
    /// Median frames-to-detect for the NIS baseline.
    pub baseline_ttd: Option<f64>,
    /// Median frames-to-detect for the correlation axis-0 component.
    pub corr_ttd: Option<f64>,
    /// Median frames from the true simulated onset to the first MI graph-separation
    /// event after resetting the MI rows at that oracle onset.
    pub mi_oracle_segmented_separation_latency: Option<f64>,
    /// Earliest delay at which the MI profile has enough post-onset rows to be
    /// eligible, independent of the requested probe step.
    pub mi_first_eligible_delay_frames: usize,
    /// Fraction with a post-onset accepted alarm (baseline/correlation) or MI
    /// separation event, with no corresponding sampled pre-onset event.
    pub reach: (f64, f64, f64),
    /// Fraction of trials with a sampled pre-onset alarm (baseline/correlation)
    /// or descriptive MI separation event.
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

/// Measure accepted-alarm and descriptive MI separation-event latency over
/// `trials` seeds, probing prefixes every `step` frames and the final capture.
/// Correlation and MI are pre-registered to projection axis 0. Post-onset MI
/// inputs are oracle-segmented at the true simulated onset; they do not model an
/// online reset rule. No event yields `None`; MI is not relabeled as an alarm.
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
    validate_mi_work_limit(
        latency_mi_work(cfg, trials, step)?,
        "latency MI quadratic fits",
    )?;
    let onset = cfg.frames / 3;
    let mut rows = Vec::with_capacity(Attack::ALL.len() - 1);
    for &attack in Attack::ALL
        .iter()
        .filter(|attack| **attack != Attack::Clean)
    {
        let (mut baseline_ttd, mut corr_ttd, mut mi_oracle_segmented_separation_latency) =
            (Vec::new(), Vec::new(), Vec::new());
        let (mut baseline_reach, mut corr_reach, mut mi_reach) = (0usize, 0usize, 0usize);
        let (mut baseline_false, mut corr_false, mut mi_false) = (0usize, 0usize, 0usize);
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
                let prefix_frames = prefix.len() / MODALITIES.len();
                let stationary_start = if prefix_frames <= onset { 0 } else { onset };
                mi_evidence(
                    prefix,
                    stationary_start,
                    &format!(
                        "latency-{}-trial-{trial}-prefix-{prefix_frames}",
                        attack.identity()
                    ),
                )
                .map(|result| result.alarm == Some(true))
            })? {
                TtdOutcome::Detected(delay) => {
                    mi_oracle_segmented_separation_latency.push(delay);
                    mi_reach += 1;
                }
                TtdOutcome::FalseStart => mi_false += 1,
                TtdOutcome::Never => {}
            }
        }
        let trial_count = trials as f64;
        rows.push(AttackLatency {
            attack,
            baseline_ttd: median(&mut baseline_ttd),
            corr_ttd: median(&mut corr_ttd),
            mi_oracle_segmented_separation_latency: median(
                &mut mi_oracle_segmented_separation_latency,
            ),
            mi_first_eligible_delay_frames: mi_research_config()?
                .required_samples()
                .saturating_sub(1),
            reach: (
                baseline_reach as f64 / trial_count,
                corr_reach as f64 / trial_count,
                mi_reach as f64 / trial_count,
            ),
            false_start_rate: (
                baseline_false as f64 / trial_count,
                corr_false as f64 / trial_count,
                mi_false as f64 / trial_count,
            ),
        });
    }
    Ok(rows)
}

/// Format accepted-alarm and descriptive MI separation-event latency.
pub fn format_latency(rows: &[AttackLatency], trials: usize, step: usize) -> String {
    let cell = |t: Option<f64>, reach: f64| match t {
        Some(v) => format!("{v:>4.0}f ({:>3.0}%)", reach * 100.0),
        None => format!("{:>5} ({:>3.0}%)", "—", reach * 100.0),
    };
    let mut s = String::new();
    s.push_str(&format!(
        "Latency — accepted axis-0 alarms and oracle-segmented MI graph separation\n\
         {trials} trials/regime · prefix step {step} frames · 100 ms/frame · '—' = no qualifying post-onset event\n\n"
    ));
    s.push_str(&format!(
        "{:<28} | {:>12} | {:>12} | {:>12}\n",
        "regime", "baseline alarm", "corr alarm", "MI separation"
    ));
    s.push_str(&format!("{}\n", "-".repeat(74)));
    for r in rows {
        s.push_str(&format!(
            "{:<28} | {} | {} | {}\n",
            r.attack.label(),
            cell(r.baseline_ttd, r.reach.0),
            cell(r.corr_ttd, r.reach.1),
            cell(r.mi_oracle_segmented_separation_latency, r.reach.2),
        ));
        s.push_str(&format!(
            "  pre-onset events (base/corr/MI-separation): {:.1}%/{:.1}%/{:.1}%\n",
            r.false_start_rate.0 * 100.0,
            r.false_start_rate.1 * 100.0,
            r.false_start_rate.2 * 100.0,
        ));
        s.push_str(&format!(
            "  MI first eligible post-onset delay: {} frames (before probe-step rounding); uncalibrated event, not an alarm\n",
            r.mi_first_eligible_delay_frames,
        ));
    }
    s.push_str(
        "\nMI is a posthoc sensitivity statistic: it resets its sample at the known simulated attack onset. It is not an online latency and is not directly comparable to the two alarm columns.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_contains_exact_proportion(k: usize, n: usize, lower: f64, upper: f64) {
        use std::cmp::Ordering::{Greater, Less};

        assert!(
            lower.is_finite() && upper.is_finite() && (0.0..=1.0).contains(&lower),
            "invalid lower endpoint for {k}/{n}: {lower}"
        );
        assert!(
            (0.0..=1.0).contains(&upper) && lower <= upper,
            "invalid interval for {k}/{n}: [{lower}, {upper}]"
        );
        assert_ne!(
            compare_f64_to_proportion(lower, k, n),
            Greater,
            "lower endpoint exceeds exact {k}/{n}: {lower}"
        );
        assert_ne!(
            compare_f64_to_proportion(upper, k, n),
            Less,
            "upper endpoint is below exact {k}/{n}: {upper}"
        );
    }

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

    fn sweep_row(decoupling: f64, diff_ci: (f64, f64)) -> SweepRow {
        SweepRow {
            decoupling,
            corr_auc: 0.4,
            corr_ci: (0.3, 0.5),
            mi_auc: 0.6,
            mi_ci: (0.5, 0.7),
            diff_ci,
        }
    }

    fn attacker_gain_row(rms: f64, detect_rate: f64) -> AttackerGainRow {
        AttackerGainRow {
            decoupling: 0.5,
            fused_perturbation_rms: rms,
            detect_rate,
        }
    }

    #[test]
    fn attacker_gain_formatter_does_not_invent_missing_partitions() {
        let undetected = format_attacker_gain(&[attacker_gain_row(2.0, 0.1)], 0.5);
        assert!(undetected.contains("detection ≤ 0.5: 2.000 σ"));
        assert!(undetected.contains("above that detection tolerance: none sampled"));

        let detected = format_attacker_gain(&[attacker_gain_row(1.0, 0.9)], 0.5);
        assert!(detected.contains("detection ≤ 0.5: none sampled"));
        assert!(detected.contains("above that detection tolerance: 1.000 σ"));

        let mixed = format_attacker_gain(
            &[
                attacker_gain_row(0.8, 0.1),
                attacker_gain_row(1.4, 0.4),
                attacker_gain_row(2.1, 0.8),
                attacker_gain_row(1.7, 0.7),
            ],
            0.5,
        );
        assert!(mixed.contains("detection ≤ 0.5: 1.400 σ"));
        assert!(mixed.contains("above that detection tolerance: 1.700 σ"));

        let inverted = format_attacker_gain(
            &[attacker_gain_row(2.0, 0.1), attacker_gain_row(1.0, 0.9)],
            0.5,
        );
        assert!(inverted.contains("detection ≤ 0.5: 2.000 σ"));
        assert!(inverted.contains("above that detection tolerance: 1.000 σ"));

        let precise = format_attacker_gain(&[attacker_gain_row(1.0, 0.008)], 0.005);
        assert!(precise.contains("detection ≤ 0.005: none sampled"));
        assert!(precise.contains("above that detection tolerance: 1.000 σ"));
        assert!(!precise.contains("detection ≤ 0.01"));

        let empty = format_attacker_gain(&[], 0.5);
        assert_eq!(empty.matches("none sampled").count(), 2);

        let nonfinite = format_attacker_gain(&[attacker_gain_row(1.0, 0.5)], f64::NAN);
        assert!(nonfinite.contains("not a finite probability in [0, 1]"));
        assert!(!nonfinite.contains("none sampled"));

        let out_of_range = format_attacker_gain(&[attacker_gain_row(1.0, 0.5)], 1.1);
        assert!(out_of_range.contains("not a finite probability in [0, 1]"));

        let mut invalid_decoupling = attacker_gain_row(1.0, 0.5);
        invalid_decoupling.decoupling = f64::NAN;
        let invalid_rows = format_attacker_gain(
            &[
                attacker_gain_row(1.0, f64::NAN),
                attacker_gain_row(-1.0, 0.5),
                invalid_decoupling,
            ],
            0.5,
        );
        assert!(invalid_rows.contains("positions {1, 2, 3}"));
        assert_eq!(
            invalid_rows
                .matches("none sampled among valid rows")
                .count(),
            2
        );
        assert!(!invalid_rows.contains("NaN"));
        assert!(!invalid_rows.contains("-1.000"));
    }

    #[test]
    fn sweep_formatter_reports_each_excluding_interval_direction() {
        let negative = format_sweep(&[sweep_row(0.5, (-0.9, -0.7))]);
        assert!(negative.contains("MI > correlation at d ∈ {0.5}"));
        assert!(!negative.contains("Every pointwise"));

        let positive = format_sweep(&[sweep_row(0.6, (0.1, 0.3))]);
        assert!(positive.contains("correlation > MI at d ∈ {0.6}"));
        assert!(!positive.contains("Every pointwise"));

        let mixed = format_sweep(&[sweep_row(0.7, (0.1, 0.3)), sweep_row(0.2, (-0.4, -0.1))]);
        assert!(mixed.contains("correlation > MI at d ∈ {0.7}"));
        assert!(mixed.contains("MI > correlation at d ∈ {0.2}"));
        assert!(mixed.contains("not confirmatory"));

        let touching = format_sweep(&[sweep_row(0.8, (0.0, 0.2)), sweep_row(0.1, (-0.2, 0.0))]);
        assert!(touching.contains("Every pointwise paired ΔAUC interval includes 0"));

        let malformed = format_sweep(&[sweep_row(0.5, (0.2, -0.2))]);
        assert!(malformed.contains("Invalid sweep rows at one-based positions {1}"));
        assert!(malformed.contains("No valid pointwise interval comparison"));
        assert!(!malformed.contains("correlation > MI"));
        assert!(!malformed.contains("MI > correlation"));

        let invalid_rows = format_sweep(&[
            sweep_row(f64::NAN, (0.1, 0.2)),
            sweep_row(0.5, (f64::NAN, 0.2)),
            sweep_row(0.5, (2.0, 3.0)),
        ]);
        assert!(invalid_rows.contains("positions {1, 2, 3}"));
        assert!(invalid_rows.contains("No valid pointwise interval comparison"));
        assert!(!invalid_rows.contains("NaN"));
        assert!(!invalid_rows.contains("correlation > MI"));
        assert!(!invalid_rows.contains("MI > correlation"));

        let empty = format_sweep(&[]);
        assert!(empty.contains("No sweep rows were sampled"));
        assert!(!empty.contains("Every pointwise"));
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
        for frames in [0, MIN_EVALUATION_FRAMES - 1, 10_001, usize::MAX] {
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
        // This is a deterministic regression witness, not the publication
        // study. Keep it at the admitted inferential minimum so the complete
        // workspace gate remains bounded on the two-core hosted runner; the
        // public study profile and evidence runner retain their larger counts.
        let r = run(&config(|params| {
            params.trials = MIN_INFERENCE_TRIALS;
            params.frames = MIN_EVALUATION_FRAMES;
        }))
        .expect("valid evaluation");

        // Every detector is quiet on the null.
        assert!(r.baseline_far < 0.1, "baseline FAR {:.3}", r.baseline_far);
        assert!(r.corr_far < 0.1, "corr-default FAR {:.3}", r.corr_far);
        assert!(
            r.mi_clean_separation_rate < 0.1,
            "clean MI graph separation {:.3}",
            r.mi_clean_separation_rate
        );
        assert!(r.default_far < 0.1, "core-default FAR {:.3}", r.default_far);

        // Fixed-seed regression for this modeled stream: the strict MI graph event is
        // present in most trials, while the magnitude baseline is largely blind. The
        // threshold is a fixture guard, not an operational detection guarantee.
        let st = metrics(&r, Attack::Stealthy);
        assert!(
            st.mi_separation_rate >= 0.75,
            "MI graph event rate {:.3}",
            st.mi_separation_rate
        );
        assert!(
            st.baseline_rate < 0.2,
            "baseline stealthy detection {:.3}",
            st.baseline_rate
        );
        assert!(st.mi_auc > 0.85, "MI stealthy AUC {:.3}", st.mi_auc);
        assert!(
            st.baseline_auc < 0.75,
            "baseline stealthy AUC {:.3}",
            st.baseline_auc
        );

        // On this linear-Gaussian stealthy spoof the cheap axis-0 correlation component
        // is sufficient; this study does not establish a need for MI here.
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

        // The authoritative core default covers all three modeled attacks.
        for a in [Attack::LoudSpoof, Attack::Stealthy, Attack::Jam] {
            assert!(
                metrics(&r, a).default_rate > 0.8,
                "{a:?} core-default {:.3}",
                metrics(&r, a).default_rate
            );
        }
    }

    #[test]
    fn auc_basics() {
        assert!((auc(&[1.0, 2.0, 3.0], &[0.0, 0.5]) - 1.0).abs() < 1e-9);
        assert!((auc(&[0.0], &[0.0]) - 0.5).abs() < 1e-9);
        assert!((auc(&[2.0, 1.0], &[1.0, 0.0]) - 0.875).abs() < 1e-9);
    }

    #[test]
    fn degenerate_correlation_axis_withholds_the_evaluation_score() {
        let cfg = config(|params| params.frames = MIN_EVALUATION_FRAMES);
        let stream = build(Attack::Clean, &cfg, 17).expect("valid synthetic stream");
        let stream = stream
            .into_iter()
            .map(|observation| {
                let source = observation
                    .consistency_projection()
                    .expect("synthetic observation has a projection");
                let values = if observation.modality() == Modality::Acoustic {
                    [0.0; galadriel_core::MAX_CONSISTENCY_PROJECTION_AXES]
                } else {
                    source.padded_values()
                };
                let projection = galadriel_core::ConsistencyProjection::try_new(
                    values,
                    source.dimensions(),
                    source.identity(),
                )
                .expect("replacement projection is valid");
                PidObservation::try_scalar(
                    observation.track_id(),
                    observation.timestamp_ms(),
                    observation.sequence(),
                    observation.modality(),
                    observation.nis(),
                    observation.dof(),
                )
                .expect("replacement observation is valid")
                .with_consistency_projection(projection)
            })
            .collect::<Vec<_>>();

        let evidence = corr_evidence(&stream).expect("degenerate input must abstain");

        assert_eq!(evidence.alarm, None);
        assert_eq!(evidence.score, None);
    }

    #[test]
    fn unavailable_mi_graph_withholds_alarm_and_evaluation_score() {
        let cfg = config(|params| params.frames = MIN_EVALUATION_FRAMES);
        let stream = build(Attack::Clean, &cfg, 17).expect("valid synthetic stream");
        let stream = stream
            .into_iter()
            .map(|observation| {
                let source = observation
                    .consistency_projection()
                    .expect("synthetic observation has a projection");
                let values = if observation.modality() == Modality::Acoustic {
                    [0.0; galadriel_core::MAX_CONSISTENCY_PROJECTION_AXES]
                } else {
                    source.padded_values()
                };
                let projection = galadriel_core::ConsistencyProjection::try_new(
                    values,
                    source.dimensions(),
                    source.identity(),
                )
                .expect("replacement projection is valid");
                PidObservation::try_scalar(
                    observation.track_id(),
                    observation.timestamp_ms(),
                    observation.sequence(),
                    observation.modality(),
                    observation.nis(),
                    observation.dof(),
                )
                .expect("replacement observation is valid")
                .with_consistency_projection(projection)
            })
            .collect::<Vec<_>>();

        let evidence =
            mi_evidence(&stream, 0, "test-degenerate").expect("degenerate MI input must abstain");

        assert_eq!(evidence.alarm, None);
        assert_eq!(evidence.score, None);
    }

    #[test]
    fn ttd_probes_non_aligned_final_capture_frame_once() {
        let cfg = config(|params| {
            params.trials = MIN_INFERENCE_TRIALS;
            params.frames = MIN_EVALUATION_FRAMES;
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
        // The full evidence route uses the configured cadence. This fixed-seed
        // witness uses the minimum admitted capture and a sparse, explicitly
        // reported probe cadence; it still exercises pre-onset false starts,
        // one intermediate probe past the 72-row MI eligibility boundary,
        // final-frame probing, and every attack-ownership row without turning
        // CI into a long study. The separate schedule tests cover denser and
        // non-aligned intermediate probes.
        let cfg = config(|params| params.frames = MIN_EVALUATION_FRAMES);
        let rows = measure_latency(&cfg, MIN_INFERENCE_TRIALS, cfg.frames / 3)
            .expect("valid latency study");

        let st = rows.iter().find(|r| r.attack == Attack::Stealthy).unwrap();
        // The cross-sensor detectors detect the stealthy spoof at a finite latency…
        assert!(
            st.corr_ttd.is_some(),
            "corr should detect the stealthy spoof"
        );
        assert!(
            st.mi_oracle_segmented_separation_latency.is_some(),
            "MI should produce a separation event for the stealthy spoof"
        );
        assert_eq!(st.mi_first_eligible_delay_frames, 71);
        assert!(st.reach.1 > 0.8, "corr reach on stealthy {:.2}", st.reach.1);
        assert!(st.reach.2 > 0.8, "MI reach on stealthy {:.2}", st.reach.2);

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
        let cfg = config(|params| {
            params.trials = MIN_INFERENCE_TRIALS;
            params.frames = MIN_EVALUATION_FRAMES;
        });
        let (rows, (diff, dlo, dhi)) = stealthy_ci_study(&cfg, 200).expect("valid bootstrap study");

        let corr = &rows[2];
        let mi = &rows[3];
        assert!(
            (diff - (corr.auc - mi.auc)).abs() < 1e-12 && dlo <= dhi,
            "paired ΔAUC {diff:.3} [{dlo:.3},{dhi:.3}] must match row AUCs"
        );

        // Both cross-sensor detectors' CIs sit well above the baseline's.
        let baseline = &rows[0];
        assert!(
            baseline.hi < corr.lo.min(mi.lo),
            "baseline CI [.,{:.3}] should not overlap corr/MI lower bounds {:.3}/{:.3}",
            baseline.hi,
            corr.lo,
            mi.lo,
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
    fn component_auc_ranking_excludes_unavailable_graph_events() {
        let unavailable = alarm_rank_evidence(DetectorEvidence {
            alarm: None,
            score: Some(0.8),
        });

        assert_eq!(unavailable.alarm, None);
        assert_eq!(unavailable.score, None);
    }

    #[test]
    fn ci_formatter_never_turns_nan_or_unordered_intervals_into_success() {
        let rows = [CiRow {
            name: "hostile".into(),
            auc: f64::NAN,
            lo: 0.9,
            hi: 0.1,
            positive_n: 1,
            negative_n: 1,
            positive_total: 1,
            negative_total: 1,
            missingness_bounds: (f64::NAN, f64::NAN),
        }];
        let rendered = format_ci(&rows, (f64::NAN, f64::NAN, f64::NAN), 10);
        assert!(rendered.contains("unavailable: non-finite, unordered"));
        assert!(!rendered.contains("pointwise CI excludes 0"));
    }

    #[test]
    fn auc_missingness_bounds_do_not_assume_availability_is_random() {
        let positive = [1.0, 0.0, 0.0];
        let negative = [0.0, 1.0, 1.0];
        let all_case = auc(&positive, &negative);
        let selected = auc(&positive[..2], &negative[..2]);
        assert!((all_case - 1.0 / 3.0).abs() < 1e-12);
        assert!((selected - 0.5).abs() < 1e-12);

        let bounds = auc_missingness_bounds(selected, 2, 2, 3, 3);
        assert!((bounds.0 - 2.0 / 9.0).abs() < 1e-12);
        assert!((bounds.1 - 7.0 / 9.0).abs() < 1e-12);
        assert!(bounds.0 <= all_case && all_case <= bounds.1);
    }

    #[test]
    fn mi_score_retains_a_negative_finite_estimate_below_a_positive_reference() {
        assert_eq!(mi_best_peer_spread(&[0.4, 0.2, -0.1]), Some(1.0));
        assert_eq!(mi_best_peer_spread(&[-0.1, -0.2, -0.3]), None);
        assert_eq!(mi_best_peer_spread(&[0.4, f64::NAN, -0.1]), None);
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
        let cfg = config(|params| {
            params.trials = MIN_INFERENCE_TRIALS;
            params.frames = MIN_EVALUATION_FRAMES;
        });
        let r = collusion_study(&cfg, MIN_INFERENCE_TRIALS).expect("valid collusion study");
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
        // MI inherits the same structural failure (it is not a way out).
        assert!(
            r.mi_accuses_honest > 0.5,
            "MI should also mis-flag the honest channel {:.3} (fires {:.3}, insufficient {:.3})",
            r.mi_accuses_honest,
            r.mi_separation_rate,
            r.mi_unavailable_rate,
        );
    }

    #[test]
    fn decoupling_sweep_shows_correlation_dominates_the_boundary() {
        let cfg = config(|params| {
            params.trials = MIN_INFERENCE_TRIALS;
            params.frames = MIN_EVALUATION_FRAMES;
        });
        let grid = [1.0, 0.4, 0.1];
        let rows = decoupling_sweep(&cfg, &grid, 200).expect("valid sweep");

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
        // At these configured points correlation is not materially worse than MI.
        for r in &rows {
            assert!(
                r.corr_auc >= r.mi_auc - 0.03,
                "d={:.2}: correlation {:.3} should not trail MI {:.3}",
                r.decoupling,
                r.corr_auc,
                r.mi_auc
            );
        }
        // Pointwise intervals are descriptive only; scanning them cannot support a
        // family-wise "strictly beats somewhere" claim without max-stat correction.
        assert!(rows.iter().all(|row| row.diff_ci.0 <= row.diff_ci.1));
    }

    #[test]
    fn adaptive_detection_declines_as_decoupling_weakens() {
        let cfg = config(|params| {
            params.trials = MIN_INFERENCE_TRIALS;
            params.frames = MIN_EVALUATION_FRAMES;
        });
        let grid = [1.0, 0.4, 0.1];
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
        assert!(study.corr_holdout_far.rate.is_finite() && study.mi_holdout_far.rate.is_finite());
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
                mi_detect: 0.3,
            }],
            target_far: 0.05,
            calibration_trials: 20,
            holdout_trials: 20,
            corr_holdout_far: RateInterval {
                rate: 0.05,
                ci: (0.01, 0.20),
            },
            mi_holdout_far: RateInterval {
                rate: 0.10,
                ci: (0.03, 0.30),
            },
        };

        let formatted = format_adaptive(&study, 0.5);
        assert!(formatted.contains("holdout FAR: corr 0.050 [0.010,0.200]"));
    }

    #[test]
    fn evasion_ceiling_distinguishes_caught_all_from_a_missed_zero_point() {
        let caught = [AdaptiveRow {
            decoupling: 0.0,
            corr_detect: 0.6,
            mi_detect: 0.6,
        }];
        let missed = [AdaptiveRow {
            decoupling: 0.0,
            corr_detect: 0.4,
            mi_detect: 0.4,
        }];
        assert_eq!(
            evasion_ceiling(&caught, |row| row.corr_detect, 0.5),
            Ok(None)
        );
        assert_eq!(
            evasion_ceiling(&missed, |row| row.corr_detect, 0.5),
            Ok(Some(0.0))
        );
        assert!(matches!(
            evasion_ceiling(&[], |row| row.corr_detect, 0.5),
            Err(EvasionCeilingError::EmptyGrid)
        ));
        let invalid = [AdaptiveRow {
            decoupling: 0.5,
            corr_detect: f64::NAN,
            mi_detect: 0.4,
        }];
        assert!(format_adaptive(
            &AdaptiveStudy {
                rows: invalid.to_vec(),
                target_far: 0.05,
                calibration_trials: 20,
                holdout_trials: 20,
                corr_holdout_far: RateInterval {
                    rate: 0.05,
                    ci: (0.01, 0.20),
                },
                mi_holdout_far: RateInterval {
                    rate: 0.05,
                    ci: (0.01, 0.20),
                },
            },
            0.5,
        )
        .contains("unavailable"));
    }

    #[test]
    fn maneuver_study_is_correlation_only_and_discloses_mi_abstention() {
        let cfg = config(|params| params.trials = 40);
        let rows = maneuver_far(&cfg, &[0, 32], 12.0, 90).expect("valid maneuver study");
        // A synchronized maneuver (lag 0) keeps channels correlated → ~no consistency FAR.
        assert!(
            rows[0].corr_far < 0.1,
            "synced corr FAR {:.3}",
            rows[0].corr_far
        );
        assert!(rows.iter().all(|row| (0.0..=1.0).contains(&row.corr_far)));
        let formatted = format_maneuver(&rows, 12.0, 90);
        assert!(formatted.contains("MI is not evaluated"));
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
            validate_maneuver_inputs(&cfg, &[0], 12.0, 1),
            Err(EvalConfigError::InvalidManeuverDuration)
        ));
        validate_maneuver_inputs(&cfg, &[0], 12.0, 2)
            .expect("two frames provide one nonzero maneuver sample");
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
            lo > 0.97 && lo < 1.0 && hi == 1.0,
            "wilson(200,200)=[{lo:.3},{hi:.3}]"
        );
        // k = 0: lower bound is exactly 0.0, despite floating-point roundoff.
        let (lo, hi) = wilson_ci(0, 200);
        assert!(
            lo == 0.0 && hi > 0.0 && hi < 0.03,
            "wilson(0,200)=[{lo:.3},{hi:.3}]"
        );
        // A p̂ = 0.5 interval is centered near 0.5.
        let (lo, hi) = wilson_ci(50, 100);
        assert!(lo > 0.40 && hi < 0.60, "wilson(50,100)=[{lo:.3},{hi:.3}]");
    }

    #[test]
    fn wilson_ci_contains_exact_machine_count_proportions() {
        let maximum = usize::MAX;
        let cases = [
            (0, maximum),
            (1, maximum),
            (maximum / 2, maximum),
            (maximum - 2, maximum),
            (maximum - 1, maximum),
            (maximum, maximum),
        ];

        for (k, n) in cases {
            let (lower, upper) = wilson_ci(k, n);
            assert_contains_exact_proportion(k, n, lower, upper);
        }

        let (lower, upper) = wilson_ci(maximum - 1, maximum);
        assert!(
            lower < 1.0 && upper == 1.0,
            "near-perfect maximum counts must retain visible uncertainty: [{lower}, {upper}]"
        );

        for n in [29, 34, 35] {
            let zero = wilson_ci(0, n);
            let perfect = wilson_ci(n, n);
            assert_contains_exact_proportion(0, n, zero.0, zero.1);
            assert_contains_exact_proportion(n, n, perfect.0, perfect.1);
            assert_eq!(zero.0, 0.0, "zero successes must have an exact lower bound");
            assert_eq!(
                perfect.1, 1.0,
                "perfect successes must have an exact upper bound"
            );
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn wilson_ci_contains_exact_proportions_across_f64_integer_boundary() {
        let exact_integer_limit = 1_usize << 53;
        for n in [
            exact_integer_limit - 1,
            exact_integer_limit,
            exact_integer_limit + 1,
        ] {
            for k in [n - 2, n - 1, n] {
                let (lower, upper) = wilson_ci(k, n);
                assert_contains_exact_proportion(k, n, lower, upper);
            }
        }
    }

    #[test]
    fn wilson_ci_reflects_high_success_counts_conservatively() {
        for (k, n) in [(0, 29), (1, 34), (17, 35), (2, 200), (1, usize::MAX)] {
            let low = wilson_ci(k, n);
            let high = wilson_ci(n - k, n);
            assert!(
                high.0 <= 1.0 - low.1 && 1.0 - low.0 <= high.1,
                "reflected interval for {}/{n} is not conservative: low={low:?}, high={high:?}",
                n - k
            );
        }
    }

    #[test]
    fn wilson_ci_is_monotone_across_the_reflection_boundary() {
        let mut sample_counts = vec![34, 35, 100, 101, usize::MAX];
        #[cfg(target_pointer_width = "64")]
        sample_counts.extend([(1_usize << 53) - 1, 1_usize << 53, (1_usize << 53) + 1]);

        for n in sample_counts {
            let midpoint = n / 2;
            let start = midpoint.saturating_sub(3);
            let end = midpoint.saturating_add(4).min(n);
            let mut previous = wilson_ci(start, n);
            for k in start + 1..=end {
                let current = wilson_ci(k, n);
                assert!(
                    previous.0 <= current.0 && previous.1 <= current.1,
                    "Wilson endpoints regressed between {}/{n}={previous:?} and {k}/{n}={current:?}",
                    k - 1
                );
                previous = current;
            }
        }
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
    fn command_preflight_rejects_mi_estimator_work_before_observation_limits() {
        let estimator_heavy = config(|params| {
            params.trials = 1_000;
            params.frames = MIN_EVALUATION_FRAMES;
        });
        let error = validate_report_suite(
            &estimator_heavy,
            &[1.0, 0.6, 0.2, 0.1],
            &[0],
            200,
            1_000,
            128,
        )
        .expect_err("quadratic MI work must reject this otherwise bounded suite");

        assert!(matches!(
            error,
            EvalConfigError::WorkLimit {
                context: "suite MI quadratic fits",
                ..
            }
        ));
    }

    #[test]
    fn individual_study_rejects_aggregate_mi_work_before_execution() {
        let cfg = config(|params| {
            params.trials = 1_000;
            params.frames = MIN_EVALUATION_FRAMES;
        });
        let grid = (0..50).map(|index| index as f64 / 49.0).collect::<Vec<_>>();
        let error = decoupling_sweep(&cfg, &grid, 200)
            .expect_err("standalone sweep must enforce the aggregate MI ceiling");
        assert!(matches!(
            error,
            GaladrielError::InvalidConfig(message)
                if message.contains("sweep MI quadratic fits")
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
            frames in MIN_EVALUATION_FRAMES..=10_000,
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

        /// The Wilson interval is a sub-interval of [0, 1] that brackets the exact
        /// rational point estimate.
        #[test]
        fn wilson_ci_brackets_the_estimate(
            (n, k) in (1usize..2000).prop_flat_map(|n| (Just(n), 0usize..=n))
        ) {
            let (lo, hi) = wilson_ci(k, n);
            prop_assert!(lo >= -1e-12 && hi <= 1.0 + 1e-12, "wilson [{lo},{hi}] ∉ [0,1]");
            prop_assert!(lo <= hi, "wilson lo {lo} > hi {hi}");
            prop_assert_ne!(
                compare_f64_to_proportion(lo, k, n),
                std::cmp::Ordering::Greater,
                "wilson lower {} exceeds exact {}/{}",
                lo,
                k,
                n
            );
            prop_assert_ne!(
                compare_f64_to_proportion(hi, k, n),
                std::cmp::Ordering::Less,
                "wilson upper {} is below exact {}/{}",
                hi,
                k,
                n
            );
        }

        /// Exact-rational containment also holds across the full machine-count domain,
        /// including integers that collapse during conversion to `f64`.
        #[test]
        fn wilson_ci_brackets_full_usize_domain(
            n in any::<usize>().prop_filter("sample count must be positive", |n| *n != 0),
            raw_k in any::<usize>(),
        ) {
            let k = ((raw_k as u128) % (n as u128 + 1)) as usize;
            let (lo, hi) = wilson_ci(k, n);
            prop_assert!((0.0..=1.0).contains(&lo), "wilson lower {lo} ∉ [0,1]");
            prop_assert!((0.0..=1.0).contains(&hi), "wilson upper {hi} ∉ [0,1]");
            prop_assert!(lo <= hi, "wilson lo {lo} > hi {hi}");
            prop_assert_ne!(
                compare_f64_to_proportion(lo, k, n),
                std::cmp::Ordering::Greater,
                "wilson lower {} exceeds exact {}/{}",
                lo,
                k,
                n
            );
            prop_assert_ne!(
                compare_f64_to_proportion(hi, k, n),
                std::cmp::Ordering::Less,
                "wilson upper {} is below exact {}/{}",
                hi,
                k,
                n
            );
        }

        /// Increasing the success count by one cannot move either Wilson endpoint down.
        #[test]
        fn wilson_ci_is_monotone_for_adjacent_machine_counts(
            n in any::<usize>().prop_filter("sample count must be positive", |n| *n != 0),
            raw_k in any::<usize>(),
        ) {
            let k = ((raw_k as u128) % n as u128) as usize;
            let current = wilson_ci(k, n);
            let next = wilson_ci(k + 1, n);
            prop_assert!(
                current.0 <= next.0 && current.1 <= next.1,
                "Wilson endpoints regressed between {}/{}={:?} and {}/{}={:?}",
                k,
                n,
                current,
                k + 1,
                n,
                next
            );
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
