//! Synthetic multi-sensor innovation streams.
//!
//! Two regimes share one generator:
//!
//! - **Independent** (`rho = 0`, the default): each channel's innovation is
//!   `y ~ N(0, σ²I₃)`, so `NIS ~ χ²(3)` and channels share no information. This is
//!   the regime the magnitude baseline is exercised on.
//! - **Corroborated** (`rho > 0`): every channel observes a shared latent target
//!   deviation plus independent noise, so channels are correlated (`corr = rho`)
//!   *and* each still has `NIS ~ χ²(3)`. This is the regime the cross-sensor PID
//!   engine needs — there is genuine redundancy for a spoof to break.
//!
//! [`generate_spoofed`] injects a **moment-matched stealthy spoof**: from
//! `start_frame` the target channel tracks an *independent phantom* latent of the
//! same variance. Its per-frame NIS is unchanged (so the magnitude baseline is
//! blind), but it has **decoupled** from the consensus of the others — exactly the
//! attack the PID engine exists to catch.
//!
//! Every generated observation also carries a three-axis `ConsistencyProjection`.
//! Modalities at one frame share frame/context IDs and one unique frozen-prior ID,
//! so fused consistency entry points can exercise their full provenance contract.

use std::collections::HashSet;

use galadriel_core::{
    ConsistencyProjection, FrozenPriorId, GaladrielError, Modality, PidObservation, Result,
    Sequence, TimestampMillis, TrackId,
};
use rand_distr::{Distribution, Normal};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::rng;

/// Maximum number of observations a single scenario may allocate.
///
/// The simulator is intended for bounded experiments, not unbounded trace
/// materialization. Keeping the limit explicit also prevents an otherwise valid
/// `usize` multiplication from turning an untrusted configuration into a huge
/// allocation request.
pub const MAX_SCENARIO_OBSERVATIONS: usize = 1_000_000;

/// Literal-friendly, untrusted inputs for a synthetic scenario.
///
/// This type is intentionally mutable. It cannot be passed to a generator until
/// [`ScenarioConfig::try_new`] has produced an immutable accepted value.
#[derive(Debug, Clone)]
pub struct ScenarioParams {
    /// Track id all observations are tagged with.
    pub track_id: u64,
    /// Number of fusion frames.
    pub frames: usize,
    /// Sensor modalities present each frame (one measurement each).
    pub modalities: Vec<Modality>,
    /// Per-axis innovation standard deviation (nominal).
    pub sigma: f64,
    /// Cross-channel correlation via a shared latent, in `[0, 1)`.
    pub rho: f64,
    /// Milliseconds between frames.
    pub dt_ms: u64,
    /// RNG seed.
    pub seed: u64,
}

/// Named, reproducible scenario profiles for research-only evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioResearchProfile {
    /// Bounded synthetic defaults shipped with the 0.9 source release.
    SyntheticV0_9,
}

impl ScenarioResearchProfile {
    /// Return raw parameters for an explicitly customized research scenario.
    #[must_use]
    pub fn params(self) -> ScenarioParams {
        match self {
            Self::SyntheticV0_9 => ScenarioParams {
                track_id: 1,
                frames: 220,
                modalities: vec![Modality::Visual, Modality::Radar, Modality::Acoustic],
                sigma: 1.0,
                rho: 0.0,
                dt_ms: 100,
                seed: 7,
            },
        }
    }

    /// Resolve this exact profile to an immutable accepted configuration.
    ///
    /// Construction is `O(m)` in the modality count and retains exactly `m`
    /// modalities. The accepted scenario admits at most
    /// [`MAX_SCENARIO_OBSERVATIONS`] observations.
    ///
    /// # Errors
    ///
    /// Returns [`ScenarioConfigError`] if the profile ceases to meet the
    /// simulator's configuration contract.
    pub fn try_config(self) -> std::result::Result<ScenarioConfig, ScenarioConfigError> {
        ScenarioConfig::try_new_with_origin(self.params(), ScenarioConfigOrigin::Named(self))
    }

    /// Stable profile identity included in canonical configuration preimages.
    #[must_use]
    pub const fn identity(self) -> &'static str {
        match self {
            Self::SyntheticV0_9 => "galadriel-sim/synthetic-v0.9",
        }
    }
}

/// Provenance and research classification of an accepted scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioConfigOrigin {
    /// An exact, unmodified named research profile.
    Named(ScenarioResearchProfile),
    /// Caller-supplied research parameters.
    CustomResearch,
}

/// Typed failures produced while accepting [`ScenarioParams`].
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum ScenarioConfigError {
    /// The track identity does not satisfy the core identity contract.
    #[error("invalid scenario track identity: {message}")]
    InvalidTrackId { message: String },
    /// No modality was supplied.
    #[error("scenario must contain at least one modality")]
    EmptyModalities,
    /// More modalities were supplied than the closed modality set contains.
    #[error("scenario contains {actual} modalities; maximum is {maximum}")]
    TooManyModalities { actual: usize, maximum: usize },
    /// A modality appears more than once.
    #[error("scenario modality {modality:?} appears more than once")]
    DuplicateModality { modality: Modality },
    /// Multiple frames were requested with a zero interval.
    #[error("scenario dt_ms must be > 0 when generating multiple frames")]
    ZeroInterval,
    /// The innovation standard deviation is not finite and strictly positive.
    #[error("scenario sigma must be finite and > 0")]
    InvalidSigma,
    /// Squaring sigma did not yield a finite, positive variance.
    #[error("scenario sigma squared must be finite and non-zero")]
    DegenerateVariance,
    /// The correlation is not finite and in `[0, 1)`.
    #[error("scenario rho must be finite and in [0, 1)")]
    InvalidCorrelation,
    /// A derived latent or independent-noise variance is degenerate.
    #[error("scenario {component} variance must be finite and non-zero")]
    DegenerateComponentVariance { component: &'static str },
    /// `frames * modalities` cannot be represented as `usize`.
    #[error("scenario frame/modality count overflows usize")]
    ObservationCountOverflow,
    /// The requested observation count exceeds the hard ceiling.
    #[error("scenario requests {actual} observations; maximum is {maximum}")]
    TooManyObservations { actual: usize, maximum: usize },
    /// A frame index cannot be represented by the domain integer.
    #[error("scenario frame index cannot be represented as u64")]
    FrameIndexOverflow,
    /// Timestamp multiplication overflowed.
    #[error("scenario timestamp arithmetic overflows u64")]
    TimestampOverflow,
    /// A terminal sequence violates the core domain contract.
    #[error("invalid scenario terminal sequence: {message}")]
    InvalidTerminalSequence { message: String },
    /// A terminal timestamp violates the core domain contract.
    #[error("invalid scenario terminal timestamp: {message}")]
    InvalidTerminalTimestamp { message: String },
    /// Frozen-prior arithmetic overflowed.
    #[error("scenario frozen-prior identity arithmetic overflows u64")]
    FrozenPriorOverflow,
    /// A terminal frozen-prior identity violates the core domain contract.
    #[error("invalid scenario terminal frozen-prior identity: {message}")]
    InvalidTerminalFrozenPrior { message: String },
}

/// Immutable, fully accepted configuration for a synthetic research scenario.
///
/// ```compile_fail
/// use galadriel_sim::scenario::ScenarioConfig;
/// let _forged = ScenarioConfig { frames: usize::MAX };
/// ```
///
/// ```compile_fail
/// use galadriel_sim::scenario::ScenarioConfig;
/// let _implicit = ScenarioConfig::default();
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioConfig {
    track_id: TrackId,
    frames: usize,
    modalities: Vec<Modality>,
    sigma: f64,
    rho: f64,
    dt_ms: u64,
    seed: u64,
    observation_capacity: usize,
    variance: f64,
    common_sd: f64,
    noise_sd: f64,
    origin: ScenarioConfigOrigin,
    canonical_digest: String,
}

fn validate_common_variance(
    rho: f64,
    common_variance: f64,
) -> std::result::Result<(), ScenarioConfigError> {
    if rho == 0.0 {
        return Ok(());
    }
    if !common_variance.is_finite() {
        return Err(ScenarioConfigError::DegenerateComponentVariance {
            component: "shared-latent",
        });
    }
    if common_variance <= 0.0 {
        return Err(ScenarioConfigError::DegenerateComponentVariance {
            component: "shared-latent",
        });
    }
    Ok(())
}

impl ScenarioConfig {
    /// Accept caller-supplied research parameters.
    ///
    /// Construction is `O(m)` in the modality count, performs no scenario-sized
    /// allocation, and retains exactly the supplied modality vector. Generation
    /// is bounded by `frames * m <= 1_000_000` observations.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ScenarioConfigError`] for any local, aggregate,
    /// arithmetic, or core-domain violation.
    pub fn try_new(params: ScenarioParams) -> std::result::Result<Self, ScenarioConfigError> {
        Self::try_new_with_origin(params, ScenarioConfigOrigin::CustomResearch)
    }

    fn try_new_with_origin(
        mut params: ScenarioParams,
        origin: ScenarioConfigOrigin,
    ) -> std::result::Result<Self, ScenarioConfigError> {
        let track_id =
            TrackId::new(params.track_id).map_err(|error| ScenarioConfigError::InvalidTrackId {
                message: error.to_string(),
            })?;
        if params.modalities.is_empty() {
            return Err(ScenarioConfigError::EmptyModalities);
        }
        if params.modalities.len() > Modality::ALL.len() {
            return Err(ScenarioConfigError::TooManyModalities {
                actual: params.modalities.len(),
                maximum: Modality::ALL.len(),
            });
        }
        let mut seen = HashSet::with_capacity(params.modalities.len());
        for modality in params.modalities.iter().copied() {
            if !seen.insert(modality) {
                return Err(ScenarioConfigError::DuplicateModality { modality });
            }
        }
        if matches!((params.frames, params.dt_ms), (2.., 0)) {
            return Err(ScenarioConfigError::ZeroInterval);
        }
        if !params.sigma.is_finite() {
            return Err(ScenarioConfigError::InvalidSigma);
        }
        if params.sigma <= 0.0 {
            return Err(ScenarioConfigError::InvalidSigma);
        }
        let variance = params.sigma * params.sigma;
        if !variance.is_finite() {
            return Err(ScenarioConfigError::DegenerateVariance);
        }
        if variance <= 0.0 {
            return Err(ScenarioConfigError::DegenerateVariance);
        }
        if !params.rho.is_finite() {
            return Err(ScenarioConfigError::InvalidCorrelation);
        }
        if !(0.0..1.0).contains(&params.rho) {
            return Err(ScenarioConfigError::InvalidCorrelation);
        }
        // Positive and negative zero define the same independent regime. Store
        // and identify exactly one canonical representation.
        if params.rho == 0.0 {
            params.rho = 0.0;
        }
        let noise_variance = (1.0 - params.rho) * variance;
        if !noise_variance.is_finite() {
            return Err(ScenarioConfigError::DegenerateComponentVariance {
                component: "independent-noise",
            });
        }
        if noise_variance <= 0.0 {
            return Err(ScenarioConfigError::DegenerateComponentVariance {
                component: "independent-noise",
            });
        }
        let common_variance = params.rho * variance;
        validate_common_variance(params.rho, common_variance)?;

        let observation_capacity = params
            .frames
            .checked_mul(params.modalities.len())
            .ok_or(ScenarioConfigError::ObservationCountOverflow)?;
        if observation_capacity > MAX_SCENARIO_OBSERVATIONS {
            return Err(ScenarioConfigError::TooManyObservations {
                actual: observation_capacity,
                maximum: MAX_SCENARIO_OBSERVATIONS,
            });
        }

        if let Some(last_frame) = params.frames.checked_sub(1) {
            let last_frame =
                u64::try_from(last_frame).map_err(|_| ScenarioConfigError::FrameIndexOverflow)?;
            let last_timestamp = last_frame
                .checked_mul(params.dt_ms)
                .ok_or(ScenarioConfigError::TimestampOverflow)?;
            Sequence::new(last_frame).map_err(|error| {
                ScenarioConfigError::InvalidTerminalSequence {
                    message: error.to_string(),
                }
            })?;
            TimestampMillis::new(last_timestamp).map_err(|error| {
                ScenarioConfigError::InvalidTerminalTimestamp {
                    message: error.to_string(),
                }
            })?;
            let frozen_prior = last_frame
                .checked_add(1)
                .ok_or(ScenarioConfigError::FrozenPriorOverflow)?;
            FrozenPriorId::new(frozen_prior).map_err(|error| {
                ScenarioConfigError::InvalidTerminalFrozenPrior {
                    message: error.to_string(),
                }
            })?;
        }

        let canonical_digest = scenario_digest(&params, origin);
        Ok(Self {
            track_id,
            frames: params.frames,
            modalities: params.modalities,
            sigma: params.sigma,
            rho: params.rho,
            dt_ms: params.dt_ms,
            seed: params.seed,
            observation_capacity,
            variance,
            common_sd: common_variance.sqrt(),
            noise_sd: noise_variance.sqrt(),
            origin,
            canonical_digest,
        })
    }

    /// Validated track identity.
    #[must_use]
    pub const fn track_id(&self) -> TrackId {
        self.track_id
    }
    /// Number of fusion frames.
    #[must_use]
    pub const fn frames(&self) -> usize {
        self.frames
    }
    /// Unique, closed-set modalities emitted per frame.
    #[must_use]
    pub fn modalities(&self) -> &[Modality] {
        &self.modalities
    }
    /// Nominal per-axis innovation standard deviation.
    #[must_use]
    pub const fn sigma(&self) -> f64 {
        self.sigma
    }
    /// Cross-channel correlation.
    #[must_use]
    pub const fn rho(&self) -> f64 {
        self.rho
    }
    /// Milliseconds between frames.
    #[must_use]
    pub const fn dt_ms(&self) -> u64 {
        self.dt_ms
    }
    /// Deterministic random seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }
    /// Exact observation capacity validated at construction.
    #[must_use]
    pub const fn observation_capacity(&self) -> usize {
        self.observation_capacity
    }
    /// Named-profile or custom-research provenance.
    #[must_use]
    pub const fn origin(&self) -> ScenarioConfigOrigin {
        self.origin
    }
    /// SHA-256 of the domain-separated canonical accepted configuration.
    #[must_use]
    pub fn canonical_digest(&self) -> &str {
        &self.canonical_digest
    }
}

impl TryFrom<ScenarioParams> for ScenarioConfig {
    type Error = ScenarioConfigError;

    fn try_from(params: ScenarioParams) -> std::result::Result<Self, Self::Error> {
        Self::try_new(params)
    }
}

fn scenario_digest(params: &ScenarioParams, origin: ScenarioConfigOrigin) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"galadriel-sim-scenario-config-v0.9\0");
    match origin {
        ScenarioConfigOrigin::Named(profile) => {
            hasher.update(b"named\0");
            hasher.update(profile.identity().as_bytes());
            hasher.update([0]);
        }
        ScenarioConfigOrigin::CustomResearch => hasher.update(b"custom-research\0"),
    }
    hasher.update(params.track_id.to_be_bytes());
    hasher.update((params.frames as u128).to_be_bytes());
    hasher.update((params.modalities.len() as u128).to_be_bytes());
    for modality in &params.modalities {
        hasher.update([modality.stable_code()]);
    }
    hasher.update(params.sigma.to_bits().to_be_bytes());
    hasher.update(params.rho.to_bits().to_be_bytes());
    hasher.update(params.dt_ms.to_be_bytes());
    hasher.update(params.seed.to_be_bytes());
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// A moment-matched stealthy spoof: from `start_frame`, `target` tracks an
/// independent phantom latent of the same variance — NIS is unchanged, but the
/// channel decouples from the consensus.
#[derive(Debug, Clone, Copy)]
pub struct StealthySpoof {
    /// Modality that is spoofed.
    pub target: Modality,
    /// Frame the decoupling begins.
    pub start_frame: u64,
}

fn valid_decoupling(decoupling: f64) -> bool {
    decoupling.is_finite() && (0.0..=1.0).contains(&decoupling)
}

fn attack_active(is_target: bool, frame: u64, start_frame: u64) -> bool {
    is_target && frame >= start_frame
}

fn mix_moment_matched_latents(truth: [f64; 3], phantom: [f64; 3], decoupling: f64) -> [f64; 3] {
    let truth_weight = (1.0 - decoupling).sqrt();
    let phantom_weight = decoupling.sqrt();
    [
        truth_weight * truth[0] + phantom_weight * phantom[0],
        truth_weight * truth[1] + phantom_weight * phantom[1],
        truth_weight * truth[2] + phantom_weight * phantom[2],
    ]
}

fn add_axes(left: [f64; 3], right: [f64; 3]) -> [f64; 3] {
    [left[0] + right[0], left[1] + right[1], left[2] + right[2]]
}

fn standardized_nis(innovation: [f64; 3], sigma: f64) -> f64 {
    let normalized = [
        innovation[0] / sigma,
        innovation[1] / sigma,
        innovation[2] / sigma,
    ];
    normalized[0] * normalized[0] + normalized[1] * normalized[1] + normalized[2] * normalized[2]
}

/// The shared generator. `targets` are the spoofed channels; from `start_frame` each
/// tracks the frame's **shared** phantom latent `p` (mixed via `decoupling`). Because all
/// targets share the *same* `p`, a set of ≥2 targets **mutually corroborate** — that is the
/// colluding-compromise mechanism ([`generate_collusion`]).
fn generate_inner(
    cfg: &ScenarioConfig,
    targets: &[Modality],
    start_frame: u64,
    decoupling: f64,
) -> Result<Vec<PidObservation>> {
    if targets.len() > cfg.modalities.len() {
        return Err(GaladrielError::InvalidConfig(format!(
            "spoof target count {} exceeds the {} configured modalities",
            targets.len(),
            cfg.modalities.len()
        )));
    }
    if !valid_decoupling(decoupling) {
        return Err(GaladrielError::InvalidConfig(
            "spoof decoupling must be finite and in [0, 1]".into(),
        ));
    }
    if !targets.is_empty() && decoupling > 0.0 {
        if cfg.rho <= 0.0 {
            return Err(GaladrielError::InvalidConfig(
                "spoof/collusion scenarios require rho > 0 so a consensus exists to break".into(),
            ));
        }
        if start_frame >= cfg.frames as u64 {
            return Err(GaladrielError::InvalidConfig(format!(
                "attack start_frame {start_frame} must be inside the {}-frame capture",
                cfg.frames
            )));
        }
    }

    let configured: HashSet<Modality> = cfg.modalities.iter().copied().collect();
    let mut unique_targets = HashSet::with_capacity(targets.len());
    for &target in targets {
        if !configured.contains(&target) {
            return Err(GaladrielError::InvalidConfig(format!(
                "spoof target {} is not present in the scenario",
                target.label()
            )));
        }
        if !unique_targets.insert(target) {
            return Err(GaladrielError::InvalidConfig(
                "spoof targets must be unique".into(),
            ));
        }
    }

    let mut r = rng::seeded(cfg.seed);
    let rho = cfg.rho;
    let noise = Normal::new(0.0, cfg.noise_sd).map_err(|error| {
        GaladrielError::InvalidConfig(format!(
            "could not construct scenario noise distribution: {error}"
        ))
    })?;
    // Only drawn when rho > 0, so rho == 0 reproduces the independent stream exactly.
    let common = if rho == 0.0 {
        None
    } else {
        Some(Normal::new(0.0, cfg.common_sd).map_err(|error| {
            GaladrielError::InvalidConfig(format!(
                "could not construct shared-latent distribution: {error}"
            ))
        })?)
    };
    let cov = [
        [cfg.variance, 0.0, 0.0],
        [0.0, cfg.variance, 0.0],
        [0.0, 0.0, cfg.variance],
    ];

    let capacity = cfg.observation_capacity;
    let mut out = Vec::new();
    out.try_reserve_exact(capacity).map_err(|_| {
        GaladrielError::InvalidConfig(format!(
            "could not reserve storage for {capacity} scenario observations"
        ))
    })?;
    for f in 0..cfg.frames {
        let frame = u64::try_from(f).map_err(|_| {
            GaladrielError::InvalidConfig(
                "scenario frame index cannot be represented as u64".into(),
            )
        })?;
        let timestamp_ms = frame.checked_mul(cfg.dt_ms).ok_or_else(|| {
            GaladrielError::InvalidConfig("scenario timestamp arithmetic overflows u64".into())
        })?;
        // Shared "truth" latent m and an independent phantom latent p for this frame.
        let (m, p) = if let Some(common) = common.as_ref() {
            (
                [
                    common.sample(&mut r),
                    common.sample(&mut r),
                    common.sample(&mut r),
                ],
                [
                    common.sample(&mut r),
                    common.sample(&mut r),
                    common.sample(&mut r),
                ],
            )
        } else {
            ([0.0; 3], [0.0; 3])
        };
        for &modality in &cfg.modalities {
            let spoofed = attack_active(unique_targets.contains(&modality), frame, start_frame);
            // Partial decoupling: mix the shared truth `m` and the phantom `p` as
            // `√(1−d)·m + √d·p`. Since m and p are independent with equal variance this
            // preserves the marginal variance for *every* d (so the spoof stays
            // moment-matched: NIS ~ χ²(3) throughout), while the cross-channel covariance
            // with honest channels scales as √(1−d). d = 1 is full decoupling (base = p);
            // d = 0 is no attack (base = m).
            let base = if spoofed {
                mix_moment_matched_latents(m, p, decoupling)
            } else {
                m
            };
            let sampled_noise = [
                noise.sample(&mut r),
                noise.sample(&mut r),
                noise.sample(&mut r),
            ];
            let y = add_axes(base, sampled_noise);
            // Standardize before squaring: `y² / sigma²` is algebraically the
            // same quantity, but this ordering cannot overflow merely because a
            // supported sigma is near the upper end of f64.
            let nis = standardized_nis(y, cfg.sigma);
            if !nis.is_finite() {
                return Err(GaladrielError::InvalidConfig(
                    "scenario sampling produced a non-finite NIS".into(),
                ));
            }
            let projection = ConsistencyProjection::try_new_raw(y, 3, 1, 1, frame + 1)?;
            let observation = PidObservation::try_scalar_raw(
                cfg.track_id.get(),
                timestamp_ms,
                frame,
                modality,
                nis,
                3,
            )?
            .try_with_research(y, cov)?
            .with_consistency_projection(projection);
            out.push(observation);
        }
    }
    Ok(out)
}

/// Generate a clean stream (independent if `rho == 0`, corroborated if `rho > 0`).
///
/// Observations are emitted frame-major (all modalities of frame 0, then frame 1,
/// …), so downstream code can chunk by `modalities.len()` to recover frames.
///
/// # Errors
///
/// Returns an error when `cfg` is invalid or its bounded allocation cannot be
/// reserved.
pub fn generate(cfg: &ScenarioConfig) -> Result<Vec<PidObservation>> {
    generate_inner(cfg, &[], 0, 1.0)
}

/// Generate a corroborated stream with a **fully** moment-matched stealthy spoof on one
/// channel (the target decouples onto an independent phantom latent). Requires
/// `cfg.rho > 0` for the spoof to be meaningful (otherwise there is no consensus to
/// decouple from).
///
/// # Errors
///
/// Returns an error when `cfg` is invalid or the spoof target is not configured.
pub fn generate_spoofed(cfg: &ScenarioConfig, spoof: StealthySpoof) -> Result<Vec<PidObservation>> {
    generate_inner(cfg, &[spoof.target], spoof.start_frame, 1.0)
}

/// Generate a stealthy spoof with a tunable **decoupling strength** `d ∈ [0, 1]`: the
/// target tracks `√(1−d)·(shared truth) + √d·(phantom)`, preserving its marginal variance
/// (so it stays moment-matched, NIS ~ χ²(3)) while its correlation with honest channels
/// scales as `√(1−d)`. `d = 1` is [`generate_spoofed`]; `d = 0` is [`generate`]. Sweeping
/// `d` traces the detection *boundary* — how weak a decoupling each detector can still see.
///
/// # Errors
///
/// Returns an error when `cfg` is invalid, the target is not configured, or
/// `decoupling` is non-finite or outside `[0, 1]`.
pub fn generate_spoofed_partial(
    cfg: &ScenarioConfig,
    spoof: StealthySpoof,
    decoupling: f64,
) -> Result<Vec<PidObservation>> {
    generate_inner(cfg, &[spoof.target], spoof.start_frame, decoupling)
}

/// Generate a stream with a **colluding compromise**: from `start_frame`, every channel in
/// `colluders` tracks ONE *shared* phantom latent (independent of the honest consensus), so
/// the colluders **mutually corroborate** and form a false consensus. When the colluders are
/// a majority (e.g. 2 of 3), cross-sensor consistency *inverts*: the honest minority is the
/// one that decouples from the (false) consensus and is mis-flagged. This exercises the
/// honest-majority assumption failing — the security limit of consistency detection.
///
/// # Errors
///
/// Returns an error when `cfg` is invalid or the colluder list is empty,
/// duplicated, or contains a modality absent from the scenario.
pub fn generate_collusion(
    cfg: &ScenarioConfig,
    colluders: &[Modality],
    start_frame: u64,
) -> Result<Vec<PidObservation>> {
    if colluders.is_empty() {
        return Err(GaladrielError::InvalidConfig(
            "collusion requires at least one colluding modality".into(),
        ));
    }
    generate_inner(cfg, colluders, start_frame, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(mut update: impl FnMut(&mut ScenarioParams)) -> ScenarioConfig {
        let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
        update(&mut params);
        ScenarioConfig::try_new(params).expect("test scenario parameters must be valid")
    }

    fn mean_nis(s: &[PidObservation], m: Modality) -> f64 {
        let v: Vec<f64> = s
            .iter()
            .filter(|o| o.modality() == m)
            .map(PidObservation::nis)
            .collect();
        v.iter().sum::<f64>() / v.len() as f64
    }

    #[test]
    fn generator_scalar_helpers_preserve_exact_boundaries_and_algebra() {
        for valid in [-0.0, 0.0, 0.25, 1.0] {
            assert!(valid_decoupling(valid));
        }
        for invalid in [-0.01, 1.01, f64::NAN, f64::INFINITY] {
            assert!(!valid_decoupling(invalid));
        }

        assert!(!attack_active(false, 10, 10));
        assert!(!attack_active(true, 9, 10));
        assert!(attack_active(true, 10, 10));
        assert!(attack_active(true, 11, 10));

        let mixed = mix_moment_matched_latents([1.0, 2.0, 3.0], [4.0, 5.0, 6.0], 0.36);
        for (actual, expected) in mixed.into_iter().zip([3.2, 4.6, 6.0]) {
            assert!((actual - expected).abs() < 1e-12, "{actual} != {expected}");
        }
        assert_eq!(
            mix_moment_matched_latents([1.0, 2.0, 3.0], [4.0, 5.0, 6.0], 0.0),
            [1.0, 2.0, 3.0]
        );
        assert_eq!(
            mix_moment_matched_latents([1.0, 2.0, 3.0], [4.0, 5.0, 6.0], 1.0),
            [4.0, 5.0, 6.0]
        );
        assert_eq!(add_axes([1.0, 2.0, 3.0], [4.0, 5.0, 6.0]), [5.0, 7.0, 9.0]);
        assert_eq!(standardized_nis([2.0, 4.0, 6.0], 2.0), 14.0);
    }

    #[test]
    fn generator_output_is_bit_reproducible_and_attack_onset_exact() {
        const INDEPENDENT: [([u64; 3], u64, u64); 4] = [
            (
                [
                    4_604_549_967_519_278_418,
                    4_610_313_026_538_115_850,
                    13_833_304_537_364_421_706,
                ],
                4_609_398_797_522_576_248,
                1,
            ),
            (
                [
                    4_608_624_943_431_547_702,
                    4_612_005_563_493_744_753,
                    13_830_688_165_065_875_773,
                ],
                4_611_000_602_866_286_242,
                1,
            ),
            (
                [
                    13_831_105_433_617_700_379,
                    4_612_329_707_424_178_502,
                    4_610_606_928_488_770_383,
                ],
                4_612_577_602_895_781_128,
                2,
            ),
            (
                [
                    4_609_914_912_758_928_005,
                    13_841_150_612_863_465_706,
                    4_608_193_284_857_863_566,
                ],
                4_620_885_018_430_812_887,
                2,
            ),
        ];
        const CORROBORATED: [([u64; 3], u64, u64); 4] = [
            (
                [
                    4_587_618_678_602_697_744,
                    4_613_061_771_870_225_141,
                    13_826_182_891_701_525_139,
                ],
                4_610_655_425_482_164_463,
                1,
            ),
            (
                [
                    4_609_057_212_809_892_016,
                    13_831_624_553_673_772_336,
                    13_828_596_535_332_431_956,
                ],
                4_607_351_364_535_007_485,
                1,
            ),
            (
                [
                    13_841_356_506_719_389_130,
                    13_834_992_363_279_335_132,
                    13_834_268_479_082_827_407,
                ],
                4_621_617_274_495_232_892,
                2,
            ),
            (
                [
                    13_838_111_997_755_712_916,
                    13_834_653_504_048_501_424,
                    13_837_455_123_986_240_960,
                ],
                4_618_527_049_184_345_753,
                2,
            ),
        ];
        const PARTIAL: [([u64; 3], u64); 4] = [
            (CORROBORATED[0].0, CORROBORATED[0].1),
            (CORROBORATED[1].0, CORROBORATED[1].1),
            (CORROBORATED[2].0, CORROBORATED[2].1),
            (
                [
                    13_837_155_734_584_725_890,
                    13_835_118_960_267_942_393,
                    13_835_159_176_425_865_824,
                ],
                4_616_438_607_819_074_600,
            ),
        ];

        for (rho, expected) in [(0.0, INDEPENDENT), (0.75, CORROBORATED)] {
            let cfg = ScenarioConfig::try_new(ScenarioParams {
                track_id: 42,
                frames: 2,
                modalities: vec![Modality::Visual, Modality::Radar],
                sigma: 2.0,
                rho,
                dt_ms: 17,
                seed: 99,
            })
            .unwrap();
            let clean = generate(&cfg).unwrap();
            assert_eq!(
                clean
                    .iter()
                    .map(|observation| (
                        observation.innovation().unwrap().map(f64::to_bits),
                        observation.nis().to_bits(),
                        observation
                            .consistency_projection()
                            .unwrap()
                            .identity()
                            .frozen_prior_id()
                            .get(),
                    ))
                    .collect::<Vec<_>>(),
                expected
            );
            if rho > 0.0 {
                let partial = generate_spoofed_partial(
                    &cfg,
                    StealthySpoof {
                        target: Modality::Radar,
                        start_frame: 1,
                    },
                    0.36,
                )
                .unwrap();
                assert_eq!(
                    partial
                        .iter()
                        .map(|observation| (
                            observation.innovation().unwrap().map(f64::to_bits),
                            observation.nis().to_bits(),
                        ))
                        .collect::<Vec<_>>(),
                    PARTIAL
                );
            }
        }
    }

    #[test]
    fn clean_stream_is_chi2_3_on_average() {
        let cfg = custom(|params| params.frames = 2000);
        let s = generate(&cfg).expect("valid clean scenario");
        let mean: f64 = s.iter().map(PidObservation::nis).sum::<f64>() / s.len() as f64;
        assert!((mean - 3.0).abs() < 0.3, "mean NIS = {mean}");
    }

    #[test]
    fn correlated_stream_stays_chi2_3_per_channel() {
        // Even with a shared latent, each channel's marginal NIS is χ²(3).
        let cfg = custom(|params| {
            params.frames = 3000;
            params.rho = 0.7;
        });
        let s = generate(&cfg).expect("valid correlated scenario");
        for m in [Modality::Visual, Modality::Radar, Modality::Acoustic] {
            assert!((mean_nis(&s, m) - 3.0).abs() < 0.35, "{m:?} mean NIS off");
        }
    }

    #[test]
    fn generated_common_projection_has_shared_per_frame_provenance() {
        let cfg = custom(|params| params.frames = 8);
        let stream = generate(&cfg).expect("valid scenario");
        let mut prior_ids = HashSet::new();
        for frame in stream.chunks(cfg.modalities().len()) {
            let first = frame[0]
                .consistency_projection()
                .expect("simulator projection");
            assert!(frame.iter().all(|observation| {
                observation
                    .consistency_projection()
                    .is_some_and(|projection| {
                        projection.dimensions() == first.dimensions()
                            && projection.identity() == first.identity()
                    })
            }));
            assert!(prior_ids.insert(first.identity().frozen_prior_id()));
        }
    }

    #[test]
    fn stealthy_spoof_is_moment_matched_so_the_baseline_is_blind() {
        // The spoofed channel's NIS distribution is unchanged: its mean stays ≈ 3,
        // which is why a magnitude/χ² baseline cannot see this attack.
        let cfg = custom(|params| {
            params.frames = 3000;
            params.rho = 0.7;
        });
        let s = generate_spoofed(
            &cfg,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: 0,
            },
        )
        .expect("valid spoofed scenario");
        assert!(
            (mean_nis(&s, Modality::Acoustic) - 3.0).abs() < 0.35,
            "stealthy spoof should NOT inflate NIS"
        );
    }

    #[test]
    fn config_rejects_nonfinite_or_out_of_range_statistics() {
        for sigma in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
            params.sigma = sigma;
            assert!(
                ScenarioConfig::try_new(params).is_err(),
                "sigma {sigma:?} must be rejected"
            );
        }

        for rho in [-0.1, 1.0, f64::NAN, f64::INFINITY] {
            let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
            params.rho = rho;
            assert!(
                ScenarioConfig::try_new(params).is_err(),
                "rho {rho:?} must be rejected"
            );
        }

        let mut underflow = ScenarioResearchProfile::SyntheticV0_9.params();
        underflow.sigma = f64::MIN_POSITIVE;
        assert!(
            ScenarioConfig::try_new(underflow).is_err(),
            "derived zero variance must be rejected"
        );

        let mut overflow = ScenarioResearchProfile::SyntheticV0_9.params();
        overflow.sigma = f64::MAX;
        assert_eq!(
            ScenarioConfig::try_new(overflow).unwrap_err(),
            ScenarioConfigError::DegenerateVariance
        );

        let mut shared_underflow = ScenarioResearchProfile::SyntheticV0_9.params();
        shared_underflow.sigma = f64::MIN_POSITIVE.sqrt();
        shared_underflow.rho = f64::MIN_POSITIVE;
        assert_eq!(
            ScenarioConfig::try_new(shared_underflow).unwrap_err(),
            ScenarioConfigError::DegenerateComponentVariance {
                component: "shared-latent"
            }
        );
    }

    #[test]
    fn config_requires_nonempty_unique_modalities() {
        let mut empty = ScenarioResearchProfile::SyntheticV0_9.params();
        empty.modalities.clear();
        assert_eq!(
            ScenarioConfig::try_new(empty).unwrap_err(),
            ScenarioConfigError::EmptyModalities
        );

        let mut duplicate = ScenarioResearchProfile::SyntheticV0_9.params();
        duplicate.modalities = vec![Modality::Radar, Modality::Radar];
        assert_eq!(
            ScenarioConfig::try_new(duplicate).unwrap_err(),
            ScenarioConfigError::DuplicateModality {
                modality: Modality::Radar
            }
        );

        let mut exact = ScenarioResearchProfile::SyntheticV0_9.params();
        exact.modalities = Modality::ALL.to_vec();
        assert_eq!(
            ScenarioConfig::try_new(exact)
                .expect("the complete closed modality set is accepted")
                .modalities(),
            Modality::ALL
        );

        let mut one_more = ScenarioResearchProfile::SyntheticV0_9.params();
        one_more.modalities = Modality::ALL
            .iter()
            .copied()
            .chain(std::iter::once(Modality::Visual))
            .collect();
        assert_eq!(
            ScenarioConfig::try_new(one_more).unwrap_err(),
            ScenarioConfigError::TooManyModalities {
                actual: Modality::ALL.len() + 1,
                maximum: Modality::ALL.len(),
            }
        );
    }

    #[test]
    fn config_guards_capacity_and_timestamp_arithmetic() {
        let mut exact_capacity = ScenarioResearchProfile::SyntheticV0_9.params();
        exact_capacity.frames = MAX_SCENARIO_OBSERVATIONS;
        exact_capacity.modalities = vec![Modality::Visual];
        assert_eq!(
            ScenarioConfig::try_new(exact_capacity)
                .expect("the exact observation ceiling is inclusive")
                .observation_capacity(),
            MAX_SCENARIO_OBSERVATIONS
        );

        let mut too_many = ScenarioResearchProfile::SyntheticV0_9.params();
        too_many.frames = MAX_SCENARIO_OBSERVATIONS + 1;
        too_many.modalities = vec![Modality::Visual];
        assert!(matches!(
            ScenarioConfig::try_new(too_many),
            Err(ScenarioConfigError::TooManyObservations { .. })
        ));

        let mut capacity_overflow = ScenarioResearchProfile::SyntheticV0_9.params();
        capacity_overflow.frames = usize::MAX;
        capacity_overflow.modalities = vec![Modality::Visual, Modality::Radar];
        assert_eq!(
            ScenarioConfig::try_new(capacity_overflow).unwrap_err(),
            ScenarioConfigError::ObservationCountOverflow
        );

        let mut timestamp_overflow = ScenarioResearchProfile::SyntheticV0_9.params();
        timestamp_overflow.frames = 3;
        timestamp_overflow.dt_ms = u64::MAX;
        assert!(matches!(
            ScenarioConfig::try_new(timestamp_overflow),
            Err(ScenarioConfigError::TimestampOverflow)
        ));

        let mut frozen_timestamps = ScenarioResearchProfile::SyntheticV0_9.params();
        frozen_timestamps.frames = 2;
        frozen_timestamps.dt_ms = 0;
        assert_eq!(
            ScenarioConfig::try_new(frozen_timestamps).unwrap_err(),
            ScenarioConfigError::ZeroInterval
        );

        let mut exact_timestamp = ScenarioResearchProfile::SyntheticV0_9.params();
        exact_timestamp.frames = 2;
        exact_timestamp.modalities = vec![Modality::Visual];
        exact_timestamp.dt_ms = TimestampMillis::MAX;
        ScenarioConfig::try_new(exact_timestamp.clone())
            .expect("the exact JSON-safe terminal timestamp is accepted");

        exact_timestamp.dt_ms = TimestampMillis::MAX + 1;
        assert!(matches!(
            ScenarioConfig::try_new(exact_timestamp),
            Err(ScenarioConfigError::InvalidTerminalTimestamp { .. })
        ));
    }

    #[test]
    fn custom_configuration_preserves_every_scalar_and_derived_quantity() {
        let params = ScenarioParams {
            track_id: 42,
            frames: 5,
            modalities: vec![Modality::Thermal, Modality::Lidar],
            sigma: 2.0,
            rho: 0.75,
            dt_ms: 17,
            seed: 99,
        };
        let config = ScenarioConfig::try_new(params).unwrap();

        assert_eq!(config.track_id().get(), 42);
        assert_eq!(config.frames(), 5);
        assert_eq!(config.modalities(), [Modality::Thermal, Modality::Lidar]);
        assert_eq!(config.sigma().to_bits(), 2.0_f64.to_bits());
        assert_eq!(config.rho().to_bits(), 0.75_f64.to_bits());
        assert_eq!(config.dt_ms(), 17);
        assert_eq!(config.seed(), 99);
        assert_eq!(config.observation_capacity(), 10);
        assert_eq!(config.variance.to_bits(), 4.0_f64.to_bits());
        assert_eq!(config.noise_sd.to_bits(), 1.0_f64.to_bits());
        assert_eq!(config.common_sd.to_bits(), 3.0_f64.sqrt().to_bits());
        assert_eq!(config.origin(), ScenarioConfigOrigin::CustomResearch);
        assert_eq!(config.canonical_digest().len(), 64);
    }

    #[test]
    fn zero_interval_is_valid_for_at_most_one_frame() {
        let one_frame = custom(|params| {
            params.frames = 1;
            params.dt_ms = 0;
        });
        assert!(generate(&one_frame).is_ok());
    }

    #[test]
    fn partial_spoof_rejects_invalid_decoupling_instead_of_clamping() {
        let cfg = ScenarioResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named scenario profile must be valid");
        let spoof = StealthySpoof {
            target: Modality::Acoustic,
            start_frame: 0,
        };
        for decoupling in [-0.01, 1.01, f64::NAN, f64::INFINITY] {
            assert!(
                generate_spoofed_partial(&cfg, spoof, decoupling).is_err(),
                "decoupling {decoupling:?} must be rejected"
            );
        }
    }

    #[test]
    fn attack_generators_reject_no_consensus_or_out_of_capture_onsets() {
        let independent = custom(|params| params.rho = 0.0);
        let spoof = StealthySpoof {
            target: Modality::Acoustic,
            start_frame: 0,
        };
        assert!(generate_spoofed(&independent, spoof).is_err());

        let corroborated = custom(|params| params.rho = 0.7);
        let outside = StealthySpoof {
            target: Modality::Acoustic,
            start_frame: corroborated.frames() as u64,
        };
        assert!(generate_spoofed(&corroborated, outside).is_err());

        assert!(
            generate_spoofed_partial(&independent, outside, 0.0).is_ok(),
            "d=0 is the explicitly documented null control"
        );
    }

    #[test]
    fn spoof_targets_must_be_present_and_unique() {
        let cfg = custom(|params| {
            params.modalities = vec![Modality::Visual, Modality::Radar];
            params.rho = 0.7;
        });
        let absent = StealthySpoof {
            target: Modality::Acoustic,
            start_frame: 0,
        };
        assert!(generate_spoofed(&cfg, absent).is_err());
        assert!(generate_collusion(&cfg, &[], 0).is_err());
        assert!(generate_collusion(&cfg, &[Modality::Radar, Modality::Radar], 0).is_err());
        assert_eq!(
            generate_collusion(&cfg, &[Modality::Visual, Modality::Radar], 0)
                .expect("one target per configured modality is accepted")
                .len(),
            cfg.observation_capacity()
        );

        let oversized = [
            Modality::Visual,
            Modality::Radar,
            Modality::Acoustic,
            Modality::Thermal,
            Modality::Lidar,
            Modality::RadioFrequency,
            Modality::Visual,
        ];
        let error = generate_collusion(&cfg, &oversized, 0)
            .expect_err("target cardinality is rejected before duplicate scanning");
        assert!(error
            .to_string()
            .contains("spoof target count 7 exceeds the 2 configured modalities"));
    }

    #[test]
    fn zero_frame_scenario_is_valid_and_empty() {
        let cfg = custom(|params| {
            params.frames = 0;
            params.dt_ms = u64::MAX;
        });
        assert!(generate(&cfg)
            .expect("zero-frame scenario is valid")
            .is_empty());
    }

    #[test]
    fn large_supported_sigma_still_produces_finite_nis() {
        let cfg = custom(|params| {
            params.frames = 100;
            params.sigma = 1e154;
        });
        let stream = generate(&cfg).expect("large finite variance remains representable");
        assert!(stream
            .iter()
            .all(|observation| observation.nis().is_finite()));
    }

    #[test]
    fn named_profile_identity_and_digest_are_exact_and_deterministic() {
        let first = ScenarioResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named profile is valid");
        let second = ScenarioResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named profile is valid");

        assert_eq!(
            (first.origin(), first.canonical_digest()),
            (second.origin(), second.canonical_digest())
        );
        assert_eq!(first.canonical_digest().len(), 64);
        assert_eq!(
            first.canonical_digest(),
            "cf45726fac85052af2f3669f9328b647aa6cc05359a5ef3801f703a2a4931b29"
        );
    }

    #[test]
    fn custom_parameters_never_inherit_named_profile_identity() {
        let named = ScenarioResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named profile is valid");
        let custom = ScenarioConfig::try_new(ScenarioResearchProfile::SyntheticV0_9.params())
            .expect("identical custom parameters are valid");

        assert_eq!(custom.origin(), ScenarioConfigOrigin::CustomResearch);
        assert_ne!(custom.canonical_digest(), named.canonical_digest());
    }

    #[test]
    fn signed_zero_canonicalizes_to_one_independent_regime_identity() {
        let mut positive = ScenarioResearchProfile::SyntheticV0_9.params();
        positive.rho = 0.0;
        let mut negative = positive.clone();
        negative.rho = -0.0;

        let positive = ScenarioConfig::try_new(positive).expect("positive zero is valid");
        let negative = ScenarioConfig::try_new(negative).expect("negative zero is valid");

        assert_eq!(negative.rho().to_bits(), 0.0_f64.to_bits());
        assert_eq!(negative.canonical_digest(), positive.canonical_digest());
    }
}
