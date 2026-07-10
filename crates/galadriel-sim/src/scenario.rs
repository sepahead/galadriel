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

use galadriel_core::{ConsistencyProjection, GaladrielError, Modality, PidObservation, Result};
use rand_distr::{Distribution, Normal};

use crate::rng;

/// Maximum number of observations a single scenario may allocate.
///
/// The simulator is intended for bounded experiments, not unbounded trace
/// materialization. Keeping the limit explicit also prevents an otherwise valid
/// `usize` multiplication from turning an untrusted configuration into a huge
/// allocation request.
pub const MAX_SCENARIO_OBSERVATIONS: usize = 1_000_000;

/// Configuration for a synthetic scenario over a single track.
#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    /// Track id all observations are tagged with.
    pub track_id: u64,
    /// Number of fusion frames.
    pub frames: usize,
    /// Sensor modalities present each frame (one measurement each).
    pub modalities: Vec<Modality>,
    /// Per-axis innovation standard deviation (nominal).
    pub sigma: f64,
    /// Cross-channel correlation via a shared latent, in `[0, 1)`. `0` = channels
    /// independent (the baseline regime); `> 0` = channels corroborate.
    pub rho: f64,
    /// Milliseconds between frames.
    pub dt_ms: u64,
    /// RNG seed.
    pub seed: u64,
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        Self {
            track_id: 1,
            frames: 220,
            modalities: vec![Modality::Visual, Modality::Radar, Modality::Acoustic],
            sigma: 1.0,
            rho: 0.0,
            dt_ms: 100,
            seed: 7,
        }
    }
}

impl ScenarioConfig {
    /// Validate the configuration and all arithmetic used to materialize it.
    ///
    /// # Errors
    ///
    /// Returns [`GaladrielError::InvalidConfig`] when a numeric parameter is
    /// outside its supported range, modalities are empty or duplicated, or the
    /// requested stream cannot be represented within the simulator's bounds.
    pub fn validate(&self) -> Result<()> {
        if !self.sigma.is_finite() || self.sigma <= 0.0 {
            return Err(GaladrielError::InvalidConfig(
                "scenario sigma must be finite and > 0".into(),
            ));
        }
        if !self.rho.is_finite() || !(0.0..1.0).contains(&self.rho) {
            return Err(GaladrielError::InvalidConfig(
                "scenario rho must be finite and in [0, 1)".into(),
            ));
        }
        if self.modalities.is_empty() {
            return Err(GaladrielError::InvalidConfig(
                "scenario must contain at least one modality".into(),
            ));
        }
        if self.frames > 1 && self.dt_ms == 0 {
            return Err(GaladrielError::InvalidConfig(
                "scenario dt_ms must be > 0 when generating multiple frames".into(),
            ));
        }

        let mut seen = HashSet::with_capacity(self.modalities.len());
        if self
            .modalities
            .iter()
            .copied()
            .any(|modality| !seen.insert(modality))
        {
            return Err(GaladrielError::InvalidConfig(
                "scenario modalities must be unique".into(),
            ));
        }

        let observations = self
            .frames
            .checked_mul(self.modalities.len())
            .ok_or_else(|| {
                GaladrielError::InvalidConfig(
                    "scenario frame/modality count overflows usize".into(),
                )
            })?;
        if observations > MAX_SCENARIO_OBSERVATIONS {
            return Err(GaladrielError::InvalidConfig(format!(
                "scenario requests {observations} observations; maximum is {MAX_SCENARIO_OBSERVATIONS}"
            )));
        }

        if let Some(last_frame) = self.frames.checked_sub(1) {
            let last_frame = u64::try_from(last_frame).map_err(|_| {
                GaladrielError::InvalidConfig(
                    "scenario frame index cannot be represented as u64".into(),
                )
            })?;
            last_frame.checked_mul(self.dt_ms).ok_or_else(|| {
                GaladrielError::InvalidConfig("scenario timestamp arithmetic overflows u64".into())
            })?;
        }

        let variance = self.sigma * self.sigma;
        if !variance.is_finite() || variance <= 0.0 {
            return Err(GaladrielError::InvalidConfig(
                "scenario sigma squared must be finite and non-zero".into(),
            ));
        }
        let noise_variance = (1.0 - self.rho) * variance;
        if !noise_variance.is_finite() || noise_variance <= 0.0 {
            return Err(GaladrielError::InvalidConfig(
                "scenario independent-noise variance must be finite and non-zero".into(),
            ));
        }
        if self.rho > 0.0 {
            let common_variance = self.rho * variance;
            if !common_variance.is_finite() || common_variance <= 0.0 {
                return Err(GaladrielError::InvalidConfig(
                    "scenario shared-latent variance must be finite and non-zero".into(),
                ));
            }
        }

        Ok(())
    }
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
    cfg.validate()?;
    if !decoupling.is_finite() || !(0.0..=1.0).contains(&decoupling) {
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
    let var = cfg.sigma * cfg.sigma;
    let common_sd = (rho * var).sqrt();
    let noise_sd = ((1.0 - rho) * var).sqrt();
    let noise = Normal::new(0.0, noise_sd).map_err(|error| {
        GaladrielError::InvalidConfig(format!(
            "could not construct scenario noise distribution: {error}"
        ))
    })?;
    // Only drawn when rho > 0, so rho == 0 reproduces the independent stream exactly.
    let common = if rho > 0.0 {
        Some(Normal::new(0.0, common_sd).map_err(|error| {
            GaladrielError::InvalidConfig(format!(
                "could not construct shared-latent distribution: {error}"
            ))
        })?)
    } else {
        None
    };
    let cov = [[var, 0.0, 0.0], [0.0, var, 0.0], [0.0, 0.0, var]];

    let capacity = cfg
        .frames
        .checked_mul(cfg.modalities.len())
        .ok_or_else(|| {
            GaladrielError::InvalidConfig("scenario capacity arithmetic overflows usize".into())
        })?;
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
            let spoofed = unique_targets.contains(&modality) && frame >= start_frame;
            // Partial decoupling: mix the shared truth `m` and the phantom `p` as
            // `√(1−d)·m + √d·p`. Since m and p are independent with equal variance this
            // preserves the marginal variance for *every* d (so the spoof stays
            // moment-matched: NIS ~ χ²(3) throughout), while the cross-channel covariance
            // with honest channels scales as √(1−d). d = 1 is full decoupling (base = p);
            // d = 0 is no attack (base = m).
            let base = if spoofed {
                let (a, b) = ((1.0 - decoupling).sqrt(), decoupling.sqrt());
                [
                    a * m[0] + b * p[0],
                    a * m[1] + b * p[1],
                    a * m[2] + b * p[2],
                ]
            } else {
                m
            };
            let y = [
                base[0] + noise.sample(&mut r),
                base[1] + noise.sample(&mut r),
                base[2] + noise.sample(&mut r),
            ];
            // Standardize before squaring: `y² / sigma²` is algebraically the
            // same quantity, but this ordering cannot overflow merely because a
            // supported sigma is near the upper end of f64.
            let normalized = [y[0] / cfg.sigma, y[1] / cfg.sigma, y[2] / cfg.sigma];
            let nis = normalized[0] * normalized[0]
                + normalized[1] * normalized[1]
                + normalized[2] * normalized[2];
            if !nis.is_finite() {
                return Err(GaladrielError::InvalidConfig(
                    "scenario sampling produced a non-finite NIS".into(),
                ));
            }
            out.push(PidObservation {
                track_id: cfg.track_id,
                timestamp_ms,
                seq: frame,
                modality,
                nis,
                dof: 3,
                innovation: Some(y),
                innovation_cov: Some(cov),
                consistency_projection: Some(ConsistencyProjection {
                    values: y,
                    dimensions: 3,
                    frame_id: 1,
                    context_id: 1,
                    prior_id: frame + 1,
                }),
            });
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

    fn mean_nis(s: &[PidObservation], m: Modality) -> f64 {
        let v: Vec<f64> = s
            .iter()
            .filter(|o| o.modality == m)
            .map(|o| o.nis)
            .collect();
        v.iter().sum::<f64>() / v.len() as f64
    }

    #[test]
    fn clean_stream_is_chi2_3_on_average() {
        let cfg = ScenarioConfig {
            frames: 2000,
            ..Default::default()
        };
        let s = generate(&cfg).expect("valid clean scenario");
        let mean: f64 = s.iter().map(|o| o.nis).sum::<f64>() / s.len() as f64;
        assert!((mean - 3.0).abs() < 0.3, "mean NIS = {mean}");
    }

    #[test]
    fn correlated_stream_stays_chi2_3_per_channel() {
        // Even with a shared latent, each channel's marginal NIS is χ²(3).
        let cfg = ScenarioConfig {
            frames: 3000,
            rho: 0.7,
            ..Default::default()
        };
        let s = generate(&cfg).expect("valid correlated scenario");
        for m in [Modality::Visual, Modality::Radar, Modality::Acoustic] {
            assert!((mean_nis(&s, m) - 3.0).abs() < 0.35, "{m:?} mean NIS off");
        }
    }

    #[test]
    fn generated_common_projection_has_shared_per_frame_provenance() {
        let cfg = ScenarioConfig {
            frames: 8,
            ..Default::default()
        };
        let stream = generate(&cfg).expect("valid scenario");
        let mut prior_ids = HashSet::new();
        for frame in stream.chunks(cfg.modalities.len()) {
            let first = frame[0]
                .consistency_projection
                .expect("simulator projection");
            assert!(frame.iter().all(|observation| {
                observation
                    .consistency_projection
                    .is_some_and(|projection| {
                        projection.dimensions == first.dimensions
                            && projection.frame_id == first.frame_id
                            && projection.context_id == first.context_id
                            && projection.prior_id == first.prior_id
                    })
            }));
            assert!(prior_ids.insert(first.prior_id));
        }
    }

    #[test]
    fn stealthy_spoof_is_moment_matched_so_the_baseline_is_blind() {
        // The spoofed channel's NIS distribution is unchanged: its mean stays ≈ 3,
        // which is why a magnitude/χ² baseline cannot see this attack.
        let cfg = ScenarioConfig {
            frames: 3000,
            rho: 0.7,
            ..Default::default()
        };
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
            let cfg = ScenarioConfig {
                sigma,
                ..Default::default()
            };
            assert!(generate(&cfg).is_err(), "sigma {sigma:?} must be rejected");
        }

        for rho in [-0.1, 1.0, f64::NAN, f64::INFINITY] {
            let cfg = ScenarioConfig {
                rho,
                ..Default::default()
            };
            assert!(generate(&cfg).is_err(), "rho {rho:?} must be rejected");
        }

        let underflow = ScenarioConfig {
            sigma: f64::MIN_POSITIVE,
            ..Default::default()
        };
        assert!(
            generate(&underflow).is_err(),
            "derived zero variance must be rejected"
        );
    }

    #[test]
    fn config_requires_nonempty_unique_modalities() {
        let empty = ScenarioConfig {
            modalities: Vec::new(),
            ..Default::default()
        };
        assert!(generate(&empty).is_err());

        let duplicate = ScenarioConfig {
            modalities: vec![Modality::Radar, Modality::Radar],
            ..Default::default()
        };
        assert!(generate(&duplicate).is_err());
    }

    #[test]
    fn config_guards_capacity_and_timestamp_arithmetic() {
        let too_many = ScenarioConfig {
            frames: MAX_SCENARIO_OBSERVATIONS + 1,
            modalities: vec![Modality::Visual],
            ..Default::default()
        };
        assert!(generate(&too_many).is_err());

        let capacity_overflow = ScenarioConfig {
            frames: usize::MAX,
            modalities: vec![Modality::Visual, Modality::Radar],
            ..Default::default()
        };
        assert!(generate(&capacity_overflow).is_err());

        let timestamp_overflow = ScenarioConfig {
            frames: 3,
            dt_ms: u64::MAX,
            ..Default::default()
        };
        assert!(generate(&timestamp_overflow).is_err());

        let frozen_timestamps = ScenarioConfig {
            frames: 2,
            dt_ms: 0,
            ..Default::default()
        };
        assert!(generate(&frozen_timestamps).is_err());
    }

    #[test]
    fn zero_interval_is_valid_for_at_most_one_frame() {
        let one_frame = ScenarioConfig {
            frames: 1,
            dt_ms: 0,
            ..Default::default()
        };
        assert!(generate(&one_frame).is_ok());
    }

    #[test]
    fn partial_spoof_rejects_invalid_decoupling_instead_of_clamping() {
        let cfg = ScenarioConfig::default();
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
        let independent = ScenarioConfig {
            rho: 0.0,
            ..Default::default()
        };
        let spoof = StealthySpoof {
            target: Modality::Acoustic,
            start_frame: 0,
        };
        assert!(generate_spoofed(&independent, spoof).is_err());

        let corroborated = ScenarioConfig {
            rho: 0.7,
            ..Default::default()
        };
        let outside = StealthySpoof {
            target: Modality::Acoustic,
            start_frame: corroborated.frames as u64,
        };
        assert!(generate_spoofed(&corroborated, outside).is_err());

        assert!(
            generate_spoofed_partial(&independent, outside, 0.0).is_ok(),
            "d=0 is the explicitly documented null control"
        );
    }

    #[test]
    fn spoof_targets_must_be_present_and_unique() {
        let cfg = ScenarioConfig {
            modalities: vec![Modality::Visual, Modality::Radar],
            ..Default::default()
        };
        let absent = StealthySpoof {
            target: Modality::Acoustic,
            start_frame: 0,
        };
        assert!(generate_spoofed(&cfg, absent).is_err());
        assert!(generate_collusion(&cfg, &[], 0).is_err());
        assert!(generate_collusion(&cfg, &[Modality::Radar, Modality::Radar], 0).is_err());
    }

    #[test]
    fn zero_frame_scenario_is_valid_and_empty() {
        let cfg = ScenarioConfig {
            frames: 0,
            dt_ms: u64::MAX,
            ..Default::default()
        };
        assert!(generate(&cfg)
            .expect("zero-frame scenario is valid")
            .is_empty());
    }

    #[test]
    fn large_supported_sigma_still_produces_finite_nis() {
        let cfg = ScenarioConfig {
            frames: 100,
            sigma: 1e154,
            ..Default::default()
        };
        let stream = generate(&cfg).expect("large finite variance remains representable");
        assert!(stream.iter().all(|observation| observation.nis.is_finite()));
    }
}
