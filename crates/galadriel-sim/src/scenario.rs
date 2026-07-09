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

use galadriel_core::observation::{Modality, PidObservation};
use rand_distr::{Distribution, Normal};

use crate::rng;

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

fn generate_inner(
    cfg: &ScenarioConfig,
    spoof: Option<StealthySpoof>,
    decoupling: f64,
) -> Vec<PidObservation> {
    let mut r = rng::seeded(cfg.seed);
    let rho = cfg.rho.clamp(0.0, 0.999);
    let var = cfg.sigma * cfg.sigma;
    let common_sd = (rho * var).sqrt();
    let noise_sd = ((1.0 - rho) * var).sqrt();
    let noise = Normal::new(0.0, noise_sd.max(1e-12)).expect("valid noise sd");
    // Only drawn when rho > 0, so rho == 0 reproduces the independent stream exactly.
    let common = Normal::new(0.0, common_sd.max(1e-12)).expect("valid common sd");
    let cov = [[var, 0.0, 0.0], [0.0, var, 0.0], [0.0, 0.0, var]];

    let mut out = Vec::with_capacity(cfg.frames * cfg.modalities.len());
    for f in 0..cfg.frames {
        // Shared "truth" latent m and an independent phantom latent p for this frame.
        let (m, p) = if rho > 0.0 {
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
            let spoofed =
                matches!(spoof, Some(s) if s.target == modality && f as u64 >= s.start_frame);
            // Partial decoupling: mix the shared truth `m` and the phantom `p` as
            // `√(1−d)·m + √d·p`. Since m and p are independent with equal variance this
            // preserves the marginal variance for *every* d (so the spoof stays
            // moment-matched: NIS ~ χ²(3) throughout), while the cross-channel covariance
            // with honest channels scales as √(1−d). d = 1 is full decoupling (base = p);
            // d = 0 is no attack (base = m).
            let base = if spoofed {
                let d = decoupling.clamp(0.0, 1.0);
                let (a, b) = ((1.0 - d).sqrt(), d.sqrt());
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
            let nis = y[0] * y[0] / var + y[1] * y[1] / var + y[2] * y[2] / var;
            out.push(PidObservation {
                track_id: cfg.track_id,
                timestamp_ms: f as u64 * cfg.dt_ms,
                seq: f as u64,
                modality,
                nis,
                dof: 3,
                innovation: Some(y),
                innovation_cov: Some(cov),
            });
        }
    }
    out
}

/// Generate a clean stream (independent if `rho == 0`, corroborated if `rho > 0`).
///
/// Observations are emitted frame-major (all modalities of frame 0, then frame 1,
/// …), so downstream code can chunk by `modalities.len()` to recover frames.
pub fn generate(cfg: &ScenarioConfig) -> Vec<PidObservation> {
    generate_inner(cfg, None, 1.0)
}

/// Generate a corroborated stream with a **fully** moment-matched stealthy spoof on one
/// channel (the target decouples onto an independent phantom latent). Requires
/// `cfg.rho > 0` for the spoof to be meaningful (otherwise there is no consensus to
/// decouple from).
pub fn generate_spoofed(cfg: &ScenarioConfig, spoof: StealthySpoof) -> Vec<PidObservation> {
    generate_inner(cfg, Some(spoof), 1.0)
}

/// Generate a stealthy spoof with a tunable **decoupling strength** `d ∈ [0, 1]`: the
/// target tracks `√(1−d)·(shared truth) + √d·(phantom)`, preserving its marginal variance
/// (so it stays moment-matched, NIS ~ χ²(3)) while its correlation with honest channels
/// scales as `√(1−d)`. `d = 1` is [`generate_spoofed`]; `d = 0` is [`generate`]. Sweeping
/// `d` traces the detection *boundary* — how weak a decoupling each detector can still see.
pub fn generate_spoofed_partial(
    cfg: &ScenarioConfig,
    spoof: StealthySpoof,
    decoupling: f64,
) -> Vec<PidObservation> {
    generate_inner(cfg, Some(spoof), decoupling)
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
        let s = generate(&cfg);
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
        let s = generate(&cfg);
        for m in [Modality::Visual, Modality::Radar, Modality::Acoustic] {
            assert!((mean_nis(&s, m) - 3.0).abs() < 0.35, "{m:?} mean NIS off");
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
        );
        assert!(
            (mean_nis(&s, Modality::Acoustic) - 3.0).abs() < 0.35,
            "stealthy spoof should NOT inflate NIS"
        );
    }
}
