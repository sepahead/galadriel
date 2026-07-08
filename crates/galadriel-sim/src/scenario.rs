//! Synthetic multi-sensor innovation streams with χ²(3) NIS under the null.

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
            dt_ms: 100,
            seed: 7,
        }
    }
}

/// Generate a clean stream: for each frame, one measurement per modality whose
/// innovation `y ~ N(0, σ²I₃)` gives `NIS = yᵀ S⁻¹ y ~ χ²(3)`.
///
/// Observations are emitted frame-major (all modalities of frame 0, then frame 1,
/// …), so downstream code can chunk by `modalities.len()` to recover frames.
pub fn generate(cfg: &ScenarioConfig) -> Vec<PidObservation> {
    let mut r = rng::seeded(cfg.seed);
    let normal = Normal::new(0.0, cfg.sigma).expect("sigma must be finite and > 0");
    let var = cfg.sigma * cfg.sigma;
    let cov = [[var, 0.0, 0.0], [0.0, var, 0.0], [0.0, 0.0, var]];
    let mut out = Vec::with_capacity(cfg.frames * cfg.modalities.len());
    for f in 0..cfg.frames {
        for &m in &cfg.modalities {
            let y = [
                normal.sample(&mut r),
                normal.sample(&mut r),
                normal.sample(&mut r),
            ];
            let nis = y[0] * y[0] / var + y[1] * y[1] / var + y[2] * y[2] / var;
            out.push(PidObservation {
                track_id: cfg.track_id,
                timestamp_ms: f as u64 * cfg.dt_ms,
                seq: f as u64,
                modality: m,
                nis,
                dof: 3,
                innovation: Some(y),
                innovation_cov: Some(cov),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_stream_is_chi2_3_on_average() {
        let cfg = ScenarioConfig {
            frames: 2000,
            ..Default::default()
        };
        let s = generate(&cfg);
        let mean: f64 = s.iter().map(|o| o.nis).sum::<f64>() / s.len() as f64;
        // E[χ²(3)] = 3; loose bound for a finite sample.
        assert!((mean - 3.0).abs() < 0.3, "mean NIS = {mean}");
    }
}
