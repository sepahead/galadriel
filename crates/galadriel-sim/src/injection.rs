//! Attack injections that transform a clean stream into a spoof or a jam.

use galadriel_core::observation::{Modality, PidObservation};

/// Recompute `nis` from the (diagonal) innovation + covariance after a mutation.
fn recompute_nis(obs: &mut PidObservation) {
    if let (Some(y), Some(s)) = (obs.innovation, obs.innovation_cov) {
        let mut nis = 0.0;
        for i in 0..3 {
            let sii = s[i][i];
            if sii > 0.0 {
                nis += y[i] * y[i] / sii;
            }
        }
        obs.nis = nis;
    }
}

/// A per-observation attack transform.
pub trait Injection {
    /// A short name for logging/UX.
    fn name(&self) -> &'static str;
    /// Mutate one observation in place.
    fn apply(&self, obs: &mut PidObservation);
}

/// Apply an injection across a whole stream in place.
pub fn inject(stream: &mut [PidObservation], injection: &dyn Injection) {
    for obs in stream.iter_mut() {
        injection.apply(obs);
    }
}

/// A targeted single-channel spoof: a persistent bias on one modality's
/// innovation from `start_frame`, inflating **only that channel's** NIS — the
/// cross-channel signature of a false-data injection (e.g. a phased acoustic
/// emitter dragging a DOA peak).
#[derive(Debug, Clone)]
pub struct PhantomAcousticDoa {
    /// Modality to corrupt.
    pub target: Modality,
    /// Frame the injection begins.
    pub start_frame: u64,
    /// Bias added to the first innovation axis (in σ units).
    pub bias: f64,
}

impl Injection for PhantomAcousticDoa {
    fn name(&self) -> &'static str {
        "phantom-doa"
    }

    fn apply(&self, obs: &mut PidObservation) {
        if obs.modality == self.target && obs.seq >= self.start_frame {
            if let Some(mut y) = obs.innovation {
                y[0] += self.bias;
                obs.innovation = Some(y);
                recompute_nis(obs);
            } else {
                obs.nis += self.bias * self.bias;
            }
        }
    }
}

/// Broadband denial: from `start_frame`, **every** channel's innovation is scaled
/// by `inflation` (> 1), raising NIS on all modalities together — the correlated
/// signature of jamming / link degradation.
#[derive(Debug, Clone)]
pub struct BroadbandJam {
    /// Frame the jam begins.
    pub start_frame: u64,
    /// Multiplicative innovation inflation (> 1).
    pub inflation: f64,
}

impl Injection for BroadbandJam {
    fn name(&self) -> &'static str {
        "broadband-jam"
    }

    fn apply(&self, obs: &mut PidObservation) {
        if obs.seq >= self.start_frame {
            if let Some(mut y) = obs.innovation {
                for v in y.iter_mut() {
                    *v *= self.inflation;
                }
                obs.innovation = Some(y);
                recompute_nis(obs);
            } else {
                obs.nis *= self.inflation * self.inflation;
            }
        }
    }
}

/// A **benign target maneuver** (not an attack): from `start_frame`, a deterministic
/// triangular ramp of peak height `magnitude` over `duration` frames is added to every
/// channel's first innovation axis — but each modality sees it with its own **lag**
/// (`lag_step` × the modality's index), modelling heterogeneous sensor dynamics/latency.
///
/// A *synchronized* maneuver (`lag_step = 0`) stays perfectly correlated across channels,
/// so the consistency detectors should not flag it; the per-channel lag transiently
/// **decorrelates** the channels through the ramp, a benign false-positive source the
/// consistency check cannot distinguish from a spoof. This is a first-order proxy for
/// maneuver-induced non-stationarity — the false-alarm regime the stationary sim omits.
#[derive(Debug, Clone)]
pub struct Maneuver {
    /// Frame the maneuver begins.
    pub start_frame: u64,
    /// Length of the ramp (frames).
    pub duration: u64,
    /// Peak ramp height added to innovation axis 0 (σ units).
    pub magnitude: f64,
    /// Per-modality lag: modality with discriminant `i` is delayed by `i × lag_step` frames.
    pub lag_step: u64,
}

impl Maneuver {
    fn profile(&self, seq: u64, lag: u64) -> f64 {
        let s = self.start_frame + lag;
        if self.duration == 0 || seq < s || seq >= s + self.duration {
            return 0.0;
        }
        let t = (seq - s) as f64 / self.duration as f64; // 0..1
        let tri = 1.0 - (2.0 * t - 1.0).abs(); // triangular bump: 0 at ends, 1 at centre
        self.magnitude * tri
    }
}

impl Injection for Maneuver {
    fn name(&self) -> &'static str {
        "maneuver"
    }

    fn apply(&self, obs: &mut PidObservation) {
        let lag = (obs.modality as u64) * self.lag_step;
        let add = self.profile(obs.seq, lag);
        if add != 0.0 {
            if let Some(mut y) = obs.innovation {
                y[0] += add;
                obs.innovation = Some(y);
                recompute_nis(obs);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{generate, ScenarioConfig};
    use galadriel_core::{DetectorConfig, Mirror, Verdict};

    fn final_verdict(stream: &[PidObservation], n_mods: usize) -> Verdict {
        let mut m = Mirror::new(DetectorConfig::default());
        let track = stream[0].track_id;
        let mut last = None;
        for chunk in stream.chunks(n_mods) {
            for o in chunk {
                m.ingest(o);
            }
            last = Some(m.assess(track, chunk[0].seq));
        }
        last.expect("non-empty stream").verdict
    }

    #[test]
    fn clean_is_nominal() {
        let cfg = ScenarioConfig::default();
        let s = generate(&cfg);
        assert_eq!(final_verdict(&s, cfg.modalities.len()), Verdict::Nominal);
    }

    #[test]
    fn phantom_is_spoof_on_the_targeted_channel() {
        let cfg = ScenarioConfig::default();
        let mut s = generate(&cfg);
        inject(
            &mut s,
            &PhantomAcousticDoa {
                target: Modality::Acoustic,
                start_frame: 110,
                bias: 8.0,
            },
        );
        match final_verdict(&s, cfg.modalities.len()) {
            Verdict::Spoof { channels } => assert!(channels.contains(&Modality::Acoustic)),
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    fn broadband_jam_is_jam() {
        let cfg = ScenarioConfig::default();
        let mut s = generate(&cfg);
        inject(
            &mut s,
            &BroadbandJam {
                start_frame: 110,
                inflation: 3.0,
            },
        );
        assert_eq!(final_verdict(&s, cfg.modalities.len()), Verdict::Jam);
    }

    #[test]
    fn phantom_scalar_fallback_raises_nis_by_bias_squared() {
        // A baseline-only observation (innovation None) exercises the scalar NIS fallback.
        let mut obs = PidObservation::scalar(1, 500, 5, Modality::Acoustic, 3.0, 3);
        PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 5,
            bias: 4.0,
        }
        .apply(&mut obs);
        assert!((obs.nis - (3.0 + 16.0)).abs() < 1e-9, "nis={}", obs.nis);

        let mut early = PidObservation::scalar(1, 0, 0, Modality::Acoustic, 3.0, 3);
        PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 5,
            bias: 4.0,
        }
        .apply(&mut early);
        assert!((early.nis - 3.0).abs() < 1e-12, "pre-onset untouched");
    }

    #[test]
    fn jam_scalar_fallback_scales_nis_by_inflation_squared() {
        let mut obs = PidObservation::scalar(1, 500, 5, Modality::Radar, 4.0, 3);
        BroadbandJam {
            start_frame: 5,
            inflation: 3.0,
        }
        .apply(&mut obs);
        assert!((obs.nis - 4.0 * 9.0).abs() < 1e-9, "nis={}", obs.nis);
    }

    #[test]
    fn maneuver_perturbs_the_innovation_inside_its_window() {
        let cfg = ScenarioConfig {
            frames: 200,
            seed: 3,
            ..Default::default()
        };
        let base = generate(&cfg);
        let mut man = base.clone();
        inject(
            &mut man,
            &Maneuver {
                start_frame: 100,
                duration: 20,
                magnitude: 8.0,
                lag_step: 0,
            },
        );
        // Inside the maneuver window the innovation is perturbed; well outside it is untouched.
        let mid = man
            .iter()
            .zip(&base)
            .find(|(m, _)| m.seq == 108 && m.modality == Modality::Visual)
            .unwrap();
        assert!(
            (mid.0.innovation.unwrap()[0] - mid.1.innovation.unwrap()[0]).abs() > 1.0,
            "innovation should be perturbed mid-maneuver"
        );
        let far = man
            .iter()
            .zip(&base)
            .find(|(m, _)| m.seq == 5 && m.modality == Modality::Visual)
            .unwrap();
        assert!(
            (far.0.innovation.unwrap()[0] - far.1.innovation.unwrap()[0]).abs() < 1e-12,
            "innovation should be untouched before the maneuver"
        );
    }
}
