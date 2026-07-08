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
}
