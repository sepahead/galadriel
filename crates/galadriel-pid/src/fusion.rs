//! Fusing the two detectors into one jam-vs-spoof verdict.
//!
//! The evaluation (`docs/EVALUATION.md`) shows the NIS baseline and the PID engine
//! are **complementary**: the baseline owns *magnitude* attacks (a loud bias spoof,
//! a jam), the PID engine owns *cross-channel decoupling* (a moment-matched stealthy
//! spoof). Fusing them yields a detector that covers the whole space and, crucially,
//! reports *how* a spoof was caught:
//!
//! | | correlation intact | PID decoupling |
//! |---|---|---|
//! | **NIS in-covariance** | `Nominal` | `Spoof { stealthy: true }` |
//! | **one channel's NIS inflated** | `Spoof { stealthy: false }` | `Spoof { stealthy: false }` |
//! | **all channels' NIS inflated** | `Jam` | `Spoof` (jam + decoupling) |

use galadriel_core::{
    combine, DetectorConfig, FusedVerdict, Mirror, MirrorReport, Modality, PidObservation,
};

use crate::{analyze, scalar_channels, PidConfig, PidReport, PidVerdict};

/// The fused report carries both component reports for transparency. The verdict type
/// ([`FusedVerdict`]) is shared with the pure default via `galadriel_core::fusion`, so
/// the MI escalation and the correlation default speak the same language.
#[derive(Debug, Clone)]
pub struct FusedReport {
    /// The unified verdict.
    pub verdict: FusedVerdict,
    /// The baseline (NIS χ²) report.
    pub baseline: MirrorReport,
    /// The PID report.
    pub pid: PidReport,
    /// Rationale.
    pub note: String,
}

/// Fuse a baseline report and a PID report into one verdict, using the shared
/// source-agnostic [`combine`] with the PID engine as the consistency source.
pub fn fuse(baseline: MirrorReport, pid: PidReport) -> FusedReport {
    let decoupled: Vec<Modality> = pid
        .channels
        .iter()
        .filter(|c| c.decoupled)
        .map(|c| c.modality)
        .collect();
    let pid_out = matches!(pid.verdict, PidVerdict::InsufficientEvidence);
    let (verdict, note) = combine(&baseline, &decoupled, pid_out);
    FusedReport {
        verdict,
        baseline,
        pid,
        note,
    }
}

/// Run both detectors over a whole (single-track) stream and fuse them.
pub fn assess_stream(
    stream: &[PidObservation],
    modalities: &[Modality],
    baseline_cfg: &DetectorConfig,
    pid_cfg: &PidConfig,
) -> FusedReport {
    let mut mirror = Mirror::new(baseline_cfg.clone());
    for o in stream {
        mirror.ingest(o);
    }
    let track = stream.first().map_or(0, |o| o.track_id);
    let last_seq = stream.iter().map(|o| o.seq).max().unwrap_or(0);
    let baseline = mirror.assess(track, last_seq);
    let pid = analyze(&scalar_channels(stream, modalities, 0), pid_cfg);
    fuse(baseline, pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use galadriel_sim::injection::{inject, BroadbandJam, PhantomAcousticDoa};
    use galadriel_sim::scenario::{generate, generate_spoofed, ScenarioConfig, StealthySpoof};

    const MODS: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

    fn scen() -> ScenarioConfig {
        ScenarioConfig {
            frames: 300,
            rho: 0.7,
            seed: 5,
            ..Default::default()
        }
    }

    fn fused(stream: &[PidObservation]) -> FusedVerdict {
        assess_stream(
            stream,
            &MODS,
            &DetectorConfig::default(),
            &PidConfig::default(),
        )
        .verdict
    }

    #[test]
    fn clean_is_nominal() {
        assert_eq!(fused(&generate(&scen())), FusedVerdict::Nominal);
    }

    #[test]
    fn stealthy_spoof_is_flagged_stealthy() {
        let s = generate_spoofed(
            &scen(),
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: 100,
            },
        );
        match fused(&s) {
            FusedVerdict::Spoof { channels, stealthy } => {
                assert!(channels.contains(&Modality::Acoustic));
                assert!(stealthy, "moment-matched spoof should be flagged stealthy");
            }
            other => panic!("expected stealthy Spoof, got {other:?}"),
        }
    }

    #[test]
    fn loud_bias_spoof_is_flagged_non_stealthy() {
        let mut s = generate(&scen());
        inject(
            &mut s,
            &PhantomAcousticDoa {
                target: Modality::Acoustic,
                start_frame: 100,
                bias: 8.0,
            },
        );
        match fused(&s) {
            FusedVerdict::Spoof { channels, stealthy } => {
                assert!(channels.contains(&Modality::Acoustic));
                assert!(!stealthy, "a loud magnitude spoof is not stealthy");
            }
            other => panic!("expected non-stealthy Spoof, got {other:?}"),
        }
    }

    #[test]
    fn jam_is_jam() {
        let mut s = generate(&scen());
        inject(
            &mut s,
            &BroadbandJam {
                start_frame: 100,
                inflation: 3.0,
            },
        );
        assert_eq!(fused(&s), FusedVerdict::Jam);
    }
}
