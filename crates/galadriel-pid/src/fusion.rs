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

use std::collections::HashSet;

use galadriel_core::{DetectorConfig, Mirror, MirrorReport, Modality, PidObservation, Verdict};

use crate::{analyze, scalar_channels, PidConfig, PidReport, PidVerdict};

/// The unified verdict.
#[derive(Debug, Clone, PartialEq)]
pub enum FusedVerdict {
    /// All channels corroborate and NIS is consistent.
    Nominal,
    /// One or more channels compromised. `stealthy` is true when the catch came from
    /// PID decoupling while the baseline saw *in-covariance* NIS — the moment-matched
    /// spoof the baseline is blind to.
    Spoof {
        channels: Vec<Modality>,
        stealthy: bool,
    },
    /// All channels' NIS inflated together while correlation stays intact — denial.
    Jam,
    /// Neither detector has enough evidence. Fail closed.
    InsufficientEvidence,
}

/// The fused report carries both component reports for transparency.
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

/// Fuse a baseline report and a PID report into one verdict.
pub fn fuse(baseline: MirrorReport, pid: PidReport) -> FusedReport {
    let elevated: HashSet<Modality> = baseline
        .channels
        .iter()
        .filter(|c| c.anomalous())
        .map(|c| c.modality)
        .collect();
    let decoupled: Vec<Modality> = pid
        .channels
        .iter()
        .filter(|c| c.decoupled)
        .map(|c| c.modality)
        .collect();

    let baseline_out = matches!(baseline.verdict, Verdict::InsufficientEvidence);
    let pid_out = matches!(pid.verdict, PidVerdict::InsufficientEvidence);

    let (verdict, note) = if baseline_out && pid_out {
        (
            FusedVerdict::InsufficientEvidence,
            "both detectors lack evidence — fail closed".to_string(),
        )
    } else if !decoupled.is_empty() {
        // A decoupled channel is a spoof; it is stealthy iff its NIS stayed in-covariance.
        let stealthy = decoupled.iter().all(|m| !elevated.contains(m));
        let names: Vec<&str> = decoupled.iter().map(|m| m.label()).collect();
        let kind = if stealthy {
            "moment-matched — NIS in-covariance, correlation broken"
        } else {
            "loud — NIS inflated and correlation broken"
        };
        (
            FusedVerdict::Spoof {
                channels: decoupled,
                stealthy,
            },
            format!("PID decoupling on {} ({kind})", names.join(", ")),
        )
    } else {
        match &baseline.verdict {
            Verdict::Jam => (
                FusedVerdict::Jam,
                "all channels' NIS inflated, correlation intact — denial".to_string(),
            ),
            Verdict::Spoof { channels } => {
                let names: Vec<&str> = channels.iter().map(|m| m.label()).collect();
                (
                    FusedVerdict::Spoof {
                        channels: channels.clone(),
                        stealthy: false,
                    },
                    format!(
                        "baseline NIS spike on {} — magnitude spoof",
                        names.join(", ")
                    ),
                )
            }
            _ => (
                FusedVerdict::Nominal,
                "all channels corroborate and NIS is consistent".to_string(),
            ),
        }
    };

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
