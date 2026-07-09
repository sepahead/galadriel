//! Fusing the NIS magnitude baseline with a cross-sensor **consistency** detector
//! into one jam-vs-spoof verdict.
//!
//! The fusion logic is **source-agnostic** ([`combine`]): it takes the baseline's
//! per-channel elevation and *any* consistency detector's decoupled-channel set —
//! the cheap [`crate::correlation`] detector by default, or the `pid` engine as an
//! escalation — and produces one [`FusedVerdict`]. This crate wires the **pure
//! default** ([`assess_default`], NIS ⊕ correlation, no heavy dependency); the `pid`
//! crate reuses [`combine`] for its MI-based variant, so both speak the same verdict.
//!
//! | | correlation intact | consistency decoupling |
//! |---|---|---|
//! | **NIS in-covariance** | `Nominal` | `Spoof { stealthy: true }` |
//! | **one channel's NIS inflated** | `Spoof { stealthy: false }` | `Spoof { stealthy: false }` |
//! | **all channels' NIS inflated** | `Jam` | `Spoof` |

use std::collections::HashSet;

use crate::correlation::{self, CorrConfig, CorrReport, CorrVerdict};
use crate::{DetectorConfig, Mirror, MirrorReport, Modality, PidObservation, Verdict};

/// The unified verdict, shared by the correlation default and the PID escalation.
#[derive(Debug, Clone, PartialEq)]
pub enum FusedVerdict {
    /// All channels corroborate and NIS is consistent.
    Nominal,
    /// One or more channels compromised. `stealthy` is true when the catch came from a
    /// consistency decoupling while the baseline saw *in-covariance* NIS — the
    /// moment-matched spoof the magnitude baseline is blind to.
    Spoof {
        channels: Vec<Modality>,
        stealthy: bool,
    },
    /// All channels' NIS inflated together while correlation stays intact — denial.
    Jam,
    /// Neither detector has enough evidence. Fail closed.
    InsufficientEvidence,
}

/// Source-agnostic 2×2 fusion: combine the NIS baseline report with a consistency
/// detector's `decoupled` channel set (from correlation *or* PID) into one verdict.
/// `consistency_insufficient` is true when the consistency detector itself lacked
/// evidence.
pub fn combine(
    baseline: &MirrorReport,
    decoupled: &[Modality],
    consistency_insufficient: bool,
) -> (FusedVerdict, String) {
    let elevated: HashSet<Modality> = baseline
        .channels
        .iter()
        .filter(|c| c.anomalous())
        .map(|c| c.modality)
        .collect();
    let baseline_out = matches!(baseline.verdict, Verdict::InsufficientEvidence);

    if baseline_out && consistency_insufficient {
        return (
            FusedVerdict::InsufficientEvidence,
            "both detectors lack evidence — fail closed".to_string(),
        );
    }

    if !decoupled.is_empty() {
        let stealthy = decoupled.iter().all(|m| !elevated.contains(m));
        let names: Vec<&str> = decoupled.iter().map(|m| m.label()).collect();
        let kind = if stealthy {
            "moment-matched — NIS in-covariance, cross-channel structure broken"
        } else {
            "loud — NIS inflated and cross-channel structure broken"
        };
        return (
            FusedVerdict::Spoof {
                channels: decoupled.to_vec(),
                stealthy,
            },
            format!("cross-sensor decoupling on {} ({kind})", names.join(", ")),
        );
    }

    match &baseline.verdict {
        Verdict::Jam => (
            FusedVerdict::Jam,
            "all channels' NIS inflated, cross-channel structure intact — denial".to_string(),
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
        Verdict::Nominal => (
            FusedVerdict::Nominal,
            "all channels corroborate and NIS is consistent".to_string(),
        ),
        // Baseline could not assess magnitude and there is no decoupling to escalate on:
        // fail closed rather than silently upgrade an insufficient baseline to Nominal.
        Verdict::InsufficientEvidence => (
            FusedVerdict::InsufficientEvidence,
            "baseline lacks magnitude evidence and no decoupling seen — fail closed".to_string(),
        ),
    }
}

/// The pure default fused report (NIS baseline ⊕ correlation consistency).
#[derive(Debug, Clone)]
pub struct DefaultReport {
    /// The unified verdict.
    pub verdict: FusedVerdict,
    /// The NIS baseline report.
    pub baseline: MirrorReport,
    /// The correlation consistency report.
    pub correlation: CorrReport,
    /// Rationale.
    pub note: String,
}

/// The **pure default** cross-sensor detector: run the NIS baseline and the cheap
/// correlation consistency check over a whole (single-track) stream, and fuse them.
/// No heavy dependency; this is the complete detector the default build ships.
pub fn assess_default(
    stream: &[PidObservation],
    modalities: &[Modality],
    baseline_cfg: &DetectorConfig,
    corr_cfg: &CorrConfig,
) -> DefaultReport {
    let mut mirror = Mirror::new(baseline_cfg.clone());
    for o in stream {
        mirror.ingest(o);
    }
    let track = stream.first().map_or(0, |o| o.track_id);
    let last_seq = stream.iter().map(|o| o.seq).max().unwrap_or(0);
    let baseline = mirror.assess(track, last_seq);

    let corr = correlation::analyze(&crate::scalar_channels(stream, modalities, 0), corr_cfg);
    let decoupled: Vec<Modality> = corr
        .channels
        .iter()
        .filter(|c| c.decoupled)
        .map(|c| c.modality)
        .collect();
    let cons_out = matches!(corr.verdict, CorrVerdict::InsufficientEvidence);

    let (verdict, note) = combine(&baseline, &decoupled, cons_out);
    DefaultReport {
        verdict,
        baseline,
        correlation: corr,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::ChannelReport;

    fn ch(modality: Modality, elevated: bool) -> ChannelReport {
        ChannelReport {
            modality,
            n: 64,
            mean_nis: if elevated { 20.0 } else { 3.0 },
            p_right: if elevated { 1e-9 } else { 0.5 },
            elevated,
            cusum_alarm: elevated,
            ready: true,
        }
    }

    fn baseline(verdict: Verdict, elevated: &[Modality]) -> MirrorReport {
        let all = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        MirrorReport {
            track_id: 1,
            seq: 100,
            verdict,
            channels: all.iter().map(|&m| ch(m, elevated.contains(&m))).collect(),
            note: String::new(),
        }
    }

    #[test]
    fn nominal_when_nothing_flagged() {
        let (v, _) = combine(&baseline(Verdict::Nominal, &[]), &[], false);
        assert_eq!(v, FusedVerdict::Nominal);
    }

    #[test]
    fn decoupling_with_in_covariance_nis_is_stealthy_spoof() {
        // baseline sees nothing (Nominal), correlation flags acoustic → stealthy.
        let (v, _) = combine(
            &baseline(Verdict::Nominal, &[]),
            &[Modality::Acoustic],
            false,
        );
        assert_eq!(
            v,
            FusedVerdict::Spoof {
                channels: vec![Modality::Acoustic],
                stealthy: true
            }
        );
    }

    #[test]
    fn decoupling_with_elevated_nis_is_loud_spoof() {
        let b = baseline(
            Verdict::Spoof {
                channels: vec![Modality::Acoustic],
            },
            &[Modality::Acoustic],
        );
        let (v, _) = combine(&b, &[Modality::Acoustic], false);
        assert_eq!(
            v,
            FusedVerdict::Spoof {
                channels: vec![Modality::Acoustic],
                stealthy: false
            }
        );
    }

    #[test]
    fn baseline_jam_no_decoupling_is_jam() {
        let all = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let (v, _) = combine(&baseline(Verdict::Jam, &all), &[], false);
        assert_eq!(v, FusedVerdict::Jam);
    }

    #[test]
    fn baseline_spoof_no_decoupling_is_non_stealthy_spoof() {
        let b = baseline(
            Verdict::Spoof {
                channels: vec![Modality::Radar],
            },
            &[Modality::Radar],
        );
        let (v, _) = combine(&b, &[], false);
        assert_eq!(
            v,
            FusedVerdict::Spoof {
                channels: vec![Modality::Radar],
                stealthy: false
            }
        );
    }

    #[test]
    fn both_insufficient_fails_closed() {
        let (v, _) = combine(&baseline(Verdict::InsufficientEvidence, &[]), &[], true);
        assert_eq!(v, FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn insufficient_baseline_without_decoupling_fails_closed_not_nominal() {
        // Baseline can't assess magnitude; the consistency check HAS evidence and sees no
        // decoupling. We must NOT upgrade to Nominal (we never verified magnitude) — the
        // fail-closed contract of Verdict::InsufficientEvidence.
        let (v, _) = combine(&baseline(Verdict::InsufficientEvidence, &[]), &[], false);
        assert_eq!(v, FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn insufficient_baseline_with_decoupling_still_escalates_to_spoof() {
        // A consistency decoupling escalates to Spoof even when the baseline is out.
        let (v, _) = combine(
            &baseline(Verdict::InsufficientEvidence, &[]),
            &[Modality::Acoustic],
            false,
        );
        assert_eq!(
            v,
            FusedVerdict::Spoof {
                channels: vec![Modality::Acoustic],
                stealthy: true
            }
        );
    }
}
