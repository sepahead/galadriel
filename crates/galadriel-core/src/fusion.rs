//! Fusing the NIS magnitude baseline with a cross-sensor **consistency** detector
//! into one jam-vs-spoof verdict.
//!
//! The fusion logic is **source-agnostic** ([`combine`]): it takes the baseline's
//! per-channel elevation and *any* consistency detector's decoupled-channel set —
//! the cheap [`crate::correlation`] detector by default, or the `pid` engine as an
//! escalation — and produces one [`FusedVerdict`]. This crate wires the **pure
//! default** ([`assess_default`], NIS ⊕ correlation, no heavy dependency); the `pid`
//! crate reuses [`combine`] for its MI-based escalation, so both speak the same
//! advisory verdict.
//!
//! | | correlation intact | consistency decoupling |
//! |---|---|---|
//! | **NIS in-covariance** | `Nominal` | `Spoof { magnitude: InCovariance }` |
//! | **one channel's NIS inflated** | `Spoof { magnitude: Elevated }` | `Spoof` |
//! | **configured broad fraction of ready channels' NIS inflated** | `Jam` | `Spoof` or fail-closed `Anomaly` |
//!
//! Every active producer-attested projection axis is assessed. The correlation
//! family budget is split across axes; contradictory or partly unavailable positive
//! axis attribution is an `Anomaly`, never a confident `Spoof`.

use std::collections::HashSet;

use crate::correlation::{self, CorrConfig, CorrReport, CorrVerdict};
use crate::{DetectorConfig, Mirror, MirrorReport, Modality, PidObservation, Verdict};

/// What the NIS magnitude detector established for a fused spoof attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagnitudeEvidence {
    /// Every attributed channel stayed in covariance; consistency alone caught it.
    InCovariance,
    /// Every attributed channel also had elevated NIS evidence.
    Elevated,
    /// Attributed channels contain both elevated and in-covariance evidence.
    Mixed,
    /// The magnitude detector did not have enough fresh evidence to classify it.
    Insufficient,
}

/// The unified verdict, shared by the correlation default and the PID escalation.
#[derive(Debug, Clone, PartialEq)]
pub enum FusedVerdict {
    /// All channels corroborate and NIS is consistent.
    Nominal,
    /// One or more channels have spoof-like evidence. This remains an advisory
    /// attribution: genuine target-specific dynamics or estimator artifacts can
    /// produce the same signature.
    Spoof {
        channels: Vec<Modality>,
        magnitude: MagnitudeEvidence,
    },
    /// The configured broad fraction of ready channels has inflated NIS while
    /// correlation stays intact — denial/degradation.
    Jam,
    /// Positive evidence exists, but incomplete/mixed-direction magnitude input
    /// prevents an honest spoof-vs-jam classification.
    Anomaly { channels: Vec<Modality> },
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
    let anomalous: HashSet<Modality> = baseline
        .channels
        .iter()
        .filter(|c| c.anomalous())
        .map(|c| c.modality)
        .collect();
    let baseline_out = matches!(baseline.verdict, Verdict::InsufficientEvidence);

    if matches!(baseline.verdict, Verdict::Anomaly { .. }) {
        let mut channels: Vec<Modality> = anomalous
            .iter()
            .copied()
            .chain(decoupled.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        channels.sort_by_key(|modality| *modality as u8);
        return (
            FusedVerdict::Anomaly { channels },
            "positive anomaly evidence exists, but magnitude attribution is incomplete or mixed-direction"
                .to_string(),
        );
    }

    if baseline_out && consistency_insufficient && decoupled.is_empty() {
        return (
            FusedVerdict::InsufficientEvidence,
            "both detectors lack evidence — fail closed".to_string(),
        );
    }

    if !decoupled.is_empty() {
        let consistency_attribution: HashSet<Modality> = decoupled.iter().copied().collect();
        let baseline_attribution = match &baseline.verdict {
            Verdict::Spoof { channels } => Some(channels.iter().copied().collect()),
            Verdict::Jam => Some(anomalous.clone()),
            Verdict::Nominal | Verdict::InsufficientEvidence | Verdict::Anomaly { .. } => None,
        };
        if let Some(baseline_attribution) =
            baseline_attribution.filter(|attribution| attribution != &consistency_attribution)
        {
            let mut channels: Vec<Modality> = baseline_attribution
                .iter()
                .copied()
                .chain(consistency_attribution)
                .collect();
            channels.sort_by_key(|modality| *modality as u8);
            channels.dedup();
            return (
                FusedVerdict::Anomaly { channels },
                "magnitude and consistency detectors positively attribute different channels; failing closed"
                    .to_string(),
            );
        }

        let mut channels: Vec<Modality> = anomalous
            .iter()
            .copied()
            .chain(decoupled.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        channels.sort_by_key(|modality| *modality as u8);
        let elevated_count = channels
            .iter()
            .filter(|modality| anomalous.contains(modality))
            .count();
        let magnitude = if baseline_out {
            MagnitudeEvidence::Insufficient
        } else if elevated_count == 0 {
            MagnitudeEvidence::InCovariance
        } else if elevated_count == channels.len() {
            MagnitudeEvidence::Elevated
        } else {
            MagnitudeEvidence::Mixed
        };
        let names: Vec<&str> = channels.iter().map(|m| m.label()).collect();
        return (
            FusedVerdict::Spoof {
                channels,
                magnitude,
            },
            format!(
                "cross-sensor decoupling/magnitude evidence on {} ({magnitude:?})",
                names.join(", ")
            ),
        );
    }

    match &baseline.verdict {
        Verdict::Jam => (
            FusedVerdict::Jam,
            "a configured broad fraction of ready channels has inflated NIS while cross-channel structure remains intact — denial/degradation"
                .to_string(),
        ),
        Verdict::Spoof { channels } => {
            let names: Vec<&str> = channels.iter().map(|m| m.label()).collect();
            (
                FusedVerdict::Spoof {
                    channels: channels.clone(),
                    magnitude: MagnitudeEvidence::Elevated,
                },
                format!(
                    "baseline NIS spike on {} — magnitude spoof",
                    names.join(", ")
                ),
            )
        }
        Verdict::Nominal if consistency_insufficient => (
            FusedVerdict::InsufficientEvidence,
            "NIS is in covariance, but the cross-sensor detector lacks evidence — fail closed"
                .to_string(),
        ),
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
        Verdict::Anomaly { channels } => (
            FusedVerdict::Anomaly {
                channels: channels.clone(),
            },
            "magnitude detector reported an unclassified anomaly".to_string(),
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
    /// Per-axis correlation consistency reports. Empty means no valid common
    /// consistency projection was available; raw innovations are never substituted.
    pub correlations: Vec<AxisCorrelationReport>,
    /// Rationale.
    pub note: String,
}

/// Correlation detail for one producer-attested consistency-projection axis.
#[derive(Debug, Clone)]
pub struct AxisCorrelationReport {
    /// Zero-based axis in [`crate::ConsistencyProjection::values`].
    pub axis: usize,
    /// Correlation analysis for this axis.
    pub report: CorrReport,
}

fn axis_attribution(reports: &[AxisCorrelationReport]) -> (Vec<Modality>, bool, bool) {
    let insufficient = reports.is_empty()
        || reports
            .iter()
            .any(|axis| matches!(axis.report.verdict, CorrVerdict::InsufficientEvidence));
    let positive = reports
        .iter()
        .filter_map(|axis| match &axis.report.verdict {
            CorrVerdict::Spoof(channels) => Some(channels.iter().copied().collect::<HashSet<_>>()),
            CorrVerdict::Nominal | CorrVerdict::InsufficientEvidence => None,
        })
        .collect::<Vec<_>>();
    let conflict = positive
        .first()
        .is_some_and(|first| positive.iter().skip(1).any(|set| set != first));
    let mut decoupled = positive
        .iter()
        .flat_map(|set| set.iter().copied())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    decoupled.sort_by_key(|modality| *modality as u8);
    (decoupled, insufficient, conflict)
}

fn anomaly_channels(baseline: &MirrorReport, decoupled: &[Modality]) -> Vec<Modality> {
    let mut channels = baseline
        .channels
        .iter()
        .filter(|channel| channel.anomalous())
        .map(|channel| channel.modality)
        .chain(decoupled.iter().copied())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    channels.sort_by_key(|modality| *modality as u8);
    channels
}

/// Combine a magnitude report with per-axis signed-correlation reports.
///
/// Positive attributions that disagree across axes, or coexist with an
/// insufficient axis, become [`FusedVerdict::Anomaly`]. An empty slice means the
/// producer supplied no valid common projection and therefore marks consistency
/// insufficient; the magnitude baseline still contributes normally.
pub fn combine_correlation_axes(
    baseline: &MirrorReport,
    correlations: &[AxisCorrelationReport],
) -> (FusedVerdict, String) {
    let (decoupled, consistency_insufficient, conflict) = axis_attribution(correlations);
    let incomplete_positive = consistency_insufficient && !decoupled.is_empty();
    if conflict || incomplete_positive {
        let reason = if conflict {
            "projection axes positively attribute different channels"
        } else {
            "a projection axis attributes a channel while another axis is insufficient"
        };
        return (
            FusedVerdict::Anomaly {
                channels: anomaly_channels(baseline, &decoupled),
            },
            format!("{reason}; failing closed instead of reporting Spoof"),
        );
    }
    combine(baseline, &decoupled, consistency_insufficient)
}

/// The **pure default** cross-sensor detector: run the NIS baseline and the cheap
/// correlation consistency check over a whole (single-track) stream, and fuse them.
/// No heavy dependency; this is the default advisory detector path.
pub fn assess_default(
    stream: &[PidObservation],
    modalities: &[Modality],
    baseline_cfg: &DetectorConfig,
    corr_cfg: &CorrConfig,
) -> crate::Result<DefaultReport> {
    let mut mirror = Mirror::with_modalities(baseline_cfg.clone(), modalities)?;
    for o in stream {
        mirror.ingest(o)?;
    }
    let track = stream.first().map_or(0, |o| o.track_id);
    let last_seq = stream.iter().map(|o| o.seq).max().unwrap_or(0);
    let baseline = mirror.assess(track, last_seq)?;

    let projection = crate::consistency_channels_with_temporal_limits(
        stream,
        modalities,
        baseline_cfg.max_seq_gap,
        baseline_cfg.max_timestamp_skew_ms,
        baseline_cfg.max_inter_sample_gap_ms,
    )?;
    let mut correlations = Vec::new();
    if let Some(projection) = projection {
        let axis_count = projection.axes.len();
        for (axis, channels) in projection.axes.iter().enumerate() {
            let mut adjusted = corr_cfg.clone();
            adjusted.family_alpha /= axis_count as f64;
            correlations.push(AxisCorrelationReport {
                axis,
                report: correlation::analyze(channels, &adjusted)?,
            });
        }
    }
    let (verdict, note) = combine_correlation_axes(&baseline, &correlations);
    Ok(DefaultReport {
        verdict,
        baseline,
        correlations,
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::ChannelReport;
    use crate::ConsistencyProjection;

    fn ch(modality: Modality, elevated: bool) -> ChannelReport {
        ChannelReport {
            modality,
            n: 64,
            last_seq: Some(100),
            last_timestamp_ms: Some(10_000),
            mean_nis: if elevated { 20.0 } else { 3.0 },
            p_right: if elevated { 1e-9 } else { 0.5 },
            elevated,
            cusum_high_alarm: elevated,
            cusum_low_alarm: false,
            fresh: true,
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
                magnitude: MagnitudeEvidence::InCovariance,
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
                magnitude: MagnitudeEvidence::Elevated,
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
                magnitude: MagnitudeEvidence::Elevated,
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
                magnitude: MagnitudeEvidence::Insufficient,
            }
        );
    }

    #[test]
    fn nominal_baseline_cannot_hide_insufficient_consistency_evidence() {
        let (verdict, _) = combine(&baseline(Verdict::Nominal, &[]), &[], true);
        assert_eq!(verdict, FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn disagreeing_positive_attributions_fail_closed() {
        let baseline = baseline(
            Verdict::Spoof {
                channels: vec![Modality::Radar],
            },
            &[Modality::Radar],
        );
        let (verdict, _) = combine(&baseline, &[Modality::Acoustic], false);
        assert_eq!(
            verdict,
            FusedVerdict::Anomaly {
                channels: vec![Modality::Acoustic, Modality::Radar]
            }
        );
    }

    #[test]
    fn jam_and_partial_consistency_attributions_fail_closed() {
        let all = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let (verdict, _) = combine(&baseline(Verdict::Jam, &all), &[Modality::Acoustic], false);
        assert_eq!(
            verdict,
            FusedVerdict::Anomaly {
                channels: vec![Modality::Visual, Modality::Acoustic, Modality::Radar]
            }
        );
    }

    #[test]
    fn projection_axes_with_different_positive_attributions_conflict() {
        let axis = |axis, modality| AxisCorrelationReport {
            axis,
            report: CorrReport {
                channels: Vec::new(),
                verdict: CorrVerdict::Spoof(vec![modality]),
                note: String::new(),
            },
        };
        let (channels, insufficient, conflict) =
            axis_attribution(&[axis(0, Modality::Radar), axis(1, Modality::Acoustic)]);

        assert_eq!(channels, vec![Modality::Acoustic, Modality::Radar]);
        assert!(!insufficient);
        assert!(conflict);
    }

    fn projected_stream() -> Vec<PidObservation> {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let mut stream = Vec::new();
        for sequence in 0..128_u64 {
            let x = sequence as f64;
            let common_a = (x * 0.17).sin();
            let common_b = (x * 0.23).sin();
            let common_c = (x * 0.29).sin();
            let outsider_a = (x * 0.73).cos();
            let outsider_b = (x * 0.83).cos();
            let values = [
                [common_a, common_b, common_c],
                [
                    common_a + 0.01 * (x * 0.31).cos(),
                    outsider_b,
                    common_c + 0.01 * (x * 0.37).cos(),
                ],
                [
                    outsider_a,
                    common_b + 0.01 * (x * 0.41).cos(),
                    common_c + 0.01 * (x * 0.43).cos(),
                ],
            ];
            for (modality, projection_values) in modalities.iter().zip(values) {
                let mut observation =
                    PidObservation::scalar(1, sequence * 100, sequence, *modality, 3.0, 3);
                observation.consistency_projection = Some(ConsistencyProjection {
                    values: projection_values,
                    dimensions: 3,
                    frame_id: 1,
                    context_id: 1,
                    prior_id: sequence + 1,
                });
                stream.push(observation);
            }
        }
        stream
    }

    #[test]
    fn default_assessment_checks_all_axes_and_rejects_conflicting_attribution() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let report = assess_default(
            &projected_stream(),
            &modalities,
            &DetectorConfig::default(),
            &CorrConfig::default(),
        )
        .unwrap();

        assert_eq!(report.correlations.len(), 3);
        assert_eq!(
            report.verdict,
            FusedVerdict::Anomaly {
                channels: vec![Modality::Acoustic, Modality::Radar]
            }
        );
    }

    #[test]
    fn default_assessment_does_not_fall_back_to_native_innovations() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let mut stream = projected_stream();
        for observation in &mut stream {
            let projection = observation.consistency_projection.take().unwrap();
            observation.innovation = Some(projection.values);
            observation.innovation_cov = Some([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]]);
        }
        let report = assess_default(
            &stream,
            &modalities,
            &DetectorConfig::default(),
            &CorrConfig::default(),
        )
        .unwrap();

        assert!(report.correlations.is_empty());
        assert_eq!(report.verdict, FusedVerdict::InsufficientEvidence);
    }
}
