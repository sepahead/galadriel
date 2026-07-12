//! Additive fusion of magnitude, signed-correlation, and PID evidence.
//!
//! PID mutual information is deliberately sign-invariant. The signed-correlation
//! default therefore remains in the path: PID may add nonlinear pairwise
//! decoupling evidence, but it cannot erase a correlation sign-flip finding. The
//! reported PID atoms are diagnostic and are not a pure-synergy decision rule.

use std::collections::HashSet;

use galadriel_core::{
    combine, correlation, AxisCorrelationReport, ConsistencyEvidence, CorrConfig, CorrReport,
    CorrVerdict, DetectorConfig, FusedVerdict, Mirror, MirrorReport, Modality, PidObservation,
};

use crate::{analyze, PidConfig, PidReport};

/// Fused report retaining all three component views for auditability.
#[derive(Debug, Clone)]
pub struct FusedReport {
    /// Unified verdict.
    pub verdict: FusedVerdict,
    /// NIS magnitude report.
    pub baseline: MirrorReport,
    /// Signed-correlation reports for every attested projection axis.
    pub correlations: Vec<AxisCorrelationReport>,
    /// Information-theoretic reports for every attested projection axis.
    pub pids: Vec<AxisPidReport>,
    /// Fusion rationale.
    pub note: String,
}

/// PID detail for one producer-attested consistency-projection axis.
#[derive(Debug, Clone)]
pub struct AxisPidReport {
    /// Zero-based axis in `ConsistencyProjection::values`.
    pub axis: usize,
    /// PID analysis for this axis.
    pub report: PidReport,
}

fn correlation_axis_attribution(
    reports: &[AxisCorrelationReport],
) -> (HashSet<Modality>, bool, Option<&'static str>) {
    let insufficient = reports.is_empty()
        || reports
            .iter()
            .any(|axis| matches!(axis.report.verdict, CorrVerdict::InsufficientEvidence));
    let positives = reports
        .iter()
        .filter_map(|axis| match &axis.report.verdict {
            CorrVerdict::Decoupled(channels) => {
                Some(channels.iter().copied().collect::<HashSet<_>>())
            }
            CorrVerdict::Nominal | CorrVerdict::InsufficientEvidence => None,
        })
        .collect::<Vec<_>>();
    let disagree = positives
        .first()
        .is_some_and(|first| positives.iter().skip(1).any(|set| set != first));
    let union = positives
        .iter()
        .flat_map(|set| set.iter().copied())
        .collect();
    let conflict = if positives.iter().any(HashSet::is_empty) {
        Some("a correlation projection axis supplied an empty positive attribution")
    } else if disagree {
        Some("correlation projection axes disagree on channel attribution")
    } else {
        None
    };
    (union, insufficient, conflict)
}

fn pid_axis_attribution(
    reports: &[AxisPidReport],
) -> (HashSet<Modality>, bool, Option<&'static str>) {
    let insufficient = reports.is_empty()
        || reports
            .iter()
            .any(|axis| matches!(axis.report.verdict, crate::PidVerdict::InsufficientEvidence));
    let positives = reports
        .iter()
        .filter_map(|axis| match &axis.report.verdict {
            crate::PidVerdict::Decoupled(channels) => {
                Some(channels.iter().copied().collect::<HashSet<_>>())
            }
            crate::PidVerdict::Nominal | crate::PidVerdict::InsufficientEvidence => None,
        })
        .collect::<Vec<_>>();
    let disagree = positives
        .first()
        .is_some_and(|first| positives.iter().skip(1).any(|set| set != first));
    let union = positives
        .iter()
        .flat_map(|set| set.iter().copied())
        .collect();
    let conflict = if positives.iter().any(HashSet::is_empty) {
        Some("a PID projection axis supplied an empty positive attribution")
    } else if disagree {
        Some("PID projection axes disagree on channel attribution")
    } else {
        None
    };
    (union, insufficient, conflict)
}

/// Fuse baseline, signed-correlation, and PID reports.
///
/// Decoupled-channel evidence is the union of both consistency detectors. The
/// signed-correlation result remains the minimum consistency contract: an
/// optional PID limitation cannot downgrade an assessable signed default, while a
/// nominal sign-invariant PID result cannot substitute for unavailable signed
/// evidence. Positive PID decoupling can still add evidence when correlation is
/// insufficient.
pub fn fuse(baseline: MirrorReport, correlation: CorrReport, pid: PidReport) -> FusedReport {
    fuse_axes(
        baseline,
        vec![AxisCorrelationReport {
            axis: 0,
            report: correlation,
        }],
        vec![AxisPidReport {
            axis: 0,
            report: pid,
        }],
    )
}

/// Fuse magnitude evidence with correlation and PID results from every supported
/// common-projection axis.
pub fn fuse_axes(
    baseline: MirrorReport,
    correlations: Vec<AxisCorrelationReport>,
    pids: Vec<AxisPidReport>,
) -> FusedReport {
    let (correlation_decoupled, correlation_insufficient, correlation_axis_conflict) =
        correlation_axis_attribution(&correlations);
    let (pid_decoupled, pid_insufficient, pid_axis_conflict) = pid_axis_attribution(&pids);
    let mut decoupled: Vec<Modality> = correlation_decoupled
        .union(&pid_decoupled)
        .copied()
        .collect();
    decoupled.sort_by_key(|modality| *modality as u8);

    // PID is an optional additive detector. Partial PID evidence cannot erase a
    // complete, conflict-free signed-correlation attribution. Mismatched positive
    // PID attribution is independently caught by `disagree` below.
    let signed_default_is_complete = !correlation_insufficient
        && correlation_axis_conflict.is_none()
        && !correlation_decoupled.is_empty();
    let incomplete_positive = (correlation_insufficient && !correlation_decoupled.is_empty())
        || (pid_insufficient && !pid_decoupled.is_empty() && !signed_default_is_complete);
    // Two assessable consistency detectors naming different channels is positive
    // evidence, but not honest attribution. Preserve the union for investigation
    // and fail closed to an unclassified anomaly.
    let disagree = !correlation_decoupled.is_empty()
        && !pid_decoupled.is_empty()
        && correlation_decoupled != pid_decoupled;
    let axis_conflict = correlation_axis_conflict.or(pid_axis_conflict);
    let conflict_reason = if let Some(reason) = axis_conflict {
        Some(reason)
    } else if disagree || incomplete_positive {
        Some(if incomplete_positive {
            "positive attribution exists alongside an insufficient projection axis"
        } else {
            "consistency detectors disagree on channel attribution"
        })
    } else {
        None
    };
    let consistency = if conflict_reason.is_some() {
        ConsistencyEvidence::Conflicted(decoupled.clone())
    } else if decoupled.is_empty() {
        if correlation_insufficient {
            ConsistencyEvidence::Insufficient
        } else {
            ConsistencyEvidence::Intact
        }
    } else {
        ConsistencyEvidence::decoupled(&decoupled)
            .unwrap_or_else(|_| ConsistencyEvidence::Conflicted(decoupled.clone()))
    };
    let (verdict, mut base_note) = combine(&baseline, consistency);
    if let Some(reason) = conflict_reason {
        base_note = format!("{reason}; {base_note}");
    }
    let correlation_note = correlations
        .iter()
        .map(|axis| format!("axis {}: {}", axis.axis, axis.report.note))
        .collect::<Vec<_>>()
        .join(" | ");
    let pid_note = pids
        .iter()
        .map(|axis| format!("axis {}: {}", axis.axis, axis.report.note))
        .collect::<Vec<_>>()
        .join(" | ");
    let note = format!(
        "{base_note}; signed correlation: {}; PID escalation: {}",
        if correlation_note.is_empty() {
            "no attested common projection"
        } else {
            &correlation_note
        },
        if pid_note.is_empty() {
            "no attested common projection"
        } else {
            &pid_note
        }
    );
    FusedReport {
        verdict,
        baseline,
        correlations,
        pids,
        note,
    }
}

/// Run the magnitude baseline, default signed-correlation configuration, and PID
/// escalation over a whole single-track stream.
pub fn assess_stream(
    stream: &[PidObservation],
    modalities: &[Modality],
    baseline_cfg: &DetectorConfig,
    pid_cfg: &PidConfig,
) -> galadriel_core::Result<FusedReport> {
    assess_stream_with_correlation(
        stream,
        modalities,
        baseline_cfg,
        &CorrConfig::default(),
        pid_cfg,
    )
}

/// Run the magnitude baseline, caller-configured signed correlation, and PID
/// escalation over a whole single-track stream.
///
/// This is the configurable counterpart to [`assess_stream`], which deliberately
/// preserves the default correlation operating point for compatibility.
pub fn assess_stream_with_correlation(
    stream: &[PidObservation],
    modalities: &[Modality],
    baseline_cfg: &DetectorConfig,
    corr_cfg: &CorrConfig,
    pid_cfg: &PidConfig,
) -> galadriel_core::Result<FusedReport> {
    // Reject structurally unresolvable confirmation settings before ingesting or
    // running any estimator. Axis multiplicity is preflighted again below once
    // producer-attested projection dimensionality is known.
    pid_cfg.validate()?;
    let mut mirror = Mirror::with_modalities(baseline_cfg.clone(), modalities)?;
    corr_cfg.validate()?;

    // Preflight whole-stream bounds and structural invariants before running the
    // baseline or any quadratic estimator.
    let projection = galadriel_core::consistency_channels_with_temporal_limits(
        stream,
        modalities,
        baseline_cfg.max_seq_gap,
        baseline_cfg.max_timestamp_skew_ms,
        baseline_cfg.max_inter_sample_gap_ms,
    )?;
    for observation in stream {
        mirror.ingest(observation)?;
    }
    let track = stream.first().map_or(0, |observation| observation.track_id);
    let last_seq = stream
        .iter()
        .map(|observation| observation.seq)
        .max()
        .unwrap_or(0);
    let baseline = mirror.assess(track, last_seq)?;

    let mut correlations = Vec::new();
    let mut pids = Vec::new();
    if let Some(projection) = projection {
        let axis_count = projection.axes.len();
        if axis_count == 0 {
            return Err(galadriel_core::GaladrielError::InvalidChannels(
                "attested consistency projection must expose at least one axis".into(),
            ));
        }
        let mut adjusted_pid = pid_cfg.clone();
        adjusted_pid.family_alpha /= axis_count as f64;
        adjusted_pid.validate()?;
        for (axis, channels) in projection.axes.iter().enumerate() {
            let mut adjusted_corr = corr_cfg.clone();
            adjusted_corr.family_alpha /= axis_count as f64;
            correlations.push(AxisCorrelationReport {
                axis,
                report: correlation::analyze(channels, &adjusted_corr)?,
            });
            pids.push(AxisPidReport {
                axis,
                report: analyze(channels, &adjusted_pid)?,
            });
        }
    }
    Ok(fuse_axes(baseline, correlations, pids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PidVerdict;
    use galadriel_core::{ChannelReport, CorrChannel, MagnitudeEvidence, MirrorReport, Verdict};
    use galadriel_sim::injection::{inject, BroadbandJam, PhantomAcousticDoa};
    use galadriel_sim::scenario::{generate, generate_spoofed, ScenarioConfig, StealthySpoof};

    const MODALITIES: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

    fn scenario() -> ScenarioConfig {
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
            &MODALITIES,
            &DetectorConfig::default(),
            &PidConfig::default(),
        )
        .unwrap()
        .verdict
    }

    fn nominal_baseline() -> MirrorReport {
        MirrorReport {
            track_id: 1,
            seq: 128,
            verdict: Verdict::Nominal,
            channels: MODALITIES
                .iter()
                .map(|&modality| ChannelReport {
                    modality,
                    n: 128,
                    last_seq: Some(128),
                    last_timestamp_ms: Some(12_800),
                    mean_nis: 3.0,
                    p_right: 0.5,
                    elevated: false,
                    cusum_high_alarm: false,
                    cusum_low_alarm: false,
                    fresh: true,
                    ready: true,
                })
                .collect(),
            note: "nominal test baseline".into(),
        }
    }

    #[test]
    fn clean_is_nominal() {
        let report = assess_stream(
            &generate(&scenario()).unwrap(),
            &MODALITIES,
            &DetectorConfig::default(),
            &PidConfig::default(),
        )
        .unwrap();

        assert_eq!(report.correlations.len(), 3);
        assert_eq!(report.pids.len(), 3);
        assert_eq!(report.verdict, FusedVerdict::Nominal);
    }

    #[test]
    fn stream_assessment_never_falls_back_to_native_innovations() {
        let mut stream = generate(&scenario()).unwrap();
        for observation in &mut stream {
            observation.consistency_projection = None;
        }
        let report = assess_stream(
            &stream,
            &MODALITIES,
            &DetectorConfig::default(),
            &PidConfig::default(),
        )
        .unwrap();

        assert!(report.correlations.is_empty());
        assert!(report.pids.is_empty());
        assert_eq!(report.verdict, FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn partial_pid_evidence_does_not_erase_complete_signed_attribution() {
        let stream = generate_spoofed(
            &scenario(),
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: 100,
            },
        )
        .unwrap();
        let report = assess_stream(
            &stream,
            &MODALITIES,
            &DetectorConfig::default(),
            &PidConfig::default(),
        )
        .unwrap();
        assert!(report
            .pids
            .iter()
            .any(|axis| matches!(axis.report.verdict, PidVerdict::InsufficientEvidence)));
        assert!(report
            .pids
            .iter()
            .any(|axis| matches!(axis.report.verdict, PidVerdict::Decoupled(_))));
        assert!(report
            .correlations
            .iter()
            .all(|axis| { !matches!(axis.report.verdict, CorrVerdict::InsufficientEvidence) }));
        assert!(
            matches!(
                report.verdict,
                FusedVerdict::AttributedInconsistency {
                    ref channels,
                    magnitude: MagnitudeEvidence::InCovariance,
                } if channels == &[Modality::Acoustic]
            ),
            "unexpected fused verdict {:?}: {}",
            report.verdict,
            report.note
        );
        let acoustic = report
            .baseline
            .channels
            .iter()
            .find(|channel| channel.modality == Modality::Acoustic)
            .unwrap();
        assert!(!acoustic.anomalous());
        assert!(report.pids.iter().all(|axis| {
            axis.report.estimator.pid_rs_revision == crate::PID_RS_REVISION
                && axis.report.estimator.atom_scientific_status == "experimental_restricted_domain"
        }));
    }

    #[test]
    fn positive_pid_axis_alongside_insufficient_pid_axis_fails_closed() {
        let correlation = AxisCorrelationReport {
            axis: 0,
            report: CorrReport {
                channels: Vec::new(),
                verdict: CorrVerdict::Nominal,
                note: "correlation nominal".into(),
            },
        };
        let pid = |axis: usize, verdict: PidVerdict, note: &str| AxisPidReport {
            axis,
            report: PidReport {
                estimator: crate::PidEstimatorEvidence::from_config(&PidConfig::default()),
                channels: Vec::new(),
                verdict,
                note: note.into(),
            },
        };

        let report = fuse_axes(
            nominal_baseline(),
            vec![correlation],
            vec![
                pid(
                    0,
                    PidVerdict::Decoupled(vec![Modality::Acoustic]),
                    "positive PID axis",
                ),
                pid(1, PidVerdict::InsufficientEvidence, "insufficient PID axis"),
            ],
        );

        assert_eq!(
            report.verdict,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic]
            }
        );
        assert!(report.note.contains("insufficient projection axis"));
    }

    #[test]
    fn matching_partial_pid_preserves_complete_signed_default() {
        let correlation = AxisCorrelationReport {
            axis: 0,
            report: CorrReport {
                channels: Vec::new(),
                verdict: CorrVerdict::Decoupled(vec![Modality::Acoustic]),
                note: "complete signed attribution".into(),
            },
        };
        let pid = |axis: usize, verdict: PidVerdict| AxisPidReport {
            axis,
            report: PidReport {
                estimator: crate::PidEstimatorEvidence::from_config(&PidConfig::default()),
                channels: Vec::new(),
                verdict,
                note: "partial PID attribution".into(),
            },
        };

        let report = fuse_axes(
            nominal_baseline(),
            vec![correlation],
            vec![
                pid(0, PidVerdict::Decoupled(vec![Modality::Acoustic])),
                pid(1, PidVerdict::InsufficientEvidence),
            ],
        );

        assert_eq!(
            report.verdict,
            FusedVerdict::AttributedInconsistency {
                channels: vec![Modality::Acoustic],
                magnitude: MagnitudeEvidence::InCovariance,
            }
        );
    }

    #[test]
    fn loud_bias_spoof_has_elevated_magnitude_evidence() {
        let mut stream = generate(&scenario()).unwrap();
        inject(
            &mut stream,
            &PhantomAcousticDoa {
                target: Modality::Acoustic,
                start_frame: 100,
                bias: 8.0,
            },
        )
        .unwrap();
        match fused(&stream) {
            FusedVerdict::AttributedInconsistency {
                channels,
                magnitude,
            } => {
                assert!(channels.contains(&Modality::Acoustic));
                assert!(matches!(
                    magnitude,
                    MagnitudeEvidence::Elevated | MagnitudeEvidence::Mixed
                ));
            }
            other => panic!("expected elevated AttributedInconsistency, got {other:?}"),
        }
    }

    #[test]
    fn broadband_jam_produces_broad_degradation_evidence() {
        let mut stream = generate(&scenario()).unwrap();
        inject(
            &mut stream,
            &BroadbandJam {
                start_frame: 100,
                inflation: 3.0,
            },
        )
        .unwrap();
        assert_eq!(fused(&stream), FusedVerdict::BroadDegradation);
    }

    #[test]
    fn signed_correlation_sign_flip_survives_pid_nominal_result() {
        let n = 128;
        let visual: Vec<f64> = (0..n).map(|i| (i as f64 * 0.17).sin()).collect();
        let radar: Vec<f64> = (0..n)
            .map(|i| (i as f64 * 0.17).sin() + 0.01 * (i as f64 * 0.31).cos())
            .collect();
        let acoustic: Vec<f64> = visual.iter().map(|value| -*value).collect();
        let channels = vec![
            (Modality::Visual, visual),
            (Modality::Radar, radar),
            (Modality::Acoustic, acoustic),
        ];

        let correlation = correlation::analyze(&channels, &CorrConfig::default()).unwrap();
        assert!(matches!(
            correlation.verdict,
            CorrVerdict::Decoupled(ref found) if found.contains(&Modality::Acoustic)
        ));

        let pid = analyze(&channels, &PidConfig::default()).unwrap();
        assert_eq!(pid.verdict, PidVerdict::Nominal, "{}", pid.note);

        match fuse(nominal_baseline(), correlation, pid).verdict {
            FusedVerdict::AttributedInconsistency {
                channels,
                magnitude,
            } => {
                assert!(channels.contains(&Modality::Acoustic));
                assert_eq!(magnitude, MagnitudeEvidence::InCovariance);
            }
            other => panic!("signed-correlation sign flip was lost: {other:?}"),
        }
    }

    #[test]
    fn pid_adds_evidence_when_signed_correlation_is_insufficient() {
        let correlation = CorrReport {
            channels: MODALITIES
                .iter()
                .map(|&modality| CorrChannel {
                    modality,
                    n: 128,
                    corroboration: None,
                    decoupled: false,
                })
                .collect(),
            verdict: CorrVerdict::InsufficientEvidence,
            note: "test correlation unavailable".into(),
        };
        let pid = PidReport {
            estimator: crate::PidEstimatorEvidence::from_config(&PidConfig::default()),
            channels: MODALITIES
                .iter()
                .map(|&modality| crate::ChannelPid {
                    modality,
                    n: 128,
                    gate_ok: true,
                    gate_note: "test".into(),
                    corroboration: Some(1.0),
                    redundancy: None,
                    synergy: None,
                    decoupled: modality == Modality::Acoustic,
                    ci: None,
                })
                .collect(),
            verdict: PidVerdict::Decoupled(vec![Modality::Acoustic]),
            note: "test PID decoupling".into(),
        };

        assert!(matches!(
            fuse(nominal_baseline(), correlation, pid).verdict,
            FusedVerdict::AttributedInconsistency { ref channels, .. }
                if channels.contains(&Modality::Acoustic)
        ));
    }

    #[test]
    fn conflicting_positive_attributions_fail_closed_to_unclassified_anomaly() {
        let correlation = CorrReport {
            channels: MODALITIES
                .iter()
                .map(|&modality| CorrChannel {
                    modality,
                    n: 128,
                    corroboration: Some(0.8),
                    decoupled: modality == Modality::Radar,
                })
                .collect(),
            verdict: CorrVerdict::Decoupled(vec![Modality::Radar]),
            note: "test correlation attribution".into(),
        };
        let pid = PidReport {
            estimator: crate::PidEstimatorEvidence::from_config(&PidConfig::default()),
            channels: MODALITIES
                .iter()
                .map(|&modality| crate::ChannelPid {
                    modality,
                    n: 128,
                    gate_ok: true,
                    gate_note: "test".into(),
                    corroboration: Some(1.0),
                    redundancy: None,
                    synergy: None,
                    decoupled: modality == Modality::Acoustic,
                    ci: None,
                })
                .collect(),
            verdict: PidVerdict::Decoupled(vec![Modality::Acoustic]),
            note: "test PID attribution".into(),
        };

        assert_eq!(
            fuse(nominal_baseline(), correlation, pid).verdict,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic, Modality::Radar],
            }
        );
    }

    #[test]
    fn empty_positive_correlation_verdict_fails_closed_instead_of_becoming_intact() {
        let report = fuse(
            nominal_baseline(),
            CorrReport {
                channels: Vec::new(),
                verdict: CorrVerdict::Decoupled(Vec::new()),
                note: "malformed empty correlation attribution".into(),
            },
            PidReport {
                estimator: crate::PidEstimatorEvidence::from_config(&PidConfig::default()),
                channels: Vec::new(),
                verdict: PidVerdict::Nominal,
                note: "PID nominal".into(),
            },
        );

        assert_eq!(
            report.verdict,
            FusedVerdict::UnclassifiedAnomaly {
                channels: Vec::new()
            }
        );
        assert!(report.note.contains("empty positive attribution"));
    }

    #[test]
    fn empty_positive_pid_verdict_fails_closed_instead_of_becoming_intact() {
        let report = fuse(
            nominal_baseline(),
            CorrReport {
                channels: Vec::new(),
                verdict: CorrVerdict::Nominal,
                note: "correlation nominal".into(),
            },
            PidReport {
                estimator: crate::PidEstimatorEvidence::from_config(&PidConfig::default()),
                channels: Vec::new(),
                verdict: PidVerdict::Decoupled(Vec::new()),
                note: "malformed empty PID attribution".into(),
            },
        );

        assert_eq!(
            report.verdict,
            FusedVerdict::UnclassifiedAnomaly {
                channels: Vec::new()
            }
        );
        assert!(report.note.contains("empty positive attribution"));
    }

    #[test]
    fn conflicting_projection_axes_fail_closed_to_unclassified_anomaly() {
        let correlation_axis = |axis, modality| AxisCorrelationReport {
            axis,
            report: CorrReport {
                channels: MODALITIES
                    .iter()
                    .map(|&candidate| CorrChannel {
                        modality: candidate,
                        n: 128,
                        corroboration: Some(0.8),
                        decoupled: candidate == modality,
                    })
                    .collect(),
                verdict: CorrVerdict::Decoupled(vec![modality]),
                note: "axis attribution".into(),
            },
        };
        let nominal_pid = |axis| AxisPidReport {
            axis,
            report: PidReport {
                estimator: crate::PidEstimatorEvidence::from_config(&PidConfig::default()),
                channels: Vec::new(),
                verdict: PidVerdict::Nominal,
                note: "axis nominal".into(),
            },
        };

        let report = fuse_axes(
            nominal_baseline(),
            vec![
                correlation_axis(0, Modality::Radar),
                correlation_axis(1, Modality::Acoustic),
            ],
            vec![nominal_pid(0), nominal_pid(1)],
        );

        assert_eq!(
            report.verdict,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic, Modality::Radar]
            }
        );
    }

    #[test]
    fn multi_axis_confirmation_resolution_is_rejected_before_pid_estimation() {
        let stream = generate(&scenario()).unwrap();
        let baseline = DetectorConfig::default();
        let projection = galadriel_core::consistency_channels_with_temporal_limits(
            &stream,
            &MODALITIES,
            baseline.max_seq_gap,
            baseline.max_timestamp_skew_ms,
            baseline.max_inter_sample_gap_ms,
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.axes.len(), 3);

        let config = PidConfig {
            n_boot: 20,
            family_alpha: 0.10,
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "single-axis settings are resolvable"
        );
        assert!(matches!(
            assess_stream(&stream, &MODALITIES, &baseline, &config),
            Err(galadriel_core::GaladrielError::InvalidConfig(ref message))
                if message.contains("cannot resolve family_alpha")
        ));
    }

    #[test]
    fn configurable_stream_assessment_preserves_the_requested_correlation_config() {
        let stream = generate(&scenario()).unwrap();
        let corr_cfg = CorrConfig {
            corr_floor: 1.0,
            ..CorrConfig::default()
        };
        let report = assess_stream_with_correlation(
            &stream,
            &MODALITIES,
            &DetectorConfig::default(),
            &corr_cfg,
            &PidConfig::default(),
        )
        .unwrap();

        assert!(report
            .correlations
            .iter()
            .all(|axis| matches!(axis.report.verdict, CorrVerdict::InsufficientEvidence)));
    }
}
