//! Additive fusion of magnitude, signed-correlation, and PID evidence.
//!
//! PID mutual information is deliberately sign-invariant. The signed-correlation
//! default therefore remains in the path: PID may add nonlinear pairwise
//! decoupling evidence, but it cannot erase a correlation sign-flip finding. The
//! reported PID atoms are diagnostic and are not a pure-synergy decision rule.

use std::collections::HashSet;

use galadriel_core::{
    combine, prepare_release_assessment, AxisCorrelationReport, ConsistencyEvidence, CorrReport,
    CorrVerdict, FusedVerdict, GaladrielError, MirrorReport, Modality, PidObservation,
    MAX_CONSISTENCY_PROJECTION_AXES,
};

#[cfg(test)]
use galadriel_core::{correlation, Mirror};

use crate::{
    analyze, PidAssessmentBinding, PidReport, PidResearchClassification, PidResearchSuite,
    PidResearchSuiteDigest,
};

/// Fused report retaining all three component views for auditability.
///
/// Reports can only be returned after every component's sealed configuration
/// identity has been checked against the accepted PID research suite:
///
/// ```compile_fail
/// use galadriel_pid::FusedReport;
/// let _ = FusedReport { note: "forged".into() };
/// ```
///
/// ```compile_fail
/// fn replace(mut report: galadriel_pid::FusedReport) {
///     report.pids = Vec::new();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct FusedReport {
    /// Unified verdict.
    verdict: FusedVerdict,
    /// NIS magnitude report.
    baseline: MirrorReport,
    /// Signed-correlation reports for every attested projection axis.
    correlations: Vec<AxisCorrelationReport>,
    /// Information-theoretic reports for every attested projection axis.
    pids: Vec<AxisPidReport>,
    /// Fusion rationale.
    note: String,
    /// Canonical complete PID research-suite identity.
    suite_identity: PidResearchSuiteDigest,
    /// Named-profile or custom-research classification.
    classification: PidResearchClassification,
    /// Canonical exact release-suite-and-input binding shared by every component.
    assessment_binding: PidAssessmentBinding,
}

impl FusedReport {
    /// Unified advisory verdict.
    pub const fn verdict(&self) -> &FusedVerdict {
        &self.verdict
    }

    /// Sealed NIS magnitude report.
    pub const fn baseline(&self) -> &MirrorReport {
        &self.baseline
    }

    /// Sealed signed-correlation reports in producer-axis order.
    pub fn correlations(&self) -> &[AxisCorrelationReport] {
        &self.correlations
    }

    /// Sealed PID reports in producer-axis order.
    pub fn pids(&self) -> &[AxisPidReport] {
        &self.pids
    }

    /// Human-readable, non-normative fusion rationale.
    pub fn note(&self) -> &str {
        &self.note
    }

    /// Canonical complete accepted PID research-suite identity.
    pub const fn suite_identity(&self) -> PidResearchSuiteDigest {
        self.suite_identity
    }

    /// Named-profile or custom-research classification.
    pub const fn classification(&self) -> PidResearchClassification {
        self.classification
    }

    /// Canonical exact release-suite-and-input binding shared by every component.
    pub const fn assessment_binding(&self) -> &PidAssessmentBinding {
        &self.assessment_binding
    }
}

/// PID detail for one producer-attested consistency-projection axis.
///
/// Axis labels are assigned only while analysing an attested projection family;
/// callers cannot relabel an analyser-produced PID report:
///
/// ```compile_fail
/// use galadriel_pid::{analyze, AxisPidReport, PidResearchProfile};
/// let config = PidResearchProfile::PointEstimateOnlyV0_9.try_config().unwrap();
/// let report = analyze(&[], &config).unwrap();
/// let _ = AxisPidReport { axis: 0, report };
/// ```
///
/// ```compile_fail
/// // Even a genuine returned axis report cannot be relabelled.
/// fn relabel(mut axis: galadriel_pid::AxisPidReport) { axis.axis = 7; }
/// ```
#[derive(Debug, Clone)]
pub struct AxisPidReport {
    /// Zero-based axis in `ConsistencyProjection::values`.
    axis: usize,
    /// PID analysis for this axis.
    report: PidReport,
    /// Exact accepted assessment binding, absent on compatibility diagnostics.
    assessment_binding: Option<PidAssessmentBinding>,
}

impl AxisPidReport {
    /// Wrap a sealed PID report as the sole producer projection axis.
    pub const fn single_axis(report: PidReport) -> Self {
        Self {
            axis: 0,
            report,
            assessment_binding: None,
        }
    }

    /// Wrap a sealed PID report for one valid producer projection axis.
    pub fn try_new(axis: usize, report: PidReport) -> galadriel_core::Result<Self> {
        if axis >= MAX_CONSISTENCY_PROJECTION_AXES {
            return Err(GaladrielError::InvalidChannels(format!(
                "PID axis must be in 0..{MAX_CONSISTENCY_PROJECTION_AXES}, got {axis}"
            )));
        }
        Ok(Self {
            axis,
            report,
            assessment_binding: None,
        })
    }

    /// Zero-based producer-attested projection axis.
    pub const fn axis(&self) -> usize {
        self.axis
    }

    /// PID analysis for this projection axis.
    pub const fn report(&self) -> &PidReport {
        &self.report
    }

    /// Exact accepted assessment binding, or `None` for an explicitly unbound
    /// compatibility diagnostic.
    pub const fn assessment_binding(&self) -> Option<&PidAssessmentBinding> {
        self.assessment_binding.as_ref()
    }

    fn try_new_bound(
        axis: usize,
        report: PidReport,
        binding: &PidAssessmentBinding,
    ) -> galadriel_core::Result<Self> {
        let mut axis = Self::try_new(axis, report)?;
        axis.assessment_binding = Some(binding.clone());
        Ok(axis)
    }
}

fn validate_component_configuration(
    suite: &PidResearchSuite,
    baseline: &MirrorReport,
    correlations: &[AxisCorrelationReport],
    pids: &[AxisPidReport],
) -> galadriel_core::Result<()> {
    if baseline.config_identity() != suite.release_suite().identity() {
        return Err(GaladrielError::InvalidConfig(
            "PID fusion baseline identity does not match the accepted release suite".into(),
        ));
    }
    if correlations.len() != pids.len() {
        return Err(GaladrielError::InvalidChannels(
            "PID and correlation evidence must cover the same projection axes".into(),
        ));
    }
    if correlations.is_empty() {
        return Ok(());
    }
    let axis_count = correlations.len();
    if axis_count > MAX_CONSISTENCY_PROJECTION_AXES {
        return Err(GaladrielError::InvalidChannels(format!(
            "projection family has {axis_count} axes; maximum is {MAX_CONSISTENCY_PROJECTION_AXES}"
        )));
    }
    for (expected_axis, (correlation, pid)) in correlations.iter().zip(pids).enumerate() {
        if correlation.axis() != expected_axis {
            return Err(GaladrielError::InvalidChannels(
                "PID fusion correlation axes must be unique and contiguous from zero".into(),
            ));
        }
        if pid.axis() != expected_axis {
            return Err(GaladrielError::InvalidChannels(
                "PID fusion report axes must be unique and contiguous from zero".into(),
            ));
        }
    }

    let expected_correlation = suite
        .release_suite()
        .correlation()
        .try_for_axis_family(axis_count)?;
    if correlations
        .iter()
        .any(|axis| axis.config_identity() != expected_correlation.identity())
    {
        return Err(GaladrielError::InvalidConfig(
            "correlation report identity does not match the accepted PID research suite".into(),
        ));
    }
    let expected_pid = suite.try_pid_for_axis_family(axis_count)?;
    if pids
        .iter()
        .any(|axis| axis.report().estimator().config_identity() != expected_pid.identity())
    {
        return Err(GaladrielError::InvalidConfig(
            "PID report identity does not match the accepted PID research suite".into(),
        ));
    }
    Ok(())
}

fn validate_component_binding(
    suite: &PidResearchSuite,
    baseline: &MirrorReport,
    correlations: &[AxisCorrelationReport],
    pids: &[AxisPidReport],
) -> galadriel_core::Result<PidAssessmentBinding> {
    let release_binding = baseline.assessment_binding().ok_or_else(|| {
        GaladrielError::InvalidConfig(
            "accepted PID fusion requires a whole-stream-bound magnitude report".into(),
        )
    })?;
    if release_binding.suite_identity() != suite.release_suite().identity() {
        return Err(GaladrielError::InvalidConfig(
            "PID fusion assessment binding does not match the accepted release suite".into(),
        ));
    }
    if correlations.iter().any(|axis| {
        axis.assessment_binding()
            .is_none_or(|axis_binding| axis_binding != release_binding)
    }) {
        return Err(GaladrielError::InvalidConfig(
            "PID fusion components do not share one exact assessment binding".into(),
        ));
    }
    let expected = PidAssessmentBinding::new(release_binding, suite.identity());
    if pids.iter().any(|axis| {
        axis.assessment_binding()
            .is_none_or(|axis_binding| axis_binding != &expected)
    }) {
        return Err(GaladrielError::InvalidConfig(
            "PID fusion reports do not share the exact input and PID-suite binding".into(),
        ));
    }
    Ok(expected)
}

fn correlation_axis_attribution(
    reports: &[AxisCorrelationReport],
) -> (HashSet<Modality>, bool, Option<&'static str>) {
    let insufficient = reports.is_empty()
        || reports
            .iter()
            .any(|axis| matches!(axis.report().verdict(), CorrVerdict::InsufficientEvidence));
    let positives = reports
        .iter()
        .filter_map(|axis| match axis.report().verdict() {
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
        || reports.iter().any(|axis| {
            matches!(
                axis.report().verdict(),
                crate::PidVerdict::InsufficientEvidence
            )
        });
    let positives = reports
        .iter()
        .filter_map(|axis| match axis.report().verdict() {
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

/// Produce explicitly unbound tuple diagnostics for one-axis component reports.
///
/// Decoupled-channel evidence is the union of both consistency detectors. The
/// signed-correlation result remains the minimum consistency contract: an
/// optional PID limitation cannot downgrade an assessable signed default, while a
/// nominal sign-invariant PID result cannot substitute for unavailable signed
/// evidence. Positive PID decoupling can still add evidence when correlation is
/// insufficient. This compatibility surface cannot mint a sealed [`FusedReport`];
/// use [`assess_stream`] for an accepted whole-stream assessment.
///
/// # Errors
///
/// Returns an error when component configuration or axis provenance does not
/// match `suite`.
pub fn fuse(
    suite: &PidResearchSuite,
    baseline: MirrorReport,
    correlation: CorrReport,
    pid: PidReport,
) -> galadriel_core::Result<(FusedVerdict, String)> {
    fuse_axes_diagnostics(
        suite,
        &baseline,
        &[AxisCorrelationReport::single_axis(correlation)],
        &[AxisPidReport::single_axis(pid)],
    )
}

/// Produce explicitly unbound tuple diagnostics for every supplied axis.
///
/// Component configuration and axis provenance are checked, but no exact input
/// binding is asserted and no sealed accepted report is created.
///
/// # Errors
///
/// Returns an error when component configuration, axis count, or axis labels do
/// not match `suite`.
pub fn fuse_axes_diagnostics(
    suite: &PidResearchSuite,
    baseline: &MirrorReport,
    correlations: &[AxisCorrelationReport],
    pids: &[AxisPidReport],
) -> galadriel_core::Result<(FusedVerdict, String)> {
    validate_component_configuration(suite, baseline, correlations, pids)?;
    Ok(fusion_decision(baseline, correlations, pids))
}

fn fusion_decision(
    baseline: &MirrorReport,
    correlations: &[AxisCorrelationReport],
    pids: &[AxisPidReport],
) -> (FusedVerdict, String) {
    let (correlation_decoupled, correlation_insufficient, correlation_axis_conflict) =
        correlation_axis_attribution(correlations);
    let (pid_decoupled, pid_insufficient, pid_axis_conflict) = pid_axis_attribution(pids);
    let mut decoupled: Vec<Modality> = correlation_decoupled
        .union(&pid_decoupled)
        .copied()
        .collect();
    decoupled.sort_by_key(|modality| modality.stable_code());

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
    let (verdict, mut base_note) = combine(baseline, consistency);
    if let Some(reason) = conflict_reason {
        base_note = format!("{reason}; {base_note}");
    }
    let correlation_note = correlations
        .iter()
        .map(|axis| format!("axis {}: {}", axis.axis(), axis.report().note()))
        .collect::<Vec<_>>()
        .join(" | ");
    let pid_note = pids
        .iter()
        .map(|axis| format!("axis {}: {}", axis.axis(), axis.report().note()))
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
    (verdict, note)
}

/// Fuse whole-stream-bound magnitude, correlation, and PID components from every
/// supported common-projection axis into a sealed accepted report.
///
/// # Errors
///
/// Returns an error unless every component has the expected accepted
/// configuration, covers one matching contiguous axis family, and carries the
/// exact same suite-and-observation binding.
pub fn fuse_axes(
    suite: &PidResearchSuite,
    baseline: MirrorReport,
    correlations: Vec<AxisCorrelationReport>,
    pids: Vec<AxisPidReport>,
) -> galadriel_core::Result<FusedReport> {
    validate_component_configuration(suite, &baseline, &correlations, &pids)?;
    let assessment_binding = validate_component_binding(suite, &baseline, &correlations, &pids)?;
    let (verdict, note) = fusion_decision(&baseline, &correlations, &pids);
    Ok(FusedReport {
        verdict,
        baseline,
        correlations,
        pids,
        note,
        suite_identity: suite.identity(),
        classification: suite.classification(),
        assessment_binding,
    })
}

/// Run the magnitude baseline, default signed-correlation configuration, and PID
/// escalation over a whole single-track stream.
pub fn assess_stream(
    stream: &[PidObservation],
    suite: &PidResearchSuite,
) -> galadriel_core::Result<FusedReport> {
    let release_suite = suite.release_suite();
    let prepared = prepare_release_assessment(stream, release_suite)?;
    let assessment_binding =
        PidAssessmentBinding::new(prepared.assessment_binding(), suite.identity());
    // A sealed `ConsistencyProjection` cannot represent zero axes, and the
    // preparation boundary preserves that invariant.
    let adjusted_pid = prepared
        .projection()
        .map(|projection| suite.try_pid_for_axis_family(projection.axes.len()))
        .transpose()?;

    let mut pids = Vec::new();
    if let (Some(projection), Some(adjusted_pid)) = (prepared.projection(), adjusted_pid) {
        for (axis, channels) in projection.axes.iter().enumerate() {
            pids.push(AxisPidReport::try_new_bound(
                axis,
                analyze(channels, &adjusted_pid)?,
                &assessment_binding,
            )?);
        }
    }
    fuse_axes(
        suite,
        prepared.baseline().clone(),
        prepared.correlations().to_vec(),
        pids,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PidConfig, PidConfirmationParams, PidResearchProfile, PidResearchSuiteParams, PidVerdict,
    };
    use galadriel_core::{
        CorrConfig, DetectorConfig, DetectorParams, MagnitudeEvidence, ProducerAxisFamilyPolicy,
        ReleaseSuite, ReleaseSuiteParams, Sequence, TimestampMillis, TrackId,
    };
    use galadriel_sim::injection::{inject, BroadbandJam, PhantomAcousticDoa};
    use galadriel_sim::scenario::{
        generate, generate_spoofed, ScenarioConfig, ScenarioResearchProfile, StealthySpoof,
    };

    const MODALITIES: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

    fn confirmed_config() -> PidConfig {
        PidResearchProfile::CircularDeleteBlockV0_9
            .try_config()
            .unwrap()
    }

    fn research_suite() -> PidResearchSuite {
        PidResearchSuite::circular_delete_block_v0_9(&MODALITIES).unwrap()
    }

    fn pid_report(verdict: PidVerdict, note: &str, axis_count: usize) -> PidReport {
        let config = confirmed_config().try_for_axis_family(axis_count).unwrap();
        PidReport::new(
            crate::PidEstimatorEvidence::from_config(&config),
            Vec::new(),
            verdict,
            note.into(),
        )
    }

    fn pid_channel(modality: Modality, decoupled: bool) -> crate::ChannelPid {
        crate::ChannelPid::new(
            modality,
            128,
            true,
            "test".into(),
            Some(1.0),
            None,
            None,
            decoupled,
            None,
        )
    }

    fn axis_pid(axis: usize, verdict: PidVerdict, note: &str, axis_count: usize) -> AxisPidReport {
        AxisPidReport::try_new(axis, pid_report(verdict, note, axis_count)).unwrap()
    }

    fn correlation_report(decoupled: Option<Modality>, axis_count: usize) -> CorrReport {
        let base = (0..128)
            .map(|index| (index as f64 * 0.17).sin())
            .collect::<Vec<_>>();
        let channels = MODALITIES
            .iter()
            .map(|&modality| {
                let values = if decoupled == Some(modality) {
                    base.iter().map(|value| -*value).collect()
                } else {
                    base.clone()
                };
                (modality, values)
            })
            .collect::<Vec<_>>();
        let config = CorrConfig::standalone_advisory_v0_9()
            .unwrap()
            .try_for_axis_family(axis_count)
            .unwrap();
        correlation::analyze(&channels, &config).unwrap()
    }

    fn insufficient_correlation(axis_count: usize) -> CorrReport {
        let config = CorrConfig::standalone_advisory_v0_9()
            .unwrap()
            .try_for_axis_family(axis_count)
            .unwrap();
        correlation::analyze(&[], &config).unwrap()
    }

    fn axis_correlation(
        axis: usize,
        decoupled: Option<Modality>,
        axis_count: usize,
    ) -> AxisCorrelationReport {
        AxisCorrelationReport::try_new(axis, correlation_report(decoupled, axis_count)).unwrap()
    }

    fn scenario() -> ScenarioConfig {
        let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
        params.frames = 300;
        params.rho = 0.7;
        params.seed = 5;
        ScenarioConfig::try_new(params).unwrap()
    }

    fn without_projection(source: &PidObservation) -> PidObservation {
        let mut observation = PidObservation::try_scalar(
            source.track_id(),
            source.timestamp_ms(),
            source.sequence(),
            source.modality(),
            source.nis(),
            source.dof(),
        )
        .unwrap();
        if let (Some(innovation), Some(covariance)) =
            (source.innovation(), source.innovation_covariance())
        {
            observation = observation
                .try_with_research(innovation, covariance)
                .unwrap();
        }
        observation
    }

    fn with_nis(source: &PidObservation, nis: f64) -> PidObservation {
        let mut observation = PidObservation::try_scalar(
            source.track_id(),
            source.timestamp_ms(),
            source.sequence(),
            source.modality(),
            nis,
            source.dof(),
        )
        .unwrap();
        if let (Some(innovation), Some(covariance)) =
            (source.innovation(), source.innovation_covariance())
        {
            observation = observation
                .try_with_research(innovation, covariance)
                .unwrap();
        }
        if let Some(projection) = source.consistency_projection() {
            observation = observation.with_consistency_projection(projection.clone());
        }
        observation
    }

    fn fused(stream: &[PidObservation]) -> FusedVerdict {
        assess_stream(stream, &research_suite())
            .unwrap()
            .verdict()
            .clone()
    }

    fn nominal_baseline() -> MirrorReport {
        let suite = ReleaseSuite::standalone_advisory_v0_9(&MODALITIES).unwrap();
        let mut mirror = Mirror::from_release_suite(&suite);
        let track = TrackId::new(1).unwrap();
        for raw_sequence in 0..64 {
            let sequence = Sequence::new(raw_sequence).unwrap();
            let timestamp = TimestampMillis::new(raw_sequence * 100).unwrap();
            for modality in MODALITIES {
                mirror
                    .ingest(
                        &PidObservation::try_scalar(track, timestamp, sequence, modality, 3.0, 3)
                            .unwrap(),
                    )
                    .unwrap();
            }
        }
        mirror.assess(track, Sequence::new(63).unwrap()).unwrap()
    }

    fn diagnostics(
        suite: &PidResearchSuite,
        baseline: MirrorReport,
        correlations: Vec<AxisCorrelationReport>,
        pids: Vec<AxisPidReport>,
    ) -> (FusedVerdict, String) {
        fuse_axes_diagnostics(suite, &baseline, &correlations, &pids).unwrap()
    }

    #[test]
    fn clean_is_nominal() {
        let suite = research_suite();
        let stream = generate(&scenario()).unwrap();
        let report = assess_stream(&stream, &suite).unwrap();

        assert_eq!(report.correlations().len(), 3);
        assert_eq!(report.pids().len(), 3);
        assert_eq!(report.verdict(), &FusedVerdict::Nominal);
        assert!(report.note().contains("signed correlation:"));
        assert!(report.note().contains("PID escalation:"));
        assert_eq!(report.suite_identity(), suite.identity());
        assert_eq!(report.classification(), suite.classification());
        assert_eq!(
            report.assessment_binding().suite_identity(),
            suite.identity()
        );
        assert!(report
            .assessment_binding()
            .release_binding()
            .verifies(&stream, suite.release_suite()));
        assert_eq!(
            report.baseline().assessment_binding(),
            Some(report.assessment_binding().release_binding())
        );
        assert!(report.correlations().iter().all(|axis| {
            axis.assessment_binding() == Some(report.assessment_binding().release_binding())
        }));
        assert!(report
            .pids()
            .iter()
            .all(|axis| { axis.assessment_binding() == Some(report.assessment_binding()) }));
    }

    #[test]
    fn accepted_pid_fusion_rejects_equal_shape_stream_and_suite_substitution() {
        let suite = PidResearchSuite::point_estimate_only_v0_9(&MODALITIES).unwrap();
        let stream_a = generate(&scenario()).unwrap();
        let mut stream_b = stream_a.clone();
        stream_b[0] = with_nis(&stream_a[0], stream_a[0].nis() + 0.125);
        let report_a = assess_stream(&stream_a, &suite).unwrap();
        let report_b = assess_stream(&stream_b, &suite).unwrap();

        assert_ne!(report_a.assessment_binding(), report_b.assessment_binding());
        assert!(fuse_axes(
            &suite,
            report_a.baseline().clone(),
            report_a.correlations().to_vec(),
            report_b.pids().to_vec(),
        )
        .is_err());
        assert!(fuse_axes(
            &suite,
            report_b.baseline().clone(),
            report_a.correlations().to_vec(),
            report_a.pids().to_vec(),
        )
        .is_err());

        let equal_components_custom_suite = PidResearchSuite::try_new(PidResearchSuiteParams {
            release_suite: suite.release_suite().clone(),
            pid: suite.pid_config().clone(),
        })
        .unwrap();
        let custom_report = assess_stream(&stream_a, &equal_components_custom_suite).unwrap();
        assert_ne!(suite.identity(), equal_components_custom_suite.identity());
        assert_eq!(
            report_a
                .pids()
                .first()
                .unwrap()
                .report()
                .estimator()
                .config_identity(),
            custom_report
                .pids()
                .first()
                .unwrap()
                .report()
                .estimator()
                .config_identity()
        );
        assert!(fuse_axes(
            &equal_components_custom_suite,
            custom_report.baseline().clone(),
            custom_report.correlations().to_vec(),
            report_a.pids().to_vec(),
        )
        .is_err());

        let mut detector_params = DetectorParams::standalone_advisory_v0_9();
        detector_params.cusum_threshold += 0.25;
        let detector_only_release_change = ReleaseSuite::try_new(ReleaseSuiteParams {
            detector: DetectorConfig::try_new(detector_params).unwrap(),
            correlation: suite.release_suite().correlation().clone(),
            expected_modalities: MODALITIES.to_vec(),
            axis_policy: suite.release_suite().axis_policy(),
        })
        .unwrap();
        let detector_changed_suite = PidResearchSuite::try_new(PidResearchSuiteParams {
            release_suite: detector_only_release_change,
            pid: suite.pid_config().clone(),
        })
        .unwrap();
        let detector_changed_report = assess_stream(&stream_a, &detector_changed_suite).unwrap();
        assert_ne!(
            report_a
                .assessment_binding()
                .release_binding()
                .suite_identity(),
            detector_changed_report
                .assessment_binding()
                .release_binding()
                .suite_identity()
        );
        assert_eq!(
            report_a.correlations()[0].config_identity(),
            detector_changed_report.correlations()[0].config_identity()
        );
        assert!(fuse_axes(
            &detector_changed_suite,
            detector_changed_report.baseline().clone(),
            report_a.correlations().to_vec(),
            detector_changed_report.pids().to_vec(),
        )
        .is_err());
    }

    #[test]
    fn stream_assessment_never_falls_back_to_native_innovations() {
        let mut stream = generate(&scenario()).unwrap();
        for observation in &mut stream {
            *observation = without_projection(observation);
        }
        let report = assess_stream(&stream, &research_suite()).unwrap();

        assert!(report.correlations().is_empty());
        assert!(report.pids().is_empty());
        assert_eq!(report.verdict(), &FusedVerdict::InsufficientEvidence);
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
        let report = assess_stream(&stream, &research_suite()).unwrap();
        assert!(report
            .pids()
            .iter()
            .any(|axis| matches!(axis.report().verdict(), PidVerdict::InsufficientEvidence)));
        assert!(report
            .pids()
            .iter()
            .any(|axis| matches!(axis.report().verdict(), PidVerdict::Decoupled(_))));
        assert!(report
            .correlations()
            .iter()
            .all(|axis| { !matches!(axis.report().verdict(), CorrVerdict::InsufficientEvidence) }));
        assert!(
            matches!(
                report.verdict(),
                FusedVerdict::AttributedInconsistency {
                    channels,
                    magnitude: MagnitudeEvidence::InCovariance,
                } if channels == &[Modality::Acoustic]
            ),
            "unexpected fused verdict {:?}: {}",
            report.verdict(),
            report.note()
        );
        let acoustic = report
            .baseline()
            .channels()
            .iter()
            .find(|channel| channel.modality() == Modality::Acoustic)
            .unwrap();
        assert!(!acoustic.anomalous());
        assert!(report.pids().iter().all(|axis| {
            axis.report().estimator().pid_rs_revision() == crate::PID_RS_REVISION
                && axis.report().estimator().atom_scientific_status()
                    == "experimental_restricted_domain"
                && axis.report().estimator().research_profile() == "circular_delete_block_v0_9"
                && axis.report().estimator().axis_family_count() == 3
                && axis.report().estimator().axis_family_was_derived()
        }));
    }

    #[test]
    fn positive_pid_axis_alongside_insufficient_pid_axis_fails_closed() {
        let suite = research_suite();
        let report = diagnostics(
            &suite,
            nominal_baseline(),
            vec![axis_correlation(0, None, 2), axis_correlation(1, None, 2)],
            vec![
                axis_pid(
                    0,
                    PidVerdict::Decoupled(vec![Modality::Acoustic]),
                    "positive PID axis",
                    2,
                ),
                axis_pid(
                    1,
                    PidVerdict::InsufficientEvidence,
                    "insufficient PID axis",
                    2,
                ),
            ],
        );

        assert_eq!(
            report.0,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic]
            }
        );
        assert!(report.1.contains("insufficient projection axis"));
    }

    #[test]
    fn matching_partial_pid_preserves_complete_signed_default() {
        let suite = research_suite();
        let report = diagnostics(
            &suite,
            nominal_baseline(),
            vec![
                axis_correlation(0, Some(Modality::Acoustic), 2),
                axis_correlation(1, Some(Modality::Acoustic), 2),
            ],
            vec![
                axis_pid(
                    0,
                    PidVerdict::Decoupled(vec![Modality::Acoustic]),
                    "partial PID attribution",
                    2,
                ),
                axis_pid(
                    1,
                    PidVerdict::InsufficientEvidence,
                    "partial PID attribution",
                    2,
                ),
            ],
        );

        assert_eq!(
            report.0,
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

        let suite = research_suite();
        let correlation_config = suite
            .release_suite()
            .correlation()
            .try_for_axis_family(1)
            .unwrap();
        let correlation = correlation::analyze(&channels, &correlation_config).unwrap();
        assert!(matches!(
            correlation.verdict(),
            CorrVerdict::Decoupled(ref found) if found.contains(&Modality::Acoustic)
        ));

        let pid_config = suite.pid_config().try_for_axis_family(1).unwrap();
        let pid = analyze(&channels, &pid_config).unwrap();
        assert_eq!(pid.verdict(), &PidVerdict::Nominal, "{}", pid.note());

        match fuse(&suite, nominal_baseline(), correlation, pid)
            .unwrap()
            .0
        {
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
    fn positive_pid_evidence_is_not_erased_when_signed_correlation_is_insufficient() {
        let suite = research_suite();
        let correlation = insufficient_correlation(1);
        let pid_config = confirmed_config().try_for_axis_family(1).unwrap();
        let pid = PidReport::new(
            crate::PidEstimatorEvidence::from_config(&pid_config),
            MODALITIES
                .iter()
                .map(|&modality| pid_channel(modality, modality == Modality::Acoustic))
                .collect(),
            PidVerdict::Decoupled(vec![Modality::Acoustic]),
            "test PID decoupling".into(),
        );

        assert!(matches!(
            fuse(&suite, nominal_baseline(), correlation, pid)
                .unwrap()
                .0,
            FusedVerdict::AttributedInconsistency { channels, .. }
                if channels.contains(&Modality::Acoustic)
        ));
    }

    #[test]
    fn conflicting_positive_attributions_fail_closed_to_unclassified_anomaly() {
        let suite = research_suite();
        let correlation = correlation_report(Some(Modality::Radar), 1);
        let pid_config = confirmed_config().try_for_axis_family(1).unwrap();
        let pid = PidReport::new(
            crate::PidEstimatorEvidence::from_config(&pid_config),
            MODALITIES
                .iter()
                .map(|&modality| pid_channel(modality, modality == Modality::Acoustic))
                .collect(),
            PidVerdict::Decoupled(vec![Modality::Acoustic]),
            "test PID attribution".into(),
        );

        assert_eq!(
            fuse(&suite, nominal_baseline(), correlation, pid)
                .unwrap()
                .0,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic, Modality::Radar],
            }
        );
    }

    #[test]
    fn sealed_insufficient_correlation_is_preserved_instead_of_becoming_intact() {
        let suite = research_suite();
        let report = fuse(
            &suite,
            nominal_baseline(),
            insufficient_correlation(1),
            pid_report(PidVerdict::Nominal, "PID nominal", 1),
        )
        .unwrap();

        assert_eq!(report.0, FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn empty_positive_pid_verdict_fails_closed_instead_of_becoming_intact() {
        let suite = research_suite();
        let report = fuse(
            &suite,
            nominal_baseline(),
            correlation_report(None, 1),
            pid_report(
                PidVerdict::Decoupled(Vec::new()),
                "malformed empty PID attribution",
                1,
            ),
        )
        .unwrap();

        assert_eq!(
            report.0,
            FusedVerdict::UnclassifiedAnomaly {
                channels: Vec::new()
            }
        );
        assert!(report.1.contains("empty positive attribution"));
    }

    #[test]
    fn conflicting_projection_axes_fail_closed_to_unclassified_anomaly() {
        let suite = research_suite();
        let nominal_pid = |axis| axis_pid(axis, PidVerdict::Nominal, "axis nominal", 2);

        let report = diagnostics(
            &suite,
            nominal_baseline(),
            vec![
                axis_correlation(0, Some(Modality::Radar), 2),
                axis_correlation(1, Some(Modality::Acoustic), 2),
            ],
            vec![nominal_pid(0), nominal_pid(1)],
        );

        assert_eq!(
            report.0,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic, Modality::Radar]
            }
        );
    }

    #[test]
    fn axis_wrapper_and_fusion_reject_invalid_or_duplicate_provenance() {
        assert!(matches!(
            AxisPidReport::try_new(
                MAX_CONSISTENCY_PROJECTION_AXES,
                pid_report(PidVerdict::Nominal, "out of range", 1),
            ),
            Err(GaladrielError::InvalidChannels(_))
        ));

        let suite = research_suite();
        let result = fuse_axes(
            &suite,
            nominal_baseline(),
            vec![
                axis_correlation(0, None, 2),
                AxisCorrelationReport::try_new(0, correlation_report(None, 2)).unwrap(),
            ],
            vec![
                axis_pid(0, PidVerdict::Nominal, "axis zero", 2),
                AxisPidReport::try_new(
                    0,
                    pid_report(PidVerdict::Nominal, "duplicate axis zero", 2),
                )
                .unwrap(),
            ],
        );
        assert!(matches!(result, Err(GaladrielError::InvalidChannels(_))));
    }

    #[test]
    fn fusion_checks_correlation_and_pid_axis_contiguity_independently() {
        let suite = research_suite();
        let baseline = nominal_baseline();
        let valid_correlations = vec![axis_correlation(0, None, 2), axis_correlation(1, None, 2)];
        let valid_pids = vec![
            axis_pid(0, PidVerdict::Nominal, "axis zero", 2),
            axis_pid(1, PidVerdict::Nominal, "axis one", 2),
        ];

        let duplicate_correlations =
            vec![axis_correlation(0, None, 2), axis_correlation(0, None, 2)];
        assert!(matches!(
            fuse_axes_diagnostics(&suite, &baseline, &duplicate_correlations, &valid_pids),
            Err(GaladrielError::InvalidChannels(_))
        ));

        let duplicate_pids = vec![
            axis_pid(0, PidVerdict::Nominal, "axis zero", 2),
            axis_pid(0, PidVerdict::Nominal, "duplicate axis zero", 2),
        ];
        assert!(matches!(
            fuse_axes_diagnostics(&suite, &baseline, &valid_correlations, &duplicate_pids),
            Err(GaladrielError::InvalidChannels(_))
        ));
    }

    #[test]
    fn accepted_fused_report_rejects_unbound_compatibility_components() {
        let suite = research_suite();
        let result = fuse_axes(
            &suite,
            nominal_baseline(),
            vec![axis_correlation(0, None, 1)],
            vec![axis_pid(0, PidVerdict::Nominal, "unbound PID", 1)],
        );

        assert!(matches!(result, Err(GaladrielError::InvalidConfig(_))));
    }

    #[test]
    fn fusion_rejects_mixed_pid_configuration_identities() {
        let suite = research_suite();
        let point = PidResearchProfile::PointEstimateOnlyV0_9
            .try_config()
            .unwrap()
            .try_for_axis_family(2)
            .unwrap();
        let point_report = PidReport::new(
            crate::PidEstimatorEvidence::from_config(&point),
            Vec::new(),
            PidVerdict::Nominal,
            "wrong config".into(),
        );
        let result = fuse_axes(
            &suite,
            nominal_baseline(),
            vec![axis_correlation(0, None, 2), axis_correlation(1, None, 2)],
            vec![
                axis_pid(0, PidVerdict::Nominal, "confirmed config", 2),
                AxisPidReport::try_new(1, point_report).unwrap(),
            ],
        );
        assert!(matches!(result, Err(GaladrielError::InvalidConfig(_))));
    }

    #[test]
    fn multi_axis_confirmation_resolution_is_rejected_before_pid_estimation() {
        let mut params = PidResearchProfile::CircularDeleteBlockV0_9.params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 20,
            block_size: 8,
            family_alpha: 0.10,
        };
        let config = PidConfig::try_new(params).unwrap();
        let release_suite = ReleaseSuite::standalone_advisory_v0_9(&MODALITIES).unwrap();
        assert!(matches!(
            PidResearchSuite::try_new(PidResearchSuiteParams {
                release_suite,
                pid: config,
            }),
            Err(crate::PidResearchSuiteError::PidConfig(
                crate::PidConfigError::ConfirmationTailRankUnresolvable { axis_count: 3, .. }
            ))
        ));
    }

    #[test]
    fn configurable_stream_assessment_preserves_the_requested_correlation_config() {
        let stream = generate(&scenario()).unwrap();
        let mut params = galadriel_core::CorrParams::standalone_advisory_v0_9();
        params.corr_floor = 1.0;
        let corr_cfg = CorrConfig::try_new(params).unwrap();
        let release_suite = ReleaseSuite::try_new(ReleaseSuiteParams {
            detector: DetectorConfig::standalone_advisory_v0_9().unwrap(),
            correlation: corr_cfg,
            expected_modalities: MODALITIES.to_vec(),
            axis_policy: ProducerAxisFamilyPolicy::AttestedCommonProjectionBonferroniV1,
        })
        .unwrap();
        let suite = PidResearchSuite::try_new(PidResearchSuiteParams {
            release_suite,
            pid: confirmed_config(),
        })
        .unwrap();
        let report = assess_stream(&stream, &suite).unwrap();

        assert!(report
            .correlations()
            .iter()
            .all(|axis| matches!(axis.report().verdict(), CorrVerdict::InsufficientEvidence)));
    }
}
