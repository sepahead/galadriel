//! Fusing the NIS magnitude baseline with a cross-sensor **consistency** detector
//! into one evidence-neutral advisory verdict.
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
//! | **NIS in-covariance** | `Nominal` | `AttributedInconsistency { magnitude: InCovariance }` |
//! | **one channel's NIS inflated** | `AttributedInconsistency { magnitude: Elevated }` | `AttributedInconsistency` |
//! | **configured broad fraction of ready channels' NIS inflated** | `BroadDegradation` | `AttributedInconsistency` or fail-closed `UnclassifiedAnomaly` |
//!
//! Every active producer-attested projection axis is assessed. The correlation
//! family budget is split across axes; contradictory or partly unavailable positive
//! axis attribution is an `UnclassifiedAnomaly`, never a confident attribution.

use std::collections::HashSet;

#[cfg(test)]
use crate::correlation::CorrConfig;
use crate::correlation::{self, CorrReport, CorrVerdict};
use crate::{
    AnomalyEvidence, AssessmentBinding, AssessmentClassification, AssessmentFailure,
    AssessmentOutcome, ConfigDigest, ConsistencyChannels, Mirror, MirrorReport, Modality,
    PidObservation, ProducerAxisFamilyPolicy, ReleaseSuite,
};
use serde::Serialize;

/// What the NIS magnitude detector established for a fused inconsistency attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum FusedVerdict {
    /// All channels corroborate and NIS is consistent.
    Nominal,
    /// One or more channels have attributed statistical inconsistency. This is not
    /// an attack-cause claim: genuine target-specific dynamics or estimator
    /// artifacts can produce the same signature.
    AttributedInconsistency {
        channels: Vec<Modality>,
        magnitude: MagnitudeEvidence,
    },
    /// The configured broad fraction of ready channels has inflated NIS while
    /// correlation stays intact — broad degradation evidence.
    BroadDegradation,
    /// Positive evidence exists, but incomplete/mixed-direction magnitude input
    /// prevents a narrower statistical classification.
    UnclassifiedAnomaly { channels: Vec<Modality> },
    /// Neither detector has enough evidence. Fail closed.
    InsufficientEvidence,
}

/// A validated, non-empty set of uniquely attributed modalities.
///
/// The tuple field is private so a [`ConsistencyEvidence::Decoupled`] value cannot
/// carry an empty attribution. Use [`Self::new`] to normalize caller input.
///
/// ```compile_fail
/// use galadriel_core::fusion::NonEmptyModalities;
///
/// let _ = NonEmptyModalities(Vec::new());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmptyModalities(Vec<Modality>);

impl NonEmptyModalities {
    /// Validate, sort, and deduplicate a non-empty modality attribution.
    pub fn new(modalities: &[Modality]) -> crate::Result<Self> {
        if modalities.is_empty() {
            return Err(crate::GaladrielError::InvalidChannels(
                "a positive consistency attribution must name at least one modality".into(),
            ));
        }
        if modalities.len() > Modality::ALL.len() {
            return Err(crate::GaladrielError::InvalidChannels(format!(
                "a consistency attribution may contain at most {} modalities",
                Modality::ALL.len()
            )));
        }
        let mut unique = modalities.to_vec();
        unique.sort_by_key(|modality| modality.stable_code());
        unique.dedup();
        Ok(Self(unique))
    }

    /// Borrow the normalized modalities in stable order.
    pub fn as_slice(&self) -> &[Modality] {
        &self.0
    }

    /// Consume the attribution and return its normalized modalities.
    pub fn into_vec(self) -> Vec<Modality> {
        self.0
    }
}

/// Cross-sensor evidence presented to source-agnostic fusion.
///
/// Each variant is one coherent state. In particular, a positive attribution
/// cannot coexist with an `insufficient` flag because no such flag exists.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsistencyEvidence {
    /// The consistency detector had enough evidence and found no decoupling.
    Intact,
    /// The consistency detector positively attributed one or more modalities.
    Decoupled(NonEmptyModalities),
    /// The consistency detector could not make an assessment.
    Insufficient,
    /// Positive/incomplete sources conflict. The vector is the bounded union of
    /// any modalities that were named and may be empty for malformed attribution.
    Conflicted(Vec<Modality>),
}

impl ConsistencyEvidence {
    /// Build positive decoupling evidence with a non-empty normalized attribution.
    pub fn decoupled(modalities: &[Modality]) -> crate::Result<Self> {
        NonEmptyModalities::new(modalities).map(Self::Decoupled)
    }

    /// Build conflicted evidence, normalizing its investigative channel union.
    pub fn conflicted(modalities: &[Modality]) -> crate::Result<Self> {
        if modalities.len() > Modality::ALL.len() {
            return Err(crate::GaladrielError::InvalidChannels(format!(
                "a consistency conflict may contain at most {} modalities",
                Modality::ALL.len()
            )));
        }
        let mut unique = modalities.to_vec();
        unique.sort_by_key(|modality| modality.stable_code());
        unique.dedup();
        Ok(Self::Conflicted(unique))
    }
}

/// Source-agnostic compatibility fusion of a NIS report and coherent consistency state.
///
/// The typed [`ConsistencyEvidence`] input makes the formerly contradictory
/// "positive attribution and insufficient evidence" combination unrepresentable.
/// [`MirrorReport`] is sealed and fusion consumes the config-bound outcome that
/// the detector retained when it created the report. The returned tuple is an
/// explicitly unbound diagnostic; only [`assess_default`] can mint a sealed
/// accepted [`DefaultReport`] with exact suite-and-input provenance.
pub fn combine(
    baseline: &MirrorReport,
    consistency: ConsistencyEvidence,
) -> (FusedVerdict, String) {
    combine_validated(baseline, baseline.magnitude_outcome(), consistency)
}

/// Fuse a sealed NIS magnitude report with one coherent consistency state.
///
/// This compatibility tuple is explicitly unbound and is not an accepted
/// whole-stream release assessment.
///
/// # Errors
///
/// This compatibility result surface remains fallible for callers that already
/// propagate typed assessment failures. A detector-created sealed report is
/// already coherent, so the current implementation returns `Ok`.
pub fn try_combine(
    baseline: &MirrorReport,
    consistency: ConsistencyEvidence,
) -> Result<(FusedVerdict, String), AssessmentFailure> {
    let baseline_outcome = baseline.magnitude_outcome();
    Ok(combine_validated(baseline, baseline_outcome, consistency))
}

fn combine_validated(
    baseline: &MirrorReport,
    baseline_outcome: AssessmentOutcome,
    consistency: ConsistencyEvidence,
) -> (FusedVerdict, String) {
    let (decoupled, consistency_insufficient) = match consistency {
        ConsistencyEvidence::Intact => (Vec::new(), false),
        ConsistencyEvidence::Decoupled(modalities) => (modalities.into_vec(), false),
        ConsistencyEvidence::Insufficient => (Vec::new(), true),
        ConsistencyEvidence::Conflicted(mut channels) => {
            channels.extend(
                baseline
                    .channels()
                    .iter()
                    .filter(|channel| channel.anomalous())
                    .map(|channel| channel.modality()),
            );
            channels.sort_by_key(|modality| modality.stable_code());
            channels.dedup();
            return (
                FusedVerdict::UnclassifiedAnomaly { channels },
                "consistency evidence is conflicting or incomplete; failing closed".to_string(),
            );
        }
    };
    let anomalous: HashSet<Modality> = baseline
        .channels()
        .iter()
        .filter(|c| c.anomalous())
        .map(|c| c.modality())
        .collect();
    let baseline_out = matches!(&baseline_outcome, AssessmentOutcome::Insufficient(_));

    if matches!(
        &baseline_outcome,
        AssessmentOutcome::Anomaly(AnomalyEvidence::Unclassified(_))
    ) {
        let mut channels: Vec<Modality> = anomalous
            .iter()
            .copied()
            .chain(decoupled.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        channels.sort_by_key(|modality| modality.stable_code());
        return (
            FusedVerdict::UnclassifiedAnomaly { channels },
            "positive anomaly evidence exists, but magnitude attribution is incomplete or mixed-direction"
                .to_string(),
        );
    }

    if baseline_out && consistency_insufficient {
        return (
            FusedVerdict::InsufficientEvidence,
            "both detectors lack evidence — fail closed".to_string(),
        );
    }

    if !decoupled.is_empty() {
        let consistency_attribution: HashSet<Modality> = decoupled.iter().copied().collect();
        let baseline_attribution = match &baseline_outcome {
            AssessmentOutcome::Anomaly(AnomalyEvidence::Attributed(channels)) => {
                Some(channels.as_slice().iter().copied().collect())
            }
            AssessmentOutcome::Anomaly(AnomalyEvidence::BroadDegradation) => {
                Some(anomalous.clone())
            }
            AssessmentOutcome::Nominal
            | AssessmentOutcome::Insufficient(_)
            | AssessmentOutcome::Anomaly(AnomalyEvidence::Unclassified(_)) => None,
        };
        if let Some(baseline_attribution) =
            baseline_attribution.filter(|attribution| attribution != &consistency_attribution)
        {
            let mut channels: Vec<Modality> = baseline_attribution
                .iter()
                .copied()
                .chain(consistency_attribution)
                .collect();
            channels.sort_by_key(|modality| modality.stable_code());
            channels.dedup();
            return (
                FusedVerdict::UnclassifiedAnomaly { channels },
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
        channels.sort_by_key(|modality| modality.stable_code());
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
            FusedVerdict::AttributedInconsistency {
                channels,
                magnitude,
            },
            format!(
                "cross-sensor decoupling/magnitude evidence on {} ({magnitude:?})",
                names.join(", ")
            ),
        );
    }

    match &baseline_outcome {
        AssessmentOutcome::Anomaly(AnomalyEvidence::BroadDegradation) => (
            FusedVerdict::BroadDegradation,
            "a configured broad fraction of ready channels has inflated NIS while cross-channel structure remains intact — broad-degradation evidence, cause unclassified"
                .to_string(),
        ),
        AssessmentOutcome::Anomaly(AnomalyEvidence::Attributed(channels)) => {
            let channels = channels.as_slice();
            let names: Vec<&str> = channels.iter().map(|m| m.label()).collect();
            (
                FusedVerdict::AttributedInconsistency {
                    channels: channels.to_vec(),
                    magnitude: MagnitudeEvidence::Elevated,
                },
                format!(
                    "localized baseline NIS inflation on {} — spoof-like evidence, cause unclassified",
                    names.join(", ")
                ),
            )
        }
        AssessmentOutcome::Nominal if consistency_insufficient => (
            FusedVerdict::InsufficientEvidence,
            "NIS is in covariance, but the cross-sensor detector lacks evidence — fail closed"
                .to_string(),
        ),
        AssessmentOutcome::Nominal => (
            FusedVerdict::Nominal,
            "all channels corroborate and NIS is consistent".to_string(),
        ),
        // Baseline could not assess magnitude and there is no decoupling to escalate on:
        // fail closed rather than silently upgrade an insufficient baseline to Nominal.
        AssessmentOutcome::Insufficient(_) => (
            FusedVerdict::InsufficientEvidence,
            "baseline lacks magnitude evidence and no decoupling seen — fail closed".to_string(),
        ),
        AssessmentOutcome::Anomaly(AnomalyEvidence::Unclassified(anomaly)) => (
            FusedVerdict::UnclassifiedAnomaly {
                channels: anomaly.affected_modalities().to_vec(),
            },
            "magnitude detector reported an unclassified anomaly".to_string(),
        ),
    }
}

/// The pure default fused report (NIS baseline ⊕ correlation consistency).
#[derive(Debug, Clone, Serialize)]
pub struct DefaultReport {
    /// The unified verdict.
    verdict: FusedVerdict,
    /// The NIS baseline report.
    baseline: MirrorReport,
    /// Per-axis correlation consistency reports. Empty means no valid common
    /// consistency projection was available; raw innovations are never substituted.
    correlations: Vec<AxisCorrelationReport>,
    /// Rationale.
    note: String,
    /// Canonical complete release-suite identity.
    suite_identity: ConfigDigest,
    /// Named/custom release classification.
    classification: AssessmentClassification,
    /// Canonical exact suite-and-input binding shared by every component.
    assessment_binding: AssessmentBinding,
}

impl DefaultReport {
    /// Unified advisory verdict.
    pub const fn verdict(&self) -> &FusedVerdict {
        &self.verdict
    }
    /// Sealed magnitude report.
    pub const fn baseline(&self) -> &MirrorReport {
        &self.baseline
    }
    /// Sealed per-axis correlation reports.
    pub fn correlations(&self) -> &[AxisCorrelationReport] {
        &self.correlations
    }
    /// Human-readable, non-normative rationale.
    pub fn note(&self) -> &str {
        &self.note
    }
    /// Canonical complete release-suite identity.
    pub const fn suite_identity(&self) -> ConfigDigest {
        self.suite_identity
    }
    /// Named/custom release classification.
    pub const fn classification(&self) -> AssessmentClassification {
        self.classification
    }
    /// Canonical exact suite-and-input binding shared by every component.
    pub const fn assessment_binding(&self) -> &AssessmentBinding {
        &self.assessment_binding
    }
}

/// Correlation detail for one producer-attested consistency-projection axis.
#[derive(Debug, Clone, Serialize)]
pub struct AxisCorrelationReport {
    /// Zero-based axis in [`crate::ConsistencyProjection::values`].
    axis: usize,
    /// Correlation analysis for this axis.
    report: CorrReport,
    /// Exact accepted assessment binding, absent on compatibility diagnostics.
    assessment_binding: Option<AssessmentBinding>,
}

impl AxisCorrelationReport {
    /// Wrap a sealed report as the sole producer projection axis.
    ///
    /// Axis zero is inside the closed projection domain by construction, so this
    /// convenience path is infallible and does not weaken range validation.
    pub fn single_axis(report: CorrReport) -> Self {
        Self {
            axis: 0,
            report,
            assessment_binding: None,
        }
    }

    /// Wrap an already sealed correlation report for one valid projection axis.
    ///
    /// # Errors
    ///
    /// Returns an error for an axis outside the producer projection domain.
    pub fn try_new(axis: usize, report: CorrReport) -> crate::Result<Self> {
        if axis >= crate::MAX_CONSISTENCY_PROJECTION_AXES {
            return Err(crate::GaladrielError::InvalidChannels(format!(
                "correlation axis must be in 0..{}, got {axis}",
                crate::MAX_CONSISTENCY_PROJECTION_AXES
            )));
        }
        Ok(Self {
            axis,
            report,
            assessment_binding: None,
        })
    }

    /// Zero-based producer projection axis.
    pub const fn axis(&self) -> usize {
        self.axis
    }
    /// Sealed correlation report.
    pub const fn report(&self) -> &CorrReport {
        &self.report
    }
    /// Canonical accepted correlation-config identity for this axis.
    pub const fn config_identity(&self) -> ConfigDigest {
        self.report.config_identity()
    }

    /// Exact accepted assessment binding, or `None` for an explicitly unbound
    /// compatibility diagnostic.
    pub const fn assessment_binding(&self) -> Option<&AssessmentBinding> {
        self.assessment_binding.as_ref()
    }

    fn try_new_bound(
        axis: usize,
        report: CorrReport,
        binding: &AssessmentBinding,
    ) -> crate::Result<Self> {
        let mut axis = Self::try_new(axis, report)?;
        axis.assessment_binding = Some(binding.clone());
        Ok(axis)
    }
}

fn axis_consistency_evidence(
    reports: &[AxisCorrelationReport],
) -> (ConsistencyEvidence, Option<&'static str>) {
    if reports.iter().enumerate().any(|(index, axis)| {
        reports[..index]
            .iter()
            .any(|earlier| earlier.axis == axis.axis)
    }) {
        return (
            ConsistencyEvidence::Conflicted(Vec::new()),
            Some("projection axes must be unique"),
        );
    }
    if reports.first().is_some_and(|first| {
        reports
            .iter()
            .skip(1)
            .any(|axis| axis.config_identity() != first.config_identity())
    }) {
        return (
            ConsistencyEvidence::Conflicted(Vec::new()),
            Some("projection axes were produced under different accepted configurations"),
        );
    }
    let insufficient = reports.is_empty()
        || reports
            .iter()
            .any(|axis| matches!(axis.report.verdict(), CorrVerdict::InsufficientEvidence));
    let positive = reports
        .iter()
        .filter_map(|axis| match axis.report.verdict() {
            CorrVerdict::Decoupled(channels) => {
                Some(channels.iter().copied().collect::<HashSet<_>>())
            }
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
    decoupled.sort_by_key(|modality| modality.stable_code());
    if positive.iter().any(HashSet::is_empty) {
        return (
            ConsistencyEvidence::Conflicted(decoupled),
            Some("a positive projection axis supplied an empty attribution"),
        );
    }
    if conflict {
        return (
            ConsistencyEvidence::Conflicted(decoupled),
            Some("projection axes positively attribute different channels"),
        );
    }
    if insufficient && !decoupled.is_empty() {
        return (
            ConsistencyEvidence::Conflicted(decoupled),
            Some("a projection axis attributes a channel while another axis is insufficient"),
        );
    }
    if insufficient {
        return (ConsistencyEvidence::Insufficient, None);
    }
    if decoupled.is_empty() {
        return (ConsistencyEvidence::Intact, None);
    }
    match NonEmptyModalities::new(&decoupled) {
        Ok(modalities) => (ConsistencyEvidence::Decoupled(modalities), None),
        Err(_) => (
            ConsistencyEvidence::Conflicted(Vec::new()),
            Some("a positive projection axis supplied an empty or invalid attribution"),
        ),
    }
}

fn validate_correlation_provenance(
    suite: &ReleaseSuite,
    baseline: &MirrorReport,
    correlations: &[AxisCorrelationReport],
) -> crate::Result<()> {
    if baseline.config_identity() != suite.identity() {
        return Err(crate::GaladrielError::InvalidConfig(
            "correlation fusion baseline identity does not match the accepted release suite".into(),
        ));
    }
    match baseline.assessment_binding() {
        Some(binding) => {
            if binding.suite_identity() != suite.identity() {
                return Err(crate::GaladrielError::InvalidConfig(
                    "assessment binding does not match the accepted release suite".into(),
                ));
            }
            if correlations.iter().any(|axis| {
                axis.assessment_binding()
                    .is_none_or(|axis_binding| axis_binding != binding)
            }) {
                return Err(crate::GaladrielError::InvalidConfig(
                    "correlation fusion components do not share one exact assessment binding"
                        .into(),
                ));
            }
        }
        None => {
            if correlations
                .iter()
                .any(|axis| axis.assessment_binding().is_some())
            {
                return Err(crate::GaladrielError::InvalidConfig(
                    "bound correlation evidence cannot be fused with an unbound baseline".into(),
                ));
            }
        }
    }
    if correlations.is_empty() {
        return Ok(());
    }
    if correlations.len() > crate::MAX_CONSISTENCY_PROJECTION_AXES {
        return Err(crate::GaladrielError::InvalidChannels(format!(
            "projection family has {} axes; maximum is {}",
            correlations.len(),
            crate::MAX_CONSISTENCY_PROJECTION_AXES
        )));
    }
    if correlations
        .iter()
        .enumerate()
        .any(|(expected_axis, report)| report.axis() != expected_axis)
    {
        return Err(crate::GaladrielError::InvalidChannels(
            "correlation fusion axes must be unique and contiguous from zero".into(),
        ));
    }
    let expected = suite
        .correlation()
        .try_for_axis_family(correlations.len())?;
    if correlations
        .iter()
        .any(|axis| axis.config_identity() != expected.identity())
    {
        return Err(crate::GaladrielError::InvalidConfig(
            "correlation report identity does not match the accepted release suite".into(),
        ));
    }
    Ok(())
}

/// Combine a magnitude report with per-axis signed-correlation reports.
///
/// Positive attributions that disagree across axes, or coexist with an
/// insufficient axis, become [`FusedVerdict::UnclassifiedAnomaly`]. An empty slice means the
/// producer supplied no valid common projection and therefore marks consistency
/// insufficient; the magnitude baseline still contributes normally.
///
/// This compatibility function returns tuple diagnostics, not a sealed accepted
/// report. All-unbound inputs remain available for offline component inspection.
/// If any input is bound, every component must share the exact same binding.
///
/// # Errors
///
/// Returns an error unless the baseline belongs to `suite` and every correlation
/// axis is contiguous and was produced by that suite's exact axis-family-derived
/// correlation configuration. Bound inputs must also share one exact suite-and-
/// observation binding; mixing bound and unbound components is rejected.
pub fn combine_correlation_axes(
    suite: &ReleaseSuite,
    baseline: &MirrorReport,
    correlations: &[AxisCorrelationReport],
) -> crate::Result<(FusedVerdict, String)> {
    validate_correlation_provenance(suite, baseline, correlations)?;
    let (consistency, conflict_reason) = axis_consistency_evidence(correlations);
    let (verdict, note) = combine(baseline, consistency);
    if let Some(reason) = conflict_reason {
        return Ok((verdict, format!("{reason}; {note}")));
    }
    Ok((verdict, note))
}

/// Sealed preparation shared by the default and PID whole-stream assessors.
///
/// Construction validates the single-track stream, derives one canonical binding
/// from every exact observation and the complete release suite, and produces only
/// components carrying that same binding. Fields are private so downstream code
/// cannot replace a component while retaining the accepted binding.
#[derive(Debug, Clone)]
pub struct PreparedReleaseAssessment {
    binding: AssessmentBinding,
    baseline: MirrorReport,
    correlations: Vec<AxisCorrelationReport>,
    projection: Option<ConsistencyChannels>,
}

impl PreparedReleaseAssessment {
    /// Canonical exact suite-and-input binding.
    pub const fn assessment_binding(&self) -> &AssessmentBinding {
        &self.binding
    }

    /// Bound magnitude component.
    pub const fn baseline(&self) -> &MirrorReport {
        &self.baseline
    }

    /// Bound signed-correlation components in producer-axis order.
    pub fn correlations(&self) -> &[AxisCorrelationReport] {
        &self.correlations
    }

    /// Validated producer-attested projection used by the consistency components.
    pub const fn projection(&self) -> Option<&ConsistencyChannels> {
        self.projection.as_ref()
    }
}

/// Validate and bind every core component of a whole-stream release assessment.
///
/// This is the only public route to a bound baseline and correlation family.
/// Compatibility component constructors remain unbound diagnostics.
///
/// # Errors
///
/// Returns an error for an empty or malformed stream, release-suite mismatch,
/// temporal/projection incoherence, detector failure, or correlation failure.
pub fn prepare_release_assessment(
    stream: &[PidObservation],
    suite: &ReleaseSuite,
) -> crate::Result<PreparedReleaseAssessment> {
    let first = stream.first().ok_or_else(|| {
        crate::GaladrielError::InvalidChannels(
            "release assessment requires at least one observation".into(),
        )
    })?;
    let modalities = suite.expected_modalities();
    let baseline_cfg = suite.detector();
    let projection = crate::consistency_channels_with_temporal_limits(
        stream,
        modalities,
        baseline_cfg.max_seq_gap(),
        baseline_cfg.max_timestamp_skew_ms(),
        baseline_cfg.max_inter_sample_gap_ms(),
    )?;
    let binding = AssessmentBinding::for_release_stream(stream, suite);

    let mut mirror = Mirror::from_release_suite(suite);
    for observation in stream {
        mirror.ingest(observation)?;
    }
    let track = first.track_id();
    let last_seq = stream
        .iter()
        .map(PidObservation::sequence)
        .fold(first.sequence(), std::cmp::max);
    let mut baseline = mirror.assess(track, last_seq)?;
    baseline.bind_assessment(binding.clone());

    let mut correlations = Vec::new();
    if let Some(projection) = &projection {
        let axis_count = projection.axes.len();
        let adjusted = match suite.axis_policy() {
            ProducerAxisFamilyPolicy::AttestedCommonProjectionBonferroniV1 => {
                suite.correlation().try_for_axis_family(axis_count)?
            }
        };
        for (axis, channels) in projection.axes.iter().enumerate() {
            correlations.push(AxisCorrelationReport::try_new_bound(
                axis,
                correlation::analyze(channels, &adjusted)?,
                &binding,
            )?);
        }
    }
    validate_correlation_provenance(suite, &baseline, &correlations)?;
    Ok(PreparedReleaseAssessment {
        binding,
        baseline,
        correlations,
        projection,
    })
}

/// The **pure default** cross-sensor detector: run the NIS baseline and the cheap
/// correlation consistency check over a whole (single-track) stream, and fuse them.
/// No heavy dependency; this is the default advisory detector path.
pub fn assess_default(
    stream: &[PidObservation],
    suite: &ReleaseSuite,
) -> crate::Result<DefaultReport> {
    let prepared = prepare_release_assessment(stream, suite)?;
    let (verdict, note) =
        combine_correlation_axes(suite, prepared.baseline(), prepared.correlations())?;
    let classification = suite.source_profile().map_or(
        AssessmentClassification::CustomReleaseSuite,
        AssessmentClassification::NamedRelease,
    );
    Ok(DefaultReport {
        verdict,
        baseline: prepared.baseline,
        correlations: prepared.correlations,
        note,
        suite_identity: suite.identity(),
        classification,
        assessment_binding: prepared.binding,
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::decision::ChannelReport;
    use crate::{
        ConsistencyProjection, DetectorConfig, DetectorParams, ProjectionIdentity, ReleaseSuite,
        Sequence, TimestampMillis, TrackId, Verdict,
    };

    fn scalar(
        track_id: u64,
        timestamp_ms: u64,
        sequence: u64,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> PidObservation {
        scalar_typed(
            TrackId::new(track_id).unwrap(),
            TimestampMillis::new(timestamp_ms).unwrap(),
            Sequence::new(sequence).unwrap(),
            modality,
            nis,
            dof,
        )
    }

    fn scalar_typed(
        track_id: TrackId,
        timestamp_ms: TimestampMillis,
        sequence: Sequence,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> PidObservation {
        PidObservation::try_scalar(track_id, timestamp_ms, sequence, modality, nis, dof).unwrap()
    }

    fn ch(modality: Modality, elevated: bool) -> ChannelReport {
        ChannelReport::test_ready(modality, elevated)
    }

    fn baseline(verdict: Verdict, elevated: &[Modality]) -> MirrorReport {
        let all = [Modality::Visual, Modality::Acoustic, Modality::Radar];
        MirrorReport::test_fixture(
            verdict,
            all.iter().map(|&m| ch(m, elevated.contains(&m))).collect(),
        )
    }

    fn decoupled(modalities: &[Modality]) -> ConsistencyEvidence {
        ConsistencyEvidence::decoupled(modalities).unwrap()
    }

    #[test]
    fn nominal_when_nothing_flagged() {
        let (v, _) = try_combine(
            &baseline(Verdict::Nominal, &[]),
            ConsistencyEvidence::Intact,
        )
        .unwrap();
        assert_eq!(v, FusedVerdict::Nominal);
    }

    #[test]
    fn decoupling_with_in_covariance_nis_is_attributed_inconsistency() {
        // The magnitude baseline is nominal while consistency attributes acoustic.
        let (v, _) = combine(
            &baseline(Verdict::Nominal, &[]),
            decoupled(&[Modality::Acoustic]),
        );
        assert_eq!(
            v,
            FusedVerdict::AttributedInconsistency {
                channels: vec![Modality::Acoustic],
                magnitude: MagnitudeEvidence::InCovariance,
            }
        );
    }

    #[test]
    fn decoupling_with_elevated_nis_is_attributed_inconsistency() {
        let b = baseline(
            Verdict::AttributedInconsistency {
                channels: vec![Modality::Acoustic],
            },
            &[Modality::Acoustic],
        );
        let (v, _) = combine(&b, decoupled(&[Modality::Acoustic]));
        assert_eq!(
            v,
            FusedVerdict::AttributedInconsistency {
                channels: vec![Modality::Acoustic],
                magnitude: MagnitudeEvidence::Elevated,
            }
        );
    }

    #[test]
    fn baseline_broad_degradation_with_intact_consistency_stays_broad() {
        let all = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let (v, _) = combine(
            &baseline(Verdict::BroadDegradation, &all),
            ConsistencyEvidence::Intact,
        );
        assert_eq!(v, FusedVerdict::BroadDegradation);
    }

    #[test]
    fn baseline_attributed_inconsistency_with_intact_consistency_stays_attributed() {
        let b = baseline(
            Verdict::AttributedInconsistency {
                channels: vec![Modality::Radar],
            },
            &[Modality::Radar],
        );
        let (v, _) = combine(&b, ConsistencyEvidence::Intact);
        assert_eq!(
            v,
            FusedVerdict::AttributedInconsistency {
                channels: vec![Modality::Radar],
                magnitude: MagnitudeEvidence::Elevated,
            }
        );
    }

    #[test]
    fn both_insufficient_fails_closed() {
        let (v, _) = combine(
            &baseline(Verdict::InsufficientEvidence, &[]),
            ConsistencyEvidence::Insufficient,
        );
        assert_eq!(v, FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn insufficient_baseline_without_decoupling_fails_closed_not_nominal() {
        // Baseline can't assess magnitude; the consistency check HAS evidence and sees no
        // decoupling. We must NOT upgrade to Nominal (we never verified magnitude) — the
        // fail-closed contract of Verdict::InsufficientEvidence.
        let (v, _) = combine(
            &baseline(Verdict::InsufficientEvidence, &[]),
            ConsistencyEvidence::Intact,
        );
        assert_eq!(v, FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn insufficient_baseline_with_decoupling_still_attributes_inconsistency() {
        // Positive consistency evidence remains attributable when magnitude is unavailable.
        let (v, _) = combine(
            &baseline(Verdict::InsufficientEvidence, &[]),
            decoupled(&[Modality::Acoustic]),
        );
        assert_eq!(
            v,
            FusedVerdict::AttributedInconsistency {
                channels: vec![Modality::Acoustic],
                magnitude: MagnitudeEvidence::Insufficient,
            }
        );
    }

    #[test]
    fn nominal_baseline_cannot_hide_insufficient_consistency_evidence() {
        let (verdict, _) = combine(
            &baseline(Verdict::Nominal, &[]),
            ConsistencyEvidence::Insufficient,
        );
        assert_eq!(verdict, FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn disagreeing_positive_attributions_fail_closed() {
        let baseline = baseline(
            Verdict::AttributedInconsistency {
                channels: vec![Modality::Radar],
            },
            &[Modality::Radar],
        );
        let (verdict, _) = combine(&baseline, decoupled(&[Modality::Acoustic]));
        assert_eq!(
            verdict,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic, Modality::Radar]
            }
        );
    }

    #[test]
    fn broad_degradation_and_partial_consistency_attributions_fail_closed() {
        let all = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let (verdict, _) = combine(
            &baseline(Verdict::BroadDegradation, &all),
            decoupled(&[Modality::Acoustic]),
        );
        assert_eq!(
            verdict,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Visual, Modality::Acoustic, Modality::Radar]
            }
        );
    }

    #[test]
    fn projection_axes_with_different_positive_attributions_conflict() {
        let axis = |axis, modality| {
            AxisCorrelationReport::try_new(
                axis,
                CorrReport::test_fixture(CorrVerdict::Decoupled(vec![modality])),
            )
            .unwrap()
        };
        let (evidence, reason) =
            axis_consistency_evidence(&[axis(0, Modality::Radar), axis(1, Modality::Acoustic)]);

        assert_eq!(
            (evidence, reason),
            (
                ConsistencyEvidence::Conflicted(vec![Modality::Acoustic, Modality::Radar]),
                Some("projection axes positively attribute different channels")
            )
        );
    }

    #[test]
    fn duplicate_axis_labels_fail_closed_before_evidence_fusion() {
        let report = CorrReport::test_fixture(CorrVerdict::Nominal);
        let axes = [
            AxisCorrelationReport::try_new(0, report.clone()).unwrap(),
            AxisCorrelationReport::try_new(0, report).unwrap(),
        ];

        assert_eq!(
            axis_consistency_evidence(&axes),
            (
                ConsistencyEvidence::Conflicted(Vec::new()),
                Some("projection axes must be unique")
            )
        );
    }

    #[test]
    fn axis_constructor_rejects_out_of_range_labels() {
        let report = CorrReport::test_fixture(CorrVerdict::Nominal);

        assert!(
            AxisCorrelationReport::try_new(crate::MAX_CONSISTENCY_PROJECTION_AXES, report,)
                .is_err()
        );
    }

    #[test]
    fn empty_positive_consistency_attribution_is_rejected() {
        assert!(NonEmptyModalities::new(&[]).is_err());
    }

    #[test]
    fn empty_positive_axis_verdict_fails_closed_instead_of_becoming_intact() {
        let axis = AxisCorrelationReport::try_new(
            0,
            CorrReport::test_fixture(CorrVerdict::Decoupled(Vec::new())),
        )
        .unwrap();

        let (evidence, reason) = axis_consistency_evidence(&[axis]);

        assert_eq!(
            (evidence, reason),
            (
                ConsistencyEvidence::Conflicted(Vec::new()),
                Some("a positive projection axis supplied an empty attribution")
            )
        );
    }

    #[test]
    fn source_conflict_fails_closed_without_a_contradictory_boolean_state() {
        let consistency =
            ConsistencyEvidence::conflicted(&[Modality::Radar, Modality::Acoustic]).unwrap();
        let (verdict, _) = combine(&baseline(Verdict::Nominal, &[]), consistency);

        assert_eq!(
            verdict,
            FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic, Modality::Radar]
            }
        );
    }

    proptest! {
        #[test]
        fn conflicted_positive_modalities_are_never_erased(mask in 1_u8..64) {
            let supplied = Modality::ALL
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, modality)| *modality)
                .collect::<Vec<_>>();
            let evidence = ConsistencyEvidence::conflicted(&supplied).unwrap();
            let (verdict, _) = combine(&baseline(Verdict::Nominal, &[]), evidence);
            let FusedVerdict::UnclassifiedAnomaly { channels } = verdict else {
                prop_assert!(false, "conflicted positive evidence was not retained as anomaly");
                return Ok(());
            };
            for modality in supplied {
                prop_assert!(channels.contains(&modality));
            }
        }
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
                stream.push(
                    scalar(1, sequence * 100, sequence, *modality, 3.0, 3)
                        .with_consistency_projection(
                            ConsistencyProjection::try_new(
                                projection_values,
                                3,
                                ProjectionIdentity::try_new(1, 1, sequence + 1).unwrap(),
                            )
                            .unwrap(),
                        ),
                );
            }
        }
        stream
    }

    fn same_shape_different_stream() -> Vec<PidObservation> {
        let mut stream = projected_stream();
        let source = &stream[0];
        let projection = source
            .consistency_projection()
            .expect("projected fixture")
            .clone();
        stream[0] = PidObservation::try_scalar(
            source.track_id(),
            source.timestamp_ms(),
            source.sequence(),
            source.modality(),
            source.nis() + 0.125,
            source.dof(),
        )
        .unwrap()
        .with_consistency_projection(projection);
        stream
    }

    #[test]
    fn default_assessment_checks_all_axes_and_rejects_conflicting_attribution() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let suite = ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap();
        let report = assess_default(&projected_stream(), &suite).unwrap();

        assert_eq!(report.correlations().len(), 3);
        assert_eq!(
            report.baseline().assessment_binding(),
            Some(report.assessment_binding())
        );
        assert!(report
            .correlations()
            .iter()
            .all(|axis| { axis.assessment_binding() == Some(report.assessment_binding()) }));
        assert!(report
            .assessment_binding()
            .verifies(&projected_stream(), &suite));
        assert_eq!(
            report.verdict(),
            &FusedVerdict::UnclassifiedAnomaly {
                channels: vec![Modality::Acoustic, Modality::Radar]
            }
        );
    }

    #[test]
    fn accepted_fusion_rejects_same_shape_components_from_different_observations() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let suite = ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap();
        let stream_a = projected_stream();
        let stream_b = same_shape_different_stream();
        let report_a = assess_default(&stream_a, &suite).unwrap();
        let report_b = assess_default(&stream_b, &suite).unwrap();

        assert_ne!(report_a.assessment_binding(), report_b.assessment_binding());
        assert!(report_a.assessment_binding().verifies(&stream_a, &suite));
        assert!(!report_a.assessment_binding().verifies(&stream_b, &suite));
        assert!(
            combine_correlation_axes(&suite, report_a.baseline(), report_b.correlations(),)
                .is_err()
        );
        assert!(
            combine_correlation_axes(&suite, report_b.baseline(), report_a.correlations(),)
                .is_err()
        );
    }

    #[test]
    fn accepted_fusion_rejects_detector_only_release_suite_substitution() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let suite_a = ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap();
        let mut detector_params = DetectorParams::standalone_advisory_v0_9();
        detector_params.cusum_threshold += 0.25;
        let suite_b = ReleaseSuite::try_new(crate::ReleaseSuiteParams {
            detector: DetectorConfig::try_new(detector_params).unwrap(),
            correlation: suite_a.correlation().clone(),
            expected_modalities: modalities.to_vec(),
            axis_policy: suite_a.axis_policy(),
        })
        .unwrap();
        let stream = projected_stream();
        let report_a = assess_default(&stream, &suite_a).unwrap();
        let report_b = assess_default(&stream, &suite_b).unwrap();

        assert_ne!(suite_a.identity(), suite_b.identity());
        assert_eq!(
            report_a.correlations()[0].config_identity(),
            report_b.correlations()[0].config_identity()
        );
        assert_ne!(report_a.assessment_binding(), report_b.assessment_binding());
        assert!(
            combine_correlation_axes(&suite_b, report_b.baseline(), report_a.correlations(),)
                .is_err()
        );
        assert!(
            combine_correlation_axes(&suite_a, report_a.baseline(), report_b.correlations(),)
                .is_err()
        );
    }

    #[test]
    fn public_correlation_fusion_rejects_mixed_release_suite_provenance() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let suite_a = ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap();
        let mut correlation_params = crate::CorrParams::standalone_advisory_v0_9();
        correlation_params.corr_floor = 0.16;
        let suite_b = ReleaseSuite::try_new(crate::ReleaseSuiteParams {
            detector: suite_a.detector().clone(),
            correlation: crate::CorrConfig::try_new(correlation_params).unwrap(),
            expected_modalities: modalities.to_vec(),
            axis_policy: suite_a.axis_policy(),
        })
        .unwrap();
        let report_a = assess_default(&projected_stream(), &suite_a).unwrap();
        let report_b = assess_default(&projected_stream(), &suite_b).unwrap();

        assert!(
            combine_correlation_axes(&suite_b, report_a.baseline(), report_a.correlations(),)
                .is_err()
        );
        assert!(
            combine_correlation_axes(&suite_a, report_a.baseline(), report_b.correlations(),)
                .is_err()
        );
    }

    #[test]
    fn default_assessment_does_not_fall_back_to_native_innovations() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let stream = projected_stream()
            .iter()
            .map(|observation| {
                scalar_typed(
                    observation.track_id(),
                    observation.timestamp_ms(),
                    observation.sequence(),
                    observation.modality(),
                    observation.nis(),
                    observation.dof(),
                )
                .try_with_research(
                    observation
                        .consistency_projection()
                        .unwrap()
                        .padded_values(),
                    [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let suite = ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap();
        let report = assess_default(&stream, &suite).unwrap();

        assert!(report.correlations().is_empty());
        assert_eq!(report.verdict(), &FusedVerdict::InsufficientEvidence);
    }

    #[test]
    fn default_assessment_requires_an_accepted_correlation_config() {
        let mut params = crate::CorrParams::standalone_advisory_v0_9();
        params.family_alpha = 0.0;

        assert_eq!(
            CorrConfig::try_new(params).unwrap_err(),
            crate::CorrConfigError::FamilyAlphaInvalid
        );
    }
}
