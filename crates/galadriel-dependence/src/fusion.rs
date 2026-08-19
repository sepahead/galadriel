//! Companion dependence assessment beside the unchanged core decision.

use galadriel_core::{
    assess_default, consistency_channels_with_temporal_limits, AssessmentScope, DefaultReport,
    FusedVerdict, Modality, PidObservation, ProjectionContextId, ProjectionFrameId, Sequence,
    TimestampMillis, MAX_CONSISTENCY_PROJECTION_AXES,
};
use serde::Serialize;

use crate::identity::IdentityBuilder;
use crate::{
    analyze, DeclaredMiInput, DependenceAssessmentBinding, DependenceResearchClassification,
    DependenceResearchSuite, DependenceResearchSuiteDigest, MiConsensusReport,
    ProjectionAxisDigest,
};

/// Versioned serialization schema of the complete companion assessment snapshot.
pub const DEPENDENCE_ASSESSMENT_REPORT_SCHEMA: &str = "galadriel.dependence-assessment-report.v3";

/// Whether core preparation supplied a common projection family for the MI companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiAxisFamilyAvailability {
    /// One or more axes were submitted; each axis retains its own graph disposition.
    Produced,
    /// The validated core stream supplied no common projection, so no MI input existed.
    UnavailableNoCommonProjection,
}

/// Producer-side row identity retained for one selected projection tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProjectionRowIdentity {
    sequence: Sequence,
    minimum_timestamp_ms: TimestampMillis,
    maximum_timestamp_ms: TimestampMillis,
}

impl ProjectionRowIdentity {
    pub const fn sequence(self) -> Sequence {
        self.sequence
    }
    pub const fn minimum_timestamp_ms(self) -> TimestampMillis {
        self.minimum_timestamp_ms
    }
    pub const fn maximum_timestamp_ms(self) -> TimestampMillis {
        self.maximum_timestamp_ms
    }
}

/// Self-describing receipt for one producer-attested projection axis.
///
/// The digest binds these fields to the exact core assessment binding. It proves
/// internal byte agreement only; producer authenticity and physical meaning remain
/// external claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectionAxisReceipt {
    digest: ProjectionAxisDigest,
    frame_id: ProjectionFrameId,
    context_id: ProjectionContextId,
    axis: usize,
    axis_count: usize,
    modality_order: Vec<Modality>,
    projection_row_count: usize,
    selected_rows: Vec<ProjectionRowIdentity>,
}

impl ProjectionAxisReceipt {
    #[expect(
        clippy::too_many_arguments,
        reason = "the receipt constructor binds every projection-axis identity coordinate"
    )]
    fn try_new(
        binding: &DependenceAssessmentBinding,
        frame_id: ProjectionFrameId,
        context_id: ProjectionContextId,
        axis: usize,
        axis_count: usize,
        modality_order: Vec<Modality>,
        projection_row_count: usize,
        selected_rows: Vec<ProjectionRowIdentity>,
    ) -> galadriel_core::Result<Self> {
        if !projection_rows_are_admissible(&selected_rows, projection_row_count) {
            return Err(galadriel_core::GaladrielError::InvalidChannels(
                "dependence projection receipt requires a nonempty selected tail with strictly ordered row identities within the extracted row set".into(),
            ));
        }
        let mut identity = IdentityBuilder::new(b"galadriel-projection-axis-receipt-v1");
        identity.bytes(b"assessment", binding.digest().as_bytes());
        identity.u64(b"frame_id", frame_id.get());
        identity.u64(b"context_id", context_id.get());
        identity.usize(b"axis", axis);
        identity.usize(b"axis_count", axis_count);
        identity.usize(b"modality_count", modality_order.len());
        for modality in &modality_order {
            identity.bytes(b"modality", modality.label().as_bytes());
        }
        identity.usize(b"projection_row_count", projection_row_count);
        identity.usize(b"selected_row_count", selected_rows.len());
        for row in &selected_rows {
            identity.u64(b"selected_sequence", row.sequence.get());
            identity.u64(
                b"selected_minimum_timestamp_ms",
                row.minimum_timestamp_ms.get(),
            );
            identity.u64(
                b"selected_maximum_timestamp_ms",
                row.maximum_timestamp_ms.get(),
            );
        }
        Ok(Self {
            digest: ProjectionAxisDigest::from_bytes(identity.finish()),
            frame_id,
            context_id,
            axis,
            axis_count,
            modality_order,
            projection_row_count,
            selected_rows,
        })
    }

    pub const fn digest(&self) -> ProjectionAxisDigest {
        self.digest
    }
    pub const fn frame_id(&self) -> ProjectionFrameId {
        self.frame_id
    }
    pub const fn context_id(&self) -> ProjectionContextId {
        self.context_id
    }
    pub const fn axis(&self) -> usize {
        self.axis
    }
    pub const fn axis_count(&self) -> usize {
        self.axis_count
    }
    pub fn modality_order(&self) -> &[Modality] {
        &self.modality_order
    }
    /// Rows in the full producer-attested suffix before the MI tail selection.
    pub const fn row_count(&self) -> usize {
        self.projection_row_count
    }
    /// Exact ordered row identities used by the inner MI report.
    pub fn selected_rows(&self) -> &[ProjectionRowIdentity] {
        &self.selected_rows
    }
    pub fn first_sequence(&self) -> Option<Sequence> {
        self.selected_rows.first().map(|row| row.sequence)
    }
    pub fn last_sequence(&self) -> Option<Sequence> {
        self.selected_rows.last().map(|row| row.sequence)
    }
    pub fn first_timestamp_ms(&self) -> Option<TimestampMillis> {
        self.selected_rows
            .first()
            .map(|row| row.minimum_timestamp_ms)
    }
    pub fn last_timestamp_ms(&self) -> Option<TimestampMillis> {
        self.selected_rows
            .last()
            .map(|row| row.maximum_timestamp_ms)
    }
}

/// Validate the complete row-identity invariant expected from core extraction.
///
/// Keeping this predicate separate makes every coordinate of the defensive
/// producer-boundary check directly auditable. Core currently constructs these
/// conditions, but the dependence receipt must fail closed if that contract ever
/// drifts rather than minting evidence over ambiguous row alignment.
fn projection_rows_are_admissible(
    selected_rows: &[ProjectionRowIdentity],
    projection_row_count: usize,
) -> bool {
    !selected_rows.is_empty()
        && selected_rows.len() <= projection_row_count
        && selected_rows.windows(2).all(|rows| {
            rows[0].sequence < rows[1].sequence
                && rows[0].minimum_timestamp_ms < rows[1].minimum_timestamp_ms
                && rows[0].maximum_timestamp_ms < rows[1].maximum_timestamp_ms
        })
        && selected_rows
            .iter()
            .all(|row| row.minimum_timestamp_ms <= row.maximum_timestamp_ms)
}

const fn projection_axis_count_is_admissible(axis_count: usize) -> bool {
    axis_count > 0 && axis_count <= MAX_CONSISTENCY_PROJECTION_AXES
}

/// MI-consensus detail for one producer-attested projection axis.
#[derive(Debug, Clone, Serialize)]
pub struct AxisMiConsensusReport {
    axis: usize,
    projection_receipt: ProjectionAxisReceipt,
    report: MiConsensusReport,
    assessment_binding: DependenceAssessmentBinding,
}

impl AxisMiConsensusReport {
    pub const fn axis(&self) -> usize {
        self.axis
    }
    pub const fn report(&self) -> &MiConsensusReport {
        &self.report
    }
    pub const fn projection_receipt(&self) -> &ProjectionAxisReceipt {
        &self.projection_receipt
    }
    pub const fn assessment_binding(&self) -> &DependenceAssessmentBinding {
        &self.assessment_binding
    }
}

/// Sealed report that keeps exploratory MI evidence beside the authoritative core report.
///
/// The MI companion cannot alter [`DefaultReport::verdict`]. This type contains no
/// fusion function and no alternate accepted verdict.
#[derive(Debug, Clone, Serialize)]
pub struct DependenceAssessmentReport {
    schema: &'static str,
    default: DefaultReport,
    mi_axes: Vec<AxisMiConsensusReport>,
    suite_identity: DependenceResearchSuiteDigest,
    classification: DependenceResearchClassification,
    assessment_binding: DependenceAssessmentBinding,
    mi_axis_family_availability: MiAxisFamilyAvailability,
    note: String,
}

impl DependenceAssessmentReport {
    /// Serialization schema of this immutable assessment snapshot.
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    /// Authoritative default NIS/CUSUM-magnitude plus signed-correlation assessment.
    pub const fn default_report(&self) -> &DefaultReport {
        &self.default
    }

    /// The unchanged authoritative core verdict.
    pub const fn authoritative_verdict(&self) -> &FusedVerdict {
        self.default.verdict()
    }

    /// Exploratory MI-consensus companions in producer-axis order.
    pub fn mi_axes(&self) -> &[AxisMiConsensusReport] {
        &self.mi_axes
    }

    pub const fn suite_identity(&self) -> DependenceResearchSuiteDigest {
        self.suite_identity
    }

    pub const fn classification(&self) -> DependenceResearchClassification {
        self.classification
    }

    pub const fn assessment_binding(&self) -> &DependenceAssessmentBinding {
        &self.assessment_binding
    }

    /// Typed top-level availability of the projection family requested by the companion.
    pub const fn mi_axis_family_availability(&self) -> MiAxisFamilyAvailability {
        self.mi_axis_family_availability
    }

    pub const fn assessment_scope(&self) -> &AssessmentScope {
        self.default.assessment_scope()
    }

    pub fn note(&self) -> &str {
        &self.note
    }
}

/// Run the unchanged core assessment and attach exploratory MI graph reports.
///
/// The scope is declared provenance, not producer authentication. Core validates
/// the exact stream/scope relationship and mints the nested assessment binding.
/// Galadriel then computes each MI report from the same validated common
/// projection. No MI disposition enters the authoritative core decision.
pub fn assess_with_dependence(
    scope: &AssessmentScope,
    stream: &[PidObservation],
    suite: &DependenceResearchSuite,
) -> galadriel_core::Result<DependenceAssessmentReport> {
    let release_suite = suite.release_suite();
    let default = assess_default(scope, stream, release_suite)?;
    let binding = DependenceAssessmentBinding::new(default.assessment_binding(), suite.identity());
    let detector = release_suite.detector();
    let projection = consistency_channels_with_temporal_limits(
        stream,
        release_suite.expected_modalities(),
        detector.max_seq_gap(),
        detector.max_timestamp_skew_ms(),
        detector.max_inter_sample_gap_ms(),
    )?;
    let mut mi_axes = Vec::new();
    let mi_axis_family_availability;
    if let Some(projection) = projection {
        if !projection_axis_count_is_admissible(projection.axes.len()) {
            return Err(galadriel_core::GaladrielError::InvalidChannels(format!(
                "dependence projection family has {} axes; expected 1..={MAX_CONSISTENCY_PROJECTION_AXES}",
                projection.axes.len()
            )));
        }
        let axis_count = projection.axes.len();
        if projection.row_sequences.len() != projection.row_timestamp_bounds.len() {
            return Err(galadriel_core::GaladrielError::InvalidChannels(
                "dependence projection row identity vectors disagree".into(),
            ));
        }
        let projection_row_count = projection.row_sequences.len();
        let selected_start =
            projection_row_count.saturating_sub(suite.mi_consensus_config().window());
        let selected_rows = projection.row_sequences[selected_start..]
            .iter()
            .copied()
            .zip(
                projection.row_timestamp_bounds[selected_start..]
                    .iter()
                    .copied(),
            )
            .map(
                |(sequence, (minimum_timestamp_ms, maximum_timestamp_ms))| ProjectionRowIdentity {
                    sequence,
                    minimum_timestamp_ms,
                    maximum_timestamp_ms,
                },
            )
            .collect::<Vec<_>>();
        for (axis, channels) in projection.axes.into_iter().enumerate() {
            let modality_order = channels
                .iter()
                .map(|(modality, _)| *modality)
                .collect::<Vec<_>>();
            let row_count = channels.first().map_or(0, |(_, values)| values.len());
            if row_count != projection_row_count {
                return Err(galadriel_core::GaladrielError::InvalidChannels(
                    "dependence projection values and row identities disagree".into(),
                ));
            }
            let projection_receipt = ProjectionAxisReceipt::try_new(
                &binding,
                projection.frame_id,
                projection.context_id,
                axis,
                axis_count,
                modality_order,
                row_count,
                selected_rows.clone(),
            )?;
            let input =
                DeclaredMiInput::from_core_projection(channels, default.assessment_binding())?;
            mi_axes.push(AxisMiConsensusReport {
                axis,
                projection_receipt,
                report: analyze(&input, suite.mi_consensus_config())?,
                assessment_binding: binding.clone(),
            });
        }
        mi_axis_family_availability = MiAxisFamilyAvailability::Produced;
    } else {
        mi_axis_family_availability = MiAxisFamilyAvailability::UnavailableNoCommonProjection;
    }
    Ok(DependenceAssessmentReport {
        schema: DEPENDENCE_ASSESSMENT_REPORT_SCHEMA,
        default,
        mi_axes,
        suite_identity: suite.identity(),
        classification: suite.classification(),
        assessment_binding: binding,
        mi_axis_family_availability,
        note: match mi_axis_family_availability {
            MiAxisFamilyAvailability::Produced => "MI-consensus reports are uncalibrated companion evidence and cannot alter the authoritative core verdict",
            MiAxisFamilyAvailability::UnavailableNoCommonProjection => "MI companion unavailable because the validated stream supplied no common projection; the authoritative core verdict remains unchanged",
        }.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContinuousLawDeclaration;
    use galadriel_core::{ConsistencyProjection, Modality};
    use galadriel_sim::scenario::{generate, ScenarioResearchProfile};

    const MODALITIES: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

    fn law() -> ContinuousLawDeclaration {
        ContinuousLawDeclaration::try_iid(
            "The simulator declares nonsingular jointly Gaussian bivariate populations with finite mutual information.",
            "Binary64 sample representation of pseudorandom draws intended from the declared continuous law; no deliberate quantization, added noise, or tie-breaking transform; exact ties abstain.",
            "Rows are independent within one generated scenario episode.",
            "All simulator projection coordinates use the same fixed innovation unit and identity gauge; no sample-fitted rescaling is applied.",
        )
        .unwrap()
    }

    fn projection_row(
        sequence: u64,
        minimum_timestamp_ms: u64,
        maximum_timestamp_ms: u64,
    ) -> ProjectionRowIdentity {
        ProjectionRowIdentity {
            sequence: Sequence::new(sequence).unwrap(),
            minimum_timestamp_ms: TimestampMillis::new(minimum_timestamp_ms).unwrap(),
            maximum_timestamp_ms: TimestampMillis::new(maximum_timestamp_ms).unwrap(),
        }
    }

    #[test]
    fn projection_receipt_row_and_axis_boundaries_are_exact() {
        let valid = [projection_row(7, 100, 102), projection_row(8, 110, 112)];
        assert!(projection_rows_are_admissible(&valid, valid.len()));
        assert!(projection_rows_are_admissible(
            &[projection_row(7, 100, 100)],
            1
        ));
        assert!(!projection_rows_are_admissible(&[], valid.len()));
        assert!(!projection_rows_are_admissible(&valid, valid.len() - 1));

        let isolated_failures = [
            [valid[0], projection_row(7, 110, 112)],
            [valid[0], projection_row(8, 100, 112)],
            [valid[0], projection_row(8, 101, 102)],
            [valid[0], projection_row(8, 113, 112)],
        ];
        for rows in isolated_failures {
            assert!(!projection_rows_are_admissible(&rows, rows.len()));
        }

        assert!(!projection_axis_count_is_admissible(0));
        assert!(projection_axis_count_is_admissible(1));
        assert!(projection_axis_count_is_admissible(
            MAX_CONSISTENCY_PROJECTION_AXES
        ));
        assert!(!projection_axis_count_is_admissible(
            MAX_CONSISTENCY_PROJECTION_AXES + 1
        ));
    }

    #[test]
    fn companion_report_preserves_the_exact_authoritative_default_verdict() {
        let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
        params.frames = 300;
        params.rho = 0.7;
        let scenario = galadriel_sim::scenario::ScenarioConfig::try_new(params).unwrap();
        let stream = generate(&scenario).unwrap();
        let scope = scenario.assessment_scope("dependence-test").unwrap();
        let suite = DependenceResearchSuite::point_estimate_only_v0_9(&MODALITIES, law()).unwrap();
        let expected = assess_default(&scope, &stream, suite.release_suite()).unwrap();
        let observed = assess_with_dependence(&scope, &stream, &suite).unwrap();

        assert_eq!(observed.authoritative_verdict(), expected.verdict());
        assert_eq!(
            observed.default_report().assessment_binding(),
            expected.assessment_binding()
        );
        assert_eq!(observed.mi_axes().len(), 3);
        for (axis, report) in observed.mi_axes().iter().enumerate() {
            assert_eq!(report.axis(), axis);
            assert_eq!(report.projection_receipt().axis(), axis);
            assert_eq!(report.projection_receipt().axis_count(), 3);
            assert_eq!(
                report.projection_receipt().modality_order(),
                suite.release_suite().expected_modalities()
            );
            assert_eq!(report.projection_receipt().row_count(), 300);
            assert_eq!(report.projection_receipt().selected_rows().len(), 128);
            assert_eq!(
                report.projection_receipt().selected_rows().len(),
                report.report().row_set().rows_per_channel()
            );
            assert_eq!(
                report
                    .projection_receipt()
                    .first_sequence()
                    .map(Sequence::get),
                Some(172)
            );
            assert_eq!(
                report
                    .projection_receipt()
                    .last_sequence()
                    .map(Sequence::get),
                Some(299)
            );
            assert_eq!(report.projection_receipt().frame_id().get(), 1);
            assert_eq!(report.projection_receipt().context_id().get(), 1);
            assert_eq!(
                report
                    .projection_receipt()
                    .first_timestamp_ms()
                    .map(TimestampMillis::get),
                Some(17_200)
            );
            assert_eq!(
                report
                    .projection_receipt()
                    .last_timestamp_ms()
                    .map(TimestampMillis::get),
                Some(29_900)
            );
        }
        assert!(observed
            .assessment_binding()
            .verifies(&scope, &stream, &suite));
        assert!(!observed.assessment_binding().verifies(
            &scope,
            &stream[..stream.len() - 1],
            &suite
        ));
        assert!(observed
            .mi_axes()
            .iter()
            .all(|axis| axis.assessment_binding() == observed.assessment_binding()));
        assert!(observed.note().contains("cannot alter"));
        assert_eq!(observed.schema(), DEPENDENCE_ASSESSMENT_REPORT_SCHEMA);
        assert_eq!(
            observed.schema(),
            "galadriel.dependence-assessment-report.v3"
        );
        let serialized = serde_json::to_value(&observed)
            .expect("complete companion assessment must serialize as one evidence snapshot");
        assert_eq!(
            serialized["schema"].as_str(),
            Some(DEPENDENCE_ASSESSMENT_REPORT_SCHEMA)
        );
        assert_eq!(
            serialized["assessment_binding"]["digest"]
                .as_str()
                .map(str::len),
            Some(64)
        );
    }

    #[test]
    fn one_axis_projection_is_a_valid_bounded_companion_family() {
        let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
        params.frames = 300;
        let scenario = galadriel_sim::scenario::ScenarioConfig::try_new(params).unwrap();
        let mut stream = generate(&scenario).unwrap();
        for observation in &mut stream {
            let projection = observation
                .consistency_projection()
                .expect("synthetic profile supplies a common projection");
            let one_axis = ConsistencyProjection::try_new(
                [projection.values()[0], 0.0, 0.0],
                1,
                projection.identity(),
            )
            .unwrap();
            *observation = observation.clone().with_consistency_projection(one_axis);
        }
        let scope = scenario
            .assessment_scope("dependence-one-axis-projection")
            .unwrap();
        let suite = DependenceResearchSuite::point_estimate_only_v0_9(&MODALITIES, law()).unwrap();
        let report = assess_with_dependence(&scope, &stream, &suite).unwrap();
        assert_eq!(report.mi_axes().len(), 1);
        assert_eq!(report.mi_axes()[0].axis(), 0);
        assert_eq!(report.mi_axes()[0].projection_receipt().axis_count(), 1);
        assert_eq!(
            report.mi_axis_family_availability(),
            MiAxisFamilyAvailability::Produced
        );
    }

    #[test]
    fn missing_common_projection_yields_no_mi_companion_and_does_not_fabricate_one() {
        let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
        params.frames = 300;
        let scenario = galadriel_sim::scenario::ScenarioConfig::try_new(params).unwrap();
        let mut stream = generate(&scenario).unwrap();
        for observation in &mut stream {
            let replacement = PidObservation::try_scalar(
                observation.track_id(),
                observation.timestamp_ms(),
                observation.sequence(),
                observation.modality(),
                observation.nis(),
                observation.dof(),
            )
            .unwrap();
            *observation = replacement;
        }
        let scope = scenario
            .assessment_scope("dependence-no-projection")
            .unwrap();
        let suite = DependenceResearchSuite::point_estimate_only_v0_9(&MODALITIES, law()).unwrap();
        let report = assess_with_dependence(&scope, &stream, &suite).unwrap();
        assert!(report.mi_axes().is_empty());
        assert_eq!(
            report.mi_axis_family_availability(),
            MiAxisFamilyAvailability::UnavailableNoCommonProjection
        );
        assert!(report.note().contains("no common projection"));
    }
}
