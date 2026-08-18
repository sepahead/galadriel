#![forbid(unsafe_code)]
//! **Is PID / mutual information actually justified over cheap Pearson correlation?**
//!
//! This is an "earn your complexity" test. For a *jointly-Gaussian, linearly* coupled
//! population, true mutual information is a monotone function of `|ρ|`
//! (`MI = −½ ln(1 − ρ²)`), so it contains no additional population dependence
//! parameter. Finite-sample Pearson and KSG estimators need not have identical ROCs.
//!
//! MI can earn its place where the dependence is **nonlinear**: there `|ρ| ≈ 0`
//! even though the variables are strongly dependent, so a linear correlation score can
//! be weak while a nonparametric dependence score retains signal. This study measures both
//! detectors' ROC-AUC at separating a *coupled* pair from a *decoupled* one (a
//! permutation null), under a **linear**
//! coupling (`Y = X + ε`) and a **nonlinear** one (`Y = ±X + ε`, random sign — for
//! which the *population* `corr(X, Y) = 0`, though the sample correlation has an
//! inflated variance from the kurtosis of `X`, so a `|ρ|` check can still score above
//! chance through that finite-sample artifact).
//!
//! The results are simulation evidence for a narrower statement: **KSG MI is a
//! nonparametric dependence score** and may detect structure that Pearson correlation
//! does not. It still relies on metric, neighbourhood, and tuning choices. The results
//! are not a calibration, a field-performance guarantee, or proof that PID is necessary.
//! The PID atoms reported below are offline diagnostic study outputs. Galadriel's
//! optional in-process/library companion is a separate pairwise-MI graph. It is not PID and
//! therefore cannot detect pure synergy by itself.

pub mod crebain_mgw;

use galadriel_core::{correlation::pearson, GaladrielError};
use pid_core::{
    experimental::continuous::{
        pid2_isx_report_with_budget, Pid2Config, Pid2Provenance, Pid2Report,
    },
    software_identity,
    stable::continuous::{ksg_mi_report_with_budget, KsgConfig, KsgProvenance},
    DiscreteMatOwned, MatOwned, ResourceBudget, SoftwareIdentity, SourceIdentity, WorkingTreeScope,
    WorkingTreeState,
};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use rand_distr::{Distribution, Normal};
use serde::Serialize;
use thiserror::Error;

/// Typed failure from the offline justification studies.
///
/// Galadriel contract/configuration failures and pid-core evaluator failures
/// remain distinct, and the original typed error is retained as the source.
#[derive(Debug, Error)]
pub enum JustificationError {
    #[error("Galadriel study contract failed: {0}")]
    Galadriel(#[from] GaladrielError),
    #[error("pid-core evaluator failed: {0}")]
    PidCore(#[from] pid_core::PidError),
    #[error("pid-core execution identity contract failed: {0}")]
    PidCoreIdentity(String),
}

/// Result type for offline justification studies.
pub type Result<T> = std::result::Result<T, JustificationError>;

/// Exact pid-rs package version selected by the workspace manifest.
pub const PID_RS_VERSION: &str = "0.9.0";
/// Immutable pid-rs revision selected by the workspace manifest.
pub const PID_RS_REVISION: &str = "bc3aa80fb6025e709c2906a08bce25a4fac40578";
/// Repository supplying the selected pid-core package.
pub const PID_RS_GIT_REPOSITORY: &str = "https://github.com/sepahead/pid-rs";
/// Versioned serialization schema of an offline PID estimand question.
pub const PID_QUESTION_SCHEMA: &str = "galadriel.pid-question.v3";
/// Versioned serialization schema of the categorical XOR study result.
pub const CATEGORICAL_PID_STUDY_SCHEMA: &str = "galadriel.categorical-pid-study.v3";
/// Versioned serialization schema of the continuous sign-parity study result.
pub const CONTINUOUS_PID_STUDY_SCHEMA: &str = "galadriel.continuous-pid-study.v3";
/// Versioned serialization schema of the comparator/composition layer around a PID question.
pub const JUSTIFICATION_STUDY_PROTOCOL_SCHEMA: &str = "galadriel.justification-study-protocol.v2";

const PID_STUDY_RESOURCE_MAX_BYTES: u64 = 1 << 30;
const PID_STUDY_RESOURCE_MAX_PAIRWISE_DISTANCES: u64 = 1_200_000_000;
const PID_STUDY_RESOURCE_MAX_OPERATIONS_HINT: u128 = 10_000_000_000;
const PID_STUDY_RESOURCE_MAX_THREADS: usize = 1;

const AUC_BOOTSTRAP_SEED_XOR: u64 = 0x5EED_B007;

/// Exact root-seed relation for one serialized AUC interval row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AucIntervalSeedRelation {
    auc_field: &'static str,
    root_seed_wrapping_add: u64,
}

impl AucIntervalSeedRelation {
    pub const fn auc_field(self) -> &'static str {
        self.auc_field
    }

    pub const fn root_seed_wrapping_add(self) -> u64 {
        self.root_seed_wrapping_add
    }
}

const CATEGORICAL_AUC_SEED_RELATIONS: [AucIntervalSeedRelation; 4] = [
    AucIntervalSeedRelation {
        auc_field: "corr_auc",
        root_seed_wrapping_add: 1,
    },
    AucIntervalSeedRelation {
        auc_field: "pairwise_mi_auc",
        root_seed_wrapping_add: 2,
    },
    AucIntervalSeedRelation {
        auc_field: "q_auc",
        root_seed_wrapping_add: 3,
    },
    AucIntervalSeedRelation {
        auc_field: "sxpid_syn_auc",
        root_seed_wrapping_add: 4,
    },
];

const CONTINUOUS_AUC_SEED_RELATIONS: [AucIntervalSeedRelation; 4] = [
    AucIntervalSeedRelation {
        auc_field: "corr_auc",
        root_seed_wrapping_add: 11,
    },
    AucIntervalSeedRelation {
        auc_field: "pairwise_mi_auc",
        root_seed_wrapping_add: 12,
    },
    AucIntervalSeedRelation {
        auc_field: "q_auc",
        root_seed_wrapping_add: 13,
    },
    AucIntervalSeedRelation {
        auc_field: "isx_syn_auc",
        root_seed_wrapping_add: 14,
    },
];

/// Typed identities for the non-PID comparator and composition rows in one study.
///
/// A [`PidQuestionSpec`] defines only the named PID functional/evaluator rows.
/// This sibling record prevents Pearson, mutual-information, and the project-defined
/// joint contrast `Q` from inheriting that PID identity by proximity in one JSON object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JustificationStudyProtocol {
    schema: &'static str,
    correlation_score_id: &'static str,
    correlation_score_origin: &'static str,
    pairwise_mi_score_id: &'static str,
    pairwise_mi_score_origin: &'static str,
    q_score_id: &'static str,
    q_formula: &'static str,
    q_score_origin: &'static str,
    pid_question_scope: &'static str,
    control_relation: &'static str,
    sampling_unit: &'static str,
    auc_interval_procedure_id: &'static str,
    auc_interval_resamples: usize,
    auc_interval_scope: &'static str,
    multiplicity_relation: &'static str,
    non_pid_aggregate_outputs: &'static [StudyAggregateOutputSpec],
    rng_implementation: &'static str,
    generation_stream_relation: &'static str,
    generation_seed_xor: u64,
    bootstrap_paired_index_algorithm: &'static str,
    bootstrap_seed_xor: u64,
    bootstrap_quantile_algorithm: &'static str,
    auc_interval_seed_relations: &'static [AucIntervalSeedRelation],
}

impl JustificationStudyProtocol {
    fn categorical_xor() -> Self {
        Self {
            schema: JUSTIFICATION_STUDY_PROTOCOL_SCHEMA,
            correlation_score_id: "galadriel.comparator.max-absolute-pearson-pairwise.v1",
            correlation_score_origin: "project-defined comparator composition of the standard Pearson product-moment statistic",
            pairwise_mi_score_id: "galadriel.comparator.max-categorical-plugin-mi-pairwise.v1",
            pairwise_mi_score_origin: "project-defined max composition of the two Shannon MI terms retained by the same pid-core discrete_sxpid2 result",
            q_score_id: "galadriel.composition.joint-information-contrast-q.v1",
            q_formula: "I(S1,S2;T) - max(I(S1;T), I(S2;T))",
            q_score_origin: "project-defined composition of MI terms retained by the same pid-core discrete_sxpid2 result; Q is not a PID atom",
            pid_question_scope: "PidQuestionSpec governs only pid_trials and sxpid_* fields; it does not identify Pearson, pairwise-MI, or Q as PID",
            control_relation: "finite-sample without-replacement target permutation; exchangeable conditional on generated rows, not an independent-law sample",
            sampling_unit: "one independently generated coupled trial plus its within-trial target-permutation control",
            auc_interval_procedure_id: "galadriel.paired-trial-percentile-bootstrap-auc.v1",
            auc_interval_resamples: N_BOOT,
            auc_interval_scope: "separate 95% percentile interval for each AUC; not an interval for an AUC difference",
            multiplicity_relation: "descriptive study rows; no familywise or false-discovery guarantee",
            non_pid_aggregate_outputs: &CATEGORICAL_NON_PID_AGGREGATE_OUTPUTS,
            rng_implementation: "rand 0.8 StdRng::seed_from_u64 plus rand_distr 0.4 APIs; exact resolved crate bytes and Galadriel source revision are not bound by this result and require a publication-bundle lock/source identity",
            generation_stream_relation: "one StdRng stream seeded by root_seed XOR generation_seed_xor; rows and within-trial without-replacement target permutations are drawn sequentially in trial-index order",
            generation_seed_xor: 0x5259_6E65,
            bootstrap_paired_index_algorithm: "for each bootstrap replicate and output position, draw one uniform index from 0..trials and use that same index for coupled and permutation-control scores",
            bootstrap_seed_xor: AUC_BOOTSTRAP_SEED_XOR,
            bootstrap_quantile_algorithm: "sort AUC replicates by f64::total_cmp; select round(q*(B-1)) at q=0.025 and q=0.975",
            auc_interval_seed_relations: &CATEGORICAL_AUC_SEED_RELATIONS,
        }
    }

    fn continuous_sign_parity() -> Self {
        Self {
            schema: JUSTIFICATION_STUDY_PROTOCOL_SCHEMA,
            correlation_score_id: "galadriel.comparator.max-absolute-pearson-pairwise.v1",
            correlation_score_origin: "project-defined comparator composition of the standard Pearson product-moment statistic",
            pairwise_mi_score_id: "galadriel.comparator.max-ksg-mi-pairwise.v1",
            pairwise_mi_score_origin: "project-defined max composition of the two KSG MI reports retained inside the same pid-core PID2 report",
            q_score_id: "galadriel.composition.joint-information-contrast-q.v1",
            q_formula: "I(S1,S2;T) - max(I(S1;T), I(S2;T))",
            q_score_origin: "project-defined composition of KSG MI terms retained inside the same pid-core PID2 report; Q is not a PID atom",
            pid_question_scope: "PidQuestionSpec governs only pid_trials and isx_syn_* fields; it does not identify Pearson, pairwise-MI, or Q as PID",
            control_relation: "finite-sample without-replacement target permutation; exchangeable conditional on generated rows, not an independent-law sample",
            sampling_unit: "one independently generated coupled trial plus its within-trial target-permutation control",
            auc_interval_procedure_id: "galadriel.paired-trial-percentile-bootstrap-auc.v1",
            auc_interval_resamples: N_BOOT,
            auc_interval_scope: "separate 95% percentile interval for each AUC; not an interval for an AUC difference",
            multiplicity_relation: "descriptive study rows; no familywise or false-discovery guarantee",
            non_pid_aggregate_outputs: &CONTINUOUS_NON_PID_AGGREGATE_OUTPUTS,
            rng_implementation: "rand 0.8 StdRng::seed_from_u64 plus rand_distr 0.4 APIs; exact resolved crate bytes and Galadriel source revision are not bound by this result and require a publication-bundle lock/source identity",
            generation_stream_relation: "one StdRng stream seeded by root_seed XOR generation_seed_xor; rows and within-trial without-replacement target permutations are drawn sequentially in trial-index order",
            generation_seed_xor: 0x516E_9A21,
            bootstrap_paired_index_algorithm: "for each bootstrap replicate and output position, draw one uniform index from 0..trials and use that same index for coupled and permutation-control scores",
            bootstrap_seed_xor: AUC_BOOTSTRAP_SEED_XOR,
            bootstrap_quantile_algorithm: "sort AUC replicates by f64::total_cmp; select round(q*(B-1)) at q=0.025 and q=0.975",
            auc_interval_seed_relations: &CONTINUOUS_AUC_SEED_RELATIONS,
        }
    }

    pub const fn schema(&self) -> &'static str {
        self.schema
    }
    pub const fn correlation_score_id(&self) -> &'static str {
        self.correlation_score_id
    }
    pub const fn correlation_score_origin(&self) -> &'static str {
        self.correlation_score_origin
    }
    pub const fn pairwise_mi_score_id(&self) -> &'static str {
        self.pairwise_mi_score_id
    }
    pub const fn pairwise_mi_score_origin(&self) -> &'static str {
        self.pairwise_mi_score_origin
    }
    pub const fn q_score_id(&self) -> &'static str {
        self.q_score_id
    }
    pub const fn q_formula(&self) -> &'static str {
        self.q_formula
    }
    pub const fn q_score_origin(&self) -> &'static str {
        self.q_score_origin
    }
    pub const fn pid_question_scope(&self) -> &'static str {
        self.pid_question_scope
    }
    pub const fn control_relation(&self) -> &'static str {
        self.control_relation
    }
    pub const fn sampling_unit(&self) -> &'static str {
        self.sampling_unit
    }
    pub const fn auc_interval_procedure_id(&self) -> &'static str {
        self.auc_interval_procedure_id
    }
    pub const fn auc_interval_resamples(&self) -> usize {
        self.auc_interval_resamples
    }
    pub const fn auc_interval_scope(&self) -> &'static str {
        self.auc_interval_scope
    }
    pub const fn multiplicity_relation(&self) -> &'static str {
        self.multiplicity_relation
    }
    pub const fn non_pid_aggregate_outputs(&self) -> &'static [StudyAggregateOutputSpec] {
        self.non_pid_aggregate_outputs
    }
    pub const fn rng_implementation(&self) -> &'static str {
        self.rng_implementation
    }
    pub const fn generation_stream_relation(&self) -> &'static str {
        self.generation_stream_relation
    }
    pub const fn generation_seed_xor(&self) -> u64 {
        self.generation_seed_xor
    }
    pub const fn bootstrap_paired_index_algorithm(&self) -> &'static str {
        self.bootstrap_paired_index_algorithm
    }
    pub const fn bootstrap_seed_xor(&self) -> u64 {
        self.bootstrap_seed_xor
    }
    pub const fn bootstrap_quantile_algorithm(&self) -> &'static str {
        self.bootstrap_quantile_algorithm
    }
    pub const fn auc_interval_seed_relations(&self) -> &'static [AucIntervalSeedRelation] {
        self.auc_interval_seed_relations
    }
}

/// Scientific role of one directed reference edge in a PID question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidReferenceRole {
    /// Defines the functional evaluated by this route.
    FunctionalDefinition,
    /// Originally defines the Williams--Beer antichain redundancy lattice used by the route.
    OriginalAntichainLatticeDefinition,
    /// Gives the part-whole/formal-logic derivation used to interpret the lattice.
    PartWholeLogicalDerivation,
    /// Defines the paper-specific estimator used by the route.
    EstimatorDefinition,
    /// Defines a sample estimator composed by the route.
    EstimatorImplementationBasis,
    /// Related construction that this exact route explicitly does not evaluate.
    RelatedConstructionNotEvaluated,
}

/// One immutable, role-distinct primary-literature edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidReferenceEdge {
    roles: &'static [PidReferenceRole],
    reference_id: &'static str,
    title: &'static str,
    complete_team: &'static str,
    locator: &'static str,
}

impl PidReferenceEdge {
    pub const fn roles(self) -> &'static [PidReferenceRole] {
        self.roles
    }
    pub const fn reference_id(self) -> &'static str {
        self.reference_id
    }
    pub const fn title(self) -> &'static str {
        self.title
    }
    pub const fn complete_team(self) -> &'static str {
        self.complete_team
    }
    pub const fn locator(self) -> &'static str {
        self.locator
    }
}

const ROLE_FUNCTIONAL: [PidReferenceRole; 1] = [PidReferenceRole::FunctionalDefinition];
const ROLE_PART_WHOLE: [PidReferenceRole; 1] = [PidReferenceRole::PartWholeLogicalDerivation];
const ROLE_ESTIMATOR_BASIS: [PidReferenceRole; 1] =
    [PidReferenceRole::EstimatorImplementationBasis];
const ROLE_FUNCTIONAL_AND_ESTIMATOR: [PidReferenceRole; 2] = [
    PidReferenceRole::FunctionalDefinition,
    PidReferenceRole::EstimatorDefinition,
];
const ROLE_NOT_EVALUATED: [PidReferenceRole; 1] =
    [PidReferenceRole::RelatedConstructionNotEvaluated];
const ROLE_ORIGINAL_LATTICE_NOT_FUNCTIONAL: [PidReferenceRole; 2] = [
    PidReferenceRole::OriginalAntichainLatticeDefinition,
    PidReferenceRole::RelatedConstructionNotEvaluated,
];

const CATEGORICAL_REFERENCE_EDGES: [PidReferenceEdge; 4] = [
    PidReferenceEdge {
        roles: &ROLE_FUNCTIONAL,
        reference_id: "makkeh-2021",
        title: "Introducing a Differentiable Measure of Pointwise Shared Information",
        complete_team: "Abdullah Makkeh; Aaron J. Gutknecht; Michael Wibral",
        locator: "https://doi.org/10.1103/PhysRevE.103.032149",
    },
    PidReferenceEdge {
        roles: &ROLE_ORIGINAL_LATTICE_NOT_FUNCTIONAL,
        reference_id: "williams-beer-2010",
        title: "Nonnegative Decomposition of Multivariate Information",
        complete_team: "Paul L. Williams; Randall D. Beer",
        locator: "https://arxiv.org/abs/1004.2515",
    },
    PidReferenceEdge {
        roles: &ROLE_PART_WHOLE,
        reference_id: "gutknecht-2021",
        title: "Bits and Pieces: Understanding Information Decomposition from Part-Whole Relationships and Formal Logic",
        complete_team: "Aaron J. Gutknecht; Michael Wibral; Abdullah Makkeh",
        locator: "https://doi.org/10.1098/rspa.2021.0110",
    },
    PidReferenceEdge {
        roles: &ROLE_NOT_EVALUATED,
        reference_id: "schick-poland-2021",
        title: "A Partial Information Decomposition for Discrete and Continuous Variables",
        complete_team: "Kyle Schick-Poland; Abdullah Makkeh; Aaron J. Gutknecht; Patricia Wollstadt; Anja Sturm; Michael Wibral",
        locator: "https://arxiv.org/abs/2106.12393",
    },
];

const CONTINUOUS_REFERENCE_EDGES: [PidReferenceEdge; 4] = [
    PidReferenceEdge {
        roles: &ROLE_FUNCTIONAL_AND_ESTIMATOR,
        reference_id: "ehrlich-2024",
        title: "Partial Information Decomposition for Continuous Variables Based on Shared Exclusions: Analytical Formulation and Estimation",
        complete_team: "David A. Ehrlich; Kyle Schick-Poland; Abdullah Makkeh; Felix Lanfermann; Patricia Wollstadt; Michael Wibral",
        locator: "https://doi.org/10.1103/PhysRevE.110.014115",
    },
    PidReferenceEdge {
        roles: &ROLE_ORIGINAL_LATTICE_NOT_FUNCTIONAL,
        reference_id: "williams-beer-2010",
        title: "Nonnegative Decomposition of Multivariate Information",
        complete_team: "Paul L. Williams; Randall D. Beer",
        locator: "https://arxiv.org/abs/1004.2515",
    },
    PidReferenceEdge {
        roles: &ROLE_ESTIMATOR_BASIS,
        reference_id: "kraskov-2004",
        title: "Estimating Mutual Information",
        complete_team: "Alexander Kraskov; Harald Stögbauer; Peter Grassberger",
        locator: "https://doi.org/10.1103/PhysRevE.69.066138",
    },
    PidReferenceEdge {
        roles: &ROLE_NOT_EVALUATED,
        reference_id: "schick-poland-2021",
        title: "A Partial Information Decomposition for Discrete and Continuous Variables",
        complete_team: "Kyle Schick-Poland; Abdullah Makkeh; Aaron J. Gutknecht; Patricia Wollstadt; Anja Sturm; Michael Wibral",
        locator: "https://arxiv.org/abs/2106.12393",
    },
];

/// Paper-defined shared-exclusions functional named by an offline PID question.
///
/// These variants are related members of one research lineage. They are not
/// aliases and their numeric outputs are not presumed interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidFunctionalIdentity {
    /// Categorical pointwise shared exclusions of Makkeh, Gutknecht, and Wibral.
    MakkehGutknechtWibralCategorical,
    /// Purely continuous construction of Ehrlich, Schick-Poland, Makkeh,
    /// Lanfermann, Wollstadt, and Wibral.
    EhrlichSchickPolandMakkehLanfermannWollstadtWibralContinuous,
}

impl PidFunctionalIdentity {
    /// Galadriel semantic identity for the paper-defined functional.
    pub const fn semantic_id(self) -> &'static str {
        match self {
            Self::MakkehGutknechtWibralCategorical => {
                "functional.shared-exclusions.mgw-categorical"
            }
            Self::EhrlichSchickPolandMakkehLanfermannWollstadtWibralContinuous => {
                "functional.shared-exclusions.ehrlich-continuous"
            }
        }
    }

    /// Complete defining team used by the study report.
    pub const fn defining_team(self) -> &'static str {
        match self {
            Self::MakkehGutknechtWibralCategorical => {
                "Abdullah Makkeh; Aaron J. Gutknecht; Michael Wibral"
            }
            Self::EhrlichSchickPolandMakkehLanfermannWollstadtWibralContinuous => {
                "David A. Ehrlich; Kyle Schick-Poland; Abdullah Makkeh; Felix Lanfermann; Patricia Wollstadt; Michael Wibral"
            }
        }
    }

    /// Role-distinct primary references and explicit non-alias boundary.
    pub const fn reference_edges(self) -> &'static [PidReferenceEdge] {
        match self {
            Self::MakkehGutknechtWibralCategorical => &CATEGORICAL_REFERENCE_EDGES,
            Self::EhrlichSchickPolandMakkehLanfermannWollstadtWibralContinuous => {
                &CONTINUOUS_REFERENCE_EDGES
            }
        }
    }
}

/// pid-rs sample-estimator route used by one fixed offline question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidStudyRoute {
    /// Empirical categorical plug-in route through `discrete_sxpid2_with_budget`.
    EmpiricalCategoricalPlugin,
    /// Continuous kNN PID2 route through the complete report-first evaluator.
    ContinuousKnnPid2Report,
}

impl PidStudyRoute {
    /// Semantic identity of the functional route used by this study record.
    ///
    /// The selected pid-rs revision carries a machine-readable method catalog.
    /// The exact compiled API route remains a separate execution coordinate.
    pub const fn method_id(self) -> &'static str {
        match self {
            Self::EmpiricalCategoricalPlugin => "shared-exclusions.categorical",
            Self::ContinuousKnnPid2Report => "pid.continuous-pid2",
        }
    }

    /// Exact public pid-core entry point used by Galadriel.
    pub const fn api_route(self) -> &'static str {
        match self {
            Self::EmpiricalCategoricalPlugin => {
                "pid_core::stable::categorical::discrete_sxpid2_with_budget"
            }
            Self::ContinuousKnnPid2Report => {
                "pid_core::experimental::continuous::pid2_isx_report_with_budget"
            }
        }
    }

    /// Cargo surface required by the exact evaluator route.
    pub const fn feature_gate(self) -> &'static str {
        match self {
            Self::EmpiricalCategoricalPlugin => "none; stable categorical surface",
            Self::ContinuousKnnPid2Report => "experimental-continuous",
        }
    }
}

/// Exact package dependency supplying one offline PID evaluation.
///
/// This is a local, mechanically checked dependency-selection envelope. The fixed
/// question retains this selection, while each produced study separately retains and
/// reconciles pid-core's build-context-dependent [`SoftwareIdentity`]. Neither is a binary
/// attestation or a proof of estimator applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidDependencyIdentity {
    package_name: &'static str,
    package_version: &'static str,
    git_repository: &'static str,
    git_revision: &'static str,
    workspace_selected_feature: &'static str,
}

impl PidDependencyIdentity {
    const fn pinned() -> Self {
        Self {
            package_name: "pid-core",
            package_version: PID_RS_VERSION,
            git_repository: PID_RS_GIT_REPOSITORY,
            git_revision: PID_RS_REVISION,
            workspace_selected_feature: "experimental-continuous",
        }
    }

    pub const fn package_name(self) -> &'static str {
        self.package_name
    }
    pub const fn package_version(self) -> &'static str {
        self.package_version
    }
    pub const fn git_repository(self) -> &'static str {
        self.git_repository
    }
    pub const fn git_revision(self) -> &'static str {
        self.git_revision
    }
    /// Cargo feature selected for pid-core by the containing justification crate.
    ///
    /// This is not necessarily required by every route in the crate: the
    /// categorical evaluator itself is on pid-core's stable default surface.
    pub const fn workspace_selected_feature(self) -> &'static str {
        self.workspace_selected_feature
    }
}

/// Build-context-dependent identity of the pid-core instance that executed one study.
///
/// Keeping this receipt at the produced-study layer prevents source/build context from changing
/// the equality or serialization identity of the scientific question itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PidExecutionIdentity {
    dependency_selection: PidDependencyIdentity,
    software_identity: SoftwareIdentity,
    package_and_version_matched: bool,
    workspace_git_revision_matched: bool,
    pid_core_package_subtree_clean: bool,
    boundary: &'static str,
}

impl PidExecutionIdentity {
    /// Immutable dependency selection that the executing package must match.
    pub const fn dependency_selection(&self) -> PidDependencyIdentity {
        self.dependency_selection
    }

    /// Build-context identity reported by the selected pid-core package.
    pub const fn software_identity(&self) -> &SoftwareIdentity {
        &self.software_identity
    }

    /// Whether the reported package name and version match the selected dependency.
    pub const fn package_and_version_matched(&self) -> bool {
        self.package_and_version_matched
    }

    /// Whether pid-core reported the selected WorkspaceGit commit and package-path scope.
    pub const fn workspace_git_revision_matched(&self) -> bool {
        self.workspace_git_revision_matched
    }

    /// Whether pid-core reported a clean package subtree under its declared narrow scope.
    pub const fn pid_core_package_subtree_clean(&self) -> bool {
        self.pid_core_package_subtree_clean
    }

    /// Explicit limits on what this execution-identity receipt establishes.
    pub const fn boundary(&self) -> &'static str {
        self.boundary
    }
}

fn pid_execution_identity() -> Result<PidExecutionIdentity> {
    let dependency_selection = PidDependencyIdentity::pinned();
    let software_identity = software_identity();
    let package_and_version_matched = software_identity.package_name()
        == dependency_selection.package_name()
        && software_identity.package_version() == dependency_selection.package_version();
    let (workspace_git_revision_matched, pid_core_package_subtree_clean) =
        match *software_identity.source() {
            SourceIdentity::WorkspaceGit {
                commit_sha1,
                working_tree_scope,
                working_tree,
                ..
            } => (
                commit_sha1 == dependency_selection.git_revision()
                    && working_tree_scope == WorkingTreeScope::PidCorePackagePath,
                working_tree == WorkingTreeState::Clean,
            ),
            _ => (false, false),
        };
    if !package_and_version_matched
        || !workspace_git_revision_matched
        || !pid_core_package_subtree_clean
    {
        return Err(JustificationError::PidCoreIdentity(format!(
            "selected {} {} at {} but compiled identity reported package={} version={} source={:?}",
            dependency_selection.package_name(),
            dependency_selection.package_version(),
            dependency_selection.git_revision(),
            software_identity.package_name(),
            software_identity.package_version(),
            software_identity.source(),
        )));
    }
    Ok(PidExecutionIdentity {
        dependency_selection,
        software_identity,
        package_and_version_matched: true,
        workspace_git_revision_matched: true,
        pid_core_package_subtree_clean: true,
        boundary: "binds the executing pid-core package/version and package-subtree WorkspaceGit source state to Galadriel's selected immutable revision. This is not whole-repository cleanliness, binary attestation, scientific validity, or numerical portability",
    })
}

/// Explicit per-call pid-core resource policy retained by an offline study result.
///
/// Galadriel separately checks aggregate quadratic work before starting a study.
/// This receipt binds each evaluator call to a deterministic single-thread ceiling.
/// It is not an aggregate peak-memory or wall-clock guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidStudyResourceContract {
    budget: ResourceBudget,
    scope: &'static str,
}

impl PidStudyResourceContract {
    fn fixed() -> Result<Self> {
        Ok(Self {
            budget: ResourceBudget::new(
                PID_STUDY_RESOURCE_MAX_BYTES,
                PID_STUDY_RESOURCE_MAX_PAIRWISE_DISTANCES,
                PID_STUDY_RESOURCE_MAX_OPERATIONS_HINT,
                PID_STUDY_RESOURCE_MAX_THREADS,
            )
            .map_err(pid_error)?,
            scope: "per evaluator call. Aggregate study work is checked separately. This is not an end-to-end memory, time, or allocation-success guarantee",
        })
    }

    pub const fn budget(self) -> ResourceBudget {
        self.budget
    }

    pub const fn scope(self) -> &'static str {
        self.scope
    }
}

/// Input-law role of a fixed offline PID study.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidInputLawKind {
    /// Equal-weight sampled categorical rows interpreted as an empirical PMF.
    EmpiricalCategoricalRows,
    /// Sample-estimator input from a declared continuous synthetic population.
    ContinuousSyntheticRows,
}

impl PidInputLawKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::EmpiricalCategoricalRows => "empirical-categorical-row-law",
            Self::ContinuousSyntheticRows => "continuous-synthetic-sample-law",
        }
    }
}

/// Exact generative-law and finite-sample selection statement for one study arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidInputLawSpec {
    semantic_id: &'static str,
    source_joint_law: &'static str,
    target_law: &'static str,
    finite_sample_acceptance: &'static str,
    numeric_representation: &'static str,
}

impl PidInputLawSpec {
    pub const fn semantic_id(self) -> &'static str {
        self.semantic_id
    }
    pub const fn source_joint_law(self) -> &'static str {
        self.source_joint_law
    }
    pub const fn target_law(self) -> &'static str {
        self.target_law
    }
    pub const fn finite_sample_acceptance(self) -> &'static str {
        self.finite_sample_acceptance
    }
    pub const fn numeric_representation(self) -> &'static str {
        self.numeric_representation
    }
}

const CATEGORICAL_XOR_LAW: PidInputLawSpec = PidInputLawSpec {
    semantic_id: "galadriel.law.categorical-xor-iid-fair-bits.v1",
    source_joint_law: "A and B are mutually independent Bernoulli(1/2) variables; rows are generated independently before the finite-sample acceptance rule",
    target_law: "T = A XOR B deterministically on each row",
    finite_sample_acceptance: "draw n-row trials until A, B, and T each contain both binary values, accepting the first such trial; abort after 32 attempts; the retained finite sample is therefore conditioned on this nondegeneracy event",
    numeric_representation: "A, B, and T are generated as exact u64 values 0 or 1; losslessly converted to binary64 0.0 or 1.0 only for Pearson and pid-core matrix input",
};

const CONTINUOUS_SIGN_PARITY_LAW: PidInputLawSpec = PidInputLawSpec {
    semantic_id: "galadriel.law.continuous-sign-parity-standard-normal.v1",
    source_joint_law: "A, B, and Z are mutually independent standard-normal variables; rows are generated independently",
    target_law: "T = sign(A) * sign(B) * abs(Z) on each generated row",
    finite_sample_acceptance: "retain the first n generated rows without data-dependent retry, filtering, or fitted preprocessing",
    numeric_representation: "binary64 pseudorandom variates from rand 0.8 StdRng and rand_distr 0.4 Normal; the exact resolved stream requires external lock/source identity",
};

/// Information unit of one explicitly named PID result layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidInformationUnits {
    Bits,
    Nats,
}

impl PidInformationUnits {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bits => "bits",
            Self::Nats => "nats",
        }
    }
}

/// Construction used to obtain one named PID output coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidQuantityConstruction {
    /// Möbius inversion of the categorical MGW cumulative lattice quantities.
    CategoricalMobiusInvertedAtom,
    /// Direct Ehrlich shared-exclusions redundancy estimate in the retained PID2 report.
    ContinuousEhrlichSharedExclusionsRedundancyEstimate,
    /// Unique or synergistic two-source atom algebra composed from the Ehrlich
    /// redundancy estimate and the retained MI constituents.
    ContinuousPid2DerivedAtomFromRedundancyAndMutualInformation,
}

/// Signed component exposed at one PID output coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidAtomComponent {
    Net,
    Informative,
    Misinformative,
}

/// Aggregation law attached to one PID output coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidAggregationScope {
    /// Probability-weighted average over the empirical categorical PMF.
    EmpiricalPmfAverage,
    /// Continuous sample-estimator output; the trial-arm record determines
    /// whether population-functional interpretation is licensed.
    ContinuousSampleEstimatorOutput,
}

/// Exact two-source redundancy-lattice coordinate of one PID atom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidLatticeCoordinate {
    Redundancy,
    UniqueSource1,
    UniqueSource2,
    Synergy,
}

impl PidLatticeCoordinate {
    pub const fn semantic_id(self) -> &'static str {
        match self {
            Self::Redundancy => "two-source-antichain:{{S1},{S2}}",
            Self::UniqueSource1 => "two-source-antichain:{{S1}}",
            Self::UniqueSource2 => "two-source-antichain:{{S2}}",
            Self::Synergy => "two-source-antichain:{{S1,S2}}",
        }
    }
}

/// Across-trial statistic represented by one serialized PID aggregate field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum StudyAggregateStatistic {
    /// ROC-AUC separating coupled trials from their paired permutation controls.
    CoupledVersusPermutationControlRocAuc,
    /// Paired-trial percentile-bootstrap 95% interval for the corresponding ROC-AUC.
    PairedTrialPercentileBootstrap95Interval,
    /// Arithmetic mean over coupled-trial values.
    CoupledTrialArithmeticMean,
}

/// Units of one serialized PID aggregate field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum StudyOutputUnits {
    Bits,
    Nats,
    Dimensionless,
}

impl StudyOutputUnits {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bits => "bits",
            Self::Nats => "nats",
            Self::Dimensionless => "dimensionless",
        }
    }
}

/// Non-PID quantity represented by one sibling study aggregate field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum StudyQuantityIdentity {
    MaxAbsolutePearsonPairwise,
    MaxPairwiseMutualInformation,
    JointInformationContrastQ,
    JointMutualInformation,
}

/// Exact root-result field outside the PID functional allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StudyAggregateOutputSpec {
    serialized_field: &'static str,
    quantity: StudyQuantityIdentity,
    statistic: StudyAggregateStatistic,
    units: StudyOutputUnits,
}

impl StudyAggregateOutputSpec {
    pub const fn serialized_field(self) -> &'static str {
        self.serialized_field
    }
    pub const fn quantity(self) -> StudyQuantityIdentity {
        self.quantity
    }
    pub const fn statistic(self) -> StudyAggregateStatistic {
        self.statistic
    }
    pub const fn units(self) -> StudyOutputUnits {
        self.units
    }
}

/// Interpretation of one retained paired PID evaluator arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum PidTrialArmRole {
    CoupledQuestionLaw,
    WithinTrialTargetPermutationControl,
}

/// Exact serialized trial field and the scientific interpretation it may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidTrialArmSpec {
    serialized_field: &'static str,
    role: PidTrialArmRole,
    interpretation: &'static str,
}

impl PidTrialArmSpec {
    pub const fn serialized_field(self) -> &'static str {
        self.serialized_field
    }
    pub const fn role(self) -> PidTrialArmRole {
        self.role
    }
    pub const fn interpretation(self) -> &'static str {
        self.interpretation
    }
}

/// Exact root-result field derived from one retained PID coordinate/component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidAggregateOutputSpec {
    serialized_field: &'static str,
    coordinate: PidLatticeCoordinate,
    component: PidAtomComponent,
    statistic: StudyAggregateStatistic,
    units: StudyOutputUnits,
}

impl PidAggregateOutputSpec {
    pub const fn serialized_field(self) -> &'static str {
        self.serialized_field
    }
    pub const fn coordinate(self) -> PidLatticeCoordinate {
        self.coordinate
    }
    pub const fn component(self) -> PidAtomComponent {
        self.component
    }
    pub const fn statistic(self) -> StudyAggregateStatistic {
        self.statistic
    }
    pub const fn units(self) -> StudyOutputUnits {
        self.units
    }
}

/// One exact output family coordinate produced inside a retained PID trial report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidOutputCoordinateSpec {
    quantity_id: &'static str,
    lattice_coordinate: PidLatticeCoordinate,
    construction: PidQuantityConstruction,
    components: &'static [PidAtomComponent],
    aggregation: PidAggregationScope,
    evaluator_units: PidInformationUnits,
}

impl PidOutputCoordinateSpec {
    pub const fn quantity_id(self) -> &'static str {
        self.quantity_id
    }
    pub const fn lattice_coordinate(self) -> PidLatticeCoordinate {
        self.lattice_coordinate
    }
    pub const fn construction(self) -> PidQuantityConstruction {
        self.construction
    }
    pub const fn components(self) -> &'static [PidAtomComponent] {
        self.components
    }
    pub const fn aggregation(self) -> PidAggregationScope {
        self.aggregation
    }
    pub const fn evaluator_units(self) -> PidInformationUnits {
        self.evaluator_units
    }
}

const CATEGORICAL_COMPONENTS: [PidAtomComponent; 3] = [
    PidAtomComponent::Net,
    PidAtomComponent::Informative,
    PidAtomComponent::Misinformative,
];
const CONTINUOUS_COMPONENTS: [PidAtomComponent; 1] = [PidAtomComponent::Net];

const CATEGORICAL_OUTPUT_COORDINATES: [PidOutputCoordinateSpec; 4] = [
    PidOutputCoordinateSpec {
        quantity_id: "quantity.shared-exclusions.mgw-categorical.mobius-atom.redundancy",
        lattice_coordinate: PidLatticeCoordinate::Redundancy,
        construction: PidQuantityConstruction::CategoricalMobiusInvertedAtom,
        components: &CATEGORICAL_COMPONENTS,
        aggregation: PidAggregationScope::EmpiricalPmfAverage,
        evaluator_units: PidInformationUnits::Nats,
    },
    PidOutputCoordinateSpec {
        quantity_id: "quantity.shared-exclusions.mgw-categorical.mobius-atom.unique-source-1",
        lattice_coordinate: PidLatticeCoordinate::UniqueSource1,
        construction: PidQuantityConstruction::CategoricalMobiusInvertedAtom,
        components: &CATEGORICAL_COMPONENTS,
        aggregation: PidAggregationScope::EmpiricalPmfAverage,
        evaluator_units: PidInformationUnits::Nats,
    },
    PidOutputCoordinateSpec {
        quantity_id: "quantity.shared-exclusions.mgw-categorical.mobius-atom.unique-source-2",
        lattice_coordinate: PidLatticeCoordinate::UniqueSource2,
        construction: PidQuantityConstruction::CategoricalMobiusInvertedAtom,
        components: &CATEGORICAL_COMPONENTS,
        aggregation: PidAggregationScope::EmpiricalPmfAverage,
        evaluator_units: PidInformationUnits::Nats,
    },
    PidOutputCoordinateSpec {
        quantity_id: "quantity.shared-exclusions.mgw-categorical.mobius-atom.synergy",
        lattice_coordinate: PidLatticeCoordinate::Synergy,
        construction: PidQuantityConstruction::CategoricalMobiusInvertedAtom,
        components: &CATEGORICAL_COMPONENTS,
        aggregation: PidAggregationScope::EmpiricalPmfAverage,
        evaluator_units: PidInformationUnits::Nats,
    },
];

const CONTINUOUS_OUTPUT_COORDINATES: [PidOutputCoordinateSpec; 4] = [
    PidOutputCoordinateSpec {
        quantity_id: "quantity.shared-exclusions.ehrlich-continuous.pid2-atom.redundancy",
        lattice_coordinate: PidLatticeCoordinate::Redundancy,
        construction: PidQuantityConstruction::ContinuousEhrlichSharedExclusionsRedundancyEstimate,
        components: &CONTINUOUS_COMPONENTS,
        aggregation: PidAggregationScope::ContinuousSampleEstimatorOutput,
        evaluator_units: PidInformationUnits::Nats,
    },
    PidOutputCoordinateSpec {
        quantity_id: "quantity.shared-exclusions.ehrlich-continuous.pid2-atom.unique-source-1",
        lattice_coordinate: PidLatticeCoordinate::UniqueSource1,
        construction:
            PidQuantityConstruction::ContinuousPid2DerivedAtomFromRedundancyAndMutualInformation,
        components: &CONTINUOUS_COMPONENTS,
        aggregation: PidAggregationScope::ContinuousSampleEstimatorOutput,
        evaluator_units: PidInformationUnits::Nats,
    },
    PidOutputCoordinateSpec {
        quantity_id: "quantity.shared-exclusions.ehrlich-continuous.pid2-atom.unique-source-2",
        lattice_coordinate: PidLatticeCoordinate::UniqueSource2,
        construction:
            PidQuantityConstruction::ContinuousPid2DerivedAtomFromRedundancyAndMutualInformation,
        components: &CONTINUOUS_COMPONENTS,
        aggregation: PidAggregationScope::ContinuousSampleEstimatorOutput,
        evaluator_units: PidInformationUnits::Nats,
    },
    PidOutputCoordinateSpec {
        quantity_id: "quantity.shared-exclusions.ehrlich-continuous.pid2-atom.synergy",
        lattice_coordinate: PidLatticeCoordinate::Synergy,
        construction:
            PidQuantityConstruction::ContinuousPid2DerivedAtomFromRedundancyAndMutualInformation,
        components: &CONTINUOUS_COMPONENTS,
        aggregation: PidAggregationScope::ContinuousSampleEstimatorOutput,
        evaluator_units: PidInformationUnits::Nats,
    },
];

const CATEGORICAL_AGGREGATE_OUTPUTS: [PidAggregateOutputSpec; 4] = [
    PidAggregateOutputSpec {
        serialized_field: "sxpid_syn_auc",
        coordinate: PidLatticeCoordinate::Synergy,
        component: PidAtomComponent::Net,
        statistic: StudyAggregateStatistic::CoupledVersusPermutationControlRocAuc,
        units: StudyOutputUnits::Dimensionless,
    },
    PidAggregateOutputSpec {
        serialized_field: "sxpid_syn_auc_ci",
        coordinate: PidLatticeCoordinate::Synergy,
        component: PidAtomComponent::Net,
        statistic: StudyAggregateStatistic::PairedTrialPercentileBootstrap95Interval,
        units: StudyOutputUnits::Dimensionless,
    },
    PidAggregateOutputSpec {
        serialized_field: "sxpid_syn_coupled_mean",
        coordinate: PidLatticeCoordinate::Synergy,
        component: PidAtomComponent::Net,
        statistic: StudyAggregateStatistic::CoupledTrialArithmeticMean,
        units: StudyOutputUnits::Bits,
    },
    PidAggregateOutputSpec {
        serialized_field: "sxpid_red_coupled_mean",
        coordinate: PidLatticeCoordinate::Redundancy,
        component: PidAtomComponent::Net,
        statistic: StudyAggregateStatistic::CoupledTrialArithmeticMean,
        units: StudyOutputUnits::Bits,
    },
];

const CONTINUOUS_AGGREGATE_OUTPUTS: [PidAggregateOutputSpec; 3] = [
    PidAggregateOutputSpec {
        serialized_field: "isx_syn_auc",
        coordinate: PidLatticeCoordinate::Synergy,
        component: PidAtomComponent::Net,
        statistic: StudyAggregateStatistic::CoupledVersusPermutationControlRocAuc,
        units: StudyOutputUnits::Dimensionless,
    },
    PidAggregateOutputSpec {
        serialized_field: "isx_syn_auc_ci",
        coordinate: PidLatticeCoordinate::Synergy,
        component: PidAtomComponent::Net,
        statistic: StudyAggregateStatistic::PairedTrialPercentileBootstrap95Interval,
        units: StudyOutputUnits::Dimensionless,
    },
    PidAggregateOutputSpec {
        serialized_field: "isx_syn_coupled_mean",
        coordinate: PidLatticeCoordinate::Synergy,
        component: PidAtomComponent::Net,
        statistic: StudyAggregateStatistic::CoupledTrialArithmeticMean,
        units: StudyOutputUnits::Nats,
    },
];

const CATEGORICAL_NON_PID_AGGREGATE_OUTPUTS: [StudyAggregateOutputSpec; 7] = [
    StudyAggregateOutputSpec {
        serialized_field: "corr_auc",
        quantity: StudyQuantityIdentity::MaxAbsolutePearsonPairwise,
        statistic: StudyAggregateStatistic::CoupledVersusPermutationControlRocAuc,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "corr_auc_ci",
        quantity: StudyQuantityIdentity::MaxAbsolutePearsonPairwise,
        statistic: StudyAggregateStatistic::PairedTrialPercentileBootstrap95Interval,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "pairwise_mi_auc",
        quantity: StudyQuantityIdentity::MaxPairwiseMutualInformation,
        statistic: StudyAggregateStatistic::CoupledVersusPermutationControlRocAuc,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "pairwise_mi_auc_ci",
        quantity: StudyQuantityIdentity::MaxPairwiseMutualInformation,
        statistic: StudyAggregateStatistic::PairedTrialPercentileBootstrap95Interval,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "q_auc",
        quantity: StudyQuantityIdentity::JointInformationContrastQ,
        statistic: StudyAggregateStatistic::CoupledVersusPermutationControlRocAuc,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "q_auc_ci",
        quantity: StudyQuantityIdentity::JointInformationContrastQ,
        statistic: StudyAggregateStatistic::PairedTrialPercentileBootstrap95Interval,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "q_coupled_mean",
        quantity: StudyQuantityIdentity::JointInformationContrastQ,
        statistic: StudyAggregateStatistic::CoupledTrialArithmeticMean,
        units: StudyOutputUnits::Bits,
    },
];

const CONTINUOUS_NON_PID_AGGREGATE_OUTPUTS: [StudyAggregateOutputSpec; 7] = [
    StudyAggregateOutputSpec {
        serialized_field: "corr_auc",
        quantity: StudyQuantityIdentity::MaxAbsolutePearsonPairwise,
        statistic: StudyAggregateStatistic::CoupledVersusPermutationControlRocAuc,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "corr_auc_ci",
        quantity: StudyQuantityIdentity::MaxAbsolutePearsonPairwise,
        statistic: StudyAggregateStatistic::PairedTrialPercentileBootstrap95Interval,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "pairwise_mi_auc",
        quantity: StudyQuantityIdentity::MaxPairwiseMutualInformation,
        statistic: StudyAggregateStatistic::CoupledVersusPermutationControlRocAuc,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "pairwise_mi_auc_ci",
        quantity: StudyQuantityIdentity::MaxPairwiseMutualInformation,
        statistic: StudyAggregateStatistic::PairedTrialPercentileBootstrap95Interval,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "q_auc",
        quantity: StudyQuantityIdentity::JointInformationContrastQ,
        statistic: StudyAggregateStatistic::CoupledVersusPermutationControlRocAuc,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "q_auc_ci",
        quantity: StudyQuantityIdentity::JointInformationContrastQ,
        statistic: StudyAggregateStatistic::PairedTrialPercentileBootstrap95Interval,
        units: StudyOutputUnits::Dimensionless,
    },
    StudyAggregateOutputSpec {
        serialized_field: "joint_mi_coupled_mean",
        quantity: StudyQuantityIdentity::JointMutualInformation,
        statistic: StudyAggregateStatistic::CoupledTrialArithmeticMean,
        units: StudyOutputUnits::Nats,
    },
];

const CATEGORICAL_TRIAL_ARMS: [PidTrialArmSpec; 2] = [
    PidTrialArmSpec {
        serialized_field: "coupled",
        role: PidTrialArmRole::CoupledQuestionLaw,
        interpretation: "empirical-PMF MGW evaluation of the generated XOR row law",
    },
    PidTrialArmSpec {
        serialized_field: "permutation_control",
        role: PidTrialArmRole::WithinTrialTargetPermutationControl,
        interpretation: "empirical-PMF MGW evaluation after within-trial target permutation; a descriptive randomization object, not an independent-law sample",
    },
];

const CONTINUOUS_TRIAL_ARMS: [PidTrialArmSpec; 2] = [
    PidTrialArmSpec {
        serialized_field: "coupled",
        role: PidTrialArmRole::CoupledQuestionLaw,
        interpretation: "sample estimate of the named continuous functional under the declared generated i.i.d. coupled law",
    },
    PidTrialArmSpec {
        serialized_field: "permutation_control",
        role: PidTrialArmRole::WithinTrialTargetPermutationControl,
        interpretation: "same evaluator applied after within-trial target permutation; an exchangeable descriptive randomization score, not an i.i.d. independent-law or population-functional estimate",
    },
];

/// Sealed estimand and provenance record for one fixed offline PID question.
///
/// The dependency identity says which pinned pid-core package supplied the
/// evaluator. It does not prove application validity, estimator assumptions,
/// source authenticity, build identity, or numerical portability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PidQuestionSpec {
    schema: &'static str,
    functional: PidFunctionalIdentity,
    reference_edges: &'static [PidReferenceEdge],
    route: PidStudyRoute,
    law_kind: PidInputLawKind,
    input_law: PidInputLawSpec,
    source_count: usize,
    ordered_sources: [&'static str; 2],
    target: &'static str,
    output_coordinates: &'static [PidOutputCoordinateSpec],
    aggregate_outputs: &'static [PidAggregateOutputSpec],
    trial_arms: &'static [PidTrialArmSpec],
    route_configuration: &'static str,
    transform_relation: &'static str,
    row_relation: &'static str,
    support_and_gauge: &'static str,
    sign_convention: &'static str,
    output_relation: &'static str,
    evaluator_units: PidInformationUnits,
    atom_aggregate_units: PidInformationUnits,
    pid_core_dependency: PidDependencyIdentity,
}

impl PidQuestionSpec {
    /// Fixed categorical XOR allocation question used by
    /// [`run_categorical_xor_justification`].
    pub fn categorical_xor() -> Self {
        Self {
            schema: PID_QUESTION_SCHEMA,
            functional: PidFunctionalIdentity::MakkehGutknechtWibralCategorical,
            reference_edges: &CATEGORICAL_REFERENCE_EDGES,
            route: PidStudyRoute::EmpiricalCategoricalPlugin,
            law_kind: PidInputLawKind::EmpiricalCategoricalRows,
            input_law: CATEGORICAL_XOR_LAW,
            source_count: 2,
            ordered_sources: ["xor.source-a", "xor.source-b"],
            target: "xor.target-a-xor-b",
            output_coordinates: &CATEGORICAL_OUTPUT_COORDINATES,
            aggregate_outputs: &CATEGORICAL_AGGREGATE_OUTPUTS,
            trial_arms: &CATEGORICAL_TRIAL_ARMS,
            route_configuration: "canonical pid-core discrete_sxpid2_with_budget empirical-PMF evaluator under the retained single-thread per-call budget. No comparator or fallback functional is used",
            transform_relation: "lossless-binary-0-or-1-encoding; no fitted transform",
            row_relation: "same sampled rows for both sources and target; shuffled-target control is a separate descriptive permutation object",
            support_and_gauge: "finite binary alphabets; empirical equal-weight plug-in PMF; no continuous source gauge",
            sign_convention: "net = informative - misinformative at every retained MGW atom; negative net atoms are preserved",
            output_relation: "pid-core evaluator and retained per-trial results remain in nats; aggregate/display atoms divide by ln(2) exactly once and are in bits",
            evaluator_units: PidInformationUnits::Nats,
            atom_aggregate_units: PidInformationUnits::Bits,
            pid_core_dependency: PidDependencyIdentity::pinned(),
        }
    }

    /// Fixed continuous sign-parity allocation question used by
    /// [`run_continuous_sign_parity_justification`].
    pub fn continuous_sign_parity() -> Self {
        Self {
            schema: PID_QUESTION_SCHEMA,
            functional:
                PidFunctionalIdentity::EhrlichSchickPolandMakkehLanfermannWollstadtWibralContinuous,
            reference_edges: &CONTINUOUS_REFERENCE_EDGES,
            route: PidStudyRoute::ContinuousKnnPid2Report,
            law_kind: PidInputLawKind::ContinuousSyntheticRows,
            input_law: CONTINUOUS_SIGN_PARITY_LAW,
            source_count: 2,
            ordered_sources: ["sign-parity.source-a", "sign-parity.source-b"],
            target: "sign-parity.target-sign-a-times-sign-b-times-abs-z",
            output_coordinates: &CONTINUOUS_OUTPUT_COORDINATES,
            aggregate_outputs: &CONTINUOUS_AGGREGATE_OUTPUTS,
            trial_arms: &CONTINUOUS_TRIAL_ARMS,
            route_configuration: "Pid2Config::assume_regular_full_dimensional through pid2_isx_report_with_budget under the retained single-thread per-call budget. Exact realized estimator reports are retained per trial. No fallback functional is used",
            transform_relation: "identity coordinates; no fitted preprocessing, quantization, added noise, or tie-breaking transform",
            row_relation: "same declared i.i.d. synthetic rows for both sources and target; shuffled-target control is a separate descriptive permutation object",
            support_and_gauge: "declared full-dimensional continuous tuple; both source gauges fixed to standard-normal simulator coordinates; target retains its generated coordinate",
            sign_convention: "signed PID2 atoms are retained without clamping; atom algebra uses the signed KSG MI constituents",
            output_relation: "pid-core evaluator, retained per-trial reports, and aggregate/display atoms all remain in nats",
            evaluator_units: PidInformationUnits::Nats,
            atom_aggregate_units: PidInformationUnits::Nats,
            pid_core_dependency: PidDependencyIdentity::pinned(),
        }
    }

    pub const fn schema(&self) -> &'static str {
        self.schema
    }
    pub const fn functional(&self) -> PidFunctionalIdentity {
        self.functional
    }
    pub const fn reference_edges(&self) -> &'static [PidReferenceEdge] {
        self.reference_edges
    }
    pub const fn route(&self) -> PidStudyRoute {
        self.route
    }
    pub const fn law_kind(&self) -> PidInputLawKind {
        self.law_kind
    }
    pub const fn input_law(&self) -> PidInputLawSpec {
        self.input_law
    }
    pub const fn source_count(&self) -> usize {
        self.source_count
    }
    pub const fn ordered_sources(&self) -> &[&'static str; 2] {
        &self.ordered_sources
    }
    pub const fn target(&self) -> &'static str {
        self.target
    }
    pub const fn output_coordinates(&self) -> &'static [PidOutputCoordinateSpec] {
        self.output_coordinates
    }
    pub const fn aggregate_outputs(&self) -> &'static [PidAggregateOutputSpec] {
        self.aggregate_outputs
    }
    pub const fn trial_arms(&self) -> &'static [PidTrialArmSpec] {
        self.trial_arms
    }
    pub const fn route_configuration(&self) -> &'static str {
        self.route_configuration
    }
    pub const fn transform_relation(&self) -> &'static str {
        self.transform_relation
    }
    pub const fn row_relation(&self) -> &'static str {
        self.row_relation
    }
    pub const fn support_and_gauge(&self) -> &'static str {
        self.support_and_gauge
    }
    pub const fn sign_convention(&self) -> &'static str {
        self.sign_convention
    }
    pub const fn output_relation(&self) -> &'static str {
        self.output_relation
    }
    pub const fn evaluator_units(&self) -> PidInformationUnits {
        self.evaluator_units
    }
    pub const fn atom_aggregate_units(&self) -> PidInformationUnits {
        self.atom_aggregate_units
    }
    pub const fn pid_core_dependency(&self) -> PidDependencyIdentity {
        self.pid_core_dependency
    }
}

fn format_pid_question(question: &PidQuestionSpec) -> String {
    let dependency = question.pid_core_dependency();
    let mut output = format!(
        "PID question: schema={} · functional={} · primary functional team={}\n\
         route={} ({}) · route feature={} · evaluation=sample estimator · law={} · evaluator units={} · atom-aggregate units={}\n\
         source count={} · ordered sources=[{}, {}] · target={}\n\
         input law={} · sources={} · target law={}\n\
         finite-sample acceptance={}\n\
         numeric representation={}\n\
         route configuration={}\n\
         transform={}\n\
         row relation={}\n\
         support/gauge={}\n\
         sign convention={}\n\
         output relation={}\n\
         pid-core package={} {} · workspace selected feature={}\n\
         pid-rs repository={} · revision={}\n",
        question.schema(),
        question.functional().semantic_id(),
        question.functional().defining_team(),
        question.route().method_id(),
        question.route().api_route(),
        question.route().feature_gate(),
        question.law_kind().name(),
        question.evaluator_units().name(),
        question.atom_aggregate_units().name(),
        question.source_count(),
        question.ordered_sources()[0],
        question.ordered_sources()[1],
        question.target(),
        question.input_law().semantic_id(),
        question.input_law().source_joint_law(),
        question.input_law().target_law(),
        question.input_law().finite_sample_acceptance(),
        question.input_law().numeric_representation(),
        question.route_configuration(),
        question.transform_relation(),
        question.row_relation(),
        question.support_and_gauge(),
        question.sign_convention(),
        question.output_relation(),
        dependency.package_name(),
        dependency.package_version(),
        dependency.workspace_selected_feature(),
        dependency.git_repository(),
        dependency.git_revision(),
    );
    output.push_str("reference edges:\n");
    for edge in question.reference_edges() {
        output.push_str(&format!(
            "  {:?}: {} · {} · team={} · {}\n",
            edge.roles(),
            edge.reference_id(),
            edge.title(),
            edge.complete_team(),
            edge.locator(),
        ));
    }
    output.push_str("output coordinates:\n");
    for coordinate in question.output_coordinates() {
        output.push_str(&format!(
            "  {} · lattice={} · construction={:?} · components={:?} · within-trial aggregation={:?} · units={}\n",
            coordinate.quantity_id(),
            coordinate.lattice_coordinate().semantic_id(),
            coordinate.construction(),
            coordinate.components(),
            coordinate.aggregation(),
            coordinate.evaluator_units().name(),
        ));
    }
    output.push_str("serialized PID aggregate fields:\n");
    for aggregate in question.aggregate_outputs() {
        output.push_str(&format!(
            "  {} <- lattice={} component={:?} statistic={:?} units={}\n",
            aggregate.serialized_field(),
            aggregate.coordinate().semantic_id(),
            aggregate.component(),
            aggregate.statistic(),
            aggregate.units().name(),
        ));
    }
    output.push_str("retained PID trial arms:\n");
    for arm in question.trial_arms() {
        output.push_str(&format!(
            "  {} · role={:?} · {}\n",
            arm.serialized_field(),
            arm.role(),
            arm.interpretation(),
        ));
    }
    output
}

fn format_study_protocol(protocol: &JustificationStudyProtocol) -> String {
    let mut output = format!(
        "Comparator/composition protocol: schema={}\n\
         correlation={} · pairwise MI={}\n\
         Q={} · formula={} · Q is not a PID atom\n\
         PID-question scope={}\n\
         control relation={}\n\
         sampling unit={}\n\
         AUC interval={} · resamples={} · scope={}\n\
         multiplicity relation={}\n\
         RNG={}\n\
         generation stream={} · generation seed XOR={:#x}\n\
         paired-index bootstrap={}\n\
         bootstrap seed XOR={:#x} · percentile selection={}\n",
        protocol.schema(),
        protocol.correlation_score_id(),
        protocol.pairwise_mi_score_id(),
        protocol.q_score_id(),
        protocol.q_formula(),
        protocol.pid_question_scope(),
        protocol.control_relation(),
        protocol.sampling_unit(),
        protocol.auc_interval_procedure_id(),
        protocol.auc_interval_resamples(),
        protocol.auc_interval_scope(),
        protocol.multiplicity_relation(),
        protocol.rng_implementation(),
        protocol.generation_stream_relation(),
        protocol.generation_seed_xor(),
        protocol.bootstrap_paired_index_algorithm(),
        protocol.bootstrap_seed_xor(),
        protocol.bootstrap_quantile_algorithm(),
    );
    output.push_str("serialized non-PID aggregate fields:\n");
    for aggregate in protocol.non_pid_aggregate_outputs() {
        output.push_str(&format!(
            "  {} <- quantity={:?} statistic={:?} units={}\n",
            aggregate.serialized_field(),
            aggregate.quantity(),
            aggregate.statistic(),
            aggregate.units().name(),
        ));
    }
    output.push_str("AUC interval seed relations:\n");
    for relation in protocol.auc_interval_seed_relations() {
        output.push_str(&format!(
            "  {} interval seed = root_seed.wrapping_add({}) before XOR\n",
            relation.auc_field(),
            relation.root_seed_wrapping_add(),
        ));
    }
    output
}

/// The cross-variable coupling under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coupling {
    /// `Y = X + ε` — the linear-Gaussian case where population MI is monotone in `|ρ|`.
    Linear,
    /// `Y = ±X + ε` (random sign per sample) — strongly dependent (`|Y| ≈ |X|`) yet
    /// *population* `corr(X, Y) = 0`. The sample correlation is *not* chance-level: its
    /// variance is inflated by the kurtosis of `X` (a fourth-moment artifact), so finite
    /// samples can give a `|ρ|` detector some separation even without population-level
    /// linear dependence.
    Nonlinear,
}

impl Coupling {
    /// All couplings.
    pub const ALL: [Coupling; 2] = [Coupling::Linear, Coupling::Nonlinear];

    /// A label.
    pub fn label(self) -> &'static str {
        match self {
            Coupling::Linear => "linear     (Y = X + e)",
            Coupling::Nonlinear => "nonlinear  (Y = +/-X + e)",
        }
    }
}

/// Absolute Pearson correlation with finite-input and equal-length validation.
pub fn abs_pearson(x: &[f64], y: &[f64]) -> Result<f64> {
    pearson(x, y).map(f64::abs).map_err(Into::into)
}

/// Report-first KSG mutual information in nats for one named synthetic row set.
///
/// The caller supplies the sampling-model description because the coupled,
/// permutation-control, and onset-crossing windows are different statistical
/// objects. Galadriel adds no noise. Exact ties therefore make the continuous
/// estimator abstain instead of changing the estimand.
fn ksg(evaluation_id: u64, x: &[f64], y: &[f64], sampling_model: &str) -> Result<f64> {
    if x.len() != y.len() || x.is_empty() {
        return Err(GaladrielError::InvalidChannels(format!(
            "KSG columns must be non-empty and equally sized ({} != {})",
            x.len(),
            y.len()
        ))
        .into());
    }
    if !x.iter().chain(y).all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("KSG input").into());
    }

    let a = MatOwned::new(x.to_vec(), x.len(), 1).map_err(pid_error)?;
    let b = MatOwned::new(y.to_vec(), y.len(), 1).map_err(pid_error)?;
    let split_id = format!("synthetic-evaluation-{evaluation_id:016x}");
    let provenance = KsgProvenance::new(
        "No fitted preprocessing; both scalar columns retain their registered simulator coordinates.",
        "Direct binary64 pseudorandom representation of the declared continuous synthetic law; no deliberate quantization, added noise, or tie-breaking transform.",
        None,
    )
    .and_then(|provenance| {
        provenance.with_sampling_model_and_splits(
            sampling_model,
            None,
            Some(&split_id),
        )
    })
    .map_err(pid_error)?;
    let report = ksg_mi_report_with_budget(
        a.as_ref(),
        b.as_ref(),
        &KsgConfig::assume_regular_full_dimensional(),
        &provenance,
        PidStudyResourceContract::fixed()?.budget(),
    )
    .map_err(pid_error)?;
    Ok(report.signed_estimate_nats)
}

fn pid_error(error: pid_core::PidError) -> JustificationError {
    JustificationError::PidCore(error)
}

/// Mechanical minimum trials per inferential class/arm; this is not a power guarantee.
pub const MIN_TRIALS: usize = 20;
/// Minimum resample count accepted for an inferential percentile interval.
pub const MIN_BOOTSTRAP_RESAMPLES: usize = 200;
/// Maximum trials per inferential class/arm.
pub const MAX_TRIALS: usize = 1_000;
const MAX_SAMPLES: usize = 10_000;
/// Upper bound on exact constituent pair-distance evaluations in one study.
const MAX_DISTANCE_COMPARISONS: u128 = 1_200_000_000;
/// Upper bound on AUC score comparisons performed across all bootstrap CIs in one study.
const MAX_BOOTSTRAP_AUC_COMPARISONS: usize = 500_000_000;
/// Upper bound on exact constituent pair-distance evaluations in the default CLI suite.
const MAX_CLI_DISTANCE_COMPARISONS: u128 = 3_000_000_000;
/// Upper bound on aggregate AUC comparisons in the default CLI suite.
const MAX_CLI_BOOTSTRAP_AUC_COMPARISONS: usize = 500_000_000;

fn checked_product(label: &str, factors: &[usize]) -> Result<usize> {
    factors
        .iter()
        .try_fold(1usize, |work, &factor| {
            work.checked_mul(factor).ok_or_else(|| {
                GaladrielError::InvalidConfig(format!("{label} work estimate overflowed"))
            })
        })
        .map_err(Into::into)
}

fn enforce_work(label: &str, work: usize, limit: usize) -> Result<()> {
    if work > limit {
        return Err(GaladrielError::InvalidConfig(format!(
            "{label} work estimate {work} exceeds limit {limit}; reduce trials, samples, or bootstrap count"
        ))
        .into());
    }
    Ok(())
}

fn checked_distance_product(label: &str, factors: &[u128]) -> Result<u128> {
    factors
        .iter()
        .try_fold(1u128, |work, &factor| {
            work.checked_mul(factor).ok_or_else(|| {
                GaladrielError::InvalidConfig(format!("{label} work estimate overflowed"))
            })
        })
        .map_err(Into::into)
}

fn checked_distance_sum(label: &str, values: &[u128]) -> Result<u128> {
    values
        .iter()
        .try_fold(0u128, |total, &value| {
            total.checked_add(value).ok_or_else(|| {
                GaladrielError::InvalidConfig(format!("{label} work estimate overflowed"))
            })
        })
        .map_err(Into::into)
}

fn triangular_pairs(n: usize) -> Result<u128> {
    let n = n as u128;
    n.checked_mul(n.saturating_sub(1))
        .and_then(|value| value.checked_div(2))
        .ok_or_else(|| {
            GaladrielError::InvalidConfig(
                "pair-distance triangular work estimate overflowed".into(),
            )
        })
        .map_err(Into::into)
}

/// One report-first KSG call evaluates four triangular pair sets: estimator,
/// first marginal support, second marginal support, and joint-shell support.
fn ksg_report_distance_work(n: usize) -> Result<u128> {
    checked_distance_product("KSG report distance-comparison", &[triangular_pairs(n)?, 4])
}

/// One complete PID2 report evaluates three report-first KSG constituents and
/// one Ehrlich shared-exclusions constituent: `3 * 4 + 1 = 13` triangular passes.
///
/// The pinned pid-rs aggregate preflight currently uses its cheaper x-blocks
/// estimate for the joined-source constituent even though execution constructs
/// and reports the full joined-source KSG route. Galadriel therefore composes the
/// four executed constituent routes explicitly and tests this count against the
/// resource estimates retained in an actual report.
fn pid2_report_distance_work(n: usize) -> Result<u128> {
    checked_distance_product(
        "PID2 report distance-comparison",
        &[triangular_pairs(n)?, 13],
    )
}

fn ksg_work(trials: usize, n: usize, report_count: usize) -> Result<u128> {
    checked_distance_product(
        "KSG distance-comparison",
        &[
            trials as u128,
            report_count as u128,
            ksg_report_distance_work(n)?,
        ],
    )
}

fn pid2_work(trials: usize, n: usize, report_count: usize) -> Result<u128> {
    checked_distance_product(
        "PID2 distance-comparison",
        &[
            trials as u128,
            report_count as u128,
            pid2_report_distance_work(n)?,
        ],
    )
}

fn bootstrap_work(class_len: usize, n_boot: usize, ci_count: usize) -> Result<usize> {
    checked_product("AUC bootstrap", &[class_len, class_len, n_boot, ci_count])
}

fn sequential_distance_work(trials: usize) -> Result<u128> {
    let arms = 3u128;
    let window_work = checked_distance_product(
        "sequential window-KSG",
        &[
            trials as u128,
            arms,
            (SEQ_EVAL_LEN / SEQ_STRIDE) as u128,
            ksg_report_distance_work(SEQ_WINDOW)?,
        ],
    )?;
    let local_per_stream = checked_distance_sum(
        "sequential local-MI",
        &[
            checked_distance_product(
                "sequential reference local-MI",
                &[SEQ_REF_LEN as u128, (SEQ_REF_LEN - 1) as u128],
            )?,
            checked_distance_product(
                "sequential evaluation local-MI",
                &[SEQ_EVAL_LEN as u128, SEQ_REF_LEN as u128],
            )?,
        ],
    )?;
    let local_work = checked_distance_product(
        "sequential local-MI",
        &[trials as u128, arms, local_per_stream],
    )?;
    checked_distance_sum("sequential distance-comparison", &[window_work, local_work])
}

fn enforce_distance_work(label: &str, work: u128, limit: u128) -> Result<()> {
    if work > limit {
        return Err(GaladrielError::InvalidConfig(format!(
            "{label} work estimate {work} exceeds limit {limit}; reduce trials or samples"
        ))
        .into());
    }
    Ok(())
}

fn validate_ksg_work(trials: usize, n: usize, report_count: usize) -> Result<()> {
    enforce_distance_work(
        "KSG distance-comparison",
        ksg_work(trials, n, report_count)?,
        MAX_DISTANCE_COMPARISONS,
    )
}

fn validate_pid2_work(trials: usize, n: usize, report_count: usize) -> Result<()> {
    enforce_distance_work(
        "PID2 distance-comparison",
        pid2_work(trials, n, report_count)?,
        MAX_DISTANCE_COMPARISONS,
    )
}

fn validate_bootstrap_work(class_len: usize, n_boot: usize, ci_count: usize) -> Result<()> {
    enforce_work(
        "AUC bootstrap",
        bootstrap_work(class_len, n_boot, ci_count)?,
        MAX_BOOTSTRAP_AUC_COMPARISONS,
    )
}

fn validate_sequential_work(trials: usize) -> Result<()> {
    enforce_distance_work(
        "sequential distance-comparison",
        sequential_distance_work(trials)?,
        MAX_DISTANCE_COMPARISONS,
    )
}

fn validate_study(trials: usize, n: usize, sigma: Option<f64>) -> Result<()> {
    if !(MIN_TRIALS..=MAX_TRIALS).contains(&trials) {
        return Err(GaladrielError::InvalidConfig(format!(
            "study trials must be in {MIN_TRIALS}..={MAX_TRIALS}"
        ))
        .into());
    }
    if !(8..=MAX_SAMPLES).contains(&n) {
        return Err(GaladrielError::InvalidConfig(format!(
            "study samples must be in 8..={MAX_SAMPLES}"
        ))
        .into());
    }
    if let Some(sigma) = sigma {
        if !sigma.is_finite() || sigma <= 0.0 || sigma > 1_000_000.0 {
            return Err(GaladrielError::InvalidConfig(
                "study sigma must be finite and in (0, 1_000_000]".into(),
            )
            .into());
        }
    }
    Ok(())
}

fn checked_sum(label: &str, values: &[usize]) -> Result<usize> {
    values
        .iter()
        .try_fold(0usize, |total, &value| {
            total.checked_add(value).ok_or_else(|| {
                GaladrielError::InvalidConfig(format!("{label} work estimate overflowed"))
            })
        })
        .map_err(Into::into)
}

/// Validate the complete default command-line study suite before any simulation starts.
///
/// This catches configurations that are individually well-formed but whose aggregate
/// quadratic neighbour-distance or AUC-bootstrap work would exceed the CLI resource budget.
pub fn preflight_default_suite(trials: usize) -> Result<()> {
    validate_study(trials, 400, Some(0.5))?;
    let synergy_trials = trials.min(250);
    let sequential_trials = trials.min(100);
    validate_study(synergy_trials, 600, None)?;
    validate_study(sequential_trials, SEQ_REF_LEN + SEQ_EVAL_LEN, Some(0.5))?;

    let distance_total = checked_distance_sum(
        "default CLI distance-comparison",
        &[
            ksg_work(trials, 400, 4)?,
            pid2_work(synergy_trials, 600, 2)?,
            checked_distance_product(
                "default CLI sequential",
                &[2, sequential_distance_work(sequential_trials)?],
            )?,
        ],
    )?;
    enforce_distance_work(
        "default CLI distance-comparison",
        distance_total,
        MAX_CLI_DISTANCE_COMPARISONS,
    )?;

    let bootstrap_total = checked_sum(
        "default CLI bootstrap",
        &[
            bootstrap_work(trials, N_BOOT, 4)?,
            bootstrap_work(synergy_trials, N_BOOT, 4)?,
            bootstrap_work(synergy_trials, N_BOOT, 4)?,
        ],
    )?;
    enforce_work(
        "default CLI AUC bootstrap",
        bootstrap_total,
        MAX_CLI_BOOTSTRAP_AUC_COMPARISONS,
    )
}

/// Generate a coupled `(X, Y)` pair. The decoupled control (in [`run`]) is a
/// permutation of `Y` — a **random-permutation control** with the identical finite
/// marginal multiset. Conditional rows are exchangeable rather than independent;
/// the comparison avoids a marginal-shape difference that would otherwise hand
/// correlation spurious power.
fn gen_coupled(
    coupling: Coupling,
    n: usize,
    sigma: f64,
    rng: &mut StdRng,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let std_normal = Normal::new(0.0, 1.0).map_err(|error| {
        GaladrielError::InvalidConfig(format!("invalid standard normal: {error}"))
    })?;
    let noise = Normal::new(0.0, sigma)
        .map_err(|error| GaladrielError::InvalidConfig(format!("invalid sigma: {error}")))?;
    let x: Vec<f64> = (0..n).map(|_| std_normal.sample(rng)).collect();
    let y: Vec<f64> = x
        .iter()
        .map(|&xi| match coupling {
            Coupling::Linear => xi + noise.sample(rng),
            // Random sign flip: population corr(X, ±X) = 0, but |Y| ≈ |X| so the
            // magnitude dependence is strong and can be visible to MI; correlation can
            // still get finite-sample separation through the variance of sample |ρ|.
            Coupling::Nonlinear => {
                let s = if rng.gen::<bool>() { 1.0 } else { -1.0 };
                xi * s + noise.sample(rng)
            }
        })
        .collect();
    Ok((x, y))
}

/// ROC-AUC via the Mann–Whitney identity (ties = ½), in `O(n log n)` time.
pub fn auc(pos: &[f64], neg: &[f64]) -> Result<f64> {
    if pos.is_empty() || neg.is_empty() {
        return Err(
            GaladrielError::InvalidChannels("AUC classes must both be non-empty".into()).into(),
        );
    }
    if pos.len() > MAX_TRIALS || neg.len() > MAX_TRIALS {
        return Err(GaladrielError::InvalidChannels(format!(
            "AUC classes accept at most {MAX_TRIALS} observations each"
        ))
        .into());
    }
    if !pos.iter().chain(neg).all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("AUC score").into());
    }
    let capacity = pos.len().checked_add(neg.len()).ok_or_else(|| {
        GaladrielError::InvalidChannels("combined AUC class length overflows usize".into())
    })?;
    let mut ranked = Vec::new();
    ranked.try_reserve_exact(capacity).map_err(|_| {
        GaladrielError::InvalidChannels(format!(
            "could not reserve {capacity} ranked AUC observations"
        ))
    })?;
    ranked.extend(pos.iter().copied().map(|score| (score, true)));
    ranked.extend(neg.iter().copied().map(|score| (score, false)));
    ranked.sort_by(|left, right| left.0.total_cmp(&right.0));

    let (mut index, mut negatives_before, mut wins) = (0usize, 0usize, 0.0_f64);
    while index < ranked.len() {
        let mut end = index + 1;
        while end < ranked.len() && ranked[end].0 == ranked[index].0 {
            end += 1;
        }
        let positives = ranked[index..end]
            .iter()
            .filter(|(_, positive)| *positive)
            .count();
        let negatives = end - index - positives;
        wins += positives as f64 * (negatives_before as f64 + 0.5 * negatives as f64);
        negatives_before += negatives;
        index = end;
    }
    Ok(wins / (pos.len() as f64 * neg.len() as f64))
}

/// Bootstrap resamples for the CIs.
const N_BOOT: usize = 500;

/// Paired percentile-bootstrap 95% CI for an AUC.
///
/// `pos[i]` and `neg[i]` must be the coupled and control scores from the same generated
/// trial. Resampling trial indices preserves that dependence instead of pretending the
/// permutation-null control is an independently generated class.
pub fn auc_ci(pos: &[f64], neg: &[f64], n_boot: usize, seed: u64) -> Result<(f64, f64)> {
    if !(MIN_BOOTSTRAP_RESAMPLES..=100_000).contains(&n_boot) {
        return Err(GaladrielError::InvalidConfig(format!(
            "AUC bootstrap count must be in {MIN_BOOTSTRAP_RESAMPLES}..=100000"
        ))
        .into());
    }
    if pos.len() != neg.len() {
        return Err(GaladrielError::InvalidChannels(
            "paired AUC bootstrap classes must have equal lengths".into(),
        )
        .into());
    }
    if pos.len() > MAX_TRIALS {
        return Err(GaladrielError::InvalidChannels(format!(
            "paired AUC bootstrap accepts at most {MAX_TRIALS} trial pairs"
        ))
        .into());
    }
    if pos.len() < MIN_TRIALS {
        return Err(GaladrielError::InvalidChannels(format!(
            "paired AUC bootstrap requires at least {MIN_TRIALS} trial pairs"
        ))
        .into());
    }
    if !pos.iter().chain(neg).all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("AUC score").into());
    }
    validate_bootstrap_work(pos.len(), n_boot, 1)?;
    let mut rng = StdRng::seed_from_u64(seed ^ AUC_BOOTSTRAP_SEED_XOR);
    let mut aucs = Vec::with_capacity(n_boot);
    let (mut rp, mut rn) = (vec![0.0; pos.len()], vec![0.0; neg.len()]);
    for _ in 0..n_boot {
        for (p, n) in rp.iter_mut().zip(&mut rn) {
            let index = rng.gen_range(0..pos.len());
            *p = pos[index];
            *n = neg[index];
        }
        aucs.push(auc(&rp, &rn)?);
    }
    aucs.sort_by(f64::total_cmp);
    let pick =
        |q: f64| aucs[((q * (aucs.len() as f64 - 1.0)).round() as usize).min(aucs.len() - 1)];
    Ok((pick(0.025), pick(0.975)))
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len().max(1) as f64
}

/// Per-coupling comparison of the two detectors.
#[derive(Debug, Clone)]
pub struct CouplingResult {
    /// Which coupling.
    pub coupling: Coupling,
    /// Correlation detector ROC-AUC (coupled vs decoupled).
    pub corr_auc: f64,
    /// Bootstrap 95% CI for `corr_auc`.
    pub corr_auc_ci: (f64, f64),
    /// MI detector ROC-AUC (coupled vs decoupled).
    pub mi_auc: f64,
    /// Bootstrap 95% CI for `mi_auc`.
    pub mi_auc_ci: (f64, f64),
    /// Mean `|ρ|` on the coupled pairs (shows correlation's blindness when ≈ 0).
    pub corr_coupled_mean: f64,
    /// Mean MI (nats) on the coupled pairs.
    pub mi_coupled_mean: f64,
}

/// The full study.
#[derive(Debug, Clone)]
pub struct Study {
    /// Trials per class.
    pub trials: usize,
    /// Samples per pair.
    pub n: usize,
    /// Coupling-noise standard deviation.
    pub sigma: f64,
    /// Root random seed.
    pub seed: u64,
    /// One result per coupling.
    pub results: Vec<CouplingResult>,
}

/// Run the study.
pub fn run(trials: usize, n: usize, sigma: f64, seed: u64) -> Result<Study> {
    validate_study(trials, n, Some(sigma))?;
    // Two couplings, each with one coupled and one control KSG estimate per trial.
    validate_ksg_work(trials, n, 4)?;
    validate_bootstrap_work(trials, N_BOOT, 4)?;
    let results = Coupling::ALL
        .iter()
        .map(|&coupling| -> Result<CouplingResult> {
            let mut rng = StdRng::seed_from_u64(seed.wrapping_add(coupling as u64 + 1));
            let (mut cp, mut cn, mut mp, mut mn) = (vec![], vec![], vec![], vec![]);
            for trial in 0..trials {
                let (x, yc) = gen_coupled(coupling, n, sigma, &mut rng)?;
                let mut yd = yc.clone();
                // Same finite marginal multiset; conditional rows are exchangeable,
                // not an independently resampled population law.
                yd.shuffle(&mut rng);
                cp.push(abs_pearson(&x, &yc)?);
                cn.push(abs_pearson(&x, &yd)?);
                let trial_seed = seed
                    ^ (coupling as u64).wrapping_mul(0x9E37_79B9)
                    ^ (trial as u64).wrapping_mul(0xD1B5_4A32_D192_ED03);
                mp.push(ksg(
                    trial_seed ^ 0x00C0_A1ED,
                    &x,
                    &yc,
                    "Independent and identically distributed rows from one fixed synthetic coupled law.",
                )?);
                mn.push(ksg(
                    trial_seed ^ 0xDEC0_A1ED,
                    &x,
                    &yd,
                    "Finite-sample without-replacement permutation control. Rows are exchangeable but not independent after conditioning on the generated vectors. The KSG value is a descriptive randomization-control score, not an i.i.d. population estimate.",
                )?);
            }
            Ok(CouplingResult {
                coupling,
                corr_auc: auc(&cp, &cn)?,
                corr_auc_ci: auc_ci(&cp, &cn, N_BOOT, seed.wrapping_add(coupling as u64))?,
                mi_auc: auc(&mp, &mn)?,
                mi_auc_ci: auc_ci(&mp, &mn, N_BOOT, seed.wrapping_add(100 + coupling as u64))?,
                corr_coupled_mean: mean(&cp),
                mi_coupled_mean: mean(&mp),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Study {
        trials,
        n,
        sigma,
        seed,
        results,
    })
}

/// Format the study as a plain-text report.
pub fn format_report(s: &Study) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Pairwise MI vs correlation study: {} paired trials · n={} · sigma={} · seed={}\n",
        s.trials, s.n, s.sigma, s.seed
    ));
    out.push_str(
        "Detector ROC-AUC at separating a coupled pair from its random-permutation control:\n\n",
    );
    out.push_str(&format!(
        "{:<26} | {:>8} | {:>8} | {:>19} | {:>19}\n",
        "coupling", "|rho| mn", "MI nats", "corr AUC [95% CI]", "MI AUC [95% CI]"
    ));
    out.push_str(&format!("{}\n", "-".repeat(91)));
    for r in &s.results {
        out.push_str(&format!(
            "{:<26} | {:>8.3} | {:>8.3} | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}]\n",
            r.coupling.label(),
            r.corr_coupled_mean,
            r.mi_coupled_mean,
            r.corr_auc,
            r.corr_auc_ci.0,
            r.corr_auc_ci.1,
            r.mi_auc,
            r.mi_auc_ci.0,
            r.mi_auc_ci.1,
        ));
    }
    out.push_str(
        "\nPopulation context: linear-Gaussian MI is monotone in |rho|, while the nonlinear\n\
         construction has zero population correlation but nonzero dependence. The rows are\n\
         finite simulation estimates for these constructions, not deployment calibration.\n\
         Percentile CIs use a paired trial bootstrap; they are not CIs for an AUC difference.\n",
    );
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 2 — joint dependence and a measure-relative categorical PID allocation.
//
// A, B are independent bits; the target T = A XOR B. In this system every pairwise
// *population* marginal — (A,T), (B,T), (A,B) — is exactly the independent-uniform
// distribution (MI(A;T) = MI(B;T) = 0), yet A and B JOINTLY determine T. So no
// statistic of any single channel pair carries population-level signal; the attack
// lives wholly in the triple, and only a joint measure can see it. Two joint
// detectors are measured:
//
// 1. The nonparametric joint-information contrast
//        Q = MI(A,B;T) − max(MI(A;T), MI(B;T)) = Syn + min(Un_A, Un_B)
//    (the identity holds for ANY redundancy-based two-source PID — it is lattice
//    algebra, independent of the redundancy measure). How tight Q is against the
//    synergy atom is measure-dependent: under Williams–Beer's I_min, XOR decomposes
//    as (Red, U_A, U_B, Syn) = (0, 0, 0, 1) bit and Q is tight; under the
//    shared-exclusions (SxPID / i^sx) decomposition this project actually ships,
//    XOR decomposes as (log₂(2/3), +0.585, +0.585, log₂(4/3)) ≈
//    (−0.585, +0.585, +0.585, +0.415) bits — negative (misinformative) redundancy
//    and non-vanishing unique atoms — so Q = 0.415 + 0.585 = 1 bit over-counts the
//    SxPID synergy atom. (Q ≥ Syn is itself only guaranteed when the unique atoms
//    are non-negative, which SxPID does not promise in general.)
//
// 2. The **categorical SxPID synergy atom itself** (Makkeh–Gutknecht–Wibral 2021), computed
//    by `pid_core::discrete_sxpid2_with_budget` on the empirical distribution. This is a diagnostic
//    estimator study. Galadriel's optional in-process/library companion is a pairwise-MI graph,
//    not PID, and cannot turn a pure-synergy atom into an operational verdict.
// ─────────────────────────────────────────────────────────────────────────────

use pid_core::stable::categorical::{discrete_sxpid2_with_budget, DiscreteSxPid2Result};
use std::f64::consts::LN_2;

fn categorical_report_scores(report: &DiscreteSxPid2Result) -> (f64, f64, f64, f64) {
    let pairwise_mi = report.mi_s1_t.max(report.mi_s2_t) / LN_2;
    (
        pairwise_mi,
        report.mi_s1s2_t / LN_2 - pairwise_mi,
        report.syn.net_nats() / LN_2,
        report.red.net_nats() / LN_2,
    )
}

fn same_f64(left: f64, right: f64) -> bool {
    left.to_bits() == right.to_bits()
}

fn same_interval(left: (f64, f64), right: (f64, f64)) -> bool {
    same_f64(left.0, right.0) && same_f64(left.1, right.1)
}

/// ROC-AUC of each detector at separating the coupled `T = A⊕B` from a decoupled `T`.
#[derive(Debug, Serialize)]
pub struct CategoricalXorJustificationResult {
    /// Versioned aggregate/result serialization schema.
    schema: &'static str,
    /// Complete typed categorical MGW question and fixed dependency selection.
    pid_question: PidQuestionSpec,
    /// Reconciled build/source identity of the pid-core package that executed this study.
    pid_execution_identity: PidExecutionIdentity,
    /// Explicit single-call resource ceiling used by every pid-core evaluation.
    pid_resource_contract: PidStudyResourceContract,
    /// Typed identities for every non-PID comparator/composition row.
    study_protocol: JustificationStudyProtocol,
    /// Paired coupled/control trials.
    trials: usize,
    /// Samples per trial.
    n: usize,
    /// Root random seed.
    seed: u64,
    /// Correlation detector AUC (`max |ρ(A,T)|, |ρ(B,T)|`).
    corr_auc: f64,
    /// Bootstrap 95% CI for `corr_auc`.
    corr_auc_ci: (f64, f64),
    /// Pairwise-MI detector AUC (`max MI(A;T), MI(B;T)`).
    pairwise_mi_auc: f64,
    /// Bootstrap 95% CI for `pairwise_mi_auc`.
    pairwise_mi_auc_ci: (f64, f64),
    /// Project-defined joint contrast `Q` AUC; this is not a PID synergy atom.
    q_auc: f64,
    /// Bootstrap 95% CI for `q_auc`.
    q_auc_ci: (f64, f64),
    /// Mean joint contrast `Q` (bits) on the coupled class (≈ 1 for XOR).
    q_coupled_mean: f64,
    /// Diagnostic SxPID synergy-atom score AUC (`i^sx` decomposition).
    sxpid_syn_auc: f64,
    /// Bootstrap 95% CI for `sxpid_syn_auc`.
    sxpid_syn_auc_ci: (f64, f64),
    /// Mean SxPID synergy atom (bits) on the coupled class (≈ log₂(4/3) ≈ 0.415 for XOR).
    sxpid_syn_coupled_mean: f64,
    /// Mean SxPID redundancy atom (bits) on the coupled class (≈ log₂(2/3) ≈ −0.585 for
    /// XOR — negative, i.e. *misinformative* sharing; never clamped).
    sxpid_red_coupled_mean: f64,
    /// Every complete upstream categorical result used by the aggregate rows.
    pid_trials: Vec<CategoricalPidTrialEvidence>,
}

impl CategoricalXorJustificationResult {
    pub const fn schema(&self) -> &'static str {
        self.schema
    }
    /// Complete estimand and provenance record for the categorical PID rows.
    pub const fn pid_question(&self) -> &PidQuestionSpec {
        &self.pid_question
    }
    /// Build-context receipt kept separate from the fixed scientific question.
    pub const fn pid_execution_identity(&self) -> &PidExecutionIdentity {
        &self.pid_execution_identity
    }
    /// Per-call evaluator ceiling, separate from aggregate study preflight.
    pub const fn pid_resource_contract(&self) -> PidStudyResourceContract {
        self.pid_resource_contract
    }
    /// Identities and provenance of Pearson, pairwise MI, and `Q` rows.
    pub const fn study_protocol(&self) -> &JustificationStudyProtocol {
        &self.study_protocol
    }
    pub const fn trials(&self) -> usize {
        self.trials
    }
    pub const fn samples_per_trial(&self) -> usize {
        self.n
    }
    pub const fn seed(&self) -> u64 {
        self.seed
    }
    pub const fn corr_auc(&self) -> f64 {
        self.corr_auc
    }
    pub const fn corr_auc_ci(&self) -> (f64, f64) {
        self.corr_auc_ci
    }
    pub const fn pairwise_mi_auc(&self) -> f64 {
        self.pairwise_mi_auc
    }
    pub const fn pairwise_mi_auc_ci(&self) -> (f64, f64) {
        self.pairwise_mi_auc_ci
    }
    pub const fn q_auc(&self) -> f64 {
        self.q_auc
    }
    pub const fn q_auc_ci(&self) -> (f64, f64) {
        self.q_auc_ci
    }
    pub const fn q_coupled_mean(&self) -> f64 {
        self.q_coupled_mean
    }
    pub const fn sxpid_syn_auc(&self) -> f64 {
        self.sxpid_syn_auc
    }
    pub const fn sxpid_syn_auc_ci(&self) -> (f64, f64) {
        self.sxpid_syn_auc_ci
    }
    pub const fn sxpid_syn_coupled_mean(&self) -> f64 {
        self.sxpid_syn_coupled_mean
    }
    pub const fn sxpid_red_coupled_mean(&self) -> f64 {
        self.sxpid_red_coupled_mean
    }
    /// Complete produced categorical reports, one coupled/control pair per trial.
    pub fn pid_trials(&self) -> &[CategoricalPidTrialEvidence] {
        &self.pid_trials
    }

    /// Recompute every PID-report-derived aggregate and compare it bit-for-bit
    /// with the sealed serialized summary.
    ///
    /// Pearson rows are outside the retained PID reports and are therefore not
    /// covered by this verifier.
    pub fn verifies_report_derived_aggregates(&self) -> Result<bool> {
        if self.pid_trials.len() != self.trials
            || self.pid_trials.iter().enumerate().any(|(index, trial)| {
                trial.trial_index != index || trial.units != PidInformationUnits::Nats
            })
        {
            return Ok(false);
        }
        let mut pairwise_coupled = Vec::with_capacity(self.trials);
        let mut pairwise_control = Vec::with_capacity(self.trials);
        let mut q_coupled = Vec::with_capacity(self.trials);
        let mut q_control = Vec::with_capacity(self.trials);
        let mut synergy_coupled = Vec::with_capacity(self.trials);
        let mut synergy_control = Vec::with_capacity(self.trials);
        let mut redundancy_coupled = Vec::with_capacity(self.trials);
        for trial in &self.pid_trials {
            let (pairwise_c, q_c, synergy_c, redundancy_c) =
                categorical_report_scores(&trial.coupled);
            let (pairwise_d, q_d, synergy_d, _) =
                categorical_report_scores(&trial.permutation_control);
            pairwise_coupled.push(pairwise_c);
            pairwise_control.push(pairwise_d);
            q_coupled.push(q_c);
            q_control.push(q_d);
            synergy_coupled.push(synergy_c);
            synergy_control.push(synergy_d);
            redundancy_coupled.push(redundancy_c);
        }

        Ok(same_f64(
            self.pairwise_mi_auc,
            auc(&pairwise_coupled, &pairwise_control)?,
        ) && same_interval(
            self.pairwise_mi_auc_ci,
            auc_ci(
                &pairwise_coupled,
                &pairwise_control,
                N_BOOT,
                self.seed.wrapping_add(2),
            )?,
        ) && same_f64(self.q_auc, auc(&q_coupled, &q_control)?)
            && same_interval(
                self.q_auc_ci,
                auc_ci(&q_coupled, &q_control, N_BOOT, self.seed.wrapping_add(3))?,
            )
            && same_f64(self.q_coupled_mean, mean(&q_coupled))
            && same_f64(self.sxpid_syn_auc, auc(&synergy_coupled, &synergy_control)?)
            && same_interval(
                self.sxpid_syn_auc_ci,
                auc_ci(
                    &synergy_coupled,
                    &synergy_control,
                    N_BOOT,
                    self.seed.wrapping_add(4),
                )?,
            )
            && same_f64(self.sxpid_syn_coupled_mean, mean(&synergy_coupled))
            && same_f64(self.sxpid_red_coupled_mean, mean(&redundancy_coupled)))
    }
}

/// Complete categorical MGW outputs retained for one paired trial.
#[derive(Debug, Serialize)]
pub struct CategoricalPidTrialEvidence {
    trial_index: usize,
    /// Native units of both retained pid-core categorical results.
    units: PidInformationUnits,
    coupled: DiscreteSxPid2Result,
    permutation_control: DiscreteSxPid2Result,
}

impl CategoricalPidTrialEvidence {
    pub const fn trial_index(&self) -> usize {
        self.trial_index
    }
    pub const fn units(&self) -> PidInformationUnits {
        self.units
    }
    pub const fn coupled(&self) -> &DiscreteSxPid2Result {
        &self.coupled
    }
    pub const fn permutation_control(&self) -> &DiscreteSxPid2Result {
        &self.permutation_control
    }
}

/// Complete categorical MGW result for a binary `(s1, s2, t)` triple, via the
/// exact plug-in `discrete_sxpid2_with_budget` on the empirical distribution (2 bins is lossless for
/// 0/1 data). The returned pid-core result remains in its native nats.
fn sxpid_result(
    s1: &[f64],
    s2: &[f64],
    t: &[f64],
    budget: ResourceBudget,
) -> Result<DiscreteSxPid2Result> {
    let n = s1.len();
    let col = |values: &[f64]| {
        let labels = values
            .iter()
            .map(|value| match *value {
                0.0 => Ok(0),
                1.0 => Ok(1),
                _ => Err(GaladrielError::InvalidChannels(
                    "SxPID binary study received a non-binary value".into(),
                )
                .into()),
            })
            .collect::<Result<Vec<_>>>()?;
        DiscreteMatOwned::new(labels, n, 1).map_err(pid_error)
    };
    let (a, b, tt) = (col(s1)?, col(s2)?, col(t)?);
    discrete_sxpid2_with_budget(a.as_ref(), b.as_ref(), tt.as_ref(), budget).map_err(pid_error)
}

const MAX_BINARY_TRIAL_DRAWS: usize = 32;

fn has_both_binary_values(values: &[u64]) -> bool {
    values.contains(&0) && values.contains(&1)
}

/// Draw a non-degenerate XOR sample. Constant Bernoulli columns are possible at small
/// accepted sample sizes and make Pearson correlation undefined, so retry a bounded
/// number of times rather than randomly aborting an otherwise valid study.
fn gen_xor_trial(n: usize, rng: &mut StdRng) -> Result<(Vec<u64>, Vec<u64>, Vec<u64>)> {
    for _ in 0..MAX_BINARY_TRIAL_DRAWS {
        let a: Vec<u64> = (0..n).map(|_| u64::from(rng.gen::<bool>())).collect();
        let b: Vec<u64> = (0..n).map(|_| u64::from(rng.gen::<bool>())).collect();
        let t: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| x ^ y).collect();
        if has_both_binary_values(&a) && has_both_binary_values(&b) && has_both_binary_values(&t) {
            return Ok((a, b, t));
        }
    }
    Err(GaladrielError::InvalidChannels(format!(
        "XOR trial inconclusive after {MAX_BINARY_TRIAL_DRAWS} degenerate Bernoulli draws"
    ))
    .into())
}

/// Run the synergy study.
pub fn run_categorical_xor_justification(
    trials: usize,
    n: usize,
    seed: u64,
) -> Result<CategoricalXorJustificationResult> {
    validate_study(trials, n, None)?;
    validate_bootstrap_work(trials, N_BOOT, 4)?;
    let pid_execution_identity = pid_execution_identity()?;
    let pid_resource_contract = PidStudyResourceContract::fixed()?;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5259_6E65);
    let (mut cc, mut cd) = (Vec::new(), Vec::new());
    let (mut pc, mut pd) = (Vec::new(), Vec::new());
    let (mut qc, mut qd) = (Vec::new(), Vec::new());
    let (mut xc, mut xd, mut xr) = (Vec::new(), Vec::new(), Vec::new());
    let mut pid_trials = Vec::with_capacity(trials);
    for trial_index in 0..trials {
        let (a, b, t) = gen_xor_trial(n, &mut rng)?;
        let mut td = t.clone();
        // Random-permutation control: same finite target multiset. Conditional on
        // the generated vectors, rows are exchangeable rather than i.i.d.
        td.shuffle(&mut rng);

        let f = |v: &[u64]| v.iter().map(|&x| x as f64).collect::<Vec<f64>>();
        let (af, bf, tf, tdf) = (f(&a), f(&b), f(&t), f(&td));

        cc.push(abs_pearson(&af, &tf)?.max(abs_pearson(&bf, &tf)?));
        cd.push(abs_pearson(&af, &tdf)?.max(abs_pearson(&bf, &tdf)?));

        // Every information-derived comparator is composed from the exact same
        // retained pid-core results as the MGW atoms. This removes a second local
        // entropy implementation and makes provenance/coherence mechanical.
        let coupled_pid = sxpid_result(&af, &bf, &tf, pid_resource_contract.budget())?;
        let control_pid = sxpid_result(&af, &bf, &tdf, pid_resource_contract.budget())?;
        let (pm_c, q_c, syn_c, red_c) = categorical_report_scores(&coupled_pid);
        let (pm_d, q_d, syn_d, _) = categorical_report_scores(&control_pid);
        pc.push(pm_c);
        pd.push(pm_d);

        qc.push(q_c);
        qd.push(q_d);

        // Diagnostic decomposition output: SxPID synergy atom as the study score
        // (and the coupled-class redundancy atom, to exhibit its negative/misinformative
        // value on XOR). Computed after the RNG draws so the rows above are unchanged.
        xc.push(syn_c);
        xd.push(syn_d);
        xr.push(red_c);
        pid_trials.push(CategoricalPidTrialEvidence {
            trial_index,
            units: PidInformationUnits::Nats,
            coupled: coupled_pid,
            permutation_control: control_pid,
        });
    }
    Ok(CategoricalXorJustificationResult {
        schema: CATEGORICAL_PID_STUDY_SCHEMA,
        pid_question: PidQuestionSpec::categorical_xor(),
        pid_execution_identity,
        pid_resource_contract,
        study_protocol: JustificationStudyProtocol::categorical_xor(),
        trials,
        n,
        seed,
        corr_auc: auc(&cc, &cd)?,
        corr_auc_ci: auc_ci(&cc, &cd, N_BOOT, seed.wrapping_add(1))?,
        pairwise_mi_auc: auc(&pc, &pd)?,
        pairwise_mi_auc_ci: auc_ci(&pc, &pd, N_BOOT, seed.wrapping_add(2))?,
        q_auc: auc(&qc, &qd)?,
        q_auc_ci: auc_ci(&qc, &qd, N_BOOT, seed.wrapping_add(3))?,
        q_coupled_mean: mean(&qc),
        sxpid_syn_auc: auc(&xc, &xd)?,
        sxpid_syn_auc_ci: auc_ci(&xc, &xd, N_BOOT, seed.wrapping_add(4))?,
        sxpid_syn_coupled_mean: mean(&xc),
        sxpid_red_coupled_mean: mean(&xr),
        pid_trials,
    })
}

/// Format the synergy study as a plain-text report.
pub fn format_categorical_xor_justification(r: &CategoricalXorJustificationResult) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nSynergy: T = A XOR B vs shuffled T · {} paired trials · n={} · seed={}\n",
        r.trials, r.n, r.seed
    ));
    o.push_str(&format_pid_question(r.pid_question()));
    o.push_str(&format_study_protocol(r.study_protocol()));
    o.push('\n');
    o.push_str(
        "Detector ROC-AUC at telling coupled T = A(+)B from its random-permutation control:\n\n",
    );
    o.push_str(&format!(
        "{:<26} | {:>6} | {:>15}\n",
        "detector", "AUC", "[95% CI]"
    ));
    o.push_str(&format!("{}\n", "-".repeat(54)));
    o.push_str(&format!(
        "{:<26} | {:>6.3} | [{:.3}, {:.3}]\n",
        "correlation (pairwise)", r.corr_auc, r.corr_auc_ci.0, r.corr_auc_ci.1
    ));
    o.push_str(&format!(
        "{:<26} | {:>6.3} | [{:.3}, {:.3}]\n",
        "mutual info (pairwise)", r.pairwise_mi_auc, r.pairwise_mi_auc_ci.0, r.pairwise_mi_auc_ci.1
    ));
    o.push_str(&format!(
        "{:<26} | {:>6.3} | [{:.3}, {:.3}]   (mean {:.3} bits)\n",
        "joint contrast Q (not PID)", r.q_auc, r.q_auc_ci.0, r.q_auc_ci.1, r.q_coupled_mean
    ));
    o.push_str(&format!(
        "{:<26} | {:>6.3} | [{:.3}, {:.3}]   (mean {:.3} bits)\n",
        "SxPID synergy atom (i^sx)",
        r.sxpid_syn_auc,
        r.sxpid_syn_auc_ci.0,
        r.sxpid_syn_auc_ci.1,
        r.sxpid_syn_coupled_mean
    ));
    o.push_str(&format!(
        "\nSxPID atoms on the coupled XOR (exact: syn = log2(4/3) = +0.415, red = log2(2/3)\n\
         = -0.585 bits): measured syn {:+.3}, red {:+.3} — the i^sx decomposition\n\
         reads XOR as unique+synergistic with *misinformative* (negative) sharing, unlike\n\
         Williams-Beer I_min's (0, 0, 0, 1). At the population distribution,\n\
         Q = Syn + min(U1,U2) = 1 bit under either decomposition.\n",
        r.sxpid_syn_coupled_mean, r.sxpid_red_coupled_mean
    ));
    o.push_str(
        "\nPopulation context: every pairwise marginal of this XOR construction is\n\
         independent-uniform, while the triple is dependent. The AUC rows report the\n\
         finite-sample behavior observed in this run. Joint and SxPID scores here are\n\
         diagnostic research outputs; the opt-in in-process pairwise-MI graph does not detect\n\
         pure synergy, and this study does not establish field performance. Degenerate\n\
         binary draws are redrawn, so very-small-n results are conditional on nonconstant\n\
         source and target columns. CIs use a paired trial percentile bootstrap.\n",
    );
    o
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 2b — continuous synergy under the Ehrlich et al. construction.
//
// Study 2's XOR uses the categorical Makkeh–Gutknecht–Wibral functional. The related
// but distinct Ehrlich et al. 2024 continuous construction and kNN estimator need a
// separate estimand and validation question. This study uses the continuous sign-parity
//
//     A, B ~ N(0,1) independent,  T = sign(A)·sign(B)·|Z|,  Z ~ N(0,1) independent.
//
// Exactly as with XOR: every pairwise marginal is independent — T | A ~ N(0,1) for
// every A (the sign flip is a fair coin from B), so MI(A;T) = MI(B;T) = 0 and all
// pairwise correlations are 0 — while jointly sign(T) = sign(A)·sign(B), so
// MI(A,B;T) = ln 2 exactly (the parity bit; |T| ⊥ (A,B) carries nothing more).
// A complete `pid2_isx_report_with_budget` per triple retains the pairwise KSG reports, joint
// KSG report, gauges, assumptions, and the continuous `I^sx` redundancy. It yields
// both the joint contrast
// `Q = MI(A,B;T) − max(MI(A;T), MI(B;T))` and the continuous SxPID synergy atom
// `Syn = MI(A,B;T) − MI(A;T) − MI(B;T) + Red`. These atoms remain diagnostic;
// they are not inputs to the opt-in in-process pairwise-MI graph or the default fusion verdict.
// ─────────────────────────────────────────────────────────────────────────────

/// ROC-AUCs of pairwise vs joint continuous detectors on the sign-parity coupling.
#[derive(Debug, Serialize)]
pub struct ContinuousSignParityJustificationResult {
    /// Versioned aggregate/result serialization schema.
    schema: &'static str,
    /// Complete typed continuous Ehrlich question and fixed dependency selection.
    pid_question: PidQuestionSpec,
    /// Reconciled build/source identity of the pid-core package that executed this study.
    pid_execution_identity: PidExecutionIdentity,
    /// Explicit single-call resource ceiling used by every pid-core evaluation.
    pid_resource_contract: PidStudyResourceContract,
    /// Typed identities for every non-PID comparator/composition row.
    study_protocol: JustificationStudyProtocol,
    /// Paired coupled/control trials.
    trials: usize,
    /// Samples per trial.
    n: usize,
    /// Root random seed.
    seed: u64,
    /// Pairwise correlation detector AUC (`max(|ρ(A,T)|, |ρ(B,T)|)`).
    corr_auc: f64,
    /// Bootstrap 95% CI for `corr_auc`.
    corr_auc_ci: (f64, f64),
    /// Pairwise KSG-MI detector AUC (`max(MI(A;T), MI(B;T))`).
    pairwise_mi_auc: f64,
    /// Bootstrap 95% CI for `pairwise_mi_auc`.
    pairwise_mi_auc_ci: (f64, f64),
    /// Joint contrast `Q` detector AUC.
    q_auc: f64,
    /// Bootstrap 95% CI for `q_auc`.
    q_auc_ci: (f64, f64),
    /// Continuous SxPID synergy-atom detector AUC.
    isx_syn_auc: f64,
    /// Bootstrap 95% CI for `isx_syn_auc`.
    isx_syn_auc_ci: (f64, f64),
    /// Mean joint KSG MI (nats) on the coupled class (exact value: ln 2 ≈ 0.693).
    joint_mi_coupled_mean: f64,
    /// Mean continuous SxPID synergy atom (nats) on the coupled class.
    isx_syn_coupled_mean: f64,
    /// Every complete upstream continuous PID2 report used by the aggregate rows.
    pid_trials: Vec<ContinuousPid2TrialEvidence>,
}

impl ContinuousSignParityJustificationResult {
    pub const fn schema(&self) -> &'static str {
        self.schema
    }
    /// Complete estimand and provenance record for the continuous PID rows.
    pub const fn pid_question(&self) -> &PidQuestionSpec {
        &self.pid_question
    }
    /// Build-context receipt kept separate from the fixed scientific question.
    pub const fn pid_execution_identity(&self) -> &PidExecutionIdentity {
        &self.pid_execution_identity
    }
    /// Per-call evaluator ceiling, separate from aggregate study preflight.
    pub const fn pid_resource_contract(&self) -> PidStudyResourceContract {
        self.pid_resource_contract
    }
    /// Identities and provenance of Pearson, pairwise MI, and `Q` rows.
    pub const fn study_protocol(&self) -> &JustificationStudyProtocol {
        &self.study_protocol
    }
    pub const fn trials(&self) -> usize {
        self.trials
    }
    pub const fn samples_per_trial(&self) -> usize {
        self.n
    }
    pub const fn seed(&self) -> u64 {
        self.seed
    }
    pub const fn corr_auc(&self) -> f64 {
        self.corr_auc
    }
    pub const fn corr_auc_ci(&self) -> (f64, f64) {
        self.corr_auc_ci
    }
    pub const fn pairwise_mi_auc(&self) -> f64 {
        self.pairwise_mi_auc
    }
    pub const fn pairwise_mi_auc_ci(&self) -> (f64, f64) {
        self.pairwise_mi_auc_ci
    }
    pub const fn q_auc(&self) -> f64 {
        self.q_auc
    }
    pub const fn q_auc_ci(&self) -> (f64, f64) {
        self.q_auc_ci
    }
    pub const fn isx_syn_auc(&self) -> f64 {
        self.isx_syn_auc
    }
    pub const fn isx_syn_auc_ci(&self) -> (f64, f64) {
        self.isx_syn_auc_ci
    }
    pub const fn joint_mi_coupled_mean(&self) -> f64 {
        self.joint_mi_coupled_mean
    }
    pub const fn isx_syn_coupled_mean(&self) -> f64 {
        self.isx_syn_coupled_mean
    }
    /// Complete produced continuous reports, one coupled/control pair per trial.
    pub fn pid_trials(&self) -> &[ContinuousPid2TrialEvidence] {
        &self.pid_trials
    }

    /// Recompute every PID2-report-derived aggregate and compare it bit-for-bit
    /// with the sealed serialized summary.
    ///
    /// Pearson rows are outside the retained PID2 reports and are therefore not
    /// covered by this verifier.
    pub fn verifies_report_derived_aggregates(&self) -> Result<bool> {
        if self.pid_trials.len() != self.trials
            || self.pid_trials.iter().enumerate().any(|(index, trial)| {
                trial.trial_index != index || trial.units != PidInformationUnits::Nats
            })
        {
            return Ok(false);
        }
        let mut pairwise_coupled = Vec::with_capacity(self.trials);
        let mut pairwise_control = Vec::with_capacity(self.trials);
        let mut q_coupled = Vec::with_capacity(self.trials);
        let mut q_control = Vec::with_capacity(self.trials);
        let mut synergy_coupled = Vec::with_capacity(self.trials);
        let mut synergy_control = Vec::with_capacity(self.trials);
        let mut joint_coupled = Vec::with_capacity(self.trials);
        for trial in &self.pid_trials {
            let (pairwise_c, q_c, synergy_c, joint_c) = continuous_report_scores(&trial.coupled);
            let (pairwise_d, q_d, synergy_d, _) =
                continuous_report_scores(&trial.permutation_control);
            pairwise_coupled.push(pairwise_c);
            pairwise_control.push(pairwise_d);
            q_coupled.push(q_c);
            q_control.push(q_d);
            synergy_coupled.push(synergy_c);
            synergy_control.push(synergy_d);
            joint_coupled.push(joint_c);
        }

        Ok(same_f64(
            self.pairwise_mi_auc,
            auc(&pairwise_coupled, &pairwise_control)?,
        ) && same_interval(
            self.pairwise_mi_auc_ci,
            auc_ci(
                &pairwise_coupled,
                &pairwise_control,
                N_BOOT,
                self.seed.wrapping_add(12),
            )?,
        ) && same_f64(self.q_auc, auc(&q_coupled, &q_control)?)
            && same_interval(
                self.q_auc_ci,
                auc_ci(&q_coupled, &q_control, N_BOOT, self.seed.wrapping_add(13))?,
            )
            && same_f64(self.isx_syn_auc, auc(&synergy_coupled, &synergy_control)?)
            && same_interval(
                self.isx_syn_auc_ci,
                auc_ci(
                    &synergy_coupled,
                    &synergy_control,
                    N_BOOT,
                    self.seed.wrapping_add(14),
                )?,
            )
            && same_f64(self.joint_mi_coupled_mean, mean(&joint_coupled))
            && same_f64(self.isx_syn_coupled_mean, mean(&synergy_coupled)))
    }
}

/// Complete Ehrlich PID2 outputs retained for one paired trial.
#[derive(Debug, Serialize)]
pub struct ContinuousPid2TrialEvidence {
    trial_index: usize,
    /// Native units of both retained pid-core continuous reports.
    units: PidInformationUnits,
    coupled: Pid2Report,
    permutation_control: Pid2Report,
}

impl ContinuousPid2TrialEvidence {
    pub const fn trial_index(&self) -> usize {
        self.trial_index
    }
    pub const fn units(&self) -> PidInformationUnits {
        self.units
    }
    pub const fn coupled(&self) -> &Pid2Report {
        &self.coupled
    }
    pub const fn permutation_control(&self) -> &Pid2Report {
        &self.permutation_control
    }
}

struct ContinuousScores {
    pairwise_mi: f64,
    q: f64,
    synergy: f64,
    /// The estimator's direct joint-MI output, before any contrast clamping.
    joint_mi: f64,
    report: Pid2Report,
}

fn continuous_report_scores(report: &Pid2Report) -> (f64, f64, f64, f64) {
    let terms = report.estimate_terms;
    let pairwise_mi = terms.mi_s1_t.max(terms.mi_s2_t);
    (
        pairwise_mi,
        terms.mi_s1s2_t - pairwise_mi,
        report.atoms.synergy,
        terms.mi_s1s2_t,
    )
}

/// Continuous scores of one `(A, B, T)` triple from one complete Ehrlich PID2 report.
fn continuous_synergy_scores(
    a: &[f64],
    b: &[f64],
    t: &[f64],
    evaluation_id: u64,
    sampling_model: &str,
    budget: ResourceBudget,
) -> Result<ContinuousScores> {
    let n = a.len();
    let col = |values: &[f64]| MatOwned::new(values.to_vec(), n, 1).map_err(pid_error);
    let (am, bm, tm) = (col(a)?, col(b)?, col(t)?);
    let split_id = format!("continuous-sign-parity-{evaluation_id:016x}");
    let provenance = Pid2Provenance::new(
        "No preprocessing; source A retains its registered standard-normal simulator coordinate and gauge.",
        "No preprocessing; source B retains its registered standard-normal simulator coordinate and gauge.",
        "No preprocessing; target T retains its registered standard-normal simulator coordinate.",
        "Direct binary64 pseudorandom representation of the declared continuous sign-parity law; no deliberate quantization, added noise, or tie-breaking transform.",
    )
    .and_then(|provenance| {
        provenance.with_sampling_model_and_splits(
            sampling_model,
            None,
            Some(&split_id),
        )
    })
    .map_err(pid_error)?;
    let report = pid2_isx_report_with_budget(
        am.as_ref(),
        bm.as_ref(),
        tm.as_ref(),
        &Pid2Config::assume_regular_full_dimensional(),
        &provenance,
        budget,
    )
    .map_err(pid_error)?;
    let (pairwise_mi, q, synergy, joint_mi) = continuous_report_scores(&report);
    Ok(ContinuousScores {
        pairwise_mi,
        q,
        synergy,
        joint_mi,
        report,
    })
}

/// Run the continuous (sign-parity) synergy study.
pub fn run_continuous_sign_parity_justification(
    trials: usize,
    n: usize,
    seed: u64,
) -> Result<ContinuousSignParityJustificationResult> {
    validate_study(trials, n, None)?;
    // Two complete PID2 reports per trial. Preflight composes the 13 triangular
    // pair-distance passes actually executed by each report.
    validate_pid2_work(trials, n, 2)?;
    validate_bootstrap_work(trials, N_BOOT, 4)?;
    let pid_execution_identity = pid_execution_identity()?;
    let pid_resource_contract = PidStudyResourceContract::fixed()?;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x516E_9A21);
    let std_normal = Normal::new(0.0, 1.0).map_err(|error| {
        GaladrielError::InvalidConfig(format!("invalid standard normal: {error}"))
    })?;
    let (mut cc, mut cd) = (Vec::new(), Vec::new()); // pairwise corr
    let (mut pc, mut pd) = (Vec::new(), Vec::new()); // pairwise MI
    let (mut qc, mut qd) = (Vec::new(), Vec::new()); // joint contrast Q
    let (mut xc, mut xd) = (Vec::new(), Vec::new()); // continuous i^sx synergy atom
    let mut joint_mi = Vec::new();
    let mut pid_trials = Vec::with_capacity(trials);
    for trial in 0..trials {
        let a: Vec<f64> = (0..n).map(|_| std_normal.sample(&mut rng)).collect();
        let b: Vec<f64> = (0..n).map(|_| std_normal.sample(&mut rng)).collect();
        let t: Vec<f64> = a
            .iter()
            .zip(&b)
            .map(|(&x, &y)| x.signum() * y.signum() * std_normal.sample(&mut rng).abs())
            .collect();
        let mut td = t.clone();
        // Random-permutation control: same finite target multiset. Conditional on
        // the generated vectors, rows are exchangeable rather than i.i.d.
        td.shuffle(&mut rng);

        cc.push(abs_pearson(&a, &t)?.max(abs_pearson(&b, &t)?));
        cd.push(abs_pearson(&a, &td)?.max(abs_pearson(&b, &td)?));

        let trial_id = seed ^ (trial as u64).wrapping_mul(0xD1B5_4A32_D192_ED03);
        let coupled = continuous_synergy_scores(
            &a,
            &b,
            &t,
            trial_id ^ 0x00C0_A1ED,
            "Independent and identically distributed rows from the fixed continuous sign-parity law.",
            pid_resource_contract.budget(),
        )?;
        let control = continuous_synergy_scores(
            &a,
            &b,
            &td,
            trial_id ^ 0xDEC0_A1ED,
            "Finite-sample without-replacement target permutation control. Rows are exchangeable but not independent after conditioning on the generated vectors. The PID2 atoms are descriptive randomization-control scores, not i.i.d. population estimates.",
            pid_resource_contract.budget(),
        )?;
        pc.push(coupled.pairwise_mi);
        pd.push(control.pairwise_mi);
        qc.push(coupled.q);
        qd.push(control.q);
        xc.push(coupled.synergy);
        xd.push(control.synergy);
        joint_mi.push(coupled.joint_mi);
        pid_trials.push(ContinuousPid2TrialEvidence {
            trial_index: trial,
            units: PidInformationUnits::Nats,
            coupled: coupled.report,
            permutation_control: control.report,
        });
    }
    Ok(ContinuousSignParityJustificationResult {
        schema: CONTINUOUS_PID_STUDY_SCHEMA,
        pid_question: PidQuestionSpec::continuous_sign_parity(),
        pid_execution_identity,
        pid_resource_contract,
        study_protocol: JustificationStudyProtocol::continuous_sign_parity(),
        trials,
        n,
        seed,
        corr_auc: auc(&cc, &cd)?,
        corr_auc_ci: auc_ci(&cc, &cd, N_BOOT, seed.wrapping_add(11))?,
        pairwise_mi_auc: auc(&pc, &pd)?,
        pairwise_mi_auc_ci: auc_ci(&pc, &pd, N_BOOT, seed.wrapping_add(12))?,
        q_auc: auc(&qc, &qd)?,
        q_auc_ci: auc_ci(&qc, &qd, N_BOOT, seed.wrapping_add(13))?,
        isx_syn_auc: auc(&xc, &xd)?,
        isx_syn_auc_ci: auc_ci(&xc, &xd, N_BOOT, seed.wrapping_add(14))?,
        joint_mi_coupled_mean: mean(&joint_mi),
        isx_syn_coupled_mean: mean(&xc),
        pid_trials,
    })
}

/// Format the continuous synergy study as a plain-text report.
pub fn format_continuous_sign_parity_justification(
    r: &ContinuousSignParityJustificationResult,
) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nContinuous synergy: T = sign(A)·sign(B)·|Z| vs shuffled T\n\
         {} paired trials · n={} · seed={} · pid-core continuous estimators (KSG + I^sx):\n\n",
        r.trials, r.n, r.seed,
    ));
    o.push_str(&format_pid_question(r.pid_question()));
    o.push_str(&format_study_protocol(r.study_protocol()));
    o.push('\n');
    o.push_str(&format!(
        "{:<28} | {:>6} | {:>15}\n",
        "detector", "AUC", "[95% CI]"
    ));
    o.push_str(&format!("{}\n", "-".repeat(56)));
    let row = |name: &str, a: f64, ci: (f64, f64)| {
        format!("{:<28} | {:>6.3} | [{:.3}, {:.3}]\n", name, a, ci.0, ci.1)
    };
    o.push_str(&row("correlation (pairwise)", r.corr_auc, r.corr_auc_ci));
    o.push_str(&row(
        "KSG MI (pairwise)",
        r.pairwise_mi_auc,
        r.pairwise_mi_auc_ci,
    ));
    o.push_str(&row("joint contrast Q (KSG)", r.q_auc, r.q_auc_ci));
    o.push_str(&row(
        "I^sx synergy atom (cont.)",
        r.isx_syn_auc,
        r.isx_syn_auc_ci,
    ));
    o.push_str(&format!(
        "\njoint KSG MI on coupled: {:.3} nats (population value: ln 2 = 0.693);\n\
         continuous I^sx synergy atom on coupled: {:.3} nats. Pairwise marginals are\n\
         independent in the population construction; the table reports finite-sample\n\
         estimator behavior. These joint scores are diagnostic and are not used by the\n\
         opt-in in-process pairwise-MI graph or default fusion verdict. CIs use a paired trial\n\
         percentile bootstrap.\n",
        r.joint_mi_coupled_mean, r.isx_syn_coupled_mean
    ));
    o
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 3 — pointwise comparison: sequential detection at a common FAR target.
//
// Studies 1–2 score *windows*; a streaming monitor pays their price in **latency**:
// a trailing window must refill with post-onset frames before a broken coupling is
// legible. Information-theoretic quantities can also be local to a realization. This
// study's local score, however, is a project-defined two-variable kNN log-density-ratio
// heuristic. It is neither the categorical Makkeh–Gutknecht–Wibral functional nor the
// continuous Ehrlich PID estimator. It can be fed to a sequential CUSUM test.
//
// The local kNN term used here is a plug-in estimate inspired by
// log[ p_coupled(x,y) / (p(x)·p(y)) ] — the **log-likelihood ratio** between the
// calibrated coupled regime and the decoupled (independent, same-marginals)
// regime. With known densities, a CUSUM over the true log-LR has classical optimality
// properties. The frozen-reference kNN estimate below is approximate and those
// properties do not transfer automatically.
//
// The forced-vs-justified question then recurs at the pointwise level, and this
// study asks it with five sequential detectors calibrated to one stream-level FAR target:
//
//   window |ρ̂|      — the runtime default's analog (trailing-window refit);
//   window KSG MI    — the windowed MI companion's analog;
//   product CUSUM    — per-frame x·y (the naive cheap pointwise statistic);
//   Gauss-LR CUSUM   — per-frame *parametric* Gaussian log-LR: the closed-form
//                      pointwise MI i(x,y; ρ̂_cal) — "correlation, pointwise";
//   local-MI CUSUM   — per-frame *nonparametric* kNN local-MI against a frozen clean
//                      reference window; metric, k, and calibration choices still matter.
//
// Hypotheses (stated before running):
//   H1 (latency): at the common FAR target, pointwise CUSUM detectors beat the windowed
//      detectors' refill latency on the coupling they can see.
//   H2 (forced, pointwise): on the linear-Gaussian coupling the parametric
//      Gauss-LR CUSUM — a one-line ρ̂ plug-in — is competitive with the kNN
//      local-MI CUSUM; extra estimator complexity may not buy useful latency here.
//   H3 (justified, pointwise): on the sign-flip coupling the product and Gauss-LR
//      CUSUMs are blind (E[xy] = 0 and ρ̂_cal ≈ 0 on *both* sides of onset), while
//      the nonparametric local-MI CUSUM can retain signal — the pointwise analog of §2.
//      (A variance-tracking chart could see this particular construction through
//      its second moment — again a bespoke feature choice, the pointwise echo of
//      §2's kurtosis artifact; the local-MI chart needs no explicit variance feature.)
// ─────────────────────────────────────────────────────────────────────────────

/// Reference/calibration segment length (frames) — frozen as the "clean past".
const SEQ_REF_LEN: usize = 256;
/// Evaluation segment length (frames).
const SEQ_EVAL_LEN: usize = 256;
/// Attack onset, as an index into the evaluation segment.
const SEQ_ONSET: usize = 64;
/// Trailing-window length for the windowed detectors.
const SEQ_WINDOW: usize = 128;
/// Evaluation stride (frames) for the windowed detectors (they are O(W²) per step).
const SEQ_STRIDE: usize = 4;
/// k for the local-MI kNN terms.
const SEQ_K: usize = 3;
/// CUSUM reference drift (in calibrated σ units).
const SEQ_KAPPA: f64 = 0.25;
/// Target stream-level false-alarm rate used to calibrate each threshold.
const SEQ_FAR: f64 = 0.05;

/// The five sequential detectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqDetector {
    /// Trailing-window `|ρ̂|`, alarm when it falls below its calibrated floor.
    WindowCorr,
    /// Trailing-window KSG MI, alarm when it falls below its calibrated floor.
    WindowMi,
    /// CUSUM over the per-frame product `x·y` (downward mean shift).
    ProductCusum,
    /// CUSUM over the per-frame parametric Gaussian log-LR (pointwise Gaussian MI
    /// at the calibration ρ̂) — a cheap detector tailored to the Gaussian model.
    GaussLrCusum,
    /// CUSUM over a project-defined per-frame kNN local-MI score against the frozen
    /// clean reference. This is not a shared-exclusions PID estimator.
    LocalMiCusum,
}

impl SeqDetector {
    /// All detectors, in report order.
    pub const ALL: [SeqDetector; 5] = [
        SeqDetector::WindowCorr,
        SeqDetector::WindowMi,
        SeqDetector::ProductCusum,
        SeqDetector::GaussLrCusum,
        SeqDetector::LocalMiCusum,
    ];

    /// A label.
    pub fn label(self) -> &'static str {
        match self {
            SeqDetector::WindowCorr => "window |rho| (W=128)",
            SeqDetector::WindowMi => "window KSG MI (W=128)",
            SeqDetector::ProductCusum => "product CUSUM (x*y)",
            SeqDetector::GaussLrCusum => "Gauss-LR CUSUM (rho-hat)",
            SeqDetector::LocalMiCusum => "local-MI CUSUM (kNN)",
        }
    }
}

type SeqTrace = Vec<(usize, f64)>;
type DetectorTraces = Vec<(SeqDetector, SeqTrace)>;

/// One detector's row in the sequential study.
#[derive(Debug, Clone)]
pub struct SeqRow {
    /// Which detector.
    pub detector: SeqDetector,
    /// Fraction of independent clean *holdout* streams that alarmed anywhere in the
    /// eval segment. These streams are not used to calibrate the threshold.
    pub realized_far: f64,
    /// Wilson score 95% interval for `realized_far` on the clean holdout arm.
    pub realized_far_ci: (f64, f64),
    /// Fraction of *attacked* streams that alarmed **before** onset (false starts).
    pub false_start: f64,
    /// Fraction of attacked streams (without a false start) alarming at/after onset.
    pub reach: f64,
    /// Median frames from onset to first alarm, among reaching trials
    /// (windowed detectors are quantized to the `SEQ_STRIDE`-frame grid).
    pub median_latency: Option<f64>,
}

/// The sequential (pointwise) study for one coupling.
#[derive(Debug, Clone)]
pub struct SeqStudy {
    /// Which coupling.
    pub coupling: Coupling,
    /// Trials per arm (clean calibration, clean holdout, and attacked).
    pub trials: usize,
    /// Coupling-noise standard deviation.
    pub sigma: f64,
    /// Root random seed.
    pub seed: u64,
    /// One row per detector.
    pub rows: Vec<SeqRow>,
}

/// Digamma via the standard shift-and-asymptotic-series recipe (|err| ≪ 1e-10 for x > 0).
fn digamma(mut x: f64) -> f64 {
    let mut r = 0.0;
    while x < 6.0 {
        r -= 1.0 / x;
        x += 1.0;
    }
    let inv = 1.0 / x;
    let inv2 = inv * inv;
    r + x.ln() - 0.5 * inv - inv2 * (1.0 / 12.0 - inv2 * (1.0 / 120.0 - inv2 / 252.0))
}

/// Pointwise MI of a *standardized* bivariate Gaussian at correlation `r` (nats):
/// `i(a,b) = −½ln(1−r²) − (r²(a²+b²) − 2rab) / (2(1−r²))` — the closed-form log-LR
/// between the coupled and independent hypotheses with N(0,1) marginals.
fn pointwise_gaussian_mi(a: f64, b: f64, r: f64) -> f64 {
    let r2 = r * r;
    if r2 >= 1.0 {
        return 0.0;
    }
    -0.5 * (1.0 - r2).ln() - (r2 * (a * a + b * b) - 2.0 * r * a * b) / (2.0 * (1.0 - r2))
}

/// KSG-style local MI term of query `(qx, qy)` against a frozen reference sample,
/// Chebyshev metric, strict counting: `ψ(k) + ψ(N) − ψ(n_x+1) − ψ(n_y+1)`.
fn local_mi_query(rx: &[f64], ry: &[f64], qx: f64, qy: f64, k: usize) -> Result<f64> {
    let n = rx.len();
    let mut joint: Vec<f64> = (0..n)
        .map(|j| (rx[j] - qx).abs().max((ry[j] - qy).abs()))
        .collect();
    let kth = k - 1;
    joint.select_nth_unstable_by(kth, |a, b| a.total_cmp(b));
    let eps = joint[kth];
    if eps <= 0.0 {
        return Err(GaladrielError::InvalidChannels(
            "local-MI query has an ambiguous zero-radius kth-neighbor shell".into(),
        )
        .into());
    }
    let (mut nx, mut ny) = (0usize, 0usize);
    for j in 0..n {
        if (rx[j] - qx).abs() < eps {
            nx += 1;
        }
        if (ry[j] - qy).abs() < eps {
            ny += 1;
        }
    }
    Ok(digamma(k as f64) + digamma(n as f64) - digamma((nx + 1) as f64) - digamma((ny + 1) as f64))
}

/// In-sample KSG local MI terms of the reference itself (self excluded) — used only
/// to standardize the CUSUM increments; the same convention offsets appear in the
/// clean calibration streams, so they cancel in the threshold.
fn local_mi_ref_terms(rx: &[f64], ry: &[f64], k: usize) -> Result<Vec<f64>> {
    let n = rx.len();
    (0..n)
        .map(|i| {
            let (xs, ys): (Vec<f64>, Vec<f64>) =
                (0..n).filter(|&j| j != i).map(|j| (rx[j], ry[j])).unzip();
            local_mi_query(&xs, &ys, rx[i], ry[i], k)
        })
        .collect()
}

/// Generate one full `(x, y)` stream of length `SEQ_REF_LEN + SEQ_EVAL_LEN`.
/// Coupled throughout if `attacked` is false; if true, `y` decouples from
/// `SEQ_REF_LEN + SEQ_ONSET` onward onto an independent stream with the *same*
/// marginal (a moment-matched decoupling — the §1/§2 spoof, sequential form).
fn gen_seq_stream(
    coupling: Coupling,
    sigma: f64,
    attacked: bool,
    rng: &mut StdRng,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let total = SEQ_REF_LEN + SEQ_EVAL_LEN;
    let onset = SEQ_REF_LEN + SEQ_ONSET;
    let std_normal = Normal::new(0.0, 1.0).map_err(|error| {
        GaladrielError::InvalidConfig(format!("invalid standard normal: {error}"))
    })?;
    let noise = Normal::new(0.0, sigma)
        .map_err(|error| GaladrielError::InvalidConfig(format!("invalid sigma: {error}")))?;
    let mut xs = Vec::with_capacity(total);
    let mut ys = Vec::with_capacity(total);
    for t in 0..total {
        let x = std_normal.sample(rng);
        // The channel under test: coupled to x, or (post-onset) to a fresh
        // independent latent x' — identical marginal, dependence gone.
        let base = if attacked && t >= onset {
            std_normal.sample(rng)
        } else {
            x
        };
        let y = match coupling {
            Coupling::Linear => base + noise.sample(rng),
            Coupling::Nonlinear => {
                let s = if rng.gen::<bool>() { 1.0 } else { -1.0 };
                base * s + noise.sample(rng)
            }
        };
        xs.push(x);
        ys.push(y);
    }
    Ok((xs, ys))
}

/// Per-stream detector traces over the eval segment: for each detector, the frames
/// (eval-segment indices) at which its statistic is *available*, and the statistic
/// value oriented so that **larger = more anomalous** (windowed scores are negated).
fn seq_traces(seed: u64, xs: &[f64], ys: &[f64]) -> Result<DetectorTraces> {
    let required = SEQ_REF_LEN + SEQ_EVAL_LEN;
    if xs.len() != required || ys.len() != required {
        return Err(GaladrielError::InvalidChannels(format!(
            "sequential traces require exactly {required} samples per channel"
        ))
        .into());
    }
    if !xs.iter().chain(ys).all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("sequential study input").into());
    }
    let onset_abs = SEQ_REF_LEN;
    let (rx, ry) = (&xs[..SEQ_REF_LEN], &ys[..SEQ_REF_LEN]);

    // Calibration statistics from the frozen reference segment.
    let stats = |v: &[f64]| {
        let n = v.len() as f64;
        let m = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / n;
        (m, var.sqrt().max(1e-12))
    };
    let (mx, sx) = stats(rx);
    let (my, sy) = stats(ry);
    let zx: Vec<f64> = rx.iter().map(|v| (v - mx) / sx).collect();
    let zy: Vec<f64> = ry.iter().map(|v| (v - my) / sy).collect();
    let rho_cal = {
        let r = zx.iter().zip(&zy).map(|(a, b)| a * b).sum::<f64>() / zx.len() as f64;
        r.clamp(-0.999, 0.999)
    };
    let prod_cal: Vec<f64> = zx.iter().zip(&zy).map(|(a, b)| a * b).collect();
    let (mp, sp) = stats(&prod_cal);
    let glr_cal: Vec<f64> = zx
        .iter()
        .zip(&zy)
        .map(|(&a, &b)| pointwise_gaussian_mi(a, b, rho_cal))
        .collect();
    let (mg, sg) = stats(&glr_cal);
    let lmi_cal = local_mi_ref_terms(&zx, &zy, SEQ_K)?;
    let (ml, sl) = stats(&lmi_cal);

    // Windowed detectors (negated: larger = more anomalous), on the stride grid.
    let mut wcorr = Vec::new();
    let mut wmi = Vec::new();
    let mut e = SEQ_STRIDE;
    while e <= SEQ_EVAL_LEN {
        let end = onset_abs + e;
        let (wx, wy) = (&xs[end - SEQ_WINDOW..end], &ys[end - SEQ_WINDOW..end]);
        wcorr.push((e - 1, -abs_pearson(wx, wy)?));
        wmi.push((
            e - 1,
            -ksg(
                seed ^ (e as u64).wrapping_mul(0x9E37_79B9),
                wx,
                wy,
                "Rows are independent within each synthetic regime. A trailing window that crosses the registered onset is not identically distributed. Its KSG value is a descriptive sequential detector score, not a stationary-law estimate.",
            )?,
        ));
        e += SEQ_STRIDE;
    }

    // Pointwise CUSUMs (every frame): S = max(0, S + (μ_cal − stat)/σ_cal − κ).
    let cusum =
        |stat: &dyn Fn(f64, f64) -> Result<f64>, m: f64, s: f64| -> Result<Vec<(usize, f64)>> {
            let mut out = Vec::with_capacity(SEQ_EVAL_LEN);
            let mut acc = 0.0f64;
            for t in 0..SEQ_EVAL_LEN {
                let (a, b) = ((xs[onset_abs + t] - mx) / sx, (ys[onset_abs + t] - my) / sy);
                let z = (m - stat(a, b)?) / s - SEQ_KAPPA;
                acc = (acc + z).max(0.0);
                out.push((t, acc));
            }
            Ok(out)
        };
    let prod = cusum(&|a, b| Ok(a * b), mp, sp)?;
    let glr = cusum(&|a, b| Ok(pointwise_gaussian_mi(a, b, rho_cal)), mg, sg)?;
    let lmi = cusum(&|a, b| local_mi_query(&zx, &zy, a, b, SEQ_K), ml, sl)?;

    Ok(vec![
        (SeqDetector::WindowCorr, wcorr),
        (SeqDetector::WindowMi, wmi),
        (SeqDetector::ProductCusum, prod),
        (SeqDetector::GaussLrCusum, glr),
        (SeqDetector::LocalMiCusum, lmi),
    ])
}

fn clean_seq_maxima(
    coupling: Coupling,
    trials: usize,
    sigma: f64,
    seed: u64,
    domain: u64,
) -> Result<Vec<Vec<f64>>> {
    let mut rng = StdRng::seed_from_u64(seed ^ domain ^ coupling as u64);
    let mut maxima = vec![Vec::with_capacity(trials); SeqDetector::ALL.len()];
    for trial in 0..trials {
        let (xs, ys) = gen_seq_stream(coupling, sigma, false, &mut rng)?;
        let trace_seed = seed ^ domain ^ trial as u64;
        for (di, (_, trace)) in seq_traces(trace_seed, &xs, &ys)?.into_iter().enumerate() {
            let maximum = trace
                .iter()
                .map(|&(_, value)| value)
                .fold(f64::NEG_INFINITY, f64::max);
            maxima[di].push(maximum);
        }
    }
    Ok(maxima)
}

fn wilson95(successes: usize, total: usize) -> Result<(f64, f64)> {
    if total == 0 || successes > total {
        return Err(GaladrielError::InvalidChannels(
            "Wilson interval requires 0 <= successes <= a nonzero total".into(),
        )
        .into());
    }
    const Z: f64 = 1.959_963_984_540_054;
    let n = total as f64;
    let proportion = successes as f64 / n;
    let z2 = Z * Z;
    let denominator = 1.0 + z2 / n;
    let center = (proportion + z2 / (2.0 * n)) / denominator;
    let margin =
        Z * ((proportion * (1.0 - proportion) / n + z2 / (4.0 * n * n)).sqrt()) / denominator;
    Ok(((center - margin).max(0.0), (center + margin).min(1.0)))
}

/// Run the sequential (pointwise) study for one coupling: calibrate every detector's
/// threshold to a common target stream-level FAR on one clean arm, estimate realized
/// FAR on an independent clean holdout arm, then measure false-start / reach / median
/// latency on an attacked arm.
pub fn run_seq(coupling: Coupling, trials: usize, sigma: f64, seed: u64) -> Result<SeqStudy> {
    validate_study(trials, SEQ_REF_LEN + SEQ_EVAL_LEN, Some(sigma))?;
    // Bound both the windowed KSG fits and frozen-reference local-MI distance scans
    // across calibration, clean-holdout, and attacked arms.
    validate_sequential_work(trials)?;
    let n_det = SeqDetector::ALL.len();

    // Calibration arm: per-detector per-stream maximum of the anomaly statistic.
    let calibration_max = clean_seq_maxima(coupling, trials, sigma, seed, 0xCA11_BA7E)?;
    // Matched operating point: each detector's threshold is its own clean-maxima
    // (1 − FAR) quantile — the same stream-level FAR for all five detectors.
    let threshold: Vec<f64> = calibration_max
        .iter()
        .map(|v| {
            let mut s = v.clone();
            s.sort_by(f64::total_cmp);
            let idx =
                (((1.0 - SEQ_FAR) * (s.len() as f64 - 1.0)).round() as usize).min(s.len() - 1);
            s[idx]
        })
        .collect();
    // Independent clean holdout: estimate FAR without reusing threshold-fitting data.
    let holdout_max = clean_seq_maxima(coupling, trials, sigma, seed, 0xC1EA_110D)?;
    let holdout_alarm_count: Vec<usize> = holdout_max
        .iter()
        .zip(&threshold)
        .map(|(values, &threshold)| values.iter().filter(|&&value| value > threshold).count())
        .collect();
    let realized_far: Vec<f64> = holdout_alarm_count
        .iter()
        .map(|&count| count as f64 / trials as f64)
        .collect();
    let realized_far_ci = holdout_alarm_count
        .iter()
        .map(|&count| wilson95(count, trials))
        .collect::<Result<Vec<_>>>()?;

    // Attacked arm: first alarm per detector per stream.
    let mut rng = StdRng::seed_from_u64(seed ^ 0xA77A_C000 ^ coupling as u64);
    let mut false_start = vec![0usize; n_det];
    let mut latencies: Vec<Vec<f64>> = vec![Vec::new(); n_det];
    for trial in 0..trials {
        let (xs, ys) = gen_seq_stream(coupling, sigma, true, &mut rng)?;
        let trace_seed = seed ^ 0xA77A_C000 ^ trial as u64;
        for (di, (_, trace)) in seq_traces(trace_seed, &xs, &ys)?.into_iter().enumerate() {
            let first = trace
                .iter()
                .find(|&&(_, v)| v > threshold[di])
                .map(|&(t, _)| t);
            match first {
                Some(t) if t < SEQ_ONSET => false_start[di] += 1,
                Some(t) => latencies[di].push((t - SEQ_ONSET) as f64),
                None => {}
            }
        }
    }

    let rows = SeqDetector::ALL
        .iter()
        .enumerate()
        .map(|(di, &detector)| {
            let no_fs = trials - false_start[di];
            let reach = if no_fs == 0 {
                0.0
            } else {
                latencies[di].len() as f64 / no_fs as f64
            };
            let median_latency = if latencies[di].is_empty() {
                None
            } else {
                let mut l = latencies[di].clone();
                l.sort_by(f64::total_cmp);
                let middle = l.len() / 2;
                Some(if l.len().is_multiple_of(2) {
                    (l[middle - 1] + l[middle]) / 2.0
                } else {
                    l[middle]
                })
            };
            SeqRow {
                detector,
                realized_far: realized_far[di],
                realized_far_ci: realized_far_ci[di],
                false_start: false_start[di] as f64 / trials as f64,
                reach,
                median_latency,
            }
        })
        .collect();

    Ok(SeqStudy {
        coupling,
        trials,
        sigma,
        seed,
        rows,
    })
}

/// Format the sequential study as a plain-text report.
pub fn format_seq(s: &SeqStudy) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nSequential (pointwise) detection — {} · onset +{} · target stream FAR {:.0}%\n\
         moment-matched decoupling at onset; {} streams in each independent calibration,\n\
         clean-holdout, and attacked arm; reported FAR is holdout FAR; sigma={}; seed={}\n\n",
        s.coupling.label(),
        SEQ_ONSET,
        SEQ_FAR * 100.0,
        s.trials,
        s.sigma,
        s.seed
    ));
    o.push_str(&format!(
        "{:<26} | {:>20} | {:>11} | {:>6} | {:>14}\n",
        "detector", "FAR [Wilson 95% CI]", "false-start", "reach", "median latency"
    ));
    o.push_str(&format!("{}\n", "-".repeat(91)));
    for r in &s.rows {
        o.push_str(&format!(
            "{:<26} | {:>5.3} [{:.3},{:.3}] | {:>11.3} | {:>6.3} | {:>14}\n",
            r.detector.label(),
            r.realized_far,
            r.realized_far_ci.0,
            r.realized_far_ci.1,
            r.false_start,
            r.reach,
            r.median_latency
                .map(|l| format!("{l:.0}f"))
                .unwrap_or_else(|| "—".into()),
        ));
    }
    o.push_str(
        "\nThese are synthetic experimental comparators, not deployed detector guarantees.\n\
         FAR intervals are Wilson score intervals on the independent clean holdout.\n\
         False-start and reach remain raw attack-arm proportions without intervals.\n\
         Detectors share a target FAR but their realized holdout FARs differ, so the latency\n\
         column is not strictly iso-FAR; read it alongside each detector's realized FAR.\n",
    );
    o
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 4 — the significance floor's i.i.d. assumption, tested on an AR(1) null.
//
// The runtime default accepts a positive cross-channel edge only past a family-wise
// Fisher-z significance floor whose standard error, 1/√(n−3), assumes the windowed
// residual pairs are i.i.d. bivariate normal. Windowed residual series need not be
// independent in time. This study measures what positive within-window autocorrelation
// does to that floor under the NULL: two *independent* AR(1) channels (population
// cross-correlation exactly zero, lag-1 coefficient φ), scored by the same one-sided
// construction the detector uses at its default window n = 128.
//
// Hypothesis (stated before running): the naive floor is anti-conservative — its
// realized false-positive rate rises above the nominal α as φ grows — and replacing n
// with Bartlett's effective sample size n_eff = n(1−φ²)/(1+φ²) improves calibration
// until the effective sample becomes too small for the asymptotic Fisher approximation.
// The large-sample theory (M. S. Bartlett, "Some Aspects of the Time-Correlation
// Problem in Regard to Tests of Significance," J. Royal Statistical Society
// 98(3):536–543, 1935) gives var(ρ̂) ≈ (1/n)·(1+φ²)/(1−φ²) for this null, which
// predicts the direction and approximate scale of the realized rates.
//
// This quantifies a *disclosed limitation* of the runtime default (PAPER.md §7); it is
// not a runtime correction. Applying the correction operationally requires estimating
// φ from data, with its own uncertainty — a registered enhancement decision.
// ─────────────────────────────────────────────────────────────────────────────

/// Window length for the AR(1) null study — matches the standalone-advisory 0.9
/// correlation profile's window.
const AR1_WINDOW: usize = 128;
/// Lag-1 AR coefficients scanned (φ = 0 is the calibration check).
pub const AR1_PHIS: [f64; 5] = [0.0, 0.3, 0.5, 0.7, 0.9];
/// One-sided standard-normal quantile at α = 0.05.
const AR1_Z_05: f64 = 1.644_853_626_951_472_2;
/// One-sided standard-normal quantile at α = 0.01.
const AR1_Z_01: f64 = 2.326_347_874_040_841;

/// Bartlett effective sample size for the cross-correlation of two independent
/// equal-φ AR(1) series: `n · (1−φ²)/(1+φ²)`.
fn bartlett_n_eff(n: usize, phi: f64) -> f64 {
    n as f64 * (1.0 - phi * phi) / (1.0 + phi * phi)
}

/// One stationary AR(1) stream: `x₀ ~ N(0,1)`, `x_t = φ·x_{t−1} + √(1−φ²)·ε_t`.
fn gen_ar1(n: usize, phi: f64, rng: &mut StdRng) -> Result<Vec<f64>> {
    let std_normal = Normal::new(0.0, 1.0).map_err(|error| {
        GaladrielError::InvalidConfig(format!("invalid standard normal: {error}"))
    })?;
    let innovation_sd = (1.0 - phi * phi).sqrt();
    let mut x = Vec::with_capacity(n);
    let mut previous = std_normal.sample(rng);
    x.push(previous);
    for _ in 1..n {
        previous = phi * previous + innovation_sd * std_normal.sample(rng);
        x.push(previous);
    }
    Ok(x)
}

/// One φ row of the AR(1) null study.
#[derive(Debug, Clone)]
pub struct Ar1NullRow {
    /// Lag-1 coefficient of both (independent) channels.
    pub phi: f64,
    /// Bartlett effective sample size at this φ.
    pub n_eff: f64,
    /// Realized FPR of the naive floor at α = 0.05, with its Wilson 95% interval.
    pub naive_fpr_05: f64,
    /// Wilson 95% interval for `naive_fpr_05`.
    pub naive_fpr_05_ci: (f64, f64),
    /// Realized FPR of the Bartlett-corrected floor at α = 0.05.
    pub bartlett_fpr_05: f64,
    /// Wilson 95% interval for `bartlett_fpr_05`.
    pub bartlett_fpr_05_ci: (f64, f64),
    /// Realized FPR of the naive floor at α = 0.01.
    pub naive_fpr_01: f64,
    /// Wilson 95% interval for `naive_fpr_01`.
    pub naive_fpr_01_ci: (f64, f64),
    /// Realized FPR of the Bartlett-corrected floor at α = 0.01.
    pub bartlett_fpr_01: f64,
    /// Wilson 95% interval for `bartlett_fpr_01`.
    pub bartlett_fpr_01_ci: (f64, f64),
}

/// The AR(1) autocorrelation-null study.
#[derive(Debug, Clone)]
pub struct Ar1NullStudy {
    /// Independent channel pairs per φ.
    pub trials: usize,
    /// Window length (matches the runtime default correlation window).
    pub n: usize,
    /// Root random seed.
    pub seed: u64,
    /// One row per φ in [`AR1_PHIS`].
    pub rows: Vec<Ar1NullRow>,
}

/// Run the autocorrelation-null study: per φ, generate `trials` pairs of independent
/// AR(1) channels and count how often the detector-style one-sided Fisher floor —
/// naive `1/√(n−3)` versus Bartlett `1/√(n_eff−3)` — falsely declares a significant
/// positive correlation.
pub fn run_autocorrelation_null(trials: usize, seed: u64) -> Result<Ar1NullStudy> {
    validate_study(trials, AR1_WINDOW, None)?;
    let floor = |z: f64, effective_n: f64| -> Result<f64> {
        if effective_n <= 4.0 {
            return Err(GaladrielError::InvalidConfig(
                "AR(1) effective sample size must exceed 4".into(),
            )
            .into());
        }
        Ok((z / (effective_n - 3.0).sqrt()).tanh())
    };
    let rows = AR1_PHIS
        .iter()
        .enumerate()
        .map(|(index, &phi)| -> Result<Ar1NullRow> {
            let n_eff = bartlett_n_eff(AR1_WINDOW, phi);
            let naive_floor_05 = floor(AR1_Z_05, AR1_WINDOW as f64)?;
            let naive_floor_01 = floor(AR1_Z_01, AR1_WINDOW as f64)?;
            let bartlett_floor_05 = floor(AR1_Z_05, n_eff)?;
            let bartlett_floor_01 = floor(AR1_Z_01, n_eff)?;
            let mut rng = StdRng::seed_from_u64(
                seed ^ 0xA21C_0221 ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
            );
            let (mut n05, mut b05, mut n01, mut b01) = (0usize, 0usize, 0usize, 0usize);
            for _ in 0..trials {
                let x = gen_ar1(AR1_WINDOW, phi, &mut rng)?;
                let y = gen_ar1(AR1_WINDOW, phi, &mut rng)?;
                let rho = pearson(&x, &y)?;
                if rho >= naive_floor_05 {
                    n05 += 1;
                }
                if rho >= bartlett_floor_05 {
                    b05 += 1;
                }
                if rho >= naive_floor_01 {
                    n01 += 1;
                }
                if rho >= bartlett_floor_01 {
                    b01 += 1;
                }
            }
            let rate = |count: usize| count as f64 / trials as f64;
            Ok(Ar1NullRow {
                phi,
                n_eff,
                naive_fpr_05: rate(n05),
                naive_fpr_05_ci: wilson95(n05, trials)?,
                bartlett_fpr_05: rate(b05),
                bartlett_fpr_05_ci: wilson95(b05, trials)?,
                naive_fpr_01: rate(n01),
                naive_fpr_01_ci: wilson95(n01, trials)?,
                bartlett_fpr_01: rate(b01),
                bartlett_fpr_01_ci: wilson95(b01, trials)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Ar1NullStudy {
        trials,
        n: AR1_WINDOW,
        seed,
        rows,
    })
}

/// Format the autocorrelation-null study as a plain-text report.
pub fn format_autocorrelation_null(s: &Ar1NullStudy) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nAutocorrelation null — two INDEPENDENT AR(1) channels · n={} (runtime default window)\n\
         false-positive rate of the one-sided Fisher significance floor · {} trials/phi · seed={}\n\n",
        s.n, s.trials, s.seed
    ));
    o.push_str(&format!(
        "{:>4} | {:>6} | {:>21} | {:>21} | {:>21} | {:>21}\n",
        "phi",
        "n_eff",
        "naive FPR@.05 [CI]",
        "Bartlett FPR@.05",
        "naive FPR@.01 [CI]",
        "Bartlett FPR@.01"
    ));
    o.push_str(&format!("{}\n", "-".repeat(110)));
    for r in &s.rows {
        o.push_str(&format!(
            "{:>4.1} | {:>6.1} | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}]\n",
            r.phi,
            r.n_eff,
            r.naive_fpr_05,
            r.naive_fpr_05_ci.0,
            r.naive_fpr_05_ci.1,
            r.bartlett_fpr_05,
            r.bartlett_fpr_05_ci.0,
            r.bartlett_fpr_05_ci.1,
            r.naive_fpr_01,
            r.naive_fpr_01_ci.0,
            r.naive_fpr_01_ci.1,
            r.bartlett_fpr_01,
            r.bartlett_fpr_01_ci.0,
            r.bartlett_fpr_01_ci.1,
        ));
    }
    o.push_str(
        "\nThe channels are independent (population rho = 0): every alarm above is a false\n\
         positive. The naive floor assumes i.i.d. pairs (SE 1/sqrt(n-3)); positive lag-1\n\
         autocorrelation inflates its realized rate above the nominal alpha, as predicted by\n\
         Bartlett's (1935) large-sample variance (1+phi^2)/((1-phi^2)n). The Bartlett column\n\
         replaces n with n_eff = n(1-phi^2)/(1+phi^2): it improves calibration at moderate\n\
         persistence, but becomes conservative at phi=0.9 where n_eff is only about 13.4 and\n\
         the asymptotic Fisher approximation is poor. The runtime default intentionally remains\n\
         naive: an operational correction needs a registered phi-estimation and finite-sample\n\
         calibration design (PAPER.md §7). The phi=0 row checks this harness. Synthetic evidence only.\n",
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(s: &Study, c: Coupling) -> CouplingResult {
        s.results.iter().find(|r| r.coupling == c).cloned().unwrap()
    }

    #[test]
    fn ranked_auc_preserves_mann_whitney_ties() {
        assert_eq!(auc(&[2.0, 3.0], &[0.0, 1.0]).unwrap(), 1.0);
        assert_eq!(auc(&[1.0], &[1.0]).unwrap(), 0.5);
        assert_eq!(auc(&[0.0, 2.0], &[1.0]).unwrap(), 0.5);
    }

    #[test]
    fn linear_coupling_correlation_matches_mi() {
        // On linear-Gaussian coupling both detectors separate perfectly — so MI
        // adds no value over the cheap correlation test. No PID claim is involved.
        let s = run(120, 300, 0.5, 7).expect("valid study");
        let lin = result(&s, Coupling::Linear);
        assert!(lin.corr_auc > 0.9, "corr AUC {:.3}", lin.corr_auc);
        assert!(lin.mi_auc > 0.9, "MI AUC {:.3}", lin.mi_auc);
        assert!(
            (lin.corr_auc - lin.mi_auc).abs() < 0.1,
            "corr and MI should agree"
        );
    }

    #[test]
    fn nonlinear_coupling_mi_beats_correlation() {
        // The good reason to retain an MI companion: on a nonlinear
        // (correlation-preserving) coupling, correlation is near chance while MI
        // still separates. This result does not establish a PID claim.
        let s = run(120, 300, 0.5, 7).expect("valid study");
        let nl = result(&s, Coupling::Nonlinear);
        assert!(
            nl.corr_auc < 0.7,
            "correlation should be near chance: {:.3}",
            nl.corr_auc
        );
        assert!(nl.mi_auc > 0.85, "MI should catch it: {:.3}", nl.mi_auc);
        assert!(
            nl.mi_auc - nl.corr_auc > 0.2,
            "MI must beat correlation clearly"
        );
    }

    #[test]
    fn joint_information_contrast_sees_xor_when_pairwise_measures_do_not() {
        // On T = A XOR B, correlation and pairwise MI are both blind. The joint
        // contrast separates coupled from decoupled without requiring a PID.
        // The separate categorical MGW atoms answer the further, measure-relative
        // allocation question tested below.
        let r = run_categorical_xor_justification(150, 600, 7)
            .expect("valid categorical XOR justification study");
        assert_eq!(r.schema(), CATEGORICAL_PID_STUDY_SCHEMA);
        assert_eq!(r.pid_trials().len(), r.trials());
        let serialized = serde_json::to_value(&r).expect("categorical evidence must serialize");
        assert_eq!(serialized["schema"], CATEGORICAL_PID_STUDY_SCHEMA);
        assert_eq!(
            serialized["pid_trials"].as_array().unwrap().len(),
            r.trials()
        );
        assert_eq!(serialized["pid_question"]["evaluator_units"], "Nats");
        assert_eq!(serialized["pid_question"]["atom_aggregate_units"], "Bits");
        assert_eq!(serialized["pid_question"]["source_count"], 2);
        assert!(serialized["pid_question"]
            .get("pid_core_software_identity")
            .is_none());
        assert_eq!(
            serialized["pid_execution_identity"]["dependency_selection"]["git_revision"],
            PID_RS_REVISION
        );
        assert_eq!(
            serialized["pid_execution_identity"]["software_identity"]["package_name"],
            "pid-core"
        );
        assert_eq!(
            serialized["pid_execution_identity"]["software_identity"]["package_version"],
            PID_RS_VERSION
        );
        assert_eq!(
            serialized["pid_execution_identity"]["software_identity"]["attestation"],
            "none"
        );
        assert_eq!(
            serialized["pid_resource_contract"]["budget"]["max_threads"],
            PID_STUDY_RESOURCE_MAX_THREADS
        );
        assert_eq!(
            serialized["pid_resource_contract"]["budget"]["max_bytes"],
            PID_STUDY_RESOURCE_MAX_BYTES
        );
        assert_eq!(
            serialized["pid_resource_contract"]["budget"]["max_pairwise_distances"],
            PID_STUDY_RESOURCE_MAX_PAIRWISE_DISTANCES
        );
        assert!(r.pid_execution_identity().package_and_version_matched());
        assert!(r.pid_execution_identity().workspace_git_revision_matched());
        assert!(r.pid_execution_identity().pid_core_package_subtree_clean());
        assert_eq!(
            serialized["pid_question"]["input_law"]["semantic_id"],
            "galadriel.law.categorical-xor-iid-fair-bits.v1"
        );
        assert!(
            serialized["pid_question"]["input_law"]["finite_sample_acceptance"]
                .as_str()
                .unwrap()
                .contains("conditioned")
        );
        assert_eq!(
            serialized["pid_question"]["output_coordinates"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(serialized["pid_trials"][0]["units"], "Nats");
        assert_eq!(
            serialized["study_protocol"]["q_score_id"],
            "galadriel.composition.joint-information-contrast-q.v1"
        );
        assert_eq!(
            serialized["study_protocol"]["auc_interval_resamples"],
            N_BOOT
        );
        assert_eq!(
            serialized["study_protocol"]["bootstrap_seed_xor"],
            AUC_BOOTSTRAP_SEED_XOR
        );
        assert_eq!(
            serialized["study_protocol"]["generation_seed_xor"],
            0x5259_6E65_u64
        );
        assert_eq!(
            serialized["study_protocol"]["auc_interval_seed_relations"][3]
                ["root_seed_wrapping_add"],
            4
        );
        assert_eq!(
            serialized["pid_question"]["aggregate_outputs"][0]["units"],
            "Dimensionless"
        );
        assert_eq!(
            serialized["pid_question"]["trial_arms"][1]["role"],
            "WithinTrialTargetPermutationControl"
        );
        assert_eq!(
            serialized["study_protocol"]["non_pid_aggregate_outputs"][6]["serialized_field"],
            "q_coupled_mean"
        );
        assert!(serialized.get("q_auc").is_some());
        assert!(serialized.get("synergy_auc").is_none());
        assert!(r
            .verifies_report_derived_aggregates()
            .expect("sealed categorical aggregate must verify"));
        assert!(
            r.corr_auc() < 0.65,
            "correlation should be blind: {:.3}",
            r.corr_auc()
        );
        assert!(
            r.pairwise_mi_auc() < 0.75,
            "pairwise MI should be blind: {:.3}",
            r.pairwise_mi_auc()
        );
        assert!(r.q_auc() > 0.9, "joint Q must separate: {:.3}", r.q_auc());
        assert!(
            r.q_coupled_mean() > 0.7,
            "XOR joint Q ~1 bit: {:.3}",
            r.q_coupled_mean()
        );
    }

    #[test]
    fn pid_question_specs_keep_categorical_and_continuous_functionals_distinct() {
        let categorical = PidQuestionSpec::categorical_xor();
        let continuous = PidQuestionSpec::continuous_sign_parity();
        let resource_contract = PidStudyResourceContract::fixed().unwrap();
        assert_eq!(
            resource_contract.budget(),
            ResourceBudget::new(
                PID_STUDY_RESOURCE_MAX_BYTES,
                PID_STUDY_RESOURCE_MAX_PAIRWISE_DISTANCES,
                PID_STUDY_RESOURCE_MAX_OPERATIONS_HINT,
                PID_STUDY_RESOURCE_MAX_THREADS,
            )
            .unwrap()
        );
        assert!(resource_contract.scope().contains("per evaluator call"));

        assert_ne!(categorical.functional(), continuous.functional());
        assert_ne!(categorical.route(), continuous.route());
        assert_ne!(categorical.law_kind(), continuous.law_kind());
        assert_ne!(
            categorical.input_law().semantic_id(),
            continuous.input_law().semantic_id()
        );
        assert!(continuous
            .input_law()
            .target_law()
            .contains("sign(A) * sign(B) * abs(Z)"));
        assert_eq!(categorical.evaluator_units(), PidInformationUnits::Nats);
        assert_eq!(
            categorical.atom_aggregate_units(),
            PidInformationUnits::Bits
        );
        assert_eq!(continuous.evaluator_units(), PidInformationUnits::Nats);
        assert_eq!(continuous.atom_aggregate_units(), PidInformationUnits::Nats);
        assert_eq!(categorical.source_count(), 2);
        assert_eq!(continuous.source_count(), 2);
        assert_eq!(categorical.output_coordinates().len(), 4);
        assert_eq!(continuous.output_coordinates().len(), 4);
        assert_eq!(
            categorical.output_coordinates()[0].components(),
            &CATEGORICAL_COMPONENTS
        );
        assert_eq!(
            continuous.output_coordinates()[0].components(),
            &CONTINUOUS_COMPONENTS
        );
        assert_eq!(
            categorical.output_coordinates()[3].lattice_coordinate(),
            PidLatticeCoordinate::Synergy
        );
        assert_eq!(
            continuous.output_coordinates()[3].construction(),
            PidQuantityConstruction::ContinuousPid2DerivedAtomFromRedundancyAndMutualInformation
        );
        assert_eq!(
            continuous.output_coordinates()[0].construction(),
            PidQuantityConstruction::ContinuousEhrlichSharedExclusionsRedundancyEstimate
        );
        assert_eq!(categorical.aggregate_outputs().len(), 4);
        assert_eq!(continuous.aggregate_outputs().len(), 3);
        assert_eq!(categorical.trial_arms().len(), 2);
        assert_eq!(continuous.trial_arms().len(), 2);
        assert_eq!(
            continuous.trial_arms()[1].role(),
            PidTrialArmRole::WithinTrialTargetPermutationControl
        );
        assert_eq!(
            categorical.aggregate_outputs()[0].units(),
            StudyOutputUnits::Dimensionless
        );
        assert_eq!(
            categorical.aggregate_outputs()[2].coordinate(),
            PidLatticeCoordinate::Synergy
        );
        assert_eq!(
            categorical.aggregate_outputs()[3].coordinate(),
            PidLatticeCoordinate::Redundancy
        );
        assert_eq!(
            categorical.output_coordinates()[0]
                .lattice_coordinate()
                .semantic_id(),
            "two-source-antichain:{{S1},{S2}}"
        );
        assert_eq!(
            categorical.functional().defining_team(),
            "Abdullah Makkeh; Aaron J. Gutknecht; Michael Wibral"
        );
        assert_eq!(
            continuous.functional().defining_team(),
            "David A. Ehrlich; Kyle Schick-Poland; Abdullah Makkeh; Felix Lanfermann; Patricia Wollstadt; Michael Wibral"
        );
        assert_eq!(categorical.schema(), PID_QUESTION_SCHEMA);
        assert_eq!(categorical.functional().reference_edges().len(), 4);
        assert_eq!(continuous.functional().reference_edges().len(), 4);
        assert_eq!(
            categorical.functional().reference_edges()[0].locator(),
            "https://doi.org/10.1103/PhysRevE.103.032149"
        );
        assert_eq!(
            categorical.functional().reference_edges()[1].locator(),
            "https://arxiv.org/abs/1004.2515"
        );
        assert_eq!(
            categorical.functional().reference_edges()[2].locator(),
            "https://doi.org/10.1098/rspa.2021.0110"
        );
        assert_eq!(
            continuous.functional().reference_edges()[0].locator(),
            "https://doi.org/10.1103/PhysRevE.110.014115"
        );
        assert_eq!(
            continuous.functional().reference_edges()[2].locator(),
            "https://doi.org/10.1103/PhysRevE.69.066138"
        );
        assert!(categorical
            .functional()
            .reference_edges()
            .iter()
            .any(|edge| edge
                .roles()
                .contains(&PidReferenceRole::RelatedConstructionNotEvaluated)));
        let categorical_json = serde_json::to_value(&categorical).unwrap();
        let continuous_json = serde_json::to_value(&continuous).unwrap();
        let categorical_refs = categorical_json["reference_edges"].as_array().unwrap();
        let continuous_refs = continuous_json["reference_edges"].as_array().unwrap();
        assert!(categorical_refs
            .iter()
            .any(|edge| { edge["locator"] == "https://doi.org/10.1098/rspa.2021.0110" }));
        assert!(continuous_refs
            .iter()
            .any(|edge| { edge["locator"] == "https://doi.org/10.1103/PhysRevE.69.066138" }));
        assert_eq!(
            categorical_json["output_coordinates"][0]["components"],
            serde_json::json!(["Net", "Informative", "Misinformative"])
        );
        assert_eq!(
            continuous_json["output_coordinates"][0]["components"],
            serde_json::json!(["Net"])
        );
        assert!(categorical_refs.iter().any(|edge| {
            edge["roles"].as_array().is_some_and(|roles| {
                roles
                    .iter()
                    .any(|role| role == "RelatedConstructionNotEvaluated")
            }) && edge["locator"] == "https://arxiv.org/abs/2106.12393"
        }));
        assert!(continuous_refs.iter().any(|edge| {
            edge["reference_id"] == "ehrlich-2024"
                && edge["roles"].as_array().is_some_and(|roles| {
                    roles.iter().any(|role| role == "FunctionalDefinition")
                        && roles.iter().any(|role| role == "EstimatorDefinition")
                })
        }));
        assert_eq!(
            categorical.route().method_id(),
            "shared-exclusions.categorical"
        );
        assert_eq!(continuous.route().method_id(), "pid.continuous-pid2");
        assert_eq!(
            continuous.route().api_route(),
            "pid_core::experimental::continuous::pid2_isx_report_with_budget"
        );
        assert_eq!(
            categorical.route().api_route(),
            "pid_core::stable::categorical::discrete_sxpid2_with_budget"
        );
        assert_eq!(
            categorical.route().feature_gate(),
            "none; stable categorical surface"
        );
        assert_eq!(continuous.route().feature_gate(), "experimental-continuous");
        assert_eq!(
            categorical.output_relation(),
            "pid-core evaluator and retained per-trial results remain in nats; aggregate/display atoms divide by ln(2) exactly once and are in bits"
        );
        assert_eq!(
            continuous.output_relation(),
            "pid-core evaluator, retained per-trial reports, and aggregate/display atoms all remain in nats"
        );
        assert_eq!(categorical.pid_core_dependency().package_name(), "pid-core");
        assert_eq!(
            categorical
                .pid_core_dependency()
                .workspace_selected_feature(),
            "experimental-continuous"
        );
        assert_eq!(
            categorical.pid_core_dependency().git_revision(),
            PID_RS_REVISION
        );
        assert!(categorical_json
            .as_object()
            .is_some_and(|object| !object.contains_key("pid_core_software_identity")));
        assert!(continuous_json
            .as_object()
            .is_some_and(|object| !object.contains_key("pid_core_software_identity")));
    }

    #[test]
    fn discrete_synergy_report_is_reproducible_and_fixed_source_information_is_invariant() {
        let first = run_categorical_xor_justification(20, 600, 7)
            .expect("first fixed-seed categorical XOR study");
        let second = run_categorical_xor_justification(20, 600, 7)
            .expect("second fixed-seed categorical XOR study");
        assert_eq!(
            format_categorical_xor_justification(&first),
            format_categorical_xor_justification(&second)
        );

        let mut response_specific_misinformation_observed = false;
        for trial in first.pid_trials() {
            let coupled = trial.coupled();
            let control = trial.permutation_control();
            for (coordinate, coupled_atom, control_atom) in [
                ("redundancy", &coupled.red, &control.red),
                ("unique-source-1", &coupled.unq1, &control.unq1),
                ("unique-source-2", &coupled.unq2, &control.unq2),
                ("synergy", &coupled.syn, &control.syn),
            ] {
                assert!(
                    (coupled_atom.informative_nats() - control_atom.informative_nats()).abs()
                        < 1e-12,
                    "fixed source rows must preserve the MGW informative {coordinate} atom"
                );
                response_specific_misinformation_observed |=
                    (coupled_atom.misinformative_nats() - control_atom.misinformative_nats()).abs()
                        > 1e-9;
            }
        }
        assert!(
            response_specific_misinformation_observed,
            "the target-permutation control must change at least one misinformative atom"
        );
    }

    #[test]
    fn sxpid_synergy_atom_sees_xor_and_matches_closed_form() {
        // The categorical Makkeh–Gutknecht–Wibral diagnostic decomposition: its
        // synergy atom separates the XOR coupling (AUC ~1), and the coupled-class
        // atoms match the closed form —
        // syn = log2(4/3) ≈ +0.415 bits, red = log2(2/3) ≈ −0.585 bits (negative:
        // misinformative sharing, a deliberate property of SxPID, never clamped).
        let r = run_categorical_xor_justification(150, 600, 7)
            .expect("valid categorical XOR justification study");
        assert!(
            r.sxpid_syn_auc() > 0.9,
            "SxPID synergy atom must separate: {:.3}",
            r.sxpid_syn_auc()
        );
        let syn_exact = (4.0_f64 / 3.0).log2();
        let red_exact = (2.0_f64 / 3.0).log2();
        assert!(
            (r.sxpid_syn_coupled_mean() - syn_exact).abs() < 0.05,
            "XOR SxPID synergy ≈ {syn_exact:.3} bits, got {:.3}",
            r.sxpid_syn_coupled_mean()
        );
        assert!(
            (r.sxpid_red_coupled_mean() - red_exact).abs() < 0.05,
            "XOR SxPID redundancy ≈ {red_exact:.3} bits (negative), got {:.3}",
            r.sxpid_red_coupled_mean()
        );
    }

    #[test]
    fn continuous_synergy_only_joint_measures_see_sign_parity() {
        // The continuous XOR analog on the pid-core estimators: pairwise KSG MI is
        // at chance (all pairwise marginals exactly independent), while the joint
        // contrast Q and the continuous I^sx synergy atom both separate.
        let r = run_continuous_sign_parity_justification(40, 600, 7)
            .expect("valid continuous sign-parity justification study");
        assert_eq!(r.schema(), CONTINUOUS_PID_STUDY_SCHEMA);
        assert_eq!(r.pid_trials().len(), r.trials());
        let serialized = serde_json::to_value(&r).expect("continuous evidence must serialize");
        assert_eq!(serialized["schema"], CONTINUOUS_PID_STUDY_SCHEMA);
        assert_eq!(
            serialized["pid_trials"].as_array().unwrap().len(),
            r.trials()
        );
        assert_eq!(serialized["pid_question"]["evaluator_units"], "Nats");
        assert_eq!(serialized["pid_question"]["atom_aggregate_units"], "Nats");
        assert_eq!(serialized["pid_trials"][0]["units"], "Nats");
        assert_eq!(
            serialized["pid_execution_identity"]["dependency_selection"]["git_revision"],
            PID_RS_REVISION
        );
        assert!(r.pid_execution_identity().package_and_version_matched());
        assert!(r.pid_execution_identity().workspace_git_revision_matched());
        assert!(r.pid_execution_identity().pid_core_package_subtree_clean());
        assert_eq!(
            serialized["pid_resource_contract"]["budget"]["max_threads"],
            PID_STUDY_RESOURCE_MAX_THREADS
        );
        assert_eq!(
            serialized["pid_resource_contract"]["budget"]["max_operations_hint"],
            serde_json::json!(PID_STUDY_RESOURCE_MAX_OPERATIONS_HINT)
        );
        assert!(r.pid_trials().iter().all(|trial| {
            trial.coupled().resource_budget == r.pid_resource_contract().budget()
                && trial.permutation_control().resource_budget == r.pid_resource_contract().budget()
        }));
        assert_eq!(
            serialized["study_protocol"]["generation_seed_xor"],
            0x516E_9A21_u64
        );
        assert_eq!(
            serialized["study_protocol"]["non_pid_aggregate_outputs"][6]["quantity"],
            "JointMutualInformation"
        );
        assert!(r
            .verifies_report_derived_aggregates()
            .expect("sealed continuous aggregate must verify"));
        assert!(
            r.pairwise_mi_auc() < 0.75,
            "pairwise KSG MI should be ~chance: {:.3}",
            r.pairwise_mi_auc()
        );
        assert!(r.q_auc() > 0.9, "joint Q must separate: {:.3}", r.q_auc());
        assert!(
            r.isx_syn_auc() > 0.85,
            "continuous I^sx synergy atom must separate: {:.3}",
            r.isx_syn_auc()
        );
        // Joint KSG MI should approximate the exact ln 2 parity bit.
        assert!(
            (r.joint_mi_coupled_mean() - std::f64::consts::LN_2).abs() < 0.2,
            "joint MI ≈ ln2: {:.3}",
            r.joint_mi_coupled_mean()
        );
    }

    #[test]
    fn pid_core_error_category_and_source_are_not_erased() {
        let error = pid_error(pid_core::PidError::NumericalInstability {
            context: "hostile-control",
        });
        assert!(matches!(
            error,
            JustificationError::PidCore(pid_core::PidError::NumericalInstability {
                context: "hostile-control"
            })
        ));
    }

    #[test]
    fn local_mi_zero_radius_shell_is_typed_failure_not_numeric_zero() {
        let error = local_mi_query(&[0.0, 0.0, 1.0], &[0.0, 0.0, 1.0], 0.0, 0.0, 2)
            .expect_err("duplicate kth-neighbor shell must abstain");
        assert!(matches!(
            error,
            JustificationError::Galadriel(GaladrielError::InvalidChannels(_))
        ));
    }

    #[test]
    fn seq_linear_pointwise_detectors_reach_and_beat_window_latency() {
        // H1/H2 on the linear coupling: every detector reaches; the pointwise CUSUMs
        // (parametric Gauss-LR and model-free local-MI alike) detect faster than the
        // windowed-refit detectors.
        let s = run_seq(Coupling::Linear, 25, 0.5, 7).expect("valid sequential study");
        let row = |d: SeqDetector| s.rows.iter().find(|r| r.detector == d).unwrap().clone();
        for d in SeqDetector::ALL {
            let r = row(d);
            assert!(r.reach > 0.85, "{}: reach {:.2}", d.label(), r.reach);
        }
        let win_mi = row(SeqDetector::WindowMi).median_latency.unwrap();
        let lmi = row(SeqDetector::LocalMiCusum).median_latency.unwrap();
        let glr = row(SeqDetector::GaussLrCusum).median_latency.unwrap();
        assert!(
            lmi < win_mi,
            "local-MI CUSUM ({lmi:.0}f) should beat window-MI refill ({win_mi:.0}f)"
        );
        assert!(
            glr < win_mi,
            "Gauss-LR CUSUM ({glr:.0}f) should beat window-MI refill ({win_mi:.0}f)"
        );
    }

    #[test]
    fn seq_nonlinear_only_model_free_pointwise_detector_survives() {
        // H3 on the sign-flip coupling: the cheap pointwise statistics are blind
        // (E[xy] = 0 and ρ̂_cal ≈ 0 on both sides of onset) and so is the windowed
        // correlation; the model-free local-MI CUSUM (and the windowed KSG MI, with
        // its refill latency) still detect.
        let s = run_seq(Coupling::Nonlinear, 25, 0.5, 7).expect("valid sequential study");
        let row = |d: SeqDetector| s.rows.iter().find(|r| r.detector == d).unwrap().clone();
        assert!(
            row(SeqDetector::WindowCorr).reach < 0.4,
            "window |rho| should be blind: {:.2}",
            row(SeqDetector::WindowCorr).reach
        );
        assert!(
            row(SeqDetector::ProductCusum).reach < 0.4,
            "product CUSUM should be blind: {:.2}",
            row(SeqDetector::ProductCusum).reach
        );
        assert!(
            row(SeqDetector::GaussLrCusum).reach < 0.4,
            "Gauss-LR CUSUM should be blind: {:.2}",
            row(SeqDetector::GaussLrCusum).reach
        );
        assert!(
            row(SeqDetector::LocalMiCusum).reach > 0.75,
            "local-MI CUSUM must detect: {:.2}",
            row(SeqDetector::LocalMiCusum).reach
        );
        assert!(
            row(SeqDetector::WindowMi).reach > 0.75,
            "window KSG MI must detect: {:.2}",
            row(SeqDetector::WindowMi).reach
        );
    }

    #[test]
    fn public_studies_reject_degenerate_or_unbounded_inputs() {
        assert!(run(0, 300, 0.5, 7).is_err());
        assert!(run(MIN_TRIALS - 1, 300, 0.5, 7).is_err());
        assert!(run(MIN_TRIALS, 7, 0.5, 7).is_err());
        assert!(run(MIN_TRIALS, 300, f64::NAN, 7).is_err());
        assert!(run(MIN_TRIALS, MAX_SAMPLES, 0.5, 7).is_err());
        assert!(run_categorical_xor_justification(MAX_TRIALS + 1, 600, 7).is_err());
        assert!(run_seq(Coupling::Linear, 0, 0.5, 7).is_err());
        assert!(auc_ci(&[1.0], &[0.0], 0, 7).is_err());
        let oversized = vec![0.0; MAX_TRIALS + 1];
        assert!(auc(&oversized, &[0.0]).is_err());
        assert!(auc_ci(&oversized, &oversized, MIN_BOOTSTRAP_RESAMPLES, 7).is_err());
    }

    #[test]
    fn bootstrap_and_cli_preflight_enforce_pairing_and_work_budgets() {
        let pos = vec![1.0; MIN_TRIALS];
        let neg = vec![0.0; MIN_TRIALS];
        assert!(auc_ci(&pos, &neg, MIN_BOOTSTRAP_RESAMPLES, 7).is_ok());
        assert!(auc_ci(&pos, &neg, MIN_BOOTSTRAP_RESAMPLES - 1, 7).is_err());
        assert!(auc_ci(&pos, &neg[..MIN_TRIALS - 1], MIN_BOOTSTRAP_RESAMPLES, 7).is_err());
        assert!(auc_ci(
            &pos[..MIN_TRIALS - 1],
            &neg[..MIN_TRIALS - 1],
            MIN_BOOTSTRAP_RESAMPLES,
            7
        )
        .is_err());

        let large_pos = vec![1.0; MAX_TRIALS];
        let large_neg = vec![0.0; MAX_TRIALS];
        assert!(auc_ci(&large_pos, &large_neg, 100_000, 7).is_err());
        assert!(preflight_default_suite(300).is_ok());
        assert!(preflight_default_suite(MAX_TRIALS).is_err());
    }

    #[test]
    fn distance_preflight_counts_the_constituent_routes_actually_executed() {
        assert_eq!(ksg_report_distance_work(8).unwrap(), 4 * 28);
        assert_eq!(pid2_report_distance_work(8).unwrap(), 13 * 28);
        assert_eq!(pid2_work(250, 600, 2).unwrap(), 1_168_050_000);

        let n = 64;
        let mut rng = StdRng::seed_from_u64(0xD157_AACE);
        let normal = Normal::new(0.0, 1.0).unwrap();
        let a = (0..n).map(|_| normal.sample(&mut rng)).collect::<Vec<_>>();
        let b = (0..n).map(|_| normal.sample(&mut rng)).collect::<Vec<_>>();
        let t = a
            .iter()
            .zip(&b)
            .map(|(&x, &y)| x + y + 0.2 * normal.sample(&mut rng))
            .collect::<Vec<_>>();
        let am = MatOwned::new(a, n, 1).unwrap();
        let bm = MatOwned::new(b, n, 1).unwrap();
        let tm = MatOwned::new(t, n, 1).unwrap();
        let provenance = Pid2Provenance::new(
            "Fixed source-A test gauge.",
            "Fixed source-B test gauge.",
            "No target preprocessing.",
            "Binary64 synthetic test observations without added noise.",
        )
        .and_then(|value| {
            value.with_sampling_model_and_splits(
                "Independent synthetic rows for a resource-accounting hostile control.",
                None,
                Some("resource-accounting-evaluation"),
            )
        })
        .unwrap();
        let resource_contract = PidStudyResourceContract::fixed().unwrap();
        let report = pid2_isx_report_with_budget(
            am.as_ref(),
            bm.as_ref(),
            tm.as_ref(),
            &Pid2Config::assume_regular_full_dimensional(),
            &provenance,
            resource_contract.budget(),
        )
        .unwrap();
        assert_eq!(report.resource_budget, resource_contract.budget());
        let executed_constituents = [
            report.mi_s1_t_report.resource_estimate.pairwise_distances,
            report.mi_s2_t_report.resource_estimate.pairwise_distances,
            report.mi_s1s2_t_report.resource_estimate.pairwise_distances,
            report
                .redundancy_isx_report
                .resource_estimate
                .pairwise_distances,
        ]
        .into_iter()
        .try_fold(0u128, u128::checked_add)
        .unwrap();
        assert_eq!(executed_constituents, pid2_report_distance_work(n).unwrap());
        assert!(
            report.resource_estimate.pairwise_distances < executed_constituents,
            "the pinned aggregate must not be mistaken for the executed constituent sum"
        );
    }

    #[test]
    fn wilson_interval_exposes_small_holdout_uncertainty() {
        assert!(wilson95(0, 0).is_err());
        assert!(wilson95(21, 20).is_err());

        let zero = wilson95(0, 20).expect("valid count");
        assert!(zero.0 <= f64::EPSILON);
        assert!(
            zero.1 > 0.15 && zero.1 < 0.17,
            "zero-event upper={}",
            zero.1
        );

        let one = wilson95(1, 20).expect("valid count");
        assert!(one.0 < 0.05 && one.1 > 0.05);

        let report = format_seq(&SeqStudy {
            coupling: Coupling::Linear,
            trials: 20,
            sigma: 0.5,
            seed: 7,
            rows: vec![SeqRow {
                detector: SeqDetector::WindowCorr,
                realized_far: 0.05,
                realized_far_ci: one,
                false_start: 0.0,
                reach: 1.0,
                median_latency: Some(4.0),
            }],
        });
        assert!(report.contains("FAR [Wilson 95% CI]"));
        assert!(report.contains(&format!("[{:.3},{:.3}]", one.0, one.1)));

        let all = wilson95(20, 20).expect("valid count");
        assert!(all.0 > 0.83 && all.0 < 0.85, "all-event lower={}", all.0);
        assert!((all.1 - 1.0).abs() <= f64::EPSILON);
    }

    #[test]
    fn xor_generator_resamples_degenerate_bernoulli_columns() {
        for seed in 0..128 {
            let mut rng = StdRng::seed_from_u64(seed);
            let (a, b, t) = gen_xor_trial(8, &mut rng).expect("bounded draw should succeed");
            assert!(has_both_binary_values(&a));
            assert!(has_both_binary_values(&b));
            assert!(has_both_binary_values(&t));
        }
        assert!(run_categorical_xor_justification(MIN_TRIALS, 8, 7).is_ok());
    }

    #[test]
    fn constant_continuous_columns_abstain_without_added_noise() {
        let constant = vec![1.0; 512];
        let result = ksg(
            7,
            &constant,
            &constant,
            "Caller-declared constant-row negative control; this law is atomic and outside the continuous KSG support contract.",
        );
        assert!(
            result.is_err(),
            "constant columns must abstain, not be noised"
        );
    }

    #[test]
    fn autocorrelation_null_exposes_naive_inflation_and_bartlett_finite_sample_limit() {
        // Hypothesis of Study 4: under the null (independent channels), positive lag-1
        // autocorrelation makes the naive i.i.d. Fisher floor anti-conservative. Bartlett's
        // effective sample size improves calibration until high persistence leaves too little
        // effective data for the asymptotic Fisher approximation.
        let s = run_autocorrelation_null(1_000, 7).expect("valid AR(1) null study");
        let row = |phi: f64| {
            s.rows
                .iter()
                .find(|r| (r.phi - phi).abs() < 1e-9)
                .cloned()
                .unwrap()
        };
        let calibrated = row(0.0);
        assert!(
            (0.02..=0.09).contains(&calibrated.naive_fpr_05),
            "phi=0 must be calibrated near alpha=.05: {}",
            calibrated.naive_fpr_05
        );
        let inflated = row(0.7);
        assert!(
            inflated.naive_fpr_05 >= 0.11,
            "phi=0.7 must inflate the naive FPR well above alpha: {}",
            inflated.naive_fpr_05
        );
        assert!(
            inflated.naive_fpr_05 > row(0.3).naive_fpr_05,
            "naive inflation must grow with phi"
        );
        for phi in [0.0, 0.3, 0.5, 0.7] {
            let r = row(phi);
            assert!(
                (0.02..=0.09).contains(&r.bartlett_fpr_05),
                "Bartlett floor should remain near alpha at phi={phi}: {}",
                r.bartlett_fpr_05
            );
        }
        let high_persistence = row(0.9);
        assert!(
            high_persistence.bartlett_fpr_05_ci.1 < 0.05
                && high_persistence.bartlett_fpr_01_ci.1 < 0.01,
            "small-n_eff Bartlett/Fisher approximation should be detectably conservative: {high_persistence:?}"
        );
    }

    #[test]
    fn autocorrelation_null_rejects_out_of_range_trials() {
        assert!(run_autocorrelation_null(MIN_TRIALS - 1, 7).is_err());
        assert!(run_autocorrelation_null(MAX_TRIALS + 1, 7).is_err());
    }
}
