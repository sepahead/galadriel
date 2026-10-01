//! Exact categorical shared-exclusions study over CREBAIN's drone sensor fixture.
//!
//! This module starts from a physically parameterized synthetic row contract. Its raw-row API
//! forms an empirical PMF and therefore supplies a sample estimate of the paper functional; it is
//! not a declared-law evaluator. Each row is one freshly initialized CREBAIN fusion-engine episode with
//! ordered pre-fusion visual, radar, and acoustic measurements, a checked row-level time window,
//! and synthetic ENU truth generated without consulting the sensor projections, fusion result,
//! Galadriel verdict, or PID calculation. The pinned producer source supplies the stronger
//! per-modality synchronization provenance that the compact fixture does not independently retain.
//! The fixture is a deterministic eight-cell categorical law repeated eight times to test
//! bounded-summary fresh-instance reproducibility. Those repetitions do not create 64 independent
//! experimental units or establish reproducibility of an unretained full fusion output.
//!
//! The primary question is the two-source Makkeh--Gutknecht--Wibral (MGW) decomposition of visual
//! and radar evidence about horizontal incursion. The three-source volumetric decomposition is
//! exploratory and does not close pid-rs's separate 108-coordinate assurance program. All PID
//! output is advisory research evidence: it cannot grant, revoke, or exercise Haldir authority.

use super::{PID_RS_GIT_REPOSITORY, PID_RS_REVISION, PID_RS_VERSION};
use pid_core::{
    software_identity,
    stable::categorical::{
        discrete_sxpid2_resource_estimate, discrete_sxpid2_with_budget,
        discrete_sxpid3_resource_estimate, discrete_sxpid3_with_budget, DiscreteSxPid2Result,
        DiscreteSxPid3Result, SxAtomAggregation, SxAtomContextRequirement,
        SxAtomCoordinateSemantics, SxAtomDecompositionMeasure, SxAtomEvidentialScope,
        SxAtomInterpretation, SxAveragedAtom, SxInterpretationGuardOrigin, SxPointwiseAtom,
        SxUnsupportedInference,
    },
    DiscreteMatOwned, ResourceBudget, ResourceEstimate, SoftwareIdentity, SourceIdentity,
    WorkingTreeScope, WorkingTreeState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

/// Serialization schema for the complete CREBAIN categorical-MGW evidence object.
pub const CREBAIN_DRONE_MGW_STUDY_SCHEMA: &str = "galadriel.crebain-drone-mgw-study.v3";
/// Repository-relative formal JSON Schema path for the v3 evidence object.
pub const CREBAIN_DRONE_MGW_STUDY_SCHEMA_PATH: &str =
    "crates/galadriel-justify/schemas/crebain-drone-mgw-study-v3.schema.json";
/// Canonical publication locator for the formal v3 JSON Schema.
pub const CREBAIN_DRONE_MGW_STUDY_SCHEMA_ID: &str = "https://raw.githubusercontent.com/sepahead/galadriel/v0.9.0/crates/galadriel-justify/schemas/crebain-drone-mgw-study-v3.schema.json";
/// Exact CREBAIN commit that produced the bundled fixture.
pub const CREBAIN_FIXTURE_REVISION: &str = "6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d";
/// Exact repository-relative path of the producer fixture.
pub const CREBAIN_FIXTURE_PATH: &str = "src-tauri/tests/fixtures/crebain_drone_mgw_v1.json";
/// SHA-256 of the exact producer fixture bytes.
pub const CREBAIN_FIXTURE_SHA256: &str =
    "82a837415b56c3646386a5c3e6fe28a492906c164edc461249bab7844aa4ebda";
/// Exact producer fixture size.
pub const CREBAIN_FIXTURE_BYTES: usize = 64_218;
/// SHA-256 of the recursively key-sorted `analysis_manifest` JSON value.
pub const CREBAIN_ANALYSIS_MANIFEST_SHA256: &str =
    "4b0381beee855e7d624066ab04cfdc07920c6182951315b65ba48d99c1e86f90";

const STUDY_ID: &str = "crebain-drone-mgw-v1";
const ROW_COUNT: usize = 64;
const CELL_COUNT: usize = 8;
const EPISODES_PER_CELL: usize = 8;
const PRIOR_TIMESTAMP_MS: u64 = 1_000;
const OBSERVATION_TIMESTAMP_MS: u64 = 1_100;
const SOURCE_ORDER: [&str; 3] = [
    "visual_north_plane_crossed",
    "radar_east_plane_crossed",
    "acoustic_up_plane_crossed",
];
const PID3_CANONICAL_ANTICHAINS: [&[u8]; 18] = [
    &[1],
    &[2],
    &[4],
    &[3],
    &[5],
    &[6],
    &[7],
    &[1, 2],
    &[1, 4],
    &[1, 6],
    &[2, 4],
    &[2, 5],
    &[3, 4],
    &[3, 5],
    &[3, 6],
    &[5, 6],
    &[1, 2, 4],
    &[3, 5, 6],
];

const PAPER_FUNCTIONAL_ID: &str = "functional.shared-exclusions.mgw-categorical";
const SAMPLE_ESTIMATOR_ROUTE_ID: &str = "route.shared-exclusions.mgw-empirical-pmf";
const UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID: &str = "shared-exclusions.categorical";
const UPSTREAM_INTERPRETATION_CATALOG_ID: &str = "software.sxpid-interpretation-contract";
const PREREGISTERED_PID_RS_REVISION: &str = "1cd2424f7967e1752dcc8e53859e8fdad3566f51";
const PREREGISTERED_AUTHORITY_BOUNDARY: &str =
    "advisory research evidence only; cannot grant, revoke, or exercise Haldir control authority";
const PREREGISTERED_PID2_ENTRY_POINT: &str = "pid_core::stable::categorical::discrete_sxpid2";
const PREREGISTERED_PID3_ENTRY_POINT: &str = "pid_core::stable::categorical::discrete_sxpid3";
const PID2_IMPLEMENTATION_ENTRY_POINT: &str =
    "pid_core::stable::categorical::discrete_sxpid2_with_budget";
const PID3_IMPLEMENTATION_ENTRY_POINT: &str =
    "pid_core::stable::categorical::discrete_sxpid3_with_budget";
const PID_RESOURCE_MAX_BYTES: u64 = 64 * 1024 * 1024;
const PID_RESOURCE_MAX_PAIRWISE_DISTANCES: u64 = 1;
const PID_RESOURCE_MAX_OPERATIONS_HINT: u128 = 100_000_000;
const PID_RESOURCE_MAX_THREADS: usize = 1;
const AUTHORITY_BOUNDARY: &str =
    "record-only advisory research evidence. For fixed admitted authority inputs, Haldir authorization, trusted-state policy, and plant-command outputs are identical across PID record states. Audit records may vary. No operator-behavior noninterference is claimed";
const PREREGISTERED_TARGET_ORIGIN_LITERAL: &str =
    "externally generated fixture truth in canonical ENU before sensor projection and before fusion";
const PREREGISTERED_OPERATIONAL_METHOD_LITERAL: &str =
    "separate operational association diagnostics";

/// Typed failure from exact fixture validation or categorical MGW evaluation.
#[derive(Debug, Error)]
pub enum CrebainMgwError {
    #[error("CREBAIN fixture byte identity mismatch: expected {expected}, observed {observed}")]
    FixtureIdentity {
        expected: &'static str,
        observed: String,
    },
    #[error("CREBAIN fixture JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("CREBAIN fixture contract failed: {0}")]
    Contract(String),
    #[error("pid-core categorical MGW evaluation failed: {0}")]
    PidCore(#[from] pid_core::PidError),
}

/// Result type for the exact CREBAIN categorical-MGW study.
pub type Result<T> = std::result::Result<T, CrebainMgwError>;

/// Return the exact CREBAIN fixture compiled into this crate.
#[must_use]
pub fn bundled_crebain_drone_mgw_fixture() -> &'static str {
    include_str!("../fixtures/crebain_drone_mgw_v1.json")
}

/// Return the closed Draft 2020-12 schema compiled into the candidate.
#[must_use]
pub fn bundled_crebain_drone_mgw_schema() -> &'static str {
    include_str!("../schemas/crebain-drone-mgw-study-v3.schema.json")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    analysis_manifest: Value,
    analysis_manifest_canonicalization: String,
    analysis_manifest_sha256: String,
    geometry: Geometry,
    rows: Vec<FixtureRow>,
    schema_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Geometry {
    axis_order: [String; 3],
    canonical_frame: String,
    entry_planes_m: EntryPlanes,
    prior_reference_enu_m: [f64; 3],
    target_definitions: TargetDefinitions,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryPlanes {
    east_at_or_below: f64,
    north_at_or_below: f64,
    up_at_or_below: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetDefinitions {
    horizontal_incursion: String,
    volumetric_incursion: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRow {
    cell_index: usize,
    episode_id: String,
    fusion_receipt: FusionReceipt,
    horizontal_incursion: usize,
    observation_timestamp_ms: u64,
    pre_fusion_observations: PreFusionObservations,
    prior_timestamp_ms: u64,
    replicate_index: usize,
    sources: [usize; 3],
    truth_enu_m: [f64; 3],
    volumetric_incursion: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FusionReceipt {
    common_projection_prior_id: u64,
    degraded: bool,
    input_count: usize,
    projection_count: usize,
    truncated: bool,
    v1_expected_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreFusionObservations {
    acoustic_cartesian_enu_m: [f64; 3],
    radar_polar_range_azimuth_elevation: [f64; 3],
    visual_cartesian_enu_m: [f64; 3],
}

/// Role of a cited work in the exact estimand graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReferenceRole {
    CategoricalSharedExclusionsFunctional,
    PartWholeLogicalDerivation,
    OriginalAntichainLattice,
    ComparatorFunctionalOnly,
    EstimatorImplementationBasisOnly,
    ContinuousFunctionalOnly,
    GeneralConstructionNotEvaluated,
    EstimatorDefinition,
    DiagnosticDefinition,
    ObjectiveComposition,
    AxiomaticCaveat,
}

/// One role-distinct source edge. A citation never licenses a different method by proximity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReferenceEdge {
    reference_id: &'static str,
    role: ReferenceRole,
    complete_team: &'static str,
    title: &'static str,
    locator: &'static str,
    boundary: &'static str,
}

impl ReferenceEdge {
    pub const fn reference_id(self) -> &'static str {
        self.reference_id
    }
    pub const fn role(self) -> ReferenceRole {
        self.role
    }
    pub const fn complete_team(self) -> &'static str {
        self.complete_team
    }
    pub const fn title(self) -> &'static str {
        self.title
    }
    pub const fn locator(self) -> &'static str {
        self.locator
    }
    pub const fn boundary(self) -> &'static str {
        self.boundary
    }
}

const MGW_REFERENCE_EDGES: [ReferenceEdge; 3] = [
    ReferenceEdge {
        reference_id: "makkeh-gutknecht-wibral-2021",
        role: ReferenceRole::CategoricalSharedExclusionsFunctional,
        complete_team: "Abdullah Makkeh; Aaron J. Gutknecht; Michael Wibral",
        title: "Introducing a differentiable measure of pointwise shared information",
        locator: "https://doi.org/10.1103/PhysRevE.103.032149",
        boundary: "defines the evaluated categorical pointwise shared-exclusions functional",
    },
    ReferenceEdge {
        reference_id: "gutknecht-wibral-makkeh-2021",
        role: ReferenceRole::PartWholeLogicalDerivation,
        complete_team: "Aaron J. Gutknecht; Michael Wibral; Abdullah Makkeh",
        title: "Bits and Pieces: Understanding Information Decomposition from Part-whole Relationships and Formal Logic",
        locator: "https://doi.org/10.1098/rspa.2021.0110",
        boundary: "role-distinct part-whole and logical foundation. This is not a second estimator alias",
    },
    ReferenceEdge {
        reference_id: "williams-beer-2010",
        role: ReferenceRole::OriginalAntichainLattice,
        complete_team: "Paul L. Williams; Randall D. Beer",
        title: "Nonnegative decomposition of multivariate information",
        locator: "https://arxiv.org/abs/1004.2515",
        boundary:
            "original antichain lattice only. The Williams--Beer I_min functional is not evaluated",
    },
];

const MGW_AXIOMATIC_CAVEAT_EDGES: [ReferenceEdge; 3] = [
    ReferenceEdge {
        reference_id: "harder-salge-polani-2013",
        role: ReferenceRole::AxiomaticCaveat,
        complete_team: "Malte Harder; Christoph Salge; Daniel Polani",
        title: "Bivariate Measure of Redundant Information",
        locator: "https://doi.org/10.1103/PhysRevE.87.012130",
        boundary: "the independent two-bit COPY identity-axiom comparison requires redundancy zero, whereas categorical shared exclusions yields ln(4/3) nats. This fixture does not adjudicate that normative choice",
    },
    ReferenceEdge {
        reference_id: "rauh-bertschinger-olbrich-jost-2014",
        role: ReferenceRole::AxiomaticCaveat,
        complete_team: "Johannes Rauh; Nils Bertschinger; Eckehard Olbrich; Jürgen Jost",
        title: "Reconsidering Unique Information: Towards a Multivariate Information Decomposition",
        locator: "https://doi.org/10.1109/ISIT.2014.6875230",
        boundary: "three-source identity, local-positivity, and Williams--Beer-lattice desiderata cannot all be inferred from successful computation on this law",
    },
    ReferenceEdge {
        reference_id: "lyu-clark-raviv-2026",
        role: ReferenceRole::AxiomaticCaveat,
        complete_team: "Aobo Lyu; Andrew Clark; Netanel Raviv",
        title: "Multivariate Partial Information Decomposition: Constructions, Inconsistencies, and Alternative Measures",
        locator: "https://doi.org/10.1103/8rzp-w5z1",
        boundary: "computing one PID3 lattice does not establish general cross-system consistency or resolve multivariate descriptor collisions",
    },
];

const IMIN_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "williams-beer-2010",
    role: ReferenceRole::ComparatorFunctionalOnly,
    complete_team: "Paul L. Williams; Randall D. Beer",
    title: "Nonnegative decomposition of multivariate information",
    locator: "https://arxiv.org/abs/1004.2515",
    boundary: "defines the I_min comparator. Its antichain lattice is shared infrastructure, not evidence that I_min and MGW are aliases",
}];

const BROJA_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "bertschinger-rauh-olbrich-jost-ay-2014",
    role: ReferenceRole::ComparatorFunctionalOnly,
    complete_team: "Nils Bertschinger; Johannes Rauh; Eckehard Olbrich; Jürgen Jost; Nihat Ay",
    title: "Quantifying unique information",
    locator: "https://doi.org/10.3390/e16042161",
    boundary: "two-source comparator only. No three-source BROJA route is asserted for this study",
}];

const SCHICK_POLAND_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "schick-poland-makkeh-gutknecht-wollstadt-sturm-wibral-2021",
    role: ReferenceRole::GeneralConstructionNotEvaluated,
    complete_team: "Kyle Schick-Poland; Abdullah Makkeh; Aaron J. Gutknecht; Patricia Wollstadt; Anja Sturm; Michael Wibral",
    title: "A partial information decomposition for discrete and continuous variables",
    locator: "https://arxiv.org/abs/2106.12393",
    boundary: "general measure-theoretic construction. Neither the categorical MGW empirical-PMF sample estimator nor the distinct Ehrlich estimator is treated as its alias",
}];

const EHRLICH_FUNCTIONAL_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "ehrlich-schick-poland-makkeh-lanfermann-wollstadt-wibral-2024",
    role: ReferenceRole::ContinuousFunctionalOnly,
    complete_team: "David A. Ehrlich; Kyle Schick-Poland; Abdullah Makkeh; Felix Lanfermann; Patricia Wollstadt; Michael Wibral",
    title: "Partial information decomposition for continuous variables based on shared exclusions: analytical formulation and estimation",
    locator: "https://doi.org/10.1103/PhysRevE.110.014115",
    boundary: "continuous functional and PID2 atom construction at a constitutive source gauge. This is not categorical MGW",
}];

const EHRLICH_ESTIMATOR_REFERENCE_EDGES: [ReferenceEdge; 2] = [
    ReferenceEdge {
        reference_id: "ehrlich-schick-poland-makkeh-lanfermann-wollstadt-wibral-2024",
        role: ReferenceRole::EstimatorDefinition,
        complete_team: "David A. Ehrlich; Kyle Schick-Poland; Abdullah Makkeh; Felix Lanfermann; Patricia Wollstadt; Michael Wibral",
        title: "Partial information decomposition for continuous variables based on shared exclusions: analytical formulation and estimation",
        locator: "https://doi.org/10.1103/PhysRevE.110.014115",
        boundary: "defines the continuous shared-exclusions nearest-neighbor estimator used for the redundancy constituent",
    },
    ReferenceEdge {
        reference_id: "kraskov-stoegbauer-grassberger-2004",
        role: ReferenceRole::EstimatorImplementationBasisOnly,
        complete_team: "Alexander Kraskov; Harald Stögbauer; Peter Grassberger",
        title: "Estimating mutual information",
        locator: "https://doi.org/10.1103/PhysRevE.69.066138",
        boundary: "mutual-information constituent estimator only. KSG does not define a PID",
    },
];

const KSG_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "kraskov-stoegbauer-grassberger-2004",
    role: ReferenceRole::EstimatorDefinition,
    complete_team: "Alexander Kraskov; Harald Stögbauer; Peter Grassberger",
    title: "Estimating mutual information",
    locator: "https://doi.org/10.1103/PhysRevE.69.066138",
    boundary:
        "pairwise continuous mutual-information estimator only. This is not a PID functional or fallback",
}];

const CO_INFORMATION_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "mcgill-1954",
    role: ReferenceRole::DiagnosticDefinition,
    complete_team: "William J. McGill",
    title: "Multivariate information transmission",
    locator: "https://doi.org/10.1007/BF02289159",
    boundary: "interaction-information antecedent. Sign conventions must be declared, and the invariant is not a PID atom",
}];

const O_INFORMATION_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "rosas-mediano-gastpar-jensen-2019",
    role: ReferenceRole::DiagnosticDefinition,
    complete_team: "Fernando E. Rosas; Pedro A. M. Mediano; Michael Gastpar; Henrik J. Jensen",
    title: "Quantifying high-order interdependencies via multivariate extensions of the mutual information",
    locator: "https://doi.org/10.1103/PhysRevE.100.032305",
    boundary: "system-level redundancy/synergy balance diagnostic. This is not a redundancy-lattice PID atom",
}];

const CUSUM_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "page-1954",
    role: ReferenceRole::DiagnosticDefinition,
    complete_team: "E. S. Page",
    title: "Continuous inspection schemes",
    locator: "https://doi.org/10.1093/biomet/41.1-2.100",
    boundary: "sequential change-detection foundation only. Galadriel's two-arm magnitude composition and lifecycle contract are project-defined and are not PID. On the fusion core's dof=3 route, the lower arm is inert. Other admitted degrees of freedom retain the general recurrence",
}];

const PNAS_INFOMORPHIC_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "makkeh-graetz-schneider-ehrlich-priesemann-wibral-2025",
    role: ReferenceRole::ObjectiveComposition,
    complete_team: "Abdullah Makkeh; Marcel Graetz; Andreas C. Schneider; David A. Ehrlich; Viola Priesemann; Michael Wibral",
    title: "A general framework for interpretable neural learning based on local information-theoretic goal functions",
    locator: "https://doi.org/10.1073/pnas.2408125122",
    boundary: "bivariate/two-input learning-objective composition. This is not a PID definition or Galadriel estimator",
}];

const ICLR_INFOMORPHIC_REFERENCE_EDGES: [ReferenceEdge; 1] = [ReferenceEdge {
    reference_id: "schneider-neuhaus-ehrlich-makkeh-ecker-priesemann-wibral-2025",
    role: ReferenceRole::ObjectiveComposition,
    complete_team: "Andreas C. Schneider; Valentin Neuhaus; David A. Ehrlich; Abdullah Makkeh; Alexander S. Ecker; Viola Priesemann; Michael Wibral",
    title: "What should a neuron aim for? Designing local objective functions based on information theory",
    locator: "https://openreview.net/forum?id=CLE09ESvul",
    boundary: "three-input-class local-objective design. This is distinct from the earlier bivariate PNAS work and is not a PID definition",
}];

const NO_REFERENCE_EDGES: [ReferenceEdge; 0] = [];

/// Scientific object kind. Paper semantics, sample estimation, implementation, and objectives are
/// separate roles even when one dependency supplies all executable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MethodObjectKind {
    Functional,
    SampleEstimatorRoute,
    ImplementationMethod,
    ImplementationEntryPoint,
    Estimator,
    Diagnostic,
    ObjectiveComposition,
}

/// Role of an object in this study, separate from whether it executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StudyRole {
    Primary,
    Exploratory,
    Comparator,
    ReferenceBoundary,
    SeparateOperationalDiagnostic,
    DownstreamOnly,
}

/// Execution disposition for this exact fixture, not a global availability claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExecutionDisposition {
    Produced,
    NotRequested,
    Inapplicable,
    NotEvaluated,
}

/// Method-specific applicability and abstention row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MethodEligibility {
    object_id: &'static str,
    object: &'static str,
    object_kind: MethodObjectKind,
    study_role: StudyRole,
    execution: ExecutionDisposition,
    estimand_or_output: &'static str,
    assumptions_or_reason: &'static str,
    implementation_entry_point: Option<&'static str>,
    reference_edges: &'static [ReferenceEdge],
    fallback_policy: &'static str,
}

impl MethodEligibility {
    pub const fn object_id(self) -> &'static str {
        self.object_id
    }
    pub const fn object(self) -> &'static str {
        self.object
    }
    pub const fn object_kind(self) -> MethodObjectKind {
        self.object_kind
    }
    pub const fn study_role(self) -> StudyRole {
        self.study_role
    }
    pub const fn execution(self) -> ExecutionDisposition {
        self.execution
    }
    pub const fn estimand_or_output(self) -> &'static str {
        self.estimand_or_output
    }
    pub const fn assumptions_or_reason(self) -> &'static str {
        self.assumptions_or_reason
    }
    pub const fn implementation_entry_point(self) -> Option<&'static str> {
        self.implementation_entry_point
    }
    pub const fn reference_edges(self) -> &'static [ReferenceEdge] {
        self.reference_edges
    }
    pub const fn fallback_policy(self) -> &'static str {
        self.fallback_policy
    }
}

const METHOD_ELIGIBILITY: [MethodEligibility; 18] = [
    MethodEligibility {
        object_id: PAPER_FUNCTIONAL_ID,
        object: "paper-defined categorical MGW shared-exclusions functional",
        object_kind: MethodObjectKind::Functional,
        study_role: StudyRole::Primary,
        execution: ExecutionDisposition::Produced,
        estimand_or_output: "paper-defined pointwise cumulatives and Möbius atoms, plus empirical-PMF averages, on a categorical law",
        assumptions_or_reason: "ordered categorical sources, a named categorical target, and the complete balanced row sample are fixed before estimation",
        implementation_entry_point: None,
        reference_edges: &MGW_REFERENCE_EDGES,
        fallback_policy: "no comparator or alternative PID is substituted on failure",
    },
    MethodEligibility {
        object_id: SAMPLE_ESTIMATOR_ROUTE_ID,
        object: "raw-row empirical-PMF categorical MGW sample-estimator route",
        object_kind: MethodObjectKind::SampleEstimatorRoute,
        study_role: StudyRole::Primary,
        execution: ExecutionDisposition::Produced,
        estimand_or_output: "empirical-PMF sample estimate of the paper-defined pointwise cumulatives and averaged atoms",
        assumptions_or_reason: "raw categorical rows are converted to empirical mass before the paper functional is evaluated. This estimates that functional from a sample; it is not a declared-law evaluator",
        implementation_entry_point: None,
        reference_edges: &MGW_REFERENCE_EDGES,
        fallback_policy: "no declared-law evaluator, comparator, or alternative PID is substituted on failure",
    },
    MethodEligibility {
        object_id: UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
        object: "pid-rs categorical shared-exclusions implementation method",
        object_kind: MethodObjectKind::ImplementationMethod,
        study_role: StudyRole::Primary,
        execution: ExecutionDisposition::Produced,
        estimand_or_output: "upstream implementation-method identity for categorical shared-exclusions sample estimation",
        assumptions_or_reason: "the pid-rs method catalog identifies implementation provenance. It is neither the paper functional ID nor the Galadriel semantic sample-estimator route ID",
        implementation_entry_point: None,
        reference_edges: &MGW_REFERENCE_EDGES,
        fallback_policy: "no unrecorded implementation method is substituted on failure",
    },
    MethodEligibility {
        object_id: PID2_IMPLEMENTATION_ENTRY_POINT,
        object: "pid-core budgeted categorical MGW PID2 implementation entry point",
        object_kind: MethodObjectKind::ImplementationEntryPoint,
        study_role: StudyRole::Primary,
        execution: ExecutionDisposition::Produced,
        estimand_or_output: "pointwise and averaged informative, misinformative, and signed net atoms on the two-source empirical categorical law",
        assumptions_or_reason: "visual and radar are passed in the declared order. The synthetic latent-truth horizontal target is derived without reading projection, fusion, verdict, or PID outputs. Repeated rows define empirical mass, not precision",
        implementation_entry_point: Some(PID2_IMPLEMENTATION_ENTRY_POINT),
        reference_edges: &MGW_REFERENCE_EDGES,
        fallback_policy: "no comparator or alternative PID is substituted on failure",
    },
    MethodEligibility {
        object_id: PID3_IMPLEMENTATION_ENTRY_POINT,
        object: "pid-core budgeted categorical MGW PID3 implementation entry point",
        object_kind: MethodObjectKind::ImplementationEntryPoint,
        study_role: StudyRole::Exploratory,
        execution: ExecutionDisposition::Produced,
        estimand_or_output: "18 pointwise and averaged Möbius coordinates on the ordered visual/radar/acoustic empirical categorical law",
        assumptions_or_reason: "the stable implementation entry point is available, but this bounded fixture does not close pid-rs's separate 108-coordinate formal-assurance program",
        implementation_entry_point: Some(PID3_IMPLEMENTATION_ENTRY_POINT),
        reference_edges: &MGW_REFERENCE_EDGES,
        fallback_policy: "no two-source result is presented as a substitute for the three-source question",
    },
    MethodEligibility {
        object_id: "pid.imin",
        object: "Williams--Beer I_min PID",
        object_kind: MethodObjectKind::Functional,
        study_role: StudyRole::Comparator,
        execution: ExecutionDisposition::NotRequested,
        estimand_or_output: "a different redundancy functional and therefore a different atom allocation",
        assumptions_or_reason: "scientifically eligible as a separately preregistered categorical comparator, but not required to answer this MGW question",
        implementation_entry_point: None,
        reference_edges: &IMIN_REFERENCE_EDGES,
        fallback_policy: "never an alias or fallback for MGW",
    },
    MethodEligibility {
        object_id: "pid.broja-two-source-external",
        object: "BROJA PID",
        object_kind: MethodObjectKind::Functional,
        study_role: StudyRole::Comparator,
        execution: ExecutionDisposition::NotRequested,
        estimand_or_output: "unique information defined through a constrained family of distributions",
        assumptions_or_reason: "eligible only as a separately preregistered comparator for the primary two-source law. It requires external implementation identity, feasibility diagnostics, and a separate claim boundary. No PID3 route is implied",
        implementation_entry_point: None,
        reference_edges: &BROJA_REFERENCE_EDGES,
        fallback_policy: "never an alias or fallback for MGW",
    },
    MethodEligibility {
        object_id: "pid.general-schick-poland-2021",
        object: "Schick-Poland general PID construction",
        object_kind: MethodObjectKind::Functional,
        study_role: StudyRole::ReferenceBoundary,
        execution: ExecutionDisposition::NotEvaluated,
        estimand_or_output: "general measure-theoretic construction for discrete and continuous variables",
        assumptions_or_reason: "recorded to prevent provenance transfer. This study implements neither a generic evaluator for that construction nor an alias through MGW or Ehrlich",
        implementation_entry_point: None,
        reference_edges: &SCHICK_POLAND_REFERENCE_EDGES,
        fallback_policy: "not an implicit fallback or compatibility umbrella",
    },
    MethodEligibility {
        object_id: "shared-exclusions.continuous-ehrlich-functional",
        object: "continuous Ehrlich shared-exclusions functional and derived PID2 atoms",
        object_kind: MethodObjectKind::Functional,
        study_role: StudyRole::ReferenceBoundary,
        execution: ExecutionDisposition::Inapplicable,
        estimand_or_output: "continuous redundancy and derived two-source PID atoms at a fixed source gauge",
        assumptions_or_reason: "the fixture is a repeated atomic categorical law. No absolutely continuous tuple law or continuous source gauge is declared",
        implementation_entry_point: None,
        reference_edges: &EHRLICH_FUNCTIONAL_REFERENCE_EDGES,
        fallback_policy: "abstain. Categorical MGW is not called a continuous-PID estimate",
    },
    MethodEligibility {
        object_id: "shared-exclusions.continuous-ehrlich-knn-estimator",
        object: "Ehrlich continuous shared-exclusions nearest-neighbor estimator",
        object_kind: MethodObjectKind::Estimator,
        study_role: StudyRole::ReferenceBoundary,
        execution: ExecutionDisposition::Inapplicable,
        estimand_or_output: "continuous shared-exclusions redundancy estimate with KSG mutual-information constituents",
        assumptions_or_reason: "atomic, repeated, and categorical inputs violate the estimator's continuous support route independently of the functional question",
        implementation_entry_point: None,
        reference_edges: &EHRLICH_ESTIMATOR_REFERENCE_EDGES,
        fallback_policy: "abstain. No added-noise or quantization repair is substituted",
    },
    MethodEligibility {
        object_id: "mutual-information.ksg1-report",
        object: "pairwise KSG mutual information",
        object_kind: MethodObjectKind::Estimator,
        study_role: StudyRole::ReferenceBoundary,
        execution: ExecutionDisposition::Inapplicable,
        estimand_or_output: "continuous pairwise MI estimate, not PID",
        assumptions_or_reason: "the fixture has repeated atomic categorical support. No full-dimensional continuous population law is declared",
        implementation_entry_point: None,
        reference_edges: &KSG_REFERENCE_EDGES,
        fallback_policy: "abstain. Added noise would change the estimand",
    },
    MethodEligibility {
        object_id: "co-information.discrete",
        object: "co-information",
        object_kind: MethodObjectKind::Diagnostic,
        study_role: StudyRole::Comparator,
        execution: ExecutionDisposition::NotRequested,
        estimand_or_output: "signed interaction invariant under a declared sign convention. This is not a PID atom",
        assumptions_or_reason: "eligible only after separately preregistering the exact variable tuple and sign convention, such as CoI(V,R,T_H). It does not answer the selected atom-allocation question",
        implementation_entry_point: None,
        reference_edges: &CO_INFORMATION_REFERENCE_EDGES,
        fallback_policy: "never relabel co-information as redundancy, uniqueness, or synergy",
    },
    MethodEligibility {
        object_id: "o-information.discrete",
        object: "O-information",
        object_kind: MethodObjectKind::Diagnostic,
        study_role: StudyRole::Comparator,
        execution: ExecutionDisposition::NotRequested,
        estimand_or_output: "system-level balance of high-order redundancy- and synergy-dominated dependence. This is not a set of PID coordinates",
        assumptions_or_reason: "eligible only after separately preregistering the exact symmetric system tuple, such as Omega(V,R,A,T_V). Changing the tuple changes the object, and it does not allocate redundancy-lattice atoms",
        implementation_entry_point: None,
        reference_edges: &O_INFORMATION_REFERENCE_EDGES,
        fallback_policy: "never relabel O-information as any MGW atom",
    },
    MethodEligibility {
        object_id: "galadriel.normalized-innovation-squared",
        object: "normalized innovation squared (NIS)",
        object_kind: MethodObjectKind::Diagnostic,
        study_role: StudyRole::SeparateOperationalDiagnostic,
        execution: ExecutionDisposition::NotEvaluated,
        estimand_or_output: "per-channel innovation magnitude under a separately qualified covariance and lifecycle contract",
        assumptions_or_reason: "the exact drone fixture contains no lifecycle-qualified NIS report. Availability elsewhere in Galadriel is not evidence produced by this study",
        implementation_entry_point: Some("galadriel_core::assess_default"),
        reference_edges: &NO_REFERENCE_EDGES,
        fallback_policy: "PID never alters the accepted verdict or Haldir authority",
    },
    MethodEligibility {
        object_id: "galadriel.two-sided-cusum",
        object: "two-arm CUSUM (fusion-core dof=3 lower arm inert)",
        object_kind: MethodObjectKind::Diagnostic,
        study_role: StudyRole::SeparateOperationalDiagnostic,
        execution: ExecutionDisposition::NotEvaluated,
        estimand_or_output: "sequential innovation-magnitude accumulator under a separately qualified state and lifecycle contract. On the fusion core's dof=3 route, only the upper arm can move. Other admitted degrees of freedom retain the general recurrence",
        assumptions_or_reason: "the exact drone fixture contains no lifecycle-qualified CUSUM state or alarm report. The stable object ID names the generic two-sided type. The configuration does not fix degrees of freedom. Galadriel's operational composition does not make this object PID evidence",
        implementation_entry_point: Some("galadriel_core::assess_default"),
        reference_edges: &CUSUM_REFERENCE_EDGES,
        fallback_policy: "no CUSUM state or alarm is inferred from the PID fixture",
    },
    MethodEligibility {
        object_id: "galadriel.signed-pearson-correlation",
        object: "signed Pearson correlation",
        object_kind: MethodObjectKind::Diagnostic,
        study_role: StudyRole::SeparateOperationalDiagnostic,
        execution: ExecutionDisposition::NotEvaluated,
        estimand_or_output: "directional pairwise linear association under Galadriel's separate lifecycle contract",
        assumptions_or_reason: "the exact drone fixture contains no qualified correlation report. Unlike MI, correlation retains sign, but it is not a PID",
        implementation_entry_point: Some("galadriel_core::assess_default"),
        reference_edges: &NO_REFERENCE_EDGES,
        fallback_policy: "no correlation result is inferred from the PID fixture",
    },
    MethodEligibility {
        object_id: "infomorphic-objective.pnas-bivariate-2025",
        object: "PNAS bivariate infomorphic objective composition",
        object_kind: MethodObjectKind::ObjectiveComposition,
        study_role: StudyRole::DownstreamOnly,
        execution: ExecutionDisposition::NotEvaluated,
        estimand_or_output: "two-input local learning objective composed from named PID atoms",
        assumptions_or_reason: "a downstream objective does not define a PID functional and is outside this fixed-law study",
        implementation_entry_point: None,
        reference_edges: &PNAS_INFOMORPHIC_REFERENCE_EDGES,
        fallback_policy: "never treat an objective composition as an estimator identity",
    },
    MethodEligibility {
        object_id: "infomorphic-objective.iclr-three-input-2025",
        object: "ICLR three-input-class local objective composition",
        object_kind: MethodObjectKind::ObjectiveComposition,
        study_role: StudyRole::DownstreamOnly,
        execution: ExecutionDisposition::NotEvaluated,
        estimand_or_output: "three-input-class local objective vocabulary composed from named information terms",
        assumptions_or_reason: "role-distinct from the earlier bivariate PNAS work and outside this fixed-law study",
        implementation_entry_point: None,
        reference_edges: &ICLR_INFOMORPHIC_REFERENCE_EDGES,
        fallback_policy: "never treat an objective composition as an estimator identity",
    },
];

/// Kind of node in the machine-readable estimand and evidence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EstimandGraphNodeKind {
    ProducerFixture,
    DeclaredLaw,
    EmpiricalPmf,
    Functional,
    SampleEstimatorRoute,
    ImplementationMethod,
    ImplementationEntryPoint,
    PointwiseOutput,
    AveragedOutput,
    ValidationReceipt,
    AdvisoryView,
}

/// Meaning of one directed edge in the estimand and evidence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EstimandGraphEdgeKind {
    Declares,
    EncodedAs,
    EstimatedBy,
    ConsumedBy,
    ImplementedBy,
    ExposedThrough,
    SubmittedTo,
    Emits,
    AggregatesInto,
    CheckedBy,
    ExposedAs,
}

/// One typed object in the CREBAIN-to-PID evidence path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EstimandGraphNode {
    node_id: &'static str,
    kind: EstimandGraphNodeKind,
    label: &'static str,
    boundary: &'static str,
}

/// One directed, role-specific relationship between two graph objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EstimandGraphEdge {
    from: &'static str,
    to: &'static str,
    kind: EstimandGraphEdgeKind,
    boundary: &'static str,
}

const ESTIMAND_GRAPH_NODES: [EstimandGraphNode; 16] = [
    EstimandGraphNode {
        node_id: "producer.crebain-fixture",
        kind: EstimandGraphNodeKind::ProducerFixture,
        label: "byte-bound CREBAIN synthetic episode fixture",
        boundary: "retains ordered source symbols, latent-truth targets, row timestamps, episode identifiers, and bounded fusion summaries. It does not include raw field data or a complete fusion replay",
    },
    EstimandGraphNode {
        node_id: "law.and2",
        kind: EstimandGraphNodeKind::DeclaredLaw,
        label: "uniform independent V,R with T_H = V AND R",
        boundary: "canonical categorical logic law. Physical names do not add external validity",
    },
    EstimandGraphNode {
        node_id: "law.and3",
        kind: EstimandGraphNodeKind::DeclaredLaw,
        label: "uniform independent V,R,A with T_V = V AND R AND A",
        boundary: "canonical categorical logic law. No noise, dropout, attack, or fusion output enters the estimand",
    },
    EstimandGraphNode {
        node_id: "pmf.horizontal",
        kind: EstimandGraphNodeKind::EmpiricalPmf,
        label: "64-row equal-weight categorical PMF for horizontal incursion",
        boundary: "eight repeats per source cell preserve exact mass and software custody. They are not 64 independent inferential units",
    },
    EstimandGraphNode {
        node_id: "pmf.volumetric",
        kind: EstimandGraphNodeKind::EmpiricalPmf,
        label: "64-row equal-weight categorical PMF for volumetric incursion",
        boundary: "ordered sources are visual, radar, and acoustic. The target is derived from latent ENU truth without reading fusion or PID",
    },
    EstimandGraphNode {
        node_id: PAPER_FUNCTIONAL_ID,
        kind: EstimandGraphNodeKind::Functional,
        label: "Makkeh--Gutknecht--Wibral categorical shared-exclusions paper functional",
        boundary: "paper-defined signed statistical allocation. It is measure-relative and non-causal",
    },
    EstimandGraphNode {
        node_id: SAMPLE_ESTIMATOR_ROUTE_ID,
        kind: EstimandGraphNodeKind::SampleEstimatorRoute,
        label: "raw categorical rows to empirical PMF to MGW sample estimate",
        boundary: "this semantic route estimates the paper functional from empirical mass. It is not a declared-law evaluator and has no fallback",
    },
    EstimandGraphNode {
        node_id: UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
        kind: EstimandGraphNodeKind::ImplementationMethod,
        label: "pid-rs categorical shared-exclusions implementation method",
        boundary: "upstream method-catalog provenance. It is neither the paper functional nor the semantic sample-estimator route",
    },
    EstimandGraphNode {
        node_id: PID2_IMPLEMENTATION_ENTRY_POINT,
        kind: EstimandGraphNodeKind::ImplementationEntryPoint,
        label: "pid-core discrete_sxpid2_with_budget implementation entry point",
        boundary: "post-preregistration bc3aa80 budgeted PID2 call. No fallback route is used",
    },
    EstimandGraphNode {
        node_id: PID3_IMPLEMENTATION_ENTRY_POINT,
        kind: EstimandGraphNodeKind::ImplementationEntryPoint,
        label: "pid-core discrete_sxpid3_with_budget implementation entry point",
        boundary: "exploratory budgeted PID3 call. It does not close the 108-coordinate assurance program",
    },
    EstimandGraphNode {
        node_id: "output.pid2-pointwise",
        kind: EstimandGraphNodeKind::PointwiseOutput,
        label: "four realization-level records, each retaining four signed PID2 coordinates",
        boundary: "pointwise categorical outputs. They are not independently recomputed by the Decimal route",
    },
    EstimandGraphNode {
        node_id: "output.pid2-averaged",
        kind: EstimandGraphNodeKind::AveragedOutput,
        label: "four empirical-PMF-averaged PID2 atoms",
        boundary: "primary deterministic conformance result in nats",
    },
    EstimandGraphNode {
        node_id: "output.pid3-pointwise",
        kind: EstimandGraphNodeKind::PointwiseOutput,
        label: "eight PID3 realization-level 18-coordinate records",
        boundary: "pointwise categorical outputs on the canonical antichain order",
    },
    EstimandGraphNode {
        node_id: "output.pid3-averaged",
        kind: EstimandGraphNodeKind::AveragedOutput,
        label: "18 empirical-PMF-averaged PID3 atoms",
        boundary: "exploratory deterministic conformance result in nats",
    },
    EstimandGraphNode {
        node_id: "receipt.validation",
        kind: EstimandGraphNodeKind::ValidationReceipt,
        label: "custody, resource, interpretation, algebra, and theorem-control receipts",
        boundary: "checks this exact software path and law. This is not a general PID validation theorem",
    },
    EstimandGraphNode {
        node_id: "view.advisory-only",
        kind: EstimandGraphNodeKind::AdvisoryView,
        label: "record-only Galadriel research evidence",
        boundary: AUTHORITY_BOUNDARY,
    },
];

const ESTIMAND_GRAPH_EDGES: [EstimandGraphEdge; 24] = [
    EstimandGraphEdge { from: "producer.crebain-fixture", to: "law.and2", kind: EstimandGraphEdgeKind::Declares, boundary: "latent ENU cells and threshold definitions induce the two-bit AND law" },
    EstimandGraphEdge { from: "producer.crebain-fixture", to: "law.and3", kind: EstimandGraphEdgeKind::Declares, boundary: "latent ENU cells and threshold definitions induce the three-bit AND law" },
    EstimandGraphEdge { from: "law.and2", to: "pmf.horizontal", kind: EstimandGraphEdgeKind::EncodedAs, boundary: "the 64 retained rows encode each two-source realization with its declared multiplicity" },
    EstimandGraphEdge { from: "law.and3", to: "pmf.volumetric", kind: EstimandGraphEdgeKind::EncodedAs, boundary: "the 64 retained rows encode eight copies of every three-source realization" },
    EstimandGraphEdge { from: PAPER_FUNCTIONAL_ID, to: SAMPLE_ESTIMATOR_ROUTE_ID, kind: EstimandGraphEdgeKind::EstimatedBy, boundary: "the raw-row empirical-PMF route estimates the named paper functional. It neither defines the functional nor evaluates a declared law directly" },
    EstimandGraphEdge { from: "pmf.horizontal", to: SAMPLE_ESTIMATOR_ROUTE_ID, kind: EstimandGraphEdgeKind::ConsumedBy, boundary: "the semantic sample-estimator route consumes the ordered two-source empirical PMF" },
    EstimandGraphEdge { from: "pmf.volumetric", to: SAMPLE_ESTIMATOR_ROUTE_ID, kind: EstimandGraphEdgeKind::ConsumedBy, boundary: "the semantic sample-estimator route consumes the ordered three-source empirical PMF" },
    EstimandGraphEdge { from: SAMPLE_ESTIMATOR_ROUTE_ID, to: UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID, kind: EstimandGraphEdgeKind::ImplementedBy, boundary: "pid-rs supplies the selected implementation method for this semantic route. Its catalog ID is not the functional ID" },
    EstimandGraphEdge { from: UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID, to: PID2_IMPLEMENTATION_ENTRY_POINT, kind: EstimandGraphEdgeKind::ExposedThrough, boundary: "the selected implementation method exposes the exact budgeted PID2 entry point" },
    EstimandGraphEdge { from: UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID, to: PID3_IMPLEMENTATION_ENTRY_POINT, kind: EstimandGraphEdgeKind::ExposedThrough, boundary: "the selected implementation method exposes the exact budgeted PID3 entry point" },
    EstimandGraphEdge { from: "pmf.horizontal", to: PID2_IMPLEMENTATION_ENTRY_POINT, kind: EstimandGraphEdgeKind::SubmittedTo, boundary: "ordered visual and radar rows with the horizontal target are submitted only to the PID2 entry point" },
    EstimandGraphEdge { from: "pmf.volumetric", to: PID3_IMPLEMENTATION_ENTRY_POINT, kind: EstimandGraphEdgeKind::SubmittedTo, boundary: "ordered visual, radar, and acoustic rows with the volumetric target are submitted only to the PID3 entry point" },
    EstimandGraphEdge { from: PID2_IMPLEMENTATION_ENTRY_POINT, to: "output.pid2-pointwise", kind: EstimandGraphEdgeKind::Emits, boundary: "nominal realization identity and signed components are retained" },
    EstimandGraphEdge { from: PID2_IMPLEMENTATION_ENTRY_POINT, to: "output.pid2-averaged", kind: EstimandGraphEdgeKind::Emits, boundary: "four named averaged lattice coordinates are retained" },
    EstimandGraphEdge { from: PID3_IMPLEMENTATION_ENTRY_POINT, to: "output.pid3-pointwise", kind: EstimandGraphEdgeKind::Emits, boundary: "all eight realized source-target states and 18 atom coordinates are retained" },
    EstimandGraphEdge { from: PID3_IMPLEMENTATION_ENTRY_POINT, to: "output.pid3-averaged", kind: EstimandGraphEdgeKind::Emits, boundary: "all 18 averaged antichain coordinates are retained" },
    EstimandGraphEdge { from: "output.pid2-pointwise", to: "output.pid2-averaged", kind: EstimandGraphEdgeKind::AggregatesInto, boundary: "empirical-count weighting is reconstructed component by component" },
    EstimandGraphEdge { from: "output.pid3-pointwise", to: "output.pid3-averaged", kind: EstimandGraphEdgeKind::AggregatesInto, boundary: "empirical-count weighting is reconstructed for all 18 coordinates" },
    EstimandGraphEdge { from: "output.pid2-pointwise", to: "receipt.validation", kind: EstimandGraphEdgeKind::CheckedBy, boundary: "support keys, nominal identity, interpretation, and source-position canaries" },
    EstimandGraphEdge { from: "output.pid2-averaged", to: "receipt.validation", kind: EstimandGraphEdgeKind::CheckedBy, boundary: "closed forms, lattice reconstruction, signed controls, and Decimal comparison" },
    EstimandGraphEdge { from: "output.pid3-pointwise", to: "receipt.validation", kind: EstimandGraphEdgeKind::CheckedBy, boundary: "support keys, canonical coordinates, interpretation, and source-position canaries" },
    EstimandGraphEdge { from: "output.pid3-averaged", to: "receipt.validation", kind: EstimandGraphEdgeKind::CheckedBy, boundary: "downset reconstruction, MI identities, signed controls, and Decimal comparison" },
    EstimandGraphEdge { from: "receipt.validation", to: "view.advisory-only", kind: EstimandGraphEdgeKind::ExposedAs, boundary: "successful checks permit only a typed research record" },
    EstimandGraphEdge { from: "producer.crebain-fixture", to: "receipt.validation", kind: EstimandGraphEdgeKind::CheckedBy, boundary: "byte, manifest, row, episode, time-window, target, and bounded-summary custody are checked before evaluation" },
];

/// Validated topology of the exact data, functional, sample estimator, implementation, output,
/// and evidence path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EstimandGraphReceipt {
    graph_id: &'static str,
    paper_functional_id: &'static str,
    sample_estimator_route_id: &'static str,
    upstream_implementation_method_catalog_id: &'static str,
    pid2_implementation_entry_point: &'static str,
    pid3_implementation_entry_point: &'static str,
    nodes: &'static [EstimandGraphNode],
    edges: &'static [EstimandGraphEdge],
    all_edge_endpoints_resolved: bool,
    declared_topological_order_validated: bool,
    question_method_and_graph_identities_reconciled: bool,
    operational_authority_node_or_edge_kind_absent: bool,
    boundary: &'static str,
}

fn estimand_graph_receipt() -> Result<EstimandGraphReceipt> {
    validate_estimand_graph(&ESTIMAND_GRAPH_NODES, &ESTIMAND_GRAPH_EDGES)?;
    Ok(EstimandGraphReceipt {
        graph_id: "galadriel.crebain-mgw-estimand-graph.v2",
        paper_functional_id: PAPER_FUNCTIONAL_ID,
        sample_estimator_route_id: SAMPLE_ESTIMATOR_ROUTE_ID,
        upstream_implementation_method_catalog_id:
            UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
        pid2_implementation_entry_point: PID2_IMPLEMENTATION_ENTRY_POINT,
        pid3_implementation_entry_point: PID3_IMPLEMENTATION_ENTRY_POINT,
        nodes: &ESTIMAND_GRAPH_NODES,
        edges: &ESTIMAND_GRAPH_EDGES,
        all_edge_endpoints_resolved: true,
        declared_topological_order_validated: true,
        question_method_and_graph_identities_reconciled: true,
        operational_authority_node_or_edge_kind_absent: true,
        boundary: "this graph separates producer custody, declared laws, empirical encodings, the paper-defined functional, semantic sample-estimator route, upstream implementation method, concrete entry points, pointwise and averaged outputs, validation receipts, and the advisory view. It contains no operational-decision or control-authority edge",
    })
}

fn validate_estimand_graph(nodes: &[EstimandGraphNode], edges: &[EstimandGraphEdge]) -> Result<()> {
    let mut node_ids = BTreeSet::new();
    for node in nodes {
        if !node_ids.insert(node.node_id) {
            return Err(CrebainMgwError::Contract(format!(
                "estimand graph repeats node {}",
                node.node_id
            )));
        }
    }
    for edge in edges {
        let from = nodes
            .iter()
            .position(|node| node.node_id == edge.from)
            .ok_or_else(|| {
                CrebainMgwError::Contract(format!(
                    "estimand graph edge has unknown source {}",
                    edge.from
                ))
            })?;
        let to = nodes
            .iter()
            .position(|node| node.node_id == edge.to)
            .ok_or_else(|| {
                CrebainMgwError::Contract(format!(
                    "estimand graph edge has unknown destination {}",
                    edge.to
                ))
            })?;
        if from >= to {
            return Err(CrebainMgwError::Contract(format!(
                "estimand graph edge {} -> {} violates the declared topological order",
                edge.from, edge.to
            )));
        }
    }
    let required_identity_nodes = [
        (PAPER_FUNCTIONAL_ID, EstimandGraphNodeKind::Functional),
        (
            SAMPLE_ESTIMATOR_ROUTE_ID,
            EstimandGraphNodeKind::SampleEstimatorRoute,
        ),
        (
            UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
            EstimandGraphNodeKind::ImplementationMethod,
        ),
        (
            PID2_IMPLEMENTATION_ENTRY_POINT,
            EstimandGraphNodeKind::ImplementationEntryPoint,
        ),
        (
            PID3_IMPLEMENTATION_ENTRY_POINT,
            EstimandGraphNodeKind::ImplementationEntryPoint,
        ),
    ];
    for required_identity in required_identity_nodes {
        let matches = nodes
            .iter()
            .filter(|node| (node.node_id, node.kind) == required_identity)
            .count();
        if matches != 1 {
            return Err(CrebainMgwError::Contract(
                "estimand graph role and identity binding changed".to_string(),
            ));
        }
    }
    let required_identity_edges = [
        (
            PAPER_FUNCTIONAL_ID,
            SAMPLE_ESTIMATOR_ROUTE_ID,
            EstimandGraphEdgeKind::EstimatedBy,
        ),
        (
            "pmf.horizontal",
            SAMPLE_ESTIMATOR_ROUTE_ID,
            EstimandGraphEdgeKind::ConsumedBy,
        ),
        (
            "pmf.volumetric",
            SAMPLE_ESTIMATOR_ROUTE_ID,
            EstimandGraphEdgeKind::ConsumedBy,
        ),
        (
            SAMPLE_ESTIMATOR_ROUTE_ID,
            UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
            EstimandGraphEdgeKind::ImplementedBy,
        ),
        (
            UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
            PID2_IMPLEMENTATION_ENTRY_POINT,
            EstimandGraphEdgeKind::ExposedThrough,
        ),
        (
            UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
            PID3_IMPLEMENTATION_ENTRY_POINT,
            EstimandGraphEdgeKind::ExposedThrough,
        ),
        (
            "pmf.horizontal",
            PID2_IMPLEMENTATION_ENTRY_POINT,
            EstimandGraphEdgeKind::SubmittedTo,
        ),
        (
            "pmf.volumetric",
            PID3_IMPLEMENTATION_ENTRY_POINT,
            EstimandGraphEdgeKind::SubmittedTo,
        ),
    ];
    for required_identity in required_identity_edges {
        let matches = edges
            .iter()
            .filter(|edge| (edge.from, edge.to, edge.kind) == required_identity)
            .count();
        if matches != 1 {
            return Err(CrebainMgwError::Contract(
                "estimand graph functional, sample-estimator, implementation, or arity binding changed"
                    .to_string(),
            ));
        }
    }
    let primary_question = CrebainMgwQuestionSpec::primary_pid2();
    let exploratory_question = CrebainMgwQuestionSpec::exploratory_pid3();
    let functional_count = METHOD_ELIGIBILITY
        .iter()
        .filter(|row| row.object_id == PAPER_FUNCTIONAL_ID)
        .count();
    let sample_estimator_route_count = METHOD_ELIGIBILITY
        .iter()
        .filter(|row| row.object_id == SAMPLE_ESTIMATOR_ROUTE_ID)
        .count();
    let implementation_method_count = METHOD_ELIGIBILITY
        .iter()
        .filter(|row| row.object_id == UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID)
        .count();
    let pid2_method_count = METHOD_ELIGIBILITY
        .iter()
        .filter(|row| row.implementation_entry_point == Some(PID2_IMPLEMENTATION_ENTRY_POINT))
        .count();
    let pid3_method_count = METHOD_ELIGIBILITY
        .iter()
        .filter(|row| row.implementation_entry_point == Some(PID3_IMPLEMENTATION_ENTRY_POINT))
        .count();
    let question_and_method_identity_coordinates = [
        primary_question.paper_functional_id == PAPER_FUNCTIONAL_ID,
        exploratory_question.paper_functional_id == PAPER_FUNCTIONAL_ID,
        primary_question.sample_estimator_route_id == SAMPLE_ESTIMATOR_ROUTE_ID,
        exploratory_question.sample_estimator_route_id == SAMPLE_ESTIMATOR_ROUTE_ID,
        primary_question.upstream_implementation_method_catalog_id
            == UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
        exploratory_question.upstream_implementation_method_catalog_id
            == UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
        primary_question.implementation_entry_point == PID2_IMPLEMENTATION_ENTRY_POINT,
        exploratory_question.implementation_entry_point == PID3_IMPLEMENTATION_ENTRY_POINT,
        functional_count == 1,
        sample_estimator_route_count == 1,
        implementation_method_count == 1,
        pid2_method_count == 1,
        pid3_method_count == 1,
    ];
    if question_and_method_identity_coordinates.contains(&false) {
        return Err(CrebainMgwError::Contract(
            "question, eligibility matrix, and estimand graph identities diverged".to_string(),
        ));
    }
    let advisory_nodes: Vec<_> = nodes
        .iter()
        .filter(|node| node.kind == EstimandGraphNodeKind::AdvisoryView)
        .collect();
    if advisory_nodes.len() != 1 {
        return Err(CrebainMgwError::Contract(
            "estimand graph advisory sink or edge semantics changed".to_string(),
        ));
    }
    if advisory_nodes[0].node_id != "view.advisory-only" {
        return Err(CrebainMgwError::Contract(
            "estimand graph advisory sink or edge semantics changed".to_string(),
        ));
    }
    if advisory_nodes[0].boundary != AUTHORITY_BOUNDARY {
        return Err(CrebainMgwError::Contract(
            "estimand graph advisory sink or edge semantics changed".to_string(),
        ));
    }
    let advisory_edges = edges
        .iter()
        .filter(|edge| edge.to == "view.advisory-only")
        .collect::<Vec<_>>();
    if advisory_edges.len() != 1 {
        return Err(CrebainMgwError::Contract(
            "estimand graph advisory sink or edge semantics changed".to_string(),
        ));
    }
    if advisory_edges[0].kind != EstimandGraphEdgeKind::ExposedAs {
        return Err(CrebainMgwError::Contract(
            "estimand graph advisory sink or edge semantics changed".to_string(),
        ));
    }
    Ok(())
}

/// Exact producer fixture identity and declared pid-core selection used by this study.
///
/// Repository and revision strings are provenance coordinates, not proof that source, archive,
/// or binary bytes equal one another. The compiled pid-core source identity is reconciled
/// separately before a study result is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FixtureIdentity {
    producer_repository: &'static str,
    producer_revision: &'static str,
    producer_path: &'static str,
    fixture_sha256: &'static str,
    fixture_bytes: usize,
    analysis_manifest_sha256: &'static str,
    pid_core_repository: &'static str,
    producer_registered_pid_core_revision: &'static str,
    actual_pid_core_version: &'static str,
    actual_pid_core_revision: &'static str,
    mutation_policy: &'static str,
}

impl FixtureIdentity {
    const fn exact() -> Self {
        Self {
            producer_repository: "https://github.com/sepahead/crebain",
            producer_revision: CREBAIN_FIXTURE_REVISION,
            producer_path: CREBAIN_FIXTURE_PATH,
            fixture_sha256: CREBAIN_FIXTURE_SHA256,
            fixture_bytes: CREBAIN_FIXTURE_BYTES,
            analysis_manifest_sha256: CREBAIN_ANALYSIS_MANIFEST_SHA256,
            pid_core_repository: PID_RS_GIT_REPOSITORY,
            producer_registered_pid_core_revision: PREREGISTERED_PID_RS_REVISION,
            actual_pid_core_version: PID_RS_VERSION,
            actual_pid_core_revision: PID_RS_REVISION,
            mutation_policy:
                "pid-rs is read-only. The exact commit is selected by Galadriel Cargo.lock. Package-subtree source state is reconciled separately",
        }
    }

    pub const fn producer_revision(self) -> &'static str {
        self.producer_revision
    }
    pub const fn fixture_sha256(self) -> &'static str {
        self.fixture_sha256
    }
    pub const fn actual_pid_core_revision(self) -> &'static str {
        self.actual_pid_core_revision
    }
}

/// Explicit adaptation from the immutable producer preregistration to the reviewed sample-
/// estimator implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SampleEstimatorImplementationAdaptation {
    producer_registered_revision: &'static str,
    selected_implementation_revision: &'static str,
    revision_relation: &'static str,
    api_change_review: &'static str,
    semantic_route_and_estimand_preservation: &'static str,
    schema_consequence: &'static str,
    verification_scope: &'static str,
}

impl SampleEstimatorImplementationAdaptation {
    const fn reviewed() -> Self {
        Self {
            producer_registered_revision: PREREGISTERED_PID_RS_REVISION,
            selected_implementation_revision: PID_RS_REVISION,
            revision_relation: "the immutable producer preregistration and selected sample-estimator implementation are distinct exact revisions. This receipt does not assert or rely on repository ancestry",
            api_change_review: "nominal pointwise/averaged atom split, explicit nats accessors, interpretation metadata, software identity, and explicit categorical resource preflight were reviewed",
            semantic_route_and_estimand_preservation: "the semantic route is raw rows to an empirical PMF sample estimate of the same categorical MGW paper functional, with the same ordered sources, targets, lattice coordinates, natural-log units, signed atoms, and pointwise inclusion",
            schema_consequence: "Galadriel study schema v3 replaces the unpublished v2 object because v2 conflated paper-functional, sample-estimator, implementation-method, and entry-point roles. The immutable producer v1 fixture and its preregistration bytes remain unchanged",
            verification_scope: "release qualification must recheck both exact revision identities, estimand preservation, the complete averaged-atom oracle, analytic PID2 law, predicate-isolating metamorphic controls, and candidate-bound output. This record alone is not compatibility proof",
        }
    }
}

/// One append-only correction to wording or field semantics retained in the producer fixture.
///
/// The fixture bytes remain unchanged. This typed record prevents a consumer from treating a
/// historically frozen sentence or label as a current scientific or operational claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProducerSourceErratum {
    source_surface: &'static str,
    json_pointer: &'static str,
    frozen_literal: &'static str,
    inspected_source_revision: &'static str,
    inspected_source_locator: &'static str,
    corrected_statement: &'static str,
    scientific_or_operational_impact: &'static str,
    disposition: &'static str,
}

const PRODUCER_SOURCE_ERRATA: [ProducerSourceErratum; 3] = [
    ProducerSourceErratum {
        source_surface: "analysis_manifest",
        json_pointer: "/target_origin",
        frozen_literal: PREREGISTERED_TARGET_ORIGIN_LITERAL,
        inspected_source_revision: CREBAIN_FIXTURE_REVISION,
        inspected_source_locator: "src-tauri/src/sensor_fusion.rs:7618-7649",
        corrected_statement: "the synthetic target is derived from the latent ENU cell after the producer constructs sensor observation objects and source symbols, but before fusion. The target calculation does not read serialized source fields, sensor projections, fusion output, Galadriel verdicts, or PID results",
        scientific_or_operational_impact: "corrects execution-order and producer-independence wording. The target remains dataflow-independent of projection, fusion, verdict, and PID, so the declared categorical law and all numerical results are unchanged",
        disposition: "consumer-side append-only erratum. Immutable producer fixture and preregistration bytes are retained",
    },
    ProducerSourceErratum {
        source_surface: "analysis_manifest",
        json_pointer: "/method_exclusions/nis_and_correlation",
        frozen_literal: PREREGISTERED_OPERATIONAL_METHOD_LITERAL,
        inspected_source_revision: "Galadriel 0.9.0 candidate source",
        inspected_source_locator: "crates/galadriel-core/src/decision.rs:31-36,80-83",
        corrected_statement: "Galadriel's separate operational magnitude lane uses normalized innovation squared plus a two-arm CUSUM. On the fusion core's dof=3 route, the lower arm is inert. Other admitted degrees of freedom retain the general recurrence. Signed Pearson correlation is a distinct directional association diagnostic. None of these objects is evaluated by this fixture",
        scientific_or_operational_impact: "adds the omitted CUSUM object and separates operational availability from evidence produced here. No PID estimand, sample-estimator call, or result changes",
        disposition: "consumer-side append-only erratum. Immutable producer fixture and preregistration bytes are retained",
    },
    ProducerSourceErratum {
        source_surface: "fixture_rows",
        json_pointer: "/rows/*/fusion_receipt/{projection_count,common_projection_prior_id}",
        frozen_literal: "projection_count=3 and common_projection_prior_id=2 in every retained row",
        inspected_source_revision: CREBAIN_FIXTURE_REVISION,
        inspected_source_locator: "src-tauri/src/sensor_fusion.rs:7664-7707",
        corrected_statement: "the producer assigns projection_count from pid_observations.len(). It proves three admitted observations, while common_projection_prior_id proves that at least one projection exists and every present projection uses prior 2. Neither field proves that all three observations carried a non-None consistency projection",
        scientific_or_operational_impact: "narrows the bounded six-field fusion-summary claim. Source symbols and targets used by PID do not depend on this field, so the declared categorical law and all numerical results are unchanged",
        disposition: "consumer-side append-only field-semantic erratum. The immutable producer field name and fixture bytes are retained",
    },
];

/// Complete consumer-side reconciliation of known wording and field-semantic defects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProducerSourceErrataReceipt {
    fixture_bytes_retained_unchanged: bool,
    entries: &'static [ProducerSourceErratum],
    every_frozen_literal_matched_before_correction: bool,
    policy: &'static str,
}

fn producer_source_errata_receipt() -> ProducerSourceErrataReceipt {
    ProducerSourceErrataReceipt {
        fixture_bytes_retained_unchanged: true,
        entries: &PRODUCER_SOURCE_ERRATA,
        every_frozen_literal_matched_before_correction: true,
        policy: "the immutable producer fixture remains custody evidence, while this append-only consumer receipt is the current authority for the three corrected statements and field semantics. No correction upgrades the synthetic fixture into field evidence",
    }
}

/// Fail-closed reconciliation of Galadriel's selected revision with pid-core's embedded source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidCoreSourceReconciliation {
    expected_revision: &'static str,
    observed_source: SourceIdentity,
    pid_core_package_subtree_clean_revision_matched: bool,
    policy: &'static str,
}

fn reconcile_pid_core_source(identity: &SoftwareIdentity) -> Result<PidCoreSourceReconciliation> {
    let observed_source = *identity.source();
    let (commit_sha1, working_tree_scope, working_tree) = match observed_source {
        SourceIdentity::WorkspaceGit {
            commit_sha1,
            working_tree_scope,
            working_tree,
            ..
        } => (commit_sha1, working_tree_scope, working_tree),
        _ => {
            return Err(CrebainMgwError::Contract(
                "pid-core source identity is not the required WorkspaceGit variant. Cargo archive metadata, unavailable identity, unknown identity, and future variants cannot prove the selected Git dependency's checked-out source state"
                    .to_string(),
            ));
        }
    };
    validate_pid_core_workspace_source(commit_sha1, working_tree_scope, working_tree)?;
    Ok(PidCoreSourceReconciliation {
        expected_revision: PID_RS_REVISION,
        observed_source,
        pid_core_package_subtree_clean_revision_matched: true,
        policy: "accept only a layout-matched WorkspaceGit pid-core source identity at the declared commit with the upstream pid-core package-path scope reporting clean at build time. This is not a whole-repository cleanliness claim, and Cargo archive metadata, unavailable, unknown, dirty, mismatched, or future unreviewed variants fail closed",
    })
}

fn validate_pid_core_workspace_source(
    commit_sha1: &str,
    working_tree_scope: WorkingTreeScope,
    working_tree: WorkingTreeState,
) -> Result<()> {
    if commit_sha1 != PID_RS_REVISION
        || working_tree_scope != WorkingTreeScope::PidCorePackagePath
        || working_tree != WorkingTreeState::Clean
    {
        return Err(CrebainMgwError::Contract(format!(
            "pid-core source identity does not match the selected clean package-subtree revision: commit={commit_sha1}, working_tree_scope={working_tree_scope:?}, working_tree={working_tree:?}, expected_commit={PID_RS_REVISION}, expected_scope={:?}",
            WorkingTreeScope::PidCorePackagePath,
        )));
    }
    Ok(())
}

/// One executed categorical implementation entry-point call and its exact upstream preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CategoricalResourceCallReceipt {
    call_id: &'static str,
    implementation_entry_point: &'static str,
    source_count: usize,
    row_count: usize,
    pointwise_included: bool,
    estimate: ResourceEstimate,
    preflight_passed: bool,
}

/// Galadriel-owned deterministic resource policy and every executed-call preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CategoricalResourceReceipt {
    budget: ResourceBudget,
    calls: Vec<CategoricalResourceCallReceipt>,
    policy: &'static str,
}

/// Reviewed upstream interpretation contract retained without redefining the paper atoms.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AtomInterpretationReceipt {
    upstream_implementation_method_catalog_id: &'static str,
    upstream_interpretation_catalog_id: &'static str,
    averaged: SxAtomInterpretation,
    pointwise: SxAtomInterpretation,
    pid2_pointwise_realizations: usize,
    pid3_pointwise_realizations: usize,
    pid3_canonical_antichains: usize,
    pointwise_support_mass_and_averaging_matched: bool,
    canonical_pointwise_realization_order_matched: bool,
    pointwise_to_averaged_max_abs_error_nats: f64,
    every_retained_atom_interpretation_matched: bool,
    axiomatic_caveat_edges: &'static [ReferenceEdge],
    axiomatic_boundary: &'static str,
    galadriel_owned_additional_limits: &'static [&'static str],
}

/// One fixed PID question. Sources are ordered and target truth is external to fusion and PID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrebainMgwQuestionSpec {
    question_id: &'static str,
    paper_functional_id: &'static str,
    sample_estimator_route_id: &'static str,
    upstream_implementation_method_catalog_id: &'static str,
    reference_edges: &'static [ReferenceEdge],
    axiomatic_caveat_edges: &'static [ReferenceEdge],
    implementation_entry_point: &'static str,
    ordered_sources: &'static [&'static str],
    target: &'static str,
    target_origin: &'static str,
    law: &'static str,
    output_coordinates: &'static str,
    units: &'static str,
    status: &'static str,
    authority_boundary: &'static str,
}

impl CrebainMgwQuestionSpec {
    fn primary_pid2() -> Self {
        Self {
            question_id: "crebain-drone-horizontal-incursion-mgw-pid2-v3",
            paper_functional_id: PAPER_FUNCTIONAL_ID,
            sample_estimator_route_id: SAMPLE_ESTIMATOR_ROUTE_ID,
            upstream_implementation_method_catalog_id:
                UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
            reference_edges: &MGW_REFERENCE_EDGES,
            axiomatic_caveat_edges: &MGW_AXIOMATIC_CAVEAT_EDGES,
            implementation_entry_point: PID2_IMPLEMENTATION_ENTRY_POINT,
            ordered_sources: &SOURCE_ORDER[..2],
            target: "horizontal_incursion",
            target_origin: "synthetic canonical map_enu truth: east <= 50 m AND north <= 1 m. It is derived from preregistered latent ENU coordinates without reading serialized source symbols, sensor projections, fusion output, Galadriel verdicts, or PID results, and before fusion",
            law: "exact equal-weight empirical categorical PMF over the 64 declared rows. Eight repetitions of each three-bit source cell add mass but no inferential precision",
            output_coordinates: "two-source Williams--Beer antichain lattice: redundancy, unique visual, unique radar, and synergy, each with informative, misinformative, and signed net components",
            units: "nats",
            status: "primary deterministic categorical decomposition",
            authority_boundary: AUTHORITY_BOUNDARY,
        }
    }

    fn exploratory_pid3() -> Self {
        Self {
            question_id: "crebain-drone-volumetric-incursion-mgw-pid3-v3",
            paper_functional_id: PAPER_FUNCTIONAL_ID,
            sample_estimator_route_id: SAMPLE_ESTIMATOR_ROUTE_ID,
            upstream_implementation_method_catalog_id:
                UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
            reference_edges: &MGW_REFERENCE_EDGES,
            axiomatic_caveat_edges: &MGW_AXIOMATIC_CAVEAT_EDGES,
            implementation_entry_point: PID3_IMPLEMENTATION_ENTRY_POINT,
            ordered_sources: &SOURCE_ORDER,
            target: "volumetric_incursion",
            target_origin: "synthetic canonical map_enu truth: east <= 50 m AND north <= 1 m AND up <= 1 m. It is derived from preregistered latent ENU coordinates without reading serialized source symbols, sensor projections, fusion output, Galadriel verdicts, or PID results, and before fusion",
            law: "exact equal-weight empirical categorical PMF over the 64 declared rows. Source order is visual, radar, and acoustic",
            output_coordinates: "all 18 antichains of the three-source Williams--Beer lattice, each with informative, misinformative, and signed net components",
            units: "nats",
            status: "exploratory. It does not close the separate 108-coordinate assurance program",
            authority_boundary: AUTHORITY_BOUNDARY,
        }
    }

    pub const fn question_id(&self) -> &'static str {
        self.question_id
    }
    pub const fn ordered_sources(&self) -> &'static [&'static str] {
        self.ordered_sources
    }
    pub const fn target(&self) -> &'static str {
        self.target
    }
}

/// Exact synthetic-row and finite-law checks completed before PID evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureValidation {
    row_count: usize,
    unique_episode_count: usize,
    cell_counts: [usize; CELL_COUNT],
    row_window_timestamps_matched: usize,
    bounded_fusion_summary_receipts: usize,
    synthetic_source_rows_reconstructed: usize,
    latent_truth_target_rows_reconstructed: usize,
    row_order_digest_algorithm: &'static str,
    row_order_sha256: String,
    inference_claim: &'static str,
}

/// Reconstruction and fixed-source controls over the produced PID values.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AlgebraChecks {
    pid2_self_redundancy_max_abs_error_nats: f64,
    pid2_joint_reconstruction_abs_error_nats: f64,
    pid3_downset_reconstruction_max_abs_error_nats: f64,
    pid3_singleton_and_joint_identity_max_abs_error_nats: f64,
    pid2_fixed_source_informative_max_abs_delta_nats: f64,
    pid3_fixed_source_informative_max_abs_delta_nats: f64,
    pid2_closed_form: Pid2ClosedFormReceipt,
    pid3_and_law_mi_max_abs_error_nats: f64,
    fixed_source_sensitivity: FixedSourceSensitivityReceipt,
    tolerance_nats: f64,
    all_passed: bool,
    caution: &'static str,
}

/// Exact-form checks for the balanced binary AND law used by the primary question.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Pid2ClosedFormReceipt {
    law: &'static str,
    redundancy_informative_formula: &'static str,
    redundancy_misinformative_formula: &'static str,
    unique_informative_formula: &'static str,
    unique_misinformative_formula: &'static str,
    synergy_informative_formula: &'static str,
    synergy_misinformative_formula: &'static str,
    joint_information_formula: &'static str,
    maximum_component_abs_error_nats: f64,
    atom_sum_abs_error_nats: f64,
    all_passed: bool,
}

/// Deterministic metamorphic controls for the fixed-source informative-invariance theorem canary.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FixedSourceSensitivityReceipt {
    pid2_rotated_target_changed_rows: usize,
    pid3_rotated_target_changed_rows: usize,
    pid2_misinformative_max_abs_delta_nats: f64,
    pid2_net_max_abs_delta_nats: f64,
    pid3_misinformative_max_abs_delta_nats: f64,
    pid3_net_max_abs_delta_nats: f64,
    changed_source_informative_max_abs_delta_nats: f64,
    rotated_pid3_minimum_net_nats: f64,
    rotated_pid3_minimum_net_antichain: Vec<u8>,
    asymmetric_wiring_unique_one_nats: f64,
    asymmetric_wiring_unique_two_nats: f64,
    asymmetric_pid2_pointwise_named_field_max_abs_error_nats: f64,
    asymmetric_pid3_source_and_atom_position_max_abs_error_nats: f64,
    all_passed: bool,
    boundary: &'static str,
}

/// Exact formal-schema artifact compiled into this candidate and checked outside Rust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineSchemaReceipt {
    identifier: &'static str,
    dialect: &'static str,
    canonical_id: &'static str,
    repository_path: &'static str,
    sha256: String,
    bytes: usize,
    closed_world_required: bool,
    validation_checker: &'static str,
    scope: &'static str,
}

fn machine_schema_receipt() -> MachineSchemaReceipt {
    let schema = bundled_crebain_drone_mgw_schema();
    MachineSchemaReceipt {
        identifier: CREBAIN_DRONE_MGW_STUDY_SCHEMA,
        dialect: "https://json-schema.org/draft/2020-12/schema",
        canonical_id: CREBAIN_DRONE_MGW_STUDY_SCHEMA_ID,
        repository_path: CREBAIN_DRONE_MGW_STUDY_SCHEMA_PATH,
        sha256: sha256_hex(schema.as_bytes()),
        bytes: schema.len(),
        closed_world_required: true,
        validation_checker: "repo_work/check_crebain_mgw_schema.py",
        scope: "the schema closes object fields, enums, role-to-identity conditionals, arity-specific entry-point pairings, required coordinates, and fixed cardinalities for this v3 wire object. The external checker also binds this receipt to the exact schema bytes and validates actual candidate JSON",
    }
}

/// Complete build-identified study output. Only the fixture and preregistration bytes are immutable.
///
/// The retained upstream objects expose every signed component. The pid-core software identity is
/// build-context dependent and therefore must be rebound for each candidate evidence bundle.
#[derive(Debug, Serialize)]
pub struct CrebainDroneMgwStudy {
    schema: &'static str,
    machine_schema: MachineSchemaReceipt,
    scientific_status: &'static str,
    authority_boundary: &'static str,
    fixture_identity: FixtureIdentity,
    sample_estimator_implementation_adaptation: SampleEstimatorImplementationAdaptation,
    producer_source_errata: ProducerSourceErrataReceipt,
    pid_core_software_identity: SoftwareIdentity,
    pid_core_source_reconciliation: PidCoreSourceReconciliation,
    fixture_validation: FixtureValidation,
    primary_question: CrebainMgwQuestionSpec,
    exploratory_question: CrebainMgwQuestionSpec,
    method_eligibility: &'static [MethodEligibility],
    estimand_graph: EstimandGraphReceipt,
    resource_receipt: CategoricalResourceReceipt,
    atom_interpretation: AtomInterpretationReceipt,
    pid2: DiscreteSxPid2Result,
    pid3: DiscreteSxPid3Result,
    algebra_checks: AlgebraChecks,
    interpretation_guard: &'static str,
}

impl CrebainDroneMgwStudy {
    pub const fn schema(&self) -> &'static str {
        self.schema
    }
    pub const fn machine_schema(&self) -> &MachineSchemaReceipt {
        &self.machine_schema
    }
    pub const fn fixture_identity(&self) -> FixtureIdentity {
        self.fixture_identity
    }
    pub const fn fixture_validation(&self) -> &FixtureValidation {
        &self.fixture_validation
    }
    pub const fn sample_estimator_implementation_adaptation(
        &self,
    ) -> SampleEstimatorImplementationAdaptation {
        self.sample_estimator_implementation_adaptation
    }
    pub const fn producer_source_errata(&self) -> ProducerSourceErrataReceipt {
        self.producer_source_errata
    }
    pub const fn resource_receipt(&self) -> &CategoricalResourceReceipt {
        &self.resource_receipt
    }
    pub const fn atom_interpretation(&self) -> &AtomInterpretationReceipt {
        &self.atom_interpretation
    }
    pub const fn primary_question(&self) -> &CrebainMgwQuestionSpec {
        &self.primary_question
    }
    pub const fn exploratory_question(&self) -> &CrebainMgwQuestionSpec {
        &self.exploratory_question
    }
    pub const fn method_eligibility(&self) -> &'static [MethodEligibility] {
        self.method_eligibility
    }
    pub const fn estimand_graph(&self) -> EstimandGraphReceipt {
        self.estimand_graph
    }
    pub const fn pid2(&self) -> &DiscreteSxPid2Result {
        &self.pid2
    }
    pub const fn pid3(&self) -> &DiscreteSxPid3Result {
        &self.pid3
    }
    pub const fn algebra_checks(&self) -> &AlgebraChecks {
        &self.algebra_checks
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    bytes_to_hex(&Sha256::digest(bytes))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn canonical_json(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(&serde_json::to_string(value)?),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key)?);
                output.push(':');
                let value = values.get(*key).ok_or_else(|| {
                    CrebainMgwError::Contract(format!(
                        "canonical JSON key disappeared during traversal: {key}"
                    ))
                })?;
                canonical_json(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn require_json(root: &Value, pointer: &str, expected: Value) -> Result<()> {
    let observed = root
        .pointer(pointer)
        .ok_or_else(|| CrebainMgwError::Contract(format!("analysis manifest omits {pointer}")))?;
    if observed != &expected {
        return Err(CrebainMgwError::Contract(format!(
            "analysis manifest {pointer} mismatch: expected {expected}, observed {observed}"
        )));
    }
    Ok(())
}

fn validate_producer_source_errata_literals(fixture: &Fixture) -> Result<()> {
    let manifest = &fixture.analysis_manifest;
    require_json(
        manifest,
        "/target_origin",
        Value::from(PREREGISTERED_TARGET_ORIGIN_LITERAL),
    )?;
    require_json(
        manifest,
        "/method_exclusions/nis_and_correlation",
        Value::from(PREREGISTERED_OPERATIONAL_METHOD_LITERAL),
    )?;
    if fixture.rows.iter().any(|row| {
        row.fusion_receipt.projection_count != 3
            || row.fusion_receipt.common_projection_prior_id != 2
    }) {
        return Err(CrebainMgwError::Contract(
            "frozen fusion-receipt observation/projection literals changed before their source erratum was applied"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_manifest(fixture: &Fixture) -> Result<()> {
    if fixture.schema_version != "crebain.drone-mgw-study/1.0.0" {
        return Err(CrebainMgwError::Contract(format!(
            "schema_version mismatch: {}",
            fixture.schema_version
        )));
    }
    if fixture.analysis_manifest_canonicalization
        != "recursive lexicographic UTF-8 object keys; serde_json scalar encoding; no whitespace; v1"
    {
        return Err(CrebainMgwError::Contract(
            "analysis-manifest canonicalization contract changed".to_string(),
        ));
    }
    if fixture.analysis_manifest_sha256 != CREBAIN_ANALYSIS_MANIFEST_SHA256 {
        return Err(CrebainMgwError::Contract(format!(
            "declared analysis-manifest digest mismatch: {}",
            fixture.analysis_manifest_sha256
        )));
    }
    let mut canonical = String::new();
    canonical_json(&fixture.analysis_manifest, &mut canonical)?;
    let observed = sha256_hex(canonical.as_bytes());
    if observed != CREBAIN_ANALYSIS_MANIFEST_SHA256 {
        return Err(CrebainMgwError::Contract(format!(
            "recomputed analysis-manifest digest mismatch: {observed}"
        )));
    }

    let manifest = &fixture.analysis_manifest;
    require_json(manifest, "/study_id", Value::from(STUDY_ID))?;
    require_json(
        manifest,
        "/scientific_status",
        Value::from("deterministic_categorical_conformance_law_not_inference"),
    )?;
    validate_producer_source_errata_literals(fixture)?;
    require_json(
        manifest,
        "/authority_boundary",
        Value::from(PREREGISTERED_AUTHORITY_BOUNDARY),
    )?;
    require_json(manifest, "/source_order", serde_json::json!(SOURCE_ORDER))?;
    require_json(
        manifest,
        "/consumer_backend/repository",
        Value::from(PID_RS_GIT_REPOSITORY),
    )?;
    require_json(
        manifest,
        "/consumer_backend/revision",
        Value::from(PREREGISTERED_PID_RS_REVISION),
    )?;
    require_json(
        manifest,
        "/consumer_backend/mutation_policy",
        Value::from("read_only"),
    )?;
    require_json(
        manifest,
        "/primary_question/functional_id",
        Value::from(PAPER_FUNCTIONAL_ID),
    )?;
    require_json(
        manifest,
        "/primary_question/route",
        Value::from(PREREGISTERED_PID2_ENTRY_POINT),
    )?;
    require_json(
        manifest,
        "/primary_question/sources",
        serde_json::json!(&SOURCE_ORDER[..2]),
    )?;
    require_json(
        manifest,
        "/primary_question/target",
        Value::from("horizontal_incursion"),
    )?;
    require_json(
        manifest,
        "/exploratory_question/functional_id",
        Value::from(PAPER_FUNCTIONAL_ID),
    )?;
    require_json(
        manifest,
        "/exploratory_question/route",
        Value::from(PREREGISTERED_PID3_ENTRY_POINT),
    )?;
    require_json(
        manifest,
        "/exploratory_question/sources",
        serde_json::json!(SOURCE_ORDER),
    )?;
    require_json(
        manifest,
        "/exploratory_question/target",
        Value::from("volumetric_incursion"),
    )?;
    require_json(manifest, "/sampling_unit/row_count", Value::from(64))?;
    require_json(manifest, "/sampling_unit/factorial_cells", Value::from(8))?;
    require_json(manifest, "/sampling_unit/episodes_per_cell", Value::from(8))?;
    require_json(
        manifest,
        "/sampling_unit/statistical_independence_claim",
        Value::from("none; the eight repetitions per law cell add no stochastic precision"),
    )?;
    require_json(
        manifest,
        "/time_contract/prior_timestamp_ms",
        Value::from(PRIOR_TIMESTAMP_MS),
    )?;
    require_json(
        manifest,
        "/time_contract/observation_timestamp_ms",
        Value::from(OBSERVATION_TIMESTAMP_MS),
    )?;
    require_json(
        manifest,
        "/time_contract/all_three_sources_synchronized",
        Value::from(true),
    )?;
    require_json(manifest, "/uncertainty/p_values", Value::from("none"))?;
    require_json(
        manifest,
        "/uncertainty/confidence_intervals",
        Value::from("none"),
    )?;
    require_json(manifest, "/uncertainty/resampling", Value::from("none"))?;
    Ok(())
}

fn validate_geometry(geometry: &Geometry) -> Result<()> {
    let coordinates = [
        geometry.axis_order == ["east", "north", "up"],
        geometry.canonical_frame == "map_enu",
        geometry.entry_planes_m.east_at_or_below == 50.0,
        geometry.entry_planes_m.north_at_or_below == 1.0,
        geometry.entry_planes_m.up_at_or_below == 1.0,
        geometry.prior_reference_enu_m == [50.0, 1.0, 1.0],
        geometry.target_definitions.horizontal_incursion
            == "truth east and north are at or below their registered entry planes",
        geometry.target_definitions.volumetric_incursion
            == "horizontal_incursion and truth up is at or below its registered entry plane",
    ];
    if coordinates.contains(&false) {
        return Err(CrebainMgwError::Contract(
            "canonical ENU geometry or target definition changed".to_string(),
        ));
    }
    Ok(())
}

fn update_row_digest(hasher: &mut Sha256, row: &FixtureRow) -> Result<()> {
    let episode_len = u64::try_from(row.episode_id.len()).map_err(|_| {
        CrebainMgwError::Contract("episode identifier length exceeds u64".to_string())
    })?;
    hasher.update(episode_len.to_le_bytes());
    hasher.update(row.episode_id.as_bytes());
    for value in [
        row.cell_index,
        row.replicate_index,
        row.sources[0],
        row.sources[1],
        row.sources[2],
        row.horizontal_incursion,
        row.volumetric_incursion,
    ] {
        let value = u64::try_from(value).map_err(|_| {
            CrebainMgwError::Contract("row categorical value exceeds u64".to_string())
        })?;
        hasher.update(value.to_le_bytes());
    }
    hasher.update(row.prior_timestamp_ms.to_le_bytes());
    hasher.update(row.observation_timestamp_ms.to_le_bytes());
    for value in row.truth_enu_m {
        hasher.update(value.to_bits().to_le_bytes());
    }
    Ok(())
}

fn bit(condition: bool) -> usize {
    usize::from(condition)
}

#[derive(Debug)]
struct ValidatedColumns {
    visual: Vec<usize>,
    radar: Vec<usize>,
    acoustic: Vec<usize>,
    horizontal: Vec<usize>,
    volumetric: Vec<usize>,
    validation: FixtureValidation,
}

fn validate_rows(rows: &[FixtureRow]) -> Result<ValidatedColumns> {
    if rows.len() != ROW_COUNT {
        return Err(CrebainMgwError::Contract(format!(
            "expected {ROW_COUNT} rows, observed {}",
            rows.len()
        )));
    }

    let mut episodes = BTreeSet::new();
    let mut cell_counts = [0_usize; CELL_COUNT];
    let mut visual = Vec::with_capacity(ROW_COUNT);
    let mut radar = Vec::with_capacity(ROW_COUNT);
    let mut acoustic = Vec::with_capacity(ROW_COUNT);
    let mut horizontal = Vec::with_capacity(ROW_COUNT);
    let mut volumetric = Vec::with_capacity(ROW_COUNT);
    let mut digest = Sha256::new();

    for (row_index, row) in rows.iter().enumerate() {
        let expected_cell = row_index / EPISODES_PER_CELL;
        let expected_replicate = row_index % EPISODES_PER_CELL;
        let canonical_row_position = [
            row.cell_index == expected_cell,
            row.replicate_index == expected_replicate,
        ];
        if canonical_row_position.contains(&false) {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} violates canonical cell/replicate order"
            )));
        }
        let expected_episode = format!("{STUDY_ID}-c{expected_cell:02}-r{expected_replicate:02}");
        let episode_coordinates = [
            row.episode_id == expected_episode,
            episodes.insert(row.episode_id.as_str()),
        ];
        if episode_coordinates.contains(&false) {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} has a duplicate or noncanonical episode identifier"
            )));
        }
        cell_counts[expected_cell] += 1;

        let expected_sources = [
            (expected_cell >> 2) & 1,
            (expected_cell >> 1) & 1,
            expected_cell & 1,
        ];
        if row.sources != expected_sources {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} source symbols do not encode its ordered factorial cell"
            )));
        }
        let timestamp_coordinates = [
            row.prior_timestamp_ms == PRIOR_TIMESTAMP_MS,
            row.observation_timestamp_ms == OBSERVATION_TIMESTAMP_MS,
        ];
        if timestamp_coordinates.contains(&false) {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} violates the retained row-window timestamp contract"
            )));
        }
        let bounded_fusion_summary_coordinates = [
            row.fusion_receipt.common_projection_prior_id == 2,
            row.fusion_receipt.input_count == 3,
            row.fusion_receipt.projection_count == 3,
            row.fusion_receipt.v1_expected_count == 3,
            !row.fusion_receipt.degraded,
            !row.fusion_receipt.truncated,
        ];
        if bounded_fusion_summary_coordinates.contains(&false) {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} lacks the frozen bounded three-input observation summary: legacy projection_count must equal the admitted-observation count, at least one present projection must use prior 2, and every present projection is producer-source constrained to that prior"
            )));
        }

        let vectors = [
            row.truth_enu_m,
            row.pre_fusion_observations.visual_cartesian_enu_m,
            row.pre_fusion_observations
                .radar_polar_range_azimuth_elevation,
            row.pre_fusion_observations.acoustic_cartesian_enu_m,
        ];
        if vectors.iter().flatten().any(|value| !value.is_finite()) {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} contains a non-finite synthetic coordinate"
            )));
        }

        let visual_bit = bit(row.pre_fusion_observations.visual_cartesian_enu_m[1] <= 1.0);
        let radar_observation = row
            .pre_fusion_observations
            .radar_polar_range_azimuth_elevation;
        let radar_axis_alignment_coordinates =
            [radar_observation[1] == 0.0, radar_observation[2] == 0.0];
        if radar_axis_alignment_coordinates.contains(&false) {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} radar fixture is not aligned with the ENU east axis"
            )));
        }
        let radar_bit = bit(radar_observation[0] <= 50.0);
        let acoustic_bit = bit(row.pre_fusion_observations.acoustic_cartesian_enu_m[2] <= 1.0);
        if [visual_bit, radar_bit, acoustic_bit] != row.sources {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} source symbols cannot be reconstructed from pre-fusion measurements"
            )));
        }

        let expected_truth = [
            if radar_bit == 1 { 49.0 } else { 51.0 },
            if visual_bit == 1 { 0.0 } else { 2.0 },
            if acoustic_bit == 1 { 0.0 } else { 2.0 },
        ];
        let expected_visual = [50.0, expected_truth[1], 1.0];
        let expected_radar = [expected_truth[0], 0.0, 0.0];
        let expected_acoustic = [50.0, 1.0, expected_truth[2]];
        let factorial_geometry_coordinates = [
            row.truth_enu_m == expected_truth,
            row.pre_fusion_observations.visual_cartesian_enu_m == expected_visual,
            radar_observation == expected_radar,
            row.pre_fusion_observations.acoustic_cartesian_enu_m == expected_acoustic,
        ];
        if factorial_geometry_coordinates.contains(&false) {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} synthetic coordinates differ from the declared factorial geometry"
            )));
        }

        let horizontal_bit = bit(row.truth_enu_m[0] <= 50.0 && row.truth_enu_m[1] <= 1.0);
        let volumetric_bit = bit(horizontal_bit == 1 && row.truth_enu_m[2] <= 1.0);
        let target_coordinates = [
            row.horizontal_incursion == horizontal_bit,
            row.volumetric_incursion == volumetric_bit,
        ];
        if target_coordinates.contains(&false) {
            return Err(CrebainMgwError::Contract(format!(
                "row {row_index} target cannot be reconstructed from synthetic latent ENU truth"
            )));
        }

        update_row_digest(&mut digest, row)?;
        visual.push(visual_bit);
        radar.push(radar_bit);
        acoustic.push(acoustic_bit);
        horizontal.push(horizontal_bit);
        volumetric.push(volumetric_bit);
    }

    if cell_counts != [EPISODES_PER_CELL; CELL_COUNT] {
        return Err(CrebainMgwError::Contract(format!(
            "factorial cell balance mismatch: {cell_counts:?}"
        )));
    }

    Ok(ValidatedColumns {
        visual,
        radar,
        acoustic,
        horizontal,
        volumetric,
        validation: FixtureValidation {
            row_count: ROW_COUNT,
            unique_episode_count: episodes.len(),
            cell_counts,
            row_window_timestamps_matched: ROW_COUNT,
            bounded_fusion_summary_receipts: ROW_COUNT,
            synthetic_source_rows_reconstructed: ROW_COUNT,
            latent_truth_target_rows_reconstructed: ROW_COUNT,
            row_order_digest_algorithm: "sha256-v1 over length-prefixed episode UTF-8, categorical fields and timestamps as little-endian u64, and truth binary64 bits as little-endian u64",
            row_order_sha256: bytes_to_hex(&digest.finalize()),
            inference_claim: "none. This is a deterministic conformance law. Repeated cell rows test bounded-summary fresh-instance reproducibility and do not provide p-values, confidence intervals, or an independent sample size of 64 or retain a complete fusion execution",
        },
    })
}

fn matrix(column: Vec<usize>) -> Result<DiscreteMatOwned> {
    let nrows = column.len();
    Ok(DiscreteMatOwned::new(column, nrows, 1)?)
}

fn categorical_resource_budget() -> Result<ResourceBudget> {
    Ok(ResourceBudget::new(
        PID_RESOURCE_MAX_BYTES,
        PID_RESOURCE_MAX_PAIRWISE_DISTANCES,
        PID_RESOURCE_MAX_OPERATIONS_HINT,
        PID_RESOURCE_MAX_THREADS,
    )?)
}

fn evaluate_ordered_pid2(
    call_id: &'static str,
    visual: &DiscreteMatOwned,
    radar: &DiscreteMatOwned,
    target: &DiscreteMatOwned,
    budget: ResourceBudget,
    resource_calls: &mut Vec<CategoricalResourceCallReceipt>,
) -> Result<DiscreteSxPid2Result> {
    let estimate =
        discrete_sxpid2_resource_estimate(visual.as_ref(), radar.as_ref(), target.as_ref(), true)?;
    budget.check(call_id, estimate)?;
    let result =
        discrete_sxpid2_with_budget(visual.as_ref(), radar.as_ref(), target.as_ref(), budget)?;
    resource_calls.push(CategoricalResourceCallReceipt {
        call_id,
        implementation_entry_point: PID2_IMPLEMENTATION_ENTRY_POINT,
        source_count: 2,
        row_count: visual.as_ref().nrows(),
        pointwise_included: true,
        estimate,
        preflight_passed: true,
    });
    Ok(result)
}

fn evaluate_ordered_pid3(
    call_id: &'static str,
    visual: &DiscreteMatOwned,
    radar: &DiscreteMatOwned,
    acoustic: &DiscreteMatOwned,
    target: &DiscreteMatOwned,
    budget: ResourceBudget,
    resource_calls: &mut Vec<CategoricalResourceCallReceipt>,
) -> Result<DiscreteSxPid3Result> {
    let estimate = discrete_sxpid3_resource_estimate(
        visual.as_ref(),
        radar.as_ref(),
        acoustic.as_ref(),
        target.as_ref(),
        true,
    )?;
    budget.check(call_id, estimate)?;
    let result = discrete_sxpid3_with_budget(
        visual.as_ref(),
        radar.as_ref(),
        acoustic.as_ref(),
        target.as_ref(),
        budget,
    )?;
    resource_calls.push(CategoricalResourceCallReceipt {
        call_id,
        implementation_entry_point: PID3_IMPLEMENTATION_ENTRY_POINT,
        source_count: 3,
        row_count: visual.as_ref().nrows(),
        pointwise_included: true,
        estimate,
        preflight_passed: true,
    });
    Ok(result)
}

fn pointwise_average_error(
    values: impl IntoIterator<Item = (f64, SxPointwiseAtom)>,
    averaged: SxAveragedAtom,
) -> f64 {
    let (informative, misinformative) = values.into_iter().fold(
        (0.0_f64, 0.0_f64),
        |(informative, misinformative), (probability, atom)| {
            (
                informative + probability * atom.informative_nats(),
                misinformative + probability * atom.misinformative_nats(),
            )
        },
    );
    max_abs(
        [
            informative - averaged.informative_nats(),
            misinformative - averaged.misinformative_nats(),
            informative - misinformative - averaged.net_nats(),
        ]
        .map(f64::abs),
    )
}

fn validate_atom_interpretation(
    pid2: &DiscreteSxPid2Result,
    pid3: &DiscreteSxPid3Result,
) -> Result<AtomInterpretationReceipt> {
    let averaged = pid2.red.interpretation();
    let pointwise = pid2
        .pointwise
        .first()
        .ok_or_else(|| CrebainMgwError::Contract("pid2 omitted pointwise output".to_string()))?
        .red
        .interpretation();
    let expected_unsupported = [
        SxUnsupportedInference::IntentionalDeception,
        SxUnsupportedInference::CausalEffect,
        SxUnsupportedInference::FaultAttribution,
        SxUnsupportedInference::PerSourceResponsibility,
        SxUnsupportedInference::MeasureIndependentDecomposition,
        SxUnsupportedInference::UnbiasedPopulationEstimate,
    ];
    let fixed_coordinate_checks = [
        averaged.contract_revision() == 1,
        averaged.aggregation_scope() == SxAtomAggregation::EmpiricalPmfAverage,
        pointwise.aggregation_scope() == SxAtomAggregation::PointwiseDistinctJointRealization,
        averaged.context_requirement()
            == SxAtomContextRequirement::ContainingResultForCoordinateAndRealizationContext,
        averaged.decomposition_measure() == SxAtomDecompositionMeasure::SharedExclusionsSxPid,
        averaged.coordinate_semantics()
            == SxAtomCoordinateSemantics::SourceCollectionAntichainMobiusContribution,
        averaged.evidential_scope()
            == SxAtomEvidentialScope::StatisticalInformationUnderSuppliedDistribution,
        averaged.guard_origin() == SxInterpretationGuardOrigin::ProjectDefined,
        averaged.not_established_by_atom_alone() == &expected_unsupported,
        pointwise.contract_revision() == averaged.contract_revision(),
        pointwise.context_requirement() == averaged.context_requirement(),
        pointwise.decomposition_measure() == averaged.decomposition_measure(),
        pointwise.coordinate_semantics() == averaged.coordinate_semantics(),
        pointwise.evidential_scope() == averaged.evidential_scope(),
        pointwise.guard_origin() == averaged.guard_origin(),
        pointwise.not_established_by_atom_alone() == averaged.not_established_by_atom_alone(),
    ];
    let fixed_coordinates = !fixed_coordinate_checks.contains(&false);
    let every_averaged_checks = [
        [pid2.red, pid2.unq1, pid2.unq2, pid2.syn]
            .into_iter()
            .all(|atom| atom.interpretation() == averaged),
        pid3.atoms
            .iter()
            .all(|atom| atom.interpretation() == averaged),
    ];
    let every_averaged = !every_averaged_checks.contains(&false);
    let canonical_pid3_antichain_checks = [
        pid3.antichains.len() == PID3_CANONICAL_ANTICHAINS.len(),
        pid3.antichains
            .iter()
            .zip(PID3_CANONICAL_ANTICHAINS)
            .all(|(observed, expected)| observed.as_slice() == expected),
    ];
    let canonical_pid3_antichains = !canonical_pid3_antichain_checks.contains(&false);
    let observed_pid2_keys = pid2
        .pointwise
        .iter()
        .filter_map(
            |row| match (row.s1.as_slice(), row.s2.as_slice(), row.t.as_slice()) {
                ([s1], [s2], [target]) => Some((*s1, *s2, *target)),
                _ => None,
            },
        )
        .collect::<BTreeSet<_>>();
    let expected_pid2_key_order = vec![(0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 1)];
    let expected_pid2_keys = expected_pid2_key_order
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let observed_pid2_key_order = pid2
        .pointwise
        .iter()
        .map(
            |row| match (row.s1.as_slice(), row.s2.as_slice(), row.t.as_slice()) {
                ([s1], [s2], [target]) => Some((*s1, *s2, *target)),
                _ => None,
            },
        )
        .collect::<Option<Vec<_>>>();
    let observed_pid3_keys = pid3
        .pointwise
        .iter()
        .filter_map(|row| {
            match (
                row.s0.as_slice(),
                row.s1.as_slice(),
                row.s2.as_slice(),
                row.t.as_slice(),
            ) {
                ([s0], [s1], [s2], [target]) => Some((*s0, *s1, *s2, *target)),
                _ => None,
            }
        })
        .collect::<BTreeSet<_>>();
    let mut expected_pid3_keys = BTreeSet::new();
    let mut expected_pid3_key_order = Vec::with_capacity(8);
    for s0 in 0..=1 {
        for s1 in 0..=1 {
            for s2 in 0..=1 {
                let key = (s0, s1, s2, s0 & s1 & s2);
                expected_pid3_keys.insert(key);
                expected_pid3_key_order.push(key);
            }
        }
    }
    let observed_pid3_key_order = pid3
        .pointwise
        .iter()
        .map(|row| {
            match (
                row.s0.as_slice(),
                row.s1.as_slice(),
                row.s2.as_slice(),
                row.t.as_slice(),
            ) {
                ([s0], [s1], [s2], [target]) => Some((*s0, *s1, *s2, *target)),
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>();
    let canonical_pointwise_order_checks = [
        observed_pid2_key_order.as_ref() == Some(&expected_pid2_key_order),
        observed_pid3_key_order.as_ref() == Some(&expected_pid3_key_order),
    ];
    let canonical_pointwise_realization_order_matched =
        !canonical_pointwise_order_checks.contains(&false);
    let mut pointwise_average_errors = vec![
        pointwise_average_error(
            pid2.pointwise
                .iter()
                .map(|row| (row.empirical_probability, row.red)),
            pid2.red,
        ),
        pointwise_average_error(
            pid2.pointwise
                .iter()
                .map(|row| (row.empirical_probability, row.unq1)),
            pid2.unq1,
        ),
        pointwise_average_error(
            pid2.pointwise
                .iter()
                .map(|row| (row.empirical_probability, row.unq2)),
            pid2.unq2,
        ),
        pointwise_average_error(
            pid2.pointwise
                .iter()
                .map(|row| (row.empirical_probability, row.syn)),
            pid2.syn,
        ),
    ];
    let pid3_pointwise_atom_shape_checks = [
        pid3.atoms.len() == PID3_CANONICAL_ANTICHAINS.len(),
        pid3.pointwise
            .iter()
            .all(|row| row.atoms.len() == PID3_CANONICAL_ANTICHAINS.len()),
    ];
    let pid3_pointwise_atom_shape = !pid3_pointwise_atom_shape_checks.contains(&false);
    if pid3_pointwise_atom_shape {
        pointwise_average_errors.extend(pid3.atoms.iter().enumerate().map(
            |(index, averaged_atom)| {
                pointwise_average_error(
                    pid3.pointwise
                        .iter()
                        .map(|row| (row.empirical_probability, row.atoms[index])),
                    *averaged_atom,
                )
            },
        ));
    } else {
        pointwise_average_errors.push(f64::INFINITY);
    }
    let pointwise_to_averaged_max_abs_error_nats = max_abs(pointwise_average_errors);
    let pointwise_support_mass_and_averaging_checks = [
        pid2.pointwise_included,
        pid3.pointwise_included,
        pid2.pointwise.len() == 4,
        pid3.pointwise.len() == 8,
        observed_pid2_keys == expected_pid2_keys,
        observed_pid3_keys == expected_pid3_keys,
        canonical_pointwise_realization_order_matched,
        pid2.pointwise.iter().all(|row| row.empirical_count == 16),
        pid2.pointwise
            .iter()
            .all(|row| row.empirical_probability.to_bits() == 0.25_f64.to_bits()),
        pid3.pointwise.iter().all(|row| row.empirical_count == 8),
        pid3.pointwise
            .iter()
            .all(|row| row.empirical_probability.to_bits() == 0.125_f64.to_bits()),
        pid3_pointwise_atom_shape,
        canonical_pid3_antichains,
        pointwise_to_averaged_max_abs_error_nats <= 1.0e-12,
    ];
    let pointwise_support_mass_and_averaging_matched =
        !pointwise_support_mass_and_averaging_checks.contains(&false);
    let every_pointwise_checks = [
        pid2.pointwise.iter().all(|row| {
            [row.red, row.unq1, row.unq2, row.syn]
                .into_iter()
                .all(|atom| atom.interpretation() == pointwise)
        }),
        pid3.pointwise.iter().all(|row| {
            row.atoms
                .iter()
                .all(|atom| atom.interpretation() == pointwise)
        }),
    ];
    let every_pointwise = !every_pointwise_checks.contains(&false);
    let interpretation_contract_checks = [
        fixed_coordinates,
        every_averaged,
        every_pointwise,
        pointwise_support_mass_and_averaging_matched,
    ];
    if interpretation_contract_checks.contains(&false) {
        return Err(CrebainMgwError::Contract(
            "pid-core categorical atom interpretation contract drifted".to_string(),
        ));
    }
    Ok(AtomInterpretationReceipt {
        upstream_implementation_method_catalog_id:
            UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
        upstream_interpretation_catalog_id: UPSTREAM_INTERPRETATION_CATALOG_ID,
        averaged,
        pointwise,
        pid2_pointwise_realizations: pid2.pointwise.len(),
        pid3_pointwise_realizations: pid3.pointwise.len(),
        pid3_canonical_antichains: pid3.antichains.len(),
        pointwise_support_mass_and_averaging_matched: true,
        canonical_pointwise_realization_order_matched: true,
        pointwise_to_averaged_max_abs_error_nats,
        every_retained_atom_interpretation_matched: true,
        axiomatic_caveat_edges: &MGW_AXIOMATIC_CAVEAT_EDGES,
        axiomatic_boundary: "exact computation of the selected categorical shared-exclusions functional on this law does not validate it as the unique normative PID, satisfy every proposed identity or positivity axiom, or establish multivariate cross-system consistency",
        galadriel_owned_additional_limits: &[
            "no Haldir authorization, restriction, command, trust, fault, intent, or causal inference",
            "no drone-performance, sensor-quality, attack-detection, or field-validity inference",
            "the PID3 result is exploratory and does not close the 108-coordinate assurance program",
        ],
    })
}

fn binary_entropy_nats(probability: f64) -> f64 {
    -probability * probability.ln() - (1.0 - probability) * (1.0 - probability).ln()
}

fn pid2_closed_form_receipt(
    result: &DiscreteSxPid2Result,
    tolerance_nats: f64,
) -> Pid2ClosedFormReceipt {
    let expected = [
        (4.0_f64 / 3.0).ln(),
        0.5 * (3.0_f64 / 2.0).ln(),
        (3.0_f64 / 2.0).ln(),
        0.25 * 3.0_f64.ln(),
        (3.0_f64 / 2.0).ln(),
        0.25 * 3.0_f64.ln(),
        (4.0_f64 / 3.0).ln(),
        0.25 * (4.0_f64 / 3.0).ln(),
    ];
    let observed = [
        result.red.informative_nats(),
        result.red.misinformative_nats(),
        result.unq1.informative_nats(),
        result.unq1.misinformative_nats(),
        result.unq2.informative_nats(),
        result.unq2.misinformative_nats(),
        result.syn.informative_nats(),
        result.syn.misinformative_nats(),
    ];
    let maximum_component_abs_error_nats = max_abs(
        observed
            .into_iter()
            .zip(expected)
            .map(|(left, right)| (left - right).abs()),
    );
    let atom_sum = result.red.net_nats()
        + result.unq1.net_nats()
        + result.unq2.net_nats()
        + result.syn.net_nats();
    let atom_sum_abs_error_nats = (atom_sum - binary_entropy_nats(0.25)).abs();
    Pid2ClosedFormReceipt {
        law: "V and R are independent Bernoulli(1/2); T = V AND R",
        redundancy_informative_formula: "ln(4/3)",
        redundancy_misinformative_formula: "(1/2) ln(3/2)",
        unique_informative_formula: "ln(3/2)",
        unique_misinformative_formula: "(1/4) ln(3)",
        synergy_informative_formula: "ln(4/3)",
        synergy_misinformative_formula: "(1/4) ln(4/3)",
        joint_information_formula: "h(1/4)",
        maximum_component_abs_error_nats,
        atom_sum_abs_error_nats,
        all_passed: maximum_component_abs_error_nats <= tolerance_nats
            && atom_sum_abs_error_nats <= tolerance_nats,
    }
}

fn pid3_and_law_mi_error(result: &DiscreteSxPid3Result) -> f64 {
    let ln2 = 2.0_f64.ln();
    let h_and2 = binary_entropy_nats(0.25);
    let h_and3 = binary_entropy_nats(0.125);
    let singleton = h_and3 - 0.5 * h_and2;
    let pair = h_and3 - 0.25 * ln2;
    max_abs(
        [
            result.subset_mis[0] - singleton,
            result.subset_mis[1] - singleton,
            result.subset_mis[3] - singleton,
            result.subset_mis[2] - pair,
            result.subset_mis[4] - pair,
            result.subset_mis[5] - pair,
            result.subset_mis[6] - h_and3,
            result.mi_s0s1s2_t - h_and3,
        ]
        .map(f64::abs),
    )
}

fn atom_identity_error(atom: SxAveragedAtom) -> f64 {
    (atom.informative_nats() - atom.misinformative_nats() - atom.net_nats()).abs()
}

fn max_abs(values: impl IntoIterator<Item = f64>) -> f64 {
    values
        .into_iter()
        .try_fold(0.0_f64, |maximum, value| {
            value.is_finite().then(|| maximum.max(value.abs()))
        })
        .unwrap_or(f64::NAN)
}

fn pid2_reconstruction_errors(result: &DiscreteSxPid2Result) -> (f64, f64) {
    let self_redundancy = max_abs([
        result.red.net_nats() + result.unq1.net_nats() - result.mi_s1_t,
        result.red.net_nats() + result.unq2.net_nats() - result.mi_s2_t,
        atom_identity_error(result.red),
        atom_identity_error(result.unq1),
        atom_identity_error(result.unq2),
        atom_identity_error(result.syn),
    ]);
    let joint = (result.red.net_nats()
        + result.unq1.net_nats()
        + result.unq2.net_nats()
        + result.syn.net_nats()
        - result.mi_s1s2_t)
        .abs();
    (self_redundancy, joint)
}

fn antichain_below_subset(antichain: &[u8], subset_mask: u8) -> bool {
    antichain
        .iter()
        .any(|collection| collection & !subset_mask == 0)
}

fn pid3_reconstruction_errors(result: &DiscreteSxPid3Result) -> Result<(f64, f64)> {
    if result.antichains.len() != 18 || result.atoms.len() != 18 || result.subset_mis.len() != 7 {
        return Err(CrebainMgwError::Contract(format!(
            "pid3 shape mismatch: {} antichains, {} atoms, {} subset MIs",
            result.antichains.len(),
            result.atoms.len(),
            result.subset_mis.len()
        )));
    }
    let mut errors = Vec::with_capacity(7 + 18);
    for subset_mask in 1_u8..=7 {
        let reconstructed = result
            .antichains
            .iter()
            .zip(&result.atoms)
            .filter(|(antichain, _)| antichain_below_subset(antichain, subset_mask))
            .map(|(_, atom)| atom.net_nats())
            .sum::<f64>();
        errors.push((reconstructed - result.subset_mis[usize::from(subset_mask - 1)]).abs());
    }
    errors.extend(result.atoms.iter().copied().map(atom_identity_error));
    let identity = max_abs(
        [
            result.mi_s0_t - result.subset_mis[0],
            result.mi_s1_t - result.subset_mis[1],
            result.mi_s2_t - result.subset_mis[3],
            result.mi_s0s1s2_t - result.subset_mis[6],
        ]
        .map(f64::abs),
    );
    Ok((max_abs(errors), identity))
}

fn fixed_source_pid2_informative_delta(
    original: &DiscreteSxPid2Result,
    control: &DiscreteSxPid2Result,
) -> f64 {
    max_abs(
        [
            original.red.informative_nats() - control.red.informative_nats(),
            original.unq1.informative_nats() - control.unq1.informative_nats(),
            original.unq2.informative_nats() - control.unq2.informative_nats(),
            original.syn.informative_nats() - control.syn.informative_nats(),
        ]
        .map(f64::abs),
    )
}

fn fixed_source_pid3_informative_delta(
    original: &DiscreteSxPid3Result,
    control: &DiscreteSxPid3Result,
) -> Result<f64> {
    if original.antichains != control.antichains || original.atoms.len() != control.atoms.len() {
        return Err(CrebainMgwError::Contract(
            "target rotation changed the pid3 lattice ordering".to_string(),
        ));
    }
    Ok(max_abs(original.atoms.iter().zip(&control.atoms).map(
        |(left, right)| (left.informative_nats() - right.informative_nats()).abs(),
    )))
}

fn pid2_misinformative_delta(
    original: &DiscreteSxPid2Result,
    control: &DiscreteSxPid2Result,
) -> f64 {
    max_abs(
        [
            original.red.misinformative_nats() - control.red.misinformative_nats(),
            original.unq1.misinformative_nats() - control.unq1.misinformative_nats(),
            original.unq2.misinformative_nats() - control.unq2.misinformative_nats(),
            original.syn.misinformative_nats() - control.syn.misinformative_nats(),
        ]
        .map(f64::abs),
    )
}

fn pid2_net_delta(original: &DiscreteSxPid2Result, control: &DiscreteSxPid2Result) -> f64 {
    max_abs(
        [
            original.red.net_nats() - control.red.net_nats(),
            original.unq1.net_nats() - control.unq1.net_nats(),
            original.unq2.net_nats() - control.unq2.net_nats(),
            original.syn.net_nats() - control.syn.net_nats(),
        ]
        .map(f64::abs),
    )
}

fn pid3_component_delta(
    original: &DiscreteSxPid3Result,
    control: &DiscreteSxPid3Result,
    component: fn(SxAveragedAtom) -> f64,
) -> Result<f64> {
    if original.antichains != control.antichains || original.atoms.len() != control.atoms.len() {
        return Err(CrebainMgwError::Contract(
            "control changed the pid3 lattice ordering".to_string(),
        ));
    }
    Ok(max_abs(
        original
            .atoms
            .iter()
            .copied()
            .zip(control.atoms.iter().copied())
            .map(|(left, right)| (component(left) - component(right)).abs()),
    ))
}

fn misinformative_nats(atom: SxAveragedAtom) -> f64 {
    atom.misinformative_nats()
}

fn net_nats(atom: SxAveragedAtom) -> f64 {
    atom.net_nats()
}

fn hamming_distance(left: &[usize], right: &[usize]) -> usize {
    left.iter()
        .zip(right)
        .filter(|(left, right)| left != right)
        .count()
}

struct FixedSourceSensitivityInputs<'a> {
    columns: &'a ValidatedColumns,
    pid2: &'a DiscreteSxPid2Result,
    pid3: &'a DiscreteSxPid3Result,
    pid2_control: &'a DiscreteSxPid2Result,
    pid3_control: &'a DiscreteSxPid3Result,
    horizontal_rotated: &'a [usize],
    volumetric_rotated: &'a [usize],
    budget: ResourceBudget,
    tolerance_nats: f64,
}

fn fixed_source_sensitivity_receipt(
    inputs: FixedSourceSensitivityInputs<'_>,
    resource_calls: &mut Vec<CategoricalResourceCallReceipt>,
) -> Result<FixedSourceSensitivityReceipt> {
    let FixedSourceSensitivityInputs {
        columns,
        pid2,
        pid3,
        pid2_control,
        pid3_control,
        horizontal_rotated,
        volumetric_rotated,
        budget,
        tolerance_nats,
    } = inputs;
    let pid2_misinformative_max_abs_delta_nats = pid2_misinformative_delta(pid2, pid2_control);
    let pid2_net_max_abs_delta_nats = pid2_net_delta(pid2, pid2_control);
    let pid3_misinformative_max_abs_delta_nats =
        pid3_component_delta(pid3, pid3_control, misinformative_nats)?;
    let pid3_net_max_abs_delta_nats = pid3_component_delta(pid3, pid3_control, net_nats)?;

    let mut changed_visual = columns.visual.clone();
    changed_visual[0] ^= 1;
    let changed_visual = matrix(changed_visual)?;
    let radar = matrix(columns.radar.clone())?;
    let horizontal = matrix(columns.horizontal.clone())?;
    let changed_source_pid2 = evaluate_ordered_pid2(
        "changed-source-premise-control-pid2",
        &changed_visual,
        &radar,
        &horizontal,
        budget,
        resource_calls,
    )?;
    let changed_source_informative_max_abs_delta_nats = max_abs(
        [
            pid2.red.informative_nats() - changed_source_pid2.red.informative_nats(),
            pid2.unq1.informative_nats() - changed_source_pid2.unq1.informative_nats(),
            pid2.unq2.informative_nats() - changed_source_pid2.unq2.informative_nats(),
            pid2.syn.informative_nats() - changed_source_pid2.syn.informative_nats(),
        ]
        .map(f64::abs),
    );

    let (rotated_pid3_minimum_net_index, rotated_pid3_minimum_net_nats) = pid3_control
        .atoms
        .iter()
        .enumerate()
        .map(|(index, atom)| (index, atom.net_nats()))
        .min_by(|(_, left), (_, right)| left.total_cmp(right))
        .ok_or_else(|| CrebainMgwError::Contract("pid3 control has no atoms".to_string()))?;

    // The UNQ gate is deliberately asymmetric: source one is the target and source two is an
    // independent nuisance bit. It is a wiring oracle for the named visual/radar adapter, not a
    // second scientific result.
    let source_one = matrix(vec![0, 0, 1, 1])?;
    let source_two = matrix(vec![0, 1, 0, 1])?;
    let unq_target = matrix(vec![0, 0, 1, 1])?;
    let asymmetric = evaluate_ordered_pid2(
        "named-source-wiring-control-pid2",
        &source_one,
        &source_two,
        &unq_target,
        budget,
        resource_calls,
    )?;
    let asymmetric_wiring_unique_one_nats = asymmetric.unq1.net_nats();
    let asymmetric_wiring_unique_two_nats = asymmetric.unq2.net_nats();
    let asymmetric_zero = asymmetric
        .pointwise
        .iter()
        .find(|row| row.s1 == [0] && row.s2 == [0] && row.t == [0])
        .ok_or_else(|| {
            CrebainMgwError::Contract(
                "pid2 named-source pointwise canary omitted the all-zero realization".to_string(),
            )
        })?;
    let expected_red_and_syn_informative = (4.0_f64 / 3.0).ln();
    let expected_unique_informative = (3.0_f64 / 2.0).ln();
    let asymmetric_pid2_pointwise_named_field_max_abs_error_nats = max_abs(
        [
            asymmetric_zero.red.informative_nats() - expected_red_and_syn_informative,
            asymmetric_zero.red.misinformative_nats(),
            asymmetric_zero.unq1.informative_nats() - expected_unique_informative,
            asymmetric_zero.unq1.misinformative_nats(),
            asymmetric_zero.unq2.informative_nats() - expected_unique_informative,
            asymmetric_zero.unq2.misinformative_nats() - 2.0_f64.ln(),
            asymmetric_zero.syn.informative_nats() - expected_red_and_syn_informative,
            asymmetric_zero.syn.misinformative_nats(),
        ]
        .map(f64::abs),
    );

    let source_zero_values = vec![0, 0, 0, 0, 1, 1, 1, 1];
    let source_one_values = vec![0, 0, 1, 1, 0, 0, 1, 1];
    let source_two_values = vec![0, 1, 0, 1, 0, 1, 0, 1];
    let source_zero = matrix(source_zero_values.clone())?;
    let source_one = matrix(source_one_values.clone())?;
    let source_two = matrix(source_two_values.clone())?;
    let mut pid3_wiring_errors = Vec::with_capacity(9);
    let positive_singleton = (5.0_f64 / 4.0).ln();
    let negative_singleton = (5.0_f64 / 6.0).ln();
    let uninformative_singleton_misinformation = (3.0_f64 / 2.0).ln();
    for (
        call_id,
        target_values,
        expected_mi,
        expected_singleton_atoms,
        expected_pointwise_misinformation,
    ) in [
        (
            "named-source-wiring-control-pid3-source-zero",
            source_zero_values,
            [2.0_f64.ln(), 0.0, 0.0],
            [positive_singleton, negative_singleton, negative_singleton],
            [
                0.0,
                uninformative_singleton_misinformation,
                uninformative_singleton_misinformation,
            ],
        ),
        (
            "named-source-wiring-control-pid3-source-one",
            source_one_values,
            [0.0, 2.0_f64.ln(), 0.0],
            [negative_singleton, positive_singleton, negative_singleton],
            [
                uninformative_singleton_misinformation,
                0.0,
                uninformative_singleton_misinformation,
            ],
        ),
        (
            "named-source-wiring-control-pid3-source-two",
            source_two_values,
            [0.0, 0.0, 2.0_f64.ln()],
            [negative_singleton, negative_singleton, positive_singleton],
            [
                uninformative_singleton_misinformation,
                uninformative_singleton_misinformation,
                0.0,
            ],
        ),
    ] {
        let target = matrix(target_values)?;
        let result = evaluate_ordered_pid3(
            call_id,
            &source_zero,
            &source_one,
            &source_two,
            &target,
            budget,
            resource_calls,
        )?;
        pid3_wiring_errors.extend(
            [result.mi_s0_t, result.mi_s1_t, result.mi_s2_t]
                .into_iter()
                .zip(expected_mi)
                .map(|(observed, expected)| (observed - expected).abs()),
        );
        for (mask, expected) in [1_u8, 2, 4].into_iter().zip(expected_singleton_atoms) {
            let observed = result.atom(&[mask]).ok_or_else(|| {
                CrebainMgwError::Contract(format!(
                    "pid3 named-source wiring control omitted singleton antichain [{mask}]"
                ))
            })?;
            pid3_wiring_errors.push((observed.net_nats() - expected).abs());
        }
        let zero_realization = result
            .pointwise
            .iter()
            .find(|row| row.s0 == [0] && row.s1 == [0] && row.s2 == [0] && row.t == [0])
            .ok_or_else(|| {
                CrebainMgwError::Contract(
                    "pid3 named-source pointwise canary omitted the all-zero realization"
                        .to_string(),
                )
            })?;
        if zero_realization.atoms.len() != PID3_CANONICAL_ANTICHAINS.len() {
            return Err(CrebainMgwError::Contract(
                "pid3 named-source pointwise canary returned a noncanonical atom count".to_string(),
            ));
        }
        for (index, expected_misinformative) in
            expected_pointwise_misinformation.into_iter().enumerate()
        {
            let atom = zero_realization.atoms[index];
            pid3_wiring_errors.extend([
                (atom.informative_nats() - positive_singleton).abs(),
                (atom.misinformative_nats() - expected_misinformative).abs(),
                (atom.net_nats() - (positive_singleton - expected_misinformative)).abs(),
            ]);
        }
    }
    let asymmetric_pid3_source_and_atom_position_max_abs_error_nats = max_abs(pid3_wiring_errors);

    let receipt = FixedSourceSensitivityReceipt {
        pid2_rotated_target_changed_rows: hamming_distance(
            &columns.horizontal,
            horizontal_rotated,
        ),
        pid3_rotated_target_changed_rows: hamming_distance(
            &columns.volumetric,
            volumetric_rotated,
        ),
        pid2_misinformative_max_abs_delta_nats,
        pid2_net_max_abs_delta_nats,
        pid3_misinformative_max_abs_delta_nats,
        pid3_net_max_abs_delta_nats,
        changed_source_informative_max_abs_delta_nats,
        rotated_pid3_minimum_net_nats,
        rotated_pid3_minimum_net_antichain: pid3_control.antichains
            [rotated_pid3_minimum_net_index]
            .clone(),
        asymmetric_wiring_unique_one_nats,
        asymmetric_wiring_unique_two_nats,
        asymmetric_pid2_pointwise_named_field_max_abs_error_nats,
        asymmetric_pid3_source_and_atom_position_max_abs_error_nats,
        all_passed: true,
        boundary: "target rotations are deterministic theorem controls, the changed-source law is a premise-violation negative control, and the asymmetric UNQ law checks adapter argument identity. None is a p-value or application result",
    };
    let sensitivity_floor = 1.0e-9;
    let expected_unique_one = (3.0_f64 / 2.0).ln();
    let expected_unique_two = (3.0_f64 / 4.0).ln();
    let expected_negative_control = -0.021_484_738_279_724_53_f64;
    let finite_receipt_max = max_abs([
        receipt.pid2_misinformative_max_abs_delta_nats,
        receipt.pid2_net_max_abs_delta_nats,
        receipt.pid3_misinformative_max_abs_delta_nats,
        receipt.pid3_net_max_abs_delta_nats,
        receipt.changed_source_informative_max_abs_delta_nats,
        receipt.rotated_pid3_minimum_net_nats,
        receipt.asymmetric_wiring_unique_one_nats,
        receipt.asymmetric_wiring_unique_two_nats,
        receipt.asymmetric_pid2_pointwise_named_field_max_abs_error_nats,
        receipt.asymmetric_pid3_source_and_atom_position_max_abs_error_nats,
    ]);
    if !finite_receipt_max.is_finite()
        || receipt.pid2_rotated_target_changed_rows == 0
        || receipt.pid3_rotated_target_changed_rows == 0
        || receipt.pid2_misinformative_max_abs_delta_nats <= sensitivity_floor
        || receipt.pid2_net_max_abs_delta_nats <= sensitivity_floor
        || receipt.pid3_misinformative_max_abs_delta_nats <= sensitivity_floor
        || receipt.pid3_net_max_abs_delta_nats <= sensitivity_floor
        || receipt.changed_source_informative_max_abs_delta_nats <= sensitivity_floor
        || receipt.rotated_pid3_minimum_net_antichain != [0b100]
        || (receipt.rotated_pid3_minimum_net_nats - expected_negative_control).abs()
            > tolerance_nats
        || (receipt.asymmetric_wiring_unique_one_nats - expected_unique_one).abs() > tolerance_nats
        || (receipt.asymmetric_wiring_unique_two_nats - expected_unique_two).abs() > tolerance_nats
        || receipt.asymmetric_pid2_pointwise_named_field_max_abs_error_nats > tolerance_nats
        || receipt.asymmetric_pid3_source_and_atom_position_max_abs_error_nats > tolerance_nats
    {
        return Err(CrebainMgwError::Contract(
            "fixed-source or named-source sensitivity control failed".to_string(),
        ));
    }
    Ok(receipt)
}

/// Validate the exact producer fixture and evaluate both declared categorical MGW questions.
///
/// No continuous estimator, comparator functional, resampling procedure, or operational verdict
/// is invoked. A pid-core failure remains a typed error and is never replaced by another method.
pub fn run_crebain_drone_mgw_study(fixture_bytes: &str) -> Result<CrebainDroneMgwStudy> {
    if fixture_bytes.len() != CREBAIN_FIXTURE_BYTES {
        return Err(CrebainMgwError::FixtureIdentity {
            expected: CREBAIN_FIXTURE_SHA256,
            observed: format!("wrong byte count: {}", fixture_bytes.len()),
        });
    }
    let fixture_digest = sha256_hex(fixture_bytes.as_bytes());
    if fixture_digest != CREBAIN_FIXTURE_SHA256 {
        return Err(CrebainMgwError::FixtureIdentity {
            expected: CREBAIN_FIXTURE_SHA256,
            observed: fixture_digest,
        });
    }

    let fixture: Fixture = serde_json::from_str(fixture_bytes)?;
    validate_manifest(&fixture)?;
    validate_geometry(&fixture.geometry)?;
    let columns = validate_rows(&fixture.rows)?;

    let visual = matrix(columns.visual.clone())?;
    let radar = matrix(columns.radar.clone())?;
    let acoustic = matrix(columns.acoustic.clone())?;
    let horizontal = matrix(columns.horizontal.clone())?;
    let volumetric = matrix(columns.volumetric.clone())?;

    let budget = categorical_resource_budget()?;
    let mut resource_calls = Vec::with_capacity(9);
    let pid2 = evaluate_ordered_pid2(
        "primary-horizontal-pid2",
        &visual,
        &radar,
        &horizontal,
        budget,
        &mut resource_calls,
    )?;
    let pid3 = evaluate_ordered_pid3(
        "exploratory-volumetric-pid3",
        &visual,
        &radar,
        &acoustic,
        &volumetric,
        budget,
        &mut resource_calls,
    )?;

    // This is not an inferential permutation test. Rotating the separately derived target while
    // leaving the sources fixed is a deterministic theorem canary: categorical MGW informative
    // cumulative terms depend only on the source-event unions, hence their Möbius atoms must be
    // invariant. Misinformative and net atoms are deliberately unconstrained.
    let mut horizontal_rotated = columns.horizontal.clone();
    horizontal_rotated.rotate_left(1);
    let mut volumetric_rotated = columns.volumetric.clone();
    volumetric_rotated.rotate_left(1);
    let horizontal_control = matrix(horizontal_rotated.clone())?;
    let volumetric_control = matrix(volumetric_rotated.clone())?;
    let pid2_control = evaluate_ordered_pid2(
        "fixed-source-target-rotation-pid2",
        &visual,
        &radar,
        &horizontal_control,
        budget,
        &mut resource_calls,
    )?;
    let pid3_control = evaluate_ordered_pid3(
        "fixed-source-target-rotation-pid3",
        &visual,
        &radar,
        &acoustic,
        &volumetric_control,
        budget,
        &mut resource_calls,
    )?;

    let (pid2_self, pid2_joint) = pid2_reconstruction_errors(&pid2);
    let (pid3_downset, pid3_identity) = pid3_reconstruction_errors(&pid3)?;
    let pid2_informative = fixed_source_pid2_informative_delta(&pid2, &pid2_control);
    let pid3_informative = fixed_source_pid3_informative_delta(&pid3, &pid3_control)?;
    let tolerance_nats = 1.0e-12;
    let pid2_closed_form = pid2_closed_form_receipt(&pid2, tolerance_nats);
    let pid3_and_law_mi_max_abs_error_nats = pid3_and_law_mi_error(&pid3);
    let fixed_source_sensitivity = fixed_source_sensitivity_receipt(
        FixedSourceSensitivityInputs {
            columns: &columns,
            pid2: &pid2,
            pid3: &pid3,
            pid2_control: &pid2_control,
            pid3_control: &pid3_control,
            horizontal_rotated: &horizontal_rotated,
            volumetric_rotated: &volumetric_rotated,
            budget,
            tolerance_nats,
        },
        &mut resource_calls,
    )?;
    if resource_calls.len() != 9 || resource_calls.iter().any(|call| !call.preflight_passed) {
        return Err(CrebainMgwError::Contract(format!(
            "categorical resource-call ledger is incomplete: retained {} of 9 calls",
            resource_calls.len()
        )));
    }
    let atom_interpretation = validate_atom_interpretation(&pid2, &pid3)?;
    let observed_max = max_abs([
        pid2_self,
        pid2_joint,
        pid3_downset,
        pid3_identity,
        pid2_informative,
        pid3_informative,
        pid2_closed_form.maximum_component_abs_error_nats,
        pid2_closed_form.atom_sum_abs_error_nats,
        pid3_and_law_mi_max_abs_error_nats,
    ]);
    if !observed_max.is_finite()
        || observed_max > tolerance_nats
        || !pid2_closed_form.all_passed
        || !fixed_source_sensitivity.all_passed
    {
        return Err(CrebainMgwError::Contract(format!(
            "PID algebra or fixed-source informative canary exceeded {tolerance_nats:e} nats: {observed_max:e}"
        )));
    }

    let pid_core_software_identity = software_identity();
    if pid_core_software_identity.package_name() != "pid-core"
        || pid_core_software_identity.package_version() != PID_RS_VERSION
    {
        return Err(CrebainMgwError::Contract(format!(
            "pid-core software identity mismatch: {} {}",
            pid_core_software_identity.package_name(),
            pid_core_software_identity.package_version()
        )));
    }
    let pid_core_source_reconciliation = reconcile_pid_core_source(&pid_core_software_identity)?;

    Ok(CrebainDroneMgwStudy {
        schema: CREBAIN_DRONE_MGW_STUDY_SCHEMA,
        machine_schema: machine_schema_receipt(),
        scientific_status: "raw-row empirical-PMF sample estimate on a deterministic categorical conformance fixture. Exact cell balance makes the empirical PMF equal the declared canonical law for this fixture; no population inference follows",
        authority_boundary: AUTHORITY_BOUNDARY,
        fixture_identity: FixtureIdentity::exact(),
        sample_estimator_implementation_adaptation:
            SampleEstimatorImplementationAdaptation::reviewed(),
        producer_source_errata: producer_source_errata_receipt(),
        pid_core_software_identity,
        pid_core_source_reconciliation,
        fixture_validation: columns.validation,
        primary_question: CrebainMgwQuestionSpec::primary_pid2(),
        exploratory_question: CrebainMgwQuestionSpec::exploratory_pid3(),
        method_eligibility: &METHOD_ELIGIBILITY,
        estimand_graph: estimand_graph_receipt()?,
        resource_receipt: CategoricalResourceReceipt {
            budget,
            calls: resource_calls,
            policy: "every executed pid-core call is separately preflighted against this fixed Galadriel-owned ceiling and retained in this ledger. Per-call success is not a checked aggregate peak-memory bound over the full study, retained outputs, controls, or serialization",
        },
        atom_interpretation,
        pid2,
        pid3,
        algebra_checks: AlgebraChecks {
            pid2_self_redundancy_max_abs_error_nats: pid2_self,
            pid2_joint_reconstruction_abs_error_nats: pid2_joint,
            pid3_downset_reconstruction_max_abs_error_nats: pid3_downset,
            pid3_singleton_and_joint_identity_max_abs_error_nats: pid3_identity,
            pid2_fixed_source_informative_max_abs_delta_nats: pid2_informative,
            pid3_fixed_source_informative_max_abs_delta_nats: pid3_informative,
            pid2_closed_form,
            pid3_and_law_mi_max_abs_error_nats,
            fixed_source_sensitivity,
            tolerance_nats,
            all_passed: true,
            caution: "the invariant is a deterministic implementation/theorem canary, not independent empirical validation or a claim of scientific novelty",
        },
        interpretation_guard: "MGW atoms are measure-relative signed statistical allocations. They do not by themselves identify causal mechanisms, sensor trustworthiness, attack intent, fault, responsibility, or control authority. Negative net atoms are retained.",
    })
}

fn format_atom_row(output: &mut String, label: &str, atom: SxAveragedAtom) {
    output.push_str(&format!(
        "| {label} | {:.9} | {:.9} | {:.9} |",
        atom.informative_nats(),
        atom.misinformative_nats(),
        atom.net_nats()
    ));
    output.push('\n');
}

fn source_subset(mask: u8) -> String {
    let mut labels = Vec::new();
    if mask & 0b001 != 0 {
        labels.push("V");
    }
    if mask & 0b010 != 0 {
        labels.push("R");
    }
    if mask & 0b100 != 0 {
        labels.push("A");
    }
    format!("{{{}}}", labels.join(","))
}

fn antichain_label(antichain: &[u8]) -> String {
    antichain
        .iter()
        .copied()
        .map(source_subset)
        .collect::<Vec<_>>()
        .join("")
}

/// Render a compact, publication-oriented Markdown view of the complete evidence object.
#[must_use]
pub fn format_crebain_drone_mgw_markdown(study: &CrebainDroneMgwStudy) -> String {
    let mut output = String::new();
    output.push_str("# CREBAIN drone categorical shared-exclusions study\n\n");
    output.push_str(
        "**Status:** raw-row empirical-PMF sample estimate on a deterministic categorical conformance fixture. Exact cell balance makes the empirical PMF equal the declared canonical law for this fixture; no population inference follows. ",
    );
    output
        .push_str("**Authority:** PID is advisory and cannot change Haldir control authority.\n\n");
    output.push_str(&format!(
        "Exact fixture: CREBAIN `{}` / `{}` (SHA-256 `{}`). The 64 rows are eight fresh-engine repetitions of each of eight source cells. They do **not** constitute 64 independent experimental units.\n",
        CREBAIN_FIXTURE_REVISION,
        CREBAIN_FIXTURE_PATH,
        CREBAIN_FIXTURE_SHA256
    ));
    output.push_str("For every lattice coordinate α, pid-core reports\n\n");
    output.push_str("$$\\Pi_\\alpha = \\Pi^+_\\alpha - \\Pi^-_\\alpha,$$\n\n");
    output.push_str("where informative and misinformative components are non-negative, while the net atom may be negative. Values below are nats.\n\n");

    output.push_str("## Primary PID2: horizontal incursion\n\n");
    output.push_str("Ordered sources: **V** = visual north-plane crossing, **R** = radar east-plane crossing. Target: synthetic latent ENU truth `east ≤ 50 m ∧ north ≤ 1 m`, derived without reading the source symbols, fusion output, Galadriel verdict, or PID result.\n\n");
    output.push_str("| MGW atom | informative Π⁺ | misinformative Π⁻ | net Π |\n");
    output.push_str("|---|---:|---:|---:|\n");
    format_atom_row(&mut output, "Redundancy {{V},{R}}", study.pid2.red);
    format_atom_row(&mut output, "Unique visual {{V}}", study.pid2.unq1);
    format_atom_row(&mut output, "Unique radar {{R}}", study.pid2.unq2);
    format_atom_row(&mut output, "Synergy {{V,R}}", study.pid2.syn);
    output.push_str(&format!(
        "\nReconstruction: `Σ atoms = I(V,R;T) = {:.9}` nats. `I(V;T) = {:.9}`, `I(R;T) = {:.9}`.\n",
        study.pid2.mi_s1s2_t, study.pid2.mi_s1_t, study.pid2.mi_s2_t
    ));

    output.push_str("## Exploratory PID3: volumetric incursion\n\n");
    output.push_str("Ordered sources: **V**, **R**, **A** (acoustic up-plane crossing). Target: synthetic latent ENU truth `east ≤ 50 m ∧ north ≤ 1 m ∧ up ≤ 1 m`, derived without reading the source symbols, fusion output, Galadriel verdict, or PID result. This 18-coordinate result does not close the separate 108-coordinate assurance program.\n\n");
    output.push_str("| Antichain coordinate | informative Π⁺ | misinformative Π⁻ | net Π |\n");
    output.push_str("|---|---:|---:|---:|\n");
    for (antichain, atom) in study.pid3.antichains.iter().zip(&study.pid3.atoms) {
        format_atom_row(&mut output, &antichain_label(antichain), *atom);
    }
    output.push_str(&format!(
        "\nSeven down-set identities reconstruct all non-empty source-subset MIs. The joint value is `I(V,R,A;T) = {:.9}` nats. The maximum reconstruction or fixed-source-informative error was `{:.3e}` nats at a `{:.1e}` tolerance.\n",
        study.pid3.mi_s0s1s2_t,
        max_abs([
            study.algebra_checks.pid2_self_redundancy_max_abs_error_nats,
            study.algebra_checks.pid2_joint_reconstruction_abs_error_nats,
            study.algebra_checks.pid3_downset_reconstruction_max_abs_error_nats,
            study.algebra_checks.pid3_singleton_and_joint_identity_max_abs_error_nats,
            study.algebra_checks.pid2_fixed_source_informative_max_abs_delta_nats,
            study.algebra_checks.pid3_fixed_source_informative_max_abs_delta_nats,
        ]),
        study.algebra_checks.tolerance_nats
    ));

    output.push_str("## Interpretation boundary\n\n");
    output.push_str(study.interpretation_guard);
    output.push_str(" KSG and continuous Ehrlich PID are ineligible and are not executed on this repeated atomic categorical law. I_min and BROJA are distinct, unrequested comparators—not fallbacks. NIS, the two-arm CUSUM, and signed correlation remain distinct operational objects and are not evaluated here. On the fusion core's dof=3 route, the CUSUM lower arm is inert. Other admitted degrees of freedom retain the general recurrence.\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    fn fixture() -> Fixture {
        serde_json::from_str(bundled_crebain_drone_mgw_fixture()).expect("bundled fixture parses")
    }

    fn assert_close(observed: f64, expected: f64, tolerance: f64) {
        assert!(
            (observed - expected).abs() <= tolerance,
            "expected {expected:.17e}, observed {observed:.17e}"
        );
    }

    fn append_json_shape(value: &Value, path: &str, output: &mut String) {
        match value {
            Value::Null => writeln!(output, "{path}:null").expect("write shape"),
            Value::Bool(_) => writeln!(output, "{path}:bool").expect("write shape"),
            Value::Number(_) => writeln!(output, "{path}:number").expect("write shape"),
            Value::String(_) => writeln!(output, "{path}:string").expect("write shape"),
            Value::Array(values) => {
                writeln!(output, "{path}:array").expect("write shape");
                if let Some(first) = values.first() {
                    append_json_shape(first, &format!("{path}[]"), output);
                }
            }
            Value::Object(values) => {
                writeln!(output, "{path}:object").expect("write shape");
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for key in keys {
                    append_json_shape(&values[key], &format!("{path}.{key}"), output);
                }
            }
        }
    }

    #[test]
    fn bundled_fixture_has_exact_custody_and_semantic_identity() {
        let bytes = bundled_crebain_drone_mgw_fixture();
        assert_eq!(bytes.len(), CREBAIN_FIXTURE_BYTES);
        assert_eq!(sha256_hex(bytes.as_bytes()), CREBAIN_FIXTURE_SHA256);

        let fixture = fixture();
        validate_manifest(&fixture).expect("manifest validates independently of outer digest");
        validate_geometry(&fixture.geometry).expect("geometry validates");
        let columns = validate_rows(&fixture.rows).expect("synthetic rows validate");
        assert_eq!(columns.validation.row_count, 64);
        assert_eq!(columns.validation.unique_episode_count, 64);
        assert_eq!(columns.validation.cell_counts, [8; 8]);
        assert_eq!(
            columns.validation.row_order_sha256,
            "5835485fac478774bc525efa21fc4f71bb137ba58aaafc704e071218f8ca657b"
        );
    }

    #[test]
    fn manifest_validator_rejects_an_isolated_schema_version_drift() {
        let mut parsed = fixture();
        parsed.schema_version = "crebain.drone-mgw-study/1.0.1".to_string();

        let error = validate_manifest(&parsed).expect_err("schema drift must fail closed");

        assert!(error.to_string().contains("schema_version mismatch"));
    }

    #[test]
    fn geometry_validator_rejects_an_isolated_axis_order_drift() {
        let mut geometry = fixture().geometry;
        geometry.axis_order[0] = "north".to_string();

        let error = validate_geometry(&geometry).expect_err("axis-order drift must fail closed");

        assert!(error.to_string().contains("canonical ENU geometry"));
    }

    #[test]
    fn producer_source_errata_bind_each_frozen_literal_before_correction() {
        validate_producer_source_errata_literals(&fixture()).expect("frozen literals match");

        let mut target_drift = fixture();
        *target_drift
            .analysis_manifest
            .pointer_mut("/target_origin")
            .expect("target-origin field") = Value::from("silently revised target claim");
        assert!(validate_producer_source_errata_literals(&target_drift).is_err());

        let mut operational_drift = fixture();
        *operational_drift
            .analysis_manifest
            .pointer_mut("/method_exclusions/nis_and_correlation")
            .expect("operational-method field") = Value::from("silently revised method claim");
        assert!(validate_producer_source_errata_literals(&operational_drift).is_err());

        let mut projection_count_drift = fixture();
        projection_count_drift.rows[0]
            .fusion_receipt
            .projection_count = 2;
        assert!(validate_producer_source_errata_literals(&projection_count_drift).is_err());

        let mut projection_prior_drift = fixture();
        projection_prior_drift.rows[0]
            .fusion_receipt
            .common_projection_prior_id = 3;
        assert!(validate_producer_source_errata_literals(&projection_prior_drift).is_err());

        let receipt = producer_source_errata_receipt();
        assert!(receipt.fixture_bytes_retained_unchanged);
        assert!(receipt.every_frozen_literal_matched_before_correction);
        assert_eq!(receipt.entries.len(), 3);
        assert_eq!(receipt.entries[0].json_pointer, "/target_origin");
        assert_eq!(
            receipt.entries[1].json_pointer,
            "/method_exclusions/nis_and_correlation"
        );
        assert!(receipt.entries[1].corrected_statement.contains("CUSUM"));
        assert_eq!(
            receipt.entries[2].json_pointer,
            "/rows/*/fusion_receipt/{projection_count,common_projection_prior_id}"
        );
        assert!(receipt.entries[2]
            .corrected_statement
            .contains("three admitted observations"));
    }

    #[test]
    fn exact_and_laws_match_closed_form_mutual_information() {
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        let ln2 = 2.0_f64.ln();
        let binary_entropy = |p: f64| -p * p.ln() - (1.0 - p) * (1.0 - p).ln();

        let h_and2 = binary_entropy(0.25);
        let i_single_and2 = h_and2 - 0.5 * ln2;
        assert_close(study.pid2.mi_s1_t, i_single_and2, 2.0e-15);
        assert_close(study.pid2.mi_s2_t, i_single_and2, 2.0e-15);
        assert_close(study.pid2.mi_s1s2_t, h_and2, 2.0e-15);

        let h_and3 = binary_entropy(0.125);
        let i_single_and3 = h_and3 - 0.5 * h_and2;
        let i_pair_and3 = h_and3 - 0.25 * ln2;
        for index in [0, 1, 3] {
            assert_close(study.pid3.subset_mis[index], i_single_and3, 2.0e-15);
        }
        for index in [2, 4, 5] {
            assert_close(study.pid3.subset_mis[index], i_pair_and3, 2.0e-15);
        }
        assert_close(study.pid3.subset_mis[6], h_and3, 2.0e-15);
        assert_close(study.pid3.mi_s0s1s2_t, h_and3, 2.0e-15);
    }

    #[test]
    fn maximum_absolute_error_propagates_every_nonfinite_coordinate() {
        assert_eq!(max_abs([-2.0, 1.0, 3.0]), 3.0);
        assert!(max_abs([0.0, f64::NAN, 1.0]).is_nan());
        assert!(max_abs([0.0, f64::INFINITY, 1.0]).is_nan());
        assert!(max_abs([0.0, f64::NEG_INFINITY, 1.0]).is_nan());
    }

    #[test]
    fn pid_core_source_reconciliation_requires_commit_scope_and_clean_state() {
        assert!(validate_pid_core_workspace_source(
            PID_RS_REVISION,
            WorkingTreeScope::PidCorePackagePath,
            WorkingTreeState::Clean,
        )
        .is_ok());
        for (commit, scope, state) in [
            (
                "0000000000000000000000000000000000000000",
                WorkingTreeScope::PidCorePackagePath,
                WorkingTreeState::Clean,
            ),
            (
                PID_RS_REVISION,
                WorkingTreeScope::CargoVcsInfoDirtyFlag,
                WorkingTreeState::Clean,
            ),
            (
                PID_RS_REVISION,
                WorkingTreeScope::PidCorePackagePath,
                WorkingTreeState::Dirty,
            ),
        ] {
            assert!(validate_pid_core_workspace_source(commit, scope, state).is_err());
        }
    }

    #[test]
    fn local_evidence_enum_spellings_are_explicitly_versioned() {
        assert_eq!(
            serde_json::to_value([
                ReferenceRole::CategoricalSharedExclusionsFunctional,
                ReferenceRole::PartWholeLogicalDerivation,
                ReferenceRole::OriginalAntichainLattice,
                ReferenceRole::ComparatorFunctionalOnly,
                ReferenceRole::EstimatorImplementationBasisOnly,
                ReferenceRole::ContinuousFunctionalOnly,
                ReferenceRole::GeneralConstructionNotEvaluated,
                ReferenceRole::EstimatorDefinition,
                ReferenceRole::DiagnosticDefinition,
                ReferenceRole::ObjectiveComposition,
                ReferenceRole::AxiomaticCaveat,
            ])
            .expect("reference roles serialize"),
            serde_json::json!([
                "categorical_shared_exclusions_functional",
                "part_whole_logical_derivation",
                "original_antichain_lattice",
                "comparator_functional_only",
                "estimator_implementation_basis_only",
                "continuous_functional_only",
                "general_construction_not_evaluated",
                "estimator_definition",
                "diagnostic_definition",
                "objective_composition",
                "axiomatic_caveat",
            ])
        );
        assert_eq!(
            serde_json::to_value([
                MethodObjectKind::Functional,
                MethodObjectKind::SampleEstimatorRoute,
                MethodObjectKind::ImplementationMethod,
                MethodObjectKind::ImplementationEntryPoint,
                MethodObjectKind::Estimator,
                MethodObjectKind::Diagnostic,
                MethodObjectKind::ObjectiveComposition,
            ])
            .expect("object kinds serialize"),
            serde_json::json!([
                "functional",
                "sample_estimator_route",
                "implementation_method",
                "implementation_entry_point",
                "estimator",
                "diagnostic",
                "objective_composition",
            ])
        );
        assert_eq!(
            serde_json::to_value([
                StudyRole::Primary,
                StudyRole::Exploratory,
                StudyRole::Comparator,
                StudyRole::ReferenceBoundary,
                StudyRole::SeparateOperationalDiagnostic,
                StudyRole::DownstreamOnly,
            ])
            .expect("study roles serialize"),
            serde_json::json!([
                "primary",
                "exploratory",
                "comparator",
                "reference_boundary",
                "separate_operational_diagnostic",
                "downstream_only",
            ])
        );
        assert_eq!(
            serde_json::to_value([
                ExecutionDisposition::Produced,
                ExecutionDisposition::NotRequested,
                ExecutionDisposition::Inapplicable,
                ExecutionDisposition::NotEvaluated,
            ])
            .expect("execution dispositions serialize"),
            serde_json::json!(["produced", "not_requested", "inapplicable", "not_evaluated",])
        );
        assert_eq!(
            serde_json::to_value([
                EstimandGraphNodeKind::ProducerFixture,
                EstimandGraphNodeKind::DeclaredLaw,
                EstimandGraphNodeKind::EmpiricalPmf,
                EstimandGraphNodeKind::Functional,
                EstimandGraphNodeKind::SampleEstimatorRoute,
                EstimandGraphNodeKind::ImplementationMethod,
                EstimandGraphNodeKind::ImplementationEntryPoint,
                EstimandGraphNodeKind::PointwiseOutput,
                EstimandGraphNodeKind::AveragedOutput,
                EstimandGraphNodeKind::ValidationReceipt,
                EstimandGraphNodeKind::AdvisoryView,
            ])
            .expect("graph node kinds serialize"),
            serde_json::json!([
                "producer_fixture",
                "declared_law",
                "empirical_pmf",
                "functional",
                "sample_estimator_route",
                "implementation_method",
                "implementation_entry_point",
                "pointwise_output",
                "averaged_output",
                "validation_receipt",
                "advisory_view",
            ])
        );
        assert_eq!(
            serde_json::to_value([
                EstimandGraphEdgeKind::Declares,
                EstimandGraphEdgeKind::EncodedAs,
                EstimandGraphEdgeKind::EstimatedBy,
                EstimandGraphEdgeKind::ConsumedBy,
                EstimandGraphEdgeKind::ImplementedBy,
                EstimandGraphEdgeKind::ExposedThrough,
                EstimandGraphEdgeKind::SubmittedTo,
                EstimandGraphEdgeKind::Emits,
                EstimandGraphEdgeKind::AggregatesInto,
                EstimandGraphEdgeKind::CheckedBy,
                EstimandGraphEdgeKind::ExposedAs,
            ])
            .expect("graph edge kinds serialize"),
            serde_json::json!([
                "declares",
                "encoded_as",
                "estimated_by",
                "consumed_by",
                "implemented_by",
                "exposed_through",
                "submitted_to",
                "emits",
                "aggregates_into",
                "checked_by",
                "exposed_as",
            ])
        );
    }

    #[test]
    fn mgw_outputs_reconstruct_every_declared_lattice_identity() {
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        assert!(study.algebra_checks.all_passed);
        assert_eq!(study.pid3.antichains.len(), 18);
        assert_eq!(study.pid3.atoms.len(), 18);
        assert_eq!(study.pid3.subset_mis.len(), 7);
        assert!(study.pid2.pointwise_included);
        assert!(study.pid3.pointwise_included);
        assert_eq!(study.pid2.empirical_pmf.sample_count, 64);
        assert_eq!(study.pid2.empirical_pmf.minimum_observed_count, 16);
        assert_eq!(study.pid3.empirical_pmf.sample_count, 64);
        assert_eq!(study.pid3.empirical_pmf.minimum_observed_count, 8);
        assert!(study
            .pid2
            .empirical_pmf
            .population_caveat
            .contains("population"));
        assert_eq!(
            study.pid2.empirical_pmf.population_caveat,
            study.pid3.empirical_pmf.population_caveat
        );

        let expected_antichains = vec![
            vec![1],
            vec![2],
            vec![4],
            vec![3],
            vec![5],
            vec![6],
            vec![7],
            vec![1, 2],
            vec![1, 4],
            vec![1, 6],
            vec![2, 4],
            vec![2, 5],
            vec![3, 4],
            vec![3, 5],
            vec![3, 6],
            vec![5, 6],
            vec![1, 2, 4],
            vec![3, 5, 6],
        ];
        assert_eq!(study.pid3.antichains, expected_antichains);
    }

    #[test]
    fn all_averaged_atom_components_match_a_separate_high_precision_event_union_oracle() {
        // These values were derived separately at 80-digit precision from the MGW event formula
        // i+(t:alpha) = -ln P(union alpha), i-(t:alpha) = ln[P(t)/P(t and union alpha)], followed
        // by a separately constructed 0/1 Möbius incidence system. This is a law-specific oracle,
        // not a claim that one implementation generally validates the functional. Pointwise
        // output is retained and internally reconstructed but is outside this Decimal oracle.
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        let expected_pid2 = [
            [
                0.287_682_072_451_780_9,
                0.202_732_554_054_082_2,
                0.084_949_518_397_698_74,
            ],
            [
                0.405_465_108_108_164_4,
                0.274_653_072_167_027_4,
                0.130_812_035_941_136_96,
            ],
            [
                0.405_465_108_108_164_4,
                0.274_653_072_167_027_4,
                0.130_812_035_941_136_96,
            ],
            [
                0.287_682_072_451_780_9,
                0.071_920_518_112_945_23,
                0.215_761_554_338_835_7,
            ],
        ];
        for (atom, expected) in [
            study.pid2.red,
            study.pid2.unq1,
            study.pid2.unq2,
            study.pid2.syn,
        ]
        .into_iter()
        .zip(expected_pid2)
        {
            assert_close(atom.informative_nats(), expected[0], 3.0e-16);
            assert_close(atom.misinformative_nats(), expected[1], 3.0e-16);
            assert_close(atom.net_nats(), expected[2], 3.0e-16);
        }

        let expected_pid3 = [
            [
                0.223_143_551_314_209_76,
                0.191_559_608_912_246_5,
                0.031_583_942_401_963_25,
            ],
            [
                0.223_143_551_314_209_76,
                0.191_559_608_912_246_5,
                0.031_583_942_401_963_25,
            ],
            [
                0.223_143_551_314_209_76,
                0.191_559_608_912_246_5,
                0.031_583_942_401_963_25,
            ],
            [
                0.117_783_035_656_383_46,
                0.094_851_776_884_664_35,
                0.022_931_258_771_719_11,
            ],
            [
                0.117_783_035_656_383_46,
                0.094_851_776_884_664_35,
                0.022_931_258_771_719_11,
            ],
            [
                0.117_783_035_656_383_46,
                0.094_851_776_884_664_35,
                0.022_931_258_771_719_11,
            ],
            [
                0.169_899_036_795_397_47,
                0.084_949_518_397_698_74,
                0.084_949_518_397_698_74,
            ],
            [
                0.154_150_679_827_258_25,
                0.133_219_807_974_628_87,
                0.020_930_871_852_629_375,
            ],
            [
                0.154_150_679_827_258_25,
                0.133_219_807_974_628_87,
                0.020_930_871_852_629_375,
            ],
            [
                0.028_170_876_966_696_35,
                0.023_932_356_880_964_633,
                0.004_238_520_085_731_717,
            ],
            [
                0.154_150_679_827_258_25,
                0.133_219_807_974_628_87,
                0.020_930_871_852_629_375,
            ],
            [
                0.028_170_876_966_696_35,
                0.023_932_356_880_964_633,
                0.004_238_520_085_731_717,
            ],
            [
                0.028_170_876_966_696_35,
                0.023_932_356_880_964_633,
                0.004_238_520_085_731_717,
            ],
            [
                0.064_538_521_137_571_2,
                0.053_647_704_340_685_08,
                0.010_890_816_796_886_119,
            ],
            [
                0.064_538_521_137_571_2,
                0.053_647_704_340_685_08,
                0.010_890_816_796_886_119,
            ],
            [
                0.064_538_521_137_571_2,
                0.053_647_704_340_685_08,
                0.010_890_816_796_886_119,
            ],
            [
                0.133_531_392_624_522_63,
                0.115_613_009_870_443_73,
                0.017_918_382_754_078_895,
            ],
            [
                0.012_651_117_553_558_62,
                0.010_475_087_175_688_18,
                0.002_176_030_377_870_441,
            ],
        ];
        for (atom, expected) in study.pid3.atoms.iter().zip(expected_pid3) {
            assert_close(atom.informative_nats(), expected[0], 3.0e-16);
            assert_close(atom.misinformative_nats(), expected[1], 3.0e-16);
            assert_close(atom.net_nats(), expected[2], 3.0e-16);
        }
    }

    #[test]
    fn balanced_source_symmetry_does_not_replace_ordered_provenance() {
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        assert_close(study.pid2.unq1.net_nats(), study.pid2.unq2.net_nats(), 0.0);
        assert_eq!(
            study.primary_question.ordered_sources(),
            &["visual_north_plane_crossed", "radar_east_plane_crossed"]
        );

        // The primary AND law is symmetric, so this predicate-isolating mutation changes every
        // field needed by the declared geometry except the serialized factorial-cell symbols.
        // Removing only the cell/source-symbol guard would therefore admit it. The asymmetric
        // PID2 and PID3 controls retained in AlgebraChecks separately protect entry-point argument
        // positions and the PID3 singleton-antichain labels.
        let mut parsed = fixture();
        let row = &mut parsed.rows[4 * EPISODES_PER_CELL];
        row.sources = [0, 1, 0];
        row.truth_enu_m = [49.0, 2.0, 2.0];
        row.pre_fusion_observations.visual_cartesian_enu_m = [50.0, 2.0, 1.0];
        row.pre_fusion_observations
            .radar_polar_range_azimuth_elevation = [49.0, 0.0, 0.0];
        row.pre_fusion_observations.acoustic_cartesian_enu_m = [50.0, 1.0, 2.0];
        let error = validate_rows(&parsed.rows).expect_err("factorial source identity must fail");
        assert!(error.to_string().contains("factorial cell"));
    }

    #[test]
    fn hostile_rows_fail_one_contract_coordinate_at_a_time() {
        let mut parsed = fixture();
        parsed.rows[0].fusion_receipt.degraded = true;
        let error = validate_rows(&parsed.rows).expect_err("degraded receipt must fail");
        assert!(error
            .to_string()
            .contains("bounded three-input observation summary"));

        let mut parsed = fixture();
        parsed.rows[0].observation_timestamp_ms += 1;
        let error = validate_rows(&parsed.rows).expect_err("unsynchronized time must fail");
        assert!(error.to_string().contains("row-window"));

        let mut parsed = fixture();
        parsed.rows[0]
            .pre_fusion_observations
            .visual_cartesian_enu_m[1] = 0.0;
        parsed.rows[0].truth_enu_m[1] = 0.0;
        let error = validate_rows(&parsed.rows).expect_err("source reconstruction must fail");
        assert!(error.to_string().contains("pre-fusion"));

        let mut parsed = fixture();
        parsed.rows[0].horizontal_incursion = 1;
        let error =
            validate_rows(&parsed.rows).expect_err("latent-truth target mismatch must fail");
        assert!(error.to_string().contains("synthetic latent ENU truth"));

        let mut parsed = fixture();
        parsed.rows[0].cell_index = 1;
        let error = validate_rows(&parsed.rows).expect_err("row position metadata must fail");
        assert!(error.to_string().contains("cell/replicate order"));

        let mut parsed = fixture();
        parsed.rows[0].episode_id = "crebain-drone-mgw-v1-noncanonical".to_string();
        let error = validate_rows(&parsed.rows).expect_err("episode identity must fail");
        assert!(error.to_string().contains("episode identifier"));
    }

    #[test]
    fn exact_byte_gate_rejects_semantically_plausible_rewrites() {
        // Replace two JSON-indentation spaces with one space plus one tab. Length, parsed values,
        // canonical manifest content, and every row predicate remain unchanged. Only the exact-byte
        // custody digest can reject this valid-JSON rewrite.
        let rewritten = bundled_crebain_drone_mgw_fixture().replacen(
            "  \"analysis_manifest\"",
            " \t\"analysis_manifest\"",
            1,
        );
        let error =
            run_crebain_drone_mgw_study(&rewritten).expect_err("digest must reject rewrite");
        assert!(matches!(error, CrebainMgwError::FixtureIdentity { .. }));
    }

    #[test]
    fn method_matrix_never_conflates_or_falls_back() {
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        assert_eq!(study.method_eligibility.len(), 18);
        for (object_id, object_kind) in [
            (PAPER_FUNCTIONAL_ID, MethodObjectKind::Functional),
            (
                SAMPLE_ESTIMATOR_ROUTE_ID,
                MethodObjectKind::SampleEstimatorRoute,
            ),
            (
                UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID,
                MethodObjectKind::ImplementationMethod,
            ),
            (
                PID2_IMPLEMENTATION_ENTRY_POINT,
                MethodObjectKind::ImplementationEntryPoint,
            ),
            (
                PID3_IMPLEMENTATION_ENTRY_POINT,
                MethodObjectKind::ImplementationEntryPoint,
            ),
        ] {
            let row = study
                .method_eligibility
                .iter()
                .find(|row| row.object_id == object_id)
                .expect("required categorical role row");
            assert_eq!(row.object_kind, object_kind);
        }
        let sample_route = study
            .method_eligibility
            .iter()
            .find(|row| row.object_id == SAMPLE_ESTIMATOR_ROUTE_ID)
            .expect("sample-estimator route row");
        assert!(sample_route
            .assumptions_or_reason
            .contains("not a declared-law evaluator"));
        let ksg = study
            .method_eligibility
            .iter()
            .find(|row| row.object == "pairwise KSG mutual information")
            .expect("KSG row");
        assert_eq!(ksg.object_kind, MethodObjectKind::Estimator);
        assert_eq!(ksg.execution, ExecutionDisposition::Inapplicable);
        assert!(ksg.assumptions_or_reason.contains("atomic categorical"));
        let ehrich_functional = study
            .method_eligibility
            .iter()
            .find(|row| row.object_id == "shared-exclusions.continuous-ehrlich-functional")
            .expect("continuous Ehrlich functional row");
        assert_eq!(ehrich_functional.object_kind, MethodObjectKind::Functional);
        assert_eq!(
            ehrich_functional.execution,
            ExecutionDisposition::Inapplicable
        );
        let ehrich_estimator = study
            .method_eligibility
            .iter()
            .find(|row| row.object_id == "shared-exclusions.continuous-ehrlich-knn-estimator")
            .expect("continuous Ehrlich estimator row");
        assert_eq!(ehrich_estimator.object_kind, MethodObjectKind::Estimator);
        let schick_poland = study
            .method_eligibility
            .iter()
            .find(|row| row.object_id == "pid.general-schick-poland-2021")
            .expect("general-construction row");
        assert_eq!(schick_poland.execution, ExecutionDisposition::NotEvaluated);
        let imin = study
            .method_eligibility
            .iter()
            .find(|row| row.object == "Williams--Beer I_min PID")
            .expect("I_min row");
        assert!(imin.fallback_policy.contains("never"));
        let broja = study
            .method_eligibility
            .iter()
            .find(|row| row.object == "BROJA PID")
            .expect("BROJA row");
        assert!(broja.fallback_policy.contains("never"));
        assert!(broja.assumptions_or_reason.contains("two-source"));
        let nis = study
            .method_eligibility
            .iter()
            .find(|row| row.object_id == "galadriel.normalized-innovation-squared")
            .expect("NIS row");
        assert_eq!(nis.execution, ExecutionDisposition::NotEvaluated);
        let correlation = study
            .method_eligibility
            .iter()
            .find(|row| row.object_id == "galadriel.signed-pearson-correlation")
            .expect("correlation row");
        assert_eq!(correlation.execution, ExecutionDisposition::NotEvaluated);
        let cusum = study
            .method_eligibility
            .iter()
            .find(|row| row.object_id == "galadriel.two-sided-cusum")
            .expect("CUSUM row");
        assert_eq!(cusum.object_kind, MethodObjectKind::Diagnostic);
        assert_eq!(cusum.execution, ExecutionDisposition::NotEvaluated);
        assert!(cusum.object.contains("lower arm inert"));
        assert!(cusum.estimand_or_output.contains("only the upper arm"));
        assert_ne!(cusum.object_id, nis.object_id);
        let objective_rows = study
            .method_eligibility
            .iter()
            .filter(|row| row.object_kind == MethodObjectKind::ObjectiveComposition)
            .count();
        assert_eq!(objective_rows, 2);
    }

    #[test]
    fn estimand_graph_is_resolved_acyclic_and_has_no_authority_sink() {
        let graph = estimand_graph_receipt().expect("estimand graph validates");
        assert_eq!(graph.nodes.len(), 16);
        assert_eq!(graph.edges.len(), 24);
        assert_eq!(graph.paper_functional_id, PAPER_FUNCTIONAL_ID);
        assert_eq!(graph.sample_estimator_route_id, SAMPLE_ESTIMATOR_ROUTE_ID);
        assert_eq!(
            graph.upstream_implementation_method_catalog_id,
            UPSTREAM_IMPLEMENTATION_METHOD_CATALOG_ID
        );
        assert_eq!(
            graph.pid2_implementation_entry_point,
            PID2_IMPLEMENTATION_ENTRY_POINT
        );
        assert_eq!(
            graph.pid3_implementation_entry_point,
            PID3_IMPLEMENTATION_ENTRY_POINT
        );
        assert!(graph.all_edge_endpoints_resolved);
        assert!(graph.declared_topological_order_validated);
        assert!(graph.question_method_and_graph_identities_reconciled);
        assert!(graph.operational_authority_node_or_edge_kind_absent);
        assert!(graph.edges.iter().any(|edge| {
            edge.from == "output.pid3-pointwise"
                && edge.to == "output.pid3-averaged"
                && edge.kind == EstimandGraphEdgeKind::AggregatesInto
        }));
        let advisory_edges: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.to == "view.advisory-only")
            .collect();
        assert_eq!(advisory_edges.len(), 1);
        assert_eq!(advisory_edges[0].kind, EstimandGraphEdgeKind::ExposedAs);
    }

    #[test]
    fn estimand_graph_rejects_each_advisory_sink_semantic_drift() {
        let mut nodes = ESTIMAND_GRAPH_NODES.to_vec();
        let advisory = nodes
            .iter_mut()
            .find(|node| node.kind == EstimandGraphNodeKind::AdvisoryView)
            .expect("advisory node");
        advisory.node_id = "view.fused-verdict";
        assert!(validate_estimand_graph(&nodes, &ESTIMAND_GRAPH_EDGES).is_err());

        let mut edges = ESTIMAND_GRAPH_EDGES.to_vec();
        let advisory_edge = edges
            .iter_mut()
            .find(|edge| edge.to == "view.advisory-only")
            .expect("advisory edge");
        advisory_edge.kind = EstimandGraphEdgeKind::CheckedBy;
        assert!(validate_estimand_graph(&ESTIMAND_GRAPH_NODES, &edges).is_err());

        let mut identity_nodes = ESTIMAND_GRAPH_NODES.to_vec();
        identity_nodes
            .iter_mut()
            .find(|node| node.node_id == PAPER_FUNCTIONAL_ID)
            .expect("functional node")
            .node_id = "functional.provenance-fork";
        let mut identity_edges = ESTIMAND_GRAPH_EDGES.to_vec();
        for edge in &mut identity_edges {
            if edge.from == PAPER_FUNCTIONAL_ID {
                edge.from = "functional.provenance-fork";
            }
        }
        assert!(validate_estimand_graph(&identity_nodes, &identity_edges).is_err());

        let mut swapped_roles = ESTIMAND_GRAPH_NODES.to_vec();
        swapped_roles
            .iter_mut()
            .find(|node| node.node_id == PAPER_FUNCTIONAL_ID)
            .expect("functional node")
            .kind = EstimandGraphNodeKind::SampleEstimatorRoute;
        swapped_roles
            .iter_mut()
            .find(|node| node.node_id == SAMPLE_ESTIMATOR_ROUTE_ID)
            .expect("sample-estimator node")
            .kind = EstimandGraphNodeKind::Functional;
        assert!(validate_estimand_graph(&swapped_roles, &ESTIMAND_GRAPH_EDGES).is_err());

        let mut crossed_arity = ESTIMAND_GRAPH_EDGES.to_vec();
        crossed_arity
            .iter_mut()
            .find(|edge| {
                edge.from == "pmf.horizontal" && edge.kind == EstimandGraphEdgeKind::SubmittedTo
            })
            .expect("PID2 submission edge")
            .to = PID3_IMPLEMENTATION_ENTRY_POINT;
        assert!(validate_estimand_graph(&ESTIMAND_GRAPH_NODES, &crossed_arity).is_err());
    }

    #[test]
    fn serialized_evidence_is_complete_but_has_no_authority_claim() {
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        let value = serde_json::to_value(&study).expect("study serializes");
        assert_eq!(value["pid3"]["atoms"].as_array().map(Vec::len), Some(18));
        assert_eq!(
            value["fixture_identity"]["actual_pid_core_revision"],
            PID_RS_REVISION
        );
        assert_eq!(
            value["fixture_identity"]["producer_registered_pid_core_revision"],
            PREREGISTERED_PID_RS_REVISION
        );
        assert_eq!(value["schema"], CREBAIN_DRONE_MGW_STUDY_SCHEMA);
        assert_eq!(
            value["atom_interpretation"]["averaged"]["aggregation_scope"],
            "empirical_pmf_average"
        );
        assert_eq!(
            value["atom_interpretation"]["pointwise"]["aggregation_scope"],
            "pointwise_distinct_joint_realization"
        );
        let resource_calls = value["resource_receipt"]["calls"]
            .as_array()
            .expect("resource-call ledger");
        assert_eq!(resource_calls.len(), 9);
        assert!(resource_calls
            .iter()
            .all(|call| call["preflight_passed"] == true));
        assert_eq!(resource_calls[0]["call_id"], "primary-horizontal-pid2");
        assert_eq!(resource_calls[1]["call_id"], "exploratory-volumetric-pid3");
        assert_eq!(value["pid_core_software_identity"]["attestation"], "none");
        assert_eq!(
            value["pid_core_source_reconciliation"]
                ["pid_core_package_subtree_clean_revision_matched"],
            true
        );
        assert_eq!(
            value["pid_core_source_reconciliation"]["observed_source"]["kind"],
            "workspace_git"
        );
        assert_eq!(
            value["pid_core_source_reconciliation"]["observed_source"]["commit_sha1"],
            PID_RS_REVISION
        );
        assert_eq!(
            value["pid_core_source_reconciliation"]["observed_source"]["working_tree"],
            "clean"
        );
        assert_eq!(value["algebra_checks"]["all_passed"], true);
        assert!(value.get("verdict").is_none());
        assert!(value.get("control_command").is_none());
        let encoded = value.to_string();
        assert!(encoded.contains("fixed admitted authority inputs"));
        assert!(encoded.contains("plant-command outputs are identical"));
        assert!(encoded.contains("Audit records may vary"));
        assert!(encoded.contains("No operator-behavior noninterference is claimed"));
    }

    #[test]
    fn fixed_source_controls_are_sensitive_and_retain_the_expected_negative_atom() {
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        let control = &study.algebra_checks.fixed_source_sensitivity;
        assert!(control.all_passed);
        assert_eq!(control.pid2_rotated_target_changed_rows, 2);
        assert_eq!(control.pid3_rotated_target_changed_rows, 2);
        assert!(control.pid2_misinformative_max_abs_delta_nats > 1.0e-9);
        assert!(control.pid3_misinformative_max_abs_delta_nats > 1.0e-9);
        assert!(control.changed_source_informative_max_abs_delta_nats > 1.0e-9);
        assert_eq!(control.rotated_pid3_minimum_net_antichain, [0b100]);
        assert_close(
            control.rotated_pid3_minimum_net_nats,
            -0.021_484_738_279_724_53,
            1.0e-15,
        );
        assert_close(
            control.asymmetric_pid2_pointwise_named_field_max_abs_error_nats,
            0.0,
            2.0e-15,
        );
        assert_close(
            control.asymmetric_pid3_source_and_atom_position_max_abs_error_nats,
            0.0,
            2.0e-15,
        );
    }

    #[test]
    fn pid2_resource_budget_rejects_one_byte_below_the_exact_preflight() {
        let columns = validate_rows(&fixture().rows).expect("fixture rows validate");
        let visual = matrix(columns.visual).expect("visual matrix");
        let radar = matrix(columns.radar).expect("radar matrix");
        let target = matrix(columns.horizontal).expect("target matrix");
        let estimate = discrete_sxpid2_resource_estimate(
            visual.as_ref(),
            radar.as_ref(),
            target.as_ref(),
            true,
        )
        .expect("estimate");
        let one_under = u64::try_from(estimate.estimated_bytes)
            .expect("fixture estimate fits u64")
            .checked_sub(1)
            .expect("fixture estimate is nonzero");
        let budget = ResourceBudget::new(
            one_under,
            PID_RESOURCE_MAX_PAIRWISE_DISTANCES,
            PID_RESOURCE_MAX_OPERATIONS_HINT,
            PID_RESOURCE_MAX_THREADS,
        )
        .expect("positive budget");
        let error =
            discrete_sxpid2_with_budget(visual.as_ref(), radar.as_ref(), target.as_ref(), budget)
                .expect_err("one-under byte budget must reject");
        assert!(matches!(
            error,
            pid_core::PidError::ResourceLimitExceeded {
                resource: "bytes",
                requested,
                limit,
                ..
            } if requested == estimate.estimated_bytes && limit == u128::from(one_under)
        ));
    }

    #[test]
    fn pid3_resource_budget_rejects_one_operation_below_the_exact_preflight() {
        let columns = validate_rows(&fixture().rows).expect("fixture rows validate");
        let visual = matrix(columns.visual).expect("visual matrix");
        let radar = matrix(columns.radar).expect("radar matrix");
        let acoustic = matrix(columns.acoustic).expect("acoustic matrix");
        let target = matrix(columns.volumetric).expect("target matrix");
        let estimate = discrete_sxpid3_resource_estimate(
            visual.as_ref(),
            radar.as_ref(),
            acoustic.as_ref(),
            target.as_ref(),
            true,
        )
        .expect("estimate");
        let one_under = estimate
            .operations_hint
            .checked_sub(1)
            .expect("fixture estimate is nonzero");
        let budget = ResourceBudget::new(
            PID_RESOURCE_MAX_BYTES,
            PID_RESOURCE_MAX_PAIRWISE_DISTANCES,
            one_under,
            PID_RESOURCE_MAX_THREADS,
        )
        .expect("positive budget");
        let error = discrete_sxpid3_with_budget(
            visual.as_ref(),
            radar.as_ref(),
            acoustic.as_ref(),
            target.as_ref(),
            budget,
        )
        .expect_err("one-under operation budget must reject");
        assert!(matches!(
            error,
            pid_core::PidError::ResourceLimitExceeded {
                resource: "operations_hint",
                requested,
                limit,
                ..
            } if requested == estimate.operations_hint && limit == one_under
        ));
    }

    #[test]
    fn v3_machine_json_shape_regression_sentinel_is_bound() {
        // This sentinel binds field paths and JSON value kinds, using the first element as the
        // representative shape of each homogeneous array. Cardinalities, scientific values, and
        // Enum spellings are governed by the separate semantic tests and candidate output receipt.
        // This digest is deliberately not described as a complete JSON Schema.
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        let value = serde_json::to_value(study).expect("serialize study");
        let mut shape = String::new();
        append_json_shape(&value, "$", &mut shape);
        assert_eq!(
            sha256_hex(shape.as_bytes()),
            "4b36dbc4f0e279db0dae6bcf21fa54c3722cca246430626a6af0e669d48f4b72"
        );
    }

    #[test]
    fn markdown_names_equation_units_and_all_coordinates() {
        let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
            .expect("exact study runs");
        let markdown = format_crebain_drone_mgw_markdown(&study);
        assert!(markdown.contains("\\Pi_\\alpha = \\Pi^+_\\alpha - \\Pi^-_\\alpha"));
        assert!(markdown.contains("Values below are nats"));
        assert!(markdown.contains("does not close the separate 108-coordinate"));
        for antichain in &study.pid3.antichains {
            assert!(markdown.contains(&format!("| {} |", antichain_label(antichain))));
        }
        assert!(markdown.contains("cannot change Haldir control authority"));
    }
}
