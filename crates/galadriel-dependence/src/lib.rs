#![forbid(unsafe_code)]
//! # galadriel-dependence
//!
//! Optional, exploratory pairwise-mutual-information (MI) consensus evidence.
//!
//! This crate is not a partial information decomposition implementation. Its
//! graph disposition comes from report-first pairwise KSG MI estimates, a
//! configured edge threshold, and a unique strict-majority clique rule. PID is
//! target-asymmetric; this sensor-consistency question is symmetric and has no
//! external target. Real categorical MGW and continuous Ehrlich PID studies stay
//! in `galadriel-justify` and must name immutable sources and a target.
//!
//! Every configuration requires a [`ContinuousLawDeclaration`]. Construction
//! checks only bounded text; neither it nor sample geometry proves the population
//! assertion. The caller must declare a common coordinate gauge. Galadriel applies
//! the fixed identity transform and adds no noise. Exact ties therefore cause
//! the upstream continuous estimator to abstain.
//!
//! [`DependenceAssessmentReport`] retains the unchanged core [`FusedVerdict`]
//! beside MI companion reports. There is no API that fuses MI into that verdict.
//! Its versioned Serde representation is an immutable evidence snapshot. The
//! pinned upstream report is serialization-only, so this crate does not claim
//! that arbitrary JSON can be deserialized into a trusted assessment.
//! [`DeleteBlockStabilityEnvelope`] enumerates all circular deletion starts and
//! reruns the entire graph rule. It is a deterministic sensitivity envelope, not
//! a confidence interval, p-value, null distribution, or calibration theorem.
//!
//! The stable core type `galadriel_core::PidObservation` is a historical wire/API
//! compatibility name for a sensor observation; it is not a PID tuple or result.

mod engine;
mod fusion;
mod identity;
mod suite;

pub use engine::{
    analyze, CandidateMarginEnvelope, ChannelDependence, ContinuousLawDeclaration,
    ContinuousSamplingRegime, DeclaredMiInput, DeleteBlockStabilityEnvelope, DependenceStability,
    DependenceStabilityParams, EpisodeReceiptOrigin, MiAcceptedConfigEvidence, MiConsensusConfig,
    MiConsensusConfigError, MiConsensusParams, MiConsensusReport, MiConsensusResearchProfile,
    MiEstimatorEvidence, MiGraphDisposition, MiGraphUnavailableReason,
    MiKsgEvaluatorConfigEvidence, PairGeometryEvidence, PairKsgEvidence, PairMiOutcome,
    PairMiReport, PairUnavailableCategory, RowSetReceipt, MAX_MI_WINDOW,
    MI_CONSENSUS_REPORT_SCHEMA, MI_PAIR_POINT_FIT_UNITS, PID_RS_GIT_REPOSITORY, PID_RS_REVISION,
    PID_RS_VERSION,
};
pub use fusion::{
    assess_with_dependence, AxisMiConsensusReport, DependenceAssessmentReport,
    MiAxisFamilyAvailability, ProjectionAxisReceipt, ProjectionRowIdentity,
    DEPENDENCE_ASSESSMENT_REPORT_SCHEMA,
};
pub use galadriel_core::FusedVerdict;
pub use identity::{
    DependenceAssessmentBinding, DependenceAssessmentDigest, DependenceResearchClassification,
    DependenceResearchSuiteDigest, MiConsensusConfigDigest, ProjectionAxisDigest,
};
pub use suite::{
    DependenceResearchSuite, DependenceResearchSuiteError, DependenceResearchSuiteParams,
    MAX_DEPENDENCE_RESEARCH_SUITE_QUADRATIC_FIT_WORK, MIN_DEPENDENCE_RESEARCH_MODALITIES,
};

// Shared extraction remains owned by the stable core.
pub use galadriel_core::{consistency_channels_with_temporal_limits, scalar_channels};
