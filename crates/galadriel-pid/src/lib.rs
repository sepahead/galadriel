#![forbid(unsafe_code)]
//! # galadriel-pid
//!
//! This crate provides optional cross-sensor partial information decomposition
//! (PID) analysis. The signed-correlation analysis remains the default.
//!
//! ## Relationship to the baseline
//!
//! The magnitude baseline in `galadriel-core` evaluates marginal normalized
//! innovation squared (NIS) evidence. A moment-matched dependence change can
//! leave this evidence consistent with the declared chi-square reference. It can
//! still change the relation between modalities.
//!
//! This optional engine evaluates that dependence pattern with pairwise mutual
//! information (MI) and a strict-majority consensus clique. The result describes
//! statistical structure only. It does not identify an attack or causal
//! mechanism. It does not establish that all dependence changes are identifiable
//! from these inputs.
//!
//! ## Estimand and scope
//!
//! [`assess_stream`] requires one [`galadriel_core::AssessmentScope`]. The scope
//! contains a producer label and one exact lifecycle position. The nested core
//! binding covers that scope, the release suite, and every ordered observation.
//! These labels are declared provenance. They do not authenticate a producer or
//! prove observation origin.
//!
//! For each channel `c`, corroboration is its best pairwise
//! Kraskov–Stögbauer–Grassberger (KSG) MI estimate. The verdict also requires one
//! unique strict-majority clique. An attributed channel must have an estimated low
//! edge to each clique member.
//!
//! Equal dyads and estimator failures are insufficient. They never produce a
//! nominal or attributed result. The
//! [`PidResearchProfile::CircularDeleteBlockV0_9`] profile applies circular
//! delete-block confirmation to a positive attribution. The joint worst-consensus
//! margin requires a positive lower bound. The joint worst-candidate margin
//! requires a negative upper bound.
//!
//! Each resample recalculates the edge maxima and minima. All fitted edges enter
//! two family-level extrema. The method does not use a per-edge Bonferroni split.
//! The [`CircularDeleteBlockConfirmation::family_alpha`] budget is divided
//! between the two one-sided bounds. [`assess_stream`] also divides this budget
//! across projection axes.
//!
//! The engine also reports shared-exclusions PID atoms. These atoms are `I^sx`
//! redundancy and its Möbius synergy. Each calculation uses a channel, a stable
//! designated peer, and the consensus of the remaining channels. These atoms are
//! advisory report-only data. The verdict does not use them. They do not make the
//! verdict a pure-synergy detector.
//!
//! The analysis does not use the fused state as a target because it depends on
//! `c`. This self-dependence can increase the estimated MI. Each pairwise estimate
//! must first pass the geometry gate. The report marks a channel with no gated
//! pair as not assessable. It does not mark that channel as corroborating.
//!
//! Estimator work has explicit bounds. Direct [`analyze`] processes one aligned
//! scalar projection. [`assess_stream`] processes each producer-attested common
//! projection axis separately.
//!
//! The geometry gates, delete-block bounds, and deterministic modality-keyed
//! Gaussian observation-noise model are safeguards. They do not supply a
//! calibration theorem. The clique and reference use the same window. The
//! empirical delete-block interval is not formal selective inference. The
//! thresholds do not have fleet calibration. The result remains advisory and has
//! `calibrated_posterior = false`.

mod engine;
mod fusion;
mod identity;
mod suite;

pub use engine::{
    analyze, ChannelPid, CircularDeleteBlockConfirmation, PairKsgEvidence, PidConfig,
    PidConfigError, PidConfirmation, PidConfirmationParams, PidEstimatorEvidence, PidParams,
    PidReport, PidResearchProfile, PidVerdict, MAX_PID_WINDOW, PID_ATOM_POINT_FIT_UNITS,
    PID_CONFIRMATION_EDGE_FIT_UNITS, PID_PAIR_POINT_FIT_UNITS, PID_RS_REVISION, PID_RS_VERSION,
};
pub use fusion::{
    assess_stream, fuse, fuse_axes, fuse_axes_diagnostics, AxisPidReport, FusedReport,
};
pub use galadriel_core::FusedVerdict;
pub use identity::{
    PidAssessmentBinding, PidAssessmentDigest, PidConfigDigest, PidResearchClassification,
    PidResearchSuiteDigest,
};
pub use suite::{
    PidResearchSuite, PidResearchSuiteError, PidResearchSuiteParams,
    MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK, MIN_PID_RESEARCH_MODALITIES,
};

// The signed-scalar channel extractor lives in galadriel-core.
// The pure correlation detector also uses it. Re-export it here for convenience.
pub use galadriel_core::{consistency_channels_with_temporal_limits, scalar_channels};
