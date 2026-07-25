#![forbid(unsafe_code)]
//! # galadriel-sim
//!
//! Deterministic synthetic scenarios for [`galadriel_core`].
//!
//! A [`scenario::generate`] call produces a clean stream of [`galadriel_core::PidObservation`]s
//! whose per-channel `NIS ~ χ²(3)` under the null. The [`injection`] module then
//! transforms that stream into a modeled perturbation.
//!
//! - [`injection::PhantomAcousticDoa`] applies a targeted single-channel bias. It can
//!   produce **attributed-inconsistency** evidence.
//! - [`injection::BroadbandJam`] applies correlated all-channel inflation. It can
//!   produce **broad-degradation** evidence.
//!
//! [`scenario::ScenarioConfig::assessment_scope`] creates deterministic synthetic
//! scope labels for nonempty accepted-path tests and evaluation. Empty scenarios
//! have no terminal scope. These labels are not operational provenance. They do
//! not authenticate a producer.

pub mod injection;
pub mod rng;
pub mod scenario;

pub use injection::{inject, BroadbandJam, Injection, PhantomAcousticDoa};
pub use scenario::{
    generate, ScenarioAssessmentScopeError, ScenarioConfig, ScenarioConfigError,
    ScenarioConfigOrigin, ScenarioParams, ScenarioResearchProfile,
};
