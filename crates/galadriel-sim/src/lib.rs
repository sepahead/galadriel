#![forbid(unsafe_code)]
//! # galadriel-sim
//!
//! Synthetic multi-sensor scenarios and an injection library for exercising
//! [`galadriel_core`]'s detector deterministically.
//!
//! A [`scenario::generate`] call produces a clean stream of [`galadriel_core::PidObservation`]s
//! whose per-channel `NIS ~ χ²(3)` under the null. The [`injection`] module then
//! transforms that stream into an attack:
//!
//! - [`injection::PhantomAcousticDoa`] — a targeted single-channel bias, expected to
//!   produce **attributed-inconsistency** evidence.
//! - [`injection::BroadbandJam`] — a correlated all-channel inflation, expected to
//!   produce **broad-degradation** evidence.

pub mod injection;
pub mod rng;
pub mod scenario;

pub use injection::{inject, BroadbandJam, Injection, PhantomAcousticDoa};
pub use scenario::{generate, ScenarioConfig};
