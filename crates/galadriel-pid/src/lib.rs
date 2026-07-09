#![forbid(unsafe_code)]
//! # galadriel-pid
//!
//! The cross-sensor **Partial Information Decomposition** engine for Galadriel's
//! Mirror — the layer that must *beat the NIS baseline* to earn its place.
//!
//! ## What it adds over the baseline
//!
//! The magnitude baseline in `galadriel-core` catches an attack that **inflates**
//! a channel's innovation. It is blind to a **moment-matched stealthy spoof**: an
//! injection that keeps each channel's NIS inside its own covariance (NIS still
//! `~ χ²(dof)`) while **decoupling** that channel from what the other sensors agree
//! on. This engine catches exactly that, by measuring, per channel, how much
//! information it still shares with a **leave-one-out consensus** of the others.
//!
//! ## The estimand (honestly scoped)
//!
//! For each channel `c`, the target `T` is the **leave-one-out consensus** of the
//! *other* channels — never the fused state (which is a function of `c` itself, so
//! a successful attack would perversely *raise* `c`'s MI with it). The signal is a
//! **collapse of `c`'s mutual information / redundancy with that consensus**, using
//! the `pid-core` KSG and `I^sx` estimators. Every window passes a mandatory
//! **geometry gate** first; a channel that fails the gate is reported as
//! not-assessable (fail closed), never as corroborating.
//!
//! Estimator validity is real and bounded: this runs on a **scalar** signed
//! innovation projection to stay in the low-dimensional band the estimators are
//! trustworthy in. It is advisory (`calibrated_posterior = false`).

mod engine;
mod fusion;

pub use engine::{analyze, ChannelPid, PidConfig, PidReport, PidVerdict};
pub use fusion::{assess_stream, fuse, FusedReport};
pub use galadriel_core::FusedVerdict;

// The signed-scalar channel extractor lives in galadriel-core (it is shared with the
// pure correlation detector); re-exported here for convenience.
pub use galadriel_core::scalar_channels;
