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
//! For each channel `c`, the **verdict-driving corroboration score is its best
//! pairwise KSG mutual information with any other channel** (two honest channels
//! keep high MI *with each other* no matter what a spoofed third does, so the
//! spoofed channel is the one that shares information with no one). Alongside it —
//! advisory, **report-only**, never read by the verdict — the engine reports the
//! channel's shared-exclusions **PID atoms** (`I^sx` redundancy and its Möbius
//! synergy) for the triple (channel, designated peer, consensus of the rest).
//! The fused state is never used as a target: it is a function of `c` itself, so
//! a successful attack would perversely *raise* `c`'s MI with it. Every pair
//! passes a mandatory **geometry gate** first; a channel with no gated pair is
//! reported as not-assessable (fail closed), never as corroborating.
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
