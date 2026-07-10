#![forbid(unsafe_code)]
//! # galadriel-pid
//!
//! The cross-sensor **Partial Information Decomposition** engine for Galadriel's
//! Mirror — an opt-in escalation alongside the signed-correlation default.
//!
//! ## What it adds over the baseline
//!
//! The magnitude baseline in `galadriel-core` catches an attack that **inflates**
//! a channel's innovation. It is blind to a **moment-matched stealthy spoof**: an
//! injection that keeps each channel's NIS inside its own covariance (NIS still
//! `~ χ²(dof)`) while **decoupling** that channel from what the other sensors agree
//! on. This engine targets that pattern by measuring how much information each
//! channel still shares with a strict-majority consensus of the others. It does
//! not establish that every stealthy spoof is identifiable from these inputs.
//!
//! ## The estimand (honestly scoped)
//!
//! For each channel `c`, the report's corroboration score is its best pairwise KSG
//! mutual information. The verdict additionally requires a **unique strict-majority
//! clique**, and an attributed channel must have a successfully estimated low edge
//! to every clique member. Equal dyads and estimator failures are therefore
//! insufficient, never nominal or attributed. Positive attribution is
//! circular delete-block-confirmed by default: the joint worst-consensus margin
//! needs a positive lower bound, and the joint worst-candidate margin needs a
//! negative upper bound. Edge maxima/minima are recomputed inside every resample,
//! so all fitted edges enter two family-level extrema rather than an unresolvable
//! per-edge Bonferroni split. [`PidConfig::family_alpha`] is divided across those
//! two one-sided bounds (and across projection axes by [`assess_stream`]). Alongside it —
//! advisory, **report-only**, never read by the verdict — the engine reports the
//! channel's shared-exclusions **PID atoms** (`I^sx` redundancy and its Möbius
//! synergy) for the triple (channel, stable designated peer, consensus of the
//! rest). These atoms do not make the verdict a pure-synergy detector.
//! The fused state is never used as a target: it is a function of `c` itself, so
//! a successful attack would perversely *raise* `c`'s MI with it. Every pair
//! passes a mandatory **geometry gate** first; a channel with no gated pair is
//! reported as not-assessable (fail closed), never as corroborating.
//!
//! Estimator work is explicitly bounded. Direct [`analyze`] handles one aligned
//! scalar projection; [`assess_stream`] evaluates each producer-attested common
//! projection axis separately. Geometry gates, bootstrap bounds, and deterministic
//! modality-keyed jitter are safeguards, not a calibration theorem: the clique and
//! reference are selected on the same window, the empirical delete-block interval
//! is not formal selective inference, thresholds are not fleet-calibrated, and
//! this remains advisory (`calibrated_posterior = false`).

mod engine;
mod fusion;

pub use engine::{analyze, ChannelPid, PidConfig, PidReport, PidVerdict, MAX_PID_WINDOW};
pub use fusion::{assess_stream, fuse, fuse_axes, AxisPidReport, FusedReport};
pub use galadriel_core::FusedVerdict;

// The signed-scalar channel extractor lives in galadriel-core (it is shared with the
// pure correlation detector); re-exported here for convenience.
pub use galadriel_core::{consistency_channels_with_temporal_limits, scalar_channels};
