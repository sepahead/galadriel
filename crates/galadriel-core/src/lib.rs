#![forbid(unsafe_code)]
//! # galadriel-core
//!
//! The pure, dependency-light core of **Galadriel's Mirror** — a cross-sensor
//! consistency monitor for multi-sensor fusion (counter-UAS / embodied-agent
//! perception).
//!
//! This crate ships the **cheap baseline** the more expensive information-theoretic
//! engine must beat before it is trusted: a per-channel **Normalized Innovation
//! Squared (NIS) χ² consistency test** plus a **CUSUM** change detector, folded
//! into a fail-closed **jam-vs-spoof** decision.
//!
//! ## What it consumes
//!
//! A stream of [`PidObservation`] records — one per associated measurement,
//! carrying the scalar `NIS = yᵀ S⁻¹ y ~ χ²(dof)` formed against the *a priori*
//! (predicted, pre-update) track state. In the sepahead ecosystem these are
//! emitted by crebain's fusion `update_track` and delivered over the NCP
//! observation plane; here they are transport-agnostic plain data.
//!
//! ## The decision, honestly scoped
//!
//! | observation | verdict | reasoning |
//! |---|---|---|
//! | all channels' NIS consistent with χ²(dof) | [`Verdict::Nominal`] | picture corroborated |
//! | **one** channel's NIS inflated, others nominal | [`Verdict::Spoof`] | targeted single-channel false-data injection |
//! | **most/all** channels' NIS inflated together | [`Verdict::Jam`] | correlated denial / degradation |
//! | too few samples / channels | [`Verdict::InsufficientEvidence`] | **fail closed** — never default to Nominal |
//!
//! This is an **advisory** detector. It authenticates *statistical consistency*,
//! not truth: a moment-matched spoof that keeps each channel's NIS within its own
//! covariance passes the baseline — separating those from benign decorrelation is
//! the job of the optional `pid` engine (cross-channel information structure). See the
//! repository's `docs/JUSTIFICATION.md` and `docs/EVALUATION.md`.

pub mod baseline;
pub mod chi2;
pub mod config;
pub mod correlation;
pub mod cusum;
pub mod decision;
pub mod error;
pub mod fusion;
pub mod observation;
pub mod window;

pub use config::DetectorConfig;
pub use correlation::{CorrChannel, CorrConfig, CorrReport, CorrVerdict};
pub use cusum::Cusum;
pub use decision::{ChannelReport, Mirror, MirrorReport, Verdict};
pub use error::{GaladrielError, Result};
pub use fusion::{assess_default, combine, DefaultReport, FusedVerdict};
pub use observation::{Modality, PidObservation};
pub use window::NisWindow;

/// Extract, per modality, the aligned series of a single signed innovation axis from a
/// stream of observations — the scalar the cross-sensor consistency detectors key off.
/// A *signed* axis (not the NIS magnitude) is used so the cross-channel correlation a
/// spoof breaks is preserved.
pub fn scalar_channels(
    stream: &[PidObservation],
    modalities: &[Modality],
    axis: usize,
) -> Vec<(Modality, Vec<f64>)> {
    modalities
        .iter()
        .map(|&m| {
            let series: Vec<f64> = stream
                .iter()
                .filter(|o| o.modality == m)
                .filter_map(|o| o.innovation.map(|y| y[axis.min(2)]))
                .collect();
            (m, series)
        })
        .collect()
}
