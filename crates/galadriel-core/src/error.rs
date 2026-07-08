//! Error type for galadriel-core.

use thiserror::Error;

/// Errors surfaced by the core detector.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum GaladrielError {
    /// A window held fewer samples than the configured minimum. The detector
    /// fails closed to [`crate::Verdict::InsufficientEvidence`] rather than
    /// returning this in normal streaming operation.
    #[error("insufficient samples: have {have}, need at least {need}")]
    InsufficientSamples { have: usize, need: usize },

    /// A non-finite (NaN/±∞) value reached a numeric path where it is not allowed.
    #[error("non-finite value in {0}")]
    NonFinite(&'static str),

    /// A configuration value was out of range.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, GaladrielError>;
