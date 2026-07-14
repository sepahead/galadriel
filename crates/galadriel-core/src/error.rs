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

    /// An observation violates the detector's wire or streaming invariants.
    #[error("invalid observation: {0}")]
    InvalidObservation(String),

    /// A cross-channel input cannot be aligned or interpreted unambiguously.
    #[error("invalid channel input: {0}")]
    InvalidChannels(String),

    /// The detector's bounded retained-state limit was reached.
    #[error("track limit reached: configured maximum is {limit}")]
    TrackLimit { limit: usize },

    /// A configuration value was out of range.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Baseline detector configuration construction or preflight failed.
    #[error("invalid detector configuration: {0}")]
    DetectorConfig(#[from] crate::config::DetectorConfigError),

    /// Release-suite composition or aggregate preflight failed.
    #[error("invalid release suite: {0}")]
    ReleaseSuite(#[from] crate::config::ReleaseSuiteError),

    /// Signed-correlation configuration construction or work preflight failed.
    #[error("invalid correlation configuration: {0}")]
    CorrelationConfig(#[from] crate::correlation::CorrConfigError),

    /// A proposed downstream advisory effect would grant, widen, or otherwise
    /// mutate authority outside the selected record/restrict-only policy.
    #[error("advisory authority violation: {0}")]
    AuthorityViolation(&'static str),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, GaladrielError>;
