//! Immutable detector and release-suite configuration boundaries.

use serde::Serialize;
use thiserror::Error;

use crate::correlation::{CorrConfig, CorrProfile};
use crate::identity::IdentityBuilder;
use crate::{ConfigDigest, Modality};

const fn modality_identity_tag(modality: Modality) -> u8 {
    match modality {
        Modality::Visual => 1,
        Modality::Thermal => 2,
        Modality::Acoustic => 3,
        Modality::Radar => 4,
        Modality::Lidar => 5,
        Modality::RadioFrequency => 6,
    }
}

/// Aggregate upper bound for retained NIS values across all tracks and modalities.
pub const MAX_RETAINED_NIS_SAMPLES: usize = 1_000_000;

/// Fixed maximum number of track identities one detector may retain.
pub const MAX_DETECTOR_TRACKS: usize = 4_096;

/// Fixed maximum number of `(track, modality)` channel states.
pub const MAX_DETECTOR_CHANNEL_STATES: usize = MAX_DETECTOR_TRACKS * Modality::ALL.len();

/// Conservative maximum retained detector-state allocation.
pub const MAX_DETECTOR_STATE_BYTES: usize = 256 * 1024 * 1024;

/// Per-channel fixed state and `HashMap` allocation allowance, excluding the
/// NIS sample buffer and exact-sum cache.
pub const CHANNEL_STATE_AND_MAP_OVERHEAD_BYTES: usize = 256;

/// Conservative full-suite lifecycle sample-work ceiling.
pub const MAX_RELEASE_LIFECYCLE_SAMPLE_UNITS: usize = 8_000_000;

/// Conservative full-suite retained and transient-state ceiling.
pub const MAX_RELEASE_SUITE_STATE_BYTES: usize = 384 * 1024 * 1024;

/// Smallest family significance whose maximum six-way Bonferroni split keeps
/// every per-channel test in the numerically supported normal `f64` range.
pub const MIN_NIS_FAMILY_ALPHA: f64 =
    crate::baseline::MIN_NIS_TEST_ALPHA * Modality::ALL.len() as f64;

/// Largest supported fusion-sequence gap for one contiguous evidence window.
pub const MAX_ALIGNMENT_SEQ_GAP: u64 = crate::correlation::MAX_CORRELATION_WINDOW as u64;

/// Largest supported timestamp span across one aligned cross-modal frame.
pub const MAX_ALIGNMENT_TIMESTAMP_SKEW_MS: u64 = 86_400_000;

/// Largest supported interval between successive samples of one modality.
pub const MAX_INTER_SAMPLE_GAP_MS: u64 = 86_400_000;

/// Closed detector-component profiles shipped in the 0.9 source release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorProfile {
    /// NIS/CUSUM component of the standalone advisory release suite.
    StandaloneAdvisoryV0_9,
}

impl DetectorProfile {
    /// Stable machine-readable profile name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::StandaloneAdvisoryV0_9 => "standalone_advisory_v0_9",
        }
    }

    /// Raw parameter template for this profile.
    pub fn params(self) -> DetectorParams {
        match self {
            Self::StandaloneAdvisoryV0_9 => DetectorParams::standalone_advisory_v0_9(),
        }
    }

    /// Resolve this profile through the normal validation boundary.
    pub fn try_config(self) -> Result<DetectorConfig, DetectorConfigError> {
        DetectorConfig::try_new_with_profile(self.params(), Some(self))
    }
}

/// Whether an accepted component came from a named release profile or custom input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationClass {
    /// A closed, versioned release-component profile.
    NamedRelease,
    /// Accepted custom parameters; never relabelled as a shipped profile.
    CustomAccepted,
}

/// Unvalidated boundary values for constructing a [`DetectorConfig`].
#[derive(Debug, Clone, PartialEq)]
pub struct DetectorParams {
    /// Per-`(track, modality)` sliding-window length, in observations.
    pub window_len: usize,
    /// Minimum samples required before one channel is ready.
    pub min_samples: usize,
    /// Minimum number of ready channels required for an evidence verdict.
    pub min_channels: usize,
    /// Largest accepted fusion-sequence gap.
    pub max_seq_gap: u64,
    /// Largest timestamp span across an aligned frame.
    pub max_timestamp_skew_ms: u64,
    /// Largest timestamp gap between successive samples of one modality.
    pub max_inter_sample_gap_ms: u64,
    /// Maximum number of track identities retained at once.
    pub max_tracks: usize,
    /// Per-assessment family-wise NIS significance.
    pub nis_alpha: f64,
    /// Two-sided CUSUM slack in scaled null-standard-deviation units.
    pub cusum_slack: f64,
    /// Two-sided CUSUM alarm threshold in scaled units.
    pub cusum_threshold: f64,
    /// Fraction of ready channels required for broad-degradation evidence.
    pub jam_fraction: f64,
}

impl DetectorParams {
    /// Raw values of the 0.9 standalone-advisory detector component.
    pub fn standalone_advisory_v0_9() -> Self {
        Self {
            window_len: 64,
            min_samples: 32,
            min_channels: 2,
            max_seq_gap: 1,
            max_timestamp_skew_ms: 1_000,
            max_inter_sample_gap_ms: 10_000,
            max_tracks: 1_024,
            nis_alpha: 0.01,
            cusum_slack: 3.0 / 6.0_f64.sqrt(),
            cusum_threshold: 15.0 / 6.0_f64.sqrt(),
            jam_fraction: 0.6,
        }
    }
}

/// Typed failure from detector configuration construction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetectorConfigError {
    /// Window length is outside the fixed allocation domain.
    #[error("window_len must be in 1..={maximum}, got {requested}")]
    WindowOutOfRange { requested: usize, maximum: usize },
    /// Readiness minimum is zero or exceeds the window.
    #[error("min_samples must be in 1..=window_len")]
    MinimumSamplesOutOfRange,
    /// Required channel count is outside the closed modality vocabulary.
    #[error("min_channels must be in 2..={maximum}, got {requested}")]
    MinimumChannelsOutOfRange { requested: usize, maximum: usize },
    /// Sequence continuity limit is unsupported.
    #[error("max_seq_gap must be in 1..={maximum}, got {requested}")]
    SequenceGapOutOfRange { requested: u64, maximum: u64 },
    /// Cross-modal timestamp skew is above the hard ceiling.
    #[error("max_timestamp_skew_ms must be in 0..={maximum}, got {requested}")]
    TimestampSkewOutOfRange { requested: u64, maximum: u64 },
    /// Inter-sample time gap is unsupported.
    #[error("max_inter_sample_gap_ms must be in 1..={maximum}, got {requested}")]
    InterSampleGapOutOfRange { requested: u64, maximum: u64 },
    /// Track ceiling is zero or above the fixed bound.
    #[error("max_tracks must be in 1..={maximum}, got {requested}")]
    TrackCountOutOfRange { requested: usize, maximum: usize },
    /// Family-wise significance is outside the numerically supported domain.
    #[error("nis_alpha must be finite and in [{minimum}, 1)")]
    NisAlphaInvalid { minimum: String },
    /// CUSUM slack is non-finite or negative.
    #[error("cusum_slack must be finite and nonnegative")]
    CusumSlackInvalid,
    /// CUSUM threshold is non-finite or nonpositive.
    #[error("cusum_threshold must be finite and positive")]
    CusumThresholdInvalid,
    /// Broad-degradation fraction is outside `(0, 1]`.
    #[error("jam_fraction must be finite and in (0, 1]")]
    JamFractionInvalid,
    /// A checked aggregate estimate overflowed.
    #[error("detector retained-state estimate overflowed")]
    StateEstimateOverflow,
    /// Channel-state cardinality exceeds the fixed ceiling.
    #[error("detector can retain {requested} channel states; maximum is {maximum}")]
    ChannelStateLimitExceeded { requested: usize, maximum: usize },
    /// Retained NIS values exceed the fixed ceiling.
    #[error("detector can retain {requested} NIS samples; maximum is {maximum}")]
    RetainedSampleLimitExceeded { requested: usize, maximum: usize },
    /// Conservative retained bytes exceed the fixed ceiling.
    #[error("detector can retain {requested} bytes; maximum is {maximum}")]
    RetainedByteLimitExceeded { requested: usize, maximum: usize },
}

/// Immutable, fully validated NIS/CUSUM detector configuration.
///
/// Construction is `O(1)` and allocates nothing. A detector can retain at most
/// `max_tracks * modalities` channel states. Each state budgets
/// `window_len * size_of::<f64>()` sample bytes, the fixed 272-byte exact
/// [`crate::NisWindow`] cache, and [`CHANNEL_STATE_AND_MAP_OVERHEAD_BYTES`] for
/// channel state plus nested `HashMap` allocation. All products are checked.
///
/// ```compile_fail
/// use galadriel_core::DetectorConfig;
/// let _ = DetectorConfig { window_len: 64 };
/// ```
///
/// ```compile_fail
/// use galadriel_core::DetectorConfig;
/// let mut config = DetectorConfig::standalone_advisory_v0_9().unwrap();
/// config.max_tracks = 1;
/// ```
///
/// ```compile_fail
/// use galadriel_core::DetectorConfig;
/// let _: DetectorConfig = Default::default();
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DetectorConfig {
    window_len: usize,
    min_samples: usize,
    min_channels: usize,
    max_seq_gap: u64,
    max_timestamp_skew_ms: u64,
    max_inter_sample_gap_ms: u64,
    max_tracks: usize,
    nis_alpha: f64,
    cusum_slack: f64,
    cusum_threshold: f64,
    jam_fraction: f64,
    source_profile: Option<DetectorProfile>,
    retained_channel_states: usize,
    retained_state_bytes: usize,
    identity: ConfigDigest,
}

impl DetectorConfig {
    /// Validate raw custom parameters and construct an immutable config.
    pub fn try_new(params: DetectorParams) -> Result<Self, DetectorConfigError> {
        Self::try_new_with_profile(params, None)
    }

    fn try_new_with_profile(
        mut params: DetectorParams,
        source_profile: Option<DetectorProfile>,
    ) -> Result<Self, DetectorConfigError> {
        if !(1..=crate::window::MAX_WINDOW_LEN).contains(&params.window_len) {
            return Err(DetectorConfigError::WindowOutOfRange {
                requested: params.window_len,
                maximum: crate::window::MAX_WINDOW_LEN,
            });
        }
        if !(1..=params.window_len).contains(&params.min_samples) {
            return Err(DetectorConfigError::MinimumSamplesOutOfRange);
        }
        if !(2..=Modality::ALL.len()).contains(&params.min_channels) {
            return Err(DetectorConfigError::MinimumChannelsOutOfRange {
                requested: params.min_channels,
                maximum: Modality::ALL.len(),
            });
        }
        validate_alignment_limits(
            params.max_seq_gap,
            params.max_timestamp_skew_ms,
            params.max_inter_sample_gap_ms,
        )?;
        if !(1..=MAX_DETECTOR_TRACKS).contains(&params.max_tracks) {
            return Err(DetectorConfigError::TrackCountOutOfRange {
                requested: params.max_tracks,
                maximum: MAX_DETECTOR_TRACKS,
            });
        }
        if !params.nis_alpha.is_finite() || !(MIN_NIS_FAMILY_ALPHA..1.0).contains(&params.nis_alpha)
        {
            return Err(DetectorConfigError::NisAlphaInvalid {
                minimum: format!("{MIN_NIS_FAMILY_ALPHA:e}"),
            });
        }
        if !params.cusum_slack.is_finite() || params.cusum_slack < 0.0 {
            return Err(DetectorConfigError::CusumSlackInvalid);
        }
        if !params.cusum_threshold.is_finite() || params.cusum_threshold <= 0.0 {
            return Err(DetectorConfigError::CusumThresholdInvalid);
        }
        if !params.jam_fraction.is_finite()
            || params.jam_fraction <= 0.0
            || params.jam_fraction > 1.0
        {
            return Err(DetectorConfigError::JamFractionInvalid);
        }

        // Canonicalize the only admitted signed zero before storage and hashing.
        if params.cusum_slack == 0.0 {
            params.cusum_slack = 0.0;
        }

        let retained_channel_states = params
            .max_tracks
            .checked_mul(Modality::ALL.len())
            .ok_or(DetectorConfigError::StateEstimateOverflow)?;
        if retained_channel_states > MAX_DETECTOR_CHANNEL_STATES {
            return Err(DetectorConfigError::ChannelStateLimitExceeded {
                requested: retained_channel_states,
                maximum: MAX_DETECTOR_CHANNEL_STATES,
            });
        }
        let retained_samples = retained_channel_states
            .checked_mul(params.window_len)
            .ok_or(DetectorConfigError::StateEstimateOverflow)?;
        if retained_samples > MAX_RETAINED_NIS_SAMPLES {
            return Err(DetectorConfigError::RetainedSampleLimitExceeded {
                requested: retained_samples,
                maximum: MAX_RETAINED_NIS_SAMPLES,
            });
        }
        let sample_bytes = retained_samples
            .checked_mul(std::mem::size_of::<f64>())
            .ok_or(DetectorConfigError::StateEstimateOverflow)?;
        let fixed_channel_bytes = crate::window::NIS_WINDOW_EXACT_CACHE_BYTES
            .checked_add(CHANNEL_STATE_AND_MAP_OVERHEAD_BYTES)
            .and_then(|bytes| bytes.checked_mul(retained_channel_states))
            .ok_or(DetectorConfigError::StateEstimateOverflow)?;
        let retained_state_bytes = sample_bytes
            .checked_add(fixed_channel_bytes)
            .ok_or(DetectorConfigError::StateEstimateOverflow)?;
        if retained_state_bytes > MAX_DETECTOR_STATE_BYTES {
            return Err(DetectorConfigError::RetainedByteLimitExceeded {
                requested: retained_state_bytes,
                maximum: MAX_DETECTOR_STATE_BYTES,
            });
        }

        let mut identity = IdentityBuilder::new(b"galadriel-detector-config-v1");
        identity.u8(
            b"classification",
            if source_profile.is_some() { 1 } else { 2 },
        );
        identity.u8(
            b"source_profile",
            match source_profile {
                Some(DetectorProfile::StandaloneAdvisoryV0_9) => 1,
                None => 0,
            },
        );
        identity.usize(b"window_len", params.window_len);
        identity.usize(b"min_samples", params.min_samples);
        identity.usize(b"min_channels", params.min_channels);
        identity.u64(b"max_seq_gap", params.max_seq_gap);
        identity.u64(b"max_timestamp_skew_ms", params.max_timestamp_skew_ms);
        identity.u64(b"max_inter_sample_gap_ms", params.max_inter_sample_gap_ms);
        identity.usize(b"max_tracks", params.max_tracks);
        identity.f64(b"nis_alpha", params.nis_alpha);
        identity.f64(b"cusum_slack", params.cusum_slack);
        identity.f64(b"cusum_threshold", params.cusum_threshold);
        identity.f64(b"jam_fraction", params.jam_fraction);
        identity.usize(b"retained_channel_states", retained_channel_states);
        identity.usize(b"retained_state_bytes", retained_state_bytes);

        Ok(Self {
            window_len: params.window_len,
            min_samples: params.min_samples,
            min_channels: params.min_channels,
            max_seq_gap: params.max_seq_gap,
            max_timestamp_skew_ms: params.max_timestamp_skew_ms,
            max_inter_sample_gap_ms: params.max_inter_sample_gap_ms,
            max_tracks: params.max_tracks,
            nis_alpha: params.nis_alpha,
            cusum_slack: params.cusum_slack,
            cusum_threshold: params.cusum_threshold,
            jam_fraction: params.jam_fraction,
            source_profile,
            retained_channel_states,
            retained_state_bytes,
            identity: identity.finish(),
        })
    }

    /// Construct the named 0.9 standalone-advisory detector component.
    pub fn standalone_advisory_v0_9() -> Result<Self, DetectorConfigError> {
        DetectorProfile::StandaloneAdvisoryV0_9.try_config()
    }

    /// Per-channel window length.
    pub const fn window_len(&self) -> usize {
        self.window_len
    }
    /// Minimum samples required for channel readiness.
    pub const fn min_samples(&self) -> usize {
        self.min_samples
    }
    /// Minimum ready channels required for an evidence verdict.
    pub const fn min_channels(&self) -> usize {
        self.min_channels
    }
    /// Largest accepted fusion-sequence gap.
    pub const fn max_seq_gap(&self) -> u64 {
        self.max_seq_gap
    }
    /// Largest timestamp span across an aligned frame.
    pub const fn max_timestamp_skew_ms(&self) -> u64 {
        self.max_timestamp_skew_ms
    }
    /// Largest timestamp gap between successive samples of one modality.
    pub const fn max_inter_sample_gap_ms(&self) -> u64 {
        self.max_inter_sample_gap_ms
    }
    /// Maximum retained track identities.
    pub const fn max_tracks(&self) -> usize {
        self.max_tracks
    }
    /// Per-assessment family-wise NIS significance.
    pub const fn nis_alpha(&self) -> f64 {
        self.nis_alpha
    }
    /// Scaled CUSUM slack.
    pub const fn cusum_slack(&self) -> f64 {
        self.cusum_slack
    }
    /// Scaled CUSUM threshold.
    pub const fn cusum_threshold(&self) -> f64 {
        self.cusum_threshold
    }
    /// Broad-degradation channel fraction.
    pub const fn jam_fraction(&self) -> f64 {
        self.jam_fraction
    }
    /// Named source profile, if any.
    pub const fn source_profile(&self) -> Option<DetectorProfile> {
        self.source_profile
    }
    /// Release/custom classification retained by this accepted component.
    pub const fn classification(&self) -> ConfigurationClass {
        if self.source_profile.is_some() {
            ConfigurationClass::NamedRelease
        } else {
            ConfigurationClass::CustomAccepted
        }
    }
    /// Maximum `(track, modality)` states budgeted by this config.
    pub const fn retained_channel_states(&self) -> usize {
        self.retained_channel_states
    }
    /// Conservative maximum retained bytes budgeted by this config.
    pub const fn retained_state_bytes(&self) -> usize {
        self.retained_state_bytes
    }
    /// Canonical complete accepted-configuration identity.
    pub const fn identity(&self) -> ConfigDigest {
        self.identity
    }
}

impl TryFrom<DetectorParams> for DetectorConfig {
    type Error = DetectorConfigError;

    fn try_from(params: DetectorParams) -> Result<Self, Self::Error> {
        Self::try_new(params)
    }
}

/// Validate temporal limits shared by streaming and direct extraction.
pub(crate) fn validate_alignment_limits(
    max_seq_gap: u64,
    max_timestamp_skew_ms: u64,
    max_inter_sample_gap_ms: u64,
) -> Result<(), DetectorConfigError> {
    if !(1..=MAX_ALIGNMENT_SEQ_GAP).contains(&max_seq_gap) {
        return Err(DetectorConfigError::SequenceGapOutOfRange {
            requested: max_seq_gap,
            maximum: MAX_ALIGNMENT_SEQ_GAP,
        });
    }
    if max_timestamp_skew_ms > MAX_ALIGNMENT_TIMESTAMP_SKEW_MS {
        return Err(DetectorConfigError::TimestampSkewOutOfRange {
            requested: max_timestamp_skew_ms,
            maximum: MAX_ALIGNMENT_TIMESTAMP_SKEW_MS,
        });
    }
    if !(1..=MAX_INTER_SAMPLE_GAP_MS).contains(&max_inter_sample_gap_ms) {
        return Err(DetectorConfigError::InterSampleGapOutOfRange {
            requested: max_inter_sample_gap_ms,
            maximum: MAX_INTER_SAMPLE_GAP_MS,
        });
    }
    Ok(())
}

/// Closed source-release suite profiles. A profile is reproducible behavior,
/// not deployment qualification or a mission-level calibration claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseProfile {
    /// NIS/CUSUM plus signed correlation; PID is intentionally absent.
    StandaloneAdvisoryV0_9,
}

impl ReleaseProfile {
    /// Stable machine-readable profile name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::StandaloneAdvisoryV0_9 => "standalone_advisory_v0_9",
        }
    }

    /// Resolve a named release suite for an explicit expected-modality set.
    pub fn try_suite(
        self,
        expected_modalities: &[Modality],
    ) -> Result<ReleaseSuite, ReleaseSuiteError> {
        match self {
            Self::StandaloneAdvisoryV0_9 => ReleaseSuite::try_new_with_profile(
                ReleaseSuiteParams {
                    detector: DetectorProfile::StandaloneAdvisoryV0_9.try_config()?,
                    correlation: CorrProfile::StandaloneAdvisoryV0_9.try_config()?,
                    expected_modalities: expected_modalities.to_vec(),
                    axis_policy: ProducerAxisFamilyPolicy::AttestedCommonProjectionBonferroniV1,
                },
                Some(self),
            ),
        }
    }
}

/// Explicit policy for producer axes and statistical family sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerAxisFamilyPolicy {
    /// Use only producer-attested common projections and split the correlation
    /// family budget once across every active axis.
    AttestedCommonProjectionBonferroniV1,
}

/// Unvalidated composition input for a release detector suite.
#[derive(Debug, Clone)]
pub struct ReleaseSuiteParams {
    /// Already accepted magnitude detector component.
    pub detector: DetectorConfig,
    /// Already accepted signed-correlation component.
    pub correlation: CorrConfig,
    /// Complete expected modality set.
    pub expected_modalities: Vec<Modality>,
    /// Producer-axis and family-sharing semantics.
    pub axis_policy: ProducerAxisFamilyPolicy,
}

/// Typed failure from release-suite composition.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReleaseSuiteError {
    /// Detector component construction failed.
    #[error("release detector component is invalid: {0}")]
    Detector(#[from] DetectorConfigError),
    /// Correlation component construction failed.
    #[error("release correlation component is invalid: {0}")]
    Correlation(#[from] crate::CorrConfigError),
    /// No modality capability was declared.
    #[error("release suite expected modalities must not be empty")]
    EmptyModalities,
    /// A modality was declared more than once.
    #[error("release suite expected modalities must be unique")]
    DuplicateModalities,
    /// The modality set cannot meet detector readiness.
    #[error("expected modality count {available} is below detector min_channels {required}")]
    TooFewModalities { available: usize, required: usize },
    /// A checked aggregate estimate overflowed.
    #[error("release-suite aggregate preflight overflowed")]
    AggregateOverflow,
    /// Lifecycle work across both statistical windows exceeds the ceiling.
    #[error("release suite requires {requested} lifecycle sample-units; maximum is {maximum}")]
    LifecycleWorkLimitExceeded { requested: usize, maximum: usize },
    /// Conservative retained plus transient bytes exceed the ceiling.
    #[error("release suite requires {requested} state bytes; maximum is {maximum}")]
    StateByteLimitExceeded { requested: usize, maximum: usize },
}

/// Immutable NIS/CUSUM plus signed-correlation release composition.
///
/// Construction sorts and validates at most six modalities (`O(m log m)`, `O(m)`
/// storage). It checks
/// `max(detector.window_len, correlation.window) * max_tracks * modalities`
/// before any detector allocation, includes every detector channel state's sample
/// buffer, 272-byte exact cache and map/state overhead, and budgets a full aligned
/// correlation tail. PID is not a field of this type.
///
/// ```compile_fail
/// use galadriel_core::ReleaseSuite;
/// let _ = ReleaseSuite { expected_modalities: Vec::new() };
/// ```
#[derive(Debug, Clone)]
pub struct ReleaseSuite {
    detector: DetectorConfig,
    correlation: CorrConfig,
    expected_modalities: Vec<Modality>,
    axis_policy: ProducerAxisFamilyPolicy,
    source_profile: Option<ReleaseProfile>,
    lifecycle_sample_units: usize,
    state_bytes: usize,
    identity: ConfigDigest,
}

impl ReleaseSuite {
    /// Compose accepted custom components into an accepted custom release suite.
    pub fn try_new(params: ReleaseSuiteParams) -> Result<Self, ReleaseSuiteError> {
        Self::try_new_with_profile(params, None)
    }

    fn try_new_with_profile(
        params: ReleaseSuiteParams,
        source_profile: Option<ReleaseProfile>,
    ) -> Result<Self, ReleaseSuiteError> {
        if params.expected_modalities.is_empty() {
            return Err(ReleaseSuiteError::EmptyModalities);
        }
        if params.expected_modalities.len() > Modality::ALL.len() {
            return Err(ReleaseSuiteError::DuplicateModalities);
        }
        let mut expected_modalities = params.expected_modalities;
        expected_modalities.sort_unstable_by_key(|modality| modality.stable_code());
        let before = expected_modalities.len();
        expected_modalities.dedup();
        if expected_modalities.len() != before {
            return Err(ReleaseSuiteError::DuplicateModalities);
        }
        if expected_modalities.len() < params.detector.min_channels() {
            return Err(ReleaseSuiteError::TooFewModalities {
                available: expected_modalities.len(),
                required: params.detector.min_channels(),
            });
        }

        let lifecycle_window = params
            .detector
            .window_len()
            .max(params.correlation.window());
        let lifecycle_sample_units = params
            .detector
            .max_tracks()
            .checked_mul(expected_modalities.len())
            .and_then(|channels| channels.checked_mul(lifecycle_window))
            .ok_or(ReleaseSuiteError::AggregateOverflow)?;
        if lifecycle_sample_units > MAX_RELEASE_LIFECYCLE_SAMPLE_UNITS {
            return Err(ReleaseSuiteError::LifecycleWorkLimitExceeded {
                requested: lifecycle_sample_units,
                maximum: MAX_RELEASE_LIFECYCLE_SAMPLE_UNITS,
            });
        }
        let aligned_tail_bytes = lifecycle_sample_units
            .checked_mul(std::mem::size_of::<f64>())
            .ok_or(ReleaseSuiteError::AggregateOverflow)?;
        let pair_count = expected_modalities
            .len()
            .checked_mul(expected_modalities.len().saturating_sub(1))
            .map(|ordered| ordered / 2)
            .ok_or(ReleaseSuiteError::AggregateOverflow)?;
        let pair_work_bytes = pair_count
            .checked_mul(params.correlation.window())
            .and_then(|values| values.checked_mul(std::mem::size_of::<f64>()))
            .ok_or(ReleaseSuiteError::AggregateOverflow)?;
        let state_bytes = params
            .detector
            .retained_state_bytes()
            .checked_add(aligned_tail_bytes)
            .and_then(|bytes| bytes.checked_add(pair_work_bytes))
            .ok_or(ReleaseSuiteError::AggregateOverflow)?;
        if state_bytes > MAX_RELEASE_SUITE_STATE_BYTES {
            return Err(ReleaseSuiteError::StateByteLimitExceeded {
                requested: state_bytes,
                maximum: MAX_RELEASE_SUITE_STATE_BYTES,
            });
        }

        let mut identity = IdentityBuilder::new(b"galadriel-release-suite-v1");
        identity.u8(
            b"classification",
            if source_profile.is_some() { 1 } else { 2 },
        );
        identity.u8(
            b"source_profile",
            match source_profile {
                Some(ReleaseProfile::StandaloneAdvisoryV0_9) => 1,
                None => 0,
            },
        );
        identity.digest(b"detector", params.detector.identity());
        identity.digest(b"correlation", params.correlation.identity());
        identity.usize(b"modality_count", expected_modalities.len());
        for (index, modality) in expected_modalities.iter().enumerate() {
            let field = match index {
                0 => b"modality_0".as_slice(),
                1 => b"modality_1".as_slice(),
                2 => b"modality_2".as_slice(),
                3 => b"modality_3".as_slice(),
                4 => b"modality_4".as_slice(),
                _ => b"modality_5".as_slice(),
            };
            identity.bytes(field, &[modality_identity_tag(*modality)]);
        }
        identity.u8(
            b"axis_policy",
            match params.axis_policy {
                ProducerAxisFamilyPolicy::AttestedCommonProjectionBonferroniV1 => 1,
            },
        );
        identity.usize(b"lifecycle_sample_units", lifecycle_sample_units);
        identity.usize(b"state_bytes", state_bytes);

        Ok(Self {
            detector: params.detector,
            correlation: params.correlation,
            expected_modalities,
            axis_policy: params.axis_policy,
            source_profile,
            lifecycle_sample_units,
            state_bytes,
            identity: identity.finish(),
        })
    }

    /// Construct the named release suite for explicit expected modalities.
    pub fn standalone_advisory_v0_9(
        expected_modalities: &[Modality],
    ) -> Result<Self, ReleaseSuiteError> {
        ReleaseProfile::StandaloneAdvisoryV0_9.try_suite(expected_modalities)
    }

    /// Accepted magnitude component.
    pub const fn detector(&self) -> &DetectorConfig {
        &self.detector
    }
    /// Accepted signed-correlation component.
    pub const fn correlation(&self) -> &CorrConfig {
        &self.correlation
    }
    /// Canonically ordered complete expected-modality capability.
    pub fn expected_modalities(&self) -> &[Modality] {
        &self.expected_modalities
    }
    /// Producer-axis and family-sharing policy.
    pub const fn axis_policy(&self) -> ProducerAxisFamilyPolicy {
        self.axis_policy
    }
    /// Named source-release profile, if any.
    pub const fn source_profile(&self) -> Option<ReleaseProfile> {
        self.source_profile
    }
    /// Checked lifecycle sample-work bound.
    pub const fn lifecycle_sample_units(&self) -> usize {
        self.lifecycle_sample_units
    }
    /// Checked retained plus transient state-byte bound.
    pub const fn state_bytes(&self) -> usize {
        self.state_bytes
    }
    /// Canonical complete accepted-suite identity.
    pub const fn identity(&self) -> ConfigDigest {
        self.identity
    }
}

/// Closed exploratory profiles that can issue a subset-only detector capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploratoryResearchProfile {
    /// Explicit subset-only magnitude research; never release-interchangeable.
    SubsetMagnitudeV0_9,
}

impl ExploratoryResearchProfile {
    /// Issue the opaque capability required by [`crate::Mirror::for_exploratory_subset`].
    pub fn capability(self) -> ExploratorySubsetResearch {
        ExploratorySubsetResearch { profile: self }
    }
}

/// Opaque capability for subset-only exploratory assessment.
///
/// It cannot be fabricated with a literal and is not interchangeable with a
/// [`ReleaseSuite`]. Obtain it only from [`ExploratoryResearchProfile::capability`].
///
/// ```compile_fail
/// use galadriel_core::ExploratorySubsetResearch;
/// let _ = ExploratorySubsetResearch {};
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExploratorySubsetResearch {
    profile: ExploratoryResearchProfile,
}

impl ExploratorySubsetResearch {
    /// Research profile that issued this capability.
    pub const fn profile(self) -> ExploratoryResearchProfile {
        self.profile
    }

    pub(crate) fn identity(self, detector: &DetectorConfig) -> ConfigDigest {
        let mut identity = IdentityBuilder::new(b"galadriel-exploratory-subset-v1");
        identity.u8(
            b"profile",
            match self.profile {
                ExploratoryResearchProfile::SubsetMagnitudeV0_9 => 1,
            },
        );
        identity.digest(b"detector", detector.identity());
        identity.finish()
    }
}

/// Release/research classification retained in every magnitude report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "class", content = "profile", rename_all = "snake_case")]
pub enum AssessmentClassification {
    /// Report came from a named release suite.
    NamedRelease(ReleaseProfile),
    /// Report came from accepted custom release-suite components.
    CustomReleaseSuite,
    /// Report came from explicit subset-only research.
    ExploratoryResearch(ExploratoryResearchProfile),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom_params() -> DetectorParams {
        DetectorParams::standalone_advisory_v0_9()
    }

    #[test]
    fn named_detector_profile_is_valid_and_identified() {
        let config = DetectorConfig::standalone_advisory_v0_9().unwrap();

        assert_eq!(
            config.source_profile(),
            Some(DetectorProfile::StandaloneAdvisoryV0_9)
        );
        assert_eq!(config.classification(), ConfigurationClass::NamedRelease);
        assert_eq!(config.retained_channel_states(), 6_144);
        assert!(config.retained_state_bytes() > 6_144 * 272);
    }

    #[test]
    fn custom_and_named_equal_parameters_have_distinct_identities() {
        let named = DetectorConfig::standalone_advisory_v0_9().unwrap();
        let custom = DetectorConfig::try_new(custom_params()).unwrap();

        assert_ne!(named.identity(), custom.identity());
    }

    #[test]
    fn detector_identity_has_a_fixed_golden_digest() {
        let identity = DetectorConfig::standalone_advisory_v0_9()
            .unwrap()
            .identity()
            .to_hex();

        assert_eq!(
            identity,
            "ee347d3fa29406b214613af183d5052f9f63d8ca7439611a8d224eef48038944"
        );
    }

    #[test]
    fn every_detector_field_changes_the_identity() {
        let baseline = DetectorConfig::try_new(custom_params()).unwrap().identity();
        let changes: [fn(&mut DetectorParams); 11] = [
            |p| {
                p.window_len = 65;
            },
            |p| {
                p.min_samples = 31;
            },
            |p| {
                p.min_channels = 3;
            },
            |p| {
                p.max_seq_gap = 2;
            },
            |p| {
                p.max_timestamp_skew_ms = 999;
            },
            |p| {
                p.max_inter_sample_gap_ms = 9_999;
            },
            |p| {
                p.max_tracks = 1_023;
            },
            |p| {
                p.nis_alpha = 0.02;
            },
            |p| {
                p.cusum_slack = 0.4;
            },
            |p| {
                p.cusum_threshold = 5.0;
            },
            |p| {
                p.jam_fraction = 0.7;
            },
        ];
        for change in changes {
            let mut params = custom_params();
            change(&mut params);
            assert_ne!(
                DetectorConfig::try_new(params).unwrap().identity(),
                baseline
            );
        }
    }

    #[test]
    fn fixed_track_ceiling_closes_small_window_overhead_hole() {
        let mut params = custom_params();
        params.window_len = 1;
        params.min_samples = 1;
        params.max_tracks = 166_000;

        assert!(matches!(
            DetectorConfig::try_new(params),
            Err(DetectorConfigError::TrackCountOutOfRange { .. })
        ));
    }

    #[test]
    fn named_release_suite_is_order_canonical_and_pid_free() {
        let left = ReleaseSuite::standalone_advisory_v0_9(&[
            Modality::Radar,
            Modality::Visual,
            Modality::Acoustic,
        ])
        .unwrap();
        let right = ReleaseSuite::standalone_advisory_v0_9(&[
            Modality::Acoustic,
            Modality::Radar,
            Modality::Visual,
        ])
        .unwrap();

        assert_eq!(left.identity(), right.identity());
        assert_eq!(left.expected_modalities(), right.expected_modalities());
        assert_eq!(
            left.source_profile(),
            Some(ReleaseProfile::StandaloneAdvisoryV0_9)
        );
    }

    #[test]
    fn release_suite_identity_has_a_fixed_golden_digest() {
        let identity = ReleaseSuite::standalone_advisory_v0_9(&[
            Modality::Visual,
            Modality::Radar,
            Modality::Acoustic,
        ])
        .unwrap()
        .identity()
        .to_hex();

        assert_eq!(
            identity,
            "6e88f0907af330ddd0919738e241038e2bc912076bda873c90fdd63bab9c756a"
        );
    }

    #[test]
    fn custom_suite_with_equal_components_is_not_mislabelled_named() {
        let named = ReleaseSuite::standalone_advisory_v0_9(&[
            Modality::Visual,
            Modality::Radar,
            Modality::Acoustic,
        ])
        .unwrap();
        let custom = ReleaseSuite::try_new(ReleaseSuiteParams {
            detector: named.detector().clone(),
            correlation: named.correlation().clone(),
            expected_modalities: named.expected_modalities().to_vec(),
            axis_policy: named.axis_policy(),
        })
        .unwrap();

        assert_eq!(custom.source_profile(), None);
        assert_ne!(custom.identity(), named.identity());
    }

    #[test]
    fn release_suite_rejects_duplicate_or_incomplete_modalities() {
        assert!(matches!(
            ReleaseSuite::standalone_advisory_v0_9(&[Modality::Visual, Modality::Visual]),
            Err(ReleaseSuiteError::DuplicateModalities)
        ));
        assert!(matches!(
            ReleaseSuite::standalone_advisory_v0_9(&[Modality::Visual]),
            Err(ReleaseSuiteError::TooFewModalities { .. })
        ));
    }

    #[test]
    fn detector_rejects_field_and_aggregate_boundaries() {
        let mut params = custom_params();
        params.window_len = crate::window::MAX_WINDOW_LEN;
        params.min_samples = 1;
        params.max_tracks = 3;
        assert!(matches!(
            DetectorConfig::try_new(params),
            Err(DetectorConfigError::RetainedSampleLimitExceeded { .. })
        ));

        let mut invalid = custom_params();
        invalid.nis_alpha = f64::NAN;
        assert!(matches!(
            DetectorConfig::try_new(invalid),
            Err(DetectorConfigError::NisAlphaInvalid { .. })
        ));
    }
}
