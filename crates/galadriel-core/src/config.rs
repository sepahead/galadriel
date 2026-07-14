//! Detector configuration.

/// Aggregate upper bound for retained NIS values across all tracks and modalities.
///
/// This bounds the worst-case state implied by a valid [`DetectorConfig`] rather
/// than validating each window and track limit in isolation.
pub const MAX_RETAINED_NIS_SAMPLES: usize = 1_000_000;

/// Largest supported fusion-sequence gap for one contiguous evidence window.
///
/// This matches the largest retained correlation window. Larger values would
/// effectively disable sequence continuity while adding no usable evidence.
pub const MAX_ALIGNMENT_SEQ_GAP: u64 = crate::correlation::MAX_CORRELATION_WINDOW as u64;

/// Largest supported timestamp span across one aligned cross-modal frame.
///
/// A zero value is valid and requests exact timestamp equality; it does not
/// disable the check. The day-scale ceiling prevents `u64::MAX`-style sentinels
/// from silently disabling temporal coherence.
pub const MAX_ALIGNMENT_TIMESTAMP_SKEW_MS: u64 = 86_400_000;

/// Largest supported interval between successive samples of one modality.
///
/// A finite ceiling prevents configurations from effectively disabling temporal
/// continuity. Slower feeds should explicitly segment runs and reset detector
/// state rather than carrying statistical evidence across day-scale holes.
pub const MAX_INTER_SAMPLE_GAP_MS: u64 = 86_400_000;

/// Tunables for the baseline [`crate::Mirror`] detector.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectorConfig {
    pub(crate) window_len: usize,
    pub(crate) min_samples: usize,
    pub(crate) min_channels: usize,
    pub(crate) max_seq_gap: u64,
    pub(crate) max_timestamp_skew_ms: u64,
    pub(crate) max_inter_sample_gap_ms: u64,
    pub(crate) max_tracks: usize,
    pub(crate) nis_alpha: f64,
    pub(crate) cusum_slack: f64,
    pub(crate) cusum_threshold: f64,
    pub(crate) jam_fraction: f64,
}

/// Unvalidated boundary values for constructing a [`DetectorConfig`].
///
/// This value is not accepted detector configuration. Call
/// [`DetectorConfig::try_new`] to validate the complete aggregate before use.
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
    /// Returns the explicitly named 0.9 standalone-advisory release values.
    ///
    /// These values are an input template, not deployment qualification. They
    /// still pass through [`DetectorConfig::try_new`] before use.
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
            // These preserve the previous dof=3 operating point (3 and 15 raw
            // NIS units) while giving the parameters consistent units for any dof.
            cusum_slack: 3.0 / 6.0_f64.sqrt(),
            cusum_threshold: 15.0 / 6.0_f64.sqrt(),
            jam_fraction: 0.6,
        }
    }
}

impl DetectorConfig {
    /// Validates a complete boundary input and constructs an immutable config.
    ///
    /// # Errors
    ///
    /// Returns [`crate::GaladrielError::InvalidConfig`] when any field or
    /// aggregate retained-state bound is invalid.
    pub fn try_new(input: DetectorParams) -> crate::Result<Self> {
        let config = Self {
            window_len: input.window_len,
            min_samples: input.min_samples,
            min_channels: input.min_channels,
            max_seq_gap: input.max_seq_gap,
            max_timestamp_skew_ms: input.max_timestamp_skew_ms,
            max_inter_sample_gap_ms: input.max_inter_sample_gap_ms,
            max_tracks: input.max_tracks,
            nis_alpha: input.nis_alpha,
            cusum_slack: input.cusum_slack,
            cusum_threshold: input.cusum_threshold,
            jam_fraction: input.jam_fraction,
        };
        config.validate()?;
        Ok(config)
    }

    /// Constructs the explicitly named 0.9 standalone-advisory release values.
    ///
    /// # Errors
    ///
    /// Returns an error if a future invariant change makes the retained template
    /// invalid rather than silently falling back to different values.
    pub fn standalone_advisory_v0_9() -> crate::Result<Self> {
        Self::try_new(DetectorParams::standalone_advisory_v0_9())
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

    /// Validate the configuration, returning an error describing the first problem.
    pub(crate) fn validate(&self) -> crate::Result<()> {
        use crate::GaladrielError::InvalidConfig;
        if self.window_len == 0 {
            return Err(InvalidConfig("window_len must be > 0".into()));
        }
        if self.window_len > crate::window::MAX_WINDOW_LEN {
            return Err(InvalidConfig(format!(
                "window_len must be <= {}",
                crate::window::MAX_WINDOW_LEN
            )));
        }
        if self.min_samples > self.window_len {
            return Err(InvalidConfig("min_samples must be <= window_len".into()));
        }
        if self.min_samples == 0 {
            return Err(InvalidConfig("min_samples must be > 0".into()));
        }
        if self.min_channels < 2 {
            return Err(InvalidConfig("min_channels must be >= 2".into()));
        }
        if self.min_channels > crate::Modality::ALL.len() {
            return Err(InvalidConfig(format!(
                "min_channels must be <= {}",
                crate::Modality::ALL.len()
            )));
        }
        validate_alignment_limits(
            self.max_seq_gap,
            self.max_timestamp_skew_ms,
            self.max_inter_sample_gap_ms,
        )?;
        if self.max_tracks == 0 {
            return Err(InvalidConfig("max_tracks must be > 0".into()));
        }
        let retained_samples = self
            .max_tracks
            .checked_mul(crate::Modality::ALL.len())
            .and_then(|channels| channels.checked_mul(self.window_len))
            .ok_or_else(|| {
                InvalidConfig("max_tracks × modalities × window_len overflows usize".into())
            })?;
        if retained_samples > MAX_RETAINED_NIS_SAMPLES {
            return Err(InvalidConfig(format!(
                "configuration can retain {retained_samples} NIS samples; maximum is {MAX_RETAINED_NIS_SAMPLES}"
            )));
        }
        if !self.nis_alpha.is_finite() || self.nis_alpha <= 0.0 || self.nis_alpha >= 1.0 {
            return Err(InvalidConfig(
                "nis_alpha must be finite and in (0, 1)".into(),
            ));
        }
        if self.nis_alpha / crate::Modality::ALL.len() as f64 == 0.0 {
            return Err(InvalidConfig(format!(
                "nis_alpha is too small to divide across {} supported modalities",
                crate::Modality::ALL.len()
            )));
        }
        if !self.jam_fraction.is_finite() || self.jam_fraction <= 0.0 || self.jam_fraction > 1.0 {
            return Err(InvalidConfig(
                "jam_fraction must be finite and in (0, 1]".into(),
            ));
        }
        if !self.cusum_slack.is_finite()
            || !self.cusum_threshold.is_finite()
            || self.cusum_slack < 0.0
            || self.cusum_threshold <= 0.0
        {
            return Err(InvalidConfig(
                "cusum_slack must be finite and >= 0; cusum_threshold must be finite and > 0"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Validate the raw temporal limits shared by streaming and direct extraction.
pub(crate) fn validate_alignment_limits(
    max_seq_gap: u64,
    max_timestamp_skew_ms: u64,
    max_inter_sample_gap_ms: u64,
) -> crate::Result<()> {
    use crate::GaladrielError::InvalidConfig;

    if !(1..=MAX_ALIGNMENT_SEQ_GAP).contains(&max_seq_gap) {
        return Err(InvalidConfig(format!(
            "max_seq_gap must be in 1..={MAX_ALIGNMENT_SEQ_GAP}"
        )));
    }
    if max_timestamp_skew_ms > MAX_ALIGNMENT_TIMESTAMP_SKEW_MS {
        return Err(InvalidConfig(format!(
            "max_timestamp_skew_ms must be in 0..={MAX_ALIGNMENT_TIMESTAMP_SKEW_MS}; zero means exact synchrony"
        )));
    }
    if !(1..=MAX_INTER_SAMPLE_GAP_MS).contains(&max_inter_sample_gap_ms) {
        return Err(InvalidConfig(format!(
            "max_inter_sample_gap_ms must be in 1..={MAX_INTER_SAMPLE_GAP_MS}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GaladrielError;

    fn is_invalid(r: crate::Result<DetectorConfig>) -> bool {
        matches!(r, Err(GaladrielError::InvalidConfig(_)))
    }

    #[test]
    fn named_standalone_advisory_profile_validates_at_construction() {
        assert!(DetectorConfig::standalone_advisory_v0_9().is_ok());
    }

    #[test]
    fn rejects_out_of_range_fields() {
        let bad = |f: fn(&mut DetectorParams)| {
            let mut input = DetectorParams::standalone_advisory_v0_9();
            f(&mut input);
            is_invalid(DetectorConfig::try_new(input))
        };
        assert!(bad(|c| c.window_len = 0), "window_len 0");
        assert!(
            bad(|c| c.window_len = crate::window::MAX_WINDOW_LEN + 1),
            "window_len above allocation bound"
        );
        assert!(bad(|c| c.min_samples = 0), "min_samples 0");
        assert!(
            bad(|c| c.min_samples = c.window_len + 1),
            "min_samples > window_len"
        );
        assert!(bad(|c| c.nis_alpha = 0.0), "nis_alpha 0");
        assert!(bad(|c| c.nis_alpha = 1.0), "nis_alpha 1");
        assert!(bad(|c| c.nis_alpha = f64::NAN), "nis_alpha NaN");
        assert!(bad(|c| c.nis_alpha = 1.5), "nis_alpha > 1");
        assert!(
            bad(|c| c.nis_alpha = f64::from_bits(1)),
            "nis_alpha must survive the maximum channel correction"
        );
        assert!(bad(|c| c.jam_fraction = 0.0), "jam_fraction 0");
        assert!(bad(|c| c.jam_fraction = f64::NAN), "jam_fraction NaN");
        assert!(bad(|c| c.jam_fraction = 1.5), "jam_fraction > 1");
        assert!(bad(|c| c.min_channels = 1), "min_channels < 2");
        assert!(bad(|c| c.max_seq_gap = 0), "max_seq_gap 0");
        assert!(
            bad(|c| c.max_seq_gap = MAX_ALIGNMENT_SEQ_GAP + 1),
            "max_seq_gap above policy bound"
        );
        assert!(
            bad(|c| c.max_timestamp_skew_ms = MAX_ALIGNMENT_TIMESTAMP_SKEW_MS + 1),
            "max_timestamp_skew_ms above policy bound"
        );
        assert!(
            bad(|c| c.max_inter_sample_gap_ms = 0),
            "max_inter_sample_gap_ms 0"
        );
        assert!(
            bad(|c| c.max_inter_sample_gap_ms = MAX_INTER_SAMPLE_GAP_MS + 1),
            "max_inter_sample_gap_ms above policy bound"
        );
        assert!(bad(|c| c.max_tracks = 0), "max_tracks 0");
        assert!(
            bad(|c| {
                c.window_len = crate::window::MAX_WINDOW_LEN;
                c.min_samples = 1;
                c.max_tracks = 3;
            }),
            "aggregate retained state above the memory budget"
        );
        assert!(bad(|c| c.max_tracks = usize::MAX), "state-size overflow");
        assert!(bad(|c| c.cusum_slack = -1.0), "cusum_slack < 0");
        assert!(
            bad(|c| c.cusum_slack = f64::INFINITY),
            "cusum_slack infinite"
        );
        assert!(bad(|c| c.cusum_threshold = 0.0), "cusum_threshold 0");
        assert!(bad(|c| c.cusum_threshold = f64::NAN), "cusum_threshold NaN");
    }

    #[test]
    fn accepts_the_inclusive_boundaries() {
        // jam_fraction = 1.0 is valid; nis_alpha remains strictly below one.
        for jam_fraction in [f64::MIN_POSITIVE, 1.0] {
            let input = DetectorParams {
                nis_alpha: 1.0 - f64::EPSILON,
                jam_fraction,
                ..DetectorParams::standalone_advisory_v0_9()
            };
            assert!(
                DetectorConfig::try_new(input).is_ok(),
                "jam_fraction {jam_fraction}"
            );
        }

        for max_timestamp_skew_ms in [0, MAX_ALIGNMENT_TIMESTAMP_SKEW_MS] {
            let input = DetectorParams {
                max_seq_gap: MAX_ALIGNMENT_SEQ_GAP,
                max_timestamp_skew_ms,
                max_inter_sample_gap_ms: MAX_INTER_SAMPLE_GAP_MS,
                ..DetectorParams::standalone_advisory_v0_9()
            };
            assert!(
                DetectorConfig::try_new(input).is_ok(),
                "timestamp skew boundary {max_timestamp_skew_ms}"
            );
        }
    }

    #[test]
    fn getters_preserve_every_validated_input_field() {
        let input = DetectorParams {
            window_len: 12,
            min_samples: 7,
            min_channels: 3,
            max_seq_gap: 4,
            max_timestamp_skew_ms: 5,
            max_inter_sample_gap_ms: 6,
            max_tracks: 8,
            nis_alpha: 0.02,
            cusum_slack: 0.5,
            cusum_threshold: 2.5,
            jam_fraction: 0.75,
        };
        let config = DetectorConfig::try_new(input).unwrap();

        assert_eq!(config.window_len(), 12);
        assert_eq!(config.min_samples(), 7);
        assert_eq!(config.min_channels(), 3);
        assert_eq!(config.max_seq_gap(), 4);
        assert_eq!(config.max_timestamp_skew_ms(), 5);
        assert_eq!(config.max_inter_sample_gap_ms(), 6);
        assert_eq!(config.max_tracks(), 8);
        assert_eq!(config.nis_alpha(), 0.02);
        assert_eq!(config.cusum_slack(), 0.5);
        assert_eq!(config.cusum_threshold(), 2.5);
        assert_eq!(config.jam_fraction(), 0.75);
    }
}
