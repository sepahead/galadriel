//! Detector configuration.

/// Aggregate upper bound for retained NIS values across all tracks and modalities.
///
/// This bounds the worst-case state implied by a valid [`DetectorConfig`] rather
/// than validating each window and track limit in isolation.
pub const MAX_RETAINED_NIS_SAMPLES: usize = 1_000_000;

/// Largest supported interval between successive samples of one modality.
///
/// A finite ceiling prevents configurations from effectively disabling temporal
/// continuity. Slower feeds should explicitly segment runs and reset detector
/// state rather than carrying statistical evidence across day-scale holes.
pub const MAX_INTER_SAMPLE_GAP_MS: u64 = 86_400_000;

/// Tunables for the baseline [`crate::Mirror`] detector.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectorConfig {
    /// Per-`(track, modality)` sliding-window length, in observations.
    pub window_len: usize,
    /// Minimum samples a channel window must hold before its verdict is trusted;
    /// below this the channel is treated as not-ready (fail closed).
    pub min_samples: usize,
    /// Minimum number of ready channels before any non-`InsufficientEvidence`
    /// verdict is issued.
    pub min_channels: usize,
    /// Maximum allowed fusion-sequence gap between successive channel samples and
    /// between assessment and a channel's newest observation. A larger ingest gap
    /// starts a new evidence window; a larger assessment gap makes the channel
    /// stale. `1` tolerates normal within-frame arrival ordering while catching a
    /// feed that stops producing after an association-gate miss.
    pub max_seq_gap: u64,
    /// Maximum timestamp span across otherwise-ready modalities at assessment.
    /// A larger span means the records do not describe one comparable fusion
    /// instant and therefore cannot support a nominal or attributed verdict.
    pub max_timestamp_skew_ms: u64,
    /// Maximum forward timestamp gap between successive observations of one
    /// `(track, modality)`. A larger gap starts a new evidence window.
    pub max_inter_sample_gap_ms: u64,
    /// Maximum number of track ids retained at once. New tracks are rejected once
    /// this limit is reached until a caller removes stale state with
    /// [`crate::Mirror::remove_track`] or [`crate::Mirror::clear`].
    pub max_tracks: usize,
    /// Per-assessment family-wise significance for the right-tailed windowed NIS
    /// χ² tests. [`crate::Mirror`] Bonferroni-divides this across assessed channels.
    pub nis_alpha: f64,
    /// CUSUM slack `k` in null-standard-deviation units after scaling NIS by
    /// `sqrt(2*dof)`. This keeps one configuration comparable across dimensions.
    pub cusum_slack: f64,
    /// CUSUM alarm threshold `h` in accumulated null-standard-deviation units.
    pub cusum_threshold: f64,
    /// Fraction of ready channels that must be anomalous to call [`crate::Verdict::Jam`]
    /// (correlated, broad degradation) rather than [`crate::Verdict::Spoof`]
    /// (isolated, single-channel injection).
    pub jam_fraction: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
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
    /// Validate the configuration, returning an error describing the first problem.
    pub fn validate(&self) -> crate::Result<()> {
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
        if self.max_seq_gap == 0 {
            return Err(InvalidConfig(
                "max_seq_gap must be > 0 so consecutive samples can accumulate".into(),
            ));
        }
        if self.max_inter_sample_gap_ms == 0
            || self.max_inter_sample_gap_ms > MAX_INTER_SAMPLE_GAP_MS
        {
            return Err(InvalidConfig(format!(
                "max_inter_sample_gap_ms must be in 1..={MAX_INTER_SAMPLE_GAP_MS}"
            )));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GaladrielError;

    fn is_invalid(r: crate::Result<()>) -> bool {
        matches!(r, Err(GaladrielError::InvalidConfig(_)))
    }

    #[test]
    fn default_config_validates() {
        assert!(DetectorConfig::default().validate().is_ok());
    }

    #[test]
    fn rejects_out_of_range_fields() {
        let bad = |f: fn(&mut DetectorConfig)| {
            let mut c = DetectorConfig::default();
            f(&mut c);
            is_invalid(c.validate())
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
        assert!(bad(|c| c.jam_fraction = 0.0), "jam_fraction 0");
        assert!(bad(|c| c.jam_fraction = f64::NAN), "jam_fraction NaN");
        assert!(bad(|c| c.jam_fraction = 1.5), "jam_fraction > 1");
        assert!(bad(|c| c.min_channels = 1), "min_channels < 2");
        assert!(bad(|c| c.max_seq_gap = 0), "max_seq_gap 0");
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
            let c = DetectorConfig {
                nis_alpha: 1.0 - f64::EPSILON,
                jam_fraction,
                ..Default::default()
            };
            assert!(c.validate().is_ok(), "jam_fraction {jam_fraction}");
        }
    }
}
