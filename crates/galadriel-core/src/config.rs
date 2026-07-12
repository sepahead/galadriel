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
    /// Zero requests exact timestamp equality; it never disables the check.
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
    ///
    /// The slack applies symmetrically to both arms. At the default `k = 3/sqrt(6)`
    /// and the fusion core's `dof = 3`, the scaled target `dof/sqrt(2*dof)` equals the
    /// slack, so the below-target (lower) arm can never accumulate: a *below*-target
    /// NIS shift — an over-conservative filter, or a replay/frozen sensor whose
    /// innovations match the prediction too closely — is intentionally not flagged at
    /// `dof <= 3`. The lower arm becomes active for `dof > 3`, or for a configured `k`
    /// strictly below the scaled target. Treating a below-target shift as an attack is
    /// a design choice deferred to a study, not an oversight.
    pub cusum_slack: f64,
    /// CUSUM alarm threshold `h` in accumulated null-standard-deviation units.
    pub cusum_threshold: f64,
    /// Fraction of ready channels that must be anomalous to call [`crate::Verdict::BroadDegradation`]
    /// (broad degradation evidence) rather than
    /// [`crate::Verdict::AttributedInconsistency`] (localized magnitude evidence).
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
            let c = DetectorConfig {
                nis_alpha: 1.0 - f64::EPSILON,
                jam_fraction,
                ..Default::default()
            };
            assert!(c.validate().is_ok(), "jam_fraction {jam_fraction}");
        }

        for max_timestamp_skew_ms in [0, MAX_ALIGNMENT_TIMESTAMP_SKEW_MS] {
            let c = DetectorConfig {
                max_seq_gap: MAX_ALIGNMENT_SEQ_GAP,
                max_timestamp_skew_ms,
                max_inter_sample_gap_ms: MAX_INTER_SAMPLE_GAP_MS,
                ..Default::default()
            };
            assert!(
                c.validate().is_ok(),
                "timestamp skew boundary {max_timestamp_skew_ms}"
            );
        }
    }
}
