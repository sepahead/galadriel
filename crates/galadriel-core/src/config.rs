//! Detector configuration.

/// Tunables for the baseline [`crate::Mirror`] detector.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    /// Per-`(track, modality)` sliding-window length, in frames.
    pub window_len: usize,
    /// Minimum samples a channel window must hold before its verdict is trusted;
    /// below this the channel is treated as not-ready (fail closed).
    pub min_samples: usize,
    /// Minimum number of ready channels before any non-`InsufficientEvidence`
    /// verdict is issued.
    pub min_channels: usize,
    /// Two-sided significance for the windowed NIS χ² test. A channel is flagged
    /// `elevated` when the right-tail p-value of its window sum drops below this.
    pub nis_alpha: f64,
    /// CUSUM slack `k` (in NIS units) — the per-sample deadband before drift accrues.
    pub cusum_slack: f64,
    /// CUSUM alarm threshold `h` (in NIS units).
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
            nis_alpha: 0.01,
            cusum_slack: 3.0,
            cusum_threshold: 15.0,
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
        if self.min_samples > self.window_len {
            return Err(InvalidConfig("min_samples must be <= window_len".into()));
        }
        if !(0.0..=1.0).contains(&self.nis_alpha) || self.nis_alpha == 0.0 {
            return Err(InvalidConfig("nis_alpha must be in (0, 1]".into()));
        }
        if !(0.0..=1.0).contains(&self.jam_fraction) {
            return Err(InvalidConfig("jam_fraction must be in [0, 1]".into()));
        }
        if self.cusum_slack < 0.0 || self.cusum_threshold <= 0.0 {
            return Err(InvalidConfig(
                "cusum_slack >= 0 and cusum_threshold > 0".into(),
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
            bad(|c| c.min_samples = c.window_len + 1),
            "min_samples > window_len"
        );
        assert!(bad(|c| c.nis_alpha = 0.0), "nis_alpha 0");
        assert!(bad(|c| c.nis_alpha = 1.5), "nis_alpha > 1");
        assert!(bad(|c| c.jam_fraction = 1.5), "jam_fraction > 1");
        assert!(bad(|c| c.cusum_slack = -1.0), "cusum_slack < 0");
        assert!(bad(|c| c.cusum_threshold = 0.0), "cusum_threshold 0");
    }

    #[test]
    fn accepts_the_inclusive_boundaries() {
        // nis_alpha = 1.0 and jam_fraction ∈ {0.0, 1.0} are valid (inclusive bounds).
        for jam_fraction in [0.0, 1.0] {
            let c = DetectorConfig {
                nis_alpha: 1.0,
                jam_fraction,
                ..Default::default()
            };
            assert!(c.validate().is_ok(), "jam_fraction {jam_fraction}");
        }
    }
}
