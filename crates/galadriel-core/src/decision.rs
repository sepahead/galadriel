//! The fail-closed jam-vs-spoof decision and the streaming [`Mirror`] detector.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::baseline;
use crate::config::DetectorConfig;
use crate::cusum::Cusum;
use crate::observation::{Modality, PidObservation};
use crate::window::NisWindow;

/// The detector's advisory verdict for one track.
///
/// This is **advisory** (`calibrated_posterior = false` in the ecosystem's terms):
/// a redundancy/consistency anomaly is equally consistent with a spoof, a genuine
/// unique detection, or an estimator artifact. It softens; it never vetoes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Every ready channel's NIS is consistent with χ²(dof).
    Nominal,
    /// One or a minority of channels' NIS is inflated while the rest corroborate —
    /// the signature of a targeted single-channel false-data injection.
    Spoof { channels: Vec<Modality> },
    /// Most/all channels' NIS is inflated together — correlated denial/degradation.
    Jam,
    /// Too few ready channels or samples to decide. **Fail closed** — never
    /// silently upgraded to `Nominal`.
    InsufficientEvidence,
}

/// Per-channel detail behind a [`MirrorReport`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelReport {
    /// Which modality this channel is.
    pub modality: Modality,
    /// Samples in the channel window.
    pub n: usize,
    /// Mean NIS over the window (≈ `dof` when healthy).
    pub mean_nis: f64,
    /// Right-tail p-value of the windowed NIS sum.
    pub p_right: f64,
    /// Whether the windowed NIS test flagged this channel elevated.
    pub elevated: bool,
    /// Whether this channel's CUSUM is in alarm.
    pub cusum_alarm: bool,
    /// Whether the window has reached `min_samples`.
    pub ready: bool,
}

impl ChannelReport {
    /// Whether this channel is currently flagged anomalous (elevated or CUSUM alarm).
    pub fn anomalous(&self) -> bool {
        self.ready && (self.elevated || self.cusum_alarm)
    }
}

/// The full advisory report for one track at one point in the stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirrorReport {
    /// Track this report concerns.
    pub track_id: u64,
    /// Fusion frame counter at assessment time.
    pub seq: u64,
    /// The advisory verdict.
    pub verdict: Verdict,
    /// Per-channel detail, in stable modality order.
    pub channels: Vec<ChannelReport>,
    /// A short human-readable rationale.
    pub note: String,
}

/// Streaming cross-sensor consistency detector.
///
/// Feed it [`PidObservation`]s with [`Mirror::ingest`]; ask for a verdict with
/// [`Mirror::assess`], or do both with [`Mirror::ingest_and_assess`].
pub struct Mirror {
    cfg: DetectorConfig,
    windows: HashMap<(u64, Modality), NisWindow>,
    cusums: HashMap<(u64, Modality), Cusum>,
}

impl Mirror {
    /// New detector with the given configuration.
    pub fn new(cfg: DetectorConfig) -> Self {
        Self {
            cfg,
            windows: HashMap::new(),
            cusums: HashMap::new(),
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &DetectorConfig {
        &self.cfg
    }

    /// Update per-channel state with one observation.
    pub fn ingest(&mut self, obs: &PidObservation) {
        let key = (obs.track_id, obs.modality);
        let cfg = &self.cfg;
        self.windows
            .entry(key)
            .or_insert_with(|| NisWindow::new(cfg.window_len, obs.dof))
            .push(obs.nis);
        self.cusums
            .entry(key)
            .or_insert_with(|| Cusum::new(obs.dof as f64, cfg.cusum_slack, cfg.cusum_threshold))
            .update(obs.nis);
    }

    /// Compute the current advisory report for `track_id`.
    pub fn assess(&self, track_id: u64, seq: u64) -> MirrorReport {
        let mut channels: Vec<ChannelReport> = Vec::new();
        for (&(tid, modality), window) in &self.windows {
            if tid != track_id {
                continue;
            }
            let stat = baseline::nis_consistency(window, self.cfg.nis_alpha);
            let cusum_alarm = self.cusums.get(&(tid, modality)).is_some_and(|c| c.alarm());
            channels.push(ChannelReport {
                modality,
                n: stat.n,
                mean_nis: stat.mean_nis,
                p_right: stat.p_right,
                elevated: stat.elevated,
                cusum_alarm,
                ready: stat.n >= self.cfg.min_samples,
            });
        }
        // Deterministic channel order regardless of HashMap iteration order.
        channels.sort_by_key(|c| c.modality as u8);

        let ready: Vec<&ChannelReport> = channels.iter().filter(|c| c.ready).collect();
        let anomalous: Vec<Modality> = ready
            .iter()
            .filter(|c| c.anomalous())
            .map(|c| c.modality)
            .collect();

        let (verdict, note) = if ready.len() < self.cfg.min_channels {
            (
                Verdict::InsufficientEvidence,
                format!(
                    "only {}/{} channels ready (need {}); failing closed",
                    ready.len(),
                    channels.len(),
                    self.cfg.min_channels
                ),
            )
        } else if anomalous.is_empty() {
            (
                Verdict::Nominal,
                format!(
                    "{} channels corroborate; NIS consistent with χ²",
                    ready.len()
                ),
            )
        } else if anomalous.len() >= 2
            && anomalous.len() as f64 >= self.cfg.jam_fraction * ready.len() as f64
        {
            (
                Verdict::Jam,
                format!(
                    "{}/{} channels inflated together — correlated denial",
                    anomalous.len(),
                    ready.len()
                ),
            )
        } else {
            let names: Vec<&str> = anomalous.iter().map(|m| m.label()).collect();
            (
                Verdict::Spoof {
                    channels: anomalous.clone(),
                },
                format!(
                    "{} of {} channels decoupled ({}) — targeted injection",
                    anomalous.len(),
                    ready.len(),
                    names.join(", ")
                ),
            )
        };

        MirrorReport {
            track_id,
            seq,
            verdict,
            channels,
            note,
        }
    }

    /// Ingest one observation and return the resulting report for its track.
    pub fn ingest_and_assess(&mut self, obs: &PidObservation) -> MirrorReport {
        self.ingest(obs);
        self.assess(obs.track_id, obs.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(mirror: &mut Mirror, track: u64, mods: &[Modality], nis: &[f64], frames: usize) {
        // `nis[i]` is the constant NIS for channel `mods[i]`.
        for f in 0..frames {
            for (i, &m) in mods.iter().enumerate() {
                mirror.ingest(&PidObservation::scalar(
                    track, f as u64, f as u64, m, nis[i], 3,
                ));
            }
        }
    }

    #[test]
    fn all_consistent_is_nominal() {
        let mut m = Mirror::new(DetectorConfig::default());
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[3.0, 3.0, 3.0], 64);
        assert_eq!(m.assess(1, 64).verdict, Verdict::Nominal);
    }

    #[test]
    fn single_channel_inflation_is_spoof() {
        let mut m = Mirror::new(DetectorConfig::default());
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[3.0, 3.0, 20.0], 64);
        match m.assess(1, 64).verdict {
            Verdict::Spoof { channels } => assert_eq!(channels, vec![Modality::Acoustic]),
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    fn all_channels_inflation_is_jam() {
        let mut m = Mirror::new(DetectorConfig::default());
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[20.0, 20.0, 20.0], 64);
        assert_eq!(m.assess(1, 64).verdict, Verdict::Jam);
    }

    #[test]
    fn too_few_samples_fails_closed() {
        let mut m = Mirror::new(DetectorConfig::default());
        let mods = [Modality::Visual, Modality::Radar];
        // Below min_samples (32).
        feed(&mut m, 1, &mods, &[3.0, 3.0], 10);
        assert_eq!(m.assess(1, 10).verdict, Verdict::InsufficientEvidence);
    }
}
