//! The fail-closed magnitude-evidence decision and the streaming [`Mirror`] detector.

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
/// a magnitude anomaly is equally consistent with an attack, a genuine unique
/// detection, or an estimator artifact. Galadriel applies no policy itself; a
/// downstream consumer remains subject to the record/restrict-only authority contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Every ready channel's NIS is consistent with χ²(dof).
    Nominal,
    /// One or a minority of channels has localized NIS inconsistency. This names
    /// statistical evidence, not an attack cause.
    #[serde(alias = "spoof")]
    AttributedInconsistency { channels: Vec<Modality> },
    /// Most/all channels have broad NIS inflation consistent with degradation.
    #[serde(alias = "jam")]
    BroadDegradation,
    /// Positive anomaly evidence exists, but missing/stale peers or a below-target
    /// shift prevents a narrower statistical classification.
    #[serde(alias = "anomaly")]
    UnclassifiedAnomaly { channels: Vec<Modality> },
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
    /// Newest fusion sequence accepted for this channel, or `None` if an expected
    /// channel has not produced an observation.
    pub last_seq: Option<u64>,
    /// Timestamp of the newest accepted measurement, or `None` for a missing
    /// expected channel.
    pub last_timestamp_ms: Option<u64>,
    /// Mean NIS over the window (≈ `dof` when healthy).
    pub mean_nis: f64,
    /// Right-tail p-value of the windowed NIS sum.
    pub p_right: f64,
    /// Whether the windowed NIS test flagged this channel elevated.
    pub elevated: bool,
    /// Whether this channel's above-target CUSUM arm is in alarm.
    pub cusum_high_alarm: bool,
    /// Whether this channel's below-target CUSUM arm is in alarm.
    pub cusum_low_alarm: bool,
    /// Whether the newest observation is within the configured sequence gap.
    pub fresh: bool,
    /// Whether the window has reached `min_samples` and is fresh.
    pub ready: bool,
}

impl ChannelReport {
    /// Whether this channel is currently flagged anomalous (elevated or CUSUM alarm).
    pub fn anomalous(&self) -> bool {
        self.ready && (self.high_anomalous() || self.cusum_low_alarm)
    }

    /// Whether this channel has evidence of NIS inflation.
    pub fn high_anomalous(&self) -> bool {
        self.ready && (self.elevated || self.cusum_high_alarm)
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
    tracks: HashMap<u64, HashMap<Modality, ChannelState>>,
    expected_modalities: Vec<Modality>,
}

#[derive(Debug, Clone)]
struct ChannelState {
    window: NisWindow,
    cusum: Cusum,
    last_seq: u64,
    last_timestamp_ms: u64,
}

impl ChannelState {
    fn cusum_coordinates(dof: u8, nis: f64) -> (f64, f64) {
        let scale = (2.0 * f64::from(dof)).sqrt();
        (f64::from(dof) / scale, nis / scale)
    }

    fn from_observation(cfg: &DetectorConfig, obs: &PidObservation) -> crate::Result<Self> {
        let mut window = NisWindow::new(cfg.window_len, obs.dof)?;
        window.push(obs.nis)?;
        let (target, value) = Self::cusum_coordinates(obs.dof, obs.nis);
        let mut cusum = Cusum::new(target, cfg.cusum_slack, cfg.cusum_threshold)?;
        cusum.update(value)?;
        Ok(Self {
            window,
            cusum,
            last_seq: obs.seq,
            last_timestamp_ms: obs.timestamp_ms,
        })
    }
}

impl Mirror {
    /// New detector with the given configuration.
    ///
    /// This constructor enforces **no expected-modality set**: [`Mirror::assess`]
    /// classifies only the channels a track has actually produced, so a subset of
    /// sensors that are individually χ²-consistent can reach [`Verdict::Nominal`].
    /// That is the intended contract for exploratory or single-stream use, but it is
    /// **not** the fail-closed cross-sensor guarantee. For a detector that returns
    /// [`Verdict::InsufficientEvidence`] until every declared modality is present,
    /// fresh, and sufficiently sampled, construct it with [`Mirror::with_modalities`]
    /// — that is what the fused `assess_default` entry point and the CLI use.
    pub fn new(cfg: DetectorConfig) -> crate::Result<Self> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            tracks: HashMap::new(),
            expected_modalities: Vec::new(),
        })
    }

    /// New detector that fails closed until every declared modality is present,
    /// sufficiently sampled, and fresh.
    pub fn with_modalities(cfg: DetectorConfig, modalities: &[Modality]) -> crate::Result<Self> {
        let mut expected_modalities = modalities.to_vec();
        expected_modalities.sort_by_key(|modality| *modality as u8);
        expected_modalities.dedup();
        if expected_modalities.len() != modalities.len() {
            return Err(crate::GaladrielError::InvalidConfig(
                "expected modalities must be unique".into(),
            ));
        }
        if expected_modalities.len() < cfg.min_channels {
            return Err(crate::GaladrielError::InvalidConfig(format!(
                "expected modality count ({}) must be >= min_channels ({})",
                expected_modalities.len(),
                cfg.min_channels
            )));
        }
        let mut mirror = Self::new(cfg)?;
        mirror.expected_modalities = expected_modalities;
        Ok(mirror)
    }

    /// The active configuration.
    pub fn config(&self) -> &DetectorConfig {
        &self.cfg
    }

    /// Update per-channel state with one observation.
    pub fn ingest(&mut self, obs: &PidObservation) -> crate::Result<()> {
        obs.validate()?;
        if !self.expected_modalities.is_empty() && !self.expected_modalities.contains(&obs.modality)
        {
            return Err(crate::GaladrielError::InvalidObservation(format!(
                "unexpected modality {} for this detector",
                obs.modality.label()
            )));
        }

        if let Some(channel) = self
            .tracks
            .get_mut(&obs.track_id)
            .and_then(|channels| channels.get_mut(&obs.modality))
        {
            if obs.seq <= channel.last_seq {
                return Err(crate::GaladrielError::InvalidObservation(format!(
                    "sequence must increase strictly for track {} / {} (last {}, got {})",
                    obs.track_id,
                    obs.modality.label(),
                    channel.last_seq,
                    obs.seq
                )));
            }
            if obs.dof != channel.window.dof() {
                return Err(crate::GaladrielError::InvalidObservation(format!(
                    "dof changed for track {} / {} (expected {}, got {}); reset the track first",
                    obs.track_id,
                    obs.modality.label(),
                    channel.window.dof(),
                    obs.dof
                )));
            }
            if obs.timestamp_ms <= channel.last_timestamp_ms {
                return Err(crate::GaladrielError::InvalidObservation(format!(
                    "timestamp must increase strictly for track {} / {} (last {}, got {})",
                    obs.track_id,
                    obs.modality.label(),
                    channel.last_timestamp_ms,
                    obs.timestamp_ms
                )));
            }
            let sequence_gap = obs.seq - channel.last_seq;
            let timestamp_gap = obs.timestamp_ms - channel.last_timestamp_ms;
            if sequence_gap > self.cfg.max_seq_gap
                || timestamp_gap > self.cfg.max_inter_sample_gap_ms
            {
                // A large sequence or wall-clock hole means the retained samples
                // are no longer a contiguous monitoring window. Reset this channel
                // so sparse records cannot accumulate into a false Nominal result.
                *channel = ChannelState::from_observation(&self.cfg, obs)?;
                return Ok(());
            }

            // Validate the only stateful arithmetic on a tiny clone first. A
            // validated window push is then infallible without cloning its buffer.
            let mut next_cusum = channel.cusum.clone();
            let (_, value) = ChannelState::cusum_coordinates(obs.dof, obs.nis);
            next_cusum.update(value)?;
            channel.window.push(obs.nis)?;
            channel.cusum = next_cusum;
            channel.last_seq = obs.seq;
            channel.last_timestamp_ms = obs.timestamp_ms;
            return Ok(());
        }

        if !self.tracks.contains_key(&obs.track_id) && self.tracks.len() >= self.cfg.max_tracks {
            return Err(crate::GaladrielError::TrackLimit {
                limit: self.cfg.max_tracks,
            });
        }

        let state = ChannelState::from_observation(&self.cfg, obs)?;
        self.tracks
            .entry(obs.track_id)
            .or_default()
            .insert(obs.modality, state);
        Ok(())
    }

    /// Compute the current advisory report for `track_id`.
    pub fn assess(&self, track_id: u64, seq: u64) -> crate::Result<MirrorReport> {
        let mut channels: Vec<ChannelReport> = Vec::new();
        let known = self.tracks.get(&track_id);
        let total_channels = known
            .into_iter()
            .flat_map(|states| states.keys().copied())
            .chain(self.expected_modalities.iter().copied())
            .collect::<std::collections::HashSet<_>>()
            .len()
            .max(1);
        // `nis_alpha` is a per-assessment family-wise bound. Bonferroni keeps the
        // probability of any channel's window test false-alarming at or below it.
        let channel_alpha = self.cfg.nis_alpha / total_channels as f64;
        for (&modality, state) in self.tracks.get(&track_id).into_iter().flatten() {
            let fresh = seq
                .checked_sub(state.last_seq)
                .is_some_and(|gap| gap <= self.cfg.max_seq_gap);
            let stat = baseline::nis_consistency(&state.window, channel_alpha)?;
            channels.push(ChannelReport {
                modality,
                n: stat.n,
                last_seq: Some(state.last_seq),
                last_timestamp_ms: Some(state.last_timestamp_ms),
                mean_nis: stat.mean_nis,
                p_right: stat.p_right,
                elevated: stat.elevated,
                cusum_high_alarm: state.cusum.high_alarm(),
                cusum_low_alarm: state.cusum.low_alarm(),
                fresh,
                ready: stat.n >= self.cfg.min_samples && fresh,
            });
        }
        for &modality in &self.expected_modalities {
            if channels.iter().any(|channel| channel.modality == modality) {
                continue;
            }
            channels.push(ChannelReport {
                modality,
                n: 0,
                last_seq: None,
                last_timestamp_ms: None,
                mean_nis: 0.0,
                p_right: 1.0,
                elevated: false,
                cusum_high_alarm: false,
                cusum_low_alarm: false,
                fresh: false,
                ready: false,
            });
        }
        // Deterministic channel order regardless of HashMap iteration order.
        channels.sort_by_key(|c| c.modality as u8);

        let ready: Vec<&ChannelReport> = channels.iter().filter(|c| c.ready).collect();
        let high_anomalous: Vec<Modality> = ready
            .iter()
            .filter(|c| c.high_anomalous())
            .map(|c| c.modality)
            .collect();
        let all_anomalous: Vec<Modality> = ready
            .iter()
            .filter(|c| c.anomalous())
            .map(|c| c.modality)
            .collect();
        let has_low_alarm = ready.iter().any(|channel| channel.cusum_low_alarm);

        let timestamp_span = ready
            .iter()
            .filter_map(|channel| channel.last_timestamp_ms)
            .fold(None::<(u64, u64)>, |range, timestamp| {
                Some(match range {
                    Some((minimum, maximum)) => (minimum.min(timestamp), maximum.max(timestamp)),
                    None => (timestamp, timestamp),
                })
            })
            .map_or(0, |(minimum, maximum)| maximum - minimum);
        let timestamps_coherent = timestamp_span <= self.cfg.max_timestamp_skew_ms;

        let all_channels_ready = !channels.is_empty() && ready.len() == channels.len();
        let enough_complete_evidence =
            ready.len() >= self.cfg.min_channels && all_channels_ready && timestamps_coherent;
        let (verdict, note) = if !all_anomalous.is_empty()
            && (!enough_complete_evidence || has_low_alarm)
        {
            let names = all_anomalous
                .iter()
                .map(|modality| modality.label())
                .collect::<Vec<_>>()
                .join(", ");
            (
                Verdict::UnclassifiedAnomaly {
                    channels: all_anomalous.clone(),
                },
                format!(
                    "verified anomaly on {names}, but stale/missing peers or a below-target shift prevents a narrower statistical classification"
                ),
            )
        } else if !enough_complete_evidence {
            (
                Verdict::InsufficientEvidence,
                format!(
                    "only {}/{} channels sampled/fresh/temporally coherent (need at least {}, every known/expected channel ready, and timestamp span <= {} ms; observed span {} ms); failing closed",
                    ready.len(),
                    channels.len(),
                    self.cfg.min_channels,
                    self.cfg.max_timestamp_skew_ms,
                    timestamp_span
                ),
            )
        } else if high_anomalous.is_empty() {
            (
                Verdict::Nominal,
                format!(
                    "{} ready channels have individually χ²-consistent NIS",
                    ready.len()
                ),
            )
        } else if high_anomalous.len() >= 2
            && high_anomalous.len() as f64 >= self.cfg.jam_fraction * ready.len() as f64
        {
            (
                Verdict::BroadDegradation,
                format!(
                    "{}/{} channels currently inflated — broad-degradation evidence (jam-like, cause unclassified)",
                    high_anomalous.len(),
                    ready.len()
                ),
            )
        } else {
            let names: Vec<&str> = high_anomalous.iter().map(|m| m.label()).collect();
            (
                Verdict::AttributedInconsistency {
                    channels: high_anomalous.clone(),
                },
                format!(
                    "{} of {} channels show localized NIS inflation ({}) — spoof-like evidence, cause unclassified",
                    high_anomalous.len(),
                    ready.len(),
                    names.join(", ")
                ),
            )
        };

        Ok(MirrorReport {
            track_id,
            seq,
            verdict,
            channels,
            note,
        })
    }

    /// Ingest one observation and return the resulting report for its track.
    pub fn ingest_and_assess(&mut self, obs: &PidObservation) -> crate::Result<MirrorReport> {
        self.ingest(obs)?;
        self.assess(obs.track_id, obs.seq)
    }

    /// Remove all retained state for one track. Returns whether the track existed.
    pub fn remove_track(&mut self, track_id: u64) -> bool {
        self.tracks.remove(&track_id).is_some()
    }

    /// Remove all retained detector state.
    pub fn clear(&mut self) {
        self.tracks.clear();
    }

    /// Number of track ids currently retained.
    pub fn track_count(&self) -> usize {
        self.tracks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(mirror: &mut Mirror, track: u64, mods: &[Modality], nis: &[f64], frames: usize) {
        // `nis[i]` is the constant NIS for channel `mods[i]`.
        for f in 0..frames {
            for (i, &m) in mods.iter().enumerate() {
                mirror
                    .ingest(&PidObservation::scalar(
                        track, f as u64, f as u64, m, nis[i], 3,
                    ))
                    .unwrap();
            }
        }
    }

    #[test]
    fn all_consistent_is_nominal() {
        let mut m = Mirror::new(DetectorConfig::default()).unwrap();
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[3.0, 3.0, 3.0], 64);
        assert_eq!(m.assess(1, 64).unwrap().verdict, Verdict::Nominal);
    }

    #[test]
    fn single_channel_inflation_is_attributed_inconsistency() {
        let mut m = Mirror::new(DetectorConfig::default()).unwrap();
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[3.0, 3.0, 20.0], 64);
        match m.assess(1, 64).unwrap().verdict {
            Verdict::AttributedInconsistency { channels } => {
                assert_eq!(channels, vec![Modality::Acoustic]);
            }
            other => panic!("expected AttributedInconsistency, got {other:?}"),
        }
    }

    #[test]
    fn all_channels_inflation_is_broad_degradation() {
        let mut m = Mirror::new(DetectorConfig::default()).unwrap();
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[20.0, 20.0, 20.0], 64);
        assert_eq!(m.assess(1, 64).unwrap().verdict, Verdict::BroadDegradation);
    }

    #[test]
    fn verdict_serialization_uses_evidence_neutral_tags() {
        let cases = [
            (
                Verdict::AttributedInconsistency {
                    channels: vec![Modality::Acoustic],
                },
                serde_json::json!({
                    "verdict": "attributed_inconsistency",
                    "channels": ["acoustic"]
                }),
            ),
            (
                Verdict::BroadDegradation,
                serde_json::json!({"verdict": "broad_degradation"}),
            ),
            (
                Verdict::UnclassifiedAnomaly {
                    channels: vec![Modality::Radar],
                },
                serde_json::json!({
                    "verdict": "unclassified_anomaly",
                    "channels": ["radar"]
                }),
            ),
        ];

        for (verdict, expected) in cases {
            assert_eq!(serde_json::to_value(verdict).unwrap(), expected);
        }
    }

    #[test]
    fn verdict_deserialization_accepts_legacy_causal_tags() {
        let cases = [
            (
                serde_json::json!({"verdict": "spoof", "channels": ["acoustic"]}),
                Verdict::AttributedInconsistency {
                    channels: vec![Modality::Acoustic],
                },
            ),
            (
                serde_json::json!({"verdict": "jam"}),
                Verdict::BroadDegradation,
            ),
            (
                serde_json::json!({"verdict": "anomaly", "channels": ["radar"]}),
                Verdict::UnclassifiedAnomaly {
                    channels: vec![Modality::Radar],
                },
            ),
        ];

        for (legacy, expected) in cases {
            assert_eq!(serde_json::from_value::<Verdict>(legacy).unwrap(), expected);
        }
    }

    #[test]
    fn too_few_samples_fails_closed() {
        let mut m = Mirror::new(DetectorConfig::default()).unwrap();
        let mods = [Modality::Visual, Modality::Radar];
        // Below min_samples (32).
        feed(&mut m, 1, &mods, &[3.0, 3.0], 10);
        assert_eq!(
            m.assess(1, 10).unwrap().verdict,
            Verdict::InsufficientEvidence
        );
    }

    #[test]
    fn duplicate_out_of_order_and_dof_changes_are_rejected_without_mutation() {
        let mut mirror = Mirror::new(DetectorConfig::default()).unwrap();
        let first = PidObservation::scalar(1, 100, 5, Modality::Radar, 3.0, 3);
        mirror.ingest(&first).unwrap();

        assert!(
            mirror.ingest(&first).is_err(),
            "duplicate must not advance readiness"
        );
        let older = PidObservation::scalar(1, 90, 4, Modality::Radar, 3.0, 3);
        assert!(mirror.ingest(&older).is_err());
        let changed_dof = PidObservation::scalar(1, 110, 6, Modality::Radar, 3.0, 2);
        assert!(mirror.ingest(&changed_dof).is_err());
        let regressed_time = PidObservation::scalar(1, 99, 6, Modality::Radar, 3.0, 3);
        assert!(mirror.ingest(&regressed_time).is_err());

        let report = mirror.assess(1, 6).unwrap();
        assert_eq!(report.channels[0].n, 1);
    }

    #[test]
    fn large_sequence_holes_reset_contiguous_evidence() {
        let cfg = DetectorConfig {
            min_samples: 2,
            window_len: 4,
            ..DetectorConfig::default()
        };
        let mut mirror = Mirror::new(cfg).unwrap();
        mirror
            .ingest(&PidObservation::scalar(1, 0, 0, Modality::Radar, 3.0, 3))
            .unwrap();
        mirror
            .ingest(&PidObservation::scalar(
                1,
                10_000,
                100,
                Modality::Radar,
                3.0,
                3,
            ))
            .unwrap();
        let report = mirror.assess(1, 100).unwrap();
        assert_eq!(
            report.channels[0].n, 1,
            "pre-gap evidence must be discarded"
        );
        assert_eq!(report.verdict, Verdict::InsufficientEvidence);
    }

    #[test]
    fn frozen_timestamps_are_rejected_without_mutating_state() {
        let cfg = DetectorConfig {
            min_samples: 2,
            window_len: 4,
            ..DetectorConfig::default()
        };
        let mut mirror = Mirror::new(cfg).unwrap();
        mirror
            .ingest(&PidObservation::scalar(1, 100, 0, Modality::Radar, 3.0, 3))
            .unwrap();

        assert!(mirror
            .ingest(&PidObservation::scalar(1, 100, 1, Modality::Radar, 3.0, 3))
            .is_err());
        assert_eq!(mirror.assess(1, 1).unwrap().channels[0].n, 1);
    }

    #[test]
    fn large_forward_timestamp_holes_reset_contiguous_evidence() {
        let cfg = DetectorConfig {
            min_samples: 2,
            window_len: 4,
            max_inter_sample_gap_ms: 100,
            ..DetectorConfig::default()
        };
        let mut mirror = Mirror::new(cfg).unwrap();
        mirror
            .ingest(&PidObservation::scalar(1, 100, 0, Modality::Radar, 3.0, 3))
            .unwrap();
        mirror
            .ingest(&PidObservation::scalar(1, 201, 1, Modality::Radar, 3.0, 3))
            .unwrap();

        let report = mirror.assess(1, 1).unwrap();
        assert_eq!(report.channels[0].n, 1);
        assert_eq!(report.verdict, Verdict::InsufficientEvidence);
    }

    #[test]
    fn retained_tracks_are_bounded_and_explicitly_reclaimable() {
        let cfg = DetectorConfig {
            max_tracks: 1,
            ..DetectorConfig::default()
        };
        let mut mirror = Mirror::new(cfg).unwrap();
        mirror
            .ingest(&PidObservation::scalar(1, 0, 0, Modality::Visual, 3.0, 3))
            .unwrap();
        assert!(mirror
            .ingest(&PidObservation::scalar(2, 0, 0, Modality::Visual, 3.0, 3,))
            .is_err());
        assert!(mirror.remove_track(1));
        assert_eq!(mirror.track_count(), 0);
    }

    #[test]
    fn stale_or_missing_expected_channels_fail_closed() {
        let cfg = DetectorConfig {
            min_samples: 1,
            window_len: 4,
            ..DetectorConfig::default()
        };
        let modalities = [Modality::Visual, Modality::Radar];
        let mut mirror = Mirror::with_modalities(cfg, &modalities).unwrap();
        mirror
            .ingest(&PidObservation::scalar(1, 0, 0, Modality::Visual, 3.0, 3))
            .unwrap();
        assert_eq!(
            mirror.assess(1, 0).unwrap().verdict,
            Verdict::InsufficientEvidence,
            "the missing expected radar channel must block Nominal"
        );
        mirror
            .ingest(&PidObservation::scalar(1, 0, 0, Modality::Radar, 3.0, 3))
            .unwrap();
        assert_eq!(mirror.assess(1, 1).unwrap().verdict, Verdict::Nominal);
        assert_eq!(
            mirror.assess(1, 2).unwrap().verdict,
            Verdict::InsufficientEvidence,
            "retained windows must not stay nominal after their feeds go stale"
        );
    }

    #[test]
    fn cross_modal_timestamp_skew_fails_closed() {
        let cfg = DetectorConfig {
            min_samples: 1,
            window_len: 4,
            max_timestamp_skew_ms: 10,
            ..DetectorConfig::default()
        };
        let modalities = [Modality::Visual, Modality::Radar];
        let mut mirror = Mirror::with_modalities(cfg, &modalities).unwrap();
        mirror
            .ingest(&PidObservation::scalar(1, 0, 0, Modality::Visual, 3.0, 3))
            .unwrap();
        mirror
            .ingest(&PidObservation::scalar(1, 100, 0, Modality::Radar, 3.0, 3))
            .unwrap();
        assert_eq!(
            mirror.assess(1, 0).unwrap().verdict,
            Verdict::InsufficientEvidence
        );
    }

    #[test]
    fn cusum_operating_point_is_comparable_across_degrees_of_freedom() {
        let cfg = DetectorConfig {
            min_samples: 1,
            window_len: 4,
            cusum_slack: 1.0,
            cusum_threshold: 4.0,
            max_tracks: 2,
            ..DetectorConfig::default()
        };
        let mut mirror = Mirror::new(cfg).unwrap();
        for (track, dof) in [(1, 1_u8), (2, 12_u8)] {
            let null_sigma = (2.0 * f64::from(dof)).sqrt();
            let shifted_nis = f64::from(dof) + 3.0 * null_sigma;
            // Use three updates so the assertion does not depend on an exact
            // floating-point equality at `hi == threshold`.
            for seq in 0..3 {
                mirror
                    .ingest(&PidObservation::scalar(
                        track,
                        seq + 1,
                        seq,
                        Modality::Radar,
                        shifted_nis,
                        dof,
                    ))
                    .unwrap();
            }
            assert!(
                mirror.assess(track, 2).unwrap().channels[0].cusum_high_alarm,
                "a sustained three-sigma shift should cross the same CUSUM threshold for dof={dof}"
            );
        }
    }
}
