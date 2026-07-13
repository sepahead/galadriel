//! Conservative statistical assessment of lifecycle-complete assembled frames.
//!
//! [`CrossRouteAssembler`](crate::assembler::CrossRouteAssembler) proves that the
//! two producer routes agree and that every declared observation arrived. That
//! does not imply that every expected modality produced an assessable update: a
//! healthy frame may explicitly contain a gate miss, update rejection, or an
//! incomparable projection. [`LifecycleDetector`] converts those explicit
//! absences into an immediate abstention and clears the affected track history so
//! samples on either side of a censored frame or excessive forward-time gap cannot
//! form one apparently clean statistical window.
//!
//! A returned detector report remains advisory, synthetic-calibration-limited
//! evidence. Lifecycle completeness is not physical truth or a calibrated
//! posterior.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use galadriel_core::{assess_default, CorrConfig, DefaultReport, DetectorConfig, Modality};

use crate::assembler::{AssembledFrame, FrameMonitorEvent};
use crate::monitor::ModalityOutcomeKind;

/// Aggregate ceiling for common-projection observations retained by one
/// lifecycle adapter across every track, modality, and history frame.
pub const MAX_LIFECYCLE_RETAINED_OBSERVATIONS: usize = 1_000_000;

/// One track-level result at a lifecycle-complete fusion frame.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum LifecycleAssessment {
    /// Every expected modality supplied a common-projection observation, so the
    /// bounded contiguous suffix was evaluated by the default detector.
    Evaluated {
        /// Numeric producer track identity.
        track_id: u64,
        /// Fusion frame being assessed.
        fusion_seq: u64,
        /// Whether this frame began a new statistical suffix.
        history_reset: bool,
        /// Advisory NIS/CUSUM and signed-correlation result.
        report: DefaultReport,
    },
    /// At least one expected modality lacked an assessable common projection.
    /// The track's retained suffix was discarded before this result was emitted.
    Abstained {
        /// Numeric producer track identity.
        track_id: u64,
        /// Fusion frame being assessed.
        fusion_seq: u64,
        /// Canonically ordered expected modalities without an assessable common
        /// projection in this frame.
        unavailable_modalities: Vec<Modality>,
    },
}

/// Terminal lifecycle-to-detector integration fault.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LifecycleDetectorError {
    /// Immutable detector configuration was invalid.
    #[error("invalid lifecycle detector configuration: {0}")]
    InvalidConfiguration(String),
    /// An assembled frame contradicted invariants required by this adapter.
    #[error("invalid assembled frame: {0}")]
    InvalidFrame(String),
    /// The frozen track set exceeded the detector's explicit state limit.
    #[error("assembled frame has {actual} frozen tracks; detector maximum is {maximum}")]
    TrackCapacity {
        /// Frozen tracks represented by the frame ledger.
        actual: usize,
        /// Configured detector track ceiling.
        maximum: usize,
    },
    /// The pure detector rejected evidence that had crossed the assembly boundary.
    #[error("detector rejected track {track_id} frame {fusion_seq}: {reason}")]
    Assessment {
        /// Track being evaluated.
        track_id: u64,
        /// Frame being evaluated.
        fusion_seq: u64,
        /// Underlying fail-closed detector error.
        reason: String,
    },
}

#[derive(Debug, Clone)]
struct TrackHistory {
    frame_id: u64,
    context_id: u64,
    modalities: Vec<Modality>,
    last_fusion_seq: u64,
    last_fusion_timestamp_ms: u64,
    frames: VecDeque<Vec<galadriel_core::PidObservation>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProducerEpoch {
    session_id: String,
    producer_id: String,
}

impl ProducerEpoch {
    fn from_frame(frame: &AssembledFrame) -> Self {
        Self {
            session_id: frame.session_id().to_owned(),
            producer_id: frame.producer_id().to_owned(),
        }
    }

    fn matches(&self, frame: &AssembledFrame) -> bool {
        self.session_id == frame.session_id() && self.producer_id == frame.producer_id()
    }
}

/// Bounded bridge from lifecycle-complete frames to Galadriel's pure default
/// detector.
///
/// The bridge owns no transport or wall clock. It retains at most the larger of
/// the configured NIS and correlation windows for at most
/// [`DetectorConfig::max_tracks`] tracks. The exact producer/session pair carried
/// by each assembled frame is an automatic history boundary. Any terminal adapter
/// error clears all history and is returned unchanged on later calls.
#[derive(Debug)]
pub struct LifecycleDetector {
    detector_config: DetectorConfig,
    correlation_config: CorrConfig,
    history_frames: usize,
    active_epoch: Option<ProducerEpoch>,
    tracks: HashMap<u64, TrackHistory>,
    fault: Option<LifecycleDetectorError>,
}

impl LifecycleDetector {
    /// Construct a bounded lifecycle detector with immutable statistical policy.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleDetectorError::InvalidConfiguration`] when either
    /// detector configuration is invalid.
    pub fn new(
        detector_config: DetectorConfig,
        correlation_config: CorrConfig,
    ) -> Result<Self, LifecycleDetectorError> {
        detector_config
            .validate()
            .map_err(|error| LifecycleDetectorError::InvalidConfiguration(error.to_string()))?;
        correlation_config
            .validate()
            .map_err(|error| LifecycleDetectorError::InvalidConfiguration(error.to_string()))?;
        let history_frames = detector_config.window_len.max(correlation_config.window);
        let retained_observations = history_frames
            .checked_mul(detector_config.max_tracks)
            .and_then(|samples| samples.checked_mul(Modality::ALL.len()))
            .ok_or_else(|| {
                LifecycleDetectorError::InvalidConfiguration(
                    "history frames × max tracks × modalities overflows usize".to_owned(),
                )
            })?;
        if retained_observations > MAX_LIFECYCLE_RETAINED_OBSERVATIONS {
            return Err(LifecycleDetectorError::InvalidConfiguration(format!(
                "lifecycle policy may retain {retained_observations} observations; maximum is \
                 {MAX_LIFECYCLE_RETAINED_OBSERVATIONS}"
            )));
        }
        Ok(Self {
            detector_config,
            correlation_config,
            history_frames,
            active_epoch: None,
            tracks: HashMap::new(),
            fault: None,
        })
    }

    /// Retained first terminal adapter fault, if any.
    pub fn fault(&self) -> Option<&LifecycleDetectorError> {
        self.fault.as_ref()
    }

    /// Number of track suffixes currently retained.
    pub fn retained_tracks(&self) -> usize {
        self.tracks.len()
    }

    /// Discard all statistical suffixes without clearing a terminal fault.
    pub fn clear_histories(&mut self) {
        self.tracks.clear();
    }

    /// Assess every frozen track represented by one assembled frame.
    ///
    /// A track is evaluated only when this exact frame contains one observation
    /// with a common projection for every summary-declared modality. Otherwise it
    /// immediately returns [`LifecycleAssessment::Abstained`] and its suffix is
    /// cleared. Track births are outside the frozen Cartesian ledger and begin
    /// participating on a later frame.
    ///
    /// # Errors
    ///
    /// Any structural, capacity, or detector error permanently faults this
    /// instance. No partial result is returned.
    pub fn assess_frame(
        &mut self,
        frame: &AssembledFrame,
    ) -> Result<Vec<LifecycleAssessment>, LifecycleDetectorError> {
        if let Some(fault) = &self.fault {
            return Err(fault.clone());
        }
        match self.assess_frame_inner(frame) {
            Ok(assessments) => Ok(assessments),
            Err(error) => {
                self.tracks.clear();
                self.fault = Some(error.clone());
                Err(error)
            }
        }
    }

    fn assess_frame_inner(
        &mut self,
        frame: &AssembledFrame,
    ) -> Result<Vec<LifecycleAssessment>, LifecycleDetectorError> {
        validate_frame_identity(frame)?;
        if self
            .active_epoch
            .as_ref()
            .is_none_or(|epoch| !epoch.matches(frame))
        {
            self.tracks.clear();
            self.active_epoch = Some(ProducerEpoch::from_frame(frame));
        }
        let modalities = &frame.summary.expected_modalities;
        validate_canonical_modalities(modalities)?;
        if modalities.len() < self.detector_config.min_channels {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "{} expected modalities cannot satisfy detector min_channels {}",
                modalities.len(),
                self.detector_config.min_channels
            )));
        }

        let frozen_tracks = frozen_track_ids(frame);
        if frozen_tracks.len() > self.detector_config.max_tracks {
            return Err(LifecycleDetectorError::TrackCapacity {
                actual: frozen_tracks.len(),
                maximum: self.detector_config.max_tracks,
            });
        }
        let mut observations_by_track =
            validate_observation_ledger(frame, &frozen_tracks, modalities)?;
        self.tracks
            .retain(|track_id, _| frozen_tracks.contains(track_id));

        let mut assessments = Vec::with_capacity(frozen_tracks.len());
        for track_id in frozen_tracks {
            let observations = observations_by_track.remove(&track_id).unwrap_or_default();
            let unavailable_modalities = modalities
                .iter()
                .copied()
                .filter(|modality| {
                    !observations.iter().any(|observation| {
                        observation.modality == *modality
                            && observation.consistency_projection.is_some()
                    })
                })
                .collect::<Vec<_>>();
            if !unavailable_modalities.is_empty() {
                self.tracks.remove(&track_id);
                assessments.push(LifecycleAssessment::Abstained {
                    track_id,
                    fusion_seq: frame.identity.fusion_seq,
                    unavailable_modalities,
                });
                continue;
            }
            if observations.len() != modalities.len() {
                return Err(LifecycleDetectorError::InvalidFrame(format!(
                    "track {track_id} frame {} has {} observations for {} expected modalities",
                    frame.identity.fusion_seq,
                    observations.len(),
                    modalities.len()
                )));
            }

            let history_reset = self.history_requires_reset(frame, track_id, modalities);
            if history_reset {
                self.tracks.remove(&track_id);
            }
            let history = self.tracks.entry(track_id).or_insert_with(|| TrackHistory {
                frame_id: frame.identity.frame_id,
                context_id: frame.identity.context_id,
                modalities: modalities.clone(),
                last_fusion_seq: frame.identity.fusion_seq,
                last_fusion_timestamp_ms: frame.identity.fusion_timestamp_ms,
                frames: VecDeque::new(),
            });
            history.last_fusion_seq = frame.identity.fusion_seq;
            history.last_fusion_timestamp_ms = frame.identity.fusion_timestamp_ms;
            history.frames.push_back(observations);
            // Each admission appends exactly one frame to a previously bounded
            // queue, so at most one oldest frame can overflow this ceiling.
            if history.frames.len() > self.history_frames {
                history.frames.pop_front();
            }
            let observation_count = history
                .frames
                .len()
                .checked_mul(modalities.len())
                .ok_or_else(|| {
                    LifecycleDetectorError::InvalidFrame(
                        "bounded history observation count overflow".to_owned(),
                    )
                })?;
            let mut stream = Vec::with_capacity(observation_count);
            for observations in &history.frames {
                stream.extend(observations.iter().cloned());
            }
            let report = assess_default(
                &stream,
                modalities,
                &self.detector_config,
                &self.correlation_config,
            )
            .map_err(|error| LifecycleDetectorError::Assessment {
                track_id,
                fusion_seq: frame.identity.fusion_seq,
                reason: error.to_string(),
            })?;
            assessments.push(LifecycleAssessment::Evaluated {
                track_id,
                fusion_seq: frame.identity.fusion_seq,
                history_reset,
                report,
            });
        }
        Ok(assessments)
    }

    fn history_requires_reset(
        &self,
        frame: &AssembledFrame,
        track_id: u64,
        modalities: &[Modality],
    ) -> bool {
        self.tracks.get(&track_id).is_none_or(|history| {
            history.frame_id != frame.identity.frame_id
                || history.context_id != frame.identity.context_id
                || history.modalities != modalities
                || history
                    .last_fusion_seq
                    .checked_add(1)
                    .is_none_or(|next| next != frame.identity.fusion_seq)
                || frame
                    .identity
                    .fusion_timestamp_ms
                    .checked_sub(history.last_fusion_timestamp_ms)
                    .is_some_and(|gap| gap > self.detector_config.max_inter_sample_gap_ms)
        })
    }
}

fn validate_frame_identity(frame: &AssembledFrame) -> Result<(), LifecycleDetectorError> {
    let summary = &frame.summary;
    if summary.fusion_seq != frame.identity.fusion_seq
        || summary.fusion_timestamp_ms != frame.identity.fusion_timestamp_ms
        || summary.frame_id != frame.identity.frame_id
        || summary.context_id != frame.identity.context_id
        || summary.prior_id != frame.identity.prior_id
    {
        return Err(LifecycleDetectorError::InvalidFrame(
            "summary identity differs from assembled identity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_canonical_modalities(modalities: &[Modality]) -> Result<(), LifecycleDetectorError> {
    if modalities.is_empty()
        || modalities
            .windows(2)
            .any(|pair| modality_rank(pair[0]) >= modality_rank(pair[1]))
    {
        return Err(LifecycleDetectorError::InvalidFrame(
            "expected modalities must be nonempty, unique, and in canonical order".to_owned(),
        ));
    }
    Ok(())
}

fn frozen_track_ids(frame: &AssembledFrame) -> BTreeSet<u64> {
    frame
        .monitor_events
        .iter()
        .filter_map(|event| match event {
            FrameMonitorEvent::Outcome(outcome)
                if outcome.outcome != ModalityOutcomeKind::TrackBirth =>
            {
                Some(outcome.track_id)
            }
            FrameMonitorEvent::Outcome(_) => None,
            FrameMonitorEvent::Miss(miss) => Some(miss.track_id),
        })
        .collect()
}

fn validate_observation_ledger(
    frame: &AssembledFrame,
    frozen_tracks: &BTreeSet<u64>,
    modalities: &[Modality],
) -> Result<HashMap<u64, Vec<galadriel_core::PidObservation>>, LifecycleDetectorError> {
    let maximum_observations = frozen_tracks
        .len()
        .checked_mul(modalities.len())
        .ok_or_else(|| {
            LifecycleDetectorError::InvalidFrame(
                "frozen track × modality observation bound overflows usize".to_owned(),
            )
        })?;
    if frame.observations.len() > maximum_observations {
        return Err(LifecycleDetectorError::InvalidFrame(format!(
            "frame {} has {} observations; frozen Cartesian maximum is {maximum_observations}",
            frame.identity.fusion_seq,
            frame.observations.len(),
        )));
    }

    let mut pairs = HashSet::with_capacity(frame.observations.len());
    let mut by_track: HashMap<u64, Vec<galadriel_core::PidObservation>> =
        HashMap::with_capacity(frozen_tracks.len());
    for observation in &frame.observations {
        observation.validate().map_err(|error| {
            LifecycleDetectorError::InvalidFrame(format!(
                "track {} / {:?} observation is invalid: {error}",
                observation.track_id, observation.modality,
            ))
        })?;
        if !frozen_tracks.contains(&observation.track_id) {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "observation track {} is absent from the frozen frame ledger",
                observation.track_id,
            )));
        }
        if !modalities.contains(&observation.modality) {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "track {} has observation for unexpected modality {:?}",
                observation.track_id, observation.modality,
            )));
        }
        if !pairs.insert((observation.track_id, observation.modality)) {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "duplicate observation for track {} / {:?}",
                observation.track_id, observation.modality,
            )));
        }
        if observation.seq != frame.identity.fusion_seq
            || observation.timestamp_ms != frame.identity.fusion_timestamp_ms
        {
            return Err(LifecycleDetectorError::InvalidFrame(format!(
                "track {} / {:?} observation sequence or timestamp differs from frame {}",
                observation.track_id, observation.modality, frame.identity.fusion_seq,
            )));
        }
        if let Some(projection) = observation.consistency_projection {
            if projection.frame_id != frame.identity.frame_id
                || projection.context_id != frame.identity.context_id
                || projection.prior_id != frame.identity.prior_id
            {
                return Err(LifecycleDetectorError::InvalidFrame(format!(
                    "track {} / {:?} projection provenance differs from frame {}",
                    observation.track_id, observation.modality, frame.identity.fusion_seq,
                )));
            }
        }
        by_track
            .entry(observation.track_id)
            .or_default()
            .push(observation.clone());
    }
    for observations in by_track.values_mut() {
        observations.sort_by_key(|observation| modality_rank(observation.modality));
    }
    Ok(by_track)
}

fn modality_rank(modality: Modality) -> u8 {
    match modality {
        Modality::Visual => 0,
        Modality::Thermal => 1,
        Modality::Acoustic => 2,
        Modality::Radar => 3,
        Modality::Lidar => 4,
        Modality::RadioFrequency => 5,
    }
}

#[cfg(test)]
mod tests {
    use galadriel_core::{ConsistencyProjection, FusedVerdict, PidObservation};

    use super::*;
    use crate::assembler::FrameIdentity;
    use crate::monitor::{
        FrameSummary, GateEvidence, GateMethod, ModalityMiss, ModalityMissReason, ModalityOutcome,
    };

    const REGISTRY_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn detector() -> LifecycleDetector {
        LifecycleDetector::new(
            DetectorConfig {
                window_len: 4,
                min_samples: 4,
                min_channels: 2,
                ..DetectorConfig::default()
            },
            CorrConfig {
                window: 4,
                min_samples: 4,
                ..CorrConfig::default()
            },
        )
        .expect("test detector config validates")
    }

    #[test]
    fn aggregate_history_bound_rejects_cross_config_state_explosion() {
        let error = LifecycleDetector::new(
            DetectorConfig {
                window_len: 1,
                min_samples: 1,
                min_channels: 2,
                max_tracks: 4,
                ..DetectorConfig::default()
            },
            CorrConfig {
                window: galadriel_core::correlation::MAX_CORRELATION_WINDOW,
                min_samples: 4,
                ..CorrConfig::default()
            },
        )
        .expect_err("combined lifecycle retention must be bounded");

        assert!(matches!(
            error,
            LifecycleDetectorError::InvalidConfiguration(reason)
                if reason.contains("may retain")
        ));
    }

    fn identity(fusion_seq: u64, context_id: u64) -> FrameIdentity {
        FrameIdentity {
            fusion_seq,
            fusion_timestamp_ms: fusion_seq * 100,
            frame_id: 7,
            context_id,
            prior_id: fusion_seq,
        }
    }

    fn observation(identity: FrameIdentity, modality: Modality) -> PidObservation {
        let offset = match modality {
            Modality::Visual => 0.0,
            Modality::Radar => 0.1,
            _ => 0.2,
        };
        PidObservation {
            track_id: 1,
            timestamp_ms: identity.fusion_timestamp_ms,
            seq: identity.fusion_seq,
            modality,
            nis: 3.0,
            dof: 3,
            innovation: None,
            innovation_cov: None,
            consistency_projection: Some(ConsistencyProjection {
                values: [identity.fusion_seq as f64 + offset, 0.0, 0.0],
                dimensions: 1,
                frame_id: identity.frame_id,
                context_id: identity.context_id,
                prior_id: identity.prior_id,
            }),
        }
    }

    fn outcome(identity: FrameIdentity, modality: Modality) -> FrameMonitorEvent {
        FrameMonitorEvent::Outcome(ModalityOutcome {
            fusion_seq: identity.fusion_seq,
            fusion_timestamp_ms: identity.fusion_timestamp_ms,
            frame_id: identity.frame_id,
            context_id: identity.context_id,
            prior_id: identity.prior_id,
            track_id: 1,
            modality,
            attempt_index: 0,
            measurement_index: Some(0),
            outcome: ModalityOutcomeKind::Updated,
            v1_expected: true,
            candidate_count: 1,
            in_gate_count: 1,
            gate_evidence: Some(GateEvidence {
                method: GateMethod::Mahalanobis,
                d2: 1.0,
                threshold: 7.0,
            }),
            consistency_projection: observation(identity, modality).consistency_projection,
        })
    }

    fn complete_frame(fusion_seq: u64, context_id: u64) -> AssembledFrame {
        let identity = identity(fusion_seq, context_id);
        let modalities = vec![Modality::Visual, Modality::Radar];
        AssembledFrame {
            session_id: "epoch-1".to_owned(),
            producer_id: "crebain".to_owned(),
            identity,
            monitor_events: modalities
                .iter()
                .copied()
                .map(|modality| outcome(identity, modality))
                .collect(),
            observations: modalities
                .iter()
                .copied()
                .map(|modality| observation(identity, modality))
                .collect(),
            summary: FrameSummary {
                fusion_seq: identity.fusion_seq,
                fusion_timestamp_ms: identity.fusion_timestamp_ms,
                frame_id: identity.frame_id,
                context_id: identity.context_id,
                prior_id: identity.prior_id,
                registry_digest: REGISTRY_DIGEST.to_owned(),
                expected_modalities: modalities,
                active_track_count: 1,
                input_count: 2,
                outcome_count: 2,
                v1_expected_count: 2,
                degraded: false,
                truncated: false,
            },
        }
    }

    fn miss_frame(fusion_seq: u64) -> AssembledFrame {
        let mut frame = complete_frame(fusion_seq, 11);
        frame.monitor_events.pop();
        frame
            .monitor_events
            .push(FrameMonitorEvent::Miss(ModalityMiss {
                fusion_seq,
                fusion_timestamp_ms: frame.identity.fusion_timestamp_ms,
                frame_id: frame.identity.frame_id,
                context_id: frame.identity.context_id,
                prior_id: frame.identity.prior_id,
                track_id: 1,
                modality: Modality::Radar,
                reason: ModalityMissReason::NoMeasurement,
            }));
        frame.observations.pop();
        frame.summary.v1_expected_count = 1;
        frame
    }

    fn birth_frame(fusion_seq: u64) -> AssembledFrame {
        let mut frame = complete_frame(fusion_seq, 11);
        let FrameMonitorEvent::Outcome(mut birth) = frame.monitor_events.remove(0) else {
            panic!("complete fixture begins with an outcome")
        };
        birth.outcome = ModalityOutcomeKind::TrackBirth;
        birth.v1_expected = false;
        birth.candidate_count = 0;
        birth.in_gate_count = 0;
        birth.gate_evidence = None;
        birth.consistency_projection = None;
        frame.monitor_events = vec![FrameMonitorEvent::Outcome(birth)];
        frame.observations.clear();
        frame.summary.active_track_count = 1;
        frame.summary.input_count = 1;
        frame.summary.outcome_count = 1;
        frame.summary.v1_expected_count = 0;
        frame
    }

    fn set_fusion_timestamp(frame: &mut AssembledFrame, timestamp_ms: u64) {
        frame.identity.fusion_timestamp_ms = timestamp_ms;
        frame.summary.fusion_timestamp_ms = timestamp_ms;
        for observation in &mut frame.observations {
            observation.timestamp_ms = timestamp_ms;
        }
        for event in &mut frame.monitor_events {
            match event {
                FrameMonitorEvent::Outcome(outcome) => {
                    outcome.fusion_timestamp_ms = timestamp_ms;
                }
                FrameMonitorEvent::Miss(miss) => {
                    miss.fusion_timestamp_ms = timestamp_ms;
                }
            }
        }
    }

    fn set_epoch(frame: &mut AssembledFrame, session_id: &str, producer_id: &str) {
        frame.session_id = session_id.to_owned();
        frame.producer_id = producer_id.to_owned();
    }

    fn assert_invalid_frame(frame: AssembledFrame, expected_reason: &str) {
        let mut detector = detector();
        let error = detector
            .assess_frame(&frame)
            .expect_err("fabricated frame must fail closed");
        assert!(matches!(
            &error,
            LifecycleDetectorError::InvalidFrame(reason) if reason.contains(expected_reason)
        ));
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn observation_count_above_frozen_cartesian_bound_is_terminal() {
        let mut frame = complete_frame(1, 11);
        frame.observations.push(frame.observations[0].clone());

        assert_invalid_frame(frame, "frozen Cartesian maximum");
    }

    #[test]
    fn observation_for_track_outside_frozen_ledger_is_terminal() {
        let mut frame = complete_frame(1, 11);
        frame.observations[1].track_id = 2;

        assert_invalid_frame(frame, "absent from the frozen frame ledger");
    }

    #[test]
    fn duplicate_or_unexpected_observation_modality_is_terminal() {
        let mut duplicate = complete_frame(1, 11);
        duplicate.observations[1].modality = Modality::Visual;
        assert_invalid_frame(duplicate, "duplicate observation");

        let mut unexpected = complete_frame(1, 11);
        unexpected.observations[1].modality = Modality::Thermal;
        assert_invalid_frame(unexpected, "unexpected modality");
    }

    #[test]
    fn observation_identity_or_projection_provenance_mismatch_is_terminal() {
        let mut wrong_sequence = complete_frame(1, 11);
        wrong_sequence.observations[0].seq = 2;
        assert_invalid_frame(wrong_sequence, "sequence or timestamp differs");

        let mut wrong_timestamp = complete_frame(1, 11);
        wrong_timestamp.observations[0].timestamp_ms += 1;
        assert_invalid_frame(wrong_timestamp, "sequence or timestamp differs");

        let mut wrong_projection_frame = complete_frame(1, 11);
        wrong_projection_frame.observations[0]
            .consistency_projection
            .as_mut()
            .expect("complete fixture has projection")
            .frame_id += 1;
        assert_invalid_frame(wrong_projection_frame, "projection provenance differs");

        let mut wrong_projection_context = complete_frame(1, 11);
        wrong_projection_context.observations[0]
            .consistency_projection
            .as_mut()
            .expect("complete fixture has projection")
            .context_id += 1;
        assert_invalid_frame(wrong_projection_context, "projection provenance differs");

        let mut wrong_projection_prior = complete_frame(1, 11);
        wrong_projection_prior.observations[0]
            .consistency_projection
            .as_mut()
            .expect("complete fixture has projection")
            .prior_id += 1;
        assert_invalid_frame(wrong_projection_prior, "projection provenance differs");
    }

    #[test]
    fn every_summary_identity_field_must_match_the_assembled_identity() {
        let mut wrong_sequence = complete_frame(1, 11);
        wrong_sequence.summary.fusion_seq += 1;
        assert_invalid_frame(wrong_sequence, "summary identity differs");

        let mut wrong_timestamp = complete_frame(1, 11);
        wrong_timestamp.summary.fusion_timestamp_ms += 1;
        assert_invalid_frame(wrong_timestamp, "summary identity differs");

        let mut wrong_frame = complete_frame(1, 11);
        wrong_frame.summary.frame_id += 1;
        assert_invalid_frame(wrong_frame, "summary identity differs");

        let mut wrong_context = complete_frame(1, 11);
        wrong_context.summary.context_id += 1;
        assert_invalid_frame(wrong_context, "summary identity differs");

        let mut wrong_prior = complete_frame(1, 11);
        wrong_prior.summary.prior_id += 1;
        assert_invalid_frame(wrong_prior, "summary identity differs");
    }

    #[test]
    fn individually_invalid_observation_is_terminal_before_assessment() {
        let mut frame = complete_frame(1, 11);
        frame.observations[0].nis = f64::NAN;

        assert_invalid_frame(frame, "observation is invalid");
    }

    #[test]
    fn complete_suffix_is_bounded_and_eventually_evaluated() {
        let mut detector = detector();
        for fusion_seq in 1..=4 {
            let assessments = detector
                .assess_frame(&complete_frame(fusion_seq, 11))
                .expect("complete frame evaluates");
            let LifecycleAssessment::Evaluated {
                history_reset,
                report,
                ..
            } = &assessments[0]
            else {
                panic!("complete frame must be evaluated")
            };
            assert_eq!(*history_reset, fusion_seq == 1);
            if fusion_seq == 4 {
                assert!(report.baseline.channels.iter().all(|channel| channel.ready));
            }
        }
        assert_eq!(detector.retained_tracks(), 1);
    }

    #[test]
    fn explicit_history_clear_discards_the_suffix_without_clearing_health() {
        let mut detector = detector();
        for fusion_seq in 1..=3 {
            detector
                .assess_frame(&complete_frame(fusion_seq, 11))
                .expect("warm-up frame evaluates");
        }
        assert_eq!(detector.retained_tracks(), 1);

        detector.clear_histories();

        assert_eq!(detector.retained_tracks(), 0);
        assert_eq!(detector.fault(), None);
        let assessment = detector
            .assess_frame(&complete_frame(4, 11))
            .expect("post-clear frame starts a new suffix");
        assert!(matches!(
            &assessment[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                report,
                ..
            } if report.verdict == FusedVerdict::InsufficientEvidence
        ));
    }

    #[test]
    fn expected_modalities_below_the_detector_minimum_are_terminal() {
        let mut detector = LifecycleDetector::new(
            DetectorConfig {
                window_len: 4,
                min_samples: 4,
                min_channels: 3,
                ..DetectorConfig::default()
            },
            CorrConfig {
                window: 4,
                min_samples: 4,
                ..CorrConfig::default()
            },
        )
        .expect("three-channel detector config validates");

        let error = detector
            .assess_frame(&complete_frame(1, 11))
            .expect_err("a two-modality frame cannot satisfy a three-channel detector");

        assert!(matches!(
            &error,
            LifecycleDetectorError::InvalidFrame(reason)
                if reason.contains("cannot satisfy detector min_channels 3")
        ));
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn track_capacity_boundary_is_inclusive() {
        let mut detector = LifecycleDetector::new(
            DetectorConfig {
                window_len: 4,
                min_samples: 4,
                min_channels: 2,
                max_tracks: 1,
                ..DetectorConfig::default()
            },
            CorrConfig {
                window: 4,
                min_samples: 4,
                ..CorrConfig::default()
            },
        )
        .expect("one-track detector config validates");

        let assessment = detector
            .assess_frame(&complete_frame(1, 11))
            .expect("exactly max_tracks frozen tracks remain admissible");

        assert!(matches!(
            assessment.as_slice(),
            [LifecycleAssessment::Evaluated {
                track_id: 1,
                history_reset: true,
                ..
            }]
        ));
        assert_eq!(detector.retained_tracks(), 1);
        assert_eq!(detector.fault(), None);
    }

    #[test]
    fn explicit_miss_abstains_immediately_and_breaks_the_suffix() {
        let mut detector = detector();
        for fusion_seq in 1..=3 {
            detector
                .assess_frame(&complete_frame(fusion_seq, 11))
                .expect("warm-up frame evaluates");
        }

        let assessments = detector
            .assess_frame(&miss_frame(4))
            .expect("a valid miss is an abstention, not an adapter fault");
        assert!(matches!(
            assessments.as_slice(),
            [LifecycleAssessment::Abstained {
                unavailable_modalities,
                ..
            }] if unavailable_modalities == &[Modality::Radar]
        ));
        assert_eq!(detector.retained_tracks(), 0);

        let next = detector
            .assess_frame(&complete_frame(5, 11))
            .expect("post-miss frame starts a new suffix");
        assert!(matches!(
            &next[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                report,
                ..
            } if report.verdict == FusedVerdict::InsufficientEvidence
        ));
    }

    #[test]
    fn context_change_and_sequence_gap_reset_history() {
        let mut detector = detector();
        detector
            .assess_frame(&complete_frame(1, 11))
            .expect("first frame evaluates");
        let changed = detector
            .assess_frame(&complete_frame(2, 12))
            .expect("context change starts a new suffix");
        assert!(matches!(
            changed[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }
        ));
        let gap = detector
            .assess_frame(&complete_frame(4, 12))
            .expect("sequence gap starts a new suffix");
        assert!(matches!(
            gap[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }
        ));
    }

    #[test]
    fn session_or_producer_change_cannot_share_a_consecutive_history_suffix() {
        let mut detector = detector();
        for fusion_seq in 1..=3 {
            detector
                .assess_frame(&complete_frame(fusion_seq, 11))
                .expect("first epoch warm-up frame evaluates");
        }

        let mut new_session = complete_frame(4, 11);
        set_epoch(&mut new_session, "epoch-2", "crebain");
        let session_assessments = detector
            .assess_frame(&new_session)
            .expect("consecutive frame in a new session starts a new suffix");
        assert!(matches!(
            &session_assessments[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                report,
                ..
            } if report.verdict == FusedVerdict::InsufficientEvidence
        ));

        let mut new_producer = complete_frame(5, 11);
        set_epoch(&mut new_producer, "epoch-2", "other-producer");
        let producer_assessments = detector
            .assess_frame(&new_producer)
            .expect("consecutive frame from a different producer starts a new suffix");
        assert!(matches!(
            &producer_assessments[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                report,
                ..
            } if report.verdict == FusedVerdict::InsufficientEvidence
        ));
    }

    #[test]
    fn forward_timestamp_gap_resets_only_above_the_configured_boundary() {
        let mut detector = detector();
        let maximum_gap = detector.detector_config.max_inter_sample_gap_ms;
        let first_timestamp = 100_u64;
        let boundary_timestamp = first_timestamp
            .checked_add(maximum_gap)
            .expect("test timestamp remains representable");
        let reset_timestamp = boundary_timestamp
            .checked_add(maximum_gap)
            .and_then(|timestamp| timestamp.checked_add(1))
            .expect("test timestamp remains representable");

        let mut first = complete_frame(1, 11);
        set_fusion_timestamp(&mut first, first_timestamp);
        detector
            .assess_frame(&first)
            .expect("first frame evaluates");

        let mut boundary = complete_frame(2, 11);
        set_fusion_timestamp(&mut boundary, boundary_timestamp);
        let boundary_assessment = detector
            .assess_frame(&boundary)
            .expect("the inclusive timestamp gap evaluates");
        assert!(matches!(
            boundary_assessment[0],
            LifecycleAssessment::Evaluated {
                history_reset: false,
                ..
            }
        ));

        let mut above = complete_frame(3, 11);
        set_fusion_timestamp(&mut above, reset_timestamp);
        let above_assessment = detector
            .assess_frame(&above)
            .expect("a forward gap starts a new valid suffix");
        assert!(matches!(
            above_assessment[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }
        ));
    }

    #[test]
    fn regressing_timestamp_remains_a_terminal_detector_error() {
        let mut detector = detector();
        let mut first = complete_frame(1, 11);
        set_fusion_timestamp(&mut first, 100);
        detector
            .assess_frame(&first)
            .expect("first frame evaluates");
        let mut regressed = complete_frame(2, 11);
        set_fusion_timestamp(&mut regressed, 99);

        let error = detector
            .assess_frame(&regressed)
            .expect_err("timestamp regression must not be converted into a reset");

        assert!(matches!(error, LifecycleDetectorError::Assessment { .. }));
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn terminal_timestamp_value_remains_a_terminal_adapter_error() {
        let mut detector = detector();
        let mut first = complete_frame(1, 11);
        set_fusion_timestamp(&mut first, u64::MAX - 1);
        detector
            .assess_frame(&first)
            .expect("largest nonterminal timestamp evaluates");
        let mut terminal = complete_frame(2, 11);
        set_fusion_timestamp(&mut terminal, u64::MAX);

        let error = detector
            .assess_frame(&terminal)
            .expect_err("terminal timestamp must not be converted into a reset");

        assert!(matches!(error, LifecycleDetectorError::InvalidFrame(_)));
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn zero_track_frame_retires_absent_history() {
        let mut detector = detector();
        detector
            .assess_frame(&complete_frame(1, 11))
            .expect("first frame evaluates");
        let mut empty = complete_frame(2, 11);
        empty.monitor_events.clear();
        empty.observations.clear();
        empty.summary.active_track_count = 0;
        empty.summary.input_count = 0;
        empty.summary.outcome_count = 0;
        empty.summary.v1_expected_count = 0;

        assert!(detector
            .assess_frame(&empty)
            .expect("zero-track closure is valid")
            .is_empty());
        assert_eq!(detector.retained_tracks(), 0);
    }

    #[test]
    fn track_birth_is_excluded_and_clears_any_reused_track_suffix() {
        let mut detector = detector();
        detector
            .assess_frame(&complete_frame(1, 11))
            .expect("first frozen frame evaluates");

        assert!(detector
            .assess_frame(&birth_frame(2))
            .expect("birth-only frame is valid")
            .is_empty());
        assert_eq!(detector.retained_tracks(), 0);

        let next = detector
            .assess_frame(&complete_frame(3, 11))
            .expect("track participates only when later frozen");
        assert!(matches!(
            next[0],
            LifecycleAssessment::Evaluated {
                history_reset: true,
                ..
            }
        ));
    }

    #[test]
    fn structural_fault_latches_and_clears_history() {
        let mut detector = detector();
        detector
            .assess_frame(&complete_frame(1, 11))
            .expect("first frame evaluates");
        let mut invalid = complete_frame(2, 11);
        invalid.summary.expected_modalities.reverse();

        let error = detector
            .assess_frame(&invalid)
            .expect_err("noncanonical modalities must fault");
        assert!(matches!(error, LifecycleDetectorError::InvalidFrame(_)));
        assert_eq!(detector.retained_tracks(), 0);
        assert_eq!(detector.fault(), Some(&error));
        assert_eq!(
            detector
                .assess_frame(&complete_frame(3, 11))
                .expect_err("fault is permanent"),
            error
        );
    }
}
