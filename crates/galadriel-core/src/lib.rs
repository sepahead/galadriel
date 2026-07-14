#![forbid(unsafe_code)]
//! # galadriel-core
//!
//! The pure, dependency-light core of **Galadriel's Mirror** — a cross-sensor
//! consistency monitor for multi-sensor fusion (counter-UAS / embodied-agent
//! perception).
//!
//! This crate ships the **cheap baseline** the more expensive information-theoretic
//! engine must beat before it is trusted: a per-channel **Normalized Innovation
//! Squared (NIS) χ² consistency test** plus a **CUSUM** change detector, folded
//! into a fail-closed, evidence-neutral magnitude assessment.
//!
//! ## What it consumes
//!
//! A stream of [`PidObservation`] records — one per associated measurement,
//! carrying the scalar `NIS = yᵀ S⁻¹ y ~ χ²(dof)` formed against the *a priori*
//! (predicted, pre-update) track state. In the sepahead ecosystem these are
//! emitted by crebain's fusion `update_track` and delivered over the NCP
//! observation plane; here they are transport-agnostic plain data.
//! Cross-sensor analysis additionally requires an optional
//! [`ConsistencyProjection`]: a bounded signed vector plus producer-attested
//! physical-frame, projection-context, and frozen-prior identifiers. Raw native
//! innovations are never compared across modalities.
//!
//! ## The decision, honestly scoped
//!
//! | observation | verdict | reasoning |
//! |---|---|---|
//! | all channels' windowed NIS consistent with χ²(dof), with no CUSUM alarm | [`Verdict::Nominal`] | individual magnitude checks are consistent |
//! | **one** channel has high-direction NIS/CUSUM evidence, others nominal | [`Verdict::AttributedInconsistency`] | localized magnitude inconsistency; cause unclassified |
//! | **most/all** channels have high-direction NIS/CUSUM evidence | [`Verdict::BroadDegradation`] | broad magnitude degradation; cause unclassified |
//! | too few samples / channels | [`Verdict::InsufficientEvidence`] | **fail closed** — never default to Nominal |
//!
//! This is an **advisory** detector. It authenticates *statistical consistency*,
//! not truth: a moment-matched spoof that keeps each channel's NIS within its own
//! covariance passes the baseline — the signed-correlation default and optional PID
//! escalation can observe some common-projection dependence changes, but cannot
//! distinguish every attack from benign decorrelation. See the repository's
//! `docs/JUSTIFICATION.md` and `docs/EVALUATION.md`.

pub mod authority;
pub mod baseline;
mod chi2;
pub mod config;
pub mod correlation;
pub mod cusum;
pub mod decision;
pub mod domain;
pub mod error;
pub mod fusion;
mod identity;
mod numeric;
pub mod observation;
pub mod outcome;
pub mod window;

pub use authority::{validate_advisory_effect, AdvisoryPolicy, AuthoritySnapshot, Authorization};
pub use config::{
    AssessmentClassification, ConfigurationClass, DetectorConfig, DetectorConfigError,
    DetectorParams, DetectorProfile, ExploratoryResearchProfile, ExploratorySubsetResearch,
    ProducerAxisFamilyPolicy, ReleaseProfile, ReleaseSuite, ReleaseSuiteError, ReleaseSuiteParams,
    CHANNEL_STATE_AND_MAP_OVERHEAD_BYTES, MAX_ALIGNMENT_SEQ_GAP, MAX_ALIGNMENT_TIMESTAMP_SKEW_MS,
    MAX_DETECTOR_CHANNEL_STATES, MAX_DETECTOR_STATE_BYTES, MAX_DETECTOR_TRACKS,
    MAX_INTER_SAMPLE_GAP_MS, MAX_RELEASE_LIFECYCLE_SAMPLE_UNITS, MAX_RELEASE_SUITE_STATE_BYTES,
    MIN_NIS_FAMILY_ALPHA,
};
pub use correlation::{
    CorrChannel, CorrConfig, CorrConfigError, CorrParams, CorrProfile, CorrReport, CorrVerdict,
};
pub use cusum::Cusum;
pub use decision::{ChannelReport, Mirror, MirrorReport, Verdict};
pub use domain::{
    ClockDomain, DomainError, EpochId, EpochIdentity, FrozenPriorId, ProducerId,
    ProjectionContextId, ProjectionFrameId, ProjectionIdentity, Sequence, SessionId,
    StateGeneration, StreamId, StreamIdentity, StreamPosition, TimestampMillis, TrackId,
    JSON_SAFE_INTEGER_MAX, MAX_IDENTIFIER_BYTES,
};
pub use error::{GaladrielError, Result};
pub use fusion::{
    assess_default, combine, combine_correlation_axes, prepare_release_assessment, try_combine,
    AxisCorrelationReport, ConsistencyEvidence, DefaultReport, FusedVerdict, MagnitudeEvidence,
    NonEmptyModalities, PreparedReleaseAssessment,
};
pub use identity::{AssessmentBinding, AssessmentDigest, ConfigDigest};
pub use observation::{
    validate_and_symmetrize_covariance, ConsistencyProjection, Modality, PidObservation,
    COVARIANCE_SYMMETRY_RELATIVE_TOLERANCE, MAX_CONSISTENCY_PROJECTION_AXES,
};
pub use outcome::{
    AnomalyEvidence, AnomalyReason, AssessmentFailure, AssessmentOutcome, CollectingReason,
    EmptyReason, FailureCode, FailureKind, Insufficiency, NonEmptyModalitySet, OutcomeError,
    StreamState, TimeoutReason, UnavailabilityReason, UnavailabilityReasons, UnclassifiedAnomaly,
};
pub use window::{NisWindow, NIS_WINDOW_EXACT_CACHE_BYTES};

/// Default maximum sequence gap for a contiguous aligned series.
pub const DEFAULT_ALIGNMENT_MAX_SEQ_GAP: u64 = 1;

/// Default maximum timestamp span for one cross-modal aligned frame.
pub const DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS: u64 = 1_000;

/// Default maximum timestamp gap between successive samples of one modality.
pub const DEFAULT_ALIGNMENT_MAX_INTER_SAMPLE_GAP_MS: u64 = 10_000;

/// Maximum observations scanned by one direct consistency extraction.
///
/// This is slightly above six full maximum correlation windows. Callers handling
/// longer recordings must feed bounded tails or segment them by session/track.
pub const MAX_CONSISTENCY_INPUT_OBSERVATIONS: usize = 400_000;

/// Maximum fusion sequences retained while aligning a consistency projection.
pub const MAX_CONSISTENCY_RETAINED_FRAMES: usize = correlation::MAX_CORRELATION_WINDOW;

fn validate_consistency_input_len(length: usize) -> Result<()> {
    if length > MAX_CONSISTENCY_INPUT_OBSERVATIONS {
        return Err(GaladrielError::InvalidChannels(format!(
            "consistency input has {length} observations; maximum is {MAX_CONSISTENCY_INPUT_OBSERVATIONS}"
        )));
    }
    Ok(())
}

/// Sequence-aligned common projections for every producer-declared axis.
///
/// `axes[axis]` contains one signed series per requested modality. `frame_id` and
/// `context_id` identify the shared physical frame and projection definition for
/// the retained suffix. Prior identifiers are checked across the full bounded input,
/// including frame/context changes, but are not retained because each sequence must
/// use a different frozen snapshot.
#[derive(Debug, Clone)]
pub struct ConsistencyChannels {
    /// Common physical coordinate-frame identifier.
    pub frame_id: ProjectionFrameId,
    /// Common projection/calibration-context identifier.
    pub context_id: ProjectionContextId,
    /// One aligned channel set per active projection axis.
    pub axes: Vec<Vec<(Modality, Vec<f64>)>>,
}

/// Extract one producer-attested consistency-projection axis.
///
/// This never falls back to [`PidObservation::innovation`]. A legacy stream with no
/// consistency projection returns empty channels, allowing the NIS baseline to run
/// while consistency fusion fails closed.
pub fn scalar_channels(
    stream: &[PidObservation],
    modalities: &[Modality],
    axis: usize,
) -> Result<Vec<(Modality, Vec<f64>)>> {
    scalar_channels_with_limits(
        stream,
        modalities,
        axis,
        DEFAULT_ALIGNMENT_MAX_SEQ_GAP,
        DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS,
    )
}

/// Extract one producer-attested projection axis with explicit temporal limits.
///
/// An incomplete frame, an excessive sequence hole, or excessive cross-modal
/// timestamp skew resets the retained suffix. A frozen or regressing timestamp
/// within one modality is malformed input and returns an error. This compatibility
/// wrapper uses [`DEFAULT_ALIGNMENT_MAX_INTER_SAMPLE_GAP_MS`] for forward gaps.
pub fn scalar_channels_with_limits(
    stream: &[PidObservation],
    modalities: &[Modality],
    axis: usize,
    max_seq_gap: u64,
    max_timestamp_skew_ms: u64,
) -> Result<Vec<(Modality, Vec<f64>)>> {
    scalar_channels_with_temporal_limits(
        stream,
        modalities,
        axis,
        max_seq_gap,
        max_timestamp_skew_ms,
        DEFAULT_ALIGNMENT_MAX_INTER_SAMPLE_GAP_MS,
    )
}

/// Extract one producer-attested projection axis with all temporal limits explicit.
///
/// Frozen or regressing per-modality timestamps are malformed. A forward timestamp
/// gap beyond `max_inter_sample_gap_ms` starts a new suffix, as do incomplete frames,
/// excessive sequence holes, and excessive cross-modal timestamp skew.
pub fn scalar_channels_with_temporal_limits(
    stream: &[PidObservation],
    modalities: &[Modality],
    axis: usize,
    max_seq_gap: u64,
    max_timestamp_skew_ms: u64,
    max_inter_sample_gap_ms: u64,
) -> Result<Vec<(Modality, Vec<f64>)>> {
    if axis >= MAX_CONSISTENCY_PROJECTION_AXES {
        return Err(GaladrielError::InvalidChannels(format!(
            "consistency projection axis must be in 0..{MAX_CONSISTENCY_PROJECTION_AXES} (got {axis})"
        )));
    }
    let Some(channels) = consistency_channels_with_temporal_limits(
        stream,
        modalities,
        max_seq_gap,
        max_timestamp_skew_ms,
        max_inter_sample_gap_ms,
    )?
    else {
        return Ok(modalities
            .iter()
            .map(|&modality| (modality, Vec::new()))
            .collect());
    };
    channels.axes.get(axis).cloned().ok_or_else(|| {
        GaladrielError::InvalidChannels(format!(
            "consistency projection has {} active axes; axis {axis} is unavailable",
            channels.axes.len()
        ))
    })
}

/// Extract every active producer-attested consistency-projection axis.
///
/// Only a newest contiguous, timestamp-coherent suffix is retained. Every complete
/// frame must attest the same physical frame, projection context, dimension, and
/// frozen prior across requested modalities. A prior identifier may not be reused
/// at another sequence. A context/frame change begins a new suffix; contradictory
/// within-frame provenance is malformed input. Frames where every modality omits
/// the optional projection reset the suffix and ultimately return `None` for a
/// legacy capture. A requested modality slice larger than the closed six-variant
/// vocabulary is rejected before set allocation or stream scanning.
pub fn consistency_channels_with_temporal_limits(
    stream: &[PidObservation],
    modalities: &[Modality],
    max_seq_gap: u64,
    max_timestamp_skew_ms: u64,
    max_inter_sample_gap_ms: u64,
) -> Result<Option<ConsistencyChannels>> {
    use std::collections::{BTreeMap, HashMap, HashSet};

    if modalities.len() > Modality::ALL.len() {
        return Err(GaladrielError::InvalidChannels(format!(
            "consistency extraction accepts at most {} modalities, got {}",
            Modality::ALL.len(),
            modalities.len()
        )));
    }
    validate_consistency_input_len(stream.len())?;
    crate::config::validate_alignment_limits(
        max_seq_gap,
        max_timestamp_skew_ms,
        max_inter_sample_gap_ms,
    )?;
    let requested: HashSet<Modality> = modalities.iter().copied().collect();
    if requested.len() != modalities.len() {
        return Err(GaladrielError::InvalidChannels(
            "requested modalities must be unique".into(),
        ));
    }
    if stream.is_empty() || modalities.is_empty() {
        return Ok(None);
    }

    let track_id = stream[0].track_id();
    let mut last_seq = None;
    let mut last_timestamp = HashMap::<Modality, TimestampMillis>::new();
    let mut temporal_breaks = HashSet::<Sequence>::new();
    let mut prior_sequences = HashMap::<FrozenPriorId, Sequence>::new();
    prior_sequences.try_reserve(stream.len()).map_err(|_| {
        GaladrielError::InvalidChannels(format!(
            "could not reserve provenance tracking for {} observations",
            stream.len()
        ))
    })?;
    let mut frames: BTreeMap<
        Sequence,
        HashMap<Modality, (Option<&ConsistencyProjection>, TimestampMillis)>,
    > = BTreeMap::new();
    for observation in stream {
        let observation_track_id = observation.track_id();
        let sequence = observation.sequence();
        let timestamp_ms = observation.timestamp_ms();
        let modality = observation.modality();
        if observation_track_id != track_id {
            return Err(GaladrielError::InvalidChannels(format!(
                "single-track analysis required (saw track {track_id} and {})",
                observation_track_id
            )));
        }
        if last_seq.is_some_and(|last| sequence < last) {
            return Err(GaladrielError::InvalidChannels(format!(
                "stream sequence regressed from {} to {}; captures must contain one run in order",
                last_seq.map_or(0, Sequence::get),
                sequence
            )));
        }
        last_seq = Some(sequence);

        if let Some(projection) = observation.consistency_projection() {
            let frozen_prior_id = projection.identity().frozen_prior_id();
            if let Some(previous_sequence) = prior_sequences.insert(frozen_prior_id, sequence) {
                if previous_sequence != sequence {
                    return Err(GaladrielError::InvalidChannels(format!(
                        "frozen prior {} was reused at sequences {previous_sequence} and {}",
                        frozen_prior_id, sequence
                    )));
                }
            }
        }

        if !requested.contains(&modality) {
            continue;
        }
        if let Some(&timestamp) = last_timestamp.get(&modality) {
            if timestamp_ms <= timestamp {
                return Err(GaladrielError::InvalidChannels(format!(
                    "timestamp must increase strictly for {} at sequence {}",
                    modality.label(),
                    sequence
                )));
            }
            if timestamp_ms.get() - timestamp.get() > max_inter_sample_gap_ms {
                temporal_breaks.insert(sequence);
            }
        }
        last_timestamp.insert(modality, timestamp_ms);
        let frame = frames.entry(sequence).or_default();
        if frame
            .insert(
                modality,
                (observation.consistency_projection(), timestamp_ms),
            )
            .is_some()
        {
            return Err(GaladrielError::InvalidChannels(format!(
                "duplicate consistency observation for sequence {} / {}",
                sequence,
                modality.label()
            )));
        }
        while frames.len() > MAX_CONSISTENCY_RETAINED_FRAMES {
            if let Some((evicted_sequence, _)) = frames.pop_first() {
                temporal_breaks.remove(&evicted_sequence);
            }
        }
    }

    let empty_axis = || {
        modalities
            .iter()
            .map(|&modality| (modality, Vec::new()))
            .collect::<Vec<_>>()
    };
    let mut aligned: Vec<Vec<(Modality, Vec<f64>)>> = Vec::new();
    let mut suffix_provenance = None::<(ProjectionFrameId, ProjectionContextId, u8)>;
    let mut last_aligned_seq = None::<Sequence>;
    for (sequence, frame) in frames {
        if !modalities
            .iter()
            .all(|modality| frame.contains_key(modality))
        {
            aligned.clear();
            suffix_provenance = None;
            last_aligned_seq = None;
            continue;
        }
        let present = modalities
            .iter()
            .filter(|modality| frame[modality].0.is_some())
            .count();
        if present == 0 {
            aligned.clear();
            suffix_provenance = None;
            last_aligned_seq = None;
            continue;
        }
        if present != modalities.len() {
            return Err(GaladrielError::InvalidChannels(format!(
                "consistency projection is only partially present at sequence {sequence}"
            )));
        }
        let projections = modalities
            .iter()
            .filter_map(|modality| frame.get(modality).and_then(|sample| sample.0))
            .collect::<Vec<_>>();
        let Some(first) = projections.first().copied() else {
            return Err(GaladrielError::InvalidChannels(format!(
                "consistency projection disappeared at sequence {sequence}"
            )));
        };
        let first_identity = first.identity();
        let provenance = (
            first_identity.frame_id(),
            first_identity.context_id(),
            first.dimensions(),
        );
        if projections.iter().any(|projection| {
            let identity = projection.identity();
            (
                identity.frame_id(),
                identity.context_id(),
                projection.dimensions(),
            ) != provenance
                || identity.frozen_prior_id() != first_identity.frozen_prior_id()
        }) {
            return Err(GaladrielError::InvalidChannels(format!(
                "modalities attest different frame/context/dimension/prior at sequence {sequence}"
            )));
        }
        let (minimum_timestamp, maximum_timestamp) = modalities
            .iter()
            .map(|modality| frame[modality].1)
            .fold((u64::MAX, 0_u64), |(minimum, maximum), timestamp| {
                (minimum.min(timestamp.get()), maximum.max(timestamp.get()))
            });
        let sequence_contiguous =
            last_aligned_seq.is_none_or(|last| sequence.get() - last.get() <= max_seq_gap);
        let timestamp_coherent = maximum_timestamp - minimum_timestamp <= max_timestamp_skew_ms;
        let timestamps_contiguous = !temporal_breaks.contains(&sequence);
        let provenance_contiguous = suffix_provenance.is_none_or(|value| value == provenance);
        if !sequence_contiguous
            || !timestamp_coherent
            || !timestamps_contiguous
            || !provenance_contiguous
        {
            aligned.clear();
            suffix_provenance = None;
            last_aligned_seq = None;
        }
        if timestamp_coherent {
            if aligned.is_empty() {
                aligned = (0..first.dimensions()).map(|_| empty_axis()).collect();
            }
            for (axis, channels) in aligned.iter_mut().enumerate() {
                for (modality, values) in channels {
                    let projection =
                        frame
                            .get(modality)
                            .and_then(|sample| sample.0)
                            .ok_or_else(|| {
                                GaladrielError::InvalidChannels(format!(
                                "consistency projection disappeared for {} at sequence {sequence}",
                                modality.label()
                            ))
                            })?;
                    values.push(projection.values()[axis]);
                }
            }
            suffix_provenance = Some(provenance);
            last_aligned_seq = Some(sequence);
        }
    }
    let Some((frame_id, context_id, _)) = suffix_provenance else {
        return Ok(None);
    };
    Ok(Some(ConsistencyChannels {
        frame_id,
        context_id,
        axes: aligned,
    }))
}

#[cfg(test)]
mod scalar_channel_tests {
    use super::*;

    fn research(seq: u64, modality: Modality, value: f64) -> PidObservation {
        research_with(1, seq * 100, seq, modality, value, 1, 1, seq + 1)
    }

    #[test]
    fn seven_modalities_are_rejected_before_set_allocation_or_stream_scans() {
        let modalities = [
            Modality::Visual,
            Modality::Thermal,
            Modality::Acoustic,
            Modality::Radar,
            Modality::Lidar,
            Modality::RadioFrequency,
            Modality::Visual,
        ];

        let direct = consistency_channels_with_temporal_limits(&[], &modalities, 0, u64::MAX, 0)
            .unwrap_err();
        let scalar = scalar_channels(&[], &modalities, 0).unwrap_err();

        assert!(matches!(
            direct,
            GaladrielError::InvalidChannels(ref message)
                if message == "consistency extraction accepts at most 6 modalities, got 7"
        ));
        assert!(matches!(
            scalar,
            GaladrielError::InvalidChannels(ref message)
                if message == "consistency extraction accepts at most 6 modalities, got 7"
        ));
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "test fixture names every wire coordinate"
    )]
    fn research_with(
        track_id: u64,
        timestamp_ms: u64,
        sequence: u64,
        modality: Modality,
        value: f64,
        frame_id: u64,
        context_id: u64,
        frozen_prior_id: u64,
    ) -> PidObservation {
        PidObservation::try_scalar(
            TrackId::new(track_id).unwrap(),
            TimestampMillis::new(timestamp_ms).unwrap(),
            Sequence::new(sequence).unwrap(),
            modality,
            3.0,
            3,
        )
        .unwrap()
        .try_with_research(
            [value, 0.0, 0.0],
            [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
        )
        .unwrap()
        .with_consistency_projection(
            ConsistencyProjection::try_new(
                [value, value + 1.0, value + 2.0],
                3,
                ProjectionIdentity::try_new(frame_id, context_id, frozen_prior_id).unwrap(),
            )
            .unwrap(),
        )
    }

    fn baseline_only(seq: u64, modality: Modality) -> PidObservation {
        PidObservation::try_scalar(
            TrackId::new(1).unwrap(),
            TimestampMillis::new(seq * 100).unwrap(),
            Sequence::new(seq).unwrap(),
            modality,
            3.0,
            3,
        )
        .unwrap()
    }

    fn research_without_projection(seq: u64, modality: Modality, value: f64) -> PidObservation {
        baseline_only(seq, modality)
            .try_with_research(
                [value, 0.0, 0.0],
                [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
            )
            .unwrap()
    }

    #[test]
    fn alignment_resets_after_a_dropped_sequence() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research(0, Modality::Visual, 10.0),
            research(0, Modality::Radar, 20.0),
            research(1, Modality::Visual, 11.0),
            research(2, Modality::Visual, 12.0),
            research(2, Modality::Radar, 22.0),
        ];
        let channels = scalar_channels(&stream, &modalities, 0).unwrap();
        assert_eq!(channels[0].1, vec![12.0]);
        assert_eq!(channels[1].1, vec![22.0]);
    }

    #[test]
    fn rejects_ambiguous_track_order_and_axis_inputs() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research(1, Modality::Visual, 1.0),
            research_with(2, 100, 1, Modality::Radar, 1.0, 1, 1, 2),
        ];
        assert!(scalar_channels(&stream, &modalities, 0).is_err());
        assert!(scalar_channels(&[], &modalities, 3).is_err());
    }

    #[test]
    fn alignment_rejects_timestamp_regression_and_resets_on_skew() {
        let modalities = [Modality::Visual, Modality::Radar];
        let regressed = vec![
            research_with(1, 100, 0, Modality::Visual, 1.0, 1, 1, 1),
            research(0, Modality::Radar, 1.0),
            research_with(1, 0, 1, Modality::Visual, 2.0, 1, 1, 2),
            research(1, Modality::Radar, 2.0),
        ];
        assert!(scalar_channels(&regressed, &modalities, 0).is_err());

        let skewed_timestamp = 100 + DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS + 1;
        let skewed = vec![
            research(0, Modality::Visual, 1.0),
            research(0, Modality::Radar, 1.0),
            research(1, Modality::Visual, 2.0),
            research_with(1, skewed_timestamp, 1, Modality::Radar, 2.0, 1, 1, 2),
            research_with(1, skewed_timestamp + 100, 2, Modality::Visual, 3.0, 1, 1, 3),
            research_with(1, skewed_timestamp + 100, 2, Modality::Radar, 3.0, 1, 1, 3),
        ];
        let channels = scalar_channels(&skewed, &modalities, 0).unwrap();
        assert_eq!(channels[0].1, vec![3.0]);
        assert_eq!(channels[1].1, vec![3.0]);
    }

    #[test]
    fn alignment_rejects_frozen_timestamps() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research(0, Modality::Visual, 1.0),
            research(0, Modality::Radar, 1.0),
            research_with(1, 0, 1, Modality::Visual, 2.0, 1, 1, 2),
            research(1, Modality::Radar, 2.0),
        ];
        assert!(scalar_channels(&stream, &modalities, 0).is_err());
    }

    #[test]
    fn alignment_resets_after_a_large_forward_timestamp_gap() {
        let modalities = [Modality::Visual, Modality::Radar];
        let mut stream = Vec::new();
        for sequence in 0..3 {
            let timestamp_ms = sequence * 100 + u64::from(sequence == 2);
            stream.push(research_with(
                1,
                timestamp_ms,
                sequence,
                Modality::Visual,
                sequence as f64,
                1,
                1,
                sequence + 1,
            ));
            stream.push(research_with(
                1,
                timestamp_ms,
                sequence,
                Modality::Radar,
                sequence as f64,
                1,
                1,
                sequence + 1,
            ));
        }

        let channels = scalar_channels_with_temporal_limits(
            &stream,
            &modalities,
            0,
            1,
            DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS,
            100,
        )
        .unwrap();
        assert_eq!(channels[0].1, vec![2.0]);
        assert_eq!(channels[1].1, vec![2.0]);
    }

    #[test]
    fn alignment_does_not_reuse_stale_research_after_fields_disappear() {
        let modalities = [Modality::Visual, Modality::Radar];
        let mut stream = Vec::new();
        for sequence in 0..4 {
            stream.push(research(sequence, Modality::Visual, sequence as f64));
            stream.push(research(sequence, Modality::Radar, sequence as f64));
        }
        for sequence in 4..8 {
            stream.push(baseline_only(sequence, Modality::Visual));
            stream.push(baseline_only(sequence, Modality::Radar));
        }
        let channels = scalar_channels(&stream, &modalities, 0).unwrap();
        assert!(channels.iter().all(|(_, values)| values.is_empty()));
    }

    #[test]
    fn legacy_native_innovations_are_not_used_as_consistency_projections() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research_without_projection(0, Modality::Visual, 1.0),
            research_without_projection(0, Modality::Radar, 2.0),
        ];

        let channels = scalar_channels(&stream, &modalities, 0).unwrap();
        assert!(channels.iter().all(|(_, values)| values.is_empty()));
    }

    #[test]
    fn extraction_rejects_different_frozen_priors_within_one_sequence() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research(0, Modality::Visual, 1.0),
            research_with(1, 0, 0, Modality::Radar, 2.0, 1, 1, 2),
        ];

        assert!(scalar_channels(&stream, &modalities, 0).is_err());
    }

    #[test]
    fn extraction_rejects_prior_reuse_across_sequences() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research(0, Modality::Visual, 1.0),
            research(0, Modality::Radar, 2.0),
            research_with(1, 100, 1, Modality::Visual, 3.0, 1, 1, 1),
            research_with(1, 100, 1, Modality::Radar, 4.0, 1, 1, 1),
        ];

        assert!(scalar_channels(&stream, &modalities, 0).is_err());
    }

    #[test]
    fn extraction_rejects_prior_reuse_after_frame_and_context_change() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research(0, Modality::Visual, 1.0),
            research(0, Modality::Radar, 2.0),
            research_with(1, 100, 1, Modality::Visual, 3.0, 2, 2, 1),
            research_with(1, 100, 1, Modality::Radar, 4.0, 2, 2, 1),
        ];

        let error = scalar_channels(&stream, &modalities, 0).unwrap_err();

        assert_eq!(
            error,
            GaladrielError::InvalidChannels(
                "frozen prior 1 was reused at sequences 0 and 1".into()
            )
        );
    }

    #[test]
    fn extraction_rejects_prior_reuse_on_unrequested_modalities() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research(0, Modality::Thermal, 1.0),
            research_with(1, 100, 1, Modality::Thermal, 2.0, 1, 1, 1),
        ];

        let error = scalar_channels(&stream, &modalities, 0).unwrap_err();

        assert_eq!(
            error,
            GaladrielError::InvalidChannels(
                "frozen prior 1 was reused at sequences 0 and 1".into()
            )
        );
    }

    #[test]
    fn extraction_returns_every_attested_axis() {
        let modalities = [Modality::Visual, Modality::Radar];
        let stream = vec![
            research(0, Modality::Visual, 1.0),
            research(0, Modality::Radar, 2.0),
        ];
        let channels = consistency_channels_with_temporal_limits(
            &stream,
            &modalities,
            1,
            DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS,
            DEFAULT_ALIGNMENT_MAX_INTER_SAMPLE_GAP_MS,
        )
        .unwrap()
        .unwrap();

        assert_eq!(channels.axes.len(), 3);
        assert_eq!(channels.axes[2][1].1, vec![4.0]);
    }

    #[test]
    fn consistency_input_work_is_explicitly_bounded() {
        assert!(validate_consistency_input_len(MAX_CONSISTENCY_INPUT_OBSERVATIONS).is_ok());
        assert!(validate_consistency_input_len(MAX_CONSISTENCY_INPUT_OBSERVATIONS + 1).is_err());
    }

    #[test]
    fn extraction_rejects_disabled_or_unbounded_temporal_limits_even_when_empty() {
        let modalities = [Modality::Visual, Modality::Radar];
        for (max_seq_gap, max_timestamp_skew_ms, max_inter_sample_gap_ms) in [
            (0, DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS, 1),
            (u64::MAX, DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS, 1),
            (1, u64::MAX, 1),
            (1, DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS, 0),
            (1, DEFAULT_ALIGNMENT_MAX_TIMESTAMP_SKEW_MS, u64::MAX),
        ] {
            assert!(consistency_channels_with_temporal_limits(
                &[],
                &modalities,
                max_seq_gap,
                max_timestamp_skew_ms,
                max_inter_sample_gap_ms,
            )
            .is_err());
        }
    }

    #[test]
    fn extraction_accepts_inclusive_temporal_limit_boundaries() {
        let modalities = [Modality::Visual, Modality::Radar];
        for max_timestamp_skew_ms in [0, MAX_ALIGNMENT_TIMESTAMP_SKEW_MS] {
            assert!(consistency_channels_with_temporal_limits(
                &[],
                &modalities,
                MAX_ALIGNMENT_SEQ_GAP,
                max_timestamp_skew_ms,
                MAX_INTER_SAMPLE_GAP_MS,
            )
            .is_ok());
        }
    }

    #[test]
    fn prior_reuse_is_rejected_after_the_original_frame_leaves_the_tail() {
        let modalities = [Modality::Visual];
        let frame_count = MAX_CONSISTENCY_RETAINED_FRAMES as u64 + 2;
        let mut stream = Vec::with_capacity(frame_count as usize);
        for sequence in 0..frame_count {
            let frozen_prior_id = if sequence + 1 == frame_count {
                1
            } else {
                sequence + 1
            };
            stream.push(research_with(
                1,
                sequence * 100,
                sequence,
                Modality::Visual,
                sequence as f64,
                1,
                1,
                frozen_prior_id,
            ));
        }

        assert!(scalar_channels(&stream, &modalities, 0).is_err());
    }
}
