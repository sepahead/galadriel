//! The fail-closed magnitude-evidence decision and the streaming [`Mirror`] detector.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::baseline;
use crate::config::{
    AssessmentClassification, DetectorConfig, ExploratorySubsetResearch, ReleaseSuite,
};
use crate::cusum::Cusum;
use crate::domain::{Sequence, TimestampMillis, TrackId};
use crate::observation::{Modality, PidObservation};
use crate::outcome::{
    AnomalyEvidence, AnomalyReason, AssessmentFailure, AssessmentOutcome, CollectingReason,
    EmptyReason, FailureCode, Insufficiency, NonEmptyModalitySet, UnavailabilityReason,
    UnavailabilityReasons, UnclassifiedAnomaly,
};
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
    /// Every ready channel's windowed NIS is consistent with χ²(dof), and no
    /// CUSUM arm is in alarm.
    Nominal,
    /// One or a minority of channels has localized high-direction NIS/CUSUM
    /// inconsistency. This names statistical evidence, not an attack cause.
    AttributedInconsistency { channels: Vec<Modality> },
    /// Most/all channels have broad high-direction NIS/CUSUM evidence consistent
    /// with degradation.
    BroadDegradation,
    /// Positive anomaly evidence exists, but missing/stale peers or a below-target
    /// shift prevents a narrower statistical classification.
    UnclassifiedAnomaly { channels: Vec<Modality> },
    /// Too few ready channels or samples to decide. **Fail closed** — never
    /// silently upgraded to `Nominal`.
    InsufficientEvidence,
}

/// Output-only per-channel detail behind a [`MirrorReport`].
///
/// Fields are private and there is no public constructor or `Deserialize`
/// implementation, so accepted evidence can only come from [`Mirror::assess`].
///
/// ```compile_fail
/// use galadriel_core::ChannelReport;
/// let _ = ChannelReport { n: 1 };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelReport {
    /// Which modality this channel is.
    modality: Modality,
    /// Samples in the channel window.
    n: usize,
    /// Immutable χ² degrees of freedom per retained sample.
    dof: u8,
    /// Correctly rounded retained NIS sum, saturated at `f64::MAX`.
    sum_nis: f64,
    /// Newest fusion sequence accepted for this channel, or `None` if an expected
    /// channel has not produced an observation.
    last_seq: Option<Sequence>,
    /// Timestamp of the newest accepted measurement, or `None` for a missing
    /// expected channel.
    last_timestamp_ms: Option<TimestampMillis>,
    /// Mean NIS over the window (≈ `dof` when healthy).
    mean_nis: f64,
    /// Right-tail p-value of the windowed NIS sum.
    p_right: f64,
    /// Effective Bonferroni-corrected per-channel threshold.
    channel_alpha: f64,
    /// Whether the windowed NIS test flagged this channel elevated.
    elevated: bool,
    /// Whether this channel's above-target CUSUM arm is in alarm.
    cusum_high_alarm: bool,
    /// Whether this channel's below-target CUSUM arm is in alarm.
    cusum_low_alarm: bool,
    /// Whether the newest observation is within the configured sequence gap.
    fresh: bool,
    /// Whether the window has reached `min_samples` and this channel contributed
    /// to the report's exact fusion sequence.
    ready: bool,
}

impl ChannelReport {
    /// Channel modality.
    pub const fn modality(&self) -> Modality {
        self.modality
    }
    /// Exact retained sample count.
    pub const fn n(&self) -> usize {
        self.n
    }
    /// Immutable χ² degrees of freedom per sample.
    pub const fn dof(&self) -> u8 {
        self.dof
    }
    /// Correctly rounded or saturated NIS sum.
    pub const fn sum_nis(&self) -> f64 {
        self.sum_nis
    }
    /// Newest accepted fusion sequence, if the channel exists.
    pub const fn last_seq(&self) -> Option<Sequence> {
        self.last_seq
    }
    /// Newest accepted timestamp, if the channel exists.
    pub const fn last_timestamp_ms(&self) -> Option<TimestampMillis> {
        self.last_timestamp_ms
    }
    /// Mean NIS over the retained window.
    pub const fn mean_nis(&self) -> f64 {
        self.mean_nis
    }
    /// Right-tail χ² probability.
    pub const fn p_right(&self) -> f64 {
        self.p_right
    }
    /// Effective per-channel significance threshold.
    pub const fn channel_alpha(&self) -> f64 {
        self.channel_alpha
    }
    /// Whether the windowed NIS test is elevated.
    pub const fn elevated(&self) -> bool {
        self.elevated
    }
    /// Whether the high CUSUM arm is in alarm.
    pub const fn cusum_high_alarm(&self) -> bool {
        self.cusum_high_alarm
    }
    /// Whether the low CUSUM arm is in alarm.
    pub const fn cusum_low_alarm(&self) -> bool {
        self.cusum_low_alarm
    }
    /// Whether retained evidence is within the configured sequence gap.
    pub const fn fresh(&self) -> bool {
        self.fresh
    }
    /// Whether this channel contributes to the exact assessed frame.
    pub const fn ready(&self) -> bool {
        self.ready
    }

    /// Whether this channel is currently flagged anomalous (elevated or CUSUM alarm).
    pub fn anomalous(&self) -> bool {
        self.ready && (self.high_anomalous() || self.cusum_low_alarm)
    }

    /// Whether this channel has evidence of NIS inflation.
    pub fn high_anomalous(&self) -> bool {
        self.ready && (self.elevated || self.cusum_high_alarm)
    }

    #[cfg(test)]
    pub(crate) fn test_ready(modality: Modality, elevated: bool) -> Self {
        Self {
            modality,
            n: 64,
            dof: 3,
            sum_nis: if elevated { 1_280.0 } else { 192.0 },
            last_seq: Some(Sequence::new(100).expect("test sequence")),
            last_timestamp_ms: Some(TimestampMillis::new(10_000).expect("test timestamp")),
            mean_nis: if elevated { 20.0 } else { 3.0 },
            p_right: if elevated { 1e-9 } else { 0.5 },
            channel_alpha: 0.01 / 3.0,
            elevated,
            cusum_high_alarm: elevated,
            cusum_low_alarm: false,
            fresh: true,
            ready: true,
        }
    }
}

/// The sealed, output-only advisory report for one track and assessment frame.
///
/// The typed outcome is created at the same time as the visible report and kept
/// privately. Fusion consumes that retained value; it never reconstructs an
/// outcome from externally mutable fields.
///
/// ```compile_fail
/// use galadriel_core::{MirrorReport, Verdict};
/// let _ = MirrorReport { verdict: Verdict::Nominal };
/// ```
///
/// ```compile_fail
/// use galadriel_core::MirrorReport;
/// let _: MirrorReport = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MirrorReport {
    /// Track this report concerns.
    track_id: TrackId,
    /// Fusion frame counter at assessment time.
    seq: Sequence,
    /// The advisory verdict.
    verdict: Verdict,
    /// Per-channel detail, in stable modality order.
    channels: Vec<ChannelReport>,
    /// A short human-readable rationale.
    note: String,
    /// Release or exploratory research classification.
    classification: AssessmentClassification,
    /// Complete accepted detector/suite identity.
    config_identity: crate::ConfigDigest,
    /// Config-bound coherent outcome created during assessment.
    #[serde(skip)]
    accepted_outcome: AssessmentOutcome,
    /// Exact whole-stream binding when this magnitude report was produced as one
    /// component of an accepted release assessment.
    #[serde(skip)]
    assessment_binding: Option<crate::AssessmentBinding>,
}

impl MirrorReport {
    /// Track this report concerns.
    pub const fn track_id(&self) -> TrackId {
        self.track_id
    }
    /// Fusion sequence assessed.
    pub const fn sequence(&self) -> Sequence {
        self.seq
    }
    /// Advisory statistical-consistency verdict.
    pub const fn verdict(&self) -> &Verdict {
        &self.verdict
    }
    /// Per-channel details in stable modality order.
    pub fn channels(&self) -> &[ChannelReport] {
        &self.channels
    }
    /// Human-readable, non-normative rationale.
    pub fn note(&self) -> &str {
        &self.note
    }
    /// Release or exploratory research classification.
    pub const fn classification(&self) -> AssessmentClassification {
        self.classification
    }
    /// Canonical complete accepted detector/suite identity.
    pub const fn config_identity(&self) -> crate::ConfigDigest {
        self.config_identity
    }
    /// Return a release-safe coherent outcome.
    ///
    /// A magnitude-only nominal result is not a completed release-suite result:
    /// the signed-consistency prerequisite has not run. Such a result is therefore
    /// exposed as explicitly unavailable until accepted fusion completes. Positive
    /// magnitude evidence and already-insufficient outcomes are preserved.
    pub fn validated_outcome(&self) -> AssessmentOutcome {
        if matches!(self.accepted_outcome, AssessmentOutcome::Nominal)
            && matches!(
                self.classification,
                AssessmentClassification::NamedRelease(_)
                    | AssessmentClassification::CustomReleaseSuite
            )
        {
            AssessmentOutcome::Insufficient(Insufficiency::Unavailable(
                UnavailabilityReasons::unavailable_prerequisite(),
            ))
        } else {
            self.accepted_outcome.clone()
        }
    }

    /// Exact accepted whole-stream binding, if release preparation produced this
    /// magnitude component.
    pub const fn assessment_binding(&self) -> Option<&crate::AssessmentBinding> {
        self.assessment_binding.as_ref()
    }

    pub(crate) fn magnitude_outcome(&self) -> AssessmentOutcome {
        self.accepted_outcome.clone()
    }

    pub(crate) fn bind_assessment(&mut self, binding: crate::AssessmentBinding) {
        self.assessment_binding = Some(binding);
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(verdict: Verdict, channels: Vec<ChannelReport>) -> Self {
        let sequence = Sequence::new(100).expect("test sequence");
        let outcome =
            accepted_outcome(&verdict, &channels, sequence).expect("coherent test report");
        let config = DetectorConfig::standalone_advisory_v0_9().expect("test config");
        Self {
            track_id: TrackId::new(1).expect("test track"),
            seq: sequence,
            verdict,
            channels,
            note: "test fixture".to_string(),
            classification: AssessmentClassification::ExploratoryResearch(
                crate::ExploratoryResearchProfile::SubsetMagnitudeV0_9,
            ),
            config_identity: config.identity(),
            accepted_outcome: outcome,
            assessment_binding: None,
        }
    }
}

fn unavailable_outcome(reason: UnavailabilityReason) -> crate::Result<AssessmentOutcome> {
    let reasons = UnavailabilityReasons::try_new([reason])
        .map_err(|error| crate::GaladrielError::InvalidObservation(error.to_string()))?;
    Ok(AssessmentOutcome::Insufficient(Insufficiency::Unavailable(
        reasons,
    )))
}

fn accepted_outcome(
    verdict: &Verdict,
    channels: &[ChannelReport],
    sequence: Sequence,
) -> crate::Result<AssessmentOutcome> {
    match verdict {
        Verdict::Nominal => Ok(AssessmentOutcome::Nominal),
        Verdict::AttributedInconsistency { channels } => {
            let modalities = NonEmptyModalitySet::try_new(channels.iter().copied())
                .map_err(|error| crate::GaladrielError::InvalidObservation(error.to_string()))?;
            Ok(AssessmentOutcome::Anomaly(AnomalyEvidence::Attributed(
                modalities,
            )))
        }
        Verdict::BroadDegradation => Ok(AssessmentOutcome::Anomaly(
            AnomalyEvidence::BroadDegradation,
        )),
        Verdict::UnclassifiedAnomaly { channels: affected } => {
            let mut reasons = vec![AnomalyReason::AmbiguousAttribution];
            if channels
                .iter()
                .any(|channel| channel.ready && channel.cusum_low_alarm)
            {
                reasons.push(AnomalyReason::LowSideShift);
            }
            let anomaly = UnclassifiedAnomaly::try_new(affected.iter().copied(), reasons)
                .map_err(|error| crate::GaladrielError::InvalidObservation(error.to_string()))?;
            Ok(AssessmentOutcome::Anomaly(AnomalyEvidence::Unclassified(
                anomaly,
            )))
        }
        Verdict::InsufficientEvidence => {
            if channels.is_empty() || channels.iter().all(|channel| channel.n == 0) {
                return Ok(AssessmentOutcome::Insufficient(Insufficiency::Empty(
                    EmptyReason::NoCompleteFrame,
                )));
            }
            if channels.iter().any(|channel| channel.last_seq.is_none()) {
                return unavailable_outcome(UnavailabilityReason::MissingModalities);
            }
            if channels
                .iter()
                .any(|channel| !channel.fresh || channel.last_seq != Some(sequence))
            {
                return unavailable_outcome(UnavailabilityReason::StaleRetainedEvidence);
            }
            if channels.iter().any(|channel| !channel.ready) {
                return Ok(AssessmentOutcome::Insufficient(Insufficiency::Collecting(
                    CollectingReason::InsufficientSamples,
                )));
            }
            unavailable_outcome(UnavailabilityReason::UnavailablePrerequisite)
        }
    }
}

/// Streaming cross-sensor consistency detector.
///
/// Feed it [`PidObservation`]s with [`Mirror::ingest`]; ask for a verdict with
/// [`Mirror::assess`], or do both with [`Mirror::ingest_and_assess`].
pub struct Mirror {
    cfg: DetectorConfig,
    tracks: HashMap<TrackId, HashMap<Modality, ChannelState>>,
    modality_contract: ModalityContract,
    classification: AssessmentClassification,
    config_identity: crate::ConfigDigest,
}

enum ModalityContract {
    Release(Vec<Modality>),
    ExploratorySubset,
}

impl ModalityContract {
    fn expected(&self) -> Option<&[Modality]> {
        match self {
            Self::Release(modalities) => Some(modalities),
            Self::ExploratorySubset => None,
        }
    }
}

fn bonferroni_channel_alpha(family_alpha: f64, channel_count: usize) -> f64 {
    family_alpha / channel_count.max(1) as f64
}

fn broad_degradation_criteria(
    high_anomalous: usize,
    ready_channels: usize,
    jam_fraction: f64,
) -> bool {
    high_anomalous >= 2 && high_anomalous as f64 >= jam_fraction * ready_channels as f64
}

#[derive(Debug, Clone)]
struct ChannelState {
    window: NisWindow,
    cusum: Cusum,
    last_seq: Sequence,
    last_timestamp_ms: TimestampMillis,
}

enum MirrorIngestError {
    Detector(crate::GaladrielError),
    ResetRequired(String),
}

impl From<crate::GaladrielError> for MirrorIngestError {
    fn from(error: crate::GaladrielError) -> Self {
        Self::Detector(error)
    }
}

impl MirrorIngestError {
    fn into_legacy(self) -> crate::GaladrielError {
        match self {
            Self::Detector(error) => error,
            Self::ResetRequired(diagnostic) => crate::GaladrielError::InvalidObservation(format!(
                "reset_required: {diagnostic}; establish a new stream generation before continuing"
            )),
        }
    }

    fn into_assessment_failure(self) -> AssessmentFailure {
        match self {
            Self::ResetRequired(diagnostic) => {
                AssessmentFailure::with_diagnostic(FailureCode::ResetRequired, &diagnostic)
            }
            Self::Detector(error) => {
                let code = match error {
                    crate::GaladrielError::InvalidConfig(_)
                    | crate::GaladrielError::DetectorConfig(_)
                    | crate::GaladrielError::ReleaseSuite(_)
                    | crate::GaladrielError::CorrelationConfig(_) => {
                        FailureCode::InvalidConfiguration
                    }
                    crate::GaladrielError::NonFinite(_) => FailureCode::NonFiniteInput,
                    crate::GaladrielError::TrackLimit { .. } => FailureCode::TrackCapacity,
                    crate::GaladrielError::InsufficientSamples { .. }
                    | crate::GaladrielError::InvalidObservation(_)
                    | crate::GaladrielError::InvalidChannels(_)
                    | crate::GaladrielError::AuthorityViolation(_) => {
                        FailureCode::InvalidObservation
                    }
                };
                AssessmentFailure::with_diagnostic(code, &error.to_string())
            }
        }
    }
}

impl ChannelState {
    fn cusum_coordinates(dof: u8, nis: f64) -> (f64, f64) {
        let scale = (2.0 * f64::from(dof)).sqrt();
        (f64::from(dof) / scale, nis / scale)
    }

    fn from_observation(cfg: &DetectorConfig, obs: &PidObservation) -> crate::Result<Self> {
        let mut window = NisWindow::new(cfg.window_len(), obs.dof())?;
        window.push(obs.nis())?;
        let (target, value) = Self::cusum_coordinates(obs.dof(), obs.nis());
        let mut cusum = Cusum::new(target, cfg.cusum_slack(), cfg.cusum_threshold())?;
        cusum.update(value)?;
        Ok(Self {
            window,
            cusum,
            last_seq: obs.sequence(),
            last_timestamp_ms: obs.timestamp_ms(),
        })
    }
}

impl Mirror {
    /// Construct the fail-closed release detector from one complete accepted suite.
    pub fn from_release_suite(suite: &ReleaseSuite) -> Self {
        Self {
            cfg: suite.detector().clone(),
            tracks: HashMap::new(),
            modality_contract: ModalityContract::Release(suite.expected_modalities().to_vec()),
            classification: suite.source_profile().map_or(
                AssessmentClassification::CustomReleaseSuite,
                AssessmentClassification::NamedRelease,
            ),
            config_identity: suite.identity(),
        }
    }

    /// Construct a subset-only research detector using an explicit opaque capability.
    ///
    /// This path does not carry an expected-modality set and therefore cannot be
    /// confused with the release path. It may report nominal for only the channels
    /// observed, subject to the detector's `min_channels` requirement.
    pub fn for_exploratory_subset(
        cfg: DetectorConfig,
        capability: ExploratorySubsetResearch,
    ) -> Self {
        let config_identity = capability.identity(&cfg);
        Self {
            cfg,
            tracks: HashMap::new(),
            modality_contract: ModalityContract::ExploratorySubset,
            classification: AssessmentClassification::ExploratoryResearch(capability.profile()),
            config_identity,
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &DetectorConfig {
        &self.cfg
    }

    /// Update per-channel state with one observation.
    ///
    /// A sequence or timestamp discontinuity returns an `invalid observation`
    /// error whose detail begins with `reset_required`; retained evidence is left
    /// untouched. New code that needs the closed machine code should use
    /// [`Mirror::ingest_checked`].
    pub fn ingest(&mut self, obs: &PidObservation) -> crate::Result<()> {
        self.ingest_inner(obs)
            .map_err(MirrorIngestError::into_legacy)
    }

    /// Update state while preserving typed reset-required failure semantics.
    ///
    /// Unlike the compatibility [`Mirror::ingest`] surface, this method returns
    /// [`FailureCode::ResetRequired`] directly for a sequence or timestamp hole.
    /// It never clears or replaces retained statistical state implicitly.
    pub fn ingest_checked(&mut self, obs: &PidObservation) -> Result<(), AssessmentFailure> {
        self.ingest_inner(obs)
            .map_err(MirrorIngestError::into_assessment_failure)
    }

    fn ingest_inner(&mut self, obs: &PidObservation) -> Result<(), MirrorIngestError> {
        let track_id = obs.track_id();
        let modality = obs.modality();
        let sequence = obs.sequence();
        let timestamp_ms = obs.timestamp_ms();
        if self
            .modality_contract
            .expected()
            .is_some_and(|expected| !expected.contains(&modality))
        {
            return Err(crate::GaladrielError::InvalidObservation(format!(
                "unexpected modality {} for this detector",
                modality.label()
            ))
            .into());
        }

        if let Some(channel) = self
            .tracks
            .get_mut(&track_id)
            .and_then(|channels| channels.get_mut(&modality))
        {
            if sequence <= channel.last_seq {
                return Err(crate::GaladrielError::InvalidObservation(format!(
                    "sequence must increase strictly for track {} / {} (last {}, got {})",
                    track_id,
                    modality.label(),
                    channel.last_seq,
                    sequence
                ))
                .into());
            }
            if obs.dof() != channel.window.dof() {
                return Err(crate::GaladrielError::InvalidObservation(format!(
                    "dof changed for track {} / {} (expected {}, got {}); reset the track first",
                    track_id,
                    modality.label(),
                    channel.window.dof(),
                    obs.dof()
                ))
                .into());
            }
            if timestamp_ms <= channel.last_timestamp_ms {
                return Err(crate::GaladrielError::InvalidObservation(format!(
                    "timestamp must increase strictly for track {} / {} (last {}, got {})",
                    track_id,
                    modality.label(),
                    channel.last_timestamp_ms,
                    timestamp_ms
                ))
                .into());
            }
            let sequence_gap = sequence.get() - channel.last_seq.get();
            let timestamp_gap = timestamp_ms.get() - channel.last_timestamp_ms.get();
            if sequence_gap > self.cfg.max_seq_gap()
                || timestamp_gap > self.cfg.max_inter_sample_gap_ms()
            {
                return Err(MirrorIngestError::ResetRequired(format!(
                    "track {track_id} / {} discontinuity (sequence gap {sequence_gap}, maximum {}; timestamp gap {timestamp_gap} ms, maximum {} ms)",
                    modality.label(),
                    self.cfg.max_seq_gap(),
                    self.cfg.max_inter_sample_gap_ms(),
                )));
            }

            // Validate the only stateful arithmetic on a tiny clone first. A
            // validated window push is then infallible without cloning its buffer.
            let mut next_cusum = channel.cusum.clone();
            let (_, value) = ChannelState::cusum_coordinates(obs.dof(), obs.nis());
            next_cusum.update(value)?;
            channel.window.push(obs.nis())?;
            channel.cusum = next_cusum;
            channel.last_seq = sequence;
            channel.last_timestamp_ms = timestamp_ms;
            return Ok(());
        }

        if !self.tracks.contains_key(&track_id) && self.tracks.len() >= self.cfg.max_tracks() {
            return Err(crate::GaladrielError::TrackLimit {
                limit: self.cfg.max_tracks(),
            }
            .into());
        }

        let state = ChannelState::from_observation(&self.cfg, obs)?;
        self.tracks
            .entry(track_id)
            .or_default()
            .insert(modality, state);
        Ok(())
    }

    /// Compute the current advisory report for `track_id`.
    pub fn assess(&self, track_id: TrackId, sequence: Sequence) -> crate::Result<MirrorReport> {
        let mut channels: Vec<ChannelReport> = Vec::new();
        let known = self.tracks.get(&track_id);
        let total_channels = known
            .into_iter()
            .flat_map(|states| states.keys().copied())
            .chain(
                self.modality_contract
                    .expected()
                    .into_iter()
                    .flatten()
                    .copied(),
            )
            .collect::<std::collections::HashSet<_>>()
            .len()
            .max(1);
        // `nis_alpha` is a per-assessment family-wise bound. Bonferroni keeps the
        // probability of any channel's window test false-alarming at or below it.
        let channel_alpha = bonferroni_channel_alpha(self.cfg.nis_alpha(), total_channels);
        for (&modality, state) in self.tracks.get(&track_id).into_iter().flatten() {
            let fresh = sequence
                .get()
                .checked_sub(state.last_seq.get())
                .is_some_and(|gap| gap <= self.cfg.max_seq_gap());
            let exact_sequence = state.last_seq == sequence;
            let stat = baseline::nis_consistency(&state.window, channel_alpha)?;
            channels.push(ChannelReport {
                modality,
                n: stat.n(),
                dof: stat.dof(),
                sum_nis: stat.sum_nis(),
                last_seq: Some(state.last_seq),
                last_timestamp_ms: Some(state.last_timestamp_ms),
                mean_nis: stat.mean_nis(),
                p_right: stat.p_right(),
                channel_alpha,
                elevated: stat.elevated(),
                cusum_high_alarm: state.cusum.high_alarm(),
                cusum_low_alarm: state.cusum.low_alarm(),
                fresh,
                ready: stat.n() >= self.cfg.min_samples() && fresh && exact_sequence,
            });
        }
        for &modality in self.modality_contract.expected().into_iter().flatten() {
            if channels.iter().any(|channel| channel.modality == modality) {
                continue;
            }
            channels.push(ChannelReport {
                modality,
                n: 0,
                dof: 0,
                sum_nis: 0.0,
                last_seq: None,
                last_timestamp_ms: None,
                mean_nis: 0.0,
                p_right: 1.0,
                channel_alpha,
                elevated: false,
                cusum_high_alarm: false,
                cusum_low_alarm: false,
                fresh: false,
                ready: false,
            });
        }
        // Deterministic channel order regardless of HashMap iteration order.
        channels.sort_by_key(|channel| channel.modality.stable_code());

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
                let timestamp = timestamp.get();
                Some(match range {
                    Some((minimum, maximum)) => (minimum.min(timestamp), maximum.max(timestamp)),
                    None => (timestamp, timestamp),
                })
            })
            .map_or(0, |(minimum, maximum)| maximum - minimum);
        let timestamps_coherent = timestamp_span <= self.cfg.max_timestamp_skew_ms();

        let all_channels_ready = !channels.is_empty() && ready.len() == channels.len();
        let enough_complete_evidence =
            ready.len() >= self.cfg.min_channels() && all_channels_ready && timestamps_coherent;
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
                    "only {}/{} channels sampled/exact-frame/temporally coherent (need at least {}, every known/expected channel ready at sequence {}, and timestamp span <= {} ms; observed span {} ms); failing closed",
                    ready.len(),
                    channels.len(),
                    self.cfg.min_channels(),
                    sequence,
                    self.cfg.max_timestamp_skew_ms(),
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
        } else if broad_degradation_criteria(
            high_anomalous.len(),
            ready.len(),
            self.cfg.jam_fraction(),
        ) {
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

        let outcome = accepted_outcome(&verdict, &channels, sequence)?;
        Ok(MirrorReport {
            track_id,
            seq: sequence,
            verdict,
            channels,
            note,
            classification: self.classification,
            config_identity: self.config_identity,
            accepted_outcome: outcome,
            assessment_binding: None,
        })
    }

    /// Ingest one observation and return the resulting report for its track.
    pub fn ingest_and_assess(&mut self, obs: &PidObservation) -> crate::Result<MirrorReport> {
        self.ingest(obs)?;
        self.assess(obs.track_id(), obs.sequence())
    }

    /// Compute a validated, coherent assessment outcome.
    ///
    /// This is the typed 0.9 decision surface. The legacy [`Mirror::assess`]
    /// report remains available for diagnostics and source compatibility.
    pub fn assess_outcome(
        &self,
        track_id: TrackId,
        sequence: Sequence,
    ) -> Result<AssessmentOutcome, AssessmentFailure> {
        let report = self
            .assess(track_id, sequence)
            .map_err(|error| MirrorIngestError::Detector(error).into_assessment_failure())?;
        Ok(report.validated_outcome())
    }

    /// Administratively evict retained state for one track.
    ///
    /// This is storage reclamation, not a statistical reset receipt. A caller must
    /// not continue the same stream generation after eviction; it must first record
    /// an authorized reset or epoch transition in its lifecycle layer.
    /// Returns whether the track existed.
    pub fn remove_track(&mut self, track_id: TrackId) -> bool {
        self.tracks.remove(&track_id).is_some()
    }

    /// Administratively evict all retained detector state.
    ///
    /// This is teardown/storage reclamation, not a collection of statistical reset
    /// receipts. Continuing any evicted stream requires a new authorized generation
    /// or epoch established by the lifecycle owner.
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
    use proptest::prelude::*;

    use super::*;

    fn outcome_channel(
        sequence: Option<Sequence>,
        n: usize,
        fresh: bool,
        ready: bool,
        low_alarm: bool,
    ) -> ChannelReport {
        ChannelReport {
            modality: Modality::Radar,
            n,
            dof: 3,
            sum_nis: 9.0,
            last_seq: sequence,
            last_timestamp_ms: Some(TimestampMillis::new(10).unwrap()),
            mean_nis: 3.0,
            p_right: 0.5,
            channel_alpha: 0.01,
            elevated: false,
            cusum_high_alarm: false,
            cusum_low_alarm: low_alarm,
            fresh,
            ready,
        }
    }

    #[test]
    fn channel_report_accessors_preserve_every_evidence_field() {
        let sequence = Sequence::new(37).unwrap();
        let timestamp = TimestampMillis::new(12_345).unwrap();
        let channel = ChannelReport {
            modality: Modality::Lidar,
            n: 29,
            dof: 7,
            sum_nis: 203.5,
            last_seq: Some(sequence),
            last_timestamp_ms: Some(timestamp),
            mean_nis: 7.017_241_379_310_345,
            p_right: 0.0125,
            channel_alpha: 0.0025,
            elevated: false,
            cusum_high_alarm: true,
            cusum_low_alarm: false,
            fresh: false,
            ready: true,
        };

        assert_eq!(channel.modality(), Modality::Lidar);
        assert_eq!(channel.n(), 29);
        assert_eq!(channel.dof(), 7);
        assert_eq!(channel.sum_nis(), 203.5);
        assert_eq!(channel.last_seq(), Some(sequence));
        assert_eq!(channel.last_timestamp_ms(), Some(timestamp));
        assert_eq!(channel.mean_nis(), 7.017_241_379_310_345);
        assert_eq!(channel.p_right(), 0.0125);
        assert_eq!(channel.channel_alpha(), 0.0025);
        assert!(!channel.elevated());
        assert!(channel.cusum_high_alarm());
        assert!(!channel.cusum_low_alarm());
        assert!(!channel.fresh());
        assert!(channel.ready());
        assert!(channel.high_anomalous());
        assert!(channel.anomalous());

        let not_ready = ChannelReport {
            ready: false,
            ..channel.clone()
        };
        assert!(!not_ready.high_anomalous());
        assert!(!not_ready.anomalous());

        let low_only = ChannelReport {
            elevated: false,
            cusum_high_alarm: false,
            cusum_low_alarm: true,
            ready: true,
            ..channel
        };
        assert!(!low_only.high_anomalous());
        assert!(low_only.anomalous());
    }

    #[test]
    fn channel_report_boolean_accessors_preserve_complementary_evidence() {
        let channel = ChannelReport {
            elevated: true,
            cusum_high_alarm: false,
            cusum_low_alarm: true,
            fresh: true,
            ready: false,
            ..outcome_channel(None, 0, false, false, false)
        };

        assert_eq!(
            (
                channel.elevated(),
                channel.cusum_high_alarm(),
                channel.cusum_low_alarm(),
                channel.fresh(),
                channel.ready(),
            ),
            (true, false, true, true, false)
        );
    }

    #[test]
    fn mirror_report_accessors_preserve_complete_sealed_evidence() {
        let channel = ChannelReport::test_ready(Modality::Thermal, true);
        let report = MirrorReport::test_fixture(Verdict::BroadDegradation, vec![channel.clone()]);

        assert_eq!(report.track_id(), TrackId::new(1).unwrap());
        assert_eq!(report.sequence(), Sequence::new(100).unwrap());
        assert_eq!(report.verdict(), &Verdict::BroadDegradation);
        assert_eq!(report.channels(), &[channel]);
        assert_eq!(report.note(), "test fixture");
        assert_eq!(
            report.classification(),
            AssessmentClassification::ExploratoryResearch(
                crate::ExploratoryResearchProfile::SubsetMagnitudeV0_9,
            )
        );
        assert_eq!(
            report.config_identity(),
            DetectorConfig::standalone_advisory_v0_9()
                .unwrap()
                .identity()
        );
        assert_eq!(
            report.validated_outcome(),
            AssessmentOutcome::Anomaly(AnomalyEvidence::BroadDegradation)
        );
        assert_eq!(report.assessment_binding(), None);
    }

    #[test]
    fn accepted_outcome_distinguishes_every_insufficiency_and_low_side_predicate() {
        let current = Sequence::new(10).unwrap();

        let zero = outcome_channel(Some(current), 0, true, true, false);
        assert_eq!(
            accepted_outcome(&Verdict::InsufficientEvidence, &[zero], current).unwrap(),
            AssessmentOutcome::Insufficient(Insufficiency::Empty(EmptyReason::NoCompleteFrame))
        );

        let missing = outcome_channel(None, 1, true, true, false);
        let AssessmentOutcome::Insufficient(Insufficiency::Unavailable(reasons)) =
            accepted_outcome(&Verdict::InsufficientEvidence, &[missing], current).unwrap()
        else {
            panic!("missing modalities must be typed unavailable evidence");
        };
        assert_eq!(
            reasons.as_slice(),
            &[UnavailabilityReason::MissingModalities]
        );

        for stale in [
            outcome_channel(Some(current), 1, false, true, false),
            outcome_channel(Some(Sequence::new(9).unwrap()), 1, true, true, false),
        ] {
            let AssessmentOutcome::Insufficient(Insufficiency::Unavailable(reasons)) =
                accepted_outcome(&Verdict::InsufficientEvidence, &[stale], current).unwrap()
            else {
                panic!("stale evidence must be typed unavailable evidence");
            };
            assert_eq!(
                reasons.as_slice(),
                &[UnavailabilityReason::StaleRetainedEvidence]
            );
        }

        let collecting = outcome_channel(Some(current), 1, true, false, false);
        assert_eq!(
            accepted_outcome(&Verdict::InsufficientEvidence, &[collecting], current).unwrap(),
            AssessmentOutcome::Insufficient(Insufficiency::Collecting(
                CollectingReason::InsufficientSamples,
            ))
        );

        let ready = outcome_channel(Some(current), 1, true, true, false);
        let AssessmentOutcome::Insufficient(Insufficiency::Unavailable(reasons)) =
            accepted_outcome(&Verdict::InsufficientEvidence, &[ready], current).unwrap()
        else {
            panic!("a ready magnitude-only report still lacks its prerequisite");
        };
        assert_eq!(
            reasons.as_slice(),
            &[UnavailabilityReason::UnavailablePrerequisite]
        );

        for (ready, low_alarm, expected_reasons) in [
            (false, true, vec![AnomalyReason::AmbiguousAttribution]),
            (true, false, vec![AnomalyReason::AmbiguousAttribution]),
            (
                true,
                true,
                vec![
                    AnomalyReason::LowSideShift,
                    AnomalyReason::AmbiguousAttribution,
                ],
            ),
        ] {
            let channel = outcome_channel(Some(current), 1, true, ready, low_alarm);
            let verdict = Verdict::UnclassifiedAnomaly {
                channels: vec![Modality::Radar],
            };
            let AssessmentOutcome::Anomaly(AnomalyEvidence::Unclassified(anomaly)) =
                accepted_outcome(&verdict, &[channel], current).unwrap()
            else {
                panic!("unclassified verdict must retain typed anomaly evidence");
            };
            assert_eq!(anomaly.affected_modalities(), &[Modality::Radar]);
            assert_eq!(anomaly.reasons(), expected_reasons);
        }
    }

    #[test]
    fn modality_contract_exposes_only_release_modalities() {
        let expected = [Modality::Visual, Modality::Radar];
        assert_eq!(
            ModalityContract::Release(expected.to_vec()).expected(),
            Some(expected.as_slice())
        );
        assert_eq!(ModalityContract::ExploratorySubset.expected(), None);

        assert_eq!(bonferroni_channel_alpha(0.03, 0), 0.03);
        assert_eq!(bonferroni_channel_alpha(0.03, 1), 0.03);
        assert_eq!(bonferroni_channel_alpha(0.03, 3), 0.03 / 3.0);
        assert_ne!(bonferroni_channel_alpha(0.03, 3), 0.03);

        assert!(broad_degradation_criteria(2, 4, 0.5));
        assert!(!broad_degradation_criteria(1, 2, 0.5));
        assert!(!broad_degradation_criteria(2, 6, 0.5));
    }
    use crate::config::{
        DetectorParams, ExploratoryResearchProfile, ProducerAxisFamilyPolicy, ReleaseSuiteParams,
    };
    use crate::CorrConfig;

    fn detector_config() -> DetectorConfig {
        DetectorConfig::standalone_advisory_v0_9().unwrap()
    }

    fn detector_config_with(change: impl FnOnce(&mut DetectorParams)) -> DetectorConfig {
        let mut params = DetectorParams::standalone_advisory_v0_9();
        change(&mut params);
        DetectorConfig::try_new(params).unwrap()
    }

    fn exploratory_mirror(config: DetectorConfig) -> Mirror {
        Mirror::for_exploratory_subset(
            config,
            ExploratoryResearchProfile::SubsetMagnitudeV0_9.capability(),
        )
    }

    fn release_mirror(config: DetectorConfig, modalities: &[Modality]) -> Mirror {
        let suite = ReleaseSuite::try_new(ReleaseSuiteParams {
            detector: config,
            correlation: CorrConfig::standalone_advisory_v0_9().unwrap(),
            expected_modalities: modalities.to_vec(),
            axis_policy: ProducerAxisFamilyPolicy::AttestedCommonProjectionBonferroniV1,
        })
        .unwrap();
        Mirror::from_release_suite(&suite)
    }

    fn track_id(value: u64) -> TrackId {
        TrackId::new(value).unwrap()
    }

    fn sequence(value: u64) -> Sequence {
        Sequence::new(value).unwrap()
    }

    fn observation(
        track: u64,
        timestamp_ms: u64,
        sequence_number: u64,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> PidObservation {
        PidObservation::try_scalar(
            track_id(track),
            TimestampMillis::new(timestamp_ms).unwrap(),
            sequence(sequence_number),
            modality,
            nis,
            dof,
        )
        .unwrap()
    }

    fn assess(mirror: &Mirror, track: u64, sequence_number: u64) -> MirrorReport {
        mirror
            .assess(track_id(track), sequence(sequence_number))
            .unwrap()
    }

    fn feed(mirror: &mut Mirror, track: u64, mods: &[Modality], nis: &[f64], frames: usize) {
        // `nis[i]` is the constant NIS for channel `mods[i]`.
        for f in 0..frames {
            for (i, &m) in mods.iter().enumerate() {
                mirror
                    .ingest(&observation(track, f as u64, f as u64, m, nis[i], 3))
                    .unwrap();
            }
        }
    }

    #[test]
    fn all_consistent_is_nominal() {
        let mut m = exploratory_mirror(detector_config());
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[3.0, 3.0, 3.0], 64);
        assert_eq!(assess(&m, 1, 63).verdict, Verdict::Nominal);
        assert_eq!(
            m.assess_outcome(track_id(1), sequence(63)).unwrap(),
            AssessmentOutcome::Nominal
        );
    }

    #[test]
    fn release_magnitude_nominal_remains_unavailable_until_consistency_fusion() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let mut mirror = release_mirror(detector_config(), &modalities);
        feed(&mut mirror, 1, &modalities, &[3.0, 3.0, 3.0], 64);

        let report = assess(&mirror, 1, 63);

        assert_eq!(report.verdict(), &Verdict::Nominal);
        assert!(matches!(
            report.validated_outcome(),
            AssessmentOutcome::Insufficient(Insufficiency::Unavailable(ref reasons))
                if reasons.as_slice() == [UnavailabilityReason::UnavailablePrerequisite]
        ));
        assert!(matches!(
            mirror.assess_outcome(track_id(1), sequence(63)).unwrap(),
            AssessmentOutcome::Insufficient(Insufficiency::Unavailable(_))
        ));
    }

    #[test]
    fn single_channel_inflation_is_attributed_inconsistency() {
        let mut m = exploratory_mirror(detector_config());
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[3.0, 3.0, 20.0], 64);
        match assess(&m, 1, 63).verdict {
            Verdict::AttributedInconsistency { channels } => {
                assert_eq!(channels, vec![Modality::Acoustic]);
            }
            other => panic!("expected AttributedInconsistency, got {other:?}"),
        }
    }

    #[test]
    fn all_channels_inflation_is_broad_degradation() {
        let mut m = exploratory_mirror(detector_config());
        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        feed(&mut m, 1, &mods, &[20.0, 20.0, 20.0], 64);
        assert_eq!(assess(&m, 1, 63).verdict, Verdict::BroadDegradation);
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
    fn verdict_deserialization_rejects_legacy_causal_tags() {
        let legacy = [
            serde_json::json!({"verdict": "spoof", "channels": ["acoustic"]}),
            serde_json::json!({"verdict": "jam"}),
            serde_json::json!({"verdict": "anomaly", "channels": ["radar"]}),
        ];

        assert!(legacy
            .into_iter()
            .all(|value| serde_json::from_value::<Verdict>(value).is_err()));
    }

    #[test]
    fn sealed_report_serializes_statistics_and_identity_but_not_private_outcome() {
        let modalities = [Modality::Visual, Modality::Radar];
        let suite = ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap();
        let mut mirror = Mirror::from_release_suite(&suite);
        feed(&mut mirror, 1, &modalities, &[3.0, 3.0], 64);
        let value = serde_json::to_value(assess(&mirror, 1, 63)).unwrap();

        assert_eq!(value["config_identity"], suite.identity().to_hex());
        assert_eq!(value["channels"][0]["dof"], 3);
        assert_eq!(value["channels"][0]["sum_nis"], 192.0);
        assert!(value.get("accepted_outcome").is_none());
    }

    #[test]
    fn too_few_samples_fails_closed() {
        let mut m = exploratory_mirror(detector_config());
        let mods = [Modality::Visual, Modality::Radar];
        // Below min_samples (32).
        feed(&mut m, 1, &mods, &[3.0, 3.0], 10);
        assert_eq!(assess(&m, 1, 9).verdict, Verdict::InsufficientEvidence);
    }

    #[test]
    fn duplicate_out_of_order_and_dof_changes_are_rejected_without_mutation() {
        let mut mirror = exploratory_mirror(detector_config());
        let first = observation(1, 100, 5, Modality::Radar, 3.0, 3);
        mirror.ingest(&first).unwrap();

        assert!(
            mirror.ingest(&first).is_err(),
            "duplicate must not advance readiness"
        );
        let older = observation(1, 90, 4, Modality::Radar, 3.0, 3);
        assert!(mirror.ingest(&older).is_err());
        let changed_dof = observation(1, 110, 6, Modality::Radar, 3.0, 2);
        assert!(mirror.ingest(&changed_dof).is_err());
        let regressed_time = observation(1, 99, 6, Modality::Radar, 3.0, 3);
        assert!(mirror.ingest(&regressed_time).is_err());

        let report = assess(&mirror, 1, 6);
        assert_eq!(report.channels[0].n, 1);
    }

    #[test]
    fn large_sequence_holes_require_explicit_reset_without_mutation() {
        let cfg = detector_config_with(|params| {
            params.min_samples = 2;
            params.window_len = 4;
        });
        let mut mirror = exploratory_mirror(cfg);
        mirror
            .ingest(&observation(1, 0, 0, Modality::Radar, 3.0, 3))
            .unwrap();
        let discontinuous = observation(1, 10_000, 100, Modality::Radar, 3.0, 3);
        let failure = mirror.ingest_checked(&discontinuous).unwrap_err();
        assert_eq!(failure.code(), FailureCode::ResetRequired);
        let legacy_error = mirror.ingest(&discontinuous).unwrap_err();
        assert!(legacy_error.to_string().contains("reset_required"));

        let report = assess(&mirror, 1, 0);
        assert_eq!(report.channels[0].n, 1);
        assert_eq!(report.channels[0].last_seq, Some(sequence(0)));
        assert_eq!(report.verdict, Verdict::InsufficientEvidence);
    }

    #[test]
    fn frozen_timestamps_are_rejected_without_mutating_state() {
        let cfg = detector_config_with(|params| {
            params.min_samples = 2;
            params.window_len = 4;
        });
        let mut mirror = exploratory_mirror(cfg);
        mirror
            .ingest(&observation(1, 100, 0, Modality::Radar, 3.0, 3))
            .unwrap();

        assert!(mirror
            .ingest(&observation(1, 100, 1, Modality::Radar, 3.0, 3))
            .is_err());
        assert_eq!(assess(&mirror, 1, 1).channels[0].n, 1);
    }

    #[test]
    fn large_forward_timestamp_holes_require_explicit_reset_without_mutation() {
        let cfg = detector_config_with(|params| {
            params.min_samples = 2;
            params.window_len = 4;
            params.max_inter_sample_gap_ms = 100;
        });
        let mut mirror = exploratory_mirror(cfg);
        mirror
            .ingest(&observation(1, 100, 0, Modality::Radar, 3.0, 3))
            .unwrap();
        let failure = mirror
            .ingest_checked(&observation(1, 201, 1, Modality::Radar, 3.0, 3))
            .unwrap_err();
        assert_eq!(failure.code(), FailureCode::ResetRequired);

        let report = assess(&mirror, 1, 0);
        assert_eq!(report.channels[0].n, 1);
        assert_eq!(
            report.channels[0].last_timestamp_ms,
            Some(TimestampMillis::new(100).unwrap())
        );
        assert_eq!(report.verdict, Verdict::InsufficientEvidence);
    }

    #[test]
    fn retained_tracks_are_bounded_and_explicitly_reclaimable() {
        let cfg = detector_config_with(|params| params.max_tracks = 1);
        let mut mirror = exploratory_mirror(cfg);
        mirror
            .ingest(&observation(1, 0, 0, Modality::Visual, 3.0, 3))
            .unwrap();
        assert!(mirror
            .ingest(&observation(2, 0, 0, Modality::Visual, 3.0, 3))
            .is_err());
        assert!(mirror.remove_track(track_id(1)));
        assert_eq!(mirror.track_count(), 0);
    }

    #[test]
    fn stale_or_missing_expected_channels_fail_closed() {
        let cfg = detector_config_with(|params| {
            params.min_samples = 1;
            params.window_len = 4;
        });
        let modalities = [Modality::Visual, Modality::Radar];
        let mut mirror = release_mirror(cfg, &modalities);
        mirror
            .ingest(&observation(1, 0, 0, Modality::Visual, 3.0, 3))
            .unwrap();
        assert_eq!(
            assess(&mirror, 1, 0).verdict,
            Verdict::InsufficientEvidence,
            "the missing expected radar channel must block Nominal"
        );
        mirror
            .ingest(&observation(1, 0, 0, Modality::Radar, 3.0, 3))
            .unwrap();
        assert_eq!(assess(&mirror, 1, 0).verdict, Verdict::Nominal);
        assert_eq!(
            assess(&mirror, 1, 1).verdict,
            Verdict::InsufficientEvidence,
            "a prior-frame peer must not complete a current-frame assessment"
        );
        assert_eq!(
            assess(&mirror, 1, 2).verdict,
            Verdict::InsufficientEvidence,
            "retained windows must not stay nominal after their feeds go stale"
        );
    }

    #[test]
    fn cross_modal_timestamp_skew_fails_closed() {
        let cfg = detector_config_with(|params| {
            params.min_samples = 1;
            params.window_len = 4;
            params.max_timestamp_skew_ms = 10;
        });
        let modalities = [Modality::Visual, Modality::Radar];
        let mut mirror = release_mirror(cfg, &modalities);
        mirror
            .ingest(&observation(1, 0, 0, Modality::Visual, 3.0, 3))
            .unwrap();
        mirror
            .ingest(&observation(1, 100, 0, Modality::Radar, 3.0, 3))
            .unwrap();
        assert_eq!(assess(&mirror, 1, 0).verdict, Verdict::InsufficientEvidence);
    }

    #[test]
    fn inter_sample_sequence_and_timestamp_gap_ceilings_are_inclusive() {
        let cfg = detector_config_with(|params| {
            params.min_samples = 1;
            params.window_len = 4;
            params.max_seq_gap = 10;
            params.max_inter_sample_gap_ms = 100;
        });
        let mut mirror = exploratory_mirror(cfg);
        mirror
            .ingest(&observation(1, 100, 5, Modality::Radar, 3.0, 3))
            .unwrap();
        mirror
            .ingest(&observation(1, 200, 15, Modality::Radar, 3.0, 3))
            .expect("both exact inter-sample ceilings are inclusive");

        let sequence_failure = mirror
            .ingest_checked(&observation(1, 201, 26, Modality::Radar, 3.0, 3))
            .unwrap_err();
        assert_eq!(sequence_failure.code(), FailureCode::ResetRequired);

        let timestamp_failure = mirror
            .ingest_checked(&observation(1, 301, 16, Modality::Radar, 3.0, 3))
            .unwrap_err();
        assert_eq!(timestamp_failure.code(), FailureCode::ResetRequired);

        let report = assess(&mirror, 1, 15);
        assert_eq!(
            report.channels()[0].last_seq(),
            Some(Sequence::new(15).unwrap())
        );
        assert_eq!(
            report.channels()[0].last_timestamp_ms(),
            Some(TimestampMillis::new(200).unwrap())
        );
    }

    #[test]
    fn mixed_sequence_frame_cannot_be_nominal() {
        let cfg = detector_config_with(|params| {
            params.min_samples = 1;
            params.window_len = 4;
        });
        let modalities = [Modality::Visual, Modality::Radar];
        let mut mirror = release_mirror(cfg, &modalities);
        for modality in modalities {
            mirror
                .ingest(&observation(1, 100, 0, modality, 3.0, 3))
                .unwrap();
        }

        let report = mirror
            .ingest_and_assess(&observation(1, 101, 1, Modality::Visual, 3.0, 3))
            .unwrap();

        assert_eq!(report.verdict, Verdict::InsufficientEvidence);
        assert!(report.channels[0].ready);
        assert!(report.channels[1].fresh);
        assert!(!report.channels[1].ready);
        assert!(matches!(
            report.validated_outcome(),
            AssessmentOutcome::Insufficient(Insufficiency::Unavailable(_))
        ));
    }

    proptest! {
        #[test]
        fn discontinuities_always_require_reset_and_preserve_the_suffix(
            sequence_gap in 2_u64..1_000,
            timestamp_discontinuity in any::<bool>(),
        ) {
            let cfg = detector_config_with(|params| {
                params.min_samples = 2;
                params.window_len = 4;
                params.max_inter_sample_gap_ms = 100;
            });
            let mut mirror = exploratory_mirror(cfg);
            mirror
                .ingest(&observation(1, 100, 0, Modality::Radar, 3.0, 3))
                .unwrap();
            let (next_sequence, next_timestamp) = if timestamp_discontinuity {
                (1, 201)
            } else {
                (sequence_gap, 101)
            };

            let failure = mirror
                .ingest_checked(&observation(
                    1,
                    next_timestamp,
                    next_sequence,
                    Modality::Radar,
                    3.0,
                    3,
                ))
                .unwrap_err();
            prop_assert_eq!(failure.code(), FailureCode::ResetRequired);

            let report = assess(&mirror, 1, 0);
            prop_assert_eq!(report.channels[0].n, 1);
            prop_assert_eq!(report.channels[0].last_seq, Some(sequence(0)));
            prop_assert_eq!(
                report.channels[0].last_timestamp_ms,
                Some(TimestampMillis::new(100).unwrap())
            );
        }
    }

    #[test]
    fn cusum_operating_point_is_comparable_across_degrees_of_freedom() {
        let cfg = detector_config_with(|params| {
            params.min_samples = 1;
            params.window_len = 4;
            params.cusum_slack = 1.0;
            params.cusum_threshold = 4.0;
            params.max_tracks = 2;
        });
        let mut mirror = exploratory_mirror(cfg);
        for (track, dof) in [(1, 1_u8), (2, 12_u8)] {
            let null_sigma = (2.0 * f64::from(dof)).sqrt();
            let shifted_nis = f64::from(dof) + 3.0 * null_sigma;
            // Use three updates so the assertion does not depend on an exact
            // floating-point equality at `hi == threshold`.
            for seq in 0..3 {
                mirror
                    .ingest(&observation(
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
                assess(&mirror, track, 2).channels[0].cusum_high_alarm,
                "a sustained three-sigma shift should cross the same CUSUM threshold for dof={dof}"
            );
        }
    }

    #[test]
    fn minimum_family_alpha_keeps_underflowed_tails_on_the_correct_side() {
        let cfg = detector_config_with(|params| {
            params.window_len = 1;
            params.min_samples = 1;
            params.min_channels = Modality::ALL.len();
            params.max_tracks = 1;
            params.nis_alpha = crate::config::MIN_NIS_FAMILY_ALPHA;
            params.cusum_slack = f64::MAX;
            params.cusum_threshold = f64::MAX;
        });
        let mut mirror = release_mirror(cfg, &Modality::ALL);
        for modality in Modality::ALL {
            mirror
                .ingest(&observation(1, 0, 0, modality, 1_440.0, 2))
                .unwrap();
        }

        // For chi-square(2), SF(1440) = exp(-720). statrs reports zero, but
        // exp(-720) is strictly below the admitted per-channel alpha floor, so
        // every high-direction classification remains mathematically correct.
        assert!((-720.0_f64).exp() < crate::baseline::MIN_NIS_TEST_ALPHA);
        let report = assess(&mirror, 1, 0);
        assert_eq!(report.verdict, Verdict::BroadDegradation);
        assert!(report.channels.iter().all(|channel| {
            channel.p_right == 0.0
                && channel.elevated
                && !channel.cusum_high_alarm
                && !channel.cusum_low_alarm
        }));
    }

    #[test]
    fn exact_cusum_residual_prevents_a_false_nominal_report() {
        let cfg = detector_config_with(|params| {
            params.window_len = 1;
            params.min_samples = 1;
            params.min_channels = 2;
            params.max_tracks = 1;
            params.nis_alpha = 1.0e-10;
            params.cusum_slack = 11.529_210_410_948_265;
            params.cusum_threshold = 1.0e-16;
        });
        let modalities = [Modality::Radar, Modality::Lidar];
        let mut mirror = release_mirror(cfg, &modalities);
        // Dividing this raw dof=1 NIS by sqrt(2) yields exactly
        // 12.236317192134813. Its exact-real CUSUM increment is 2^-51, although
        // ordinary binary64 subtraction rounds the increment to zero.
        for modality in modalities {
            mirror
                .ingest(&observation(1, 0, 0, modality, 17.304_765_726_616_12, 1))
                .unwrap();
        }

        let report = assess(&mirror, 1, 0);
        assert_eq!(report.verdict, Verdict::BroadDegradation);
        assert!(report.channels.iter().all(|channel| {
            !channel.elevated && channel.cusum_high_alarm && !channel.cusum_low_alarm
        }));
    }

    #[test]
    fn exact_window_estimand_prevents_history_dependent_false_nominal_report() {
        // The former incremental cache ended 383 ULP below the correctly rounded
        // retained sum after this rolling history. At alpha equal to that cached tail,
        // strict comparison classified both channels as nominal even though the
        // exact retained-window estimand has a smaller p-value.
        let old_cached_sum = 9.0;
        let old_p_right = crate::chi2::chi2_sf(old_cached_sum, 3.0 * 3.0);
        let cfg = detector_config_with(|params| {
            params.window_len = 3;
            params.min_samples = 3;
            params.min_channels = 2;
            params.max_tracks = 1;
            params.nis_alpha = 2.0 * old_p_right;
            params.cusum_slack = f64::MAX;
            params.cusum_threshold = f64::MAX;
        });
        let modalities = [Modality::Radar, Modality::Lidar];
        let mut mirror = release_mirror(cfg, &modalities);
        for frame in 0..1_023 {
            let nis = 3.0 + frame as f64 * f64::EPSILON;
            for modality in modalities {
                mirror
                    .ingest(&observation(1, frame, frame, modality, nis, 3))
                    .unwrap();
            }
        }

        let report = assess(&mirror, 1, 1_022);
        assert!(
            report.channels.iter().all(|channel| {
                channel.p_right < old_p_right
                    && channel.elevated
                    && !channel.cusum_high_alarm
                    && !channel.cusum_low_alarm
            }),
            "old p={old_p_right:?}, channels={:?}",
            report.channels
        );
        assert_eq!(report.verdict, Verdict::BroadDegradation);
    }
}
