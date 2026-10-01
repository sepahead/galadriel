#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
//! A local library seam for actual scalar NIS evidence.
//!
//! This adapter invokes Galadriel's existing `SubsetMagnitudeV0_9` detector.
//! It returns research magnitude reports, not accepted cross-sensor release reports.
//! Normalized innovation squared (NIS) is dimensionless. Its chi-square reference
//! needs a justified innovation covariance, degrees of freedom, and sampling model.
//! Representation checks do not establish those assumptions or authenticate a producer.
//! The scalar API owns no transport, command capability, persistence, or clock.
//! The optional `ncp-local` feature adds a separately bounded private-pipe owner.

use galadriel_core::{
    AssessmentClassification, AssessmentFailure, ClockDomain, DetectorConfig,
    ExploratoryResearchProfile, GaladrielError, Mirror, MirrorReport, Modality, PidObservation,
    Sequence, TimestampMillis, TrackId,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Explicitly selected candidate NCP private-pipe monitor owner.
#[cfg(feature = "ncp-local")]
pub mod ncp_local;

/// Exact research profile selected by this adapter.
pub const RESEARCH_PROFILE: ExploratoryResearchProfile =
    ExploratoryResearchProfile::SubsetMagnitudeV0_9;

/// Untrusted preparation values for one ordered scalar channel.
#[derive(Debug, Clone, Copy)]
pub struct ScalarChannelParams {
    /// Producer-declared sensor modality.
    pub modality: Modality,
    /// Immutable positive innovation dimension for this channel.
    pub dof: u8,
}

/// Accepted channel meaning retained during one prepared monitor lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalarChannel {
    modality: Modality,
    dof: u8,
}

impl ScalarChannel {
    /// Producer-declared modality.
    pub const fn modality(self) -> Modality {
        self.modality
    }

    /// Immutable positive degrees of freedom.
    pub const fn dof(self) -> u8 {
        self.dof
    }
}

/// Untrusted scalar evidence for one prepared channel.
#[derive(Debug, Clone, Copy)]
pub struct NisEvidenceParams {
    /// Dimensionless normalized innovation squared from the actual producer.
    pub nis: f64,
    /// The producer's declared innovation dimension.
    pub dof: u8,
}

/// Failure at the local adapter boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AdapterError {
    /// Preparation requires between one and six channels.
    #[error("channel count must be in 1..=6, got {0}")]
    ChannelCount(usize),
    /// A prepared modality occurred more than once.
    #[error("duplicate modality: {0:?}")]
    DuplicateModality(Modality),
    /// A channel declared zero degrees of freedom.
    #[error("zero degrees of freedom for {0:?}")]
    ZeroDegreesOfFreedom(Modality),
    /// A frame did not contain one explicit availability slot per channel.
    #[error("frame arity differs from prepared roster: expected {expected}, got {actual}")]
    FrameArity {
        /// Exact prepared slot count.
        expected: usize,
        /// Submitted slot count.
        actual: usize,
    },
    /// The caller changed a channel's prepared innovation dimension.
    #[error("degrees of freedom changed for {modality:?}: expected {expected}, got {actual}")]
    DegreesOfFreedomChanged {
        /// Affected modality.
        modality: Modality,
        /// Prepared dimension.
        expected: u8,
        /// Submitted dimension.
        actual: u8,
    },
    /// Input failed the actual Galadriel scalar-observation constructor.
    #[error("invalid scalar observation: {0}")]
    InvalidObservation(#[source] GaladrielError),
    /// Sequence was not the prepared first position or exact successor.
    #[error("noncontiguous sequence: expected {expected}, got {actual}")]
    SequenceDiscontinuity {
        /// Required next sequence.
        expected: u64,
        /// Submitted sequence.
        actual: u64,
    },
    /// The JSON-safe sequence domain has no remaining successor.
    #[error("sequence domain exhausted")]
    SequenceExhausted,
    /// Timestamp did not increase within the configured inter-sample limit.
    #[error("timestamp is not a bounded increasing successor")]
    TimestampDiscontinuity,
    /// A missing observation or lifecycle fault already retired this monitor.
    #[error("monitor retired; prepare a fresh monitor and external generation")]
    Retired,
    /// The actual detector refused ingestion after complete local preflight.
    #[error("detector ingestion failed: {0}")]
    DetectorIngest(#[source] AssessmentFailure),
    /// The actual detector failed during report construction.
    #[error("detector assessment failed: {0}")]
    DetectorAssessment(#[source] GaladrielError),
}

#[derive(Debug, Clone, Copy)]
enum WindowState {
    Prepared,
    Active {
        sequence: Sequence,
        timestamp_ms: TimestampMillis,
    },
    Retired,
}

/// A sealed result containing an actual detector report or explicit missingness.
///
/// Missingness has no fabricated report. Insufficient samples or channels remain
/// the actual report's `InsufficientEvidence` verdict. Neither path grants authority.
#[derive(Debug)]
pub struct ScalarAssessment {
    track_id: TrackId,
    sequence: Sequence,
    timestamp_ms: TimestampMillis,
    clock_domain: ClockDomain,
    adapter_identity: [u8; 32],
    report: Option<MirrorReport>,
    unavailable: Vec<Modality>,
}

impl ScalarAssessment {
    /// Exact prepared track.
    pub const fn track_id(&self) -> TrackId {
        self.track_id
    }

    /// Submitted exact logical position.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Submitted timestamp in the prepared clock domain, in milliseconds.
    pub const fn timestamp_ms(&self) -> TimestampMillis {
        self.timestamp_ms
    }

    /// Clock domain declared at preparation.
    pub const fn clock_domain(&self) -> ClockDomain {
        self.clock_domain
    }

    /// Complete prepared-adapter identity. This digest is not authentication.
    pub const fn adapter_identity(&self) -> &[u8; 32] {
        &self.adapter_identity
    }

    /// Actual sealed magnitude report, absent only for explicit missing evidence.
    pub const fn report(&self) -> Option<&MirrorReport> {
        self.report.as_ref()
    }

    /// Missing channels in prepared roster order. A nonempty value retires the monitor.
    pub fn unavailable(&self) -> &[Modality] {
        &self.unavailable
    }

    /// Fixed research classification, including when no report could be formed.
    pub const fn classification(&self) -> AssessmentClassification {
        AssessmentClassification::ExploratoryResearch(RESEARCH_PROFILE)
    }

    /// No result from this adapter is a calibrated posterior.
    pub const fn calibrated_posterior(&self) -> bool {
        false
    }
}

/// One bounded track and fixed scalar roster using the actual Galadriel engine.
///
/// Preparation costs `O(m)` time and memory for `1 <= m <= 6` channels.
/// The retained detector samples are at most `m * config.window_len()`.
/// Each assessment handles at most six scalar observations and six report rows.
/// Work and retained memory do not grow with the total number of completed frames.
/// Missing evidence retires the instance. A fresh instance requires an externally
/// coordinated new generation; this library cannot authenticate that coordination.
pub struct ScalarMonitor {
    track_id: TrackId,
    clock_domain: ClockDomain,
    first_sequence: Sequence,
    channels: Vec<ScalarChannel>,
    adapter_identity: [u8; 32],
    mirror: Mirror,
    state: WindowState,
}

impl ScalarMonitor {
    /// Prepare immutable channel meaning before any detector observation.
    ///
    /// A one-channel roster is valid research input. It cannot satisfy the core's
    /// unchanged two-channel readiness minimum. No second channel is fabricated.
    ///
    /// # Errors
    /// Rejects empty or oversized rosters, duplicate modalities, and zero dimensions.
    pub fn prepare(
        track_id: TrackId,
        clock_domain: ClockDomain,
        first_sequence: Sequence,
        channels: &[ScalarChannelParams],
        config: DetectorConfig,
    ) -> Result<Self, AdapterError> {
        if channels.is_empty() || channels.len() > Modality::ALL.len() {
            return Err(AdapterError::ChannelCount(channels.len()));
        }
        let mut seen = [false; Modality::ALL.len()];
        for channel in channels {
            if channel.dof == 0 {
                return Err(AdapterError::ZeroDegreesOfFreedom(channel.modality));
            }
            let slot = &mut seen[usize::from(channel.modality.stable_code())];
            if *slot {
                return Err(AdapterError::DuplicateModality(channel.modality));
            }
            *slot = true;
        }

        let mut identity = Sha256::new();
        identity.update(b"galadriel-local-subset-magnitude-v1\0");
        identity.update(config.identity().as_bytes());
        identity.update(track_id.get().to_be_bytes());
        identity.update(first_sequence.get().to_be_bytes());
        identity.update(clock_domain.as_str().as_bytes());
        identity.update([0, channels.len() as u8]);
        for channel in channels {
            identity.update([channel.modality.stable_code(), channel.dof]);
        }

        Ok(Self {
            track_id,
            clock_domain,
            first_sequence,
            channels: channels
                .iter()
                .map(|channel| ScalarChannel {
                    modality: channel.modality,
                    dof: channel.dof,
                })
                .collect(),
            adapter_identity: identity.finalize().into(),
            mirror: Mirror::for_exploratory_subset(config, RESEARCH_PROFILE.capability()),
            state: WindowState::Prepared,
        })
    }

    /// Immutable accepted detector configuration.
    pub fn config(&self) -> &DetectorConfig {
        self.mirror.config()
    }

    /// Immutable channel order and dimensions.
    pub fn channels(&self) -> &[ScalarChannel] {
        &self.channels
    }

    /// Digest of the complete prepared meaning, excluding runtime observations.
    pub const fn adapter_identity(&self) -> &[u8; 32] {
        &self.adapter_identity
    }

    /// Whether this instance can no longer accept observations.
    pub const fn is_retired(&self) -> bool {
        matches!(self.state, WindowState::Retired)
    }

    /// Check one complete frame without changing the monitor.
    ///
    /// A protocol owner can call this method before its mutation boundary.
    /// Missing slots are valid input with a later explicit abstention outcome.
    /// Validation does not reserve a position or authorize future execution.
    ///
    /// # Errors
    /// Returns the same pre-ingestion errors as [`Self::assess_frame`].
    pub fn validate_frame(
        &self,
        sequence: Sequence,
        timestamp_ms: TimestampMillis,
        evidence: &[Option<NisEvidenceParams>],
    ) -> Result<(), AdapterError> {
        self.stage_frame(sequence, timestamp_ms, evidence)?;
        self.check_position(sequence, timestamp_ms)
    }

    /// Assess one exact frame through Galadriel's existing scalar detector.
    ///
    /// Every channel needs an explicit `Some` or `None` slot in prepared order.
    /// NIS and dimensions are validated for the complete frame before ingestion.
    /// A missing slot returns an abstention and permanently retires this instance.
    /// Invalid numeric values or arity fail before mutation and permit corrected input.
    /// Lifecycle errors retire the instance. No method clears a retired state.
    ///
    /// # Errors
    /// Rejects wrong arity, changed dimensions, invalid NIS, retired state,
    /// sequence discontinuity, timestamp discontinuity, or an actual engine failure.
    pub fn assess_frame(
        &mut self,
        sequence: Sequence,
        timestamp_ms: TimestampMillis,
        evidence: &[Option<NisEvidenceParams>],
    ) -> Result<ScalarAssessment, AdapterError> {
        let (observations, unavailable) = self.stage_frame(sequence, timestamp_ms, evidence)?;

        if let Err(error) = self.check_position(sequence, timestamp_ms) {
            self.retire();
            return Err(error);
        }

        if !unavailable.is_empty() {
            self.retire();
            return Ok(self.result(sequence, timestamp_ms, None, unavailable));
        }

        for observation in observations.iter().flatten() {
            if let Err(error) = self.mirror.ingest_checked(observation) {
                self.retire();
                return Err(AdapterError::DetectorIngest(error));
            }
        }
        let report = match self.mirror.assess(self.track_id, sequence) {
            Ok(report) => report,
            Err(error) => {
                self.retire();
                return Err(AdapterError::DetectorAssessment(error));
            }
        };
        self.state = WindowState::Active {
            sequence,
            timestamp_ms,
        };
        Ok(self.result(sequence, timestamp_ms, Some(report), unavailable))
    }

    fn stage_frame(
        &self,
        sequence: Sequence,
        timestamp_ms: TimestampMillis,
        evidence: &[Option<NisEvidenceParams>],
    ) -> Result<([Option<PidObservation>; Modality::ALL.len()], Vec<Modality>), AdapterError> {
        if self.is_retired() {
            return Err(AdapterError::Retired);
        }
        if evidence.len() != self.channels.len() {
            return Err(AdapterError::FrameArity {
                expected: self.channels.len(),
                actual: evidence.len(),
            });
        }

        // Stage at most six observations so a later invalid channel cannot admit
        // an earlier channel into the retained statistical window.
        let mut observations: [Option<PidObservation>; Modality::ALL.len()] =
            std::array::from_fn(|_| None);
        let mut unavailable = Vec::new();
        for (index, (channel, sample)) in self.channels.iter().zip(evidence).enumerate() {
            let Some(sample) = sample else {
                unavailable.push(channel.modality);
                continue;
            };
            if sample.dof != channel.dof {
                return Err(AdapterError::DegreesOfFreedomChanged {
                    modality: channel.modality,
                    expected: channel.dof,
                    actual: sample.dof,
                });
            }
            observations[index] = Some(
                PidObservation::try_scalar(
                    self.track_id,
                    timestamp_ms,
                    sequence,
                    channel.modality,
                    sample.nis,
                    sample.dof,
                )
                .map_err(AdapterError::InvalidObservation)?,
            );
        }

        Ok((observations, unavailable))
    }

    fn check_position(
        &self,
        sequence: Sequence,
        timestamp_ms: TimestampMillis,
    ) -> Result<(), AdapterError> {
        let expected = match self.state {
            WindowState::Prepared => self.first_sequence,
            WindowState::Active {
                sequence: previous,
                timestamp_ms: previous_time,
            } => {
                let gap = timestamp_ms.get().checked_sub(previous_time.get());
                if !matches!(gap, Some(gap) if gap > 0 && gap <= self.config().max_inter_sample_gap_ms())
                {
                    return Err(AdapterError::TimestampDiscontinuity);
                }
                previous
                    .checked_successor()
                    .map_err(|_| AdapterError::SequenceExhausted)?
            }
            WindowState::Retired => return Err(AdapterError::Retired),
        };
        if sequence != expected {
            return Err(AdapterError::SequenceDiscontinuity {
                expected: expected.get(),
                actual: sequence.get(),
            });
        }
        Ok(())
    }

    fn result(
        &self,
        sequence: Sequence,
        timestamp_ms: TimestampMillis,
        report: Option<MirrorReport>,
        unavailable: Vec<Modality>,
    ) -> ScalarAssessment {
        ScalarAssessment {
            track_id: self.track_id,
            sequence,
            timestamp_ms,
            clock_domain: self.clock_domain,
            adapter_identity: self.adapter_identity,
            report,
            unavailable,
        }
    }

    fn retire(&mut self) {
        self.state = WindowState::Retired;
        self.mirror.clear();
    }
}
