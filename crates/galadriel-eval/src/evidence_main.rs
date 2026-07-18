#![forbid(unsafe_code)]
//! Reproducible, machine-readable post-audit evidence runner.
//!
//! This binary intentionally evaluates the streaming NIS baseline and the default
//! signed-correlation fusion path. PID remains a terminal-only replay experiment in
//! the current product, so this runner does not invent a PID assessment cadence.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use galadriel_core::{
    combine_correlation_axes, consistency_channels_with_temporal_limits, correlation,
    AxisCorrelationReport, ConsistencyProjection, CorrConfig, CorrConfigError, CorrParams,
    CorrVerdict, DetectorConfig, DetectorConfigError, DetectorParams, FailureCode, FusedVerdict,
    Mirror, Modality, PidObservation, ProducerAxisFamilyPolicy, ReleaseSuite, ReleaseSuiteError,
    ReleaseSuiteParams, Sequence, TimestampMillis, TrackId, Verdict, JSON_SAFE_INTEGER_MAX,
};
use galadriel_eval::wilson_ci;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand_distr::{Distribution, Normal};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use statrs::distribution::{ChiSquared, ContinuousCDF};
use thiserror::Error;

const ARTIFACT_SCHEMA_VERSION: u32 = 1;
const TRIAL_SCHEMA: &str = "galadriel.evidence.trial.v3";
const SUMMARY_SCHEMA: &str = "galadriel.evidence.summary.v2";
const MANIFEST_SCHEMA: &str = "galadriel.evidence.manifest.v2";
const GENERATOR_PROFILE: &str = "galadriel-evidence-synthetic-generator-v3";
const RECORDED_REPLAY_PROFILE: &str = "verified-recorded-fixture-replay-v1";
const MISSINGNESS_PROFILE: &str = "deterministic-independent-bernoulli-acoustic-v1";
const ACCEPTANCE_METRIC_PROFILE: &str = "galadriel-0.9-frozen-acceptance-metrics-v2";
const MAX_GENERATED_OBSERVATIONS: usize = 25_000_000;
const MAX_CORRELATION_SAMPLE_PRODUCTS: usize = 500_000_000;
const MAX_TRACE_ASSESSMENTS: usize = 2_000_000;
const MAX_BOOTSTRAP_TRACK_DRAWS: usize = 50_000_000;
const MAX_METRICS_PER_CONDITION: usize = 8;
const MAX_GENERATION_RESETS: usize = 1_000_000;
const MIN_COVARIANCE_SCALE_DELTA: f64 = 0.01;
const MAX_EVIDENCE_CONFIG_BYTES: usize = 1_048_576;
const MAX_STUDY_ID_BYTES: usize = 128;
const DEFAULT_MODALITIES: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

type AppResult<T> = Result<T, String>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceConfigFile {
    schema_version: u32,
    study_id: String,
    #[serde(
        deserialize_with = "deserialize_exact_u64",
        serialize_with = "serialize_exact_u64"
    )]
    base_seed: u64,
    calibration_tracks: usize,
    holdout_tracks: usize,
    frames: usize,
    dt_ms: u64,
    assessment_step: usize,
    alert_episode_reset_policy: AlertEpisodeResetPolicy,
    attack_onset_frame: usize,
    mission_frames: usize,
    rho: f64,
    sigma: f64,
    loud_bias_sigma: f64,
    ordinary_missing_probability: f64,
    autocorrelation_phis: Vec<f64>,
    covariance_scales: Vec<f64>,
    bootstrap_resamples: usize,
    min_metric_eligible_tracks: usize,
    min_recorded_duration_ms: u64,
    detector: DetectorConfigFile,
    correlation: CorrConfigFile,
    recorded_fixture: RecordedFixtureConfig,
}

fn serialize_exact_u64<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_exact_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct ExactU64Visitor;

    impl Visitor<'_> for ExactU64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an unsigned integer or its exact decimal string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value.parse::<u64>().map_err(|_| {
                E::invalid_value(de::Unexpected::Str(value), &"an exact decimal u64 string")
            })
        }
    }

    deserializer.deserialize_any(ExactU64Visitor)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorConfigFile {
    window_len: usize,
    min_samples: usize,
    min_channels: usize,
    max_seq_gap: u64,
    max_timestamp_skew_ms: u64,
    max_inter_sample_gap_ms: u64,
    max_tracks: usize,
    nis_alpha: f64,
    cusum_slack: f64,
    cusum_threshold: f64,
    jam_fraction: f64,
}

impl DetectorConfigFile {
    fn runtime(&self) -> Result<DetectorConfig, DetectorConfigError> {
        DetectorConfig::try_new(DetectorParams {
            window_len: self.window_len,
            min_samples: self.min_samples,
            min_channels: self.min_channels,
            max_seq_gap: self.max_seq_gap,
            max_timestamp_skew_ms: self.max_timestamp_skew_ms,
            max_inter_sample_gap_ms: self.max_inter_sample_gap_ms,
            max_tracks: self.max_tracks,
            nis_alpha: self.nis_alpha,
            cusum_slack: self.cusum_slack,
            cusum_threshold: self.cusum_threshold,
            jam_fraction: self.jam_fraction,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrConfigFile {
    window: usize,
    min_samples: usize,
    decouple_ratio: f64,
    corr_floor: f64,
    family_alpha: f64,
}

impl CorrConfigFile {
    fn runtime(&self) -> Result<CorrConfig, CorrConfigError> {
        CorrConfig::try_new(CorrParams {
            window: self.window,
            min_samples: self.min_samples,
            decouple_ratio: self.decouple_ratio,
            corr_floor: self.corr_floor,
            family_alpha: self.family_alpha,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedFixtureConfig {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct EvidenceWorkEstimate {
    synthetic_tracks: usize,
    synthetic_trial_records: usize,
    generated_observations: usize,
    trace_assessments: usize,
    correlation_sample_products: usize,
    bootstrap_track_draws: usize,
    maximum_synthetic_generation_resets: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct RecordedWorkEstimate {
    tracks: usize,
    trial_records: usize,
    observations: usize,
    trace_assessments: usize,
    correlation_sample_products: usize,
    maximum_generation_resets: usize,
}

impl EvidenceConfigFile {
    fn validate(&self) -> AppResult<EvidenceWorkEstimate> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION {
            return Err(format!(
                "config schema_version must be {ARTIFACT_SCHEMA_VERSION}"
            ));
        }
        if self.study_id.is_empty()
            || self.study_id.len() > MAX_STUDY_ID_BYTES
            || !self
                .study_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(format!(
                "study_id must contain 1..={MAX_STUDY_ID_BYTES} ASCII letters, digits, '.', '-', or '_'"
            ));
        }
        if self.calibration_tracks < 2 || self.holdout_tracks < 2 {
            return Err("calibration_tracks and holdout_tracks must both be >= 2".into());
        }
        let warm_up = self.correlation.min_samples.max(self.detector.min_samples);
        if self.frames < warm_up || self.frames > 100_000 {
            return Err(
                "frames must cover detector/correlation min_samples and be <= 100000".into(),
            );
        }
        if self.dt_ms == 0 {
            return Err("dt_ms must be > 0".into());
        }
        if self.assessment_step == 0 || self.assessment_step > self.frames {
            return Err("assessment_step must be in 1..=frames".into());
        }
        if self.attack_onset_frame < warm_up || self.attack_onset_frame >= self.frames {
            return Err("attack_onset_frame must follow warm-up and be inside the track".into());
        }
        let first_assessable_scheduled_frame =
            warm_up.div_ceil(self.assessment_step) * self.assessment_step;
        if self.mission_frames < first_assessable_scheduled_frame
            || self.mission_frames > self.frames
        {
            return Err(format!(
                "mission_frames must be in {first_assessable_scheduled_frame}..=frames so the mission includes the first scheduled assessable point"
            ));
        }
        if !self.rho.is_finite() || !(0.0..1.0).contains(&self.rho) {
            return Err("rho must be finite and in [0, 1)".into());
        }
        if !self.sigma.is_finite() || self.sigma <= 0.0 {
            return Err("sigma must be finite and > 0".into());
        }
        if !self.loud_bias_sigma.is_finite() || self.loud_bias_sigma <= 0.0 {
            return Err("loud_bias_sigma must be finite and > 0".into());
        }
        if !self.ordinary_missing_probability.is_finite()
            || !(0.0..1.0).contains(&self.ordinary_missing_probability)
            || self.ordinary_missing_probability == 0.0
        {
            return Err("ordinary_missing_probability must be finite and in (0, 1)".into());
        }
        if self.autocorrelation_phis.is_empty() || self.autocorrelation_phis.len() > 16 {
            return Err("autocorrelation_phis must contain 1..=16 values".into());
        }
        if self
            .autocorrelation_phis
            .iter()
            .any(|phi| !phi.is_finite() || phi.abs() >= 1.0)
        {
            return Err("autocorrelation phis must be finite and have |phi| < 1".into());
        }
        if self.covariance_scales.is_empty() || self.covariance_scales.len() > 16 {
            return Err("covariance_scales must contain 1..=16 values".into());
        }
        if self
            .covariance_scales
            .iter()
            .any(|scale| !scale.is_finite() || *scale <= 0.0 || *scale > 100.0)
        {
            return Err("covariance scales must be finite and in (0, 100]".into());
        }
        reject_duplicate_floats("autocorrelation_phis", &self.autocorrelation_phis)?;
        reject_duplicate_floats("covariance_scales", &self.covariance_scales)?;
        if !self.autocorrelation_phis.contains(&0.0)
            || !self.autocorrelation_phis.iter().any(|phi| *phi != 0.0)
        {
            return Err(
                "autocorrelation_phis must include zero and a non-zero sensitivity value".into(),
            );
        }
        if !self.covariance_scales.contains(&1.0)
            || !self.covariance_scales.iter().any(|scale| *scale != 1.0)
        {
            return Err(
                "covariance_scales must include 1.0 and a non-reference sensitivity value".into(),
            );
        }
        if self
            .covariance_scales
            .iter()
            .any(|scale| *scale != 1.0 && (*scale - 1.0).abs() < MIN_COVARIANCE_SCALE_DELTA)
        {
            return Err(format!(
                "non-reference covariance scales must differ from 1.0 by at least {MIN_COVARIANCE_SCALE_DELTA}"
            ));
        }
        if !(200..=10_000).contains(&self.bootstrap_resamples) {
            return Err("bootstrap_resamples must be in 200..=10000".into());
        }
        if !(2..=self.holdout_tracks).contains(&self.min_metric_eligible_tracks) {
            return Err("min_metric_eligible_tracks must be in 2..=holdout_tracks".into());
        }
        if self.min_recorded_duration_ms == 0 {
            return Err("min_recorded_duration_ms must be > 0".into());
        }
        if self.recorded_fixture.path.trim().is_empty()
            || self.recorded_fixture.sha256.len() != 64
            || !self
                .recorded_fixture
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("recorded fixture path and 64-digit SHA-256 are required".into());
        }
        if self.detector.min_channels > DEFAULT_MODALITIES.len() {
            return Err(format!(
                "detector.min_channels must be <= {} for this three-modality study",
                DEFAULT_MODALITIES.len()
            ));
        }
        if self.dt_ms > self.detector.max_inter_sample_gap_ms {
            return Err("dt_ms must not exceed detector.max_inter_sample_gap_ms".into());
        }
        let last_sequence = u64::try_from(self.frames.saturating_sub(1))
            .map_err(|_| "frames - 1 is not representable as u64".to_string())?;
        if last_sequence > Sequence::MAX {
            return Err(format!(
                "frames require sequence {last_sequence}; maximum is {}",
                Sequence::MAX
            ));
        }
        let last_timestamp_ms = last_sequence
            .checked_mul(self.dt_ms)
            .ok_or_else(|| "(frames - 1) * dt_ms overflows u64".to_string())?;
        if last_timestamp_ms > TimestampMillis::MAX {
            return Err(format!(
                "frames and dt_ms require timestamp {last_timestamp_ms}; maximum is {}",
                TimestampMillis::MAX
            ));
        }

        let clean_conditions = self
            .autocorrelation_phis
            .len()
            .checked_add(
                self.covariance_scales
                    .iter()
                    .filter(|scale| **scale != 1.0)
                    .count(),
            )
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| "condition count overflowed".to_string())?;
        let tracks_per_clean_condition =
            self.calibration_tracks
                .checked_add(self.holdout_tracks)
                .ok_or_else(|| "calibration + holdout track count overflowed".to_string())?;
        let clean_tracks = clean_conditions
            .checked_mul(tracks_per_clean_condition)
            .ok_or_else(|| "clean track count overflowed".to_string())?;
        let other_tracks = self
            .holdout_tracks
            .checked_mul(5)
            .ok_or_else(|| "attack/provenance track count overflowed".to_string())?;
        let total_tracks = clean_tracks
            .checked_add(other_tracks)
            .ok_or_else(|| "total track count overflowed".to_string())?;
        let bootstrap_track_draws = total_tracks
            .checked_mul(2)
            .and_then(|records| records.checked_mul(MAX_METRICS_PER_CONDITION))
            .and_then(|draws| draws.checked_mul(self.bootstrap_resamples))
            .ok_or_else(|| "bootstrap track-draw work estimate overflowed".to_string())?;
        if bootstrap_track_draws > MAX_BOOTSTRAP_TRACK_DRAWS {
            return Err(format!(
                "config requests up to {bootstrap_track_draws} bootstrap track draws; maximum is {MAX_BOOTSTRAP_TRACK_DRAWS}"
            ));
        }
        let observations = total_tracks
            .checked_mul(self.frames)
            .and_then(|frames| frames.checked_mul(DEFAULT_MODALITIES.len()))
            .ok_or_else(|| "generated observation work overflowed".to_string())?;
        if observations > MAX_GENERATED_OBSERVATIONS {
            return Err(format!(
                "config requests about {observations} observations; maximum is {MAX_GENERATED_OBSERVATIONS}"
            ));
        }
        let assessments_per_track = self.frames.div_ceil(self.assessment_step);
        let trace_assessments = total_tracks
            .checked_mul(assessments_per_track)
            .and_then(|assessments| assessments.checked_mul(2))
            .ok_or_else(|| "trace/output work estimate overflowed".to_string())?;
        if trace_assessments > MAX_TRACE_ASSESSMENTS {
            return Err(format!(
                "config requests about {trace_assessments} detector assessments in trial traces; maximum is {MAX_TRACE_ASSESSMENTS}"
            ));
        }
        let modality_pairs = DEFAULT_MODALITIES
            .len()
            .checked_mul(DEFAULT_MODALITIES.len().saturating_sub(1))
            .map(|ordered| ordered / 2)
            .ok_or_else(|| "modality pair count overflowed".to_string())?;
        let correlation_work = total_tracks
            .checked_mul(assessments_per_track)
            .and_then(|work| work.checked_mul(3))
            .and_then(|work| work.checked_mul(modality_pairs))
            .and_then(|work| work.checked_mul(self.correlation.window.min(self.frames)))
            .ok_or_else(|| "correlation work estimate overflowed".to_string())?;
        if correlation_work > MAX_CORRELATION_SAMPLE_PRODUCTS {
            return Err(format!(
                "config requests about {correlation_work} correlation pair-sample products; maximum is {MAX_CORRELATION_SAMPLE_PRODUCTS}"
            ));
        }
        let maximum_synthetic_generation_resets = tracks_per_clean_condition
            .checked_mul(self.frames / 2)
            .ok_or_else(|| "synthetic generation-reset estimate overflowed".to_string())?;
        if maximum_synthetic_generation_resets > MAX_GENERATION_RESETS {
            return Err(format!(
                "ordinary missingness can require up to {maximum_synthetic_generation_resets} explicit detector-generation resets; maximum is {MAX_GENERATION_RESETS}"
            ));
        }
        let synthetic_trial_records = total_tracks
            .checked_mul(2)
            .ok_or_else(|| "trial-record count overflowed".to_string())?;
        Ok(EvidenceWorkEstimate {
            synthetic_tracks: total_tracks,
            synthetic_trial_records,
            generated_observations: observations,
            trace_assessments,
            correlation_sample_products: correlation_work,
            bootstrap_track_draws,
            maximum_synthetic_generation_resets,
        })
    }
}

/// Typed rejection while decoding or accepting an evidence configuration.
#[derive(Debug, Error)]
#[non_exhaustive]
enum EvidenceConfigError {
    #[error("evidence configuration contains {actual} bytes; maximum is {maximum}")]
    ConfigTooLarge { actual: usize, maximum: usize },
    #[error("strict evidence JSON is invalid: {source}")]
    Json {
        #[source]
        source: serde_json::Error,
    },
    #[error("evidence configuration is invalid: {reason}")]
    Invalid { reason: String },
    #[error("detector configuration is invalid: {source}")]
    Detector {
        #[source]
        source: DetectorConfigError,
    },
    #[error("correlation configuration is invalid: {source}")]
    Correlation {
        #[source]
        source: CorrConfigError,
    },
    #[error("evidence release-suite composition is invalid: {source}")]
    Suite {
        #[source]
        source: ReleaseSuiteError,
    },
    #[error("resolve {kind} path {path}: {source}")]
    PathIo {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("recorded fixture resolves outside workspace root {workspace_root}: {path}")]
    FixtureOutsideWorkspace {
        workspace_root: PathBuf,
        path: PathBuf,
    },
    #[error("recorded fixture is not a regular file: {path}")]
    FixtureNotFile { path: PathBuf },
    #[error("recorded fixture exceeds the parser maximum of {maximum} bytes")]
    FixtureTooLarge { maximum: usize },
    #[error("recorded fixture SHA-256 mismatch: configured {configured}, actual {actual}")]
    FixtureHashMismatch { configured: String, actual: String },
    #[error("recorded fixture is not UTF-8 at {path}: {source}")]
    FixtureUtf8 {
        path: PathBuf,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("recorded fixture cannot be parsed at {path}: {source}")]
    FixtureParse {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("serialize canonical accepted evidence configuration: {source}")]
    CanonicalSerialization {
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug)]
struct VerifiedRecordedFixture {
    configured_path: String,
    resolved_path: PathBuf,
    sha256: String,
    bytes: Box<[u8]>,
    observations: Box<[PidObservation]>,
}

/// Immutable configuration accepted once after strict JSON decoding.
///
/// The raw DTO is consumed and not retained. Both statistical component configs
/// are accepted immutable values; bounded vectors are moved into boxed slices;
/// and the fixture bytes are path-contained, size-bounded, and hash-verified
/// before this value exists.
#[derive(Debug)]
struct ValidatedEvidenceConfig {
    schema_version: u32,
    study_id: String,
    base_seed: u64,
    calibration_tracks: usize,
    holdout_tracks: usize,
    frames: usize,
    dt_ms: u64,
    assessment_step: usize,
    alert_episode_reset_policy: AlertEpisodeResetPolicy,
    attack_onset_frame: usize,
    mission_frames: usize,
    rho: f64,
    sigma: f64,
    loud_bias_sigma: f64,
    ordinary_missing_probability: f64,
    autocorrelation_phis: Box<[f64]>,
    covariance_scales: Box<[f64]>,
    bootstrap_resamples: usize,
    min_metric_eligible_tracks: usize,
    min_recorded_duration_ms: u64,
    work_estimate: EvidenceWorkEstimate,
    recorded_work_estimate: RecordedWorkEstimate,
    suite: ReleaseSuite,
    recorded_fixture: VerifiedRecordedFixture,
    canonical_digest: String,
    artifact_config: Box<[u8]>,
}

impl ValidatedEvidenceConfig {
    fn try_new(
        mut raw: EvidenceConfigFile,
        config_path: &Path,
        workspace_root: &Path,
    ) -> Result<Self, EvidenceConfigError> {
        let work_estimate = raw
            .validate()
            .map_err(|reason| EvidenceConfigError::Invalid { reason })?;
        canonicalize_signed_zero(&mut raw.rho);
        canonicalize_signed_zero(&mut raw.detector.cusum_slack);
        canonicalize_signed_zero(&mut raw.correlation.decouple_ratio);
        canonicalize_signed_zero(&mut raw.correlation.corr_floor);
        for value in &mut raw.autocorrelation_phis {
            canonicalize_signed_zero(value);
        }
        let detector = raw
            .detector
            .runtime()
            .map_err(|source| EvidenceConfigError::Detector { source })?;
        let correlation = raw
            .correlation
            .runtime()
            .map_err(|source| EvidenceConfigError::Correlation { source })?;
        let suite = ReleaseSuite::try_new(ReleaseSuiteParams {
            detector,
            correlation,
            expected_modalities: DEFAULT_MODALITIES.to_vec(),
            axis_policy: ProducerAxisFamilyPolicy::AttestedCommonProjectionBonferroniV1,
        })
        .map_err(|source| EvidenceConfigError::Suite { source })?;
        let configured_fixture = PathBuf::from(&raw.recorded_fixture.path);
        let unresolved_fixture = if configured_fixture.is_absolute() {
            configured_fixture
        } else {
            let parent = config_path
                .parent()
                .ok_or_else(|| EvidenceConfigError::Invalid {
                    reason: "config path has no parent directory".into(),
                })?;
            parent.join(configured_fixture)
        };
        let resolved_fixture =
            unresolved_fixture
                .canonicalize()
                .map_err(|source| EvidenceConfigError::PathIo {
                    kind: "recorded fixture",
                    path: unresolved_fixture.clone(),
                    source,
                })?;
        let workspace_root =
            workspace_root
                .canonicalize()
                .map_err(|source| EvidenceConfigError::PathIo {
                    kind: "workspace root",
                    path: workspace_root.to_path_buf(),
                    source,
                })?;
        if !resolved_fixture.starts_with(&workspace_root) {
            return Err(EvidenceConfigError::FixtureOutsideWorkspace {
                workspace_root,
                path: resolved_fixture,
            });
        }
        if !resolved_fixture.is_file() {
            return Err(EvidenceConfigError::FixtureNotFile {
                path: resolved_fixture,
            });
        }
        let maximum_bytes = galadriel_ncp::DEFAULT_MAX_JSONL_BYTES;
        let read_limit = u64::try_from(maximum_bytes)
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .ok_or_else(|| EvidenceConfigError::Invalid {
                reason: "recorded fixture parser byte limit is not representable".into(),
            })?;
        let file = File::open(&resolved_fixture).map_err(|source| EvidenceConfigError::PathIo {
            kind: "recorded fixture",
            path: resolved_fixture.clone(),
            source,
        })?;
        let mut fixture_bytes = Vec::new();
        file.take(read_limit)
            .read_to_end(&mut fixture_bytes)
            .map_err(|source| EvidenceConfigError::PathIo {
                kind: "recorded fixture",
                path: resolved_fixture.clone(),
                source,
            })?;
        if fixture_bytes.len() > maximum_bytes {
            return Err(EvidenceConfigError::FixtureTooLarge {
                maximum: maximum_bytes,
            });
        }
        let actual_hash = sha256_bytes(&fixture_bytes);
        let configured_hash = raw.recorded_fixture.sha256.to_ascii_lowercase();
        if actual_hash != configured_hash {
            return Err(EvidenceConfigError::FixtureHashMismatch {
                configured: configured_hash,
                actual: actual_hash,
            });
        }
        let fixture_text = std::str::from_utf8(&fixture_bytes).map_err(|source| {
            EvidenceConfigError::FixtureUtf8 {
                path: resolved_fixture.clone(),
                source,
            }
        })?;
        let mut fixture_observations =
            galadriel_ncp::parse_jsonl(fixture_text).map_err(|source| {
                EvidenceConfigError::FixtureParse {
                    path: resolved_fixture.clone(),
                    source,
                }
            })?;
        if fixture_observations.is_empty() {
            return Err(EvidenceConfigError::Invalid {
                reason: "recorded fixture contains no observations".into(),
            });
        }
        fixture_observations.sort_by_key(|observation| {
            (
                observation.track_id(),
                observation.sequence(),
                observation.modality().stable_code(),
            )
        });
        let recorded_work_estimate = preflight_recorded_work(
            &fixture_observations,
            raw.assessment_step,
            suite.correlation().window(),
        )
        .map_err(|reason| EvidenceConfigError::Invalid { reason })?;

        let mut accepted = Self {
            schema_version: raw.schema_version,
            study_id: raw.study_id,
            base_seed: raw.base_seed,
            calibration_tracks: raw.calibration_tracks,
            holdout_tracks: raw.holdout_tracks,
            frames: raw.frames,
            dt_ms: raw.dt_ms,
            assessment_step: raw.assessment_step,
            alert_episode_reset_policy: raw.alert_episode_reset_policy,
            attack_onset_frame: raw.attack_onset_frame,
            mission_frames: raw.mission_frames,
            rho: raw.rho,
            sigma: raw.sigma,
            loud_bias_sigma: raw.loud_bias_sigma,
            ordinary_missing_probability: raw.ordinary_missing_probability,
            autocorrelation_phis: raw.autocorrelation_phis.into_boxed_slice(),
            covariance_scales: raw.covariance_scales.into_boxed_slice(),
            bootstrap_resamples: raw.bootstrap_resamples,
            min_metric_eligible_tracks: raw.min_metric_eligible_tracks,
            min_recorded_duration_ms: raw.min_recorded_duration_ms,
            work_estimate,
            recorded_work_estimate,
            suite,
            recorded_fixture: VerifiedRecordedFixture {
                configured_path: raw.recorded_fixture.path,
                resolved_path: resolved_fixture,
                sha256: actual_hash,
                bytes: fixture_bytes.into_boxed_slice(),
                observations: fixture_observations.into_boxed_slice(),
            },
            canonical_digest: String::new(),
            artifact_config: Box::new([]),
        };
        let canonical = accepted_config_value(&accepted, None);
        let canonical_bytes = serde_json::to_vec(&canonical)
            .map_err(|source| EvidenceConfigError::CanonicalSerialization { source })?;
        let mut hasher = Sha256::new();
        hasher.update(b"galadriel-evidence-config-v0.9\0");
        hasher.update(&canonical_bytes);
        accepted.canonical_digest = hex_lower(&hasher.finalize());
        let artifact = accepted_config_value(&accepted, Some(&accepted.canonical_digest));
        let mut artifact_config = serde_json::to_vec_pretty(&artifact)
            .map_err(|source| EvidenceConfigError::CanonicalSerialization { source })?;
        artifact_config.push(b'\n');
        accepted.artifact_config = artifact_config.into_boxed_slice();
        Ok(accepted)
    }
}

fn canonicalize_signed_zero(value: &mut f64) {
    if *value == 0.0 {
        *value = 0.0;
    }
}

fn accepted_config_value(
    config: &ValidatedEvidenceConfig,
    digest: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": config.schema_version,
        "classification": "custom_research_evidence",
        "accepted_profile": "galadriel-evidence/custom-v0.9",
        "canonical_digest": digest,
        "runner_contract": {
            "trial_schema": TRIAL_SCHEMA,
            "summary_schema": SUMMARY_SCHEMA,
            "manifest_schema": MANIFEST_SCHEMA,
            "generator_profile": GENERATOR_PROFILE,
            "recorded_replay_profile": RECORDED_REPLAY_PROFILE,
            "missingness_profile": MISSINGNESS_PROFILE,
            "acceptance_metric_profile": ACCEPTANCE_METRIC_PROFILE,
            "delay_p95_definition": "nearest_rank_empirical_p95_milliseconds",
            "attribution_error_definition": "wrong_first_emitted_attribution_after_onset_over_emitted_attributions",
        },
        "study_id": &config.study_id,
        "base_seed": config.base_seed.to_string(),
        "base_seed_decimal": config.base_seed.to_string(),
        "base_seed_hex": format!("0x{:016x}", config.base_seed),
        "calibration_tracks": config.calibration_tracks,
        "holdout_tracks": config.holdout_tracks,
        "frames": config.frames,
        "dt_ms": config.dt_ms,
        "assessment_step": config.assessment_step,
        "alert_episode_reset_policy": config.alert_episode_reset_policy,
        "attack_onset_frame": config.attack_onset_frame,
        "mission_frames": config.mission_frames,
        "rho": config.rho,
        "sigma": config.sigma,
        "loud_bias_sigma": config.loud_bias_sigma,
        "ordinary_missing_probability": config.ordinary_missing_probability,
        "autocorrelation_phis": &config.autocorrelation_phis,
        "covariance_scales": &config.covariance_scales,
        "bootstrap_resamples": config.bootstrap_resamples,
        "min_metric_eligible_tracks": config.min_metric_eligible_tracks,
        "min_recorded_duration_ms": config.min_recorded_duration_ms,
        "detector": {
            "accepted_profile": "custom_evidence_input",
            "window_len": config.suite.detector().window_len(),
            "min_samples": config.suite.detector().min_samples(),
            "min_channels": config.suite.detector().min_channels(),
            "max_seq_gap": config.suite.detector().max_seq_gap(),
            "max_timestamp_skew_ms": config.suite.detector().max_timestamp_skew_ms(),
            "max_inter_sample_gap_ms": config.suite.detector().max_inter_sample_gap_ms(),
            "max_tracks": config.suite.detector().max_tracks(),
            "nis_alpha": config.suite.detector().nis_alpha(),
            "cusum_slack": config.suite.detector().cusum_slack(),
            "cusum_threshold": config.suite.detector().cusum_threshold(),
            "jam_fraction": config.suite.detector().jam_fraction(),
        },
        "correlation": {
            "accepted_profile": config.suite.correlation().source_profile().map(|profile| profile.name()).unwrap_or("custom_evidence_input"),
            "axis_family_count": config.suite.correlation().axis_family_count(),
            "window": config.suite.correlation().window(),
            "min_samples": config.suite.correlation().min_samples(),
            "decouple_ratio": config.suite.correlation().decouple_ratio(),
            "corr_floor": config.suite.correlation().corr_floor(),
            "family_alpha": config.suite.correlation().family_alpha(),
        },
        "release_suite": {
            "accepted_profile": "custom_evidence_input",
            "identity": config.suite.identity(),
            "expected_modalities": config.suite.expected_modalities(),
            "axis_policy": config.suite.axis_policy(),
            "lifecycle_sample_units": config.suite.lifecycle_sample_units(),
            "state_bytes": config.suite.state_bytes(),
        },
        "recorded_fixture": {
            "path": &config.recorded_fixture.configured_path,
            "sha256": &config.recorded_fixture.sha256,
            "bytes": config.recorded_fixture.bytes.len(),
        },
        "preflight_estimate": config.work_estimate,
        "recorded_preflight_estimate": config.recorded_work_estimate,
        "resource_ceilings": {
            "generated_observations": MAX_GENERATED_OBSERVATIONS,
            "correlation_sample_products": MAX_CORRELATION_SAMPLE_PRODUCTS,
            "trace_assessments": MAX_TRACE_ASSESSMENTS,
            "bootstrap_track_draws": MAX_BOOTSTRAP_TRACK_DRAWS,
            "synthetic_generation_resets": MAX_GENERATION_RESETS,
        }
    })
}

#[derive(Clone, Copy)]
struct DuplicateCheckedSeed;

impl<'de> DeserializeSeed<'de> for DuplicateCheckedSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateCheckedVisitor)
    }
}

struct DuplicateCheckedVisitor;

impl<'de> Visitor<'de> for DuplicateCheckedVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateCheckedSeed.deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateCheckedSeed)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            map.next_value_seed(DuplicateCheckedSeed)?;
        }
        Ok(())
    }
}

fn decode_evidence_config(bytes: &[u8]) -> Result<EvidenceConfigFile, EvidenceConfigError> {
    if bytes.len() > MAX_EVIDENCE_CONFIG_BYTES {
        return Err(EvidenceConfigError::ConfigTooLarge {
            actual: bytes.len(),
            maximum: MAX_EVIDENCE_CONFIG_BYTES,
        });
    }
    let mut duplicate_checked = serde_json::Deserializer::from_slice(bytes);
    DuplicateCheckedSeed
        .deserialize(&mut duplicate_checked)
        .and_then(|()| duplicate_checked.end())
        .map_err(|source| EvidenceConfigError::Json { source })?;
    serde_json::from_slice(bytes).map_err(|source| EvidenceConfigError::Json { source })
}

fn reject_duplicate_floats(label: &str, values: &[f64]) -> AppResult<()> {
    let mut bits = HashSet::with_capacity(values.len());
    if values
        .iter()
        .any(|value| !bits.insert(canonical_float_bits(*value)))
    {
        return Err(format!("{label} must not contain duplicates"));
    }
    Ok(())
}

fn canonical_float_bits(value: f64) -> u64 {
    if value == 0.0 {
        0
    } else {
        value.to_bits()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Calibration,
    Holdout,
    RecordedHoldout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AlertEpisodeResetPolicy {
    /// Insufficient and rejected-input outcomes preserve an active episode; only
    /// an explicit nominal assessment clears it.
    NominalOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Perturbation {
    None,
    LoudAcoustic,
    StealthyAcoustic,
    BroadDegradation,
    MissingProjection,
    InvalidProvenance,
}

#[derive(Debug, Clone)]
struct ExperimentSpec {
    id: String,
    kind: String,
    phi: f64,
    covariance_scale: f64,
    missing_probability: f64,
    perturbation: Perturbation,
}

impl ExperimentSpec {
    fn clean(id: String, kind: &str, phi: f64, covariance_scale: f64) -> Self {
        Self {
            id,
            kind: kind.into(),
            phi,
            covariance_scale,
            missing_probability: 0.0,
            perturbation: Perturbation::None,
        }
    }

    fn truth(&self, onset: usize) -> Truth {
        match self.perturbation {
            Perturbation::LoudAcoustic | Perturbation::StealthyAcoustic => Truth {
                class: "attributed_inconsistency".into(),
                channels: vec![Modality::Acoustic],
                onset_frame: Some(onset),
                expected_abstention: false,
            },
            Perturbation::BroadDegradation => Truth {
                class: "broad_degradation".into(),
                channels: Vec::new(),
                onset_frame: Some(onset),
                expected_abstention: false,
            },
            Perturbation::MissingProjection | Perturbation::InvalidProvenance => Truth {
                class: "clean_invalid_or_missing_provenance".into(),
                channels: Vec::new(),
                onset_frame: None,
                expected_abstention: true,
            },
            Perturbation::None => Truth {
                class: "clean".into(),
                channels: Vec::new(),
                onset_frame: None,
                expected_abstention: false,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Truth {
    class: String,
    channels: Vec<Modality>,
    onset_frame: Option<usize>,
    expected_abstention: bool,
}

fn synthetic_specs(config: &ValidatedEvidenceConfig) -> AppResult<Vec<(ExperimentSpec, bool)>> {
    let mut specs = Vec::new();
    for &phi in &config.autocorrelation_phis {
        specs.push((
            ExperimentSpec::clean(
                format!("clean_autocorrelation_phi_{}", float_id(phi)),
                "clean_autocorrelation",
                phi,
                1.0,
            ),
            true,
        ));
    }
    for &scale in &config.covariance_scales {
        if scale == 1.0 {
            continue;
        }
        specs.push((
            ExperimentSpec::clean(
                format!("clean_covariance_scale_{}", float_id(scale)),
                "clean_covariance_sensitivity",
                0.0,
                scale,
            ),
            true,
        ));
    }
    specs.push((
        ExperimentSpec {
            id: "clean_ordinary_missingness".into(),
            kind: "ordinary_missingness".into(),
            phi: 0.0,
            covariance_scale: 1.0,
            missing_probability: config.ordinary_missing_probability,
            perturbation: Perturbation::None,
        },
        true,
    ));
    for (id, kind, perturbation) in [
        (
            "attack_loud_acoustic",
            "targeted_attack",
            Perturbation::LoudAcoustic,
        ),
        (
            "attack_stealthy_acoustic",
            "targeted_attack",
            Perturbation::StealthyAcoustic,
        ),
        (
            "attack_broad_degradation",
            "broad_degradation_attack",
            Perturbation::BroadDegradation,
        ),
        (
            "provenance_missing_projection",
            "provenance_abstention",
            Perturbation::MissingProjection,
        ),
        (
            "provenance_invalid_prior",
            "provenance_abstention",
            Perturbation::InvalidProvenance,
        ),
    ] {
        specs.push((
            ExperimentSpec {
                id: id.into(),
                kind: kind.into(),
                phi: 0.0,
                covariance_scale: 1.0,
                missing_probability: 0.0,
                perturbation,
            },
            false,
        ));
    }
    let mut ids = HashSet::with_capacity(specs.len());
    if specs.iter().any(|(spec, _)| !ids.insert(spec.id.clone())) {
        return Err("generated experiment condition identifiers are not unique".into());
    }
    Ok(specs)
}

fn float_id(value: f64) -> String {
    let normalized = if value == 0.0 { 0.0 } else { value };
    let human = format!("{normalized:.6}")
        .replace('-', "m")
        .replace('.', "p");
    format!("{human}_{:016x}", canonical_float_bits(value))
}

fn fnv1a64(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn mix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn synthetic_track_id(seed: u64) -> AppResult<TrackId> {
    let value = mix64(seed ^ 0x7a6b_1d3e_51c9_4f02) % JSON_SAFE_INTEGER_MAX + 1;
    TrackId::new(value).map_err(|error| error.to_string())
}

fn trial_seed(
    config: &ValidatedEvidenceConfig,
    spec: &ExperimentSpec,
    role: Role,
    trial: usize,
) -> u64 {
    let role_domain = match role {
        Role::Calibration => 0xca11_ba7e_0000_0001,
        Role::Holdout => 0xc1ea_110d_0000_0002,
        Role::RecordedHoldout => 0x5ec0_7ded_0000_0003,
    };
    mix64(
        config.base_seed
            ^ fnv1a64(&spec.id)
            ^ role_domain
            ^ (trial as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15),
    )
}

fn deterministic_missing(seed: u64, frame: usize, modality: Modality, probability: f64) -> bool {
    if probability <= 0.0 || modality != Modality::Acoustic {
        return false;
    }
    let bits = mix64(
        seed ^ (frame as u64).wrapping_mul(0xd1b5_4a32_d192_ed03)
            ^ u64::from(modality.stable_code()),
    );
    let unit = (bits >> 11) as f64 / ((1_u64 << 53) as f64);
    unit < probability
}

fn generate_stream(
    config: &ValidatedEvidenceConfig,
    spec: &ExperimentSpec,
    seed: u64,
    track_id: TrackId,
) -> AppResult<Vec<PidObservation>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let standard = Normal::new(0.0, 1.0).map_err(|error| error.to_string())?;
    let mut common = [0.0; 3];
    let mut phantom = [0.0; 3];
    let mut individual = [[0.0; 3]; 3];
    for axis in 0..3 {
        common[axis] = standard.sample(&mut rng);
        phantom[axis] = standard.sample(&mut rng);
        for modality in &mut individual {
            modality[axis] = standard.sample(&mut rng);
        }
    }
    let ar_noise = (1.0 - spec.phi * spec.phi).sqrt();
    let common_weight = config.rho.sqrt();
    let individual_weight = (1.0 - config.rho).sqrt();
    let declared_variance = config.sigma * config.sigma * spec.covariance_scale;
    if !declared_variance.is_finite() || declared_variance <= 0.0 {
        return Err("declared covariance is not finite and positive".into());
    }
    let covariance = [
        [declared_variance, 0.0, 0.0],
        [0.0, declared_variance, 0.0],
        [0.0, 0.0, declared_variance],
    ];
    let capacity = config
        .frames
        .checked_mul(DEFAULT_MODALITIES.len())
        .ok_or_else(|| "stream capacity overflowed".to_string())?;
    let mut stream = Vec::with_capacity(capacity);

    for frame in 0..config.frames {
        let raw_sequence = frame as u64;
        let sequence = Sequence::new(raw_sequence).map_err(|error| error.to_string())?;
        let raw_timestamp = raw_sequence
            .checked_mul(config.dt_ms)
            .ok_or_else(|| "timestamp overflowed".to_string())?;
        let timestamp = TimestampMillis::new(raw_timestamp).map_err(|error| error.to_string())?;
        if frame > 0 {
            for axis in 0..3 {
                common[axis] = spec.phi * common[axis] + ar_noise * standard.sample(&mut rng);
                phantom[axis] = spec.phi * phantom[axis] + ar_noise * standard.sample(&mut rng);
                for modality in &mut individual {
                    modality[axis] =
                        spec.phi * modality[axis] + ar_noise * standard.sample(&mut rng);
                }
            }
        }
        for (modality_index, &modality) in DEFAULT_MODALITIES.iter().enumerate() {
            if deterministic_missing(seed, frame, modality, spec.missing_probability) {
                continue;
            }
            let decoupled = spec.perturbation == Perturbation::StealthyAcoustic
                && modality == Modality::Acoustic
                && frame >= config.attack_onset_frame;
            let latent = if decoupled { &phantom } else { &common };
            let mut innovation = [0.0; 3];
            for axis in 0..3 {
                innovation[axis] = config.sigma
                    * (common_weight * latent[axis]
                        + individual_weight * individual[modality_index][axis]);
            }
            if spec.perturbation == Perturbation::LoudAcoustic
                && modality == Modality::Acoustic
                && frame >= config.attack_onset_frame
            {
                innovation[0] += config.loud_bias_sigma * config.sigma;
            }
            if spec.perturbation == Perturbation::BroadDegradation
                && frame >= config.attack_onset_frame
            {
                innovation[0] += config.loud_bias_sigma * config.sigma;
            }
            let nis = innovation.iter().map(|value| value * value).sum::<f64>() / declared_variance;
            let projection = match spec.perturbation {
                Perturbation::MissingProjection => None,
                _ => Some(
                    ConsistencyProjection::try_new_raw(
                        innovation,
                        3,
                        1,
                        1,
                        if spec.perturbation == Perturbation::InvalidProvenance
                            && modality == Modality::Acoustic
                        {
                            1_000_000_u64.saturating_add(raw_sequence)
                        } else {
                            raw_sequence + 1
                        },
                    )
                    .map_err(|error| error.to_string())?,
                ),
            };
            let mut observation =
                PidObservation::try_scalar(track_id, timestamp, sequence, modality, nis, 3)
                    .and_then(|observation| observation.try_with_research(innovation, covariance))
                    .map_err(|error| error.to_string())?;
            if let Some(projection) = projection {
                observation = observation.with_consistency_projection(projection);
            }
            stream.push(observation);
        }
    }
    Ok(stream)
}

/// Lowercase hex encoding of a byte slice. `sha2` 0.11's finalize output no longer
/// implements `LowerHex`, so format the digest explicitly; the SHA-256 value is
/// identical to the previous `{:x}` rendering.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex_lower(&digest.finalize())
}

fn sha256_file(path: &Path) -> AppResult<String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex_lower(&digest.finalize()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DetectorId {
    NisBaseline,
    DefaultCorrelationFusion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TraceLabel {
    state: String,
    classification: String,
    channels: Vec<Modality>,
}

impl TraceLabel {
    fn nominal() -> Self {
        Self {
            state: "nominal".into(),
            classification: "nominal".into(),
            channels: Vec::new(),
        }
    }

    fn insufficient() -> Self {
        Self {
            state: "insufficient_evidence".into(),
            classification: "insufficient_evidence".into(),
            channels: Vec::new(),
        }
    }

    fn rejected_input() -> Self {
        Self {
            state: "rejected_input".into(),
            classification: "invalid_consistency_input".into(),
            channels: Vec::new(),
        }
    }

    fn alert(classification: &str, channels: &[Modality]) -> Self {
        let mut channels = channels.to_vec();
        channels.sort_by_key(|modality| modality.stable_code());
        channels.dedup();
        Self {
            state: "alert".into(),
            classification: classification.into(),
            channels,
        }
    }

    fn is_alert(&self) -> bool {
        self.state == "alert"
    }

    fn is_insufficient(&self) -> bool {
        self.state == "insufficient_evidence"
    }

    fn is_rejected_input(&self) -> bool {
        self.state == "rejected_input"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TraceSpan {
    assessment_start: usize,
    assessment_end: usize,
    frame_start: usize,
    frame_end: usize,
    seq_start: u64,
    seq_end: u64,
    label: TraceLabel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AlertEpisode {
    assessment_index: usize,
    frame_index: usize,
    seq: u64,
    timestamp_ms: u64,
    classification: String,
    channels: Vec<Modality>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ConsistencyCounts {
    assessed: usize,
    insufficient_axis: usize,
    missing_projection: usize,
    extraction_error: usize,
    analysis_error: usize,
    too_few_modalities: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RealizedModalityCount {
    modality: Modality,
    observations: usize,
    missing_frames: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DetectorGenerationResetReason {
    SequenceOrTimestampDiscontinuity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DetectorGenerationReset {
    frame_index: usize,
    seq: u64,
    timestamp_ms: u64,
    reason: DetectorGenerationResetReason,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TrialRecord {
    schema: String,
    study_id: String,
    condition: String,
    experiment_kind: String,
    role: Role,
    source: String,
    source_profile: String,
    trial_index: usize,
    /// Exact decimal seed text. Trial seeds span the full `u64` domain and are
    /// therefore strings on the JSON wire rather than lossy binary64 numbers.
    seed: Option<String>,
    seed_hex: Option<String>,
    track_id: u64,
    track_id_hex: String,
    detector: DetectorId,
    modalities: Vec<Modality>,
    truth: Truth,
    phi: Option<f64>,
    covariance_scale: Option<f64>,
    ordinary_missing_probability: Option<f64>,
    frame_count: usize,
    duration_ms: u64,
    assessment_step_frames: usize,
    alert_episode_reset_policy: AlertEpisodeResetPolicy,
    assessments: usize,
    alert_episode_count: usize,
    mission_alert: bool,
    first_alert_assessment: Option<usize>,
    pre_onset_alert: Option<bool>,
    first_post_onset_delay_frames: Option<usize>,
    first_post_onset_delay_ms: Option<u64>,
    attribution_emitted: Option<bool>,
    attribution_correct: Option<bool>,
    insufficient_assessments: usize,
    rejected_input_assessments: usize,
    abstention_assessments: usize,
    abstention_fraction: f64,
    startup_assessments: usize,
    startup_abstention_assessments: usize,
    startup_abstention_fraction: f64,
    monitoring_assessments: usize,
    monitoring_abstention_assessments: usize,
    monitoring_abstention_fraction: f64,
    realized_modality_counts: Vec<RealizedModalityCount>,
    detector_generation_resets: Vec<DetectorGenerationReset>,
    consistency: ConsistencyCounts,
    evidence_status: String,
    status_reasons: Vec<String>,
    alert_episodes: Vec<AlertEpisode>,
    trace: Vec<TraceSpan>,
}

#[derive(Debug, Clone)]
struct TrackMeta<'a> {
    config: &'a ValidatedEvidenceConfig,
    spec: &'a ExperimentSpec,
    role: Role,
    source: &'a str,
    trial_index: usize,
    seed: Option<u64>,
    truth: Truth,
    duration_ms: u64,
    evidence_status: &'a str,
    status_reasons: Vec<String>,
}

struct FinishContext<'a, 'config> {
    meta: &'a TrackMeta<'config>,
    detector: DetectorId,
    track_id: u64,
    modalities: &'a [Modality],
    consistency: ConsistencyCounts,
    frame_count: usize,
    realized_modality_counts: &'a [RealizedModalityCount],
    detector_generation_resets: &'a [DetectorGenerationReset],
}

#[derive(Debug, Default)]
struct TraceAccumulator {
    assessments: usize,
    insufficient_assessments: usize,
    rejected_input_assessments: usize,
    startup_assessments: usize,
    startup_abstention_assessments: usize,
    monitoring_assessments: usize,
    monitoring_abstention_assessments: usize,
    mission_alert: bool,
    alert_episodes: Vec<AlertEpisode>,
    trace: Vec<TraceSpan>,
    previous_alert: bool,
}

impl TraceAccumulator {
    fn observe(
        &mut self,
        frame_index: usize,
        seq: u64,
        timestamp_ms: u64,
        label: TraceLabel,
        mission_frames: usize,
        monitoring_start_frame: usize,
    ) {
        self.assessments += 1;
        let abstention = label.is_insufficient() || label.is_rejected_input();
        if label.is_insufficient() {
            self.insufficient_assessments += 1;
        }
        if label.is_rejected_input() {
            self.rejected_input_assessments += 1;
        }
        if frame_index < monitoring_start_frame {
            self.startup_assessments += 1;
            if abstention {
                self.startup_abstention_assessments += 1;
            }
        } else {
            self.monitoring_assessments += 1;
            if abstention {
                self.monitoring_abstention_assessments += 1;
            }
        }
        if label.is_alert() && frame_index < mission_frames {
            self.mission_alert = true;
        }
        if label.is_alert() && !self.previous_alert {
            self.alert_episodes.push(AlertEpisode {
                assessment_index: self.assessments,
                frame_index,
                seq,
                timestamp_ms,
                classification: label.classification.clone(),
                channels: label.channels.clone(),
            });
        }
        if label.is_alert() {
            self.previous_alert = true;
        } else if label.state == "nominal" {
            self.previous_alert = false;
        }

        if let Some(last) = self.trace.last_mut().filter(|span| span.label == label) {
            last.assessment_end = self.assessments;
            last.frame_end = frame_index;
            last.seq_end = seq;
        } else {
            self.trace.push(TraceSpan {
                assessment_start: self.assessments,
                assessment_end: self.assessments,
                frame_start: frame_index,
                frame_end: frame_index,
                seq_start: seq,
                seq_end: seq,
                label,
            });
        }
    }

    fn finish(self, context: FinishContext<'_, '_>) -> AppResult<TrialRecord> {
        let FinishContext {
            meta,
            detector,
            track_id,
            modalities,
            consistency,
            frame_count,
            realized_modality_counts,
            detector_generation_resets,
        } = context;
        let first_alert_assessment = self
            .alert_episodes
            .first()
            .map(|episode| episode.assessment_index);
        let (
            pre_onset_alert,
            first_post_onset_delay_frames,
            attribution_emitted,
            attribution_correct,
        ) = if let Some(onset) = meta.truth.onset_frame {
            let pre_onset = self
                .alert_episodes
                .iter()
                .any(|episode| episode.frame_index < onset);
            let post = self
                .alert_episodes
                .iter()
                .find(|episode| episode.frame_index >= onset);
            let delay = (!pre_onset)
                .then(|| post.map(|episode| episode.frame_index - onset))
                .flatten();
            let first_attribution = self.trace.iter().find(|span| {
                span.frame_end >= onset && span.label.classification == "attributed_inconsistency"
            });
            let unique_attribution_truth =
                meta.truth.class == "attributed_inconsistency" && meta.truth.channels.len() == 1;
            let attribution_emitted =
                (!pre_onset && unique_attribution_truth).then(|| first_attribution.is_some());
            let attribution_correct = (!pre_onset && unique_attribution_truth)
                .then(|| {
                    first_attribution.map(|span| {
                        let mut observed = span.label.channels.clone();
                        observed.sort_by_key(|modality| modality.stable_code());
                        observed.dedup();
                        let mut expected = meta.truth.channels.clone();
                        expected.sort_by_key(|modality| modality.stable_code());
                        expected.dedup();
                        observed == expected
                    })
                })
                .flatten();
            (
                Some(pre_onset),
                delay,
                attribution_emitted,
                attribution_correct,
            )
        } else {
            (None, None, None, None)
        };
        let first_post_onset_delay_ms = first_post_onset_delay_frames
            .map(|delay_frames| {
                u64::try_from(delay_frames)
                    .map_err(|_| "post-onset delay is not representable as u64".to_string())?
                    .checked_mul(meta.config.dt_ms)
                    .ok_or_else(|| "post-onset delay in milliseconds overflowed u64".to_string())
            })
            .transpose()?;
        let abstention_assessments = self
            .insufficient_assessments
            .saturating_add(self.rejected_input_assessments);
        let abstention_fraction = if self.assessments == 0 {
            0.0
        } else {
            abstention_assessments as f64 / self.assessments as f64
        };
        let startup_abstention_fraction = if self.startup_assessments == 0 {
            0.0
        } else {
            self.startup_abstention_assessments as f64 / self.startup_assessments as f64
        };
        let monitoring_abstention_fraction = if self.monitoring_assessments == 0 {
            0.0
        } else {
            self.monitoring_abstention_assessments as f64 / self.monitoring_assessments as f64
        };
        let mut truth = meta.truth.clone();
        let mut status_reasons = meta.status_reasons.clone();
        if detector == DetectorId::NisBaseline {
            truth.expected_abstention = false;
            status_reasons.retain(|reason| reason != "missing_consistency_projection");
        }
        if !detector_generation_resets.is_empty() {
            status_reasons.push(format!(
                "detector_generation_resets:{}",
                detector_generation_resets.len()
            ));
        }
        let evidence_status = if status_reasons.is_empty() {
            "estimable"
        } else {
            meta.evidence_status
        };
        Ok(TrialRecord {
            schema: TRIAL_SCHEMA.into(),
            study_id: meta.config.study_id.clone(),
            condition: meta.spec.id.clone(),
            experiment_kind: meta.spec.kind.clone(),
            role: meta.role,
            source: meta.source.into(),
            source_profile: if meta.source == "synthetic" {
                GENERATOR_PROFILE.into()
            } else {
                RECORDED_REPLAY_PROFILE.into()
            },
            trial_index: meta.trial_index,
            seed: meta.seed.map(|seed| seed.to_string()),
            seed_hex: meta.seed.map(|seed| format!("0x{seed:016x}")),
            track_id,
            track_id_hex: format!("0x{track_id:016x}"),
            detector,
            modalities: modalities.to_vec(),
            truth,
            phi: (meta.source == "synthetic").then_some(meta.spec.phi),
            covariance_scale: (meta.source == "synthetic").then_some(meta.spec.covariance_scale),
            ordinary_missing_probability: (meta.source == "synthetic")
                .then_some(meta.spec.missing_probability),
            frame_count,
            duration_ms: meta.duration_ms,
            assessment_step_frames: meta.config.assessment_step,
            alert_episode_reset_policy: meta.config.alert_episode_reset_policy,
            assessments: self.assessments,
            alert_episode_count: self.alert_episodes.len(),
            mission_alert: self.mission_alert,
            first_alert_assessment,
            pre_onset_alert,
            first_post_onset_delay_frames,
            first_post_onset_delay_ms,
            attribution_emitted,
            attribution_correct,
            insufficient_assessments: self.insufficient_assessments,
            rejected_input_assessments: self.rejected_input_assessments,
            abstention_assessments,
            abstention_fraction,
            startup_assessments: self.startup_assessments,
            startup_abstention_assessments: self.startup_abstention_assessments,
            startup_abstention_fraction,
            monitoring_assessments: self.monitoring_assessments,
            monitoring_abstention_assessments: self.monitoring_abstention_assessments,
            monitoring_abstention_fraction,
            realized_modality_counts: realized_modality_counts.to_vec(),
            detector_generation_resets: detector_generation_resets.to_vec(),
            consistency,
            evidence_status: evidence_status.into(),
            status_reasons,
            alert_episodes: self.alert_episodes,
            trace: self.trace,
        })
    }
}

fn baseline_label(verdict: &Verdict) -> TraceLabel {
    match verdict {
        Verdict::Nominal => TraceLabel::nominal(),
        Verdict::AttributedInconsistency { channels } => {
            TraceLabel::alert("attributed_inconsistency", channels)
        }
        Verdict::BroadDegradation => TraceLabel::alert("broad_degradation", &[]),
        Verdict::UnclassifiedAnomaly { channels } => {
            TraceLabel::alert("unclassified_anomaly", channels)
        }
        Verdict::InsufficientEvidence => TraceLabel::insufficient(),
    }
}

fn fused_label(verdict: &FusedVerdict) -> TraceLabel {
    match verdict {
        FusedVerdict::Nominal => TraceLabel::nominal(),
        FusedVerdict::AttributedInconsistency { channels, .. } => {
            TraceLabel::alert("attributed_inconsistency", channels)
        }
        FusedVerdict::BroadDegradation => TraceLabel::alert("broad_degradation", &[]),
        FusedVerdict::UnclassifiedAnomaly { channels } => {
            TraceLabel::alert("unclassified_anomaly", channels)
        }
        FusedVerdict::InsufficientEvidence => TraceLabel::insufficient(),
    }
}

fn monitoring_start_frame(config: &ValidatedEvidenceConfig, detector: DetectorId) -> usize {
    let required_samples = match detector {
        DetectorId::NisBaseline => config.suite.detector().min_samples(),
        DetectorId::DefaultCorrelationFusion => config
            .suite
            .detector()
            .min_samples()
            .max(config.suite.correlation().min_samples()),
    };
    required_samples.div_ceil(config.assessment_step) * config.assessment_step - 1
}

fn evaluate_track(
    stream: &[PidObservation],
    modalities: &[Modality],
    meta: &TrackMeta<'_>,
) -> AppResult<[TrialRecord; 2]> {
    if stream.is_empty() {
        return Err(format!(
            "condition {} produced an empty track",
            meta.spec.id
        ));
    }
    let detector_cfg = meta.config.suite.detector();
    let corr_cfg = meta.config.suite.correlation();
    let mut mirror = Mirror::from_release_suite(&meta.config.suite);
    let track_id = stream[0].track_id();
    if stream
        .iter()
        .any(|observation| observation.track_id() != track_id)
    {
        return Err("evaluate_track requires exactly one track".into());
    }

    let mut baseline_trace = TraceAccumulator::default();
    let mut fused_trace = TraceAccumulator::default();
    let mut consistency = ConsistencyCounts::default();
    let mut frame_starts = VecDeque::with_capacity(corr_cfg.window().saturating_add(1));
    let mut last_coordinates = HashMap::<Modality, (Sequence, TimestampMillis)>::new();
    let mut detector_generation_resets = Vec::<DetectorGenerationReset>::new();
    let mut frame_start = 0usize;
    let mut frame_index = 0usize;
    while frame_start < stream.len() {
        let seq = stream[frame_start].sequence();
        let mut frame_end = frame_start + 1;
        while frame_end < stream.len() && stream[frame_end].sequence() == seq {
            frame_end += 1;
        }
        let frame = &stream[frame_start..frame_end];
        let timestamp_ms = frame
            .iter()
            .map(PidObservation::timestamp_ms)
            .max()
            .ok_or_else(|| "track frame unexpectedly contained no observations".to_string())?;
        let preemptive_reset = frame.iter().any(|observation| {
            last_coordinates.get(&observation.modality()).is_some_and(
                |(last_sequence, last_timestamp)| {
                    observation.sequence() > *last_sequence
                        && observation.timestamp_ms() > *last_timestamp
                        && (observation.sequence().get() - last_sequence.get()
                            > detector_cfg.max_seq_gap()
                            || observation.timestamp_ms().get() - last_timestamp.get()
                                > detector_cfg.max_inter_sample_gap_ms())
                },
            )
        });
        if preemptive_reset {
            mirror = Mirror::from_release_suite(&meta.config.suite);
            last_coordinates.clear();
            frame_starts.clear();
            detector_generation_resets.push(DetectorGenerationReset {
                frame_index,
                seq: seq.get(),
                timestamp_ms: timestamp_ms.get(),
                reason: DetectorGenerationResetReason::SequenceOrTimestampDiscontinuity,
            });
        }

        if let Err(error) = frame
            .iter()
            .try_for_each(|observation| mirror.ingest_checked(observation))
        {
            if error.code() != FailureCode::ResetRequired {
                return Err(format!(
                    "{} track {track_id} ingest at seq {seq}: {error:?}",
                    meta.spec.id
                ));
            }
            mirror = Mirror::from_release_suite(&meta.config.suite);
            last_coordinates.clear();
            frame_starts.clear();
            if !preemptive_reset {
                detector_generation_resets.push(DetectorGenerationReset {
                    frame_index,
                    seq: seq.get(),
                    timestamp_ms: timestamp_ms.get(),
                    reason: DetectorGenerationResetReason::SequenceOrTimestampDiscontinuity,
                });
            }
            frame
                .iter()
                .try_for_each(|observation| mirror.ingest_checked(observation))
                .map_err(|retry_error| {
                    format!(
                        "{} track {track_id} ingest after explicit generation reset at seq {seq}: {retry_error:?}",
                        meta.spec.id
                    )
                })?;
        }
        for observation in frame {
            last_coordinates.insert(
                observation.modality(),
                (observation.sequence(), observation.timestamp_ms()),
            );
        }
        frame_starts.push_back(frame_start);
        if frame_starts.len() > corr_cfg.window() {
            frame_starts.pop_front();
        }
        let final_frame = frame_end == stream.len();
        let assess_now =
            (frame_index + 1).is_multiple_of(meta.config.assessment_step) || final_frame;
        if assess_now {
            let baseline = mirror
                .assess(track_id, seq)
                .map_err(|error| format!("{} assess at seq {seq}: {error}", meta.spec.id))?;
            let tail_start = frame_starts.front().copied().unwrap_or(frame_start);
            let mut correlations = Vec::<AxisCorrelationReport>::new();
            let mut rejected_input = false;
            if modalities.len() < detector_cfg.min_channels() {
                consistency.too_few_modalities += 1;
            } else {
                match consistency_channels_with_temporal_limits(
                    &stream[tail_start..frame_end],
                    modalities,
                    detector_cfg.max_seq_gap(),
                    detector_cfg.max_timestamp_skew_ms(),
                    detector_cfg.max_inter_sample_gap_ms(),
                ) {
                    Ok(Some(projection)) => {
                        let axis_count = projection.axes.len();
                        let adjusted =
                            corr_cfg.try_for_axis_family(axis_count).map_err(|error| {
                                format!(
                                    "{} correlation family derivation at seq {seq}: {error}",
                                    meta.spec.id
                                )
                            })?;
                        let mut analysis_failed = false;
                        for (axis, channels) in projection.axes.iter().enumerate() {
                            match correlation::analyze(channels, &adjusted) {
                                Ok(report) => correlations.push(
                                    AxisCorrelationReport::try_new(axis, report).map_err(
                                        |error| {
                                            format!(
                                                "{} correlation axis wrapper at seq {seq}: {error}",
                                                meta.spec.id
                                            )
                                        },
                                    )?,
                                ),
                                Err(_) => {
                                    analysis_failed = true;
                                    rejected_input = true;
                                    correlations.clear();
                                    break;
                                }
                            }
                        }
                        if analysis_failed {
                            consistency.analysis_error += 1;
                        } else if correlations.is_empty()
                            || correlations.iter().any(|axis| {
                                matches!(axis.report().verdict(), CorrVerdict::InsufficientEvidence)
                            })
                        {
                            consistency.insufficient_axis += 1;
                        } else {
                            consistency.assessed += 1;
                        }
                    }
                    Ok(None) => consistency.missing_projection += 1,
                    Err(_) => {
                        consistency.extraction_error += 1;
                        rejected_input = true;
                    }
                }
            }
            let (fused, _) = combine_correlation_axes(&meta.config.suite, &baseline, &correlations)
                .map_err(|error| {
                    format!(
                        "{} correlation fusion provenance at seq {seq}: {error}",
                        meta.spec.id
                    )
                })?;
            baseline_trace.observe(
                frame_index,
                seq.get(),
                timestamp_ms.get(),
                baseline_label(baseline.verdict()),
                meta.config.mission_frames,
                monitoring_start_frame(meta.config, DetectorId::NisBaseline),
            );
            let fused_outcome = if rejected_input {
                TraceLabel::rejected_input()
            } else {
                fused_label(&fused)
            };
            fused_trace.observe(
                frame_index,
                seq.get(),
                timestamp_ms.get(),
                fused_outcome,
                meta.config.mission_frames,
                monitoring_start_frame(meta.config, DetectorId::DefaultCorrelationFusion),
            );
        }
        frame_index += 1;
        frame_start = frame_end;
    }

    let realized_modality_counts = modalities
        .iter()
        .map(|&modality| {
            let observations = stream
                .iter()
                .filter(|observation| observation.modality() == modality)
                .count();
            RealizedModalityCount {
                modality,
                observations,
                missing_frames: frame_index.saturating_sub(observations),
            }
        })
        .collect::<Vec<_>>();
    let baseline = baseline_trace.finish(FinishContext {
        meta,
        detector: DetectorId::NisBaseline,
        track_id: track_id.get(),
        modalities,
        consistency: ConsistencyCounts::default(),
        frame_count: frame_index,
        realized_modality_counts: &realized_modality_counts,
        detector_generation_resets: &detector_generation_resets,
    })?;
    let fused = fused_trace.finish(FinishContext {
        meta,
        detector: DetectorId::DefaultCorrelationFusion,
        track_id: track_id.get(),
        modalities,
        consistency,
        frame_count: frame_index,
        realized_modality_counts: &realized_modality_counts,
        detector_generation_resets: &detector_generation_resets,
    })?;
    Ok([baseline, fused])
}

fn run_synthetic(config: &ValidatedEvidenceConfig) -> AppResult<Vec<TrialRecord>> {
    let specs = synthetic_specs(config)?;
    let clean_spec_count = specs.iter().filter(|(_, calibrated)| *calibrated).count();
    let tracks_per_clean_condition = config
        .calibration_tracks
        .checked_add(config.holdout_tracks)
        .ok_or_else(|| "calibration + holdout track count overflowed".to_string())?;
    let clean_tracks = clean_spec_count
        .checked_mul(tracks_per_clean_condition)
        .ok_or_else(|| "synthetic clean track count overflowed".to_string())?;
    let other_spec_count = specs
        .len()
        .checked_sub(clean_spec_count)
        .ok_or_else(|| "synthetic condition count underflowed".to_string())?;
    let other_tracks = other_spec_count
        .checked_mul(config.holdout_tracks)
        .ok_or_else(|| "synthetic non-clean track count overflowed".to_string())?;
    let track_count = clean_tracks
        .checked_add(other_tracks)
        .ok_or_else(|| "synthetic track count overflowed".to_string())?;
    let record_capacity = track_count
        .checked_mul(2)
        .ok_or_else(|| "synthetic record count overflowed".to_string())?;
    let mut records = Vec::with_capacity(record_capacity);
    for (spec, has_calibration_partition) in &specs {
        let roles: &[(Role, usize)] = if *has_calibration_partition {
            &[
                (Role::Calibration, config.calibration_tracks),
                (Role::Holdout, config.holdout_tracks),
            ]
        } else {
            &[(Role::Holdout, config.holdout_tracks)]
        };
        for &(role, trials) in roles {
            for trial_index in 0..trials {
                let seed = trial_seed(config, spec, role, trial_index);
                let track_id = synthetic_track_id(seed)?;
                let stream = generate_stream(config, spec, seed, track_id)?;
                let duration_ms = (config.frames.saturating_sub(1) as u64)
                    .checked_mul(config.dt_ms)
                    .ok_or_else(|| "synthetic duration overflowed".to_string())?;
                let meta = TrackMeta {
                    config,
                    spec,
                    role,
                    source: "synthetic",
                    trial_index,
                    seed: Some(seed),
                    truth: spec.truth(config.attack_onset_frame),
                    duration_ms,
                    evidence_status: "estimable",
                    status_reasons: Vec::new(),
                };
                records.extend(evaluate_track(&stream, &DEFAULT_MODALITIES, &meta)?);
            }
        }
    }
    Ok(records)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecordedRunInfo {
    configured_path: String,
    resolved_path: String,
    sha256: String,
    bytes: u64,
    observations: usize,
    tracks: usize,
    projection_observations: usize,
    total_duration_ms: u64,
    detector_generation_resets: usize,
    tracks_with_detector_generation_resets: usize,
    evidence_status: String,
    status_reasons: Vec<String>,
}

fn preflight_recorded_work(
    observations: &[PidObservation],
    assessment_step: usize,
    correlation_window: usize,
) -> AppResult<RecordedWorkEstimate> {
    if assessment_step == 0 || correlation_window == 0 {
        return Err(
            "recorded preflight requires nonzero assessment step and correlation window".into(),
        );
    }
    let mut trace_assessments = 0usize;
    let mut correlation_work = 0usize;
    let mut maximum_generation_resets = 0usize;
    let mut tracks = 0usize;
    let mut track_start = 0usize;
    while track_start < observations.len() {
        let track_id = observations[track_start].track_id();
        let mut track_end = track_start + 1;
        while track_end < observations.len() && observations[track_end].track_id() == track_id {
            track_end += 1;
        }
        let stream = &observations[track_start..track_end];
        let frames = 1 + stream
            .windows(2)
            .filter(|pair| pair[0].sequence() != pair[1].sequence())
            .count();
        let modality_count = stream
            .iter()
            .map(PidObservation::modality)
            .collect::<HashSet<_>>()
            .len();
        let modality_pairs = modality_count * modality_count.saturating_sub(1) / 2;
        tracks = tracks
            .checked_add(1)
            .ok_or_else(|| "recorded track count overflowed".to_string())?;
        let assessments = frames.div_ceil(assessment_step);
        maximum_generation_resets = maximum_generation_resets
            .checked_add(frames.saturating_sub(1))
            .ok_or_else(|| "recorded generation-reset estimate overflowed".to_string())?;
        trace_assessments = trace_assessments
            .checked_add(
                assessments
                    .checked_mul(2)
                    .ok_or_else(|| "recorded trace work estimate overflowed".to_string())?,
            )
            .ok_or_else(|| "recorded trace work estimate overflowed".to_string())?;
        let track_correlation_work = assessments
            .checked_mul(3)
            .and_then(|work| work.checked_mul(modality_pairs))
            .and_then(|work| work.checked_mul(correlation_window.min(frames)))
            .ok_or_else(|| "recorded correlation work estimate overflowed".to_string())?;
        correlation_work = correlation_work
            .checked_add(track_correlation_work)
            .ok_or_else(|| "recorded correlation work estimate overflowed".to_string())?;
        track_start = track_end;
    }
    if trace_assessments > MAX_TRACE_ASSESSMENTS {
        return Err(format!(
            "recorded fixture requests about {trace_assessments} detector assessments in trial traces; maximum is {MAX_TRACE_ASSESSMENTS}"
        ));
    }
    if correlation_work > MAX_CORRELATION_SAMPLE_PRODUCTS {
        return Err(format!(
            "recorded fixture requests about {correlation_work} correlation pair-sample products; maximum is {MAX_CORRELATION_SAMPLE_PRODUCTS}"
        ));
    }
    if maximum_generation_resets > MAX_GENERATION_RESETS {
        return Err(format!(
            "recorded fixture can require up to {maximum_generation_resets} explicit detector-generation resets; maximum is {MAX_GENERATION_RESETS}"
        ));
    }
    Ok(RecordedWorkEstimate {
        tracks,
        trial_records: tracks
            .checked_mul(2)
            .ok_or_else(|| "recorded trial-record count overflowed".to_string())?,
        observations: observations.len(),
        trace_assessments,
        correlation_sample_products: correlation_work,
        maximum_generation_resets,
    })
}

fn add_recorded_duration(total_duration_ms: &mut u64, duration_ms: u64) -> AppResult<()> {
    *total_duration_ms = total_duration_ms
        .checked_add(duration_ms)
        .ok_or_else(|| "recorded total duration overflowed u64".to_string())?;
    Ok(())
}

fn run_recorded(
    config: &ValidatedEvidenceConfig,
) -> AppResult<(Vec<TrialRecord>, RecordedRunInfo)> {
    let fixture_bytes = &config.recorded_fixture.bytes;
    let fixture_path = &config.recorded_fixture.resolved_path;
    let observations = &config.recorded_fixture.observations;
    let projection_observations = observations
        .iter()
        .filter(|observation| observation.consistency_projection().is_some())
        .count();
    let spec = ExperimentSpec {
        id: "recorded_crebain_clean".into(),
        kind: "recorded_smoke".into(),
        phi: 0.0,
        covariance_scale: 1.0,
        missing_probability: 0.0,
        perturbation: Perturbation::None,
    };
    let mut records = Vec::new();
    let mut total_duration_ms = 0_u64;
    let mut track_start = 0usize;
    let mut trial_index = 0usize;
    let mut all_reasons = Vec::<String>::new();
    let mut detector_generation_resets = 0usize;
    let mut tracks_with_detector_generation_resets = 0usize;
    while track_start < observations.len() {
        let track_id = observations[track_start].track_id();
        let mut track_end = track_start + 1;
        while track_end < observations.len() && observations[track_end].track_id() == track_id {
            track_end += 1;
        }
        let stream = &observations[track_start..track_end];
        let minimum_timestamp = stream
            .iter()
            .map(|observation| observation.timestamp_ms().get())
            .min()
            .unwrap_or(0);
        let maximum_timestamp = stream
            .iter()
            .map(|observation| observation.timestamp_ms().get())
            .max()
            .unwrap_or(minimum_timestamp);
        let duration_ms = maximum_timestamp - minimum_timestamp;
        add_recorded_duration(&mut total_duration_ms, duration_ms)?;
        let mut reasons = Vec::new();
        if duration_ms < config.min_recorded_duration_ms {
            reasons.push(format!(
                "insufficient_duration: {duration_ms} ms is below configured minimum {} ms",
                config.min_recorded_duration_ms
            ));
        }
        let missing_projection = stream
            .iter()
            .all(|observation| observation.consistency_projection().is_none());
        if missing_projection {
            reasons.push("missing_consistency_projection".into());
        }
        all_reasons.extend(reasons.iter().cloned());
        let mut modalities = stream
            .iter()
            .map(PidObservation::modality)
            .collect::<Vec<_>>();
        modalities.sort_by_key(|modality| modality.stable_code());
        modalities.dedup();
        let evidence_status = if reasons.is_empty() {
            "estimable"
        } else {
            "not_estimable"
        };
        let mut truth = spec.truth(config.attack_onset_frame);
        if missing_projection {
            truth.class = "clean_invalid_or_missing_provenance".into();
            truth.expected_abstention = true;
        }
        let meta = TrackMeta {
            config,
            spec: &spec,
            role: Role::RecordedHoldout,
            source: "recorded",
            trial_index,
            seed: None,
            truth,
            duration_ms,
            evidence_status,
            status_reasons: reasons,
        };
        let evaluated = evaluate_track(stream, &modalities, &meta)?;
        let track_resets = evaluated[0].detector_generation_resets.len();
        detector_generation_resets = detector_generation_resets
            .checked_add(track_resets)
            .ok_or_else(|| "recorded generation-reset count overflowed".to_string())?;
        tracks_with_detector_generation_resets = tracks_with_detector_generation_resets
            .checked_add(usize::from(track_resets > 0))
            .ok_or_else(|| "recorded reset-track count overflowed".to_string())?;
        records.extend(evaluated);
        trial_index += 1;
        track_start = track_end;
    }
    all_reasons.sort();
    all_reasons.dedup();
    let info = RecordedRunInfo {
        configured_path: config.recorded_fixture.configured_path.clone(),
        resolved_path: fixture_path.display().to_string(),
        sha256: config.recorded_fixture.sha256.clone(),
        bytes: u64::try_from(fixture_bytes.len())
            .map_err(|_| "recorded fixture length does not fit u64".to_string())?,
        observations: observations.len(),
        tracks: trial_index,
        projection_observations,
        total_duration_ms,
        detector_generation_resets,
        tracks_with_detector_generation_resets,
        evidence_status: if all_reasons.is_empty() {
            "estimable".into()
        } else {
            "not_estimable".into()
        },
        status_reasons: all_reasons,
    };
    Ok((records, info))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricKind {
    FalseAlertsPerHour,
    MissionProbabilityAnyAlert,
    Arl0Assessments,
    Arl0CensoringFraction,
    AbstentionFraction,
    AnyAlertProbability,
    PreOnsetAlertProbability,
    ConditionalDetectionProbability,
    ConditionalDelayFrames,
    ConditionalDelayP95Millis,
    ConditionalAttributionCoverage,
    ConditionalAttributionAccuracy,
    ConditionalAttributionError,
}

impl MetricKind {
    fn id(self) -> &'static str {
        match self {
            Self::FalseAlertsPerHour => "false_alerts_per_hour",
            Self::MissionProbabilityAnyAlert => "mission_probability_any_alert",
            Self::Arl0Assessments => "arl0_assessments",
            Self::Arl0CensoringFraction => "arl0_censoring_fraction",
            Self::AbstentionFraction => "abstention_fraction",
            Self::AnyAlertProbability => "any_alert_probability",
            Self::PreOnsetAlertProbability => "pre_onset_alert_probability",
            Self::ConditionalDetectionProbability => "conditional_detection_probability",
            Self::ConditionalDelayFrames => "conditional_delay_frames",
            Self::ConditionalDelayP95Millis => "conditional_delay_p95_ms",
            Self::ConditionalAttributionCoverage => "conditional_attribution_coverage",
            Self::ConditionalAttributionAccuracy => "conditional_attribution_accuracy",
            Self::ConditionalAttributionError => "conditional_attribution_error",
        }
    }

    fn unit(self) -> &'static str {
        match self {
            Self::FalseAlertsPerHour => "alert_episodes/hour",
            Self::Arl0Assessments => "assessments",
            Self::ConditionalDelayFrames => "frames",
            Self::ConditionalDelayP95Millis => "ms",
            Self::MissionProbabilityAnyAlert
            | Self::Arl0CensoringFraction
            | Self::AbstentionFraction
            | Self::AnyAlertProbability
            | Self::PreOnsetAlertProbability
            | Self::ConditionalDetectionProbability
            | Self::ConditionalAttributionCoverage
            | Self::ConditionalAttributionAccuracy
            | Self::ConditionalAttributionError => "probability",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::FalseAlertsPerHour => "pooled alert episodes / pooled track exposure",
            Self::Arl0Assessments => {
                "restricted mean time to first alert; right-censored at each track end"
            }
            Self::ConditionalDelayFrames => {
                "median first post-onset alert delay among detected tracks without pre-onset alert"
            }
            Self::ConditionalDelayP95Millis => {
                "nearest-rank empirical 95th percentile of first post-onset alert delay in milliseconds among detected tracks without pre-onset alert"
            }
            Self::ConditionalDetectionProbability => {
                "detected tracks / tracks without a pre-onset alert"
            }
            Self::ConditionalAttributionCoverage => {
                "tracks emitting an attribution / uniquely altered tracks without a pre-onset alert"
            }
            Self::ConditionalAttributionAccuracy => {
                "correct first attribution / tracks emitting an attribution"
            }
            Self::ConditionalAttributionError => {
                "wrong first attribution / tracks emitting an attribution"
            }
            Self::AbstentionFraction => {
                "post-warm-up pooled insufficient-or-rejected assessments / pooled monitoring assessments"
            }
            Self::MissionProbabilityAnyAlert
            | Self::Arl0CensoringFraction
            | Self::AnyAlertProbability
            | Self::PreOnsetAlertProbability => "track-level proportion",
        }
    }

    fn is_track_binomial(self) -> bool {
        matches!(
            self,
            Self::MissionProbabilityAnyAlert
                | Self::Arl0CensoringFraction
                | Self::AnyAlertProbability
                | Self::PreOnsetAlertProbability
                | Self::ConditionalDetectionProbability
                | Self::ConditionalAttributionCoverage
                | Self::ConditionalAttributionAccuracy
                | Self::ConditionalAttributionError
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MetricEstimate {
    status: String,
    value: Option<f64>,
    ci95: Option<[f64; 2]>,
    ci_status: String,
    unit: String,
    estimator: String,
    interval: String,
    tracks: usize,
    eligible_tracks: usize,
    bootstrap_requested: usize,
    bootstrap_usable: usize,
}

impl MetricEstimate {
    fn not_applicable(kind: MetricKind, tracks: usize) -> Self {
        Self {
            status: "not_applicable".into(),
            value: None,
            ci95: None,
            ci_status: "not_applicable".into(),
            unit: kind.unit().into(),
            estimator: kind.method().into(),
            interval: "none".into(),
            tracks,
            eligible_tracks: 0,
            bootstrap_requested: 0,
            bootstrap_usable: 0,
        }
    }
}

fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        Some(values[middle - 1] / 2.0 + values[middle] / 2.0)
    } else {
        Some(values[middle])
    }
}

fn nearest_rank_p95(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let rank = values.len().checked_mul(95)?.div_ceil(100);
    values.get(rank.saturating_sub(1)).copied()
}

fn statistic(records: &[&TrialRecord], kind: MetricKind) -> (Option<f64>, usize) {
    match kind {
        MetricKind::FalseAlertsPerHour => {
            let exposure_hours = records
                .iter()
                .map(|record| record.duration_ms as f64 / 3_600_000.0)
                .sum::<f64>();
            let episodes = records
                .iter()
                .map(|record| record.alert_episode_count)
                .sum::<usize>();
            (
                (exposure_hours > 0.0).then_some(episodes as f64 / exposure_hours),
                records.len(),
            )
        }
        MetricKind::MissionProbabilityAnyAlert => (
            (!records.is_empty()).then(|| {
                records.iter().filter(|record| record.mission_alert).count() as f64
                    / records.len() as f64
            }),
            records.len(),
        ),
        MetricKind::Arl0Assessments => (
            (!records.is_empty()).then(|| {
                records
                    .iter()
                    .map(|record| {
                        record.first_alert_assessment.unwrap_or(record.assessments) as f64
                    })
                    .sum::<f64>()
                    / records.len() as f64
            }),
            records.len(),
        ),
        MetricKind::Arl0CensoringFraction => (
            (!records.is_empty()).then(|| {
                records
                    .iter()
                    .filter(|record| record.first_alert_assessment.is_none())
                    .count() as f64
                    / records.len() as f64
            }),
            records.len(),
        ),
        MetricKind::AbstentionFraction => {
            let assessments = records
                .iter()
                .map(|record| record.monitoring_assessments)
                .sum::<usize>();
            let insufficient = records
                .iter()
                .map(|record| record.monitoring_abstention_assessments)
                .sum::<usize>();
            (
                (assessments > 0).then_some(insufficient as f64 / assessments as f64),
                records.len(),
            )
        }
        MetricKind::AnyAlertProbability => (
            (!records.is_empty()).then(|| {
                records
                    .iter()
                    .filter(|record| record.alert_episode_count > 0)
                    .count() as f64
                    / records.len() as f64
            }),
            records.len(),
        ),
        MetricKind::PreOnsetAlertProbability => {
            let eligible = records
                .iter()
                .filter_map(|record| record.pre_onset_alert)
                .collect::<Vec<_>>();
            (
                (!eligible.is_empty()).then(|| {
                    eligible.iter().filter(|value| **value).count() as f64 / eligible.len() as f64
                }),
                eligible.len(),
            )
        }
        MetricKind::ConditionalDetectionProbability => {
            let eligible = records
                .iter()
                .filter(|record| record.pre_onset_alert == Some(false))
                .collect::<Vec<_>>();
            (
                (!eligible.is_empty()).then(|| {
                    eligible
                        .iter()
                        .filter(|record| record.first_post_onset_delay_frames.is_some())
                        .count() as f64
                        / eligible.len() as f64
                }),
                eligible.len(),
            )
        }
        MetricKind::ConditionalDelayFrames => {
            let mut delays = records
                .iter()
                .filter(|record| record.pre_onset_alert == Some(false))
                .filter_map(|record| record.first_post_onset_delay_frames)
                .map(|delay| delay as f64)
                .collect::<Vec<_>>();
            let eligible = delays.len();
            (median(&mut delays), eligible)
        }
        MetricKind::ConditionalDelayP95Millis => {
            let mut delays = records
                .iter()
                .filter(|record| record.pre_onset_alert == Some(false))
                .filter_map(|record| record.first_post_onset_delay_ms)
                .map(|delay_ms| delay_ms as f64)
                .collect::<Vec<_>>();
            let eligible = delays.len();
            (nearest_rank_p95(&mut delays), eligible)
        }
        MetricKind::ConditionalAttributionCoverage => {
            let values = records
                .iter()
                .filter_map(|record| record.attribution_emitted)
                .collect::<Vec<_>>();
            (
                (!values.is_empty()).then(|| {
                    values.iter().filter(|value| **value).count() as f64 / values.len() as f64
                }),
                values.len(),
            )
        }
        MetricKind::ConditionalAttributionAccuracy => {
            let values = records
                .iter()
                .filter(|record| record.pre_onset_alert == Some(false))
                .filter_map(|record| record.attribution_correct)
                .collect::<Vec<_>>();
            (
                (!values.is_empty()).then(|| {
                    values.iter().filter(|value| **value).count() as f64 / values.len() as f64
                }),
                values.len(),
            )
        }
        MetricKind::ConditionalAttributionError => {
            let values = records
                .iter()
                .filter_map(|record| record.attribution_correct)
                .collect::<Vec<_>>();
            (
                (!values.is_empty()).then(|| {
                    values.iter().filter(|value| !**value).count() as f64 / values.len() as f64
                }),
                values.len(),
            )
        }
    }
}

fn binomial_counts(records: &[&TrialRecord], kind: MetricKind) -> Option<(usize, usize)> {
    let (successes, trials) = match kind {
        MetricKind::MissionProbabilityAnyAlert => (
            records.iter().filter(|record| record.mission_alert).count(),
            records.len(),
        ),
        MetricKind::Arl0CensoringFraction => (
            records
                .iter()
                .filter(|record| record.first_alert_assessment.is_none())
                .count(),
            records.len(),
        ),
        MetricKind::AnyAlertProbability => (
            records
                .iter()
                .filter(|record| record.alert_episode_count > 0)
                .count(),
            records.len(),
        ),
        MetricKind::PreOnsetAlertProbability => {
            let values = records
                .iter()
                .filter_map(|record| record.pre_onset_alert)
                .collect::<Vec<_>>();
            (values.iter().filter(|value| **value).count(), values.len())
        }
        MetricKind::ConditionalDetectionProbability => {
            let eligible = records
                .iter()
                .filter(|record| record.pre_onset_alert == Some(false))
                .collect::<Vec<_>>();
            (
                eligible
                    .iter()
                    .filter(|record| record.first_post_onset_delay_frames.is_some())
                    .count(),
                eligible.len(),
            )
        }
        MetricKind::ConditionalAttributionCoverage => {
            let values = records
                .iter()
                .filter_map(|record| record.attribution_emitted)
                .collect::<Vec<_>>();
            (values.iter().filter(|value| **value).count(), values.len())
        }
        MetricKind::ConditionalAttributionAccuracy => {
            let values = records
                .iter()
                .filter(|record| record.pre_onset_alert == Some(false))
                .filter_map(|record| record.attribution_correct)
                .collect::<Vec<_>>();
            (values.iter().filter(|value| **value).count(), values.len())
        }
        MetricKind::ConditionalAttributionError => {
            let values = records
                .iter()
                .filter_map(|record| record.attribution_correct)
                .collect::<Vec<_>>();
            (values.iter().filter(|value| !**value).count(), values.len())
        }
        MetricKind::FalseAlertsPerHour
        | MetricKind::Arl0Assessments
        | MetricKind::AbstentionFraction
        | MetricKind::ConditionalDelayFrames
        | MetricKind::ConditionalDelayP95Millis => return None,
    };
    (trials > 0).then_some((successes, trials))
}

fn alert_rate_parts(records: &[&TrialRecord]) -> (usize, f64) {
    let events = records
        .iter()
        .map(|record| record.alert_episode_count)
        .sum();
    let exposure_hours = records
        .iter()
        .map(|record| record.duration_ms as f64 / 3_600_000.0)
        .sum();
    (events, exposure_hours)
}

fn garwood_rate_ci(events: usize, exposure_hours: f64) -> Option<[f64; 2]> {
    if !exposure_hours.is_finite() || exposure_hours <= 0.0 {
        return None;
    }
    let lower = if events == 0 {
        0.0
    } else {
        let distribution = ChiSquared::new(2.0 * events as f64).ok()?;
        0.5 * distribution.inverse_cdf(0.025) / exposure_hours
    };
    let distribution = ChiSquared::new(2.0 * events.saturating_add(1) as f64).ok()?;
    let upper = 0.5 * distribution.inverse_cdf(0.975) / exposure_hours;
    (lower.is_finite() && upper.is_finite() && lower <= upper).then_some([lower, upper])
}

fn interval_envelope(model: [f64; 2], bootstrap: Option<[f64; 2]>) -> [f64; 2] {
    bootstrap.map_or(model, |bootstrap| {
        [model[0].min(bootstrap[0]), model[1].max(bootstrap[1])]
    })
}

fn hoeffding_bounded_mean_ci(
    mean: f64,
    lower_bound: f64,
    upper_bound: f64,
    sum_squared_weights: f64,
) -> Option<[f64; 2]> {
    if !mean.is_finite()
        || !lower_bound.is_finite()
        || !upper_bound.is_finite()
        || !sum_squared_weights.is_finite()
        || lower_bound >= upper_bound
        || sum_squared_weights <= 0.0
    {
        return None;
    }
    let radius =
        (upper_bound - lower_bound) * (sum_squared_weights * (2.0_f64 / 0.05).ln() / 2.0).sqrt();
    Some([
        (mean - radius).max(lower_bound),
        (mean + radius).min(upper_bound),
    ])
}

fn abstention_hoeffding_ci(records: &[&TrialRecord], point: f64) -> Option<[f64; 2]> {
    let total = records
        .iter()
        .map(|record| record.monitoring_assessments)
        .sum::<usize>();
    if total == 0 {
        return None;
    }
    let sum_squared_weights = records
        .iter()
        .map(|record| {
            let weight = record.monitoring_assessments as f64 / total as f64;
            weight * weight
        })
        .sum();
    hoeffding_bounded_mean_ci(point, 0.0, 1.0, sum_squared_weights)
}

fn arl0_hoeffding_ci(records: &[&TrialRecord], point: f64) -> Option<[f64; 2]> {
    let horizon = records.iter().map(|record| record.assessments).max()? as f64;
    let sum_squared_weights = 1.0 / records.len() as f64;
    hoeffding_bounded_mean_ci(point, 0.0, horizon, sum_squared_weights)
}

fn bootstrap_sample_is_sufficient(usable: usize, requested: usize) -> bool {
    usable.saturating_mul(5) >= requested.saturating_mul(4)
}

fn percentile(sorted: &[f64], probability: f64) -> f64 {
    let index = (probability * (sorted.len().saturating_sub(1)) as f64).floor() as usize;
    sorted[index]
}

fn estimate_metric(
    records: &[&TrialRecord],
    kind: MetricKind,
    config: &ValidatedEvidenceConfig,
    group_id: &str,
) -> MetricEstimate {
    let (point, eligible_tracks) = statistic(records, kind);
    let Some(point) = point else {
        return MetricEstimate {
            status: "not_estimable".into(),
            value: None,
            ci95: None,
            ci_status: "not_estimable".into(),
            unit: kind.unit().into(),
            estimator: kind.method().into(),
            interval: "none: no eligible tracks".into(),
            tracks: records.len(),
            eligible_tracks,
            bootstrap_requested: config.bootstrap_resamples,
            bootstrap_usable: 0,
        };
    };
    if matches!(
        kind,
        MetricKind::ConditionalDetectionProbability
            | MetricKind::ConditionalDelayFrames
            | MetricKind::ConditionalDelayP95Millis
            | MetricKind::ConditionalAttributionAccuracy
            | MetricKind::ConditionalAttributionError
    ) && eligible_tracks < config.min_metric_eligible_tracks
    {
        return MetricEstimate {
            status: "descriptive_sparse".into(),
            value: Some(point),
            ci95: None,
            ci_status: "not_estimable_sparse".into(),
            unit: kind.unit().into(),
            estimator: kind.method().into(),
            interval: format!(
                "not estimable: {eligible_tracks} eligible tracks is below configured minimum {}",
                config.min_metric_eligible_tracks
            ),
            tracks: records.len(),
            eligible_tracks,
            bootstrap_requested: config.bootstrap_resamples,
            bootstrap_usable: 0,
        };
    }
    let mut rng = StdRng::seed_from_u64(mix64(
        config.base_seed ^ fnv1a64(group_id) ^ fnv1a64(kind.id()),
    ));
    let mut sample = Vec::with_capacity(records.len());
    let mut bootstrap = Vec::with_capacity(config.bootstrap_resamples);
    for _ in 0..config.bootstrap_resamples {
        sample.clear();
        for _ in 0..records.len() {
            sample.push(records[rng.gen_range(0..records.len())]);
        }
        if let (Some(value), _) = statistic(&sample, kind) {
            bootstrap.push(value);
        }
    }
    bootstrap.sort_by(f64::total_cmp);
    let bootstrap_usable = bootstrap.len();
    let bootstrap_ci = (!bootstrap.is_empty())
        .then(|| [percentile(&bootstrap, 0.025), percentile(&bootstrap, 0.975)]);
    let usable_bootstrap_ci =
        bootstrap_sample_is_sufficient(bootstrap_usable, config.bootstrap_resamples)
            .then_some(bootstrap_ci)
            .flatten();
    let (ci95, ci_status, interval) = if kind.is_track_binomial() {
        let Some((successes, trials)) = binomial_counts(records, kind) else {
            return MetricEstimate {
                status: "estimated".into(),
                value: Some(point),
                ci95: None,
                ci_status: "not_estimable".into(),
                unit: kind.unit().into(),
                estimator: kind.method().into(),
                interval: "not estimable: binomial denominator is zero".into(),
                tracks: records.len(),
                eligible_tracks,
                bootstrap_requested: config.bootstrap_resamples,
                bootstrap_usable,
            };
        };
        let (lower, upper) = wilson_ci(successes, trials);
        (
            Some([lower, upper]),
            "estimated".into(),
            format!(
                "95% Wilson score interval for a track-level binomial proportion; whole-track bootstrap is retained as a diagnostic but does not replace or envelope the preregistered Wilson bound ({bootstrap_usable} usable of {} requested)",
                config.bootstrap_resamples,
            ),
        )
    } else if kind == MetricKind::FalseAlertsPerHour {
        let (events, exposure_hours) = alert_rate_parts(records);
        match garwood_rate_ci(events, exposure_hours) {
            Some(garwood) => (
                Some(interval_envelope(garwood, usable_bootstrap_ci)),
                "estimated".into(),
                format!(
                    "95% Garwood exact Poisson count-rate interval under a homogeneous episode-rate model; whole-track bootstrap envelope used only when at least 80% of replicates are usable ({bootstrap_usable} usable of {} requested)",
                    config.bootstrap_resamples,
                ),
            ),
            None => (
                None,
                "not_estimable".into(),
                "not estimable: invalid or zero exposure".into(),
            ),
        }
    } else if kind == MetricKind::AbstentionFraction {
        match abstention_hoeffding_ci(records, point) {
            Some(hoeffding) => (
                Some(interval_envelope(hoeffding, usable_bootstrap_ci)),
                "estimated".into(),
                format!(
                    "95% distribution-free weighted-track Hoeffding interval for bounded post-warm-up abstention fractions; whole-track bootstrap envelope used only when at least 80% of replicates are usable ({bootstrap_usable} usable of {} requested)",
                    config.bootstrap_resamples
                ),
            ),
            None => (
                None,
                "not_estimable".into(),
                "not estimable: no post-warm-up monitoring exposure".into(),
            ),
        }
    } else if kind == MetricKind::Arl0Assessments {
        match arl0_hoeffding_ci(records, point) {
            Some(hoeffding) => (
                Some(interval_envelope(hoeffding, usable_bootstrap_ci)),
                "estimated".into(),
                format!(
                    "95% distribution-free Hoeffding interval for track-level time-to-first-alert bounded by the configured assessment horizon; whole-track bootstrap envelope used only when at least 80% of replicates are usable ({bootstrap_usable} usable of {} requested)",
                    config.bootstrap_resamples
                ),
            ),
            None => (
                None,
                "not_estimable".into(),
                "not estimable: no finite ARL0 assessment horizon".into(),
            ),
        }
    } else if let Some(ci) = usable_bootstrap_ci {
        (
            Some(ci),
            "estimated".into(),
            format!(
                "95% percentile bootstrap; {bootstrap_usable} usable of {} requested whole-track resamples (minimum 80% required)",
                config.bootstrap_resamples
            ),
        )
    } else {
        (
            None,
            "not_estimable".into(),
            format!(
                "not estimable: {bootstrap_usable} usable of {} requested whole-track resamples is below the 80% minimum",
                config.bootstrap_resamples,
            ),
        )
    };
    MetricEstimate {
        status: "estimated".into(),
        value: Some(point),
        ci95,
        ci_status,
        unit: kind.unit().into(),
        estimator: kind.method().into(),
        interval,
        tracks: records.len(),
        eligible_tracks,
        bootstrap_requested: config.bootstrap_resamples,
        bootstrap_usable,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ConditionMetrics {
    false_alerts_per_hour: MetricEstimate,
    mission_probability_any_alert: MetricEstimate,
    arl0_assessments: MetricEstimate,
    arl0_censoring_fraction: MetricEstimate,
    abstention_fraction: MetricEstimate,
    any_alert_probability: MetricEstimate,
    pre_onset_alert_probability: MetricEstimate,
    conditional_detection_probability: MetricEstimate,
    conditional_delay_frames: MetricEstimate,
    conditional_delay_p95_ms: MetricEstimate,
    conditional_attribution_coverage: MetricEstimate,
    conditional_attribution_accuracy: MetricEstimate,
    conditional_attribution_error: MetricEstimate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConditionRawCounts {
    tracks: usize,
    assessments: usize,
    monitoring_assessments: usize,
    monitoring_abstention_assessments: usize,
    alert_episodes: usize,
    mission_alert_tracks: usize,
    onset_labeled_tracks: usize,
    pre_onset_alert_tracks: usize,
    post_onset_detection_eligible_tracks: usize,
    detected_post_onset_tracks: usize,
    undetected_post_onset_tracks: usize,
    attribution_coverage_eligible_tracks: usize,
    emitted_attribution_tracks: usize,
    correct_attribution_tracks: usize,
    wrong_attribution_tracks: usize,
    detector_generation_resets: usize,
    tracks_with_detector_generation_resets: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ConditionSummary {
    condition: String,
    experiment_kind: String,
    role: Role,
    detector: DetectorId,
    truth_class: String,
    tracks: usize,
    exposure_hours: f64,
    detector_generation_resets: usize,
    tracks_with_detector_generation_resets: usize,
    phi: Option<f64>,
    covariance_scale: Option<f64>,
    ordinary_missing_probability: Option<f64>,
    raw_counts: ConditionRawCounts,
    metrics: ConditionMetrics,
}

fn condition_raw_counts(records: &[&TrialRecord]) -> ConditionRawCounts {
    ConditionRawCounts {
        tracks: records.len(),
        assessments: records.iter().map(|record| record.assessments).sum(),
        monitoring_assessments: records
            .iter()
            .map(|record| record.monitoring_assessments)
            .sum(),
        monitoring_abstention_assessments: records
            .iter()
            .map(|record| record.monitoring_abstention_assessments)
            .sum(),
        alert_episodes: records
            .iter()
            .map(|record| record.alert_episode_count)
            .sum(),
        mission_alert_tracks: records.iter().filter(|record| record.mission_alert).count(),
        onset_labeled_tracks: records
            .iter()
            .filter(|record| record.pre_onset_alert.is_some())
            .count(),
        pre_onset_alert_tracks: records
            .iter()
            .filter(|record| record.pre_onset_alert == Some(true))
            .count(),
        post_onset_detection_eligible_tracks: records
            .iter()
            .filter(|record| record.pre_onset_alert == Some(false))
            .count(),
        detected_post_onset_tracks: records
            .iter()
            .filter(|record| {
                record.pre_onset_alert == Some(false) && record.first_post_onset_delay_ms.is_some()
            })
            .count(),
        undetected_post_onset_tracks: records
            .iter()
            .filter(|record| {
                record.pre_onset_alert == Some(false) && record.first_post_onset_delay_ms.is_none()
            })
            .count(),
        attribution_coverage_eligible_tracks: records
            .iter()
            .filter(|record| record.attribution_emitted.is_some())
            .count(),
        emitted_attribution_tracks: records
            .iter()
            .filter(|record| record.attribution_emitted == Some(true))
            .count(),
        correct_attribution_tracks: records
            .iter()
            .filter(|record| record.attribution_correct == Some(true))
            .count(),
        wrong_attribution_tracks: records
            .iter()
            .filter(|record| record.attribution_correct == Some(false))
            .count(),
        detector_generation_resets: records
            .iter()
            .map(|record| record.detector_generation_resets.len())
            .sum(),
        tracks_with_detector_generation_resets: records
            .iter()
            .filter(|record| !record.detector_generation_resets.is_empty())
            .count(),
    }
}

fn summarize_condition(
    records: &[&TrialRecord],
    config: &ValidatedEvidenceConfig,
) -> ConditionSummary {
    let first = records[0];
    let group_id = format!("{}:{:?}:{:?}", first.condition, first.role, first.detector);
    let clean = first.truth.class == "clean";
    let attack = first.truth.onset_frame.is_some();
    let attributed_attack = first.truth.class == "attributed_inconsistency";
    let provenance = first.truth.expected_abstention;
    let estimate = |kind| estimate_metric(records, kind, config, &group_id);
    let na = |kind| MetricEstimate::not_applicable(kind, records.len());
    ConditionSummary {
        condition: first.condition.clone(),
        experiment_kind: first.experiment_kind.clone(),
        role: first.role,
        detector: first.detector,
        truth_class: first.truth.class.clone(),
        tracks: records.len(),
        exposure_hours: records
            .iter()
            .map(|record| record.duration_ms as f64 / 3_600_000.0)
            .sum(),
        detector_generation_resets: records
            .iter()
            .map(|record| record.detector_generation_resets.len())
            .sum(),
        tracks_with_detector_generation_resets: records
            .iter()
            .filter(|record| !record.detector_generation_resets.is_empty())
            .count(),
        phi: first.phi,
        covariance_scale: first.covariance_scale,
        ordinary_missing_probability: first.ordinary_missing_probability,
        raw_counts: condition_raw_counts(records),
        metrics: ConditionMetrics {
            false_alerts_per_hour: if clean {
                estimate(MetricKind::FalseAlertsPerHour)
            } else {
                na(MetricKind::FalseAlertsPerHour)
            },
            mission_probability_any_alert: if clean {
                estimate(MetricKind::MissionProbabilityAnyAlert)
            } else {
                na(MetricKind::MissionProbabilityAnyAlert)
            },
            arl0_assessments: if clean {
                estimate(MetricKind::Arl0Assessments)
            } else {
                na(MetricKind::Arl0Assessments)
            },
            arl0_censoring_fraction: if clean {
                estimate(MetricKind::Arl0CensoringFraction)
            } else {
                na(MetricKind::Arl0CensoringFraction)
            },
            abstention_fraction: estimate(MetricKind::AbstentionFraction),
            any_alert_probability: if provenance {
                estimate(MetricKind::AnyAlertProbability)
            } else {
                na(MetricKind::AnyAlertProbability)
            },
            pre_onset_alert_probability: if attack {
                estimate(MetricKind::PreOnsetAlertProbability)
            } else {
                na(MetricKind::PreOnsetAlertProbability)
            },
            conditional_detection_probability: if attack {
                estimate(MetricKind::ConditionalDetectionProbability)
            } else {
                na(MetricKind::ConditionalDetectionProbability)
            },
            conditional_delay_frames: if attack {
                estimate(MetricKind::ConditionalDelayFrames)
            } else {
                na(MetricKind::ConditionalDelayFrames)
            },
            conditional_delay_p95_ms: if attack {
                estimate(MetricKind::ConditionalDelayP95Millis)
            } else {
                na(MetricKind::ConditionalDelayP95Millis)
            },
            conditional_attribution_coverage: if attributed_attack {
                estimate(MetricKind::ConditionalAttributionCoverage)
            } else {
                na(MetricKind::ConditionalAttributionCoverage)
            },
            conditional_attribution_accuracy: if attributed_attack {
                estimate(MetricKind::ConditionalAttributionAccuracy)
            } else {
                na(MetricKind::ConditionalAttributionAccuracy)
            },
            conditional_attribution_error: if attributed_attack {
                estimate(MetricKind::ConditionalAttributionError)
            } else {
                na(MetricKind::ConditionalAttributionError)
            },
        },
    }
}

fn summarize_partition(
    records: &[TrialRecord],
    role: Role,
    config: &ValidatedEvidenceConfig,
) -> Vec<ConditionSummary> {
    let mut groups = BTreeMap::<(String, DetectorId), Vec<&TrialRecord>>::new();
    for record in records
        .iter()
        .filter(|record| record.source == "synthetic" && record.role == role)
    {
        groups
            .entry((record.condition.clone(), record.detector))
            .or_default()
            .push(record);
    }
    groups
        .into_values()
        .map(|records| summarize_condition(&records, config))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EvidenceSummary {
    schema: String,
    generator_profile: String,
    recorded_replay_profile: String,
    missingness_profile: String,
    acceptance_metric_profile: String,
    study_id: String,
    base_seed_hex: String,
    claim_partition: String,
    interval_method: String,
    sensitivity_axes: Vec<String>,
    calibration_diagnostics: Vec<ConditionSummary>,
    holdout_results: Vec<ConditionSummary>,
    recorded_fixture: RecordedRunInfo,
    limitations: Vec<String>,
}

fn build_summary(
    records: &[TrialRecord],
    config: &ValidatedEvidenceConfig,
    recorded_fixture: RecordedRunInfo,
) -> EvidenceSummary {
    EvidenceSummary {
        schema: SUMMARY_SCHEMA.into(),
        generator_profile: GENERATOR_PROFILE.into(),
        recorded_replay_profile: RECORDED_REPLAY_PROFILE.into(),
        missingness_profile: MISSINGNESS_PROFILE.into(),
        acceptance_metric_profile: ACCEPTANCE_METRIC_PROFILE.into(),
        study_id: config.study_id.clone(),
        base_seed_hex: format!("0x{:016x}", config.base_seed),
        claim_partition: "holdout_results only; calibration_diagnostics are descriptive and never pooled with holdout"
            .into(),
        interval_method: format!(
            "Boundary-safe 95% intervals: preregistered Wilson bounds for track proportions; Garwood Poisson count-rate intervals for alert episodes and distribution-free bounded-track Hoeffding intervals for ARL0 and post-warm-up abstention, conservatively enveloped by whole-track bootstrap when >=80% of {} requested replicates are usable; whole-track percentile bootstrap for delay summaries. Delay p95 is the nearest-rank empirical percentile in milliseconds",
            config.bootstrap_resamples
        ),
        sensitivity_axes: vec![
            "clean_autocorrelation varies AR(1) phi at covariance_scale=1".into(),
            "clean_covariance_sensitivity varies declared covariance scale at phi=0; clean_autocorrelation phi=0 is the scale=1 reference"
                .into(),
            "ordinary_missingness applies deterministic independent Bernoulli acoustic misses; continuity holes create explicit, recorded whole-detector generation resets"
                .into(),
        ],
        calibration_diagnostics: summarize_partition(records, Role::Calibration, config),
        holdout_results: summarize_partition(records, Role::Holdout, config),
        recorded_fixture,
        limitations: vec![
            "Synthetic observations are controlled stress tests, not a deployed residual population or operational accuracy claim."
                .into(),
            "Configured family_alpha is a per-assessment family-wise bound under the detector model; it is not a stream false-alert-rate guarantee."
                .into(),
            "Garwood episode-rate intervals assume a homogeneous Poisson count process; whole-track bootstrap envelopes are reported when sufficiently estimable, but neither turns the controlled stream into an operational FAR claim."
                .into(),
            "ARL0 is a finite-horizon restricted mean and must be read with its censoring fraction."
                .into(),
            "Attack delay and attribution are conditional on no pre-onset alert; delay is also conditional on detection."
                .into(),
            "Alert episodes use the configured nominal_only reset policy: abstention preserves an active episode, and only a nominal assessment clears it."
                .into(),
            "The default runner evaluates streaming NIS and signed correlation only; PID has no product streaming cadence in this revision."
                .into(),
            "Independent missingness may cross an accepted continuity limit. Each such event creates a recorded whole-detector generation boundary; post-reset warm-up remains abstention and is never recoded as nominal."
                .into(),
        ],
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GitProvenance {
    commit: String,
    dirty: bool,
    status_porcelain_v1: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ToolchainProvenance {
    rustc_verbose: String,
    cargo_version: String,
    package_version: String,
    build_profile: String,
    target_os: String,
    target_arch: String,
    available_parallelism: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InputProvenance {
    config_source_path: String,
    config_source_sha256: String,
    canonical_config_sha256: String,
    workspace_manifest_sha256: String,
    cargo_lock_sha256: String,
    recorded_fixture_path: String,
    recorded_fixture_sha256: String,
    runner_binary_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvidenceManifest {
    schema: String,
    trial_schema: String,
    summary_schema: String,
    generator_profile: String,
    recorded_replay_profile: String,
    missingness_profile: String,
    acceptance_metric_profile: String,
    study_id: String,
    base_seed_hex: String,
    git: GitProvenance,
    toolchain: ToolchainProvenance,
    inputs: InputProvenance,
    scope: Vec<String>,
    trial_records: usize,
    synthetic_tracks: usize,
    recorded_tracks: usize,
    dirty_override_used: bool,
    publication_source_policy: PublicationSourcePolicy,
    accepted_config_profile: String,
    accepted_config_digest: String,
    deterministic_time_policy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PublicationSourcePolicy {
    RequireClean,
    PermitDirtyWithAudit,
}

#[derive(Debug)]
struct Arguments {
    config_path: PathBuf,
    output_path: PathBuf,
    publication_source_policy: PublicationSourcePolicy,
}

fn command_stdout(
    working_directory: &Path,
    program: &str,
    arguments: &[&str],
) -> AppResult<String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(working_directory)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| format!("{program} output was not UTF-8: {error}"))
}

fn git_snapshot(config_path: &Path) -> AppResult<(PathBuf, GitProvenance)> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .map_err(|error| format!("resolve compiled manifest directory: {error}"))?;
    let workspace_root_text = command_stdout(
        &manifest_directory,
        "git",
        &["rev-parse", "--show-toplevel"],
    )?;
    let workspace_root = PathBuf::from(workspace_root_text)
        .canonicalize()
        .map_err(|error| format!("resolve compiled workspace root: {error}"))?;
    let config_path = config_path
        .canonicalize()
        .map_err(|error| format!("resolve evidence config for provenance: {error}"))?;
    if !config_path.starts_with(&workspace_root) {
        return Err(format!(
            "evidence config must be inside the compiled Galadriel worktree {}: {}",
            workspace_root.display(),
            config_path.display()
        ));
    }
    let config_directory = config_path
        .parent()
        .ok_or_else(|| "config path has no parent directory".to_string())?;
    let config_root_text =
        command_stdout(config_directory, "git", &["rev-parse", "--show-toplevel"])?;
    let config_root = PathBuf::from(config_root_text)
        .canonicalize()
        .map_err(|error| format!("resolve config Git worktree: {error}"))?;
    if config_root != workspace_root {
        return Err(format!(
            "evidence config belongs to a different or nested Git worktree: {}",
            config_root.display()
        ));
    }
    let commit = command_stdout(&workspace_root, "git", &["rev-parse", "HEAD"])?;
    let status = command_stdout(
        &workspace_root,
        "git",
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )?;
    Ok((
        workspace_root,
        GitProvenance {
            commit,
            dirty: !status.is_empty(),
            status_porcelain_v1: status,
        },
    ))
}

fn require_publication_clean(
    git: &GitProvenance,
    policy: PublicationSourcePolicy,
) -> AppResult<()> {
    if git.dirty && policy == PublicationSourcePolicy::RequireClean {
        return Err(
            "Git worktree is dirty; commit/stash changes for publication or pass --allow-dirty only for a development smoke run"
                .into(),
        );
    }
    Ok(())
}

struct ManifestBuild<'a> {
    config: &'a ValidatedEvidenceConfig,
    config_path: &'a Path,
    config_source_hash: String,
    canonical_config_hash: String,
    records: &'a [TrialRecord],
    recorded: &'a RecordedRunInfo,
    workspace_root: &'a Path,
    git: GitProvenance,
    publication_source_policy: PublicationSourcePolicy,
}

fn build_manifest(input: ManifestBuild<'_>) -> AppResult<EvidenceManifest> {
    let ManifestBuild {
        config,
        config_path,
        config_source_hash,
        canonical_config_hash,
        records,
        recorded,
        workspace_root,
        git,
        publication_source_policy,
    } = input;
    let rustc_verbose = command_stdout(workspace_root, "rustc", &["--version", "--verbose"])?;
    let cargo_version = command_stdout(workspace_root, "cargo", &["--version"])?;
    let workspace_manifest = workspace_root.join("Cargo.toml");
    let cargo_lock = workspace_root.join("Cargo.lock");
    let executable =
        env::current_exe().map_err(|error| format!("locate runner binary: {error}"))?;
    let synthetic_tracks = records
        .iter()
        .filter(|record| record.source == "synthetic" && record.detector == DetectorId::NisBaseline)
        .count();
    Ok(EvidenceManifest {
        schema: MANIFEST_SCHEMA.into(),
        trial_schema: TRIAL_SCHEMA.into(),
        summary_schema: SUMMARY_SCHEMA.into(),
        generator_profile: GENERATOR_PROFILE.into(),
        recorded_replay_profile: RECORDED_REPLAY_PROFILE.into(),
        missingness_profile: MISSINGNESS_PROFILE.into(),
        acceptance_metric_profile: ACCEPTANCE_METRIC_PROFILE.into(),
        study_id: config.study_id.clone(),
        base_seed_hex: format!("0x{:016x}", config.base_seed),
        git,
        toolchain: ToolchainProvenance {
            rustc_verbose,
            cargo_version,
            package_version: env!("CARGO_PKG_VERSION").into(),
            build_profile: if cfg!(debug_assertions) {
                "debug".into()
            } else {
                "release".into()
            },
            target_os: env::consts::OS.into(),
            target_arch: env::consts::ARCH.into(),
            available_parallelism: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
        },
        inputs: InputProvenance {
            config_source_path: config_path
                .strip_prefix(workspace_root)
                .unwrap_or(config_path)
                .display()
                .to_string(),
            config_source_sha256: config_source_hash,
            canonical_config_sha256: canonical_config_hash,
            workspace_manifest_sha256: sha256_file(&workspace_manifest)?,
            cargo_lock_sha256: sha256_file(&cargo_lock)?,
            recorded_fixture_path: recorded.resolved_path.clone(),
            recorded_fixture_sha256: recorded.sha256.clone(),
            runner_binary_sha256: sha256_file(&executable)?,
        },
        scope: vec![
            "streaming NIS baseline".into(),
            "streaming default signed-correlation fusion over producer-attested projections"
                .into(),
            "PID excluded because this revision exposes only a terminal replay assessment"
                .into(),
        ],
        trial_records: records.len(),
        synthetic_tracks,
        recorded_tracks: recorded.tracks,
        dirty_override_used: publication_source_policy
            == PublicationSourcePolicy::PermitDirtyWithAudit,
        publication_source_policy,
        accepted_config_profile: "galadriel-evidence/custom-v0.9".into(),
        accepted_config_digest: config.canonical_digest.clone(),
        deterministic_time_policy: "No wall-clock timestamp is stored; deterministic artifacts depend only on declared inputs and recorded tool/source provenance."
            .into(),
    })
}

fn json_pretty<T: Serialize>(value: &T) -> AppResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_bytes(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let file = File::create(path).map_err(|error| format!("create {}: {error}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    writer
        .flush()
        .map_err(|error| format!("flush {}: {error}", path.display()))
}

fn metric_text(metric: &MetricEstimate) -> String {
    match (metric.value, metric.ci95) {
        (Some(value), Some([lower, upper])) => {
            format!("{value:.4} [{lower:.4}, {upper:.4}]")
        }
        (Some(value), None) => {
            format!("{value:.4} ({}/{})", metric.status, metric.ci_status)
        }
        (None, _) => metric.status.clone(),
    }
}

fn detector_text(detector: DetectorId) -> &'static str {
    match detector {
        DetectorId::NisBaseline => "nis_baseline",
        DetectorId::DefaultCorrelationFusion => "default_correlation_fusion",
    }
}

fn render_report(summary: &EvidenceSummary, manifest: &EvidenceManifest) -> String {
    let mut report = String::new();
    report.push_str("# Galadriel post-audit evidence\n\n");
    report.push_str(&format!("Study: `{}`\n\n", summary.study_id));
    report.push_str(&format!("Git commit: `{}`\n\n", manifest.git.commit));
    report.push_str(&format!(
        "Dirty worktree at invocation: `{}`\n\n",
        manifest.git.dirty
    ));
    report.push_str("Only holdout rows below support reported results. Calibration tracks are retained in `summary.json` as separate diagnostics and are never pooled. Track proportions use preregistered Wilson intervals; alert-episode rates use labeled Garwood Poisson intervals; ARL0 and abstention use bounded-track Hoeffding intervals; delay summaries use whole-track bootstrap. Where an envelope is declared, bootstrap never replaces the boundary-safe analytic interval.\n\n");
    report.push_str("Alert episodes reset only on an explicit nominal assessment. Insufficient or rejected-input outcomes preserve any active episode; rejected inputs count toward abstention.\n\n");
    report.push_str("| condition | detector | exposure h | generation resets (tracks) | false alerts/hour | mission P(any) | restricted ARL0 | ARL0 censored | abstention | provenance P(any alert) | pre-onset P | conditional detection | delay median (frames) | delay p95 (ms) | attribution coverage | attribution error | attribution accuracy |\n");
    report.push_str(
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for condition in &summary.holdout_results {
        let metrics = &condition.metrics;
        report.push_str(&format!(
            "| {} | {} | {:.4} | {} ({}) | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            condition.condition,
            detector_text(condition.detector),
            condition.exposure_hours,
            condition.detector_generation_resets,
            condition.tracks_with_detector_generation_resets,
            metric_text(&metrics.false_alerts_per_hour),
            metric_text(&metrics.mission_probability_any_alert),
            metric_text(&metrics.arl0_assessments),
            metric_text(&metrics.arl0_censoring_fraction),
            metric_text(&metrics.abstention_fraction),
            metric_text(&metrics.any_alert_probability),
            metric_text(&metrics.pre_onset_alert_probability),
            metric_text(&metrics.conditional_detection_probability),
            metric_text(&metrics.conditional_delay_frames),
            metric_text(&metrics.conditional_delay_p95_ms),
            metric_text(&metrics.conditional_attribution_coverage),
            metric_text(&metrics.conditional_attribution_error),
            metric_text(&metrics.conditional_attribution_accuracy),
        ));
    }
    report.push_str("\nExact event, eligibility, undetected, emitted-attribution, correct-attribution, and wrong-attribution counts are retained per row in `summary.json`; per-track delays and outcomes are retained in `trials.jsonl`.\n");
    report.push_str("\n## Recorded fixture\n\n");
    report.push_str(&format!(
        "Status: `{}`; {} observations across {} track(s), {} ms total observed duration, {} observations with a consistency projection, and {} explicit detector-generation reset(s) across {} track(s).\n\n",
        summary.recorded_fixture.evidence_status,
        summary.recorded_fixture.observations,
        summary.recorded_fixture.tracks,
        summary.recorded_fixture.total_duration_ms,
        summary.recorded_fixture.projection_observations,
        summary.recorded_fixture.detector_generation_resets,
        summary
            .recorded_fixture
            .tracks_with_detector_generation_resets,
    ));
    if !summary.recorded_fixture.status_reasons.is_empty() {
        report.push_str("Reasons:\n\n");
        for reason in &summary.recorded_fixture.status_reasons {
            report.push_str(&format!("- {reason}\n"));
        }
        report.push('\n');
    }
    report.push_str("The checked-in capture is therefore a parser/provenance/abstention smoke test. The runner does not extrapolate its short duration into an operational false-alert rate or detection claim.\n\n");
    report.push_str("## Interpretation limits\n\n");
    for limitation in &summary.limitations {
        report.push_str(&format!("- {limitation}\n"));
    }
    report
}

fn write_artifacts(
    output_directory: &Path,
    config: &ValidatedEvidenceConfig,
    records: &[TrialRecord],
    summary: &EvidenceSummary,
    manifest: &EvidenceManifest,
) -> AppResult<()> {
    if output_directory.exists() {
        return Err(format!(
            "output path already exists; refusing to mix or overwrite evidence: {}",
            output_directory.display()
        ));
    }
    fs::create_dir_all(output_directory)
        .map_err(|error| format!("create {}: {error}", output_directory.display()))?;
    let config_path = output_directory.join("config.json");
    let trials_path = output_directory.join("trials.jsonl");
    let summary_path = output_directory.join("summary.json");
    let report_path = output_directory.join("report.md");
    let manifest_path = output_directory.join("manifest.json");
    write_bytes(&config_path, &config.artifact_config)?;

    let trials_file = File::create(&trials_path)
        .map_err(|error| format!("create {}: {error}", trials_path.display()))?;
    let mut trials_writer = BufWriter::new(trials_file);
    for record in records {
        serde_json::to_writer(&mut trials_writer, record).map_err(|error| error.to_string())?;
        trials_writer
            .write_all(b"\n")
            .map_err(|error| format!("write {}: {error}", trials_path.display()))?;
    }
    trials_writer
        .flush()
        .map_err(|error| format!("flush {}: {error}", trials_path.display()))?;
    write_bytes(&summary_path, &json_pretty(summary)?)?;
    write_bytes(&report_path, render_report(summary, manifest).as_bytes())?;
    write_bytes(&manifest_path, &json_pretty(manifest)?)?;

    let artifact_names = [
        "config.json",
        "manifest.json",
        "report.md",
        "summary.json",
        "trials.jsonl",
    ];
    let mut checksum_lines = String::new();
    for name in artifact_names {
        let hash = sha256_file(&output_directory.join(name))?;
        checksum_lines.push_str(&format!("{hash}  {name}\n"));
    }
    write_bytes(
        &output_directory.join("SHA256SUMS"),
        checksum_lines.as_bytes(),
    )
}

fn parse_arguments() -> AppResult<Option<Arguments>> {
    let mut config_path = None;
    let mut output_path = None;
    let mut publication_source_policy = PublicationSourcePolicy::RequireClean;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                println!(
                    "galadriel-evidence --config <config.json> --out <new-directory> [--allow-dirty]\n\nRuns deterministic synthetic calibration/holdout tracks plus the configured recorded fixture, then writes JSONL trials, JSON summary, manifest, report, and SHA-256 checksums. Publication runs refuse a dirty Git tree; --allow-dirty is only for development smoke runs and is recorded in the manifest."
                );
                return Ok(None);
            }
            "--config" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--config requires a path".to_string())?;
                if config_path.replace(PathBuf::from(value)).is_some() {
                    return Err("--config may be supplied only once".into());
                }
            }
            "--out" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--out requires a path".to_string())?;
                if output_path.replace(PathBuf::from(value)).is_some() {
                    return Err("--out may be supplied only once".into());
                }
            }
            "--allow-dirty" => {
                if publication_source_policy == PublicationSourcePolicy::PermitDirtyWithAudit {
                    return Err("--allow-dirty may be supplied only once".into());
                }
                publication_source_policy = PublicationSourcePolicy::PermitDirtyWithAudit;
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    let config_path = config_path.ok_or_else(|| "missing --config <path>".to_string())?;
    let output_path = output_path.ok_or_else(|| "missing --out <path>".to_string())?;
    Ok(Some(Arguments {
        config_path,
        output_path,
        publication_source_policy,
    }))
}

fn read_bounded_config(path: &Path) -> AppResult<Vec<u8>> {
    let read_limit = u64::try_from(MAX_EVIDENCE_CONFIG_BYTES)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| "evidence config byte limit is not representable".to_string())?;
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() > MAX_EVIDENCE_CONFIG_BYTES {
        return Err(format!(
            "evidence configuration contains more than {MAX_EVIDENCE_CONFIG_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

fn run() -> AppResult<()> {
    let Some(arguments) = parse_arguments()? else {
        return Ok(());
    };
    if arguments.output_path.exists() {
        return Err(format!(
            "output path already exists; choose a new directory: {}",
            arguments.output_path.display()
        ));
    }
    let config_path = arguments
        .config_path
        .canonicalize()
        .map_err(|error| format!("resolve config: {error}"))?;
    let config_bytes = read_bounded_config(&config_path)?;
    let raw_config = decode_evidence_config(&config_bytes)
        .map_err(|error| format!("parse config {}: {error}", config_path.display()))?;
    let (workspace_root, initial_git) = git_snapshot(&config_path)?;
    let config = ValidatedEvidenceConfig::try_new(raw_config, &config_path, &workspace_root)
        .map_err(|error| format!("accept config {}: {error}", config_path.display()))?;
    require_publication_clean(&initial_git, arguments.publication_source_policy)?;

    let mut records = run_synthetic(&config)?;
    let (recorded_records, mut recorded_info) = run_recorded(&config)?;
    if let Ok(relative_fixture) =
        Path::new(&recorded_info.resolved_path).strip_prefix(&workspace_root)
    {
        recorded_info.resolved_path = relative_fixture.display().to_string();
    }
    records.extend(recorded_records);
    let summary = build_summary(&records, &config, recorded_info.clone());
    let canonical_config = config.artifact_config.as_ref();
    let (final_workspace_root, final_git) = git_snapshot(&config_path)?;
    if final_workspace_root != workspace_root || final_git != initial_git {
        return Err(
            "Git commit or worktree state changed while the evidence run was executing; rerun from a stable source tree"
                .into(),
        );
    }
    require_publication_clean(&final_git, arguments.publication_source_policy)?;
    let manifest = build_manifest(ManifestBuild {
        config: &config,
        config_path: &config_path,
        config_source_hash: sha256_bytes(&config_bytes),
        canonical_config_hash: sha256_bytes(canonical_config),
        records: &records,
        recorded: &recorded_info,
        workspace_root: &workspace_root,
        git: final_git,
        publication_source_policy: arguments.publication_source_policy,
    })?;
    write_artifacts(
        &arguments.output_path,
        &config,
        &records,
        &summary,
        &manifest,
    )?;
    println!(
        "wrote {} trial records and verified artifacts to {}",
        records.len(),
        arguments.output_path.display()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("galadriel-evidence: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn fixture_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../galadriel-ncp/tests/fixtures/crebain_clean_capture.jsonl")
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root must resolve")
    }

    fn tiny_config_file() -> EvidenceConfigFile {
        EvidenceConfigFile {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            study_id: "test_evidence".into(),
            base_seed: 0x001d_cafe_1234_5678,
            calibration_tracks: 2,
            holdout_tracks: 2,
            frames: 80,
            dt_ms: 100,
            assessment_step: 4,
            alert_episode_reset_policy: AlertEpisodeResetPolicy::NominalOnly,
            attack_onset_frame: 40,
            mission_frames: 80,
            rho: 0.7,
            sigma: 1.0,
            loud_bias_sigma: 6.0,
            ordinary_missing_probability: 0.2,
            autocorrelation_phis: vec![0.0, 0.6],
            covariance_scales: vec![1.0, 0.7],
            bootstrap_resamples: 200,
            min_metric_eligible_tracks: 2,
            min_recorded_duration_ms: 3_600_000,
            detector: DetectorConfigFile {
                window_len: 16,
                min_samples: 8,
                min_channels: 2,
                max_seq_gap: 1,
                max_timestamp_skew_ms: 1_000,
                max_inter_sample_gap_ms: 10_000,
                max_tracks: 128,
                nis_alpha: 0.01,
                cusum_slack: 3.0 / 6.0_f64.sqrt(),
                cusum_threshold: 15.0 / 6.0_f64.sqrt(),
                jam_fraction: 0.6,
            },
            correlation: CorrConfigFile {
                window: 16,
                min_samples: 8,
                decouple_ratio: 0.4,
                corr_floor: 0.15,
                family_alpha: 0.01,
            },
            recorded_fixture: RecordedFixtureConfig {
                path: fixture_path().display().to_string(),
                sha256: "154b2b6534659500bc8ef99b53f482692d01f4b3f65d6d52a1e890796eea643c".into(),
            },
        }
    }

    fn accept(raw: EvidenceConfigFile) -> Result<ValidatedEvidenceConfig, EvidenceConfigError> {
        ValidatedEvidenceConfig::try_new(
            raw,
            &workspace_root().join("evidence/test-config.json"),
            &workspace_root(),
        )
    }

    fn tiny_config() -> ValidatedEvidenceConfig {
        accept(tiny_config_file()).expect("tiny evidence config must be accepted")
    }

    fn fake_manifest(config: &ValidatedEvidenceConfig, record_count: usize) -> EvidenceManifest {
        EvidenceManifest {
            schema: MANIFEST_SCHEMA.into(),
            trial_schema: TRIAL_SCHEMA.into(),
            summary_schema: SUMMARY_SCHEMA.into(),
            generator_profile: GENERATOR_PROFILE.into(),
            recorded_replay_profile: RECORDED_REPLAY_PROFILE.into(),
            missingness_profile: MISSINGNESS_PROFILE.into(),
            acceptance_metric_profile: ACCEPTANCE_METRIC_PROFILE.into(),
            study_id: config.study_id.clone(),
            base_seed_hex: format!("0x{:016x}", config.base_seed),
            git: GitProvenance {
                commit: "test".into(),
                dirty: true,
                status_porcelain_v1: "test fixture".into(),
            },
            toolchain: ToolchainProvenance {
                rustc_verbose: "test".into(),
                cargo_version: "test".into(),
                package_version: env!("CARGO_PKG_VERSION").into(),
                build_profile: "test".into(),
                target_os: env::consts::OS.into(),
                target_arch: env::consts::ARCH.into(),
                available_parallelism: 1,
            },
            inputs: InputProvenance {
                config_source_path: "test".into(),
                config_source_sha256: "0".repeat(64),
                canonical_config_sha256: "0".repeat(64),
                workspace_manifest_sha256: "0".repeat(64),
                cargo_lock_sha256: "0".repeat(64),
                recorded_fixture_path: fixture_path().display().to_string(),
                recorded_fixture_sha256: config.recorded_fixture.sha256.clone(),
                runner_binary_sha256: "0".repeat(64),
            },
            scope: vec!["test".into()],
            trial_records: record_count,
            synthetic_tracks: 0,
            recorded_tracks: 1,
            dirty_override_used: true,
            publication_source_policy: PublicationSourcePolicy::PermitDirtyWithAudit,
            accepted_config_profile: "galadriel-evidence/custom-v0.9".into(),
            accepted_config_digest: config.canonical_digest.clone(),
            deterministic_time_policy: "test".into(),
        }
    }

    fn temporary_output() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "galadriel-evidence-test-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn synthetic_records_are_deterministic_and_partitions_are_disjoint() {
        let config = tiny_config();
        let first = run_synthetic(&config).expect("first synthetic run should succeed");
        let second = run_synthetic(&config).expect("second synthetic run should succeed");
        assert_eq!(first, second);
        assert_eq!(first.len(), 52);
        assert!(first.iter().all(|record| record.schema == TRIAL_SCHEMA));
        assert!(serde_json::to_value(&first[0])
            .expect("trial record must serialize")
            .get("seed")
            .is_some_and(serde_json::Value::is_string));

        let calibration_seeds = first
            .iter()
            .filter(|record| {
                record.role == Role::Calibration && record.detector == DetectorId::NisBaseline
            })
            .filter_map(|record| record.seed.clone())
            .collect::<HashSet<_>>();
        let holdout_seeds = first
            .iter()
            .filter(|record| {
                record.role == Role::Holdout && record.detector == DetectorId::NisBaseline
            })
            .filter_map(|record| record.seed.clone())
            .collect::<HashSet<_>>();
        assert!(calibration_seeds.is_disjoint(&holdout_seeds));
        for record in &first {
            let seed = record
                .seed
                .as_deref()
                .map(str::parse::<u64>)
                .transpose()
                .expect("synthetic seed text must be an exact u64");
            assert_eq!(record.seed_hex, seed.map(|seed| format!("0x{seed:016x}")));
            assert_eq!(record.track_id_hex, format!("0x{:016x}", record.track_id));
            assert_eq!(
                record.startup_assessments + record.monitoring_assessments,
                record.assessments
            );
        }
        let missingness = first
            .iter()
            .find(|record| {
                record.condition == "clean_ordinary_missingness"
                    && record.role == Role::Holdout
                    && record.detector == DetectorId::NisBaseline
            })
            .expect("ordinary-missingness trial should exist");
        let acoustic = missingness
            .realized_modality_counts
            .iter()
            .find(|count| count.modality == Modality::Acoustic)
            .expect("acoustic count should exist");
        assert!(acoustic.missing_frames > 0);
        assert!(missingness
            .realized_modality_counts
            .iter()
            .filter(|count| count.modality != Modality::Acoustic)
            .all(|count| count.missing_frames == 0));
        assert!(!missingness.detector_generation_resets.is_empty());
        assert!(missingness.detector_generation_resets.iter().all(|reset| {
            reset.reason == DetectorGenerationResetReason::SequenceOrTimestampDiscontinuity
        }));

        for record in first.iter().filter(|record| {
            record.detector == DetectorId::DefaultCorrelationFusion
                && record.condition == "provenance_missing_projection"
        }) {
            assert_eq!(record.consistency.missing_projection, record.assessments);
            assert!(record
                .trace
                .iter()
                .all(|span| span.label.state != "nominal"));
        }
        for record in first.iter().filter(|record| {
            record.detector == DetectorId::DefaultCorrelationFusion
                && record.condition == "provenance_invalid_prior"
        }) {
            assert_eq!(record.consistency.extraction_error, record.assessments);
            assert_eq!(record.rejected_input_assessments, record.assessments);
            assert_eq!(record.abstention_assessments, record.assessments);
            assert!(record
                .trace
                .iter()
                .all(|span| span.label.state == "rejected_input"));
        }
        for record in first.iter().filter(|record| {
            record.experiment_kind == "provenance_abstention"
                && record.detector == DetectorId::NisBaseline
        }) {
            assert!(!record.truth.expected_abstention);
        }
        for record in first.iter().filter(|record| {
            record.experiment_kind == "provenance_abstention"
                && record.detector == DetectorId::DefaultCorrelationFusion
        }) {
            assert!(record.truth.expected_abstention);
        }

        let summaries = summarize_partition(&first, Role::Holdout, &config);
        let broad = summaries
            .iter()
            .find(|summary| {
                summary.condition == "attack_broad_degradation"
                    && summary.detector == DetectorId::NisBaseline
            })
            .expect("broad-degradation summary should exist");
        assert_ne!(
            broad.metrics.conditional_detection_probability.status,
            "not_applicable"
        );
        assert_eq!(
            broad.metrics.conditional_attribution_accuracy.status,
            "not_applicable"
        );
        assert_eq!(
            broad.metrics.conditional_attribution_error.status,
            "not_applicable"
        );
        assert_eq!(
            broad.metrics.conditional_attribution_coverage.status,
            "not_applicable"
        );
    }

    #[test]
    fn delay_and_attribution_metrics_preserve_exact_denominators() {
        let mut percentile_fixture = (1..=100).map(f64::from).collect::<Vec<_>>();
        assert_eq!(nearest_rank_p95(&mut percentile_fixture), Some(95.0));

        let config = tiny_config();
        let records = run_synthetic(&config).expect("synthetic denominator fixture should run");
        let mut attributed = records
            .into_iter()
            .filter(|record| {
                record.condition == "attack_loud_acoustic"
                    && record.role == Role::Holdout
                    && record.detector == DetectorId::NisBaseline
            })
            .collect::<Vec<_>>();
        assert_eq!(attributed.len(), 2);

        for (index, record) in attributed.iter_mut().enumerate() {
            record.pre_onset_alert = Some(false);
            record.first_post_onset_delay_frames = Some((index + 1) * 10);
            record.first_post_onset_delay_ms = Some((index as u64 + 1) * 1_000);
            record.attribution_emitted = Some(false);
            record.attribution_correct = None;
        }
        let references = attributed.iter().collect::<Vec<_>>();
        let no_attribution = summarize_condition(&references, &config);
        assert_eq!(
            no_attribution
                .raw_counts
                .post_onset_detection_eligible_tracks,
            2
        );
        assert_eq!(no_attribution.raw_counts.detected_post_onset_tracks, 2);
        assert_eq!(no_attribution.raw_counts.undetected_post_onset_tracks, 0);
        assert_eq!(
            no_attribution
                .raw_counts
                .attribution_coverage_eligible_tracks,
            2
        );
        assert_eq!(no_attribution.raw_counts.emitted_attribution_tracks, 0);
        assert_eq!(
            no_attribution
                .metrics
                .conditional_attribution_coverage
                .value,
            Some(0.0)
        );
        assert_eq!(
            no_attribution.metrics.conditional_attribution_error.status,
            "not_estimable"
        );
        assert_eq!(
            no_attribution
                .metrics
                .conditional_attribution_error
                .eligible_tracks,
            0
        );

        attributed[0].attribution_emitted = Some(true);
        attributed[0].attribution_correct = Some(true);
        attributed[1].attribution_emitted = Some(true);
        attributed[1].attribution_correct = Some(false);
        let references = attributed.iter().collect::<Vec<_>>();
        let mixed = summarize_condition(&references, &config);
        assert_eq!(mixed.raw_counts.emitted_attribution_tracks, 2);
        assert_eq!(mixed.raw_counts.correct_attribution_tracks, 1);
        assert_eq!(mixed.raw_counts.wrong_attribution_tracks, 1);
        assert_eq!(
            mixed.metrics.conditional_attribution_error.eligible_tracks,
            2
        );
        assert_eq!(mixed.metrics.conditional_attribution_error.value, Some(0.5));
        let expected_error_interval = wilson_ci(1, 2);
        assert_eq!(
            mixed.metrics.conditional_attribution_error.ci95,
            Some([expected_error_interval.0, expected_error_interval.1])
        );
        assert!(mixed
            .metrics
            .conditional_attribution_error
            .interval
            .contains("Wilson"));
        assert_eq!(
            mixed.metrics.conditional_attribution_accuracy.value,
            Some(0.5)
        );
        assert_eq!(mixed.metrics.conditional_delay_p95_ms.value, Some(2_000.0));

        attributed[1].first_post_onset_delay_frames = None;
        attributed[1].first_post_onset_delay_ms = None;
        attributed[1].attribution_emitted = Some(false);
        attributed[1].attribution_correct = None;
        let references = attributed.iter().collect::<Vec<_>>();
        let with_undetected = summarize_condition(&references, &config);
        assert_eq!(with_undetected.raw_counts.detected_post_onset_tracks, 1);
        assert_eq!(with_undetected.raw_counts.undetected_post_onset_tracks, 1);
        assert_eq!(
            with_undetected
                .metrics
                .conditional_detection_probability
                .eligible_tracks,
            2
        );
        assert_eq!(
            with_undetected
                .metrics
                .conditional_detection_probability
                .value,
            Some(0.5)
        );
    }

    #[test]
    fn abstention_does_not_split_an_active_alert_episode() {
        let mut trace = TraceAccumulator::default();
        trace.observe(
            0,
            0,
            0,
            TraceLabel::alert("attributed_inconsistency", &[Modality::Acoustic]),
            10,
            0,
        );
        trace.observe(1, 1, 100, TraceLabel::insufficient(), 10, 0);
        trace.observe(2, 2, 200, TraceLabel::rejected_input(), 10, 0);
        trace.observe(
            3,
            3,
            300,
            TraceLabel::alert("broad_degradation", &[]),
            10,
            0,
        );
        assert_eq!(trace.alert_episodes.len(), 1);
        trace.observe(4, 4, 400, TraceLabel::nominal(), 10, 0);
        trace.observe(
            5,
            5,
            500,
            TraceLabel::alert("broad_degradation", &[]),
            10,
            0,
        );
        assert_eq!(trace.alert_episodes.len(), 2);
    }

    #[test]
    fn float_arms_use_exact_ids_and_normalize_signed_zero() {
        let mut config = tiny_config_file();
        config.autocorrelation_phis = vec![0.0, 0.123_400_1, 0.123_400_2];
        let config = accept(config).expect("close float arms should validate");
        let specs = synthetic_specs(&config).expect("spec identifiers should be unique");
        let ids = specs
            .iter()
            .map(|(spec, _)| spec.id.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(ids.len(), specs.len());
        assert_ne!(float_id(0.123_400_1), float_id(0.123_400_2));
        assert_eq!(float_id(0.0), float_id(-0.0));

        let mut duplicate = tiny_config_file();
        duplicate.autocorrelation_phis = vec![0.0, -0.0, 0.6];
        let error = duplicate
            .validate()
            .expect_err("signed zero arms are numeric duplicates");
        assert!(error.contains("duplicates"));
    }

    #[test]
    fn zero_event_intervals_retain_nonzero_upper_uncertainty() {
        let (_, wilson_upper) = wilson_ci(0, 24);
        assert!(wilson_upper > 0.0);
        let garwood = garwood_rate_ci(0, 2.4).expect("positive exposure should be estimable");
        assert_eq!(garwood[0], 0.0);
        assert!(garwood[1] > 0.0);

        let config = tiny_config();
        let mut records = run_synthetic(&config).expect("synthetic run should succeed");
        let condition = records
            .iter()
            .find(|record| {
                record.role == Role::Holdout
                    && record.detector == DetectorId::NisBaseline
                    && record.experiment_kind == "clean_autocorrelation"
                    && record.phi == Some(0.0)
            })
            .expect("reference clean condition should exist")
            .condition
            .clone();
        let mut clean = records
            .iter_mut()
            .filter(|record| {
                record.role == Role::Holdout
                    && record.detector == DetectorId::NisBaseline
                    && record.condition == condition
            })
            .collect::<Vec<_>>();
        for record in &mut clean {
            record.alert_episode_count = 0;
            record.mission_alert = false;
            record.first_alert_assessment = None;
        }
        let clean = clean.into_iter().map(|record| &*record).collect::<Vec<_>>();
        let mission = estimate_metric(
            &clean,
            MetricKind::MissionProbabilityAnyAlert,
            &config,
            "zero-mission",
        );
        assert_eq!(mission.value, Some(0.0));
        assert!(mission.ci95.expect("Wilson interval should exist")[1] > 0.0);
        assert!(mission.interval.contains("Wilson"));
        let rate = estimate_metric(&clean, MetricKind::FalseAlertsPerHour, &config, "zero-rate");
        assert_eq!(rate.value, Some(0.0));
        assert!(rate.ci95.expect("Garwood interval should exist")[1] > 0.0);
        assert!(rate.interval.contains("Garwood"));
        let abstention = estimate_metric(
            &clean,
            MetricKind::AbstentionFraction,
            &config,
            "zero-abstention",
        );
        assert_eq!(abstention.value, Some(0.0));
        assert!(
            abstention
                .ci95
                .expect("Hoeffding abstention interval should exist")[1]
                > 0.0
        );
        assert!(abstention.interval.contains("Hoeffding"));
        let arl0 = estimate_metric(
            &clean,
            MetricKind::Arl0Assessments,
            &config,
            "censored-arl0",
        );
        let arl0_point = arl0.value.expect("ARL0 point should exist");
        let arl0_interval = arl0.ci95.expect("Hoeffding ARL0 interval should exist");
        assert!(arl0_interval[0] < arl0_point);
        assert!(arl0.interval.contains("Hoeffding"));
    }

    #[test]
    fn validation_bounds_study_shape_and_repeated_work() {
        let mut config = tiny_config_file();
        config.detector.min_channels = 4;
        assert!(config
            .validate()
            .expect_err("four channels cannot be generated")
            .contains("three-modality"));

        let mut config = tiny_config_file();
        config.mission_frames = 4;
        assert!(config
            .validate()
            .expect_err("mission must include first assessable scheduled point")
            .contains("first scheduled assessable"));

        let mut config = tiny_config_file();
        config.bootstrap_resamples = 199;
        assert!(config
            .validate()
            .expect_err("too few bootstrap replicates should be rejected")
            .contains("200..=10000"));

        let mut config = tiny_config_file();
        config.calibration_tracks = usize::MAX;
        assert!(config
            .validate()
            .expect_err("extreme partition counts must not wrap the work estimate")
            .contains("calibration + holdout"));
        assert!(accept(config).is_err());

        let mut config = tiny_config_file();
        config.calibration_tracks = 500;
        config.holdout_tracks = 500;
        config.bootstrap_resamples = 10_000;
        assert!(config
            .validate()
            .expect_err("bootstrap resampling work must have an aggregate cap")
            .contains("bootstrap track draws"));

        let mut config = tiny_config_file();
        config.covariance_scales = vec![1.0, 1.001];
        assert!(config
            .validate()
            .expect_err("negligible covariance sensitivity arm should be rejected")
            .contains("at least 0.01"));

        let mut config = tiny_config_file();
        config.frames = 100_000;
        config.attack_onset_frame = 50_000;
        config.mission_frames = 100_000;
        config.assessment_step = 1;
        assert!(config
            .validate()
            .expect_err("trace work should be bounded")
            .contains("trial traces"));

        config.assessment_step = 5;
        config.correlation.window = 65_536;
        assert!(config
            .validate()
            .expect_err("correlation work should be bounded")
            .contains("correlation pair-sample"));

        let mut reset_heavy = tiny_config_file();
        reset_heavy.calibration_tracks = 98;
        reset_heavy.holdout_tracks = 2;
        reset_heavy.frames = 20_200;
        reset_heavy.assessment_step = 20_200;
        reset_heavy.attack_onset_frame = 10_000;
        reset_heavy.mission_frames = 20_200;
        assert!(reset_heavy
            .validate()
            .expect_err("worst-case reset records must have an aggregate cap")
            .contains("detector-generation resets"));

        let mut recorded_config = tiny_config_file();
        recorded_config.assessment_step = 1;
        recorded_config.correlation.window = 16_384;
        recorded_config
            .validate()
            .expect("small synthetic arm remains bounded");
        let recorded_config = accept(recorded_config).expect("recorded config must be accepted");
        let recorded = (0..8_000_u64)
            .flat_map(|seq| {
                DEFAULT_MODALITIES.map(|modality| {
                    PidObservation::try_scalar_raw(
                        1,
                        seq.saturating_mul(100),
                        seq,
                        modality,
                        3.0,
                        3,
                    )
                    .expect("recorded-work fixture coordinates are valid")
                })
            })
            .collect::<Vec<_>>();
        assert!(preflight_recorded_work(
            &recorded,
            recorded_config.assessment_step,
            recorded_config.suite.correlation().window(),
        )
        .expect_err("large recorded repeated work should be bounded")
        .contains("recorded fixture requests"));

        let mut total_duration_ms = u64::MAX;
        assert!(add_recorded_duration(&mut total_duration_ms, 1)
            .expect_err("recorded track durations must not saturate")
            .contains("total duration overflowed"));
        assert_eq!(total_duration_ms, u64::MAX);
    }

    #[test]
    fn dirty_publication_requires_an_explicit_development_override() {
        let git = GitProvenance {
            commit: "test".into(),
            dirty: true,
            status_porcelain_v1: " M test".into(),
        };
        assert!(require_publication_clean(&git, PublicationSourcePolicy::RequireClean).is_err());
        require_publication_clean(&git, PublicationSourcePolicy::PermitDirtyWithAudit)
            .expect("development override should be explicit");

        let outside_config = temporary_output().with_extension("json");
        fs::write(&outside_config, b"{}\n").expect("temporary config should be writable");
        let error = git_snapshot(&outside_config)
            .expect_err("provenance must not bind to a config outside this worktree");
        assert!(error.contains("compiled Galadriel worktree"));
        fs::remove_file(outside_config).expect("temporary config should be removable");
    }

    #[test]
    fn published_config_is_valid_and_has_declared_long_holdout_exposure() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../evidence/post-audit-v1.json");
        let bytes = fs::read(&path).expect("published config should be readable");
        let raw = decode_evidence_config(&bytes).expect("published config should parse");
        let config = ValidatedEvidenceConfig::try_new(raw, &path, &workspace_root())
            .expect("published config should validate");
        assert_eq!(config.frames, 3_600);
        let condition_exposure_hours =
            config.holdout_tracks as f64 * (config.frames - 1) as f64 * config.dt_ms as f64
                / 3_600_000.0;
        assert!(condition_exposure_hours > 2.39);
    }

    #[test]
    fn candidate_config_matches_the_declared_design_and_preflights() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../evidence/galadriel-0.9-candidate.json");
        let bytes = fs::read(&path).expect("candidate config should be readable");
        assert_eq!(
            sha256_bytes(&bytes),
            "2eb3018c7aed325c5cefd03b8b1d3ab0db9ece3c8cbe798d80bc0746aec74092"
        );
        let candidate_wire: serde_json::Value =
            serde_json::from_slice(&bytes).expect("candidate JSON should decode");
        assert_eq!(
            candidate_wire["base_seed"],
            serde_json::Value::String("2026071409001".into())
        );
        let raw = decode_evidence_config(&bytes).expect("candidate config should parse strictly");
        let config = ValidatedEvidenceConfig::try_new(raw, &path, &workspace_root())
            .expect("candidate config should pass complete work preflight");

        assert!(config.calibration_tracks >= 20);
        assert!(config.holdout_tracks >= 100);
        assert_eq!(config.frames, 3_600);
        assert_eq!(config.dt_ms, 100);
        assert_eq!(config.assessment_step, 10);
        assert_eq!(config.attack_onset_frame, 1_800);
        assert_eq!(config.mission_frames, 3_600);
        assert!(config.bootstrap_resamples >= 1_000);
        assert_eq!(config.suite.detector().max_seq_gap(), 1);
        assert_eq!(
            config.work_estimate,
            EvidenceWorkEstimate {
                synthetic_tracks: 980,
                synthetic_trial_records: 1_960,
                generated_observations: 10_584_000,
                trace_assessments: 705_600,
                correlation_sample_products: 406_425_600,
                bootstrap_track_draws: 15_680_000,
                maximum_synthetic_generation_resets: 216_000,
            }
        );
        assert_eq!(
            config.recorded_work_estimate,
            RecordedWorkEstimate {
                tracks: 1,
                trial_records: 2,
                observations: 476,
                trace_assessments: 32,
                correlation_sample_products: 18_432,
                maximum_generation_resets: 158,
            }
        );
        assert_eq!(
            config.canonical_digest,
            "5f4ac9d98e087cbfaff6e6fd3bc51b10699190884af1782254bb8ddf72a23e8f"
        );
        assert_eq!(
            sha256_bytes(&config.artifact_config),
            "ff1dc462ba196371113b4e2d8068ea94343f964c98468b47ecc245a1c6a0d6bc"
        );
        let accepted_wire: serde_json::Value = serde_json::from_slice(&config.artifact_config)
            .expect("accepted config JSON should decode");
        assert_eq!(accepted_wire["base_seed"], candidate_wire["base_seed"]);
        assert_eq!(
            accepted_wire["base_seed_hex"],
            serde_json::Value::String("0x000001d7bb444169".into())
        );
    }

    #[test]
    fn strict_decode_rejects_duplicate_unknown_and_missing_fields_at_every_depth() {
        let raw = tiny_config_file();
        let json = serde_json::to_string(&raw).expect("test config must serialize");
        decode_evidence_config(json.as_bytes()).expect("strict valid config must decode");

        let duplicate_top = json.replacen(
            "\"study_id\":\"test_evidence\"",
            "\"study_id\":\"first\",\"study_id\":\"test_evidence\"",
            1,
        );
        assert!(decode_evidence_config(duplicate_top.as_bytes())
            .expect_err("duplicate top-level key must fail")
            .to_string()
            .contains("duplicate JSON object key"));

        let duplicate_nested =
            json.replacen("\"window_len\":16", "\"window_len\":8,\"window_len\":16", 1);
        assert!(decode_evidence_config(duplicate_nested.as_bytes())
            .expect_err("duplicate nested key must fail")
            .to_string()
            .contains("duplicate JSON object key"));

        let mut unknown: serde_json::Value =
            serde_json::from_str(&json).expect("test JSON must parse");
        unknown["detector"]["unexpected"] = serde_json::json!(true);
        assert!(decode_evidence_config(
            &serde_json::to_vec(&unknown).expect("unknown-field case must serialize")
        )
        .expect_err("nested unknown key must fail")
        .to_string()
        .contains("unknown field"));

        let mut missing: serde_json::Value =
            serde_json::from_str(&json).expect("test JSON must parse");
        missing
            .as_object_mut()
            .expect("top-level JSON object")
            .remove("study_id");
        assert!(decode_evidence_config(
            &serde_json::to_vec(&missing).expect("missing-field case must serialize")
        )
        .expect_err("missing required key must fail")
        .to_string()
        .contains("missing field"));

        let oversized = vec![b' '; MAX_EVIDENCE_CONFIG_BYTES + 1];
        assert!(matches!(
            decode_evidence_config(&oversized),
            Err(EvidenceConfigError::ConfigTooLarge { .. })
        ));
    }

    #[test]
    fn acceptance_rejects_version_range_aggregate_hash_and_containment_before_output_creation() {
        let output = temporary_output();
        if output.exists() {
            fs::remove_dir_all(&output).expect("stale output must be removable");
        }

        let mut wrong_version = tiny_config_file();
        wrong_version.schema_version += 1;
        assert!(accept(wrong_version).is_err());

        let mut out_of_range = tiny_config_file();
        out_of_range.ordinary_missing_probability = 1.0;
        assert!(accept(out_of_range).is_err());

        let mut ambiguous_study = tiny_config_file();
        ambiguous_study.study_id = "contains whitespace".into();
        assert!(accept(ambiguous_study).is_err());

        let mut aggregate = tiny_config_file();
        aggregate.calibration_tracks = 500;
        aggregate.holdout_tracks = 500;
        aggregate.bootstrap_resamples = 10_000;
        assert!(accept(aggregate).is_err());

        let mut bad_hash = tiny_config_file();
        bad_hash.recorded_fixture.sha256 = "0".repeat(64);
        assert!(matches!(
            accept(bad_hash),
            Err(EvidenceConfigError::FixtureHashMismatch { .. })
        ));

        let workspace_target = workspace_root().join("target");
        let workspace_target_was_absent = !workspace_target.exists();
        fs::create_dir_all(&workspace_target)
            .expect("workspace target fixture directory must be creatable");
        let malformed = workspace_target.join(format!(
            "malformed-evidence-fixture-{}-{}.jsonl",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&malformed, b"{not-json}\n").expect("malformed fixture must be writable");
        let mut malformed_config = tiny_config_file();
        malformed_config.recorded_fixture.path = malformed.display().to_string();
        malformed_config.recorded_fixture.sha256 =
            sha256_file(&malformed).expect("malformed fixture must hash");
        assert!(matches!(
            accept(malformed_config),
            Err(EvidenceConfigError::FixtureParse { .. })
        ));
        fs::remove_file(malformed).expect("malformed fixture must be removable");
        if workspace_target_was_absent {
            fs::remove_dir(workspace_target)
                .expect("workspace target fixture directory must be removable");
        }

        let outside = temporary_output().with_extension("jsonl");
        fs::write(&outside, b"{}\n").expect("outside fixture must be writable");
        let mut outside_path = tiny_config_file();
        outside_path.recorded_fixture.path = outside.display().to_string();
        outside_path.recorded_fixture.sha256 = sha256_file(&outside).expect("fixture must hash");
        assert!(matches!(
            accept(outside_path),
            Err(EvidenceConfigError::FixtureOutsideWorkspace { .. })
        ));
        fs::remove_file(outside).expect("outside fixture must be removable");

        assert!(
            !output.exists(),
            "configuration rejection must not create output artifacts"
        );
    }

    #[test]
    fn accepted_config_digest_is_deterministic_and_components_are_immutable() {
        let first = tiny_config();
        let second = tiny_config();

        assert_eq!(first.canonical_digest, second.canonical_digest);
        assert_eq!(first.canonical_digest.len(), 64);
        assert_eq!(first.suite.detector().window_len(), 16);
        assert_eq!(first.suite.correlation().window(), 16);
        let artifact = std::str::from_utf8(&first.artifact_config)
            .expect("accepted config artifact must be UTF-8 JSON");
        assert!(artifact.contains("custom_research_evidence"));
        assert!(artifact.ends_with('\n'));

        let positive_zero = tiny_config_file();
        let mut negative_zero = positive_zero.clone();
        negative_zero.autocorrelation_phis[0] = -0.0;
        let positive_zero = accept(positive_zero).expect("positive zero must be accepted");
        let negative_zero = accept(negative_zero).expect("negative zero must be accepted");
        assert_eq!(
            negative_zero.autocorrelation_phis[0].to_bits(),
            0.0_f64.to_bits()
        );
        assert_eq!(
            negative_zero.canonical_digest,
            positive_zero.canonical_digest
        );
    }

    #[test]
    fn recorded_fixture_is_explicitly_not_estimable() {
        let config = tiny_config();
        let (records, info) = run_recorded(&config).expect("recorded fixture should replay");
        assert_eq!(records.len(), 2);
        assert_eq!(info.total_duration_ms, 15_800);
        assert_eq!(info.evidence_status, "not_estimable");
        assert!(info.detector_generation_resets > 0);
        assert_eq!(info.tracks_with_detector_generation_resets, 1);
        assert!(info
            .status_reasons
            .iter()
            .any(|reason| reason.starts_with("insufficient_duration:")));
        assert!(info
            .status_reasons
            .iter()
            .any(|reason| reason == "missing_consistency_projection"));
        let fused = records
            .iter()
            .find(|record| record.detector == DetectorId::DefaultCorrelationFusion)
            .expect("default fused record should exist");
        assert_eq!(fused.evidence_status, "not_estimable");
        assert_eq!(fused.consistency.missing_projection, fused.assessments);
        assert!(fused.truth.expected_abstention);
        assert!(fused
            .status_reasons
            .iter()
            .any(|reason| reason == "missing_consistency_projection"));
        assert!(!fused.detector_generation_resets.is_empty());
        let baseline = records
            .iter()
            .find(|record| record.detector == DetectorId::NisBaseline)
            .expect("baseline record should exist");
        assert!(!baseline.truth.expected_abstention);
        assert!(baseline
            .status_reasons
            .iter()
            .all(|reason| reason != "missing_consistency_projection"));
        assert!(baseline
            .status_reasons
            .iter()
            .any(|reason| reason.starts_with("insufficient_duration:")));
        assert_eq!(
            baseline.detector_generation_resets,
            fused.detector_generation_resets
        );
    }

    #[test]
    fn artifact_set_is_complete_checksummed_and_never_overwritten() {
        let config = tiny_config();
        let mut records = run_synthetic(&config).expect("synthetic artifacts should run");
        let (recorded, info) = run_recorded(&config).expect("recorded fixture should replay");
        records.extend(recorded);
        let summary = build_summary(&records, &config, info);
        let manifest = fake_manifest(&config, records.len());
        assert_eq!(summary.schema, SUMMARY_SCHEMA);
        assert_eq!(manifest.schema, MANIFEST_SCHEMA);
        let output = temporary_output();
        if output.exists() {
            fs::remove_dir_all(&output).expect("stale test directory should be removable");
        }
        write_artifacts(&output, &config, &records, &summary, &manifest)
            .expect("artifacts should write");
        for name in [
            "config.json",
            "manifest.json",
            "report.md",
            "summary.json",
            "trials.jsonl",
            "SHA256SUMS",
        ] {
            assert!(output.join(name).is_file(), "missing {name}");
        }
        let report = fs::read_to_string(output.join("report.md"))
            .expect("generated report should be readable");
        assert!(
            report
                .lines()
                .all(|line| !line.ends_with(' ') && !line.ends_with('\t')),
            "generated Markdown must not contain trailing whitespace"
        );
        let config_json: serde_json::Value = serde_json::from_slice(
            &fs::read(output.join("config.json")).expect("accepted config should be readable"),
        )
        .expect("accepted config should be JSON");
        assert_eq!(config_json["runner_contract"]["trial_schema"], TRIAL_SCHEMA);
        assert_eq!(
            config_json["runner_contract"]["acceptance_metric_profile"],
            ACCEPTANCE_METRIC_PROFILE
        );
        let summary_json: serde_json::Value = serde_json::from_slice(
            &fs::read(output.join("summary.json")).expect("summary should be readable"),
        )
        .expect("summary should be JSON");
        assert_eq!(summary_json["schema"], SUMMARY_SCHEMA);
        assert!(summary_json["holdout_results"][0]["raw_counts"]["tracks"].is_u64());
        let manifest_json: serde_json::Value = serde_json::from_slice(
            &fs::read(output.join("manifest.json")).expect("manifest should be readable"),
        )
        .expect("manifest should be JSON");
        assert_eq!(manifest_json["schema"], MANIFEST_SCHEMA);
        assert_eq!(manifest_json["trial_schema"], TRIAL_SCHEMA);
        let trials =
            fs::read_to_string(output.join("trials.jsonl")).expect("trials should be readable");
        let first_trial: serde_json::Value = serde_json::from_str(
            trials
                .lines()
                .next()
                .expect("trials must contain one record"),
        )
        .expect("trial line should be JSON");
        assert_eq!(first_trial["schema"], TRIAL_SCHEMA);
        assert_eq!(first_trial["source_profile"], GENERATOR_PROFILE);
        let checksums = fs::read_to_string(output.join("SHA256SUMS"))
            .expect("checksum file should be readable");
        for line in checksums.lines() {
            let (expected, name) = line
                .split_once("  ")
                .expect("checksum line should have two fields");
            assert_eq!(
                sha256_file(&output.join(name)).expect("artifact should hash"),
                expected
            );
        }
        assert!(write_artifacts(&output, &config, &records, &summary, &manifest).is_err());
        fs::remove_dir_all(output).expect("test output should be removable");
    }
}
