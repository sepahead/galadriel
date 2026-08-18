//! Geometry-gated pairwise mutual-information consensus research.
//!
//! This module implements a graph heuristic over report-first KSG mutual
//! information estimates. It does not implement partial information decomposition,
//! infer causality, or produce a calibrated security decision.

use std::{cmp::Ordering, collections::HashSet, error::Error, fmt, sync::Arc};

use galadriel_core::{AssessmentBinding, GaladrielError, Modality};
use pid_core::{
    diagnostics::{
        distance_concentration_stats, intrinsic_dimension_report, DistanceConcentrationConfig,
        IntrinsicDimConfig, IntrinsicDimensionReport,
    },
    stable::continuous::{
        ksg_mi_report_with_budget, ksg_report_resource_estimate, AssumptionLedgerEntry,
        AssumptionState, BoundaryModel, EstimandIdentity, InformationUnit, KsgConfig,
        KsgGeometryModel, KsgMethodStatus, KsgMiReport, KsgNeighborBackend, KsgProvenance,
        KsgReportWarning, NegativeHandling, ScientificStatus, SupportContract, WarningCode,
    },
    MatOwned, Metric, PidError, ResourceBudget, ResourceEstimate,
};
use serde::{Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::identity::{DependenceResearchClassification, IdentityBuilder, MiConsensusConfigDigest};

const MAX_DECLARATION_BYTES: usize = 4_096;
const MAX_EPISODE_LABEL_BYTES: usize = 512;
const MAX_QUADRATIC_FIT_WORK: usize = 200_000_000;
const MAX_MODALITIES: usize = Modality::ALL.len();
const KSG_NEIGHBORS: usize = 3;
const KSG_REPORT_ROUTE_ID: &str = "pid-core/stable::continuous::ksg_mi_report_with_budget";
const KSG_RESOURCE_MAX_BYTES: u64 = 1 << 30;
const KSG_RESOURCE_MAX_PAIRWISE_DISTANCES: u64 = 50_000_000;
const KSG_RESOURCE_MAX_OPERATIONS_HINT: u128 = 10_000_000_000;
const KSG_RESOURCE_MAX_THREADS: usize = 1;
const KSG_ESTIMAND_REVISION: &str = "ksg1-product-small-ball-v1";
const KSG_ESTIMATOR_REVISION: &str = "strict-unique-shell-integer-harmonic-report-v4";
const KSG_ESTIMAND_FAMILY: &str = "kraskov-stoegbauer-grassberger-mutual-information";
const KSG_ESTIMAND_METRIC: &str = "chebyshev-max-product";
const MI_FUNCTIONAL_ID: &str = "mutual-information/shannon";
const MI_ESTIMATOR_ID: &str = "kraskov-stoegbauer-grassberger/ksg-1";
const MI_GRAPH_COMPOSITION_ID: &str = "galadriel/pairwise-mi-strict-majority-graph-v1";
const MI_GRAPH_RULE_ID: &str =
    "global-max-reference+floor+unique-strict-majority-clique+all-cross-edges-v1";
const TAIL_SELECTION_RULE_ID: &str =
    "caller-ordered-channels+newest-configured-equal-length-row-tail-v1";
const PREPROCESSING_RELATION_ID: &str =
    "fixed-identity-transform+no-data-adaptive-fit+same-declared-evaluation-row-set-v1";
const OBSERVATION_TRANSFORM_ID: &str = "no-stochastic-transform+no-added-noise-v1";
const ID_LOCAL_MEDIAN_MINIMUM: f64 = 1.30;
const GEOMETRY_PROTOCOL_ID: &str = "levina-bickel-mackay-ghahramani-configured-k+local-median-screen+distance-concentration-chebyshev-v2";
const UPSTREAM_WARNING_POLICY_ID: &str =
    "retain-all;reject-unsupported-observed-condition;warnings-remain-disclosures-v1";

/// Conservative quadratic scan units for one pair: intrinsic dimension,
/// distance concentration, and report-first KSG diagnostics/estimation.
pub const MI_PAIR_POINT_FIT_UNITS: usize = 6;

/// Exact upstream dependency identity used by this research adapter.
pub const PID_RS_VERSION: &str = "0.9.0";
/// Immutable pid-rs revision selected by the workspace manifest.
pub const PID_RS_REVISION: &str = "bc3aa80fb6025e709c2906a08bce25a4fac40578";
/// Repository supplying the selected pid-core package.
pub const PID_RS_GIT_REPOSITORY: &str = "https://github.com/sepahead/pid-rs";

/// Versioned serialization schema of a standalone MI graph report.
pub const MI_CONSENSUS_REPORT_SCHEMA: &str = "galadriel.mi-consensus-report.v2";

/// Maximum scalar analysis window. Exhaustive delete-block configurations are
/// usually admitted only at smaller windows by the aggregate work ceiling.
pub const MAX_MI_WINDOW: usize = 512;

const fn pair_count(channels: usize) -> usize {
    channels.saturating_mul(channels.saturating_sub(1)) / 2
}

fn validate_bounded_text(
    field: &'static str,
    value: impl Into<String>,
    maximum: usize,
) -> Result<String, MiConsensusConfigError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(MiConsensusConfigError::DeclarationTextEmpty { field });
    }
    if value.len() > maximum {
        return Err(MiConsensusConfigError::DeclarationTextTooLong { field, maximum });
    }
    Ok(value)
}

/// Closed sampling regime accepted by the current KSG companion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ContinuousSamplingRegime {
    /// Rows are asserted to be independent draws from one unchanged population law.
    IndependentIdenticallyDistributed,
}

impl ContinuousSamplingRegime {
    pub const fn name(self) -> &'static str {
        match self {
            Self::IndependentIdenticallyDistributed => "independent-identically-distributed",
        }
    }
}

/// Caller assertion about the population law and sampling process required by KSG.
///
/// Construction checks only bounded nonempty text. It cannot prove the assertion.
/// Sample geometry diagnostics also cannot prove it. The declaration is required
/// so Galadriel cannot silently manufacture a population-support claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuousLawDeclaration {
    population_model: String,
    observation_model: String,
    sampling_model: String,
    coordinate_gauge: String,
    sampling_regime: ContinuousSamplingRegime,
}

impl ContinuousLawDeclaration {
    /// Construct an explicit continuous-law declaration for i.i.d. rows.
    ///
    /// `population_model` must state why every required bivariate law is regular,
    /// full-dimensional, and has finite MI. `observation_model` must address
    /// rounding, quantization, atoms, and added noise. `sampling_model` must state
    /// the asserted independent-and-identically-distributed sampling model.
    pub fn try_iid(
        population_model: impl Into<String>,
        observation_model: impl Into<String>,
        sampling_model: impl Into<String>,
        coordinate_gauge: impl Into<String>,
    ) -> Result<Self, MiConsensusConfigError> {
        Ok(Self {
            population_model: validate_bounded_text(
                "population_model",
                population_model,
                MAX_DECLARATION_BYTES,
            )?,
            observation_model: validate_bounded_text(
                "observation_model",
                observation_model,
                MAX_DECLARATION_BYTES,
            )?,
            sampling_model: validate_bounded_text(
                "sampling_model",
                sampling_model,
                MAX_DECLARATION_BYTES,
            )?,
            coordinate_gauge: validate_bounded_text(
                "coordinate_gauge",
                coordinate_gauge,
                MAX_DECLARATION_BYTES,
            )?,
            sampling_regime: ContinuousSamplingRegime::IndependentIdenticallyDistributed,
        })
    }

    /// Caller-declared population-law model.
    pub fn population_model(&self) -> &str {
        &self.population_model
    }

    /// Caller-declared observation model.
    pub fn observation_model(&self) -> &str {
        &self.observation_model
    }

    /// Caller-declared sampling/dependence model.
    pub fn sampling_model(&self) -> &str {
        &self.sampling_model
    }

    /// Caller-declared common coordinate gauge used without adaptive scaling.
    pub fn coordinate_gauge(&self) -> &str {
        &self.coordinate_gauge
    }

    /// Machine-readable sampling assertion required by the current estimator route.
    pub const fn sampling_regime(&self) -> ContinuousSamplingRegime {
        self.sampling_regime
    }

    fn add_identity(&self, identity: &mut IdentityBuilder) {
        identity.bytes(b"population_model", self.population_model.as_bytes());
        identity.bytes(b"observation_model", self.observation_model.as_bytes());
        identity.bytes(b"sampling_model", self.sampling_model.as_bytes());
        identity.bytes(b"coordinate_gauge", self.coordinate_gauge.as_bytes());
        identity.bytes(b"sampling_regime", self.sampling_regime.name().as_bytes());
    }
}

/// Provenance strength of an input episode label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EpisodeReceiptOrigin {
    /// The direct caller asserted one episode and one-to-one row alignment.
    CallerDeclaredAlignmentAsserted,
    /// Core preparation validated one scoped stream and supplied its assessment binding.
    CoreAssessmentBinding,
}

/// Exact content receipt for the rows used in one MI graph.
///
/// The digest binds modality order, row order, exact binary64 values, and the
/// episode label. It detects substitution. A caller-declared label does not prove
/// episode membership; a core-bound receipt inherits only the guarantees of the
/// nested core assessment binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RowSetReceipt {
    #[serde(serialize_with = "serialize_sha256")]
    sha256: [u8; 32],
    episode_label: String,
    origin: EpisodeReceiptOrigin,
    channel_count: usize,
    rows_per_channel: usize,
}

fn serialize_sha256<S>(digest: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex_digest(*digest))
}

impl RowSetReceipt {
    /// Lowercase SHA-256 content identity.
    pub fn sha256_hex(&self) -> String {
        let mut output = String::with_capacity(64);
        use std::fmt::Write as _;
        for byte in self.sha256 {
            let _ = write!(output, "{byte:02x}");
        }
        output
    }

    /// Episode label included in the receipt.
    pub fn episode_label(&self) -> &str {
        &self.episode_label
    }

    /// Whether the label is direct caller provenance or nested core provenance.
    pub const fn origin(&self) -> EpisodeReceiptOrigin {
        self.origin
    }

    /// Number of submitted channels.
    pub const fn channel_count(&self) -> usize {
        self.channel_count
    }

    /// Number of tail rows used from every channel.
    pub const fn rows_per_channel(&self) -> usize {
        self.rows_per_channel
    }

    /// Verify this receipt against the exact input tail selected by `config`.
    ///
    /// A successful check proves only byte-level agreement with the supplied
    /// values and declared episode label. It does not prove that a direct caller
    /// assigned the rows to the correct physical episode.
    pub fn verifies(&self, input: &DeclaredMiInput, config: &MiConsensusConfig) -> bool {
        let available_rows = input.channels.first().map_or(0, |(_, values)| values.len());
        let rows = available_rows.min(config.window);
        let tail = input.tail(rows);
        self == &row_set_receipt(&tail, &input.episode_label, input.origin)
    }
}

/// Immutable, validated direct input for one declared episode.
///
/// The constructor verifies shape, modality uniqueness, and finite values. It
/// retains only the newest [`MAX_MI_WINDOW`] rows because no accepted configuration
/// can evaluate an earlier prefix; constructor validation and derived cloning are
/// therefore bounded by the same public row ceiling. A
/// direct column API cannot independently verify that index `i` names the same
/// physical row in every column. Its typed origin therefore records alignment as
/// a caller assertion. Use the core-bound route when validated sequence and
/// lifecycle provenance is required.
#[derive(Debug, Clone)]
pub struct DeclaredMiInput {
    channels: Vec<(Modality, Vec<f64>)>,
    episode_label: String,
    origin: EpisodeReceiptOrigin,
}

impl DeclaredMiInput {
    /// Construct direct research input for one caller-declared episode.
    pub fn try_new(
        channels: Vec<(Modality, Vec<f64>)>,
        episode_label: impl Into<String>,
    ) -> galadriel_core::Result<Self> {
        Self::try_new_with_origin(
            channels,
            episode_label.into(),
            EpisodeReceiptOrigin::CallerDeclaredAlignmentAsserted,
        )
    }

    pub(crate) fn from_core_projection(
        channels: Vec<(Modality, Vec<f64>)>,
        binding: &AssessmentBinding,
    ) -> galadriel_core::Result<Self> {
        Self::try_new_with_origin(
            channels,
            format!("core-assessment:{}", binding.digest()),
            EpisodeReceiptOrigin::CoreAssessmentBinding,
        )
    }

    fn try_new_with_origin(
        mut channels: Vec<(Modality, Vec<f64>)>,
        episode_label: String,
        origin: EpisodeReceiptOrigin,
    ) -> galadriel_core::Result<Self> {
        if episode_label.trim().is_empty() || episode_label.len() > MAX_EPISODE_LABEL_BYTES {
            return Err(GaladrielError::InvalidChannels(format!(
                "MI episode label must contain 1..={MAX_EPISODE_LABEL_BYTES} bytes"
            )));
        }
        if channels.len() > MAX_MODALITIES {
            return Err(GaladrielError::InvalidChannels(format!(
                "MI consensus accepts at most {MAX_MODALITIES} channels, got {}",
                channels.len()
            )));
        }
        let unique: HashSet<Modality> = channels.iter().map(|(modality, _)| *modality).collect();
        if unique.len() != channels.len() {
            return Err(GaladrielError::InvalidChannels(
                "MI consensus modalities must be unique".into(),
            ));
        }
        let lengths: HashSet<usize> = channels.iter().map(|(_, values)| values.len()).collect();
        if lengths.len() > 1 {
            return Err(GaladrielError::InvalidChannels(
                "MI consensus columns must be equal-length; direct callers separately assert one-to-one row alignment".into(),
            ));
        }
        for (_, values) in &mut channels {
            if values.len() > MAX_MI_WINDOW {
                *values = values.split_off(values.len() - MAX_MI_WINDOW);
            }
        }
        if channels
            .iter()
            .flat_map(|(_, values)| values)
            .any(|value| !value.is_finite())
        {
            return Err(GaladrielError::NonFinite("MI consensus channel input"));
        }
        Ok(Self {
            channels,
            episode_label,
            origin,
        })
    }

    /// Exact submitted channels in caller order.
    pub fn channels(&self) -> &[(Modality, Vec<f64>)] {
        &self.channels
    }

    /// Declared episode label.
    pub fn episode_label(&self) -> &str {
        &self.episode_label
    }

    /// Provenance strength of the episode label.
    pub const fn origin(&self) -> EpisodeReceiptOrigin {
        self.origin
    }

    /// Whether one-to-one row alignment was validated by core or asserted by a
    /// direct caller. Neither variant authenticates physical provenance.
    pub const fn alignment_is_caller_asserted(&self) -> bool {
        matches!(
            self.origin,
            EpisodeReceiptOrigin::CallerDeclaredAlignmentAsserted
        )
    }

    fn tail(&self, rows: usize) -> Vec<(Modality, Vec<f64>)> {
        self.channels
            .iter()
            .map(|(modality, values)| {
                (
                    *modality,
                    values[values.len().saturating_sub(rows)..].to_vec(),
                )
            })
            .collect()
    }
}

/// Unvalidated stability choice accepted only by [`MiConsensusConfig::try_new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependenceStabilityParams {
    /// Run only the configured graph on the submitted tail.
    PointEstimateOnly,
    /// Delete each possible circular block and require exact graph-disposition stability.
    ExhaustiveCircularDeleteBlock { block_size: usize },
}

/// Unvalidated numerical boundary values for [`MiConsensusConfig`].
#[derive(Debug, Clone, PartialEq)]
pub struct MiConsensusParams {
    pub window: usize,
    pub min_samples: usize,
    pub geom_k: usize,
    pub id_min: f64,
    pub id_max: f64,
    pub cv_min: f64,
    pub nn_ratio_max: f64,
    pub separation_ratio: f64,
    pub mi_floor_nats: f64,
    pub stability: DependenceStabilityParams,
}

/// Closed exploratory profiles shipped by the unpublished 0.9 source candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiConsensusResearchProfile {
    /// Point graph plus exhaustive circular delete-block stability.
    ExhaustiveCircularDeleteBlockV0_9,
    /// Point graph with no deletion-stability claim.
    PointEstimateOnlyV0_9,
}

impl MiConsensusResearchProfile {
    /// Stable machine-readable profile name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ExhaustiveCircularDeleteBlockV0_9 => "exhaustive_circular_delete_block_v0_9",
            Self::PointEstimateOnlyV0_9 => "point_estimate_only_v0_9",
        }
    }

    /// Numeric profile template. The population-law declaration is deliberately absent.
    pub const fn params(self) -> MiConsensusParams {
        MiConsensusParams {
            window: 128,
            min_samples: 64,
            geom_k: 5,
            // Each KSG edge is a bivariate scalar joint. These project-defined
            // screening bounds reject a materially one-dimensional sample and
            // an implausibly high estimate while retaining the fixed Gaussian
            // controls. They do not prove full-dimensional population support.
            id_min: 1.5,
            id_max: 3.0,
            cv_min: 0.01,
            nn_ratio_max: 0.999,
            separation_ratio: 0.4,
            mi_floor_nats: 0.03,
            stability: match self {
                Self::ExhaustiveCircularDeleteBlockV0_9 => {
                    DependenceStabilityParams::ExhaustiveCircularDeleteBlock { block_size: 8 }
                }
                Self::PointEstimateOnlyV0_9 => DependenceStabilityParams::PointEstimateOnly,
            },
        }
    }

    /// Resolve the profile with an explicit caller-supplied population-law declaration.
    pub fn try_config(
        self,
        law: ContinuousLawDeclaration,
    ) -> Result<MiConsensusConfig, MiConsensusConfigError> {
        MiConsensusConfig::try_new_with_profile(self.params(), law, Some(self))
    }
}

/// Validated stability semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependenceStability {
    PointEstimateOnly,
    ExhaustiveCircularDeleteBlock { block_size: usize },
}

impl DependenceStability {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PointEstimateOnly => "point_estimate_only",
            Self::ExhaustiveCircularDeleteBlock { .. } => {
                "exhaustive_circular_delete_block_stability"
            }
        }
    }

    pub const fn block_size(&self) -> Option<usize> {
        match self {
            Self::PointEstimateOnly => None,
            Self::ExhaustiveCircularDeleteBlock { block_size } => Some(*block_size),
        }
    }
}

/// Typed rejection from MI-consensus configuration construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiConsensusConfigError {
    WindowOutOfRange,
    GeometryKTooSmall,
    MinimumSamplesOutOfRange,
    IntrinsicDimensionMinimumInvalid,
    IntrinsicDimensionMaximumInvalid,
    DistanceCvMinimumInvalid,
    NearestNeighborRatioInvalid,
    SeparationRatioInvalid,
    MiFloorInvalid,
    DeleteBlockSizeInvalid,
    DeclarationTextEmpty { field: &'static str },
    DeclarationTextTooLong { field: &'static str, maximum: usize },
    WorkEstimateOverflow,
    WorkEstimateExceedsLimit { requested: usize, maximum: usize },
}

impl fmt::Display for MiConsensusConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowOutOfRange => write!(
                formatter,
                "MI-consensus window must be in 4..={MAX_MI_WINDOW}"
            ),
            Self::GeometryKTooSmall => formatter.write_str("MI-consensus geom_k must be >= 3"),
            Self::MinimumSamplesOutOfRange => formatter.write_str(
                "MI-consensus min_samples must exceed geom_k and KSG k and be <= window",
            ),
            Self::IntrinsicDimensionMaximumInvalid => {
                formatter.write_str("MI-consensus id_max must be finite and exceed id_min")
            }
            Self::IntrinsicDimensionMinimumInvalid => {
                formatter.write_str("MI-consensus id_min must be finite and in (0, 2)")
            }
            Self::DistanceCvMinimumInvalid => {
                formatter.write_str("MI-consensus cv_min must be finite and > 0")
            }
            Self::NearestNeighborRatioInvalid => formatter
                .write_str("MI-consensus nn_ratio_max must be finite and in (0, 1]"),
            Self::SeparationRatioInvalid => formatter
                .write_str("MI-consensus separation_ratio must be finite and in (0, 1]"),
            Self::MiFloorInvalid => {
                formatter.write_str("MI-consensus mi_floor_nats must be finite and > 0")
            }
            Self::DeleteBlockSizeInvalid => formatter.write_str(
                "exhaustive delete-block size must be positive and leave min_samples rows",
            ),
            Self::DeclarationTextEmpty { field } => {
                write!(formatter, "continuous-law declaration {field} must be nonempty")
            }
            Self::DeclarationTextTooLong { field, maximum } => write!(
                formatter,
                "continuous-law declaration {field} exceeds {maximum} bytes"
            ),
            Self::WorkEstimateOverflow => {
                formatter.write_str("MI-consensus checked work estimate overflowed")
            }
            Self::WorkEstimateExceedsLimit { requested, maximum } => write!(
                formatter,
                "MI-consensus requests {requested} quadratic scan-equivalent units; maximum is {maximum}"
            ),
        }
    }
}

impl Error for MiConsensusConfigError {}

impl From<MiConsensusConfigError> for GaladrielError {
    fn from(error: MiConsensusConfigError) -> Self {
        Self::InvalidConfig(error.to_string())
    }
}

/// Immutable accepted configuration for the exploratory pairwise-MI graph.
#[derive(Debug, Clone, PartialEq)]
pub struct MiConsensusConfig {
    window: usize,
    min_samples: usize,
    geom_k: usize,
    id_min: f64,
    id_max: f64,
    cv_min: f64,
    nn_ratio_max: f64,
    separation_ratio: f64,
    mi_floor_nats: f64,
    stability: DependenceStability,
    law: ContinuousLawDeclaration,
    source_profile: Option<MiConsensusResearchProfile>,
    quadratic_fit_work: usize,
}

impl MiConsensusConfig {
    /// Validate custom numerical parameters and the required law declaration.
    pub fn try_new(
        params: MiConsensusParams,
        law: ContinuousLawDeclaration,
    ) -> Result<Self, MiConsensusConfigError> {
        Self::try_new_with_profile(params, law, None)
    }

    fn try_new_with_profile(
        params: MiConsensusParams,
        law: ContinuousLawDeclaration,
        source_profile: Option<MiConsensusResearchProfile>,
    ) -> Result<Self, MiConsensusConfigError> {
        if !(4..=MAX_MI_WINDOW).contains(&params.window) {
            return Err(MiConsensusConfigError::WindowOutOfRange);
        }
        if params.geom_k < 3 {
            return Err(MiConsensusConfigError::GeometryKTooSmall);
        }
        if params.min_samples <= params.geom_k.max(KSG_NEIGHBORS)
            || params.min_samples > params.window
        {
            return Err(MiConsensusConfigError::MinimumSamplesOutOfRange);
        }
        if !params.id_min.is_finite() || params.id_min <= 0.0 || params.id_min >= 2.0 {
            return Err(MiConsensusConfigError::IntrinsicDimensionMinimumInvalid);
        }
        if !params.id_max.is_finite() || params.id_max <= params.id_min {
            return Err(MiConsensusConfigError::IntrinsicDimensionMaximumInvalid);
        }
        if !params.cv_min.is_finite() || params.cv_min <= 0.0 {
            return Err(MiConsensusConfigError::DistanceCvMinimumInvalid);
        }
        if !params.nn_ratio_max.is_finite()
            || params.nn_ratio_max <= 0.0
            || params.nn_ratio_max > 1.0
        {
            return Err(MiConsensusConfigError::NearestNeighborRatioInvalid);
        }
        if !params.separation_ratio.is_finite()
            || params.separation_ratio <= 0.0
            || params.separation_ratio > 1.0
        {
            return Err(MiConsensusConfigError::SeparationRatioInvalid);
        }
        if !params.mi_floor_nats.is_finite() || params.mi_floor_nats <= 0.0 {
            return Err(MiConsensusConfigError::MiFloorInvalid);
        }
        let stability = match params.stability {
            DependenceStabilityParams::PointEstimateOnly => DependenceStability::PointEstimateOnly,
            DependenceStabilityParams::ExhaustiveCircularDeleteBlock { block_size } => {
                if block_size == 0
                    || block_size >= params.window
                    || params
                        .min_samples
                        .checked_add(block_size)
                        .is_none_or(|required| required > params.window)
                {
                    return Err(MiConsensusConfigError::DeleteBlockSizeInvalid);
                }
                DependenceStability::ExhaustiveCircularDeleteBlock { block_size }
            }
        };
        let quadratic_fit_work = quadratic_fit_work(params.window, &stability)?;
        Ok(Self {
            window: params.window,
            min_samples: params.min_samples,
            geom_k: params.geom_k,
            id_min: params.id_min,
            id_max: params.id_max,
            cv_min: params.cv_min,
            nn_ratio_max: params.nn_ratio_max,
            separation_ratio: params.separation_ratio,
            mi_floor_nats: params.mi_floor_nats,
            stability,
            law,
            source_profile,
            quadratic_fit_work,
        })
    }

    pub const fn window(&self) -> usize {
        self.window
    }
    pub const fn min_samples(&self) -> usize {
        self.min_samples
    }
    pub fn required_samples(&self) -> usize {
        self.min_samples + self.stability.block_size().unwrap_or(0)
    }
    pub const fn geom_k(&self) -> usize {
        self.geom_k
    }
    pub const fn id_max(&self) -> f64 {
        self.id_max
    }
    pub const fn id_min(&self) -> f64 {
        self.id_min
    }
    pub const fn cv_min(&self) -> f64 {
        self.cv_min
    }
    pub const fn nn_ratio_max(&self) -> f64 {
        self.nn_ratio_max
    }
    pub const fn separation_ratio(&self) -> f64 {
        self.separation_ratio
    }
    pub const fn mi_floor_nats(&self) -> f64 {
        self.mi_floor_nats
    }
    pub const fn stability(&self) -> &DependenceStability {
        &self.stability
    }
    pub const fn law(&self) -> &ContinuousLawDeclaration {
        &self.law
    }
    pub const fn source_profile(&self) -> Option<MiConsensusResearchProfile> {
        self.source_profile
    }
    pub const fn quadratic_fit_work(&self) -> usize {
        self.quadratic_fit_work
    }
    pub const fn classification(&self) -> DependenceResearchClassification {
        if self.source_profile.is_some() {
            DependenceResearchClassification::NamedResearchProfile
        } else {
            DependenceResearchClassification::CustomAcceptedResearch
        }
    }

    /// Canonical identity of all accepted values and fixed estimator semantics.
    pub fn identity(&self) -> MiConsensusConfigDigest {
        let mut identity = IdentityBuilder::new(b"galadriel-mi-consensus-config-v1");
        identity.u8(
            b"classification",
            match self.classification() {
                DependenceResearchClassification::NamedResearchProfile => 1,
                DependenceResearchClassification::CustomAcceptedResearch => 2,
            },
        );
        identity.u8(
            b"source_profile",
            match self.source_profile {
                Some(MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9) => 1,
                Some(MiConsensusResearchProfile::PointEstimateOnlyV0_9) => 2,
                None => 0,
            },
        );
        identity.usize(b"window", self.window);
        identity.usize(b"min_samples", self.min_samples);
        identity.usize(b"geom_k", self.geom_k);
        identity.f64(b"id_min", self.id_min);
        identity.f64(b"id_max", self.id_max);
        identity.f64(b"id_local_median_min", ID_LOCAL_MEDIAN_MINIMUM);
        identity.f64(b"cv_min", self.cv_min);
        identity.f64(b"nn_ratio_max", self.nn_ratio_max);
        identity.f64(b"separation_ratio", self.separation_ratio);
        identity.f64(b"mi_floor_nats", self.mi_floor_nats);
        match self.stability {
            DependenceStability::PointEstimateOnly => identity.u8(b"stability", 1),
            DependenceStability::ExhaustiveCircularDeleteBlock { block_size } => {
                identity.u8(b"stability", 2);
                identity.usize(b"block_size", block_size);
            }
        }
        self.law.add_identity(&mut identity);
        identity.usize(b"quadratic_fit_work", self.quadratic_fit_work);
        identity.bytes(b"pid_rs_version", PID_RS_VERSION.as_bytes());
        identity.bytes(b"pid_rs_revision", PID_RS_REVISION.as_bytes());
        identity.bytes(b"pid_rs_git_repository", PID_RS_GIT_REPOSITORY.as_bytes());
        identity.bytes(b"functional_id", MI_FUNCTIONAL_ID.as_bytes());
        identity.bytes(b"estimator_id", MI_ESTIMATOR_ID.as_bytes());
        identity.bytes(b"graph_composition_id", MI_GRAPH_COMPOSITION_ID.as_bytes());
        identity.bytes(b"graph_rule_id", MI_GRAPH_RULE_ID.as_bytes());
        identity.bytes(b"tail_selection_rule_id", TAIL_SELECTION_RULE_ID.as_bytes());
        identity.bytes(
            b"preprocessing_relation_id",
            PREPROCESSING_RELATION_ID.as_bytes(),
        );
        identity.bytes(
            b"observation_transform_id",
            OBSERVATION_TRANSFORM_ID.as_bytes(),
        );
        identity.bytes(b"units", b"nats");
        identity.bytes(b"ksg_report_route", KSG_REPORT_ROUTE_ID.as_bytes());
        identity.bytes(b"ksg_estimand_revision", KSG_ESTIMAND_REVISION.as_bytes());
        identity.bytes(b"ksg_estimator_revision", KSG_ESTIMATOR_REVISION.as_bytes());
        identity.usize(b"ksg_k", KSG_NEIGHBORS);
        identity.bytes(b"metric", b"chebyshev");
        identity.bytes(
            b"neighbor_backend_selector",
            b"pid-rs-auto-exact-chebyshev-kdtree-or-bruteforce",
        );
        identity.f64(b"tie_epsilon", 0.0);
        identity.bytes(b"negative_handling", b"allow");
        identity.bytes(b"support_contract", b"assume_regular_full_dimensional");
        identity.bytes(b"support_boundary", b"unknown");
        identity.u8(b"support_density_regular", 1);
        identity.u8(b"support_finite_information", 1);
        identity.bytes(b"observation_transform", b"no-added-noise");
        identity.bytes(b"geometry_protocol", GEOMETRY_PROTOCOL_ID.as_bytes());
        identity.bytes(
            b"upstream_warning_policy",
            UPSTREAM_WARNING_POLICY_ID.as_bytes(),
        );
        identity.usize(b"max_modalities", MAX_MODALITIES);
        identity.usize(b"max_mi_window", MAX_MI_WINDOW);
        identity.usize(b"max_quadratic_fit_work", MAX_QUADRATIC_FIT_WORK);
        identity.usize(b"pair_point_fit_units", MI_PAIR_POINT_FIT_UNITS);
        MiConsensusConfigDigest::from_bytes(identity.finish())
    }
}

fn quadratic_fit_work(
    window: usize,
    stability: &DependenceStability,
) -> Result<usize, MiConsensusConfigError> {
    let graph_count = match stability {
        DependenceStability::PointEstimateOnly => 1,
        DependenceStability::ExhaustiveCircularDeleteBlock { .. } => window
            .checked_add(1)
            .ok_or(MiConsensusConfigError::WorkEstimateOverflow)?,
    };
    let work = pair_count(MAX_MODALITIES)
        .checked_mul(MI_PAIR_POINT_FIT_UNITS)
        .and_then(|value| value.checked_mul(graph_count))
        .and_then(|value| value.checked_mul(window))
        .and_then(|value| value.checked_mul(window))
        .ok_or(MiConsensusConfigError::WorkEstimateOverflow)?;
    if work > MAX_QUADRATIC_FIT_WORK {
        return Err(MiConsensusConfigError::WorkEstimateExceedsLimit {
            requested: work,
            maximum: MAX_QUADRATIC_FIT_WORK,
        });
    }
    Ok(work)
}

/// Self-describing snapshot of every accepted numerical MI-graph parameter.
///
/// The enclosing [`MiEstimatorEvidence`] supplies the declared population law and
/// fixed method semantics. This snapshot supplies the accepted numerical values,
/// including custom values, so the configuration digest is independently
/// reconstructible instead of being an opaque difference marker.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MiAcceptedConfigEvidence {
    research_profile: &'static str,
    window: usize,
    minimum_samples: usize,
    required_samples: usize,
    geometry_k: usize,
    intrinsic_dimension_minimum: f64,
    intrinsic_dimension_maximum: f64,
    intrinsic_dimension_local_median_minimum: f64,
    distance_pairwise_cv_minimum: f64,
    nearest_neighbor_over_pairwise_mean_maximum: f64,
    separation_ratio: f64,
    mi_floor_nats: f64,
    stability_protocol: &'static str,
    delete_block_size: Option<usize>,
    quadratic_fit_work: usize,
    quadratic_fit_work_maximum: usize,
    maximum_modalities: usize,
    maximum_input_tail_rows: usize,
    pair_point_fit_units: usize,
}

impl MiAcceptedConfigEvidence {
    fn from_config(config: &MiConsensusConfig) -> Self {
        Self {
            research_profile: config
                .source_profile
                .map_or("custom", |profile| profile.name()),
            window: config.window,
            minimum_samples: config.min_samples,
            required_samples: config.required_samples(),
            geometry_k: config.geom_k,
            intrinsic_dimension_minimum: config.id_min,
            intrinsic_dimension_maximum: config.id_max,
            intrinsic_dimension_local_median_minimum: ID_LOCAL_MEDIAN_MINIMUM,
            distance_pairwise_cv_minimum: config.cv_min,
            nearest_neighbor_over_pairwise_mean_maximum: config.nn_ratio_max,
            separation_ratio: config.separation_ratio,
            mi_floor_nats: config.mi_floor_nats,
            stability_protocol: config.stability.name(),
            delete_block_size: config.stability.block_size(),
            quadratic_fit_work: config.quadratic_fit_work,
            quadratic_fit_work_maximum: MAX_QUADRATIC_FIT_WORK,
            maximum_modalities: MAX_MODALITIES,
            maximum_input_tail_rows: MAX_MI_WINDOW,
            pair_point_fit_units: MI_PAIR_POINT_FIT_UNITS,
        }
    }

    pub const fn research_profile(&self) -> &'static str {
        self.research_profile
    }
    pub const fn window(&self) -> usize {
        self.window
    }
    pub const fn minimum_samples(&self) -> usize {
        self.minimum_samples
    }
    pub const fn required_samples(&self) -> usize {
        self.required_samples
    }
    pub const fn geometry_k(&self) -> usize {
        self.geometry_k
    }
    pub const fn intrinsic_dimension_minimum(&self) -> f64 {
        self.intrinsic_dimension_minimum
    }
    pub const fn intrinsic_dimension_maximum(&self) -> f64 {
        self.intrinsic_dimension_maximum
    }
    pub const fn intrinsic_dimension_local_median_minimum(&self) -> f64 {
        self.intrinsic_dimension_local_median_minimum
    }
    pub const fn distance_pairwise_cv_minimum(&self) -> f64 {
        self.distance_pairwise_cv_minimum
    }
    pub const fn nearest_neighbor_over_pairwise_mean_maximum(&self) -> f64 {
        self.nearest_neighbor_over_pairwise_mean_maximum
    }
    pub const fn separation_ratio(&self) -> f64 {
        self.separation_ratio
    }
    pub const fn mi_floor_nats(&self) -> f64 {
        self.mi_floor_nats
    }
    pub const fn stability_protocol(&self) -> &'static str {
        self.stability_protocol
    }
    pub const fn delete_block_size(&self) -> Option<usize> {
        self.delete_block_size
    }
    pub const fn quadratic_fit_work(&self) -> usize {
        self.quadratic_fit_work
    }
    pub const fn quadratic_fit_work_maximum(&self) -> usize {
        self.quadratic_fit_work_maximum
    }
    pub const fn maximum_modalities(&self) -> usize {
        self.maximum_modalities
    }
    pub const fn maximum_input_tail_rows(&self) -> usize {
        self.maximum_input_tail_rows
    }
    pub const fn pair_point_fit_units(&self) -> usize {
        self.pair_point_fit_units
    }
}

/// Self-describing fixed KSG evaluator configuration used by every graph edge.
///
/// Successful pair evidence also retains the complete upstream report. This
/// sibling record keeps an unavailable graph report independently interpretable:
/// it states the evaluator configuration that was attempted even when no pair
/// produced a report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MiKsgEvaluatorConfigEvidence {
    neighbors: usize,
    metric: &'static str,
    tie_epsilon: f64,
    negative_handling: &'static str,
    support_contract: &'static str,
    support_boundary: &'static str,
    support_density_regular: bool,
    support_finite_information: bool,
    geometry_model: &'static str,
    exact_backend_policy: &'static str,
    estimand_definition_revision: &'static str,
    estimator_revision: &'static str,
}

impl MiKsgEvaluatorConfigEvidence {
    const fn fixed() -> Self {
        Self {
            neighbors: KSG_NEIGHBORS,
            metric: "chebyshev",
            tie_epsilon: 0.0,
            negative_handling: "allow",
            support_contract: "assume_regular_full_dimensional",
            support_boundary: "unknown",
            support_density_regular: true,
            support_finite_information: true,
            geometry_model: "ambient_chebyshev",
            exact_backend_policy: "pid-rs auto exact Chebyshev kd-tree or brute-force",
            estimand_definition_revision: KSG_ESTIMAND_REVISION,
            estimator_revision: KSG_ESTIMATOR_REVISION,
        }
    }

    pub const fn neighbors(&self) -> usize {
        self.neighbors
    }
    pub const fn metric(&self) -> &'static str {
        self.metric
    }
    pub const fn tie_epsilon(&self) -> f64 {
        self.tie_epsilon
    }
    pub const fn negative_handling(&self) -> &'static str {
        self.negative_handling
    }
    pub const fn support_contract(&self) -> &'static str {
        self.support_contract
    }
    pub const fn support_boundary(&self) -> &'static str {
        self.support_boundary
    }
    pub const fn support_density_regular(&self) -> bool {
        self.support_density_regular
    }
    pub const fn support_finite_information(&self) -> bool {
        self.support_finite_information
    }
    pub const fn geometry_model(&self) -> &'static str {
        self.geometry_model
    }
    pub const fn exact_backend_policy(&self) -> &'static str {
        self.exact_backend_policy
    }
    pub const fn estimand_definition_revision(&self) -> &'static str {
        self.estimand_definition_revision
    }
    pub const fn estimator_revision(&self) -> &'static str {
        self.estimator_revision
    }
}

/// Complete functional/estimator identity attached to each graph report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MiEstimatorEvidence {
    config_identity: MiConsensusConfigDigest,
    accepted_config: MiAcceptedConfigEvidence,
    ksg_evaluator_config: MiKsgEvaluatorConfigEvidence,
    classification: DependenceResearchClassification,
    law: ContinuousLawDeclaration,
    research_profile: &'static str,
    functional_id: &'static str,
    estimator_id: &'static str,
    report_route_id: &'static str,
    estimator_reference: &'static str,
    composition_id: &'static str,
    graph_rule_id: &'static str,
    tail_selection_rule_id: &'static str,
    preprocessing_relation: &'static str,
    observation_transform: &'static str,
    geometry_protocol_id: &'static str,
    upstream_warning_policy_id: &'static str,
    units: &'static str,
    pid_rs_version: &'static str,
    pid_rs_revision: &'static str,
    pid_rs_git_repository: &'static str,
    calibrated_security_role: bool,
}

/// Numeric evidence from the two geometry gates applied before one KSG fit.
///
/// These sample diagnostics can reject a submitted row set. They cannot prove the
/// declared population law, estimator consistency, or security relevance.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PairGeometryEvidence {
    intrinsic_dimension_report: Arc<IntrinsicDimensionReport>,
    intrinsic_dimension_minimum: f64,
    intrinsic_dimension_maximum: f64,
    intrinsic_dimension_local_median_minimum: f64,
    distance_pairwise_cv: f64,
    distance_pairwise_cv_minimum: f64,
    nearest_neighbor_over_pairwise_mean: f64,
    nearest_neighbor_ratio_maximum: f64,
}

impl PairGeometryEvidence {
    pub fn intrinsic_dimension(&self) -> f64 {
        self.intrinsic_dimension_report.mean
    }
    pub fn intrinsic_dimension_k(&self) -> usize {
        self.intrinsic_dimension_report.k
    }
    /// Complete upstream local-distribution report used by the one-sided screen.
    pub fn intrinsic_dimension_report(&self) -> &IntrinsicDimensionReport {
        &self.intrinsic_dimension_report
    }
    pub const fn intrinsic_dimension_minimum(&self) -> f64 {
        self.intrinsic_dimension_minimum
    }
    pub const fn intrinsic_dimension_maximum(&self) -> f64 {
        self.intrinsic_dimension_maximum
    }
    pub const fn intrinsic_dimension_local_median_minimum(&self) -> f64 {
        self.intrinsic_dimension_local_median_minimum
    }
    pub const fn distance_pairwise_cv(&self) -> f64 {
        self.distance_pairwise_cv
    }
    pub const fn distance_pairwise_cv_minimum(&self) -> f64 {
        self.distance_pairwise_cv_minimum
    }
    pub const fn nearest_neighbor_over_pairwise_mean(&self) -> f64 {
        self.nearest_neighbor_over_pairwise_mean
    }
    pub const fn nearest_neighbor_ratio_maximum(&self) -> f64 {
        self.nearest_neighbor_ratio_maximum
    }
}

impl MiEstimatorEvidence {
    fn from_config(config: &MiConsensusConfig) -> Self {
        Self {
            config_identity: config.identity(),
            accepted_config: MiAcceptedConfigEvidence::from_config(config),
            ksg_evaluator_config: MiKsgEvaluatorConfigEvidence::fixed(),
            classification: config.classification(),
            law: config.law.clone(),
            research_profile: config
                .source_profile
                .map_or("custom", |profile| profile.name()),
            functional_id: MI_FUNCTIONAL_ID,
            estimator_id: MI_ESTIMATOR_ID,
            report_route_id: KSG_REPORT_ROUTE_ID,
            estimator_reference: "https://doi.org/10.1103/PhysRevE.69.066138",
            composition_id: MI_GRAPH_COMPOSITION_ID,
            graph_rule_id: MI_GRAPH_RULE_ID,
            tail_selection_rule_id: TAIL_SELECTION_RULE_ID,
            preprocessing_relation: PREPROCESSING_RELATION_ID,
            observation_transform: OBSERVATION_TRANSFORM_ID,
            geometry_protocol_id: GEOMETRY_PROTOCOL_ID,
            upstream_warning_policy_id: UPSTREAM_WARNING_POLICY_ID,
            units: "nats",
            pid_rs_version: PID_RS_VERSION,
            pid_rs_revision: PID_RS_REVISION,
            pid_rs_git_repository: PID_RS_GIT_REPOSITORY,
            calibrated_security_role: false,
        }
    }

    pub const fn config_identity(&self) -> MiConsensusConfigDigest {
        self.config_identity
    }
    /// Complete accepted numerical configuration represented by
    /// [`Self::config_identity`].
    pub const fn accepted_config(&self) -> &MiAcceptedConfigEvidence {
        &self.accepted_config
    }
    /// Complete fixed KSG configuration attempted for every graph edge.
    pub const fn ksg_evaluator_config(&self) -> &MiKsgEvaluatorConfigEvidence {
        &self.ksg_evaluator_config
    }
    pub const fn classification(&self) -> DependenceResearchClassification {
        self.classification
    }
    pub const fn law(&self) -> &ContinuousLawDeclaration {
        &self.law
    }
    pub const fn research_profile(&self) -> &'static str {
        self.research_profile
    }
    pub const fn functional_id(&self) -> &'static str {
        self.functional_id
    }
    pub const fn estimator_id(&self) -> &'static str {
        self.estimator_id
    }
    pub const fn report_route_id(&self) -> &'static str {
        self.report_route_id
    }
    pub const fn estimator_reference(&self) -> &'static str {
        self.estimator_reference
    }
    pub const fn composition_id(&self) -> &'static str {
        self.composition_id
    }
    pub const fn graph_rule_id(&self) -> &'static str {
        self.graph_rule_id
    }
    pub const fn tail_selection_rule_id(&self) -> &'static str {
        self.tail_selection_rule_id
    }
    pub const fn pid_rs_version(&self) -> &'static str {
        self.pid_rs_version
    }
    pub const fn pid_rs_revision(&self) -> &'static str {
        self.pid_rs_revision
    }
    pub const fn pid_rs_git_repository(&self) -> &'static str {
        self.pid_rs_git_repository
    }
    pub const fn units(&self) -> &'static str {
        self.units
    }
    pub const fn observation_transform(&self) -> &'static str {
        self.observation_transform
    }
    pub const fn preprocessing_relation(&self) -> &'static str {
        self.preprocessing_relation
    }
    pub const fn geometry_protocol_id(&self) -> &'static str {
        self.geometry_protocol_id
    }
    /// Policy for upstream warnings and assumption-ledger states.
    ///
    /// Every warning remains in the retained upstream report. A typed
    /// `UnsupportedObservedCondition` abstains. `WarningPresent` and trajectory
    /// warnings remain explicit limitations; they are never silently upgraded to
    /// satisfied assumptions.
    pub const fn upstream_warning_policy_id(&self) -> &'static str {
        self.upstream_warning_policy_id
    }
    pub fn coordinate_gauge(&self) -> &str {
        self.law.coordinate_gauge()
    }
    pub const fn calibrated_security_role(&self) -> bool {
        self.calibrated_security_role
    }
}

/// Successful report-first KSG evidence for one canonical modality pair.
///
/// This value is a component of [`PairMiReport`]. The enclosing pair report supplies
/// source identities; the enclosing [`MiConsensusReport`] supplies the full law and
/// episode receipt. Fields are private so callers cannot mutate duplicated summary
/// values into a contradiction with the retained upstream report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PairKsgEvidence {
    config_identity: MiConsensusConfigDigest,
    graph_row_values_sha256: String,
    pid_rs_version: &'static str,
    pid_rs_revision: &'static str,
    pid_rs_git_repository: &'static str,
    functional_id: &'static str,
    estimator_id: &'static str,
    units: &'static str,
    geometry: PairGeometryEvidence,
    upstream_report: Arc<KsgMiReport>,
}

impl PairKsgEvidence {
    pub const fn config_identity(&self) -> MiConsensusConfigDigest {
        self.config_identity
    }
    /// Digest of every modality/value column in the enclosing graph row set.
    pub fn graph_row_values_sha256(&self) -> &str {
        &self.graph_row_values_sha256
    }
    pub const fn pid_rs_version(&self) -> &'static str {
        self.pid_rs_version
    }
    pub const fn pid_rs_revision(&self) -> &'static str {
        self.pid_rs_revision
    }
    pub const fn pid_rs_git_repository(&self) -> &'static str {
        self.pid_rs_git_repository
    }
    pub const fn functional_id(&self) -> &'static str {
        self.functional_id
    }
    pub const fn estimator_id(&self) -> &'static str {
        self.estimator_id
    }
    pub const fn units(&self) -> &'static str {
        self.units
    }
    pub fn signed_estimate_nats(&self) -> f64 {
        self.upstream_report.signed_estimate_nats
    }
    pub fn n_samples(&self) -> usize {
        self.upstream_report.n_samples
    }
    pub fn k(&self) -> usize {
        self.upstream_report.k
    }
    pub fn support_contract(&self) -> SupportContract {
        self.upstream_report.support_contract
    }
    pub fn method_status(&self) -> KsgMethodStatus {
        self.upstream_report.method_status
    }
    pub fn scientific_status(&self) -> ScientificStatus {
        self.upstream_report.scientific_status
    }
    pub fn estimand(&self) -> &EstimandIdentity {
        &self.upstream_report.estimand
    }
    pub fn assumption_ledger(&self) -> &[AssumptionLedgerEntry] {
        &self.upstream_report.assumption_ledger
    }
    pub fn warnings(&self) -> &[KsgReportWarning] {
        &self.upstream_report.warnings
    }
    pub fn report_warnings(&self) -> &[WarningCode] {
        &self.upstream_report.report_warnings
    }
    pub fn preprocessing_description(&self) -> &str {
        self.upstream_report.provenance.preprocessing_description()
    }
    pub fn observation_model_description(&self) -> &str {
        self.upstream_report
            .provenance
            .observation_model_description()
    }
    pub fn sampling_model_description(&self) -> Option<&str> {
        self.upstream_report.provenance.sampling_model_description()
    }
    pub fn resource_estimate(&self) -> ResourceEstimate {
        self.upstream_report.resource_estimate
    }

    /// Exact numeric values and configured boundaries used by both geometry gates.
    pub const fn geometry(&self) -> &PairGeometryEvidence {
        &self.geometry
    }

    /// Complete report-first result returned by the pinned pid-rs revision.
    ///
    /// This retains the marginal cardinalities, neighbor-shell diagnostics, local
    /// diagnostic quantiles, backend identity, warnings, assumptions, provenance,
    /// and resource budget instead of reducing the upstream report to one scalar.
    pub fn upstream_report(&self) -> &KsgMiReport {
        &self.upstream_report
    }
}

/// Nominal reason a requested pair could not enter the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PairUnavailableCategory {
    PopulationAssumptionUnavailable,
    ObservedSampleIncompatibility,
    GeometryRejected,
    ResourceRejected,
    NumericalAbstention,
}

/// Outcome for one canonical modality pair.
///
/// The successful variant deliberately retains the complete inline report evidence.
/// The domain is fixed at most 15 pairs, so avoiding a new fallible allocation per
/// pair is preferable to shrinking this closed research enum.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum PairMiOutcome {
    Estimated(PairKsgEvidence),
    Unavailable {
        category: PairUnavailableCategory,
        note: String,
    },
}

/// One canonical edge in the complete requested graph.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PairMiReport {
    first: Modality,
    second: Modality,
    outcome: PairMiOutcome,
}

impl PairMiReport {
    pub const fn first(&self) -> Modality {
        self.first
    }
    pub const fn second(&self) -> Modality {
        self.second
    }
    pub const fn outcome(&self) -> &PairMiOutcome {
        &self.outcome
    }
    pub fn estimate_nats(&self) -> Option<f64> {
        match &self.outcome {
            PairMiOutcome::Estimated(evidence) => Some(evidence.signed_estimate_nats()),
            PairMiOutcome::Unavailable { .. } => None,
        }
    }
}

/// Per-channel summary derived only from the complete pair graph.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelDependence {
    modality: Modality,
    n: usize,
    strongest_pair_mi_nats: Option<f64>,
    separated_from_majority_graph: bool,
}

impl ChannelDependence {
    pub const fn modality(&self) -> Modality {
        self.modality
    }
    pub const fn n(&self) -> usize {
        self.n
    }
    pub const fn strongest_pair_mi_nats(&self) -> Option<f64> {
        self.strongest_pair_mi_nats
    }
    pub const fn is_separated_from_majority_graph(&self) -> bool {
        self.separated_from_majority_graph
    }
}

/// Why the configured graph did not support either retained descriptive outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MiGraphUnavailableReason {
    TooFewChannelsOrRows,
    DegenerateColumn,
    PairEvidenceUnavailable,
    /// At least one requested pair was rejected by a checked resource or allocation boundary.
    PairResourceRejected,
    ReferenceBelowConfiguredFloor,
    AmbiguousMajorityGraph,
    UnstableUnderExhaustiveDeletion,
    /// A deletion replay hit a resource boundary; no stability claim was evaluated.
    ResourceRejectedDuringExhaustiveDeletion,
}

/// Descriptive result of the configured MI graph heuristic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MiGraphDisposition {
    /// Every requested channel belongs to the one complete threshold graph.
    NoSeparationAtConfiguredThreshold,
    /// A strict minority lies outside one unique strict-majority clique.
    SeparatedFromMajorityGraph(Vec<Modality>),
    /// The requested graph could not support either descriptive result.
    Unavailable(MiGraphUnavailableReason),
}

/// Full-range margin for one separated candidate across all circular deletions.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CandidateMarginEnvelope {
    modality: Modality,
    minimum_nats: f64,
    maximum_nats: f64,
}

impl CandidateMarginEnvelope {
    pub const fn modality(&self) -> Modality {
        self.modality
    }
    pub const fn minimum_nats(&self) -> f64 {
        self.minimum_nats
    }
    pub const fn maximum_nats(&self) -> f64 {
        self.maximum_nats
    }
}

/// Deterministic sensitivity envelope over every circular block deletion.
///
/// This is not a confidence interval, p-value, null distribution, or error-rate
/// guarantee. The endpoints are literal minima and maxima over the enumerated
/// perturbations.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeleteBlockStabilityEnvelope {
    deletions_evaluated: usize,
    block_size: usize,
    consensus_margin_minimum_nats: f64,
    consensus_margin_maximum_nats: f64,
    candidate_margins: Vec<CandidateMarginEnvelope>,
}

impl DeleteBlockStabilityEnvelope {
    pub const fn deletions_evaluated(&self) -> usize {
        self.deletions_evaluated
    }
    pub const fn block_size(&self) -> usize {
        self.block_size
    }
    pub const fn consensus_margin_minimum_nats(&self) -> f64 {
        self.consensus_margin_minimum_nats
    }
    pub const fn consensus_margin_maximum_nats(&self) -> f64 {
        self.consensus_margin_maximum_nats
    }
    pub fn candidate_margins(&self) -> &[CandidateMarginEnvelope] {
        &self.candidate_margins
    }
}

/// Immutable analysis report for one exact scalar projection and row set.
#[derive(Debug, Clone, Serialize)]
pub struct MiConsensusReport {
    schema: &'static str,
    estimator: MiEstimatorEvidence,
    row_set: RowSetReceipt,
    pairs: Vec<PairMiReport>,
    channels: Vec<ChannelDependence>,
    disposition: MiGraphDisposition,
    threshold_nats: Option<f64>,
    stability: Option<DeleteBlockStabilityEnvelope>,
    note: String,
}

impl MiConsensusReport {
    /// Serialization schema of this immutable graph-report snapshot.
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    pub const fn estimator(&self) -> &MiEstimatorEvidence {
        &self.estimator
    }
    pub const fn row_set(&self) -> &RowSetReceipt {
        &self.row_set
    }
    pub fn pairs(&self) -> &[PairMiReport] {
        &self.pairs
    }
    pub fn channels(&self) -> &[ChannelDependence] {
        &self.channels
    }
    pub const fn disposition(&self) -> &MiGraphDisposition {
        &self.disposition
    }
    pub const fn threshold_nats(&self) -> Option<f64> {
        self.threshold_nats
    }
    pub const fn stability(&self) -> Option<&DeleteBlockStabilityEnvelope> {
        self.stability.as_ref()
    }
    pub fn note(&self) -> &str {
        &self.note
    }

    /// Verify the row receipt against the exact configured input tail.
    ///
    /// This check does not rerun the estimators or validate the caller's episode
    /// or population-law declarations.
    pub fn verifies_input(&self, input: &DeclaredMiInput, config: &MiConsensusConfig) -> bool {
        self.estimator.config_identity == config.identity() && self.row_set.verifies(input, config)
    }
}

#[derive(Debug)]
struct PointAnalysis {
    pairs: Vec<PairMiReport>,
    channels: Vec<ChannelDependence>,
    disposition: MiGraphDisposition,
    threshold: Option<f64>,
    mi: Vec<Vec<Option<f64>>>,
    consensus: Vec<usize>,
}

/// Analyze one exact caller-declared episode input.
///
/// The function uses only the configured tail, applies no stochastic transform,
/// and returns descriptive companion evidence. It never changes a core verdict.
pub fn analyze(
    input: &DeclaredMiInput,
    config: &MiConsensusConfig,
) -> galadriel_core::Result<MiConsensusReport> {
    let channel_count = input.channels.len();
    let available_rows = input.channels.first().map_or(0, |(_, values)| values.len());
    let rows = available_rows.min(config.window);
    let tail = input.tail(rows);
    let row_set = row_set_receipt(&tail, &input.episode_label, input.origin);
    let estimator = MiEstimatorEvidence::from_config(config);

    if channel_count < 3 || rows < config.required_samples() {
        return Ok(MiConsensusReport {
            schema: MI_CONSENSUS_REPORT_SCHEMA,
            estimator,
            row_set,
            pairs: Vec::new(),
            channels: Vec::new(),
            disposition: MiGraphDisposition::Unavailable(
                MiGraphUnavailableReason::TooFewChannelsOrRows,
            ),
            threshold_nats: None,
            stability: None,
            note: format!(
                "need at least 3 channels and {} rows; received {channel_count} channels and {rows} rows",
                config.required_samples()
            ),
        });
    }

    let mut point = point_analysis(&tail, config)?;
    let mut stability = None;
    if let DependenceStability::ExhaustiveCircularDeleteBlock { block_size } = config.stability() {
        let retained = matches!(
            point.disposition,
            MiGraphDisposition::NoSeparationAtConfiguredThreshold
                | MiGraphDisposition::SeparatedFromMajorityGraph(_)
        );
        if retained {
            match exhaustive_delete_stability(&tail, config, &point.disposition, *block_size) {
                Ok(envelope) => stability = Some(envelope),
                Err(StabilityFailure::AdapterInvariant(error)) => return Err(error),
                Err(StabilityFailure::ResourceRejected(note)) => {
                    for channel in &mut point.channels {
                        channel.separated_from_majority_graph = false;
                    }
                    point.disposition = MiGraphDisposition::Unavailable(
                        MiGraphUnavailableReason::ResourceRejectedDuringExhaustiveDeletion,
                    );
                    return Ok(MiConsensusReport {
                        schema: MI_CONSENSUS_REPORT_SCHEMA,
                        estimator,
                        row_set,
                        pairs: point.pairs,
                        channels: point.channels,
                        disposition: point.disposition,
                        threshold_nats: point.threshold,
                        stability: None,
                        note: format!(
                            "a circular-deletion replay was resource-rejected; no graph-stability claim was evaluated: {note}"
                        ),
                    });
                }
                Err(StabilityFailure::Unstable(note)) => {
                    for channel in &mut point.channels {
                        channel.separated_from_majority_graph = false;
                    }
                    point.disposition = MiGraphDisposition::Unavailable(
                        MiGraphUnavailableReason::UnstableUnderExhaustiveDeletion,
                    );
                    return Ok(MiConsensusReport {
                        schema: MI_CONSENSUS_REPORT_SCHEMA,
                        estimator,
                        row_set,
                        pairs: point.pairs,
                        channels: point.channels,
                        disposition: point.disposition,
                        threshold_nats: point.threshold,
                        stability: None,
                        note: format!(
                            "point graph disposition was not stable under every circular block deletion: {note}"
                        ),
                    });
                }
            }
        }
    }

    let note = match &point.disposition {
        MiGraphDisposition::NoSeparationAtConfiguredThreshold => {
            if stability.is_some() {
                format!(
                    "all {channel_count} requested channels form one complete graph at the configured threshold under every circular block deletion; this is deterministic sensitivity evidence, not a nominal-security claim"
                )
            } else {
                format!(
                    "all {channel_count} requested channels form one complete graph at the configured threshold in point-estimate-only mode; this is not a nominal-security claim"
                )
            }
        }
        MiGraphDisposition::SeparatedFromMajorityGraph(modalities) => {
            let names = modalities
                .iter()
                .map(|modality| modality.label())
                .collect::<Vec<_>>()
                .join(", ");
            if stability.is_some() {
                format!(
                    "{names} remain outside the same unique strict-majority MI graph under every circular block deletion; this is deterministic sensitivity evidence, not inference"
                )
            } else {
                format!(
                    "{names} lie outside one unique strict-majority MI graph in point-estimate-only mode; this is an uncalibrated descriptive heuristic"
                )
            }
        }
        MiGraphDisposition::Unavailable(reason) => {
            format!("MI graph unavailable: {reason:?}")
        }
    };
    Ok(MiConsensusReport {
        schema: MI_CONSENSUS_REPORT_SCHEMA,
        estimator,
        row_set,
        pairs: point.pairs,
        channels: point.channels,
        disposition: point.disposition,
        threshold_nats: point.threshold,
        stability,
        note,
    })
}

fn point_analysis(
    channels: &[(Modality, Vec<f64>)],
    config: &MiConsensusConfig,
) -> galadriel_core::Result<PointAnalysis> {
    let channel_count = channels.len();
    let rows = channels.first().map_or(0, |(_, values)| values.len());
    for (_modality, values) in channels {
        if column_is_degenerate(values) {
            return Ok(PointAnalysis {
                pairs: Vec::new(),
                channels: channels
                    .iter()
                    .map(|(candidate, _)| ChannelDependence {
                        modality: *candidate,
                        n: rows,
                        strongest_pair_mi_nats: None,
                        separated_from_majority_graph: false,
                    })
                    .collect(),
                disposition: MiGraphDisposition::Unavailable(
                    MiGraphUnavailableReason::DegenerateColumn,
                ),
                threshold: None,
                mi: vec![vec![None; channel_count]; channel_count],
                consensus: Vec::new(),
            });
        }
    }

    let receipt = raw_rows_digest(channels);
    let split_id = hex_digest(receipt);
    let mut mi = vec![vec![None; channel_count]; channel_count];
    let mut pairs = Vec::with_capacity(pair_count(channel_count));
    for first in 0..channel_count {
        for second in (first + 1)..channel_count {
            let report = pair_mi(
                config,
                channels[first].0,
                &channels[first].1,
                channels[second].0,
                &channels[second].1,
                &split_id,
            )?;
            if let PairMiOutcome::Estimated(evidence) = &report.outcome {
                mi[first][second] = Some(evidence.signed_estimate_nats());
                mi[second][first] = Some(evidence.signed_estimate_nats());
            }
            pairs.push(report);
        }
    }

    let mut summaries: Vec<ChannelDependence> = channels
        .iter()
        .enumerate()
        .map(|(index, (modality, _))| ChannelDependence {
            modality: *modality,
            n: rows,
            strongest_pair_mi_nats: (0..channel_count)
                .filter(|candidate| *candidate != index)
                .filter_map(|candidate| mi[index][candidate])
                .reduce(f64::max),
            separated_from_majority_graph: false,
        })
        .collect();

    if resource_rejection_note(&pairs).is_some() {
        for summary in &mut summaries {
            summary.strongest_pair_mi_nats = None;
        }
        return Ok(PointAnalysis {
            pairs,
            channels: summaries,
            disposition: MiGraphDisposition::Unavailable(
                MiGraphUnavailableReason::PairResourceRejected,
            ),
            threshold: None,
            mi,
            consensus: Vec::new(),
        });
    }

    if pairs
        .iter()
        .any(|pair| matches!(pair.outcome, PairMiOutcome::Unavailable { .. }))
    {
        for summary in &mut summaries {
            summary.strongest_pair_mi_nats = None;
        }
        return Ok(PointAnalysis {
            pairs,
            channels: summaries,
            disposition: MiGraphDisposition::Unavailable(
                MiGraphUnavailableReason::PairEvidenceUnavailable,
            ),
            threshold: None,
            mi,
            consensus: Vec::new(),
        });
    }

    let reference = pairs
        .iter()
        .filter_map(PairMiReport::estimate_nats)
        .fold(f64::NEG_INFINITY, f64::max);
    if reference.total_cmp(&config.mi_floor_nats) == Ordering::Less {
        return Ok(PointAnalysis {
            pairs,
            channels: summaries,
            disposition: MiGraphDisposition::Unavailable(
                MiGraphUnavailableReason::ReferenceBelowConfiguredFloor,
            ),
            threshold: None,
            mi,
            consensus: Vec::new(),
        });
    }
    let threshold = config
        .mi_floor_nats
        .max(config.separation_ratio * reference);
    let Some(consensus) = unique_strict_majority_consensus(&mi, threshold) else {
        return Ok(PointAnalysis {
            pairs,
            channels: summaries,
            disposition: MiGraphDisposition::Unavailable(
                MiGraphUnavailableReason::AmbiguousMajorityGraph,
            ),
            threshold: Some(threshold),
            mi,
            consensus: Vec::new(),
        });
    };
    let consensus_set: HashSet<usize> = consensus.iter().copied().collect();
    let candidates: Vec<usize> = (0..channel_count)
        .filter(|index| !consensus_set.contains(index))
        .collect();
    if candidates.iter().any(|candidate| {
        consensus
            .iter()
            .any(|peer| mi[*candidate][*peer].is_none_or(|value| value >= threshold))
    }) {
        return Ok(PointAnalysis {
            pairs,
            channels: summaries,
            disposition: MiGraphDisposition::Unavailable(
                MiGraphUnavailableReason::AmbiguousMajorityGraph,
            ),
            threshold: Some(threshold),
            mi,
            consensus: Vec::new(),
        });
    }
    for candidate in &candidates {
        summaries[*candidate].separated_from_majority_graph = true;
    }
    let disposition = if candidates.is_empty() {
        MiGraphDisposition::NoSeparationAtConfiguredThreshold
    } else {
        let mut modalities: Vec<Modality> =
            candidates.iter().map(|index| channels[*index].0).collect();
        modalities.sort_unstable_by_key(|modality| modality_key(*modality));
        MiGraphDisposition::SeparatedFromMajorityGraph(modalities)
    };
    Ok(PointAnalysis {
        pairs,
        channels: summaries,
        disposition,
        threshold: Some(threshold),
        mi,
        consensus,
    })
}

#[derive(Debug)]
enum StabilityFailure {
    Unstable(String),
    ResourceRejected(String),
    AdapterInvariant(GaladrielError),
}

impl From<String> for StabilityFailure {
    fn from(note: String) -> Self {
        Self::Unstable(note)
    }
}

fn exhaustive_delete_stability(
    channels: &[(Modality, Vec<f64>)],
    config: &MiConsensusConfig,
    expected: &MiGraphDisposition,
    block_size: usize,
) -> Result<DeleteBlockStabilityEnvelope, StabilityFailure> {
    let rows = channels
        .first()
        .map(|(_, values)| values.len())
        .ok_or_else(|| StabilityFailure::Unstable("no rows are available".to_string()))?;
    let expected_candidates = match expected {
        MiGraphDisposition::NoSeparationAtConfiguredThreshold => Vec::new(),
        MiGraphDisposition::SeparatedFromMajorityGraph(modalities) => {
            let mut modalities = modalities.clone();
            modalities.sort_unstable_by_key(|modality| modality_key(*modality));
            modalities
        }
        MiGraphDisposition::Unavailable(reason) => {
            return Err(StabilityFailure::Unstable(format!(
                "cannot claim deletion stability for unavailable point graph {reason:?}"
            )));
        }
    };
    let mut consensus_min = f64::INFINITY;
    let mut consensus_max = f64::NEG_INFINITY;
    let mut candidate_ranges: Vec<(Modality, f64, f64)> = expected_candidates
        .iter()
        .map(|modality| (*modality, f64::INFINITY, f64::NEG_INFINITY))
        .collect();

    for start in 0..rows {
        let plan = circular_retained_plan(rows, start, block_size);
        let retained: Vec<(Modality, Vec<f64>)> = channels
            .iter()
            .map(|(modality, values)| {
                (*modality, plan.iter().map(|index| values[*index]).collect())
            })
            .collect();
        // Full replay: retained-row validation, both geometry gates, every
        // report-first edge, global reference, threshold, clique, and attribution.
        let replay =
            point_analysis(&retained, config).map_err(StabilityFailure::AdapterInvariant)?;
        let observed_candidates = match &replay.disposition {
            MiGraphDisposition::NoSeparationAtConfiguredThreshold => Vec::new(),
            MiGraphDisposition::SeparatedFromMajorityGraph(modalities) => modalities.clone(),
            other => return Err(replay_disposition_failure(&replay, start, other)),
        };
        if observed_candidates != expected_candidates {
            return Err(StabilityFailure::Unstable(format!(
                "deletion start {start} selected {observed_candidates:?}, expected {expected_candidates:?}"
            )));
        }
        let threshold = replay.threshold.ok_or_else(|| {
            StabilityFailure::Unstable(format!("deletion start {start} omitted its threshold"))
        })?;
        let consensus_margin = consensus_margin(&replay.mi, &replay.consensus, threshold)
            .ok_or_else(|| {
                StabilityFailure::Unstable(format!(
                    "deletion start {start} omitted a consensus edge"
                ))
            })?;
        consensus_min = consensus_min.min(consensus_margin);
        consensus_max = consensus_max.max(consensus_margin);
        for (modality, minimum, maximum) in &mut candidate_ranges {
            let index = retained
                .iter()
                .position(|(candidate, _)| candidate == modality)
                .ok_or_else(|| {
                    StabilityFailure::Unstable("candidate modality disappeared".to_string())
                })?;
            let margin = candidate_margin(&replay.mi, &replay.consensus, index, threshold)
                .ok_or_else(|| {
                    StabilityFailure::Unstable(format!(
                        "deletion start {start} omitted a candidate edge"
                    ))
                })?;
            *minimum = minimum.min(margin);
            *maximum = maximum.max(margin);
        }
    }
    Ok(DeleteBlockStabilityEnvelope {
        deletions_evaluated: rows,
        block_size,
        consensus_margin_minimum_nats: consensus_min,
        consensus_margin_maximum_nats: consensus_max,
        candidate_margins: candidate_ranges
            .into_iter()
            .map(
                |(modality, minimum_nats, maximum_nats)| CandidateMarginEnvelope {
                    modality,
                    minimum_nats,
                    maximum_nats,
                },
            )
            .collect(),
    })
}

fn resource_rejection_note(pairs: &[PairMiReport]) -> Option<String> {
    pairs.iter().find_map(|pair| match &pair.outcome {
        PairMiOutcome::Unavailable {
            category: PairUnavailableCategory::ResourceRejected,
            note,
        } => Some(format!(
            "{}-{}: {note}",
            pair.first.label(),
            pair.second.label()
        )),
        PairMiOutcome::Estimated(_)
        | PairMiOutcome::Unavailable {
            category:
                PairUnavailableCategory::PopulationAssumptionUnavailable
                | PairUnavailableCategory::ObservedSampleIncompatibility
                | PairUnavailableCategory::GeometryRejected
                | PairUnavailableCategory::NumericalAbstention,
            ..
        } => None,
    })
}

fn replay_disposition_failure(
    replay: &PointAnalysis,
    start: usize,
    disposition: &MiGraphDisposition,
) -> StabilityFailure {
    if matches!(
        disposition,
        MiGraphDisposition::Unavailable(MiGraphUnavailableReason::PairResourceRejected)
    ) {
        return StabilityFailure::ResourceRejected(format!(
            "deletion start {start}: {}",
            resource_rejection_note(&replay.pairs)
                .unwrap_or_else(|| "resource rejection omitted pair detail".to_string())
        ));
    }
    StabilityFailure::Unstable(format!(
        "deletion start {start} produced {disposition:?} instead of the retained point disposition"
    ))
}

fn consensus_margin(mi: &[Vec<Option<f64>>], consensus: &[usize], threshold: f64) -> Option<f64> {
    let mut minimum: Option<f64> = None;
    for &first in consensus {
        for &second in consensus {
            if first == second {
                continue;
            }
            if let Some(value) = mi[first][second] {
                let margin = value - threshold;
                minimum = Some(minimum.map_or(margin, |current| current.min(margin)));
            }
        }
    }
    minimum
}

fn candidate_margin(
    mi: &[Vec<Option<f64>>],
    consensus: &[usize],
    candidate: usize,
    threshold: f64,
) -> Option<f64> {
    consensus
        .iter()
        .filter_map(|peer| mi[candidate][*peer])
        .map(|value| value - threshold)
        .reduce(f64::max)
}

fn circular_retained_plan(rows: usize, start: usize, block_size: usize) -> Vec<usize> {
    (0..rows)
        .filter(|index| {
            let offset = if *index >= start {
                *index - start
            } else {
                rows - (start - *index)
            };
            offset >= block_size
        })
        .collect()
}

#[derive(Debug)]
enum PairFitFailure {
    Unavailable {
        category: PairUnavailableCategory,
        note: String,
    },
    AdapterInvariant(PidError),
}

fn pair_mi(
    config: &MiConsensusConfig,
    first_modality: Modality,
    first: &[f64],
    second_modality: Modality,
    second: &[f64],
    row_set_id: &str,
) -> galadriel_core::Result<PairMiReport> {
    let (first_modality, first, second_modality, second) =
        canonical_pair(first_modality, first, second_modality, second);
    let outcome = match pair_mi_inner(
        config,
        first_modality,
        first,
        second_modality,
        second,
        row_set_id,
    ) {
        Ok(outcome) => outcome,
        Err(PairFitFailure::Unavailable { category, note }) => {
            PairMiOutcome::Unavailable { category, note }
        }
        Err(PairFitFailure::AdapterInvariant(error)) => {
            return Err(GaladrielError::InternalFault {
                component: "pid-rs KSG adapter",
                detail: format!("{}: {error}", pid_error_category(&error)),
            });
        }
    };
    Ok(PairMiReport {
        first: first_modality,
        second: second_modality,
        outcome,
    })
}

fn pid_error_category(error: &PidError) -> &'static str {
    match error {
        PidError::InvalidConfig { .. } => "invalid-config-invariant",
        PidError::ShapeMismatch { .. } => "shape-mismatch-invariant",
        PidError::InvalidK { .. } => "invalid-k-invariant",
        PidError::NotImplemented { .. } => "not-implemented-invariant",
        PidError::Cancelled { .. } => "unexpected-cancellation",
        PidError::ParallelExecutionFailed { .. } => "parallel-execution-failure",
        _ => "unexpected-pid-core-failure",
    }
}

fn intrinsic_geometry_is_admissible(
    intrinsic_dimension: f64,
    local_median: f64,
    config: &MiConsensusConfig,
) -> bool {
    // The closed finite interval itself rejects both infinities and NaN for the
    // mean. The one-sided local-median bound still needs an explicit finiteness
    // check so +infinity cannot satisfy it.
    local_median.is_finite()
        && intrinsic_dimension >= config.id_min
        && intrinsic_dimension <= config.id_max
        && local_median >= ID_LOCAL_MEDIAN_MINIMUM
}

fn concentration_geometry_is_admissible(
    pairwise_cv: f64,
    nearest_neighbor_ratio: f64,
    config: &MiConsensusConfig,
) -> bool {
    pairwise_cv.is_finite()
        && nearest_neighbor_ratio.is_finite()
        && pairwise_cv >= config.cv_min
        && nearest_neighbor_ratio <= config.nn_ratio_max
}

#[derive(Debug, Clone, Copy)]
struct UpstreamKsgContractChecks {
    method_status: bool,
    scientific_status: bool,
    signed_estimate_finite: bool,
    sample_count: bool,
    neighbors: bool,
    metric: bool,
    negative_handling: bool,
    support_contract: bool,
    geometry_model: bool,
    exact_neighbor_backend: bool,
    definition_revision: bool,
    estimator_revision: bool,
    estimand_family: bool,
    information_units: bool,
    estimand_metric: bool,
    no_source_gauge: bool,
    resource_budget: bool,
    resource_estimate: bool,
}

impl UpstreamKsgContractChecks {
    fn from_report(
        report: &KsgMiReport,
        expected: &KsgConfig,
        sample_count: usize,
        expected_budget: ResourceBudget,
        expected_estimate: ResourceEstimate,
    ) -> Self {
        Self {
            method_status: report.method_status == KsgMethodStatus::RestrictedDomain,
            scientific_status: report.scientific_status == ScientificStatus::ConditionalContinuous,
            signed_estimate_finite: report.signed_estimate_nats.is_finite(),
            sample_count: report.n_samples == sample_count,
            neighbors: report.k == expected.k,
            metric: report.metric == expected.metric,
            negative_handling: report.negative_handling == expected.negative_handling,
            support_contract: report.support_contract == expected.support_contract,
            geometry_model: report.geometry_model == KsgGeometryModel::AmbientChebyshev,
            // pid-core 0.9 selects one of two exact implementations before estimation and
            // never silently falls back after selection. Reject a future unrecognized backend
            // until this adapter has reviewed its numerical and resource contract.
            exact_neighbor_backend: matches!(
                report.neighbor_backend,
                KsgNeighborBackend::BruteForce | KsgNeighborBackend::ExactChebyshevKdTree
            ),
            definition_revision: report.estimand.definition_revision == KSG_ESTIMAND_REVISION,
            estimator_revision: report.estimand.estimator_revision == KSG_ESTIMATOR_REVISION,
            estimand_family: report.estimand.family == KSG_ESTIMAND_FAMILY,
            information_units: report.estimand.units == InformationUnit::Nats,
            estimand_metric: report.estimand.metric == KSG_ESTIMAND_METRIC,
            no_source_gauge: report.estimand.source_gauge.is_none(),
            resource_budget: report.resource_budget == expected_budget,
            resource_estimate: report.resource_estimate == expected_estimate,
        }
    }

    fn all_satisfied(self) -> bool {
        self.method_status
            && self.scientific_status
            && self.signed_estimate_finite
            && self.sample_count
            && self.neighbors
            && self.metric
            && self.negative_handling
            && self.support_contract
            && self.geometry_model
            && self.exact_neighbor_backend
            && self.definition_revision
            && self.estimator_revision
            && self.estimand_family
            && self.information_units
            && self.estimand_metric
            && self.no_source_gauge
            && self.resource_budget
            && self.resource_estimate
    }
}

fn pair_mi_inner(
    config: &MiConsensusConfig,
    first_modality: Modality,
    first: &[f64],
    second_modality: Modality,
    second: &[f64],
    row_set_id: &str,
) -> Result<PairMiOutcome, PairFitFailure> {
    let first_matrix = column_matrix(first).map_err(classify_pid_error)?;
    let second_matrix = column_matrix(second).map_err(classify_pid_error)?;
    let joint = joint_matrix(first, second).map_err(classify_pid_error)?;
    let intrinsic_report = intrinsic_dimension_report(
        joint.as_ref(),
        &IntrinsicDimConfig::default()
            .with_k(config.geom_k)
            .with_metric(Metric::Chebyshev),
        ResourceBudget::default(),
    )
    .map_err(classify_pid_error)?;
    let intrinsic = intrinsic_report.mean;
    let local_median = intrinsic_report.local_estimate_quantiles.median;
    if !intrinsic_geometry_is_admissible(intrinsic, local_median, config) {
        return Err(PairFitFailure::Unavailable {
            category: PairUnavailableCategory::GeometryRejected,
            note: format!(
                "intrinsic-dimension mean {intrinsic:.3} and local median {local_median:.3} fail the configured bivariate screen: mean [{:.3}, {:.3}], local median >= {:.3}",
                config.id_min, config.id_max, ID_LOCAL_MEDIAN_MINIMUM
            ),
        });
    }
    let concentration = distance_concentration_stats(
        joint.as_ref(),
        &DistanceConcentrationConfig::default().with_metric(Metric::Chebyshev),
    )
    .map_err(classify_pid_error)?;
    if !concentration_geometry_is_admissible(
        concentration.pairwise_cv,
        concentration.nn_over_pairwise_mean,
        config,
    ) {
        return Err(PairFitFailure::Unavailable {
            category: PairUnavailableCategory::GeometryRejected,
            note: format!(
                "geometry diagnostic rejected pair (cv {:.4}, nn/pair {:.4})",
                concentration.pairwise_cv, concentration.nn_over_pairwise_mean
            ),
        });
    }

    let provenance = KsgProvenance::new(
        format!(
            "Galadriel fixed identity transform (no data-adaptive preprocessing) for canonical pair {}-{}",
            first_modality.label(),
            second_modality.label()
        ),
        format!(
            "{}; Galadriel added no noise or tie-breaking transform",
            config.law.observation_model
        ),
        None,
    )
    .and_then(|value| {
        value.with_sampling_model_and_splits(
            &config.law.sampling_model,
            None,
            Some(row_set_id),
        )
    })
    .map_err(classify_pid_error)?;
    // Execute the report under the same explicit single-thread resource policy used by the
    // retained preflight. Galadriel separately enforces its own aggregate pair-scan ceiling at
    // configuration construction. This per-report budget is not an aggregate peak-memory claim.
    let resource_budget = ksg_resource_budget().map_err(classify_pid_error)?;
    let expected_resource_estimate = ksg_report_resource_estimate(
        first_matrix.as_ref(),
        second_matrix.as_ref(),
        &provenance,
        resource_budget.max_threads,
    )
    .map_err(classify_pid_error)?;
    let report = ksg_mi_report_with_budget(
        first_matrix.as_ref(),
        second_matrix.as_ref(),
        &ksg_config(),
        &provenance,
        resource_budget,
    )
    .map_err(classify_pid_error)?;
    let expected_config = ksg_config();
    if !UpstreamKsgContractChecks::from_report(
        &report,
        &expected_config,
        first.len(),
        resource_budget,
        expected_resource_estimate,
    )
    .all_satisfied()
    {
        return Err(PairFitFailure::AdapterInvariant(PidError::InvalidConfig {
            context: "galadriel-dependence",
            message: "upstream KSG report returned an unexpected status or non-finite estimate",
        }));
    }
    if report
        .assumption_ledger
        .iter()
        .any(|entry| entry.state == AssumptionState::UnsupportedObservedCondition)
    {
        return Err(PairFitFailure::Unavailable {
            category: PairUnavailableCategory::ObservedSampleIncompatibility,
            note: "upstream KSG assumption ledger recorded an unsupported observed condition"
                .into(),
        });
    }
    let geometry = PairGeometryEvidence {
        intrinsic_dimension_report: Arc::new(intrinsic_report),
        intrinsic_dimension_minimum: config.id_min,
        intrinsic_dimension_maximum: config.id_max,
        intrinsic_dimension_local_median_minimum: ID_LOCAL_MEDIAN_MINIMUM,
        distance_pairwise_cv: concentration.pairwise_cv,
        distance_pairwise_cv_minimum: config.cv_min,
        nearest_neighbor_over_pairwise_mean: concentration.nn_over_pairwise_mean,
        nearest_neighbor_ratio_maximum: config.nn_ratio_max,
    };
    let report = Arc::new(report);
    Ok(PairMiOutcome::Estimated(PairKsgEvidence {
        config_identity: config.identity(),
        graph_row_values_sha256: row_set_id.to_owned(),
        pid_rs_version: PID_RS_VERSION,
        pid_rs_revision: PID_RS_REVISION,
        pid_rs_git_repository: PID_RS_GIT_REPOSITORY,
        functional_id: MI_FUNCTIONAL_ID,
        estimator_id: MI_ESTIMATOR_ID,
        units: "nats",
        geometry,
        upstream_report: report,
    }))
}

fn classify_pid_error(error: PidError) -> PairFitFailure {
    let category = match error {
        PidError::ResourceLimitExceeded { .. }
        | PidError::AllocationFailed { .. }
        | PidError::SizeOverflow { .. } => PairUnavailableCategory::ResourceRejected,
        PidError::ObservedContinuousSampleIncompatibility { .. }
        | PidError::AmbiguousKthNeighborShell { .. } => {
            PairUnavailableCategory::ObservedSampleIncompatibility
        }
        PidError::NumericalInstability { .. } => PairUnavailableCategory::NumericalAbstention,
        other => return PairFitFailure::AdapterInvariant(other),
    };
    PairFitFailure::Unavailable {
        category,
        note: error.to_string(),
    }
}

fn ksg_resource_budget() -> Result<ResourceBudget, PidError> {
    ResourceBudget::new(
        KSG_RESOURCE_MAX_BYTES,
        KSG_RESOURCE_MAX_PAIRWISE_DISTANCES,
        KSG_RESOURCE_MAX_OPERATIONS_HINT,
        KSG_RESOURCE_MAX_THREADS,
    )
}

fn ksg_config() -> KsgConfig {
    KsgConfig::default()
        .with_k(KSG_NEIGHBORS)
        .with_metric(Metric::Chebyshev)
        .with_tie_epsilon(0.0)
        .with_negative_handling(NegativeHandling::Allow)
        .with_support_contract(SupportContract::AssumeRegularFullDimensional {
            boundary: BoundaryModel::Unknown,
            density_regular: true,
            finite_information: true,
        })
}

fn column_is_degenerate(values: &[f64]) -> bool {
    // Input construction has already rejected non-finite values. For at most
    // 512 finite binary64 rows, the former normalization left distinct extrema
    // an order-one distance apart, so its epsilon-times-count test was true
    // exactly when every value compared equal. State that contract directly.
    values.windows(2).all(|pair| pair[0] == pair[1])
}

fn column_matrix(values: &[f64]) -> Result<MatOwned, PidError> {
    MatOwned::new(values.to_vec(), values.len(), 1)
}

fn joint_matrix(first: &[f64], second: &[f64]) -> Result<MatOwned, PidError> {
    let mut flat = Vec::with_capacity(first.len().saturating_mul(2));
    for (left, right) in first.iter().zip(second) {
        flat.extend([*left, *right]);
    }
    MatOwned::new(flat, first.len(), 2)
}

fn canonical_pair<'a>(
    first_modality: Modality,
    first: &'a [f64],
    second_modality: Modality,
    second: &'a [f64],
) -> (Modality, &'a [f64], Modality, &'a [f64]) {
    if modality_key(first_modality) < modality_key(second_modality) {
        (first_modality, first, second_modality, second)
    } else {
        (second_modality, second, first_modality, first)
    }
}

fn largest_consensus_cliques(mi: &[Vec<Option<f64>>], threshold: f64) -> (usize, Vec<Vec<usize>>) {
    let channels = mi.len();
    let mut largest_size = 0;
    let mut largest_cliques = Vec::new();
    for mask in 1usize..(1usize << channels) {
        let members: Vec<usize> = (0..channels)
            .filter(|index| mask & (1 << index) != 0)
            .collect();
        if members.len() < largest_size {
            continue;
        }
        let is_clique = members.iter().enumerate().all(|(position, first)| {
            members[position + 1..]
                .iter()
                .all(|second| mi[*first][*second].is_some_and(|value| value >= threshold))
        });
        if !is_clique {
            continue;
        }
        if members.len() > largest_size {
            largest_size = members.len();
            largest_cliques.clear();
        }
        largest_cliques.push(members);
    }
    (largest_size, largest_cliques)
}

/// Return the only largest clique exactly when it is a strict majority.
///
/// Keeping the even-cardinality boundary in this pure helper makes the graph
/// rule directly testable without manufacturing KSG estimates for a desired
/// graph. A clique containing exactly half the channels is not a majority.
fn unique_strict_majority_consensus(mi: &[Vec<Option<f64>>], threshold: f64) -> Option<Vec<usize>> {
    let (largest_size, mut largest_cliques) = largest_consensus_cliques(mi, threshold);
    if largest_size <= mi.len() / 2 || largest_cliques.len() != 1 {
        return None;
    }
    largest_cliques.pop()
}

const fn modality_key(modality: Modality) -> u64 {
    match modality {
        Modality::Visual => 0,
        Modality::Thermal => 1,
        Modality::Acoustic => 2,
        Modality::Radar => 3,
        Modality::Lidar => 4,
        Modality::RadioFrequency => 5,
    }
}

fn row_set_receipt(
    channels: &[(Modality, Vec<f64>)],
    episode_label: &str,
    origin: EpisodeReceiptOrigin,
) -> RowSetReceipt {
    let mut digest = Sha256::new();
    digest.update(b"galadriel-mi-row-set-v1\0");
    digest.update((episode_label.len() as u64).to_be_bytes());
    digest.update(episode_label.as_bytes());
    digest.update([match origin {
        EpisodeReceiptOrigin::CallerDeclaredAlignmentAsserted => 1,
        EpisodeReceiptOrigin::CoreAssessmentBinding => 2,
    }]);
    digest.update(raw_rows_digest(channels));
    RowSetReceipt {
        sha256: digest.finalize().into(),
        episode_label: episode_label.to_owned(),
        origin,
        channel_count: channels.len(),
        rows_per_channel: channels.first().map_or(0, |(_, values)| values.len()),
    }
}

fn raw_rows_digest(channels: &[(Modality, Vec<f64>)]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"galadriel-mi-raw-rows-v1\0");
    digest.update((channels.len() as u64).to_be_bytes());
    for (modality, values) in channels {
        digest.update(modality_key(*modality).to_be_bytes());
        digest.update((values.len() as u64).to_be_bytes());
        for value in values {
            digest.update(value.to_bits().to_be_bytes());
        }
    }
    digest.finalize().into()
}

fn hex_digest(digest: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use galadriel_sim::scenario::{
        generate, generate_spoofed, ScenarioConfig, ScenarioResearchProfile, StealthySpoof,
    };

    fn law() -> ContinuousLawDeclaration {
        ContinuousLawDeclaration::try_iid(
            "The simulator declares a nonsingular jointly Gaussian population for every requested bivariate projection, with finite mutual information.",
            "Binary64 sample representation of pseudorandom draws intended from the declared continuous law; no deliberate quantization, added noise, or tie-breaking transform; exact ties abstain.",
            "Rows are independent draws within one synthetic episode under the fixed scenario parameters.",
            "All compared simulator projection coordinates use the same fixed physical innovation unit and identity gauge; no sample-fitted rescaling is applied.",
        )
        .unwrap()
    }

    fn point_config() -> MiConsensusConfig {
        MiConsensusResearchProfile::PointEstimateOnlyV0_9
            .try_config(law())
            .unwrap()
    }

    fn stable_config() -> MiConsensusConfig {
        MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9
            .try_config(law())
            .unwrap()
    }

    fn scenario(seed: u64) -> ScenarioConfig {
        let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
        params.frames = 400;
        params.rho = 0.7;
        params.seed = seed;
        ScenarioConfig::try_new(params).unwrap()
    }

    fn input_for(stream: &[galadriel_core::PidObservation]) -> DeclaredMiInput {
        DeclaredMiInput::try_new(
            galadriel_core::scalar_channels(
                stream,
                &[Modality::Visual, Modality::Radar, Modality::Acoustic],
                0,
            )
            .unwrap(),
            "one-synthetic-episode",
        )
        .unwrap()
    }

    #[test]
    fn config_requires_explicit_bounded_law_text_and_checked_work() {
        assert!(matches!(
            ContinuousLawDeclaration::try_iid("", "observed", "iid", "fixed common gauge"),
            Err(MiConsensusConfigError::DeclarationTextEmpty {
                field: "population_model"
            })
        ));
        let config = stable_config();
        assert_eq!(config.required_samples(), 72);
        assert!(config.quadratic_fit_work() <= MAX_QUADRATIC_FIT_WORK);
        assert_eq!(
            config.stability().name(),
            "exhaustive_circular_delete_block_stability"
        );
        assert_eq!(
            config.source_profile(),
            Some(MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9)
        );
    }

    #[test]
    fn configuration_boundaries_and_identity_fields_are_exact() {
        assert_eq!(pair_count(4), 6);
        assert_eq!(pair_count(MAX_MODALITIES), 15);
        assert_ne!(
            MAX_QUADRATIC_FIT_WORK % (pair_count(MAX_MODALITIES) * MI_PAIR_POINT_FIT_UNITS),
            0,
            "no work estimate can equal the configured ceiling"
        );
        assert_eq!(
            quadratic_fit_work(128, &DependenceStability::PointEstimateOnly).unwrap(),
            1_474_560
        );
        assert_eq!(
            quadratic_fit_work(
                128,
                &DependenceStability::ExhaustiveCircularDeleteBlock { block_size: 8 }
            )
            .unwrap(),
            190_218_240
        );
        assert!(matches!(
            quadratic_fit_work(
                131,
                &DependenceStability::ExhaustiveCircularDeleteBlock { block_size: 8 }
            ),
            Err(MiConsensusConfigError::WorkEstimateExceedsLimit { .. })
        ));

        let exact_text = "x".repeat(MAX_DECLARATION_BYTES);
        assert!(
            ContinuousLawDeclaration::try_iid(exact_text, "observation", "sampling", "gauge")
                .is_ok()
        );
        assert_eq!(
            ContinuousLawDeclaration::try_iid(
                "x".repeat(MAX_DECLARATION_BYTES + 1),
                "observation",
                "sampling",
                "gauge"
            )
            .unwrap_err(),
            MiConsensusConfigError::DeclarationTextTooLong {
                field: "population_model",
                maximum: MAX_DECLARATION_BYTES,
            }
        );

        let declared_law = law();
        assert!(declared_law.population_model().contains("nonsingular"));
        assert!(declared_law.observation_model().contains("Binary64"));
        assert!(declared_law.sampling_model().contains("independent draws"));
        assert!(declared_law.coordinate_gauge().contains("identity gauge"));
        assert_eq!(
            declared_law.sampling_regime(),
            ContinuousSamplingRegime::IndependentIdenticallyDistributed
        );
        let base = MiConsensusResearchProfile::PointEstimateOnlyV0_9.params();
        let original = MiConsensusConfig::try_new(base.clone(), declared_law.clone()).unwrap();
        let changed_laws = [
            ContinuousLawDeclaration::try_iid(
                format!("{} changed", declared_law.population_model()),
                declared_law.observation_model(),
                declared_law.sampling_model(),
                declared_law.coordinate_gauge(),
            )
            .unwrap(),
            ContinuousLawDeclaration::try_iid(
                declared_law.population_model(),
                format!("{} changed", declared_law.observation_model()),
                declared_law.sampling_model(),
                declared_law.coordinate_gauge(),
            )
            .unwrap(),
            ContinuousLawDeclaration::try_iid(
                declared_law.population_model(),
                declared_law.observation_model(),
                format!("{} changed", declared_law.sampling_model()),
                declared_law.coordinate_gauge(),
            )
            .unwrap(),
            ContinuousLawDeclaration::try_iid(
                declared_law.population_model(),
                declared_law.observation_model(),
                declared_law.sampling_model(),
                format!("{} changed", declared_law.coordinate_gauge()),
            )
            .unwrap(),
        ];
        for changed_law in changed_laws {
            let changed = MiConsensusConfig::try_new(base.clone(), changed_law).unwrap();
            assert_ne!(original.identity(), changed.identity());
        }

        let mut params = base.clone();
        params.window = 3;
        assert_eq!(
            MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
            MiConsensusConfigError::WindowOutOfRange
        );
        let mut params = base.clone();
        params.window = MAX_MI_WINDOW + 1;
        assert_eq!(
            MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
            MiConsensusConfigError::WindowOutOfRange
        );
        let mut params = base.clone();
        params.geom_k = 2;
        assert_eq!(
            MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
            MiConsensusConfigError::GeometryKTooSmall
        );
        let mut params = base.clone();
        params.min_samples = params.geom_k.max(KSG_NEIGHBORS);
        assert_eq!(
            MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
            MiConsensusConfigError::MinimumSamplesOutOfRange
        );
        let mut params = base.clone();
        params.min_samples = params.window + 1;
        assert_eq!(
            MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
            MiConsensusConfigError::MinimumSamplesOutOfRange
        );

        for value in [f64::NAN, 0.0, 2.0] {
            let mut params = base.clone();
            params.id_min = value;
            assert_eq!(
                MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
                MiConsensusConfigError::IntrinsicDimensionMinimumInvalid
            );
        }
        for value in [f64::NAN, base.id_min] {
            let mut params = base.clone();
            params.id_max = value;
            assert_eq!(
                MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
                MiConsensusConfigError::IntrinsicDimensionMaximumInvalid
            );
        }
        for value in [f64::NAN, 0.0] {
            let mut params = base.clone();
            params.cv_min = value;
            assert_eq!(
                MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
                MiConsensusConfigError::DistanceCvMinimumInvalid
            );
        }
        for value in [f64::NAN, 0.0, 1.01] {
            let mut params = base.clone();
            params.nn_ratio_max = value;
            assert_eq!(
                MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
                MiConsensusConfigError::NearestNeighborRatioInvalid
            );
        }
        for value in [f64::NAN, 0.0, 1.01] {
            let mut params = base.clone();
            params.separation_ratio = value;
            assert_eq!(
                MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
                MiConsensusConfigError::SeparationRatioInvalid
            );
        }
        for value in [f64::NAN, 0.0] {
            let mut params = base.clone();
            params.mi_floor_nats = value;
            assert_eq!(
                MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
                MiConsensusConfigError::MiFloorInvalid
            );
        }
        for block_size in [0, base.window, base.window - base.min_samples + 1] {
            let mut params = base.clone();
            params.stability =
                DependenceStabilityParams::ExhaustiveCircularDeleteBlock { block_size };
            assert_eq!(
                MiConsensusConfig::try_new(params, declared_law.clone()).unwrap_err(),
                MiConsensusConfigError::DeleteBlockSizeInvalid
            );
        }

        let mut accepted_ceilings = base.clone();
        accepted_ceilings.nn_ratio_max = 1.0;
        accepted_ceilings.separation_ratio = 1.0;
        accepted_ceilings.stability = DependenceStabilityParams::ExhaustiveCircularDeleteBlock {
            block_size: accepted_ceilings.window - accepted_ceilings.min_samples,
        };
        assert!(MiConsensusConfig::try_new(accepted_ceilings, declared_law.clone()).is_ok());

        let mut exact = base;
        exact.window = 4;
        exact.min_samples = 4;
        exact.geom_k = 3;
        assert!(MiConsensusConfig::try_new(exact, declared_law).is_ok());
        assert!(MiConsensusConfigError::GeometryKTooSmall
            .to_string()
            .contains("geom_k"));
    }

    #[test]
    fn custom_config_json_records_every_accepted_value_and_truthful_geometry_k() {
        let mut params = MiConsensusResearchProfile::PointEstimateOnlyV0_9.params();
        params.window = 96;
        params.min_samples = 48;
        params.geom_k = 7;
        params.id_min = 1.4;
        params.id_max = 2.8;
        params.cv_min = 0.02;
        params.nn_ratio_max = 0.95;
        params.separation_ratio = 0.55;
        params.mi_floor_nats = 0.04;
        let expected_params = params.clone();
        let config = MiConsensusConfig::try_new(params, law()).unwrap();
        let empty_input = DeclaredMiInput::try_new(Vec::new(), "custom-config-empty-episode")
            .expect("empty graph input is a typed unavailable request");
        let unavailable = analyze(&empty_input, &config).unwrap();
        assert_eq!(
            unavailable.disposition(),
            &MiGraphDisposition::Unavailable(MiGraphUnavailableReason::TooFewChannelsOrRows)
        );
        let estimator = unavailable.estimator();
        let serialized = serde_json::to_value(estimator).unwrap();
        let accepted = &serialized["accepted_config"];

        assert_eq!(serialized["research_profile"].as_str(), Some("custom"));
        assert_eq!(accepted["research_profile"].as_str(), Some("custom"));
        assert_eq!(accepted["window"].as_u64(), Some(96));
        assert_eq!(accepted["minimum_samples"].as_u64(), Some(48));
        assert_eq!(accepted["required_samples"].as_u64(), Some(48));
        assert_eq!(accepted["geometry_k"].as_u64(), Some(7));
        assert_eq!(accepted["intrinsic_dimension_minimum"].as_f64(), Some(1.4));
        assert_eq!(accepted["intrinsic_dimension_maximum"].as_f64(), Some(2.8));
        assert_eq!(
            accepted["distance_pairwise_cv_minimum"].as_f64(),
            Some(0.02)
        );
        assert_eq!(
            accepted["nearest_neighbor_over_pairwise_mean_maximum"].as_f64(),
            Some(0.95)
        );
        assert_eq!(accepted["separation_ratio"].as_f64(), Some(0.55));
        assert_eq!(accepted["mi_floor_nats"].as_f64(), Some(0.04));
        assert_eq!(
            accepted["stability_protocol"].as_str(),
            Some("point_estimate_only")
        );
        assert!(accepted["delete_block_size"].is_null());
        assert_eq!(accepted["maximum_modalities"].as_u64(), Some(6));
        assert_eq!(accepted["maximum_input_tail_rows"].as_u64(), Some(512));
        assert_eq!(accepted["pair_point_fit_units"].as_u64(), Some(6));
        let ksg = &serialized["ksg_evaluator_config"];
        assert_eq!(ksg["neighbors"].as_u64(), Some(3));
        assert_eq!(ksg["metric"].as_str(), Some("chebyshev"));
        assert_eq!(ksg["tie_epsilon"].as_f64(), Some(0.0));
        assert_eq!(ksg["negative_handling"].as_str(), Some("allow"));
        assert_eq!(
            ksg["support_contract"].as_str(),
            Some("assume_regular_full_dimensional")
        );
        assert_eq!(ksg["support_boundary"].as_str(), Some("unknown"));
        assert_eq!(ksg["support_density_regular"].as_bool(), Some(true));
        assert_eq!(ksg["support_finite_information"].as_bool(), Some(true));
        assert_eq!(ksg["geometry_model"].as_str(), Some("ambient_chebyshev"));
        assert_eq!(
            ksg["estimand_definition_revision"].as_str(),
            Some(KSG_ESTIMAND_REVISION)
        );
        assert_eq!(
            ksg["estimator_revision"].as_str(),
            Some(KSG_ESTIMATOR_REVISION)
        );
        assert_eq!(
            serialized["geometry_protocol_id"].as_str(),
            Some(GEOMETRY_PROTOCOL_ID)
        );
        assert!(GEOMETRY_PROTOCOL_ID.contains("configured-k"));
        assert!(!GEOMETRY_PROTOCOL_ID.contains("k5"));
        assert_eq!(estimator.accepted_config().geometry_k(), 7);
        assert_eq!(estimator.ksg_evaluator_config().neighbors(), 3);
        assert_eq!(estimator.config_identity(), config.identity());
        assert_eq!(
            estimator.classification(),
            DependenceResearchClassification::CustomAcceptedResearch
        );
        assert_eq!(estimator.law(), config.law());

        // JSON and the public Rust accessors are independent consumption routes.
        // Compare both against the submitted parameters and named constants,
        // rather than merely comparing an accessor with its backing field.
        assert_eq!(config.window(), expected_params.window);
        assert_eq!(config.min_samples(), expected_params.min_samples);
        assert_eq!(config.required_samples(), expected_params.min_samples);
        assert_eq!(config.geom_k(), expected_params.geom_k);
        assert_eq!(config.id_min().to_bits(), expected_params.id_min.to_bits());
        assert_eq!(config.id_max().to_bits(), expected_params.id_max.to_bits());
        assert_eq!(config.cv_min().to_bits(), expected_params.cv_min.to_bits());
        assert_eq!(
            config.nn_ratio_max().to_bits(),
            expected_params.nn_ratio_max.to_bits()
        );
        assert_eq!(
            config.separation_ratio().to_bits(),
            expected_params.separation_ratio.to_bits()
        );
        assert_eq!(
            config.mi_floor_nats().to_bits(),
            expected_params.mi_floor_nats.to_bits()
        );
        assert_eq!(
            config.quadratic_fit_work(),
            quadratic_fit_work(config.window(), config.stability()).unwrap()
        );
        assert_eq!(
            MiConsensusResearchProfile::PointEstimateOnlyV0_9.name(),
            "point_estimate_only_v0_9"
        );
        assert_eq!(
            ContinuousSamplingRegime::IndependentIdenticallyDistributed.name(),
            "independent-identically-distributed"
        );

        let accepted = estimator.accepted_config();
        assert_eq!(accepted.research_profile(), "custom");
        assert_eq!(accepted.window(), config.window());
        assert_eq!(accepted.minimum_samples(), config.min_samples());
        assert_eq!(accepted.required_samples(), config.required_samples());
        assert_eq!(accepted.geometry_k(), config.geom_k());
        assert_eq!(
            accepted.intrinsic_dimension_minimum().to_bits(),
            config.id_min().to_bits()
        );
        assert_eq!(
            accepted.intrinsic_dimension_maximum().to_bits(),
            config.id_max().to_bits()
        );
        assert_eq!(
            accepted
                .intrinsic_dimension_local_median_minimum()
                .to_bits(),
            ID_LOCAL_MEDIAN_MINIMUM.to_bits()
        );
        assert_eq!(
            accepted.distance_pairwise_cv_minimum().to_bits(),
            config.cv_min().to_bits()
        );
        assert_eq!(
            accepted
                .nearest_neighbor_over_pairwise_mean_maximum()
                .to_bits(),
            config.nn_ratio_max().to_bits()
        );
        assert_eq!(
            accepted.separation_ratio().to_bits(),
            config.separation_ratio().to_bits()
        );
        assert_eq!(
            accepted.mi_floor_nats().to_bits(),
            config.mi_floor_nats().to_bits()
        );
        assert_eq!(accepted.stability_protocol(), config.stability().name());
        assert_eq!(
            accepted.delete_block_size(),
            config.stability().block_size()
        );
        assert_eq!(accepted.quadratic_fit_work(), config.quadratic_fit_work());
        assert_eq!(
            accepted.quadratic_fit_work_maximum(),
            MAX_QUADRATIC_FIT_WORK
        );
        assert_eq!(accepted.maximum_modalities(), MAX_MODALITIES);
        assert_eq!(accepted.maximum_input_tail_rows(), MAX_MI_WINDOW);
        assert_eq!(accepted.pair_point_fit_units(), MI_PAIR_POINT_FIT_UNITS);

        let ksg = estimator.ksg_evaluator_config();
        assert_eq!(ksg.neighbors(), KSG_NEIGHBORS);
        assert_eq!(ksg.metric(), "chebyshev");
        assert_eq!(ksg.tie_epsilon().to_bits(), 0.0_f64.to_bits());
        assert_eq!(ksg.negative_handling(), "allow");
        assert_eq!(ksg.support_contract(), "assume_regular_full_dimensional");
        assert_eq!(ksg.support_boundary(), "unknown");
        assert!(ksg.support_density_regular());
        assert!(ksg.support_finite_information());
        assert_eq!(ksg.geometry_model(), "ambient_chebyshev");
        assert_eq!(
            ksg.exact_backend_policy(),
            "pid-rs auto exact Chebyshev kd-tree or brute-force"
        );
        assert_eq!(ksg.estimand_definition_revision(), KSG_ESTIMAND_REVISION);
        assert_eq!(ksg.estimator_revision(), KSG_ESTIMATOR_REVISION);

        assert_eq!(estimator.research_profile(), "custom");
        assert_eq!(estimator.functional_id(), MI_FUNCTIONAL_ID);
        assert_eq!(estimator.estimator_id(), MI_ESTIMATOR_ID);
        assert_eq!(estimator.report_route_id(), KSG_REPORT_ROUTE_ID);
        assert_eq!(
            estimator.estimator_reference(),
            "https://doi.org/10.1103/PhysRevE.69.066138"
        );
        assert_eq!(estimator.composition_id(), MI_GRAPH_COMPOSITION_ID);
        assert_eq!(estimator.graph_rule_id(), MI_GRAPH_RULE_ID);
        assert_eq!(estimator.tail_selection_rule_id(), TAIL_SELECTION_RULE_ID);
        assert_eq!(estimator.pid_rs_version(), PID_RS_VERSION);
        assert_eq!(estimator.pid_rs_revision(), PID_RS_REVISION);
        assert_eq!(estimator.pid_rs_git_repository(), PID_RS_GIT_REPOSITORY);
        assert_eq!(estimator.units(), "nats");
        assert_eq!(estimator.observation_transform(), OBSERVATION_TRANSFORM_ID);
        assert_eq!(
            estimator.preprocessing_relation(),
            PREPROCESSING_RELATION_ID
        );
        assert_eq!(estimator.geometry_protocol_id(), GEOMETRY_PROTOCOL_ID);
        assert_eq!(
            estimator.coordinate_gauge(),
            config.law().coordinate_gauge()
        );
        assert!(!estimator.calibrated_security_role());

        let stable_config = stable_config();
        let stable_report = analyze(&empty_input, &stable_config).unwrap();
        let stable_estimator = stable_report.estimator();
        assert_eq!(
            stable_estimator.accepted_config().delete_block_size(),
            Some(8)
        );
    }

    #[test]
    fn input_rejects_duplicate_modalities_unequal_lengths_and_nonfinite_values() {
        assert!(DeclaredMiInput::try_new(
            vec![(Modality::Visual, vec![0.0]), (Modality::Visual, vec![1.0])],
            "episode"
        )
        .is_err());
        assert!(DeclaredMiInput::try_new(
            vec![
                (Modality::Visual, vec![0.0]),
                (Modality::Radar, vec![1.0, 2.0])
            ],
            "episode"
        )
        .is_err());
        assert!(DeclaredMiInput::try_new(
            vec![
                (Modality::Visual, vec![f64::NAN]),
                (Modality::Radar, vec![1.0])
            ],
            "episode"
        )
        .is_err());
    }

    #[test]
    fn input_boundaries_preserve_exact_label_channel_tail_and_origin_contracts() {
        let exact_channels = Modality::ALL
            .into_iter()
            .enumerate()
            .map(|(index, modality)| (modality, vec![index as f64; MAX_MI_WINDOW]))
            .collect::<Vec<_>>();
        let exact_label = "e".repeat(MAX_EPISODE_LABEL_BYTES);
        let exact = DeclaredMiInput::try_new(exact_channels.clone(), exact_label.clone()).unwrap();
        assert_eq!(exact.channels().len(), MAX_MODALITIES);
        assert_eq!(exact.episode_label(), exact_label);
        assert_eq!(
            exact.origin(),
            EpisodeReceiptOrigin::CallerDeclaredAlignmentAsserted
        );
        assert!(exact.alignment_is_caller_asserted());

        assert!(DeclaredMiInput::try_new(exact_channels.clone(), "").is_err());
        assert!(DeclaredMiInput::try_new(
            exact_channels.clone(),
            "e".repeat(MAX_EPISODE_LABEL_BYTES + 1)
        )
        .is_err());
        let mut too_many = exact_channels;
        too_many.push((Modality::Visual, vec![0.0; MAX_MI_WINDOW]));
        assert!(matches!(
            DeclaredMiInput::try_new(too_many, "too-many-channels"),
            Err(GaladrielError::InvalidChannels(note))
                if note.contains("accepts at most") && note.contains("channels")
        ));

        let core_bound = DeclaredMiInput::try_new_with_origin(
            vec![(Modality::Visual, vec![0.0; MAX_MI_WINDOW])],
            "core-bound".into(),
            EpisodeReceiptOrigin::CoreAssessmentBinding,
        )
        .unwrap();
        assert_eq!(
            core_bound.origin(),
            EpisodeReceiptOrigin::CoreAssessmentBinding
        );
        assert!(!core_bound.alignment_is_caller_asserted());
    }

    #[test]
    fn direct_input_retains_only_the_bounded_analyzable_tail() {
        let mut first = (0..MAX_MI_WINDOW + 2)
            .map(|value| value as f64)
            .collect::<Vec<_>>();
        first[0] = f64::NAN;
        let input = DeclaredMiInput::try_new(
            vec![
                (Modality::Visual, first),
                (Modality::Radar, vec![2.0; MAX_MI_WINDOW + 2]),
                (Modality::Acoustic, vec![3.0; MAX_MI_WINDOW + 2]),
            ],
            "bounded-tail",
        )
        .expect("the unused prefix is discarded before finite-value validation");

        assert!(input
            .channels()
            .iter()
            .all(|(_, values)| values.len() == MAX_MI_WINDOW));
        assert!(input
            .channels()
            .iter()
            .flat_map(|(_, values)| values)
            .all(|value| value.is_finite()));
        assert_eq!(input.clone().channels()[0].1.len(), MAX_MI_WINDOW);
        assert_eq!(input.channels()[0].1[0], 2.0);
        assert_eq!(
            input.channels()[0].1[MAX_MI_WINDOW - 1],
            (MAX_MI_WINDOW + 1) as f64
        );
    }

    #[test]
    fn analyze_enforces_each_channel_and_row_boundary_independently() {
        let stream = generate(&scenario(19)).unwrap();
        let source = input_for(&stream);
        let config = point_config();
        let required = config.required_samples();
        let make_input = |channels: usize, rows: usize, label: &str| {
            DeclaredMiInput::try_new(
                source.channels()[..channels]
                    .iter()
                    .map(|(modality, values)| (*modality, values[values.len() - rows..].to_vec()))
                    .collect(),
                label,
            )
            .unwrap()
        };

        let too_few_channels =
            analyze(&make_input(2, required, "two-channels-exact-rows"), &config).unwrap();
        assert_eq!(
            too_few_channels.disposition(),
            &MiGraphDisposition::Unavailable(MiGraphUnavailableReason::TooFewChannelsOrRows)
        );
        assert!(too_few_channels.pairs().is_empty());

        let too_few_rows = analyze(
            &make_input(3, required - 1, "three-channels-short-rows"),
            &config,
        )
        .unwrap();
        assert_eq!(
            too_few_rows.disposition(),
            &MiGraphDisposition::Unavailable(MiGraphUnavailableReason::TooFewChannelsOrRows)
        );
        assert!(too_few_rows.pairs().is_empty());

        let exact_boundary = analyze(
            &make_input(3, required, "three-channels-exact-rows"),
            &config,
        )
        .unwrap();
        assert_eq!(exact_boundary.pairs().len(), pair_count(3));
        assert!(!matches!(
            exact_boundary.disposition(),
            MiGraphDisposition::Unavailable(MiGraphUnavailableReason::TooFewChannelsOrRows)
        ));
    }

    #[test]
    fn geometry_admission_checks_every_coordinate_and_inclusive_boundary() {
        let config = point_config();
        let intrinsic = (config.id_min() + config.id_max()) / 2.0;
        let local_median = ID_LOCAL_MEDIAN_MINIMUM + 0.25;
        assert!(intrinsic_geometry_is_admissible(
            intrinsic,
            local_median,
            &config
        ));
        assert!(intrinsic_geometry_is_admissible(
            config.id_min(),
            ID_LOCAL_MEDIAN_MINIMUM,
            &config
        ));
        assert!(intrinsic_geometry_is_admissible(
            config.id_max(),
            ID_LOCAL_MEDIAN_MINIMUM,
            &config
        ));
        for (rejected_intrinsic, rejected_median) in [
            (f64::NAN, local_median),
            (intrinsic, f64::NAN),
            (intrinsic, f64::INFINITY),
            (config.id_min() - 0.01, local_median),
            (config.id_max() + 0.01, local_median),
            (intrinsic, ID_LOCAL_MEDIAN_MINIMUM - 0.01),
        ] {
            assert!(!intrinsic_geometry_is_admissible(
                rejected_intrinsic,
                rejected_median,
                &config
            ));
        }

        let pairwise_cv = config.cv_min() + 0.1;
        let neighbor_ratio = config.nn_ratio_max() - 0.1;
        assert!(concentration_geometry_is_admissible(
            pairwise_cv,
            neighbor_ratio,
            &config
        ));
        assert!(concentration_geometry_is_admissible(
            config.cv_min(),
            config.nn_ratio_max(),
            &config
        ));
        for (rejected_cv, rejected_ratio) in [
            (f64::NAN, neighbor_ratio),
            (pairwise_cv, f64::NAN),
            (f64::INFINITY, neighbor_ratio),
            (pairwise_cv, f64::NEG_INFINITY),
            (config.cv_min() - 0.001, neighbor_ratio),
            (pairwise_cv, config.nn_ratio_max() + 0.001),
        ] {
            assert!(!concentration_geometry_is_admissible(
                rejected_cv,
                rejected_ratio,
                &config
            ));
        }
    }

    #[test]
    fn margins_deletion_plan_and_pid_error_categories_have_exact_semantics() {
        let mut mi = vec![vec![Some(0.0); 4]; 4];
        for (index, row) in mi.iter_mut().enumerate() {
            row[index] = None;
        }
        for (first, second, value) in [
            (0, 1, 1.4),
            (0, 2, 1.2),
            (1, 2, 1.3),
            (3, 0, 0.7),
            (3, 1, 0.9),
            (3, 2, 0.8),
        ] {
            mi[first][second] = Some(value);
            mi[second][first] = Some(value);
        }
        let consensus = [0, 1, 2];
        assert_eq!(
            consensus_margin(&mi, &consensus, 1.0).map(f64::to_bits),
            Some((1.2_f64 - 1.0).to_bits())
        );
        assert_eq!(
            candidate_margin(&mi, &consensus, 3, 1.0).map(f64::to_bits),
            Some((0.9_f64 - 1.0).to_bits())
        );
        assert_eq!(circular_retained_plan(8, 6, 3), vec![1, 2, 3, 4, 5]);
        assert_eq!(circular_retained_plan(8, 2, 3), vec![0, 1, 5, 6, 7]);

        let categories = [
            (
                PidError::InvalidConfig {
                    context: "test",
                    message: "test",
                },
                "invalid-config-invariant",
            ),
            (
                PidError::ShapeMismatch {
                    context: "test",
                    expected_len: 1,
                    actual_len: 2,
                },
                "shape-mismatch-invariant",
            ),
            (
                PidError::InvalidK { k: 3, n_samples: 3 },
                "invalid-k-invariant",
            ),
            (
                PidError::NotImplemented { feature: "test" },
                "not-implemented-invariant",
            ),
            (
                PidError::Cancelled {
                    operation: "test",
                    completed_units: 0,
                    total_units: 1,
                },
                "unexpected-cancellation",
            ),
            (
                PidError::ParallelExecutionFailed { operation: "test" },
                "parallel-execution-failure",
            ),
            (
                PidError::NonFiniteInput { context: "test" },
                "unexpected-pid-core-failure",
            ),
        ];
        for (error, expected) in categories {
            assert_eq!(pid_error_category(&error), expected);
        }
    }

    #[test]
    fn finite_column_degeneracy_is_exact_constancy() {
        assert!(column_is_degenerate(&[7.0]));
        assert!(column_is_degenerate(&[-0.0, 0.0, -0.0]));
        assert!(!column_is_degenerate(&[1.0, 1.0, 2.0]));
        assert!(!column_is_degenerate(&[0.0, f64::from_bits(1)]));
        assert!(!column_is_degenerate(&[-f64::MAX, f64::MAX]));
    }

    #[test]
    fn strict_majority_rejects_a_unique_half_clique_for_even_channel_counts() {
        let mut half = vec![vec![Some(0.0); 4]; 4];
        for (index, row) in half.iter_mut().enumerate() {
            row[index] = None;
        }
        half[0][1] = Some(2.0);
        half[1][0] = Some(2.0);
        assert_eq!(unique_strict_majority_consensus(&half, 1.0), None);

        let mut majority = half;
        for (first, second) in [(0, 2), (1, 2)] {
            majority[first][second] = Some(2.0);
            majority[second][first] = Some(2.0);
        }
        assert_eq!(
            unique_strict_majority_consensus(&majority, 1.0),
            Some(vec![0, 1, 2])
        );

        let mut tied = vec![vec![Some(0.0); 5]; 5];
        for (index, row) in tied.iter_mut().enumerate() {
            row[index] = None;
        }
        for (first, second) in [(0, 1), (0, 2), (1, 2), (0, 3), (0, 4), (3, 4)] {
            tied[first][second] = Some(2.0);
            tied[second][first] = Some(2.0);
        }
        assert_eq!(
            largest_consensus_cliques(&tied, 1.0),
            (3, vec![vec![0, 1, 2], vec![0, 3, 4]])
        );
        assert_eq!(unique_strict_majority_consensus(&tied, 1.0), None);

        assert_eq!(Modality::ALL.map(modality_key), [0_u64, 1, 2, 3, 4, 5]);
        let visual = [1.0];
        let radar = [2.0];
        let (first_modality, first, second_modality, second) =
            canonical_pair(Modality::Radar, &radar, Modality::Visual, &visual);
        assert_eq!(first_modality, Modality::Visual);
        assert_eq!(first, &visual);
        assert_eq!(second_modality, Modality::Radar);
        assert_eq!(second, &radar);
    }

    #[test]
    fn exact_row_receipt_changes_with_value_order_and_episode() {
        let first = DeclaredMiInput::try_new(
            vec![
                (Modality::Visual, vec![1.0, 2.0, 3.0, 4.0]),
                (Modality::Radar, vec![2.0, 3.0, 4.0, 5.0]),
                (Modality::Acoustic, vec![3.0, 4.0, 5.0, 6.0]),
            ],
            "episode-a",
        )
        .unwrap();
        let mut second = first.clone();
        second.channels[0].1.swap(0, 1);
        let left = row_set_receipt(&first.channels, first.episode_label(), first.origin());
        assert!(left.verifies(&first, &point_config()));
        assert_eq!(left.episode_label(), "episode-a");
        assert_eq!(
            left.origin(),
            EpisodeReceiptOrigin::CallerDeclaredAlignmentAsserted
        );
        assert_eq!(left.channel_count(), 3);
        assert_eq!(left.rows_per_channel(), 4);
        let right = row_set_receipt(&second.channels, second.episode_label(), second.origin());
        assert!(!left.verifies(&second, &point_config()));
        assert_ne!(left.sha256_hex(), right.sha256_hex());
        let other_episode = row_set_receipt(&first.channels, "episode-b", first.origin());
        assert_ne!(left.sha256_hex(), other_episode.sha256_hex());
        let other_origin = row_set_receipt(
            &first.channels,
            first.episode_label(),
            EpisodeReceiptOrigin::CoreAssessmentBinding,
        );
        assert_ne!(left.sha256_hex(), other_origin.sha256_hex());
        let mut reordered_channels = first.channels.clone();
        reordered_channels.swap(0, 1);
        let reordered = row_set_receipt(&reordered_channels, first.episode_label(), first.origin());
        assert_ne!(left.sha256_hex(), reordered.sha256_hex());
        assert!(first.alignment_is_caller_asserted());
        // Equal-length columns cannot prove paired-row identity. An independently
        // permuted column is accepted only under the explicit caller-asserted
        // origin, and it mints a different estimand receipt.
        assert!(second.alignment_is_caller_asserted());
        assert_ne!(left.sha256_hex(), right.sha256_hex());
    }

    #[test]
    fn clean_simulator_graph_is_descriptive_not_nominal_security() {
        let stream = generate(&scenario(7)).unwrap();
        let input = input_for(&stream);
        let config = point_config();
        let report = analyze(&input, &config).unwrap();
        assert_eq!(
            report.disposition(),
            &MiGraphDisposition::NoSeparationAtConfiguredThreshold
        );
        assert!(report.note().contains("not a nominal-security claim"));
        assert_eq!(report.pairs().len(), 3);
        assert!(report
            .pairs()
            .iter()
            .all(|pair| matches!(pair.outcome(), PairMiOutcome::Estimated(_))));
        assert_eq!(
            report.estimator().observation_transform(),
            OBSERVATION_TRANSFORM_ID
        );
        assert_eq!(
            report.estimator().upstream_warning_policy_id(),
            UPSTREAM_WARNING_POLICY_ID
        );
        let serialized = serde_json::to_value(&report)
            .expect("complete MI report must be a durable serializable artifact");
        assert_eq!(
            serialized["estimator"]["config_identity"]
                .as_str()
                .map(str::len),
            Some(64)
        );
        assert_eq!(
            serialized["row_set"]["sha256"].as_str().map(str::len),
            Some(64)
        );
        assert_eq!(
            serialized["estimator"]["functional_id"].as_str(),
            Some(MI_FUNCTIONAL_ID)
        );
        assert_eq!(
            serialized["estimator"]["report_route_id"].as_str(),
            Some(KSG_REPORT_ROUTE_ID)
        );
        assert_eq!(
            serialized["estimator"]["graph_rule_id"].as_str(),
            Some(MI_GRAPH_RULE_ID)
        );
        assert_eq!(
            serialized["estimator"]["pid_rs_revision"].as_str(),
            Some(PID_RS_REVISION)
        );
        assert_eq!(serialized["estimator"]["units"].as_str(), Some("nats"));
        assert_eq!(
            serialized["estimator"]["calibrated_security_role"].as_bool(),
            Some(false)
        );
        assert!(serialized["pairs"][0]["outcome"]["Estimated"]["upstream_report"].is_object());
        assert!(!report.estimator().calibrated_security_role());

        assert_eq!(report.schema(), MI_CONSENSUS_REPORT_SCHEMA);
        assert_eq!(report.channels().len(), input.channels().len());
        assert_eq!(report.row_set().channel_count(), input.channels().len());
        assert_eq!(report.row_set().rows_per_channel(), config.window());
        let reference = report
            .pairs()
            .iter()
            .filter_map(PairMiReport::estimate_nats)
            .reduce(f64::max)
            .unwrap();
        let expected_threshold = config
            .mi_floor_nats()
            .max(config.separation_ratio() * reference);
        assert_eq!(
            report.threshold_nats().map(f64::to_bits),
            Some(expected_threshold.to_bits())
        );
        assert!(report.verifies_input(&input, &config));
        let mut changed_input = input.clone();
        let changed_row = changed_input.channels[0].1.len() - 1;
        changed_input.channels[0].1[changed_row] += 0.25;
        assert!(!report.verifies_input(&changed_input, &config));
        let mut changed_params = MiConsensusResearchProfile::PointEstimateOnlyV0_9.params();
        changed_params.mi_floor_nats = 0.031;
        let changed_config = MiConsensusConfig::try_new(changed_params, law()).unwrap();
        assert!(!report.verifies_input(&input, &changed_config));

        for (channel, (expected_modality, expected_values)) in
            report.channels().iter().zip(input.channels())
        {
            assert_eq!(channel.modality(), *expected_modality);
            assert_eq!(channel.n(), expected_values.len().min(config.window()));
            let expected_strongest = report
                .pairs()
                .iter()
                .filter(|pair| {
                    pair.first() == *expected_modality || pair.second() == *expected_modality
                })
                .filter_map(PairMiReport::estimate_nats)
                .reduce(f64::max);
            assert_eq!(
                channel.strongest_pair_mi_nats().map(f64::to_bits),
                expected_strongest.map(f64::to_bits)
            );
            assert!(!channel.is_separated_from_majority_graph());
        }
        let analyzed_channels = input
            .channels()
            .iter()
            .map(|(modality, values)| {
                let start = values.len() - config.window();
                (*modality, values[start..].to_vec())
            })
            .collect::<Vec<_>>();
        let expected_graph_hash = hex_digest(raw_rows_digest(&analyzed_channels));
        let expected_pairs = [
            (Modality::Visual, Modality::Radar),
            (Modality::Visual, Modality::Acoustic),
            (Modality::Acoustic, Modality::Radar),
        ];
        for (pair, (expected_first, expected_second)) in report.pairs().iter().zip(expected_pairs) {
            assert_eq!(pair.first(), expected_first);
            assert_eq!(pair.second(), expected_second);
            let PairMiOutcome::Estimated(evidence) = pair.outcome() else {
                panic!("clean fixed Gaussian control must retain every pair report");
            };
            assert_eq!(evidence.config_identity(), config.identity());
            assert_eq!(evidence.graph_row_values_sha256(), expected_graph_hash);
            assert_eq!(evidence.pid_rs_version(), PID_RS_VERSION);
            assert_eq!(evidence.pid_rs_revision(), PID_RS_REVISION);
            assert_eq!(evidence.pid_rs_git_repository(), PID_RS_GIT_REPOSITORY);
            assert_eq!(evidence.functional_id(), MI_FUNCTIONAL_ID);
            assert_eq!(evidence.estimator_id(), MI_ESTIMATOR_ID);
            assert_eq!(evidence.units(), "nats");
            let upstream = evidence.upstream_report();
            let expected_budget = ksg_resource_budget().expect("fixed resource budget");
            let first_values = analyzed_channels
                .iter()
                .find(|(modality, _)| *modality == expected_first)
                .map(|(_, values)| values.as_slice())
                .expect("first pair column");
            let second_values = analyzed_channels
                .iter()
                .find(|(modality, _)| *modality == expected_second)
                .map(|(_, values)| values.as_slice())
                .expect("second pair column");
            let first_matrix = column_matrix(first_values).expect("first pair matrix");
            let second_matrix = column_matrix(second_values).expect("second pair matrix");
            let expected_estimate = ksg_report_resource_estimate(
                first_matrix.as_ref(),
                second_matrix.as_ref(),
                &upstream.provenance,
                expected_budget.max_threads,
            )
            .expect("independent report preflight");
            let checks = UpstreamKsgContractChecks::from_report(
                upstream,
                &ksg_config(),
                config.window(),
                expected_budget,
                expected_estimate,
            );
            assert!(checks.all_satisfied());
            if expected_first == Modality::Visual && expected_second == Modality::Radar {
                macro_rules! reject_missing_coordinate {
                    ($field:ident) => {{
                        let mut changed = checks;
                        changed.$field = false;
                        assert!(!changed.all_satisfied(), stringify!($field));
                    }};
                }
                reject_missing_coordinate!(method_status);
                reject_missing_coordinate!(scientific_status);
                reject_missing_coordinate!(signed_estimate_finite);
                reject_missing_coordinate!(sample_count);
                reject_missing_coordinate!(neighbors);
                reject_missing_coordinate!(metric);
                reject_missing_coordinate!(negative_handling);
                reject_missing_coordinate!(support_contract);
                reject_missing_coordinate!(geometry_model);
                reject_missing_coordinate!(exact_neighbor_backend);
                reject_missing_coordinate!(definition_revision);
                reject_missing_coordinate!(estimator_revision);
                reject_missing_coordinate!(estimand_family);
                reject_missing_coordinate!(information_units);
                reject_missing_coordinate!(estimand_metric);
                reject_missing_coordinate!(no_source_gauge);
                reject_missing_coordinate!(resource_budget);
                reject_missing_coordinate!(resource_estimate);
            }
            assert_eq!(
                evidence.signed_estimate_nats().to_bits(),
                upstream.signed_estimate_nats.to_bits()
            );
            assert_eq!(evidence.n_samples(), upstream.n_samples);
            assert_eq!(evidence.k(), upstream.k);
            assert_eq!(evidence.support_contract(), upstream.support_contract);
            assert_eq!(evidence.method_status(), upstream.method_status);
            assert_eq!(evidence.scientific_status(), upstream.scientific_status);
            assert_eq!(evidence.estimand(), &upstream.estimand);
            assert_eq!(evidence.resource_estimate(), upstream.resource_estimate);
            assert_eq!(
                evidence.assumption_ledger(),
                upstream.assumption_ledger.as_slice()
            );
            assert_eq!(evidence.warnings(), upstream.warnings.as_slice());
            assert_eq!(
                evidence.report_warnings(),
                upstream.report_warnings.as_slice()
            );
            assert_eq!(
                evidence.preprocessing_description(),
                upstream.provenance.preprocessing_description()
            );
            assert_eq!(
                evidence.observation_model_description(),
                upstream.provenance.observation_model_description()
            );
            assert_eq!(
                evidence.sampling_model_description(),
                upstream.provenance.sampling_model_description()
            );

            let geometry = evidence.geometry();
            let intrinsic = geometry.intrinsic_dimension_report();
            assert_eq!(
                geometry.intrinsic_dimension().to_bits(),
                intrinsic.mean.to_bits()
            );
            assert_eq!(geometry.intrinsic_dimension_k(), intrinsic.k);
            assert_eq!(
                geometry.intrinsic_dimension_minimum().to_bits(),
                config.id_min().to_bits()
            );
            assert_eq!(
                geometry.intrinsic_dimension_maximum().to_bits(),
                config.id_max().to_bits()
            );
            assert_eq!(
                geometry
                    .intrinsic_dimension_local_median_minimum()
                    .to_bits(),
                ID_LOCAL_MEDIAN_MINIMUM.to_bits()
            );
            assert_eq!(
                geometry.distance_pairwise_cv_minimum().to_bits(),
                config.cv_min().to_bits()
            );
            assert_eq!(
                geometry.nearest_neighbor_ratio_maximum().to_bits(),
                config.nn_ratio_max().to_bits()
            );
            let geometry_json = serde_json::to_value(geometry).unwrap();
            assert_eq!(
                geometry.distance_pairwise_cv().to_bits(),
                geometry_json["distance_pairwise_cv"]
                    .as_f64()
                    .unwrap()
                    .to_bits()
            );
            assert_eq!(
                geometry.nearest_neighbor_over_pairwise_mean().to_bits(),
                geometry_json["nearest_neighbor_over_pairwise_mean"]
                    .as_f64()
                    .unwrap()
                    .to_bits()
            );
        }
    }

    #[test]
    fn exhaustive_stability_replays_no_separation_instead_of_skipping_it() {
        let stream = generate(&scenario(7)).unwrap();
        let report = analyze(&input_for(&stream), &stable_config()).unwrap();
        assert_eq!(
            report.disposition(),
            &MiGraphDisposition::NoSeparationAtConfiguredThreshold
        );
        let envelope = report
            .stability()
            .expect("retained no-separation disposition must replay every deletion");
        assert_eq!(envelope.deletions_evaluated(), stable_config().window());
        assert!(envelope.candidate_margins().is_empty());
        assert!(envelope.consensus_margin_minimum_nats() >= 0.0);
        assert!(report.note().contains("every circular block deletion"));
    }

    #[test]
    fn deletion_resource_rejection_is_not_relabelled_as_graph_instability() {
        let replay = PointAnalysis {
            pairs: vec![PairMiReport {
                first: Modality::Visual,
                second: Modality::Radar,
                outcome: PairMiOutcome::Unavailable {
                    category: PairUnavailableCategory::ResourceRejected,
                    note: "allocation rejected by hostile control".into(),
                },
            }],
            channels: Vec::new(),
            disposition: MiGraphDisposition::Unavailable(
                MiGraphUnavailableReason::PairResourceRejected,
            ),
            threshold: None,
            mi: Vec::new(),
            consensus: Vec::new(),
        };

        assert!(matches!(
            replay_disposition_failure(&replay, 17, &replay.disposition),
            StabilityFailure::ResourceRejected(note)
                if note.contains("deletion start 17")
                    && note.contains("allocation rejected by hostile control")
        ));
    }

    #[test]
    fn exhaustive_stability_enumerates_every_circular_start_when_separation_survives() {
        let config = stable_config();
        let scenario = scenario(1);
        let stream = generate_spoofed(
            &scenario,
            StealthySpoof {
                target: Modality::Acoustic,
                // The declared input is one fixed-law episode, not a change-point
                // mixture. Starting at zero makes that constraint structural.
                start_frame: 0,
            },
        )
        .unwrap();
        let report = analyze(&input_for(&stream), &config).unwrap();
        assert_eq!(
            report.disposition(),
            &MiGraphDisposition::SeparatedFromMajorityGraph(vec![Modality::Acoustic])
        );
        assert!(report
            .channels()
            .iter()
            .find(|channel| channel.modality() == Modality::Acoustic)
            .expect("separated modality has a channel summary")
            .is_separated_from_majority_graph());
        let envelope = report.stability().expect("stable separation has envelope");
        assert_eq!(envelope.deletions_evaluated(), config.window());
        assert_eq!(envelope.block_size(), 8);
        assert!(envelope.consensus_margin_minimum_nats() > 0.0);
        assert!(
            envelope.consensus_margin_minimum_nats() <= envelope.consensus_margin_maximum_nats()
        );
        let envelope_json = serde_json::to_value(envelope).unwrap();
        assert_eq!(
            envelope.consensus_margin_minimum_nats().to_bits(),
            envelope_json["consensus_margin_minimum_nats"]
                .as_f64()
                .unwrap()
                .to_bits()
        );
        assert_eq!(
            envelope.consensus_margin_maximum_nats().to_bits(),
            envelope_json["consensus_margin_maximum_nats"]
                .as_f64()
                .unwrap()
                .to_bits()
        );
        assert_eq!(envelope.candidate_margins().len(), 1);
        for (index, margin) in envelope.candidate_margins().iter().enumerate() {
            assert_eq!(margin.modality(), Modality::Acoustic);
            assert!(margin.minimum_nats() <= margin.maximum_nats());
            assert!(margin.maximum_nats() < 0.0);
            assert_eq!(
                margin.minimum_nats().to_bits(),
                envelope_json["candidate_margins"][index]["minimum_nats"]
                    .as_f64()
                    .unwrap()
                    .to_bits()
            );
            assert_eq!(
                margin.maximum_nats().to_bits(),
                envelope_json["candidate_margins"][index]["maximum_nats"]
                    .as_f64()
                    .unwrap()
                    .to_bits()
            );
        }
        assert!(envelope
            .candidate_margins()
            .iter()
            .all(|margin| margin.maximum_nats() < 0.0));
    }

    #[test]
    fn materially_subambient_curve_is_rejected_by_the_bivariate_id_screen() {
        let mut parameters = ScenarioResearchProfile::SyntheticV0_9.params();
        parameters.frames = 128;
        parameters.rho = 0.0;
        parameters.seed = 927;
        let stream = generate(&ScenarioConfig::try_new(parameters).unwrap()).unwrap();
        let x = galadriel_core::scalar_channels(&stream, &[Modality::Visual], 0)
            .unwrap()
            .remove(0)
            .1;
        let y = x
            .iter()
            .enumerate()
            .map(|(index, value)| value * value + 1e-3 * ((index * 17 % 31) as f64 - 15.0))
            .collect::<Vec<_>>();
        let z = x
            .iter()
            .enumerate()
            .map(|(index, value)| value.sin() + (index as f64 + 1.0).ln())
            .collect::<Vec<_>>();
        let input = DeclaredMiInput::try_new(
            vec![
                (Modality::Visual, x),
                (Modality::Radar, y),
                (Modality::Acoustic, z),
            ],
            "hostile-near-manifold-control",
        )
        .unwrap();
        let report = analyze(&input, &point_config()).unwrap();
        assert_eq!(
            report.disposition(),
            &MiGraphDisposition::Unavailable(MiGraphUnavailableReason::PairEvidenceUnavailable)
        );
        assert!(report
            .pairs()
            .iter()
            .any(|pair| matches!(pair.outcome(), PairMiOutcome::Estimated(_))));
        assert!(report.pairs().iter().any(|pair| matches!(
            pair.outcome(),
            PairMiOutcome::Unavailable {
                category: PairUnavailableCategory::GeometryRejected,
                note,
            } if note.contains("intrinsic-dimension")
        )));
        assert!(report
            .channels()
            .iter()
            .all(|channel| channel.strongest_pair_mi_nats().is_none()));
    }

    #[test]
    fn fixed_gaussian_controls_retain_full_id_reports_across_correlation_strengths() {
        for rho in [0.0, 0.7, 0.99] {
            for seed in 0..10 {
                let mut parameters = ScenarioResearchProfile::SyntheticV0_9.params();
                parameters.frames = 128;
                parameters.rho = rho;
                parameters.seed = seed;
                let stream = generate(&ScenarioConfig::try_new(parameters).unwrap()).unwrap();
                let report = analyze(&input_for(&stream), &point_config()).unwrap();
                assert!(report.pairs().iter().all(|pair| match pair.outcome() {
                    PairMiOutcome::Estimated(evidence) => {
                        let id = evidence.geometry().intrinsic_dimension_report();
                        id.mean.is_finite()
                            && id.local_estimate_quantiles.median.is_finite()
                            && id.n_samples == 128
                            && id.ambient_dimension == 2
                    }
                    PairMiOutcome::Unavailable { category, .. } => {
                        !matches!(category, PairUnavailableCategory::GeometryRejected)
                    }
                }));
            }
        }
    }

    #[test]
    fn heterogeneous_near_manifold_is_rejected_by_the_local_id_distribution() {
        let mut parameters = ScenarioResearchProfile::SyntheticV0_9.params();
        parameters.frames = 128;
        parameters.rho = 0.0;
        parameters.seed = 927;
        let stream = generate(&ScenarioConfig::try_new(parameters).unwrap()).unwrap();
        let channels =
            galadriel_core::scalar_channels(&stream, &[Modality::Visual, Modality::Radar], 0)
                .unwrap();
        let x = &channels[0].1;
        let y = x
            .iter()
            .enumerate()
            .map(|(index, value)| {
                if index < 64 {
                    value * value + 1e-3 * ((index * 17 % 31) as f64 - 15.0)
                } else {
                    channels[1].1[index]
                }
            })
            .collect::<Vec<_>>();
        let input = DeclaredMiInput::try_new(
            vec![
                (Modality::Visual, x.clone()),
                (Modality::Radar, y),
                (Modality::Acoustic, channels[1].1.clone()),
            ],
            "hostile-heterogeneous-manifold-control",
        )
        .unwrap();
        let report = analyze(&input, &point_config()).unwrap();
        assert_eq!(
            report.disposition(),
            &MiGraphDisposition::Unavailable(MiGraphUnavailableReason::PairEvidenceUnavailable)
        );
        assert!(report.pairs().iter().any(|pair| matches!(
            pair.outcome(),
            PairMiOutcome::Unavailable {
                category: PairUnavailableCategory::GeometryRejected,
                note,
            } if note.contains("local median")
        )));
    }

    #[test]
    fn degenerate_input_abstains_before_support_assumption_can_create_an_estimate() {
        let input = DeclaredMiInput::try_new(
            vec![
                (Modality::Visual, vec![1.0; 128]),
                (
                    Modality::Radar,
                    (0..128).map(|value| value as f64).collect(),
                ),
                (
                    Modality::Acoustic,
                    (0..128).map(|value| value as f64 * 2.0).collect(),
                ),
            ],
            "degenerate-episode",
        )
        .unwrap();
        let report = analyze(&input, &point_config()).unwrap();
        assert_eq!(
            report.disposition(),
            &MiGraphDisposition::Unavailable(MiGraphUnavailableReason::DegenerateColumn)
        );
        assert!(report.pairs().is_empty());
    }

    #[test]
    fn modality_order_does_not_change_graph_disposition_or_canonical_pair_values() {
        let stream = generate(&scenario(11)).unwrap();
        let input = input_for(&stream);
        let original = analyze(&input, &point_config()).unwrap();
        let mut reordered = input.channels.clone();
        reordered.rotate_left(1);
        reordered.reverse();
        let reordered = analyze(
            &DeclaredMiInput::try_new(reordered, "one-synthetic-episode").unwrap(),
            &point_config(),
        )
        .unwrap();
        assert_eq!(original.disposition(), reordered.disposition());
        let mut left: Vec<_> = original
            .pairs()
            .iter()
            .map(|pair| {
                (
                    modality_key(pair.first()),
                    modality_key(pair.second()),
                    pair.estimate_nats().map(f64::to_bits),
                )
            })
            .collect();
        let mut right: Vec<_> = reordered
            .pairs()
            .iter()
            .map(|pair| {
                (
                    modality_key(pair.first()),
                    modality_key(pair.second()),
                    pair.estimate_nats().map(f64::to_bits),
                )
            })
            .collect();
        left.sort_unstable();
        right.sort_unstable();
        assert_eq!(left, right);
    }
}
