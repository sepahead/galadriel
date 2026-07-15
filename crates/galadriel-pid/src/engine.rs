//! Geometry-gated mutual-information consistency analysis.
//!
//! Pairwise MI is sign-invariant, so this engine is an additive escalation over
//! the signed-correlation default rather than a replacement for it. Attribution
//! requires a unique strict-majority clique. PID atoms remain advisory diagnostics
//! and never drive the verdict.

use std::{cmp::Ordering, collections::HashSet, error::Error, fmt, sync::Arc};

use galadriel_core::{GaladrielError, Modality};
use pid_core::experimental::continuous::raw_scalars::ksg_mi;
use pid_core::{
    diagnostics::{
        distance_concentration_stats, intrinsic_dimension_levina_bickel,
        DistanceConcentrationConfig, IntrinsicDimConfig,
    },
    experimental::{
        continuous::{pid2_isx_estimate, IsxMethod, Pid2Config},
        pipelines::Jitter,
    },
    stable::continuous::{
        ksg_mi_report, AssumptionLedgerEntry, EstimandIdentity, KsgConfig, KsgMethodStatus,
        KsgProvenance, KsgReportWarning, NegativeHandling, ProvenanceHashes, ScientificStatus,
        SupportContract, WarningCode,
    },
    MatOwned, Metric, ResourceEstimate,
};

use crate::identity::{IdentityBuilder, PidConfigDigest, PidResearchClassification};

const MIN_BOOTSTRAP_RESAMPLES: usize = 20;
const MAX_BOOTSTRAP_RESAMPLES: usize = MAX_PID_WINDOW;
const MAX_QUADRATIC_FIT_WORK: usize = 200_000_000;
const MAX_MODALITIES: usize = Modality::ALL.len();
/// Conservative quadratic fit units for one point-gate pair: intrinsic dimension,
/// distance concentration, and four report-first KSG distance/count scans.
pub const PID_PAIR_POINT_FIT_UNITS: usize = 6;
const MAX_PAIR_ESTIMATOR_FITS: usize = pair_count(MAX_MODALITIES) * PID_PAIR_POINT_FIT_UNITS;
/// Conservative quadratic fit units for one PID2 atom calculation: three mutual
/// information estimates plus one shared-exclusions estimate.
pub const PID_ATOM_POINT_FIT_UNITS: usize = 4;
const MAX_ATOM_ESTIMATOR_FITS: usize = MAX_MODALITIES * PID_ATOM_POINT_FIT_UNITS;
/// Conservative quadratic scan units for one raw-scalar KSG confirmation edge:
/// one joint-neighbor-radius scan, two marginal-count scans, plus one overhead unit.
pub const PID_CONFIRMATION_EDGE_FIT_UNITS: usize = 4;
const MAX_EXCLUDED_CANDIDATES: usize = (MAX_MODALITIES - 1) / 2;
const MAX_CONFIRMATION_EDGE_FITS: usize = max_confirmation_edge_fits(MAX_MODALITIES);
const CONFIRMATION_BOUND_GROUPS: usize = 2;
const PID_KSG_NEIGHBORS: usize = 3;
const PID_ISX_NEIGHBORS: usize = 3;

/// Exact upstream dependency identity used for every report from this crate.
pub const PID_RS_VERSION: &str = "1.0.0";
/// Immutable pid-rs revision selected by the workspace manifest.
pub const PID_RS_REVISION: &str = "1cd2424f7967e1752dcc8e53859e8fdad3566f51";

/// Maximum PID analysis window. The mandatory geometry and kNN estimators are
/// quadratic in the number of samples, so the much larger scalar-window bound
/// is not a safe computational bound for this engine.
pub const MAX_PID_WINDOW: usize = 512;

const ROLE_PAIR_POINT: u64 = 0x5041_4952_504f_494e;
const ROLE_PID_ATOMS: u64 = 0x5049_445f_4154_4f4d;
const ROLE_BOOT_PLAN: u64 = 0x424f_4f54_5f50_4c41;
const ROLE_BOOT_JITTER: u64 = 0x424f_4f54_5f4a_4954;

const fn pair_count(channels: usize) -> usize {
    channels.saturating_mul(channels.saturating_sub(1)) / 2
}

const fn max_confirmation_edge_fits(max_channels: usize) -> usize {
    let mut channels = 3;
    let mut maximum = 0;
    while channels <= max_channels {
        let mut consensus = channels / 2 + 1;
        while consensus < channels {
            let excluded = channels - consensus;
            let fits = pair_count(consensus) + excluded * consensus;
            if fits > maximum {
                maximum = fits;
            }
            consensus += 1;
        }
        channels += 1;
    }
    maximum
}

/// Unvalidated confirmation parameters accepted only by [`PidConfig::try_new`].
#[derive(Debug, Clone, PartialEq)]
pub enum PidConfirmationParams {
    /// Run the research point gate without interval confirmation.
    PointEstimateOnly,
    /// Confirm attribution using common circular delete-block resamples.
    CircularDeleteBlock {
        /// Number of distinct deterministic resample plans.
        resamples: usize,
        /// Consecutive circular frames removed from each plan.
        block_size: usize,
        /// One-sided family budget shared by the two joint confirmation bounds.
        family_alpha: f64,
    },
}

/// Unvalidated boundary values for constructing an immutable [`PidConfig`].
#[derive(Debug, Clone, PartialEq)]
pub struct PidParams {
    /// Window length (frames) analysed, taken from each channel's tail.
    pub window: usize,
    /// Minimum aligned samples per channel before a point estimate is trusted.
    pub min_samples: usize,
    /// Seeded additive Gaussian observation-noise standard deviation after
    /// per-column standardisation.
    pub observation_noise_std: f64,
    /// Observation-noise and estimator seed.
    pub seed: u64,
    /// `k` for the Levina-Bickel intrinsic-dimension estimator.
    pub geom_k: usize,
    /// Maximum accepted intrinsic dimension.
    pub id_max: f64,
    /// Minimum accepted pairwise-distance coefficient of variation.
    pub cv_min: f64,
    /// Maximum nearest-neighbour / pairwise-mean distance ratio.
    pub nn_ratio_max: f64,
    /// Edge threshold relative to the strongest pairwise MI.
    pub decouple_ratio: f64,
    /// Absolute minimum MI in nats for a consensus edge.
    pub mi_floor: f64,
    /// Explicit research confirmation choice and its applicable parameters.
    pub confirmation: PidConfirmationParams,
}

/// Closed, versioned PID research profiles shipped by the 0.9 source release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidResearchProfile {
    /// Seeded point gate plus circular delete-block confirmation.
    CircularDeleteBlockV0_9,
    /// Explicitly unconfirmed point-estimate research path.
    PointEstimateOnlyV0_9,
}

impl PidResearchProfile {
    /// Stable machine-readable profile name retained in estimator evidence.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CircularDeleteBlockV0_9 => "circular_delete_block_v0_9",
            Self::PointEstimateOnlyV0_9 => "point_estimate_only_v0_9",
        }
    }

    /// Returns this profile's raw parameter template.
    pub fn params(self) -> PidParams {
        let confirmation = match self {
            Self::CircularDeleteBlockV0_9 => PidConfirmationParams::CircularDeleteBlock {
                resamples: 100,
                block_size: 8,
                family_alpha: 0.10,
            },
            Self::PointEstimateOnlyV0_9 => PidConfirmationParams::PointEstimateOnly,
        };
        PidParams {
            window: 128,
            min_samples: 64,
            observation_noise_std: 1e-4,
            seed: 1,
            geom_k: 5,
            id_max: 10.0,
            cv_min: 0.01,
            nn_ratio_max: 0.999,
            decouple_ratio: 0.4,
            mi_floor: 0.03,
            confirmation,
        }
    }

    /// Resolves this named profile through the same checked boundary as custom input.
    ///
    /// # Errors
    ///
    /// Returns [`PidConfigError`] if a future invariant change makes the frozen
    /// profile invalid instead of silently substituting different semantics.
    pub fn try_config(self) -> Result<PidConfig, PidConfigError> {
        PidConfig::try_new_with_axis_family(
            self.params(),
            Some(self),
            AxisFamilyIdentity::Unadjusted,
        )
    }
}

/// Validated circular delete-block confirmation settings.
#[derive(Debug, Clone, PartialEq)]
pub struct CircularDeleteBlockConfirmation {
    resamples: usize,
    block_size: usize,
    family_alpha: f64,
}

impl CircularDeleteBlockConfirmation {
    /// Number of distinct deterministic resample plans.
    pub const fn resamples(&self) -> usize {
        self.resamples
    }

    /// Consecutive circular frames deleted from each plan.
    pub const fn block_size(&self) -> usize {
        self.block_size
    }

    /// Effective one-sided family budget after any axis split.
    pub const fn family_alpha(&self) -> f64 {
        self.family_alpha
    }
}

/// Validated, closed confirmation semantics retained by [`PidConfig`].
#[derive(Debug, Clone, PartialEq)]
pub enum PidConfirmation {
    /// Research point gate with no interval-confirmed attribution.
    PointEstimateOnly,
    /// Common circular delete-block confirmation with validated settings.
    CircularDeleteBlock(CircularDeleteBlockConfirmation),
}

impl PidConfirmation {
    /// Stable confirmation-mode name retained in estimator evidence.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PointEstimateOnly => "point_estimate_only",
            Self::CircularDeleteBlock(_) => "circular_delete_block",
        }
    }

    /// Returns circular delete-block settings when that mode is selected.
    pub const fn circular_delete_block(&self) -> Option<&CircularDeleteBlockConfirmation> {
        match self {
            Self::PointEstimateOnly => None,
            Self::CircularDeleteBlock(settings) => Some(settings),
        }
    }
}

/// Typed rejection from PID configuration construction or derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PidConfigError {
    /// `window` is outside the quadratic-estimator policy range.
    WindowOutOfRange,
    /// `geom_k` is below the estimator's minimum.
    GeometryKTooSmall,
    /// `min_samples` is incompatible with `geom_k` or `window`.
    MinimumSamplesOutOfRange,
    /// Observation-noise standard deviation is not finite and positive.
    ObservationNoiseInvalid,
    /// Intrinsic-dimension ceiling is not finite and positive.
    IntrinsicDimensionMaximumInvalid,
    /// Distance-CV floor is not finite and positive.
    DistanceCvMinimumInvalid,
    /// Nearest-neighbour ratio is outside `(0, 1]`.
    NearestNeighborRatioInvalid,
    /// Decoupling ratio is outside `(0, 1]`.
    DecoupleRatioInvalid,
    /// MI floor is not finite and positive.
    MiFloorInvalid,
    /// Circular delete-block resample count is outside the fixed range.
    ConfirmationResamplesOutOfRange,
    /// Delete-block size does not leave enough estimator samples.
    ConfirmationBlockSizeInvalid,
    /// Confirmation asks for more distinct plans than the window permits.
    ConfirmationResamplesExceedWindow,
    /// Confirmation family alpha is outside `(0, 1)`.
    ConfirmationFamilyAlphaInvalid,
    /// Dividing the confirmation family budget underflowed to zero.
    ConfirmationFamilyAlphaUnderflow { axis_count: usize },
    /// Confirmation resamples cannot resolve a non-empty tail rank.
    ConfirmationTailRankUnresolvable { resamples: usize, axis_count: usize },
    /// A checked fit-count or work calculation overflowed.
    WorkEstimateOverflow,
    /// The conservative quadratic work ceiling would be exceeded.
    WorkEstimateExceedsLimit { requested: usize, maximum: usize },
    /// Projection-axis family count is zero or above the fixed protocol ceiling.
    AxisCountOutOfRange { requested: usize, maximum: usize },
    /// A family split was requested from an already-derived config.
    AxisFamilyAlreadyDerived { current: usize },
}

impl fmt::Display for PidConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowOutOfRange => write!(
                formatter,
                "PID window must be in 4..={MAX_PID_WINDOW} (estimators are quadratic)"
            ),
            Self::GeometryKTooSmall => formatter.write_str("PID geom_k must be >= 3"),
            Self::MinimumSamplesOutOfRange => formatter.write_str(
                "PID min_samples must be greater than geom_k and <= window",
            ),
            Self::ObservationNoiseInvalid => formatter
                .write_str("PID observation_noise_std must be finite and > 0"),
            Self::IntrinsicDimensionMaximumInvalid => {
                formatter.write_str("PID id_max must be finite and > 0")
            }
            Self::DistanceCvMinimumInvalid => {
                formatter.write_str("PID cv_min must be finite and > 0")
            }
            Self::NearestNeighborRatioInvalid => {
                formatter.write_str("PID nn_ratio_max must be finite and in (0, 1]")
            }
            Self::DecoupleRatioInvalid => {
                formatter.write_str("PID decouple_ratio must be finite and in (0, 1]")
            }
            Self::MiFloorInvalid => formatter.write_str("PID mi_floor must be finite and > 0"),
            Self::ConfirmationResamplesOutOfRange => write!(
                formatter,
                "PID confirmation resamples must be in {MIN_BOOTSTRAP_RESAMPLES}..={MAX_BOOTSTRAP_RESAMPLES}"
            ),
            Self::ConfirmationBlockSizeInvalid => formatter.write_str(
                "PID confirmation block_size must leave more than geom_k samples at min_samples",
            ),
            Self::ConfirmationResamplesExceedWindow => formatter.write_str(
                "PID confirmation resamples cannot exceed window for distinct circular delete-block plans",
            ),
            Self::ConfirmationFamilyAlphaInvalid => formatter
                .write_str("PID confirmation family_alpha must be finite and in (0, 1)"),
            Self::ConfirmationFamilyAlphaUnderflow { axis_count } => write!(
                formatter,
                "PID confirmation family_alpha is too small to divide across {axis_count} projection axes"
            ),
            Self::ConfirmationTailRankUnresolvable {
                resamples,
                axis_count,
            } => write!(
                formatter,
                "PID confirmation resamples={resamples} cannot resolve family_alpha across {axis_count} axis family and the {CONFIRMATION_BOUND_GROUPS} joint bounds"
            ),
            Self::WorkEstimateOverflow => {
                formatter.write_str("PID checked fit-count/work estimate overflowed")
            }
            Self::WorkEstimateExceedsLimit { requested, maximum } => write!(
                formatter,
                "PID requests {requested} quadratic scan-equivalent fit-units (including up to {MAX_PAIR_ESTIMATOR_FITS} mandatory pair-estimator units, {MAX_ATOM_ESTIMATOR_FITS} atom-estimator units, and {MAX_CONFIRMATION_EDGE_FITS} confirmation edges × {PID_CONFIRMATION_EDGE_FIT_UNITS} units per resample across as many as {MAX_EXCLUDED_CANDIDATES} excluded candidates); maximum is {maximum}"
            ),
            Self::AxisCountOutOfRange { requested, maximum } => write!(
                formatter,
                "PID projection-axis family count must be in 1..={maximum}, got {requested}"
            ),
            Self::AxisFamilyAlreadyDerived { current } => write!(
                formatter,
                "PID family budget is already derived across {current} projection axes"
            ),
        }
    }
}

impl Error for PidConfigError {}

impl From<PidConfigError> for GaladrielError {
    fn from(error: PidConfigError) -> Self {
        Self::InvalidConfig(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AxisFamilyIdentity {
    Unadjusted,
    Derived { axis_count: usize },
}

impl AxisFamilyIdentity {
    const fn axis_count(self) -> usize {
        match self {
            Self::Unadjusted => 1,
            Self::Derived { axis_count } => axis_count,
        }
    }

    const fn was_derived(self) -> bool {
        matches!(self, Self::Derived { .. })
    }
}

/// Immutable, fully validated PID research configuration.
///
/// Construction is `O(1)` time and retains `O(1)` memory. The checked work
/// estimate conservatively bounds all pair, atom, and confirmation scans for the
/// complete modality domain before any estimator is invoked.
///
/// Accepted configs cannot be fabricated or modified by callers:
///
/// ```compile_fail
/// use galadriel_pid::PidConfig;
/// let _ = PidConfig { window: 128 };
/// ```
///
/// ```compile_fail
/// use galadriel_pid::PidResearchProfile;
/// let mut config = PidResearchProfile::CircularDeleteBlockV0_9.try_config().unwrap();
/// config.window = 64;
/// ```
///
/// ```compile_fail
/// use galadriel_pid::PidConfig;
/// let _: PidConfig = Default::default();
/// ```
///
/// Raw parameters cannot cross the estimator boundary:
///
/// ```compile_fail
/// use galadriel_pid::{analyze, PidResearchProfile};
/// let raw = PidResearchProfile::PointEstimateOnlyV0_9.params();
/// let _ = analyze(&[], &raw);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PidConfig {
    window: usize,
    min_samples: usize,
    observation_noise_std: f64,
    seed: u64,
    geom_k: usize,
    id_max: f64,
    cv_min: f64,
    nn_ratio_max: f64,
    decouple_ratio: f64,
    mi_floor: f64,
    confirmation: PidConfirmation,
    source_profile: Option<PidResearchProfile>,
    axis_family: AxisFamilyIdentity,
    quadratic_fit_work: usize,
}

impl PidConfig {
    /// Validates raw parameters and constructs an immutable accepted config.
    ///
    /// # Errors
    ///
    /// Returns [`PidConfigError`] for an invalid scalar, cross-field relation,
    /// confirmation plan, tail rank, checked product, or work ceiling.
    pub fn try_new(params: PidParams) -> Result<Self, PidConfigError> {
        Self::try_new_with_axis_family(params, None, AxisFamilyIdentity::Unadjusted)
    }

    fn try_new_with_axis_family(
        params: PidParams,
        source_profile: Option<PidResearchProfile>,
        axis_family: AxisFamilyIdentity,
    ) -> Result<Self, PidConfigError> {
        let axis_family_count = axis_family.axis_count();
        let maximum_axes = galadriel_core::MAX_CONSISTENCY_PROJECTION_AXES;
        if !(1..=maximum_axes).contains(&axis_family_count) {
            return Err(PidConfigError::AxisCountOutOfRange {
                requested: axis_family_count,
                maximum: maximum_axes,
            });
        }
        if !(4..=MAX_PID_WINDOW).contains(&params.window) {
            return Err(PidConfigError::WindowOutOfRange);
        }
        if params.geom_k < 3 {
            return Err(PidConfigError::GeometryKTooSmall);
        }
        if params.min_samples <= params.geom_k || params.min_samples > params.window {
            return Err(PidConfigError::MinimumSamplesOutOfRange);
        }
        if !params.observation_noise_std.is_finite() || params.observation_noise_std <= 0.0 {
            return Err(PidConfigError::ObservationNoiseInvalid);
        }
        if !params.id_max.is_finite() || params.id_max <= 0.0 {
            return Err(PidConfigError::IntrinsicDimensionMaximumInvalid);
        }
        if !params.cv_min.is_finite() || params.cv_min <= 0.0 {
            return Err(PidConfigError::DistanceCvMinimumInvalid);
        }
        if !params.nn_ratio_max.is_finite()
            || params.nn_ratio_max <= 0.0
            || params.nn_ratio_max > 1.0
        {
            return Err(PidConfigError::NearestNeighborRatioInvalid);
        }
        if !params.decouple_ratio.is_finite()
            || params.decouple_ratio <= 0.0
            || params.decouple_ratio > 1.0
        {
            return Err(PidConfigError::DecoupleRatioInvalid);
        }
        if !params.mi_floor.is_finite() || params.mi_floor <= 0.0 {
            return Err(PidConfigError::MiFloorInvalid);
        }

        let confirmation = match params.confirmation {
            PidConfirmationParams::PointEstimateOnly => PidConfirmation::PointEstimateOnly,
            PidConfirmationParams::CircularDeleteBlock {
                resamples,
                block_size,
                family_alpha,
            } => {
                if !(MIN_BOOTSTRAP_RESAMPLES..=MAX_BOOTSTRAP_RESAMPLES).contains(&resamples) {
                    return Err(PidConfigError::ConfirmationResamplesOutOfRange);
                }
                if block_size == 0
                    || block_size >= params.min_samples
                    || params.min_samples - block_size <= params.geom_k
                {
                    return Err(PidConfigError::ConfirmationBlockSizeInvalid);
                }
                if resamples > params.window {
                    return Err(PidConfigError::ConfirmationResamplesExceedWindow);
                }
                if !family_alpha.is_finite() || family_alpha <= 0.0 || family_alpha >= 1.0 {
                    return Err(PidConfigError::ConfirmationFamilyAlphaInvalid);
                }
                if axis_family_count == 1 && family_alpha / maximum_axes as f64 == 0.0 {
                    return Err(PidConfigError::ConfirmationFamilyAlphaUnderflow {
                        axis_count: maximum_axes,
                    });
                }
                let tail_rank = confirmation_tail_rank(resamples, family_alpha);
                if tail_rank == 0 || tail_rank >= resamples {
                    return Err(PidConfigError::ConfirmationTailRankUnresolvable {
                        resamples,
                        axis_count: axis_family_count,
                    });
                }
                PidConfirmation::CircularDeleteBlock(CircularDeleteBlockConfirmation {
                    resamples,
                    block_size,
                    family_alpha,
                })
            }
        };
        let quadratic_fit_work = quadratic_fit_work(params.window, &confirmation)?;
        Ok(Self {
            window: params.window,
            min_samples: params.min_samples,
            observation_noise_std: params.observation_noise_std,
            seed: params.seed,
            geom_k: params.geom_k,
            id_max: params.id_max,
            cv_min: params.cv_min,
            nn_ratio_max: params.nn_ratio_max,
            decouple_ratio: params.decouple_ratio,
            mi_floor: params.mi_floor,
            confirmation,
            source_profile,
            axis_family,
            quadratic_fit_work,
        })
    }

    /// Returns a new accepted config with its family budget split across axes.
    ///
    /// The source is never mutated. A derived config cannot be divided again,
    /// which prevents accidental double correction.
    ///
    /// # Errors
    ///
    /// Returns [`PidConfigError`] for an invalid axis count, floating-point
    /// underflow, unresolvable confirmation tail rank, or repeated derivation.
    pub fn try_for_axis_family(&self, axis_count: usize) -> Result<Self, PidConfigError> {
        if let AxisFamilyIdentity::Derived { axis_count } = self.axis_family {
            return Err(PidConfigError::AxisFamilyAlreadyDerived {
                current: axis_count,
            });
        }
        let maximum_axes = galadriel_core::MAX_CONSISTENCY_PROJECTION_AXES;
        if !(1..=maximum_axes).contains(&axis_count) {
            return Err(PidConfigError::AxisCountOutOfRange {
                requested: axis_count,
                maximum: maximum_axes,
            });
        }
        let confirmation = match &self.confirmation {
            PidConfirmation::PointEstimateOnly => PidConfirmationParams::PointEstimateOnly,
            PidConfirmation::CircularDeleteBlock(settings) => {
                let family_alpha = settings.family_alpha / axis_count as f64;
                if family_alpha == 0.0 {
                    return Err(PidConfigError::ConfirmationFamilyAlphaUnderflow { axis_count });
                }
                PidConfirmationParams::CircularDeleteBlock {
                    resamples: settings.resamples,
                    block_size: settings.block_size,
                    family_alpha,
                }
            }
        };
        Self::try_new_with_axis_family(
            PidParams {
                window: self.window,
                min_samples: self.min_samples,
                observation_noise_std: self.observation_noise_std,
                seed: self.seed,
                geom_k: self.geom_k,
                id_max: self.id_max,
                cv_min: self.cv_min,
                nn_ratio_max: self.nn_ratio_max,
                decouple_ratio: self.decouple_ratio,
                mi_floor: self.mi_floor,
                confirmation,
            },
            self.source_profile,
            AxisFamilyIdentity::Derived { axis_count },
        )
    }

    /// Analysis window length.
    pub const fn window(&self) -> usize {
        self.window
    }

    /// Minimum aligned samples required by the point gate.
    pub const fn min_samples(&self) -> usize {
        self.min_samples
    }

    /// Effective aligned-sample requirement including confirmation diversity.
    pub fn required_samples(&self) -> usize {
        match &self.confirmation {
            PidConfirmation::PointEstimateOnly => self.min_samples,
            PidConfirmation::CircularDeleteBlock(settings) => {
                self.min_samples.max(settings.resamples)
            }
        }
    }

    /// Seeded observation-noise standard deviation.
    pub const fn observation_noise_std(&self) -> f64 {
        self.observation_noise_std
    }

    /// Observation-noise and estimator seed.
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Intrinsic-dimension neighbour count.
    pub const fn geom_k(&self) -> usize {
        self.geom_k
    }

    /// Intrinsic-dimension ceiling.
    pub const fn id_max(&self) -> f64 {
        self.id_max
    }

    /// Pairwise-distance CV floor.
    pub const fn cv_min(&self) -> f64 {
        self.cv_min
    }

    /// Nearest-neighbour / pairwise-mean distance ceiling.
    pub const fn nn_ratio_max(&self) -> f64 {
        self.nn_ratio_max
    }

    /// Relative MI decoupling threshold.
    pub const fn decouple_ratio(&self) -> f64 {
        self.decouple_ratio
    }

    /// Absolute MI consensus floor in nats.
    pub const fn mi_floor(&self) -> f64 {
        self.mi_floor
    }

    /// Validated confirmation semantics.
    pub const fn confirmation(&self) -> &PidConfirmation {
        &self.confirmation
    }

    /// Named source profile when the accepted values exactly originate from one.
    pub const fn source_profile(&self) -> Option<PidResearchProfile> {
        self.source_profile
    }

    /// Number of projection axes sharing the confirmation family budget.
    pub const fn axis_family_count(&self) -> usize {
        self.axis_family.axis_count()
    }

    /// Whether [`Self::try_for_axis_family`] produced this accepted config.
    pub const fn axis_family_was_derived(&self) -> bool {
        self.axis_family.was_derived()
    }

    /// Named-profile or custom-research classification.
    pub const fn classification(&self) -> PidResearchClassification {
        if self.source_profile.is_some() {
            PidResearchClassification::NamedResearchProfile
        } else {
            PidResearchClassification::CustomAcceptedResearch
        }
    }

    /// Canonical identity of the complete accepted configuration.
    ///
    /// The preimage includes every accepted field, profile/custom
    /// classification, confirmation variant and applicable payload, axis-family
    /// derivation, resource ceilings, and the fixed upstream estimator revision
    /// and semantics selected by this adapter.
    pub fn identity(&self) -> PidConfigDigest {
        let mut identity = IdentityBuilder::new(b"galadriel-pid-config-v1");
        identity.u8(
            b"classification",
            match self.classification() {
                PidResearchClassification::NamedResearchProfile => 1,
                PidResearchClassification::CustomAcceptedResearch => 2,
            },
        );
        identity.u8(
            b"source_profile",
            match self.source_profile {
                Some(PidResearchProfile::CircularDeleteBlockV0_9) => 1,
                Some(PidResearchProfile::PointEstimateOnlyV0_9) => 2,
                None => 0,
            },
        );
        identity.usize(b"window", self.window);
        identity.usize(b"min_samples", self.min_samples);
        identity.f64(b"observation_noise_std", self.observation_noise_std);
        identity.u64(b"seed", self.seed);
        identity.usize(b"geom_k", self.geom_k);
        identity.f64(b"id_max", self.id_max);
        identity.f64(b"cv_min", self.cv_min);
        identity.f64(b"nn_ratio_max", self.nn_ratio_max);
        identity.f64(b"decouple_ratio", self.decouple_ratio);
        identity.f64(b"mi_floor", self.mi_floor);
        match &self.confirmation {
            PidConfirmation::PointEstimateOnly => {
                identity.u8(b"confirmation", 1);
            }
            PidConfirmation::CircularDeleteBlock(settings) => {
                identity.u8(b"confirmation", 2);
                identity.usize(b"confirmation_resamples", settings.resamples);
                identity.usize(b"confirmation_block_size", settings.block_size);
                identity.f64(b"confirmation_family_alpha", settings.family_alpha);
            }
        }
        identity.u8(
            b"axis_family_derived",
            if self.axis_family.was_derived() { 1 } else { 0 },
        );
        identity.usize(b"axis_family_count", self.axis_family.axis_count());
        identity.usize(b"quadratic_fit_work", self.quadratic_fit_work);

        identity.bytes(b"pid_rs_version", PID_RS_VERSION.as_bytes());
        identity.bytes(b"pid_rs_revision", PID_RS_REVISION.as_bytes());
        identity.usize(b"pairwise_ksg_k", PID_KSG_NEIGHBORS);
        identity.usize(b"atom_ksg_k", PID_KSG_NEIGHBORS);
        identity.usize(b"atom_isx_k", PID_ISX_NEIGHBORS);
        identity.bytes(b"metric", b"chebyshev");
        identity.f64(b"tie_epsilon", 0.0);
        identity.bytes(b"negative_handling", b"allow");
        identity.bytes(b"atom_method", b"ehrlich_ksg");
        identity.usize(b"max_pid_window", MAX_PID_WINDOW);
        identity.usize(b"max_quadratic_fit_work", MAX_QUADRATIC_FIT_WORK);
        identity.usize(b"max_modalities", MAX_MODALITIES);
        identity.usize(
            b"max_projection_axes",
            galadriel_core::MAX_CONSISTENCY_PROJECTION_AXES,
        );
        identity.usize(b"min_confirmation_resamples", MIN_BOOTSTRAP_RESAMPLES);
        identity.usize(b"max_confirmation_resamples", MAX_BOOTSTRAP_RESAMPLES);
        identity.usize(b"pair_point_fit_units", PID_PAIR_POINT_FIT_UNITS);
        identity.usize(b"atom_point_fit_units", PID_ATOM_POINT_FIT_UNITS);
        identity.usize(
            b"confirmation_edge_fit_units",
            PID_CONFIRMATION_EDGE_FIT_UNITS,
        );
        identity.usize(b"confirmation_bound_groups", CONFIRMATION_BOUND_GROUPS);
        PidConfigDigest::from_bytes(identity.finish())
    }

    /// Conservative quadratic scan-equivalent work admitted by this config.
    pub const fn quadratic_fit_work(&self) -> usize {
        self.quadratic_fit_work
    }

    /// Resolved confirmation tail rank, or `None` for point-estimate-only mode.
    pub fn confirmation_tail_rank(&self) -> Option<usize> {
        self.confirmation
            .circular_delete_block()
            .map(|settings| confirmation_tail_rank(settings.resamples, settings.family_alpha))
    }
}

fn confirmation_tail_rank(resamples: usize, family_alpha: f64) -> usize {
    let tail_probability = family_alpha / CONFIRMATION_BOUND_GROUPS as f64;
    (tail_probability * resamples as f64).floor() as usize
}

fn quadratic_fit_work(
    window: usize,
    confirmation: &PidConfirmation,
) -> Result<usize, PidConfigError> {
    let mandatory_fits = MAX_PAIR_ESTIMATOR_FITS
        .checked_add(MAX_ATOM_ESTIMATOR_FITS)
        .ok_or(PidConfigError::WorkEstimateOverflow)?;
    let confirmation_fits = match confirmation {
        PidConfirmation::PointEstimateOnly => 0,
        PidConfirmation::CircularDeleteBlock(settings) => MAX_CONFIRMATION_EDGE_FITS
            .checked_mul(PID_CONFIRMATION_EDGE_FIT_UNITS)
            .and_then(|fits| fits.checked_mul(settings.resamples))
            .ok_or(PidConfigError::WorkEstimateOverflow)?,
    };
    let fit_count = mandatory_fits
        .checked_add(confirmation_fits)
        .ok_or(PidConfigError::WorkEstimateOverflow)?;
    let work = window
        .checked_mul(window)
        .and_then(|distance_pairs| distance_pairs.checked_mul(fit_count))
        .ok_or(PidConfigError::WorkEstimateOverflow)?;
    if matches!(work.cmp(&MAX_QUADRATIC_FIT_WORK), Ordering::Greater) {
        return Err(PidConfigError::WorkEstimateExceedsLimit {
            requested: work,
            maximum: MAX_QUADRATIC_FIT_WORK,
        });
    }
    Ok(work)
}

/// Machine-readable estimator/dependency evidence attached to every PID result.
///
/// Evidence is created only by the analyser from an accepted [`PidConfig`].
/// Callers can inspect it but cannot fabricate or modify its provenance:
///
/// ```compile_fail
/// use galadriel_pid::PidEstimatorEvidence;
/// let _ = PidEstimatorEvidence { pid_rs_version: "forged" };
/// ```
///
/// ```compile_fail
/// use galadriel_pid::{analyze, PidResearchProfile};
/// let config = PidResearchProfile::PointEstimateOnlyV0_9.try_config().unwrap();
/// let report = analyze(&[], &config).unwrap();
/// let mut evidence = report.estimator().clone();
/// evidence.seed = 7;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PidEstimatorEvidence {
    /// Complete canonical identity of the accepted PID configuration.
    config_identity: PidConfigDigest,
    /// Named-profile or custom-research classification.
    classification: PidResearchClassification,
    pid_rs_version: &'static str,
    pid_rs_revision: &'static str,
    pairwise_estimator: &'static str,
    pairwise_scientific_status: &'static str,
    atom_estimator: &'static str,
    atom_scientific_status: &'static str,
    support_contract: &'static str,
    /// Fixed KSG neighbour count selected for pairwise MI.
    pairwise_ksg_k: usize,
    /// Fixed KSG neighbour count selected inside PID2.
    atom_ksg_k: usize,
    /// Fixed shared-exclusions neighbour count selected inside PID2.
    atom_isx_k: usize,
    /// Fixed upstream metric selected for all kNN estimators.
    estimator_metric: &'static str,
    /// Fixed upstream finite-sample negative-MI policy.
    negative_handling: &'static str,
    /// Fixed upstream shared-exclusions method.
    atom_method: &'static str,
    observation_noise_model: &'static str,
    observation_noise_std: f64,
    seed: u64,
    geom_k: usize,
    /// Stable named profile identity, or `"custom"` for caller-supplied values.
    research_profile: &'static str,
    /// Stable confirmation-mode identity.
    confirmation: &'static str,
    /// Projection axes sharing the effective confirmation family budget.
    axis_family_count: usize,
    /// Whether this config was explicitly derived for an attested axis family.
    axis_family_derived: bool,
    /// Effective confirmation family alpha, absent for point-estimate-only mode.
    confirmation_family_alpha: Option<f64>,
    /// Typed summaries of every successful report-first pairwise estimate used
    /// by the point gate. Delete-block resample scalar fits are intentionally excluded.
    pairwise_reports: Vec<PairKsgEvidence>,
}

impl PidEstimatorEvidence {
    pub(crate) fn from_config(config: &PidConfig) -> Self {
        Self {
            config_identity: config.identity(),
            classification: config.classification(),
            pid_rs_version: PID_RS_VERSION,
            pid_rs_revision: PID_RS_REVISION,
            pairwise_estimator:
                "KSG MI (report-first point gate; raw-scalar circular-resample confirmation)",
            pairwise_scientific_status:
                "conditional_continuous/restricted_domain point; experimental circular delete-block pipeline",
            atom_estimator: "continuous shared-exclusions PID2 (Ehrlich KSG)",
            atom_scientific_status: "experimental_restricted_domain",
            support_contract: "caller-declared regular full-dimensional continuous law",
            pairwise_ksg_k: PID_KSG_NEIGHBORS,
            atom_ksg_k: PID_KSG_NEIGHBORS,
            atom_isx_k: PID_ISX_NEIGHBORS,
            estimator_metric: "chebyshev",
            negative_handling: "allow",
            atom_method: "ehrlich_ksg",
            observation_noise_model:
                "seeded additive Gaussian noise after per-column standardisation",
            observation_noise_std: config.observation_noise_std(),
            seed: config.seed(),
            geom_k: config.geom_k(),
            research_profile: config
                .source_profile()
                .map_or("custom", |profile| profile.name()),
            confirmation: config.confirmation().name(),
            axis_family_count: config.axis_family_count(),
            axis_family_derived: config.axis_family_was_derived(),
            confirmation_family_alpha: config
                .confirmation()
                .circular_delete_block()
                .map(CircularDeleteBlockConfirmation::family_alpha),
            pairwise_reports: Vec::new(),
        }
    }

    /// Canonical complete accepted PID configuration identity.
    pub const fn config_identity(&self) -> PidConfigDigest {
        self.config_identity
    }

    /// Named-profile or custom-research classification.
    pub const fn classification(&self) -> PidResearchClassification {
        self.classification
    }

    /// Exact upstream `pid-core` version selected for this analysis.
    pub const fn pid_rs_version(&self) -> &'static str {
        self.pid_rs_version
    }

    /// Exact immutable upstream revision selected for this analysis.
    pub const fn pid_rs_revision(&self) -> &'static str {
        self.pid_rs_revision
    }

    /// Pairwise estimator identity and role.
    pub const fn pairwise_estimator(&self) -> &'static str {
        self.pairwise_estimator
    }

    /// Scientific-status classification for the pairwise estimator path.
    pub const fn pairwise_scientific_status(&self) -> &'static str {
        self.pairwise_scientific_status
    }

    /// Advisory PID atom estimator identity.
    pub const fn atom_estimator(&self) -> &'static str {
        self.atom_estimator
    }

    /// Scientific-status classification for advisory PID atoms.
    pub const fn atom_scientific_status(&self) -> &'static str {
        self.atom_scientific_status
    }

    /// Upstream support contract retained for interpretation.
    pub const fn support_contract(&self) -> &'static str {
        self.support_contract
    }

    /// Fixed KSG neighbour count for pairwise MI.
    pub const fn pairwise_ksg_k(&self) -> usize {
        self.pairwise_ksg_k
    }

    /// Fixed KSG neighbour count inside PID2.
    pub const fn atom_ksg_k(&self) -> usize {
        self.atom_ksg_k
    }

    /// Fixed shared-exclusions neighbour count inside PID2.
    pub const fn atom_isx_k(&self) -> usize {
        self.atom_isx_k
    }

    /// Fixed metric used by the kNN estimators.
    pub const fn estimator_metric(&self) -> &'static str {
        self.estimator_metric
    }

    /// Fixed strict-radius compatibility value selected upstream.
    pub const fn tie_epsilon(&self) -> f64 {
        0.0
    }

    /// Upstream finite-sample negative-MI policy.
    pub const fn negative_handling(&self) -> &'static str {
        self.negative_handling
    }

    /// Upstream shared-exclusions method.
    pub const fn atom_method(&self) -> &'static str {
        self.atom_method
    }

    /// Observation-noise model identity.
    pub const fn observation_noise_model(&self) -> &'static str {
        self.observation_noise_model
    }

    /// Observation-noise standard deviation after standardisation.
    pub const fn observation_noise_std(&self) -> f64 {
        self.observation_noise_std
    }

    /// Observation-noise and estimator seed.
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Intrinsic-dimension neighbour count.
    pub const fn geom_k(&self) -> usize {
        self.geom_k
    }

    /// Stable named profile, or `"custom"` for caller-supplied parameters.
    pub const fn research_profile(&self) -> &'static str {
        self.research_profile
    }

    /// Stable confirmation-mode identity.
    pub const fn confirmation(&self) -> &'static str {
        self.confirmation
    }

    /// Projection axes sharing the confirmation family budget.
    pub const fn axis_family_count(&self) -> usize {
        self.axis_family_count
    }

    /// Whether the accepted config was derived for an attested axis family.
    pub const fn axis_family_was_derived(&self) -> bool {
        self.axis_family_derived
    }

    /// Effective confirmation family alpha, when confirmation is enabled.
    pub const fn confirmation_family_alpha(&self) -> Option<f64> {
        self.confirmation_family_alpha
    }

    /// Successful report-first pairwise estimates used by the point gate.
    pub fn pairwise_reports(&self) -> &[PairKsgEvidence] {
        &self.pairwise_reports
    }
}

/// Report-first KSG evidence retained for one canonical modality pair.
///
/// The upstream report owns additional high-volume diagnostics. Galadriel keeps
/// the typed scientific status, assumptions, warnings, hashes, estimand, support
/// contract, and resource preflight that a downstream audit needs to interpret
/// the scalar used by the clique gate.
#[derive(Debug, Clone, PartialEq)]
pub struct PairKsgEvidence {
    pub first: Modality,
    pub second: Modality,
    pub estimate_nats: f64,
    pub n_samples: usize,
    pub k: usize,
    pub support_contract: SupportContract,
    pub method_status: KsgMethodStatus,
    pub scientific_status: ScientificStatus,
    pub estimand: EstimandIdentity,
    pub assumption_ledger: Vec<AssumptionLedgerEntry>,
    pub warnings: Vec<KsgReportWarning>,
    pub report_warnings: Vec<WarningCode>,
    pub provenance_hashes: Arc<ProvenanceHashes>,
    pub preprocessing_description: String,
    pub observation_model_description: String,
    pub sampling_model_description: Option<String>,
    pub resource_estimate: ResourceEstimate,
}

struct PairMiEstimate {
    value: f64,
    evidence: PairKsgEvidence,
}

/// Per-channel analysis detail.
///
/// Only [`analyze`] creates channel reports. In particular, callers cannot flip
/// the attribution bit on an analyser-produced result:
///
/// ```compile_fail
/// use galadriel_pid::{analyze, PidResearchProfile};
/// let config = PidResearchProfile::PointEstimateOnlyV0_9.try_config().unwrap();
/// let report = analyze(&[], &config).unwrap();
/// let mut channel = report.channels()[0].clone();
/// channel.decoupled = true;
/// ```
#[derive(Debug, Clone)]
pub struct ChannelPid {
    /// Which modality.
    modality: Modality,
    /// Aligned samples used.
    n: usize,
    /// Whether at least one pair was safely assessable for this channel.
    gate_ok: bool,
    /// Human-readable geometry/estimator status.
    gate_note: String,
    /// Best safely estimated pairwise MI (nats).
    corroboration: Option<f64>,
    /// Advisory shared-exclusions redundancy atom (nats).
    redundancy: Option<f64>,
    /// Advisory shared-exclusions synergy atom (nats).
    synergy: Option<f64>,
    /// Whether this channel was attributed as decoupled from the consensus clique.
    /// Attribution is delete-block-confirmed unless point-estimate-only mode was selected.
    decoupled: bool,
    /// Circular delete-block interval for the worst candidate-to-consensus confirmation
    /// margin: edge MI minus the replicate-selected consensus threshold, in nats.
    /// A confirmed candidate has an upper endpoint below zero.
    ci: Option<(f64, f64)>,
}

impl ChannelPid {
    #[expect(
        clippy::too_many_arguments,
        reason = "one sealed report row retains all diagnostics"
    )]
    pub(crate) fn new(
        modality: Modality,
        n: usize,
        gate_ok: bool,
        gate_note: String,
        corroboration: Option<f64>,
        redundancy: Option<f64>,
        synergy: Option<f64>,
        decoupled: bool,
        ci: Option<(f64, f64)>,
    ) -> Self {
        Self {
            modality,
            n,
            gate_ok,
            gate_note,
            corroboration,
            redundancy,
            synergy,
            decoupled,
            ci,
        }
    }

    /// Modality represented by this row.
    pub const fn modality(&self) -> Modality {
        self.modality
    }

    /// Number of aligned samples used.
    pub const fn n(&self) -> usize {
        self.n
    }

    /// Whether at least one pair was safely assessable.
    pub const fn gate_ok(&self) -> bool {
        self.gate_ok
    }

    /// Human-readable geometry and estimator status.
    pub fn gate_note(&self) -> &str {
        &self.gate_note
    }

    /// Best safely estimated pairwise MI in nats.
    pub const fn corroboration(&self) -> Option<f64> {
        self.corroboration
    }

    /// Advisory shared-exclusions redundancy atom in nats.
    pub const fn redundancy(&self) -> Option<f64> {
        self.redundancy
    }

    /// Advisory shared-exclusions synergy atom in nats.
    pub const fn synergy(&self) -> Option<f64> {
        self.synergy
    }

    /// Whether this channel was attributed as decoupled.
    pub const fn is_decoupled(&self) -> bool {
        self.decoupled
    }

    /// Circular delete-block interval for the confirmation margin.
    pub const fn confirmation_interval(&self) -> Option<(f64, f64)> {
        self.ci
    }
}

/// The engine's advisory verdict. Uniform magnitude inflation is owned by the
/// baseline; this engine detects cross-channel decoupling.
#[derive(Debug, Clone, PartialEq)]
pub enum PidVerdict {
    /// Every requested channel belongs to one assessable consensus clique.
    Nominal,
    /// One or a strict minority of channels was attributed as decoupled. This
    /// identifies information-theoretic structure, not an attack cause.
    Decoupled(Vec<Modality>),
    /// The estimator or consensus structure was not sufficient for attribution.
    InsufficientEvidence,
}

/// Full PID consistency report.
///
/// Reports are analyser-produced, read-only evidence. Literal construction and
/// verdict mutation are intentionally unavailable to downstream callers:
///
/// ```compile_fail
/// use galadriel_pid::PidReport;
/// let _ = PidReport { note: "forged".into() };
/// ```
///
/// ```compile_fail
/// use galadriel_pid::{analyze, PidResearchProfile, PidVerdict};
/// let config = PidResearchProfile::PointEstimateOnlyV0_9.try_config().unwrap();
/// let mut report = analyze(&[], &config).unwrap();
/// report.verdict = PidVerdict::Nominal;
/// ```
#[derive(Debug, Clone)]
pub struct PidReport {
    /// Exact dependency, estimator, support, noise, and seed classification.
    estimator: PidEstimatorEvidence,
    /// Per-channel detail, in input order.
    channels: Vec<ChannelPid>,
    /// Advisory verdict.
    verdict: PidVerdict,
    /// Human-readable rationale.
    note: String,
}

impl PidReport {
    pub(crate) fn new(
        estimator: PidEstimatorEvidence,
        channels: Vec<ChannelPid>,
        verdict: PidVerdict,
        note: String,
    ) -> Self {
        Self {
            estimator,
            channels,
            verdict,
            note,
        }
    }

    /// Estimator, dependency, configuration, and provenance evidence.
    pub const fn estimator(&self) -> &PidEstimatorEvidence {
        &self.estimator
    }

    /// Per-channel detail in input order.
    pub fn channels(&self) -> &[ChannelPid] {
        &self.channels
    }

    /// Advisory PID verdict.
    pub const fn verdict(&self) -> &PidVerdict {
        &self.verdict
    }

    /// Human-readable rationale.
    pub fn note(&self) -> &str {
        &self.note
    }
}

/// Analyse already sequence-aligned signed-scalar channel series.
///
/// More channels than the closed modality vocabulary, duplicate modalities,
/// unequal lengths, non-finite values, and numerically degenerate raw columns are
/// malformed inputs and return an error. Too few
/// channels/samples and estimator limitations return an explicit insufficient
/// report instead. Circular delete-block positive attributions fit every selected
/// consensus and candidate-to-consensus edge, then bound the joint worst-consensus and
/// worst-candidate margins across common circular delete-block resamples. These
/// bounds are a conservative screening guard, not a post-selection calibration
/// guarantee for the clique search.
pub fn analyze(
    channels: &[(Modality, Vec<f64>)],
    cfg: &PidConfig,
) -> galadriel_core::Result<PidReport> {
    let c = channels.len();
    if c > MAX_MODALITIES {
        return Err(GaladrielError::InvalidChannels(format!(
            "PID accepts at most {MAX_MODALITIES} channels, got {c}"
        )));
    }
    let mut estimator = PidEstimatorEvidence::from_config(cfg);

    let unique: HashSet<Modality> = channels.iter().map(|(modality, _)| *modality).collect();
    if unique.len() != c {
        return Err(GaladrielError::InvalidChannels(
            "PID modalities must be unique".into(),
        ));
    }
    let lengths: HashSet<usize> = channels.iter().map(|(_, values)| values.len()).collect();
    if lengths.len() > 1 {
        return Err(GaladrielError::InvalidChannels(
            "PID columns must already be sequence-aligned and equal-length".into(),
        ));
    }
    if channels
        .iter()
        .flat_map(|(_, values)| values)
        .any(|value| !value.is_finite())
    {
        return Err(GaladrielError::NonFinite("PID channel input"));
    }

    let w = channels
        .first()
        .map_or(0, |(_, values)| values.len())
        .min(cfg.window());
    let required_samples = cfg.required_samples();
    if c < 3 || w < required_samples {
        return Ok(PidReport::new(
            estimator,
            Vec::new(),
            PidVerdict::InsufficientEvidence,
            format!(
                "need >=3 channels and >={required_samples} aligned samples (have {c} channels, w={w})"
            ),
        ));
    }
    // KSG distances are not scale invariant when one fixed observation-noise
    // amplitude is added. Validate and standardise every verdict-eligible column.
    let mut cols = Vec::with_capacity(c);
    for (modality, values) in channels {
        cols.push(standardize(&values[values.len() - w..], modality.label())?);
    }

    let mut mi = vec![vec![None::<f64>; c]; c];
    let mut pair_failures = vec![Vec::<String>::new(); c];
    for i in 0..c {
        for j in (i + 1)..c {
            match pair_mi(cfg, channels[i].0, &cols[i], channels[j].0, &cols[j]) {
                Ok(estimate) => {
                    mi[i][j] = Some(estimate.value);
                    mi[j][i] = Some(estimate.value);
                    estimator.pairwise_reports.push(estimate.evidence);
                }
                Err(reason) => {
                    pair_failures[i].push(format!("{}: {reason}", channels[j].0.label()));
                    pair_failures[j].push(format!("{}: {reason}", channels[i].0.label()));
                }
            }
        }
    }
    for failures in &mut pair_failures {
        failures.sort_unstable();
    }

    let mut reports = Vec::with_capacity(c);
    for (i, (modality, _)) in channels.iter().enumerate() {
        let peers: Vec<f64> = (0..c)
            .filter(|&j| j != i)
            .filter_map(|j| mi[i][j])
            .collect();
        let corroboration = peers.iter().copied().reduce(f64::max);
        let gate_ok = corroboration.is_some();
        let gate_note = if pair_failures[i].is_empty() {
            "all pair estimators ready".to_string()
        } else if gate_ok {
            format!(
                "{}/{} pairs assessable; {}",
                peers.len(),
                c - 1,
                pair_failures[i].join("; ")
            )
        } else {
            format!("no assessable pair; {}", pair_failures[i].join("; "))
        };
        let atoms = isx_atoms(cfg, channels, &cols, i, w);
        reports.push(ChannelPid::new(
            *modality,
            w,
            gate_ok,
            gate_note,
            corroboration,
            atoms.map(|atom| atom.0),
            atoms.map(|atom| atom.1),
            false,
            None,
        ));
    }

    if reports.iter().any(|report| !report.gate_ok) {
        let missing = reports
            .iter()
            .filter(|report| !report.gate_ok)
            .map(|report| report.modality.label())
            .collect::<Vec<_>>()
            .join(", ");
        return Ok(PidReport::new(
            estimator,
            reports,
            PidVerdict::InsufficientEvidence,
            format!("requested channel(s) not assessable: {missing}"),
        ));
    }
    let failed_pairs = pair_failures.iter().map(Vec::len).sum::<usize>() / 2;
    if has_pair_estimator_failures(failed_pairs) {
        return Ok(PidReport::new(
            estimator,
            reports,
            PidVerdict::InsufficientEvidence,
            format!(
                "{failed_pairs} requested pair estimator(s) failed a geometry or numerical gate"
            ),
        ));
    }

    let reference = reports
        .iter()
        .filter_map(|report| report.corroboration)
        .fold(0.0_f64, f64::max);
    if below_mi_floor(reference, cfg.mi_floor()) {
        return Ok(PidReport::new(
            estimator,
            reports,
            PidVerdict::InsufficientEvidence,
            format!(
                "no coherent MI consensus (strongest pair {reference:.3} < floor {:.3})",
                cfg.mi_floor()
            ),
        ));
    }
    let threshold = cfg.mi_floor().max(cfg.decouple_ratio() * reference);

    let (largest_size, largest_cliques) = largest_consensus_cliques(&mi, threshold);
    if !has_unique_strict_majority(largest_size, largest_cliques.len(), c) {
        return Ok(PidReport::new(
            estimator,
            reports,
            PidVerdict::InsufficientEvidence,
            format!(
                "ambiguous MI-consensus structure (largest clique {largest_size}/{c}, {} tied); no unique strict majority",
                largest_cliques.len()
            ),
        ));
    }

    let consensus = &largest_cliques[0];
    let consensus_set: HashSet<usize> = consensus.iter().copied().collect();
    let candidates: Vec<usize> = (0..c)
        .filter(|index| !consensus_set.contains(index))
        .collect();

    // An excluded channel is attributable only when every edge from it to the
    // consensus was successfully estimated and is below threshold. A missing
    // estimate or a partial bridge is ambiguity, never evidence against it.
    for &candidate in &candidates {
        let fully_assessed_low = consensus
            .iter()
            .all(|&peer| mi[candidate][peer].is_some_and(|value| value < threshold));
        if !fully_assessed_low {
            return Ok(PidReport::new(
                estimator,
                reports,
                PidVerdict::InsufficientEvidence,
                format!(
                    "{} is outside the majority clique but is not uniformly assessable-and-low against it",
                    channels[candidate].0.label()
                ),
            ));
        }
    }

    if candidates.is_empty() {
        return Ok(PidReport::new(
            estimator,
            reports,
            PidVerdict::Nominal,
            format!(
                "all {c} requested channels form one assessable MI-consensus clique (strongest MI {reference:.3} nats)"
            ),
        ));
    }

    let confirmed = matches!(cfg.confirmation(), PidConfirmation::CircularDeleteBlock(_));
    if confirmed {
        if let Err(reason) =
            confirm_attribution(cfg, channels, &cols, consensus, &candidates, &mut reports)
        {
            return Ok(PidReport::new(
                estimator,
                reports,
                PidVerdict::InsufficientEvidence,
                format!(
                    "circular delete-block confirmation did not confirm the selected attribution: {reason}"
                ),
            ));
        }
    }

    let mut decoupled = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        reports[candidate].decoupled = true;
        decoupled.push(reports[candidate].modality);
    }
    decoupled.sort_by_key(|modality| modality_key(*modality));
    let names = decoupled
        .iter()
        .map(|modality| modality.label())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(PidReport::new(
        estimator,
        reports,
        PidVerdict::Decoupled(decoupled.clone()),
        format!(
            "{} channel(s) {} a unique {}/{} MI-consensus clique: {names}",
            decoupled.len(),
            if confirmed {
                "circular-delete-block-confirmed decoupled from"
            } else {
                "point-estimate decoupled from (unconfirmed research mode)"
            },
            largest_size,
            c
        ),
    ))
}

fn has_pair_estimator_failures(failed_pairs: usize) -> bool {
    failed_pairs != 0
}

fn below_mi_floor(reference: f64, floor: f64) -> bool {
    matches!(reference.total_cmp(&floor), Ordering::Less)
}

fn has_unique_strict_majority(
    largest_size: usize,
    clique_count: usize,
    channel_count: usize,
) -> bool {
    largest_size > channel_count / 2 && clique_count == 1
}

fn standardize(values: &[f64], modality: &str) -> galadriel_core::Result<Vec<f64>> {
    let (minimum, maximum) = values.iter().copied().fold(
        (f64::INFINITY, f64::NEG_INFINITY),
        |(minimum, maximum), value| (minimum.min(value), maximum.max(value)),
    );
    if minimum == maximum {
        return Err(GaladrielError::InvalidChannels(format!(
            "PID {modality} column is degenerate"
        )));
    }
    let center = minimum / 2.0 + maximum / 2.0;
    let scale = (minimum - center).abs().max((maximum - center).abs());
    let n = values.len() as f64;
    let mean = values
        .iter()
        .map(|value| (value - center) / scale)
        .sum::<f64>()
        / n;
    let centered: Vec<f64> = values
        .iter()
        .map(|value| (value - center) / scale - mean)
        .collect();
    let sum_squares = centered.iter().map(|value| value * value).sum::<f64>();
    if !sum_squares.is_finite() || sum_squares <= f64::EPSILON * n {
        return Err(GaladrielError::InvalidChannels(format!(
            "PID {modality} column is numerically degenerate"
        )));
    }
    let rms = (sum_squares / n).sqrt();
    let standardized: Vec<f64> = centered.into_iter().map(|value| value / rms).collect();
    if standardized.iter().any(|value| !value.is_finite()) {
        return Err(GaladrielError::NonFinite("PID standardisation"));
    }
    Ok(standardized)
}

fn largest_consensus_cliques(mi: &[Vec<Option<f64>>], threshold: f64) -> (usize, Vec<Vec<usize>>) {
    let c = mi.len();
    let mut largest_size = 0;
    let mut largest_cliques = Vec::new();
    for mask in 1usize..(1usize << c) {
        let members: Vec<usize> = (0..c).filter(|index| mask & (1 << index) != 0).collect();
        if members.len() < largest_size {
            continue;
        }
        let is_clique = members.iter().enumerate().all(|(position, &i)| {
            members[position + 1..]
                .iter()
                .all(|&j| mi[i][j].is_some_and(|value| value >= threshold))
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

fn intrinsic_dimension_config(cfg: &PidConfig) -> IntrinsicDimConfig {
    IntrinsicDimConfig::default()
        .with_k(cfg.geom_k())
        .with_metric(Metric::Chebyshev)
}

fn ksg_estimator_config() -> KsgConfig {
    KsgConfig::assume_regular_full_dimensional()
        .with_k(PID_KSG_NEIGHBORS)
        .with_metric(Metric::Chebyshev)
        .with_tie_epsilon(0.0)
        .with_negative_handling(NegativeHandling::Allow)
}

fn pid2_estimator_config() -> Pid2Config {
    let mut config = Pid2Config::assume_regular_full_dimensional();
    config.ksg = ksg_estimator_config();
    config.isx.k = PID_ISX_NEIGHBORS;
    config.isx.metric = Metric::Chebyshev;
    config.isx.tie_epsilon = 0.0;
    config.isx.method = IsxMethod::EhrlichKsg;
    config
}

/// Geometry-gated pairwise MI. Geometry and estimator failures remain
/// distinguishable from a successfully estimated low MI through `Err`.
fn pair_mi(
    cfg: &PidConfig,
    a_modality: Modality,
    a: &[f64],
    b_modality: Modality,
    b: &[f64],
) -> Result<PairMiEstimate, String> {
    let (first_modality, first, second_modality, second) =
        canonical_pair(a_modality, a, b_modality, b);
    let seed = domain_seed(
        cfg.seed(),
        ROLE_PAIR_POINT,
        modality_key(first_modality),
        modality_key(second_modality),
    );
    let (joint, columns) =
        noised_matrix_and_columns(&[first, second], cfg.observation_noise_std(), seed)?;
    let id = intrinsic_dimension_levina_bickel(joint.as_ref(), &intrinsic_dimension_config(cfg))
        .map_err(|error| format!("intrinsic-dimension estimator failed: {error}"))?;
    if intrinsic_dimension_gate_failed(id, cfg.id_max()) {
        return Err(format!(
            "intrinsic dimension {id:.3} exceeds {:.3}",
            cfg.id_max()
        ));
    }
    let concentration =
        distance_concentration_stats(joint.as_ref(), &DistanceConcentrationConfig::default())
            .map_err(|error| format!("distance-concentration estimator failed: {error}"))?;
    if geometry_gate_failed(
        concentration.pairwise_cv,
        concentration.nn_over_pairwise_mean,
        cfg.cv_min(),
        cfg.nn_ratio_max(),
    ) {
        return Err(format!(
            "geometry gate failed (cv {:.4}, nn/pair {:.4})",
            concentration.pairwise_cv, concentration.nn_over_pairwise_mean
        ));
    }
    estimate_mi_reported(
        cfg,
        first_modality,
        second_modality,
        seed,
        &columns[0],
        &columns[1],
    )
}

fn intrinsic_dimension_gate_failed(intrinsic_dimension: f64, maximum: f64) -> bool {
    !intrinsic_dimension.is_finite() || intrinsic_dimension > maximum
}

fn geometry_gate_failed(
    pairwise_cv: f64,
    nn_over_pairwise_mean: f64,
    cv_min: f64,
    nn_ratio_max: f64,
) -> bool {
    !pairwise_cv.is_finite()
        || !nn_over_pairwise_mean.is_finite()
        || pairwise_cv < cv_min
        || nn_over_pairwise_mean > nn_ratio_max
}

fn canonical_pair<'a>(
    a_modality: Modality,
    a: &'a [f64],
    b_modality: Modality,
    b: &'a [f64],
) -> (Modality, &'a [f64], Modality, &'a [f64]) {
    if modality_key(a_modality) < modality_key(b_modality) {
        (a_modality, a, b_modality, b)
    } else {
        (b_modality, b, a_modality, a)
    }
}

fn estimate_mi_reported(
    cfg: &PidConfig,
    first: Modality,
    second: Modality,
    derived_seed: u64,
    a: &MatOwned,
    b: &MatOwned,
) -> Result<PairMiEstimate, String> {
    let provenance = KsgProvenance::new(
        format!(
            "Galadriel overflow-resistant per-column standardisation (midrange/range preconditioning, then mean centering and population-RMS scaling) of the canonical {}-{} modality pair",
            first.label(),
            second.label()
        ),
        format!(
            "seeded additive Gaussian observation noise after standardisation (std={:.17e}, root_seed={}, derived_pair_seed={derived_seed}); population support is declared separately by KsgConfig",
            cfg.observation_noise_std(), cfg.seed()
        ),
        None,
    )
    .and_then(|provenance| {
        provenance.with_sampling_model_and_splits(
            "one temporally ordered sequence-aligned analysis window; temporal dependence is not diagnosed by the point report, and circular delete-block confirmation is a separate experimental pipeline",
            None,
            None,
        )
    })
    .map_err(|error| format!("KSG provenance rejected: {error}"))?;
    let report = ksg_mi_report(a.as_ref(), b.as_ref(), &ksg_estimator_config(), &provenance)
        .map_err(|error| format!("KSG estimator failed: {error}"))?;
    validate_ksg_report_status(report.method_status, report.scientific_status)?;
    let value = report.signed_estimate_nats;
    // KSG's finite-sample estimate is signed. The pinned revision's
    // manifest-declared 1.0 API deliberately defaults to NegativeHandling::Allow,
    // so a small negative estimate remains an auditable low-dependence result
    // rather than a numerical failure. The clique threshold is positive, so
    // retaining the sign cannot create a corroborating edge.
    if !value.is_finite() {
        return Err("KSG estimator returned a non-finite MI".into());
    }
    let preprocessing_description = report.provenance.preprocessing_description().to_owned();
    let observation_model_description =
        report.provenance.observation_model_description().to_owned();
    let sampling_model_description = report
        .provenance
        .sampling_model_description()
        .map(str::to_owned);
    Ok(PairMiEstimate {
        value,
        evidence: PairKsgEvidence {
            first,
            second,
            estimate_nats: value,
            n_samples: report.n_samples,
            k: report.k,
            support_contract: report.support_contract,
            method_status: report.method_status,
            scientific_status: report.scientific_status,
            estimand: report.estimand,
            assumption_ledger: report.assumption_ledger,
            warnings: report.warnings,
            report_warnings: report.report_warnings,
            provenance_hashes: Arc::new(report.provenance_hashes),
            preprocessing_description,
            observation_model_description,
            sampling_model_description,
            resource_estimate: report.resource_estimate,
        },
    })
}

fn validate_ksg_report_status(
    method_status: KsgMethodStatus,
    scientific_status: ScientificStatus,
) -> Result<(), String> {
    if method_status != KsgMethodStatus::RestrictedDomain
        || scientific_status != ScientificStatus::ConditionalContinuous
    {
        return Err("KSG report returned an unexpected scientific-status classification".into());
    }
    Ok(())
}

/// Inner resample scalar path. The point gate above carries pid-rs's full
/// report/status/diagnostics; bootstrap replicates reuse the same explicit
/// support contract but avoid multiplying report materialization by every
/// edge×resample. The enclosing [`PidEstimatorEvidence`] classifies this part of
/// the pipeline as experimental.
fn estimate_mi(a: &MatOwned, b: &MatOwned) -> Result<f64, String> {
    let value = ksg_mi(a.as_ref(), b.as_ref(), &ksg_estimator_config())
        .map_err(|error| format!("KSG bootstrap estimator failed: {error}"))?;
    if !value.is_finite() {
        return Err("KSG bootstrap estimator returned a non-finite MI".into());
    }
    Ok(value)
}

/// Apply the configured observation-noise model to one joint matrix, then split
/// its columns. Noise is i.i.d. across the row-major joint matrix; no two columns
/// can receive the identical restarted PRNG sequence.
fn noised_matrix_and_columns(
    columns: &[&[f64]],
    observation_noise_std: f64,
    seed: u64,
) -> Result<(MatOwned, Vec<MatOwned>), String> {
    let Some(first) = columns.first() else {
        return Err("cannot apply observation noise to an empty column set".into());
    };
    let n = first.len();
    if n == 0 || columns.iter().any(|column| column.len() != n) {
        return Err("observation-noise columns must be non-empty and equal-length".into());
    }
    let dimensions = columns.len();
    let mut flat = Vec::with_capacity(n.saturating_mul(dimensions));
    for row in 0..n {
        for column in columns {
            flat.push(column[row]);
        }
    }
    let raw = MatOwned::new(flat, n, dimensions)
        .map_err(|error| format!("joint matrix construction failed: {error}"))?;
    let jitter = Jitter::new(observation_noise_std, seed)
        .map_err(|error| format!("observation-noise construction failed: {error}"))?;
    let joint = jitter
        .apply(raw.as_ref())
        .map_err(|error| format!("joint observation-noise application failed: {error}"))?;

    let view = joint.as_ref();
    let mut split = Vec::with_capacity(dimensions);
    for dimension in 0..dimensions {
        let data: Vec<f64> = (0..n).map(|row| view.row(row)[dimension]).collect();
        split.push(
            MatOwned::new(data, n, 1)
                .map_err(|error| format!("noised column construction failed: {error}"))?,
        );
    }
    Ok((joint, split))
}

/// Advisory `I^sx` atoms for `(channel, stable designated peer, remaining consensus)`.
fn isx_atoms(
    cfg: &PidConfig,
    channels: &[(Modality, Vec<f64>)],
    cols: &[Vec<f64>],
    i: usize,
    w: usize,
) -> Option<(f64, f64)> {
    let mut others: Vec<usize> = (0..channels.len()).filter(|&index| index != i).collect();
    others.sort_by_key(|&index| modality_key(channels[index].0));
    if others.len() < 2 {
        return None;
    }
    let target = consensus(cols, &others[1..], w);
    let seed = domain_seed(
        cfg.seed(),
        ROLE_PID_ATOMS,
        modality_key(channels[i].0),
        modality_key(channels[others[0]].0),
    );
    let (_, columns) = noised_matrix_and_columns(
        &[&cols[i], &cols[others[0]], &target],
        cfg.observation_noise_std(),
        seed,
    )
    .ok()?;
    let estimate = pid2_isx_estimate(
        columns[0].as_ref(),
        columns[1].as_ref(),
        columns[2].as_ref(),
        &pid2_estimator_config(),
    )
    .ok()?;
    let redundancy = estimate.redundancy_isx;
    let synergy = estimate.mi_s1s2_t - estimate.mi_s1_t - estimate.mi_s2_t + redundancy;
    (redundancy.is_finite() && synergy.is_finite()).then_some((redundancy, synergy))
}

fn consensus(cols: &[Vec<f64>], indices: &[usize], w: usize) -> Vec<f64> {
    (0..w)
        .map(|frame| {
            indices.iter().map(|&index| cols[index][frame]).sum::<f64>() / indices.len() as f64
        })
        .collect()
}

#[derive(Debug, Clone)]
struct EdgeBootstrap {
    left: usize,
    right: usize,
    estimates: Vec<f64>,
}

#[derive(Debug, Clone)]
struct EdgeMargins {
    left: usize,
    right: usize,
    values: Vec<f64>,
}

#[derive(Debug, Clone, Copy)]
enum JointBoundExtremum {
    Minimum,
    Maximum,
}

/// Confirm the selected clique and every candidate-to-clique low edge with
/// simultaneous one-sided circular delete-block bounds. Each resample uses one
/// common row plan across every edge and reselects the strongest consensus
/// reference. Delete-block plans avoid the duplicated rows that make a
/// replacement bootstrap pathological for nearest-neighbour MI estimators.
fn confirm_attribution(
    cfg: &PidConfig,
    channels: &[(Modality, Vec<f64>)],
    cols: &[Vec<f64>],
    consensus: &[usize],
    candidates: &[usize],
    reports: &mut [ChannelPid],
) -> Result<(), String> {
    let confirmation = cfg
        .confirmation()
        .circular_delete_block()
        .ok_or_else(|| "circular delete-block confirmation was not configured".to_string())?;
    let mut stable_consensus = consensus.to_vec();
    stable_consensus.sort_by_key(|&index| modality_key(channels[index].0));
    let mut stable_candidates = candidates.to_vec();
    stable_candidates.sort_by_key(|&index| modality_key(channels[index].0));

    let consensus_fit_count = pair_count(stable_consensus.len());
    let candidate_fit_count = stable_candidates
        .len()
        .checked_mul(stable_consensus.len())
        .ok_or_else(|| "confirmation edge count overflowed".to_string())?;
    let required_edges = consensus_fit_count
        .checked_add(candidate_fit_count)
        .ok_or_else(|| "confirmation edge count overflowed".to_string())?;
    if required_edges == 0 {
        return Err("selected attribution has no confirmable edges".into());
    }

    let plans = delete_block_plans(cfg, cols[0].len(), channels)?;
    let mut consensus_bootstraps = Vec::with_capacity(consensus_fit_count);
    for (position, &left) in stable_consensus.iter().enumerate() {
        for &right in &stable_consensus[position + 1..] {
            consensus_bootstraps.push(EdgeBootstrap {
                left,
                right,
                estimates: bootstrap_mi_series(
                    cfg,
                    channels[left].0,
                    &cols[left],
                    channels[right].0,
                    &cols[right],
                    &plans,
                )?,
            });
        }
    }

    let mut candidate_bootstraps = Vec::with_capacity(candidate_fit_count);
    for &candidate in &stable_candidates {
        for &peer in &stable_consensus {
            candidate_bootstraps.push(EdgeBootstrap {
                left: candidate,
                right: peer,
                estimates: bootstrap_mi_series(
                    cfg,
                    channels[candidate].0,
                    &cols[candidate],
                    channels[peer].0,
                    &cols[peer],
                    &plans,
                )?,
            });
        }
    }

    let thresholds: Vec<f64> = (0..confirmation.resamples())
        .map(|replicate| {
            let reference = consensus_bootstraps
                .iter()
                .map(|edge| edge.estimates[replicate])
                .fold(0.0_f64, f64::max);
            cfg.mi_floor().max(cfg.decouple_ratio() * reference)
        })
        .collect();
    let consensus_margins = bootstrap_margins(consensus_bootstraps, &thresholds, cfg)?;
    let candidate_margins = bootstrap_margins(candidate_bootstraps, &thresholds, cfg)?;
    let tail_rank = cfg
        .confirmation_tail_rank()
        .ok_or_else(|| "circular delete-block confirmation has no tail rank".to_string())?;
    let consensus_interval =
        joint_margin_interval(&consensus_margins, tail_rank, JointBoundExtremum::Minimum)?;
    let candidate_interval =
        joint_margin_interval(&candidate_margins, tail_rank, JointBoundExtremum::Maximum)?;

    for &candidate in &stable_candidates {
        let candidate_edges: Vec<&EdgeMargins> = candidate_margins
            .iter()
            .filter(|edge| edge.left == candidate)
            .collect();
        reports[candidate].ci = Some(joint_margin_interval_refs(
            &candidate_edges,
            tail_rank,
            JointBoundExtremum::Maximum,
        )?);
    }

    if consensus_interval.0 <= 0.0 {
        let edge = consensus_margins
            .iter()
            .min_by(|left, right| {
                margin_interval(left, tail_rank)
                    .0
                    .total_cmp(&margin_interval(right, tail_rank).0)
            })
            .ok_or_else(|| "selected consensus has no margin series".to_string())?;
        return Err(format!(
            "joint worst-consensus lower margin {:.3} is not positive (weakest diagnostic edge {}-{})",
            consensus_interval.0,
            channels[edge.left].0.label(),
            channels[edge.right].0.label(),
        ));
    }
    if candidate_interval.1 >= 0.0 {
        let edge = candidate_margins
            .iter()
            .max_by(|left, right| {
                margin_interval(left, tail_rank)
                    .1
                    .total_cmp(&margin_interval(right, tail_rank).1)
            })
            .ok_or_else(|| "selected candidates have no margin series".to_string())?;
        return Err(format!(
            "joint worst-candidate upper margin {:.3} is not negative (worst diagnostic edge {}-{})",
            candidate_interval.1,
            channels[edge.left].0.label(),
            channels[edge.right].0.label(),
        ));
    }
    Ok(())
}

fn delete_block_plans(
    cfg: &PidConfig,
    n: usize,
    channels: &[(Modality, Vec<f64>)],
) -> Result<Vec<Vec<usize>>, String> {
    let confirmation = cfg
        .confirmation()
        .circular_delete_block()
        .ok_or_else(|| "circular delete-block confirmation was not configured".to_string())?;
    let retained = valid_delete_block_dimensions(
        n,
        confirmation.block_size(),
        cfg.geom_k(),
        confirmation.resamples(),
    )
    .ok_or_else(|| "invalid circular delete-block dimensions".to_string())?;

    let set_tag = modality_set_tag(channels);
    let mut rng = SplitMix64::new(domain_seed(cfg.seed(), ROLE_BOOT_PLAN, set_tag, n as u64));
    let mut starts: Vec<usize> = (0..n).collect();
    for index in (1..starts.len()).rev() {
        let other = rng.index(index + 1);
        starts.swap(index, other);
    }
    starts.truncate(confirmation.resamples());
    let mut plans = Vec::with_capacity(confirmation.resamples());
    for start in starts {
        let plan = circular_retained_plan(n, start, confirmation.block_size());
        debug_assert_eq!(plan.len(), retained);
        plans.push(plan);
    }
    Ok(plans)
}

fn valid_delete_block_dimensions(
    n: usize,
    block_size: usize,
    geom_k: usize,
    resamples: usize,
) -> Option<usize> {
    let retained = n.checked_sub(block_size)?;
    if retained <= geom_k {
        return None;
    }
    if resamples > n {
        return None;
    }
    Some(retained)
}

fn modality_set_tag(channels: &[(Modality, Vec<f64>)]) -> u64 {
    let mut keys: Vec<u64> = channels
        .iter()
        .map(|(modality, _)| modality_key(*modality))
        .collect();
    keys.sort_unstable();
    keys.into_iter()
        .fold(0x6a09_e667_f3bc_c909_u64, |tag, key| {
            domain_seed(tag, ROLE_BOOT_PLAN, key, 0)
        })
}

fn circular_retained_plan(n: usize, start: usize, block_size: usize) -> Vec<usize> {
    (0..n)
        .filter(|&index| {
            let circular_offset = if index >= start {
                index - start
            } else {
                n - (start - index)
            };
            circular_offset >= block_size
        })
        .collect()
}

/// Evaluate one edge over common deterministic circular delete-block plans. Every
/// resample must estimate successfully; point substitution would narrow the
/// eventual margin interval and is therefore prohibited.
fn bootstrap_mi_series(
    cfg: &PidConfig,
    a_modality: Modality,
    a: &[f64],
    b_modality: Modality,
    b: &[f64],
    plans: &[Vec<usize>],
) -> Result<Vec<f64>, String> {
    let confirmation = cfg
        .confirmation()
        .circular_delete_block()
        .ok_or_else(|| "circular delete-block confirmation was not configured".to_string())?;
    let (first_modality, first, second_modality, second) =
        canonical_pair(a_modality, a, b_modality, b);
    let n = first.len();
    let Some(retained) = n.checked_sub(confirmation.block_size()) else {
        return Err("invalid circular delete-block dimensions".into());
    };
    if !valid_bootstrap_plan_family(n, second.len(), retained, confirmation.resamples(), plans) {
        return Err("invalid circular delete-block dimensions".into());
    }
    let mut estimates = Vec::with_capacity(confirmation.resamples());
    for (replicate, plan) in plans.iter().enumerate() {
        let resampled_a: Vec<f64> = plan.iter().map(|&index| first[index]).collect();
        let resampled_b: Vec<f64> = plan.iter().map(|&index| second[index]).collect();

        let seed = bootstrap_jitter_seed(
            cfg.seed(),
            first_modality,
            second_modality,
            replicate as u64,
        );
        let (_, columns) = noised_matrix_and_columns(
            &[&resampled_a, &resampled_b],
            cfg.observation_noise_std(),
            seed,
        )?;
        estimates.push(estimate_mi(&columns[0], &columns[1])?);
    }
    Ok(estimates)
}

fn valid_bootstrap_plan_family(
    first_len: usize,
    second_len: usize,
    retained: usize,
    resamples: usize,
    plans: &[Vec<usize>],
) -> bool {
    if first_len != second_len {
        return false;
    }
    if plans.len() != resamples {
        return false;
    }
    for plan in plans {
        if plan.len() != retained {
            return false;
        }
        if plan.iter().any(|&index| index >= first_len) {
            return false;
        }
    }
    true
}

fn bootstrap_jitter_seed(base: u64, first: Modality, second: Modality, replicate: u64) -> u64 {
    let pair = domain_seed(
        0,
        ROLE_BOOT_JITTER,
        modality_key(first),
        modality_key(second),
    );
    domain_seed(base, ROLE_BOOT_JITTER, pair, replicate)
}

fn bootstrap_margins(
    bootstraps: Vec<EdgeBootstrap>,
    thresholds: &[f64],
    cfg: &PidConfig,
) -> Result<Vec<EdgeMargins>, String> {
    let confirmation = cfg
        .confirmation()
        .circular_delete_block()
        .ok_or_else(|| "circular delete-block confirmation was not configured".to_string())?;
    if thresholds.len() != confirmation.resamples() {
        return Err("bootstrap requires a complete non-empty bound family".into());
    }
    bootstraps
        .into_iter()
        .map(|edge| {
            if edge.estimates.len() != thresholds.len() {
                return Err("bootstrap edge series is incomplete".into());
            }
            let values: Vec<f64> = edge
                .estimates
                .iter()
                .zip(thresholds)
                .map(|(estimate, threshold)| estimate - threshold)
                .collect();
            Ok(EdgeMargins {
                left: edge.left,
                right: edge.right,
                values,
            })
        })
        .collect()
}

fn margin_interval(edge: &EdgeMargins, tail_rank: usize) -> (f64, f64) {
    let mut values = edge.values.clone();
    values.sort_by(f64::total_cmp);
    let upper = values.len() - tail_rank - 1;
    (values[tail_rank], values[upper])
}

fn joint_margin_interval(
    edges: &[EdgeMargins],
    tail_rank: usize,
    extremum: JointBoundExtremum,
) -> Result<(f64, f64), String> {
    let references: Vec<&EdgeMargins> = edges.iter().collect();
    joint_margin_interval_refs(&references, tail_rank, extremum)
}

fn joint_margin_interval_refs(
    edges: &[&EdgeMargins],
    tail_rank: usize,
    extremum: JointBoundExtremum,
) -> Result<(f64, f64), String> {
    let Some(first) = edges.first() else {
        return Err("cannot form a joint bound from an empty edge family".into());
    };
    let replicates = first.values.len();
    if replicates == 0
        || edges.iter().any(|edge| edge.values.len() != replicates)
        || tail_rank >= replicates
    {
        return Err("incomplete joint edge-margin family".into());
    }
    let mut extrema: Vec<f64> = (0..replicates)
        .map(|replicate| {
            edges
                .iter()
                .skip(1)
                .fold(first.values[replicate], |value, edge| match extremum {
                    JointBoundExtremum::Minimum => value.min(edge.values[replicate]),
                    JointBoundExtremum::Maximum => value.max(edge.values[replicate]),
                })
        })
        .collect();
    extrema.sort_by(f64::total_cmp);
    let upper = replicates - tail_rank - 1;
    Ok((extrema[tail_rank], extrema[upper]))
}

fn domain_seed(base: u64, role: u64, first: u64, second: u64) -> u64 {
    mix64(mix64(base ^ role) ^ mix64(first) ^ mix64(second.rotate_left(32)))
}

fn mix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mix64(self.state)
    }

    fn index(&mut self, upper: usize) -> usize {
        (((self.next_u64() as u128) * (upper as u128)) >> 64) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar_channels;
    use galadriel_sim::scenario::{
        generate, generate_spoofed, ScenarioConfig, ScenarioParams, ScenarioResearchProfile,
        StealthySpoof,
    };

    fn confirmed_config() -> PidConfig {
        PidResearchProfile::CircularDeleteBlockV0_9
            .try_config()
            .unwrap()
    }

    fn point_config() -> PidConfig {
        PidResearchProfile::PointEstimateOnlyV0_9
            .try_config()
            .unwrap()
    }

    fn confirmed_params() -> PidParams {
        PidResearchProfile::CircularDeleteBlockV0_9.params()
    }

    fn scen(seed: u64) -> ScenarioConfig {
        let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
        params.frames = 400;
        params.rho = 0.7;
        params.seed = seed;
        ScenarioConfig::try_new(params).unwrap()
    }

    fn pseudo_random_series(n: usize, seed: u64) -> Vec<f64> {
        let mut rng = SplitMix64::new(seed);
        (0..n)
            .map(|_| {
                let bits = rng.next_u64() >> 11;
                2.0 * bits as f64 / ((1_u64 << 53) as f64) - 1.0
            })
            .collect()
    }

    #[test]
    fn deterministic_seed_derivation_has_locked_domain_separation() {
        assert_eq!(mix64(0), 0);
        assert_eq!(mix64(1), 0x5692_161d_100b_05e5);
        assert_eq!(mix64(u64::MAX), 0xb4d0_55fc_f2cb_bd7b);
        assert_eq!(domain_seed(7, ROLE_PAIR_POINT, 2, 5), 0x14bd_8450_bac7_a166);

        let mut rng = SplitMix64::new(7);
        assert_eq!(rng.next_u64(), 0x63cb_e1e4_5932_0dd7);
        assert_eq!(rng.next_u64(), 0x044c_3cd7_f43c_661c);
        assert_eq!(rng.next_u64(), 0xe698_4080_bab1_2a02);

        assert_eq!(
            bootstrap_jitter_seed(7, Modality::Visual, Modality::Radar, 0),
            0xcfd7_eb37_7a97_0aff
        );
        assert_eq!(
            bootstrap_jitter_seed(7, Modality::Visual, Modality::Radar, 1),
            0x794c_3a49_4de2_40fd
        );
        assert_eq!(
            bootstrap_jitter_seed(7, Modality::Visual, Modality::Radar, 17),
            0xe343_990d_b80e_ef16
        );
    }

    #[test]
    fn delete_block_dimension_and_plan_boundaries_are_exact() {
        assert_eq!(valid_delete_block_dimensions(5, 2, 2, 5), Some(3));
        assert_eq!(valid_delete_block_dimensions(5, 2, 3, 5), None);
        assert_eq!(valid_delete_block_dimensions(5, 5, 0, 1), None);
        assert_eq!(valid_delete_block_dimensions(5, 6, 0, 1), None);
        assert_eq!(valid_delete_block_dimensions(5, 2, 2, 6), None);

        assert_eq!(circular_retained_plan(5, 0, 2), [2, 3, 4]);
        assert_eq!(circular_retained_plan(5, 1, 2), [0, 3, 4]);
        assert_eq!(circular_retained_plan(5, 2, 2), [0, 1, 4]);
        assert_eq!(circular_retained_plan(5, 3, 2), [0, 1, 2]);
        assert_eq!(circular_retained_plan(5, 4, 2), [1, 2, 3]);
    }

    #[test]
    fn bootstrap_plan_family_rejects_each_shape_failure_independently() {
        let valid = vec![vec![0, 1, 2], vec![2, 3, 4]];
        assert!(valid_bootstrap_plan_family(5, 5, 3, 2, &valid));
        assert!(!valid_bootstrap_plan_family(5, 4, 3, 2, &valid));
        assert!(!valid_bootstrap_plan_family(5, 5, 3, 1, &valid));

        let wrong_length = vec![vec![0, 1], vec![2, 3, 4]];
        assert!(!valid_bootstrap_plan_family(5, 5, 3, 2, &wrong_length));
        let out_of_range = vec![vec![0, 1, 5], vec![2, 3, 4]];
        assert!(!valid_bootstrap_plan_family(5, 5, 3, 2, &out_of_range));
    }

    #[test]
    fn modality_set_tag_is_order_independent_and_value_locked() {
        let channels = vec![
            (Modality::Visual, Vec::new()),
            (Modality::Radar, Vec::new()),
            (Modality::Acoustic, Vec::new()),
        ];
        let mut reordered = channels.clone();
        reordered.rotate_left(1);
        assert_eq!(modality_set_tag(&channels), 0xdde1_98a6_3727_1174);
        assert_eq!(modality_set_tag(&channels), modality_set_tag(&reordered));
    }

    #[test]
    fn named_delete_block_plan_order_is_seed_locked() {
        let channels = vec![
            (Modality::Visual, Vec::new()),
            (Modality::Radar, Vec::new()),
            (Modality::Acoustic, Vec::new()),
        ];
        let plans = delete_block_plans(&confirmed_config(), 128, &channels).unwrap();
        assert_eq!(plans.len(), 100);
        for (plan, start) in plans.iter().zip([77, 0, 107, 6, 56]) {
            assert_eq!(plan, &circular_retained_plan(128, start, 8));
        }
    }

    #[test]
    fn clean_corroborated_stream_is_nominal() {
        for seed in [7, 11, 23, 42] {
            let scenario = scen(seed);
            let stream = generate(&scenario).unwrap();
            let channels = scalar_channels(&stream, scenario.modalities(), 0).unwrap();
            let report = analyze(&channels, &confirmed_config()).unwrap();
            assert_eq!(
                report.verdict(),
                &PidVerdict::Nominal,
                "seed {seed}: {}",
                report.note()
            );
        }
    }

    #[test]
    fn fewer_than_three_channels_is_insufficient_evidence() {
        let scenario = scen(7);
        let stream = generate(&scenario).unwrap();
        let two = [Modality::Visual, Modality::Radar];
        let channels = scalar_channels(&stream, &two, 0).unwrap();
        let report = analyze(&channels, &confirmed_config()).unwrap();
        assert_eq!(report.verdict(), &PidVerdict::InsufficientEvidence);
    }

    #[test]
    fn bootstrap_readiness_precedes_nominal_or_positive_verdicts() {
        let scenario = ScenarioConfig::try_new(ScenarioParams {
            frames: confirmed_config().min_samples(),
            rho: 0.7,
            ..ScenarioResearchProfile::SyntheticV0_9.params()
        })
        .unwrap();
        let stream = generate(&scenario).unwrap();
        let channels = scalar_channels(&stream, scenario.modalities(), 0).unwrap();
        let report = analyze(&channels, &confirmed_config()).unwrap();

        assert_eq!(confirmed_config().required_samples(), 100);
        assert_eq!(report.verdict(), &PidVerdict::InsufficientEvidence);
        assert!(report.note().contains("100 aligned samples"));
    }

    #[test]
    fn default_confirmation_never_overstates_point_decoupling_evidence() {
        let mut confirmed = 0;
        for seed in [7, 23] {
            let scenario = scen(seed);
            let stream = generate_spoofed(
                &scenario,
                StealthySpoof {
                    target: Modality::Acoustic,
                    start_frame: scenario.frames() as u64 / 3,
                },
            )
            .unwrap();
            let channels = scalar_channels(&stream, scenario.modalities(), 0).unwrap();
            let point = analyze(&channels, &point_config()).unwrap();
            let report = analyze(&channels, &confirmed_config()).unwrap();
            assert!(
                matches!(
                    point.verdict(),
                    PidVerdict::Decoupled(ref modalities)
                        if modalities == &[Modality::Acoustic]
                ),
                "seed {seed}: point estimate did not isolate acoustic: {}",
                point.note()
            );
            match report.verdict() {
                PidVerdict::Decoupled(modalities) => {
                    assert_eq!(modalities, &[Modality::Acoustic]);
                    let acoustic = report
                        .channels()
                        .iter()
                        .find(|channel| channel.modality() == Modality::Acoustic)
                        .unwrap();
                    assert!(acoustic
                        .confirmation_interval()
                        .is_some_and(|interval| interval.1 < 0.0));
                    confirmed += 1;
                }
                PidVerdict::InsufficientEvidence => {
                    assert!(report
                        .channels()
                        .iter()
                        .all(|channel| !channel.is_decoupled()));
                }
                PidVerdict::Nominal => {
                    panic!("seed {seed}: confirmation erased a point candidate as nominal")
                }
            }
        }
        assert!(
            confirmed > 0,
            "default confirmation never accepted a clear decoupling"
        );
    }

    #[test]
    fn default_bootstrap_confirms_a_strong_deterministic_decoupling() {
        let shared = pseudo_random_series(128, 0x51);
        let honest_noise = pseudo_random_series(128, 0x52);
        let weak_noise = pseudo_random_series(128, 0x53);
        let radar = shared
            .iter()
            .zip(&honest_noise)
            .map(|(&signal, &noise)| signal + 0.03 * noise)
            .collect::<Vec<_>>();
        let acoustic = shared
            .iter()
            .zip(&weak_noise)
            .map(|(&signal, &noise)| 0.5 * signal + noise)
            .collect::<Vec<_>>();
        let channels = vec![
            (Modality::Visual, shared),
            (Modality::Radar, radar),
            (Modality::Acoustic, acoustic),
        ];

        let report = analyze(&channels, &confirmed_config()).unwrap();
        assert_eq!(
            report.verdict(),
            &PidVerdict::Decoupled(vec![Modality::Acoustic]),
            "{}",
            report.note()
        );
        let acoustic = report
            .channels()
            .iter()
            .find(|channel| channel.modality() == Modality::Acoustic)
            .unwrap();
        assert!(acoustic.is_decoupled());
        assert!(acoustic
            .confirmation_interval()
            .is_some_and(|(_, upper)| upper < 0.0));

        let evidence = report.estimator().pairwise_reports();
        assert_eq!(evidence.len(), 3);
        assert!(evidence.iter().all(|pair| {
            pair.method_status == KsgMethodStatus::RestrictedDomain
                && pair.scientific_status == ScientificStatus::ConditionalContinuous
                && !pair.assumption_ledger.is_empty()
                && !pair.warnings.is_empty()
                && pair.provenance_hashes.input_hashes_sha256.len() == 2
                && pair.sampling_model_description.is_some()
                && pair.observation_model_description.contains("root_seed=1")
        }));
    }

    #[test]
    fn rejects_constant_columns_before_noise_can_create_false_information() {
        let channels = vec![
            (Modality::Visual, vec![0.0; 128]),
            (Modality::Radar, vec![10.0; 128]),
            (Modality::Acoustic, vec![-7.0; 128]),
        ];
        assert!(matches!(
            analyze(&channels, &confirmed_config()),
            Err(GaladrielError::InvalidChannels(_))
        ));

        let short = channels
            .iter()
            .map(|(modality, values)| (*modality, values[..16].to_vec()))
            .collect::<Vec<_>>();
        assert_eq!(
            analyze(&short, &confirmed_config()).unwrap().verdict(),
            &PidVerdict::InsufficientEvidence,
            "too few samples are inconclusive, even when the observed prefix is constant"
        );
    }

    #[test]
    fn joint_observation_noise_does_not_reuse_one_sequence_across_columns() {
        let zeros = vec![0.0; 128];
        let (_, columns) = noised_matrix_and_columns(&[&zeros, &zeros], 1e-4, 7).unwrap();
        assert!(
            (0..128).all(|row| columns[0].as_ref().row(row)[0] != columns[1].as_ref().row(row)[0])
        );
    }

    #[test]
    fn observation_noise_rejects_zero_rows_before_matrix_construction() {
        let empty = Vec::new();

        let error = noised_matrix_and_columns(&[&empty, &empty], 1e-4, 7).unwrap_err();

        assert_eq!(
            error,
            "observation-noise columns must be non-empty and equal-length"
        );
    }

    #[test]
    fn ksg_report_status_rejects_unexpected_method_with_expected_scientific_status() {
        let error = validate_ksg_report_status(
            KsgMethodStatus::Experimental,
            ScientificStatus::ConditionalContinuous,
        )
        .unwrap_err();

        assert_eq!(
            error,
            "KSG report returned an unexpected scientific-status classification"
        );
    }

    #[test]
    fn ksg_report_status_rejects_unexpected_scientific_status_with_expected_method() {
        let error = validate_ksg_report_status(
            KsgMethodStatus::RestrictedDomain,
            ScientificStatus::ResearchOnly,
        )
        .unwrap_err();

        assert_eq!(
            error,
            "KSG report returned an unexpected scientific-status classification"
        );
    }

    #[test]
    fn isx_atoms_reports_deterministic_nontrivial_values() {
        let first = pseudo_random_series(128, 11);
        let second = pseudo_random_series(128, 17);
        let noise = pseudo_random_series(128, 23);
        let target = first
            .iter()
            .zip(&second)
            .zip(&noise)
            .map(|((&a, &b), &epsilon)| a + b + 0.2 * epsilon)
            .collect::<Vec<_>>();
        let channels = vec![
            (Modality::Visual, first),
            (Modality::Radar, second),
            (Modality::Acoustic, target),
        ];
        let columns = channels
            .iter()
            .map(|(modality, values)| standardize(values, modality.label()))
            .collect::<galadriel_core::Result<Vec<_>>>()
            .unwrap();

        let (redundancy, synergy) =
            isx_atoms(&confirmed_config(), &channels, &columns, 0, 128).unwrap();

        assert!(
            (0.16..0.17).contains(&redundancy) && (0.73..0.74).contains(&synergy),
            "unexpected deterministic I^sx atoms: ({redundancy}, {synergy})"
        );
    }

    #[test]
    fn finite_negative_ksg_estimates_remain_valid_low_edges() {
        for seed in 1..=128 {
            let first = pseudo_random_series(64, seed);
            let second = pseudo_random_series(64, seed.wrapping_add(10_000));
            let (_, columns) = noised_matrix_and_columns(&[&first, &second], 1e-4, seed).unwrap();
            let raw = ksg_mi(
                columns[0].as_ref(),
                columns[1].as_ref(),
                &ksg_estimator_config(),
            )
            .unwrap();
            if raw < 0.0 {
                assert_eq!(estimate_mi(&columns[0], &columns[1]).unwrap(), raw);
                let reported = estimate_mi_reported(
                    &confirmed_config(),
                    Modality::Visual,
                    Modality::Radar,
                    seed,
                    &columns[0],
                    &columns[1],
                )
                .unwrap();
                assert_eq!(reported.value, raw);
                return;
            }
        }
        panic!("fixed seed scan did not produce a signed negative KSG estimate");
    }

    #[test]
    fn pid_rs_1_0_evidence_and_upstream_status_are_locked() {
        use pid_core::experimental::continuous::{
            pid2_isx_report, Pid2MethodStatus, Pid2Provenance,
        };

        let evidence: serde_json::Value =
            serde_json::from_str(include_str!("../../../evidence/pid-rs-1.0-migration.json"))
                .unwrap();
        assert_eq!(evidence["schema_version"], 3);
        assert_eq!(evidence["to"]["pid_core_version"], PID_RS_VERSION);
        assert_eq!(evidence["to"]["pid_rs_revision"], PID_RS_REVISION);
        let lock = include_str!("../../../Cargo.lock");
        let locked_identity = format!(
            "name = \"pid-core\"\nversion = \"{PID_RS_VERSION}\"\nsource = \"git+https://github.com/sepahead/pid-rs?rev={PID_RS_REVISION}#{PID_RS_REVISION}\""
        );
        assert!(
            lock.contains(&locked_identity),
            "PID report identity constants must match the resolved Cargo.lock pin"
        );
        assert_eq!(
            evidence["execution_environment"]["rustc"],
            "1.96.0 (ac68faa20)"
        );
        assert_eq!(
            evidence["reproduction"]["discrete_xor"]["from"],
            evidence["reproduction"]["discrete_xor"]["to"]
        );
        assert_eq!(
            evidence["reproduction"]["stdout_sha256"]["from"],
            evidence["reproduction"]["stdout_sha256"]["to"]
        );
        assert_eq!(
            evidence["reproduction"]["sequential"]["from"],
            evidence["reproduction"]["sequential"]["to"]
        );
        assert_eq!(
            evidence["reproduction"]["autocorrelation_null"]["from"],
            evidence["reproduction"]["autocorrelation_null"]["to"]
        );

        let first = pseudo_random_series(128, 11);
        let second = pseudo_random_series(128, 17);
        let noise = pseudo_random_series(128, 23);
        let target = first
            .iter()
            .zip(&second)
            .zip(&noise)
            .map(|((&a, &b), &epsilon)| a + b + 0.2 * epsilon)
            .collect::<Vec<_>>();
        let (_, columns) =
            noised_matrix_and_columns(&[&first, &second, &target], 1e-4, 29).unwrap();
        let provenance = Pid2Provenance::new(
            "locked synthetic source-1 preprocessing",
            "locked synthetic source-2 preprocessing",
            "locked synthetic target preprocessing",
            "locked regular full-dimensional synthetic observation model",
        )
        .unwrap();
        let report = pid2_isx_report(
            columns[0].as_ref(),
            columns[1].as_ref(),
            columns[2].as_ref(),
            &pid2_estimator_config(),
            &provenance,
        )
        .unwrap();
        assert_eq!(
            report.method_status,
            Pid2MethodStatus::ExperimentalRestrictedDomain
        );
        assert!(!report.warnings.is_empty());
    }

    #[test]
    fn rejects_non_finite_and_ambiguous_channel_inputs() {
        let base = pseudo_random_series(128, 1);
        let mut nan = base.clone();
        nan[17] = f64::NAN;
        let non_finite = vec![
            (Modality::Visual, base.clone()),
            (Modality::Radar, base.clone()),
            (Modality::Acoustic, nan),
        ];
        assert!(matches!(
            analyze(&non_finite, &confirmed_config()),
            Err(GaladrielError::NonFinite(_))
        ));

        let unequal = vec![
            (Modality::Visual, base.clone()),
            (Modality::Radar, base[..127].to_vec()),
            (Modality::Acoustic, base.clone()),
        ];
        assert!(matches!(
            analyze(&unequal, &confirmed_config()),
            Err(GaladrielError::InvalidChannels(_))
        ));

        let duplicate = vec![
            (Modality::Visual, base.clone()),
            (Modality::Visual, base.clone()),
            (Modality::Acoustic, base),
        ];
        assert!(matches!(
            analyze(&duplicate, &confirmed_config()),
            Err(GaladrielError::InvalidChannels(_))
        ));
    }

    #[test]
    fn seven_channels_are_rejected_before_modality_or_column_scans() {
        let exact_closed_vocabulary = Modality::ALL
            .into_iter()
            .map(|modality| (modality, Vec::new()))
            .collect::<Vec<_>>();
        let exact_report = analyze(&exact_closed_vocabulary, &confirmed_config())
            .expect("the exact closed modality vocabulary is admissible");
        assert_eq!(exact_report.verdict(), &PidVerdict::InsufficientEvidence);

        let point = point_config();
        let constant = vec![1.0; point.required_samples()];
        let exact_readiness_boundary = vec![
            (Modality::Visual, constant.clone()),
            (Modality::Radar, constant.clone()),
            (Modality::Acoustic, constant),
        ];
        assert!(matches!(
            analyze(&exact_readiness_boundary, &point),
            Err(GaladrielError::InvalidChannels(_))
        ));

        let channels = vec![
            (Modality::Visual, Vec::new()),
            (Modality::Thermal, Vec::new()),
            (Modality::Acoustic, Vec::new()),
            (Modality::Radar, Vec::new()),
            (Modality::Lidar, Vec::new()),
            (Modality::RadioFrequency, Vec::new()),
            (Modality::Visual, vec![f64::NAN]),
        ];

        let error = analyze(&channels, &confirmed_config()).unwrap_err();

        assert!(matches!(
            error,
            GaladrielError::InvalidChannels(ref message)
                if message == "PID accepts at most 6 channels, got 7"
        ));
    }

    #[test]
    fn pair_failure_and_mi_floor_predicates_preserve_strict_boundaries() {
        assert!(!has_pair_estimator_failures(0));
        assert!(has_pair_estimator_failures(1));
        assert!(below_mi_floor(0.02, 0.03));
        assert!(!below_mi_floor(0.03, 0.03));
        assert!(!below_mi_floor(0.04, 0.03));
        assert!(has_unique_strict_majority(4, 1, 6));
        assert!(has_unique_strict_majority(3, 1, 5));
        assert!(!has_unique_strict_majority(3, 1, 6));
        assert!(!has_unique_strict_majority(4, 2, 6));
        assert!(!geometry_gate_failed(0.02, 0.8, 0.02, 0.8));
        assert!(geometry_gate_failed(f64::NAN, 0.8, 0.02, 0.8));
        assert!(geometry_gate_failed(0.02, f64::NAN, 0.02, 0.8));
        assert!(geometry_gate_failed(0.019, 0.8, 0.02, 0.8));
        assert!(geometry_gate_failed(0.02, 0.801, 0.02, 0.8));
        assert!(!intrinsic_dimension_gate_failed(9.0, 10.0));
        assert!(!intrinsic_dimension_gate_failed(10.0, 10.0));
        assert!(intrinsic_dimension_gate_failed(10.1, 10.0));
        assert!(intrinsic_dimension_gate_failed(f64::NAN, 10.0));
    }

    #[test]
    fn equal_disconnected_dyads_are_insufficient_not_nominal() {
        let first = pseudo_random_series(128, 7);
        let second = pseudo_random_series(128, 19);
        let channels = vec![
            (Modality::Visual, first.clone()),
            (Modality::Radar, first),
            (Modality::Acoustic, second.clone()),
            (Modality::Lidar, second),
        ];
        let report = analyze(&channels, &confirmed_config()).unwrap();
        assert_eq!(
            report.verdict(),
            &PidVerdict::InsufficientEvidence,
            "{}",
            report.note()
        );
    }

    #[test]
    fn common_scalar_boundaries_are_checked_once_at_construction() {
        fn rejects(update: impl FnOnce(&mut PidParams), expected: PidConfigError) {
            let mut params = PidResearchProfile::PointEstimateOnlyV0_9.params();
            update(&mut params);
            assert_eq!(PidConfig::try_new(params).unwrap_err(), expected);
        }

        rejects(|params| params.window = 3, PidConfigError::WindowOutOfRange);
        rejects(
            |params| params.geom_k = 2,
            PidConfigError::GeometryKTooSmall,
        );
        rejects(
            |params| params.min_samples = params.geom_k,
            PidConfigError::MinimumSamplesOutOfRange,
        );
        rejects(
            |params| params.min_samples = params.window + 1,
            PidConfigError::MinimumSamplesOutOfRange,
        );
        for value in [0.0, f64::NAN] {
            rejects(
                |params| params.observation_noise_std = value,
                PidConfigError::ObservationNoiseInvalid,
            );
            rejects(
                |params| params.id_max = value,
                PidConfigError::IntrinsicDimensionMaximumInvalid,
            );
            rejects(
                |params| params.cv_min = value,
                PidConfigError::DistanceCvMinimumInvalid,
            );
            rejects(
                |params| params.mi_floor = value,
                PidConfigError::MiFloorInvalid,
            );
        }
        for value in [0.0, 1.0 + f64::EPSILON, f64::NAN] {
            rejects(
                |params| params.nn_ratio_max = value,
                PidConfigError::NearestNeighborRatioInvalid,
            );
            rejects(
                |params| params.decouple_ratio = value,
                PidConfigError::DecoupleRatioInvalid,
            );
        }

        let mut minimum = PidResearchProfile::PointEstimateOnlyV0_9.params();
        minimum.window = 4;
        minimum.min_samples = 4;
        minimum.geom_k = 3;
        minimum.observation_noise_std = f64::MIN_POSITIVE;
        minimum.id_max = f64::MIN_POSITIVE;
        minimum.cv_min = f64::MIN_POSITIVE;
        minimum.nn_ratio_max = 1.0;
        minimum.decouple_ratio = 1.0;
        minimum.mi_floor = f64::MIN_POSITIVE;
        let accepted = PidConfig::try_new(minimum).unwrap();
        assert_eq!(accepted.window(), 4);
        assert!(accepted.quadratic_fit_work() <= MAX_QUADRATIC_FIT_WORK);
    }

    #[test]
    fn invalid_confirmation_configuration_is_rejected_at_construction() {
        let mut accepted = confirmed_params();
        accepted.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 100,
            block_size: 16,
            family_alpha: 0.10,
        };
        let accepted = PidConfig::try_new(accepted)
            .expect("retaining more than geom_k samples is valid regardless of the size ratio");
        assert_eq!(
            accepted
                .confirmation()
                .circular_delete_block()
                .expect("the requested confirmation mode is retained")
                .block_size(),
            16
        );

        let mut exact_resample_ceiling = confirmed_params();
        exact_resample_ceiling.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: exact_resample_ceiling.window,
            block_size: 8,
            family_alpha: 0.10,
        };
        let exact_resample_ceiling = PidConfig::try_new(exact_resample_ceiling)
            .expect("one resample per retained window position is valid");
        assert_eq!(
            exact_resample_ceiling
                .confirmation()
                .circular_delete_block()
                .expect("the requested confirmation mode is retained")
                .resamples(),
            exact_resample_ceiling.window()
        );

        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 100,
            block_size: 0,
            family_alpha: 0.10,
        };
        assert_eq!(
            PidConfig::try_new(params).unwrap_err(),
            PidConfigError::ConfirmationBlockSizeInvalid
        );

        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 0,
            block_size: 8,
            family_alpha: 0.10,
        };
        assert_eq!(
            PidConfig::try_new(params).unwrap_err(),
            PidConfigError::ConfirmationResamplesOutOfRange
        );

        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 100,
            block_size: params.min_samples,
            family_alpha: 0.10,
        };
        assert_eq!(
            PidConfig::try_new(params).unwrap_err(),
            PidConfigError::ConfirmationBlockSizeInvalid
        );

        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 100,
            block_size: params.min_samples - params.geom_k,
            family_alpha: 0.10,
        };
        assert_eq!(
            PidConfig::try_new(params).unwrap_err(),
            PidConfigError::ConfirmationBlockSizeInvalid
        );

        let mut params = confirmed_params();
        params.window = 64;
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 100,
            block_size: 8,
            family_alpha: 0.10,
        };
        assert_eq!(
            PidConfig::try_new(params).unwrap_err(),
            PidConfigError::ConfirmationResamplesExceedWindow
        );

        let mut params = confirmed_params();
        params.window = MAX_PID_WINDOW + 1;
        assert_eq!(
            PidConfig::try_new(params).unwrap_err(),
            PidConfigError::WindowOutOfRange
        );

        let mut params = confirmed_params();
        params.window = MAX_PID_WINDOW;
        params.min_samples = MAX_PID_WINDOW;
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 200,
            block_size: 8,
            family_alpha: 0.10,
        };
        assert!(matches!(
            PidConfig::try_new(params),
            Err(PidConfigError::WorkEstimateExceedsLimit { .. })
        ));

        for invalid_alpha in [0.0, 1.0, f64::NAN] {
            let mut params = confirmed_params();
            params.confirmation = PidConfirmationParams::CircularDeleteBlock {
                resamples: 100,
                block_size: 8,
                family_alpha: invalid_alpha,
            };
            assert_eq!(
                PidConfig::try_new(params).unwrap_err(),
                PidConfigError::ConfirmationFamilyAlphaInvalid
            );
        }

        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 100,
            block_size: 8,
            family_alpha: f64::from_bits(1),
        };
        assert!(matches!(
            PidConfig::try_new(params),
            Err(PidConfigError::ConfirmationFamilyAlphaUnderflow { .. })
        ));

        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: MIN_BOOTSTRAP_RESAMPLES,
            block_size: 8,
            family_alpha: 0.01,
        };
        assert!(matches!(
            PidConfig::try_new(params),
            Err(PidConfigError::ConfirmationTailRankUnresolvable {
                resamples: MIN_BOOTSTRAP_RESAMPLES,
                axis_count: 1,
            })
        ));
    }

    #[test]
    fn configuration_rejects_positive_infinite_observation_noise() {
        let mut params = confirmed_params();
        params.observation_noise_std = f64::INFINITY;

        assert_eq!(
            PidConfig::try_new(params).unwrap_err(),
            PidConfigError::ObservationNoiseInvalid
        );
    }

    #[test]
    fn quadratic_preflight_counts_full_report_first_pair_work() {
        let mut params = confirmed_params();
        params.window = 180;
        params.min_samples = 100;
        let config = PidConfig::try_new(params.clone()).unwrap();
        let fits = MAX_PAIR_ESTIMATOR_FITS
            + MAX_ATOM_ESTIMATOR_FITS
            + MAX_CONFIRMATION_EDGE_FITS * PID_CONFIRMATION_EDGE_FIT_UNITS * 100;
        assert_eq!(PID_PAIR_POINT_FIT_UNITS, 6);
        assert_eq!(PID_CONFIRMATION_EDGE_FIT_UNITS, 4);
        assert_eq!(config.window() * config.window() * fits, 198_093_600);
        assert_eq!(config.quadratic_fit_work(), 198_093_600);

        params.window = 181;
        assert!(matches!(
            PidConfig::try_new(params),
            Err(PidConfigError::WorkEstimateExceedsLimit {
                maximum: MAX_QUADRATIC_FIT_WORK,
                ..
            })
        ));
    }

    #[test]
    fn named_profile_resolves_six_modalities_across_three_projection_axes() {
        let config = confirmed_config();
        assert_eq!(config.window(), 128);
        assert_eq!(config.min_samples(), 64);
        assert_eq!(config.observation_noise_std(), 1e-4);
        assert_eq!(config.seed(), 1);
        assert_eq!(config.geom_k(), 5);
        assert_eq!(config.id_max(), 10.0);
        assert_eq!(config.cv_min(), 0.01);
        assert_eq!(config.nn_ratio_max(), 0.999);
        assert_eq!(config.decouple_ratio(), 0.4);
        assert_eq!(config.mi_floor(), 0.03);
        assert_eq!(
            config.source_profile(),
            Some(PidResearchProfile::CircularDeleteBlockV0_9)
        );
        let confirmation = config.confirmation().circular_delete_block().unwrap();
        assert_eq!(confirmation.resamples(), 100);
        assert_eq!(confirmation.block_size(), 8);
        assert_eq!(confirmation.family_alpha(), 0.10);
        assert_eq!(config.confirmation_tail_rank().unwrap(), 5);
        assert_eq!(pair_count(Modality::ALL.len()), 15);
        assert_eq!(MAX_EXCLUDED_CANDIDATES, 2);
        assert_eq!(MAX_CONFIRMATION_EDGE_FITS, 15);
        assert_eq!(CONFIRMATION_BOUND_GROUPS, 2);

        let three_axis = config.try_for_axis_family(3).unwrap();
        assert_eq!(three_axis.confirmation_tail_rank().unwrap(), 1);
        assert_eq!(config.axis_family_count(), 1);
        assert_eq!(three_axis.axis_family_count(), 3);
        assert_eq!(
            config
                .confirmation()
                .circular_delete_block()
                .unwrap()
                .family_alpha(),
            0.10
        );
        assert_eq!(
            three_axis
                .confirmation()
                .circular_delete_block()
                .unwrap()
                .family_alpha(),
            0.10 / 3.0
        );
        assert_eq!(three_axis.source_profile(), config.source_profile());
        let evidence = PidEstimatorEvidence::from_config(&three_axis);
        assert_eq!(evidence.research_profile(), "circular_delete_block_v0_9");
        assert_eq!(evidence.confirmation(), "circular_delete_block");
        assert_eq!(evidence.axis_family_count(), 3);
        assert!(evidence.axis_family_was_derived());
        assert_eq!(evidence.confirmation_family_alpha(), Some(0.10 / 3.0));
        assert_eq!(
            three_axis.try_for_axis_family(2).unwrap_err(),
            PidConfigError::AxisFamilyAlreadyDerived { current: 3 }
        );
        assert!(matches!(
            config.try_for_axis_family(0),
            Err(PidConfigError::AxisCountOutOfRange { requested: 0, .. })
        ));
        let too_many_axes = galadriel_core::MAX_CONSISTENCY_PROJECTION_AXES + 1;
        assert!(matches!(
            config.try_for_axis_family(too_many_axes),
            Err(PidConfigError::AxisCountOutOfRange { requested, .. })
                if requested == too_many_axes
        ));
    }

    #[test]
    fn custom_pid_config_accessors_preserve_every_accepted_scalar() {
        let params = PidParams {
            window: 140,
            min_samples: 70,
            observation_noise_std: 0.002,
            seed: 42,
            geom_k: 6,
            id_max: 9.0,
            cv_min: 0.02,
            nn_ratio_max: 0.8,
            decouple_ratio: 0.3,
            mi_floor: 0.04,
            confirmation: PidConfirmationParams::PointEstimateOnly,
        };
        let config = PidConfig::try_new(params).unwrap();

        assert_eq!(config.window(), 140);
        assert_eq!(config.min_samples(), 70);
        assert_eq!(config.required_samples(), 70);
        assert_eq!(config.observation_noise_std(), 0.002);
        assert_eq!(config.seed(), 42);
        assert_eq!(config.geom_k(), 6);
        assert_eq!(config.id_max(), 9.0);
        assert_eq!(config.cv_min(), 0.02);
        assert_eq!(config.nn_ratio_max(), 0.8);
        assert_eq!(config.decouple_ratio(), 0.3);
        assert_eq!(config.mi_floor(), 0.04);
        assert_eq!(config.confirmation(), &PidConfirmation::PointEstimateOnly);
        assert_eq!(config.source_profile(), None);
        assert_eq!(config.axis_family_count(), 1);
        assert!(!config.axis_family_was_derived());
        assert_eq!(
            config.classification(),
            PidResearchClassification::CustomAcceptedResearch
        );

        let evidence = PidEstimatorEvidence::from_config(&config);
        assert_eq!(evidence.observation_noise_std(), 0.002);
        assert_eq!(evidence.seed(), 42);
        assert_eq!(evidence.geom_k(), 6);
        assert_eq!(evidence.research_profile(), "custom");
        assert_eq!(
            evidence.classification(),
            PidResearchClassification::CustomAcceptedResearch
        );
    }

    #[test]
    fn estimator_channel_and_report_accessors_preserve_complete_evidence() {
        let config = confirmed_config().try_for_axis_family(3).unwrap();
        let evidence = PidEstimatorEvidence::from_config(&config);

        assert_eq!(evidence.config_identity(), config.identity());
        assert_eq!(
            evidence.classification(),
            PidResearchClassification::NamedResearchProfile
        );
        assert_eq!(evidence.pid_rs_version(), PID_RS_VERSION);
        assert_eq!(evidence.pid_rs_revision(), PID_RS_REVISION);
        assert_eq!(
            evidence.pairwise_estimator(),
            "KSG MI (report-first point gate; raw-scalar circular-resample confirmation)"
        );
        assert_eq!(
            evidence.pairwise_scientific_status(),
            "conditional_continuous/restricted_domain point; experimental circular delete-block pipeline"
        );
        assert_eq!(
            evidence.atom_estimator(),
            "continuous shared-exclusions PID2 (Ehrlich KSG)"
        );
        assert_eq!(
            evidence.atom_scientific_status(),
            "experimental_restricted_domain"
        );
        assert_eq!(
            evidence.support_contract(),
            "caller-declared regular full-dimensional continuous law"
        );
        assert_eq!(evidence.pairwise_ksg_k(), PID_KSG_NEIGHBORS);
        assert_eq!(evidence.atom_ksg_k(), PID_KSG_NEIGHBORS);
        assert_eq!(evidence.atom_isx_k(), PID_ISX_NEIGHBORS);
        assert_eq!(evidence.estimator_metric(), "chebyshev");
        assert_eq!(evidence.tie_epsilon(), 0.0);
        assert_eq!(evidence.negative_handling(), "allow");
        assert_eq!(evidence.atom_method(), "ehrlich_ksg");
        assert_eq!(
            evidence.observation_noise_model(),
            "seeded additive Gaussian noise after per-column standardisation"
        );
        assert_eq!(evidence.observation_noise_std(), 1e-4);
        assert_eq!(evidence.seed(), 1);
        assert_eq!(evidence.geom_k(), 5);
        assert_eq!(evidence.research_profile(), "circular_delete_block_v0_9");
        assert_eq!(evidence.confirmation(), "circular_delete_block");
        assert_eq!(evidence.axis_family_count(), 3);
        assert!(evidence.axis_family_was_derived());
        assert_eq!(evidence.confirmation_family_alpha(), Some(0.10 / 3.0));
        assert!(evidence.pairwise_reports().is_empty());

        let channel = ChannelPid::new(
            Modality::Thermal,
            73,
            true,
            "exact gate note".to_owned(),
            Some(0.7),
            Some(0.2),
            Some(0.3),
            true,
            Some((-0.4, -0.1)),
        );
        assert_eq!(channel.modality(), Modality::Thermal);
        assert_eq!(channel.n(), 73);
        assert!(channel.gate_ok());
        assert_eq!(channel.gate_note(), "exact gate note");
        assert_eq!(channel.corroboration(), Some(0.7));
        assert_eq!(channel.redundancy(), Some(0.2));
        assert_eq!(channel.synergy(), Some(0.3));
        assert!(channel.is_decoupled());
        assert_eq!(channel.confirmation_interval(), Some((-0.4, -0.1)));

        let rejected_gate = ChannelPid::new(
            Modality::Radar,
            2,
            false,
            "independent rejected gate".to_owned(),
            None,
            None,
            None,
            false,
            None,
        );
        assert_eq!(rejected_gate.n(), 2);
        assert!(!rejected_gate.gate_ok());
        assert_eq!(rejected_gate.gate_note(), "independent rejected gate");

        let verdict = PidVerdict::Decoupled(vec![Modality::Thermal]);
        let report = PidReport::new(
            evidence.clone(),
            vec![channel],
            verdict.clone(),
            "exact PID report note".to_owned(),
        );
        assert_eq!(report.estimator(), &evidence);
        assert_eq!(report.channels().len(), 1);
        assert_eq!(report.channels()[0].modality(), Modality::Thermal);
        assert_eq!(report.verdict(), &verdict);
        assert_eq!(report.note(), "exact PID report note");
    }

    #[test]
    fn pid_configuration_identity_is_complete_and_profile_distinct() {
        let named = confirmed_config();
        let named_identity = named.identity();
        let custom =
            PidConfig::try_new(PidResearchProfile::CircularDeleteBlockV0_9.params()).unwrap();
        let derived = named.try_for_axis_family(3).unwrap();
        let point = point_config();

        assert_eq!(named.identity(), named_identity);
        assert_ne!(custom.identity(), named_identity);
        assert_ne!(derived.identity(), named_identity);
        assert_ne!(point.identity(), named_identity);
        assert_eq!(
            PidEstimatorEvidence::from_config(&derived).config_identity(),
            derived.identity()
        );
        assert_eq!(
            named_identity.to_hex(),
            "3e0d507b46139df7e613f4467420ff337316a4246b17725d388c1a244b379c88"
        );
    }

    #[test]
    fn every_pid_scalar_and_confirmation_payload_changes_identity() {
        let base_params = PidResearchProfile::PointEstimateOnlyV0_9.params();
        let baseline = PidConfig::try_new(base_params.clone()).unwrap().identity();
        let mutations: [fn(&mut PidParams); 10] = [
            |params| params.window += 1,
            |params| params.min_samples += 1,
            |params| params.observation_noise_std *= 2.0,
            |params| params.seed += 1,
            |params| params.geom_k += 1,
            |params| params.id_max += 1.0,
            |params| params.cv_min *= 2.0,
            |params| params.nn_ratio_max -= 0.01,
            |params| params.decouple_ratio -= 0.01,
            |params| params.mi_floor += 0.01,
        ];
        for mutation in mutations {
            let mut params = base_params.clone();
            mutation(&mut params);
            assert_ne!(PidConfig::try_new(params).unwrap().identity(), baseline);
        }

        let confirmation_base = confirmed_params();
        let confirmation_identity = PidConfig::try_new(confirmation_base.clone())
            .unwrap()
            .identity();
        for confirmation in [
            PidConfirmationParams::CircularDeleteBlock {
                resamples: 101,
                block_size: 8,
                family_alpha: 0.10,
            },
            PidConfirmationParams::CircularDeleteBlock {
                resamples: 100,
                block_size: 9,
                family_alpha: 0.10,
            },
            PidConfirmationParams::CircularDeleteBlock {
                resamples: 100,
                block_size: 8,
                family_alpha: 0.11,
            },
        ] {
            let mut params = confirmation_base.clone();
            params.confirmation = confirmation;
            assert_ne!(
                PidConfig::try_new(params).unwrap().identity(),
                confirmation_identity
            );
        }
    }

    #[test]
    fn point_mode_has_no_dormant_confirmation_payload_or_repeat_derivation() {
        let point = point_config();
        assert!(matches!(
            point.confirmation(),
            PidConfirmation::PointEstimateOnly
        ));
        assert_eq!(point.confirmation().name(), "point_estimate_only");
        assert_eq!(
            confirmed_config().confirmation().name(),
            "circular_delete_block"
        );
        assert_eq!(point.required_samples(), point.min_samples());
        assert_eq!(point.confirmation_tail_rank(), None);
        assert!(!point.axis_family_was_derived());
        let evidence = PidEstimatorEvidence::from_config(&point);
        assert_eq!(evidence.research_profile(), "point_estimate_only_v0_9");
        assert_eq!(evidence.confirmation(), "point_estimate_only");
        assert_eq!(evidence.confirmation_family_alpha(), None);
        assert!(!evidence.axis_family_was_derived());

        let derived = point.try_for_axis_family(1).unwrap();
        assert!(derived.axis_family_was_derived());
        assert_eq!(derived.axis_family_count(), 1);
        assert_eq!(derived.source_profile(), point.source_profile());
        assert_eq!(
            derived.try_for_axis_family(1).unwrap_err(),
            PidConfigError::AxisFamilyAlreadyDerived { current: 1 }
        );

        let same_values_without_profile =
            PidConfig::try_new(PidResearchProfile::PointEstimateOnlyV0_9.params()).unwrap();
        assert_eq!(same_values_without_profile.source_profile(), None);
    }

    #[test]
    fn named_profile_locks_upstream_estimator_semantics() {
        let config = confirmed_config();
        let intrinsic = intrinsic_dimension_config(&config);
        assert_eq!(intrinsic.k, 5);
        assert_eq!(intrinsic.metric, Metric::Chebyshev);

        let concentration = DistanceConcentrationConfig::default();
        assert_eq!(concentration.metric, Metric::Chebyshev);

        let mut custom_params = PidResearchProfile::PointEstimateOnlyV0_9.params();
        custom_params.geom_k = 6;
        let custom = PidConfig::try_new(custom_params).unwrap();
        assert_eq!(intrinsic_dimension_config(&custom).k, 6);

        let ksg = ksg_estimator_config();
        assert_eq!(ksg.k, PID_KSG_NEIGHBORS);
        assert_eq!(ksg.metric, Metric::Chebyshev);
        assert_eq!(ksg.tie_epsilon, 0.0);
        assert_eq!(ksg.negative_handling, NegativeHandling::Allow);
        assert!(matches!(
            ksg.support_contract,
            SupportContract::AssumeRegularFullDimensional { .. }
        ));

        let pid2 = pid2_estimator_config();
        assert_eq!(pid2.ksg.k, PID_KSG_NEIGHBORS);
        assert_eq!(pid2.isx.k, PID_ISX_NEIGHBORS);
        assert_eq!(pid2.isx.metric, Metric::Chebyshev);
        assert_eq!(pid2.isx.tie_epsilon, 0.0);
        assert_eq!(pid2.isx.method, IsxMethod::EhrlichKsg);

        let jitter = Jitter::new(config.observation_noise_std(), config.seed()).unwrap();
        assert_eq!(jitter.std(), 1e-4);

        let evidence = PidEstimatorEvidence::from_config(&config);
        assert_eq!(evidence.pairwise_ksg_k(), PID_KSG_NEIGHBORS);
        assert_eq!(evidence.atom_ksg_k(), PID_KSG_NEIGHBORS);
        assert_eq!(evidence.atom_isx_k(), PID_ISX_NEIGHBORS);
        assert_eq!(evidence.estimator_metric(), "chebyshev");
        assert_eq!(evidence.tie_epsilon(), 0.0);
        assert_eq!(evidence.negative_handling(), "allow");
        assert_eq!(evidence.atom_method(), "ehrlich_ksg");
    }

    #[test]
    fn accepted_parameter_grid_never_exceeds_checked_work_bound() {
        for window in [64, 100, 128, 160, 180, MAX_PID_WINDOW] {
            for resamples in [20, 40, 64, 100] {
                if resamples > window {
                    continue;
                }
                let mut params = confirmed_params();
                params.window = window;
                params.min_samples = 64.min(window);
                params.confirmation = PidConfirmationParams::CircularDeleteBlock {
                    resamples,
                    block_size: 8,
                    family_alpha: 0.10,
                };
                if let Ok(config) = PidConfig::try_new(params) {
                    assert!(config.quadratic_fit_work() <= MAX_QUADRATIC_FIT_WORK);
                }
            }
        }
    }

    #[test]
    fn bootstrap_never_flags_a_clean_stream() {
        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 40,
            block_size: 8,
            family_alpha: 0.10,
        };
        let config = PidConfig::try_new(params).unwrap();
        for seed in [7, 11, 23] {
            let scenario = scen(seed);
            let stream = generate(&scenario).unwrap();
            let channels = scalar_channels(&stream, scenario.modalities(), 0).unwrap();
            let report = analyze(&channels, &config).unwrap();
            assert_eq!(
                report.verdict(),
                &PidVerdict::Nominal,
                "seed {seed}: {}",
                report.note()
            );
        }
    }

    #[test]
    fn bootstrap_is_a_fail_closed_subset_of_point_estimates() {
        let scenario = scen(7);
        let stream = generate_spoofed(
            &scenario,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: scenario.frames() as u64 / 3,
            },
        )
        .unwrap();
        let channels = scalar_channels(&stream, scenario.modalities(), 0).unwrap();
        let point = analyze(&channels, &point_config()).unwrap();
        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: 40,
            block_size: 8,
            family_alpha: 0.10,
        };
        let bootstrap = analyze(&channels, &PidConfig::try_new(params).unwrap()).unwrap();

        let point_flagged: HashSet<Modality> = point
            .channels()
            .iter()
            .filter(|channel| channel.is_decoupled())
            .map(ChannelPid::modality)
            .collect();
        for channel in bootstrap
            .channels()
            .iter()
            .filter(|channel| channel.is_decoupled())
        {
            assert!(point_flagged.contains(&channel.modality()));
            assert!(channel.confirmation_interval().is_some());
        }
        if !matches!(bootstrap.verdict(), PidVerdict::Decoupled(_)) {
            assert!(bootstrap
                .channels()
                .iter()
                .all(|channel| !channel.is_decoupled()));
        }
    }

    #[test]
    fn modality_permutation_preserves_point_atoms_and_bootstrap_intervals() {
        let scenario = scen(23);
        let stream = generate_spoofed(
            &scenario,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: scenario.frames() as u64 / 3,
            },
        )
        .unwrap();
        let channels = scalar_channels(&stream, scenario.modalities(), 0).unwrap();
        let config = point_config();
        let original = analyze(&channels, &config).unwrap();
        let mut permuted = channels.clone();
        permuted.rotate_left(1);
        permuted.reverse();
        let reordered = analyze(&permuted, &config).unwrap();

        assert_eq!(original.verdict(), reordered.verdict());
        assert_eq!(original.note(), reordered.note());
        for (modality, _) in &channels {
            let left = original
                .channels()
                .iter()
                .find(|channel| channel.modality() == *modality)
                .unwrap();
            let right = reordered
                .channels()
                .iter()
                .find(|channel| channel.modality() == *modality)
                .unwrap();
            assert_eq!(left.gate_note(), right.gate_note());
            assert_eq!(
                left.corroboration().map(f64::to_bits),
                right.corroboration().map(f64::to_bits)
            );
            assert_eq!(
                left.redundancy().map(f64::to_bits),
                right.redundancy().map(f64::to_bits)
            );
            assert_eq!(
                left.synergy().map(f64::to_bits),
                right.synergy().map(f64::to_bits)
            );
        }

        let mut params = confirmed_params();
        params.confirmation = PidConfirmationParams::CircularDeleteBlock {
            resamples: MIN_BOOTSTRAP_RESAMPLES,
            block_size: 8,
            family_alpha: 0.10,
        };
        let bootstrap = PidConfig::try_new(params).unwrap();
        let plans = delete_block_plans(&bootstrap, channels[0].1.len(), &channels).unwrap();
        let reordered_plans =
            delete_block_plans(&bootstrap, permuted[0].1.len(), &permuted).unwrap();
        assert_eq!(plans, reordered_plans);
        let first = bootstrap_mi_series(
            &bootstrap,
            channels[0].0,
            &channels[0].1,
            channels[1].0,
            &channels[1].1,
            &plans,
        )
        .unwrap();
        let reversed = bootstrap_mi_series(
            &bootstrap,
            channels[1].0,
            &channels[1].1,
            channels[0].0,
            &channels[0].1,
            &plans,
        )
        .unwrap();
        assert_eq!(
            first
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            reversed
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>()
        );
    }
}
