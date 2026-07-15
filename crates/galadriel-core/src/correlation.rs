//! The cheap, pure cross-sensor consistency check: signed pairwise **Pearson correlation**.
//!
//! This is galadriel's **default** cross-channel detector. The controlled synthetic
//! studies described in `docs/JUSTIFICATION.md` compare it with the optional MI/PID
//! engine under explicitly generated linear and nonlinear dependence. Those studies
//! do not establish equivalence, operational accuracy, or coverage of a deployed
//! residual distribution. Correlation remains the default because it is inexpensive,
//! signed, and interpretable; MI/PID is an opt-in research diagnostic.
//!
//! Like the PID engine, it builds pairwise evidence and requires a unique positive
//! strict-majority consensus before attributing an outsider. The statistics and
//! confirmation procedures differ, so their scores are comparable only within the
//! explicitly documented evaluation protocol (see `galadriel-eval`).

use std::{cmp::Ordering, error::Error, fmt};

use serde::Serialize;

use crate::identity::IdentityBuilder;
use crate::observation::Modality;
use crate::{ConfigDigest, ConfigurationClass};

/// Largest tail window accepted by the correlation detector.
pub const MAX_CORRELATION_WINDOW: usize = 65_536;

/// Maximum pair-sample products evaluated in one correlation assessment.
///
/// For the current six modalities this admits the full maximum window while
/// retaining a separate work bound if the modality set grows in the future.
pub const MAX_CORRELATION_PAIR_SAMPLES: usize = 1_000_000;

/// Maximum family-wise correction performed by the default fused assessment:
/// every pair among all modalities on every producer-supported projection axis.
const MAX_FUSED_CORRELATION_TESTS: usize =
    crate::MAX_CONSISTENCY_PROJECTION_AXES * (Modality::ALL.len() * (Modality::ALL.len() - 1) / 2);

const MIN_CORRELATION_WINDOW: usize = 4;
const MAX_CORRELATION_CHANNELS: usize = Modality::ALL.len();
const MAX_CORRELATION_PAIRS: usize = MAX_CORRELATION_CHANNELS * (MAX_CORRELATION_CHANNELS - 1) / 2;

/// Unvalidated boundary values for constructing a [`CorrConfig`].
///
/// This record is not accepted detector configuration. Pass the complete value
/// to [`CorrConfig::try_new`] before use.
#[derive(Debug, Clone, PartialEq)]
pub struct CorrParams {
    /// Window length (frames) analysed, taken from each channel's tail.
    pub window: usize,
    /// Minimum aligned samples per channel before a verdict is trusted.
    pub min_samples: usize,
    /// A channel is flagged decoupled if its corroboration falls below
    /// `decouple_ratio × the strongest corroboration in the group`.
    pub decouple_ratio: f64,
    /// …and only when that strongest corroboration clears this floor (there is a
    /// genuine linear consensus to have decoupled from).
    pub corr_floor: f64,
    /// Per-assessment family-wise false-consensus bound under the approximate
    /// Fisher-z null, Bonferroni-corrected across all channel pairs.
    pub family_alpha: f64,
}

impl CorrParams {
    /// Returns the explicitly named 0.9 standalone-advisory release values.
    ///
    /// These raw values still pass through [`CorrConfig::try_new`] before use.
    pub fn standalone_advisory_v0_9() -> Self {
        Self {
            window: 128,
            min_samples: 64,
            decouple_ratio: 0.4,
            corr_floor: 0.15,
            family_alpha: 0.01,
        }
    }
}

/// Closed, versioned correlation profiles shipped by the 0.9 source release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrProfile {
    /// Signed-correlation settings for the standalone advisory release suite.
    StandaloneAdvisoryV0_9,
}

impl CorrProfile {
    /// Stable machine-readable profile name retained by accepted configs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::StandaloneAdvisoryV0_9 => "standalone_advisory_v0_9",
        }
    }

    /// Returns this profile's raw parameter template.
    pub fn params(self) -> CorrParams {
        match self {
            Self::StandaloneAdvisoryV0_9 => CorrParams::standalone_advisory_v0_9(),
        }
    }

    /// Resolves this named profile through the normal validation boundary.
    ///
    /// # Errors
    ///
    /// Returns [`CorrConfigError`] if a future invariant change makes the
    /// versioned profile invalid rather than silently substituting values.
    pub fn try_config(self) -> Result<CorrConfig, CorrConfigError> {
        CorrConfig::try_new_with_identity(self.params(), Some(self), AxisFamilyIdentity::Unadjusted)
    }
}

/// Typed rejection from correlation configuration construction or derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrConfigError {
    /// The tail window is outside the fixed allocation domain.
    WindowOutOfRange,
    /// The minimum sample count is incompatible with the accepted window.
    MinimumSamplesOutOfRange,
    /// The relative decoupling threshold is outside `(0, 1]`.
    DecoupleRatioInvalid,
    /// The absolute correlation floor is outside `(0, 1]`.
    CorrelationFloorInvalid,
    /// The family-wise probability is outside `(0, 1)`.
    FamilyAlphaInvalid,
    /// Dividing the family budget underflowed to zero.
    FamilyAlphaUnderflow { divisor: usize },
    /// The corrected tail probability cannot produce a finite, usable Fisher floor.
    FamilyAlphaResolutionInsufficient {
        correction_count: usize,
        min_samples: usize,
    },
    /// The projection-axis family count is outside the fixed protocol domain.
    AxisCountOutOfRange { requested: usize, maximum: usize },
    /// A family split was requested from an already-derived config.
    AxisFamilyAlreadyDerived { current: usize },
    /// A checked channel-pair or pair-sample calculation overflowed.
    WorkEstimateOverflow,
    /// The conservative pair-sample ceiling would be exceeded.
    WorkEstimateExceedsLimit { requested: usize, maximum: usize },
}

impl fmt::Display for CorrConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowOutOfRange => write!(
                formatter,
                "correlation window must be in {MIN_CORRELATION_WINDOW}..={MAX_CORRELATION_WINDOW}"
            ),
            Self::MinimumSamplesOutOfRange => write!(
                formatter,
                "correlation min_samples must be in {MIN_CORRELATION_WINDOW}..=window"
            ),
            Self::DecoupleRatioInvalid => formatter
                .write_str("correlation decouple_ratio must be finite and in (0, 1]"),
            Self::CorrelationFloorInvalid => formatter
                .write_str("correlation corr_floor must be finite and in (0, 1]"),
            Self::FamilyAlphaInvalid => formatter
                .write_str("correlation family_alpha must be finite and in (0, 1)"),
            Self::FamilyAlphaUnderflow { divisor } => write!(
                formatter,
                "correlation family_alpha underflows when divided by {divisor} family members"
            ),
            Self::FamilyAlphaResolutionInsufficient {
                correction_count,
                min_samples,
            } => write!(
                formatter,
                "correlation family_alpha cannot resolve a finite usable Fisher floor after {correction_count} corrections at min_samples={min_samples}"
            ),
            Self::AxisCountOutOfRange { requested, maximum } => write!(
                formatter,
                "correlation projection-axis family count must be in 1..={maximum}, got {requested}"
            ),
            Self::AxisFamilyAlreadyDerived { current } => write!(
                formatter,
                "correlation family budget is already derived across {current} projection axes"
            ),
            Self::WorkEstimateOverflow => {
                formatter.write_str("correlation checked pair-sample work estimate overflowed")
            }
            Self::WorkEstimateExceedsLimit { requested, maximum } => write!(
                formatter,
                "correlation assessment requires {requested} pair-samples; maximum is {maximum}"
            ),
        }
    }
}

impl Error for CorrConfigError {}

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

/// Immutable, fully validated signed-correlation configuration.
///
/// Construction is `O(1)` time and retains `O(1)` memory. Assessment preflight
/// checks `pairs(channel_count) * min(input_tail, window)` against
/// [`MAX_CORRELATION_PAIR_SAMPLES`] before matrix allocation or pair evaluation.
///
/// Accepted configs cannot be fabricated or modified by callers:
///
/// ```compile_fail
/// use galadriel_core::CorrConfig;
/// let _ = CorrConfig { window: 128 };
/// ```
///
/// ```compile_fail
/// use galadriel_core::CorrConfig;
/// let mut config = CorrConfig::standalone_advisory_v0_9().unwrap();
/// config.family_alpha = 0.5;
/// ```
///
/// ```compile_fail
/// use galadriel_core::CorrConfig;
/// let _: CorrConfig = Default::default();
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct CorrConfig {
    window: usize,
    min_samples: usize,
    decouple_ratio: f64,
    corr_floor: f64,
    family_alpha: f64,
    source_profile: Option<CorrProfile>,
    axis_family: AxisFamilyIdentity,
}

impl CorrConfig {
    /// Validates raw parameters and constructs an immutable accepted config.
    ///
    /// # Errors
    ///
    /// Returns [`CorrConfigError`] for an invalid scalar, cross-field relation,
    /// probability-domain value, or family-correction underflow.
    pub fn try_new(params: CorrParams) -> Result<Self, CorrConfigError> {
        Self::try_new_with_identity(params, None, AxisFamilyIdentity::Unadjusted)
    }

    fn try_new_with_identity(
        params: CorrParams,
        source_profile: Option<CorrProfile>,
        axis_family: AxisFamilyIdentity,
    ) -> Result<Self, CorrConfigError> {
        let axis_count = axis_family.axis_count();
        let maximum_axes = crate::MAX_CONSISTENCY_PROJECTION_AXES;
        if !(1..=maximum_axes).contains(&axis_count) {
            return Err(CorrConfigError::AxisCountOutOfRange {
                requested: axis_count,
                maximum: maximum_axes,
            });
        }
        if !(MIN_CORRELATION_WINDOW..=MAX_CORRELATION_WINDOW).contains(&params.window) {
            return Err(CorrConfigError::WindowOutOfRange);
        }
        if !(MIN_CORRELATION_WINDOW..=params.window).contains(&params.min_samples) {
            return Err(CorrConfigError::MinimumSamplesOutOfRange);
        }
        if !params.decouple_ratio.is_finite()
            || params.decouple_ratio <= 0.0
            || params.decouple_ratio > 1.0
        {
            return Err(CorrConfigError::DecoupleRatioInvalid);
        }
        if !params.corr_floor.is_finite() || params.corr_floor <= 0.0 || params.corr_floor > 1.0 {
            return Err(CorrConfigError::CorrelationFloorInvalid);
        }
        if !params.family_alpha.is_finite()
            || params.family_alpha <= 0.0
            || params.family_alpha >= 1.0
        {
            return Err(CorrConfigError::FamilyAlphaInvalid);
        }
        let correction_count = match axis_family {
            AxisFamilyIdentity::Unadjusted => MAX_FUSED_CORRELATION_TESTS,
            AxisFamilyIdentity::Derived { .. } => MAX_CORRELATION_PAIRS,
        };
        if params.family_alpha / correction_count as f64 == 0.0 {
            return Err(CorrConfigError::FamilyAlphaUnderflow {
                divisor: correction_count,
            });
        }
        validate_family_resolution(params.family_alpha, correction_count, params.min_samples)?;
        Ok(Self {
            window: params.window,
            min_samples: params.min_samples,
            decouple_ratio: params.decouple_ratio,
            corr_floor: params.corr_floor,
            family_alpha: params.family_alpha,
            source_profile,
            axis_family,
        })
    }

    /// Constructs the named standalone-advisory 0.9 release profile.
    ///
    /// # Errors
    ///
    /// Returns [`CorrConfigError`] if a future invariant change makes the
    /// versioned profile invalid.
    pub fn standalone_advisory_v0_9() -> Result<Self, CorrConfigError> {
        CorrProfile::StandaloneAdvisoryV0_9.try_config()
    }

    /// Returns a new accepted config with its family budget split across axes.
    ///
    /// The source is not mutated. A derived config cannot be divided again,
    /// preventing an accidental double correction.
    ///
    /// # Errors
    ///
    /// Returns [`CorrConfigError`] for an invalid axis count, floating-point
    /// underflow, or repeated derivation.
    pub fn try_for_axis_family(&self, axis_count: usize) -> Result<Self, CorrConfigError> {
        if let AxisFamilyIdentity::Derived { axis_count } = self.axis_family {
            return Err(CorrConfigError::AxisFamilyAlreadyDerived {
                current: axis_count,
            });
        }
        let maximum_axes = crate::MAX_CONSISTENCY_PROJECTION_AXES;
        if !(1..=maximum_axes).contains(&axis_count) {
            return Err(CorrConfigError::AxisCountOutOfRange {
                requested: axis_count,
                maximum: maximum_axes,
            });
        }
        let family_alpha = self.family_alpha / axis_count as f64;
        if family_alpha == 0.0 {
            return Err(CorrConfigError::FamilyAlphaUnderflow {
                divisor: axis_count,
            });
        }
        Self::try_new_with_identity(
            CorrParams {
                window: self.window,
                min_samples: self.min_samples,
                decouple_ratio: self.decouple_ratio,
                corr_floor: self.corr_floor,
                family_alpha,
            },
            self.source_profile,
            AxisFamilyIdentity::Derived { axis_count },
        )
    }

    /// Analysis tail-window length.
    pub const fn window(&self) -> usize {
        self.window
    }

    /// Minimum aligned samples required before a verdict is trusted.
    pub const fn min_samples(&self) -> usize {
        self.min_samples
    }

    /// Relative corroboration threshold used to identify an outsider.
    pub const fn decouple_ratio(&self) -> f64 {
        self.decouple_ratio
    }

    /// Absolute positive-correlation floor for a candidate consensus.
    pub const fn corr_floor(&self) -> f64 {
        self.corr_floor
    }

    /// Effective family-wise probability budget after any axis split.
    pub const fn family_alpha(&self) -> f64 {
        self.family_alpha
    }

    /// Named source profile when this config originated from one.
    pub const fn source_profile(&self) -> Option<CorrProfile> {
        self.source_profile
    }

    /// Number of projection axes sharing the family budget.
    pub const fn axis_family_count(&self) -> usize {
        self.axis_family.axis_count()
    }

    /// Whether [`Self::try_for_axis_family`] produced this accepted config.
    pub const fn axis_family_was_derived(&self) -> bool {
        self.axis_family.was_derived()
    }

    /// Named-release or custom classification retained by this accepted component.
    pub const fn classification(&self) -> ConfigurationClass {
        if self.source_profile.is_some() {
            ConfigurationClass::NamedRelease
        } else {
            ConfigurationClass::CustomAccepted
        }
    }

    /// Canonical complete identity of this accepted configuration and derivation.
    pub fn identity(&self) -> ConfigDigest {
        let mut identity = IdentityBuilder::new(b"galadriel-correlation-config-v1");
        identity.u8(
            b"classification",
            match self.classification() {
                ConfigurationClass::NamedRelease => 1,
                ConfigurationClass::CustomAccepted => 2,
            },
        );
        identity.u8(
            b"source_profile",
            match self.source_profile {
                Some(CorrProfile::StandaloneAdvisoryV0_9) => 1,
                None => 0,
            },
        );
        identity.usize(b"window", self.window);
        identity.usize(b"min_samples", self.min_samples);
        identity.f64(b"decouple_ratio", self.decouple_ratio);
        identity.f64(b"corr_floor", self.corr_floor);
        identity.f64(b"family_alpha", self.family_alpha);
        identity.u8(
            b"axis_family_derived",
            if self.axis_family.was_derived() { 1 } else { 0 },
        );
        identity.usize(b"axis_family_count", self.axis_family.axis_count());
        identity.finish()
    }

    fn preflight_assessment(
        &self,
        channel_count: usize,
        input_tail: usize,
    ) -> Result<(usize, usize), CorrConfigError> {
        let window = input_tail.min(self.window);
        let pair_count = channel_count
            .checked_mul(channel_count.saturating_sub(1))
            .map(|ordered_pairs| ordered_pairs / 2)
            .ok_or(CorrConfigError::WorkEstimateOverflow)?;
        let pair_samples = pair_count
            .checked_mul(window)
            .ok_or(CorrConfigError::WorkEstimateOverflow)?;
        if matches!(
            pair_samples.cmp(&MAX_CORRELATION_PAIR_SAMPLES),
            Ordering::Greater
        ) {
            return Err(CorrConfigError::WorkEstimateExceedsLimit {
                requested: pair_samples,
                maximum: MAX_CORRELATION_PAIR_SAMPLES,
            });
        }
        Ok((window, pair_count))
    }
}

fn validate_family_resolution(
    family_alpha: f64,
    correction_count: usize,
    min_samples: usize,
) -> Result<(), CorrConfigError> {
    let corrected_alpha = family_alpha / correction_count as f64;
    let quantile_probability = 1.0 - corrected_alpha;
    if quantile_probability >= 1.0 {
        return Err(CorrConfigError::FamilyAlphaResolutionInsufficient {
            correction_count,
            min_samples,
        });
    }
    let z = statrs::distribution::ContinuousCDF::inverse_cdf(
        &statrs::distribution::Normal::standard(),
        quantile_probability,
    );
    // `min_samples >= 4`, and the largest finite inverse-normal value reachable
    // from an f64 probability below one is about 8.21. Therefore a finite `z`
    // also proves that `tanh(z / sqrt(min_samples - 3))` is finite and strictly
    // below one; repeating that derived calculation here adds no independent gate.
    if !z.is_finite() {
        return Err(CorrConfigError::FamilyAlphaResolutionInsufficient {
            correction_count,
            min_samples,
        });
    }
    Ok(())
}

fn corrected_pair_alpha(family_alpha: f64, pair_count: usize) -> f64 {
    family_alpha / pair_count.max(1) as f64
}

fn significance_floor_is_usable(significance_floor: f64) -> bool {
    significance_floor.is_finite() && significance_floor < 1.0
}

fn relative_decoupling_floor(decouple_ratio: f64, reference: f64) -> f64 {
    decouple_ratio * reference
}

fn is_unique_strict_majority(
    largest_size: usize,
    channel_count: usize,
    tied_largest_cliques: usize,
) -> bool {
    largest_size > channel_count / 2 && tied_largest_cliques == 1
}

impl TryFrom<CorrParams> for CorrConfig {
    type Error = CorrConfigError;

    fn try_from(params: CorrParams) -> Result<Self, Self::Error> {
        Self::try_new(params)
    }
}

/// Per-channel correlation detail.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CorrChannel {
    /// Which modality.
    modality: Modality,
    /// Aligned samples used.
    n: usize,
    /// Corroboration: the channel's best signed pairwise `ρ` with any peer.
    corroboration: Option<f64>,
    /// Whether it was flagged decoupled.
    decoupled: bool,
}

impl CorrChannel {
    /// Channel modality.
    pub const fn modality(&self) -> Modality {
        self.modality
    }
    /// Aligned sample count.
    pub const fn n(&self) -> usize {
        self.n
    }
    /// Best signed pairwise corroboration, if defined.
    pub const fn corroboration(&self) -> Option<f64> {
        self.corroboration
    }
    /// Whether this channel is outside the admitted consensus clique.
    pub const fn decoupled(&self) -> bool {
        self.decoupled
    }
}

/// The correlation verdict (same shape as the PID engine's).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "verdict", content = "channels", rename_all = "snake_case")]
pub enum CorrVerdict {
    /// All ready channels belong to one strict-majority positive-consensus clique.
    Nominal,
    /// One or a minority of channels decoupled (low signed `ρ` with every member
    /// of the positive-consensus clique). This identifies statistical structure,
    /// not an attack cause.
    Decoupled(Vec<Modality>),
    /// Too few channels/samples or no consensus. Fail closed.
    InsufficientEvidence,
}

/// The full report.
///
/// The report is output-only and cannot be deserialized or fabricated by an
/// external caller. Only [`analyze`] creates an accepted report.
///
/// ```compile_fail
/// use galadriel_core::{CorrReport, CorrVerdict};
/// let _ = CorrReport { channels: Vec::new(), verdict: CorrVerdict::Nominal, note: String::new() };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CorrReport {
    /// Per-channel detail.
    channels: Vec<CorrChannel>,
    /// The verdict.
    verdict: CorrVerdict,
    /// Rationale.
    note: String,
    /// Complete accepted correlation-config identity.
    config_identity: ConfigDigest,
    /// Named-release or custom accepted classification.
    classification: ConfigurationClass,
    /// Named source profile, if present.
    source_profile: Option<CorrProfile>,
    /// Projection-axis family count represented by the effective config.
    axis_family_count: usize,
    /// Whether the effective family budget was derived for projection axes.
    axis_family_derived: bool,
}

impl CorrReport {
    fn new(
        channels: Vec<CorrChannel>,
        verdict: CorrVerdict,
        note: String,
        config: &CorrConfig,
    ) -> Self {
        Self {
            channels,
            verdict,
            note,
            config_identity: config.identity(),
            classification: config.classification(),
            source_profile: config.source_profile(),
            axis_family_count: config.axis_family_count(),
            axis_family_derived: config.axis_family_was_derived(),
        }
    }

    /// Per-channel details in input modality order.
    pub fn channels(&self) -> &[CorrChannel] {
        &self.channels
    }
    /// Correlation verdict.
    pub const fn verdict(&self) -> &CorrVerdict {
        &self.verdict
    }
    /// Human-readable, non-normative rationale.
    pub fn note(&self) -> &str {
        &self.note
    }
    /// Canonical complete accepted correlation-config identity.
    pub const fn config_identity(&self) -> ConfigDigest {
        self.config_identity
    }
    /// Named-release or custom accepted classification.
    pub const fn classification(&self) -> ConfigurationClass {
        self.classification
    }
    /// Named source profile, if any.
    pub const fn source_profile(&self) -> Option<CorrProfile> {
        self.source_profile
    }
    /// Effective projection-axis family count.
    pub const fn axis_family_count(&self) -> usize {
        self.axis_family_count
    }
    /// Whether the family budget was derived for projection axes.
    pub const fn axis_family_was_derived(&self) -> bool {
        self.axis_family_derived
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(verdict: CorrVerdict) -> Self {
        let config = CorrConfig::standalone_advisory_v0_9().expect("test correlation config");
        Self::new(Vec::new(), verdict, "test fixture".to_string(), &config)
    }
}

/// Signed Pearson correlation of two equal-length finite series no longer than
/// [`MAX_CORRELATION_WINDOW`].
///
/// Each column is independently scaled before centering so large but finite input
/// cannot overflow the mean, variance, or covariance. Constant or numerically
/// degenerate columns are undefined for Pearson correlation and return an error;
/// they are never fabricated into a low edge that could accuse a channel.
pub fn pearson(x: &[f64], y: &[f64]) -> crate::Result<f64> {
    if x.len() != y.len() {
        return Err(crate::GaladrielError::InvalidChannels(format!(
            "Pearson columns must have equal length ({} != {})",
            x.len(),
            y.len()
        )));
    }
    if x.is_empty() {
        return Err(crate::GaladrielError::InvalidChannels(
            "Pearson columns must not be empty".into(),
        ));
    }
    if x.len() > MAX_CORRELATION_WINDOW {
        return Err(crate::GaladrielError::InvalidChannels(format!(
            "Pearson columns contain {} samples; maximum is {MAX_CORRELATION_WINDOW}",
            x.len()
        )));
    }
    if !x.iter().chain(y).all(|value| value.is_finite()) {
        return Err(crate::GaladrielError::NonFinite("Pearson input"));
    }
    let n = x.len();
    let bounds = |values: &[f64]| {
        values.iter().copied().fold(
            (f64::INFINITY, f64::NEG_INFINITY),
            |(minimum, maximum), value| (minimum.min(value), maximum.max(value)),
        )
    };
    let ((x_min, x_max), (y_min, y_max)) = (bounds(x), bounds(y));
    if x_min == x_max || y_min == y_max {
        return Err(crate::GaladrielError::InvalidChannels(
            "Pearson columns must be non-degenerate".into(),
        ));
    }
    // Range-center before accumulating. Unlike scaling by max(|x|), this is
    // translation invariant: a large finite offset cannot erase small but
    // representable variation. The midpoint formula cannot overflow.
    let x_center = x_min / 2.0 + x_max / 2.0;
    let y_center = y_min / 2.0 + y_max / 2.0;
    let x_scale = (x_min - x_center).abs().max((x_max - x_center).abs());
    let y_scale = (y_min - y_center).abs().max((y_max - y_center).abs());
    let nf = n as f64;
    let mx = x
        .iter()
        .map(|value| (value - x_center) / x_scale)
        .sum::<f64>()
        / nf;
    let my = y
        .iter()
        .map(|value| (value - y_center) / y_scale)
        .sum::<f64>()
        / nf;
    let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
    for i in 0..n {
        let (dx, dy) = (
            (x[i] - x_center) / x_scale - mx,
            (y[i] - y_center) / y_scale - my,
        );
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    if !sxx.is_finite() || !syy.is_finite() || sxx <= f64::EPSILON * nf || syy <= f64::EPSILON * nf
    {
        Err(crate::GaladrielError::InvalidChannels(
            "Pearson columns are numerically degenerate".into(),
        ))
    } else {
        let correlation = sxy / (sxx.sqrt() * syy.sqrt());
        if !correlation.is_finite() {
            return Err(crate::GaladrielError::NonFinite("Pearson result"));
        }
        Ok(correlation.clamp(-1.0, 1.0))
    }
}

/// Absolute Pearson magnitude, retained for evaluation code that intentionally
/// studies sign-invariant dependence. The production detector uses [`pearson`].
pub fn abs_pearson(x: &[f64], y: &[f64]) -> crate::Result<f64> {
    pearson(x, y).map(f64::abs)
}

/// Analyse aligned per-channel signed-scalar series for linear cross-sensor decoupling.
/// Requires ≥ 3 channels; the tail `window` is taken and aligned.
pub fn analyze(channels: &[(Modality, Vec<f64>)], cfg: &CorrConfig) -> crate::Result<CorrReport> {
    let c = channels.len();
    if c > MAX_CORRELATION_CHANNELS {
        return Err(crate::GaladrielError::InvalidChannels(format!(
            "correlation accepts at most {MAX_CORRELATION_CHANNELS} modalities, got {c}"
        )));
    }
    let input_tail = channels.first().map_or(0, |(_, values)| values.len());
    let (w, pair_count) = cfg.preflight_assessment(c, input_tail)?;
    if channels
        .iter()
        .any(|(_, values)| values.len() != input_tail)
    {
        return Err(crate::GaladrielError::InvalidChannels(
            "correlation columns must already be sequence-aligned and equal-length".into(),
        ));
    }
    let unique = channels
        .iter()
        .map(|(modality, _)| *modality)
        .collect::<std::collections::HashSet<_>>();
    if unique.len() != c {
        return Err(crate::GaladrielError::InvalidChannels(
            "correlation modalities must be unique".into(),
        ));
    }
    if c < 3 || w < cfg.min_samples() {
        return Ok(CorrReport::new(
            Vec::new(),
            CorrVerdict::InsufficientEvidence,
            format!(
                "need ≥3 channels and ≥{} aligned samples (have {c} channels, w={w})",
                cfg.min_samples()
            ),
            cfg,
        ));
    }

    let cols: Vec<&[f64]> = channels
        .iter()
        .map(|(_, values)| &values[values.len() - w..])
        .collect();

    // Pairwise signed ρ matrix (negative edges are never folded to magnitude).
    let mut corr = vec![vec![0.0_f64; c]; c];
    for i in 0..c {
        for j in (i + 1)..c {
            let r = pearson(cols[i], cols[j])?;
            corr[i][j] = r;
            corr[j][i] = r;
        }
    }

    let mut reports: Vec<CorrChannel> = channels
        .iter()
        .enumerate()
        .map(|(i, (m, _))| {
            let corroboration = (0..c)
                .filter(|&j| j != i)
                .map(|j| corr[i][j])
                .reduce(f64::max);
            CorrChannel {
                modality: *m,
                n: w,
                corroboration,
                decoupled: false,
            }
        })
        .collect();

    let reference = reports
        .iter()
        .filter_map(|r| r.corroboration)
        .fold(f64::MIN, f64::max);

    if reference < cfg.corr_floor() {
        return Ok(CorrReport::new(
            reports,
            CorrVerdict::InsufficientEvidence,
            format!(
                "no coherent positive linear consensus (strongest rho {reference:.3} < floor {:.3})",
                cfg.corr_floor()
            ),
            cfg,
        ));
    }

    let pair_alpha = corrected_pair_alpha(cfg.family_alpha(), pair_count);
    let z = statrs::distribution::ContinuousCDF::inverse_cdf(
        &statrs::distribution::Normal::standard(),
        1.0 - pair_alpha,
    );
    // A pathologically small `family_alpha` rounds `1 - pair_alpha` to exactly 1.0; the
    // inverse-normal quantile then saturates to +INF and `tanh` clamps the floor to exactly
    // 1.0. That is not a usable requirement: byte-identical (replayed) channels also clamp
    // to exactly rho = 1.0 and would still "clear" it, so a degenerate floor could fabricate
    // a consensus or an attribution. Abstain instead of scoring.
    let significance_floor = (z / (w as f64 - 3.0).sqrt()).tanh();
    if !significance_floor_is_usable(significance_floor) {
        return Ok(CorrReport::new(
            reports,
            CorrVerdict::InsufficientEvidence,
            format!(
                "family_alpha {:e} is too small to yield a usable Fisher significance floor for {pair_count} channel pair(s)",
                cfg.family_alpha()
            ),
            cfg,
        ));
    }
    let threshold = cfg
        .corr_floor()
        .max(significance_floor)
        .max(relative_decoupling_floor(cfg.decouple_ratio(), reference));

    if reference < threshold {
        return Ok(CorrReport::new(
            reports,
            CorrVerdict::InsufficientEvidence,
            format!(
                "no family-wise-significant positive consensus (strongest rho {reference:.3}, required {threshold:.3})"
            ),
            cfg,
        ));
    }

    // With at most six Modality variants, exhaustively enumerate cliques. A unique
    // strict-majority clique is the minimum structure that supports attribution:
    // mere graph connectivity would let an A-B-C chain masquerade as all-pairs
    // corroboration, while equal disconnected dyads remain honestly ambiguous.
    let mut largest_cliques = Vec::<Vec<usize>>::new();
    let mut largest_size = 0;
    for mask in 1usize..(1usize << c) {
        let members: Vec<usize> = (0..c).filter(|index| mask & (1 << index) != 0).collect();
        if members.len() < largest_size {
            continue;
        }
        let is_clique = members.iter().enumerate().all(|(position, &i)| {
            members[position + 1..]
                .iter()
                .all(|&j| corr[i][j] >= threshold)
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
    if !is_unique_strict_majority(largest_size, c, largest_cliques.len()) {
        return Ok(CorrReport::new(
            reports,
            CorrVerdict::InsufficientEvidence,
            format!(
                "ambiguous positive-consensus structure (largest clique {largest_size}/{c}, {} tied); no unique strict majority",
                largest_cliques.len()
            ),
            cfg,
        ));
    }
    let consensus = &largest_cliques[0];
    let consensus_set: std::collections::HashSet<usize> = consensus.iter().copied().collect();
    let bridged_outsider = (0..c).find(|index| {
        !consensus_set.contains(index)
            && consensus
                .iter()
                .any(|&member| corr[*index][member] >= threshold)
    });
    if let Some(index) = bridged_outsider {
        return Ok(CorrReport::new(
            reports,
            CorrVerdict::InsufficientEvidence,
            format!(
                "{} remains positively connected to part of the consensus clique; attribution is ambiguous",
                channels[index].0.label()
            ),
            cfg,
        ));
    }
    let mut decoupled = Vec::new();
    for (index, report) in reports.iter_mut().enumerate() {
        if !consensus_set.contains(&index) {
            report.decoupled = true;
            decoupled.push(report.modality);
        }
    }

    let (verdict, note) = if decoupled.is_empty() {
        (
            CorrVerdict::Nominal,
            format!(
                "{c} channels form one positive-consensus clique (strongest rho {reference:.3})"
            ),
        )
    } else {
        let names: Vec<&str> = decoupled.iter().map(|m| m.label()).collect();
        (
            CorrVerdict::Decoupled(decoupled.clone()),
            format!(
                "{} channel(s) linearly decoupled: {}",
                decoupled.len(),
                names.join(", ")
            ),
        )
    };

    Ok(CorrReport::new(reports, verdict, note, cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release_corr() -> CorrConfig {
        CorrConfig::standalone_advisory_v0_9().unwrap()
    }

    fn series(n: usize, f: impl Fn(usize) -> f64) -> Vec<f64> {
        (0..n).map(f).collect()
    }

    #[test]
    fn named_profile_preserves_exact_values_and_identity() {
        let config = release_corr();

        assert_eq!(MAX_CORRELATION_PAIRS, 15);
        assert_eq!(
            CorrConfigError::WindowOutOfRange.to_string(),
            format!(
                "correlation window must be in {MIN_CORRELATION_WINDOW}..={MAX_CORRELATION_WINDOW}"
            )
        );
        assert_eq!(
            CorrProfile::StandaloneAdvisoryV0_9.name(),
            "standalone_advisory_v0_9"
        );
        assert_eq!(
            (
                config.window(),
                config.min_samples(),
                config.decouple_ratio(),
                config.corr_floor(),
                config.family_alpha(),
                config.source_profile(),
                config.axis_family_count(),
                config.axis_family_was_derived(),
            ),
            (
                128,
                64,
                0.4,
                0.15,
                0.01,
                Some(CorrProfile::StandaloneAdvisoryV0_9),
                1,
                false,
            )
        );
    }

    #[test]
    fn channel_evidence_accessors_preserve_every_field() {
        let channel = CorrChannel {
            modality: Modality::Radar,
            n: 37,
            corroboration: Some(-0.25),
            decoupled: true,
        };

        assert_eq!(channel.modality(), Modality::Radar);
        assert_eq!(channel.n(), 37);
        assert_eq!(channel.corroboration(), Some(-0.25));
        assert!(channel.decoupled());
        assert_eq!(
            serde_json::to_value(&channel).unwrap(),
            serde_json::json!({
                "modality": "radar",
                "n": 37,
                "corroboration": -0.25,
                "decoupled": true,
            })
        );
    }

    #[test]
    fn report_accessors_preserve_complete_derived_evidence() {
        let config = release_corr().try_for_axis_family(3).unwrap();
        let channel = CorrChannel {
            modality: Modality::Lidar,
            n: 41,
            corroboration: Some(0.75),
            decoupled: true,
        };
        let verdict = CorrVerdict::Decoupled(vec![Modality::Lidar]);
        let report = CorrReport::new(
            vec![channel.clone()],
            verdict.clone(),
            "exact report note".to_owned(),
            &config,
        );

        assert_eq!(report.channels(), &[channel]);
        assert_eq!(report.verdict(), &verdict);
        assert_eq!(report.note(), "exact report note");
        assert_eq!(report.config_identity(), config.identity());
        assert_eq!(report.classification(), config.classification());
        assert_eq!(
            report.source_profile(),
            Some(CorrProfile::StandaloneAdvisoryV0_9)
        );
        assert_eq!(report.axis_family_count(), 3);
        assert!(report.axis_family_was_derived());
    }

    #[test]
    fn named_correlation_identity_has_a_fixed_golden_digest() {
        assert_eq!(
            release_corr().identity().to_hex(),
            "810722c36e36ebdb777235ee63a045544e373837ad20e8684e37ebdcf54e3f0c"
        );
    }

    #[test]
    fn custom_profile_and_axis_derivation_are_identity_distinct() {
        let named = release_corr();
        let custom = CorrConfig::try_new(CorrParams::standalone_advisory_v0_9()).unwrap();
        let derived = named.try_for_axis_family(3).unwrap();

        assert_ne!(named.identity(), custom.identity());
        assert_ne!(named.identity(), derived.identity());
        assert_ne!(custom.identity(), derived.identity());
    }

    #[test]
    fn every_correlation_field_changes_the_identity() {
        let baseline = CorrConfig::try_new(CorrParams::standalone_advisory_v0_9())
            .unwrap()
            .identity();
        let changes: [fn(&mut CorrParams); 5] = [
            |params| params.window = 129,
            |params| params.min_samples = 63,
            |params| params.decouple_ratio = 0.5,
            |params| params.corr_floor = 0.2,
            |params| params.family_alpha = 0.02,
        ];
        for change in changes {
            let mut params = CorrParams::standalone_advisory_v0_9();
            change(&mut params);
            assert_ne!(CorrConfig::try_new(params).unwrap().identity(), baseline);
        }
    }

    #[test]
    fn raw_constructor_rejects_every_scalar_domain() {
        let rejected = |change: fn(&mut CorrParams), expected| {
            let mut params = CorrParams::standalone_advisory_v0_9();
            change(&mut params);
            assert_eq!(CorrConfig::try_new(params).unwrap_err(), expected);
        };

        rejected(
            |params| params.window = MIN_CORRELATION_WINDOW - 1,
            CorrConfigError::WindowOutOfRange,
        );
        rejected(
            |params| params.window = MAX_CORRELATION_WINDOW + 1,
            CorrConfigError::WindowOutOfRange,
        );
        rejected(
            |params| params.min_samples = MIN_CORRELATION_WINDOW - 1,
            CorrConfigError::MinimumSamplesOutOfRange,
        );
        rejected(
            |params| params.min_samples = params.window + 1,
            CorrConfigError::MinimumSamplesOutOfRange,
        );
        for value in [0.0, -1.0, 1.0 + f64::EPSILON, f64::NAN, f64::INFINITY] {
            let mut params = CorrParams::standalone_advisory_v0_9();
            params.decouple_ratio = value;
            assert_eq!(
                CorrConfig::try_new(params).unwrap_err(),
                CorrConfigError::DecoupleRatioInvalid
            );
        }
        for value in [0.0, -1.0, 1.0 + f64::EPSILON, f64::NAN, f64::NEG_INFINITY] {
            let mut params = CorrParams::standalone_advisory_v0_9();
            params.corr_floor = value;
            assert_eq!(
                CorrConfig::try_new(params).unwrap_err(),
                CorrConfigError::CorrelationFloorInvalid
            );
        }
        for value in [0.0, -1.0, 1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut params = CorrParams::standalone_advisory_v0_9();
            params.family_alpha = value;
            assert_eq!(
                CorrConfig::try_new(params).unwrap_err(),
                CorrConfigError::FamilyAlphaInvalid
            );
        }
    }

    #[test]
    fn inclusive_scalar_boundaries_are_accepted() {
        let mut params = CorrParams::standalone_advisory_v0_9();
        params.window = MAX_CORRELATION_WINDOW;
        params.min_samples = MIN_CORRELATION_WINDOW;
        params.decouple_ratio = 1.0;
        params.corr_floor = 1.0;

        let config = CorrConfig::try_new(params).unwrap();

        assert_eq!(
            (
                config.window(),
                config.min_samples(),
                config.decouple_ratio(),
                config.corr_floor(),
            ),
            (MAX_CORRELATION_WINDOW, MIN_CORRELATION_WINDOW, 1.0, 1.0)
        );
    }

    #[test]
    fn axis_family_derivation_is_single_use_and_preserves_source() {
        let source = release_corr();
        let derived = source.try_for_axis_family(3).unwrap();

        assert_eq!(source.family_alpha(), 0.01);
        assert_eq!(derived.family_alpha(), 0.01 / 3.0);
        assert_eq!(derived.source_profile(), source.source_profile());
        assert_eq!(derived.axis_family_count(), 3);
        assert!(derived.axis_family_was_derived());
        assert_eq!(
            derived.try_for_axis_family(2).unwrap_err(),
            CorrConfigError::AxisFamilyAlreadyDerived { current: 3 }
        );
        assert_eq!(
            source.try_for_axis_family(0).unwrap_err(),
            CorrConfigError::AxisCountOutOfRange {
                requested: 0,
                maximum: crate::MAX_CONSISTENCY_PROJECTION_AXES,
            }
        );
        assert_eq!(
            source
                .try_for_axis_family(crate::MAX_CONSISTENCY_PROJECTION_AXES + 1)
                .unwrap_err(),
            CorrConfigError::AxisCountOutOfRange {
                requested: crate::MAX_CONSISTENCY_PROJECTION_AXES + 1,
                maximum: crate::MAX_CONSISTENCY_PROJECTION_AXES,
            }
        );
    }

    #[test]
    fn assessment_work_preflight_rejects_ceiling_and_checked_overflow() {
        let mut params = CorrParams::standalone_advisory_v0_9();
        params.window = MAX_CORRELATION_WINDOW;
        let config = CorrConfig::try_new(params).unwrap();
        assert_eq!(
            config
                .preflight_assessment(MAX_CORRELATION_CHANNELS, MAX_CORRELATION_WINDOW)
                .unwrap(),
            (MAX_CORRELATION_WINDOW, MAX_CORRELATION_PAIRS)
        );
        assert_eq!(MAX_CORRELATION_PAIRS * MAX_CORRELATION_WINDOW, 983_040);
        assert_eq!(
            config
                .preflight_assessment(MAX_CORRELATION_CHANNELS + 1, MAX_CORRELATION_WINDOW)
                .unwrap_err(),
            CorrConfigError::WorkEstimateExceedsLimit {
                requested: 21 * MAX_CORRELATION_WINDOW,
                maximum: MAX_CORRELATION_PAIR_SAMPLES,
            }
        );
        assert_eq!(
            config
                .preflight_assessment(usize::MAX, MAX_CORRELATION_WINDOW)
                .unwrap_err(),
            CorrConfigError::WorkEstimateOverflow
        );
    }

    #[test]
    fn pairwise_family_budget_is_divided_by_the_exact_pair_count() {
        assert_eq!(corrected_pair_alpha(0.01, 0), 0.01);
        assert_eq!(corrected_pair_alpha(0.01, 1), 0.01);
        assert_eq!(corrected_pair_alpha(0.01, 3), 0.01 / 3.0);
        assert_ne!(corrected_pair_alpha(0.01, 3), 0.01);

        assert!(significance_floor_is_usable(0.999));
        assert!(!significance_floor_is_usable(1.0));
        assert!(!significance_floor_is_usable(f64::INFINITY));
        assert!(!significance_floor_is_usable(f64::NAN));

        assert_eq!(relative_decoupling_floor(0.4, 0.8), 0.4_f64 * 0.8);
        assert_ne!(relative_decoupling_floor(0.4, 0.8), 0.5);

        assert!(is_unique_strict_majority(3, 4, 1));
        assert!(is_unique_strict_majority(2, 3, 1));
        assert!(!is_unique_strict_majority(2, 4, 1));
        assert!(!is_unique_strict_majority(1, 3, 1));
        assert!(!is_unique_strict_majority(3, 4, 2));
    }

    #[test]
    fn correlation_floor_comparison_is_strict_at_the_measured_reference() {
        use std::f64::consts::PI;

        let n = 120;
        let channels = vec![
            (
                Modality::Visual,
                series(n, |i| (2.0 * PI * i as f64 / n as f64).sin()),
            ),
            (
                Modality::Radar,
                series(n, |i| {
                    let phase = 2.0 * PI * i as f64 / n as f64;
                    0.5 * phase.sin() + (3.0_f64.sqrt() / 2.0) * phase.cos()
                }),
            ),
            (
                Modality::Acoustic,
                series(n, |i| (2.0 * PI * i as f64 / n as f64).cos()),
            ),
        ];
        let reference = [
            pearson(&channels[0].1, &channels[1].1).unwrap(),
            pearson(&channels[0].1, &channels[2].1).unwrap(),
            pearson(&channels[1].1, &channels[2].1).unwrap(),
        ]
        .into_iter()
        .fold(f64::MIN, f64::max);
        assert!(reference > 0.0 && reference < 1.0);

        let mut exact_params = CorrParams::standalone_advisory_v0_9();
        exact_params.corr_floor = reference;
        let exact = analyze(&channels, &CorrConfig::try_new(exact_params).unwrap()).unwrap();
        assert!(!exact
            .note()
            .starts_with("no coherent positive linear consensus"));

        let mut above_params = CorrParams::standalone_advisory_v0_9();
        above_params.corr_floor = f64::from_bits(reference.to_bits() + 1);
        let above = analyze(&channels, &CorrConfig::try_new(above_params).unwrap()).unwrap();
        assert!(above
            .note()
            .starts_with("no coherent positive linear consensus"));
    }

    #[test]
    fn pearson_basics() {
        let x = series(100, |i| i as f64);
        assert!((pearson(&x, &x).unwrap() - 1.0).abs() < 1e-9);
        let y = series(100, |i| -(i as f64));
        assert!((pearson(&x, &y).unwrap() + 1.0).abs() < 1e-9);
        assert!(abs_pearson(&x, &y).unwrap() > 1.0 - 1e-9);
        assert!(pearson(&x, &vec![1.0; 100]).is_err());
    }

    #[test]
    fn pearson_rejects_work_above_the_public_window_bound() {
        let oversized = vec![0.0; MAX_CORRELATION_WINDOW + 1];

        assert!(matches!(
            pearson(&oversized, &oversized),
            Err(crate::GaladrielError::InvalidChannels(message))
                if message.contains("maximum")
        ));
    }

    #[test]
    fn correlated_channels_with_one_outsider_are_decoupled() {
        // Three channels: A and B track a shared ramp (correlated); C is decoupled noise.
        let n = 128;
        let a = series(n, |i| (i as f64).sin());
        let b = series(n, |i| (i as f64).sin() + 0.05 * (i as f64).cos());
        let c_good = series(n, |i| (i as f64).sin() - 0.05);
        let c_bad = series(n, |i| ((i * 7 % 13) as f64) - 6.0); // unrelated

        let mods = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let clean = vec![
            (mods[0], a.clone()),
            (mods[1], b.clone()),
            (mods[2], c_good),
        ];
        assert_eq!(
            analyze(&clean, &release_corr()).unwrap().verdict,
            CorrVerdict::Nominal
        );

        let decoupled = vec![(mods[0], a), (mods[1], b), (mods[2], c_bad)];
        match analyze(&decoupled, &release_corr()).unwrap().verdict {
            CorrVerdict::Decoupled(v) => assert!(v.contains(&Modality::Acoustic)),
            other => panic!("expected Decoupled(acoustic), got {other:?}"),
        }
    }

    #[test]
    fn fewer_than_three_channels_is_insufficient_evidence() {
        let n = 128;
        let a = series(n, |i| (i as f64).sin());
        let b = series(n, |i| (i as f64).sin() + 0.05);
        let two = vec![(Modality::Visual, a), (Modality::Radar, b)];
        let report = analyze(&two, &release_corr()).unwrap();
        assert_eq!(report.verdict(), &CorrVerdict::InsufficientEvidence);
        assert!(report.channels().is_empty());
        assert_eq!(
            report.note(),
            "need ≥3 channels and ≥64 aligned samples (have 2 channels, w=128)"
        );

        let one = vec![(Modality::Visual, series(n, |i| (i as f64).cos()))];
        let report = analyze(&one, &release_corr()).unwrap();
        assert_eq!(report.verdict(), &CorrVerdict::InsufficientEvidence);
        assert!(report.channels().is_empty());
        assert_eq!(
            report.note(),
            "need ≥3 channels and ≥64 aligned samples (have 1 channels, w=128)"
        );
    }

    #[test]
    fn no_linear_consensus_fails_closed() {
        use std::f64::consts::PI;
        // Three orthogonal sinusoids (DFT basis over a full period) — pairwise |ρ| ≈ 0, so
        // There is no coherent consensus to decouple from, so fail closed rather
        // than manufacturing a false decoupling attribution.
        let n = 120;
        let s = |k: f64| series(n, |i| (2.0 * PI * k * i as f64 / n as f64).sin());
        let chans = vec![
            (Modality::Visual, s(1.0)),
            (Modality::Radar, s(2.0)),
            (Modality::Acoustic, s(3.0)),
        ];
        assert_eq!(
            analyze(&chans, &release_corr()).unwrap().verdict,
            CorrVerdict::InsufficientEvidence
        );
    }

    #[test]
    fn sign_flip_is_a_decoupling_not_corroboration() {
        let n = 128;
        let x = series(n, |i| (i as f64 / 7.0).sin());
        let channels = vec![
            (Modality::Visual, x.clone()),
            (Modality::Radar, x.clone()),
            (Modality::Acoustic, x.iter().map(|value| -value).collect()),
        ];
        assert_eq!(
            analyze(&channels, &release_corr()).unwrap().verdict,
            CorrVerdict::Decoupled(vec![Modality::Acoustic])
        );
    }

    #[test]
    fn constant_outlier_is_unassessable_not_decoupled() {
        let n = 128;
        let x = series(n, |i| (i as f64 / 7.0).sin());
        let channels = vec![
            (Modality::Visual, x.clone()),
            (Modality::Radar, x),
            (Modality::Acoustic, vec![1.0; n]),
        ];
        assert!(matches!(
            analyze(&channels, &release_corr()),
            Err(crate::GaladrielError::InvalidChannels(_))
        ));
    }

    #[test]
    fn disconnected_equal_dyads_are_ambiguous() {
        let n = 128;
        let a = series(n, |i| (i as f64 / 5.0).sin());
        let b = series(n, |i| (i as f64 / 11.0).cos());
        let channels = vec![
            (Modality::Visual, a.clone()),
            (Modality::Radar, a),
            (Modality::Acoustic, b.clone()),
            (Modality::Lidar, b),
        ];
        assert_eq!(
            analyze(&channels, &release_corr()).unwrap().verdict,
            CorrVerdict::InsufficientEvidence
        );
    }

    #[test]
    fn outsider_bridged_to_one_consensus_member_is_ambiguous() {
        use std::f64::consts::PI;

        let n = 128;
        let common = series(n, |i| (2.0 * PI * i as f64 / n as f64).sin());
        let private = series(n, |i| (4.0 * PI * i as f64 / n as f64).sin());
        let bridge: Vec<f64> = common
            .iter()
            .zip(&private)
            .map(|(shared, private)| shared + private)
            .collect();
        let channels = vec![
            (Modality::Visual, bridge),
            (Modality::Radar, common.clone()),
            (Modality::Acoustic, common),
            (Modality::Lidar, private),
        ];

        assert_eq!(
            analyze(&channels, &release_corr()).unwrap().verdict,
            CorrVerdict::InsufficientEvidence
        );
    }

    #[test]
    fn configuration_and_actual_pair_work_are_bounded() {
        let mut params = CorrParams::standalone_advisory_v0_9();
        params.window = MAX_CORRELATION_WINDOW + 1;
        params.min_samples = MIN_CORRELATION_WINDOW;
        assert_eq!(
            CorrConfig::try_new(params).unwrap_err(),
            CorrConfigError::WindowOutOfRange
        );

        let mut params = CorrParams::standalone_advisory_v0_9();
        params.window = MAX_CORRELATION_WINDOW;
        params.min_samples = MIN_CORRELATION_WINDOW;
        let cfg = CorrConfig::try_new(params).unwrap();
        let values: Vec<f64> = (0..MAX_CORRELATION_WINDOW)
            .map(|index| index as f64)
            .collect();
        let channels: Vec<_> = Modality::ALL
            .iter()
            .copied()
            .map(|modality| (modality, values.clone()))
            .collect();
        assert!(analyze(&channels, &cfg).is_ok());
    }

    #[test]
    fn finite_scaling_is_stable_and_nonfinite_input_errors() {
        let x = series(128, |i| 1e200 * (i as f64 / 5.0).sin());
        let y = series(128, |i| 1e200 * (i as f64 / 11.0).cos());
        let r = pearson(&x, &y).unwrap();
        assert!(r.is_finite() && r.abs() < 0.5, "rho={r}");
        let mut poisoned = x.clone();
        poisoned[0] = f64::NAN;
        assert!(pearson(&poisoned, &y).is_err());

        let shifted = series(128, |i| 1e15 + i as f64);
        assert!(
            (pearson(&shifted, &shifted).unwrap() - 1.0).abs() < 1e-12,
            "large offsets must not erase representable variation"
        );
    }

    #[test]
    fn configuration_rejects_unresolvable_fisher_tail_before_analysis() {
        let mut params = CorrParams::standalone_advisory_v0_9();
        params.family_alpha = 1e-300;

        assert_eq!(
            CorrConfig::try_new(params).unwrap_err(),
            CorrConfigError::FamilyAlphaResolutionInsufficient {
                correction_count: MAX_FUSED_CORRELATION_TESTS,
                min_samples: 64,
            }
        );
    }

    #[test]
    fn fisher_tail_resolution_boundary_rejects_midpoint_and_accepts_successor() {
        // `1 - 2^-54` is the exact midpoint between 1.0 and its predecessor and
        // rounds to 1.0 (ties-to-even). Its immediate positive successor resolves
        // to the predecessor of 1.0 and yields a finite Fisher floor.
        let midpoint = f64::EPSILON / 4.0;
        let successor = f64::from_bits(midpoint.to_bits() + 1);
        let mut params = CorrParams::standalone_advisory_v0_9();
        params.family_alpha = midpoint * MAX_FUSED_CORRELATION_TESTS as f64;
        assert!(matches!(
            CorrConfig::try_new(params.clone()),
            Err(CorrConfigError::FamilyAlphaResolutionInsufficient { .. })
        ));

        params.family_alpha = successor * MAX_FUSED_CORRELATION_TESTS as f64;
        let config = CorrConfig::try_new(params).unwrap();
        let derived = config
            .try_for_axis_family(crate::MAX_CONSISTENCY_PROJECTION_AXES)
            .unwrap();
        assert!(1.0 - derived.family_alpha() / (MAX_CORRELATION_PAIRS as f64) < 1.0);
    }

    #[test]
    fn configuration_rejects_alpha_that_underflows_during_fused_correction() {
        let mut params = CorrParams::standalone_advisory_v0_9();
        params.family_alpha = f64::from_bits(1);

        assert_eq!(
            CorrConfig::try_new(params).unwrap_err(),
            CorrConfigError::FamilyAlphaUnderflow {
                divisor: MAX_FUSED_CORRELATION_TESTS
            }
        );
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// `|ρ|` is always a finite value in [0, 1] and symmetric in its arguments.
        #[test]
        fn abs_pearson_is_a_unit_symmetric_magnitude(
            pairs in prop::collection::vec((-1000.0f64..1000.0, -1000.0f64..1000.0), 3..80)
        ) {
            let x: Vec<f64> = pairs.iter().map(|p| p.0).collect();
            let y: Vec<f64> = pairs.iter().map(|p| p.1).collect();
            prop_assume!(x.iter().any(|&value| (value - x[0]).abs() > 1e-9));
            prop_assume!(y.iter().any(|&value| (value - y[0]).abs() > 1e-9));
            let r = abs_pearson(&x, &y).unwrap();
            prop_assert!(r.is_finite(), "abs_pearson not finite: {r}");
            prop_assert!((-1e-9..=1.0 + 1e-9).contains(&r), "abs_pearson {r} ∉ [0,1]");
            prop_assert!(
                (abs_pearson(&x, &y).unwrap() - abs_pearson(&y, &x).unwrap()).abs() < 1e-9,
                "abs_pearson not symmetric"
            );
        }

        /// A non-constant series correlates perfectly with itself.
        #[test]
        fn abs_pearson_self_correlation_is_one(
            v in prop::collection::vec(-1000.0f64..1000.0, 3..80)
        ) {
            prop_assume!(v.iter().any(|&a| (a - v[0]).abs() > 1e-2));
            prop_assert!((abs_pearson(&v, &v).unwrap() - 1.0).abs() < 1e-4, "self-corr ≠ 1");
        }
    }
}
