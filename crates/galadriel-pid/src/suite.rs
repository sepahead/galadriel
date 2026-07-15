//! Accepted composition boundary for opt-in PID research.

use std::{error::Error, fmt};

use galadriel_core::{
    GaladrielError, Modality, ReleaseSuite, ReleaseSuiteError, MAX_CONSISTENCY_PROJECTION_AXES,
};

use crate::identity::{IdentityBuilder, PidResearchClassification, PidResearchSuiteDigest};
use crate::{PidConfig, PidConfigError, PidResearchProfile};

/// Minimum modality count for a PID strict-majority clique assessment.
pub const MIN_PID_RESEARCH_MODALITIES: usize = 3;

/// Fixed worst-case multi-axis quadratic-fit ceiling for one PID suite.
///
/// The component ceiling is 200,000,000 and the producer projection protocol
/// admits at most three axes. Suite construction checks this full product before
/// observations are read or any estimator is entered.
pub const MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK: usize = 600_000_000;

fn checked_suite_work(
    component_work: usize,
    axis_count: usize,
) -> Result<usize, PidResearchSuiteError> {
    let requested = component_work
        .checked_mul(axis_count)
        .ok_or(PidResearchSuiteError::WorkEstimateOverflow)?;
    if requested > MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK {
        return Err(PidResearchSuiteError::WorkLimitExceeded {
            requested,
            maximum: MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK,
        });
    }
    Ok(requested)
}

/// Unvalidated composition parameters for [`PidResearchSuite::try_new`].
#[derive(Debug, Clone)]
pub struct PidResearchSuiteParams {
    /// Accepted PID-free standalone release suite.
    pub release_suite: ReleaseSuite,
    /// Accepted, underived PID component configuration.
    pub pid: PidConfig,
}

/// Typed rejection from PID research-suite composition or axis preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PidResearchSuiteError {
    /// The embedded PID-free release suite was invalid.
    ReleaseSuite(ReleaseSuiteError),
    /// The PID component or its axis derivation was invalid.
    PidConfig(PidConfigError),
    /// Fewer than three expected modalities cannot form the PID clique contract.
    TooFewModalities { available: usize, minimum: usize },
    /// An already-derived PID config cannot be composed and divided again.
    PidConfigAlreadyDerived { axis_count: usize },
    /// A checked aggregate work calculation overflowed.
    WorkEstimateOverflow,
    /// Aggregate multi-axis PID work exceeds the fixed suite ceiling.
    WorkLimitExceeded { requested: usize, maximum: usize },
}

impl fmt::Display for PidResearchSuiteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReleaseSuite(error) => write!(formatter, "invalid release suite: {error}"),
            Self::PidConfig(error) => write!(formatter, "invalid PID config: {error}"),
            Self::TooFewModalities { available, minimum } => write!(
                formatter,
                "PID research requires at least {minimum} expected modalities, got {available}"
            ),
            Self::PidConfigAlreadyDerived { axis_count } => write!(
                formatter,
                "PID research suite requires an underived config, got a {axis_count}-axis derivative"
            ),
            Self::WorkEstimateOverflow => {
                formatter.write_str("PID research-suite work estimate overflowed")
            }
            Self::WorkLimitExceeded { requested, maximum } => write!(
                formatter,
                "PID research suite requests {requested} quadratic fit-units; maximum is {maximum}"
            ),
        }
    }
}

impl Error for PidResearchSuiteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReleaseSuite(error) => Some(error),
            Self::PidConfig(error) => Some(error),
            Self::TooFewModalities { .. }
            | Self::PidConfigAlreadyDerived { .. }
            | Self::WorkEstimateOverflow
            | Self::WorkLimitExceeded { .. } => None,
        }
    }
}

impl From<ReleaseSuiteError> for PidResearchSuiteError {
    fn from(error: ReleaseSuiteError) -> Self {
        Self::ReleaseSuite(error)
    }
}

impl From<PidConfigError> for PidResearchSuiteError {
    fn from(error: PidConfigError) -> Self {
        Self::PidConfig(error)
    }
}

impl From<PidResearchSuiteError> for GaladrielError {
    fn from(error: PidResearchSuiteError) -> Self {
        Self::InvalidConfig(error.to_string())
    }
}

/// Immutable capability required before any whole-stream PID work can run.
///
/// Construction is `O(m)` time and allocation for the release suite's canonical
/// `m`-modality set, and `O(1)` additional retained memory. It checks the full
/// three-axis PID work product with checked arithmetic. This type is intentionally
/// distinct from [`ReleaseSuite`]: enabling the crate does not activate research.
///
/// Accepted suites cannot be fabricated or modified:
///
/// ```compile_fail
/// use galadriel_pid::PidResearchSuite;
/// let _ = PidResearchSuite { maximum_quadratic_fit_work: 0 };
/// ```
///
/// A PID-free release suite cannot cross the PID entry point:
///
/// ```compile_fail
/// use galadriel_core::{Modality, ReleaseSuite};
/// use galadriel_pid::assess_stream;
/// let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
/// let release = ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap();
/// let _ = assess_stream(&[], &release);
/// ```
#[derive(Debug, Clone)]
pub struct PidResearchSuite {
    release_suite: ReleaseSuite,
    pid: PidConfig,
    source_profile: Option<PidResearchProfile>,
    maximum_quadratic_fit_work: usize,
    identity: PidResearchSuiteDigest,
}

impl PidResearchSuite {
    /// Compose accepted custom release and PID components.
    ///
    /// # Errors
    ///
    /// Rejects a modality set incapable of PID assessment, an already-derived
    /// PID config, checked-product overflow, or a suite work ceiling violation.
    pub fn try_new(params: PidResearchSuiteParams) -> Result<Self, PidResearchSuiteError> {
        Self::try_new_with_profile(params, None)
    }

    fn try_new_with_profile(
        params: PidResearchSuiteParams,
        source_profile: Option<PidResearchProfile>,
    ) -> Result<Self, PidResearchSuiteError> {
        let modality_count = params.release_suite.expected_modalities().len();
        if modality_count < MIN_PID_RESEARCH_MODALITIES {
            return Err(PidResearchSuiteError::TooFewModalities {
                available: modality_count,
                minimum: MIN_PID_RESEARCH_MODALITIES,
            });
        }
        if params.pid.axis_family_was_derived() {
            return Err(PidResearchSuiteError::PidConfigAlreadyDerived {
                axis_count: params.pid.axis_family_count(),
            });
        }
        // Resolve the maximum protocol family at composition time so an
        // accepted suite can never discover an unresolvable confirmation tail
        // only after input has been read.
        let maximum_axis_pid = params
            .pid
            .try_for_axis_family(MAX_CONSISTENCY_PROJECTION_AXES)?;
        let maximum_quadratic_fit_work = checked_suite_work(
            maximum_axis_pid.quadratic_fit_work(),
            MAX_CONSISTENCY_PROJECTION_AXES,
        )?;

        let mut identity = IdentityBuilder::new(b"galadriel-pid-research-suite-v1");
        identity.u8(
            b"classification",
            if source_profile.is_some() { 1 } else { 2 },
        );
        identity.u8(
            b"source_profile",
            match source_profile {
                Some(PidResearchProfile::CircularDeleteBlockV0_9) => 1,
                Some(PidResearchProfile::PointEstimateOnlyV0_9) => 2,
                None => 0,
            },
        );
        identity.bytes(b"release_suite", params.release_suite.identity().as_bytes());
        identity.bytes(b"pid_config", params.pid.identity().as_bytes());
        identity.bytes(
            b"maximum_axis_pid_config",
            maximum_axis_pid.identity().as_bytes(),
        );
        identity.usize(b"maximum_axes", MAX_CONSISTENCY_PROJECTION_AXES);
        identity.usize(b"maximum_quadratic_fit_work", maximum_quadratic_fit_work);

        Ok(Self {
            release_suite: params.release_suite,
            pid: params.pid,
            source_profile,
            maximum_quadratic_fit_work,
            identity: PidResearchSuiteDigest::from_bytes(identity.finish()),
        })
    }

    /// Compose the named circular delete-block research suite.
    pub fn circular_delete_block_v0_9(
        expected_modalities: &[Modality],
    ) -> Result<Self, PidResearchSuiteError> {
        let release_suite = ReleaseSuite::standalone_advisory_v0_9(expected_modalities)?;
        let profile = PidResearchProfile::CircularDeleteBlockV0_9;
        let pid = profile.try_config()?;
        Self::try_new_with_profile(PidResearchSuiteParams { release_suite, pid }, Some(profile))
    }

    /// Compose the explicitly unconfirmed point-estimate research suite.
    pub fn point_estimate_only_v0_9(
        expected_modalities: &[Modality],
    ) -> Result<Self, PidResearchSuiteError> {
        let release_suite = ReleaseSuite::standalone_advisory_v0_9(expected_modalities)?;
        let profile = PidResearchProfile::PointEstimateOnlyV0_9;
        let pid = profile.try_config()?;
        Self::try_new_with_profile(PidResearchSuiteParams { release_suite, pid }, Some(profile))
    }

    /// Accepted PID-free release component.
    pub const fn release_suite(&self) -> &ReleaseSuite {
        &self.release_suite
    }

    /// Accepted underived PID component.
    pub const fn pid_config(&self) -> &PidConfig {
        &self.pid
    }

    /// Named source research profile, when selected by a named suite constructor.
    pub const fn source_profile(&self) -> Option<PidResearchProfile> {
        self.source_profile
    }

    /// Named-profile or custom-research classification.
    pub const fn classification(&self) -> PidResearchClassification {
        if self.source_profile.is_some() {
            PidResearchClassification::NamedResearchProfile
        } else {
            PidResearchClassification::CustomAcceptedResearch
        }
    }

    /// Worst-case PID work across every protocol-admitted projection axis.
    pub const fn maximum_quadratic_fit_work(&self) -> usize {
        self.maximum_quadratic_fit_work
    }

    /// Canonical complete identity of this accepted research suite.
    pub const fn identity(&self) -> PidResearchSuiteDigest {
        self.identity
    }

    /// Derive one accepted PID config for the actual attested axis family.
    ///
    /// The aggregate work product is rechecked before the derived configuration
    /// is created and before any estimator is entered.
    pub(crate) fn try_pid_for_axis_family(
        &self,
        axis_count: usize,
    ) -> Result<PidConfig, PidResearchSuiteError> {
        checked_suite_work(self.pid.quadratic_fit_work(), axis_count)?;
        Ok(self.pid.try_for_axis_family(axis_count)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODALITIES: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

    #[test]
    fn named_suite_is_explicit_bounded_and_identity_stable() {
        let suite = PidResearchSuite::circular_delete_block_v0_9(&MODALITIES).unwrap();
        let repeated = PidResearchSuite::circular_delete_block_v0_9(&MODALITIES).unwrap();

        assert_eq!(
            suite.classification(),
            PidResearchClassification::NamedResearchProfile
        );
        assert_eq!(
            suite.source_profile(),
            Some(PidResearchProfile::CircularDeleteBlockV0_9)
        );
        assert_eq!(suite.identity(), repeated.identity());
        let expected_work = suite
            .pid_config()
            .try_for_axis_family(MAX_CONSISTENCY_PROJECTION_AXES)
            .unwrap()
            .quadratic_fit_work()
            .checked_mul(MAX_CONSISTENCY_PROJECTION_AXES)
            .unwrap();
        assert_eq!(suite.maximum_quadratic_fit_work(), expected_work);
        assert!(expected_work > 1);
        assert!(expected_work <= MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK);
        assert_eq!(
            suite.identity().to_hex(),
            "4c0b4c91a1e26f08715329aabd2dcf955876d5a751ac8e16821076ebf421331b"
        );
    }

    #[test]
    fn named_suite_modality_order_is_canonical() {
        let reordered = [Modality::Acoustic, Modality::Visual, Modality::Radar];
        assert_eq!(
            PidResearchSuite::circular_delete_block_v0_9(&MODALITIES)
                .unwrap()
                .identity(),
            PidResearchSuite::circular_delete_block_v0_9(&reordered)
                .unwrap()
                .identity()
        );
    }

    #[test]
    fn custom_composition_is_identity_distinct_and_rejects_double_derivation() {
        let release_suite = ReleaseSuite::standalone_advisory_v0_9(&MODALITIES).unwrap();
        let pid = PidResearchProfile::CircularDeleteBlockV0_9
            .try_config()
            .unwrap();
        let custom = PidResearchSuite::try_new(PidResearchSuiteParams {
            release_suite: release_suite.clone(),
            pid: pid.clone(),
        })
        .unwrap();
        let named = PidResearchSuite::circular_delete_block_v0_9(&MODALITIES).unwrap();
        assert_ne!(custom.identity(), named.identity());
        assert_eq!(custom.source_profile(), None);
        assert_eq!(
            custom.classification(),
            PidResearchClassification::CustomAcceptedResearch
        );

        let error = PidResearchSuite::try_new(PidResearchSuiteParams {
            release_suite,
            pid: pid.try_for_axis_family(2).unwrap(),
        })
        .unwrap_err();
        assert_eq!(
            error,
            PidResearchSuiteError::PidConfigAlreadyDerived { axis_count: 2 }
        );
    }

    #[test]
    fn two_modalities_are_rejected_before_analysis() {
        let modalities = [Modality::Visual, Modality::Radar];
        let release_suite = ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap();
        let pid = PidResearchProfile::PointEstimateOnlyV0_9
            .try_config()
            .unwrap();
        assert_eq!(
            PidResearchSuite::try_new(PidResearchSuiteParams { release_suite, pid }).unwrap_err(),
            PidResearchSuiteError::TooFewModalities {
                available: 2,
                minimum: 3
            }
        );
    }

    #[test]
    fn suite_work_ceiling_is_inclusive_and_checked_before_composition() {
        let per_axis = MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK
            .checked_div(MAX_CONSISTENCY_PROJECTION_AXES)
            .unwrap();
        assert_eq!(
            checked_suite_work(per_axis, MAX_CONSISTENCY_PROJECTION_AXES).unwrap(),
            MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK
        );
        assert_eq!(
            checked_suite_work(per_axis + 1, MAX_CONSISTENCY_PROJECTION_AXES).unwrap_err(),
            PidResearchSuiteError::WorkLimitExceeded {
                requested: MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK
                    + MAX_CONSISTENCY_PROJECTION_AXES,
                maximum: MAX_PID_RESEARCH_SUITE_QUADRATIC_FIT_WORK,
            }
        );
        assert_eq!(
            checked_suite_work(usize::MAX, 2).unwrap_err(),
            PidResearchSuiteError::WorkEstimateOverflow
        );
    }

    #[test]
    fn suite_errors_expose_exact_display_and_nested_source() {
        let inner = PidConfigError::WindowOutOfRange;
        let error = PidResearchSuiteError::PidConfig(inner.clone());
        assert_eq!(
            error.to_string(),
            "invalid PID config: PID window must be in 4..=512 (estimators are quadratic)"
        );
        let source = error.source().expect("PID configuration error is retained");
        assert!(source.is::<PidConfigError>());
        assert_eq!(source.to_string(), inner.to_string());

        let terminal = PidResearchSuiteError::WorkLimitExceeded {
            requested: 600_000_001,
            maximum: 600_000_000,
        };
        assert_eq!(
            terminal.to_string(),
            "PID research suite requests 600000001 quadratic fit-units; maximum is 600000000"
        );
        assert!(terminal.source().is_none());
    }
}
