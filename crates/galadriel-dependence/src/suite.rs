//! Accepted composition boundary for opt-in dependence research.

use std::{error::Error, fmt};

use galadriel_core::{
    GaladrielError, Modality, ReleaseSuite, ReleaseSuiteError, MAX_CONSISTENCY_PROJECTION_AXES,
};

use crate::identity::{
    DependenceResearchClassification, DependenceResearchSuiteDigest, IdentityBuilder,
};
use crate::{
    ContinuousLawDeclaration, MiConsensusConfig, MiConsensusConfigError, MiConsensusResearchProfile,
};

/// Minimum modality count for a strict-majority graph assessment.
pub const MIN_DEPENDENCE_RESEARCH_MODALITIES: usize = 3;

/// Fixed worst-case work ceiling for all producer-attested projection axes.
pub const MAX_DEPENDENCE_RESEARCH_SUITE_QUADRATIC_FIT_WORK: usize = 600_000_000;

/// Unvalidated composition values for [`DependenceResearchSuite::try_new`].
#[derive(Debug, Clone)]
pub struct DependenceResearchSuiteParams {
    /// Accepted authoritative release suite.
    pub release_suite: ReleaseSuite,
    /// Accepted exploratory MI-consensus configuration.
    pub mi_consensus: MiConsensusConfig,
}

/// Typed rejection from dependence-suite composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependenceResearchSuiteError {
    ReleaseSuite(ReleaseSuiteError),
    MiConsensusConfig(MiConsensusConfigError),
    TooFewModalities { available: usize, minimum: usize },
    WorkEstimateOverflow,
    WorkLimitExceeded { requested: usize, maximum: usize },
}

impl fmt::Display for DependenceResearchSuiteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReleaseSuite(error) => write!(formatter, "invalid release suite: {error}"),
            Self::MiConsensusConfig(error) => {
                write!(formatter, "invalid MI-consensus config: {error}")
            }
            Self::TooFewModalities { available, minimum } => write!(
                formatter,
                "dependence research requires at least {minimum} expected modalities, got {available}"
            ),
            Self::WorkEstimateOverflow => {
                formatter.write_str("dependence research-suite work estimate overflowed")
            }
            Self::WorkLimitExceeded { requested, maximum } => write!(
                formatter,
                "dependence research suite requests {requested} quadratic scan-equivalent units; maximum is {maximum}"
            ),
        }
    }
}

impl Error for DependenceResearchSuiteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReleaseSuite(error) => Some(error),
            Self::MiConsensusConfig(error) => Some(error),
            Self::TooFewModalities { .. }
            | Self::WorkEstimateOverflow
            | Self::WorkLimitExceeded { .. } => None,
        }
    }
}

impl From<ReleaseSuiteError> for DependenceResearchSuiteError {
    fn from(error: ReleaseSuiteError) -> Self {
        Self::ReleaseSuite(error)
    }
}

impl From<MiConsensusConfigError> for DependenceResearchSuiteError {
    fn from(error: MiConsensusConfigError) -> Self {
        Self::MiConsensusConfig(error)
    }
}

impl From<DependenceResearchSuiteError> for GaladrielError {
    fn from(error: DependenceResearchSuiteError) -> Self {
        Self::InvalidConfig(error.to_string())
    }
}

/// Immutable capability required before whole-stream companion MI work can run.
///
/// Enabling the Cargo feature does not construct this value or execute research.
#[derive(Debug, Clone)]
pub struct DependenceResearchSuite {
    release_suite: ReleaseSuite,
    mi_consensus: MiConsensusConfig,
    source_profile: Option<MiConsensusResearchProfile>,
    maximum_quadratic_fit_work: usize,
    identity: DependenceResearchSuiteDigest,
}

impl DependenceResearchSuite {
    /// Compose accepted custom release and MI-consensus components.
    pub fn try_new(
        params: DependenceResearchSuiteParams,
    ) -> Result<Self, DependenceResearchSuiteError> {
        Self::try_new_with_profile(params, None)
    }

    fn try_new_with_profile(
        params: DependenceResearchSuiteParams,
        source_profile: Option<MiConsensusResearchProfile>,
    ) -> Result<Self, DependenceResearchSuiteError> {
        let modality_count = params.release_suite.expected_modalities().len();
        if modality_count < MIN_DEPENDENCE_RESEARCH_MODALITIES {
            return Err(DependenceResearchSuiteError::TooFewModalities {
                available: modality_count,
                minimum: MIN_DEPENDENCE_RESEARCH_MODALITIES,
            });
        }
        let maximum_quadratic_fit_work = params
            .mi_consensus
            .quadratic_fit_work()
            .checked_mul(MAX_CONSISTENCY_PROJECTION_AXES)
            .ok_or(DependenceResearchSuiteError::WorkEstimateOverflow)?;
        if maximum_quadratic_fit_work > MAX_DEPENDENCE_RESEARCH_SUITE_QUADRATIC_FIT_WORK {
            return Err(DependenceResearchSuiteError::WorkLimitExceeded {
                requested: maximum_quadratic_fit_work,
                maximum: MAX_DEPENDENCE_RESEARCH_SUITE_QUADRATIC_FIT_WORK,
            });
        }

        let mut identity = IdentityBuilder::new(b"galadriel-dependence-research-suite-v1");
        identity.u8(
            b"classification",
            if source_profile.is_some() { 1 } else { 2 },
        );
        identity.u8(
            b"source_profile",
            match source_profile {
                Some(MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9) => 1,
                Some(MiConsensusResearchProfile::PointEstimateOnlyV0_9) => 2,
                None => 0,
            },
        );
        identity.bytes(b"release_suite", params.release_suite.identity().as_bytes());
        identity.bytes(b"mi_consensus", params.mi_consensus.identity().as_bytes());
        identity.usize(b"maximum_axes", MAX_CONSISTENCY_PROJECTION_AXES);
        identity.usize(b"maximum_quadratic_fit_work", maximum_quadratic_fit_work);

        Ok(Self {
            release_suite: params.release_suite,
            mi_consensus: params.mi_consensus,
            source_profile,
            maximum_quadratic_fit_work,
            identity: DependenceResearchSuiteDigest::from_bytes(identity.finish()),
        })
    }

    /// Compose the named exhaustive deletion-stability companion suite.
    pub fn exhaustive_circular_delete_block_v0_9(
        expected_modalities: &[Modality],
        law: ContinuousLawDeclaration,
    ) -> Result<Self, DependenceResearchSuiteError> {
        let release_suite = ReleaseSuite::standalone_advisory_v0_9(expected_modalities)?;
        let profile = MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9;
        let mi_consensus = profile.try_config(law)?;
        Self::try_new_with_profile(
            DependenceResearchSuiteParams {
                release_suite,
                mi_consensus,
            },
            Some(profile),
        )
    }

    /// Compose the point-estimate-only companion suite.
    pub fn point_estimate_only_v0_9(
        expected_modalities: &[Modality],
        law: ContinuousLawDeclaration,
    ) -> Result<Self, DependenceResearchSuiteError> {
        let release_suite = ReleaseSuite::standalone_advisory_v0_9(expected_modalities)?;
        let profile = MiConsensusResearchProfile::PointEstimateOnlyV0_9;
        let mi_consensus = profile.try_config(law)?;
        Self::try_new_with_profile(
            DependenceResearchSuiteParams {
                release_suite,
                mi_consensus,
            },
            Some(profile),
        )
    }

    pub const fn release_suite(&self) -> &ReleaseSuite {
        &self.release_suite
    }
    pub const fn mi_consensus_config(&self) -> &MiConsensusConfig {
        &self.mi_consensus
    }
    pub const fn source_profile(&self) -> Option<MiConsensusResearchProfile> {
        self.source_profile
    }
    pub const fn classification(&self) -> DependenceResearchClassification {
        if self.source_profile.is_some() {
            DependenceResearchClassification::NamedResearchProfile
        } else {
            DependenceResearchClassification::CustomAcceptedResearch
        }
    }
    pub const fn maximum_quadratic_fit_work(&self) -> usize {
        self.maximum_quadratic_fit_work
    }
    pub const fn identity(&self) -> DependenceResearchSuiteDigest {
        self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn law() -> ContinuousLawDeclaration {
        ContinuousLawDeclaration::try_iid(
            "nonsingular finite-MI Gaussian bivariate populations",
            "binary64 sample representation of declared continuous-law draws; no deliberate quantization or added noise; exact ties abstain",
            "independent rows within one synthetic episode",
            "fixed common simulator innovation unit and identity gauge; no sample-fitted rescaling",
        )
        .unwrap()
    }

    #[test]
    fn suite_checks_modality_and_multi_axis_work_before_execution() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let suite =
            DependenceResearchSuite::exhaustive_circular_delete_block_v0_9(&modalities, law())
                .unwrap();
        assert_eq!(suite.maximum_quadratic_fit_work(), 570_654_720);
        assert_eq!(
            suite.maximum_quadratic_fit_work(),
            suite
                .mi_consensus_config()
                .quadratic_fit_work()
                .checked_mul(MAX_CONSISTENCY_PROJECTION_AXES)
                .unwrap()
        );
        let mut frontier = MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9.params();
        frontier.window = 130;
        let frontier_config = MiConsensusConfig::try_new(frontier, law()).unwrap();
        assert_eq!(frontier_config.quadratic_fit_work(), 199_251_000);
        let frontier_suite = DependenceResearchSuite::try_new(DependenceResearchSuiteParams {
            release_suite: ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap(),
            mi_consensus: frontier_config,
        })
        .unwrap();
        assert_eq!(frontier_suite.maximum_quadratic_fit_work(), 597_753_000);

        let mut rejected = MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9.params();
        rejected.window = 131;
        assert!(matches!(
            MiConsensusConfig::try_new(rejected, law()),
            Err(MiConsensusConfigError::WorkEstimateExceedsLimit { .. })
        ));
        assert_eq!(
            suite.classification(),
            DependenceResearchClassification::NamedResearchProfile
        );
        assert_eq!(
            suite.source_profile(),
            Some(MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9)
        );

        let too_few = [Modality::Visual, Modality::Radar];
        assert!(matches!(
            DependenceResearchSuite::point_estimate_only_v0_9(&too_few, law()),
            Err(DependenceResearchSuiteError::TooFewModalities { .. })
        ));
    }

    #[test]
    fn named_and_custom_suites_have_distinct_identities() {
        let modalities = [Modality::Visual, Modality::Radar, Modality::Acoustic];
        let named = DependenceResearchSuite::point_estimate_only_v0_9(&modalities, law()).unwrap();
        let custom = DependenceResearchSuite::try_new(DependenceResearchSuiteParams {
            release_suite: ReleaseSuite::standalone_advisory_v0_9(&modalities).unwrap(),
            mi_consensus: MiConsensusResearchProfile::PointEstimateOnlyV0_9
                .try_config(law())
                .unwrap(),
        })
        .unwrap();
        assert_ne!(named.identity(), custom.identity());
    }

    #[test]
    fn wrapped_component_errors_retain_display_and_source_categories() {
        let error = DependenceResearchSuiteError::MiConsensusConfig(
            MiConsensusConfigError::GeometryKTooSmall,
        );
        assert_eq!(
            error.to_string(),
            "invalid MI-consensus config: MI-consensus geom_k must be >= 3"
        );
        let source = std::error::Error::source(&error).expect("component error remains typed");
        assert!(source
            .downcast_ref::<MiConsensusConfigError>()
            .is_some_and(|source| *source == MiConsensusConfigError::GeometryKTooSmall));

        let plain = DependenceResearchSuiteError::TooFewModalities {
            available: 2,
            minimum: 3,
        };
        assert!(std::error::Error::source(&plain).is_none());
    }
}
