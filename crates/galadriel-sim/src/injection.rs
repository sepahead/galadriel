//! Attack injections that transform a clean stream into a spoof or a jam.

use galadriel_core::{
    validate_and_symmetrize_covariance, ConsistencyProjection, GaladrielError, Modality,
    PidObservation, Result,
};

const MAX_INJECTION_OBSERVATIONS: usize = 1_000_000;

/// Recompute `yᵀ S⁻¹ y` using a scaled Cholesky solve of the full
/// symmetric positive-definite covariance.
fn recompute_nis(innovation: [f64; 3], covariance: [[f64; 3]; 3]) -> Result<f64> {
    if !innovation.iter().all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("injected innovation"));
    }
    let covariance = validate_and_symmetrize_covariance(covariance)?;

    // Scaling keeps the Cholesky products bounded for very large finite
    // covariances. The corresponding residual is divided by sqrt(scale), which
    // leaves the Mahalanobis distance unchanged.
    let scale = covariance
        .iter()
        .flatten()
        .map(|value| value.abs())
        .fold(0.0_f64, f64::max);
    if !scale.is_finite() || scale <= 0.0 {
        return Err(GaladrielError::InvalidObservation(
            "innovation covariance must be positive definite".into(),
        ));
    }

    let a00 = covariance[0][0] / scale;
    let a11 = covariance[1][1] / scale;
    let a22 = covariance[2][2] / scale;
    let a10 = covariance[1][0] / scale;
    let a20 = covariance[2][0] / scale;
    let a21 = covariance[2][1] / scale;

    if a00 <= 0.0 {
        return Err(GaladrielError::InvalidObservation(
            "innovation covariance must be positive definite".into(),
        ));
    }
    let l00 = a00.sqrt();
    let l10 = a10 / l00;
    let l20 = a20 / l00;

    let pivot11 = a11 - l10 * l10;
    if !pivot11.is_finite() || pivot11 <= 0.0 {
        return Err(GaladrielError::InvalidObservation(
            "innovation covariance must be positive definite".into(),
        ));
    }
    let l11 = pivot11.sqrt();
    let l21 = (a21 - l20 * l10) / l11;

    let pivot22 = a22 - l20 * l20 - l21 * l21;
    if !pivot22.is_finite() || pivot22 <= 0.0 {
        return Err(GaladrielError::InvalidObservation(
            "innovation covariance must be positive definite".into(),
        ));
    }
    let l22 = pivot22.sqrt();

    let root_scale = scale.sqrt();
    let rhs = [
        innovation[0] / root_scale,
        innovation[1] / root_scale,
        innovation[2] / root_scale,
    ];
    if !rhs.iter().all(|value| value.is_finite()) {
        return Err(GaladrielError::InvalidObservation(
            "innovation/covariance scale produces a non-finite NIS".into(),
        ));
    }

    // Forward substitution solves Lz = y/sqrt(scale); zᵀz is the desired
    // quadratic form without explicitly forming an inverse.
    let z0 = rhs[0] / l00;
    let z1 = (rhs[1] - l10 * z0) / l11;
    let z2 = (rhs[2] - l20 * z0 - l21 * z1) / l22;
    let nis = z0 * z0 + z1 * z1 + z2 * z2;
    if !nis.is_finite() {
        return Err(GaladrielError::InvalidObservation(
            "injection produced a non-finite NIS".into(),
        ));
    }
    Ok(nis)
}

/// Directional injectors can propagate a native innovation delta into the common
/// projection only for the simulator's explicit identity projection. Producer
/// projections may otherwise use different units or a nonlinear basis.
fn require_identity_projection(obs: &PidObservation, innovation: [f64; 3]) -> Result<()> {
    if let Some(projection) = obs.consistency_projection() {
        if projection.dimensions() != 3 || projection.padded_values() != innovation {
            return Err(GaladrielError::InvalidObservation(
                "directional injection can update consistency_projection only when it is the simulator identity projection"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn rebuilt_observation(
    source: &PidObservation,
    nis: f64,
    research: Option<([f64; 3], [[f64; 3]; 3])>,
    projection: Option<ConsistencyProjection>,
) -> Result<PidObservation> {
    let mut rebuilt = PidObservation::try_scalar(
        source.track_id(),
        source.timestamp_ms(),
        source.sequence(),
        source.modality(),
        nis,
        source.dof(),
    )?;
    if let Some((innovation, covariance)) = research {
        rebuilt = rebuilt.try_with_research(innovation, covariance)?;
    }
    if let Some(projection) = projection {
        rebuilt = rebuilt.with_consistency_projection(projection);
    }
    Ok(rebuilt)
}

fn map_projection(
    observation: &PidObservation,
    mut update: impl FnMut(&mut [f64]),
) -> Result<Option<ConsistencyProjection>> {
    observation
        .consistency_projection()
        .map(|projection| {
            let mut values = projection.padded_values();
            update(&mut values[..usize::from(projection.dimensions())]);
            ConsistencyProjection::try_new(values, projection.dimensions(), projection.identity())
        })
        .transpose()
}

/// A per-observation attack transform.
pub trait Injection {
    /// A short name for logging/UX.
    fn name(&self) -> &'static str;
    /// Validate parameters before a stream is mutated.
    fn validate(&self) -> Result<()> {
        Ok(())
    }
    /// Mutate one observation in place.
    ///
    /// Implementations must leave `obs` unchanged when returning an error.
    fn apply(&self, obs: &mut PidObservation) -> Result<()>;
}

/// Apply an injection across a whole stream in place.
///
/// Parameters are validated before the first observation is changed, so an
/// invalid injection cannot partially corrupt a stream.
///
/// # Errors
///
/// Returns an error when injection parameters are invalid or an applicable
/// observation cannot be safely transformed.
pub fn inject(stream: &mut [PidObservation], injection: &dyn Injection) -> Result<()> {
    injection.validate()?;
    if stream.len() > MAX_INJECTION_OBSERVATIONS {
        return Err(GaladrielError::InvalidConfig(format!(
            "injection stream has {} observations; maximum is {MAX_INJECTION_OBSERVATIONS}",
            stream.len()
        )));
    }
    let mut updated = Vec::new();
    updated.try_reserve_exact(stream.len()).map_err(|_| {
        GaladrielError::InvalidConfig(format!(
            "could not reserve transactional storage for {} observations",
            stream.len()
        ))
    })?;
    updated.extend_from_slice(stream);
    for obs in &mut updated {
        injection.apply(obs)?;
    }
    stream.clone_from_slice(&updated);
    Ok(())
}

/// A targeted single-channel spoof: a persistent bias on one modality's
/// innovation from `start_frame`, inflating **only that channel's** NIS — the
/// cross-channel signature of a false-data injection (e.g. a phased acoustic
/// emitter dragging a DOA peak).
#[derive(Debug, Clone)]
pub struct PhantomAcousticDoa {
    /// Modality to corrupt.
    pub target: Modality,
    /// Frame the injection begins.
    pub start_frame: u64,
    /// Bias added to the first innovation axis (in σ units).
    pub bias: f64,
}

impl Injection for PhantomAcousticDoa {
    fn name(&self) -> &'static str {
        "phantom-doa"
    }

    fn validate(&self) -> Result<()> {
        if !self.bias.is_finite() || !(self.bias * self.bias).is_finite() {
            return Err(GaladrielError::InvalidConfig(
                "phantom bias must be finite and have a finite square".into(),
            ));
        }
        Ok(())
    }

    fn apply(&self, obs: &mut PidObservation) -> Result<()> {
        self.validate()?;
        if obs.modality() != self.target || obs.sequence().get() < self.start_frame {
            return Ok(());
        }

        match (obs.innovation(), obs.innovation_covariance()) {
            (Some(mut innovation), Some(covariance)) => {
                require_identity_projection(obs, innovation)?;
                let sigma = covariance[0][0].sqrt();
                let delta = self.bias * sigma;
                let biased = innovation[0] + delta;
                if !delta.is_finite() || !biased.is_finite() {
                    return Err(GaladrielError::InvalidObservation(
                        "phantom bias produces a non-finite innovation".into(),
                    ));
                }
                innovation[0] = biased;
                let projection = map_projection(obs, |values| values[0] += delta)?;
                let nis = recompute_nis(innovation, covariance)?;
                *obs = rebuilt_observation(obs, nis, Some((innovation, covariance)), projection)?;
            }
            (None, None) => {
                return Err(GaladrielError::InvalidObservation(
                    "directional phantom injection requires signed innovation/covariance fields"
                        .into(),
                ));
            }
            _ => {
                return Err(GaladrielError::InvalidObservation(
                    "innovation and covariance must either both be present or both be absent"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// Broadband denial: from `start_frame`, **every** channel's innovation is scaled
/// by `inflation` (> 1), raising NIS on all modalities together — the correlated
/// signature of jamming / link degradation.
///
/// A consistency projection is transformed only when signed native innovation
/// fields attest the simulator's identity projection. Scalar-only observations
/// remain injectable when they carry no projection; an arbitrary producer
/// projection is never assumed to be linear or expressed in native units.
#[derive(Debug, Clone)]
pub struct BroadbandJam {
    /// Frame the jam begins.
    pub start_frame: u64,
    /// Multiplicative innovation inflation (> 1).
    pub inflation: f64,
}

impl Injection for BroadbandJam {
    fn name(&self) -> &'static str {
        "broadband-jam"
    }

    fn validate(&self) -> Result<()> {
        if !self.inflation.is_finite()
            || self.inflation <= 1.0
            || !(self.inflation * self.inflation).is_finite()
        {
            return Err(GaladrielError::InvalidConfig(
                "jam inflation must be finite, > 1, and have a finite square".into(),
            ));
        }
        Ok(())
    }

    fn apply(&self, obs: &mut PidObservation) -> Result<()> {
        self.validate()?;
        if obs.sequence().get() < self.start_frame {
            return Ok(());
        }

        match (obs.innovation(), obs.innovation_covariance()) {
            (Some(mut innovation), Some(covariance)) => {
                require_identity_projection(obs, innovation)?;
                for value in &mut innovation {
                    *value *= self.inflation;
                }
                if !innovation.iter().all(|value| value.is_finite()) {
                    return Err(GaladrielError::InvalidObservation(
                        "jam inflation produces a non-finite innovation".into(),
                    ));
                }
                let projection = map_projection(obs, |values| {
                    for value in values {
                        *value *= self.inflation;
                    }
                })?;
                let nis = recompute_nis(innovation, covariance)?;
                *obs = rebuilt_observation(obs, nis, Some((innovation, covariance)), projection)?;
            }
            (None, None) => {
                if obs.consistency_projection().is_some() {
                    return Err(GaladrielError::InvalidObservation(
                        "scalar jam injection cannot transform a consistency projection without an identity-attested innovation"
                            .into(),
                    ));
                }
                let nis = obs.nis() * self.inflation * self.inflation;
                if !nis.is_finite() {
                    return Err(GaladrielError::InvalidObservation(
                        "jam inflation produces a non-finite scalar NIS".into(),
                    ));
                }
                let projection = map_projection(obs, |values| {
                    for value in values {
                        *value *= self.inflation;
                    }
                })?;
                *obs = rebuilt_observation(obs, nis, None, projection)?;
            }
            _ => {
                return Err(GaladrielError::InvalidObservation(
                    "innovation and covariance must either both be present or both be absent"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// A **benign target maneuver** (not an attack): from `start_frame`, a deterministic
/// triangular ramp of peak height `magnitude` over `duration` frames is added to every
/// channel's first innovation axis — but each modality sees it with its own **lag**
/// (`lag_step` × the modality's stable code), modelling heterogeneous sensor dynamics/latency.
///
/// A *synchronized* maneuver (`lag_step = 0`) stays perfectly correlated across channels,
/// so the consistency detectors should not flag it; the per-channel lag transiently
/// **decorrelates** the channels through the ramp, a benign false-positive source the
/// consistency check cannot distinguish from a spoof. This is a first-order proxy for
/// maneuver-induced non-stationarity — the false-alarm regime the stationary sim omits.
#[derive(Debug, Clone)]
pub struct Maneuver {
    /// Frame the maneuver begins.
    pub start_frame: u64,
    /// Length of the ramp (frames).
    pub duration: u64,
    /// Peak ramp height added to innovation axis 0 (σ units).
    pub magnitude: f64,
    /// Per-modality lag: modality with stable code `i` is delayed by `i × lag_step` frames.
    pub lag_step: u64,
}

impl Maneuver {
    fn profile(&self, seq: u64, lag: u64) -> Result<f64> {
        if self.duration == 0 {
            return Ok(0.0);
        }
        let start = self.start_frame.checked_add(lag).ok_or_else(|| {
            GaladrielError::InvalidConfig("maneuver start/lag arithmetic overflows u64".into())
        })?;
        let end = start.checked_add(self.duration).ok_or_else(|| {
            GaladrielError::InvalidConfig("maneuver end-frame arithmetic overflows u64".into())
        })?;
        if seq < start || seq >= end {
            return Ok(0.0);
        }
        let t = (seq - start) as f64 / self.duration as f64; // 0..1
        let tri = 1.0 - (2.0 * t - 1.0).abs(); // triangular bump: 0 at ends, 1 at centre
        Ok(self.magnitude * tri)
    }
}

impl Injection for Maneuver {
    fn name(&self) -> &'static str {
        "maneuver"
    }

    fn validate(&self) -> Result<()> {
        if !self.magnitude.is_finite() {
            return Err(GaladrielError::InvalidConfig(
                "maneuver magnitude must be finite".into(),
            ));
        }
        if self.duration == 0 {
            return Ok(());
        }

        let max_modality_code = Modality::ALL
            .iter()
            .map(|&modality| u64::from(modality.stable_code()))
            .max()
            .unwrap_or(0);
        let max_lag = max_modality_code
            .checked_mul(self.lag_step)
            .ok_or_else(|| {
                GaladrielError::InvalidConfig(
                    "maneuver modality/lag arithmetic overflows u64".into(),
                )
            })?;
        let latest_start = self.start_frame.checked_add(max_lag).ok_or_else(|| {
            GaladrielError::InvalidConfig("maneuver start/lag arithmetic overflows u64".into())
        })?;
        latest_start.checked_add(self.duration).ok_or_else(|| {
            GaladrielError::InvalidConfig("maneuver end-frame arithmetic overflows u64".into())
        })?;
        Ok(())
    }

    fn apply(&self, obs: &mut PidObservation) -> Result<()> {
        self.validate()?;
        if self.duration == 0 {
            return Ok(());
        }
        let lag = u64::from(obs.modality().stable_code())
            .checked_mul(self.lag_step)
            .ok_or_else(|| {
                GaladrielError::InvalidConfig(
                    "maneuver modality/lag arithmetic overflows u64".into(),
                )
            })?;
        let add = self.profile(obs.sequence().get(), lag)?;
        if add == 0.0 {
            return Ok(());
        }
        let (Some(mut innovation), Some(covariance)) =
            (obs.innovation(), obs.innovation_covariance())
        else {
            return Err(GaladrielError::InvalidObservation(
                "maneuver injection requires signed innovation/covariance fields".into(),
            ));
        };
        require_identity_projection(obs, innovation)?;
        let delta = add * covariance[0][0].sqrt();
        let perturbed = innovation[0] + delta;
        if !perturbed.is_finite() {
            return Err(GaladrielError::InvalidObservation(
                "maneuver produces a non-finite innovation".into(),
            ));
        }
        innovation[0] = perturbed;
        let nis = recompute_nis(innovation, covariance)?;

        let projection = map_projection(obs, |values| values[0] += delta)?;
        *obs = rebuilt_observation(obs, nis, Some((innovation, covariance)), projection)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{generate, ScenarioConfig, ScenarioParams, ScenarioResearchProfile};
    use galadriel_core::{ConsistencyProjection, Mirror, ReleaseSuite, Verdict};

    const IDENTITY_COVARIANCE: [[f64; 3]; 3] = [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];

    fn scenario(mut update: impl FnMut(&mut ScenarioParams)) -> ScenarioConfig {
        let mut params = ScenarioResearchProfile::SyntheticV0_9.params();
        update(&mut params);
        ScenarioConfig::try_new(params).expect("test scenario must be valid")
    }

    fn scalar(
        track_id: u64,
        timestamp_ms: u64,
        sequence: u64,
        modality: Modality,
        nis: f64,
        dof: u8,
    ) -> PidObservation {
        PidObservation::try_scalar_raw(track_id, timestamp_ms, sequence, modality, nis, dof)
            .unwrap()
    }

    fn research_observation(
        modality: Modality,
        nis: f64,
        innovation: [f64; 3],
        covariance: [[f64; 3]; 3],
        projection_values: [f64; 3],
        context_id: u64,
    ) -> PidObservation {
        let projection =
            ConsistencyProjection::try_new_raw(projection_values, 3, 1, context_id, 1).unwrap();
        scalar(1, 0, 1, modality, nis, 3)
            .try_with_research(innovation, covariance)
            .unwrap()
            .with_consistency_projection(projection)
    }

    fn final_verdict(stream: &[PidObservation], n_mods: usize) -> Verdict {
        let modalities = stream[..n_mods]
            .iter()
            .map(PidObservation::modality)
            .collect::<Vec<_>>();
        let suite = ReleaseSuite::standalone_advisory_v0_9(&modalities)
            .expect("valid release-suite config");
        let mut m = Mirror::from_release_suite(&suite);
        let track = stream[0].track_id();
        let mut last = None;
        for chunk in stream.chunks(n_mods) {
            for o in chunk {
                m.ingest(o).expect("generated observation must be valid");
            }
            last = Some(
                m.assess(track, chunk[0].sequence())
                    .expect("generated frame must be assessable"),
            );
        }
        last.expect("non-empty stream").verdict().clone()
    }

    #[test]
    fn clean_is_nominal() {
        let cfg = ScenarioResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named scenario profile must be valid");
        let s = generate(&cfg).expect("valid scenario");
        assert_eq!(final_verdict(&s, cfg.modalities().len()), Verdict::Nominal);
    }

    #[test]
    fn phantom_produces_attributed_inconsistency_on_the_targeted_channel() {
        let cfg = ScenarioResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named scenario profile must be valid");
        let mut s = generate(&cfg).expect("valid scenario");
        inject(
            &mut s,
            &PhantomAcousticDoa {
                target: Modality::Acoustic,
                start_frame: 110,
                bias: 8.0,
            },
        )
        .expect("valid phantom injection");
        match final_verdict(&s, cfg.modalities().len()) {
            Verdict::AttributedInconsistency { channels } => {
                assert!(channels.contains(&Modality::Acoustic))
            }
            other => panic!("expected AttributedInconsistency, got {other:?}"),
        }
    }

    #[test]
    fn broadband_jam_produces_broad_degradation_evidence() {
        let cfg = ScenarioResearchProfile::SyntheticV0_9
            .try_config()
            .expect("named scenario profile must be valid");
        let mut s = generate(&cfg).expect("valid scenario");
        inject(
            &mut s,
            &BroadbandJam {
                start_frame: 110,
                inflation: 3.0,
            },
        )
        .expect("valid jam injection");
        assert_eq!(
            final_verdict(&s, cfg.modalities().len()),
            Verdict::BroadDegradation
        );
    }

    #[test]
    fn directional_phantom_rejects_scalar_only_observations() {
        let mut obs = scalar(1, 500, 5, Modality::Acoustic, 3.0, 3);
        let original = obs.clone();
        assert!(PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 5,
            bias: 4.0,
        }
        .apply(&mut obs)
        .is_err());
        assert_eq!(obs.nis(), original.nis());

        let mut early = scalar(1, 0, 0, Modality::Acoustic, 3.0, 3);
        PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 5,
            bias: 4.0,
        }
        .apply(&mut early)
        .expect("valid pre-onset phantom injection");
        assert!((early.nis() - 3.0).abs() < 1e-12, "pre-onset untouched");
    }

    #[test]
    fn projection_transforming_injectors_reject_nonidentity_common_projections() {
        let mut observation = research_observation(
            Modality::Acoustic,
            0.0,
            [0.0; 3],
            IDENTITY_COVARIANCE,
            [10.0, 0.0, 0.0],
            2,
        );
        let original_projection = observation.consistency_projection().cloned();

        assert!(PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 0,
            bias: 2.0,
        }
        .apply(&mut observation)
        .is_err());
        assert_eq!(
            observation.consistency_projection(),
            original_projection.as_ref()
        );
        assert_eq!(observation.innovation(), Some([0.0; 3]));

        let mut jammed = research_observation(
            Modality::Acoustic,
            0.0,
            [0.0; 3],
            IDENTITY_COVARIANCE,
            [10.0, 0.0, 0.0],
            2,
        );
        let original = jammed.clone();
        assert!(BroadbandJam {
            start_frame: 0,
            inflation: 2.0,
        }
        .apply(&mut jammed)
        .is_err());
        assert_eq!(jammed, original);
    }

    #[test]
    fn jam_scalar_fallback_scales_nis_by_inflation_squared() {
        let mut obs = scalar(1, 500, 5, Modality::Radar, 4.0, 3);
        BroadbandJam {
            start_frame: 5,
            inflation: 3.0,
        }
        .apply(&mut obs)
        .expect("valid scalar jam injection");
        assert!((obs.nis() - 4.0 * 9.0).abs() < 1e-9, "nis={}", obs.nis());

        let projection = ConsistencyProjection::try_new_raw([1.0, 0.0, 0.0], 3, 1, 1, 1).unwrap();
        let mut projected =
            scalar(1, 500, 5, Modality::Radar, 4.0, 3).with_consistency_projection(projection);
        let original = projected.clone();
        assert!(BroadbandJam {
            start_frame: 5,
            inflation: 3.0,
        }
        .apply(&mut projected)
        .is_err());
        assert_eq!(projected, original);
    }

    #[test]
    fn maneuver_perturbs_the_innovation_inside_its_window() {
        let cfg = scenario(|params| {
            params.frames = 200;
            params.seed = 3;
        });
        let base = generate(&cfg).expect("valid scenario");
        let mut man = base.clone();
        inject(
            &mut man,
            &Maneuver {
                start_frame: 100,
                duration: 20,
                magnitude: 8.0,
                lag_step: 0,
            },
        )
        .expect("valid maneuver injection");
        // Inside the maneuver window the innovation is perturbed; well outside it is untouched.
        let mid = man
            .iter()
            .zip(&base)
            .find(|(m, _)| m.sequence().get() == 108 && m.modality() == Modality::Visual)
            .unwrap();
        assert!(
            (mid.0.innovation().unwrap()[0] - mid.1.innovation().unwrap()[0]).abs() > 1.0,
            "innovation should be perturbed mid-maneuver"
        );
        let far = man
            .iter()
            .zip(&base)
            .find(|(m, _)| m.sequence().get() == 5 && m.modality() == Modality::Visual)
            .unwrap();
        assert!(
            (far.0.innovation().unwrap()[0] - far.1.innovation().unwrap()[0]).abs() < 1e-12,
            "innovation should be untouched before the maneuver"
        );
    }

    #[test]
    fn maneuver_magnitude_is_in_axis_standard_deviations() {
        let covariance = [[9.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let mut observation =
            research_observation(Modality::Visual, 0.0, [0.0; 3], covariance, [0.0; 3], 1);
        Maneuver {
            start_frame: 0,
            duration: 2,
            magnitude: 2.0,
            lag_step: 0,
        }
        .apply(&mut observation)
        .expect("valid maneuver");
        assert_eq!(observation.innovation().unwrap()[0], 6.0);
        assert_eq!(
            observation.consistency_projection().unwrap().values()[0],
            6.0
        );
        assert!((observation.nis() - 4.0).abs() < 1e-12);
    }

    #[test]
    fn stream_injection_is_transactional_on_late_failure() {
        struct FailAfterFirstFrame;

        impl Injection for FailAfterFirstFrame {
            fn name(&self) -> &'static str {
                "fail-after-first-frame"
            }

            fn apply(&self, observation: &mut PidObservation) -> Result<()> {
                if observation.sequence().get() > 0 {
                    return Err(GaladrielError::InvalidObservation(
                        "deliberate late test failure".into(),
                    ));
                }
                *observation = rebuilt_observation(
                    observation,
                    observation.nis() + 1.0,
                    observation
                        .innovation()
                        .zip(observation.innovation_covariance()),
                    observation.consistency_projection().cloned(),
                )?;
                Ok(())
            }
        }

        let cfg = scenario(|params| params.frames = 2);
        let mut stream = generate(&cfg).unwrap();
        let original = stream.clone();
        assert!(inject(&mut stream, &FailAfterFirstFrame).is_err());
        assert_eq!(stream[0].nis(), original[0].nis());
        assert_eq!(stream.last().unwrap().nis(), original.last().unwrap().nis());
    }

    #[test]
    fn recompute_nis_uses_the_full_covariance() {
        let covariance = [[2.0, 1.0, 0.0], [1.0, 2.0, 0.0], [0.0, 0.0, 1.0]];
        let nis = recompute_nis([1.0, 1.0, 2.0], covariance)
            .expect("symmetric positive-definite covariance");
        assert!((nis - 14.0 / 3.0).abs() < 1e-12, "nis={nis}");
    }

    #[test]
    fn recompute_nis_rejects_non_spd_covariance() {
        let indefinite = [[1.0, 2.0, 0.0], [2.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        assert!(recompute_nis([1.0, 0.0, 0.0], indefinite).is_err());

        let asymmetric = [[1.0, 0.5, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        assert!(recompute_nis([1.0, 0.0, 0.0], asymmetric).is_err());

        let tiny_asymmetric = [[1e-12, 0.0, 0.0], [1e-10, 1e-12, 0.0], [0.0, 0.0, 1e-12]];
        assert!(recompute_nis([1e-12, 0.0, 0.0], tiny_asymmetric).is_err());
    }

    #[test]
    fn recompute_nis_accepts_fixture_scale_covariance_roundoff() {
        let covariance = [
            [
                1.588_373_458_602_466_3,
                8.673_617_379_884_035e-19,
                -4.336_808_689_942_018e-19,
            ],
            [
                0.0,
                0.001_170_253_521_333_416_1,
                -3.388_131_789_017_201_4e-21,
            ],
            [
                -4.336_808_689_942_018e-19,
                -3.388_131_789_017_201_4e-21,
                0.001_153_509_640_919_248_5,
            ],
        ];
        let nis = recompute_nis([-1.0, 0.01, 0.001], covariance)
            .expect("accepted covariance must be symmetrized before Cholesky");
        assert!(nis.is_finite());
    }

    #[test]
    fn phantom_bias_scales_by_axis_standard_deviation() {
        let covariance = [[4.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let mut obs =
            research_observation(Modality::Acoustic, 0.0, [0.0; 3], covariance, [0.0; 3], 1);
        PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 0,
            bias: 2.0,
        }
        .apply(&mut obs)
        .expect("valid phantom injection");

        assert_eq!(obs.innovation().expect("research innovation")[0], 4.0);
        assert_eq!(obs.consistency_projection().unwrap().values()[0], 4.0);
        assert!((obs.nis() - 4.0).abs() < 1e-12, "nis={}", obs.nis());
    }

    #[test]
    fn invalid_injection_parameters_do_not_mutate_observations() {
        let original = scalar(1, 0, 0, Modality::Acoustic, 3.0, 3);

        let mut phantom = vec![original.clone()];
        assert!(inject(
            &mut phantom,
            &PhantomAcousticDoa {
                target: Modality::Acoustic,
                start_frame: 0,
                bias: f64::NAN,
            },
        )
        .is_err());
        assert_eq!(phantom[0].nis(), original.nis());

        let mut jam = vec![original.clone()];
        assert!(inject(
            &mut jam,
            &BroadbandJam {
                start_frame: 0,
                inflation: f64::INFINITY,
            },
        )
        .is_err());
        assert_eq!(jam[0].nis(), original.nis());

        let mut maneuver = vec![original.clone()];
        assert!(inject(
            &mut maneuver,
            &Maneuver {
                start_frame: 0,
                duration: 10,
                magnitude: f64::NAN,
                lag_step: 0,
            },
        )
        .is_err());
        assert_eq!(maneuver[0].nis(), original.nis());
    }

    #[test]
    fn invalid_research_state_is_rejected_before_an_observation_exists() {
        let innovation = [1.0, 0.0, 0.0];
        let covariance = [[1.0, 2.0, 0.0], [2.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let baseline = scalar(1, 0, 0, Modality::Acoustic, 1.0, 3);
        let result = baseline.clone().try_with_research(innovation, covariance);

        assert!(result.is_err());
        assert_eq!(baseline.nis(), 1.0);
        assert_eq!(baseline.innovation(), None);
        assert_eq!(baseline.innovation_covariance(), None);
    }

    #[test]
    fn maneuver_rejects_overflow_before_mutating_the_stream() {
        let original = scalar(1, 0, 0, Modality::Visual, 3.0, 3);
        let mut stream = vec![original.clone()];
        let result = inject(
            &mut stream,
            &Maneuver {
                start_frame: u64::MAX,
                duration: 1,
                magnitude: 2.0,
                lag_step: u64::MAX,
            },
        );

        assert!(result.is_err());
        assert_eq!(stream[0].nis(), original.nis());
    }
}
