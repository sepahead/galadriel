//! Attack injections that transform a clean stream into a spoof or a jam.

use galadriel_core::{
    validate_and_symmetrize_covariance, GaladrielError, Modality, PidObservation, Result,
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
        if obs.modality != self.target || obs.seq < self.start_frame {
            return Ok(());
        }
        obs.validate()?;

        let mut updated = obs.clone();
        match (updated.innovation, updated.innovation_cov) {
            (Some(mut innovation), Some(covariance)) => {
                let sigma = covariance[0][0].sqrt();
                let delta = self.bias * sigma;
                let biased = innovation[0] + delta;
                if !delta.is_finite() || !biased.is_finite() {
                    return Err(GaladrielError::InvalidObservation(
                        "phantom bias produces a non-finite innovation".into(),
                    ));
                }
                innovation[0] = biased;
                updated.innovation = Some(innovation);
                if let Some(mut projection) = updated.consistency_projection {
                    projection.values[0] += delta;
                    projection.validate()?;
                    updated.consistency_projection = Some(projection);
                }
                updated.nis = recompute_nis(innovation, covariance)?;
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
        updated.validate()?;
        *obs = updated;
        Ok(())
    }
}

/// Broadband denial: from `start_frame`, **every** channel's innovation is scaled
/// by `inflation` (> 1), raising NIS on all modalities together — the correlated
/// signature of jamming / link degradation.
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
        if obs.seq < self.start_frame {
            return Ok(());
        }
        obs.validate()?;

        let mut updated = obs.clone();
        match (updated.innovation, updated.innovation_cov) {
            (Some(mut innovation), Some(covariance)) => {
                for value in &mut innovation {
                    *value *= self.inflation;
                }
                if !innovation.iter().all(|value| value.is_finite()) {
                    return Err(GaladrielError::InvalidObservation(
                        "jam inflation produces a non-finite innovation".into(),
                    ));
                }
                updated.innovation = Some(innovation);
                if let Some(mut projection) = updated.consistency_projection {
                    for value in &mut projection.values[..projection.dimensions as usize] {
                        *value *= self.inflation;
                    }
                    projection.validate()?;
                    updated.consistency_projection = Some(projection);
                }
                updated.nis = recompute_nis(innovation, covariance)?;
            }
            (None, None) => {
                let nis = updated.nis * self.inflation * self.inflation;
                if !nis.is_finite() {
                    return Err(GaladrielError::InvalidObservation(
                        "jam inflation produces a non-finite scalar NIS".into(),
                    ));
                }
                updated.nis = nis;
                if let Some(mut projection) = updated.consistency_projection {
                    for value in &mut projection.values[..projection.dimensions as usize] {
                        *value *= self.inflation;
                    }
                    projection.validate()?;
                    updated.consistency_projection = Some(projection);
                }
            }
            _ => {
                return Err(GaladrielError::InvalidObservation(
                    "innovation and covariance must either both be present or both be absent"
                        .into(),
                ));
            }
        }
        updated.validate()?;
        *obs = updated;
        Ok(())
    }
}

/// A **benign target maneuver** (not an attack): from `start_frame`, a deterministic
/// triangular ramp of peak height `magnitude` over `duration` frames is added to every
/// channel's first innovation axis — but each modality sees it with its own **lag**
/// (`lag_step` × the modality's enum discriminant), modelling heterogeneous sensor dynamics/latency.
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
    /// Per-modality lag: modality with discriminant `i` is delayed by `i × lag_step` frames.
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

        let max_modality_discriminant = Modality::ALL
            .iter()
            .map(|&modality| modality as u64)
            .max()
            .unwrap_or(0);
        let max_lag = max_modality_discriminant
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
        let lag = (obs.modality as u64)
            .checked_mul(self.lag_step)
            .ok_or_else(|| {
                GaladrielError::InvalidConfig(
                    "maneuver modality/lag arithmetic overflows u64".into(),
                )
            })?;
        let add = self.profile(obs.seq, lag)?;
        if add == 0.0 {
            return Ok(());
        }
        obs.validate()?;

        let (Some(mut innovation), Some(covariance)) = (obs.innovation, obs.innovation_cov) else {
            return Err(GaladrielError::InvalidObservation(
                "maneuver injection requires signed innovation/covariance fields".into(),
            ));
        };
        let delta = add * covariance[0][0].sqrt();
        let perturbed = innovation[0] + delta;
        if !perturbed.is_finite() {
            return Err(GaladrielError::InvalidObservation(
                "maneuver produces a non-finite innovation".into(),
            ));
        }
        innovation[0] = perturbed;
        let nis = recompute_nis(innovation, covariance)?;

        let mut updated = obs.clone();
        updated.innovation = Some(innovation);
        if let Some(mut projection) = updated.consistency_projection {
            projection.values[0] += delta;
            projection.validate()?;
            updated.consistency_projection = Some(projection);
        }
        updated.nis = nis;
        updated.validate()?;
        *obs = updated;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{generate, ScenarioConfig};
    use galadriel_core::{ConsistencyProjection, DetectorConfig, Mirror, Verdict};

    fn final_verdict(stream: &[PidObservation], n_mods: usize) -> Verdict {
        let mut m = Mirror::new(DetectorConfig::default()).expect("valid detector config");
        let track = stream[0].track_id;
        let mut last = None;
        for chunk in stream.chunks(n_mods) {
            for o in chunk {
                m.ingest(o).expect("generated observation must be valid");
            }
            last = Some(
                m.assess(track, chunk[0].seq)
                    .expect("generated frame must be assessable"),
            );
        }
        last.expect("non-empty stream").verdict
    }

    #[test]
    fn clean_is_nominal() {
        let cfg = ScenarioConfig::default();
        let s = generate(&cfg).expect("valid scenario");
        assert_eq!(final_verdict(&s, cfg.modalities.len()), Verdict::Nominal);
    }

    #[test]
    fn phantom_is_spoof_on_the_targeted_channel() {
        let cfg = ScenarioConfig::default();
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
        match final_verdict(&s, cfg.modalities.len()) {
            Verdict::Spoof { channels } => assert!(channels.contains(&Modality::Acoustic)),
            other => panic!("expected Spoof, got {other:?}"),
        }
    }

    #[test]
    fn broadband_jam_is_jam() {
        let cfg = ScenarioConfig::default();
        let mut s = generate(&cfg).expect("valid scenario");
        inject(
            &mut s,
            &BroadbandJam {
                start_frame: 110,
                inflation: 3.0,
            },
        )
        .expect("valid jam injection");
        assert_eq!(final_verdict(&s, cfg.modalities.len()), Verdict::Jam);
    }

    #[test]
    fn directional_phantom_rejects_scalar_only_observations() {
        let mut obs = PidObservation::scalar(1, 500, 5, Modality::Acoustic, 3.0, 3);
        let original = obs.clone();
        assert!(PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 5,
            bias: 4.0,
        }
        .apply(&mut obs)
        .is_err());
        assert_eq!(obs.nis, original.nis);

        let mut early = PidObservation::scalar(1, 0, 0, Modality::Acoustic, 3.0, 3);
        PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 5,
            bias: 4.0,
        }
        .apply(&mut early)
        .expect("valid pre-onset phantom injection");
        assert!((early.nis - 3.0).abs() < 1e-12, "pre-onset untouched");
    }

    #[test]
    fn jam_scalar_fallback_scales_nis_by_inflation_squared() {
        let mut obs = PidObservation::scalar(1, 500, 5, Modality::Radar, 4.0, 3);
        BroadbandJam {
            start_frame: 5,
            inflation: 3.0,
        }
        .apply(&mut obs)
        .expect("valid scalar jam injection");
        assert!((obs.nis - 4.0 * 9.0).abs() < 1e-9, "nis={}", obs.nis);
    }

    #[test]
    fn maneuver_perturbs_the_innovation_inside_its_window() {
        let cfg = ScenarioConfig {
            frames: 200,
            seed: 3,
            ..Default::default()
        };
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
            .find(|(m, _)| m.seq == 108 && m.modality == Modality::Visual)
            .unwrap();
        assert!(
            (mid.0.innovation.unwrap()[0] - mid.1.innovation.unwrap()[0]).abs() > 1.0,
            "innovation should be perturbed mid-maneuver"
        );
        let far = man
            .iter()
            .zip(&base)
            .find(|(m, _)| m.seq == 5 && m.modality == Modality::Visual)
            .unwrap();
        assert!(
            (far.0.innovation.unwrap()[0] - far.1.innovation.unwrap()[0]).abs() < 1e-12,
            "innovation should be untouched before the maneuver"
        );
    }

    #[test]
    fn maneuver_magnitude_is_in_axis_standard_deviations() {
        let mut observation = PidObservation {
            track_id: 1,
            timestamp_ms: 0,
            seq: 1,
            modality: Modality::Visual,
            nis: 0.0,
            dof: 3,
            innovation: Some([0.0; 3]),
            innovation_cov: Some([[9.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]]),
            consistency_projection: Some(ConsistencyProjection {
                values: [0.0; 3],
                dimensions: 3,
                frame_id: 1,
                context_id: 1,
                prior_id: 1,
            }),
        };
        Maneuver {
            start_frame: 0,
            duration: 2,
            magnitude: 2.0,
            lag_step: 0,
        }
        .apply(&mut observation)
        .expect("valid maneuver");
        assert_eq!(observation.innovation.unwrap()[0], 6.0);
        assert_eq!(observation.consistency_projection.unwrap().values[0], 6.0);
        assert!((observation.nis - 4.0).abs() < 1e-12);
    }

    #[test]
    fn stream_injection_is_transactional_on_late_failure() {
        let cfg = ScenarioConfig {
            frames: 2,
            ..Default::default()
        };
        let mut stream = generate(&cfg).unwrap();
        stream.last_mut().unwrap().innovation_cov =
            Some([[1.0, 2.0, 0.0], [2.0, 1.0, 0.0], [0.0, 0.0, 1.0]]);
        let original = stream.clone();
        assert!(inject(
            &mut stream,
            &BroadbandJam {
                start_frame: 0,
                inflation: 2.0,
            },
        )
        .is_err());
        assert_eq!(stream[0].nis, original[0].nis);
        assert_eq!(stream.last().unwrap().nis, original.last().unwrap().nis);
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
        let mut obs = PidObservation {
            track_id: 1,
            timestamp_ms: 0,
            seq: 0,
            modality: Modality::Acoustic,
            nis: 0.0,
            dof: 3,
            innovation: Some([0.0; 3]),
            innovation_cov: Some([[4.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]]),
            consistency_projection: Some(ConsistencyProjection {
                values: [0.0; 3],
                dimensions: 3,
                frame_id: 1,
                context_id: 1,
                prior_id: 1,
            }),
        };
        PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 0,
            bias: 2.0,
        }
        .apply(&mut obs)
        .expect("valid phantom injection");

        assert_eq!(obs.innovation.expect("research innovation")[0], 4.0);
        assert_eq!(obs.consistency_projection.unwrap().values[0], 4.0);
        assert!((obs.nis - 4.0).abs() < 1e-12, "nis={}", obs.nis);
    }

    #[test]
    fn invalid_injection_parameters_do_not_mutate_observations() {
        let original = PidObservation::scalar(1, 0, 0, Modality::Acoustic, 3.0, 3);

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
        assert_eq!(phantom[0].nis, original.nis);

        let mut jam = vec![original.clone()];
        assert!(inject(
            &mut jam,
            &BroadbandJam {
                start_frame: 0,
                inflation: f64::INFINITY,
            },
        )
        .is_err());
        assert_eq!(jam[0].nis, original.nis);

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
        assert_eq!(maneuver[0].nis, original.nis);
    }

    #[test]
    fn failed_research_update_is_transactional() {
        let innovation = [1.0, 0.0, 0.0];
        let covariance = [[1.0, 2.0, 0.0], [2.0, 1.0, 0.0], [0.0, 0.0, 1.0]];
        let mut obs = PidObservation {
            track_id: 1,
            timestamp_ms: 0,
            seq: 0,
            modality: Modality::Acoustic,
            nis: 1.0,
            dof: 3,
            innovation: Some(innovation),
            innovation_cov: Some(covariance),
            consistency_projection: None,
        };
        let result = PhantomAcousticDoa {
            target: Modality::Acoustic,
            start_frame: 0,
            bias: 2.0,
        }
        .apply(&mut obs);

        assert!(result.is_err());
        assert_eq!(obs.nis, 1.0);
        assert_eq!(obs.innovation, Some(innovation));
        assert_eq!(obs.innovation_cov, Some(covariance));
    }

    #[test]
    fn maneuver_rejects_overflow_before_mutating_the_stream() {
        let original = PidObservation::scalar(1, 0, 0, Modality::Visual, 3.0, 3);
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
        assert_eq!(stream[0].nis, original.nis);
    }
}
