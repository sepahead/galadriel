#![forbid(unsafe_code)]
//! **Is PID / mutual information actually justified over cheap Pearson correlation?**
//!
//! This is an "earn your complexity" test. For a *jointly-Gaussian, linearly* coupled
//! population, true mutual information is a monotone function of `|ρ|`
//! (`MI = −½ ln(1 − ρ²)`), so it contains no additional population dependence
//! parameter. Finite-sample Pearson and KSG estimators need not have identical ROCs.
//!
//! MI can earn its place where the dependence is **nonlinear**: there `|ρ| ≈ 0`
//! even though the variables are strongly dependent, so a linear correlation score can
//! be weak while a nonparametric dependence score retains signal. This study measures both
//! detectors' ROC-AUC at separating a *coupled* pair from a *decoupled* one (a
//! permutation null), under a **linear**
//! coupling (`Y = X + ε`) and a **nonlinear** one (`Y = ±X + ε`, random sign — for
//! which the *population* `corr(X, Y) = 0`, though the sample correlation has an
//! inflated variance from the kurtosis of `X`, so a `|ρ|` check can still score above
//! chance through that finite-sample artifact).
//!
//! The results are simulation evidence for a narrower statement: **KSG MI is a
//! nonparametric dependence score** and may detect structure that Pearson correlation
//! does not. It still relies on metric, neighbourhood, and tuning choices. The results
//! are not a calibration, a field-performance guarantee, or proof that PID is necessary.
//! The PID atoms reported below are diagnostic study outputs; Galadriel's current PID
//! verdict is based on pairwise MI and therefore does not detect pure synergy by itself.

use galadriel_core::{correlation::pearson, GaladrielError, Result};
use pid_core::{ksg_mi, pid2_isx_estimate, Jitter, KsgConfig, MatOwned, Pid2Config};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use rand_distr::{Distribution, Normal};

/// The cross-variable coupling under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coupling {
    /// `Y = X + ε` — the linear-Gaussian case where population MI is monotone in `|ρ|`.
    Linear,
    /// `Y = ±X + ε` (random sign per sample) — strongly dependent (`|Y| ≈ |X|`) yet
    /// *population* `corr(X, Y) = 0`. The sample correlation is *not* chance-level: its
    /// variance is inflated by the kurtosis of `X` (a fourth-moment artifact), so finite
    /// samples can give a `|ρ|` detector some separation even without population-level
    /// linear dependence.
    Nonlinear,
}

impl Coupling {
    /// All couplings.
    pub const ALL: [Coupling; 2] = [Coupling::Linear, Coupling::Nonlinear];

    /// A label.
    pub fn label(self) -> &'static str {
        match self {
            Coupling::Linear => "linear     (Y = X + e)",
            Coupling::Nonlinear => "nonlinear  (Y = +/-X + e)",
        }
    }
}

/// Absolute Pearson correlation with finite-input and equal-length validation.
pub fn abs_pearson(x: &[f64], y: &[f64]) -> Result<f64> {
    pearson(x, y).map(f64::abs)
}

/// KSG mutual information (nats), jittered to break kNN-radius ties.
fn ksg(seed: u64, x: &[f64], y: &[f64]) -> Result<f64> {
    if x.len() != y.len() || x.is_empty() {
        return Err(GaladrielError::InvalidChannels(format!(
            "KSG columns must be non-empty and equally sized ({} != {})",
            x.len(),
            y.len()
        )));
    }
    if !x.iter().chain(y).all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("KSG input"));
    }

    // pid-core's Jitter restarts its deterministic RNG on every `apply`. Reusing one
    // instance for both columns would therefore add the *same* noise to X and Y and
    // manufacture dependence. Domain-separated seeds make the perturbations independent.
    let build = |values: &[f64], domain: u64| {
        let matrix = MatOwned::new(values.to_vec(), values.len(), 1).map_err(pid_error)?;
        Jitter::new(1e-6, seed ^ domain)
            .and_then(|jitter| jitter.apply(matrix.as_ref()))
            .map_err(pid_error)
    };
    let a = build(x, 0x584A_4954_5445_5201)?;
    let b = build(y, 0x594A_4954_5445_5202)?;
    ksg_mi(a.as_ref(), b.as_ref(), &KsgConfig::default()).map_err(pid_error)
}

fn pid_error(error: pid_core::PidError) -> GaladrielError {
    GaladrielError::InvalidChannels(format!("PID estimator rejected study input: {error}"))
}

/// Mechanical minimum trials per inferential class/arm; this is not a power guarantee.
pub const MIN_TRIALS: usize = 20;
/// Minimum resample count accepted for an inferential percentile interval.
pub const MIN_BOOTSTRAP_RESAMPLES: usize = 200;
/// Maximum trials per inferential class/arm.
pub const MAX_TRIALS: usize = 1_000;
const MAX_SAMPLES: usize = 10_000;
/// Upper bound on the approximate number of pair-distance comparisons in one study.
const MAX_DISTANCE_COMPARISONS: usize = 1_000_000_000;
/// Upper bound on AUC score comparisons performed across all bootstrap CIs in one study.
const MAX_BOOTSTRAP_AUC_COMPARISONS: usize = 500_000_000;
/// Upper bound on aggregate pair-distance comparisons in the default CLI suite.
const MAX_CLI_DISTANCE_COMPARISONS: usize = 2_000_000_000;
/// Upper bound on aggregate AUC comparisons in the default CLI suite.
const MAX_CLI_BOOTSTRAP_AUC_COMPARISONS: usize = 500_000_000;

fn checked_product(label: &str, factors: &[usize]) -> Result<usize> {
    factors.iter().try_fold(1usize, |work, &factor| {
        work.checked_mul(factor).ok_or_else(|| {
            GaladrielError::InvalidConfig(format!("{label} work estimate overflowed"))
        })
    })
}

fn enforce_work(label: &str, work: usize, limit: usize) -> Result<()> {
    if work > limit {
        return Err(GaladrielError::InvalidConfig(format!(
            "{label} work estimate {work} exceeds limit {limit}; reduce trials, samples, or bootstrap count"
        )));
    }
    Ok(())
}

fn ksg_work(trials: usize, n: usize, estimator_equivalents: usize) -> Result<usize> {
    checked_product(
        "KSG distance-comparison",
        &[trials, n, n, estimator_equivalents],
    )
}

fn bootstrap_work(class_len: usize, n_boot: usize, ci_count: usize) -> Result<usize> {
    checked_product("AUC bootstrap", &[class_len, class_len, n_boot, ci_count])
}

fn sequential_distance_work(trials: usize) -> Result<usize> {
    let arms = 3;
    let window_work = checked_product(
        "sequential window-KSG",
        &[
            trials,
            arms,
            SEQ_EVAL_LEN / SEQ_STRIDE,
            SEQ_WINDOW,
            SEQ_WINDOW,
        ],
    )?;
    let local_per_stream = checked_sum(
        "sequential local-MI",
        &[
            checked_product(
                "sequential reference local-MI",
                &[SEQ_REF_LEN, SEQ_REF_LEN - 1],
            )?,
            checked_product(
                "sequential evaluation local-MI",
                &[SEQ_EVAL_LEN, SEQ_REF_LEN],
            )?,
        ],
    )?;
    let local_work = checked_product("sequential local-MI", &[trials, arms, local_per_stream])?;
    checked_sum("sequential distance-comparison", &[window_work, local_work])
}

fn validate_ksg_work(trials: usize, n: usize, estimator_equivalents: usize) -> Result<()> {
    enforce_work(
        "KSG distance-comparison",
        ksg_work(trials, n, estimator_equivalents)?,
        MAX_DISTANCE_COMPARISONS,
    )
}

fn validate_bootstrap_work(class_len: usize, n_boot: usize, ci_count: usize) -> Result<()> {
    enforce_work(
        "AUC bootstrap",
        bootstrap_work(class_len, n_boot, ci_count)?,
        MAX_BOOTSTRAP_AUC_COMPARISONS,
    )
}

fn validate_sequential_work(trials: usize) -> Result<()> {
    enforce_work(
        "sequential distance-comparison",
        sequential_distance_work(trials)?,
        MAX_DISTANCE_COMPARISONS,
    )
}

fn validate_study(trials: usize, n: usize, sigma: Option<f64>) -> Result<()> {
    if !(MIN_TRIALS..=MAX_TRIALS).contains(&trials) {
        return Err(GaladrielError::InvalidConfig(format!(
            "study trials must be in {MIN_TRIALS}..={MAX_TRIALS}"
        )));
    }
    if !(8..=MAX_SAMPLES).contains(&n) {
        return Err(GaladrielError::InvalidConfig(format!(
            "study samples must be in 8..={MAX_SAMPLES}"
        )));
    }
    if let Some(sigma) = sigma {
        if !sigma.is_finite() || sigma <= 0.0 || sigma > 1_000_000.0 {
            return Err(GaladrielError::InvalidConfig(
                "study sigma must be finite and in (0, 1_000_000]".into(),
            ));
        }
    }
    Ok(())
}

fn checked_sum(label: &str, values: &[usize]) -> Result<usize> {
    values.iter().try_fold(0usize, |total, &value| {
        total.checked_add(value).ok_or_else(|| {
            GaladrielError::InvalidConfig(format!("{label} work estimate overflowed"))
        })
    })
}

/// Validate the complete default command-line study suite before any simulation starts.
///
/// This catches configurations that are individually well-formed but whose aggregate
/// quadratic neighbour-distance or AUC-bootstrap work would exceed the CLI resource budget.
pub fn preflight_default_suite(trials: usize) -> Result<()> {
    validate_study(trials, 400, Some(0.5))?;
    let synergy_trials = trials.min(250);
    let sequential_trials = trials.min(100);
    validate_study(synergy_trials, 600, None)?;
    validate_study(sequential_trials, SEQ_REF_LEN + SEQ_EVAL_LEN, Some(0.5))?;

    let distance_total = checked_sum(
        "default CLI distance-comparison",
        &[
            ksg_work(trials, 400, 4)?,
            ksg_work(synergy_trials, 600, 8)?,
            checked_product(
                "default CLI sequential",
                &[2, sequential_distance_work(sequential_trials)?],
            )?,
        ],
    )?;
    enforce_work(
        "default CLI distance-comparison",
        distance_total,
        MAX_CLI_DISTANCE_COMPARISONS,
    )?;

    let bootstrap_total = checked_sum(
        "default CLI bootstrap",
        &[
            bootstrap_work(trials, N_BOOT, 4)?,
            bootstrap_work(synergy_trials, N_BOOT, 4)?,
            bootstrap_work(synergy_trials, N_BOOT, 4)?,
        ],
    )?;
    enforce_work(
        "default CLI AUC bootstrap",
        bootstrap_total,
        MAX_CLI_BOOTSTRAP_AUC_COMPARISONS,
    )
}

/// Generate a coupled `(X, Y)` pair. The decoupled control (in [`run`]) is a
/// permutation of `Y` — a **permutation null**: identical marginal, dependence
/// destroyed — so the comparison isolates *dependence*, not any marginal-shape
/// difference (which would otherwise hand correlation spurious power).
fn gen_coupled(
    coupling: Coupling,
    n: usize,
    sigma: f64,
    rng: &mut StdRng,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let std_normal = Normal::new(0.0, 1.0).map_err(|error| {
        GaladrielError::InvalidConfig(format!("invalid standard normal: {error}"))
    })?;
    let noise = Normal::new(0.0, sigma)
        .map_err(|error| GaladrielError::InvalidConfig(format!("invalid sigma: {error}")))?;
    let x: Vec<f64> = (0..n).map(|_| std_normal.sample(rng)).collect();
    let y: Vec<f64> = x
        .iter()
        .map(|&xi| match coupling {
            Coupling::Linear => xi + noise.sample(rng),
            // Random sign flip: population corr(X, ±X) = 0, but |Y| ≈ |X| so the
            // magnitude dependence is strong and can be visible to MI; correlation can
            // still get finite-sample separation through the variance of sample |ρ|.
            Coupling::Nonlinear => {
                let s = if rng.gen::<bool>() { 1.0 } else { -1.0 };
                xi * s + noise.sample(rng)
            }
        })
        .collect();
    Ok((x, y))
}

/// ROC-AUC via the Mann–Whitney identity (ties = ½), in `O(n log n)` time.
pub fn auc(pos: &[f64], neg: &[f64]) -> Result<f64> {
    if pos.is_empty() || neg.is_empty() {
        return Err(GaladrielError::InvalidChannels(
            "AUC classes must both be non-empty".into(),
        ));
    }
    if !pos.iter().chain(neg).all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("AUC score"));
    }
    let capacity = pos.len().checked_add(neg.len()).ok_or_else(|| {
        GaladrielError::InvalidChannels("combined AUC class length overflows usize".into())
    })?;
    let mut ranked = Vec::new();
    ranked.try_reserve_exact(capacity).map_err(|_| {
        GaladrielError::InvalidChannels(format!(
            "could not reserve {capacity} ranked AUC observations"
        ))
    })?;
    ranked.extend(pos.iter().copied().map(|score| (score, true)));
    ranked.extend(neg.iter().copied().map(|score| (score, false)));
    ranked.sort_by(|left, right| left.0.total_cmp(&right.0));

    let (mut index, mut negatives_before, mut wins) = (0usize, 0usize, 0.0_f64);
    while index < ranked.len() {
        let mut end = index + 1;
        while end < ranked.len() && ranked[end].0 == ranked[index].0 {
            end += 1;
        }
        let positives = ranked[index..end]
            .iter()
            .filter(|(_, positive)| *positive)
            .count();
        let negatives = end - index - positives;
        wins += positives as f64 * (negatives_before as f64 + 0.5 * negatives as f64);
        negatives_before += negatives;
        index = end;
    }
    Ok(wins / (pos.len() as f64 * neg.len() as f64))
}

/// Bootstrap resamples for the CIs.
const N_BOOT: usize = 500;

/// Paired percentile-bootstrap 95% CI for an AUC.
///
/// `pos[i]` and `neg[i]` must be the coupled and control scores from the same generated
/// trial. Resampling trial indices preserves that dependence instead of pretending the
/// permutation-null control is an independently generated class.
pub fn auc_ci(pos: &[f64], neg: &[f64], n_boot: usize, seed: u64) -> Result<(f64, f64)> {
    if !(MIN_BOOTSTRAP_RESAMPLES..=100_000).contains(&n_boot) {
        return Err(GaladrielError::InvalidConfig(format!(
            "AUC bootstrap count must be in {MIN_BOOTSTRAP_RESAMPLES}..=100000"
        )));
    }
    if pos.len() != neg.len() {
        return Err(GaladrielError::InvalidChannels(
            "paired AUC bootstrap classes must have equal lengths".into(),
        ));
    }
    if pos.len() < MIN_TRIALS {
        return Err(GaladrielError::InvalidChannels(format!(
            "paired AUC bootstrap requires at least {MIN_TRIALS} trial pairs"
        )));
    }
    if !pos.iter().chain(neg).all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("AUC score"));
    }
    validate_bootstrap_work(pos.len(), n_boot, 1)?;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5EED_B007);
    let mut aucs = Vec::with_capacity(n_boot);
    let (mut rp, mut rn) = (vec![0.0; pos.len()], vec![0.0; neg.len()]);
    for _ in 0..n_boot {
        for (p, n) in rp.iter_mut().zip(&mut rn) {
            let index = rng.gen_range(0..pos.len());
            *p = pos[index];
            *n = neg[index];
        }
        aucs.push(auc(&rp, &rn)?);
    }
    aucs.sort_by(f64::total_cmp);
    let pick =
        |q: f64| aucs[((q * (aucs.len() as f64 - 1.0)).round() as usize).min(aucs.len() - 1)];
    Ok((pick(0.025), pick(0.975)))
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len().max(1) as f64
}

/// Per-coupling comparison of the two detectors.
#[derive(Debug, Clone)]
pub struct CouplingResult {
    /// Which coupling.
    pub coupling: Coupling,
    /// Correlation detector ROC-AUC (coupled vs decoupled).
    pub corr_auc: f64,
    /// Bootstrap 95% CI for `corr_auc`.
    pub corr_auc_ci: (f64, f64),
    /// MI detector ROC-AUC (coupled vs decoupled).
    pub mi_auc: f64,
    /// Bootstrap 95% CI for `mi_auc`.
    pub mi_auc_ci: (f64, f64),
    /// Mean `|ρ|` on the coupled pairs (shows correlation's blindness when ≈ 0).
    pub corr_coupled_mean: f64,
    /// Mean MI (nats) on the coupled pairs.
    pub mi_coupled_mean: f64,
}

/// The full study.
#[derive(Debug, Clone)]
pub struct Study {
    /// Trials per class.
    pub trials: usize,
    /// Samples per pair.
    pub n: usize,
    /// Coupling-noise standard deviation.
    pub sigma: f64,
    /// Root random seed.
    pub seed: u64,
    /// One result per coupling.
    pub results: Vec<CouplingResult>,
}

/// Run the study.
pub fn run(trials: usize, n: usize, sigma: f64, seed: u64) -> Result<Study> {
    validate_study(trials, n, Some(sigma))?;
    // Two couplings, each with one coupled and one control KSG estimate per trial.
    validate_ksg_work(trials, n, 4)?;
    validate_bootstrap_work(trials, N_BOOT, 4)?;
    let results = Coupling::ALL
        .iter()
        .map(|&coupling| -> Result<CouplingResult> {
            let mut rng = StdRng::seed_from_u64(seed.wrapping_add(coupling as u64 + 1));
            let (mut cp, mut cn, mut mp, mut mn) = (vec![], vec![], vec![], vec![]);
            for trial in 0..trials {
                let (x, yc) = gen_coupled(coupling, n, sigma, &mut rng)?;
                let mut yd = yc.clone();
                yd.shuffle(&mut rng); // permutation null: same marginal, dependence gone
                cp.push(abs_pearson(&x, &yc)?);
                cn.push(abs_pearson(&x, &yd)?);
                let trial_seed = seed
                    ^ (coupling as u64).wrapping_mul(0x9E37_79B9)
                    ^ (trial as u64).wrapping_mul(0xD1B5_4A32_D192_ED03);
                mp.push(ksg(trial_seed ^ 0x00C0_A1ED, &x, &yc)?);
                mn.push(ksg(trial_seed ^ 0xDEC0_A1ED, &x, &yd)?);
            }
            Ok(CouplingResult {
                coupling,
                corr_auc: auc(&cp, &cn)?,
                corr_auc_ci: auc_ci(&cp, &cn, N_BOOT, seed.wrapping_add(coupling as u64))?,
                mi_auc: auc(&mp, &mn)?,
                mi_auc_ci: auc_ci(&mp, &mn, N_BOOT, seed.wrapping_add(100 + coupling as u64))?,
                corr_coupled_mean: mean(&cp),
                mi_coupled_mean: mean(&mp),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Study {
        trials,
        n,
        sigma,
        seed,
        results,
    })
}

/// Format the study as a plain-text report.
pub fn format_report(s: &Study) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Pairwise MI vs correlation study: {} paired trials · n={} · sigma={} · seed={}\n",
        s.trials, s.n, s.sigma, s.seed
    ));
    out.push_str(
        "Detector ROC-AUC at separating a coupled pair from a decoupled (independent) one:\n\n",
    );
    out.push_str(&format!(
        "{:<26} | {:>8} | {:>8} | {:>19} | {:>19}\n",
        "coupling", "|rho| mn", "MI nats", "corr AUC [95% CI]", "MI AUC [95% CI]"
    ));
    out.push_str(&format!("{}\n", "-".repeat(91)));
    for r in &s.results {
        out.push_str(&format!(
            "{:<26} | {:>8.3} | {:>8.3} | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}]\n",
            r.coupling.label(),
            r.corr_coupled_mean,
            r.mi_coupled_mean,
            r.corr_auc,
            r.corr_auc_ci.0,
            r.corr_auc_ci.1,
            r.mi_auc,
            r.mi_auc_ci.0,
            r.mi_auc_ci.1,
        ));
    }
    out.push_str(
        "\nPopulation context: linear-Gaussian MI is monotone in |rho|, while the nonlinear\n\
         construction has zero population correlation but nonzero dependence. The rows are\n\
         finite simulation estimates for these constructions, not deployment calibration.\n\
         Percentile CIs use a paired trial bootstrap; they are not CIs for an AUC difference.\n",
    );
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 2 — synergy: the case where PID is not merely better but *irreducible*.
//
// A, B are independent bits; the target T = A XOR B. In this system every pairwise
// *population* marginal — (A,T), (B,T), (A,B) — is exactly the independent-uniform
// distribution (MI(A;T) = MI(B;T) = 0), yet A and B JOINTLY determine T. So no
// statistic of any single channel pair carries population-level signal; the attack
// lives wholly in the triple, and only a joint measure can see it. Two joint
// detectors are measured:
//
// 1. The nonparametric joint-information contrast
//        Q = MI(A,B;T) − max(MI(A;T), MI(B;T)) = Syn + min(Un_A, Un_B)
//    (the identity holds for ANY redundancy-based two-source PID — it is lattice
//    algebra, independent of the redundancy measure). How tight Q is against the
//    synergy atom is measure-dependent: under Williams–Beer's I_min, XOR decomposes
//    as (Red, U_A, U_B, Syn) = (0, 0, 0, 1) bit and Q is tight; under the
//    shared-exclusions (SxPID / i^sx) decomposition this project actually ships,
//    XOR decomposes as (log₂(2/3), +0.585, +0.585, log₂(4/3)) ≈
//    (−0.585, +0.585, +0.585, +0.415) bits — negative (misinformative) redundancy
//    and non-vanishing unique atoms — so Q = 0.415 + 0.585 = 1 bit over-counts the
//    SxPID synergy atom. (Q ≥ Syn is itself only guaranteed when the unique atoms
//    are non-negative, which SxPID does not promise in general.)
//
// 2. The **SxPID synergy atom itself** (Makkeh–Gutknecht–Wibral 2021), computed
//    by `pid_core::discrete_sxpid2` on the empirical distribution. This is a diagnostic
//    estimator study: Galadriel's current PID verdict uses pairwise MI and does not turn
//    a pure-synergy atom into an operational verdict.
// ─────────────────────────────────────────────────────────────────────────────

use pid_core::discrete_sxpid2;
use std::collections::HashMap;
use std::f64::consts::LN_2;

/// Plug-in Shannon entropy (bits) of a label sequence.
fn entropy_bits(labels: &[u64]) -> f64 {
    let n = labels.len() as f64;
    if n == 0.0 {
        return 0.0;
    }
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for &l in labels {
        *counts.entry(l).or_default() += 1;
    }
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Combine two small-alphabet label vectors into one joint label vector.
fn join(a: &[u64], b: &[u64]) -> Vec<u64> {
    a.iter()
        .zip(b)
        .map(|(&x, &y)| x.wrapping_mul(1024).wrapping_add(y))
        .collect()
}

/// Discrete plug-in mutual information (bits), clamped at 0.
fn mi_bits(a: &[u64], b: &[u64]) -> f64 {
    (entropy_bits(a) + entropy_bits(b) - entropy_bits(&join(a, b))).max(0.0)
}

/// ROC-AUC of each detector at separating the coupled `T = A⊕B` from a decoupled `T`.
#[derive(Debug, Clone)]
pub struct SynergyResult {
    /// Paired coupled/control trials.
    pub trials: usize,
    /// Samples per trial.
    pub n: usize,
    /// Root random seed.
    pub seed: u64,
    /// Correlation detector AUC (`max |ρ(A,T)|, |ρ(B,T)|`).
    pub corr_auc: f64,
    /// Bootstrap 95% CI for `corr_auc`.
    pub corr_auc_ci: (f64, f64),
    /// Pairwise-MI detector AUC (`max MI(A;T), MI(B;T)`).
    pub pairwise_mi_auc: f64,
    /// Bootstrap 95% CI for `pairwise_mi_auc`.
    pub pairwise_mi_auc_ci: (f64, f64),
    /// Joint/synergy detector AUC (`MI(A,B;T) − max marginal MI`).
    pub synergy_auc: f64,
    /// Bootstrap 95% CI for `synergy_auc`.
    pub synergy_auc_ci: (f64, f64),
    /// Mean synergy (bits) on the coupled class (≈ 1 for XOR).
    pub synergy_coupled_mean: f64,
    /// Diagnostic SxPID synergy-atom score AUC (`i^sx` decomposition).
    pub sxpid_syn_auc: f64,
    /// Bootstrap 95% CI for `sxpid_syn_auc`.
    pub sxpid_syn_auc_ci: (f64, f64),
    /// Mean SxPID synergy atom (bits) on the coupled class (≈ log₂(4/3) ≈ 0.415 for XOR).
    pub sxpid_syn_coupled_mean: f64,
    /// Mean SxPID redundancy atom (bits) on the coupled class (≈ log₂(2/3) ≈ −0.585 for
    /// XOR — negative, i.e. *misinformative* sharing; never clamped).
    pub sxpid_red_coupled_mean: f64,
}

/// SxPID synergy and redundancy atoms (bits) of a binary `(s1, s2, t)` triple, via the
/// exact plug-in `discrete_sxpid2` on the empirical distribution (2 bins is lossless for
/// 0/1 data). Returns `(syn, red)` in bits.
fn sxpid_atoms_bits(s1: &[f64], s2: &[f64], t: &[f64]) -> Result<(f64, f64)> {
    let n = s1.len();
    let col = |values: &[f64]| MatOwned::new(values.to_vec(), n, 1).map_err(pid_error);
    let (a, b, tt) = (col(s1)?, col(s2)?, col(t)?);
    let result = discrete_sxpid2(a.as_ref(), b.as_ref(), tt.as_ref(), 2).map_err(pid_error)?;
    Ok((result.syn.net / LN_2, result.red.net / LN_2))
}

const MAX_BINARY_TRIAL_DRAWS: usize = 32;

fn has_both_binary_values(values: &[u64]) -> bool {
    values.contains(&0) && values.contains(&1)
}

/// Draw a non-degenerate XOR sample. Constant Bernoulli columns are possible at small
/// accepted sample sizes and make Pearson correlation undefined, so retry a bounded
/// number of times rather than randomly aborting an otherwise valid study.
fn gen_xor_trial(n: usize, rng: &mut StdRng) -> Result<(Vec<u64>, Vec<u64>, Vec<u64>)> {
    for _ in 0..MAX_BINARY_TRIAL_DRAWS {
        let a: Vec<u64> = (0..n).map(|_| u64::from(rng.gen::<bool>())).collect();
        let b: Vec<u64> = (0..n).map(|_| u64::from(rng.gen::<bool>())).collect();
        let t: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| x ^ y).collect();
        if has_both_binary_values(&a) && has_both_binary_values(&b) && has_both_binary_values(&t) {
            return Ok((a, b, t));
        }
    }
    Err(GaladrielError::InvalidChannels(format!(
        "XOR trial inconclusive after {MAX_BINARY_TRIAL_DRAWS} degenerate Bernoulli draws"
    )))
}

/// Run the synergy study.
pub fn run_synergy(trials: usize, n: usize, seed: u64) -> Result<SynergyResult> {
    validate_study(trials, n, None)?;
    validate_bootstrap_work(trials, N_BOOT, 4)?;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5259_6E65);
    let (mut cc, mut cd) = (Vec::new(), Vec::new());
    let (mut pc, mut pd) = (Vec::new(), Vec::new());
    let (mut sc, mut sd) = (Vec::new(), Vec::new());
    let (mut xc, mut xd, mut xr) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..trials {
        let (a, b, t) = gen_xor_trial(n, &mut rng)?;
        let mut td = t.clone();
        td.shuffle(&mut rng); // permutation null: same T marginal, dependence gone

        let f = |v: &[u64]| v.iter().map(|&x| x as f64).collect::<Vec<f64>>();
        let (af, bf, tf, tdf) = (f(&a), f(&b), f(&t), f(&td));

        cc.push(abs_pearson(&af, &tf)?.max(abs_pearson(&bf, &tf)?));
        cd.push(abs_pearson(&af, &tdf)?.max(abs_pearson(&bf, &tdf)?));

        let pm_c = mi_bits(&a, &t).max(mi_bits(&b, &t));
        let pm_d = mi_bits(&a, &td).max(mi_bits(&b, &td));
        pc.push(pm_c);
        pd.push(pm_d);

        let ab = join(&a, &b);
        sc.push((mi_bits(&ab, &t) - pm_c).max(0.0));
        sd.push((mi_bits(&ab, &td) - pm_d).max(0.0));

        // Diagnostic decomposition output: SxPID synergy atom as the study score
        // (and the coupled-class redundancy atom, to exhibit its negative/misinformative
        // value on XOR). Computed after the RNG draws so the rows above are unchanged.
        let (syn_c, red_c) = sxpid_atoms_bits(&af, &bf, &tf)?;
        let (syn_d, _) = sxpid_atoms_bits(&af, &bf, &tdf)?;
        xc.push(syn_c);
        xd.push(syn_d);
        xr.push(red_c);
    }
    Ok(SynergyResult {
        trials,
        n,
        seed,
        corr_auc: auc(&cc, &cd)?,
        corr_auc_ci: auc_ci(&cc, &cd, N_BOOT, seed.wrapping_add(1))?,
        pairwise_mi_auc: auc(&pc, &pd)?,
        pairwise_mi_auc_ci: auc_ci(&pc, &pd, N_BOOT, seed.wrapping_add(2))?,
        synergy_auc: auc(&sc, &sd)?,
        synergy_auc_ci: auc_ci(&sc, &sd, N_BOOT, seed.wrapping_add(3))?,
        synergy_coupled_mean: mean(&sc),
        sxpid_syn_auc: auc(&xc, &xd)?,
        sxpid_syn_auc_ci: auc_ci(&xc, &xd, N_BOOT, seed.wrapping_add(4))?,
        sxpid_syn_coupled_mean: mean(&xc),
        sxpid_red_coupled_mean: mean(&xr),
    })
}

/// Format the synergy study as a plain-text report.
pub fn format_synergy(r: &SynergyResult) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nSynergy: T = A XOR B vs shuffled T · {} paired trials · n={} · seed={}\n",
        r.trials, r.n, r.seed
    ));
    o.push_str("Detector ROC-AUC at telling the coupled T = A(+)B from the decoupled one:\n\n");
    o.push_str(&format!(
        "{:<26} | {:>6} | {:>15}\n",
        "detector", "AUC", "[95% CI]"
    ));
    o.push_str(&format!("{}\n", "-".repeat(54)));
    o.push_str(&format!(
        "{:<26} | {:>6.3} | [{:.3}, {:.3}]\n",
        "correlation (pairwise)", r.corr_auc, r.corr_auc_ci.0, r.corr_auc_ci.1
    ));
    o.push_str(&format!(
        "{:<26} | {:>6.3} | [{:.3}, {:.3}]\n",
        "mutual info (pairwise)", r.pairwise_mi_auc, r.pairwise_mi_auc_ci.0, r.pairwise_mi_auc_ci.1
    ));
    o.push_str(&format!(
        "{:<26} | {:>6.3} | [{:.3}, {:.3}]   (mean {:.3} bits)\n",
        "synergy contrast Q (joint)",
        r.synergy_auc,
        r.synergy_auc_ci.0,
        r.synergy_auc_ci.1,
        r.synergy_coupled_mean
    ));
    o.push_str(&format!(
        "{:<26} | {:>6.3} | [{:.3}, {:.3}]   (mean {:.3} bits)\n",
        "SxPID synergy atom (i^sx)",
        r.sxpid_syn_auc,
        r.sxpid_syn_auc_ci.0,
        r.sxpid_syn_auc_ci.1,
        r.sxpid_syn_coupled_mean
    ));
    o.push_str(&format!(
        "\nSxPID atoms on the coupled XOR (exact: syn = log2(4/3) = +0.415, red = log2(2/3)\n\
         = -0.585 bits): measured syn {:+.3}, red {:+.3} — the i^sx decomposition\n\
         reads XOR as unique+synergistic with *misinformative* (negative) sharing, unlike\n\
         Williams-Beer I_min's (0, 0, 0, 1). At the population distribution,\n\
         Q = Syn + min(U1,U2) = 1 bit under either decomposition.\n",
        r.sxpid_syn_coupled_mean, r.sxpid_red_coupled_mean
    ));
    o.push_str(
        "\nPopulation context: every pairwise marginal of this XOR construction is\n\
         independent-uniform, while the triple is dependent. The AUC rows report the\n\
         finite-sample behavior observed in this run. Joint and SxPID scores here are\n\
         diagnostic research outputs; the current pairwise-MI PID verdict does not detect\n\
         pure synergy, and this study does not establish field performance. Degenerate\n\
         binary draws are redrawn, so very-small-n results are conditional on nonconstant\n\
         source and target columns. CIs use a paired trial percentile bootstrap.\n",
    );
    o
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 2b — continuous synergy on the estimators exposed by pid-core.
//
// Study 2's XOR is discrete and exact — but the shipped engine runs *continuous*
// estimators (KSG MI; the Ehrlich et al. 2024 continuous `I^sx`). This study narrows
// that gap with a continuous XOR analog, the **sign-parity coupling**:
//
//     A, B ~ N(0,1) independent,  T = sign(A)·sign(B)·|Z|,  Z ~ N(0,1) independent.
//
// Exactly as with XOR: every pairwise marginal is independent — T | A ~ N(0,1) for
// every A (the sign flip is a fair coin from B), so MI(A;T) = MI(B;T) = 0 and all
// pairwise correlations are 0 — while jointly sign(T) = sign(A)·sign(B), so
// MI(A,B;T) = ln 2 exactly (the parity bit; |T| ⊥ (A,B) carries nothing more).
// A single `pid2_isx_estimate` call per triple yields the pairwise KSG MIs, the
// joint KSG MI, the continuous `I^sx` redundancy — hence both the joint contrast
// `Q = MI(A,B;T) − max(MI(A;T), MI(B;T))` and the continuous SxPID synergy atom
// `Syn = MI(A,B;T) − MI(A;T) − MI(B;T) + Red`. These atoms remain diagnostic;
// they are not inputs to the current pairwise-MI PID verdict.
// ─────────────────────────────────────────────────────────────────────────────

/// ROC-AUCs of pairwise vs joint continuous detectors on the sign-parity coupling.
#[derive(Debug, Clone)]
pub struct ContinuousSynergyResult {
    /// Paired coupled/control trials.
    pub trials: usize,
    /// Samples per trial.
    pub n: usize,
    /// Root random seed.
    pub seed: u64,
    /// Pairwise correlation detector AUC (`max(|ρ(A,T)|, |ρ(B,T)|)`).
    pub corr_auc: f64,
    /// Bootstrap 95% CI for `corr_auc`.
    pub corr_auc_ci: (f64, f64),
    /// Pairwise KSG-MI detector AUC (`max(MI(A;T), MI(B;T))`).
    pub pairwise_mi_auc: f64,
    /// Bootstrap 95% CI for `pairwise_mi_auc`.
    pub pairwise_mi_auc_ci: (f64, f64),
    /// Joint contrast `Q` detector AUC.
    pub q_auc: f64,
    /// Bootstrap 95% CI for `q_auc`.
    pub q_auc_ci: (f64, f64),
    /// Continuous SxPID synergy-atom detector AUC.
    pub isx_syn_auc: f64,
    /// Bootstrap 95% CI for `isx_syn_auc`.
    pub isx_syn_auc_ci: (f64, f64),
    /// Mean joint KSG MI (nats) on the coupled class (exact value: ln 2 ≈ 0.693).
    pub joint_mi_coupled_mean: f64,
    /// Mean continuous SxPID synergy atom (nats) on the coupled class.
    pub isx_syn_coupled_mean: f64,
}

struct ContinuousScores {
    pairwise_mi: f64,
    q: f64,
    synergy: f64,
    /// The estimator's direct joint-MI output, before any contrast clamping.
    joint_mi: f64,
}

/// Continuous scores of one `(A, B, T)` triple from one `pid2_isx_estimate` call.
fn continuous_synergy_scores(a: &[f64], b: &[f64], t: &[f64]) -> Result<ContinuousScores> {
    let n = a.len();
    let col = |values: &[f64]| MatOwned::new(values.to_vec(), n, 1).map_err(pid_error);
    let (am, bm, tm) = (col(a)?, col(b)?, col(t)?);
    let est = pid2_isx_estimate(
        am.as_ref(),
        bm.as_ref(),
        tm.as_ref(),
        &Pid2Config::default(),
    )
    .map_err(pid_error)?;
    let pm = est.mi_s1_t.max(est.mi_s2_t);
    let q = (est.mi_s1s2_t - pm).max(0.0);
    let syn = est.mi_s1s2_t - est.mi_s1_t - est.mi_s2_t + est.redundancy_isx;
    Ok(ContinuousScores {
        pairwise_mi: pm.max(0.0),
        q,
        synergy: syn,
        joint_mi: est.mi_s1s2_t,
    })
}

/// Run the continuous (sign-parity) synergy study.
pub fn run_synergy_continuous(
    trials: usize,
    n: usize,
    seed: u64,
) -> Result<ContinuousSynergyResult> {
    validate_study(trials, n, None)?;
    // Two PID estimates per trial; each evaluates several pairwise/joint kNN spaces.
    validate_ksg_work(trials, n, 8)?;
    validate_bootstrap_work(trials, N_BOOT, 4)?;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x516E_9A21);
    let std_normal = Normal::new(0.0, 1.0).map_err(|error| {
        GaladrielError::InvalidConfig(format!("invalid standard normal: {error}"))
    })?;
    let (mut cc, mut cd) = (Vec::new(), Vec::new()); // pairwise corr
    let (mut pc, mut pd) = (Vec::new(), Vec::new()); // pairwise MI
    let (mut qc, mut qd) = (Vec::new(), Vec::new()); // joint contrast Q
    let (mut xc, mut xd) = (Vec::new(), Vec::new()); // continuous i^sx synergy atom
    let mut joint_mi = Vec::new();
    for _ in 0..trials {
        let a: Vec<f64> = (0..n).map(|_| std_normal.sample(&mut rng)).collect();
        let b: Vec<f64> = (0..n).map(|_| std_normal.sample(&mut rng)).collect();
        let t: Vec<f64> = a
            .iter()
            .zip(&b)
            .map(|(&x, &y)| x.signum() * y.signum() * std_normal.sample(&mut rng).abs())
            .collect();
        let mut td = t.clone();
        td.shuffle(&mut rng); // permutation null: same T marginal, dependence gone

        cc.push(abs_pearson(&a, &t)?.max(abs_pearson(&b, &t)?));
        cd.push(abs_pearson(&a, &td)?.max(abs_pearson(&b, &td)?));

        let coupled = continuous_synergy_scores(&a, &b, &t)?;
        let control = continuous_synergy_scores(&a, &b, &td)?;
        pc.push(coupled.pairwise_mi);
        pd.push(control.pairwise_mi);
        qc.push(coupled.q);
        qd.push(control.q);
        xc.push(coupled.synergy);
        xd.push(control.synergy);
        joint_mi.push(coupled.joint_mi);
    }
    Ok(ContinuousSynergyResult {
        trials,
        n,
        seed,
        corr_auc: auc(&cc, &cd)?,
        corr_auc_ci: auc_ci(&cc, &cd, N_BOOT, seed.wrapping_add(11))?,
        pairwise_mi_auc: auc(&pc, &pd)?,
        pairwise_mi_auc_ci: auc_ci(&pc, &pd, N_BOOT, seed.wrapping_add(12))?,
        q_auc: auc(&qc, &qd)?,
        q_auc_ci: auc_ci(&qc, &qd, N_BOOT, seed.wrapping_add(13))?,
        isx_syn_auc: auc(&xc, &xd)?,
        isx_syn_auc_ci: auc_ci(&xc, &xd, N_BOOT, seed.wrapping_add(14))?,
        joint_mi_coupled_mean: mean(&joint_mi),
        isx_syn_coupled_mean: mean(&xc),
    })
}

/// Format the continuous synergy study as a plain-text report.
pub fn format_synergy_continuous(r: &ContinuousSynergyResult) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nContinuous synergy: T = sign(A)·sign(B)·|Z| vs shuffled T\n\
         {} paired trials · n={} · seed={} · pid-core continuous estimators (KSG + I^sx):\n\n",
        r.trials, r.n, r.seed,
    ));
    o.push_str(&format!(
        "{:<28} | {:>6} | {:>15}\n",
        "detector", "AUC", "[95% CI]"
    ));
    o.push_str(&format!("{}\n", "-".repeat(56)));
    let row = |name: &str, a: f64, ci: (f64, f64)| {
        format!("{:<28} | {:>6.3} | [{:.3}, {:.3}]\n", name, a, ci.0, ci.1)
    };
    o.push_str(&row("correlation (pairwise)", r.corr_auc, r.corr_auc_ci));
    o.push_str(&row(
        "KSG MI (pairwise)",
        r.pairwise_mi_auc,
        r.pairwise_mi_auc_ci,
    ));
    o.push_str(&row("joint contrast Q (KSG)", r.q_auc, r.q_auc_ci));
    o.push_str(&row(
        "I^sx synergy atom (cont.)",
        r.isx_syn_auc,
        r.isx_syn_auc_ci,
    ));
    o.push_str(&format!(
        "\njoint KSG MI on coupled: {:.3} nats (population value: ln 2 = 0.693);\n\
         continuous I^sx synergy atom on coupled: {:.3} nats. Pairwise marginals are\n\
         independent in the population construction; the table reports finite-sample\n\
         estimator behavior. These joint scores are diagnostic and are not used by the\n\
         current pairwise-MI PID verdict. CIs use a paired trial percentile bootstrap.\n",
        r.joint_mi_coupled_mean, r.isx_syn_coupled_mean
    ));
    o
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 3 — the pointwise escalation: sequential detection at a common FAR target.
//
// Studies 1–2 score *windows*; a streaming monitor pays their price in **latency**:
// a trailing window must refill with post-onset frames before a broken coupling is
// legible. Information-theoretic quantities can also be **pointwise** — they exist
// per realization (Makkeh–Gutknecht–
// Wibral 2021; the single-source node is the pointwise MI, by self-redundancy) —
// so consistency can be scored *per frame* and fed to a sequential (CUSUM) test.
//
// The local kNN term used here is a plug-in estimate inspired by
// log[ p_coupled(x,y) / (p(x)·p(y)) ] — the **log-likelihood ratio** between the
// calibrated coupled regime and the decoupled (independent, same-marginals)
// regime. With known densities, a CUSUM over the true log-LR has classical optimality
// properties. The frozen-reference kNN estimate below is approximate and those
// properties do not transfer automatically.
//
// The forced-vs-justified question then recurs at the pointwise level, and this
// study asks it with five sequential detectors calibrated to one stream-level FAR target:
//
//   window |ρ̂|      — the runtime default's analog (trailing-window refit);
//   window KSG MI    — the windowed escalation's analog;
//   product CUSUM    — per-frame x·y (the naive cheap pointwise statistic);
//   Gauss-LR CUSUM   — per-frame *parametric* Gaussian log-LR: the closed-form
//                      pointwise MI i(x,y; ρ̂_cal) — "correlation, pointwise";
//   local-MI CUSUM   — per-frame *nonparametric* kNN local-MI against a frozen clean
//                      reference window; metric, k, and calibration choices still matter.
//
// Hypotheses (stated before running):
//   H1 (latency): at the common FAR target, pointwise CUSUM detectors beat the windowed
//      detectors' refill latency on the coupling they can see.
//   H2 (forced, pointwise): on the linear-Gaussian coupling the parametric
//      Gauss-LR CUSUM — a one-line ρ̂ plug-in — is competitive with the kNN
//      local-MI CUSUM; extra estimator complexity may not buy useful latency here.
//   H3 (justified, pointwise): on the sign-flip coupling the product and Gauss-LR
//      CUSUMs are blind (E[xy] = 0 and ρ̂_cal ≈ 0 on *both* sides of onset), while
//      the nonparametric local-MI CUSUM can retain signal — the pointwise analog of §2.
//      (A variance-tracking chart could see this particular construction through
//      its second moment — again a bespoke feature choice, the pointwise echo of
//      §2's kurtosis artifact; the local-MI chart needs no explicit variance feature.)
// ─────────────────────────────────────────────────────────────────────────────

/// Reference/calibration segment length (frames) — frozen as the "clean past".
const SEQ_REF_LEN: usize = 256;
/// Evaluation segment length (frames).
const SEQ_EVAL_LEN: usize = 256;
/// Attack onset, as an index into the evaluation segment.
const SEQ_ONSET: usize = 64;
/// Trailing-window length for the windowed detectors.
const SEQ_WINDOW: usize = 128;
/// Evaluation stride (frames) for the windowed detectors (they are O(W²) per step).
const SEQ_STRIDE: usize = 4;
/// k for the local-MI kNN terms.
const SEQ_K: usize = 3;
/// CUSUM reference drift (in calibrated σ units).
const SEQ_KAPPA: f64 = 0.25;
/// Target stream-level false-alarm rate used to calibrate each threshold.
const SEQ_FAR: f64 = 0.05;

/// The five sequential detectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqDetector {
    /// Trailing-window `|ρ̂|`, alarm when it falls below its calibrated floor.
    WindowCorr,
    /// Trailing-window KSG MI, alarm when it falls below its calibrated floor.
    WindowMi,
    /// CUSUM over the per-frame product `x·y` (downward mean shift).
    ProductCusum,
    /// CUSUM over the per-frame parametric Gaussian log-LR (pointwise Gaussian MI
    /// at the calibration ρ̂) — a cheap detector tailored to the Gaussian model.
    GaussLrCusum,
    /// CUSUM over the per-frame nonparametric kNN local-MI term against the frozen
    /// clean reference — the Wibral-pointwise detector.
    LocalMiCusum,
}

impl SeqDetector {
    /// All detectors, in report order.
    pub const ALL: [SeqDetector; 5] = [
        SeqDetector::WindowCorr,
        SeqDetector::WindowMi,
        SeqDetector::ProductCusum,
        SeqDetector::GaussLrCusum,
        SeqDetector::LocalMiCusum,
    ];

    /// A label.
    pub fn label(self) -> &'static str {
        match self {
            SeqDetector::WindowCorr => "window |rho| (W=128)",
            SeqDetector::WindowMi => "window KSG MI (W=128)",
            SeqDetector::ProductCusum => "product CUSUM (x*y)",
            SeqDetector::GaussLrCusum => "Gauss-LR CUSUM (rho-hat)",
            SeqDetector::LocalMiCusum => "local-MI CUSUM (kNN)",
        }
    }
}

type SeqTrace = Vec<(usize, f64)>;
type DetectorTraces = Vec<(SeqDetector, SeqTrace)>;

/// One detector's row in the sequential study.
#[derive(Debug, Clone)]
pub struct SeqRow {
    /// Which detector.
    pub detector: SeqDetector,
    /// Fraction of independent clean *holdout* streams that alarmed anywhere in the
    /// eval segment. These streams are not used to calibrate the threshold.
    pub realized_far: f64,
    /// Wilson score 95% interval for `realized_far` on the clean holdout arm.
    pub realized_far_ci: (f64, f64),
    /// Fraction of *attacked* streams that alarmed **before** onset (false starts).
    pub false_start: f64,
    /// Fraction of attacked streams (without a false start) alarming at/after onset.
    pub reach: f64,
    /// Median frames from onset to first alarm, among reaching trials
    /// (windowed detectors are quantized to the `SEQ_STRIDE`-frame grid).
    pub median_latency: Option<f64>,
}

/// The sequential (pointwise) study for one coupling.
#[derive(Debug, Clone)]
pub struct SeqStudy {
    /// Which coupling.
    pub coupling: Coupling,
    /// Trials per arm (clean calibration, clean holdout, and attacked).
    pub trials: usize,
    /// Coupling-noise standard deviation.
    pub sigma: f64,
    /// Root random seed.
    pub seed: u64,
    /// One row per detector.
    pub rows: Vec<SeqRow>,
}

/// Digamma via the standard shift-and-asymptotic-series recipe (|err| ≪ 1e-10 for x > 0).
fn digamma(mut x: f64) -> f64 {
    let mut r = 0.0;
    while x < 6.0 {
        r -= 1.0 / x;
        x += 1.0;
    }
    let inv = 1.0 / x;
    let inv2 = inv * inv;
    r + x.ln() - 0.5 * inv - inv2 * (1.0 / 12.0 - inv2 * (1.0 / 120.0 - inv2 / 252.0))
}

/// Pointwise MI of a *standardized* bivariate Gaussian at correlation `r` (nats):
/// `i(a,b) = −½ln(1−r²) − (r²(a²+b²) − 2rab) / (2(1−r²))` — the closed-form log-LR
/// between the coupled and independent hypotheses with N(0,1) marginals.
fn pointwise_gaussian_mi(a: f64, b: f64, r: f64) -> f64 {
    let r2 = r * r;
    if r2 >= 1.0 {
        return 0.0;
    }
    -0.5 * (1.0 - r2).ln() - (r2 * (a * a + b * b) - 2.0 * r * a * b) / (2.0 * (1.0 - r2))
}

/// KSG-style local MI term of query `(qx, qy)` against a frozen reference sample,
/// Chebyshev metric, strict counting: `ψ(k) + ψ(N) − ψ(n_x+1) − ψ(n_y+1)`.
fn local_mi_query(rx: &[f64], ry: &[f64], qx: f64, qy: f64, k: usize) -> f64 {
    let n = rx.len();
    let mut joint: Vec<f64> = (0..n)
        .map(|j| (rx[j] - qx).abs().max((ry[j] - qy).abs()))
        .collect();
    let kth = k - 1;
    joint.select_nth_unstable_by(kth, |a, b| a.total_cmp(b));
    let eps = joint[kth];
    if eps <= 0.0 {
        return 0.0; // duplicate guard; continuous data makes this measure-zero
    }
    let (mut nx, mut ny) = (0usize, 0usize);
    for j in 0..n {
        if (rx[j] - qx).abs() < eps {
            nx += 1;
        }
        if (ry[j] - qy).abs() < eps {
            ny += 1;
        }
    }
    digamma(k as f64) + digamma(n as f64) - digamma((nx + 1) as f64) - digamma((ny + 1) as f64)
}

/// In-sample KSG local MI terms of the reference itself (self excluded) — used only
/// to standardize the CUSUM increments; the same convention offsets appear in the
/// clean calibration streams, so they cancel in the threshold.
fn local_mi_ref_terms(rx: &[f64], ry: &[f64], k: usize) -> Vec<f64> {
    let n = rx.len();
    (0..n)
        .map(|i| {
            let (xs, ys): (Vec<f64>, Vec<f64>) =
                (0..n).filter(|&j| j != i).map(|j| (rx[j], ry[j])).unzip();
            local_mi_query(&xs, &ys, rx[i], ry[i], k)
        })
        .collect()
}

/// Generate one full `(x, y)` stream of length `SEQ_REF_LEN + SEQ_EVAL_LEN`.
/// Coupled throughout if `attacked` is false; if true, `y` decouples from
/// `SEQ_REF_LEN + SEQ_ONSET` onward onto an independent stream with the *same*
/// marginal (a moment-matched decoupling — the §1/§2 spoof, sequential form).
fn gen_seq_stream(
    coupling: Coupling,
    sigma: f64,
    attacked: bool,
    rng: &mut StdRng,
) -> Result<(Vec<f64>, Vec<f64>)> {
    let total = SEQ_REF_LEN + SEQ_EVAL_LEN;
    let onset = SEQ_REF_LEN + SEQ_ONSET;
    let std_normal = Normal::new(0.0, 1.0).map_err(|error| {
        GaladrielError::InvalidConfig(format!("invalid standard normal: {error}"))
    })?;
    let noise = Normal::new(0.0, sigma)
        .map_err(|error| GaladrielError::InvalidConfig(format!("invalid sigma: {error}")))?;
    let mut xs = Vec::with_capacity(total);
    let mut ys = Vec::with_capacity(total);
    for t in 0..total {
        let x = std_normal.sample(rng);
        // The channel under test: coupled to x, or (post-onset) to a fresh
        // independent latent x' — identical marginal, dependence gone.
        let base = if attacked && t >= onset {
            std_normal.sample(rng)
        } else {
            x
        };
        let y = match coupling {
            Coupling::Linear => base + noise.sample(rng),
            Coupling::Nonlinear => {
                let s = if rng.gen::<bool>() { 1.0 } else { -1.0 };
                base * s + noise.sample(rng)
            }
        };
        xs.push(x);
        ys.push(y);
    }
    Ok((xs, ys))
}

/// Per-stream detector traces over the eval segment: for each detector, the frames
/// (eval-segment indices) at which its statistic is *available*, and the statistic
/// value oriented so that **larger = more anomalous** (windowed scores are negated).
fn seq_traces(seed: u64, xs: &[f64], ys: &[f64]) -> Result<DetectorTraces> {
    let required = SEQ_REF_LEN + SEQ_EVAL_LEN;
    if xs.len() != required || ys.len() != required {
        return Err(GaladrielError::InvalidChannels(format!(
            "sequential traces require exactly {required} samples per channel"
        )));
    }
    if !xs.iter().chain(ys).all(|value| value.is_finite()) {
        return Err(GaladrielError::NonFinite("sequential study input"));
    }
    let onset_abs = SEQ_REF_LEN;
    let (rx, ry) = (&xs[..SEQ_REF_LEN], &ys[..SEQ_REF_LEN]);

    // Calibration statistics from the frozen reference segment.
    let stats = |v: &[f64]| {
        let n = v.len() as f64;
        let m = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / n;
        (m, var.sqrt().max(1e-12))
    };
    let (mx, sx) = stats(rx);
    let (my, sy) = stats(ry);
    let zx: Vec<f64> = rx.iter().map(|v| (v - mx) / sx).collect();
    let zy: Vec<f64> = ry.iter().map(|v| (v - my) / sy).collect();
    let rho_cal = {
        let r = zx.iter().zip(&zy).map(|(a, b)| a * b).sum::<f64>() / zx.len() as f64;
        r.clamp(-0.999, 0.999)
    };
    let prod_cal: Vec<f64> = zx.iter().zip(&zy).map(|(a, b)| a * b).collect();
    let (mp, sp) = stats(&prod_cal);
    let glr_cal: Vec<f64> = zx
        .iter()
        .zip(&zy)
        .map(|(&a, &b)| pointwise_gaussian_mi(a, b, rho_cal))
        .collect();
    let (mg, sg) = stats(&glr_cal);
    let lmi_cal = local_mi_ref_terms(&zx, &zy, SEQ_K);
    let (ml, sl) = stats(&lmi_cal);

    // Windowed detectors (negated: larger = more anomalous), on the stride grid.
    let mut wcorr = Vec::new();
    let mut wmi = Vec::new();
    let mut e = SEQ_STRIDE;
    while e <= SEQ_EVAL_LEN {
        let end = onset_abs + e;
        let (wx, wy) = (&xs[end - SEQ_WINDOW..end], &ys[end - SEQ_WINDOW..end]);
        wcorr.push((e - 1, -abs_pearson(wx, wy)?));
        wmi.push((
            e - 1,
            -ksg(seed ^ (e as u64).wrapping_mul(0x9E37_79B9), wx, wy)?,
        ));
        e += SEQ_STRIDE;
    }

    // Pointwise CUSUMs (every frame): S = max(0, S + (μ_cal − stat)/σ_cal − κ).
    let cusum = |stat: &dyn Fn(f64, f64) -> f64, m: f64, s: f64| -> Vec<(usize, f64)> {
        let mut out = Vec::with_capacity(SEQ_EVAL_LEN);
        let mut acc = 0.0f64;
        for t in 0..SEQ_EVAL_LEN {
            let (a, b) = ((xs[onset_abs + t] - mx) / sx, (ys[onset_abs + t] - my) / sy);
            let z = (m - stat(a, b)) / s - SEQ_KAPPA;
            acc = (acc + z).max(0.0);
            out.push((t, acc));
        }
        out
    };
    let prod = cusum(&|a, b| a * b, mp, sp);
    let glr = cusum(&|a, b| pointwise_gaussian_mi(a, b, rho_cal), mg, sg);
    let lmi = cusum(&|a, b| local_mi_query(&zx, &zy, a, b, SEQ_K), ml, sl);

    Ok(vec![
        (SeqDetector::WindowCorr, wcorr),
        (SeqDetector::WindowMi, wmi),
        (SeqDetector::ProductCusum, prod),
        (SeqDetector::GaussLrCusum, glr),
        (SeqDetector::LocalMiCusum, lmi),
    ])
}

fn clean_seq_maxima(
    coupling: Coupling,
    trials: usize,
    sigma: f64,
    seed: u64,
    domain: u64,
) -> Result<Vec<Vec<f64>>> {
    let mut rng = StdRng::seed_from_u64(seed ^ domain ^ coupling as u64);
    let mut maxima = vec![Vec::with_capacity(trials); SeqDetector::ALL.len()];
    for trial in 0..trials {
        let (xs, ys) = gen_seq_stream(coupling, sigma, false, &mut rng)?;
        let trace_seed = seed ^ domain ^ trial as u64;
        for (di, (_, trace)) in seq_traces(trace_seed, &xs, &ys)?.into_iter().enumerate() {
            let maximum = trace
                .iter()
                .map(|&(_, value)| value)
                .fold(f64::NEG_INFINITY, f64::max);
            maxima[di].push(maximum);
        }
    }
    Ok(maxima)
}

fn wilson95(successes: usize, total: usize) -> Result<(f64, f64)> {
    if total == 0 || successes > total {
        return Err(GaladrielError::InvalidChannels(
            "Wilson interval requires 0 <= successes <= a nonzero total".into(),
        ));
    }
    const Z: f64 = 1.959_963_984_540_054;
    let n = total as f64;
    let proportion = successes as f64 / n;
    let z2 = Z * Z;
    let denominator = 1.0 + z2 / n;
    let center = (proportion + z2 / (2.0 * n)) / denominator;
    let margin =
        Z * ((proportion * (1.0 - proportion) / n + z2 / (4.0 * n * n)).sqrt()) / denominator;
    Ok(((center - margin).max(0.0), (center + margin).min(1.0)))
}

/// Run the sequential (pointwise) study for one coupling: calibrate every detector's
/// threshold to a common target stream-level FAR on one clean arm, estimate realized
/// FAR on an independent clean holdout arm, then measure false-start / reach / median
/// latency on an attacked arm.
pub fn run_seq(coupling: Coupling, trials: usize, sigma: f64, seed: u64) -> Result<SeqStudy> {
    validate_study(trials, SEQ_REF_LEN + SEQ_EVAL_LEN, Some(sigma))?;
    // Bound both the windowed KSG fits and frozen-reference local-MI distance scans
    // across calibration, clean-holdout, and attacked arms.
    validate_sequential_work(trials)?;
    let n_det = SeqDetector::ALL.len();

    // Calibration arm: per-detector per-stream maximum of the anomaly statistic.
    let calibration_max = clean_seq_maxima(coupling, trials, sigma, seed, 0xCA11_BA7E)?;
    // Matched operating point: each detector's threshold is its own clean-maxima
    // (1 − FAR) quantile — the same stream-level FAR for all five detectors.
    let threshold: Vec<f64> = calibration_max
        .iter()
        .map(|v| {
            let mut s = v.clone();
            s.sort_by(f64::total_cmp);
            let idx =
                (((1.0 - SEQ_FAR) * (s.len() as f64 - 1.0)).round() as usize).min(s.len() - 1);
            s[idx]
        })
        .collect();
    // Independent clean holdout: estimate FAR without reusing threshold-fitting data.
    let holdout_max = clean_seq_maxima(coupling, trials, sigma, seed, 0xC1EA_110D)?;
    let holdout_alarm_count: Vec<usize> = holdout_max
        .iter()
        .zip(&threshold)
        .map(|(values, &threshold)| values.iter().filter(|&&value| value > threshold).count())
        .collect();
    let realized_far: Vec<f64> = holdout_alarm_count
        .iter()
        .map(|&count| count as f64 / trials as f64)
        .collect();
    let realized_far_ci = holdout_alarm_count
        .iter()
        .map(|&count| wilson95(count, trials))
        .collect::<Result<Vec<_>>>()?;

    // Attacked arm: first alarm per detector per stream.
    let mut rng = StdRng::seed_from_u64(seed ^ 0xA77A_C000 ^ coupling as u64);
    let mut false_start = vec![0usize; n_det];
    let mut latencies: Vec<Vec<f64>> = vec![Vec::new(); n_det];
    for trial in 0..trials {
        let (xs, ys) = gen_seq_stream(coupling, sigma, true, &mut rng)?;
        let trace_seed = seed ^ 0xA77A_C000 ^ trial as u64;
        for (di, (_, trace)) in seq_traces(trace_seed, &xs, &ys)?.into_iter().enumerate() {
            let first = trace
                .iter()
                .find(|&&(_, v)| v > threshold[di])
                .map(|&(t, _)| t);
            match first {
                Some(t) if t < SEQ_ONSET => false_start[di] += 1,
                Some(t) => latencies[di].push((t - SEQ_ONSET) as f64),
                None => {}
            }
        }
    }

    let rows = SeqDetector::ALL
        .iter()
        .enumerate()
        .map(|(di, &detector)| {
            let no_fs = trials - false_start[di];
            let reach = if no_fs == 0 {
                0.0
            } else {
                latencies[di].len() as f64 / no_fs as f64
            };
            let median_latency = if latencies[di].is_empty() {
                None
            } else {
                let mut l = latencies[di].clone();
                l.sort_by(f64::total_cmp);
                let middle = l.len() / 2;
                Some(if l.len() % 2 == 0 {
                    (l[middle - 1] + l[middle]) / 2.0
                } else {
                    l[middle]
                })
            };
            SeqRow {
                detector,
                realized_far: realized_far[di],
                realized_far_ci: realized_far_ci[di],
                false_start: false_start[di] as f64 / trials as f64,
                reach,
                median_latency,
            }
        })
        .collect();

    Ok(SeqStudy {
        coupling,
        trials,
        sigma,
        seed,
        rows,
    })
}

/// Format the sequential study as a plain-text report.
pub fn format_seq(s: &SeqStudy) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nSequential (pointwise) detection — {} · onset +{} · target stream FAR {:.0}%\n\
         moment-matched decoupling at onset; {} streams in each independent calibration,\n\
         clean-holdout, and attacked arm; reported FAR is holdout FAR; sigma={}; seed={}\n\n",
        s.coupling.label(),
        SEQ_ONSET,
        SEQ_FAR * 100.0,
        s.trials,
        s.sigma,
        s.seed
    ));
    o.push_str(&format!(
        "{:<26} | {:>20} | {:>11} | {:>6} | {:>14}\n",
        "detector", "FAR [Wilson 95% CI]", "false-start", "reach", "median latency"
    ));
    o.push_str(&format!("{}\n", "-".repeat(91)));
    for r in &s.rows {
        o.push_str(&format!(
            "{:<26} | {:>5.3} [{:.3},{:.3}] | {:>11.3} | {:>6.3} | {:>14}\n",
            r.detector.label(),
            r.realized_far,
            r.realized_far_ci.0,
            r.realized_far_ci.1,
            r.false_start,
            r.reach,
            r.median_latency
                .map(|l| format!("{l:.0}f"))
                .unwrap_or_else(|| "—".into()),
        ));
    }
    o.push_str(
        "\nThese are synthetic experimental comparators, not deployed detector guarantees.\n\
         FAR intervals are Wilson score intervals on the independent clean holdout.\n\
         False-start and reach remain raw attack-arm proportions without intervals.\n\
         Detectors share a target FAR but their realized holdout FARs differ, so the latency\n\
         column is not strictly iso-FAR; read it alongside each detector's realized FAR.\n",
    );
    o
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 4 — the significance floor's i.i.d. assumption, tested on an AR(1) null.
//
// The runtime default accepts a positive cross-channel edge only past a family-wise
// Fisher-z significance floor whose standard error, 1/√(n−3), assumes the windowed
// residual pairs are i.i.d. bivariate normal. Windowed residual series need not be
// independent in time. This study measures what positive within-window autocorrelation
// does to that floor under the NULL: two *independent* AR(1) channels (population
// cross-correlation exactly zero, lag-1 coefficient φ), scored by the same one-sided
// construction the detector uses at its default window n = 128.
//
// Hypothesis (stated before running): the naive floor is anti-conservative — its
// realized false-positive rate rises above the nominal α as φ grows — and replacing n
// with Bartlett's effective sample size n_eff = n(1−φ²)/(1+φ²) improves calibration
// until the effective sample becomes too small for the asymptotic Fisher approximation.
// The large-sample theory (M. S. Bartlett, "Some Aspects of the Time-Correlation
// Problem in Regard to Tests of Significance," J. Royal Statistical Society
// 98(3):536–543, 1935) gives var(ρ̂) ≈ (1/n)·(1+φ²)/(1−φ²) for this null, which
// predicts the direction and approximate scale of the realized rates.
//
// This quantifies a *disclosed limitation* of the runtime default (PAPER.md §7); it is
// not a runtime correction. Applying the correction operationally requires estimating
// φ from data, with its own uncertainty — a registered enhancement decision.
// ─────────────────────────────────────────────────────────────────────────────

/// Window length for the AR(1) null study — matches `CorrConfig::default().window`.
const AR1_WINDOW: usize = 128;
/// Lag-1 AR coefficients scanned (φ = 0 is the calibration check).
pub const AR1_PHIS: [f64; 5] = [0.0, 0.3, 0.5, 0.7, 0.9];
/// One-sided standard-normal quantile at α = 0.05.
const AR1_Z_05: f64 = 1.644_853_626_951_472_2;
/// One-sided standard-normal quantile at α = 0.01.
const AR1_Z_01: f64 = 2.326_347_874_040_841;

/// Bartlett effective sample size for the cross-correlation of two independent
/// equal-φ AR(1) series: `n · (1−φ²)/(1+φ²)`.
fn bartlett_n_eff(n: usize, phi: f64) -> f64 {
    n as f64 * (1.0 - phi * phi) / (1.0 + phi * phi)
}

/// One stationary AR(1) stream: `x₀ ~ N(0,1)`, `x_t = φ·x_{t−1} + √(1−φ²)·ε_t`.
fn gen_ar1(n: usize, phi: f64, rng: &mut StdRng) -> Result<Vec<f64>> {
    let std_normal = Normal::new(0.0, 1.0).map_err(|error| {
        GaladrielError::InvalidConfig(format!("invalid standard normal: {error}"))
    })?;
    let innovation_sd = (1.0 - phi * phi).sqrt();
    let mut x = Vec::with_capacity(n);
    let mut previous = std_normal.sample(rng);
    x.push(previous);
    for _ in 1..n {
        previous = phi * previous + innovation_sd * std_normal.sample(rng);
        x.push(previous);
    }
    Ok(x)
}

/// One φ row of the AR(1) null study.
#[derive(Debug, Clone)]
pub struct Ar1NullRow {
    /// Lag-1 coefficient of both (independent) channels.
    pub phi: f64,
    /// Bartlett effective sample size at this φ.
    pub n_eff: f64,
    /// Realized FPR of the naive floor at α = 0.05, with its Wilson 95% interval.
    pub naive_fpr_05: f64,
    /// Wilson 95% interval for `naive_fpr_05`.
    pub naive_fpr_05_ci: (f64, f64),
    /// Realized FPR of the Bartlett-corrected floor at α = 0.05.
    pub bartlett_fpr_05: f64,
    /// Wilson 95% interval for `bartlett_fpr_05`.
    pub bartlett_fpr_05_ci: (f64, f64),
    /// Realized FPR of the naive floor at α = 0.01.
    pub naive_fpr_01: f64,
    /// Wilson 95% interval for `naive_fpr_01`.
    pub naive_fpr_01_ci: (f64, f64),
    /// Realized FPR of the Bartlett-corrected floor at α = 0.01.
    pub bartlett_fpr_01: f64,
    /// Wilson 95% interval for `bartlett_fpr_01`.
    pub bartlett_fpr_01_ci: (f64, f64),
}

/// The AR(1) autocorrelation-null study.
#[derive(Debug, Clone)]
pub struct Ar1NullStudy {
    /// Independent channel pairs per φ.
    pub trials: usize,
    /// Window length (matches the runtime default correlation window).
    pub n: usize,
    /// Root random seed.
    pub seed: u64,
    /// One row per φ in [`AR1_PHIS`].
    pub rows: Vec<Ar1NullRow>,
}

/// Run the autocorrelation-null study: per φ, generate `trials` pairs of independent
/// AR(1) channels and count how often the detector-style one-sided Fisher floor —
/// naive `1/√(n−3)` versus Bartlett `1/√(n_eff−3)` — falsely declares a significant
/// positive correlation.
pub fn run_autocorrelation_null(trials: usize, seed: u64) -> Result<Ar1NullStudy> {
    validate_study(trials, AR1_WINDOW, None)?;
    let floor = |z: f64, effective_n: f64| -> Result<f64> {
        if effective_n <= 4.0 {
            return Err(GaladrielError::InvalidConfig(
                "AR(1) effective sample size must exceed 4".into(),
            ));
        }
        Ok((z / (effective_n - 3.0).sqrt()).tanh())
    };
    let rows = AR1_PHIS
        .iter()
        .enumerate()
        .map(|(index, &phi)| -> Result<Ar1NullRow> {
            let n_eff = bartlett_n_eff(AR1_WINDOW, phi);
            let naive_floor_05 = floor(AR1_Z_05, AR1_WINDOW as f64)?;
            let naive_floor_01 = floor(AR1_Z_01, AR1_WINDOW as f64)?;
            let bartlett_floor_05 = floor(AR1_Z_05, n_eff)?;
            let bartlett_floor_01 = floor(AR1_Z_01, n_eff)?;
            let mut rng = StdRng::seed_from_u64(
                seed ^ 0xA21C_0221 ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
            );
            let (mut n05, mut b05, mut n01, mut b01) = (0usize, 0usize, 0usize, 0usize);
            for _ in 0..trials {
                let x = gen_ar1(AR1_WINDOW, phi, &mut rng)?;
                let y = gen_ar1(AR1_WINDOW, phi, &mut rng)?;
                let rho = pearson(&x, &y)?;
                if rho >= naive_floor_05 {
                    n05 += 1;
                }
                if rho >= bartlett_floor_05 {
                    b05 += 1;
                }
                if rho >= naive_floor_01 {
                    n01 += 1;
                }
                if rho >= bartlett_floor_01 {
                    b01 += 1;
                }
            }
            let rate = |count: usize| count as f64 / trials as f64;
            Ok(Ar1NullRow {
                phi,
                n_eff,
                naive_fpr_05: rate(n05),
                naive_fpr_05_ci: wilson95(n05, trials)?,
                bartlett_fpr_05: rate(b05),
                bartlett_fpr_05_ci: wilson95(b05, trials)?,
                naive_fpr_01: rate(n01),
                naive_fpr_01_ci: wilson95(n01, trials)?,
                bartlett_fpr_01: rate(b01),
                bartlett_fpr_01_ci: wilson95(b01, trials)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Ar1NullStudy {
        trials,
        n: AR1_WINDOW,
        seed,
        rows,
    })
}

/// Format the autocorrelation-null study as a plain-text report.
pub fn format_autocorrelation_null(s: &Ar1NullStudy) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nAutocorrelation null — two INDEPENDENT AR(1) channels · n={} (runtime default window)\n\
         false-positive rate of the one-sided Fisher significance floor · {} trials/phi · seed={}\n\n",
        s.n, s.trials, s.seed
    ));
    o.push_str(&format!(
        "{:>4} | {:>6} | {:>21} | {:>21} | {:>21} | {:>21}\n",
        "phi",
        "n_eff",
        "naive FPR@.05 [CI]",
        "Bartlett FPR@.05",
        "naive FPR@.01 [CI]",
        "Bartlett FPR@.01"
    ));
    o.push_str(&format!("{}\n", "-".repeat(110)));
    for r in &s.rows {
        o.push_str(&format!(
            "{:>4.1} | {:>6.1} | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}] | {:>7.3} [{:.3},{:.3}]\n",
            r.phi,
            r.n_eff,
            r.naive_fpr_05,
            r.naive_fpr_05_ci.0,
            r.naive_fpr_05_ci.1,
            r.bartlett_fpr_05,
            r.bartlett_fpr_05_ci.0,
            r.bartlett_fpr_05_ci.1,
            r.naive_fpr_01,
            r.naive_fpr_01_ci.0,
            r.naive_fpr_01_ci.1,
            r.bartlett_fpr_01,
            r.bartlett_fpr_01_ci.0,
            r.bartlett_fpr_01_ci.1,
        ));
    }
    o.push_str(
        "\nThe channels are independent (population rho = 0): every alarm above is a false\n\
         positive. The naive floor assumes i.i.d. pairs (SE 1/sqrt(n-3)); positive lag-1\n\
         autocorrelation inflates its realized rate above the nominal alpha, as predicted by\n\
         Bartlett's (1935) large-sample variance (1+phi^2)/((1-phi^2)n). The Bartlett column\n\
         replaces n with n_eff = n(1-phi^2)/(1+phi^2): it improves calibration at moderate\n\
         persistence, but becomes conservative at phi=0.9 where n_eff is only about 13.4 and\n\
         the asymptotic Fisher approximation is poor. The runtime default intentionally remains\n\
         naive: an operational correction needs a registered phi-estimation and finite-sample\n\
         calibration design (PAPER.md §7). The phi=0 row checks this harness. Synthetic evidence only.\n",
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(s: &Study, c: Coupling) -> CouplingResult {
        s.results.iter().find(|r| r.coupling == c).cloned().unwrap()
    }

    #[test]
    fn ranked_auc_preserves_mann_whitney_ties() {
        assert_eq!(auc(&[2.0, 3.0], &[0.0, 1.0]).unwrap(), 1.0);
        assert_eq!(auc(&[1.0], &[1.0]).unwrap(), 0.5);
        assert_eq!(auc(&[0.0, 2.0], &[1.0]).unwrap(), 0.5);
    }

    #[test]
    fn linear_coupling_correlation_matches_mi() {
        // On linear-Gaussian coupling both detectors separate perfectly — so MI/PID
        // adds no value over the cheap correlation test.
        let s = run(120, 300, 0.5, 7).expect("valid study");
        let lin = result(&s, Coupling::Linear);
        assert!(lin.corr_auc > 0.9, "corr AUC {:.3}", lin.corr_auc);
        assert!(lin.mi_auc > 0.9, "MI AUC {:.3}", lin.mi_auc);
        assert!(
            (lin.corr_auc - lin.mi_auc).abs() < 0.1,
            "corr and MI should agree"
        );
    }

    #[test]
    fn nonlinear_coupling_mi_beats_correlation() {
        // The good reason for PID: on a nonlinear (correlation-preserving) coupling,
        // correlation is at chance while MI still separates.
        let s = run(120, 300, 0.5, 7).expect("valid study");
        let nl = result(&s, Coupling::Nonlinear);
        assert!(
            nl.corr_auc < 0.7,
            "correlation should be near chance: {:.3}",
            nl.corr_auc
        );
        assert!(nl.mi_auc > 0.85, "MI should catch it: {:.3}", nl.mi_auc);
        assert!(
            nl.mi_auc - nl.corr_auc > 0.2,
            "MI must beat correlation clearly"
        );
    }

    #[test]
    fn synergy_only_the_joint_measure_sees_xor() {
        // The irreducible reason for PID: on T = A XOR B, correlation AND pairwise MI
        // are both blind; only the joint/synergy measure separates coupled from decoupled.
        let r = run_synergy(150, 600, 7).expect("valid synergy study");
        assert!(
            r.corr_auc < 0.65,
            "correlation should be blind: {:.3}",
            r.corr_auc
        );
        assert!(
            r.pairwise_mi_auc < 0.75,
            "pairwise MI should be blind: {:.3}",
            r.pairwise_mi_auc
        );
        assert!(
            r.synergy_auc > 0.9,
            "synergy must separate: {:.3}",
            r.synergy_auc
        );
        assert!(
            r.synergy_coupled_mean > 0.7,
            "XOR synergy ~1 bit: {:.3}",
            r.synergy_coupled_mean
        );
    }

    #[test]
    fn sxpid_synergy_atom_sees_xor_and_matches_closed_form() {
        // The Wibral i^sx diagnostic decomposition: its synergy atom separates the
        // XOR coupling (AUC ~1), and the coupled-class atoms match the closed form —
        // syn = log2(4/3) ≈ +0.415 bits, red = log2(2/3) ≈ −0.585 bits (negative:
        // misinformative sharing, a deliberate property of SxPID, never clamped).
        let r = run_synergy(150, 600, 7).expect("valid synergy study");
        assert!(
            r.sxpid_syn_auc > 0.9,
            "SxPID synergy atom must separate: {:.3}",
            r.sxpid_syn_auc
        );
        let syn_exact = (4.0_f64 / 3.0).log2();
        let red_exact = (2.0_f64 / 3.0).log2();
        assert!(
            (r.sxpid_syn_coupled_mean - syn_exact).abs() < 0.05,
            "XOR SxPID synergy ≈ {syn_exact:.3} bits, got {:.3}",
            r.sxpid_syn_coupled_mean
        );
        assert!(
            (r.sxpid_red_coupled_mean - red_exact).abs() < 0.05,
            "XOR SxPID redundancy ≈ {red_exact:.3} bits (negative), got {:.3}",
            r.sxpid_red_coupled_mean
        );
    }

    #[test]
    fn continuous_synergy_only_joint_measures_see_sign_parity() {
        // The continuous XOR analog on the pid-core estimators: pairwise KSG MI is
        // at chance (all pairwise marginals exactly independent), while the joint
        // contrast Q and the continuous I^sx synergy atom both separate.
        let r = run_synergy_continuous(40, 600, 7).expect("valid continuous study");
        assert!(
            r.pairwise_mi_auc < 0.75,
            "pairwise KSG MI should be ~chance: {:.3}",
            r.pairwise_mi_auc
        );
        assert!(r.q_auc > 0.9, "joint Q must separate: {:.3}", r.q_auc);
        assert!(
            r.isx_syn_auc > 0.85,
            "continuous I^sx synergy atom must separate: {:.3}",
            r.isx_syn_auc
        );
        // Joint KSG MI should approximate the exact ln 2 parity bit.
        assert!(
            (r.joint_mi_coupled_mean - std::f64::consts::LN_2).abs() < 0.2,
            "joint MI ≈ ln2: {:.3}",
            r.joint_mi_coupled_mean
        );
    }

    #[test]
    fn seq_linear_pointwise_detectors_reach_and_beat_window_latency() {
        // H1/H2 on the linear coupling: every detector reaches; the pointwise CUSUMs
        // (parametric Gauss-LR and model-free local-MI alike) detect faster than the
        // windowed-refit detectors.
        let s = run_seq(Coupling::Linear, 25, 0.5, 7).expect("valid sequential study");
        let row = |d: SeqDetector| s.rows.iter().find(|r| r.detector == d).unwrap().clone();
        for d in SeqDetector::ALL {
            let r = row(d);
            assert!(r.reach > 0.85, "{}: reach {:.2}", d.label(), r.reach);
        }
        let win_mi = row(SeqDetector::WindowMi).median_latency.unwrap();
        let lmi = row(SeqDetector::LocalMiCusum).median_latency.unwrap();
        let glr = row(SeqDetector::GaussLrCusum).median_latency.unwrap();
        assert!(
            lmi < win_mi,
            "local-MI CUSUM ({lmi:.0}f) should beat window-MI refill ({win_mi:.0}f)"
        );
        assert!(
            glr < win_mi,
            "Gauss-LR CUSUM ({glr:.0}f) should beat window-MI refill ({win_mi:.0}f)"
        );
    }

    #[test]
    fn seq_nonlinear_only_model_free_pointwise_detector_survives() {
        // H3 on the sign-flip coupling: the cheap pointwise statistics are blind
        // (E[xy] = 0 and ρ̂_cal ≈ 0 on both sides of onset) and so is the windowed
        // correlation; the model-free local-MI CUSUM (and the windowed KSG MI, with
        // its refill latency) still detect.
        let s = run_seq(Coupling::Nonlinear, 25, 0.5, 7).expect("valid sequential study");
        let row = |d: SeqDetector| s.rows.iter().find(|r| r.detector == d).unwrap().clone();
        assert!(
            row(SeqDetector::WindowCorr).reach < 0.4,
            "window |rho| should be blind: {:.2}",
            row(SeqDetector::WindowCorr).reach
        );
        assert!(
            row(SeqDetector::ProductCusum).reach < 0.4,
            "product CUSUM should be blind: {:.2}",
            row(SeqDetector::ProductCusum).reach
        );
        assert!(
            row(SeqDetector::GaussLrCusum).reach < 0.4,
            "Gauss-LR CUSUM should be blind: {:.2}",
            row(SeqDetector::GaussLrCusum).reach
        );
        assert!(
            row(SeqDetector::LocalMiCusum).reach > 0.75,
            "local-MI CUSUM must detect: {:.2}",
            row(SeqDetector::LocalMiCusum).reach
        );
        assert!(
            row(SeqDetector::WindowMi).reach > 0.75,
            "window KSG MI must detect: {:.2}",
            row(SeqDetector::WindowMi).reach
        );
    }

    #[test]
    fn public_studies_reject_degenerate_or_unbounded_inputs() {
        assert!(run(0, 300, 0.5, 7).is_err());
        assert!(run(MIN_TRIALS - 1, 300, 0.5, 7).is_err());
        assert!(run(MIN_TRIALS, 7, 0.5, 7).is_err());
        assert!(run(MIN_TRIALS, 300, f64::NAN, 7).is_err());
        assert!(run(MIN_TRIALS, MAX_SAMPLES, 0.5, 7).is_err());
        assert!(run_synergy(MAX_TRIALS + 1, 600, 7).is_err());
        assert!(run_seq(Coupling::Linear, 0, 0.5, 7).is_err());
        assert!(auc_ci(&[1.0], &[0.0], 0, 7).is_err());
    }

    #[test]
    fn bootstrap_and_cli_preflight_enforce_pairing_and_work_budgets() {
        let pos = vec![1.0; MIN_TRIALS];
        let neg = vec![0.0; MIN_TRIALS];
        assert!(auc_ci(&pos, &neg, MIN_BOOTSTRAP_RESAMPLES, 7).is_ok());
        assert!(auc_ci(&pos, &neg, MIN_BOOTSTRAP_RESAMPLES - 1, 7).is_err());
        assert!(auc_ci(&pos, &neg[..MIN_TRIALS - 1], MIN_BOOTSTRAP_RESAMPLES, 7).is_err());
        assert!(auc_ci(
            &pos[..MIN_TRIALS - 1],
            &neg[..MIN_TRIALS - 1],
            MIN_BOOTSTRAP_RESAMPLES,
            7
        )
        .is_err());

        let large_pos = vec![1.0; MAX_TRIALS];
        let large_neg = vec![0.0; MAX_TRIALS];
        assert!(auc_ci(&large_pos, &large_neg, 100_000, 7).is_err());
        assert!(preflight_default_suite(300).is_ok());
        assert!(preflight_default_suite(MAX_TRIALS).is_err());
    }

    #[test]
    fn wilson_interval_exposes_small_holdout_uncertainty() {
        assert!(wilson95(0, 0).is_err());
        assert!(wilson95(21, 20).is_err());

        let zero = wilson95(0, 20).expect("valid count");
        assert!(zero.0 <= f64::EPSILON);
        assert!(
            zero.1 > 0.15 && zero.1 < 0.17,
            "zero-event upper={}",
            zero.1
        );

        let one = wilson95(1, 20).expect("valid count");
        assert!(one.0 < 0.05 && one.1 > 0.05);

        let report = format_seq(&SeqStudy {
            coupling: Coupling::Linear,
            trials: 20,
            sigma: 0.5,
            seed: 7,
            rows: vec![SeqRow {
                detector: SeqDetector::WindowCorr,
                realized_far: 0.05,
                realized_far_ci: one,
                false_start: 0.0,
                reach: 1.0,
                median_latency: Some(4.0),
            }],
        });
        assert!(report.contains("FAR [Wilson 95% CI]"));
        assert!(report.contains(&format!("[{:.3},{:.3}]", one.0, one.1)));

        let all = wilson95(20, 20).expect("valid count");
        assert!(all.0 > 0.83 && all.0 < 0.85, "all-event lower={}", all.0);
        assert!((all.1 - 1.0).abs() <= f64::EPSILON);
    }

    #[test]
    fn xor_generator_resamples_degenerate_bernoulli_columns() {
        for seed in 0..128 {
            let mut rng = StdRng::seed_from_u64(seed);
            let (a, b, t) = gen_xor_trial(8, &mut rng).expect("bounded draw should succeed");
            assert!(has_both_binary_values(&a));
            assert!(has_both_binary_values(&b));
            assert!(has_both_binary_values(&t));
        }
        assert!(run_synergy(MIN_TRIALS, 8, 7).is_ok());
    }

    #[test]
    fn domain_separated_jitter_does_not_create_constant_channel_dependence() {
        let constant = vec![1.0; 512];
        let mi = ksg(7, &constant, &constant).expect("finite columns");
        assert!(mi < 0.2, "independent jitter should not fabricate MI: {mi}");
    }

    #[test]
    fn autocorrelation_null_exposes_naive_inflation_and_bartlett_finite_sample_limit() {
        // Hypothesis of Study 4: under the null (independent channels), positive lag-1
        // autocorrelation makes the naive i.i.d. Fisher floor anti-conservative. Bartlett's
        // effective sample size improves calibration until high persistence leaves too little
        // effective data for the asymptotic Fisher approximation.
        let s = run_autocorrelation_null(1_000, 7).expect("valid AR(1) null study");
        let row = |phi: f64| {
            s.rows
                .iter()
                .find(|r| (r.phi - phi).abs() < 1e-9)
                .cloned()
                .unwrap()
        };
        let calibrated = row(0.0);
        assert!(
            (0.02..=0.09).contains(&calibrated.naive_fpr_05),
            "phi=0 must be calibrated near alpha=.05: {}",
            calibrated.naive_fpr_05
        );
        let inflated = row(0.7);
        assert!(
            inflated.naive_fpr_05 >= 0.11,
            "phi=0.7 must inflate the naive FPR well above alpha: {}",
            inflated.naive_fpr_05
        );
        assert!(
            inflated.naive_fpr_05 > row(0.3).naive_fpr_05,
            "naive inflation must grow with phi"
        );
        for phi in [0.0, 0.3, 0.5, 0.7] {
            let r = row(phi);
            assert!(
                (0.02..=0.09).contains(&r.bartlett_fpr_05),
                "Bartlett floor should remain near alpha at phi={phi}: {}",
                r.bartlett_fpr_05
            );
        }
        let high_persistence = row(0.9);
        assert!(
            high_persistence.bartlett_fpr_05_ci.1 < 0.05
                && high_persistence.bartlett_fpr_01_ci.1 < 0.01,
            "small-n_eff Bartlett/Fisher approximation should be detectably conservative: {high_persistence:?}"
        );
    }

    #[test]
    fn autocorrelation_null_rejects_out_of_range_trials() {
        assert!(run_autocorrelation_null(MIN_TRIALS - 1, 7).is_err());
        assert!(run_autocorrelation_null(MAX_TRIALS + 1, 7).is_err());
    }
}
