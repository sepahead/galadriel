#![forbid(unsafe_code)]
//! **Is PID / mutual information actually justified over cheap Pearson correlation?**
//!
//! This is the honest "earn your complexity" test. For *jointly-Gaussian, linearly*
//! coupled variables, KSG mutual information is a monotone function of `|ρ|`
//! (`MI = −½ ln(1 − ρ²)`), so an MI detector and a correlation detector have the
//! **same ROC** — MI adds nothing, and using it would be *forcing* the method.
//!
//! MI earns its place only where the dependence is **nonlinear**: there `|ρ| ≈ 0`
//! even though the variables are strongly dependent, so correlation is (at best) weak
//! while MI is decisive. This study measures both detectors' ROC-AUC at separating a
//! *coupled* pair from a *decoupled* one (a permutation null), under a **linear**
//! coupling (`Y = X + ε`) and a **nonlinear** one (`Y = ±X + ε`, random sign — for
//! which `corr(X, Y) = 0` with the same sample-correlation variance as independence).
//!
//! The result is the good reason to use PID, stated precisely: **MI is a model-free
//! dependence detector**. It catches an attack that breaks cross-channel structure
//! *without knowing the form of that structure in advance* — which is exactly the
//! position a defender is in against an adversary who is free to choose a
//! correlation-preserving (nonlinear) manipulation.

use pid_core::{ksg_mi, Jitter, KsgConfig, MatOwned};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use rand_distr::{Distribution, Normal};

/// The cross-variable coupling under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coupling {
    /// `Y = X + ε` — the linear-Gaussian case where correlation ≡ MI as a detector.
    Linear,
    /// `Y = ±X + ε` (random sign per sample) — strongly dependent (`|Y| ≈ |X|`) yet
    /// `corr(X, Y) = 0`, *and* with the same sample-correlation variance as the
    /// independent case, so correlation is genuinely chance-level here.
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

/// Absolute Pearson correlation.
pub fn abs_pearson(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len() as f64;
    let mx = x.iter().sum::<f64>() / n;
    let my = y.iter().sum::<f64>() / n;
    let (mut sxy, mut sxx, mut syy) = (0.0, 0.0, 0.0);
    for i in 0..x.len() {
        let (dx, dy) = (x[i] - mx, y[i] - my);
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    if sxx <= 0.0 || syy <= 0.0 {
        0.0
    } else {
        (sxy / (sxx.sqrt() * syy.sqrt())).abs()
    }
}

/// KSG mutual information (nats), jittered to break kNN-radius ties.
fn ksg(jit: &Jitter, x: &[f64], y: &[f64]) -> f64 {
    let build =
        |v: &[f64]| MatOwned::new(v.to_vec(), v.len(), 1).and_then(|m| jit.apply(m.as_ref()));
    match (build(x), build(y)) {
        (Ok(a), Ok(b)) => ksg_mi(a.as_ref(), b.as_ref(), &KsgConfig::default()).unwrap_or(0.0),
        _ => 0.0,
    }
}

/// Generate a coupled `(X, Y)` pair. The decoupled control (in [`run`]) is a
/// permutation of `Y` — a **permutation null**: identical marginal, dependence
/// destroyed — so the comparison isolates *dependence*, not any marginal-shape
/// difference (which would otherwise hand correlation spurious power).
fn gen_coupled(coupling: Coupling, n: usize, sigma: f64, rng: &mut StdRng) -> (Vec<f64>, Vec<f64>) {
    let std_normal = Normal::new(0.0, 1.0).expect("normal");
    let noise = Normal::new(0.0, sigma).expect("noise");
    let x: Vec<f64> = (0..n).map(|_| std_normal.sample(rng)).collect();
    let y: Vec<f64> = x
        .iter()
        .map(|&xi| match coupling {
            Coupling::Linear => xi + noise.sample(rng),
            // Random sign flip: corr(X, ±X) = 0 (and the sample-corr variance matches
            // the independent case), but |Y| ≈ |X| so the magnitude dependence is
            // strong — decisive to MI, invisible to correlation.
            Coupling::Nonlinear => {
                let s = if rng.gen::<bool>() { 1.0 } else { -1.0 };
                xi * s + noise.sample(rng)
            }
        })
        .collect();
    (x, y)
}

/// ROC-AUC via the Mann–Whitney identity (ties = ½).
pub fn auc(pos: &[f64], neg: &[f64]) -> f64 {
    if pos.is_empty() || neg.is_empty() {
        return f64::NAN;
    }
    let mut s = 0.0;
    for &p in pos {
        for &n in neg {
            s += if p > n + 1e-12 {
                1.0
            } else if (p - n).abs() <= 1e-12 {
                0.5
            } else {
                0.0
            };
        }
    }
    s / (pos.len() as f64 * neg.len() as f64)
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
    /// MI detector ROC-AUC (coupled vs decoupled).
    pub mi_auc: f64,
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
    /// One result per coupling.
    pub results: Vec<CouplingResult>,
}

/// Run the study.
pub fn run(trials: usize, n: usize, sigma: f64, seed: u64) -> Study {
    let jit = Jitter::new(1e-6, seed).expect("jitter");
    let results = Coupling::ALL
        .iter()
        .map(|&coupling| {
            let mut rng = StdRng::seed_from_u64(seed.wrapping_add(coupling as u64 + 1));
            let (mut cp, mut cn, mut mp, mut mn) = (vec![], vec![], vec![], vec![]);
            for _ in 0..trials {
                let (x, yc) = gen_coupled(coupling, n, sigma, &mut rng);
                let mut yd = yc.clone();
                yd.shuffle(&mut rng); // permutation null: same marginal, dependence gone
                cp.push(abs_pearson(&x, &yc));
                cn.push(abs_pearson(&x, &yd));
                mp.push(ksg(&jit, &x, &yc));
                mn.push(ksg(&jit, &x, &yd));
            }
            CouplingResult {
                coupling,
                corr_auc: auc(&cp, &cn),
                mi_auc: auc(&mp, &mn),
                corr_coupled_mean: mean(&cp),
                mi_coupled_mean: mean(&mp),
            }
        })
        .collect();
    Study { trials, n, results }
}

/// Format the study as a plain-text report.
pub fn format_report(s: &Study) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Is PID/MI justified over correlation?  {} trials/class · n={} samples/pair\n",
        s.trials, s.n
    ));
    out.push_str(
        "Detector ROC-AUC at separating a coupled pair from a decoupled (independent) one:\n\n",
    );
    out.push_str(&format!(
        "{:<30} | {:>10} | {:>8} | {:>9} | {:>8}\n",
        "coupling", "|rho| mean", "MI mean", "corr AUC", "MI AUC"
    ));
    out.push_str(&format!("{}\n", "-".repeat(78)));
    for r in &s.results {
        out.push_str(&format!(
            "{:<30} | {:>10.3} | {:>8.3} | {:>9.3} | {:>8.3}\n",
            r.coupling.label(),
            r.corr_coupled_mean,
            r.mi_coupled_mean,
            r.corr_auc,
            r.mi_auc,
        ));
    }
    out.push_str(
        "\nLinear:    correlation = MI (same AUC) -> MI adds nothing; using PID here is FORCED.\n\
         Nonlinear: |rho|~0 and correlation is weak (a higher-moment artifact) while MI is\n\
         decisive -> PID's model-free dependence detection is the good, precise reason to\n\
         use it: it catches a correlation-preserving attack a linear check largely misses.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(s: &Study, c: Coupling) -> CouplingResult {
        s.results.iter().find(|r| r.coupling == c).cloned().unwrap()
    }

    #[test]
    fn linear_coupling_correlation_matches_mi() {
        // On linear-Gaussian coupling both detectors separate perfectly — so MI/PID
        // adds no value over the cheap correlation test.
        let s = run(120, 300, 0.5, 7);
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
        let s = run(120, 300, 0.5, 7);
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
}
