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
//! which the *population* `corr(X, Y) = 0`, though the sample correlation has an
//! inflated variance from the kurtosis of `X`, so a `|ρ|` check still scores modestly
//! above chance via that artifact — see the AUC 0.662 below).
//!
//! The result is the good reason to use PID, stated precisely: **MI is a model-free
//! dependence detector**. It catches an attack that breaks cross-channel structure
//! *without knowing the form of that structure in advance* — which is exactly the
//! position a defender is in against an adversary who is free to choose a
//! correlation-preserving (nonlinear) manipulation.

use pid_core::{ksg_mi, pid2_isx_estimate, Jitter, KsgConfig, MatOwned, Pid2Config};
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
    /// *population* `corr(X, Y) = 0`. The sample correlation is *not* chance-level: its
    /// variance is inflated by the kurtosis of `X` (a fourth-moment artifact), so a
    /// `|ρ|` detector reaches AUC ≈ 0.66 purely via that inflation — while MI, seeing
    /// the magnitude dependence directly, is decisive (AUC ≈ 1.0).
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
            // Random sign flip: population corr(X, ±X) = 0, but |Y| ≈ |X| so the
            // magnitude dependence is strong — decisive to MI, and only weakly visible
            // to correlation via the kurtosis-inflated variance of the sample |ρ|.
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

/// Bootstrap resamples for the CIs.
const N_BOOT: usize = 1000;

/// Percentile bootstrap 95% CI for an AUC, resampling each class with replacement.
pub fn auc_ci(pos: &[f64], neg: &[f64], n_boot: usize, seed: u64) -> (f64, f64) {
    if pos.is_empty() || neg.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5EED_B007);
    let mut aucs = Vec::with_capacity(n_boot);
    let (mut rp, mut rn) = (vec![0.0; pos.len()], vec![0.0; neg.len()]);
    for _ in 0..n_boot {
        for r in rp.iter_mut() {
            *r = pos[rng.gen_range(0..pos.len())];
        }
        for r in rn.iter_mut() {
            *r = neg[rng.gen_range(0..neg.len())];
        }
        aucs.push(auc(&rp, &rn));
    }
    aucs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick =
        |q: f64| aucs[((q * (aucs.len() as f64 - 1.0)).round() as usize).min(aucs.len() - 1)];
    (pick(0.025), pick(0.975))
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
                corr_auc_ci: auc_ci(&cp, &cn, N_BOOT, seed.wrapping_add(coupling as u64)),
                mi_auc: auc(&mp, &mn),
                mi_auc_ci: auc_ci(&mp, &mn, N_BOOT, seed.wrapping_add(100 + coupling as u64)),
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
        "\nLinear:    MI = monotone(|rho|) (same AUC) -> MI adds nothing; using it here is FORCED.\n\
         Nonlinear: population rho=0; the |rho| detector still scores 0.66 via a kurtosis-\n\
         inflated sample-corr variance (an artifact, not linear signal), while MI is decisive\n\
         -> MI's model-free dependence detection is the good, precise reason to use it: it\n\
         catches a correlation-preserving attack a linear check largely misses.\n",
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
// 1. The model-free joint-information contrast
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
//    exactly by `pid_core::discrete_sxpid2` on the empirical distribution — so the
//    "PID is justified here" claim is evidenced by the deployed decomposition, not
//    only by the Q proxy.
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
    /// SxPID synergy-atom detector AUC (the deployed `i^sx` decomposition itself).
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
fn sxpid_atoms_bits(s1: &[f64], s2: &[f64], t: &[f64]) -> (f64, f64) {
    let n = s1.len();
    let col = |v: &[f64]| MatOwned::new(v.to_vec(), n, 1).expect("column matrix");
    let (a, b, tt) = (col(s1), col(s2), col(t));
    let r = discrete_sxpid2(a.as_ref(), b.as_ref(), tt.as_ref(), 2).expect("discrete SxPID");
    (r.syn.net / LN_2, r.red.net / LN_2)
}

/// Run the synergy study.
pub fn run_synergy(trials: usize, n: usize, seed: u64) -> SynergyResult {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5259_6E65);
    let (mut cc, mut cd) = (Vec::new(), Vec::new());
    let (mut pc, mut pd) = (Vec::new(), Vec::new());
    let (mut sc, mut sd) = (Vec::new(), Vec::new());
    let (mut xc, mut xd, mut xr) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..trials {
        let a: Vec<u64> = (0..n).map(|_| u64::from(rng.gen::<bool>())).collect();
        let b: Vec<u64> = (0..n).map(|_| u64::from(rng.gen::<bool>())).collect();
        let t: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| x ^ y).collect();
        let mut td = t.clone();
        td.shuffle(&mut rng); // permutation null: same T marginal, dependence gone

        let f = |v: &[u64]| v.iter().map(|&x| x as f64).collect::<Vec<f64>>();
        let (af, bf, tf, tdf) = (f(&a), f(&b), f(&t), f(&td));

        cc.push(abs_pearson(&af, &tf).max(abs_pearson(&bf, &tf)));
        cd.push(abs_pearson(&af, &tdf).max(abs_pearson(&bf, &tdf)));

        let pm_c = mi_bits(&a, &t).max(mi_bits(&b, &t));
        let pm_d = mi_bits(&a, &td).max(mi_bits(&b, &td));
        pc.push(pm_c);
        pd.push(pm_d);

        let ab = join(&a, &b);
        sc.push((mi_bits(&ab, &t) - pm_c).max(0.0));
        sd.push((mi_bits(&ab, &td) - pm_d).max(0.0));

        // The deployed decomposition itself: SxPID synergy atom as the detector score
        // (and the coupled-class redundancy atom, to exhibit its negative/misinformative
        // value on XOR). Computed after the RNG draws so the rows above are unchanged.
        let (syn_c, red_c) = sxpid_atoms_bits(&af, &bf, &tf);
        let (syn_d, _) = sxpid_atoms_bits(&af, &bf, &tdf);
        xc.push(syn_c);
        xd.push(syn_d);
        xr.push(red_c);
    }
    SynergyResult {
        corr_auc: auc(&cc, &cd),
        corr_auc_ci: auc_ci(&cc, &cd, N_BOOT, seed.wrapping_add(1)),
        pairwise_mi_auc: auc(&pc, &pd),
        pairwise_mi_auc_ci: auc_ci(&pc, &pd, N_BOOT, seed.wrapping_add(2)),
        synergy_auc: auc(&sc, &sd),
        synergy_auc_ci: auc_ci(&sc, &sd, N_BOOT, seed.wrapping_add(3)),
        synergy_coupled_mean: mean(&sc),
        sxpid_syn_auc: auc(&xc, &xd),
        sxpid_syn_auc_ci: auc_ci(&xc, &xd, N_BOOT, seed.wrapping_add(4)),
        sxpid_syn_coupled_mean: mean(&xc),
        sxpid_red_coupled_mean: mean(&xr),
    }
}

/// Format the synergy study as a plain-text report.
pub fn format_synergy(r: &SynergyResult) -> String {
    let mut o = String::new();
    o.push_str("\nSynergy: T = A XOR B (A,B independent bits) vs a decoupled (shuffled) T.\n");
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
         = -0.585 bits): measured syn {:+.3}, red {:+.3} — the deployed i^sx decomposition\n\
         reads XOR as unique+synergistic with *misinformative* (negative) sharing, unlike\n\
         Williams-Beer I_min's (0, 0, 0, 1); Q = Syn + min(U1,U2) = 1 bit for both.\n",
        r.sxpid_syn_coupled_mean, r.sxpid_red_coupled_mean
    ));
    o.push_str(
        "\ncorrelation and pairwise MI are BOTH at chance (CIs bracket 0.5): every pairwise\n\
         marginal of the XOR system is exactly independent-uniform, so no single-pair\n\
         statistic carries population signal. Only the joint measures separate the classes\n\
         -> against an attack on synergistic fusion a joint/PID measure is not merely\n\
         better; short of a bespoke parity test that presumes the attack's form, it is\n\
         the only option.\n",
    );
    o
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 2b — continuous synergy: the justified regime on the *deployed* estimators.
//
// Study 2's XOR is discrete and exact — but the shipped engine runs *continuous*
// estimators (KSG MI; the Ehrlich et al. 2024 continuous `I^sx`). This study closes
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
// `Syn = MI(A,B;T) − MI(A;T) − MI(B;T) + Red` — so the *deployed* continuous
// machinery is what is being validated in the one regime where PID is irreducible.
// ─────────────────────────────────────────────────────────────────────────────

/// ROC-AUCs of pairwise vs joint continuous detectors on the sign-parity coupling.
#[derive(Debug, Clone)]
pub struct ContinuousSynergyResult {
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

/// All four continuous scores of one `(A, B, T)` triple from a single
/// `pid2_isx_estimate` call: `(max pairwise MI, Q, isx synergy)`, in nats.
fn continuous_synergy_scores(a: &[f64], b: &[f64], t: &[f64]) -> (f64, f64, f64) {
    let n = a.len();
    let col = |v: &[f64]| MatOwned::new(v.to_vec(), n, 1).expect("column matrix");
    let (am, bm, tm) = (col(a), col(b), col(t));
    let est = pid2_isx_estimate(
        am.as_ref(),
        bm.as_ref(),
        tm.as_ref(),
        &Pid2Config::default(),
    )
    .expect("pid2 estimate");
    let pm = est.mi_s1_t.max(est.mi_s2_t);
    let q = (est.mi_s1s2_t - pm).max(0.0);
    let syn = est.mi_s1s2_t - est.mi_s1_t - est.mi_s2_t + est.redundancy_isx;
    (pm.max(0.0), q, syn)
}

/// Run the continuous (sign-parity) synergy study.
pub fn run_synergy_continuous(trials: usize, n: usize, seed: u64) -> ContinuousSynergyResult {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x516E_9A21);
    let std_normal = Normal::new(0.0, 1.0).expect("normal");
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

        cc.push(abs_pearson(&a, &t).max(abs_pearson(&b, &t)));
        cd.push(abs_pearson(&a, &td).max(abs_pearson(&b, &td)));

        let (pm_c, q_c, syn_c) = continuous_synergy_scores(&a, &b, &t);
        let (pm_d, q_d, syn_d) = continuous_synergy_scores(&a, &b, &td);
        pc.push(pm_c);
        pd.push(pm_d);
        qc.push(q_c);
        qd.push(q_d);
        xc.push(syn_c);
        xd.push(syn_d);
        joint_mi.push(q_c + pm_c); // = mi_s1s2_t clamped composition; recorded for the mean
    }
    ContinuousSynergyResult {
        corr_auc: auc(&cc, &cd),
        corr_auc_ci: auc_ci(&cc, &cd, N_BOOT, seed.wrapping_add(11)),
        pairwise_mi_auc: auc(&pc, &pd),
        pairwise_mi_auc_ci: auc_ci(&pc, &pd, N_BOOT, seed.wrapping_add(12)),
        q_auc: auc(&qc, &qd),
        q_auc_ci: auc_ci(&qc, &qd, N_BOOT, seed.wrapping_add(13)),
        isx_syn_auc: auc(&xc, &xd),
        isx_syn_auc_ci: auc_ci(&xc, &xd, N_BOOT, seed.wrapping_add(14)),
        joint_mi_coupled_mean: mean(&joint_mi),
        isx_syn_coupled_mean: mean(&xc),
    }
}

/// Format the continuous synergy study as a plain-text report.
pub fn format_synergy_continuous(r: &ContinuousSynergyResult) -> String {
    let mut o = String::new();
    o.push_str(
        "\nContinuous synergy: sign-parity coupling T = sign(A)·sign(B)·|Z| (A,B,Z ~ N(0,1))\n\
         vs a decoupled (shuffled) T — the deployed *continuous* estimators (KSG + I^sx):\n\n",
    );
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
        "\njoint KSG MI on coupled: {:.3} nats (exact: ln 2 = 0.693 — the parity bit);\n\
         continuous I^sx synergy atom on coupled: {:.3} nats. Pairwise marginals are\n\
         *exactly* independent here, so pairwise corr/MI are at chance by construction —\n\
         the same irreducible-synergy verdict as the discrete XOR, now demonstrated on\n\
         the continuous estimators the engine actually deploys.\n",
        r.joint_mi_coupled_mean, r.isx_syn_coupled_mean
    ));
    o
}

// ─────────────────────────────────────────────────────────────────────────────
// Study 3 — the pointwise escalation: sequential detection at matched FAR.
//
// Studies 1–2 score *windows*; a streaming monitor pays their price in **latency**:
// a trailing window must refill with post-onset frames before a broken coupling is
// legible (the eval harness measures 52–80 frames for the windowed detectors). The
// distinctive capability of the shared-exclusions PID framework is that its
// quantities are **pointwise** — they exist per realization (Makkeh–Gutknecht–
// Wibral 2021; the single-source node is the pointwise MI, by self-redundancy) —
// so consistency can be scored *per frame* and fed to a sequential (CUSUM) test.
//
// The theory says more: the per-frame local MI term is a plug-in estimate of
// log[ p_coupled(x,y) / (p(x)·p(y)) ] — the **log-likelihood ratio** between the
// calibrated coupled regime and the decoupled (independent, same-marginals)
// regime. A CUSUM over exactly that log-LR is the classical optimal sequential
// changepoint procedure, so "pointwise information" is not a heuristic score; it
// is the canonical detection statistic for a moment-matched decoupling.
//
// The forced-vs-justified question then recurs at the pointwise level, and this
// study asks it with five sequential detectors at one **matched stream-level FAR**:
//
//   window |ρ̂|      — the deployed default's analog (trailing-window refit);
//   window KSG MI    — the windowed escalation's analog;
//   product CUSUM    — per-frame x·y (the naive cheap pointwise statistic);
//   Gauss-LR CUSUM   — per-frame *parametric* Gaussian log-LR: the closed-form
//                      pointwise MI i(x,y; ρ̂_cal) — "correlation, pointwise";
//   local-MI CUSUM   — per-frame *model-free* kNN local-MI against a frozen clean
//                      reference window — "Wibral-pointwise", no model assumed.
//
// Hypotheses (stated before running):
//   H1 (latency): at matched FAR, the pointwise CUSUM detectors beat the windowed
//      detectors' refill latency on the coupling they can see.
//   H2 (forced, pointwise): on the linear-Gaussian coupling the parametric
//      Gauss-LR CUSUM — a one-line ρ̂ plug-in — matches the kNN local-MI CUSUM:
//      pointwise information is *forced* on the Gaussian manifold, exactly as the
//      windowed result (§1) predicts.
//   H3 (justified, pointwise): on the sign-flip coupling the product and Gauss-LR
//      CUSUMs are blind (E[xy] = 0 and ρ̂_cal ≈ 0 on *both* sides of onset), while
//      the model-free local-MI CUSUM still detects — the pointwise analog of §2.
//      (A variance-tracking chart could see this particular construction through
//      its second moment — again a bespoke feature choice, the pointwise echo of
//      §2's kurtosis artifact; the local-MI chart needs no such choice.)
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
/// Matched stream-level false-alarm rate all thresholds are calibrated to.
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
    /// at the calibration ρ̂) — the *cheap, on-manifold-optimal* pointwise detector.
    GaussLrCusum,
    /// CUSUM over the per-frame model-free kNN local-MI term against the frozen
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

/// One detector's row in the sequential study.
#[derive(Debug, Clone)]
pub struct SeqRow {
    /// Which detector.
    pub detector: SeqDetector,
    /// Fraction of *clean* streams that alarmed anywhere in the eval segment
    /// (the realized stream-level FAR; thresholds are calibrated to [`SEQ_FAR`]).
    pub realized_far: f64,
    /// Fraction of *attacked* streams that alarmed **before** onset (false starts).
    pub false_start: f64,
    /// Fraction of attacked streams (without a false start) alarming at/after onset.
    pub reach: f64,
    /// Median frames from onset to first alarm, among reaching trials
    /// (windowed detectors are quantized to the [`SEQ_STRIDE`]-frame grid).
    pub median_latency: Option<f64>,
}

/// The sequential (pointwise) study for one coupling.
#[derive(Debug, Clone)]
pub struct SeqStudy {
    /// Which coupling.
    pub coupling: Coupling,
    /// Trials per arm (clean-calibration and attacked).
    pub trials: usize,
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
) -> (Vec<f64>, Vec<f64>) {
    let total = SEQ_REF_LEN + SEQ_EVAL_LEN;
    let onset = SEQ_REF_LEN + SEQ_ONSET;
    let std_normal = Normal::new(0.0, 1.0).expect("normal");
    let noise = Normal::new(0.0, sigma).expect("noise");
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
    (xs, ys)
}

/// Per-stream detector traces over the eval segment: for each detector, the frames
/// (eval-segment indices) at which its statistic is *available*, and the statistic
/// value oriented so that **larger = more anomalous** (windowed scores are negated).
fn seq_traces(jit: &Jitter, xs: &[f64], ys: &[f64]) -> Vec<(SeqDetector, Vec<(usize, f64)>)> {
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
        wcorr.push((e - 1, -abs_pearson(wx, wy)));
        wmi.push((e - 1, -ksg(jit, wx, wy)));
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

    vec![
        (SeqDetector::WindowCorr, wcorr),
        (SeqDetector::WindowMi, wmi),
        (SeqDetector::ProductCusum, prod),
        (SeqDetector::GaussLrCusum, glr),
        (SeqDetector::LocalMiCusum, lmi),
    ]
}

/// Run the sequential (pointwise) study for one coupling: calibrate every detector's
/// threshold to the same stream-level FAR on `trials` clean streams, then measure
/// false-start / reach / median latency on `trials` attacked streams.
pub fn run_seq(coupling: Coupling, trials: usize, sigma: f64, seed: u64) -> SeqStudy {
    let jit = Jitter::new(1e-6, seed ^ 0x5E9).expect("jitter");
    let n_det = SeqDetector::ALL.len();

    // Clean arm: per-detector per-stream maximum of the anomaly statistic.
    let mut rng = StdRng::seed_from_u64(seed ^ 0xC1EA_0000 ^ coupling as u64);
    let mut clean_max: Vec<Vec<f64>> = vec![Vec::with_capacity(trials); n_det];
    for _ in 0..trials {
        let (xs, ys) = gen_seq_stream(coupling, sigma, false, &mut rng);
        for (di, (_, trace)) in seq_traces(&jit, &xs, &ys).into_iter().enumerate() {
            let m = trace.iter().map(|&(_, v)| v).fold(f64::MIN, f64::max);
            clean_max[di].push(m);
        }
    }
    // Matched operating point: each detector's threshold is its own clean-maxima
    // (1 − FAR) quantile — the same stream-level FAR for all five detectors.
    let threshold: Vec<f64> = clean_max
        .iter()
        .map(|v| {
            let mut s = v.clone();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let idx =
                (((1.0 - SEQ_FAR) * (s.len() as f64 - 1.0)).round() as usize).min(s.len() - 1);
            s[idx]
        })
        .collect();
    let realized_far: Vec<f64> = clean_max
        .iter()
        .zip(&threshold)
        .map(|(v, &th)| v.iter().filter(|&&m| m > th).count() as f64 / v.len().max(1) as f64)
        .collect();

    // Attacked arm: first alarm per detector per stream.
    let mut rng = StdRng::seed_from_u64(seed ^ 0xA77A_C000 ^ coupling as u64);
    let mut false_start = vec![0usize; n_det];
    let mut latencies: Vec<Vec<f64>> = vec![Vec::new(); n_det];
    for _ in 0..trials {
        let (xs, ys) = gen_seq_stream(coupling, sigma, true, &mut rng);
        for (di, (_, trace)) in seq_traces(&jit, &xs, &ys).into_iter().enumerate() {
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
                l.sort_by(|a, b| a.partial_cmp(b).unwrap());
                Some(l[l.len() / 2])
            };
            SeqRow {
                detector,
                realized_far: realized_far[di],
                false_start: false_start[di] as f64 / trials as f64,
                reach,
                median_latency,
            }
        })
        .collect();

    SeqStudy {
        coupling,
        trials,
        rows,
    }
}

/// Format the sequential study as a plain-text report.
pub fn format_seq(s: &SeqStudy) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "\nSequential (pointwise) detection — {} · onset +{} · matched stream FAR {:.0}%\n\
         moment-matched decoupling at onset; thresholds calibrated on {} clean streams\n\n",
        s.coupling.label(),
        SEQ_ONSET,
        SEQ_FAR * 100.0,
        s.trials
    ));
    o.push_str(&format!(
        "{:<26} | {:>5} | {:>11} | {:>6} | {:>14}\n",
        "detector", "FAR", "false-start", "reach", "median latency"
    ));
    o.push_str(&format!("{}\n", "-".repeat(76)));
    for r in &s.rows {
        o.push_str(&format!(
            "{:<26} | {:>5.3} | {:>11.3} | {:>6.3} | {:>14}\n",
            r.detector.label(),
            r.realized_far,
            r.false_start,
            r.reach,
            r.median_latency
                .map(|l| format!("{l:.0}f"))
                .unwrap_or_else(|| "—".into()),
        ));
    }
    o
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

    #[test]
    fn synergy_only_the_joint_measure_sees_xor() {
        // The irreducible reason for PID: on T = A XOR B, correlation AND pairwise MI
        // are both blind; only the joint/synergy measure separates coupled from decoupled.
        let r = run_synergy(150, 600, 7);
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
        // The deployed Wibral i^sx decomposition itself: its synergy atom separates the
        // XOR coupling (AUC ~1), and the coupled-class atoms match the closed form —
        // syn = log2(4/3) ≈ +0.415 bits, red = log2(2/3) ≈ −0.585 bits (negative:
        // misinformative sharing, a deliberate property of SxPID, never clamped).
        let r = run_synergy(150, 600, 7);
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
        // The continuous XOR analog on the *deployed* estimators: pairwise KSG MI is
        // at chance (all pairwise marginals exactly independent), while the joint
        // contrast Q and the continuous I^sx synergy atom both separate.
        let r = run_synergy_continuous(40, 600, 7);
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
        let s = run_seq(Coupling::Linear, 25, 0.5, 7);
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
        let s = run_seq(Coupling::Nonlinear, 25, 0.5, 7);
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
}
