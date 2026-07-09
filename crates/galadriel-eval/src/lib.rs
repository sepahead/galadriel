#![forbid(unsafe_code)]
//! Monte-Carlo evaluation of Galadriel's Mirror across four regimes, comparing four
//! detectors: the cheap **NIS χ² baseline**, the **pure correlation default**
//! (NIS ⊕ `|ρ|`, no `pid-core`), the **cross-sensor PID engine** (KSG-MI), and the
//! **NIS ⊕ PID fusion**.
//!
//! All regimes run on the *same* corroborated sim (`rho > 0`) so every detector sees a
//! genuine consensus. Per trial we record, for each detector, a binary alarm and a
//! continuous score; across trials we report detection rate, false-alarm rate (on the
//! clean/null regime), and ROC-AUC (attack scores vs clean scores, via the Mann–Whitney
//! identity `AUC = P(score_attack > score_clean)`).
//!
//! The headline result is **complementarity**: the baseline catches the *magnitude*
//! attacks (a loud bias spoof and a jam) but is blind to a *moment-matched stealthy
//! spoof* whose NIS stays χ²(3) by construction; the cross-sensor detectors catch
//! exactly that stealthy spoof — and, correctly, stay quiet on the pure-magnitude
//! attacks, which preserve cross-channel correlation and are the baseline's job. The
//! **fused** detector covers the whole space.
//!
//! The second, methodological result: the **pure correlation default matches the PID
//! engine** on this (linear-Gaussian) stealthy spoof — the empirical statement of
//! `docs/JUSTIFICATION.md` that MI is *forced*, not justified, in this regime. The PID
//! engine earns its cost only on nonlinear or synergistic couplings, quantified
//! separately in the `galadriel-justify` crate.

use std::collections::HashMap;

use galadriel_core::{
    assess_default, CorrConfig, DetectorConfig, Mirror, Modality, PidObservation, Verdict,
};
use galadriel_pid::{analyze, assess_stream, scalar_channels, FusedVerdict, PidConfig, PidVerdict};
use galadriel_sim::injection::{inject, BroadbandJam, PhantomAcousticDoa};
use galadriel_sim::scenario::{generate, generate_spoofed, ScenarioConfig, StealthySpoof};

/// The sensor channels under test.
pub const MODALITIES: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

/// Evaluation parameters.
#[derive(Debug, Clone)]
pub struct EvalConfig {
    /// Trials per attack regime.
    pub trials: usize,
    /// First seed (trial `t` uses `base_seed + t`).
    pub base_seed: u64,
    /// Frames per trial.
    pub frames: usize,
    /// Cross-channel correlation of the corroborated regime.
    pub rho: f64,
    /// Nominal per-axis innovation std.
    pub sigma: f64,
    /// Loud bias-spoof magnitude (σ units).
    pub spoof_bias: f64,
    /// Broadband-jam innovation inflation (×).
    pub jam_inflation: f64,
}

impl Default for EvalConfig {
    fn default() -> Self {
        Self {
            trials: 200,
            base_seed: 1000,
            frames: 300,
            rho: 0.7,
            sigma: 1.0,
            spoof_bias: 8.0,
            jam_inflation: 3.0,
        }
    }
}

/// The four regimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attack {
    /// Corroborated, no attack (the negative class / false-alarm probe).
    Clean,
    /// A large constant bias on one channel — inflates NIS, preserves correlation.
    LoudSpoof,
    /// A moment-matched decoupling — NIS unchanged, correlation broken.
    Stealthy,
    /// Correlated all-channel innovation inflation.
    Jam,
}

impl Attack {
    /// All regimes.
    pub const ALL: [Attack; 4] = [
        Attack::Clean,
        Attack::LoudSpoof,
        Attack::Stealthy,
        Attack::Jam,
    ];

    /// A human label.
    pub fn label(self) -> &'static str {
        match self {
            Attack::Clean => "clean (null)",
            Attack::LoudSpoof => "loud bias spoof",
            Attack::Stealthy => "stealthy (moment-matched)",
            Attack::Jam => "broadband jam",
        }
    }
}

fn build(attack: Attack, cfg: &EvalConfig, seed: u64) -> Vec<PidObservation> {
    let s = ScenarioConfig {
        track_id: 1,
        frames: cfg.frames,
        modalities: MODALITIES.to_vec(),
        sigma: cfg.sigma,
        rho: cfg.rho,
        dt_ms: 100,
        seed,
    };
    let start = (cfg.frames as u64) / 3;
    match attack {
        Attack::Clean => generate(&s),
        Attack::LoudSpoof => {
            let mut v = generate(&s);
            inject(
                &mut v,
                &PhantomAcousticDoa {
                    target: Modality::Acoustic,
                    start_frame: start,
                    bias: cfg.spoof_bias,
                },
            );
            v
        }
        Attack::Stealthy => generate_spoofed(
            &s,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: start,
            },
        ),
        Attack::Jam => {
            let mut v = generate(&s);
            inject(
                &mut v,
                &BroadbandJam {
                    start_frame: start,
                    inflation: cfg.jam_inflation,
                },
            );
            v
        }
    }
}

/// Baseline: streaming NIS χ² Mirror. Alarm = `Spoof`/`Jam`; score = the strongest
/// per-channel NIS surprise `max_c -log10(p_right)`.
fn baseline_eval(stream: &[PidObservation]) -> (bool, f64) {
    let mut m = Mirror::new(DetectorConfig::default());
    for o in stream {
        m.ingest(o);
    }
    let last = stream.iter().map(|o| o.seq).max().unwrap_or(0);
    let rep = m.assess(1, last);
    let alarm = matches!(rep.verdict, Verdict::Spoof { .. } | Verdict::Jam);
    let score = rep
        .channels
        .iter()
        .filter(|c| c.ready)
        .map(|c| -(c.p_right + 1e-300).log10())
        .fold(0.0_f64, f64::max);
    (alarm, score)
}

/// Decoupling depth `1 − min/max corroboration` over a channel group's best-peer
/// corroborations — the score shared by the PID engine and the correlation default so
/// the two are **directly comparable** (the whole point of `docs/JUSTIFICATION.md`).
fn decoupling_depth(corrs: &[f64]) -> f64 {
    if corrs.len() < 2 {
        return 0.0;
    }
    let mx = corrs.iter().copied().fold(f64::MIN, f64::max);
    let mn = corrs.iter().copied().fold(f64::MAX, f64::min);
    if mx > 1e-9 {
        (1.0 - mn / mx).clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// PID: alarm = `Spoof`; score = decoupling depth over KSG-MI corroborations.
fn pid_eval(stream: &[PidObservation]) -> (bool, f64) {
    let rep = analyze(
        &scalar_channels(stream, &MODALITIES, 0),
        &PidConfig::default(),
    );
    let alarm = matches!(rep.verdict, PidVerdict::Spoof(_));
    let corrs: Vec<f64> = rep
        .channels
        .iter()
        .filter_map(|c| c.corroboration)
        .collect();
    (alarm, decoupling_depth(&corrs))
}

/// Correlation default: the **pure** NIS ⊕ correlation fused detector (no `pid-core`).
/// Alarm on a Spoof/Jam verdict; score = decoupling depth over `|ρ|` corroborations —
/// the same score as [`pid_eval`], so the cheap default and the MI engine are directly
/// comparable. Per `docs/JUSTIFICATION.md`, they should **match** on this linear-Gaussian
/// stealthy spoof, because `MI = −½ln(1−ρ²)` is monotone in `ρ`.
fn corr_eval(stream: &[PidObservation]) -> (bool, f64) {
    let rep = assess_default(
        stream,
        &MODALITIES,
        &DetectorConfig::default(),
        &CorrConfig::default(),
    );
    let alarm = matches!(rep.verdict, FusedVerdict::Spoof { .. } | FusedVerdict::Jam);
    let corrs: Vec<f64> = rep
        .correlation
        .channels
        .iter()
        .filter_map(|c| c.corroboration)
        .collect();
    (alarm, decoupling_depth(&corrs))
}

/// Fused detector: alarm on a `Spoof` or `Jam` fused verdict (NIS ⊕ PID escalation).
fn fused_eval(stream: &[PidObservation]) -> bool {
    let r = assess_stream(
        stream,
        &MODALITIES,
        &DetectorConfig::default(),
        &PidConfig::default(),
    );
    matches!(r.verdict, FusedVerdict::Spoof { .. } | FusedVerdict::Jam)
}

/// ROC-AUC via the Mann–Whitney identity (ties count 0.5).
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

/// Per-attack metrics for both detectors and their fusion.
#[derive(Debug, Clone)]
pub struct AttackMetrics {
    /// Which regime.
    pub attack: Attack,
    /// Baseline detection rate.
    pub baseline_rate: f64,
    /// Correlation-default (pure NIS ⊕ |ρ|) detection rate.
    pub corr_rate: f64,
    /// PID detection rate.
    pub pid_rate: f64,
    /// Fused (baseline ⊕ PID) detection rate.
    pub fused_rate: f64,
    /// Baseline ROC-AUC vs clean.
    pub baseline_auc: f64,
    /// Correlation-default ROC-AUC vs clean.
    pub corr_auc: f64,
    /// PID ROC-AUC vs clean.
    pub pid_auc: f64,
}

/// Full evaluation results.
#[derive(Debug, Clone)]
pub struct EvalResults {
    /// The config used.
    pub cfg: EvalConfig,
    /// Baseline false-alarm rate (on clean).
    pub baseline_far: f64,
    /// Correlation-default false-alarm rate (on clean).
    pub corr_far: f64,
    /// PID false-alarm rate (on clean).
    pub pid_far: f64,
    /// Fused false-alarm rate (on clean).
    pub fused_far: f64,
    /// Metrics for the three attack regimes.
    pub per_attack: Vec<AttackMetrics>,
}

/// Run the Monte-Carlo evaluation.
pub fn run(cfg: &EvalConfig) -> EvalResults {
    let mut b_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut c_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut p_scores: HashMap<Attack, Vec<f64>> = HashMap::new();
    let mut b_alarms: HashMap<Attack, usize> = HashMap::new();
    let mut c_alarms: HashMap<Attack, usize> = HashMap::new();
    let mut p_alarms: HashMap<Attack, usize> = HashMap::new();
    let mut f_alarms: HashMap<Attack, usize> = HashMap::new();

    for &attack in &Attack::ALL {
        let mut bs = Vec::with_capacity(cfg.trials);
        let mut cs = Vec::with_capacity(cfg.trials);
        let mut ps = Vec::with_capacity(cfg.trials);
        let (mut ba, mut ca, mut pa, mut fa) = (0usize, 0usize, 0usize, 0usize);
        for t in 0..cfg.trials {
            let stream = build(attack, cfg, cfg.base_seed + t as u64);
            let (b_al, b_sc) = baseline_eval(&stream);
            let (c_al, c_sc) = corr_eval(&stream);
            let (p_al, p_sc) = pid_eval(&stream);
            bs.push(b_sc);
            cs.push(c_sc);
            ps.push(p_sc);
            ba += usize::from(b_al);
            ca += usize::from(c_al);
            pa += usize::from(p_al);
            fa += usize::from(fused_eval(&stream));
        }
        b_scores.insert(attack, bs);
        c_scores.insert(attack, cs);
        p_scores.insert(attack, ps);
        b_alarms.insert(attack, ba);
        c_alarms.insert(attack, ca);
        p_alarms.insert(attack, pa);
        f_alarms.insert(attack, fa);
    }

    let n = cfg.trials as f64;
    let clean_b = &b_scores[&Attack::Clean];
    let clean_c = &c_scores[&Attack::Clean];
    let clean_p = &p_scores[&Attack::Clean];
    let per_attack = Attack::ALL
        .iter()
        .filter(|a| **a != Attack::Clean)
        .map(|&a| AttackMetrics {
            attack: a,
            baseline_rate: b_alarms[&a] as f64 / n,
            corr_rate: c_alarms[&a] as f64 / n,
            pid_rate: p_alarms[&a] as f64 / n,
            fused_rate: f_alarms[&a] as f64 / n,
            baseline_auc: auc(&b_scores[&a], clean_b),
            corr_auc: auc(&c_scores[&a], clean_c),
            pid_auc: auc(&p_scores[&a], clean_p),
        })
        .collect();

    EvalResults {
        baseline_far: b_alarms[&Attack::Clean] as f64 / n,
        corr_far: c_alarms[&Attack::Clean] as f64 / n,
        pid_far: p_alarms[&Attack::Clean] as f64 / n,
        fused_far: f_alarms[&Attack::Clean] as f64 / n,
        per_attack,
        cfg: cfg.clone(),
    }
}

/// Format results as a plain-text report (suitable for a docs code block).
pub fn format_report(r: &EvalResults) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Galadriel evaluation — {} trials/regime · rho={} · frames={} · sigma={}\n",
        r.cfg.trials, r.cfg.rho, r.cfg.frames, r.cfg.sigma
    ));
    s.push_str(&format!(
        "False-alarm rate (clean):   baseline {:.3}   corr {:.3}   PID {:.3}   fused {:.3}\n\n",
        r.baseline_far, r.corr_far, r.pid_far, r.fused_far
    ));
    s.push_str(&format!(
        "{:<28} | {:>8} | {:>8} | {:>7} | {:>9} | {:>8} | {:>8} | {:>7}\n",
        "regime", "base det", "corr det", "PID det", "fused det", "base AUC", "corr AUC", "PID AUC"
    ));
    s.push_str(&format!("{}\n", "-".repeat(104)));
    for m in &r.per_attack {
        s.push_str(&format!(
            "{:<28} | {:>8.3} | {:>8.3} | {:>7.3} | {:>9.3} | {:>8.3} | {:>8.3} | {:>7.3}\n",
            m.attack.label(),
            m.baseline_rate,
            m.corr_rate,
            m.pid_rate,
            m.fused_rate,
            m.baseline_auc,
            m.corr_auc,
            m.pid_auc,
        ));
    }
    s.push_str(
        "\ncorr = pure NIS⊕|rho| default (no pid-core); PID = KSG-MI escalation. They match on\n\
         the linear-Gaussian stealthy spoof — the empirical basis for docs/JUSTIFICATION.md.\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(r: &EvalResults, a: Attack) -> AttackMetrics {
        r.per_attack
            .iter()
            .find(|m| m.attack == a)
            .cloned()
            .unwrap()
    }

    #[test]
    fn hypothesis_holds() {
        // Smaller trial count keeps the test fast but statistically clear.
        let r = run(&EvalConfig {
            trials: 40,
            ..Default::default()
        });

        // Every detector is quiet on the null.
        assert!(r.baseline_far < 0.1, "baseline FAR {:.3}", r.baseline_far);
        assert!(r.corr_far < 0.1, "corr-default FAR {:.3}", r.corr_far);
        assert!(r.pid_far < 0.1, "PID FAR {:.3}", r.pid_far);
        assert!(r.fused_far < 0.1, "fused FAR {:.3}", r.fused_far);

        // The headline: the cross-sensor detectors catch the stealthy spoof the baseline
        // is blind to.
        let st = metrics(&r, Attack::Stealthy);
        assert!(
            st.pid_rate > 0.8,
            "PID stealthy detection {:.3}",
            st.pid_rate
        );
        assert!(
            st.baseline_rate < 0.2,
            "baseline stealthy detection {:.3}",
            st.baseline_rate
        );
        assert!(st.pid_auc > 0.85, "PID stealthy AUC {:.3}", st.pid_auc);
        assert!(
            st.baseline_auc < 0.75,
            "baseline stealthy AUC {:.3}",
            st.baseline_auc
        );

        // The JUSTIFICATION claim, empirically: on this linear-Gaussian stealthy spoof
        // the CHEAP correlation default matches the MI engine — PID is *forced*, not
        // justified, here. It should detect at least as reliably as PID does.
        assert!(
            st.corr_rate > 0.8,
            "corr-default stealthy detection {:.3}",
            st.corr_rate
        );
        assert!(
            st.corr_auc > 0.85,
            "corr-default stealthy AUC {:.3}",
            st.corr_auc
        );

        // Complementarity: the baseline owns the magnitude attacks.
        let loud = metrics(&r, Attack::LoudSpoof);
        let jam = metrics(&r, Attack::Jam);
        assert!(
            loud.baseline_rate > 0.8,
            "baseline loud {:.3}",
            loud.baseline_rate
        );
        assert!(
            jam.baseline_rate > 0.8,
            "baseline jam {:.3}",
            jam.baseline_rate
        );

        // The fused detector covers all three attacks.
        for a in [Attack::LoudSpoof, Attack::Stealthy, Attack::Jam] {
            assert!(
                metrics(&r, a).fused_rate > 0.8,
                "{a:?} fused {:.3}",
                metrics(&r, a).fused_rate
            );
        }
    }

    #[test]
    fn auc_basics() {
        assert!((auc(&[1.0, 2.0, 3.0], &[0.0, 0.5]) - 1.0).abs() < 1e-9);
        assert!((auc(&[0.0], &[0.0]) - 0.5).abs() < 1e-9);
    }
}
