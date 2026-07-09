//! The cross-sensor consistency engine.
//!
//! The corroboration score of a channel is its **best pairwise mutual information
//! with any other channel** (each pair gated by a geometry check). This is robust
//! with as few as three channels: two honest channels keep high MI *with each
//! other* no matter what a spoofed third channel does, so the spoofed channel
//! stands out as the one that shares information with *no one*. A leave-one-out
//! *mean* consensus, by contrast, is polluted by the very channel it is trying to
//! judge. The `I^sx` redundancy atom is reported alongside as the decomposition.

use galadriel_core::Modality;
use pid_core::{
    block_bootstrap_paired, distance_concentration_stats, intrinsic_dimension_levina_bickel,
    ksg_mi, pid2_isx, BootstrapConfig, DistanceConcentrationConfig, IntrinsicDimConfig, Jitter,
    KsgConfig, MatOwned, Metric, Pid2Config, PidResult,
};

/// Engine tunables.
#[derive(Debug, Clone)]
pub struct PidConfig {
    /// Window length (frames) analysed, taken from each channel's tail.
    pub window: usize,
    /// Minimum aligned samples per channel before a verdict is trusted.
    pub min_samples: usize,
    /// Seeded jitter magnitude — breaks kNN-radius ties on quantised/duplicate rows.
    pub jitter_std: f64,
    /// Jitter/estimator seed for reproducibility.
    pub seed: u64,
    /// k for the Levina–Bickel intrinsic-dimension estimator (needs `k >= 3`).
    pub geom_k: usize,
    /// Geometry gate: reject (fail closed) if intrinsic dimension exceeds this.
    pub id_max: f64,
    /// Geometry gate: reject if the pairwise-distance coefficient of variation is below this.
    pub cv_min: f64,
    /// Geometry gate: reject if mean-nn / mean-pairwise distance exceeds this (concentration).
    pub nn_ratio_max: f64,
    /// A channel is flagged decoupled if its corroboration falls below
    /// `decouple_ratio × the strongest corroboration in the group`.
    pub decouple_ratio: f64,
    /// …and only when that strongest corroboration itself clears this floor (nats) —
    /// i.e. there is a genuine consensus to have decoupled *from*.
    pub mi_floor: f64,
    /// When true, confirm each candidate decoupling with a block-bootstrap CI on its
    /// best-pair MI and flag it only if the CI's upper bound stays below the decouple
    /// threshold — a fail-closed guard against estimator-artifact false positives. Off
    /// by default (bootstrap is ~`n_boot`× the cost of a point estimate).
    pub bootstrap: bool,
    /// Bootstrap resamples (when `bootstrap`).
    pub n_boot: usize,
    /// Moving-block length for the bootstrap (handles innovation autocorrelation).
    pub block_size: usize,
}

impl Default for PidConfig {
    fn default() -> Self {
        Self {
            window: 128,
            min_samples: 64,
            jitter_std: 1e-4,
            seed: 1,
            geom_k: 5,
            id_max: 10.0,
            cv_min: 0.01,
            nn_ratio_max: 0.999,
            decouple_ratio: 0.4,
            mi_floor: 0.03,
            bootstrap: false,
            n_boot: 200,
            block_size: 8,
        }
    }
}

/// Per-channel analysis detail.
#[derive(Debug, Clone)]
pub struct ChannelPid {
    /// Which modality.
    pub modality: Modality,
    /// Aligned samples used.
    pub n: usize,
    /// Whether at least one gated pair was assessable for this channel.
    pub gate_ok: bool,
    /// Human-readable gate note.
    pub gate_note: String,
    /// Corroboration score (nats): the channel's best gated pairwise MI with another channel.
    pub corroboration: Option<f64>,
    /// `I^sx` redundancy atom (nats): info this channel shares about the rest.
    pub redundancy: Option<f64>,
    /// Whether this channel was flagged as decoupled from the group.
    pub decoupled: bool,
    /// Block-bootstrap CI (nats) on this channel's best-pair MI, set when a decoupling
    /// candidate was bootstrap-checked (`None` otherwise).
    pub ci: Option<(f64, f64)>,
}

/// The engine's advisory verdict. Unlike the baseline it does **not** emit `Jam`:
/// a uniform magnitude inflation preserves cross-channel agreement, so it is the
/// baseline's job; this engine detects *decoupling* (stealthy spoofing).
#[derive(Debug, Clone, PartialEq)]
pub enum PidVerdict {
    /// All ready channels still corroborate one another.
    Nominal,
    /// One or a minority of channels decoupled from the group.
    Spoof(Vec<Modality>),
    /// Too few assessable channels / no coherent consensus. Fail closed.
    InsufficientEvidence,
}

/// The full report.
#[derive(Debug, Clone)]
pub struct PidReport {
    /// Per-channel detail, in input order.
    pub channels: Vec<ChannelPid>,
    /// The advisory verdict.
    pub verdict: PidVerdict,
    /// Rationale.
    pub note: String,
}

/// Analyse aligned per-channel signed-scalar series for cross-sensor decoupling.
///
/// Each entry is `(modality, series)`; series may differ in length (the tail
/// `window` is taken and aligned). Requires ≥ 3 channels.
pub fn analyze(channels: &[(Modality, Vec<f64>)], cfg: &PidConfig) -> PidReport {
    let c = channels.len();
    let w = channels
        .iter()
        .map(|(_, v)| v.len())
        .min()
        .unwrap_or(0)
        .min(cfg.window);

    if c < 3 || w < cfg.min_samples {
        return PidReport {
            channels: Vec::new(),
            verdict: PidVerdict::InsufficientEvidence,
            note: format!(
                "need ≥3 channels and ≥{} aligned samples (have {c} channels, w={w})",
                cfg.min_samples
            ),
        };
    }

    // Align on the tail so every channel covers the same recent frames.
    let cols: Vec<Vec<f64>> = channels
        .iter()
        .map(|(_, v)| v[v.len() - w..].to_vec())
        .collect();

    let jitter = match Jitter::new(cfg.jitter_std, cfg.seed) {
        Ok(j) => j,
        Err(e) => {
            return PidReport {
                channels: Vec::new(),
                verdict: PidVerdict::InsufficientEvidence,
                note: format!("jitter init failed: {e}"),
            }
        }
    };

    // Gated pairwise MI matrix (symmetric; `None` where the pair failed the gate).
    let mut mi = vec![vec![None::<f64>; c]; c];
    for i in 0..c {
        for j in (i + 1)..c {
            let m = pair_mi(&jitter, cfg, &cols[i], &cols[j]);
            mi[i][j] = m;
            mi[j][i] = m;
        }
    }

    let mut reports: Vec<ChannelPid> = Vec::with_capacity(c);
    for (i, (modality, _)) in channels.iter().enumerate() {
        let peers: Vec<f64> = (0..c)
            .filter(|&j| j != i)
            .filter_map(|j| mi[i][j])
            .collect();
        let corroboration = peers.iter().copied().reduce(f64::max);
        let gate_ok = !peers.is_empty();
        reports.push(ChannelPid {
            modality: *modality,
            n: w,
            gate_ok,
            gate_note: if gate_ok {
                "go".into()
            } else {
                "no gated pair".into()
            },
            corroboration,
            redundancy: redundancy_atom(&jitter, cfg, &cols, i, c, w),
            decoupled: false,
            ci: None,
        });
    }

    let ready: Vec<usize> = reports
        .iter()
        .enumerate()
        .filter(|(_, r)| r.corroboration.is_some())
        .map(|(i, _)| i)
        .collect();

    if ready.len() < 2 {
        return PidReport {
            verdict: PidVerdict::InsufficientEvidence,
            note: format!("only {} channel(s) had a gated pair", ready.len()),
            channels: reports,
        };
    }

    // Strongest corroboration in the group is the reference "there is a consensus".
    let reference = ready
        .iter()
        .map(|&i| reports[i].corroboration.unwrap())
        .fold(f64::MIN, f64::max);

    if reference < cfg.mi_floor {
        return PidReport {
            verdict: PidVerdict::InsufficientEvidence,
            note: format!(
                "no coherent consensus (strongest pairwise MI {reference:.3} < floor {:.3})",
                cfg.mi_floor
            ),
            channels: reports,
        };
    }

    let threshold = cfg.decouple_ratio * reference;
    let mut decoupled: Vec<Modality> = Vec::new();
    for &i in &ready {
        if reports[i].corroboration.unwrap() >= threshold {
            continue; // corroborates — not a candidate
        }
        if cfg.bootstrap {
            // Confirm the decoupling is significant: bootstrap the channel's best-pair MI
            // and confirm only if even its upper CI bound stays below the *decouple
            // threshold* (`decouple_ratio × reference`) — i.e. it confidently sits below
            // the decouple line, not merely below the group leader. This is strictly
            // stronger than the point gate, so the confirmed set is a fail-closed subset.
            if let Some(peer) = best_peer(&mi, i, c) {
                let point = reports[i].corroboration.unwrap();
                let (lo, hi) = bootstrap_mi_ci(cfg, &cols[i], &cols[peer], point);
                reports[i].ci = Some((lo, hi));
                if hi < threshold {
                    reports[i].decoupled = true;
                    decoupled.push(reports[i].modality);
                }
                // else: candidate not confirmed — fail closed, do not accuse.
            }
        } else {
            reports[i].decoupled = true;
            decoupled.push(reports[i].modality);
        }
    }

    let (verdict, note) = if decoupled.is_empty() {
        (
            PidVerdict::Nominal,
            format!(
                "{} channels corroborate (strongest pairwise MI {reference:.3} nats)",
                ready.len()
            ),
        )
    } else {
        let names: Vec<&str> = decoupled.iter().map(|m| m.label()).collect();
        (
            PidVerdict::Spoof(decoupled.clone()),
            format!(
                "{} of {} channels decoupled from the group: {}",
                decoupled.len(),
                ready.len(),
                names.join(", ")
            ),
        )
    };

    PidReport {
        channels: reports,
        verdict,
        note,
    }
}

/// The peer index giving channel `i` its best gated MI (its corroboration partner).
fn best_peer(mi: &[Vec<Option<f64>>], i: usize, c: usize) -> Option<usize> {
    (0..c)
        .filter(|&j| j != i && mi[i][j].is_some())
        .max_by(|&x, &y| mi[i][x].unwrap().total_cmp(&mi[i][y].unwrap()))
}

/// Block-bootstrap CI (`alpha = 0.10`) on the MI between two channels. Each resample
/// is jittered to break kNN-radius ties from repeated blocks; a failed resample falls
/// back to `point_mi` (neutral) so estimation hiccups cannot bias the CI toward a
/// false accusation.
fn bootstrap_mi_ci(cfg: &PidConfig, a: &[f64], b: &[f64], point_mi: f64) -> (f64, f64) {
    let bcfg = BootstrapConfig {
        n_boot: cfg.n_boot,
        block_size: cfg.block_size.max(1),
        seed: cfg.seed,
        alpha: 0.10,
    };
    let jit = match Jitter::new(cfg.jitter_std.max(1e-9), cfg.seed) {
        Ok(j) => j,
        Err(_) => return (point_mi, point_mi),
    };
    let stat = move |rx: &[f64], ry: &[f64]| -> f64 {
        let jx = MatOwned::new(rx.to_vec(), rx.len(), 1).and_then(|m| jit.apply(m.as_ref()));
        let jy = MatOwned::new(ry.to_vec(), ry.len(), 1).and_then(|m| jit.apply(m.as_ref()));
        match (jx, jy) {
            (Ok(x), Ok(y)) => {
                ksg_mi(x.as_ref(), y.as_ref(), &KsgConfig::default()).unwrap_or(point_mi)
            }
            _ => point_mi,
        }
    };
    let res = block_bootstrap_paired(a, b, &bcfg, stat);
    (res.ci_low, res.ci_high)
}

/// Geometry-gated pairwise KSG mutual information; `None` if the pair is not
/// safely assessable (fail closed).
fn pair_mi(j: &Jitter, cfg: &PidConfig, a: &[f64], b: &[f64]) -> Option<f64> {
    let x = jmat2(j, a, b).ok()?;
    let id = intrinsic_dimension_levina_bickel(
        x.as_ref(),
        &IntrinsicDimConfig {
            k: cfg.geom_k,
            metric: Metric::Chebyshev,
        },
    )
    .ok()?;
    if id > cfg.id_max {
        return None;
    }
    let dc = distance_concentration_stats(
        x.as_ref(),
        &DistanceConcentrationConfig {
            metric: Metric::Chebyshev,
        },
    )
    .ok()?;
    if dc.pairwise_cv < cfg.cv_min || dc.nn_over_pairwise_mean > cfg.nn_ratio_max {
        return None;
    }
    let sa = jcol(j, a).ok()?;
    let sb = jcol(j, b).ok()?;
    ksg_mi(sa.as_ref(), sb.as_ref(), &KsgConfig::default()).ok()
}

/// `I^sx` redundancy atom for channel `i`: info that `i` and one peer share about
/// the consensus of the remaining channels. `s1 = i`, `s2 = first other`,
/// `t = mean of the rest`.
fn redundancy_atom(
    j: &Jitter,
    _cfg: &PidConfig,
    cols: &[Vec<f64>],
    i: usize,
    c: usize,
    w: usize,
) -> Option<f64> {
    let others: Vec<usize> = (0..c).filter(|&x| x != i).collect();
    if others.len() < 2 {
        return None;
    }
    let s1 = jcol(j, &cols[i]).ok()?;
    let s2 = jcol(j, &cols[others[0]]).ok()?;
    let t_raw = consensus(cols, &others[1..], w);
    let t = jcol(j, &t_raw).ok()?;
    pid2_isx(s1.as_ref(), s2.as_ref(), t.as_ref(), &Pid2Config::default())
        .ok()
        .map(|p| p.redundancy)
}

/// Per-frame mean of the given channel columns.
fn consensus(cols: &[Vec<f64>], idxs: &[usize], w: usize) -> Vec<f64> {
    if idxs.is_empty() {
        return vec![0.0; w];
    }
    (0..w)
        .map(|f| idxs.iter().map(|&i| cols[i][f]).sum::<f64>() / idxs.len() as f64)
        .collect()
}

/// A jittered `w × 1` column.
fn jcol(j: &Jitter, data: &[f64]) -> PidResult<MatOwned> {
    let m = MatOwned::new(data.to_vec(), data.len(), 1)?;
    j.apply(m.as_ref())
}

/// A jittered `w × 2` matrix from two aligned columns (row-major).
fn jmat2(j: &Jitter, a: &[f64], b: &[f64]) -> PidResult<MatOwned> {
    let n = a.len();
    let mut flat = Vec::with_capacity(n * 2);
    for i in 0..n {
        flat.push(a[i]);
        flat.push(b[i]);
    }
    let m = MatOwned::new(flat, n, 2)?;
    j.apply(m.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar_channels;
    use galadriel_sim::scenario::{generate, generate_spoofed, ScenarioConfig, StealthySpoof};

    fn scen(seed: u64) -> ScenarioConfig {
        ScenarioConfig {
            frames: 400,
            rho: 0.7,
            seed,
            ..Default::default()
        }
    }

    #[test]
    fn clean_corroborated_stream_is_nominal() {
        // Robust across several seeds.
        for seed in [7, 11, 23, 42] {
            let s = generate(&scen(seed));
            let chans = scalar_channels(&s, &scen(seed).modalities, 0);
            let rep = analyze(&chans, &PidConfig::default());
            assert_eq!(
                rep.verdict,
                PidVerdict::Nominal,
                "seed {seed}: {}",
                rep.note
            );
        }
    }

    #[test]
    fn stealthy_spoof_missed_by_baseline_is_caught_by_pid() {
        for seed in [7, 11, 23, 42] {
            let cfg = scen(seed);
            let s = generate_spoofed(
                &cfg,
                StealthySpoof {
                    target: Modality::Acoustic,
                    start_frame: cfg.frames as u64 / 3,
                },
            );
            let chans = scalar_channels(&s, &cfg.modalities, 0);
            let rep = analyze(&chans, &PidConfig::default());
            match rep.verdict {
                PidVerdict::Spoof(ref v) => {
                    assert!(
                        v.contains(&Modality::Acoustic),
                        "seed {seed}: flagged {v:?}"
                    )
                }
                other => panic!(
                    "seed {seed}: expected Spoof(acoustic), got {other:?}: {}",
                    rep.note
                ),
            }
        }
    }

    #[test]
    fn bootstrap_never_flags_a_clean_stream() {
        // With bootstrap on, a clean corroborated stream is never accused.
        let cfg = PidConfig {
            bootstrap: true,
            n_boot: 120,
            ..Default::default()
        };
        for seed in [7, 11, 23] {
            let s = generate(&scen(seed));
            let rep = analyze(&scalar_channels(&s, &scen(seed).modalities, 0), &cfg);
            assert_eq!(
                rep.verdict,
                PidVerdict::Nominal,
                "seed {seed}: {}",
                rep.note
            );
        }
    }

    #[test]
    fn bootstrap_is_a_fail_closed_subset_of_point_estimates() {
        // Bootstrap confirmation can only REMOVE candidates, never add: the confirmed
        // decoupled set is a subset of the point-estimate set, and every confirmed
        // channel carries the CI it was judged on. (At W=128 the near-zero MI of a
        // decoupled channel has a CI too wide to confirm — an honest estimator limit,
        // which is exactly why this stricter mode fails *closed*.)
        use std::collections::HashSet;
        let sc = scen(7);
        let s = generate_spoofed(
            &sc,
            StealthySpoof {
                target: Modality::Acoustic,
                start_frame: sc.frames as u64 / 3,
            },
        );
        let chans = scalar_channels(&s, &sc.modalities, 0);
        let point = analyze(&chans, &PidConfig::default());
        let boot = analyze(
            &chans,
            &PidConfig {
                bootstrap: true,
                n_boot: 120,
                ..Default::default()
            },
        );

        let point_flagged: HashSet<Modality> = point
            .channels
            .iter()
            .filter(|c| c.decoupled)
            .map(|c| c.modality)
            .collect();
        for c in boot.channels.iter().filter(|c| c.decoupled) {
            assert!(
                point_flagged.contains(&c.modality),
                "bootstrap flagged a non-candidate"
            );
            assert!(c.ci.is_some(), "confirmed channel missing its CI");
        }
    }
}
