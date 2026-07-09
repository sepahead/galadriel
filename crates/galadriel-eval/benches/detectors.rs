//! Throughput benchmarks — the **cost** companion to the accuracy (`EVALUATION.md` §2)
//! and latency (§2.1) studies. They price each detector on one representative workload
//! (a 300-frame, 3-channel stealthy-spoofed stream) so the "correlation by default, PID
//! on escalation" recommendation is grounded in cost, not just accuracy.
//!
//! Run with `cargo bench -p galadriel-eval`.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use galadriel_core::{
    assess_default, correlation, CorrConfig, DetectorConfig, Mirror, Modality, PidObservation,
};
use galadriel_pid::{analyze, assess_stream, scalar_channels, PidConfig};
use galadriel_sim::scenario::{generate_spoofed, ScenarioConfig, StealthySpoof};

const MODS: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

fn stream(frames: usize) -> Vec<PidObservation> {
    let cfg = ScenarioConfig {
        track_id: 1,
        frames,
        modalities: MODS.to_vec(),
        sigma: 1.0,
        rho: 0.7,
        dt_ms: 100,
        seed: 42,
    };
    generate_spoofed(
        &cfg,
        StealthySpoof {
            target: Modality::Acoustic,
            start_frame: (frames as u64) / 3,
        },
    )
}

fn bench_detectors(c: &mut Criterion) {
    let s = stream(300);
    let last_seq = s.iter().map(|o| o.seq).max().unwrap_or(0);
    let mut g = c.benchmark_group("detectors");

    // The cheap magnitude yardstick.
    g.bench_function("baseline_nis_chi2", |b| {
        b.iter(|| {
            let mut m = Mirror::new(DetectorConfig::default());
            for o in &s {
                m.ingest(o);
            }
            black_box(m.assess(1, last_seq))
        })
    });

    // The pure default: NIS ⊕ pairwise-|ρ| consistency (no pid-core).
    g.bench_function("correlation_default_fused", |b| {
        b.iter(|| {
            black_box(assess_default(
                &s,
                &MODS,
                &DetectorConfig::default(),
                &CorrConfig::default(),
            ))
        })
    });

    // The escalation: geometry-gated KSG mutual information.
    g.bench_function("pid_ksg_mi", |b| {
        b.iter(|| {
            black_box(analyze(
                &scalar_channels(&s, &MODS, 0),
                &PidConfig::default(),
            ))
        })
    });

    // The full NIS ⊕ PID fusion.
    g.bench_function("fused_nis_pid", |b| {
        b.iter(|| {
            black_box(assess_stream(
                &s,
                &MODS,
                &DetectorConfig::default(),
                &PidConfig::default(),
            ))
        })
    });

    g.finish();
}

/// How the two **consistency scores** scale with the analysis window `W` (this turns §5.3's
/// single-point ratio into a curve). `|ρ|` is linear in `W` and sub-µs; the KSG engine caps
/// its own window, so its cost is roughly constant (~2 ms) once its geometry gate passes
/// (W ≥ 64; below that the gate fails closed and it does no work). The isolated ratio is thus
/// ~10³ across the range, dominated by KSG's fixed k-NN cost rather than the window length.
fn bench_cost_vs_window(c: &mut Criterion) {
    let base = stream(600);
    let full = scalar_channels(&base, &MODS, 0);
    let mut g = c.benchmark_group("cost_vs_window");
    for &w in &[32usize, 64, 128, 256, 512] {
        // The like-for-like comparison: both consistency scores over the same W samples.
        let chans: Vec<(Modality, Vec<f64>)> = full
            .iter()
            .map(|(m, v)| (*m, v[v.len() - w..].to_vec()))
            .collect();
        let corr_cfg = CorrConfig {
            window: w,
            min_samples: (w / 2).max(2),
            ..CorrConfig::default()
        };
        g.bench_with_input(BenchmarkId::new("correlation", w), &w, |b, _| {
            b.iter(|| black_box(correlation::analyze(&chans, &corr_cfg)))
        });
        g.bench_with_input(BenchmarkId::new("pid_ksg", w), &w, |b, _| {
            b.iter(|| black_box(analyze(&chans, &PidConfig::default())))
        });
    }
    g.finish();
}

criterion_group!(benches, bench_detectors, bench_cost_vs_window);
criterion_main!(benches);
