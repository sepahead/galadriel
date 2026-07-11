#![forbid(unsafe_code)]
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
    .expect("valid benchmark scenario")
}

fn bench_detectors(c: &mut Criterion) {
    let s = stream(300);
    let channels = scalar_channels(&s, &MODS, 0).expect("valid benchmark channels");
    let last_seq = s.iter().map(|o| o.seq).max().unwrap_or(0);
    let mut g = c.benchmark_group("detectors");

    // The cheap magnitude yardstick.
    g.bench_function("baseline_nis_chi2", |b| {
        b.iter(|| {
            let mut m = Mirror::with_modalities(DetectorConfig::default(), &MODS)
                .expect("valid benchmark detector");
            for o in &s {
                m.ingest(o).expect("valid benchmark observation");
            }
            black_box(m.assess(1, last_seq).expect("valid benchmark assessment"))
        })
    });

    // The pure default: NIS ⊕ signed pairwise-ρ consistency (no pid-core).
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
        b.iter(|| black_box(analyze(&channels, &PidConfig::default())))
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

/// How the two consistency scores scale with the same analysis window `W`.
/// Benchmark output, rather than a hard-coded timing claim, is the source of truth.
fn bench_cost_vs_window(c: &mut Criterion) {
    let base = stream(600);
    let full = scalar_channels(&base, &MODS, 0).expect("valid benchmark channels");
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
        let pid_cfg = PidConfig {
            window: w,
            min_samples: (w / 2).max(PidConfig::default().geom_k + 1),
            // This benchmark isolates the KSG point-estimate scaling. Bootstrap
            // confirmation has its own bounded fit count and would make the small
            // windows invalid when n_boot exceeds the available samples.
            bootstrap: false,
            ..PidConfig::default()
        };
        g.bench_with_input(BenchmarkId::new("correlation", w), &w, |b, _| {
            b.iter(|| black_box(correlation::analyze(&chans, &corr_cfg)))
        });
        g.bench_with_input(BenchmarkId::new("pid_ksg", w), &w, |b, _| {
            b.iter(|| black_box(analyze(&chans, &pid_cfg)))
        });
    }
    g.finish();
}

/// Steady-state streaming cost after the NIS window is full. This catches an
/// accidental return to rescanning the whole retained window on every assessment.
fn bench_streaming_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_baseline_window");
    for &window_len in &[64usize, 4_096, 65_536] {
        let cfg = DetectorConfig {
            window_len,
            min_samples: window_len,
            max_tracks: 1,
            ..DetectorConfig::default()
        };
        let mut mirror = Mirror::with_modalities(cfg, &MODS).expect("valid streaming benchmark");
        for seq in 0..window_len as u64 {
            for modality in MODS {
                mirror
                    .ingest(&PidObservation::scalar(
                        1,
                        seq.saturating_mul(100),
                        seq,
                        modality,
                        3.0,
                        3,
                    ))
                    .expect("valid benchmark warmup");
            }
        }
        let mut seq = window_len as u64;
        group.bench_with_input(
            BenchmarkId::new("ingest_and_assess", window_len),
            &window_len,
            |b, _| {
                b.iter(|| {
                    for modality in MODS {
                        mirror
                            .ingest(&PidObservation::scalar(
                                1,
                                seq.saturating_mul(100),
                                seq,
                                modality,
                                3.0,
                                3,
                            ))
                            .expect("valid benchmark sample");
                    }
                    let report = mirror.assess(1, seq).expect("valid benchmark assessment");
                    seq += 1;
                    black_box(report)
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_detectors,
    bench_cost_vs_window,
    bench_streaming_baseline
);
criterion_main!(benches);
