//! Throughput benchmarks — the **cost** companion to the accuracy (`EVALUATION.md` §2)
//! and latency (§2.1) studies. They price each detector on one representative workload
//! (a 300-frame, 3-channel stealthy-spoofed stream) so the "correlation by default, PID
//! on escalation" recommendation is grounded in cost, not just accuracy.
//!
//! Run with `cargo bench -p galadriel-eval`.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use galadriel_core::{
    assess_default, CorrConfig, DetectorConfig, Mirror, Modality, PidObservation,
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

criterion_group!(benches, bench_detectors);
criterion_main!(benches);
