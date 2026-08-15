#![forbid(unsafe_code)]
//! Throughput benchmarks — the **cost** companion to the accuracy (`EVALUATION.md` §2)
//! and latency (§2.1) studies. They price each detector on one representative workload
//! (a 300-frame, 3-channel fixed-law stealthy-spoofed stream) so the cost comparison
//! does not submit a change point under an i.i.d. declaration.
//!
//! Run with `cargo bench -p galadriel-eval`.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use galadriel_core::{
    assess_default, correlation, AssessmentScope, CorrConfig, CorrParams, DetectorConfig,
    DetectorParams, Mirror, Modality, PidObservation, ProducerAxisFamilyPolicy, ReleaseSuite,
    ReleaseSuiteParams, Sequence, TrackId,
};
use galadriel_dependence::{
    analyze, assess_with_dependence, scalar_channels, ContinuousLawDeclaration, DeclaredMiInput,
    DependenceResearchSuite, MiConsensusConfig, MiConsensusResearchProfile,
};
use galadriel_sim::scenario::{generate_spoofed, ScenarioConfig, ScenarioParams, StealthySpoof};

const MODS: [Modality; 3] = [Modality::Visual, Modality::Radar, Modality::Acoustic];

fn law() -> ContinuousLawDeclaration {
    ContinuousLawDeclaration::try_iid(
        "The benchmark simulator declares nonsingular jointly Gaussian bivariate populations with finite mutual information.",
        "Binary64 sample representation of pseudorandom draws intended from the declared continuous law; no deliberate quantization, added noise, or tie-breaking transform; exact ties abstain.",
        "Rows are independent within one fixed-parameter synthetic benchmark episode.",
        "All benchmark projection coordinates use the same fixed simulator innovation unit and identity gauge; no sample-fitted rescaling is applied.",
    )
    .expect("benchmark continuous-law declaration is valid")
}

fn stream(frames: usize) -> (AssessmentScope, Vec<PidObservation>) {
    let cfg = ScenarioConfig::try_new(ScenarioParams {
        track_id: 1,
        frames,
        modalities: MODS.to_vec(),
        sigma: 1.0,
        rho: 0.7,
        dt_ms: 100,
        seed: 42,
    })
    .expect("benchmark scenario configuration must be valid");
    let scope = cfg
        .assessment_scope("benchmark-detectors")
        .expect("benchmark assessment scope must be valid");
    let stream = generate_spoofed(
        &cfg,
        StealthySpoof {
            target: Modality::Acoustic,
            start_frame: 0,
        },
    )
    .expect("valid benchmark scenario");
    (scope, stream)
}

fn bench_detectors(c: &mut Criterion) {
    let (scope, s) = stream(300);
    let channels = scalar_channels(&s, &MODS, 0).expect("valid benchmark channels");
    let mi_input = DeclaredMiInput::try_new(channels.clone(), "benchmark-detectors")
        .expect("valid benchmark MI input");
    let track_id = s.first().expect("benchmark stream is non-empty").track_id();
    let last_seq = s
        .iter()
        .map(PidObservation::sequence)
        .max()
        .expect("benchmark stream is non-empty");
    let mi_config = MiConsensusResearchProfile::ExhaustiveCircularDeleteBlockV0_9
        .try_config(law())
        .expect("0.9 circular delete-block MI profile is valid");
    let mi_suite = DependenceResearchSuite::exhaustive_circular_delete_block_v0_9(&MODS, law())
        .expect("0.9 circular delete-block MI suite is valid");
    let release_suite = ReleaseSuite::standalone_advisory_v0_9(&MODS)
        .expect("standalone-advisory benchmark suite is valid");
    let mut g = c.benchmark_group("detectors");

    // The cheap magnitude yardstick.
    g.bench_function("baseline_nis_chi2", |b| {
        b.iter(|| {
            let mut m = Mirror::from_release_suite(&release_suite);
            for o in &s {
                m.ingest(o).expect("valid benchmark observation");
            }
            black_box(
                m.assess(track_id, last_seq)
                    .expect("valid benchmark assessment"),
            )
        })
    });

    // The pure default: NIS ⊕ signed pairwise-ρ consistency (no pid-core).
    g.bench_function("correlation_default_fused", |b| {
        b.iter(|| black_box(assess_default(&scope, &s, &release_suite)))
    });

    // The escalation: geometry-gated KSG mutual information.
    g.bench_function("mi_ksg_mi", |b| {
        b.iter(|| black_box(analyze(&mi_input, &mi_config)))
    });

    // The unchanged default plus the non-authoritative MI companion.
    g.bench_function("default_with_mi_companion", |b| {
        b.iter(|| black_box(assess_with_dependence(&scope, &s, &mi_suite)))
    });

    g.finish();
}

/// How the two consistency scores scale with the same analysis window `W`.
/// Benchmark output, rather than a hard-coded timing claim, is the source of truth.
fn bench_cost_vs_window(c: &mut Criterion) {
    let (_, base) = stream(600);
    let full = scalar_channels(&base, &MODS, 0).expect("valid benchmark channels");
    let mut g = c.benchmark_group("cost_vs_window");
    for &w in &[32usize, 64, 128, 256, 512] {
        // The same row count and W samples for two distinct estimands; timings
        // compare implementation cost, not scientific interchangeability.
        let chans: Vec<(Modality, Vec<f64>)> = full
            .iter()
            .map(|(m, v)| (*m, v[v.len() - w..].to_vec()))
            .collect();
        let corr_cfg = CorrConfig::try_new(CorrParams {
            window: w,
            min_samples: (w / 2).max(2),
            ..CorrParams::standalone_advisory_v0_9()
        })
        .expect("correlation scaling benchmark config is valid");
        let mut mi_params = MiConsensusResearchProfile::PointEstimateOnlyV0_9.params();
        mi_params.window = w;
        mi_params.min_samples = (w / 2).max(mi_params.geom_k + 1);
        // This benchmark isolates KSG point-estimate scaling. Exhaustive circular
        // delete-block stability has its own bounded fit count and row requirements.
        let mi_cfg = MiConsensusConfig::try_new(mi_params, law())
            .expect("point-estimate MI scaling benchmark config is valid");
        let mi_input = DeclaredMiInput::try_new(chans.clone(), format!("benchmark-window-{w}"))
            .expect("valid scaling benchmark MI input");
        g.bench_with_input(BenchmarkId::new("correlation", w), &w, |b, _| {
            b.iter(|| black_box(correlation::analyze(&chans, &corr_cfg)))
        });
        g.bench_with_input(BenchmarkId::new("mi_ksg", w), &w, |b, _| {
            b.iter(|| black_box(analyze(&mi_input, &mi_cfg)))
        });
    }
    g.finish();
}

/// Steady-state streaming cost after the NIS window is full. This catches an
/// accidental return to rescanning the whole retained window on every assessment.
fn bench_streaming_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_baseline_window");
    for &window_len in &[64usize, 4_096, 65_536] {
        let cfg = DetectorConfig::try_new(DetectorParams {
            window_len,
            min_samples: window_len,
            max_tracks: 1,
            ..DetectorParams::standalone_advisory_v0_9()
        })
        .expect("streaming benchmark config is valid");
        let track_id = TrackId::new(1).expect("benchmark track identity is valid");
        let suite = ReleaseSuite::try_new(ReleaseSuiteParams {
            detector: cfg,
            correlation: CorrConfig::standalone_advisory_v0_9()
                .expect("benchmark correlation profile is valid"),
            expected_modalities: MODS.to_vec(),
            axis_policy: ProducerAxisFamilyPolicy::AttestedCommonProjectionBonferroniV1,
        })
        .expect("custom streaming benchmark suite is valid");
        let mut mirror = Mirror::from_release_suite(&suite);
        for seq in 0..window_len as u64 {
            for modality in MODS {
                mirror
                    .ingest(
                        &PidObservation::try_scalar_raw(
                            1,
                            seq.saturating_mul(100),
                            seq,
                            modality,
                            3.0,
                            3,
                        )
                        .expect("benchmark warmup coordinates are valid"),
                    )
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
                            .ingest(
                                &PidObservation::try_scalar_raw(
                                    1,
                                    seq.saturating_mul(100),
                                    seq,
                                    modality,
                                    3.0,
                                    3,
                                )
                                .expect("benchmark sample coordinates are valid"),
                            )
                            .expect("valid benchmark sample");
                    }
                    let assessment_sequence =
                        Sequence::new(seq).expect("benchmark sequence is valid");
                    let report = mirror
                        .assess(track_id, assessment_sequence)
                        .expect("valid benchmark assessment");
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
