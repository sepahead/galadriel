# galadriel-core

This crate is the safe-Rust core of Galadriel's Mirror.
Galadriel's Mirror is an experimental cross-sensor consistency monitor for multi-sensor fusion.

It supplies these functions:

- It validates `PidObservation` and `Modality` types.
- It supports an optional bounded `ConsistencyProjection` with frame, context, and frozen-prior provenance.
- It keeps bounded NIS windows for each track and modality.
- It supplies chi-square distribution functions through `statrs`.
- It supplies windowed-NIS magnitude evidence with per-assessment family-wise control.
- It supplies historical CUSUM evidence without a calibrated p-value.
- It calculates signed Pearson correlation with one unique strict-majority positive-consensus clique.
- Its fail-closed fusion preserves `InsufficientEvidence` and `UnclassifiedAnomaly`.
- It does not fabricate `Nominal`.
- It seals whole-stream reports and binds them canonically to the complete release suite.
- It also binds each report to every exact ordered observation field.

```rust
use galadriel_core::{
    Mirror, Modality, PidObservation, ReleaseSuite, Sequence, TimestampMillis, TrackId,
};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let modalities = [Modality::Visual, Modality::Radar];
let suite = ReleaseSuite::standalone_advisory_v0_9(&modalities)?;
let mut mirror = Mirror::from_release_suite(&suite);
let track = TrackId::new(1)?;
let timestamp = TimestampMillis::new(0)?;
let sequence = Sequence::new(0)?;
for modality in modalities {
    mirror.ingest(&PidObservation::try_scalar(
        track, timestamp, sequence, modality, 3.1, 3,
    )?)?;
}
let report = mirror.assess(track, sequence)?;
println!("{:?} ({})", report.verdict(), report.config_identity());
# Ok(())
# }
```

`Mirror` is the magnitude component.
A magnitude-only nominal result remains an unavailable typed `AssessmentOutcome`.
It remains unavailable until the signed-consistency prerequisite runs.
Use `assess_default` for a sealed accepted default report.
You can compare its opaque `AssessmentBinding` with the exact stream and suite.
You can also verify it against the exact stream and suite.

You cannot fabricate it or attach it to replacement component reports.

Invalid input or configuration returns `Err(...)`.
Missing, stale, or insufficient evidence returns `InsufficientEvidence`.
Cross-channel analysis consumes only the producer-attested common projection.
It evaluates every active axis with a shared multiple-testing budget.
It never falls back to native innovations.

Direct extraction scans at most 400,000 observations.
It retains at most 65,536 frames.

This crate is a pre-1.0 research component.
It uses workspace MSRV Rust 1.89 and sets `publish = false`.
It is not a field-validated safety or enforcement layer.
Licensed under MIT OR Apache-2.0.
