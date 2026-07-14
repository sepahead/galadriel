# galadriel-core

The safe-Rust core of Galadriel's Mirror, an experimental cross-sensor
consistency monitor for multi-sensor fusion.

It provides:

- validated `PidObservation` / `Modality` types, including an optional bounded
  `ConsistencyProjection` with frame/context/frozen-prior provenance;
- bounded per-track, per-modality NIS windows;
- chi-square distribution functions backed by `statrs`;
- windowed-NIS magnitude evidence with per-assessment family-wise control,
  plus historical CUSUM evidence without a calibrated p-value;
- signed Pearson correlation with a unique strict-majority positive-consensus
  clique;
- fail-closed fusion that preserves `InsufficientEvidence` and
  `UnclassifiedAnomaly` rather than fabricating `Nominal`;
- sealed whole-stream reports bound canonically to the complete release suite and
  every exact ordered observation field.

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

`Mirror` is the magnitude component, so a magnitude-only nominal result remains
an unavailable typed `AssessmentOutcome` until the signed-consistency prerequisite
has run. Use `assess_default` for a sealed accepted default report. Its opaque
`AssessmentBinding` can be compared or verified against the exact stream and
suite, but cannot be fabricated or attached to replacement component reports.

Invalid input/configuration returns `Err(...)`. Missing, stale, or insufficient
evidence returns `InsufficientEvidence`. Cross-channel analysis consumes only the
producer-attested common projection, evaluates every active axis with a shared
multiple-testing budget, and never falls back to native innovations. Direct
extraction scans at most 400,000 observations and retains at most 65,536 frames.

This crate is a pre-1.0 research component, uses workspace MSRV Rust 1.89, and
sets `publish = false`. It is not a field-validated safety or enforcement layer.
Licensed under MIT OR Apache-2.0.
