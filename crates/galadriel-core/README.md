# galadriel-core

The safe-Rust core of Galadriel's Mirror, an experimental cross-sensor
consistency monitor for multi-sensor fusion.

It provides:

- validated `PidObservation` / `Modality` types, including an optional bounded
  `ConsistencyProjection` with frame/context/frozen-prior provenance;
- bounded per-track, per-modality NIS windows;
- chi-square distribution functions backed by `statrs`;
- NIS/CUSUM magnitude evidence with per-assessment family-wise control;
- signed Pearson correlation with a unique strict-majority positive-consensus
  clique;
- fail-closed fusion that preserves `InsufficientEvidence` and
  `UnclassifiedAnomaly` rather than fabricating `Nominal`.

```rust
use galadriel_core::{DetectorConfig, Mirror, Modality, PidObservation};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut mirror = Mirror::new(DetectorConfig::default())?;
mirror.ingest(&PidObservation::scalar(1, 0, 0, Modality::Radar, 3.1, 3))?;
let report = mirror.assess(1, 0)?;
println!("{:?}", report.verdict);
# Ok(())
# }
```

Invalid input/configuration returns `Err(...)`. Missing, stale, or insufficient
evidence returns `InsufficientEvidence`. Cross-channel analysis consumes only the
producer-attested common projection, evaluates every active axis with a shared
multiple-testing budget, and never falls back to native innovations. Direct
extraction scans at most 400,000 observations and retains at most 65,536 frames.

This crate is a pre-1.0 research component, uses workspace MSRV Rust 1.89, and
sets `publish = false`. It is not a field-validated safety or enforcement layer.
Licensed under MIT OR Apache-2.0.
