# galadriel-core

The pure, dependency-light core of **Galadriel's Mirror** — a cross-sensor
consistency monitor for multi-sensor fusion.

It ships the **cheap baseline** the heavier information-theoretic engine must beat
before it is trusted:

- `PidObservation` / `Modality` — the wire types (byte-compatible with crebain's
  `SensorModality`).
- `NisWindow` — a fixed-capacity sliding window of NIS samples per channel.
- `chi2` — a dependency-free χ² implementation (`ln_gamma`, regularized incomplete
  gamma, CDF / survival).
- `baseline` — the windowed **NIS χ² consistency test** (right-tail p-value of the
  window sum under `χ²(n·dof)`).
- `cusum` — a two-sided CUSUM change detector on the NIS stream.
- `decision` — the fail-closed **jam-vs-spoof** verdict and the streaming `Mirror`.

```rust
use galadriel_core::{DetectorConfig, Mirror, Modality, PidObservation};

let mut mirror = Mirror::new(DetectorConfig::default());
mirror.ingest(&PidObservation::scalar(1, 0, 0, Modality::Radar, 3.1, 3));
let report = mirror.assess(1, 0);
println!("{:?}", report.verdict);
```

`#![forbid(unsafe_code)]`. Dependencies: `serde`, `thiserror`.

Part of the [`galadriel`](https://github.com/sepahead/galadriel) workspace.
Licensed under MIT OR Apache-2.0.
