# Contributing to galadriel

Thanks for your interest. galadriel is **Galadriel's Mirror** — an
information-theoretic cross-sensor consistency / spoof detector for multi-sensor
fusion. It is part of the [`sepahead`](https://github.com/sepahead) ecosystem and
consumes per-measurement innovation records (`PidObservation`) that crebain's
fusion emits.

## Ground rules

- **The baseline must stay honest.** The cheap NIS χ² detector in `galadriel-core`
  is the yardstick; the optional `pid` engine only ships a capability once it
  demonstrably *beats* the baseline on the same fixtures. Do not add a heavier
  method that a cheaper statistic already covers.
- **Fail closed.** Below `min_samples` / `min_channels`, or on any estimator gate
  failure, the verdict is `InsufficientEvidence` — never silently `Nominal`.
- **Advisory, not enforced.** galadriel softens (down-weights, recommends); it
  never vetoes a control path. Keep `calibrated_posterior = false` semantics.
- **Pure default build.** The default workspace build has no heavy dependencies.
  `pid` (pid-core) and `ncp` (ncp-core / ncp-zenoh) are additive, off-by-default
  features. Never enable them by default or pull Zenoh/tokio into the default graph.
- **Safe Rust.** Every crate is `#![forbid(unsafe_code)]`.

## Before you push

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build -p galadriel-core --no-default-features   # pure-core smoke
```

CI runs exactly this, plus a build on the pinned **MSRV (1.80)** for the default
build (the union MSRV rises to 1.88 once the `pid`/`ncp` features are enabled).

## Commit / PR hygiene

- Small, focused commits with imperative subjects.
- Do **not** add AI assistants or agents as commit/PR co-authors, and do not add
  "Generated with …" trailers.

## Design reference

The full, adversarially-reviewed design (threat model, estimand, estimator gates,
evaluation plan) lives in the ecosystem docs as `galadriels-mirror.md`. New
detection logic should trace back to it.
