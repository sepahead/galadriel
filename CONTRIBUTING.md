# Contributing to galadriel

Thank you for your interest. Galadriel is **Galadriel's Mirror**.
It is an information-theoretic cross-sensor consistency and spoof detector for multi-sensor fusion.
It is part of the [`sepahead`](https://github.com/sepahead) ecosystem.
It consumes accepted `(track, modality, frame)` innovation records (`PidObservation`).

The bundled historical Crebain fixture supports contract and baseline smoke tests.
It is not a valid source of cross-modal correlation or PID evidence.
The repository implements and tests the operational producer and receiver interface.
No accepted recorded study establishes field performance, calibration, deployed validity, or cross-repository qualification.

## Ground rules

- **Keep the baseline honest.** Use the low-cost NIS χ² detector in `galadriel-core` as the baseline.
  A more complex optional method needs a registered estimand.
  Evidence must show that the method adds information unavailable to a less complex statistic.
  A synthetic point estimate is not sufficient.
- **Fail closed.** Invalid input or configuration returns `Err(...)`.
  Missing, stale, incomparable, or statistically insufficient evidence produces `InsufficientEvidence`.
  Such evidence never silently produces `Nominal`.
- **Preserve the estimand.** Cross-channel samples must share one track and an exact sequence.
  They must also share a coordinate frame and a frozen pre-update prior.
  Do not align unequal streams by ordinal position. Do not mix tracks.
- **Treat missingness as evidence.** Association misses, gate misses, and rejected updates are censored observations.
  They are not random gaps.
  All-modal silence requires an external heartbeat because a detector cannot infer time from absent calls.
- **Keep the output advisory.** Galadriel reports evidence only.
  It does not down-weight, recommend, authorize, or veto a control path.
  A downstream restrict-only policy is a separately reviewed consumer concern.
  Preserve the `calibrated_posterior = false` semantics.
- **Keep the default build small.** The default workspace build has no heavy dependencies.
  The off-by-default `pid` feature adds `pid-core`.
  The off-by-default `ncp` feature adds `ncp-core`.
  The `ncp-live` feature also adds `ncp-zenoh`, Zenoh, and Tokio.
  Do not enable these features by default. Do not add Zenoh or Tokio to the default graph.
- **Safe Rust.** Workspace lint policy forbids unsafe code in every target.

## Before you push

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
cargo deny --all-features --locked check
```

The pinned workspace MSRV is **Rust 1.89**.
Version 0.9.x freezes the public `galadriel-core` source surface in `docs/API-SURFACE.md`.
Other crates remain experimental.
All packages set `publish = false`.
A change to `publish = false` is a release decision, not a routine metadata edit.

## Commit and pull request hygiene

- Make small, focused commits. Use imperative subjects.
- Do **not** add AI assistants or agents as commit or pull request co-authors.
- Do not add "Generated with …" trailers.

## Design reference

The repository README and `docs/` define the current threat model and estimand.
They also define the estimator gates and evidence boundary.
Update these documents when you add detection logic.
Add tests for invalid, missing, mixed-track, out-of-order, and degenerate inputs.
