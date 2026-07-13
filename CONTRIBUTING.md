# Contributing to galadriel

Thanks for your interest. galadriel is **Galadriel's Mirror** — an
information-theoretic cross-sensor consistency / spoof detector for multi-sensor
fusion. It is part of the [`sepahead`](https://github.com/sepahead) ecosystem and
consumes per-measurement innovation records (`PidObservation`). The bundled historical
Crebain fixture is a contract/baseline smoke test, not a valid source of cross-modal
correlation/PID evidence. The operational producer/receiver seam is component-complete, but
no accepted recorded study establishes field performance, calibration, or deployed validity.

## Ground rules

- **The baseline must stay honest.** The cheap NIS χ² detector in `galadriel-core`
  is the yardstick. A heavier optional method needs a registered estimand and
  evidence that it adds information unavailable to a cheaper statistic; a
  synthetic point estimate alone is not enough.
- **Fail closed.** Invalid input or configuration returns `Err(...)`. Missing,
  stale, incomparable, or statistically insufficient evidence produces
  `InsufficientEvidence` — never silently `Nominal`.
- **Preserve the estimand.** Cross-channel samples must share a track, exact
  sequence, common coordinate frame, and common frozen pre-update prior. Do not
  align unequal streams by ordinal position or mix tracks.
- **Treat missingness as evidence.** Association/gate misses and rejected updates
  are censored observations, not random gaps. All-modal silence requires an
  external heartbeat because a detector cannot infer time from absent calls.
- **Advisory, not enforced.** galadriel reports evidence only; it does not
  down-weight, recommend, authorize, or veto a control path. Any downstream
  restrict-only policy is a separately reviewed consumer concern. Keep
  `calibrated_posterior = false` semantics.
- **Pure default build.** The default workspace build has no heavy dependencies.
  `pid` (pid-core) and `ncp` (ncp-core / ncp-zenoh) are additive, off-by-default
  features. Never enable them by default or pull Zenoh/tokio into the default graph.
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

The pinned workspace MSRV is **Rust 1.89**. All packages currently set
`publish = false`; changing that is a release decision, not a routine metadata edit.

## Commit / PR hygiene

- Small, focused commits with imperative subjects.
- Do **not** add AI assistants or agents as commit/PR co-authors, and do not add
  "Generated with …" trailers.

## Design reference

The current threat model, estimand, estimator gates, and evidence boundary live
in this repository's README and `docs/`. New detection logic must update those
documents and add tests for invalid, missing, mixed-track, out-of-order, and
degenerate inputs.
