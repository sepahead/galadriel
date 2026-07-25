# Contributing to galadriel

## Abbreviations

| Short form | Meaning |
|---|---|
| AI | artificial intelligence |
| CLI | command-line interface |
| JSONL | JavaScript Object Notation Lines |
| MSRV | minimum supported Rust version |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |

Thank you for your interest. Galadriel is **Galadriel's Mirror**.
It is a statistical consistency monitor for multi-sensor fusion.
It also provides optional information-theoretic research methods.
It is part of the [`sepahead`](https://github.com/sepahead) ecosystem.
It consumes accepted `(track, modality, frame)` innovation records (`PidObservation`).

Version 0.9.0 is a review-gated GitHub research source release.

The bundled historical Crebain fixture supports bounded parsing and basic NIS baseline checks.
It is not a valid source of cross-modal correlation or PID evidence.
The repository implements and tests its local consumer and receiver boundaries.
An external producer MUST conform to the producer contract.
No accepted recorded study establishes field performance, calibration, deployed validity, or cross-repository qualification.

## Ground rules

- **Preserve the baseline.** Use the low-cost NIS χ² detector in `galadriel-core` as the baseline.
  A more complex optional method needs a registered estimand.
  Evidence MUST show that the method adds information unavailable to a less complex statistic.
  A synthetic point estimate is not sufficient.
- **Fail closed.** Invalid input or configuration returns `Err(...)`.
  Missing, stale, incomparable, or statistically insufficient evidence produces `InsufficientEvidence`.
  Such evidence never silently produces `Nominal`.
- **Preserve the estimand.** Cross-channel samples MUST share one track and an exact sequence.
  They MUST also share a coordinate frame and a frozen pre-update prior.
  Do not align unequal streams by ordinal position.
  Do not mix tracks.
- **Preserve assessment scope.** Every accepted whole-stream assessment MUST bind
  its producer, session, epoch, stream, state generation, terminal sequence,
  terminal timestamp, and clock domain.
  The NCP lifecycle adapter MUST derive this scope from the validated producer
  and exact admitted position.
  Raw JSONL input lacks this complete scope.
  Keep raw replay diagnostic-only.
  Do not invent provenance labels.
  Treat assessment and receipt digests as integrity checks, not authentication.
- **Treat missingness as evidence.** Association misses, gate misses, and rejected updates are censored observations.
  They are not random gaps.
  All-modal silence requires a separate producer heartbeat because a detector cannot infer time from absent calls.
- **Keep the output advisory.** Galadriel reports evidence only.
  It does not down-weight, recommend, authorize, or veto a control path.
  A downstream restrict-only policy requires separate admission.
  Preserve the `calibrated_posterior = false` semantics.
- **Keep the default build small.** The default CLI build excludes optional integration dependencies.
  The off-by-default `pid` feature adds `pid-core`.
  The off-by-default `ncp` feature adds `ncp-core`.
  The `ncp-live` feature also adds `ncp-zenoh`, Zenoh, and Tokio.

  Do not enable these features by default.
  Do not add Zenoh or Tokio to the default graph.
- **Forbid unsafe code.** The workspace lint policy forbids unsafe code in every Rust target.

## Focused local checks

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
cargo fetch --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml
cargo deny --offline --all-features --locked check
cargo deny --offline --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```

These commands are a focused development subset.
They are not the complete continuous integration (CI) mirror.
Use `.github/workflows/ci.yml` as the exact command source.
Follow `AGENTS.md` for the complete pre-push gate set.

The pinned workspace MSRV is **Rust 1.89**.
Version 0.9.x freezes the public `galadriel-core` source surface in `docs/API-SURFACE.md`.
Other crates remain experimental.
All packages set `publish = false`.
A change to `publish = false` is a release decision, not a routine metadata edit.

## Commit and pull request hygiene

- Make small, focused commits.
- Use imperative commit subjects.
- Do **not** add AI assistants or agents as commit or pull request co-authors.
- Do not add "Generated with …" trailers.

## Design reference

The repository README and `docs/` define the current threat model and estimand.
They also define the estimator gates and evidence boundary.
Update these documents when you add detection logic.
Add tests for invalid, missing, mixed-track, out-of-order, and degenerate inputs.
