# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor
versions may make breaking changes).

## [Unreleased]

### Added
- **`galadriel-core`** — the pure baseline: `Modality` / `PidObservation` wire
  types (byte-compatible with crebain's `SensorModality`); a fixed-capacity NIS
  sliding window; a dependency-free χ² implementation (`ln_gamma`, regularized
  incomplete gamma, CDF/survival); the windowed NIS consistency test; a two-sided
  CUSUM; and the fail-closed jam-vs-spoof decision
  (`Nominal` / `Spoof` / `Jam` / `InsufficientEvidence`).
- **`galadriel-sim`** — deterministic synthetic χ²(3) scenarios plus the
  `PhantomAcousticDoa` (targeted single-channel) and `BroadbandJam` (correlated
  all-channel) injections; **shared-latent correlated scenarios** (`rho`) and a
  **moment-matched `StealthySpoof`** (same variance, so the NIS baseline is blind).
- **`galadriel-pid`** (feature `pid`) — the **cross-sensor PID engine**:
  geometry-gated **pairwise KSG mutual information** as a corroboration score plus
  the `I^sx` **redundancy atom** (via `pid-core`), with a leave-one-out framing and
  a fail-closed `InsufficientEvidence` state. On a moment-matched stealthy spoof it
  flags the decoupled channel the NIS baseline cannot see — empirically validating
  the "must beat the baseline" hypothesis (robust across seeds).
- **`galadriel-cli`** — the `demo` subcommand: CLEAN → NOMINAL, phantom → SPOOF,
  jam → JAM, with per-channel NIS sparklines; under `--features pid`, a
  baseline-vs-PID panel showing the baseline blind while PID catches the stealthy spoof.
- **`galadriel-ncp`** (feature `ncp`) — NCP observation-plane ingest:
  `PidObservation` JSONL read/write plus the NCP key scheme via `ncp-core`
  (`observation_key`, and the non-wire `sidecar_key` that never touches
  `CONTRACT_HASH`). The cli gains a `replay <jsonl>` subcommand that runs a captured
  stream through the baseline (and PID with `--features pid,ncp`). `.ncp-consumer`
  pins the dependency.
- Dual MIT / Apache-2.0 licensing, CI (fmt + clippy + test + MSRV + pure-core
  smoke), and project docs.

### Notes
- The live Zenoh observation tap (`ncp-zenoh` + `tokio`, behind a future `ncp-live`
  feature) is planned and additive; the default build remains pure and
  heavy-dependency-free.

[Unreleased]: https://github.com/sepahead/galadriel
