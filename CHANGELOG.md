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
  all-channel) injections.
- **`galadriel-cli`** — the `demo` subcommand: CLEAN → NOMINAL, phantom → SPOOF,
  jam → JAM, with per-channel NIS sparklines.
- Dual MIT / Apache-2.0 licensing, CI (fmt + clippy + test + MSRV + pure-core
  smoke), and project docs.

### Notes
- The `pid` (cross-sensor PID engine, pulls `pid-core`) and `ncp` (observation
  ingest, pulls `ncp-core`; live tap behind `ncp-live`) features are planned and
  additive; the default build remains pure and heavy-dependency-free.

[Unreleased]: https://github.com/sepahead/galadriel
