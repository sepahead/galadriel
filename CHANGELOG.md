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
  the "must beat the baseline" hypothesis (robust across seeds). A `fuse` /
  `assess_stream` layer combines the baseline and PID into one jam-vs-spoof verdict
  (`Nominal` / `Spoof { stealthy }` / `Jam`); the evaluation shows the fused detector
  covers all attack regimes (1.000 / 0.965 / 1.000) at the baseline's false-alarm rate.
- **`galadriel-cli`** — the `demo` subcommand: CLEAN → NOMINAL, phantom → SPOOF,
  jam → JAM, with per-channel NIS sparklines; under `--features pid`, a
  baseline-vs-PID panel showing the baseline blind while PID catches the stealthy spoof.
- **`galadriel-ncp`** (feature `ncp`) — NCP observation-plane ingest:
  `PidObservation` JSONL read/write plus the NCP key scheme via `ncp-core`
  (`observation_key`, and the non-wire `sidecar_key` that never touches
  `CONTRACT_HASH`). The cli gains a `replay <jsonl>` subcommand that runs a captured
  stream through the baseline (and PID with `--features pid,ncp`). `.ncp-consumer`
  pins the dependency.
- **`galadriel-eval`** — a Monte-Carlo harness across clean / loud bias spoof /
  moment-matched stealthy spoof / jam, on a **three-axis** basis:
  - *Accuracy* — detection rate, false-alarm rate, ROC-AUC. On the stealthy spoof the
    baseline is at chance (AUC 0.547) while the cross-sensor detectors recover it; on
    magnitude attacks the baseline is 100% and they are correctly silent (complementary).
  - *Latency* (§2.1, `measure_latency`) — median time-to-detect over growing prefixes:
    magnitude attacks fire in ~4 frames, the stealthy spoof carries a real window-fill
    latency (52 f PID / 80 f correlation), caught reliably (100% reach) but not instantly.
  - *Cost* (§2.2, `benches/detectors.rs`, criterion) — the correlation default is
    ~1× the NIS baseline (tens of µs), the PID/KSG engine ~100×; on the linear spoof
    that is ~100× compute for zero accuracy gain.
- **`docs/JUSTIFICATION.md` + `galadriel-justify`** — a rigorous answer to *when is PID
  justified, and when is it forced?* On linear-Gaussian data `MI = −½ln(1−ρ²)` is
  monotone in `ρ`, so MI and correlation are the same detector (corr AUC = MI AUC =
  1.000) — **PID is forced**. It is **justified** only by (1) model-free nonlinear
  dependence (ΔAUC 0.34 on `Y=±X`), (2) adversarial robustness (Kerckhoffs), and
  (3) **irreducible synergy** — on `T=A⊕B` correlation *and* pairwise MI are both at
  chance while only the joint decomposition separates (AUC 1.000). Both empirical.
- **`galadriel-core` correlation default** — a `correlation` module (cheap pairwise-`|ρ|`
  cross-sensor consistency) and a source-agnostic `fusion::combine` + `assess_default`
  (NIS ⊕ correlation): a **complete detector with no `pid-core` dependency**, the pure
  build's shipped default. The eval confirms it matches the MI engine on the linear
  stealthy spoof (AUC 1.000 vs 0.999).
- **`galadriel-ncp` live tap** (feature `zenoh`, via `ncp-live`) — `live::SidecarTap`, a
  read-only Zenoh subscriber on the non-wire sidecar key that decodes streaming
  `PidObservation`s; the transport counterpart to JSONL ingest. Verified to compile
  against the real `ncp-zenoh` 1.9 API.
- Dual MIT / Apache-2.0 licensing, CI (fmt + clippy + test + MSRV + pure-core
  smoke), and project docs.

### Changed
- **Correlation is now the default cross-sensor detector; PID is the opt-in escalation.**
  Following the `JUSTIFICATION.md` analysis, the pure build ships `assess_default`
  (NIS ⊕ correlation) and `galadriel-pid` reuses the shared `galadriel_core::fusion`
  logic, so both variants speak one `FusedVerdict`. The `galadriel demo` gained a fourth,
  **pure** scene showing the correlation default catch a stealthy spoof the baseline
  misses; `--features pid` reframes the PID panel as the KSG-MI escalation.

### Notes
- The default build remains pure and heavy-dependency-free; `pid`, `ncp`, and
  `ncp-live` are additive, off-by-default features.

[Unreleased]: https://github.com/sepahead/galadriel
