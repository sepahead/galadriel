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
- **`galadriel-eval`** — a Monte-Carlo harness (clean / loud bias spoof / moment-matched
  stealthy spoof / jam) that grew into an **eight-part evaluation**, all with
  **percentile-bootstrap 95 % confidence intervals** (`auc_ci`, plus a *paired* corr-vs-PID
  `auc_diff_ci`) and, for rates, Wilson intervals:
  - *Accuracy* — detection rate, FAR, ROC-AUC. Stealthy spoof: baseline at chance
    (AUC 0.547 [0.490, 0.603], CI brackets 0.5) while the cross-sensor detectors recover it
    (corr 1.000, PID 0.999, paired ΔAUC +0.001 [+0.000, +0.001] — a tie).
  - *Latency* (`measure_latency`) — median time-to-detect: magnitude attacks fire in
    ~4 frames, the stealthy spoof carries a real window-fill latency (52 f / 80 f).
  - *Cost* (`benches/detectors.rs`, criterion) — correlation default ~1× the NIS baseline,
    the PID/KSG engine ~100× (≈100× compute for zero accuracy gain on the linear spoof).
  - *Detection boundary* (`decoupling_sweep`) — sweeping decoupling strength, correlation
    **strictly beats** PID through the mid-boundary (paired ΔAUC CI > 0, `d ∈ [0.2, 0.8]`):
    MI/PID is not merely forced but strictly *worse* where the nonparametric estimator's
    variance bites.
  - *Honest-majority failure* (`collusion_study`) — a colluding 2-of-3 majority inverts the
    detector: it accuses the honest channel (correlation 100 % [0.981, 1.000], PID 97.5 %),
    structurally, so neither escapes it.
  - *Adaptive adversary* (`adaptive_adversary`) — at a **matched FAR**, correlation's evasion
    ceiling is lower (0.20 vs 0.40): a Kerckhoffs-aware adversary does not favour PID.
  - *Non-stationary FAR* (`maneuver_far`, `galadriel-sim`'s `Maneuver`) — a synchronized
    maneuver never false-alarms; heterogeneous ones do (a disclosed limit), with correlation
    again more robust than PID, and coherent maneuvers routed to `Jam` not `Spoof`.
- **`docs/JUSTIFICATION.md` + `galadriel-justify`** — a rigorous answer to *when is MI/PID
  justified, and when is it forced?* On linear-Gaussian data the plug-in Gaussian
  `MI = −½ln(1−ρ²)` is monotone in `ρ` (and every Gaussian PID atom is a function of the
  covariance), so MI/PID and correlation are the same detector (corr AUC = MI AUC = 1.000,
  CIs both degenerate) — **MI/PID is forced**, and (per the eval) strictly *worse* near the
  boundary. It is **justified** only by (1) model-free nonlinear dependence
  (ΔAUC 0.34 on `Y=±X`; corr 0.662 [0.617, 0.707] is a kurtosis artifact); (2) adversarial
  robustness — *a framing of (1) that bites only off the Gaussian manifold* (the §5.7 adaptive
  study shows correlation is the harder detector to evade on the linear manifold); and
  (3) **irreducible synergy** — on `T=A⊕B`, correlation *and* pairwise MI are both at chance
  (0.544, CIs bracket 0.5) while only a joint-information contrast `Q` separates (AUC 1.000).
  `I^sx` is correctly the *redundancy* atom (Makkeh–Gutknecht–Wibral 2021).
- **`docs/MOTIVATION.md`** — the real-world threat grounding, with cited sources: UAV GNSS
  spoofing is demonstrated and theatre-wide (UT Austin 2012; Ukraine EW), multi-sensor fusion is
  the standard defense but is itself attacked by *faking* cross-sensor consistency (`MSF-ADV`,
  IEEE S&P 2021; the frustum attack, USENIX Security 2022 — which is exactly galadriel's honest
  limit), and cross-sensor consistency checking is a recognized countermeasure. Crucially, the
  paper's *forced-vs-justified* dichotomy maps onto the real attack classes: GNSS/kinematic
  spoofing is linear-Gaussian (correlation forced) while learned-perception fusion attacks are
  nonlinear/synergistic (PID justified). All academic and threat citations independently verified.
- **`docs/PAPER.md`** — the consolidated research paper (*Forced or Justified? Mutual
  Information vs. Correlation for Cross-Sensor Spoof Detection in Counter-UAS Fusion*),
  hardened through **two adversarial peer-review passes** (a 5-lens review, then a 3-lens
  verification) to a state all reviewers rated ready-for-preprint. Every number is a `cargo`
  command; linked from the README.
- **`docs/RELATED-WORK.md`** — a survey of competing and complementary spoof/fault detectors
  organized by **observation layer** (signal-level GNSS anti-spoofing, cryptographic
  authentication / OSNMA, RAIM, innovation-based FDI, cross-sensor consistency, resilient state
  estimation, Byzantine-robust fusion, learning-based anomaly detection, active challenge-response),
  each with its threat model, honest limits, cited sources, and relation to galadriel; a two-part
  head-to-head comparison table; and a **fair-benchmark methodology** (comparison axes, a shared
  attack ontology, a matched operating point) — most of which galadriel's own eval harness already
  instantiates. RAIM is named as galadriel's closest classical analog (galadriel = its model-free,
  multi-modality generalization).
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
- **Sibling ecosystem deps pinned by git tag** (was: relative path deps). `pid-core`
  (pid-rs `v0.4.0`) and `ncp-core` / `ncp-zenoh` (NCP `v0.6.0`) are now git dependencies in
  the workspace root, so a clone resolves the workspace without the siblings on disk. The
  repos are private, so the `pid` / `ncp` features need read access to build (the shipped
  `.cargo/config.toml` sets `git-fetch-with-cli`; a commented `paths` override is offered for
  local sibling-tree development).
- **Correlation is now the default cross-sensor detector; PID is the opt-in escalation.**
  Following the `JUSTIFICATION.md` analysis, the pure build ships `assess_default`
  (NIS ⊕ correlation) and `galadriel-pid` reuses the shared `galadriel_core::fusion`
  logic, so both variants speak one `FusedVerdict`. The `galadriel demo` gained a fourth,
  **pure** scene showing the correlation default catch a stealthy spoof the baseline
  misses; `--features pid` reframes the PID panel as the KSG-MI escalation.

### Fixed
- **Scientific-rigour triple-check.** A six-dimension adversarial verification (theory · statistics ·
  reproducibility · code-vs-prose fidelity · overclaim/consistency · citation integrity; each raised
  concern confirmed by three independent skeptics) reproduced every number and confirmed 74/74 tests
  pass, and surfaced three prose defects — now fixed:
  - **Overclaim corrected (PAPER §4.3, MOTIVATION §4a).** The claim that MI/PID is "the only thing
    that can see" the `MSF-ADV` / frustum attacks and that "the escalation earns its cost" against
    them contradicted the paper's own honest boundary (§6/§7: the frustum attack *preserves*
    cross-sensor consistency and so defeats **every** consistency detector, MI/PID included). It is
    now stated as a hypothesis (restoring §4.2(3)'s "we do not evaluate this here"): a joint measure
    is the only *candidate* worth escalating to for genuinely nonlinear/synergistic couplings that
    still leave a dependence signature, while a statistics-matching FDI is the family's shared blind
    spot — and galadriel consumes kinematic residuals, not the semantic fusion feature these attacks
    target.
  - **Citation corrected (PAPER §3.3, §5.5, MOTIVATION §5).** "KSG underestimates MI under strong
    dependence" / "k-NN estimators break down in high dimensions" were misattributed to [Gao2018]
    (*Demystifying Fixed k-NN Information Estimators*, which in fact proves KSG **consistent**). The
    strong-dependence underestimation is now cited to **Gao, Ver Steeg & Galstyan (AISTATS 2015)**
    [GaoSVG2015]; only the dimension-dependent bias-rate claim stays with [Gao2018].
  - **Minor precision.** Removed an inconsistent "~700×" isolated-cost figure (the isolated
    KSG-vs-`|ρ|` ratio is now uniformly reported as ~10³); softened §5.7 "detects more at every
    strength" to "…every strength we tested"; corrected a `Maneuver` doc-comment ("modality's index"
    → "enum discriminant").

### Notes
- The default build remains pure and heavy-dependency-free; `pid`, `ncp`, and
  `ncp-live` are additive, off-by-default features.
- **Headline finding.** Across five independent axes — accuracy, detection boundary,
  compute cost, adaptive evasion, and non-stationary FAR — the cheap correlation default is
  ≥ the KSG-MI/PID engine on the linear-Gaussian sensor-fusion regime; MI/PID is *forced*
  there (and ~100× costlier), justified only for genuinely nonlinear or synergistic couplings.
  This is the disciplined position the project was built to establish.

[Unreleased]: https://github.com/sepahead/galadriel
