# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor
versions may make breaking changes).

## [Unreleased]

### Added (cross-repo integration proof)
- **A real crebain-emitted capture is now a CI-checked galadriel fixture.**
  `crates/galadriel-ncp/tests/fixtures/crebain_clean_capture.jsonl` (476 records; one
  constant-velocity target; visual/acoustic Cartesian + radar through crebain's EKF polar
  path; NIS mean 2.93 ≈ the χ²(3) expectation) was produced by crebain's own emitter
  (its `generate_galadriel_pid_fixture` test), not hand-written. Two integration tests
  prove the seam beyond the byte-frozen contracts: genuine emitter output parses with full
  modality coverage and χ²-plausible NIS, and a clean capture does **not** false-alarm the
  NIS baseline or the fused correlation default. The `replay` CLI on the fixture reads:
  `VERDICT: NOMINAL — 3 channels corroborate; NIS consistent with χ²`.

### Changed
- **README: crebain now emits the sidecar.** The "designated emitter" hedge is resolved -
  crebain's `update_track` emits contract-frozen `PidObservation` records (feature
  `emit_innovations` / `CREBAIN_PID_JSONL` JSONL sink, golden-tested against this repo's
  frozen contract on both sides). The live Zenoh leg remains on the roadmap.

### Added
- **`galadriel-justify` — the deployed Wibral decomposition now evidences its own
  justification.** The XOR synergy study gains the **SxPID synergy atom** as a detector
  (exact discrete plug-in via `pid_core::discrete_sxpid2`): AUC 1.000 [1.000, 1.000], with
  the coupled-class atoms matching the closed form (syn +0.413 ≈ log2(4/3), red −0.583 ≈
  log2(2/3) — SxPID's deliberately *negative*, misinformative XOR redundancy, never clamped).
- **`galadriel-justify` — continuous synergy study (`run_synergy_continuous`)**: a
  sign-parity coupling `T = sign(A)·sign(B)·|Z|` (the continuous XOR — every pairwise
  marginal exactly independent, joint MI exactly ln 2) evaluated with the *deployed*
  continuous estimators via one `pid2_isx_estimate` call per triple: pairwise KSG MI at
  chance (0.513), the joint contrast Q **and the continuous `I^sx` synergy atom** (Ehrlich
  et al. 2024 estimator) both AUC 1.000 — the irreducible-synergy verdict now demonstrated
  on the estimators the engine actually runs, not only on discrete plug-ins.
- **`galadriel-justify` — sequential (pointwise) detection study (`run_seq`)**: five
  detectors at one matched 5 % stream-level FAR — windowed `|ρ̂|` / windowed KSG MI vs three
  per-frame CUSUMs (naive product, **parametric Gaussian log-LR** at the calibration ρ̂, and
  **model-free kNN local-MI** against a frozen clean reference). The per-frame local MI term
  is the plug-in log-likelihood ratio for a moment-matched decoupling, so the CUSUM over it
  is the classical optimal sequential test (Page 1954; Moustakides 1986). Results: on the
  linear coupling the parametric pointwise plug-in wins (2 f — pointwise information is
  *forced* on the Gaussian manifold too); on the sign-flip coupling every cheap statistic is
  blind (reach 0.000–0.082) while the local-MI CUSUM reaches 100 % at **19 f vs 43 f** for
  the windowed KSG — the pointwise capability of the shared-exclusions PID made operational,
  with its calibration assumption (a clean reference window) disclosed. Three new tests
  assert the closed-form atoms, the continuous-synergy separation, and the sequential
  hypotheses (7 tests total in `-justify`).
- **`galadriel-pid` — the engine now reports the full 2-source SxPID atom set**: `ChannelPid`
  gains a `synergy` field (the top Möbius atom `I(S1,S2;T) − I(S1;T) − I(S2;T) + I^sx`)
  alongside `redundancy`, both from the single `pid2_isx_estimate` call the engine already
  made (zero added estimator cost). Report-only: the verdict logic is unchanged and all
  evaluation numbers are unaffected.
- **`galadriel-ncp` — the sidecar payload contract is frozen by test**
  (`sidecar_payload_contract_is_frozen`): byte-exact golden JSON for the full and minimal
  `PidObservation` shapes, so a producer (crebain's emitter) can be written against a tested
  contract and an accidental wire change fails CI instead of silently starving the tap. The
  live `SidecarTap` now **counts decode failures** (`decode_failures()`): malformed payloads
  are still dropped (never delivered to the callback) but never silently — contract drift
  surfaces as a rising counter instead of "no data".

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
- **README `Project status` + `Roadmap`.** Added a per-crate status table (role · state · test
  count, summing to the 74 passing) and a grounded roadmap (validation · integration · release,
  with an explicit *out-of-scope-by-design* list). Fixed the architecture crate listing (it omitted
  `galadriel-justify`) and marked the pure default-members; corrected "this release" → "default
  build" (galadriel is `0.1.0`, untagged).

### Fixed
- **Wibral-PID faithfulness pass (theory · attribution · citations), with primary-source
  verification.** A second adversarial review focused on the decomposition itself:
  - **Barrett's theorem re-scoped (PAPER §4.1, MOTIVATION §5).** Previous text implied every
    Gaussian PID redundancy reduces to MMI per Barrett (2015) and that Venkatesh & Schamberg
    "reproduced" the covariance claim. Barrett's reduction covers PIDs whose redundant/unique
    atoms depend only on the pairwise source–target marginals, for a **univariate** target; the
    deployed `I^sx` is **outside** that class (full-joint dependence, negative atoms; on additive
    Gaussians its redundancy ≈ 0.22 nats where MMI gives ≈ 0.28 — pid-core's Gaussian oracle).
    Venkatesh & Schamberg *confirm* the scalar-target reduction and show it **fails** for
    multivariate targets. The "forced" argument now rests, correctly, on covariance sufficiency
    (any atom of any measure is a function of the covariance) plus a quantifier note (an
    information statement, not a per-atom ROC identity).
  - **Q-bound tightness measure-scoped (PAPER §4.2(3), JUSTIFICATION §3.3).** "Q is tight for
    XOR (both unique atoms vanish)" holds under Williams–Beer's `I_min` but is **false under the
    shipped SxPID**, whose XOR atoms are (−0.585, +0.585, +0.585, +0.415) bits
    (Makkeh–Gutknecht–Wibral 2021 §VI; reproduced exactly by the extended study) — Q = 1 bit
    over-counts the SxPID synergy atom, and Q ≥ Syn is only guaranteed for non-negative unique
    atoms. The "no pairwise statistic" claim is tightened to its exact population form (every
    single-pair marginal of XOR is independent-uniform).
  - **Synergy-atom attribution (PAPER §3.3).** The synergy the engine computes is the SxPID
    synergy (Möbius inversion of `I^sx` on the Williams–Beer *lattice*), not Williams–Beer's
    `I_min` atom; and the continuous `I^sx` estimator actually deployed is **Ehrlich et al. 2024**
    (PRE 110, 014115) — now cited alongside the discrete Makkeh 2021 measure (previously the
    continuous estimator was uncited).
  - **KSG bias-sign claim corrected (PAPER §4.1).** "The known positive finite-sample bias of
    KSG" is unsupported: the bias sign is regime-dependent (Holmes & Nemenman 2019) and negative
    under strong dependence (GaoSVG 2015). Now described as configuration-specific.
  - **Stale estimand docstring (`galadriel-pid/src/lib.rs`).** It described
    MI-with-leave-one-out-consensus as the corroboration score; the verdict-driving score is (and
    was) *best pairwise* MI, the consensus being only the PID atoms' target. Docs now match code.
  - **Degenerate-CI gloss (PAPER scope box).** `AUC 1.000 [1.000, 1.000]` cells are now read as
    "no observed class overlap" (consistent with true AUC ≈ 0.99 at these trial counts), never
    as certainty.
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
