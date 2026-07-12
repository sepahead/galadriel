# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before `1.0`, minor releases
may contain breaking changes.

## [Unreleased]

### Security

- Refuse `SidecarTap::close()` on a tap created with `from_bus`: `ZenohBus` clones share
  one Zenoh session and one retained-subscriber registry, so closing from the tap would
  have silently torn down the **host's** entire transport (all of its subscriptions, not
  just galadriel's). A shared tap now returns a typed error and the host closes its own
  session; taps opened by the `open*` constructors still close normally.
- Bound sidecar `session_id`/`producer_id` to 64 bytes, mirroring NCP 0.8's 1..=64-byte
  transport-neutral session-identifier rule, so an envelope can never carry an identity
  the NCP control plane itself would reject (JSON Schema updated to `maxLength: 64`).
- Widen the CI compression guard for the `RUSTSEC-2026-0041` exception from
  `-p galadriel-ncp` to `--workspace --all-features --locked`, so no workspace member's
  feature unification can re-enable `zenoh-transport/transport_compression` unseen; the
  vulnerable lz4_flex decompression path is `cfg`-gated behind that feature and compiled
  out entirely while the guard holds.
- Document that `LiveLimits::max_payload_bytes` bounds decode work only — the transport
  copies a received message before the gate, and Zenoh's own `max_message_size` defaults
  to 1 GiB — so deployments bound peak receive memory in the Zenoh config.
- Document that `TransportMode::QuietDevelopment`'s scouting-off property holds for NCP's
  hardened default config and is superseded when `NCP_ZENOH_CONFIG` names another config.

### Added

- An in-process Zenoh loopback end-to-end suite for the live leg
  (`crates/galadriel-ncp/tests/live_zenoh_e2e.rs`, feature `zenoh`): a real `ZenohBus`
  round trip through `SidecarTap` on the multi-segment `engram/ncp` realm proving decoded
  delivery with full field fidelity, wrong-session provenance rejection, duplicate-JSON-key
  rejection at the typed parse, size-gate-before-parse, `from_bus` realm derivation, the
  shared-bus close refusal, and health-counter semantics — the first runtime proof of the
  NCP live leg (previously covered only by synthetic payload-delivery unit tests).
- Re-export the exact pinned `ncp_core` (and `ncp_zenoh` under feature `zenoh`) from
  `galadriel-ncp`, so hosts building a shared bus for `SidecarTap::from_bus` cannot
  accidentally resolve a second, diverging NCP revision in the same process.
- Document the sidecar's session-epoch discipline relative to NCP 0.8: control-plane
  sessions carry server-issued generations, the sidecar deliberately does not — a producer
  restart mints a new `session_id` instead.

- Pin CI actions by commit SHA, grant read-only repository contents permission, disable
  persisted checkout credentials, and cancel superseded runs.
- Add Dependabot and `cargo-deny` policy for advisories, licenses, and sources.
- Remove the global git credential rewrite previously used for sibling repositories; the
  pinned `pid-rs` and `NCP` sources are public.
- Add common secret/key/certificate patterns to `.gitignore`.
- Bound JSONL record count and line size, live payload size, and per-stream tracking state.
- Validate NCP realms and IDs as concrete key segments and count callback panics separately
  from decode failures.
- Make live sequence resets explicit serialized epoch boundaries with typed rejection of
  callback-context and in-flight-delivery reset attempts, avoiding re-entrant deadlocks.
- Bind live payloads to the subscribed NCP session and expected producer, reject incompatible
  NCP/sidecar versions and non-exact JSON integer identities, and expose advisory contract-hash
  drift without weakening NCP's version gate.
- Require callers to select strict mTLS `Secure` transport or explicitly unverified
  `QuietDevelopment` transport; the live tap no longer implies that a quiet default is secure.
- Carry a time-bounded exception for `RUSTSEC-2026-0041` only while CI proves Zenoh's
  vulnerable transport-compression feature remains disabled.
- Add an easy bounded live-observation handoff with a fixed `DropNewest` policy,
  reset generations, replay-safe overflow semantics, and queue/drop/latency health
  metrics; the advanced inline callback API remains available.

### Changed

- Migrate the exact `pid-core` pin from 0.4.0 (`ad489f5…`) to the canonical pid-rs
  1.0.0 main revision (`1cd2424…`), opt into its explicitly experimental continuous
  surface, adopt its report-first KSG point gate and caller-declared support contract,
  and attach exact dependency/scientific-status/noise/seed evidence to PID reports.
  The fixed-seed 0.4→1.0 reproduction and delta dispositions are recorded in
  `docs/PID_RS_1_0_MIGRATION.md` and `evidence/pid-rs-1.0-migration.json`.
- Raise the workspace MSRV to Rust **1.89** and pin that toolchain. pid-rs 1.0 requires
  Rust 1.89; the previous Rust 1.88 pin cannot build the migrated graph.
- Mark every package `publish = false`. No crates.io release or production-support promise
  is currently made.
- Make public detector, simulator, PID, fusion, and serialization paths fail closed with
  `Result` where invalid data or configuration was previously accepted or could panic.
- Change the correlation default from absolute best-peer scoring to **signed Pearson
  correlation** with family-wise significance and one unique strict-majority positive
  consensus clique.
- Treat PID as additive, sign-invariant evidence. It no longer substitutes for signed
  geometry or allows a ready pair to hide an unassessable channel.
- Preserve magnitude, consistency, anomaly, and insufficient evidence during fusion instead
  of silently dropping one source or manufacturing `Nominal`.
- Align cross-channel observations by exact sequence and track rather than ordinal tail
  position.
- Enforce frozen-prior uniqueness across the complete accepted bounded capture, not only
  the retained correlation tail.
- Require the optional producer-attested `ConsistencyProjection` for cross-channel work;
  modality-native innovation vectors are no longer accepted as an implicit common frame.
- Move the live sidecar from the unrecognized `.../galadriel/pid` key to NCP's ACL-covered
  named perception route `Keys::sensor_named(session, "galadriel-pid")`.
- Assess every active common-projection axis, split applicable family-wise error budgets
  across axes, and fail closed on conflicting or partly insufficient axis attribution.
- Use `statrs` for chi-square/gamma tails instead of the cancellation-prone local
  implementation.
- Express Mirror CUSUM slack and threshold in normalized `sqrt(2*dof)` units so one
  configuration has a comparable operating point across innovation dimensions.
- Validate synthetic scenarios and compute multivariate NIS with the full covariance rather
  than a diagonal approximation.
- Validate evaluation/justification command-line trial counts and reject invalid or
  unbounded runs.
- Confirm PID clique and outsider edges with common-plan circular delete-block margins,
  stable modality-derived randomness, explicit family budgets, and estimator-work limits.
- Label Monte Carlo and justification evidence as synthetic. Remove stale exact AUC,
  false-alarm, latency, benchmark, and test-count claims until regenerated against the
  audited implementation.
- Print a mandatory synthetic-evidence banner (with seed and a provenance reminder) at the
  top of the `galadriel-eval` and `galadriel-justify` reports, so copied numeric output
  cannot be read as an operational detection or false-alarm rate.
- Inherit the workspace `homepage`, `keywords`, and `categories` in every member manifest,
  and reference `galadriel-sim` through the workspace table in `galadriel-pid` dev-dependencies.
- Track the NCP wire through its pre-1.0 churn, ending at the **0.8 wire revision**: pin
  `ncp-core`/`ncp-zenoh` to the immutable commit for the public `v0.8.0` tag (`2f5bd58`,
  contract hash `d1b50a2d8a265276`; an earlier `v0.7.1` pin in this cycle was superseded).
  The sidecar now stamps `ncp_version` `"0.8"`; the `PidObservation` payload shape is
  unchanged, so this is a wire-addressing/version bump, not a payload re-versioning. It
  keeps interoperability with the Crebain producer and Prisoma observer, which are already
  on NCP 0.8 — NCP's `check_version` is an exact major.minor fail-closed gate, so a
  0.7-stamped sidecar would be hard-rejected by 0.8 peers.
- Document Galadriel's downstream advisory boundary from its own side in
  [`docs/ADVISORY-BOUNDARY.md`](docs/ADVISORY-BOUNDARY.md): the contract any consumer (a
  Haldir-style authorization gate) must honour — non-authoritative, record-only until
  independently calibrated, never `ALLOW`-widening, monotonic restrict-only afterward, no
  synchronous feedback loop, and no self-asserted calibration or `StateUnusable` verdict.
- Clarify that "signed" (the sign of the correlation) and "producer-attested" (a provenance
  claim on the projection input) are not cryptographic signatures (README intro).
- Document that `Mirror::new` enforces no expected-modality set — a sensor subset can reach
  `Nominal`; `Mirror::with_modalities` is the fail-closed cross-sensor constructor.
- Record that the `galadriel-pid` sidecar route/kind name is historical (PID is now
  optional); a rename is deferred to the next sidecar-schema version bump.
- Rename causal-sounding detector verdicts to evidence-neutral
  `AttributedInconsistency`, `BroadDegradation`, `UnclassifiedAnomaly`, and `Decoupled`.
  Baseline-verdict JSON serialization uses the new tags while deserialization accepts the
  legacy `spoof`, `jam`, and `anomaly` tags for compatibility.
- Replace the contradictory public fusion slice-plus-boolean input with typed
  `ConsistencyEvidence`; positive attribution is non-empty by construction and explicit
  conflicts always fail closed.

### Fixed

- Reject non-finite/negative NIS, invalid degrees of freedom, malformed innovation/covariance
  pairs, non-positive-definite covariance, duplicate/out-of-order sequences, changed DoF,
  mixed tracks, invalid axes, and degenerate channel series.
- Bound detector track state and provide explicit track removal/clear operations.
- Prevent floating-point overflow or NaN from becoming perfect correlation.
- Prevent negative/sign-flipped correlation from counting as corroboration.
- Require all configured/expected modalities to be fresh and assessable before returning
  `Nominal`.
- Separate high-direction inflation from lower-direction or otherwise non-attributable
  anomaly evidence.
- Domain-separate PID jitter so constant or duplicate channels cannot acquire fabricated
  dependence from identical noise.
- Validate bootstrap counts/block sizes and keep failed resamples inconclusive rather than
  replacing them with optimistic values.
- Exclude pre-onset alarms from time-to-detect and stop presenting pointwise parameter-grid
  intervals as simultaneous evidence of a win somewhere.
- Preserve replay histories for alarms, insufficient evidence, and rejected consistency
  frames even when a later clean tail recovers to a nominal terminal verdict.
- Evaluate CLI replay and PID demo terminal reports across every attested projection axis.
- Separate adaptive-study threshold calibration from clean holdout measurement and make
  bootstrap intervals target the same alarm-ranked AUC statistic as the main report.
- Correct the NCP consumer manifest path and make JSONL serialization fallible.
- Correct rustdoc links that targeted private constants.
- Abstain with `InsufficientEvidence` when a pathologically small `family_alpha` makes the
  Fisher significance floor degenerate. The inverse-normal quantile saturates to `+INF` and
  `tanh` already clamped the floor to exactly `1.0` (no `NaN` is ever produced), but
  byte-identical replayed channels also clamp to exactly `rho = 1.0`, so the degenerate
  floor could still admit a fabricated consensus — or an attribution against the one
  non-identical channel — instead of abstention.
- Preserve finite signed-negative pid-rs 1.0 KSG estimates as valid low-dependence
  evidence. The upstream default intentionally allows finite-sample negative estimates;
  rejecting them had converted decoupled edges into false estimator insufficiency.
- Make the fixed-seed XOR study process-reproducible by replacing randomized `HashMap`
  entropy reduction with deterministic key order; the corrected 0.4/1.0 compatibility
  stdout hashes and reported tables are identical.
- Count raw-scalar bootstrap KSG confirmation work in conservative quadratic scan units
  in both the engine and evaluation-suite preflights, instead of mixing whole-call and
  inner-scan units in one resource budget.
- Pass the intended Rust 1.89 MSRV and current-stable channels explicitly to the pinned
  toolchain actions, avoiding an unused action-default toolchain installation.
- Keep pull-request mutation testing bounded without excluding changed evaluation code. The
  unmodified workspace baseline previously timed out before testing any mutant because seven
  deliberate Monte Carlo campaigns exceed the per-mutant deadline; normal CI still runs those
  campaigns, while mutation trials use the fast unit/invariant suite across every package.
- Preserve a complete conflict-free signed-correlation attribution when partial positive
  PID evidence names the same channels; optional PID insufficiency cannot erase the
  independently assessable signed default, while PID-only partial evidence still fails closed.
- Reject duplicate JSON keys on the live sidecar path: payloads now deserialize directly
  into the typed envelope instead of through a `serde_json::Value` intermediate, which
  collapsed repeated keys (last occurrence wins) before `deny_unknown_fields` could reject
  them — a parser differential with first-wins JSON consumers on a security boundary.
- Print the advisory `calibrated_posterior=false` footer on `replay` output, matching the
  demo; a real-capture replay previously ended with bare per-track verdicts.
- Impose explicit policy ceilings on alignment sequence gaps and timestamp skew (with zero
  documented as exact timestamp equality) so `u64::MAX` cannot silently disable temporal
  comparability in streaming or direct extraction APIs.

### Documentation

- Replace production-readiness, feature-complete, mutable test-count, private-sibling, and
  split-MSRV claims with the current research-prototype status.
- Correct the crebain integration claim. Normal `CREBAIN_PID_JSONL` captures do not enable
  innovation/covariance research fields. Radar residuals are polar while visual/acoustic
  residuals are Cartesian; sequential filter updates do not share a common frozen prior;
  and association/gating censors misses and rejected measurements.
- Reclassify the bundled crebain fixture as bounded parsing and baseline smoke evidence.
  It is not a valid cross-modal correlation/PID validation capture; correlation and fused
  assessment correctly remain `InsufficientEvidence`.
- Document that the Zenoh live tap now uses NCP's sensor-plane ACL and a versioned envelope,
  while remaining non-operational until Crebain publishes it and mTLS/heartbeat behavior is
  verified end to end.
- Document that per-channel silence requires another channel to advance assessment time and
  all-modal silence requires an external producer/transport heartbeat.
- Add the producer roadmap: common frozen prior, common frame, explicit miss/rejection
  events, heartbeat, stable session identity, and a versioned schema.
- Align CONTRIBUTING's `cargo deny` invocation with CI (`--all-features --locked`).
- Correct citation integrity across `docs/`: remove two misattributed verbatim quotations
  (a Defense One "visual or inertial position data" line and a fabricated survey
  "defensive toolkit" quote); correct the SoK author from "Ren et al." to "Xu et al." with
  its full title and IEEE EuroS&P 2023 venue; drop an unsupported "below 10% under heavy
  jamming" statistic; restore the exact Hallyburton frustum-attack quotation; and replace a
  dead EurekAlert URL. Remove phantom `[Liu2011]`/`[Mo2010]` reference keys, correct
  `RELATED-WORK.md`'s key-provenance note, and cite `[Gao2018]`/`[WilliamsBeer2010]` inline
  in `PAPER.md`.
- Disclose that at the fusion core's `dof = 3` with the default symmetric CUSUM slack the
  below-target arm is inert, so a moment-shrinking channel (over-conservative filter, replay,
  or frozen sensor) is not flagged by the magnitude layer at that operating point.
- Sharpen the temporal-calibration limitation: the Fisher-z significance floor assumes
  i.i.d. bivariate-normal pairs, so positive within-window autocorrelation makes a single
  assessment anti-conservative — distinct from the separate stream-level repeated-looks
  caveat.
- Note that the sequential study's detectors run at different realized false-alarm rates, so
  its latency column is not strictly iso-FAR, and clarify that `prior_id` non-reuse is a
  producer attestation enforced within each aligned frame/context window.
- Reorder the README's opening around the problem, architecture, one verified command,
  representative output, current evidence boundary, and then the full caveats.
- Distinguish the published post-audit streaming evidence slice from the still-pending
  full comparative AUC/adaptive/maneuver/collusion/latency/cost report, and clarify that
  Galadriel reports advisory evidence rather than controlling downstream weights.

### Added

- `UnclassifiedAnomaly` verdicts for positive evidence that cannot support a localized or
  broad attribution.
- Expected-modality registration and freshness reporting.
- Explicit maximum sequence gap and maximum active-track configuration.
- Full JSONL/live-ingest limits and sequence validation.
- Supply-chain policy and comprehensive security/review artifacts.
- A bounded common-projection wire field with physical-frame, projection-context, and
  frozen-prior provenance, plus bounded multi-axis extraction and reporting APIs.
- A canonical autocorrelation-null study in `galadriel-justify`: two independent AR(1)
  channels measure how positive within-window autocorrelation inflates the naive Fisher-z
  significance floor's false-positive rate at the runtime default window, and show that a
  Bartlett (1935) effective-sample-size correction improves moderate-persistence calibration
  but becomes conservative when `phi = 0.9` leaves a small effective sample. Tests assert the
  `phi = 0` calibration check, naive inflation, moderate correction, and finite-sample limit; the
  runtime floor intentionally remains uncorrected pending a registered phi-estimation
  design (`docs/JUSTIFICATION.md` §5, `docs/PAPER.md` §7).
- A regression test proving the live sidecar path rejects duplicate JSON keys as a typed
  `Data` error while a `serde_json::Value` round-trip would have accepted them last-wins —
  the parser differential closed in this release.
- A strict, machine-readable `galadriel_pid_observation` schema-`1.0` live envelope carrying
  NCP version/hash, session, producer, and the frozen Crebain-compatible observation payload;
  undeclared envelope and nested observation fields are rejected. Because `PidObservation`
  itself now rejects unknown fields, this tightening applies to every ingest path, including
  bounded JSONL replay.
- A one-command `galadriel-evidence` runner with explicit versioned configuration,
  commit/toolchain manifest, per-trial JSONL, holdout-only summaries, stream metrics,
  provenance-abstention arms, a human report, and checksums.
- A clean-source, commit-bound evidence snapshot whose high repeated-look false-alert
  rates and missingness abstention are retained as non-production calibration findings.
- Cargo-fuzz targets for NCP/JSONL decoding and stateful detector/projection boundaries,
  plus a strict pull-request mutation diff, an observational scheduled mutation baseline,
  and a current-stable CI lane alongside the pinned MSRV.
- `CITATION.cff` for commit-exact citation of the research prototype.

### Known limitations

- Current evidence is synthetic; there is no field-validated detection or false-alarm rate.
- Current crebain output does not satisfy the common-frame/common-prior estimand required for
  cross-channel correlation or PID.
- Association and chi-square gating make the observed accepted-update stream selection-biased;
  a strong attack may appear as missingness.
- A consistency-preserving adversary and a colluding majority remain fundamental blind spots.
- PID delete-block confirmation is approximate and conditional on the selected same-window
  clique; it is not formal selective inference or fleet-level calibration.
- The optional Zenoh live dependency retains an ignored compression advisory until upstream
  can be upgraded; CI verifies that the affected feature is disabled and expires the
  exception on 2026-10-01.
- All-modal silence is invisible without an external heartbeat.
- Galadriel remains advisory and must not be wired as an automatic control veto.
