# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before `1.0`, minor releases
may contain breaking changes.

## [Unreleased]

### Security

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

### Changed

- Raise the workspace MSRV to Rust **1.88** and pin that toolchain. The previous Rust 1.80
  claim was incompatible with the locked dependency graph.
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
- Migrate the NCP integration to the 0.7 wire revision and pin `ncp-core`/`ncp-zenoh`
  to the immutable commit corresponding to the public `v0.7.1` tag.

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
- Reject duplicate JSON keys on the live sidecar path: payloads now deserialize directly
  into the typed envelope instead of through a `serde_json::Value` intermediate, which
  collapsed repeated keys (last occurrence wins) before `deny_unknown_fields` could reject
  them — a parser differential with first-wins JSON consumers on a security boundary.
- Print the advisory `calibrated_posterior=false` footer on `replay` output, matching the
  demo; a real-capture replay previously ended with bare per-track verdicts.

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

### Added

- `Anomaly` verdicts for positive evidence that cannot honestly be classified as a targeted
  spoof or broad jam.
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
