# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before `1.0`, minor releases
may contain breaking changes.

## [Unreleased]

## [0.9.0] - 2026-07-21

### Release contract

- Establish the first reviewed research release under author Sepehr Mahmoudian, with
  an explicit GitHub-source-only scope and no DOI, Zenodo, crates.io, deployment, or
  production-support claim.
- Bind the current standalone handoff by full archive/task-ledger SHA-256 while adapting
  its complete technical and evidence obligations to the requested 0.9.0 identity;
  remove the superseded embedded handoff so inherited prose cannot be mistaken for proof.
- Add a generated immutable audit manifest, four-tier claims matrix, exact statistical
  contract, threat model, stable-core API policy, requirement/evidence ledger, and
  protected-main change-control policy.
- Add semantic verification for the signed, canonical frozen-input manifest and an
  acyclic exact-candidate closure protocol: bounded no-follow input snapshots, signed
  qualification/review/decision/task records, schema-validated local convergence,
  signed closure inventory, checksums, flushed same-parent staging, and atomic
  no-replace publication. Qualification artifacts cannot occupy the closure `inputs/`
  or convergence namespaces, and the NCP feature report records checker-tooling and
  runtime-pin identities separately.
- Add a verdict-independent authority-effect validator proving record-only and
  monotonically restrict-only consumer transitions; `Nominal` cannot grant authority,
  relax a limit, extend TTL/lease, refresh a watchdog, or change capabilities.
- Remove the accidental public chi-square implementation module; consumers use typed
  detector reports rather than binding to a numerical backend.

### Security

- Add a deterministic exact-epoch Zenoh profile renderer/checker: mTLS-only clients,
  default-deny router ACL, exact producer/observer certificate CNs, directional
  producer-put and observer-subscribe/delivery rules on only the two evidence keys,
  bounded transport messages, a hashed application/registry handoff, preflighted and
  individually atomic owner-only output, duplicate-key and credential-path rejection,
  digest manifest, absolute production credential paths, atomic no-replace publication,
  alias-safe credential identity, owner-only private-key modes, and 67 security regression
  checks. The runbook explicitly keeps real-router wrong/no-certificate and allow/deny
  results as an external evidence gate.
- Add a secure-only operational observer constructor and CLI. All Galadriel-owned secure
  live paths single-load the configuration, require connector-side client-certificate
  presentation plus the complete local strict profile, and open that same parsed value.
  Caller-supplied buses are separately labeled inherited/unverified; local validation is
  never presented as proof of a remote router's active ACL.
- Disclose the pinned Zenoh 1.9 client trust asymmetry: server authentication uses the
  built-in public WebPKI roots plus the configured deployment CA, so exclusive custom-CA
  router pinning is `NOT_CLAIMED`. Router-side client mTLS remains constrained by its
  configured CA; deployments use a non-publicly-issuable private router name with
  controlled resolution or add external exact-certificate/SPKI pinning.
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
- Fence operational callback entry, startup activation, and shutdown with one ingress-state
  lock; drain registered startup callbacks before activation; and retain the first terminal
  fault while discarding already-materializing post-close payloads. Async close can resume
  cleanup after cancellation, implicit Drop accounts buffered discards, and an owned monitor
  tap refuses transport close while a scoped receiver is active. Deterministic race/lifecycle
  tests cover callbacks paused before classification, inside materialization, at the close
  fence, and receiver-before-tap cleanup ordering.

### Added

- Add an immutable, strict, deployment-pinned frame/projection registry with canonical
  JSON SHA-256, applicability and source-frame bindings, global content-identifier
  consistency, versioned projection-algorithm identity, deterministic opportunity caps,
  and a frozen Galadriel-side fixture historically verified byte/hash-identical with
  Crebain `4c311900ade5668200a48d56fb191be1916b884a`. That historical pairing does not
  qualify the current candidate across repositories.
- Add `CrossRouteAssembler`: bounded observation/monitor joining, canonical byte
  accounting, global prior-reuse rejection, contiguous event sequencing, registry and
  gate-accounting verification, transactional frame closure, and exact frame/reorder/
  heartbeat deadlines. The initial heartbeat has a separate finite startup grace;
  immutable summary ledgers are cached for constant-time later joins; lifetime replay
  capacity is exposed for coordinated pre-exhaustion epoch rollover.
- Add `LifecycleDetector`, which evaluates only lifecycle-complete frozen tracks and
  immediately abstains/clears a track suffix on an explicit miss, rejection, or
  incomparable projection. Its aggregate retained-observation state is capped across
  detector/correlation configurations.
- Add the `ncp-live` `galadriel observe` service and `OperationalLiveReceiver`: one shared
  Zenoh session, two exact subscriptions, one serialized bounded nonblocking ingress,
  first-fault delivery boundary, coherent health counters, and in-process valid/silence/
  saturation/provenance/decode/deadline tests.
- Retain exact raw Zenoh subscriber guards in the monitor and operational receivers so
  close/drop undeclares only their selectors, partial startup rolls back, timer state is
  cancelled, and a host-owned shared session remains open.
- Retain a historical compatibility fixture for an opt-in Crebain normal-runtime producer
  baseline: one immutable
  pre-association prior, registered Cartesian residuals, explicit lifecycle records,
  bounded ordered publisher lanes, frame summaries, independent heartbeat, and strict
  registry/configuration/executable pins. Crebain
  `4c311900ade5668200a48d56fb191be1916b884a` recorded Galadriel
  `81437d807ca83b66b45c8353968948e540072d97`; both identities predate this 0.9.0
  candidate. A current reciprocal pin and final cross-repository qualification are
  `NOT_CLAIMED`. Historical JSONL captures remain baseline-only.
- Add the separate strict `galadriel_producer_event` monitor wire contract on
  `sensor/galadriel-monitor`: bounded encode/decode, heartbeat health, typed modality
  outcomes and misses, frozen-prior/frame/context provenance, strict gate-method
  evidence, frame closure counts, registry digest binding, JSON-safe identities,
  contiguous operational sequencing, a matching JSON Schema, and golden/negative tests.
- Require canonical NCP version spelling, common-frame evidence on every `updated`
  outcome, gate evidence on every gate-dependent disposition, and global prior-reuse
  detection even for modalities excluded from a requested analysis.
- Record the normative two-route producer and lifecycle contract, including common-frame
  frozen-prior semantics, fresh process epochs, fail-closed cross-route assembly,
  backpressure/loss behavior, mTLS/ACL identity binding, and five-lens acceptance evidence.
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

- Replace the stale producer/runtime roadmap with a truthful split between implemented
  Galadriel consumer components and the historical Crebain/Galadriel compatibility fixture.
  The old commit pair is not a reciprocal pin of the current candidate; current
  cross-repository qualification, a real multi-process mTLS/ACL campaign, and an independent
  recorded stream-calibration study remain `NOT_CLAIMED`.
- Add a dated exact-cut ecosystem record for pid-rs, NCP, Crebain, Haldir, and Prisoma
  that separates immutable dependency pins, byte/schema fixture compatibility, mutable
  audit heads, prospective downstream relationships, and missing reciprocal/deployment
  qualification. Record pid-rs activation, its same-revision `pid-runlog` edge, and the
  absence of a published upstream 1.x claim. Clarify that NCP wire 1.0 is
  unreleased/proposed, Haldir has no runtime adapter, and Prisoma's base-route observer
  rejects Galadriel's named sidecars. Preserve Haldir's discovery-head observation at
  `0e94f61cfd5c78482198a765157571746a256181` and the later 2026-07-18 reinspection at
  descendant `dd3d8a1c993721f89a1edb04dec5247761c694ad`; the later value supersedes only
  the mutable discovery-head reference and does not rewrite frozen or historical evidence.
  Bind the same objects and relationship semantics in a machine-readable ecosystem cut.
- Split the unchanged strict changed-Rust mutation set into four deterministic CI shards so
  feature-sized diffs complete within the bounded job window. Add exact lifecycle identity,
  inclusive capacity/channel, history-clear, nested-endpoint, whitespace-path, and Unix
  private-key-mode regressions for every survivor found by the pre-merge mutation audit.
- Close the receiver, registry, assembler, and observer-CLI mutation gaps with exact size and
  sequence boundaries, distinct malformed/oversized fault taxonomy, state-accessor and
  heartbeat telemetry assertions, frame-ledger birth/attempt/miss truth tables, deep registry
  projection snapshots, and a real process-exit test that proves observe errors reach `main`.
- Migrate the exact `pid-core` pin from 0.4.0 (`ad489f5…`) to immutable pid-rs revision
  `1cd2424…`, whose manifest declares 1.0.0 but which has no public v1 tag or released
  upstream 1.x artifact; opt into its explicitly experimental continuous
  surface, adopt its report-first KSG point gate and caller-declared support contract,
  and attach exact dependency/scientific-status/noise/seed evidence to PID reports.
  The fixed-seed 0.4→1.0 reproduction and delta dispositions are recorded in
  `docs/PID_RS_1_0_MIGRATION.md` and `evidence/pid-rs-1.0-migration.json`.
- Raise the workspace MSRV to Rust **1.89** and pin that toolchain. The pinned
  pid-rs revision requires Rust 1.89; the previous Rust 1.88 pin cannot build the
  migrated graph.
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
  records the NCP 0.8 compatibility basis used by the retained historical Crebain and
  Prisoma fixture revisions. In that fixture, only Crebain published the Galadriel sidecar;
  Prisoma consumed normative NCP sensor frames. NCP's `check_version` is an exact
  major.minor fail-closed gate, so a
  0.7-stamped payload would be hard-rejected by 0.8 peers.
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

- Make Wilson binomial intervals conservatively contain the exact rational point estimate
  for every valid machine count, including counts beyond `f64`'s exact-integer range; use
  failure-side symmetry and outward-rounded complements to prevent near-one intervals from
  collapsing under floating-point roundoff.
- Fail closed when acceptance evidence supplies a numeric value that cannot be represented
  as finite binary64, a negative rate or delay, or a probability point estimate or
  confidence interval outside `[0, 1]`, while preserving the distinct nonnegative domains
  of rates and delays.
- Make release and deployment JSON tooling reject duplicate members, nonstandard constants,
  non-finite or underflowing floats, malformed UTF-8, and resource-exhausting integer
  tokens through controlled domain errors. Exact retained `u64` provenance remains valid;
  binary64-safe or narrower integer limits are enforced only by schemas that require them.
- Make monitor gaps expire after a positive bounded receipt-time deadline even if no
  later sample arrives; preserve raw receipt time while exposing a nondecreasing ordered
  time for direct assembler composition, and serialize fault/handoff state so queued or
  concurrent work cannot cross the first terminal boundary.
- Prevent a lifecycle-complete frame carrying an explicit per-modality absence from
  inheriting the previous frame's fresh detector window and appearing nominal.
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
- Preserve finite signed-negative KSG estimates from the pinned pid-rs revision as
  valid low-dependence evidence. The upstream default intentionally allows finite-sample
  negative estimates; rejecting them had converted decoupled edges into false estimator
  insufficiency.
- Make the fixed-seed XOR study process-reproducible by replacing randomized `HashMap`
  entropy reduction with deterministic key order; the corrected 0.4/1.0 compatibility
  stdout hashes and reported tables are identical.
- Count raw-scalar bootstrap KSG confirmation work in conservative quadratic scan units
  in both the engine and evaluation-suite preflights, instead of mixing whole-call and
  inner-scan units in one resource budget.
- Pin the generated Rust 1.89 MSRV action revision and select current stable explicitly. The
  version-specific action encodes 1.89 itself and therefore receives only its supported component
  inputs, avoiding both an ignored `toolchain` warning and installation of the former 1.88 MSRV.
- Keep pull-request mutation testing bounded to runtime packages. The unmodified workspace
  baseline previously timed out before testing any mutant because the deliberate Monte Carlo
  evaluation and justification harnesses exceed the per-mutant deadline; the evidence publisher
  also correctly rejects cargo-mutants' temporary dirty worktree. Those harnesses remain covered
  by the ordinary all-feature CI matrix and their dedicated assertions.
- Add mutation-resistant regressions for KSG report classification, observation-noise boundaries,
  deterministic PID atom diagnostics, partial-PID/signed-default fusion, and CLI evidence labels
  and demo output; remove an observationally redundant fusion conjunct exposed by the audit.
- Bind the pid-rs migration evidence to PR #16's actual squash-landed `main` commit and tree while
  retaining the audited source-snapshot identities that produced the paired compatibility run.
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
- Bind each accepted whole-stream default assessment to the complete release-suite identity
  and every exact ordered observation field. Sealed default reports and all component axes
  share the opaque `AssessmentBinding`; compatibility component fusion remains explicitly
  unbound and cannot mint an accepted report. PID assessments add a nested binding to the
  complete research suite.
- Replace implicit lifecycle clearing on accepted operational paths with typed positioned
  admission, explicit reset/timeout/rollover operations, and bounded hash-linked receipts.
  Legacy convenience entry points are compatibility adapters and do not claim new NCP wire
  fields or durable receipt persistence.
- Freeze strict-JSON lifecycle receipt interchange behind a 16 KiB-inclusive decode gate.
  Assessment digests bind the accepted suite and complete serialized reports, while
  `Faulted { reason }` binds the exact returned reason; internal digest verification is
  explicitly neither writer authentication nor durable chain retention.
- Bound secure startup inputs before foreign parsing: standalone strict-JSON configuration
  is capped at 256 KiB inclusive, Zenoh `__config__` external includes are rejected, and
  each credential file is capped at 1 MiB inclusive at validation time.
- Advance generated trial records to `galadriel.evidence.trial.v3`: every synthetic
  per-trial seed is an exact decimal string with a fixed-width hexadecimal mirror.
  Candidate `base_seed` input is likewise a decimal string; legacy JSON integer input is
  accepted only for the retained historical configuration, and normalized accepted output
  carries canonical decimal and hexadecimal seed strings.
- Preflight maneuver grids and complete exposure before generation: unique bounded lags,
  finite positive magnitude, nonzero duration, checked per-modality window ends, and fixed
  grid/trial/observation work ceilings reject malformed or right-censored studies.

### Documentation

- Add an explicit README ecosystem-boundary matrix for pid-rs, NCP, Crebain, Haldir, and
  Prisoma; distinguish optional build dependencies, upstream transport/producer
  relationships, the unimplemented downstream advisory-publisher boundary, and the
  absence of a direct Prisoma sidecar edge without upgrading any cross-repository claim.
- Use one `{epoch}` route template, label false-alert exposure consistently per track-hour,
  and align the NCP feature declaration and accepted API-snapshot wording with the code and
  retained release records.
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
  while producer/consumer component coverage remains non-operational until a real
  multi-process mTLS/ACL campaign verifies delivery and heartbeat behavior end to end.
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
  `docs/RELATED-WORK.md`'s key-provenance note, and cite
  `[Gao2018]`/`[WilliamsBeer2010]` inline in `docs/PAPER.md`.
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
- The bundled historical Crebain capture does not satisfy the common-frame/common-prior
  estimand required for cross-channel correlation or PID; the retained historical producer
  fixture has no accepted recorded calibration artifact and does not qualify a current
  reciprocal integration.
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
