# Changelog

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| AR(1) | first-order autoregressive model |
| API | application programming interface |
| AUC | area under the receiver operating characteristic curve |
| CA | certificate authority |
| CI | continuous integration |
| CLI | command-line interface |
| CN | certificate common name |
| CUSUM | cumulative sum |
| DoF | degrees of freedom |
| DOI | digital object identifier |
| `et al.` | and others |
| EuroS&P | European Symposium on Security and Privacy |
| FAR | false-alarm rate |
| IEEE | Institute of Electrical and Electronics Engineers |
| JSON | JavaScript Object Notation |
| JSONL | JavaScript Object Notation Lines |
| KSG | Kraskov-Stögbauer-Grassberger |
| mTLS | mutual Transport Layer Security |
| MSRV | minimum supported Rust version |
| NaN | not a number |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |
| ROS / ROS 2 | Robot Operating System / Robot Operating System 2 |
| SBOM | software bill of materials |
| SHA | Secure Hash Algorithm |
| SHA-256 | Secure Hash Algorithm 256 |
| SoK | systematization of knowledge |
| SPKI | Subject Public Key Info |
| SSH | Secure Shell |
| TTL | time to live |
| URL | Uniform Resource Locator |
| UTF-8 | 8-bit Unicode Transformation Format |
| WebPKI | Web Public Key Infrastructure |
| XOR | exclusive OR |

This file documents all notable project changes.
It uses the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before `1.0`, minor releases can contain breaking changes.

## [Unreleased]

## [0.9.0] - 2026-07-24

### Release contract

- Establish the first review-gated GitHub research source release under author Sepehr Mahmoudian.
  Give it an explicit GitHub-source-only scope.
  Make no DOI, Zenodo, crates.io, deployment, or production-support claim.
- Bind the current standalone handoff by the full archive and task-ledger SHA-256 values.
  Adapt all its technical and evidence obligations to the requested 0.9.0 identity.
  Remove the superseded embedded handoff.
  Thus, readers cannot treat inherited prose as evidence.
- Add a generated immutable audit manifest and a four-tier claims matrix.
  Add an exact statistical contract, threat model, and stable-core API policy.
  Add a requirement and evidence ledger and a protected-main change-control policy.
- Add semantic verification for the signed canonical frozen-input manifest.
  Add an acyclic exact-candidate closure protocol.
  The protocol uses bounded no-follow input snapshots and signed qualification, review, decision, and task records.
  It also uses schema-validated local convergence, a signed closure inventory, and checksums.

  It requires flushed same-parent staging and atomic no-replace publication.
  Qualification artifacts cannot occupy the closure `inputs/` or convergence namespaces.
  The NCP feature report records checker-tooling and runtime-pin identities separately.
- Bind every published JSON Schema identifier to the immutable `v0.9.0` raw-tag URL.
  Release consumers never resolve a schema identity through the mutable default branch.
- Add deterministic public release packaging for the qualification and closure tiers.
  The package contains two path-preserving uncompressed tar files.
  It also contains a canonical exact-candidate, tree, and tag asset map with a detached SSH signature.

  Build, verification, and reconstruction now authenticate both internal tier signatures.
  They bind each tier to the expected candidate commit and tree.
  They also verify the complete signed inventory and each `SHA256SUMS` file.

  Verification rejects extra, missing, linked, or special input.
  It rejects input with path traversal, duplicates, or incorrect order.
  It also rejects oversized or noncanonical input.
  It rejects input that changes during verification.

  Strict UTF-8 tar names do not depend on locale.
  Safe reconstruction never gives path handling to the archive library.
  Release publication pins canonical asset construction, verification, and reconstruction to CPython 3.14.6.
  It compares all four downloaded upload files at the byte level.
- Bind retained supply-chain reports to the exact stream that each pinned tool uses.
  Capture `cargo-deny` 0.19.9 license JSON from stderr with byte-empty stdout.
  Capture `cargo-audit` JSON from stdout and retain its stderr as diagnostics.
  Finalization rejects stream swaps, unexpected deny output, and malformed diagnostics.
  It also rejects report identities that differ from the signed artifact inventory.
- Advance exact-candidate qualification to `galadriel.candidate-qualification.v3`.
  Require an independently obtained allowed-signers file.
  Require a clean external clone of the exact pinned RustSec database.
  Freeze that database identity on 2026-07-23.
  Bind its origin, commit, tree, 1,187-entry inventory, and inventory digest.
  Retain exactly 22 auxiliary command receipts with command, sandbox, exit, log, and stream bindings.

  Add a stop-before-exec launch gate and fixed process resource limits.
  Track the process group and scan for the inherited sandbox identity on macOS.
  Record the non-atomic short-lived process race.
  Record that the scan cannot attribute existing external-service work.
- Run exact-candidate qualification with a 16-key base environment.
  Isolate home, Cargo, target, and temporary state in a private root.
  Remove ambient credentials, proxies, wrappers, loader variables, and compiler flags.
  Reject a file, directory, or link at each Cargo configuration path before and after each retained command.
  Bind the environment policy in the signed qualification record.
- Refresh public `main` before candidate comparisons and again before a result returns.
  Use the literal public repository URL and exact `main` refspec.
  Disable credential use, tags, submodules, pruning, maintenance, commit-graph writes, and `FETCH_HEAD` writes.
  Reject local Git settings that can redirect the fetch, run a helper, or weaken object checks.
- Retain exactly six flat candidate-evidence files after a successful evidence command.
  Apply a 1 GiB per-file limit and a 4 GiB aggregate limit before retention.
  Stream the files into a private host snapshot without following links.
  Compare the source, snapshot, quarantined source, and installed snapshot.
  Parse only the bounded JSON bytes captured from the verified snapshot.
  Only a deep qualification run can have qualification status `PASS`.
- Pin current-stable qualification and continuous integration checks to Rust and Cargo 1.97.1.
  Preserve Rust 1.89.0 as the workspace minimum supported Rust version.
- Add exact semantic validation for retained release artifacts.
  Bind the 437-package metadata graph to `Cargo.lock`.
  Bind source-archive types, modes, owners, times, and content to the exact Git tree.
  Bind every package member byte and mode to the exact tracked crate-file map.
  Close each SBOM identity, component, and dependency field against the validated Cargo graph.

  Compare one source archive, seven package archives, and seven SBOM documents across two runs.
  Retain all 15 comparisons.
  Bind the license inventory to the exact 382-package `CARGO_DENY_HOST_FILTERED_GRAPH` subset.
  This host-filtered evidence does not describe the complete 437-package graph on another target.
  The author-operated same-host comparisons do not prove independent or cross-platform reproduction.
- Add a focused 26-mutant acceptance-estimation gate.
  Require 23 caught mutants and three exact compile-unviable replacements.
  Permit no missed, timed-out, or surviving mutant.
- Add exact isolated execution receipts for all mutation gates.
  Retain 13 signed artifacts.
  These artifacts contain seven outcome files, five run receipts, and one exact `git.diff`.
  Four receipts bind the broad shards.
  One receipt binds the three focused outcomes.
- Add a verdict-independent authority-effect validator.
  It proves record-only and monotonically restrict-only consumer transitions.
  `Nominal` cannot grant authority, relax a limit, or extend TTL or lease.
  It cannot refresh a watchdog or change capabilities.
- Remove the accidental public chi-square implementation module.
  Consumers use typed detector reports instead of a numerical backend.

### Security

- Add a deterministic exact-epoch Zenoh profile renderer and checker.
  It configures mTLS-only clients and a default-deny router ACL.
  It uses exact producer and observer certificate CNs.
  Directional rules permit producer `put` and observer subscription and delivery only on the two evidence keys.
  It bounds transport messages and creates a hashed application and registry handoff.

  It checks outputs before it writes them.
  It writes each output atomically with owner-only access.
  It rejects duplicate keys and invalid credential paths.
  It produces a digest manifest and requires absolute deployment credential paths.
  It uses atomic no-replace publication and alias-safe credential identity.

  It requires owner-only private-key modes and a maintained security regression suite.
  The runbook keeps real-router wrong-certificate, no-certificate, allow, and deny results as an external evidence gate.
- Add a secure-only operational observer constructor and CLI.
  All Galadriel-owned secure live paths load the configuration once.
  They require connector-side client-certificate presentation and the complete local strict profile.
  They open the same parsed value.
  Caller-supplied buses have a separate inherited or unverified label.
  Local validation never proves the active ACL of a remote router.
- Disclose the pinned Zenoh 1.9 client trust asymmetry.
  Server authentication uses built-in public WebPKI roots and the configured deployment CA.
  Thus, exclusive custom-CA router pinning is `NOT_CLAIMED`.
  The configured CA still constrains router-side client mTLS.
  Deployments use a private router name that a public authority cannot issue.
  They control name resolution or add external exact-certificate or SPKI pinning.
- Refuse `SidecarTap::close()` on a tap that `from_bus` created.
  `ZenohBus` clones share one Zenoh session and one retained-subscriber registry.
  Without this refusal, a close from the tap can silently stop the **host's** complete transport.
  This stop affects all subscriptions, not only Galadriel subscriptions.

  A shared tap now returns a typed error. The host closes its own session.
  Taps that the `open*` constructors open still close normally.
- Bound sidecar `session_id` and `producer_id` to 64 bytes.
  The length bound matches the generic NCP 0.8 transport-neutral rule of 1..=64 bytes.
  Galadriel also requires its narrower ASCII core identity grammar.
  Thus, a generic NCP segment can still be invalid for a Galadriel envelope.
  The JSON Schema now uses `maxLength: 64`.
- Widen the CI compression guard for the `RUSTSEC-2026-0041` exception.
  Change it from `-p galadriel-ncp` to `--workspace --all-features --locked`.
  Thus, feature unification cannot silently enable `zenoh-transport/transport_compression` for a workspace member.
  The vulnerable `lz4_flex` decompression path has a `cfg` gate behind that feature.
  The compiler excludes the path while the guard holds.
- Document that `LiveLimits::max_payload_bytes` bounds decode work only.
  The transport copies a received message before the gate.
  Zenoh's own `max_message_size` defaults to 1 GiB.
  Thus, deployments must bound peak receive memory in the Zenoh configuration.
- Document the scouting-off property of `TransportMode::QuietDevelopment`.
  It applies to the hardened default NCP configuration.
  A configuration that `NCP_ZENOH_CONFIG` names supersedes it.
- Protect operational callback entry, startup activation, and shutdown with one ingress-state lock.
  Drain registered startup callbacks before activation.
  Retain the first terminal fault.
  Discard post-close payloads that already started materialization.

  Asynchronous close can resume cleanup after cancellation.
  Implicit `Drop` accounts for buffered discards.
  An owned monitor tap refuses transport close while a scoped receiver is active.
  Deterministic race and lifecycle tests pause callbacks before classification and during materialization.
  They also cover the close fence and receiver-before-tap cleanup ordering.

### Added

- Add an immutable, strict, deployment-pinned frame and projection registry.
  It uses canonical JSON SHA-256 and applicability and source-frame bindings.
  It enforces global content-identifier consistency and versioned projection-algorithm identity.
  It also applies deterministic opportunity caps.
  Add a frozen Galadriel-side fixture.
  Historical verification found it byte-identical and hash-identical to Crebain `4c311900ade5668200a48d56fb191be1916b884a`.

  This historical pair does not qualify the current candidate across repositories.
- Add `CrossRouteAssembler` with bounded observation and monitor joining.
  It supplies canonical byte accounting and global prior-reuse rejection.
  It enforces contiguous event sequencing and verifies registry and gate accounting.
  It supplies transactional frame closure and exact frame, reorder, and heartbeat deadlines.

  The initial heartbeat has a separate finite startup grace.
  Immutable summary ledgers support constant-time subsequent joins.
  The component exposes lifetime replay capacity for coordinated pre-exhaustion epoch rollover.
- Add `LifecycleDetector`.
  It evaluates only lifecycle-complete frozen tracks.
  An explicit miss, rejection, or incomparable projection causes immediate abstention and clears a track suffix.
  A cap applies to its aggregate retained-observation state across detector and correlation configurations.
- Add the `ncp-live` `galadriel observe` service and `OperationalLiveReceiver`.
  They use one shared Zenoh session and two exact subscriptions.
  They use one serialized bounded nonblocking ingress and a first-fault delivery boundary.
  They supply coherent health counters.
  In-process tests cover valid, silence, saturation, provenance, decode, and deadline cases.
- Retain exact raw Zenoh subscriber guards in the monitor and operational receivers.
  Close and drop operations undeclare only their selectors.
  Partial startup rolls back, timer state stops, and a host-owned shared session remains open.
- Retain a historical compatibility fixture for an opt-in Crebain normal-runtime producer baseline.
  It has one immutable pre-association prior and registered Cartesian residuals.
  It has explicit lifecycle records, bounded ordered publisher lanes, frame summaries, and an independent heartbeat.
  It also has strict registry, configuration, and executable pins.
  Crebain `4c311900ade5668200a48d56fb191be1916b884a` recorded Galadriel `81437d807ca83b66b45c8353968948e540072d97`.
  Both identities predate this 0.9.0 candidate.

  A current reciprocal pin and final cross-repository qualification are `NOT_CLAIMED`.
  Historical JSONL captures remain baseline-only.
- Add the separate strict `galadriel_producer_event` monitor wire contract on `sensor/galadriel-monitor`.
  It supplies bounded encode and decode and heartbeat health.
  It defines typed modality outcomes and misses with frozen-prior, frame, and context provenance.
  It includes strict gate-method evidence, frame closure counts, and registry digest binding.
  It enforces JSON-safe identities and contiguous operational sequencing.
  It has a matching JSON Schema and golden and negative tests.
- Require the canonical NCP version form and common-frame evidence on every `updated` outcome.
  Require gate evidence on every gate-dependent disposition.
  Detect global prior reuse even for modalities that a requested analysis excludes.
- Record the normative two-route producer and lifecycle contract.
  It includes common-frame frozen-prior semantics and fresh process epochs.
  It defines fail-closed cross-route assembly and backpressure and loss behavior.
  It also defines mTLS/ACL identity binding and five-lens acceptance evidence.
- Add an in-process Zenoh loopback end-to-end suite for the live leg.
  The file is `crates/galadriel-ncp/tests/live_zenoh_e2e.rs` and the feature is `zenoh`.
  A real `ZenohBus` round trip uses `SidecarTap` on the multi-segment `engram/ncp` realm.
  It proves decoded delivery with complete field fidelity and rejects wrong-session provenance.
  It rejects duplicate JSON keys during the typed parse.

  It proves size-gate-before-parse and `from_bus` realm derivation.
  It also proves shared-bus close refusal and health-counter semantics.
  This suite gives the first runtime evidence for the NCP live leg.
  Previously, only synthetic payload-delivery unit tests covered it.
- Re-export the exact pinned `ncp_core` from `galadriel-ncp`.
  Re-export `ncp_zenoh` when feature `zenoh` is active.
  Thus, hosts can build a shared bus for `SidecarTap::from_bus` without an accidentally divergent NCP revision.
- Document the session-epoch discipline of the sidecar relative to NCP 0.8.
  Control-plane sessions carry server-issued generations. The sidecar deliberately does not carry them.
  A producer restart mints a new `session_id` instead.

- Pin CI actions by commit SHA, grant read-only repository contents permission, disable
  persisted checkout credentials, and cancel superseded runs.
- Add Dependabot and `cargo-deny` policy for advisories, licenses, and sources.
- Remove the global Git credential rewrite that previously supported sibling repositories.
  The pinned `pid-rs` and `NCP` sources are public.
- Add common secret/key/certificate patterns to `.gitignore`.
- Bound JSONL record count and line size, live payload size, and per-stream tracking state.
- Validate NCP realms and identifiers as concrete key segments and count callback panics separately
  from decode failures.
- Make live sequence resets explicit serialized epoch boundaries with typed rejection of
  callback-context and in-flight-delivery reset attempts.
  This prevents reentrant deadlocks.
- Bind live payloads to the subscribed NCP session and expected producer.
  Reject incompatible NCP and sidecar versions and non-exact JSON integer identities.
  Expose advisory contract-hash drift.
  Keep the strength of the NCP version gate.
- Require callers to select strict mTLS `Secure` transport or explicitly unverified `QuietDevelopment` transport.
  The live tap no longer implies that a quiet default is secure.
- Carry a time-bounded exception for `RUSTSEC-2026-0041` only while CI proves Zenoh's
  vulnerable transport-compression feature remains disabled.
- Add a simple bounded live-observation handoff with a fixed `DropNewest` policy.
  It supplies reset generations, replay-safe overflow semantics, and queue, drop, and latency health metrics.
  The advanced inline callback API remains available.

### Changed

- Replace the stale producer/runtime roadmap with a truthful split between implemented
  Galadriel consumer components and the historical Crebain/Galadriel compatibility fixture.
  The old commit pair is not a reciprocal pin of the current candidate.
  Current cross-repository qualification remains `NOT_CLAIMED`.
  A real multi-process mTLS/ACL campaign remains `NOT_CLAIMED`.
  An independent recorded stream-calibration study also remains `NOT_CLAIMED`.
- Add a dated exact-cut ecosystem record.
  It covers pid-rs, NCP, Crebain, Haldir, Prisoma, Engram/Paper2Brain, ROS/ROS 2, and external authority.
  It includes explicit non-edges and the acyclic command and dataflow boundary.
  The boundary separates immutable dependency pins from byte and schema fixture compatibility.

  It also separates mutable audit heads, prospective downstream relationships, and missing reciprocal or deployment qualification.
  Record pid-rs activation and its same-revision `pid-runlog` edge.
  Record the absence of a published upstream 1.x claim.
  Clarify that NCP wire 1.0 is unreleased and proposed.
  Clarify that Haldir has no runtime adapter.
  Clarify that Prisoma's base-route observer rejects Galadriel's named sidecars.

  Preserve Haldir's discovery-head observation at `0e94f61cfd5c78482198a765157571746a256181`.
  Preserve the 2026-07-18 reinspection at descendant `dd3d8a1c993721f89a1edb04dec5247761c694ad`.
  Preserve the 2026-07-22 descendant `c0e4b3d156500684329a92bcb16e0609894fd738`.
  Preserve the 2026-07-23 descendant `590ba767b32a27d9dd61a2462968306c1052434e`.

  These changes explicitly record no runtime or external-conformance change.
  Each subsequent value supersedes only the prior mutable-head reference.
  It does not rewrite frozen or historical evidence.

  Preserve the 2026-07-23 Paper2Brain observation at `24e74b781a5bf8af069f69cbc2d0c42d89008211`.
  Record it as mutable provenance and an explicit integration non-edge.
  Bind the same objects and relationship semantics in a machine-readable ecosystem cut.
- Split the unchanged strict changed-Rust mutation set into four deterministic CI shards.
  This split lets feature-sized differences complete within the bounded job window.
  Add exact lifecycle-identity and inclusive-capacity and channel regressions for the pre-merge survivors.
  Add history-clear, nested-endpoint, whitespace-path, and Unix private-key-mode regressions for them.
  Add a noncentral odd-duration maneuver-slope regression for the final subtraction-to-division survivor.
- Close mutation gaps in the receiver, registry, assembler, and observer CLI.
  Add exact size and sequence boundaries and distinct malformed and oversized fault classes.
  Add state-accessor and heartbeat telemetry assertions.
  Add frame-ledger birth, attempt, and miss truth tables and deep registry projection snapshots.
  Add a real process-exit test that proves observe errors reach `main`.
- Migrate the exact `pid-core` pin from 0.4.0 (`ad489f5…`) to immutable pid-rs revision `1cd2424…`.
  Its manifest declares 1.0.0.
  But it has no public v1 tag or released upstream 1.x artifact.
  Select its explicitly experimental continuous surface.
  Adopt its report-first KSG point gate and caller-declared support contract.
  Attach exact dependency, scientific-status, noise, and seed evidence to PID reports.

  `docs/PID_RS_1_0_MIGRATION.md` and `evidence/pid-rs-1.0-migration.json` record the fixed-seed 0.4→1.0 reproduction and delta dispositions.
- Raise the workspace MSRV to Rust **1.89** and pin that toolchain.
  The pinned pid-rs revision requires Rust 1.89.
  The previous Rust 1.88 pin cannot build the migrated graph.
- Mark every package `publish = false`.
  The project now makes no crates.io release or production-support promise.
- Make public detector, simulator, PID, fusion, and serialization paths fail closed with `Result`.
  Previously, these paths accepted invalid data or configuration or could panic.
- Change the correlation default from absolute best-peer scoring to **signed Pearson
  correlation** with family-wise significance and one unique strict-majority positive
  consensus clique.
- Treat PID as additive, sign-invariant evidence. It no longer substitutes for signed
  geometry or allows a ready pair to hide an unassessable channel.
- Preserve magnitude, consistency, anomaly, and insufficient evidence during fusion.
  Do not silently drop one source. Do not create `Nominal`.
- Align cross-channel observations by exact sequence and track rather than ordinal tail
  position.
- Enforce frozen-prior uniqueness across the complete accepted bounded capture, not only
  the retained correlation tail.
- Require the optional producer-attested `ConsistencyProjection` for cross-channel work.
  Do not accept modality-native innovation vectors as an implicit common frame.
- Move the live sidecar from the unrecognized `.../galadriel/pid` key to NCP's ACL-covered
  named perception route `Keys::sensor_named(session, "galadriel-pid")`.
- Assess every active common-projection axis.
  Split applicable family-wise error budgets across axes.
  Fail closed if axis attribution conflicts or is partly insufficient.
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
- Print a mandatory synthetic-evidence banner at the top of `galadriel-eval` and `galadriel-justify` reports.
  The banner includes the seed and a provenance reminder.
  Thus, copied numeric output cannot appear to be an operational detection or false-alarm rate.
- Inherit the workspace `homepage`, `keywords`, and `categories` in every member manifest,
  and reference `galadriel-sim` through the workspace table in `galadriel-pid` dev-dependencies.
- Track the NCP wire through its pre-1.0 changes to the **0.8 wire revision**.
  Pin `ncp-core` and `ncp-zenoh` to the immutable commit for public tag `v0.8.0`.
  The short commit is `2f5bd58`, and the contract hash is `d1b50a2d8a265276`.
  This pin superseded an earlier `v0.7.1` pin in this cycle.

  The sidecar now stamps `ncp_version` `"0.8"`.
  The `PidObservation` payload shape is unchanged.
  Thus, this is a wire-addressing and version change, not payload re-versioning.

  It records the NCP 0.8 compatibility basis for the retained historical Crebain and Prisoma fixture revisions.
  In that fixture, only Crebain published the Galadriel sidecar.
  Prisoma consumed normative NCP sensor frames.
  NCP's `check_version` is an exact major.minor fail-closed gate.

  Thus, 0.8 peers reject a payload stamped with 0.7.
- Document Galadriel's downstream advisory boundary in [`docs/ADVISORY-BOUNDARY.md`](docs/ADVISORY-BOUNDARY.md).
  The contract applies to each consumer.
  A Haldir-style authorization gate is one such consumer.
  The evidence is non-authoritative and record-only until independent calibration.
  It never widens `ALLOW`.

  After independent admission, it permits only monotonic restrictions.
  The contract prohibits a synchronous feedback loop.
  It prohibits self-asserted calibration and a `StateUnusable` verdict.
- Clarify that "signed" (the sign of the correlation) and "producer-attested" (a provenance
  claim on the projection input) are not cryptographic signatures (README intro).
- Remove the former `Mirror::new` and `Mirror::with_modalities` constructors.
  The former `Mirror::new` had no expected-modality set.
  A sensor subset could reach `Nominal`.
  Release code now uses `ReleaseSuite` and `Mirror::from_release_suite`.
  Explicit subset research uses `Mirror::for_exploratory_subset`.
- Record that the `galadriel-pid` sidecar route and kind name is historical.
  PID is now optional.
  Defer a rename to the next sidecar-schema version change.
- Rename detector verdicts that suggest a cause to evidence-neutral
  `AttributedInconsistency`, `BroadDegradation`, `UnclassifiedAnomaly`, and `Decoupled`.
  Baseline-verdict JSON serialization uses the new tags while deserialization accepts the
  legacy `spoof`, `jam`, and `anomaly` tags for compatibility.
- Replace the contradictory public fusion slice-plus-boolean input with typed `ConsistencyEvidence`.
  Positive attribution is nonempty by construction.
  Explicit conflicts always fail closed.

### Fixed

- Make Wilson binomial intervals conservatively contain the exact rational point estimate for every valid machine count.
  This rule includes counts beyond the exact-integer range of `f64`.
  Use failure-side symmetry and outward-rounded complements.
  These methods prevent the collapse of near-one intervals because of floating-point rounding.
- Fail closed when acceptance evidence supplies a numeric value that finite binary64 cannot represent.
  Also fail closed for a negative rate or delay.
  Reject a probability point estimate or confidence interval outside `[0, 1]`.
  Preserve the distinct nonnegative domains of rates and delays.
- Make release and deployment JSON tools reject duplicate members and nonstandard constants.
  Reject non-finite floats, floats with underflow, and malformed UTF-8.
  Reject integer tokens that exhaust resources through controlled domain errors.
  Exact retained `u64` provenance remains valid.
  Only schemas that require binary64-safe or narrower integers enforce those limits.
- Make monitor gaps expire after a positive bounded receipt-time deadline without a subsequent sample.
  Preserve raw receipt time.
  Expose a nondecreasing ordered time for direct assembler composition.
  Serialize fault and handoff state.
  Thus, queued or concurrent work cannot cross the first terminal boundary.
- Do not let a lifecycle-complete frame with an explicit per-modality absence reuse the previous fresh detector window.
  Such a frame must not appear nominal.
- Reject non-finite or negative NIS and invalid degrees of freedom.
  Reject malformed innovation and covariance pairs.
  Reject covariance that is not positive-definite.
  Reject duplicate or out-of-order sequences.
  Reject changed DoF, mixed tracks, invalid axes, and degenerate channel series.
- Bound detector track state and add explicit track removal and clear operations.
- Do not let floating-point overflow or NaN become perfect correlation.
- Do not count negative or sign-flipped correlation as corroboration.
- Require all configured and expected modalities to be fresh and assessable before the detector returns `Nominal`.
- Separate high-direction inflation from lower-direction or otherwise non-attributable
  anomaly evidence.
- Domain-separate PID jitter so constant or duplicate channels cannot acquire fabricated
  dependence from identical noise.
- Validate bootstrap counts and block sizes.
  Keep failed resamples inconclusive. Do not replace them with optimistic values.
- Exclude pre-onset alarms from time-to-detect.
  Stop the presentation of pointwise parameter-grid intervals as simultaneous evidence of a win somewhere.
- Preserve replay histories for alarms and insufficient evidence.
  Preserve them for rejected consistency frames.
  Continue preservation when a subsequent clean tail recovers to a nominal terminal verdict.
- Evaluate CLI replay and PID demo terminal reports across every attested projection axis.
- Separate adaptive-study threshold calibration from clean holdout measurement and make
  bootstrap intervals target the same alarm-ranked AUC statistic as the main report.
- Correct the NCP consumer manifest path and make JSONL serialization fallible.
- Correct rustdoc links that targeted private constants.
- Abstain with `InsufficientEvidence` when a pathologically small `family_alpha` makes the
  Fisher significance floor degenerate.
  The inverse-normal quantile saturates to `+INF`.
  `tanh` already clamped the floor to exactly `1.0`, and it never produced `NaN`.
  But byte-identical replayed channels also clamp to exactly `rho = 1.0`.
  Thus, the degenerate floor could admit a fabricated consensus instead of abstention.
  It could also admit an attribution against the one nonidentical channel.
- Preserve finite signed-negative KSG estimates from the pinned pid-rs revision as
  valid low-dependence evidence. The upstream default intentionally allows finite-sample
  negative estimates.
  Their rejection had converted decoupled edges into false estimator insufficiency.
- Make the fixed-seed XOR study process-reproducible.
  Use deterministic key order instead of randomized `HashMap` entropy reduction.
  The corrected 0.4/1.0 compatibility stdout hashes and reported tables are identical.
- Count raw-scalar bootstrap KSG confirmation work in conservative quadratic scan units.
  Apply these units in the engine and evaluation-suite preflights.
  Do not combine whole-call and inner-scan units in one resource budget.
- Pin the generated Rust 1.89 MSRV action revision and select current stable explicitly.
  The version-specific action encodes 1.89.
  Thus, it receives only its supported component inputs.
  This avoids an ignored `toolchain` warning and installation of the former 1.88 MSRV.
- Keep pull-request mutation testing bounded to runtime packages.
  The unchanged workspace baseline previously timed out before it tested a mutant.
  The deliberate Monte Carlo evaluation and justification harnesses exceed the per-mutant deadline.
  The evidence publisher also correctly rejects the temporary dirty worktree from cargo-mutants.
  The standard all-feature CI matrix and dedicated assertions still cover those harnesses.
- Add mutation-resistant regressions for KSG report classification and observation-noise boundaries.
  Add them for deterministic PID atom diagnostics and partial-PID and signed-default fusion.
  Add them for CLI evidence labels and demo output.
  Remove an observationally redundant fusion condition that the audit exposed.
- Bind the pid-rs migration evidence to the actual squash commit and tree on `main` from pull request #16.
  Retain the audited source-snapshot identities that produced the paired compatibility run.
- Preserve a complete conflict-free signed-correlation attribution when partial positive
  PID evidence names the same channels.
  Optional PID insufficiency cannot erase the independently assessable signed default.
  PID-only partial evidence still fails closed.
- Reject duplicate JSON keys on the live sidecar path.
  Payloads now deserialize directly into the typed envelope.
  They do not pass through a `serde_json::Value` intermediate.
  That intermediate collapsed repeated keys with the last value before `deny_unknown_fields` could reject them.
  This behavior differed from first-value JSON consumers on a security boundary.
- Print the advisory `calibrated_posterior=false` footer on `replay` output to match the demo.
  A real-capture replay previously ended with bare per-track verdicts.
- Apply explicit policy ceilings to alignment sequence gaps and timestamp skew.
  Document zero as exact timestamp equality.
  Thus, `u64::MAX` cannot silently disable temporal comparability in streaming or direct extraction APIs.
- Bind each accepted whole-stream default assessment to the complete release-suite identity
  and every exact ordered observation field. Sealed default reports and all component axes
  share the opaque `AssessmentBinding`.
  Compatibility component fusion remains explicitly unbound.
  It cannot create an accepted report.
  PID assessments add a nested binding to the complete research suite.
- Replace implicit lifecycle clear operations on accepted paths with typed positioned admission.
  Add explicit reset, timeout, and rollover operations and bounded hash-linked receipts.
  Legacy convenience entry points are compatibility adapters and do not claim new NCP wire
  fields or durable receipt persistence.
- Freeze strict-JSON lifecycle receipt interchange behind a 16 KiB-inclusive decode gate.
  Assessment digests bind the accepted suite and complete serialized reports.
  `Faulted { reason }` binds the exact returned reason.
  Internal digest verification supplies neither writer authentication nor durable chain retention.
- Bound secure startup inputs before foreign parsing.
  Cap standalone strict-JSON configuration at 256 KiB inclusive.
  Reject Zenoh `__config__` external includes.
  Cap each credential file at 1 MiB inclusive during validation.
- Advance generated trial records to `galadriel.evidence.trial.v3`.
  Every synthetic per-trial seed is an exact decimal string with a fixed-width hexadecimal mirror.
  Candidate `base_seed` input is also a decimal string.
  Accept legacy JSON integer input only for the retained historical configuration.
  Normalized accepted output carries canonical decimal and hexadecimal seed strings.
- Parse the release feature graph as strict UTF-8 from raw subprocess bytes with terminal
  color disabled explicitly. Reject lone carriage returns, terminal controls, Unicode
  line/paragraph separators, and other unsafe non-printable characters so ambient terminal
  settings cannot alter dependency identities.
- Report exploratory confidence-interval sweeps in both directions that favor a detector and
  name empty sampled partitions explicitly. Attacker-gain summaries no longer invent a
  boundary when one class is absent.
  Disclose and omit malformed public formatter rows.
  Alarm-ranked AUC tests pin half-weight tie handling.
- Check maneuver grids and complete exposure before generation.
  Require unique bounded lags and a finite positive magnitude.
  Require a duration of at least two frames and checked per-modality window ends.
  Fixed grid, trial, and observation work ceilings reject malformed studies.
  They also reject zero-exposure or right-censored studies.
- Sample odd-duration maneuver profiles through mirrored integer distance.
  Their two central samples are bit-identical.
  Retain the established even-duration `D=90` trace exactly.

### Documentation

- Add an explicit README ecosystem-boundary matrix for pid-rs, NCP, Crebain, Haldir, and Prisoma.
  Distinguish optional build dependencies from upstream transport and producer relationships.
  Identify the unimplemented downstream advisory-publisher boundary.
  Identify the absence of a direct Prisoma sidecar edge.
  Do not upgrade a cross-repository claim.
- Use one `{epoch}` route template.
  Label false-alert exposure consistently per track-hour.
  Align the NCP feature declaration and accepted API-snapshot text with the code and retained release records.
- Replace claims about production readiness, feature completeness, and mutable test counts.
  Replace claims about private sibling repositories and split MSRVs with the current research-prototype status.
- Correct the Crebain integration claim. Normal `CREBAIN_PID_JSONL` captures do not enable
  innovation/covariance research fields. Radar residuals are polar while visual/acoustic
  residuals are Cartesian.
  Sequential filter updates do not share a common frozen prior.
  Association and gating censor misses and rejected measurements.
- Reclassify the bundled Crebain fixture as bounded parsing and baseline smoke evidence.
  It is not a valid cross-modal correlation or PID validation capture.
  Correlation and fused assessment correctly remain `InsufficientEvidence`.
- Document that the Zenoh live tap now uses the NCP sensor-plane ACL and a versioned envelope.
  Producer and consumer component coverage remains non-operational.
  A real multi-process mTLS/ACL campaign must verify delivery and heartbeat behavior from end to end.
- Document that per-channel silence requires another channel to advance assessment time and
  all-modal silence requires an external producer/transport heartbeat.
- Add the producer roadmap: common frozen prior, common frame, explicit miss/rejection
  events, heartbeat, stable session identity, and a versioned schema.
- Align documented supply-chain checks with the two locked fetches and two offline CI checks.
- Correct citation integrity across `docs/`.
  Remove two misattributed verbatim quotations.
  One was a Defense One "visual or inertial position data" line.
  The other was a fabricated survey "defensive toolkit" quotation.
  Correct the SoK author from "Ren et al." to "Xu et al."
  Add its complete title and IEEE EuroS&P 2023 venue.

  Remove an unsupported "below 10% under heavy jamming" statistic.
  Restore the exact Hallyburton frustum-attack quotation.
  Replace a dead EurekAlert URL.
  Remove phantom `[Liu2011]` and `[Mo2010]` reference keys.
  Correct the key-provenance note in `docs/RELATED-WORK.md`.

  Cite `[Gao2018]` and `[WilliamsBeer2010]` in `docs/PAPER.md`.
- Disclose the inert below-target arm at the fusion core's `dof = 3` with default symmetric CUSUM slack.
  At that operating point, the magnitude layer does not flag a moment-shrinking channel.
  Such a channel can show an over-conservative filter, replay, or frozen sensor.
- Clarify the temporal-calibration limitation.
  The Fisher-z significance floor assumes independent and identically distributed bivariate-normal pairs.
  Thus, positive within-window autocorrelation makes one assessment anti-conservative.
  This limitation differs from the separate stream-level repeated-looks limitation.
- Record that the sequential-study detectors run at different realized false-alarm rates.
  Thus, its latency column is not strictly iso-FAR.
  Clarify that `prior_id` non-reuse is a producer attestation.
  The producer enforces it within each aligned frame and context window.
- Reorder the README's opening around the problem, architecture, one source demo command,
  representative output, current evidence boundary, and then the full caveats.
- Distinguish the published post-audit streaming evidence slice from the complete comparative report.
  The complete report is not yet available.
  That report covers AUC, adaptive, maneuver, collusion, latency, and cost results.
  Clarify that Galadriel reports advisory evidence and does not control downstream weights.

### Research additions

- `UnclassifiedAnomaly` verdicts for positive evidence that cannot support a localized or
  broad attribution.
- Expected-modality registration and freshness reporting.
- Explicit maximum sequence gap and maximum active-track configuration.
- Full JSONL/live-ingest limits and sequence validation.
- Supply-chain policy and comprehensive security/review artifacts.
- A bounded common-projection wire field with physical-frame, projection-context, and
  frozen-prior provenance, plus bounded multi-axis extraction and reporting APIs.
- Add a canonical autocorrelation-null study in `galadriel-justify`.
  Two independent AR(1) channels measure positive within-window autocorrelation.
  They measure its inflation of the naive Fisher-z floor's false-positive rate at the runtime default window.
  A Bartlett (1935) effective-sample-size correction improves moderate-persistence calibration.
  It becomes conservative when `phi = 0.9` leaves a small effective sample.

  Tests assert the `phi = 0` calibration check and naive inflation.
  They also assert moderate correction and the finite-sample limit.
  The runtime floor intentionally remains uncorrected until there is a registered phi-estimation design.
  See `docs/JUSTIFICATION.md` §5 and `docs/PAPER.md` §7.
- Add a regression test for duplicate JSON keys on the live sidecar path.
  It proves that the path rejects them as a typed `Data` error.
  A `serde_json::Value` round trip accepted the last value.
  This release closes the parser difference.
- Add a strict machine-readable schema-`1.0` live envelope named `galadriel_pid_observation`.
  It carries NCP version and hash, session, producer, and the frozen Crebain-compatible observation payload.
  It rejects undeclared envelope and nested observation fields.
  `PidObservation` also rejects unknown fields.
  Thus, this restriction applies to every ingest path.
  It applies to bounded JSONL replay.
- A one-command `galadriel-evidence` runner with explicit versioned configuration,
  commit/toolchain manifest, per-trial JSONL, holdout-only summaries, stream metrics,
  provenance-abstention arms, a human report, and checksums.
- Add a clean-source, commit-bound evidence snapshot.
  It retains high repeated-look false-alert rates and missingness abstention as non-production calibration findings.
- Add cargo-fuzz targets for NCP and JSONL decoding and stateful detector and projection boundaries.
  Add a strict pull-request mutation difference and an observational scheduled mutation baseline.
  Add a current-stable CI lane beside the pinned MSRV.
- `CITATION.cff` for commit-exact citation of the research prototype.

### Known limitations

- Current evidence is synthetic. There is no field-validated detection or false-alarm rate.
- The bundled historical Crebain capture does not satisfy the common-frame/common-prior
  estimand required for cross-channel correlation or PID.
  The retained historical producer fixture has no accepted recorded calibration artifact.
  It does not qualify a current reciprocal integration.
- Association and chi-square gating make the observed accepted-update stream selection-biased.
  A strong attack can appear as missingness.
- A consistency-preserving adversary and a colluding majority remain fundamental blind spots.
- PID delete-block confirmation is approximate and conditional on the selected same-window
  clique.
  It is not formal selective inference or fleet-level calibration.
- The optional Zenoh live dependency retains an ignored compression advisory until the project can use an upstream upgrade.
  CI verifies that no build enables the affected feature.
  The exception expires on 2026-10-01.
- All-modal silence is invisible without an external heartbeat.
- Keep Galadriel advisory. Do not wire it as an automatic control veto.
