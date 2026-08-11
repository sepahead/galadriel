# Security Policy

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| API | application programming interface |
| CI | continuous integration |
| CPU | central processing unit |
| JSON | JavaScript Object Notation |
| MI | mutual information |
| mTLS | mutual Transport Layer Security |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |
| SBOM | software bill of materials |
| SHA | Secure Hash Algorithm |
| SHA-256 | Secure Hash Algorithm 256 |
| SLA | service-level agreement |
| UTF-8 | 8-bit Unicode Transformation Format |

Galadriel is a defensive research tool.
It reports statistical consistency evidence for a multi-sensor fusion picture.
It does not identify spoofing, jamming, or malicious intent.
Its output is **advisory**.
It presents anomaly evidence to a person or a slow policy layer.
It is not an enforcement gate on a control path.

Do not represent it as an enforcement gate.

"Fail closed" has one specific definition in the detector API.
Invalid or insufficient evidence cannot become `Nominal`.
This behavior does not authorize a control action.

## Scope and honest boundaries

- Galadriel tests **statistical consistency**, not truth.
  A moment-matched spoof can pass the NIS baseline.
  Signed correlation and optional MI/PID can identify evidence of some dependence changes.
  Coordinated consistency-preserving attacks remain outside the threat boundary.
- Cross-channel evidence is valid only for one track and an exact sequence alignment.
  It also requires a common coordinate frame and a common frozen pre-update prior.
  Historical and default Crebain captures do not satisfy this contract.
  They omit the producer-attested common projection.

  Radar residuals use polar coordinates, but other residuals use Cartesian coordinates.
  Sequential updates use different priors.
  The retained Crebain component fixture implements the required frozen-prior Cartesian projection.
  Crebain's formal 0.9 boundary freezes an earlier Galadriel audit head.
  A current reciprocal pin and multi-process mTLS/ACL qualification remain absent.
- Crebain's association and chi-square gates censor rejected measurements.
  A stream of successful updates is selection-biased.
  A large attack can appear as missingness.
  Historical captures remain subject to that limit.
  The producer contract requires explicit bounded misses and rejections.
- Per-channel silence is detectable only while another channel advances assessment time.
  The operational profile includes a separate producer heartbeat.
  It also includes a receiver deadline for all-modal silence.
  Real deployment behavior remains an external evidence gate.
- The bus needs cryptographic controls through the per-plane ACL and mTLS on NCP.
  It also needs the safety governor for `mode`, `ttl_ms`, and geofence controls.
  Galadriel adds instrumentation. It does not replace these controls.
- A verdict is `calibrated_posterior = false`.
  A verdict **MUST NOT** become a direct control input.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories for this repository.
You can also email Sepehr Mahmoudian at `sepmhn@gmail.com`.
Do not open a public issue for an undisclosed vulnerability.
The maintainer aims to acknowledge receipt within three business days.
This research source version has no remediation-time SLA.

## Supply chain

- Do not use unsafe Rust code (`#![forbid(unsafe_code)]`).
- CI uses the lockfile to pin dependencies and uses `cargo deny` to review them.
  Optional `pid-core`, `ncp-core`, and `ncp-zenoh` integrations remain off by default.
- The workspace gate uses Rust and Cargo 1.89.0.
  The current-stable Clippy and test gate uses Rust and Cargo 1.97.1.
- Qualification uses schema `galadriel.candidate-qualification.v3`.
  Candidate commands use an exact 16-key base environment.
  The qualifier isolates home, Cargo, target, and temporary state in a private root.
  Candidate commands do not receive ambient credentials, proxies, wrappers, loader variables, or compiler flags.
  The qualifier rejects a file, directory, or link at each Cargo configuration path.
  It checks before and after each retained command.
- Critical host Git and SSH commands use fixed root-owned executable identities.
  macOS Git resolves only to the selected direct Apple developer path.
  The fixed SSH paths are `/usr/bin/ssh-add` and `/usr/bin/ssh-keygen`.
  The host captures each no-follow file identity and digest before execution.
  It requires the same identity after execution.
  It removes dynamic-loader and toolchain selectors from the host command environment.
- Qualification inventories the declared CPython and Rustup runtime inputs before and after the retained command sequence.
  These checkpoints detect a persistent change.
  They do not make user-owned toolchain paths immutable.
  A process under the same operating-system user can replace a path between checkpoints.
  Use a separately protected, read-only toolchain for stronger execution-byte assurance.
- Qualification pins `sandbox-exec` to `/usr/bin/sandbox-exec`.
  It records the resolved path, SHA-256 value, size, owner, group, and mode.
  Finalization requires the expected SHA-256 value and size.
- Qualification requires an independently obtained allowed-signers file.
  The candidate-tracked signer file is comparison metadata only.
  It cannot authenticate the candidate or qualification tier.
- Qualification requires a clean external RustSec advisory database clone.
  The release input pins this database identity at the 2026-07-23 inspection cut.
  The exact origin is `https://github.com/RustSec/advisory-db`.
  The exact commit is `f981d991604f3e7d4a0eb94e559cb3e5a94a6dc2`.
  The exact tree is `26bea0ac10667f826b5522a828a27861ae4b5287`.

  The inventory contains 1,187 entries.
  Its SHA-256 value is `bfc26634ed164598c75c91fc462f0fa527b73634859faeb9476f2631bf529619`.

  The qualifier rejects another origin, commit, tree, or a dirty clone.
  A qualification result remains bound to that pinned input.
- The qualifier installs the pinned advisory database in isolated tool state.
  The vulnerability tools use it without a network fetch.
- A passing signed qualification tier MUST retain exactly 22 auxiliary command receipts.
  Each receipt binds the command, directory, sandbox, exit status, log, and output streams.
  Each command uses a stop-before-exec launch gate.
  It receives fixed CPU, core-file, output-file, open-file, and 64 MiB stream limits.
  The qualifier signals the original process group before it reaps the root.
  After root reap, it uses only read-only extinction checks.
  The candidate sandbox denies signal operations by default.
  It permits a candidate process to signal only itself or its children.

  macOS does not provide atomic recursive descendant tracking.
  A short-lived reparented process can exit between scans.
  The sandbox-identity scan detects an active detached process that retains that identity.

  The inherited sandbox and resource limits apply before candidate execution.
  A sandboxed process can request work from an existing external service.
  The process scan cannot attribute that external service work.

  The tier compares one source archive, seven package archives, and seven SBOM documents across two runs.
  These 15 comparisons use the recorded host and command contract.

- Candidate evidence uses an exact six-file flat set.
  The summary schema is `galadriel.evidence.summary.v3`.
  The manifest schema is `galadriel.evidence.manifest.v3`.
  The acceptance profile is `galadriel-0.9-frozen-acceptance-metrics-v3`.
  The bootstrap profile is `splitmix64-rejection-group-metric-v1`.
  The profile uses SplitMix64 with unbiased rejection sampling over complete tracks.

  The qualifier builds the evidence runner separately.
  It creates a private directory with mode `0700`.
  It copies the executable into that directory through no-follow descriptors with mode `0500`.
  It executes that exact snapshot directly.
  The manifest binds the snapshot digest and exact Git commit and tree.

  The host streams every trial and reconstructs the complete summary and report.
  It verifies the exact manifest, configuration, and checksum semantics.
  It evaluates acceptance only from the reconstructed holdout summary.
  Finalization repeats this replay against the signed outer inventory.
  This process prevents a candidate summary from certifying itself.
  It does not prove model validity or deployment security.

- A schema-valid candidate acceptance result with `status=FAIL` remains negative.
  An otherwise passing qualification records `NARROWED_REVIEW_REQUIRED` after an acceptance failure.
  Only a signed human decision can select `NARROWED_GO` or `NO_GO`.
  `GO` is prohibited while an acceptance criterion fails.

- Exact mutation commands use environment schema `galadriel.mutation-environment.v2`.
  They require the Linux process file system (`procfs`), process file descriptors, and serialized child-subreaper ownership.
  They start behind a stop-before-exec gate.
  They reap the root only after the tracked candidate tree becomes extinct.
  They fail before process creation on an unsupported host.

  An uninterruptible process can outlive the stop deadline and fails the run.
  This cleanup control is not a control group, container, or deployment-isolation boundary.
  It cannot attribute work that an existing external service performs.
- Semantic checks bind the source archive and package members to the exact candidate tree.
  They close each SBOM package and dependency graph against `Cargo.lock`.
  They reject hidden components and conflicting identity or license fields.
  The exact checks are in `docs/DEPENDENCY-POLICY.md`.
- The license inventory covers the exact 382-package `CARGO_DENY_HOST_FILTERED_GRAPH` subset.
  The qualification Cargo graph contains 437 packages.
  This inventory does not describe another host or target graph.
  Same-host comparison does not prove independent or cross-platform reproduction.
  Source-graph checks do not prove deployed-binary content.
  These checks do not qualify deployment security.
- Commit SHAs pin GitHub Actions.
  The actions run with read-only permission for repository contents.
  Dependabot proposes dependency updates.
- Release and deployment JSON uses strict UTF-8 decoding.
  The decoder rejects duplicate members and nonstandard constants through controlled errors.
  It also rejects non-finite floats and floats with overflow or nonzero underflow.
  The fixed resource bound permits integer tokens with at most 128 decimal digits.
  Exact retained `u64` provenance remains valid.
  Individual wire and evidence schemas apply binary64-safe or narrower integer domains when necessary.
- The Zenoh `SidecarTap` is not an operational security boundary.
  It uses the ACL-covered NCP named-sensor route `sensor/galadriel-pid`.
  It validates a versioned, session-bound, and producer-bound envelope.
  It requires an explicit `Secure` or `QuietDevelopment` transport choice.
  Crebain has an opt-in two-route publisher baseline.
  Galadriel has a bounded operational receiver with lifecycle and heartbeat handling.

  The lifecycle adapter derives each accepted assessment scope from the validated
  producer and exact admitted position.
  The assessment binding covers that scope, the ordered observations, and the
  accepted release suite.
  Receipt verification requires each evaluated report scope to match the receipt.
  These checks establish internal identity and evidence consistency.
  They do not authenticate the caller, producer, or physical source.

  Live CLI records contain the complete receipt and ordered assessments.
  They use schema `galadriel.observe.lifecycle.v1`.
  They are advisory, unsigned, and not durably retained by Galadriel.

  No retained external mTLS/ACL allow-and-deny campaign with the actual binaries exists.
  Payload provenance is only a claim unless the transport authenticates the publisher.
  The preferred standalone-tap handoff uses a nonblocking `DropNewest` queue.
  It supplies overflow and lag metrics so detector work cannot stop the receive task.
  The application payload limit applies after `ncp-zenoh` materializes callback bytes.

  A broker or transport message-size limit MUST still bound receive-memory pressure.
  Standalone tap silence remains ambiguous.
  Use the operational two-route receiver for heartbeat and liveness semantics.
- Workspace packages are `publish = false`.
  The project makes no crate-release security guarantees.

[`docs/ECOSYSTEM-CONNECTIONS.md`](docs/ECOSYSTEM-CONNECTIONS.md) records the dated cross-repository status.
It also distinguishes dependency, fixture, and deployment evidence.
