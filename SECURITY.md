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
It reports and attributes anomalies for a person or a slow policy layer.
It is not an enforcement gate on a control path.

Do not represent it as an enforcement gate.

"Fail closed" has one specific definition in the detector API.
Invalid or insufficient evidence cannot become `Nominal`.
This behavior does not authorize a control action.

## Scope and honest boundaries

- Galadriel tests **statistical consistency**, not truth.
  A moment-matched spoof can pass the NIS baseline.
  Signed correlation and optional MI/PID can detect some dependence changes.
  Coordinated consistency-preserving attacks remain outside the threat boundary.
- Cross-channel evidence is valid only for one track and an exact sequence alignment.
  It also requires a common coordinate frame and a common frozen pre-update prior.
  Historical and default Crebain captures do not satisfy this contract.
  They omit the research fields.

  Radar residuals use polar coordinates, but other residuals use Cartesian coordinates.
  Sequential updates use different priors.
  The retained Crebain component fixture implements the required frozen-prior Cartesian projection.
  But Crebain's formal 0.9 boundary freezes an earlier Galadriel audit head.
  A current reciprocal pin and secured multi-process qualification remain absent.
- Crebain's association and chi-square gates censor rejected measurements.
  A stream of successful updates is selection-biased.
  A large attack can appear as missingness.
  Historical captures remain subject to that limit.
  The operational producer emits explicit bounded misses and rejections.
- Per-channel silence is detectable only while another channel advances assessment time.
  The operational profile includes an independent producer heartbeat.
  It also includes a receiver deadline for all-modal silence.
  Real deployment behavior remains an external evidence gate.
- The bus needs cryptographic controls through the per-plane ACL and mTLS on NCP.
  It also needs the safety governor for `mode`, `ttl_ms`, and geofence controls.
  Galadriel adds instrumentation. It does not replace these controls.
- A verdict is `calibrated_posterior = false`. Do not wire it as a silent
  kill-switch.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories for this repository.
You can also email Sepehr Mahmoudian at `sepmhn@gmail.com`.
Do not open a public issue for an undisclosed vulnerability.
We aim to acknowledge receipt within three business days.
This review-gated GitHub research source release has no remediation-time SLA.

## Supply chain

- Use Safe Rust only (`#![forbid(unsafe_code)]`).
- CI uses the lockfile to pin dependencies and uses `cargo deny` to review them.
  Optional `pid-core`, `ncp-core`, and `ncp-zenoh` integrations remain off by default.
- The workspace gate uses Rust and Cargo 1.89.0.
  The current-stable Clippy and test gate uses Rust and Cargo 1.97.1.
- Qualification uses schema `galadriel.candidate-qualification.v3`.
  Candidate commands use an exact 16-key base environment.
  It isolates home, Cargo, target, and temporary state in a private root.
  Candidate commands do not receive ambient credentials, proxies, wrappers, loader variables, or compiler flags.
  The qualifier rejects a file, directory, or link at each Cargo configuration path.
  It checks before and after each retained command.
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
- A passing signed qualification tier must retain exactly 22 auxiliary command receipts.
  Each receipt binds the command, directory, sandbox, exit status, log, and output streams.
  Each command uses a stop-before-exec launch gate.
  It receives fixed CPU, core-file, output-file, open-file, and 64 MiB stream limits.

  macOS does not provide atomic recursive descendant tracking.
  A short-lived reparented process can exit between scans.
  The process scan detects a detached process that remains active.

  The inherited sandbox and resource limits apply before candidate execution.
  A sandboxed process can request work from an existing external service.
  The process scan cannot attribute that external service work.

  The tier compares one source archive, seven package archives, and seven SBOM documents across two runs.
  These 15 comparisons use the recorded host and command contract.
- Semantic checks bind the source archive and package members to the exact candidate tree.
  They close each SBOM package and dependency graph against `Cargo.lock`.
  They reject hidden components and conflicting identity or license fields.
  The exact checks are in `docs/DEPENDENCY-POLICY.md`.
- The license inventory covers the exact 382-package `CARGO_DENY_HOST_FILTERED_GRAPH` subset.
  The validated Cargo graph contains 437 packages.
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
- The Zenoh `SidecarTap` is not an operational security boundary. It uses the
  ACL-covered NCP named-sensor route `sensor/galadriel-pid`, validates a versioned
  session-bound and producer-bound envelope.
  It requires an explicit secure or unverified development transport choice.
  Crebain has an opt-in two-route publisher baseline.
  Galadriel has a bounded operational receiver with lifecycle and heartbeat handling.

  No retained external actual-binary mTLS/ACL allow-and-deny campaign exists.
  Payload provenance is only a claim unless the transport authenticates the publisher.
  The preferred standalone-tap handoff uses a nonblocking `DropNewest` queue.
  It supplies overflow and lag metrics so detector work cannot stop the receive task.
  The application payload limit applies after `ncp-zenoh` materializes callback bytes.

  A broker or transport message-size limit must still bound receive-memory pressure.
  Standalone tap silence remains ambiguous.
  Use the operational two-route receiver for heartbeat and liveness semantics.
- Workspace packages are `publish = false`.
  The project makes no crate-release security guarantees.

[`docs/ECOSYSTEM-CONNECTIONS.md`](docs/ECOSYSTEM-CONNECTIONS.md) records the dated cross-repository status.
It also distinguishes dependency, fixture, and deployment evidence.
