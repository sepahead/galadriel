# Security Policy

Galadriel is a defensive security tool.
It detects spoofing and jamming in a multi-sensor fusion picture.
Its output is **advisory**.
It reports and attributes anomalies for a person or a slow policy layer.
It is not an enforcement gate on a control path. Do not represent it as one.

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
This research release has no remediation-time SLA.

## Supply chain

- Use Safe Rust only (`#![forbid(unsafe_code)]`).
- CI uses the lockfile to pin dependencies and uses `cargo deny` to review them.
  Optional `pid-core`, `ncp-core`, and `ncp-zenoh` integrations remain off by default.
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
