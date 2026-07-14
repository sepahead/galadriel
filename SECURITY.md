# Security Policy

galadriel is defensive security tooling: it detects spoofing and jamming of a
multi-sensor fusion picture. It is **advisory** — it raises and attributes
anomalies for a human or a slow policy layer; it is not an enforcement gate on
any control path, and it must never be represented as one. "Fail closed" in the
detector API means invalid or insufficient evidence cannot become `Nominal`; it
does not authorize a control action.

## Scope and honest boundaries

- galadriel tests **statistical consistency**, not truth. A moment-matched spoof
  can pass the NIS baseline. Signed correlation and optional MI/PID can detect
  some dependence changes, but coordinated consistency-preserving attacks remain
  outside the threat boundary.
- Cross-channel evidence is valid only for one track, exact sequence alignment,
  a common coordinate frame, and a common frozen pre-update prior. Historical and
  default Crebain captures do not satisfy that contract: they omit the research
  fields, radar residuals are polar while other residuals are Cartesian, and
  sequential updates use different priors. Crebain's separately gated operational
  producer baseline implements the required frozen-prior Cartesian projection.
- Crebain's association and chi-square gates censor rejected measurements. A
  successful-update-only stream is selection-biased; a large attack may appear as
  missingness. Historical captures remain subject to that limit; the operational
  producer emits explicit bounded misses/rejections.
- Per-channel silence is detectable only while another channel advances assessment
  time. The operational profile includes an independent producer heartbeat and a
  receiver deadline for all-modal silence; real deployment behavior remains an
  external evidence gate.
- The real remedies for the underlying bus are cryptographic (per-plane ACL +
  mTLS on NCP) and the safety governor (`mode` / `ttl_ms` / geofence). galadriel
  is instrumentation layered on top, not a replacement for them.
- A verdict is `calibrated_posterior = false`. Do not wire it as a silent
  kill-switch.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
on this repository, or email Sepehr Mahmoudian at `sepmhn@gmail.com`. Do not open a
public issue for an undisclosed vulnerability. We aim to acknowledge receipt within
three business days; this research release makes no remediation-time SLA.

## Supply chain

- Safe Rust only (`#![forbid(unsafe_code)]`).
- Dependencies are lockfile-pinned in CI and reviewed with `cargo deny`; optional
  `pid-core`, `ncp-core`, and `ncp-zenoh` integrations remain off by default.
- GitHub Actions are commit-SHA pinned and run with read-only repository contents
  permission. Dependency updates are proposed through Dependabot.
- The Zenoh `SidecarTap` is not an operational security boundary. It uses the
  ACL-covered NCP named-sensor route `sensor/galadriel-pid`, validates a versioned
  session/producer-bound envelope, and forces an explicit secure versus unverified
  development transport choice. Crebain has an opt-in two-route publisher baseline and
  Galadriel has a bounded operational receiver with lifecycle and heartbeat handling,
  but no retained external actual-binary mTLS/ACL allow-and-deny campaign exists yet.
  Payload provenance is only a claim unless the transport authenticates the publisher.
  The standalone tap's preferred bounded handoff uses a nonblocking `DropNewest` queue
  and exposes overflow/lag metrics so detector work cannot stall the receive task. The
  application payload limit runs after `ncp-zenoh`
  materializes callback bytes, so a broker/transport message-size limit is still required
  to bound receive-memory pressure. Standalone tap silence remains ambiguous; use the
  operational two-route receiver for heartbeat/liveness semantics.
- Workspace packages are `publish = false`; no crate-release security guarantees
  are made.
