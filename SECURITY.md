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
  a common coordinate frame, and a common frozen pre-update prior. Current
  crebain output does not yet satisfy that contract: normal captures omit the
  research fields, radar residuals are polar while other residuals are Cartesian,
  and sequential updates use different priors.
- Crebain's association and chi-square gates censor rejected measurements. A
  successful-update-only stream is selection-biased; a large attack may appear as
  missingness. Producers must emit misses/rejections explicitly.
- Per-channel silence is detectable only while another channel advances assessment
  time. All-modal silence requires a producer or transport heartbeat.
- The real remedies for the underlying bus are cryptographic (per-plane ACL +
  mTLS on NCP) and the safety governor (`mode` / `ttl_ms` / geofence). galadriel
  is instrumentation layered on top, not a replacement for them.
- A verdict is `calibrated_posterior = false`. Do not wire it as a silent
  kill-switch.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
on this repository, or by contacting the maintainer. Do not open a public issue
for an undisclosed vulnerability. We aim to acknowledge within a few business days.

## Supply chain

- Safe Rust only (`#![forbid(unsafe_code)]`).
- Dependencies are lockfile-pinned in CI and reviewed with `cargo deny`; optional
  `pid-core`, `ncp-core`, and `ncp-zenoh` integrations remain off by default.
- GitHub Actions are commit-SHA pinned and run with read-only repository contents
  permission. Dependency updates are proposed through Dependabot.
- The Zenoh `SidecarTap` is not an operational security boundary. Its custom key
  is not currently authorized by NCP's hardened ACL and no production publisher
  emits it. Subscriber silence is ambiguous until end-to-end liveness telemetry
  exists.
- Workspace packages are `publish = false`; no crate-release security guarantees
  are made.
