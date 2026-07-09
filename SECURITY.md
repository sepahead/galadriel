# Security Policy

galadriel is defensive security tooling: it detects spoofing and jamming of a
multi-sensor fusion picture. It is **advisory** — it raises and attributes
anomalies for a human or a slow policy layer; it is not a fail-closed enforcement
gate on any control path, and it must never be represented as one.

## Scope and honest boundaries

- galadriel authenticates **statistical consistency**, not truth. A moment-matched
  spoof that keeps each channel's NIS within its own covariance can pass the
  baseline; separating those from benign decorrelation is the job of the optional
  cross-channel information-theoretic engine, and even that has a documented
  detection boundary (coordinated multi-channel and statistics-matching attacks).
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
- The default build has a small, audited dependency surface (serde, thiserror,
  rand, rand_distr, clap, anyhow). Heavier optional dependencies (pid-core, ncp-core,
  ncp-zenoh) are gated behind off-by-default features and pinned for reproducible
  builds.
