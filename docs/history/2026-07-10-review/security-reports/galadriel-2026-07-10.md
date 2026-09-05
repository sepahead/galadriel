# Comprehensive Security Review — galadriel

**Date:** 2026-07-10

**Mode:** Comprehensive

**Confidence gate:** 2/10

**Scope:** Entire repository, working tree, dependency graph, CI, git history, installed skill supply chain, sibling integration seams, and documented deployment assumptions.

## Executive Summary

Galadriel's local research implementation is materially hardened: public inputs are validated, state and work are bounded, statistical ambiguity fails closed, unsafe Rust is forbidden, replay retains adverse history, live callback/reset races are contained, and CI dependencies are immutable. No critical or high-severity exploitable defect remains in the audited repository.

It is **not production-integration ready**. The optional live path now uses NCP's ACL-covered named-sensor route and a versioned session/producer-bound envelope, but still lacks a Crebain publisher, deployed mTLS proof, and heartbeat. Crebain does not emit the required common-frame/common-frozen-prior projection, and producer provenance labels remain attestations rather than cryptographic proof. One transitive Zenoh compression advisory is temporarily accepted only because the vulnerable feature is disabled and mechanically checked; that exception expires on 2026-10-01.

## Phase 0 — Architecture and Stack

| Dimension | Result |
|-----------|--------|
| Language | Safe Rust, edition 2021, pinned Rust 1.88 |
| Structure | Seven-crate Cargo workspace |
| Core | Streaming NIS/CUSUM, signed correlation, fail-closed fusion |
| Optional research | KSG mutual information / shared-exclusions PID |
| Inputs | Library structs, bounded JSONL file replay, optional Zenoh payloads |
| Storage | Caller-owned files plus bounded in-memory windows/maps; no database |
| Auth | None in this repository; live security depends on external NCP configuration |
| Deployment | No server, container, cloud resource, or on-chain program; crates are unpublished |
| LLM/AI | None |

## Phase 1 — Attack Surface Census

| Entry point | Type | Authentication | Validation / bound |
|-------------|------|----------------|--------------------|
| `galadriel demo` arguments | Local CLI | Local process | Clap domains plus scenario validation |
| `galadriel replay <JSONL>` | Local untrusted file | Filesystem permissions | Line, record, aggregate-byte, track, numeric, temporal, and provenance bounds |
| `PidObservation` library input | Public Rust API | Caller trust | Finite/domain/covariance/projection validation; strict sequence/time rules |
| `SidecarTap` payload | Optional Zenoh subscription | External/absent in repo | Payload size, JSON, observation, sequence, LRU, callback, and reset bounds |
| CI dependency resolution | Build-time network | GitHub/Cargo trust | Lockfile, source allowlist, SHA-pinned actions, `cargo-deny` |

No HTTP listener, REST/GraphQL route, database, webhook, shell-execution sink, on-chain instruction, wallet authority, or file upload service exists.

## Phase 2 — Secrets Archaeology

- Current-tree scans found no private keys, common live-token prefixes, credential files, or world-writable project files.
- Git-history addition scans for `.env`, private-key/certificate, credential, secret, and keypair filenames returned no matches.
- CI does not interpolate repository secrets and checkout credentials are not persisted.
- `.gitignore` covers common environment, key, certificate, credential, secret, and keypair artifacts.

**Result:** No secret exposure found.

## Phase 3 — Dependency Supply Chain

| Package/path | Status | Risk | Action |
|--------------|--------|------|--------|
| `lz4_flex 0.10.0` via Zenoh 1.9 | `RUSTSEC-2026-0041`; vulnerable decompression feature disabled | Medium residual | Upgrade NCP/Zenoh; exception expires 2026-10-01; CI asserts feature stays off |
| `paste 1.0.15` | `RUSTSEC-2024-0436`, unmaintained | Low | Remove through upstream dependency upgrade |
| `rustls-pemfile 2.2.0` | `RUSTSEC-2025-0134`, unmaintained | Low | Remove through upstream dependency upgrade |
| `pid-rs v0.4.0` | Public git tag + exact lock commit | Controlled | Continue Dependabot/manual review |
| `NCP v0.7.1` | Public git tag + exact lock commit | Controlled but large graph | Continue Dependabot/manual review |

`cargo deny --all-features --locked check` passed advisories, bans, licenses, and sources under the documented policy. `cargo audit --ignore RUSTSEC-2026-0041` exited successfully with only the two unmaintained warnings above. Duplicate versions are warned rather than denied and remain a maintenance-cost signal.

## Phase 4 — CI/CD Security

- Every action is pinned to a full commit SHA.
- Top-level permissions are read-only `contents`.
- Checkout credentials are not persisted.
- No `pull_request_target`, deploy job, dynamic shell interpolation from issue/PR bodies, or secret logging exists.
- Locked fetch/build, formatting, all-target/all-feature Clippy, tests, rustdoc, pure-core smoke, dependency policy, and compression-feature assertion are configured.
- Concurrent obsolete runs are cancelled.
- Hosted evidence is currently unavailable: GitHub reports that jobs never start because recent account payments failed or the spending limit must be increased. This is an external operations blocker, not a passing CI result.

## Phases 5–7 — Infrastructure, Integrations, and AI

- No cloud/IaC, DNS, database migration, webhook, OAuth, payment callback, or LLM integration was found.
- The only network integration is the optional read-only Zenoh subscriber. Its NCP named-sensor route is covered by the sensor-plane ACL, but it has no production Crebain publisher or receiver-verified mTLS deployment, and silence is ambiguous without heartbeat/liveness integration.
- There is no deployment signing, SBOM, or artifact provenance because there is no release pipeline. Add those if package publishing begins.

## Phase 8 — Skill Supply Chain

Forty-four installed `SKILL.md` packages across the configured Codex/Claude/agent paths were enumerated. Content and file-type scans found normal Markdown/reference assets and expected helper scripts. Security/prompt-override keywords resolved to audit instructions (not project-local executable payloads), and the project contains no local skill package. No encoded download-and-execute chain was found.

## Phase 9 — OWASP Top 10:2025 Mapping

| Category | Assessment |
|----------|------------|
| A01 Broken Access Control | No application routes; live authorization is external and missing operational integration (SEC-02). |
| A02 Security Misconfiguration | Safe defaults, strict bounds, unpublished packages; hosted CI billing remains unresolved. |
| A03 Software Supply Chain | SHA pins and `cargo-deny` are strong; one feature-disabled advisory and two unmaintained transitives remain (SEC-01/04). |
| A04 Cryptographic Failures | No secrets/crypto implementation; projection provenance is not authenticated proof (SEC-03). |
| A05 Injection | No SQL, command, template, or eval sink found; JSON is typed and bounded. |
| A06 Insecure Design | Advisory-only semantics and fail-closed ambiguity are explicit; live heartbeat/auth and field evidence remain design gates. |
| A07 Authentication Failures | No user auth surface; producer/session authentication must be provided by NCP before live use. |
| A08 Data Integrity Failures | Inputs/provenance are validated and CI is pinned; a malicious authenticated producer can still attest false projection metadata. |
| A09 Logging/Alerting Failures | Typed live counters and historical replay summaries exist; fleet alert routing is outside this repository. |
| A10 Exceptional Conditions | Non-finite, malformed, stale, missing, over-budget, panic, reentrancy, and ambiguity paths reject or fail closed. |

Solana-specific signer, PDA, CPI, rent, reinitialization, and arithmetic-account checks are not applicable: this repository contains no Solana program or on-chain accounts.

## Phase 10 — STRIDE Threat Model

| Component | Threat | Risk | Existing mitigation | Required next action |
|-----------|--------|------|---------------------|----------------------|
| JSONL replay | Tampering / DoS | Low | Strict parsing, aggregate/line/record/work/track bounds, full adverse history | Sign captures if used as evidence |
| Zenoh sidecar | Spoofing / Tampering | Medium | Typed versioned envelope, session/producer binding, sequence monotonicity, explicit secure mode, ACL-covered route | Crebain publisher, deployed mTLS identity proof, and end-to-end forged-payload tests |
| Zenoh sidecar | Denial of service | Medium | Payload/LRU/gap bounds, rejection counters, deadlock-safe reset | Heartbeat, rate policy, operator alerting, end-to-end denial tests |
| Projection metadata | Spoofing / integrity | Medium | Frame/context/prior equality and global reuse validation | Independent producer/reference validation and authenticated provenance |
| Detector state | DoS / exceptional conditions | Low | Track/window/observation/estimator bounds and fallible allocation | Operational resource monitoring |
| CI/dependencies | Tampering | Low/medium | Lockfile, action SHAs, source allowlist, Dependabot | Restore hosted CI and remove advisory exception |
| Reports | Repudiation | Low | Stable notes, terminal plus historical states | Signed capture/report manifest if used for incident response |

## Phase 11 — Data Classification

The repository stores no credentials, PII, financial data, wallet material, or regulated database. Runtime observations can contain operationally sensitive sensor/track telemetry; callers control capture location, retention, encryption, and access. A production deployment should classify captures as operational security data, encrypt them in transit/at rest, define retention, and avoid logging raw payloads beyond need.

## Phase 12 — Active Verification

- Reproduced and fixed strict-Clippy failures.
- Exercised invalid numeric/configuration/temporal/provenance paths and fail-closed verdicts.
- Reproduced prior-ID reuse after the old retained tail and added a full-input regression.
- Reproduced PID confirmation-rank exhaustion and changed it to resolvable joint extrema with preflight.
- Analyzed and fixed cross-subscription callback/reset deadlock paths with callback-context and in-flight delivery rejection.
- Exercised replay recovery so earlier insufficient/rejected frames remain reported.
- Verified the vulnerable Zenoh compression feature is absent from the all-feature tree.
- Verified the latest hosted run has zero executed steps and a billing/spending annotation.

False-positive classes filtered: test-only `unwrap`/panic sites, documentation/example secret words, and audit-language matches inside installed security skills.

## Phase 13 — Findings

### [MEDIUM] SEC-01: Feature-disabled Zenoh compression advisory remains in the lock graph

**Confidence:** 9/10

**Phase:** 3 — Dependency Supply Chain

**Category:** OWASP A03 / STRIDE Tampering

**Location:** `Cargo.lock:1456`, `deny.toml:8`, `.github/workflows/ci.yml:60`

**Description:** Zenoh 1.9 transitively locks `lz4_flex 0.10`, affected by `RUSTSEC-2026-0041`. The vulnerable decompression methods are gated behind Zenoh's `transport_compression` feature, which is not enabled in Galadriel's all-feature tree. Policy currently ignores the advisory with an owner, reason, and expiry.

**Exploit scenario:** A future dependency or feature change enables `transport_compression`; a malicious compressed frame reaches the affected decoder. Without the feature assertion, the exception could silently become unsafe.

**Evidence:** `cargo tree -p galadriel-ncp --all-features -e features` contains no `zenoh-transport feature "transport_compression"`; CI fails if it appears or after 2026-10-01.

**Remediation:** Upgrade NCP/Zenoh to a release without the advisory, then delete the `RUSTSEC-2026-0041` ignore and feature assertion. Until then, keep both gates mandatory.

**Priority:** P1 — before the exception expiry or any transport feature change.

### [MEDIUM] SEC-02: Live producer authentication, ACL, and liveness are not integrated

**Confidence:** 10/10

**Phase:** 1/6/9 — Attack Surface and Integration

**Category:** OWASP A01/A07/A09 / STRIDE Spoofing and DoS

**Location:** `crates/galadriel-ncp/src/live.rs:700`, `README.md:150`

**Description:** `SidecarTap` is a read-only prototype. It now uses NCP's least-privilege named-sensor route, requires an explicit secure or unverified-development transport choice, and rejects envelopes whose NCP/sidecar version, session, producer, or observation contract is invalid. The repository still has no production Crebain publisher, receiver-verified mTLS deployment, or all-modal heartbeat.

**Exploit scenario:** If operators deploy the subscriber on a permissive bus, an unauthorized publisher can inject syntactically valid observations or suppress traffic. Silence cannot distinguish attack, ACL denial, key mismatch, or producer failure.

**Evidence:** The sidecar route is `Keys::sensor_named(session, "galadriel-pid")`, which the NCP sensor-plane ACL covers, and unit/integration tests exercise the versioned envelope against a real Crebain capture. There is still no executable live publisher or brokered mTLS test.

**Remediation:** Add the Crebain named-sensor producer, deploy the existing ACL with mTLS identities, use fresh session IDs per process epoch, add heartbeat, and run end-to-end traffic/denial/restart tests. Keep the detector advisory.

**Priority:** P1 — mandatory before live deployment.

### [MEDIUM] SEC-03: Projection provenance is an attestation, not proof of truthful computation

**Confidence:** 9/10

**Phase:** 9/10 — Data Integrity and Threat Modeling

**Category:** OWASP A08 / STRIDE Spoofing and Tampering

**Location:** `crates/galadriel-core/src/observation.rs:20`, `crates/galadriel-core/src/lib.rs:220`

**Description:** Galadriel proves internal equality, dimension, freshness, and non-reuse properties of `frame_id`, `context_id`, and `prior_id`. It cannot prove that an upstream producer computed the values in the claimed frame from one frozen prior.

**Exploit scenario:** A compromised or buggy authenticated producer labels modality-native or sequentially conditioned residuals with matching IDs. Galadriel treats incomparable values as one estimand and can issue misleading consistency results.

**Evidence:** `PidObservation::validate` explicitly documents that it does not authenticate the producer or prove the NIS/projection computation.

**Remediation:** Instrument crebain before gating/sequential updates, compute all projection values from one frozen prior in a documented frame, sign/version the envelope, and compare recorded output against an independent reference implementation before accepting field claims.

```rust
consistency_projection: Some(ConsistencyProjection {
    values: residual_in_registered_common_frame,
    dimensions: 3,
    frame_id: REGISTERED_FRAME_ID,
    context_id: projection_schema_version,
    prior_id: unique_frozen_prior_id,
})
```

**Priority:** P1 — mandatory before recorded or live cross-channel claims.

### [LOW] SEC-04: Two transitive crates are unmaintained

**Confidence:** 8/10

**Phase:** 3 — Dependency Supply Chain

**Category:** OWASP A03

**Location:** `Cargo.lock:1753`, `Cargo.lock:2387`

**Description:** RustSec flags `paste 1.0.15` and `rustls-pemfile 2.2.0` as unmaintained. No vulnerability is asserted, but future fixes may not arrive.

**Remediation:** Track their reverse dependency chains during NCP/Zenoh upgrades and remove them when compatible upstream releases permit. Keep Dependabot and `cargo-deny` warnings visible.

**Priority:** P2 — dependency maintenance cycle.

### [INFO] SEC-05: Hosted CI is externally blocked

**Confidence:** 10/10

**Phase:** 4 — CI/CD

**Category:** Operational assurance

**Location:** GitHub Actions run `29074859763`

The latest jobs failed before any step ran. GitHub's annotation states that recent account payments failed or the spending limit must be increased. Local checks are strong evidence but do not replace an independent hosted run. Restore billing and rerun the pushed commit.

### [INFO] SEC-06: Scientific and threat-model limits remain

**Confidence:** 10/10

**Phase:** 10 — Threat Model

**Category:** Insecure interpretation risk

**Location:** `README.md`, `docs/EVALUATION.md`, `docs/JUSTIFICATION.md`

The evidence is synthetic. A colluding majority, consistency-preserving attacker, genuine unique event, producer censoring, and all-modal silence can defeat or confound attribution. The implementation and documentation now preserve these as explicit advisory boundaries; they are product validation work, not hidden code defects.

## Remediation Roadmap

1. **P1 / before live or recorded claims (roughly 1–3 engineering weeks across repositories):** upgrade Zenoh or renew only after review; implement the Crebain pre-gate common-prior projection and named-sensor publisher; deploy ACL/mTLS/session/heartbeat and run end-to-end denial/restart tests.
2. **P2 / dependency cycle (hours to days once upstream releases exist):** remove unmaintained transitives, reduce duplicate graph versions, add SBOM/artifact provenance if publishing begins.
3. **P3 / research program (multi-week study):** preregister recorded field evaluation, include misses/rejections/benign maneuvers, calibrate operating points, and red-team coordinated attacks.

## Confidence Calibration

- Total findings: 6
- CRITICAL: 0
- HIGH: 0
- MEDIUM: 3 (average confidence: 9.3/10)
- LOW: 1 (average confidence: 8/10)
- INFO: 2 (average confidence: 10/10)
- False positives filtered: 3 classes
- Mode: Comprehensive (2/10 gate)

## Phase 14 — Report Tracking

This is the first saved comprehensive report, so all six tracked items are new. Resolved-in-audit defects—including provenance-tail reuse, PID rank exhaustion, callback/reset deadlock, replay-history erasure, statistical-report mismatch, and strict-Clippy failures—are documented in the companion HTML review rather than counted as persistent security findings.
