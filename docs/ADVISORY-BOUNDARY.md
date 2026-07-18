# Galadriel's downstream advisory boundary

Galadriel is **instrumentation, not enforcement**. The real enforcement layer in the
ecosystem is cryptographic — per-plane ACL / mTLS on the NCP bus — plus a plant-side
safety governor; Galadriel sits on top of it and reports statistical *consistency*
evidence (see [`MOTIVATION.md`](MOTIVATION.md) §4b and the README "Honest scope" box).

This document states, from Galadriel's own side, the contract that any component which
consumes Galadriel verdicts must honour. The concrete near-term consumer is a
Haldir-style inline authorization gate, but the contract is written to be
consumer-agnostic. It is **normative for how Galadriel expects to be consumed**; it does
not describe an implemented advisory publisher, because none exists yet (see §5).

**GLD-090-AUTH-001:** Galadriel output **SHALL** remain advisory and **SHALL NOT**
create `ALLOW`, change `DENY` to `ALLOW`, add a capability, relax a velocity/slew
limit, extend a command TTL or lease, refresh a watchdog, or erase an independent
fault.

**GLD-090-AUTH-002:** Record-only handling **SHALL** leave the complete consumer
policy snapshot unchanged. A future independently admitted restrict-only handler
**SHALL** be monotonically non-widening and **SHALL** preserve capability and
watchdog identities. `validate_advisory_effect` is the machine-testable reference
for these transitions.

## 1. What Galadriel is, and is not

- It detects **statistical inconsistency, not truth.** It cannot prove an attributed
  channel is malicious, and — by construction — it cannot see an attacker that preserves
  cross-channel consistency (a statistics-matching FDI is the whole detector family's
  shared blind spot).
- Its outputs are **advisory** (`calibrated_posterior = false`): a magnitude anomaly is
  equally consistent with an attack, a genuine unique detection, or an estimator artifact.
  A verdict is not a calibrated probability and must never be treated as one.
- It is a **read-only observer.** `OperationalLiveReceiver` subscribes only to
  Galadriel's two project-owned named-sensor sidecar routes; it does not subscribe to the
  normative NCP base observation key, opens no NCP control session, publishes nothing to
  a control or action plane, and is not a participant in the control loop.
- Its own diagnostic evidence is **not yet fit for restrictive policy use.** The published
  post-audit artifact reports ~26.26 alert episodes/track-hour on the clean arm (102.95 and
  262.57 on the φ=0.5 / φ=0.85 autocorrelated arms), a 0.9167 mission probability of at
  least one alert, and ~99.35% fused-monitoring abstention under ordinary acoustic
  missingness. These are diagnostic, not acceptance, results; they block operational
  policy use until repeated-look and availability calibration is completed.

## 2. Verdict vocabulary — and what each verdict does *not* license

Galadriel's fused advisory vocabulary is [`FusedVerdict`](../crates/galadriel-core/src/fusion.rs),
with exactly `Nominal`, `AttributedInconsistency`, `BroadDegradation`,
`UnclassifiedAnomaly`, and `InsufficientEvidence`. Invalid input or configuration is
returned as `Err(..)` outside that enum. The vocabulary deliberately contains neither a
`StateUnusable` verdict nor a `calibrated_for_policy` self-assertion (see §3.5).

| Verdict | Means | Must **not** be read as |
|---|---|---|
| `Nominal` | Magnitude evidence is ready and χ²-consistent, and every configured common-projection correlation axis is intact. | State is true / sensors uncompromised / controller may act / lease valid / no coordinated spoof / a limit may be relaxed. |
| `AttributedInconsistency { channels, magnitude }` | One or more channels have attributed statistical inconsistency from localized NIS elevation, signed-correlation decoupling, or both; `magnitude` records the magnitude evidence. | A named attack cause. It is statistical evidence, cause unclassified. |
| `BroadDegradation` | A configured broad fraction of ready channels has inflated NIS while cross-channel structure remains intact. | Proof of jamming; cause is unclassified. |
| `UnclassifiedAnomaly { channels }` | Positive but conflicting, mixed-direction, cross-axis, or otherwise incomplete anomaly evidence prevents a narrower fused class. | Absence of a problem. |
| `InsufficientEvidence` | Too little / stale / missing / geometrically incomparable evidence. **Fail-closed.** | `Nominal`. It must never be silently upgraded. |

The single most important rule: **`Nominal` cannot widen authority.** For any consumer it
must be *mechanically impossible* for a `Nominal` (or any) Galadriel verdict to create an
`ALLOW`, flip a `DENY` to `ALLOW`, raise a velocity/slew limit, extend a command TTL,
refresh a plant watchdog, restore an expired lease, substitute for stale trusted state, or
erase an independent source-health fault.

## 3. The consumer contract (normative for integrators)

1. **Non-authoritative and monotonic.** Galadriel evidence may only ever *reduce*
   authority, never grant or widen it. A consumer's authorization must be complete and
   correct with Galadriel absent.
2. **Record-only first.** Until Galadriel is independently calibrated on the consumer's
   own pre-gate data (§4), the consumer records Galadriel evidence and lets it change
   *no* `ALLOW`/`DENY` outcome. This is not fail-open: the assurance profile makes
   Galadriel optional and places no safety claim on it.
3. **Restrict-only after calibration.** A later profile may let a *specific qualified*
   verdict reduce a speed envelope, shorten a command horizon, or require hold/replan —
   but only with a bounded effect, dwell, hysteresis, rate limit, and explicit recovery,
   because restrictive evidence is itself a denial-of-service lever.
4. **No synchronous feedback loop.** Do not feed a Galadriel verdict back into the same
   authorization epoch whose commands changed the motion Galadriel is observing. That
   closes a causal cycle (verdict → restriction → changed motion → changed residuals →
   new verdict) that can oscillate or self-confirm. Export decisions asynchronously to an
   immutable evidence archive and let Galadriel evaluate the joined trace offline.
5. **Derive state-usability and policy-eligibility yourself.** Galadriel supplies one
   advisory input, not the conclusion. `StateUnusable` is a consumer-derived
   qualification over *multiple* signed inputs (covariance, freshness, heartbeat, frame
   validity, plant mode, and — optionally — an admitted Galadriel result), never a
   Galadriel verdict. Likewise, whether a Galadriel profile is eligible to affect policy
   is decided by the consumer against an independent, signed monitor-admission record
   keyed by a profile digest — it is never a boolean Galadriel places in its own message.
6. **Authenticate independently; "signed"/"attested" are not signatures (today).** In
   current Galadriel, "signed correlation" means the *sign* (±) of the Pearson coefficient
   and "producer-attested projection" means a producer *provenance claim* that is
   authenticated only when the NCP transport identity / ACL binds the publisher. Neither
   is a cryptographic signature. A consumer must not treat Galadriel output as signed
   evidence until a signed advisory envelope exists (§5), and must bind transport identity
   to application identity itself. The pinned Zenoh 1.9 client also trusts built-in public
   WebPKI roots in addition to the deployment CA, so the deployment must apply the router-
   authentication mitigation in
   [`SECURE-DEPLOYMENT.md`](SECURE-DEPLOYMENT.md#tls-server-authentication-limitation);
   local configuration alone does not exclusively pin the router.
7. **Distinct identities for a future publisher.** When a signed Galadriel→consumer
   advisory publisher is built, it must use separate input (subscribe) and output
   (advisory-publish) identities, neither of which is usable on any control route.
8. **Prove the negatives.** Integration is not complete until tests demonstrate that
   Galadriel cannot publish a controller intent or a final command, cannot issue or extend
   a lease, that `Nominal` cannot create `ALLOW` or relax any limit, that replayed / stale
   / wrong-session / malformed advisories have no policy effect, that a Galadriel crash or
   disappearance does not change the profile, and that advisory flooding cannot exhaust
   consumer memory or delay a command deadline.

## 4. What Galadriel needs from upstream (Crebain) to be meaningful

Galadriel's standalone cross-sensor assessment requires accepted observations for one
track and sequence in a common coordinate projection derived from a common frozen
pre-update prior. A lifecycle-complete operational two-route deployment additionally
requires explicit rejected observations, misses, and a producer heartbeat.

Historical/default Crebain captures omit the attested common projection, so Galadriel's
correlation and fused assessment correctly return `InsufficientEvidence` even though the
NIS baseline remains usable. Their successful-update-only stream is downstream of
association and a chi-square gate, so rejected and missed measurements are censored rather
than represented and cannot qualify lifecycle-complete operational availability. A
consumer must not read either gap as safety. A retained historical opt-in
producer fixture carried frozen-prior projections plus explicit misses/rejections, but it
does not qualify a current reciprocal integration. No accepted recorded study has measured
the resulting selection effects or calibrated the stream.

## 5. Current implementation status

- **Input only.** `galadriel-ncp` provides bounded JSONL ingest and a strict two-route
  operational Zenoh receiver. It remains read-only with respect to downstream policy:
  there is no Galadriel→consumer signed advisory *publisher* yet, and reports surface
  only as in-process library results or through the CLI/files, not an external advisory
  transport. Haldir is therefore a downstream contract example, not a
  qualified integration: Galadriel holds no command credential and cannot call an
  authorization path.
- **NCP wire: 0.8.** Galadriel pins `ncp-core`/`ncp-zenoh` to the immutable revision
  selected by the public `v0.8.0` tag. NCP's current wire-1.0 extension topology is an
  unreleased candidate whose ecosystem ADRs remain proposed with no normative effect.
  Galadriel's named sensor sidecars are wire-0.8 project surfaces, not native wire-1.0
  extensions. Crebain
  `4c311900ade5668200a48d56fb191be1916b884a` and Galadriel
  `81437d807ca83b66b45c8353968948e540072d97` form a retained historical sidecar/
  registry compatibility fixture; that pair does not pin or qualify the current candidate.
  Current reciprocal integration and final cross-repository qualification are
  `NOT_CLAIMED`. Prisoma observes normative NCP sensor frames and is not a Galadriel
  sidecar consumer; Galadriel's project-owned sidecars are forbidden from the normative
  `SensorFrame` publication path. Galadriel's live taps and operational join have in-process Zenoh
  loopback coverage, but no retained external multi-process mTLS/ACL run between current
  binaries exists.
- **No downstream runtime edge.** A read-only 2026-07-18 inspection found no Galadriel
  dependency, route, publisher, subscriber, or adapter in Haldir remote `main`
  `dd3d8a1c993721f89a1edb04dec5247761c694ad`; its Galadriel phase remains not started.
  Any future adapter MUST admit a raw Galadriel verdict into a Haldir-owned record and
  derive `StateUnusable` and policy eligibility independently. It MUST NOT accept those
  conclusions as producer assertions. Prisoma
  `63cff105e0e40281376e6f827d7782e9b351961a` likewise has no direct Galadriel edge:
  its optional observer accepts only exact base-plane keys and rejects named sensor
  subkeys. A future offline covariate importer MUST bind exact source/configuration,
  session/epoch, source window, and receipt time; reject stale, replayed, malformed, and
  post-treatment inputs; preserve abstention; and remain unable to alter treatment or
  result logic. Shared `pid-rs` use creates a common implementation dependency, so the
  outputs are not independent-implementation replication; it does not by itself prove
  statistical dependence between them.
- Building the signed advisory envelope, retaining the external secured interop campaign,
  and completing an independent recorded calibration study are the ordered prerequisites
  before *any* restrict-only profile in §3.3 is even a candidate.

## 6. Prohibited connections

- **No Galadriel-controlled Crebain fusion down-weight or feedback** in an initial
  deployment. Down-weighting is itself a DoS lever (an attacker can induce apparent
  uniqueness in a healthy channel to suppress it), and it re-enters the feedback loop of
  §3.4. It is a separate Crebain sensor-quality-arbitration research program with its own
  calibration, falsification, weight floor, and stability analysis — not a basic interface.
- **No consumer→Galadriel control authority** of any kind: no controller-intent or
  final-command credentials, no ability to issue leases, and no ability to modify admission
  or policy. The command path (e.g. Haldir→Crebain) must remain fully functional and
  independently safe with Galadriel absent.

---

*This boundary is the advisory-evidence complement to the cryptographic ACL/mTLS
enforcement and plant-side safety governor. When a deployment actually binds transport
identity and ACLs, Galadriel reports consistency evidence from that authenticated producer;
the local artifacts do not attest that binding, and `producer_id` alone is asserted
metadata. Galadriel never authenticates physical truth. Treat every verdict here
accordingly.*
