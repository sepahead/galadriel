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

## 1. What Galadriel is, and is not

- It detects **statistical inconsistency, not truth.** It cannot prove an attributed
  channel is malicious, and — by construction — it cannot see an attacker that preserves
  cross-channel consistency (a statistics-matching FDI is the whole detector family's
  shared blind spot).
- Its outputs are **advisory** (`calibrated_posterior = false`): a magnitude anomaly is
  equally consistent with an attack, a genuine unique detection, or an estimator artifact.
  A verdict is not a calibrated probability and must never be treated as one.
- It is a **read-only observer.** `galadriel-ncp` subscribes to the NCP observation /
  named-perception plane; it opens no NCP control session, publishes nothing to a control
  or action plane, and is not a participant in the control loop.
- Its own diagnostic evidence is **not yet fit for restrictive policy use.** The published
  post-audit artifact reports ~26.26 alert episodes/track-hour on the clean arm (102.95 and
  262.57 on the φ=0.5 / φ=0.85 autocorrelated arms), a 0.9167 mission probability of at
  least one alert, and ~99.35% fused-monitoring abstention under ordinary acoustic
  missingness. These are diagnostic, not acceptance, results; they block operational
  policy use until repeated-look and availability calibration is completed.

## 2. Verdict vocabulary — and what each verdict does *not* license

Galadriel's published verdict enum is exactly: `Nominal`, `AttributedInconsistency`,
`BroadDegradation`, `UnclassifiedAnomaly`, `InsufficientEvidence`, and `Err(..)` for
invalid input/configuration. It deliberately does **not** contain a `StateUnusable`
verdict or any `calibrated_for_policy` self-assertion (see §3.5).

| Verdict | Means | Must **not** be read as |
|---|---|---|
| `Nominal` | Every configured channel was fresh, ready, and individually χ²-consistent in this assessment. | State is true / sensors uncompromised / controller may act / lease valid / no coordinated spoof / a limit may be relaxed. |
| `AttributedInconsistency { channels }` | A minority of channels show localized NIS inflation while peers remain usable. | A named attack cause. It is statistical evidence, cause unclassified. |
| `BroadDegradation` | Most/all channels inflated together (jam-like). | Proof of jamming; cause is unclassified. |
| `UnclassifiedAnomaly { channels }` | Positive anomaly evidence exists but stale/missing peers or a below-target shift block a narrower class. | Absence of a problem. |
| `InsufficientEvidence` | Too little / stale / missing / geometrically incomparable evidence. **Fail-closed.** | `Nominal`. It must never be silently upgraded. |
| `Err(..)` | Invalid input or configuration. | A verdict. It is not converted into one. |

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
   to application identity itself.
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

Galadriel's cross-sensor layers require **pre-association** evidence for one track and
sequence, in a common coordinate projection derived from a common frozen pre-update prior:
accepted observations, **rejected** observations, misses, and a producer heartbeat.

Today's normal Crebain captures omit the attested common projection, and its
successful-update-only stream is downstream of association and a chi-square gate, so
rejected and missed measurements are censored rather than represented. A consumer must not
read that gap as safety: with those preconditions absent, Galadriel's correlation and
fused assessment correctly return `InsufficientEvidence`. This selection-bias limitation is
a **disclosed structural property** of the current data seam, not a hidden detector defect;
closing it is an upstream Crebain producer milestone, not a Galadriel workaround.

## 5. Current implementation status

- **Input only.** `galadriel-ncp` provides a bounded JSONL ingest and an optional Zenoh
  named-perception subscriber. Both are read-only; there is no Galadriel→consumer advisory
  *publisher* yet, and verdicts surface only via the CLI / files.
- **NCP wire: 0.8.** Galadriel pins `ncp-core`/`ncp-zenoh` to the `v0.8.0` tag. The Crebain
  producer and Prisoma observer are already on NCP 0.8, so the enveloped/live paths
  interoperate at the version gate again.
- Building the signed advisory envelope, the missing Crebain pre-gate producer, and the
  independent calibration campaign are the ordered prerequisites before *any* restrict-only
  profile in §3.3 is even a candidate.

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
enforcement and plant-side safety governor. Galadriel authenticates consistency, not
truth; treat every verdict here accordingly.*
