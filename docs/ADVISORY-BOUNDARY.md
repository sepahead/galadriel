# Galadriel downstream advisory boundary

## Abbreviations

| Short form | Meaning |
|---|---|
| ACLs | access control lists |
| ADRs | architecture decision records |
| API | application programming interface |
| CA | certificate authority |
| CLI | command-line interface |
| FDI | false-data injection |
| JSONL | JavaScript Object Notation Lines |
| mTLS | mutual Transport Layer Security |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| ROS | Robot Operating System |
| TTL | time to live |
| WebPKI | Web Public Key Infrastructure |

Galadriel is **instrumentation, not enforcement**. Per-plane ACLs and mTLS on the
NCP bus supply cryptographic enforcement. A plant-side safety governor supplies
the other enforcement layer. Galadriel runs above these layers and reports
statistical *consistency* evidence.

See [`MOTIVATION.md`](MOTIVATION.md) section 4.2 and the README "Honest scope" box.

This document defines the Galadriel contract for a component that consumes its
verdicts. A Haldir-style inline authorization gate is the specific near-term
consumer example. The contract is not specific to that consumer.

This contract is **normative for how Galadriel expects consumption**. It does not
describe an implemented advisory publisher. Section 5 records that no publisher
exists.

**GLD-090-AUTH-001:** Galadriel output **SHALL** remain advisory. It **SHALL NOT**
create `ALLOW`, change `DENY` to `ALLOW`, or add a capability. It **SHALL NOT**
relax a velocity or slew limit. It **SHALL NOT** extend a command TTL or lease,
refresh a watchdog, or erase an independent fault.

**GLD-090-AUTH-002:** Record-only handling **SHALL** leave the complete consumer
policy snapshot unchanged. A future independently admitted restrict-only handler
**SHALL** be monotonically non-widening. It **SHALL** preserve capability and
watchdog identities. `validate_advisory_effect` is the machine-testable reference
for these transitions.

## 1. What Galadriel is and is not

- Galadriel detects **statistical inconsistency, not truth**. It cannot prove that
  an attributed channel is malicious.
- The detector cannot see an attacker that preserves cross-channel consistency.
  A statistics-matching FDI is a shared blind spot for this detector family.
- Outputs are **advisory** and have `calibrated_posterior = false`.
- A magnitude anomaly can show an attack, a unique detection, or an estimator
  artifact. It is not a calibrated probability.
- Galadriel is a **read-only observer**.
- `OperationalLiveReceiver` subscribes only to two project-owned named-sensor
  sidecar routes.
- It does not subscribe to the normative NCP base observation key. It opens no
  NCP control session and publishes nothing to a control or action plane.
- Galadriel does not participate in the control loop.
- Current diagnostic evidence is not suitable for restrictive policy use.
- The published post-audit artifact reports about 26.26 alert
  episodes/track-hour on the clean arm.
- It reports 102.95 and 262.57 on the φ=0.5 and φ=0.85 autocorrelated arms.
- It reports a 0.9167 mission probability of at least one alert.
- It reports about 99.35% fused-monitoring abstention under ordinary acoustic
  missingness.
- These results are diagnostic, not acceptance results. They block operational
  policy use until repeated-look and availability calibration is complete.

## 2. Verdict vocabulary and limits

[`FusedVerdict`](../crates/galadriel-core/src/fusion.rs) defines exactly these
fused advisory values:

- `Nominal`
- `AttributedInconsistency`
- `BroadDegradation`
- `UnclassifiedAnomaly`
- `InsufficientEvidence`

Invalid input or configuration returns `Err(..)` outside the enum. The vocabulary
has no `StateUnusable` verdict. It also has no `calibrated_for_policy`
self-assertion. See item 5 in section 3.

The retained
[0.9.0 public-API snapshot](../release/0.9.0/api/galadriel-core.0.9.0.txt)
locks the exact enum surface. Unit tests next to
[`fusion.rs`](../crates/galadriel-core/src/fusion.rs) cover the variants and
fail-closed cases.

| Verdict | Meaning | Prohibited interpretation |
|---|---|---|
| `Nominal` | Magnitude evidence is ready and χ²-consistent. Every configured common-projection correlation axis is intact. | The state is true. Sensors are safe. A controller can act. A lease is valid. No coordinated spoof exists. A limit can be relaxed. |
| `AttributedInconsistency { channels, magnitude }` | One or more channels have attributed statistical inconsistency. Localized NIS elevation, signed-correlation decoupling, or both supply this evidence. `magnitude` records magnitude evidence. | The report identifies an attack cause. It contains statistical evidence only. The cause is unclassified. |
| `BroadDegradation` | A configured broad fraction of ready channels has inflated NIS. Cross-channel structure remains intact. | The report proves jamming. The cause is unclassified. |
| `UnclassifiedAnomaly { channels }` | Positive but conflicting, mixed-direction, cross-axis, or incomplete evidence prevents a narrower fused class. | No problem exists. |
| `InsufficientEvidence` | Evidence is too small, stale, missing, or geometrically incomparable. This verdict fails closed. | `Nominal`. A consumer must never silently upgrade it. |

The primary rule is that **`Nominal` cannot widen authority**. A consumer must
make these effects mechanically impossible for every Galadriel verdict:

- create `ALLOW`
- change `DENY` to `ALLOW`
- increase a velocity or slew limit
- extend a command TTL
- refresh a plant watchdog
- restore an expired lease
- replace stale trusted state
- erase an independent source-health fault

## 3. Consumer contract

This section is normative for integrators.

1. **Keep Galadriel non-authoritative and monotonic.** Evidence can reduce
   authority only. It cannot grant or widen authority. Consumer authorization
   must remain complete and correct without Galadriel.
2. **Start with record-only use.** First calibrate Galadriel independently on the
   consumer's own pre-gate data. Before that calibration, record evidence without
   changing an `ALLOW` or `DENY` result. This behavior is not fail-open. The
   assurance profile makes Galadriel optional and assigns no safety claim to it.
3. **Use restrict-only behavior only after calibration.** A future profile can let
   a specific qualified verdict reduce a speed envelope. It can instead shorten a
   command horizon or require a hold or replan. The effect needs a bound, dwell,
   hysteresis, rate limit, and explicit recovery. Restrictive evidence is also a
   denial-of-service lever.
4. **Do not make a synchronous feedback loop.** Do not feed a verdict into the
   authorization epoch whose commands changed the observed motion. That path
   closes a causal cycle. The cycle can oscillate or confirm itself. Export
   decisions asynchronously to an immutable evidence archive. Evaluate the joined
   trace offline.
5. **Derive state usability and policy eligibility in the consumer.** Galadriel
   supplies one advisory input, not a conclusion. `StateUnusable` is a
   consumer-derived qualification over several signed inputs. These inputs include
   covariance, freshness, heartbeat, frame validity, and plant mode. They can also
   include an admitted Galadriel result. Galadriel never emits `StateUnusable`.

   The consumer uses an independent signed monitor-admission record to decide
   policy eligibility. It keys that record by a profile digest. Galadriel never
   puts a self-admission Boolean in its message.
6. **Authenticate independently.** Current uses of "signed" and "attested" do not
   mean cryptographic signatures. "Signed correlation" is the positive or negative
   sign of the Pearson coefficient. "Producer-attested projection" is a producer
   provenance claim. NCP transport identity and ACLs must bind the publisher to
   authenticate that claim.

   A consumer must not treat Galadriel output as signed
   evidence before a signed advisory envelope exists. See section 5.

   The consumer must bind transport identity to application identity. Zenoh 1.9
   trusts built-in public WebPKI roots and the deployment CA. The deployment must
   apply the router-authentication mitigation in
   [`SECURE-DEPLOYMENT.md`](SECURE-DEPLOYMENT.md#tls-server-authentication-limitation).
   Local configuration alone does not exclusively pin the router.
7. **Use distinct identities for a future publisher.** A signed
   Galadriel-to-consumer publisher needs separate input and output identities. The
   input identity subscribes. The output identity publishes advisories. Neither
   identity can access a control route.
8. **Prove prohibited effects.** Integration tests must prove that Galadriel cannot
   publish controller intent or a final command. They must prove that it cannot
   issue or extend a lease. They must prove that `Nominal` cannot create `ALLOW`
   or relax a limit.

   Replayed, stale, wrong-session, and malformed advisories must
   have no policy effect. A Galadriel crash or absence must not change the profile.
   Advisory flooding must not exhaust consumer memory or delay a command deadline.

## 4. Upstream requirements for meaningful evidence

Standalone cross-sensor assessment needs accepted observations for one track and
sequence. Each observation must use a common coordinate projection from one
frozen pre-update prior.

A complete operational two-route lifecycle also needs explicit rejected
observations, misses, and a producer heartbeat.

Historical and default Crebain captures omit the attested common projection.
Thus, correlation and fused assessment correctly return
`InsufficientEvidence`. The NIS baseline remains usable.

The captures contain only successful updates after association and a chi-square
gate. Rejected and missed measurements are censored instead of represented. The
stream cannot qualify lifecycle-complete operational availability. A consumer
must not interpret either gap as safety.

A retained historical opt-in producer fixture had frozen-prior projections and
explicit misses and rejections. It does not qualify a current reciprocal
integration. No accepted recorded study has measured the selection effects or
calibrated the stream.

## 5. Current implementation status

### Input only

`galadriel-ncp` provides bounded JSONL input and a strict two-route operational
Zenoh receiver. It remains read-only for downstream policy. No signed
Galadriel-to-consumer advisory publisher exists.

Reports are available only through in-process library results or CLI files. They
are not available through an external advisory transport. Haldir is a downstream
contract example, not a qualified integration. Galadriel has no command credential
and cannot call an authorization path.

### NCP wire 0.8

Galadriel pins `ncp-core` and `ncp-zenoh` to the immutable revision selected by
the public `v0.8.0` tag. The current NCP wire-1.0 extension topology is an
unreleased candidate. Its ecosystem ADRs remain proposals with no normative
effect.

Galadriel named sensor sidecars are wire-0.8 project surfaces. They are not native
wire-1.0 extensions.

Crebain `4c311900ade5668200a48d56fb191be1916b884a` and Galadriel
`81437d807ca83b66b45c8353968948e540072d97` form a retained historical sidecar and
registry compatibility fixture. This pair does not pin or qualify the current
candidate. Current reciprocal integration and final cross-repository
qualification are `NOT_CLAIMED`.

Prisoma observes normative NCP sensor frames. It is not a Galadriel sidecar
consumer. Galadriel project-owned sidecars are prohibited from the normative
`SensorFrame` publication path.

The live taps and operational join have in-process Zenoh loopback coverage. No
retained external multi-process mTLS and ACL run exists between current binaries.

### No downstream runtime edge

The 2026-07-18 discovery inspection found no Galadriel dependency, route,
publisher, subscriber, or adapter in Haldir remote `main` at
`0e94f61cfd5c78482198a765157571746a256181`.

The second read-only inspection on 2026-07-18 observed
`dd3d8a1c993721f89a1edb04dec5247761c694ad`. Git history retains it as a
descendant. It follows Haldir current-head qualification and initial repository
inventory commits.

The 2026-07-22 inspection observed descendant
`c0e4b3d156500684329a92bcb16e0609894fd738`. Its active CH-T001 downstream
disposition records no runtime-surface or external-conformance change.

A later read-only observation on 2026-07-23 found descendant
`590ba767b32a27d9dd61a2462968306c1052434e`. Its intervening changes affect
audit, evidence, and release tooling only. It creates no runtime edge or
external-conformance change.

This later object is mutable coordination provenance.
The refreshed Galadriel inspection cut retains it.

These commits did not create a Galadriel edge. A newer observation changes only
the preceding mutable-head reference. It does not change an earlier observation
or frozen historical evidence.

The Haldir Galadriel phase has not started. A future adapter MUST admit a raw
Galadriel verdict into a Haldir-owned record. It MUST derive `StateUnusable` and
policy eligibility independently. It MUST NOT accept these conclusions as
producer assertions.

Prisoma `63cff105e0e40281376e6f827d7782e9b351961a` also has no direct Galadriel
edge. Its optional observer accepts only exact base-plane keys. It rejects named
sensor subkeys.

A future offline covariate importer MUST bind these values:

- exact source and configuration
- session and epoch
- source window
- receipt time

It MUST reject stale, replayed, malformed, and post-treatment inputs. It MUST
preserve abstention. It MUST remain unable to change treatment or result logic.

Both projects use `pid-rs`. Their outputs are not independent-implementation
replication. Shared code alone does not prove statistical dependence between
their outputs.

### Explicit local non-edges

`engram/ncp` is a configurable NCP realm example. It is not an Engram or
Paper2Brain application interface.

The 2026-07-23 Paper2Brain observation records remote `main` at
`24e74b781a5bf8af069f69cbc2d0c42d89008211`.
It found no Galadriel dependency, API, process, route, adapter, or runtime edge.
The object is mutable provenance, not an integration pin.

Galadriel has no ROS or ROS 2 dependency, message binding, topic, service, action,
node, bag importer, or bridge. It has no external command, control, credential,
lease, watchdog, or authority path. These relationships are absent, not optional.

The declared graph is acyclic. Upstream libraries and an optional producer point
into Galadriel. Prospective evidence consumers point outward. No feedback edge
returns to an upstream or command path.

Before any restrict-only profile becomes a candidate, complete these actions in
order:

1. Build the signed advisory envelope.
2. Retain an external secured interoperability campaign.
3. Complete an independent recorded calibration study.

## 6. Prohibited connections

- **Do not let Galadriel control Crebain fusion weights or feedback in an initial
  deployment.** Down-weighting is a denial-of-service lever. An attacker can
  induce apparent uniqueness in a healthy channel and suppress it. Down-weighting
  also reenters the feedback loop from item 4 in section 3.

  Treat sensor-quality arbitration as a separate Crebain research program.
  This program needs calibration, falsification, a weight floor, and stability analysis.
  It is not a basic interface.
- **Do not give a consumer-to-Galadriel path control authority.** Galadriel must
  have no controller-intent or final-command credentials. It must not issue leases
  or change admission or policy. The command path, such as Haldir to Crebain, must
  remain available without Galadriel. Its governance must remain independent of Galadriel.

---

This boundary complements cryptographic ACL and mTLS enforcement and the
plant-side safety governor. A deployment can bind transport identity and ACLs.
Galadriel then reports consistency evidence from that authenticated producer.

Local artifacts do not prove that binding. `producer_id` alone is asserted
metadata. Galadriel never authenticates physical truth. Interpret every verdict
under this boundary.
