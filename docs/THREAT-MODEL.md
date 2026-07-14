# Threat model

This threat model covers the 0.9.0 advisory monitor, its evidence inputs, optional
transport adapters, release artifacts, and downstream use. It complements rather
than replaces the deployment-specific ACL/mTLS model.

## Assets and trust boundaries

Protected assets are the integrity and availability of observation evidence,
provenance identities, detector state/configuration, report interpretation,
release evidence, and the independence of the actual control/safety path. Trust
crosses boundaries at the physical sensor, estimator/producer, NCP transport,
Galadriel decoder, detector core, evidence archive, and any downstream consumer.

The physical scene, sensor and estimator are not trusted to be honest. A
producer-declared frame/prior is only a claim until a deployment binds it to an
authenticated producer. The transport is not trusted merely because a local
configuration file is strict. Galadriel is never trusted with controller, lease,
plant, or authorization credentials.

**GLD-090-THR-001:** Invalid, stale, missing, replayed, contradictory, incomparable,
or resource-excess evidence **SHALL NOT** become `Nominal`. It shall produce a
typed error, explicit insufficiency/unclassified evidence, or bounded rejection.

**GLD-090-THR-002:** Galadriel **SHALL NOT** grant authority, authenticate physical
truth, infer malicious intent, close a synchronous control feedback loop, or
replace an independent safety mechanism.

**GLD-090-THR-003:** Every ingestion surface **SHALL** impose explicit size, count,
identity, sequence, time, and retained-state bounds before unbounded work or state
growth. A transport-level message bound remains required before callback materialization.

## Adversaries and failures

The model includes an external spoofer; one or several compromised sensors; a
compromised or faulty producer; a publisher with the wrong route/session/epoch; a
network attacker without, and separately with, a valid credential; a replaying or
delaying broker; a malicious fixture/configuration author; an accidental operator;
and a downstream consumer that misinterprets advisory output. It also treats
ordinary faults, drift, clock errors, scheduler delays, missing data and overload as
indistinguishable from attacks where the evidence cannot separate them.

| Threat | Required behavior | Residual risk / non-claim |
|---|---|---|
| Single-sensor spoof or fault | Magnitude and common-projection dependence evidence may localize inconsistency; cause remains unclassified. | A bias inside the covariance model or censored by association may evade detection. |
| Correlated or coordinated compromise | Axis disagreement and broad magnitude changes fail closed; signed geometry is retained. | A coordinated statistics-preserving attack can remain nominal; truth is not claimed. |
| Moment-matched spoof | Report only the statistics actually observed. | It can defeat NIS and any preserved dependence statistic. |
| Association/gate missingness | Operational lifecycle evidence represents update, rejection, miss and heartbeat; absence never becomes a healthy sample. | Historical successful-update-only captures are selection-biased and cannot validate cross-modal claims. |
| Partial sensor silence | Expected modalities remain unready/stale and block nominal. | All-modal silence needs an independent heartbeat/deadline because no input call advances detector time. |
| Timestamp freeze/regression | Reject as malformed; do not mutate accepted state. | Authenticated but false producer time remains a producer-compromise case. |
| Excessive gap/skew/reorder | Reset/abstain according to the explicit epoch and window rules; never ordinally realign unequal tails. | Loss can create prolonged abstention and is a denial-of-service lever. |
| Replay/prior reuse | Reject duplicate/regressing identities and cross-sequence frozen-prior reuse in the bounded operational assembler. | Lifetime replay protection requires epoch rollover before bounded ledgers exhaust. |
| Route/session/producer confusion | Exact realm, route, schema, session, producer, registry and version checks; wrong provenance is terminal or rejected. | Payload identity is not authenticated without transport identity/ACL binding. |
| Router/server substitution | Use a non-publicly-issuable private router hostname with controlled resolution, or enforce the exact router certificate/SPKI in an external layer; retain the certificate actually presented. | The pinned Zenoh 1.9 client trusts built-in public WebPKI roots in addition to the deployment CA. Local profile validation does not exclusively pin the router, and that exclusivity is `NOT_CLAIMED`. |
| Malformed/duplicate-key/oversized JSON | Bound size before parse where the API permits, reject duplicate keys and non-exact integers, retain typed fault counters. | Zenoh may allocate transport bytes before the application size gate; broker bounds are mandatory. |
| Advisory replay/staleness | A future consumer must independently authenticate, bind profile digest/session/time and apply no effect when invalid. | No signed downstream advisory publisher or consumer is qualified in 0.9.0. |
| Verdict-induced authority widening | The core non-widening validator rejects deny-to-allow, increased limits/TTL/lease, watchdog mutation, and all record-only changes. | A consumer that bypasses the validator remains outside the claim. |
| Restriction abuse | Record-only is the only initial mode; any future restriction needs independent calibration, bounded effect, dwell, hysteresis and recovery. | Even restrict-only evidence is a DoS input. No such profile is qualified. |
| Feedback oscillation | No synchronous verdict-to-same-epoch control connection. | Offline joins can still have confounding; causal claims are excluded. |
| State/memory exhaustion | Cap tracks, windows, payload/line/record counts, queues, registry entries, join state and estimator work. | Sustained valid traffic can force drops/abstention; availability is not guaranteed. |
| CPU denial of service | Validate work bounds before pair/PID/bootstrap work; optional heavy features stay off by default. | Platform-specific deadlines need independent benchmarks and admission control. |
| Callback race/shutdown fault | Serialize ingress state, retain first terminal fault, bound queues, account drops, and test close/reset interleavings. | OS, network and actual-binary deployment timing remains unqualified. |
| Configuration substitution | Validate strict closed schemas/canonical digests and bind profile/registry/credential identities. | A privileged operator can replace all local artifacts unless deployment signing/attestation is provided. |
| Dependency/source substitution | Cargo.lock, exact Git revisions, pinned toolchain and generated audit hashes are mandatory. | Registry compromise and compiler trust require external supply-chain controls. |
| Evidence tampering or cherry-picking | Complete logs, checksums, exact commits/toolchains, seeds, status ledger and residual risks are retained. | 0.9.0 has no independent archive/DOI; GitHub availability is not permanent preservation. |

## Safe failure states

Malformed representation is an error, statistical non-identifiability is
`InsufficientEvidence`, positive but non-localizable evidence is
`UnclassifiedAnomaly`, transport/assembler integrity faults stop the affected
epoch, and resource pressure rejects/drops according to the documented bounded
policy with health accounting. None of these states is silently mapped to
`Nominal`; none directly commands a plant.

## Security acceptance boundary

Component tests can establish parsing, state and policy invariants. Deployment
qualification additionally requires an actual multi-process router campaign that
retains correct-certificate allow results, wrong/no-certificate denies, wrong-route
denies, replay/stale behavior, saturation, resource measurements, the router certificate
actually presented, the server-authentication mitigation, and independent configuration
identities. That evidence does not exist for 0.9.0, so secured deployment remains
`NOT_CLAIMED`.
