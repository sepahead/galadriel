# Galadriel 0.9.0 normative claims

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| DOI | digital object identifier |
| mTLS | mutual Transport Layer Security |
| NCP | Neuro-Cybernetic Protocol |
| ROS | Robot Operating System |

The machine-readable source of truth is
[`release/0.9.0/claims.json`](../release/0.9.0/claims.json). This page explains
how to read that file. It does not add a claim.

**GLD-090-CLM-001:** Every public statement about 0.9.0 **SHALL** use one of
these four tiers:

- `IMPLEMENTED`
- `VALIDATED`
- `DEPLOYMENT_QUALIFIED`
- `NOT_CLAIMED`

Component tests establish implementation. They **SHALL NOT** be described as
deployment qualification.

**GLD-090-CLM-002:** A `VALIDATED` claim **SHALL** name its exact evidence
population. The evidence can use a synthetic, fixture-based, in-process, or
external population. The claim **SHALL NOT** extend to field performance, attack
coverage, safety, or another platform.

**GLD-090-CLM-003:** A `DEPLOYMENT_QUALIFIED` claim **SHALL** require retained,
independent evidence from the target deployment. Galadriel 0.9.0 has no claim in
this tier.

**GLD-090-CLM-004:** `NOT_CLAIMED` **SHALL** mean that the release promises no
affirmative behavior.
The reason and missing evidence **SHALL** remain visible.
This tier is not an implementation success.
A public statement **SHALL NOT** describe it as one.

Version 0.9.0 implements a bounded and fail-closed advisory component. It validates
parts of the component under specified conditions. It makes none of these claims:

- sensor truth
- attack intent
- calibrated posterior probabilities
- accepted operational rates
- `Galadriel NCP observer` native-1.0 qualification
- `Galadriel raw-advisory publisher` native-1.0 qualification
- a released upstream pid-rs 1.x artifact
- a downstream policy integration
- multi-process mTLS and ACL deployment
- crates.io publication
- production support
- a DOI
- a Zenodo record

Dated read-only ecosystem inspections through 2026-08-18 do not change a claim
tier.
Galadriel remains pinned to NCP wire 0.8.
The implemented sidecars are historical NCP 1.0 migration input.
They are not native-1.0 role evidence.

The 2026-08-03 NCP status inspection is bound to
[commit `1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd`](https://github.com/sepahead/NCP/commit/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd).
The pinned [NCP task ledger](https://github.com/sepahead/NCP/blob/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd/evidence/implementation/task-ledger.v1.json)
records `G03` as `OPEN`.
`G03` depends on `X02`, which is also `OPEN`, so `G03` is not dependency-ready.
Both named external role qualifications have no exact evidence and remain **NOT RUN**.

The pinned [NCP ecosystem blueprint](https://github.com/sepahead/NCP/blob/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd/docs/handoff/NCP_V1_0_ECOSYSTEM_FINALIZATION_BLUEPRINT.md)
defines the release-facing raw-advisory publisher as the `Galadriel assessor`.
The observer requires a read-only principal and an exact bounded grant.
The assessor requires a separate principal and a default-off push-only path.
Its payload contains raw verdict and evidence provenance with an optional
non-authoritative requested effect.
It cannot reuse observer credentials, self-admit, derive `StateUnusable`, grant
or widen authority, or encode an authoritative effect, `ALLOW`, or command.
No native-1.0 raw-advisory publisher exists.
Galadriel uses `NOT_CLAIMED` for its release claim tier.
NCP uses **NOT RUN** for the unexecuted external qualification gates.
Neither state is implementation or validation evidence.

Crebain is an optional reference producer with no Galadriel Cargo dependency.
The inspected Crebain component has schema-v1 fixture alignment.
It has no reciprocal Galadriel final-candidate pin or runtime qualification.
The separate immutable fixture-source cut is bound to CREBAIN commit
`6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d` and exact fixture bytes. That
source-specific custody relationship is not a reciprocal deployment claim.
The separate offline CREBAIN drone fixture and categorical MGW empirical-PMF
sample-estimator implementation are
`IMPLEMENTED` only for the exact 64-row deterministic law named in `CLM-018`.
This does not retype the raw-row route as a declared-law evaluator; exact cell
balance makes its empirical PMF coincide with the canonical fixture law only.
That claim does not establish recorded-flight inference, continuous-PID
eligibility, the wider PID3 assurance program, field performance, attack
classification, or a runtime/control edge.
Haldir is a prospective record-only consumer with no version 0.9.0 runtime edge.
Prisoma is a prospective immutable offline consumer with no version 0.9.0
runtime edge.

The local source inventory records four more boundaries.
`engram/ncp` is an example realm.
The 2026-07-23 Paper2Brain observation does not create an integration.
ROS and ROS 2 have no binding or bridge.
Galadriel has no external command-authority path.

[`ECOSYSTEM-CONNECTIONS.md`](ECOSYSTEM-CONNECTIONS.md) lists the exact inspected
objects. It also lists the explicit non-edges and missing evidence for each
relationship.
