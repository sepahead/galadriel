# Galadriel 0.9.0 normative claims

## Abbreviations

| Short form | Meaning |
|---|---|
| DOI | digital object identifier |
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
affirmative behavior. The reason and missing evidence **SHALL** remain visible. This
tier is not an implementation success. A public statement may not describe it as
one.

The release implements a bounded and fail-closed advisory component. It validates
parts of the component under specified conditions. It makes none of these claims:

- sensor truth
- attack intent
- calibrated posterior probabilities
- accepted operational rates
- NCP 1.0 qualification
- a released upstream pid-rs 1.x artifact
- a downstream policy integration
- secured multi-process deployment
- crates.io publication
- production support
- a DOI
- a Zenodo record

Dated read-only ecosystem inspections through 2026-07-23 do not change a claim tier.
Galadriel remains pinned to NCP wire 0.8. The inspected Crebain component retains
schema-v1 fixture alignment without a reciprocal final-candidate pin. Haldir has
no runtime adapter. Prisoma has no direct sidecar route.

The local source inventory records three more boundaries.
`engram/ncp` is an example realm.
The 2026-07-23 Paper2Brain observation does not create an integration.
ROS and ROS 2 have no binding or bridge.
Galadriel has no external command-authority path.

[`ECOSYSTEM-CONNECTIONS.md`](ECOSYSTEM-CONNECTIONS.md) lists the exact inspected
objects. It also lists the explicit non-edges and missing evidence for each
relationship.
