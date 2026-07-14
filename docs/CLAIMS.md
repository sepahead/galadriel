# Galadriel 0.9.0 normative claims

The machine-readable source of truth is
[`release/0.9.0/claims.json`](../release/0.9.0/claims.json). This page explains how
to read it; it does not expand any claim.

**GLD-090-CLM-001:** Every public statement about 0.9.0 **SHALL** use one of four
tiers: `IMPLEMENTED`, `VALIDATED`, `DEPLOYMENT_QUALIFIED`, or `NOT_CLAIMED`.
Component tests establish implementation; they **SHALL NOT** be represented as
deployment qualification.

**GLD-090-CLM-002:** A `VALIDATED` claim **SHALL** name the exact synthetic,
fixture, in-process, or external population to which its evidence applies. It
**SHALL NOT** be generalized to field performance, attack coverage, safety, or
another platform.

**GLD-090-CLM-003:** A `DEPLOYMENT_QUALIFIED` claim **SHALL** require retained,
independent target-deployment evidence. Galadriel 0.9.0 has no claims in that tier.

**GLD-090-CLM-004:** `NOT_CLAIMED` **SHALL** mean no affirmative behavior is
promised; the reason and missing evidence shall remain visible. It is not an
implementation success and may not be paraphrased as one.

The release implements a bounded, fail-closed advisory component and validates
parts of it under explicit component conditions. It does not claim sensor truth,
attack intent, calibrated posterior probabilities, accepted operational rates,
NCP 1.0 qualification, a released upstream pid-rs 1.x artifact, a downstream
policy integration, secured multi-process deployment, crates.io publication,
production support, a DOI, or a Zenodo record.
