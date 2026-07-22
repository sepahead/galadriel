# Galadriel 0.9.0 review method

Release author and final decision owner: **Sepehr Mahmoudian**

Review date: 2026-07-14

Target: GitHub source release 0.9.0

The target has no project DOI or Zenodo record.
This record adapts the supplied Galadriel 1.0 handoff to version 0.9.0.
The adaptation does not weaken a technical check.

The repository review uses immutable Git blobs and retained command logs.
It also uses explicit claim and task ledgers.
Machine assistance does not create authorship or an independent human review.
Independent statistical and security review remains `NOT_CLAIMED`.
Independent clean-room reproduction also remains `NOT_CLAIMED`.
That status changes only when an independent person or organization supplies evidence.

An external reviewer can comment on these records:

- per-file ledger
- task dispositions
- threat register
- claims matrix
- final decision

A comment alone is not a completed review.
The release record must identify the reviewer, commit, tree, finding, disposition, and date.

## Review states

- `RESOLVED` means that the review checked a concrete finding.
  The release corrects each blocking defect or removes the affected affirmative claim.
  The named evidence must exist.
- `NOT_APPLICABLE` means that the exact task scope has no surface for the lens.
  The finding must state a falsifiable reason.
  It must identify evidence that establishes the absence.
- `NOT_CLAIMED` means that the outcome needs unavailable evidence or authority.
  Remove the affected public claim.
  The record must retain the residual risk.
- `OPEN` means that evidence or review is incomplete.
  An `OPEN` task blocks publication.

Compilation alone cannot close a task.
Each completed task records normative requirements, tests, and retained evidence.
It also records all twenty lens results and a residual risk.
Task dependencies close in order from T000 through T115.

## Adversarial twenty-lens standard

Apply all twenty lenses to each task and public statement.
Also apply them to each schema, example, proof, benchmark, and release artifact.
A `NOT_APPLICABLE` result needs the same evidence discipline as a `RESOLVED` result.

1. **L01: Claims and scope.**
   Separate implemented, verified, validated, field-validated, deployment-qualified, and unclaimed statements.
   Check if a reader can infer a stronger result than the evidence supports.
2. **L02: First-principles semantics.**
   Make inputs, state, transitions, outputs, invariants, units, and failure states explicit.
3. **L03: Mathematics and statistics.**
   Check definitions, assumptions, estimands, finite-sample behavior, multiplicity, uncertainty, calibration, and failure regions.
4. **L04: Type and state integrity.**
   Try to construct invalid combinations through safe application programming interfaces (APIs).
   Also test decoding, features, defaults, and migration paths.
5. **L05: Time, ordering, and replay.**
   Check clock domains, freshness, deadlines, epochs, sequences, duplicates, restarts, and rollover.
6. **L06: Identity and provenance.**
   Bind results, configurations, builds, evidence, schemas, datasets, and commands to immutable identities.
7. **L07: Authentication and cryptography.**
   Check canonical bytes, domain separation, identities, rotation, revocation, downgrade behavior, and terminal failure semantics.
8. **L08: Authority and safety.**
   Distinguish observation, advice, intent, authorization, publication, application, and confirmation.
   An optional or failed component cannot widen authority.
9. **L09: Hostile inputs and parsers.**
   Exercise duplicates, unknown fields, unsafe integers, non-finite values, malformed nesting, paths, and contradictory metadata.
10. **L10: Resource and denial-of-service bounds.**
    Bound bytes, allocation, dimensions, state, queues, retries, tasks, log volume, and compute before work.
11. **L11: Concurrency and lifecycle.**
    Review initialization, callback ownership, races, cancellation, cleanup, poison, crash consistency, and shutdown.
12. **L12: Determinism and reproducibility.**
    Record exact inputs and commands for builds, fixtures, simulations, evidence, and archives.
13. **L13: API, FFI, and SemVer.**
    Minimize the stable surface.
    Define panics, ownership, allocation, thread safety, features, minimum Rust version (MSRV), and compatibility.
14. **L14: Schema, wire, and language parity.**
    Use one normative semantic source.
    Require matching accept and reject behavior across encodings and consumers.
15. **L15: Configuration and deployment.**
    Reject invalid profiles before startup.
    Review paths, secrets, permissions, access controls, certificates, ordering, rollback, and withdrawal.
16. **L16: Observability and forensics.**
    Distinguish disabled, unavailable, stale, incompatible, insufficient, anomalous, denied, and internal-fault states.
    Do not leak a secret.
17. **L17: Verification and evidence quality.**
    Match each claim to its required evidence type.
    Evidence can include a theorem, model, property, fuzz run, mutation run, or clean-room run.
    It can also include router, statistical, or physical evidence.
18. **L18: Ecosystem composition.**
    Make the pid-rs, NCP, Crebain, Haldir, Prisoma, Paper2Brain, and Engram relationships explicit.
    Make the ROS and authority relationships explicit.
    Keep the relationship graph acyclic.
19. **L19: Human factors and governance.**
    Review naming, examples, runbooks, roles, incident response, support, deprecation, rollback, and withdrawal.
    Review these items under operator stress.
20. **L20: Counterfactual and unusual cases.**
    Look for a malicious peer or rushed operator that can falsify the claim.
    Also test a small unusual dataset, future maintenance, and generated patches.

Each lens result records four items:

1. the defect or counterexample considered
2. the control or claim removal
3. the exact evidence
4. the remaining risk

The task residual-risk field records effects that span more than one lens.

## Mandatory combined cases

The final hostile-input and lifecycle campaigns must cover these cases:

- authenticated input with a stale epoch, wrong route, or oversized payload
- validly encoded input with a stale epoch, wrong route, or oversized payload
- valid schema with contradictory semantics
- green component tests with a divergent schema or generated artifact
- green component tests with a divergent public API snapshot
- nominal statistics with missing lifecycle evidence
- nominal statistics with missing common-projection evidence
- cancellation before and after a selected event or advisory publication
- a crash before and after a selected event or advisory publication
- matching package version with the wrong revision or contract digest
- timeout, poison, or optional-component loss followed by a convenience fallback
- locally valid security configuration with an untested real router
- synthetic success with failure on a representative distribution
- canonical payload with noncanonical identity or signing bytes
- feature unification that enables an unexpected privileged adapter
- partial migration that retains a legacy implicit default
- clock rollback with an apparently valid time-to-live value, lease, or deadline

Remove the applicable claim when a required campaign cannot cover its case.
Do not fabricate unavailable evidence.
Keep the affected deployment claim at `NOT_CLAIMED`.
