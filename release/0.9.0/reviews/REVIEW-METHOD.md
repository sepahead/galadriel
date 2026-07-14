# Galadriel 0.9.0 review method

Release author and final decision owner: **Sepehr Mahmoudian**

Review date: 2026-07-14

Target: GitHub source release 0.9.0 (no project DOI or Zenodo record)

This record adapts the supplied Galadriel 1.0 handoff to the author's requested
0.9.0 release identity without weakening its technical checks. Repository review
is machine-assisted and performed against immutable Git blobs, retained command
logs, and explicit claim/task ledgers. Machine assistance is not authorship or an
independent human review. Independent statistical/security review and an
independent clean-room reproduction remain `NOT_CLAIMED` until a person or
organization independent of this preparation supplies evidence.

An external reviewer can comment on the per-file ledger, task dispositions,
threat register, claims matrix, and final decision. A comment does not become a completed
review merely by existing: the release record must identify the reviewer, exact
commit/tree, finding, disposition, and date before it may be credited.

## Review states

- `RESOLVED`: a concrete finding was checked, any release-blocking defect was
  corrected or its affirmative claim was removed, and the named evidence exists.
- `NOT_APPLICABLE`: the lens has no semantic surface in the task's exact scope;
  the finding must state a falsifiable reason and identify the evidence used to
  establish absence.
- `NOT_CLAIMED`: the requested outcome needs evidence outside this release's
  authority or available inputs. The corresponding public claim is explicitly
  removed and residual risk retained.
- `OPEN`: evidence or review is incomplete. An `OPEN` task blocks publication.

Passing compilation alone cannot close a task. Each completed task records
normative requirements, tests, retained evidence, all twenty lens results, and a
residual risk. Task dependencies close strictly in order from T000 through T115.

## Adversarial twenty-lens standard

Every task, public statement, schema, example, proof, benchmark, and release
artifact receives all twenty reviews. `NOT_APPLICABLE` requires the same concrete
evidence and review discipline as `RESOLVED`.

1. **L01 — Claims and scope.** Separate implemented, verified, validated,
   deployment-qualified, field-validated, and not-claimed statements; test whether
   a reader could infer more than the exact evidence tier supports.
2. **L02 — First-principles semantics.** Make inputs, state, transitions, outputs,
   invariants, units, and failure states explicit.
3. **L03 — Mathematics and statistics.** Check definitions, assumptions,
   estimands, finite-sample behavior, multiplicity, uncertainty, calibration, and
   failure regions.
4. **L04 — Type and state integrity.** Attempt to construct invalid combinations
   through safe APIs, decoding, features, defaults, and migration paths.
5. **L05 — Time, ordering, and replay.** Check clock domains, freshness,
   deadlines, epochs, sequences, duplicates, restart, and rollover.
6. **L06 — Identity and provenance.** Bind results, configurations, builds,
   evidence, schemas, datasets, and commands to immutable identities.
7. **L07 — Authentication and cryptography.** Check canonical bytes, domain
   separation, identities, rotation, revocation, downgrade behavior, and terminal
   failure semantics.
8. **L08 — Authority and safety.** Distinguish observation, advice, intent,
   authorization, publication, application, and confirmation; optional or failed
   components may not widen authority.
9. **L09 — Hostile inputs and parsers.** Exercise duplicates, unknown fields,
   unsafe integers, non-finite values, malformed nesting, paths, and contradictory
   metadata.
10. **L10 — Resource and denial-of-service bounds.** Bound bytes, allocation,
    dimensions, state, queues, retries, tasks, log volume, and compute before work.
11. **L11 — Concurrency and lifecycle.** Review initialization, callback
    ownership, races, cancellation, cleanup, poison, crash consistency, and
    shutdown.
12. **L12 — Determinism and reproducibility.** Record exact inputs and commands
    for builds, fixtures, simulations, evidence, and archives.
13. **L13 — API, FFI, and SemVer.** Minimize stable surface and make panics,
    ownership, allocation, thread safety, features, MSRV, and compatibility clear.
14. **L14 — Schema, wire, and language parity.** Require one normative semantic
    source and matching accept/reject behavior across encodings and consumers.
15. **L15 — Configuration and deployment.** Reject invalid profiles before
    startup and review paths, secrets, permissions, ACLs, certificates, ordering,
    rollback, and withdrawal.
16. **L16 — Observability and forensics.** Distinguish disabled, unavailable,
    stale, incompatible, insufficient, anomalous, denied, and internal-fault states
    without secret leakage.
17. **L17 — Verification and evidence quality.** Match each claim to the needed
    theorem, model, property, fuzz, mutation, clean-room, router, statistical, or
    physical evidence.
18. **L18 — Ecosystem composition.** Make pid-rs, NCP, Crebain, Haldir, Prisoma,
    Paper2Brain/Engram, ROS, and authority relationships explicit and acyclic.
19. **L19 — Human factors and governance.** Review naming, examples, runbooks,
    roles, incident response, support, deprecation, rollback, and withdrawal under
    operator stress.
20. **L20 — Counterfactual and quirky cases.** Ask how a malicious peer, rushed
    operator, simple odd dataset, future maintainer, or generated patch could
    falsify the intended claim.

Every lens result records the defect or counterexample considered, the control or
claim removal, the exact evidence, and remaining risk. The task-level residual-risk
field records impacts that span more than one lens.

## Mandatory combined cases

The final hostile-input and lifecycle campaigns cover, or explicitly remove the
claim requiring, each of these combinations:

- authenticated or validly encoded input with stale epoch, wrong route, or an
  oversized payload;
- valid schema with contradictory semantics;
- green component tests with a divergent schema, generated artifact, or public
  API snapshot;
- nominal statistics with missing lifecycle or common-projection evidence;
- crash/cancellation before and after a selected event or advisory publication;
- matching package version with a wrong revision or contract digest;
- timeout, poison, or optional-component loss followed by a convenience fallback;
- locally valid security configuration with an untested real router;
- synthetic success with failure on a representative distribution;
- canonical payload with noncanonical identity/signing bytes;
- feature unification that unexpectedly enables a privileged adapter;
- partial migration that retains a legacy implicit default;
- clock rollback with an apparently valid TTL, lease, or deadline.

Where external router, representative field distribution, independent reviewer,
or downstream deployment evidence is unavailable, the result is not fabricated:
the affected deployment claim remains `NOT_CLAIMED`.
