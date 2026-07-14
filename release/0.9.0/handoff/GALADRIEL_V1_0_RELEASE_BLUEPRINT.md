# Galadriel 1.0 — Exhaustive 1.0 Release Blueprint

## Handoff purpose

This is a standalone implementation specification for an agent working primarily in `https://github.com/sepahead/galadriel`. The agent may edit related repositories only when required to qualify a claimed integration, update an immutable pin, add a conformance fixture or adapter, migrate a consumer, or correct public documentation. It must not redesign unrelated repositories.

The release may intentionally break pre-1.0 compatibility. Correctness, security, mathematical meaning and verifiability take priority over preserving ambiguous behavior.

## Mission

Deliver a mathematically explicit, fail-closed, advisory-only cross-sensor consistency monitor whose stable API, statistical meaning, calibration evidence, wire contracts, resource bounds, and ecosystem behavior are suitable for a truthful 1.0 release.

## Audited starting point

The audited public README describes version 0.1.0 as a pre-1.0 research prototype. It implements NIS/CUSUM magnitude monitoring, signed cross-channel correlation, conservative fusion, optional pid-rs evidence, bounded NCP/Zenoh ingestion, synthetic evaluation, and an opt-in Crebain producer/receiver path. Its own retained evidence reports high false-alert rates and severe abstention under ordinary missingness, so operational claims are not yet justified.

## Hard non-goals

- Do not claim that consistency establishes truth or identifies an attacker.
- Do not grant Galadriel command authority or permit it to create or widen ALLOW.
- Do not make Galadriel mandatory for pid-rs, Prisoma, Crebain core, Haldir baseline policy, or NCP.
- Do not use PID or mutual information to repair missing geometry, lifecycle evidence, or signed-consensus failures.
- Do not market synthetic studies as field validation.

## Definition of “rock solid”

For this handoff, “rock solid” means:

- the stable contract is explicit and internally consistent;
- invalid or unavailable prerequisites fail closed or produce explicit abstention;
- every resource is bounded or the unbounded dependency is clearly outside the claim;
- security and authority assumptions are machine-enforced where possible;
- cross-language or cross-repository semantics are proven by shared vectors;
- mathematical/statistical claims have independent evidence suitable to their scope;
- deployment claims have real multi-process evidence, not only in-process mocks;
- all public metadata is truthful at the exact release commit;
- an independent party can reproduce the build and critical evidence;
- unsupported capabilities are removed from the 1.0 claim set rather than hand-waved.

## Agent operating rules

1. Begin by reading `PACKAGE_INDEX.md`, this blueprint, the architecture, schema, migration guide, checklist and ledger.
2. Create a work branch and immutable `audit-inputs.json` before modifying code.
3. Do not mark tasks complete based only on compilation or unit tests.
4. Use requirement identifiers in code comments, tests, schemas and evidence manifests.
5. Preserve complete command output for release gates.
6. Do not update evidence files manually; generate them with checked-in deterministic tooling.
7. When evidence disproves a desired claim, narrow the claim or redesign the system.
8. Never convert optional-component absence into success.
9. Never invent a cross-repository compatibility claim; run it.
10. Stop publication if any go/no-go item is unresolved.

## Release claim tiers

- **Implemented:** code path exists and basic tests pass.
- **Verified:** specified invariants and conformance tests pass.
- **Validated:** quantitative or domain evidence supports the declared operating region.
- **Deployment-qualified:** real multi-process secure-reference evidence exists.
- **Field-validated:** independent representative physical evidence exists.
- **Not claimed:** deliberately excluded from 1.0.

The README and release notes must state the correct tier for every major feature.

## Required deliverables in the repository

- normative architecture and contract documents;
- stable schemas/IDL and generated parity checks;
- golden positive and negative vectors;
- requirement and evidence ledgers;
- reproducible release audit tooling;
- migration guide and consumer impact table;
- secure deployment or calibration artifacts where applicable;
- release manifest, checksums, SBOM and provenance attestations;
- independent reproduction record;
- final residual-risk register.

## Phase 1: Freeze claims, estimands, threat model and release identity

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T000 — Create an immutable audit manifest for every repository, toolchain, dataset and external paper used.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Create an immutable audit manifest for every repository, toolchain, dataset and external paper used.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T001 — Write a normative 1.0 claims matrix separating implemented, validated, deployment-qualified and explicitly unclaimed behavior.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Write a normative 1.0 claims matrix separating implemented, validated, deployment-qualified and explicitly unclaimed behavior.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T002 — Define the exact statistical estimands for every report field and verdict.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define the exact statistical estimands for every report field and verdict.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T003 — Write a threat model covering spoofing, correlated compromise, missingness, timing faults, route confusion and denial of service.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Write a threat model covering spoofing, correlated compromise, missingness, timing faults, route confusion and denial of service.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T004 — Define advisory-only authority invariants and machine-testable non-widening rules.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define advisory-only authority invariants and machine-testable non-widening rules.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T005 — Choose the stable crate and feature surface; remove accidental public APIs.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Choose the stable crate and feature surface; remove accidental public APIs.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T006 — Resolve licensing, citation, authorship, support and security-contact metadata.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Resolve licensing, citation, authorship, support and security-contact metadata.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T007 — Replace mutable-version dependencies with immutable release or revision pins for qualification.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Replace mutable-version dependencies with immutable release or revision pins for qualification.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T008 — Create a requirement-to-evidence ledger with no prose-only closure.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Create a requirement-to-evidence ledger with no prose-only closure.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T009 — Declare the 1.0 release candidate branch, freeze window and change-control rules.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Declare the 1.0 release candidate branch, freeze window and change-control rules.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 2: Refactor core types, errors, state machines and stable API

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T010 — Introduce domain types for track, modality, projection context, frozen prior, epoch, session and stream position.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Introduce domain types for track, modality, projection context, frozen prior, epoch, session and stream position.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T011 — Separate invalid input, insufficient evidence, anomaly evidence and internal fault in the public result model.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Separate invalid input, insufficient evidence, anomaly evidence and internal fault in the public result model.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T012 — Make every detector configuration validated at construction and immutable thereafter.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Make every detector configuration validated at construction and immutable thereafter.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T013 — Eliminate Boolean configuration where a closed enum or capability type is required.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Eliminate Boolean configuration where a closed enum or capability type is required.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T014 — Define deterministic state-transition tables for observation, miss, rejection, heartbeat, timeout and reset events.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define deterministic state-transition tables for observation, miss, rejection, heartbeat, timeout and reset events.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T015 — Make reset and epoch rollover explicit, auditable operations rather than implicit state clearing.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Make reset and epoch rollover explicit, auditable operations rather than implicit state clearing.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T016 — Version all serialized reports and reject unknown required semantics.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Version all serialized reports and reject unknown required semantics.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T017 — Implement canonical serialization and domain-separated report digests.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Implement canonical serialization and domain-separated report digests.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T018 — Audit numerical conversions, timestamps, integer widths and unsafe JSON number handling.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Audit numerical conversions, timestamps, integer widths and unsafe JSON number handling.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T019 — Freeze a minimal stable Rust API and document all panic, allocation and complexity behavior.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Freeze a minimal stable Rust API and document all panic, allocation and complexity behavior.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 3: Prove NIS and sequential-test mathematics and multiplicity control

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T020 — Derive and document the exact NIS reference distribution and assumptions for each supported observation model.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Derive and document the exact NIS reference distribution and assumptions for each supported observation model.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T021 — Specify behavior for rank-deficient, ill-conditioned and estimated innovation covariance.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Specify behavior for rank-deficient, ill-conditioned and estimated innovation covariance.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T022 — Implement robust covariance validation and stable factorization with explicit tolerances.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Implement robust covariance validation and stable factorization with explicit tolerances.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T023 — Define the sequential statistic, reset rule, head-start, sidedness and alarm episode semantics.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define the sequential statistic, reset rule, head-start, sidedness and alarm episode semantics.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T024 — Replace repeated-look ambiguity with an explicit alpha-spending, anytime-valid or calibrated sequential procedure.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Replace repeated-look ambiguity with an explicit alpha-spending, anytime-valid or calibrated sequential procedure.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T025 — Control multiplicity across channels, directions, axes and repeated assessments.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Control multiplicity across channels, directions, axes and repeated assessments.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T026 — Add analytic and simulation tests against chi-square quantiles and known noncentral alternatives.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Add analytic and simulation tests against chi-square quantiles and known noncentral alternatives.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T027 — Measure calibration sensitivity to covariance-scale error, heavy tails and serial dependence.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Measure calibration sensitivity to covariance-scale error, heavy tails and serial dependence.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T028 — Define lower-tail anomalies separately from high-magnitude anomalies.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define lower-tail anomalies separately from high-magnitude anomalies.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T029 — Produce machine-readable operating curves with uncertainty intervals for every supported configuration.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Produce machine-readable operating curves with uncertainty intervals for every supported configuration.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 4: Prove signed-correlation, geometry and attribution semantics

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T030 — State the exact signed-correlation estimand, sample window and missing-data rule.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'State the exact signed-correlation estimand, sample window and missing-data rule.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T031 — Prove or replace the strict-majority positive-consensus attribution algorithm.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Prove or replace the strict-majority positive-consensus attribution algorithm.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T032 — Define dyad, tie, no-clique, contradictory-axis and partial-readiness behavior.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define dyad, tie, no-clique, contradictory-axis and partial-readiness behavior.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T033 — Control pairwise and axis-wise multiplicity under the actual decision rule.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Control pairwise and axis-wise multiplicity under the actual decision rule.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T034 — Add robust alternatives or explicitly reject non-Gaussian/outlier-sensitive use cases.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Add robust alternatives or explicitly reject non-Gaussian/outlier-sensitive use cases.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T035 — Make producer-attested geometry validation mandatory before cross-modal comparison.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Make producer-attested geometry validation mandatory before cross-modal comparison.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T036 — Prohibit native mixed-frame innovation vectors from being used as silent fallbacks.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Prohibit native mixed-frame innovation vectors from being used as silent fallbacks.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T037 — Test sign inversions, axis swaps, unit mismatches, frame mismatches and stale context identifiers.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Test sign inversions, axis swaps, unit mismatches, frame mismatches and stale context identifiers.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T038 — Quantify power and false attribution under correlated channels and common-mode errors.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Quantify power and false attribution under correlated channels and common-mode errors.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T039 — Publish attribution as bounded inconsistency evidence, never causal or maliciousness classification.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Publish attribution as bounded inconsistency evidence, never causal or maliciousness classification.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 5: Redesign conservative fusion, abstention and availability behavior

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T040 — Write a complete fusion truth table for every magnitude, correlation, PID and availability state.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Write a complete fusion truth table for every magnitude, correlation, PID and availability state.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T041 — Prove that unavailable evidence cannot become Nominal.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Prove that unavailable evidence cannot become Nominal.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T042 — Prove that contradictory positive evidence cannot be erased by another layer.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Prove that contradictory positive evidence cannot be erased by another layer.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T043 — Separate anomaly severity, channel attribution, availability and confidence in the report.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Separate anomaly severity, channel attribution, availability and confidence in the report.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T044 — Model ordinary missingness explicitly and stop treating it as an incidental edge case.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Model ordinary missingness explicitly and stop treating it as an incidental edge case.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T045 — Design availability budgets and readiness metrics independent of anomaly statistics.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Design availability budgets and readiness metrics independent of anomaly statistics.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T046 — Add bounded hysteresis or episode semantics without hiding repeated alerts.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Add bounded hysteresis or episode semantics without hiding repeated alerts.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T047 — Define exact downgrade behavior when a configured modality becomes stale.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define exact downgrade behavior when a configured modality becomes stale.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T048 — Create metamorphic tests for monotonic conservatism of fusion.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Create metamorphic tests for monotonic conservatism of fusion.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T049 — Require calibration acceptance criteria for every default threshold and window.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Require calibration acceptance criteria for every default threshold and window.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 6: Qualify optional pid-rs evidence without contaminating core claims

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T050 — Pin a released pid-rs 1.x version and record its algorithm and schema identities.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Pin a released pid-rs 1.x version and record its algorithm and schema identities.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T051 — Define which pid-rs estimators and support assumptions are permitted.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define which pid-rs estimators and support assumptions are permitted.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T052 — Keep PID diagnostics feature-gated and absent from the default authority-neutral core.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Keep PID diagnostics feature-gated and absent from the default authority-neutral core.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T053 — Require report-first APIs and prohibit raw scalar-only decisions.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Require report-first APIs and prohibit raw scalar-only decisions.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T054 — Record preprocessing, quantization, jitter/noise and seed choices as estimand-changing provenance.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Record preprocessing, quantization, jitter/noise and seed choices as estimand-changing provenance.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T055 — Prove PID cannot repair failed geometry, lifecycle or signed-consensus prerequisites.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Prove PID cannot repair failed geometry, lifecycle or signed-consensus prerequisites.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T056 — Design nested validation to prevent tuning PID gates on evaluation streams.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Design nested validation to prevent tuning PID gates on evaluation streams.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T057 — Add synthetic regimes where PID helps, does not help and actively misleads.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Add synthetic regimes where PID helps, does not help and actively misleads.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T058 — Mark unsupported high-dimensional or mixed-support cases as not estimable.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Mark unsupported high-dimensional or mixed-support cases as not estimable.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T059 — Create cross-repository conformance tests against pid-rs golden reports.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Create cross-repository conformance tests against pid-rs golden reports.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 7: Harden NCP ingestion, lifecycle assembly and replay boundaries

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T060 — Freeze strict sidecar envelope schemas and distinguish them from normative NCP SensorFrame messages.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Freeze strict sidecar envelope schemas and distinguish them from normative NCP SensorFrame messages.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T061 — Adopt NCP 1.0 session, generation, epoch and stream-position semantics where applicable.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Adopt NCP 1.0 session, generation, epoch and stream-position semantics where applicable.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T062 — Enforce exact route derivation and producer, registry, context and prior identity binding.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Enforce exact route derivation and producer, registry, context and prior identity binding.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T063 — Bound payload bytes before or at transport ingress; document any lower-layer allocation gap.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Bound payload bytes before or at transport ingress; document any lower-layer allocation gap.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T064 — Implement replay high-water marks with explicit capacity and epoch rollover policy.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Implement replay high-water marks with explicit capacity and epoch rollover policy.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T065 — Make lifecycle completeness and heartbeat liveness independently observable.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Make lifecycle completeness and heartbeat liveness independently observable.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T066 — Prove the first terminal ingress fault prevents later FrameReady emission.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Prove the first terminal ingress fault prevents later FrameReady emission.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T067 — Reject duplicate, reordered, cross-session, cross-producer and unsafe-number payloads.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Reject duplicate, reordered, cross-session, cross-producer and unsafe-number payloads.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T068 — Build two-process and real-router allow/deny tests with retained mTLS and ACL evidence.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Build two-process and real-router allow/deny tests with retained mTLS and ACL evidence.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T069 — Specify compatibility and migration behavior when NCP wire revisions change.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Specify compatibility and migration behavior when NCP wire revisions change.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 8: Calibrate synthetic and recorded-stream operating characteristics

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T070 — Replace demonstration-only studies with preregistered calibration protocols.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Replace demonstration-only studies with preregistered calibration protocols.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T071 — Separate threshold-development, validation and final holdout seeds and streams.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Separate threshold-development, validation and final holdout seeds and streams.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T072 — Estimate false-alert episodes per track-hour and mission-level alarm probability.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Estimate false-alert episodes per track-hour and mission-level alarm probability.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T073 — Estimate conditional delay, miss probability, attribution error and abstention separately.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Estimate conditional delay, miss probability, attribution error and abstention separately.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T074 — Use block/bootstrap or model-based uncertainty appropriate for serially dependent streams.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Use block/bootstrap or model-based uncertainty appropriate for serially dependent streams.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T075 — Run broad grids over autocorrelation, covariance error, missingness and attack duration.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Run broad grids over autocorrelation, covariance error, missingness and attack duration.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T076 — Add recorded pre-gate Crebain streams with attested projection and lifecycle evidence.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Add recorded pre-gate Crebain streams with attested projection and lifecycle evidence.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T077 — Require external datasets or independently authored generators for at least one validation arm.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Require external datasets or independently authored generators for at least one validation arm.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T078 — Publish negative results and failure regions, not only favorable scenarios.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Publish negative results and failure regions, not only favorable scenarios.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T079 — Set explicit acceptance thresholds or keep the affected operational claim unclaimed.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Set explicit acceptance thresholds or keep the affected operational claim unclaimed.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 9: Harden security, resource limits, fuzzing and fault injection

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T080 — Complete a security review of parsers, route construction, configuration and cryptographic handoff assumptions.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Complete a security review of parsers, route construction, configuration and cryptographic handoff assumptions.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T081 — Fuzz every public decoder and state-machine event boundary with persistent corpora.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Fuzz every public decoder and state-machine event boundary with persistent corpora.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T082 — Run mutation testing on validation, replay, abstention and non-widening logic.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Run mutation testing on validation, replay, abstention and non-widening logic.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T083 — Prove bounded memory for tracks, modalities, windows, reordering, prior identities and payloads.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Prove bounded memory for tracks, modalities, windows, reordering, prior identities and payloads.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T084 — Benchmark worst-case latency and allocation at configured maxima.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Benchmark worst-case latency and allocation at configured maxima.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T085 — Test clock jumps, delayed heartbeats, duplicate callbacks, cancellation and shutdown races.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Test clock jumps, delayed heartbeats, duplicate callbacks, cancellation and shutdown races.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T086 — Remove secrets and private keys from logs, reports, examples and retained evidence.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Remove secrets and private keys from logs, reports, examples and retained evidence.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T087 — Generate SBOM, license, vulnerability and provenance attestations.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Generate SBOM, license, vulnerability and provenance attestations.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T088 — Test under Miri, sanitizers and supported platforms where applicable.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Test under Miri, sanitizers and supported platforms where applicable.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T089 — Create a vulnerability-response and schema-revocation procedure.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Create a vulnerability-response and schema-revocation procedure.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 10: Complete ecosystem adapters and downstream conformance

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T090 — Keep Galadriel optional in all ecosystem profiles.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Keep Galadriel optional in all ecosystem profiles.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T091 — Define a generic advisory evidence contract not coupled to Haldir implementation types.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define a generic advisory evidence contract not coupled to Haldir implementation types.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T092 — Make record-only the only initially qualified downstream policy effect.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Make record-only the only initially qualified downstream policy effect.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T093 — Test Galadriel absence, startup failure and runtime loss without changing baseline authorization.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Test Galadriel absence, startup failure and runtime loss without changing baseline authorization.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T094 — Test Haldir consumption without importing Galadriel into the authorization kernel.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Test Haldir consumption without importing Galadriel into the authorization kernel.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T095 — Update Crebain producer adapters only where needed for truthful contract compatibility.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Update Crebain producer adapters only where needed for truthful contract compatibility.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T096 — Do not redesign Crebain internal communication or make NCP mandatory for its internals.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Do not redesign Crebain internal communication or make NCP mandatory for its internals.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T097 — Document Engram/NCP relationships without making Galadriel an Engram prerequisite.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Document Engram/NCP relationships without making Galadriel an Engram prerequisite.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T098 — Add compatibility fixtures for NCP, Crebain, Haldir and pid-rs exact claimed versions.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Add compatibility fixtures for NCP, Crebain, Haldir and pid-rs exact claimed versions.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T099 — Remove ecosystem claims that lack a retained cross-repository qualification run.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Remove ecosystem claims that lack a retained cross-repository qualification run.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 11: Finish documentation, packaging, migration and governance

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T100 — Rewrite README around honest 1.0 scope, quick start, evidence status and limitations.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Rewrite README around honest 1.0 scope, quick start, evidence status and limitations.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T101 — Add ARCHITECTURE, STATISTICAL-CONTRACT, THREAT-MODEL and ADVISORY-BOUNDARY documents.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Add ARCHITECTURE, STATISTICAL-CONTRACT, THREAT-MODEL and ADVISORY-BOUNDARY documents.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T102 — Write a complete 0.x-to-1.0 migration guide with compile and semantic breaks.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Write a complete 0.x-to-1.0 migration guide with compile and semantic breaks.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T103 — Publish schemas, examples and golden vectors as versioned artifacts.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Publish schemas, examples and golden vectors as versioned artifacts.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T104 — Add operator runbooks for offline replay, calibration and secure observation.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Add operator runbooks for offline replay, calibration and secure observation.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T105 — Make every default and threshold discoverable and justified.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Make every default and threshold discoverable and justified.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T106 — Update GitHub description, topics, release notes, citation and package metadata.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Update GitHub description, topics, release notes, citation and package metadata.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T107 — Define SemVer policy for API, report schema, detector algorithm and calibration profiles.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Define SemVer policy for API, report schema, detector algorithm and calibration profiles.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T108 — Create support tiers and an end-of-life policy for old schemas.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Create support tiers and an end-of-life policy for old schemas.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T109 — Ensure documentation examples execute in CI from clean checkouts.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Ensure documentation examples execute in CI from clean checkouts.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

## Phase 12: Run independent reproduction and release ceremony

**Exit objective:** all ten tasks below have retained evidence and no unresolved release-blocking defect.

### T110 — Run the complete locked CI matrix on the exact release commit.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Run the complete locked CI matrix on the exact release commit.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T111 — Commission an independent clean-room build and numerical reproduction.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Commission an independent clean-room build and numerical reproduction.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T112 — Re-run calibration from immutable inputs and compare checksums.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Re-run calibration from immutable inputs and compare checksums.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T113 — Verify every requirement ledger entry has acceptable evidence or is explicitly not claimed.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Verify every requirement ledger entry has acceptable evidence or is explicitly not claimed.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T114 — Create signed source archives, SBOMs, checksums and provenance attestations.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Create signed source archives, SBOMs, checksums and provenance attestations.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T115 — Rehearse publish and rollback without changing the candidate.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Rehearse publish and rollback without changing the candidate.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T116 — Tag only after all evidence is bound to the exact commit.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Tag only after all evidence is bound to the exact commit.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T117 — Publish crates and release assets in a controlled order and verify registry contents.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Publish crates and release assets in a controlled order and verify registry contents.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T118 — Run post-publication install, demo, replay and schema verification.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Run post-publication install, demo, replay and schema verification.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.

### T119 — Record final go/no-go decision, residual risks and post-1.0 monitoring plan.

**Why this is required.** A 1.0 release freezes expectations. This task prevents ambiguous, unsafe, scientifically unsupported or operationally irreproducible behavior from becoming part of that contract.

**Implementation procedure.**

1. Read all files and tests relevant to 'Record final go/no-go decision, residual risks and post-1.0 monitoring plan.' before editing.
2. Write or update a normative requirement with stable identifier and explicit SHALL/SHALL NOT language.
3. Implement the smallest coherent change that satisfies the requirement; remove contradictory legacy behavior.
4. Add positive, negative, boundary, adversarial and regression tests.
5. Generate retained machine-readable evidence tied to the exact commit and toolchain.
6. Update public documentation, migration notes and the requirement ledger.
7. Run the phase-specific and full repository gates; do not mark complete on prose or green compilation alone.

**Mandatory test/evidence package.**

- unit or model-level tests
- negative and malformed-input tests
- boundary and state-transition tests
- property or metamorphic tests where applicable
- integration or clean-room reproduction appropriate to the claim
- requirement ledger entry
- test command and complete result
- exact commit and dependency identities
- generated vectors/reports/checksums where applicable
- review record and residual-risk statement

**Ten-lens review.**
- **Correctness and invariants:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Safety and failure behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Security and adversarial behavior:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Determinism and reproducibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Performance and bounded resources:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **API, schema, and compatibility:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Observability and provenance:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Testing and independent evidence:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Documentation and operator usability:** record the concrete result and evidence; do not use an unsupported “N/A”.
- **Ecosystem composition and governance:** record the concrete result and evidence; do not use an unsupported “N/A”.

**Done only when:** Complete only when every acceptance condition and evidence item is satisfied; otherwise leave OPEN or mark the unsupported claim NOT_CLAIMED.


## Final release decision

The release manager must issue one of:

- **GO:** every mandatory gate passes and the exact artifacts are published.
- **GO WITH NARROWED CLAIMS:** unsupported optional claims are removed from metadata, docs and manifests before tagging.
- **NO-GO:** any core correctness, security, authority, wire, mathematical or evidence gate remains open.

There is no “temporary” 1.0 exception for a known fail-open path, ambiguous version identity, unaudited cryptographic contract, cross-language divergence, unbounded hostile input, or materially misleading claim.
