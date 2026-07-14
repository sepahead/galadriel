# Galadriel 1.0 — Normative 1.0 Architecture

## Status

This document is an implementation target, not a statement that 1.0 is already qualified. The implementing agent must reconcile it against the exact repository checkout and record deviations.

## Mission

Deliver a mathematically explicit, fail-closed, advisory-only cross-sensor consistency monitor whose stable API, statistical meaning, calibration evidence, wire contracts, resource bounds, and ecosystem behavior are suitable for a truthful 1.0 release.

## Current audited starting point

The audited public README describes version 0.1.0 as a pre-1.0 research prototype. It implements NIS/CUSUM magnitude monitoring, signed cross-channel correlation, conservative fusion, optional pid-rs evidence, bounded NCP/Zenoh ingestion, synthetic evaluation, and an opt-in Crebain producer/receiver path. Its own retained evidence reports high false-alert rates and severe abstention under ordinary missingness, so operational claims are not yet justified.

## Non-goals and hard boundaries

- Do not claim that consistency establishes truth or identifies an attacker.
- Do not grant Galadriel command authority or permit it to create or widen ALLOW.
- Do not make Galadriel mandatory for pid-rs, Prisoma, Crebain core, Haldir baseline policy, or NCP.
- Do not use PID or mutual information to repair missing geometry, lifecycle evidence, or signed-consensus failures.
- Do not market synthetic studies as field validation.

## Architectural principles

1. **Fail closed or abstain explicitly.** Missing, invalid, stale, incompatible or unauthenticated evidence is never silently converted into success.
2. **Make authority explicit.** Observation, advice, intent, authorization and plant command are different types and capabilities.
3. **One normative source per semantic fact.** Generated artifacts must be reproducible and checked against their source.
4. **Immutable identity.** Every release, schema, algorithm, profile, dataset and evidence artifact is content-addressed or commit-pinned.
5. **Bounded operation.** Inputs, state, queues, windows, retries, clocks and shutdown are bounded and testable.
6. **Evidence-scoped claims.** A unit test, synthetic fixture, formal model and field deployment prove different things.
7. **No semantic fallback.** Unsupported or failed advanced behavior cannot silently fall back to a weaker behavior under the same claimed profile.
8. **Composition without hidden coupling.** Optional ecosystem components remain optional unless a deployment profile explicitly selects them.
9. **Deterministic core.** External I/O, clocks, entropy, filesystem and transport are outside pure core logic.
10. **Migration may break compatibility.** Pre-1.0 behavior that is ambiguous, unsafe or unverifiable must be removed rather than preserved.

## Component boundaries

- **galadriel-core** — Pure deterministic detector state machines, statistical tests, fusion, typed errors and reports.
- **galadriel-sim** — Synthetic generators, controlled attacks, missingness and autocorrelation studies.
- **galadriel-eval** — Calibration, operating-characteristic estimation, uncertainty and cost analysis.
- **galadriel-pid** — Optional restricted-domain pid-rs diagnostics, never an authority source.
- **galadriel-ncp** — Bounded NCP-sidecar codecs, route validation, lifecycle assembler and replay protection.
- **galadriel-cli** — Demo, replay, observe, validate-config, inspect-evidence and calibration commands.
- **deployment assets** — mTLS/ACL reference profile, manifests, registry and epoch handoff tooling.

## Required dependency direction

```text
schemas / normative contracts
        ↓
pure core validation and state machines
        ↓
language or transport adapters
        ↓
CLI / services / deployment profiles
        ↓
retained evidence and release manifests
```

No lower layer may depend on an application-specific upper layer. Transport adapters must not redefine core semantics.

## Stable identity model

Every serialized object that can affect a scientific or authorization claim must bind:

- schema identifier and revision;
- protocol or algorithm revision;
- software version and source commit;
- configuration/profile digest;
- producer identity;
- session and epoch/generation;
- typed stream position;
- source and receipt time with clock-domain declaration;
- payload or decision digest;
- relevant dataset/model/calibration provenance;
- validation status and reason codes.

## Error and state taxonomy

The public model must distinguish:

- invalid input or configuration;
- unauthenticated or unauthorized input;
- incompatible version or schema;
- stale, duplicate, reordered or replayed input;
- insufficient evidence or unavailable prerequisite;
- explicit negative/anomaly/deny evidence;
- bounded resource exhaustion;
- backend or internal fault;
- successful result.

These classes must not collapse into a Boolean.

## Ecosystem boundary

- `pid-rs` remains a standalone estimator library.
- NCP is mandatory for Engram's external neural-service and closed-loop relationships.
- NCP is not mandated for Crebain's internal self-communication.
- Galadriel is optional advisory infrastructure.
- Haldir is optional to select; once `HaldirGate` is selected it is mandatory and non-bypassable.
- Cross-repository edits are allowed only to qualify a claimed interface or correct a truthful dependency/contract statement.

## Ten-lens design review

For every architectural change, review:

1. Correctness and invariants
2. Safety and failure behavior
3. Security and adversarial behavior
4. Determinism and reproducibility
5. Performance and bounded resources
6. API, schema, and compatibility
7. Observability and provenance
8. Testing and independent evidence
9. Documentation and operator usability
10. Ecosystem composition and governance

A design review is incomplete when any lens merely says “not applicable” without justification.

## Release architecture acceptance

The architecture is acceptable only when:

- every public route and type has one documented owner;
- every privilege is represented by an explicit capability;
- every state transition has a testable table or model;
- every optional component has absence and failure tests;
- every claimed integration has immutable cross-repository evidence;
- no unsupported claim appears in README, GitHub metadata, package metadata or release notes.
