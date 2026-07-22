# Decision to apply the 1.0 handoff to release 0.9.0

Status: accepted

Author: Sepehr Mahmoudian

Date: 2026-07-14

## Context

The supplied standalone handoff uses version `1.0.0`.
The requested first public research release uses version `0.9.0`.
It has no DOI or Zenodo record.

The external source package remains immutable.
Its archive and task-ledger SHA-256 values identify it.
The version `1.0.0` label contradicts the selected release scope.
It also overstates qualification.

## Decision

**GLD-090-REL-001:** The implementation **SHALL** bind the supplied handoff through `release/0.9.0/handoff-source.json`.
That record **SHALL** include the complete archive and task-ledger SHA-256 values.
The release process **SHALL** interpret each handoff product-version reference as the complete target design.
The `0.9.0` process reviews that design and keeps all obligations.
Superseded handoffs **SHALL NOT** control closure.

**GLD-090-REL-002:** The version adaptation **SHALL NOT** relax an obligation in these areas:

- technical behavior
- safety
- security
- tests
- evidence
- reproducibility
- documentation
- governance

An unsupported optional integration or publication claim can use `NOT_CLAIMED` only.
The disposition must state the missing evidence.

**GLD-090-REL-003:** All product manifests **SHALL** identify version `0.9.0`.
Citation metadata, release artifacts, tags, and release notes **SHALL** also identify version `0.9.0`.
They **SHALL NOT** claim a project DOI or Zenodo record.
They **SHALL NOT** claim crates.io publication, production support, or final 1.0 compatibility.

**GLD-090-REL-004:** These records **SHALL** identify `Sepehr Mahmoudian` as the author:

- Cargo metadata
- `CITATION.cff`
- release records
- signed Git authorship

Tools and assistants **SHALL NOT** be authors or co-authors.

**GLD-090-REL-005:** The protected `main` branch **SHALL** contain the accepted 0.9.0 candidate.
The release request requires all accepted changes to land there.
`RELEASE-POLICY.md` supplies the required change control.
This release does not need a divergent release branch.

**GLD-090-REL-006:** The supplied convergence schema requires all task IDs from T000 through T115.
The supplied dependency order places T113 before the T114 final review and T115 signed decision.

T113 **SHALL** qualify these exact-candidate items:

- the schema
- the generator
- the semantic validator
- the fixed cross-repository requirement set
- the negative tests

T113 **SHALL NOT** cite a future `LOCAL-CONVERGENCE.json` file as evidence.
Finalization **SHALL** create and sign the complete convergence record after T114 and T115 exist.
This interpretation preserves the 116-task schema and the supplied dependency order.
It does not weaken a substantive gate.

**GLD-090-REL-007:** Version 0.9 advertises exact dependency-pin contracts for pid-rs and NCP.
Qualified optional build graphs exercise those contracts.
`dependency_pin_required_for_qualified_graphs` describes this local build obligation.

Crebain remains an optional reference producer.
Haldir and Prisoma remain prospective consumers.
Engram and Paper2Brain remain explicit non-edges.
ROS and ROS 2 remain explicit non-edges.
External authority remains an explicit non-edge.

The directed graph **SHALL** remain acyclic.
It **SHALL** contain no evidence-to-command feedback.
Local pin reconciliation **SHALL** pass before T115.
`CLM-008` and `CLM-009` remove unsupported relationship claims.

The release does not claim these qualification results:

- reciprocal final-candidate qualification
- deployed-producer qualification
- downstream-adapter qualification
- middleware qualification
- command qualification

Readiness for a new reconciliation **SHALL NOT** become reciprocal acceptance or deployment evidence.

**GLD-090-REL-008:** Final closure **SHALL** use this evidence order:

1. signed candidate and qualification
2. T113 mechanism evidence
3. detached-signed T114 review
4. detached-signed candidate-bound T115 decision
5. detached-signed ordered task dispositions that cite the T114 and T115 inputs
6. signed convergence record
7. signed closure manifest
8. checksums

The finalizer **SHALL** stage the complete bundle outside the requested output path.
It **SHALL** verify and flush that bundle.
It **SHALL** publish the bundle with one atomic, no-replace, same-parent rename.

Every pre-publication failure **SHALL** leave the requested path absent.
It **SHALL** retain no partial result at that path.
The rename is the publication commit point.

If durability or the result report fails after the rename, the tool **SHALL** return status 3.
It **SHALL** retain the complete output.
An independent verifier must check that output before use.

## Consequences

The complete ordered 116-task ledger controls closure.
Version 0.9.0 means the first reviewable release.
It does not mean partial safety.

A version 1.0.0 release needs a new decision and new evidence.
It must close each promoted 0.9.0 `NOT_CLAIMED` item.
Version 0.9.0 does not reserve or assert a DOI.
