# Decision: apply the standalone 1.0 handoff to release 0.9.0

Status: accepted

Author: Sepehr Mahmoudian

Date: 2026-07-14

## Context

The supplied standalone handoff names `1.0.0` throughout. The author and release
owner has instead requested a first public research release at `0.9.0`,
with no DOI or Zenodo record yet. The source package remains externally immutable
and is identified by its archive and task-ledger SHA-256 values. Calling the result
1.0.0 would contradict the release owner's explicit scope and overstate qualification.

## Decision

**GLD-090-REL-001:** The implementation **SHALL** bind the current supplied handoff
through `release/0.9.0/handoff-source.json` and its full archive/task-ledger
SHA-256 identities. It **SHALL** interpret every product-version or “1.0 release”
reference in that handoff as the complete target design being reviewed in the
`0.9.0` release process. Superseded handoffs **SHALL NOT** control closure.

**GLD-090-REL-002:** The version adaptation **SHALL NOT** relax a technical,
safety, security, test, evidence, reproducibility, documentation, or governance
obligation. Unsupported optional integration/publication claims may only be
disposed as `NOT_CLAIMED`, with the missing evidence stated.

**GLD-090-REL-003:** All product manifests, citation metadata, release artifacts,
tags, and release notes **SHALL** identify `0.9.0`. They **SHALL NOT** claim a
project DOI, Zenodo record, crates.io publication, production support, or final
1.0 compatibility.

**GLD-090-REL-004:** The author identity **SHALL** be `Sepehr Mahmoudian` in Cargo,
CITATION.cff, release records, and signed Git authorship. Tools and assistants
**SHALL NOT** be named as authors or co-authors.

**GLD-090-REL-005:** The protected `main` branch **SHALL** be the 0.9.0 candidate
branch because the release owner explicitly required all changes to land there.
The handoff's generic release-branch instruction is satisfied by the change-control
rules in `RELEASE-POLICY.md`, not by maintaining a divergent branch.

**GLD-090-REL-006:** The supplied convergence schema requires all T000–T115 IDs,
while the supplied dependency order places T113 before the T114 final review and
T115 signed decision. T113 **SHALL** therefore qualify the exact candidate-bound
schema, generator, semantic validator, fixed cross-repository requirement set, and
negative tests. It **SHALL NOT** cite a future `LOCAL-CONVERGENCE.json` as evidence.
After the signed T114 review and signed T115 decision exist, finalization **SHALL**
materialize and sign the all-task convergence record as a transaction output. This
is the only acyclic interpretation that preserves both the exact 116-task schema and
the supplied dependency order; it does not weaken any substantive gate.

**GLD-090-REL-007:** The 0.9 advertised cross-repository edges are the exact pid-rs
and NCP dependency-pin contracts exercised by qualified optional build graphs.
`dependency_pin_required_for_qualified_graphs` describes that local build
obligation. Local pin reconciliation **SHALL** pass before T115, while reciprocal
final-candidate, deployed-producer, and downstream-adapter qualification remains
removed through `CLM-008` and `CLM-009`. Readiness for later reconciliation **SHALL
NOT** be represented as reciprocal acceptance or deployment evidence.

**GLD-090-REL-008:** Final closure **SHALL** follow this evidence order: signed
candidate and qualification; T113 mechanism evidence; detached-signed T114 review;
detached-signed candidate-bound T115 decision; detached-signed ordered task
dispositions citing those two inputs; signed convergence; signed closure manifest;
checksums. The finalizer **SHALL** stage the complete bundle outside the requested
path, verify it, flush it, and publish it with one atomic, no-replace,
same-parent rename. Every pre-publication failure **SHALL** leave the requested
path absent and retain no partial result there. The rename is the publication
commit point: a later parent-directory durability or result-reporting failure
**SHALL** return status 3, retain the complete output, and require independent
verification before use.

## Consequences

The complete 116-task ledger remains controlling and ordered. Version 0.9.0 means
“first reviewable release,” not “partial safety.” A later 1.0.0 requires a new
decision, a fresh evidence set, and closure of any 0.9.0 `NOT_CLAIMED` items that
are promoted into 1.0 claims. Nothing in 0.9.0 reserves or asserts a DOI.
