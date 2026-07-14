# Decision: apply the standalone 1.0 handoff to release 0.9.0

Status: accepted

Author: Sepehr Mahmoudian

Date: 2026-07-14

## Context

The supplied standalone handoff names `1.0.0` throughout. The author and release
owner has instead requested a first public supervisor-review release at `0.9.0`,
with no DOI or Zenodo record yet. Rewriting the source handoff would destroy its
provenance; calling the result 1.0.0 would contradict the release owner's explicit
scope and overstate qualification.

## Decision

**GLD-090-REL-001:** The implementation **SHALL** preserve the supplied handoff
byte-for-byte under `release/0.9.0/handoff/` and **SHALL** interpret every product
version or “1.0 release” reference in that handoff as the complete target design
being reviewed in the `0.9.0` release process.

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

## Consequences

The complete 120-task ledger remains controlling and ordered. Version 0.9.0 means
“first reviewable release,” not “partial safety.” A later 1.0.0 requires a new
decision, a fresh evidence set, and closure of any 0.9.0 `NOT_CLAIMED` items that
are promoted into 1.0 claims. Nothing in 0.9.0 reserves or asserts a DOI.
