# Galadriel 1.0 — 1.0 Migration and Ecosystem Qualification

## Purpose

This document tells the implementing agent how to break pre-1.0 compatibility safely and how to update consumers without turning cross-repository work into an uncontrolled redesign.

## Migration policy

1. Preserve behavior only when its semantics are explicit, safe, testable and supportable.
2. Remove aliases and permissive parsers that hide semantic changes.
3. Never auto-convert data when conversion requires guessing an epoch, unit, frame, identity, authority or estimand.
4. Provide machine-readable migration errors and validation tools.
5. Maintain old readers only in a separate, time-limited conversion utility when safe.
6. Do not allow a compatibility mode on a live authority or action path unless separately qualified.
7. Every migrated consumer must pin the exact 1.0 contract and pass shared vectors.

## Required migration inventory

For every public item in the pre-1.0 repository, record:

- old path and symbol/schema field;
- old meaning and known ambiguities;
- 1.0 replacement or removal;
- source compatibility;
- wire/data compatibility;
- semantic compatibility;
- automated conversion availability;
- consumer repositories affected;
- tests proving the migration;
- deprecation/removal documentation.

## Cross-repository edit authority

The assigned agent may change related repositories only for:

- exact dependency pins;
- schema/IDL vectors;
- thin adapters;
- data lineage and provenance;
- migration of a claimed consumer;
- CI conformance jobs;
- public descriptions of the relationship;
- removal of an unsupported claim.

The agent must not redesign Crebain internals, Prisoma hypotheses, pid-rs mathematics, Engram internals, or another repository's authority model unless the 1.0 contract cannot otherwise be made sound and the change is documented as a separate reviewed decision.

## Ecosystem truths to preserve

- NCP is mandatory for Engram external neural-service and closed-loop relationships.
- pid-rs does not depend on NCP, Galadriel or Haldir.
- Prisoma may consume immutable NCP captures and must preserve row-level lineage.
- Galadriel is optional advisory infrastructure.
- Haldir is optional to select but non-bypassable after selecting HaldirGate.
- Crebain internal communication is outside these release plans.
- Crebain external federation with Engram uses NCP when that integration is claimed.

## Qualification matrix

| Integration | Required for this 1.0? | Minimum evidence |
|---|---:|---|
| Standalone repository core | Yes | Clean build, unit/property/model tests, release evidence |
| NCP 1.0 | Claim-dependent except NCP itself | Shared vectors, exact pin, multi-process test |
| Engram external profile | Mandatory for NCP claim | End-to-end profile, provenance, timing and failure tests |
| pid-rs | Optional or claim-dependent | Exact released pin and golden report compatibility |
| Prisoma | Optional consumer | Capture/replay and lineage validation |
| Galadriel | Optional | Absence/failure semantics and advisory vectors |
| Haldir | Optional | Authority-profile vectors and non-bypass tests |
| Crebain | Optional | Thin adapter/fixture and no internal redesign |

## Required breaking-change workflow

1. Generate API/schema diff against the last public pre-1.0 revision.
2. Classify each change as corrective, security-critical, semantic clarification, removal or feature.
3. Update the migration inventory.
4. Add compile-fail, decode-fail or semantic regression tests.
5. Update every claimed consumer.
6. Run the consumer's own tests at immutable revisions.
7. Store the matrix and logs in the release evidence.
8. Remove stale examples, badges and GitHub description text.
9. Do not tag until no undocumented break remains.

## Dataset and capture migration

Captures must preserve:

- source repository and commit;
- protocol/schema identity;
- session, epoch/generation and sequence;
- producer and route;
- source and receipt clocks;
- unit and coordinate frame;
- transformation history;
- original payload digest;
- row or sample lineage;
- validation outcome.

If these cannot be reconstructed, label the capture `legacy_unqualified` and prohibit it from supporting a 1.0 validation claim.

## Rollback

A rollback may revert deployment or package distribution, but must never silently reuse an old epoch, lease, stream position, key, schema identity or calibration identity. Publish revocation/withdrawal metadata and preserve the failed release evidence for audit.
