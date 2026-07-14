# Galadriel 0.9 release policy

Owner and author: Sepehr Mahmoudian

Candidate branch: protected `main`

Release target: `0.9.0` GitHub source release

## Freeze and change control

**GLD-090-CTL-001:** `main` **SHALL** be the sole 0.9.0 candidate line. The freeze
begins when the current-handoff audit-and-scope wave is closed and ends only after T115 is
closed or explicitly `NOT_CLAIMED` in dependency order and the final decision is
`GO` or `NARROWED_GO` for the exact publication scope. A `NO_GO` decision stops
publication. No separate branch may carry unreviewed release-only changes.

**GLD-090-CTL-002:** During freeze, every change **SHALL** identify affected stable
requirements, tests, generated evidence, claims and residual risks. A change that
alters code, configuration, schemas, dependencies, fixtures, claims or release
tooling **SHALL** rerun its phase gates and the full release verifier.

**GLD-090-CTL-003:** Commits **SHALL** be signed and authored by Sepehr Mahmoudian,
use professional imperative messages, retain linear history, and pass protected
branch checks. Assistants **SHALL NOT** appear as authors/co-authors.

**GLD-090-CTL-004:** An emergency freeze exception **SHALL** be limited to a
release-blocking correctness, security, reproducibility or metadata defect. Its
review record shall explain the defect, smallest coherent repair, regression
coverage and why the candidate evidence remains valid. Cosmetic churn is deferred.

**GLD-090-CTL-005:** Cross-repository edits **SHALL** be limited to a claimed
adapter, conformance fixture, immutable pin, migration or truthful documentation.
Before editing, the operator shall check for concurrent work and preserve it.
Unqualified integrations shall be `NOT_CLAIMED`, not forced into another repository.

## Candidate and publication gates

A commit is a candidate only when the worktree is clean, metadata says 0.9.0, the
lockfile/toolchain/pins are immutable, the release audit verifies, phase and full
commands have complete retained output, and its exact source task plan is frozen.
Because review results can exist only after that commit exists, closure is carried
by separately signed post-commit dispositions bound to the candidate commit and
tree; publication requires that set to contain no `OPEN` task. Publication also
requires signed tag/archive/checksums/provenance, clean candidate qualification,
final multi-lens review, withdrawal/rollback instructions, and remote
post-publication verification. Independent clean-room
reproduction is required only for a claim that such reproduction occurred; a
`NARROWED_GO` GitHub source release may instead close that task as `NOT_CLAIMED`
when the claims matrix, decision, and release notes all preserve the exclusion.

Old tags/releases are removed only after their exact identities and withdrawal
reason are retained in the 0.9.0 release record. Deletion is not evidence erasure.
The 0.9.0 tag is `v0.9.0`; no `v1` tag is implied.
