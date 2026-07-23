# Galadriel 0.9 release policy

Owner and author: Sepehr Mahmoudian

Candidate branch: protected `main`

Release target: review-gated `0.9.0` GitHub research source release

No project digital object identifier exists.
No project Zenodo record exists.

## Freeze and change control

**GLD-090-CTL-001:** `main` **SHALL** be the sole 0.9.0 candidate line.
The freeze starts after the current handoff audit and scope work closes.
The freeze ends only after T115 closes or becomes explicitly `NOT_CLAIMED` in dependency order.
The final decision **SHALL** be `GO` or `NARROWED_GO` for the exact publication scope.
A `NO_GO` decision stops publication.
No separate branch can contain unreviewed release-only changes.

**GLD-090-CTL-002:** During the freeze, every change **SHALL** identify all affected stable requirements.
It **SHALL** also identify affected tests, generated evidence, claims, and residual risks.
Rerun the applicable phase gates after a change to code, configuration, schemas, dependencies, fixtures, claims, or release tools.
Then run the full release verifier.

**GLD-090-CTL-003:** Sepehr Mahmoudian **SHALL** author and sign all commits.
Commit messages **SHALL** be professional and imperative.
Commits **SHALL** retain linear history and pass protected branch checks.
Assistants **SHALL NOT** appear as authors or co-authors.

**GLD-090-CTL-004:** An emergency freeze exception **SHALL** correct only a release-blocking defect.
The defect **SHALL** affect correctness, security, reproducibility, or metadata.
The review record **SHALL** explain the defect and the smallest coherent repair.
It **SHALL** identify the regression coverage, replacement candidate evidence, and repeated gates.
Defer cosmetic changes.

**GLD-090-CTL-005:** Cross-repository edits **SHALL** apply only to a claimed adapter, conformance fixture, immutable pin, migration, or truthful documentation.
Before an edit, the operator **SHALL** check for concurrent work and preserve it.
Unqualified integrations **SHALL** be `NOT_CLAIMED`.
Do not force an unqualified integration into another repository.

**GLD-090-CTL-006:** The threat register **SHALL** remain `LIVING_UNTIL_CANDIDATE_FREEZE` during implementation.
Only the release operator **SHALL** change it to `FROZEN_AT_CANDIDATE`.
The operator **SHALL** make that change with the final staged release inputs.
Freeze generation and strict verification **SHALL** reject the living status.
Implementation verification **SHALL** reject an active pair while the status is living.

The signed audit-input manifest is the sole pre-commit evidence exception.
It binds exact stage-zero index blobs and external inputs.
It does not claim a candidate commit or tree.
The next signed commit establishes the exact candidate identity.

A later tracked change **SHALL** reopen the freeze.
It **SHALL** require a new active signed input pair and candidate.

**GLD-090-CTL-007:** Only the release operator **SHALL** merge, tag, publish, delete references, or change repository settings.
A delegated agent **SHALL NOT** perform these actions.
An agent can prepare and verify a reviewed milestone.
The release operator must accept that milestone before promotion.

## Candidate and publication gates

A commit is a candidate only when the worktree is clean and metadata identifies version 0.9.0.
The lockfile, toolchain, and pins must be immutable.
The release audit must verify.
Phase and full commands must have complete retained output.
The release process must freeze the exact source task plan.

Review results can exist only after the candidate commit exists.
Thus, separately signed post-commit dispositions carry closure.
Each disposition binds to the candidate commit and tree.
The disposition set must contain no `OPEN` task before publication.

Publication also requires a signed tag, archive, checksums, and provenance.
It requires clean candidate qualification and a final multi-lens review.
It also requires withdrawal instructions, rollback instructions, and remote post-publication verification.

Independent clean-room reproduction is necessary only when the release claims that reproduction occurred.
A `NARROWED_GO` GitHub research source release can instead close that task as `NOT_CLAIMED`.
The claims matrix, decision, and release notes must preserve the exclusion.

Remove old tags and releases only after the 0.9.0 release record retains their exact identities and withdrawal reasons.
Deletion does not erase evidence.
The 0.9.0 tag is `v0.9.0`. It does not imply a `v1` tag.
