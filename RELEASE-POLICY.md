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
The release operator has sole authority to change it to `FROZEN_AT_CANDIDATE`.
The operator **SHALL** make that change with the final staged release inputs.
Freeze generation and strict verification **SHALL** reject the living status.
Implementation verification **SHALL** reject an active pair while the status is living.

The signed audit-input manifest is the sole pre-commit evidence exception.
It uses schema `galadriel.frozen-audit-inputs.v2`.
It binds each release-input path, Git mode, blob identifier, Secure Hash Algorithm 256 (SHA-256) value, and size.
It derives source semantics and release-tool coverage from one bounded index capture.
It binds each external handoff regular-file mode.
It does not claim a candidate commit or tree.
The next signed commit establishes the exact candidate identity.

The unversioned signed version 1 pair is a historical record.
It is not the active pair.

Pair installation and audit-manifest generation **SHALL** form one bounded
candidate-construction transaction.
The frozen release-input set **SHALL** include the requirements ledger.
It **SHALL NOT** include the active pair or the audit manifest.
The audit manifest **SHALL** inventory the staged pair and exclude only itself.
It **SHALL** use schema `galadriel.release-audit-manifest.v2`.
Each artifact row **SHALL** bind its path, Git mode, blob identifier, SHA-256 value, size, and purpose.
All semantic checks **SHALL** use bytes from one bounded stage-zero index capture.
One held-root transaction **SHALL** compare the worktree with those captured identities.
The signed candidate commit **SHALL** bind the complete tracked result.
The operator **SHALL** generate and stage the requirements ledger before pair generation.
The operator **SHALL** stage the installed pair before audit-manifest generation.
Audit-manifest generation **SHALL NOT** change the frozen requirements ledger.
Release-input drift during the transaction **SHALL** abort the transaction.
Such drift **SHALL** require a new active signed input pair.

After the final generated inventory is staged, a tracked change **SHALL** reopen
the freeze.
It **SHALL** require a new active signed input pair and candidate.

**GLD-090-CTL-007:** The release operator has sole authority to merge, tag, publish, delete references, or change repository settings.
A delegated agent **SHALL NOT** perform these actions.
An agent can prepare and verify a reviewed milestone.
The release operator **SHALL** accept that milestone before promotion.

## Candidate and publication gates

A commit is a candidate only when the worktree is clean and metadata identifies version 0.9.0.
The lockfile, toolchain, and pins **SHALL** be immutable.
The release audit **SHALL** pass.
Phase and full commands **SHALL** have complete retained output.
The release process **SHALL** freeze the exact source task plan.

Review results can exist only after the candidate commit exists.
Thus, separately signed post-commit dispositions carry closure.
Each disposition binds to the candidate commit and tree.
The disposition set **SHALL** contain no `OPEN` task before publication.

Publication also requires a signed tag, archive, checksums, and provenance.
It requires clean candidate qualification and a final multi-lens review.
It also requires withdrawal instructions, rollback instructions, and remote post-publication verification.

Independent clean-room reproduction is necessary only when the release claims that reproduction occurred.
A `NARROWED_GO` GitHub research source release can instead close that task as `NOT_CLAIMED`.
The claims matrix, decision, and release notes **SHALL** preserve the exclusion.

Remove old tags and releases only after the 0.9.0 release record retains their exact identities and withdrawal reasons.
Deletion does not erase evidence.
The 0.9.0 tag is `v0.9.0`. It does not imply a `v1` tag.
