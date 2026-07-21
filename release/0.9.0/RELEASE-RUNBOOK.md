# Galadriel 0.9.0 publication, rollback, and withdrawal runbook

Owner and release author: Sepehr Mahmoudian

Channel: GitHub source release only. There is no crates.io publication, project
DOI, Zenodo record, deployment qualification, or production-support promise.

**GLD-090-PUB-001:** Publication **SHALL** use the exact clean, signed `main`
candidate that passed every retained gate; a post-qualification source or metadata
change **SHALL** create a new candidate and rerun qualification.

**GLD-090-PUB-002:** The release **SHALL** use signed annotated tag `v0.9.0`,
verified checksummed assets, and reviewed GitHub notes. It **SHALL NOT** publish to
crates.io or claim a project DOI, Zenodo record, deployment qualification, or
production support.

**GLD-090-PUB-003:** A withdrawal **SHALL** preserve the affected tag, commit,
asset, checksum, signature, reason, consumer, and claim identities before deletion.
A withdrawn identity **SHALL NOT** be reused.

## Immutable entry conditions

1. `main` and `origin/main` resolve to the same signed commit and the worktree is clean.
2. The candidate's source plan contains exactly T000–T115 and remains an honest
   pre-result record: post-commit tasks are pending and unavailable external claims
   are `NOT_CLAIMED`. It must not contain fabricated future results.
3. A separately signed post-commit disposition set binds that exact commit and tree,
   covers all 116 tasks and twenty lenses, has no `OPEN` item, and names retained
   evidence for every `COMPLETE` result and the removed claim for every
   `NOT_CLAIMED` result.
   T114 cites the separately signed final review; T115 cites the separately signed,
   candidate-bound v3 `NARROWED_GO` decision. T113 cites the candidate-bound
   convergence mechanism and qualification evidence, never its future output;
   additional retained predecessor evidence is permitted.
4. The full locked build/test/documentation, feature, fuzz, mutation, supply-chain,
   signed frozen-input semantic verification, release-audit, source-inventory, and
   author-operated isolated qualification gates pass on that commit.
5. Release notes, `CITATION.cff`, Cargo metadata, schemas, API snapshot, changelog,
   support policy, and GitHub metadata all say 0.9.0 and agree on scope.
6. The signed finalization manifest records exact artifacts, checksums, review
   dispositions, negative results, residual risks, and a `GO` or `NARROWED_GO`
   decision for this source release.
7. Finalization emits and signs a schema-valid `LOCAL-CONVERGENCE.json` whose ten
   waves are `WAVE_ACCEPTED`, whose task set is exactly T000–T115, and whose
   explicit pid-rs, NCP, Crebain, Haldir, and Prisoma requirements preserve the
   required/optional/absent boundaries. This record permits reconciliation to
   begin; it does not claim that reconciliation or downstream qualification passed.
8. The decision records `LOCAL_PIN_PASS` for the locally qualified pid-rs/NCP pins
   and removes reciprocal/deployed claims `CLM-008` and `CLM-009` with the complete
   frozen exclusion set. No external repository acceptance is inferred.

If any entry condition changes, abort. Do not repair a frozen candidate in-place;
make a new signed commit on `main`, rerun qualification, and mint artifacts again.

## Rehearsal without publication

Run from a fresh temporary clone of the candidate:

```bash
set -euo pipefail
test "$(git branch --show-current)" = main
test "$(git status --porcelain=v1)" = ""
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
python3 repo_work/freeze_audit_inputs.py verify \
  --repo . \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json \
  --allowed-signers release/0.9.0/audit/ALLOWED_SIGNERS
python3 scripts/release_audit.py verify
python3 repo_work/local_convergence.py schema --repo .
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
cargo deny --all-features --locked check
```

Generate source archive, SBOM, license/vulnerability reports, provenance, and
checksums into an empty directory outside the checkout. Verify them from a second
fresh directory. The archive prefix is exactly `galadriel-0.9.0/`; archive content
must equal `git ls-files` subject only to explicitly documented GitHub-generated
archive metadata.

The qualifying command must include the tracked evidence configuration, the SSH
signing key, and the signed exact-candidate mutation manifest:

```bash
python3 repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --require-branch main \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$(git config --get user.signingkey)" \
  --mutation-evidence /path/to/exact-candidate-mutation.json \
  --mutation-evidence-signature /path/to/exact-candidate-mutation.json.sig \
  --evidence-config evidence/galadriel-0.9-candidate.json \
  --deep --keep-going
```

After producing the signed T114 review, the detached-signed canonical v3 decision,
and the signed ordered task dispositions, finalize into a previously absent path:

```bash
python3 repo_work/finalize_release.py \
  --repo . \
  --candidate "$(git rev-parse HEAD)" \
  --qualification /new/path/galadriel-0.9.0-qualification \
  --review-ledger /reviewed/path/FILE_REVIEW_LEDGER.completed.csv \
  --task-dispositions /reviewed/path/reviewed-task-dispositions.json \
  --task-dispositions-signature /reviewed/path/reviewed-task-dispositions.json.sig \
  --final-review /reviewed/path/FINAL-TWENTY-LENS-REVIEW.json \
  --final-review-signature /reviewed/path/FINAL-TWENTY-LENS-REVIEW.json.sig \
  --decision-input /reviewed/path/RELEASE-DECISION.json \
  --decision-input-signature /reviewed/path/RELEASE-DECISION.json.sig \
  --signing-key "$(git config --get user.signingkey)" \
  --snapshot-dir /secure/path/with-at-least-8-GiB-free \
  --out /new/path/galadriel-0.9.0-closure
```

The finalizer snapshots the signed qualification tier once before semantic use, so
the selected snapshot filesystem must have room for the bounded 8 GiB tier plus
review inputs. Prefer an agent-backed Ed25519 public-key handle for `--signing-key`;
if a private-key path is supplied, its bytes are copied only into this mode-0700
temporary snapshot and removed during cleanup. A cleanup warning identifies the
exact retained temporary path and must be resolved before GitHub publication proceeds.
The tier must contain exactly the signed artifact rows, qualification manifest,
detached signature, and `SHA256SUMS`; the checksum must enumerate every other file.
Unlisted or special entries and any inventory change during streaming are fatal.

Finalization publishes only after the staged decision, convergence, closure manifest,
and checksum set all verify and are flushed. Any error before the atomic no-replace
rename leaves the requested output absent; hidden abandoned staging directories are
never valid closure tiers. Atomic publication requires macOS `renamex_np` or a Linux
libc exposing `renameat2`; unsupported platforms fail closed before publication. Exit
status 3 means the rename committed a complete output but its parent-directory
durability, temporary-input cleanup, or result reporting was not confirmed. A cleanup
failure also emits `publication_status: COMMITTED_WITH_CLEANUP_WARNING` with the output
path. Retain that output, resolve any reported snapshot path, and run the independent
verification below before deciding whether to use or remove it.

After finalization, independently verify the signed convergence record against
the retained closure artifacts and exact candidate:

```bash
python3 repo_work/local_convergence.py verify \
  --repo . \
  --manifest /new/path/galadriel-0.9.0-closure/LOCAL-CONVERGENCE.json \
  --signature /new/path/galadriel-0.9.0-closure/LOCAL-CONVERGENCE.json.sig \
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --expected-commit "$(git rev-parse HEAD)" \
  --artifact-root /new/path/galadriel-0.9.0-closure
```

## Publication

1. Re-fetch `origin`; prove the candidate commit is unchanged and all required
   GitHub checks succeeded.
2. Create signed annotated tag `v0.9.0` at the exact candidate commit with a
   professional release message naming the source-only research scope.
3. Push only `main` and `v0.9.0`; verify the remote object IDs and signatures.
4. Create the GitHub release from `v0.9.0` using the reviewed notes and upload the
   author-operated, isolated-verification archive, SBOM, reports, provenance, and
   checksum file.
5. Download every asset through GitHub, verify all digests, install/build from the
   downloaded source in a fresh environment, and retain the complete result.
6. Only after the replacement release and downloaded assets are verified, re-check
   the legacy identities in `WITHDRAWN-RELEASES.md`; delete that tag and obsolete
   release-work branch locally and remotely, without deleting their commits or
   evidence, and verify that both refs and any legacy GitHub release are absent.
7. Confirm the release contains no DOI/Zenodo/crates.io/production claim and that
   the remote branch, tag, release, signature, asset, and checksum state is exact.

## Rollback and withdrawal

Do not move or reuse `v0.9.0`. If publication metadata alone is wrong, correct the
GitHub release text without replacing assets and record the edit. If source,
evidence, security, or provenance is wrong:

1. mark the GitHub release withdrawn with the exact reason and affected claims;
2. remove download promotion, but preserve hashes, logs, and the incident record;
3. delete the remote tag only after recording its tag object, target commit,
   signature, assets, and reason in `WITHDRAWN-RELEASES.md`;
4. notify affected consumers and reject the withdrawn artifact identity in future
   qualification;
5. repair on `main`, choose a fresh version, and rerun every entry condition;
6. never reuse a version, tag, checksum, provenance identity, epoch, key, or release asset.

Rollback occurs in reverse dependency order. Galadriel 0.9.0 has no authority to
roll back pid-rs, NCP, Crebain, Haldir, or Prisoma; cross-repository changes require
their respective leads and the reconciliation change-request process.
