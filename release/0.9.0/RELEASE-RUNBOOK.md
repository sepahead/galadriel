# Galadriel 0.9.0 publication, rollback, and withdrawal runbook

## Abbreviations

| Short form | Meaning |
|---|---|
| DOI | digital object identifier |
| JSON | JavaScript Object Notation |
| NCP | Neuro-Cybernetic Protocol |
| ROS | Robot Operating System |
| SBOM | software bill of materials |
| SHA-256 | Secure Hash Algorithm 256 |
| SSH | Secure Shell |
| URLs | Uniform Resource Locators |

Owner and release author: Sepehr Mahmoudian

Channel: GitHub source release only. There is no crates.io publication, project
DOI, Zenodo record, deployment qualification, or production-support promise.

**GLD-090-PUB-001:** Publication **SHALL** use the exact clean and signed `main` candidate.
That candidate **SHALL** pass every retained gate.
A post-qualification source or metadata change **SHALL** create a new candidate.
The new candidate **SHALL** repeat qualification.

**GLD-090-PUB-002:** The release **SHALL** use signed annotated tag `v0.9.0`,
verified checksummed assets, and reviewed GitHub notes. It **SHALL NOT** publish to
crates.io or claim a project DOI, Zenodo record, deployment qualification, or
production support.

**GLD-090-PUB-003:** A withdrawal **SHALL** preserve the affected tag, commit,
asset, checksum, signature, reason, consumer, and claim identities before deletion.
The release operator **SHALL NOT** reuse a withdrawn identity.

## Immutable entry conditions

1. `main` and `origin/main` resolve to the same signed commit and the worktree is clean.
2. The candidate source plan contains exactly T000 through T115.
   It remains an honest pre-result record.
   Post-commit tasks are pending.
   Unavailable external claims are `NOT_CLAIMED`.
   The plan must not contain fabricated future results.
3. A separately signed post-commit disposition set binds the exact commit and tree.
   It covers all 116 tasks and twenty lenses.
   It has no `OPEN` item.
   It names retained evidence for each `COMPLETE` result.
   It names the removed claim for each `NOT_CLAIMED` result.
   T114 cites the separately signed final review.
   T115 cites the separately signed candidate-bound version 3 `NARROWED_GO` decision.

   T113 cites the candidate-bound convergence mechanism and qualification evidence.
   T113 never cites its future output.
   The disposition can include more retained predecessor evidence.
4. All locked build, test, documentation, feature, fuzz, and mutation gates pass on that commit.
   All supply-chain and frozen-input semantic gates also pass.
   The release-audit, source-inventory, and author-operated isolated qualification gates also pass.
5. Release notes and `CITATION.cff` identify version 0.9.0 and agree on scope.
   Cargo metadata, schemas, and the application programming interface (API) snapshot also agree.
   The changelog, support policy, and GitHub metadata also agree.
6. The signed finalization manifest records exact artifacts and checksums.
   It records review dispositions, negative results, and residual risks.
   It records a `GO` or `NARROWED_GO` decision for this source release.
7. Finalization emits and signs a schema-valid `LOCAL-CONVERGENCE.json` file.
   All ten waves are `WAVE_ACCEPTED`.
   The task set is exactly T000 through T115.
   The ecosystem requirements preserve each required, optional, and absent boundary.
   They also preserve the acyclic no-command graph.
   The ecosystem scope includes pid-rs, NCP, Crebain, Haldir, and Prisoma.
   It also includes Engram, Paper2Brain, ROS, and external authority.

   This record permits reconciliation to start.
   It does not claim successful reconciliation or downstream qualification.
8. The decision records `LOCAL_PIN_PASS` for the locally qualified pid-rs/NCP pins
   and removes reciprocal/deployed claims `CLM-008` and `CLM-009` with the complete
   frozen exclusion set.
   Do not infer acceptance by an external repository.

If an entry condition changes, abort.
Do not repair a frozen candidate in place.
Create a new signed commit on `main`.
Repeat qualification and create new artifacts.

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
fresh directory.
The archive prefix is exactly `galadriel-0.9.0/`.
Archive content must equal `git ls-files`.
Only documented GitHub archive metadata can differ.

The qualification command must include the tracked evidence configuration, the SSH
signing key, and the signed exact-candidate mutation manifest:

```bash
set -euo pipefail
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"

python3 repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --require-branch main \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$signing_key" \
  --mutation-evidence /path/to/exact-candidate-mutation.json \
  --mutation-evidence-signature /path/to/exact-candidate-mutation.json.sig \
  --evidence-config evidence/galadriel-0.9-candidate.json \
  --deep --keep-going
```

Create the signed T114 review and detached-signed canonical version 3 decision.
Create the signed ordered task dispositions.
Then finalize into a previously absent path:

```bash
set -euo pipefail
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"

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
  --signing-key "$signing_key" \
  --snapshot-dir /secure/path/with-at-least-8-GiB-free \
  --out /new/path/galadriel-0.9.0-closure
```

The finalizer takes one snapshot of the signed qualification tier before semantic use.
The selected file system must hold the bounded 8 GiB tier and review inputs.
Prefer an agent-backed Ed25519 public-key handle for `--signing-key`.

If you supply a private-key path, the finalizer copies its bytes into a temporary snapshot.
That snapshot has mode 0700.
The finalizer removes it during cleanup.
A cleanup warning identifies an exact retained temporary path.
Resolve that path before GitHub publication.

The tier must contain the signed artifact rows, qualification manifest, detached signature, and `SHA256SUMS`.
The checksum must list every other file.
An unlisted or special entry is fatal.
An inventory change during a stream read is also fatal.

Finalization verifies and flushes the staged decision, convergence, closure manifest, and checksum set.
It publishes only after those actions pass.
An error before the atomic no-replace rename leaves the requested output absent.
An abandoned hidden stage directory is never a valid closure tier.

Atomic publication needs macOS `renamex_np` or Linux `renameat2` support.
An unsupported platform fails closed before publication.
Status 3 means that the rename committed a complete output.
The tool did not confirm durability, cleanup, or result output.
A cleanup failure also reports `publication_status: COMMITTED_WITH_CLEANUP_WARNING` and the output path.
Retain that output.

Resolve each reported snapshot path.
Run the independent verification below before you use or remove the output.

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

1. Fetch `origin` again.
   Confirm that the candidate commit did not change.
   Confirm that local and remote `main` are identical.
   Confirm that the worktree is clean.
   Confirm that each required exact-head GitHub check passed.
2. Create signed annotated tag `v0.9.0` at that commit.
   Use a professional message that identifies the source-only research scope.
   Derive the complete candidate, tree, tag-object, and peeled tag-target identifiers.
   Require the tag target to equal the candidate.
   Verify the commit and tag with an independently obtained allowed-signers trust root.
   Never move or reuse a failed or withdrawn tag name.
3. Build the upload set in a previously absent directory.
   Preserve the two completed evidence roots as separate deterministic tar roots.
   The signed map binds both tar byte identities.
   It also binds all candidate, tree, and tag identities.
   Verification enforces the exact map, signature, and tar file set:

   ```bash
   set -euo pipefail
   test "$(python3 -c 'import platform; print(platform.python_implementation(), platform.python_version())')" = "CPython 3.14.6"
   candidate="$(git rev-parse 'HEAD^{commit}')"
   tree="$(git rev-parse "$candidate^{tree}")"
   tag=v0.9.0
   tag_object="$(git rev-parse "$tag^{tag}")"
   tag_target="$(git rev-parse "$tag^{}")"
   test "$tag_target" = "$candidate"
   signing_key="$(git config --get user.signingkey)"
   test -n "$signing_key"

   python3 repo_work/package_release_assets.py build \
     --qualification-root /exact/path/galadriel-0.9.0-qualification \
     --closure-root /exact/path/galadriel-0.9.0-closure \
     --out /new/path/galadriel-0.9.0-github-assets \
     --signing-key "$signing_key" \
     --candidate-commit "$candidate" \
     --candidate-tree "$tree" \
     --tag-name "$tag" \
     --tag-object "$tag_object" \
     --tag-target "$tag_target"
   ```

   Exit status 3 means that the no-replace rename can have committed a complete output.
   Parent-directory durability or the result report remains uncertain.
   Retain that path and verify it independently.
   Resolve the durability warning before upload.
   Do not repeat or delete the output without verification.

   The directory must contain exactly:

   - `galadriel-0.9.0-qualification.tar`
   - `galadriel-0.9.0-closure.tar`
   - `galadriel-0.9.0-release-asset-map.json`
   - `galadriel-0.9.0-release-asset-map.json.sig`

   Verify that exact set before upload.
   Use the independent trust root and not the candidate copy:

   ```bash
   set -euo pipefail
   test "$(python3 -c 'import platform; print(platform.python_implementation(), platform.python_version())')" = "CPython 3.14.6"
   candidate="$(git rev-parse 'HEAD^{commit}')"
   tree="$(git rev-parse "$candidate^{tree}")"
   tag=v0.9.0
   tag_object="$(git rev-parse "$tag^{tag}")"
   tag_target="$(git rev-parse "$tag^{}")"
   test "$tag_target" = "$candidate"

   python3 repo_work/package_release_assets.py verify \
     --assets /new/path/galadriel-0.9.0-github-assets \
     --allowed-signers /independent/path/ALLOWED_SIGNERS \
     --expected-candidate "$candidate" \
     --expected-tree "$tree" \
     --expected-tag-name "$tag" \
     --expected-tag-object "$tag_object" \
     --expected-tag-target "$tag_target"
   ```

4. Push only the exact `main` and `v0.9.0` identities.
   Verify the remote commit, annotated tag object, peeled target, and both signatures again.
   Check hooks, installed automation, and releases immediately before publication.
   No process may create a DOI, Zenodo record, package publication, replacement asset, or second release.
5. Create a **draft** GitHub release from `v0.9.0`.
   Use the literal title `Galadriel 0.9.0`.
   Use the exact tracked `RELEASE-NOTES.md` body.
   Upload the four named files without replacement.
   Require exactly those four names in the application programming interface (API) asset list.
   Compare each API byte length with its local file value.
   Compare each API SHA-256 digest with its local file value.

   If the API omits a digest, record that field as unavailable.
   Use the mandatory authenticated byte-for-byte comparison in the next step.
   Never invent an API digest or omit the comparison.

   For the two tar files only, compare the local values with their rows in the signed map.
   The map does not contain rows for itself or its detached signature.
   The next authenticated download verifies the map signature and exact four-file set.

   GitHub generates the source ZIP and tar archives automatically.
   Use them only as convenience snapshots.
   Do not treat them as attached assurance assets.
   The signed map does not cover them.
   They cannot replace either evidence tar file.
6. Download all four draft assets through the authenticated GitHub path.
   Use a new empty directory.
   Require each downloaded file to equal its local upload source byte-for-byte.
   Run `verify` and reconstruct both path-preserving tiers atomically.
   Use the audit-pinned `CPython 3.14.6` for asset creation and canonical tar verification.
   A different interpreter is outside the qualified deterministic representation:

   ```bash
   set -euo pipefail
   test "$(python3 -c 'import platform; print(platform.python_implementation(), platform.python_version())')" = "CPython 3.14.6"
   local_assets=/new/path/galadriel-0.9.0-github-assets
   downloaded_assets=/downloaded/galadriel-0.9.0-github-assets
   asset_names=(
     "galadriel-0.9.0-qualification.tar"
     "galadriel-0.9.0-closure.tar"
     "galadriel-0.9.0-release-asset-map.json"
     "galadriel-0.9.0-release-asset-map.json.sig"
   )
   for name in "${asset_names[@]}"; do
     cmp -s "$local_assets/$name" "$downloaded_assets/$name"
   done

   candidate="$(git rev-parse 'HEAD^{commit}')"
   tree="$(git rev-parse "$candidate^{tree}")"
   tag=v0.9.0
   tag_object="$(git rev-parse "$tag^{tag}")"
   tag_target="$(git rev-parse "$tag^{}")"
   test "$tag_target" = "$candidate"

   python3 repo_work/package_release_assets.py reconstruct \
     --assets "$downloaded_assets" \
     --allowed-signers /independent/path/ALLOWED_SIGNERS \
     --out /new/path/galadriel-0.9.0-reconstructed \
     --expected-candidate "$candidate" \
     --expected-tree "$tree" \
     --expected-tag-name "$tag" \
     --expected-tag-object "$tag_object" \
     --expected-tag-target "$tag_target"
   ```

   Apply the same retain-and-verify rule if reconstruction reports status 3.

   In each reconstructed root, verify `SHA256SUMS` over the exact internal file set.
   Authenticate both tier manifests with the independent trust root.
   The release principal is `sepmhn@gmail.com`.
   Use these literal namespaces:

   - `galadriel-qualification-manifest`
   - `galadriel-closure-manifest`

   ```bash
   set -euo pipefail
   qualification_root=/new/path/galadriel-0.9.0-reconstructed/galadriel-0.9.0-qualification
   closure_root=/new/path/galadriel-0.9.0-reconstructed/galadriel-0.9.0-closure
   allowed_signers=/independent/path/ALLOWED_SIGNERS

   ssh-keygen -Y verify \
     -f "$allowed_signers" \
     -I sepmhn@gmail.com \
     -n galadriel-qualification-manifest \
     -s "$qualification_root/QUALIFICATION-MANIFEST.json.sig" \
     < "$qualification_root/QUALIFICATION-MANIFEST.json"
   ssh-keygen -Y verify \
     -f "$allowed_signers" \
     -I sepmhn@gmail.com \
     -n galadriel-closure-manifest \
     -s "$closure_root/CLOSURE-MANIFEST.json.sig" \
     < "$closure_root/CLOSURE-MANIFEST.json"

   PYTHONPATH=repo_work python3 -c \
     'import sys; from pathlib import Path; from finalize_release import verify_sha256sums; roots = sys.argv[1:]; len(roots) == 2 or sys.exit("expected exactly two tier roots"); tuple(verify_sha256sums(Path(root)) for root in roots)' \
     "$qualification_root" "$closure_root"
   ```

   The outer signed map proves the exact reconstructed inventory.
   The checksum verifier independently requires one `SHA256SUMS` row for each other file.
   Repeat the `local_convergence.py verify` command against the reconstructed closure.
   Extract the qualification `galadriel-0.9.0.tar.gz` file into a second fresh directory.
   Run the locked build, test, and documentation gates from that downloaded source.
7. Publish the draft only after each authenticated-download check passes.
   Also wait until Coordinated Universal Time (UTC) reaches the declared release date.
   Download the four public assets anonymously into another empty directory.
   Compare the four files with the local upload sources.
   Repeat exact-set verification and reconstruction.
   Repeat the internal signature and checksum checks.
   Repeat the fresh-source build.

   Require all six tag-bound release-body links to resolve.

   GitHub `blob` links return Hypertext Markup Language (HTML).
   Compare each raw file with the applicable tagged Git blob.
   Do not compare the HTML page as source content.
   Compare all three public JSON Schema `$id` URLs with their tagged Git blobs:

   ```bash
   set -euo pipefail
   tag=v0.9.0
   verification_dir="$(mktemp -d)"
   trap 'rm -rf "$verification_dir"' EXIT

   release_paths=(
     "release/0.9.0/ecosystem-cut.json"
     "release/0.9.0/claims.json"
     "docs/ADVISORY-BOUNDARY.md"
     "docs/ECOSYSTEM-CONNECTIONS.md"
     "release/0.9.0/RELEASE-RUNBOOK.md"
     "CITATION.cff"
   )
   schema_paths=(
     "release/0.9.0/local-convergence-schema.json"
     "crates/galadriel-ncp/schemas/galadriel-pid-envelope-v1.schema.json"
     "crates/galadriel-ncp/schemas/galadriel-monitor-envelope-v1.schema.json"
   )

   for path in "${release_paths[@]}"; do
     curl --fail --silent --show-error --location \
       --output /dev/null \
       "https://github.com/sepahead/galadriel/blob/$tag/$path"
     git show "$tag:$path" > "$verification_dir/expected"
     curl --fail --silent --show-error --location \
       --output "$verification_dir/downloaded" \
       "https://raw.githubusercontent.com/sepahead/galadriel/$tag/$path"
     cmp -s "$verification_dir/expected" "$verification_dir/downloaded"
   done

   for path in "${schema_paths[@]}"; do
     git show "$tag:$path" > "$verification_dir/expected"
     curl --fail --silent --show-error --location \
       --output "$verification_dir/downloaded" \
       "https://raw.githubusercontent.com/sepahead/galadriel/$tag/$path"
     cmp -s "$verification_dir/expected" "$verification_dir/downloaded"
   done

   rm -rf "$verification_dir"
   trap - EXIT
   ```
8. Verify the published release and anonymous downloads first.
   Then preserve the legacy identities in `WITHDRAWN-RELEASES.md`.
   Delete only the obsolete tag and release-work references.
   Delete the local and remote references.
   Do not delete their commits or evidence.
   Confirm that none of those references exists.
   Confirm that no applicable legacy GitHub release exists.
9. Confirm that the release author is Sepehr Mahmoudian.
   Confirm that the literal title is `Galadriel 0.9.0`.
   Confirm that the version, date, and tracked body are exact.
   Require exactly four attached assets.
   Require no DOI, Zenodo, crates.io, deployment, or production claim.
   Retain the branch, signed tag, and release evidence.
   Retain download, signature, reconstruction, fresh-build, and cleanup evidence.

## Rollback and withdrawal

Do not move or reuse `v0.9.0`.
If only publication metadata is wrong, correct the GitHub release text.
Do not replace assets.
Record the edit.
If source, evidence, security, or provenance is wrong:

1. Mark the GitHub release as withdrawn with the exact reason and affected claims.
2. Remove download promotion.
   Preserve hashes, logs, and the incident record.
3. Delete the remote tag only after recording its tag object, target commit,
   signature, assets, and reason in `WITHDRAWN-RELEASES.md`.
4. Notify affected consumers.
   Reject the withdrawn artifact identity in new qualification work.
5. Repair the defect on `main`.
   Select a new version and repeat each entry condition.
6. Never reuse a version, tag, checksum, provenance identity, epoch, key, or release asset.

Rollback occurs in reverse dependency order.
Galadriel 0.9.0 has no authority to roll back pid-rs, NCP, Crebain, Haldir, or Prisoma.
Cross-repository changes require the applicable project lead and reconciliation process.
