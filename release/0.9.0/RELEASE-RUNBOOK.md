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
   explicit pid-rs, NCP, Crebain, Haldir, Prisoma, Engram/Paper2Brain, ROS, and
   external-authority requirements preserve the required/optional/absent boundaries
   and the acyclic no-command graph. This record permits reconciliation to
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

After producing the signed T114 review, the detached-signed canonical v3 decision,
and the signed ordered task dispositions, finalize into a previously absent path:

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

1. Re-fetch `origin`; prove the candidate commit is unchanged, `main` and remote `main`
   are identical, the worktree is clean, and every required exact-head GitHub check passed.
2. Create signed annotated tag `v0.9.0` at that commit with a professional message naming
   the source-only research scope. Derive the full candidate, tree, tag-object, and peeled
   tag-target IDs; require the target to equal the candidate. Verify the commit and tag with
   an independently obtained allowed-signers trust root. A failed or withdrawn tag name is
   never moved or reused.
3. Build the upload set into a previously absent directory. The two completed evidence
   roots are preserved as distinct deterministic tar roots. The signed map binds both tar
   byte identities and all candidate/tree/tag identities, while verification enforces the
   exact map/signature/tar file set:

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

   Exit status 3 means the no-replace rename may already have committed a complete
   output while parent-directory durability or result reporting remained uncertain.
   Retain that path, verify it independently, and resolve the durability warning before
   upload; do not blindly rerun or delete it.

   The directory must contain exactly:

   - `galadriel-0.9.0-qualification.tar`
   - `galadriel-0.9.0-closure.tar`
   - `galadriel-0.9.0-release-asset-map.json`
   - `galadriel-0.9.0-release-asset-map.json.sig`

   Verify that exact set before upload, using the independent trust root rather than the
   candidate-tracked copy:

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

4. Push only the exact `main` and `v0.9.0` identities, then verify the remote commit,
   annotated tag object, peeled target, and both signatures again. Re-check hooks, installed
   automation, and releases immediately before publication; no process may create a DOI,
   Zenodo record, package publication, replacement asset, or second release.
5. Create a **draft** GitHub release from `v0.9.0` with literal title
   `Galadriel 0.9.0` and the exact tracked `RELEASE-NOTES.md` body. Upload the four named
   files explicitly and without replacement. Require the API asset list to contain exactly
   those four names, and compare every API-reported byte length and SHA-256 digest with the
   corresponding locally computed file value. If the API omits a digest, record that field
   as unavailable and use the mandatory authenticated byte-for-byte comparison in the next
   step; never invent an API digest or waive the comparison. For the two tar files only,
   additionally require locally computed values to equal their rows in the signed map; the
   map does not contain rows for itself or its detached signature. The authenticated draft
   re-download in the next step verifies the map signature and exact four-file set.
   GitHub's automatically
   generated “Source code” zip and tarball are separate convenience snapshots: they are
   not attached assurance assets, are not covered by the map, and must not substitute for
   either evidence tar.
6. Download all four draft assets through the authenticated GitHub path into a new empty
   directory. Require each downloaded file to be byte-identical to its local upload source,
   then run `verify` and reconstruct both path-preserving tiers atomically. Release asset
   construction and canonical-tar verification use the audit-pinned `CPython 3.14.6`;
   another interpreter is outside the qualified deterministic representation:

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

   In each reconstructed root, verify `SHA256SUMS` over the exact internal file set and
   authenticate both tier manifests with the independent trust root. The release
   principal is `sepmhn@gmail.com`; the literal namespaces are
   `galadriel-qualification-manifest` and `galadriel-closure-manifest`:

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

   The outer signed map has already proved the exact reconstructed inventory; the
   checksum verifier independently requires `SHA256SUMS` to enumerate every other file
   exactly once. Re-run the `local_convergence.py verify` command above against the
   reconstructed closure. Extract the qualification tier's
   `galadriel-0.9.0.tar.gz` into a second fresh directory and run the locked
   build/test/documentation gates from that downloaded source.
7. Publish the draft only after every authenticated-download check passes and UTC has
   reached the declared release date. Then download the four public assets anonymously
   into another empty directory and repeat the four-file comparison with the local upload
   source, exact-set verification, reconstruction, internal signature/checksum checks, and
   the fresh-source build. Require all six tag-bound links
   in the release body to resolve successfully. Because GitHub `blob` links return HTML,
   byte-compare their raw counterparts—not the HTML pages—with the corresponding tagged
   Git blobs. Also byte-compare all three public JSON Schema `$id` URLs with their tagged
   Git blobs:

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
8. Only after the published release and anonymous downloads are verified, preserve the
   legacy identities listed in `WITHDRAWN-RELEASES.md`; then delete only the obsolete tag
   and release-work refs locally/remotely, without deleting their commits or evidence, and
   prove the refs and any legacy GitHub release are absent.
9. Confirm the release author is Sepehr Mahmoudian, the literal title is
   `Galadriel 0.9.0`, and the version, date, and tracked body are exact. Require exactly
   four attached assets and no DOI/Zenodo/crates.io/deployment/production claim. Retain
   the remote branch, signed tag, release, download, signature, reconstruction,
   fresh-build, and cleanup evidence.

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
