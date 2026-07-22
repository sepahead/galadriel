# Repository review utilities

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| DOI | digital object identifier |
| JSON | JavaScript Object Notation |
| NCP | Neuro-Cybernetic Protocol |
| PAX | portable archive exchange |
| PID | partial information decomposition |
| POSIX | Portable Operating System Interface |
| ROS | Robot Operating System |
| SHA-256 | Secure Hash Algorithm 256 |
| SSH | Secure Shell |
| URL | Uniform Resource Locator |
| UTF-8 | 8-bit Unicode Transformation Format |

These standard-library-only utilities implement the exact-checkout review workflow for the Galadriel 0.9 research release.
They inventory evidence.
They never claim human review of a machine-generated row.

Source readiness and release closure are separate.
The checked-in `task-closure-plan.json` is a byte-bound projection of all 116 handoff tasks.
It contains only open source questions, requirements, counterfactuals, evidence types, and explicit exclusions.
It never contains generated completion findings.
Verify that source state with these commands:

```bash
python3 repo_work/build_task_dispositions.py verify
python3 scripts/release_audit.py verify
```

The release process produces exact-file completion after the signed candidate exists.
It also produces task findings, the final twenty-lens review, and the release decision.
An external closure bundle retains these records.

Run them from a clean candidate checkout:

```bash
python3 repo_work/check_frozen_head.py --expected "$(git rev-parse HEAD)"
python3 repo_work/check_feature_graph.py
python3 repo_work/local_convergence.py schema --repo .
python3 repo_work/check_public_api.py
python3 repo_work/audit_tracked_files.py --repo . --out audit/generated
python3 repo_work/make_review_packets.py audit/generated/FILE_REVIEW_LEDGER.csv --lanes 3
python3 repo_work/scan_claim_language.py --repo . --out audit/generated/CLAIM_LANGUAGE.json
```

The feature-graph gate reads `.ncp-consumer` one time through a bounded regular-file descriptor.
The descriptor does not follow links or block.
The gate binds the exact PID, NCP, Zenoh, and Tokio feature sets.
These feature sets apply to each profile where those dependencies affect security.

For qualification bundles, `audit_tracked_files.py --out` can point outside the checkout.
`scan_claim_language.py --out` can also point outside the checkout.
Use a new output path for each command.
This requirement prevents an overwrite or a silent mix of review cuts.

If the candidate checkout is dirty, reproduce the frozen unmodified baseline separately.
The output directory must not exist before this command:

```bash
python3 repo_work/reproduce_baseline.py \
  --repo . \
  --commit 94e2f8cc01f352d2bf899b7f656997f143a2588f \
  --out /new/path/galadriel-baseline-94e2f8cc
```

The runner uses a detached temporary worktree and a temporary Cargo target directory.
It records the exact commit and tree.
It also records tool identities, command arguments, combined output, exit codes, timestamps, Cargo metadata, and artifact digests.

After the release input records are final, freeze the complete supplied master handoff and exact baseline inputs.
Generate the artifacts in a new temporary directory.
The tool refuses a manifest, signer file, or signature that already exists.
Before you replace tracked generated artifacts, verify the temporary bytes.
Then, regenerate the audit inventory:

```bash
set -euo pipefail
handoff_root=/path/to/SEPAHEAD_V1_0_CURRENT_HEAD_MAX_EFFORT_MASTER_HANDOFF
freeze_dir="$(mktemp -d "${TMPDIR:-/tmp}/galadriel-0.9.0-freeze.XXXXXX")"
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"
python3 repo_work/freeze_audit_inputs.py \
  --repo . \
  --handoff-root "$handoff_root" \
  --out "$freeze_dir/FROZEN-AUDIT-INPUTS.json" \
  --allowed-signers "$freeze_dir/ALLOWED_SIGNERS"
ssh-keygen -Y sign \
  -f "$signing_key" \
  -n galadriel-release-audit \
  "$freeze_dir/FROZEN-AUDIT-INPUTS.json"
python3 repo_work/freeze_audit_inputs.py verify \
  --repo . \
  --handoff-root "$handoff_root" \
  --out "$freeze_dir/FROZEN-AUDIT-INPUTS.json" \
  --allowed-signers "$freeze_dir/ALLOWED_SIGNERS"
cmp "$freeze_dir/ALLOWED_SIGNERS" release/0.9.0/audit/ALLOWED_SIGNERS
install -m 0644 "$freeze_dir/FROZEN-AUDIT-INPUTS.json" \
  release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json
install -m 0644 "$freeze_dir/FROZEN-AUDIT-INPUTS.json.sig" \
  release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json.sig
python3 scripts/release_audit.py generate
python3 repo_work/freeze_audit_inputs.py verify \
  --repo . \
  --handoff-root "$handoff_root" \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json \
  --allowed-signers release/0.9.0/audit/ALLOWED_SIGNERS
python3 scripts/release_audit.py verify
```

The semantic verifier checks canonical manifest bytes and the detached signature.
It checks the ordered release-input set and current digests.
It also checks baseline object bindings, handoff cross-bindings, and signer metadata.

When the command includes `--handoff-root`, the verifier inventories each external handoff entry again.
Continuous integration and portable qualification omit that external path.
They still validate the retained handoff structure.
They also validate the declared child-archive and task-ledger digests.

The recorded origin and tag list are historical discovery inputs.
The verifier validates their shape but does not compare them with mutable live references.
During the pre-commit freeze, release-input digests bind the current worktree bytes.
Candidate qualification accepts those bytes only from a clean checkout at the exact signed commit.

For the first trust-file bootstrap, confirm that no tracked trust file exists.
Then, independently inspect the temporary public key.
Install `ALLOWED_SIGNERS` only after that inspection.

A key rotation after bootstrap is a release-boundary change.
Replace the tracked public key deliberately.
Regenerate and sign the frozen manifest again.
Restart candidacy and each candidate-bound check.

The public-key entry intentionally has no namespace.
Its byte-identical external counterpart authenticates signed Git commits and several release bundles.
Each consumer pins its literal namespace in Git or the release tools.
Before you add a consumer, review the new use.
Do not use this file as a general application trust policy.

Never copy private signing material into the repository.
`ALLOWED_SIGNERS` contains only the public key for reproducible signature verification.
The `--signing-key` handle can be that public key when `ssh-agent` has its private half.

For closure finalization, prefer that agent-backed public-key handle.
Pass `--snapshot-dir` to a secure external file system.
The file system must have at least 8 GiB plus capacity for review inputs.
The finalizer authenticates each signed input one time.
It takes one snapshot of each input.
If temporary cleanup fails, it reports the exact path.

The finalizer never accepts an abandoned temporary directory as a valid closure tier.

Public-API verification invokes `cargo-public-api` through the exact
`nightly-2026-06-16` rustdoc toolchain and rejects a different rustc commit.

After all four `mutation-diff` jobs pass for the exact candidate, download their four artifact directories.
Inspect each directory.
Shard `2/4` also contains two focused direct-test runs for synchronization mutants.
When active, those mutants intentionally block unrelated full-suite tests.
Assemble all six checked outcome records and their run receipt.
Do not rewrite the candidate or trust a candidate-provided key:

```bash
set -euo pipefail
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"

python3 repo_work/prepare_mutation_evidence.py \
  --repo . \
  --candidate "$(git rev-parse HEAD)" \
  --out /new/path/galadriel-0.9.0-mutation-evidence \
  --signing-key "$signing_key" \
  --shard 0/4=/downloaded/mutation-diff-results-1-of-4 \
  --shard 1/4=/downloaded/mutation-diff-results-2-of-4 \
  --shard 2/4=/downloaded/mutation-diff-results-3-of-4 \
  --shard 3/4=/downloaded/mutation-diff-results-4-of-4
```

The workflow disables ambient cargo-mutants configuration.
It validates the two focused outputs before the broad shard runs.

The assembler requires these items from each job:

- exact candidate and tree record
- canonical frozen-baseline difference and digest
- one successful non-vacuous Cargo baseline
- at least one caught mutant per shard
- no missed mutant
- no timed-out mutant

It binds the focused runs to the exact Cargo build and test commands.
It also binds process outcomes and complete package, file, function, and span mutant descriptors.
The records include the named `non-blocking` tests.
The assembler copies the six checked `outcomes.json` files into a signed external evidence directory.
It also copies their exact-run receipt.

Qualify a final clean signed `main` commit into a new directory outside the checkout.
The deep form runs the pinned hostile-input campaigns.
It also runs these complete gates:

- build
- test
- documentation
- feature
- release
- dependency
- source inventory
- evidence
- source archive
- software bill of materials (SBOM)
- checksum

```bash
set -euo pipefail
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"

python3 repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$signing_key" \
  --mutation-evidence /new/path/galadriel-0.9.0-mutation-evidence/mutation-evidence.json \
  --mutation-evidence-signature /new/path/galadriel-0.9.0-mutation-evidence/mutation-evidence.json.sig \
  --evidence-config evidence/galadriel-0.9-candidate.json \
  --deep \
  --keep-going
```

The retained supply-chain evidence binds each stream to a pinned tool.
`cargo-deny` 0.19.9 writes license JSON only to standard error (stderr).
Its standard output (stdout) must contain zero bytes.
`cargo-audit` writes JSON to stdout.
The evidence retains its stderr as diagnostics.
Before it accepts the qualification bundle, finalization verifies these stream declarations.

It also verifies the opposite-stream diagnostics and each report's exact signed-manifest identity.

The retained `.crate` files are reproducible unpublished-source packages.
They do not claim a crates.io publication.
Cargo prepares each package two times in disposable exact-commit clones.
It uses offline path overrides for the locked unpublished workspace and Git dependencies.
Cargo excludes per-package generated lockfiles.
The signed full source archive retains the exact candidate `Cargo.lock`.

The qualifier works in a detached temporary worktree.
It refuses these conditions:

- dirty subject
- wrong branch or commit
- unsigned commit
- output directory that already exists
- stale audit
- source drift after the run

It regenerates the complete core and PID Rust API inventories with exactly `cargo-public-api 0.52.0`.
It rejects byte-level drift from the retained snapshots.
The author operates and records each run.
The run supplies evidence.
It is not an independent clean-room or deployment qualification.

Its signed manifest covers each semantic artifact.
It excludes only the manifest, its detached signature, and the final `SHA256SUMS` control file.
That checksum lists each other retained file.
This list includes the manifest and signature pair.

Finalization requires exactly the signed rows and the three control files.
It snapshots each required item one time and calculates `SHA256SUMS` again.
Finalization aborts before closure publication if it finds one of these conditions:

- unlisted regular file
- symbolic link
- first-in, first-out (FIFO) special file
- other special file
- empty directory
- inventory change during a copy

After you intentionally refresh an accepted snapshot, regenerate its derived core comparison.
Use `python3 repo_work/check_public_api.py --refresh-diff`.
The command first proves that both retained snapshots exactly match source and the pinned tool.
It never rewrites either snapshot.
Its unified difference omits mutable file timestamps.

After reviewers complete the exact file ledger and review inputs, sign the T114 review.
Then, sign the candidate-bound v3 T115 decision.
Next, sign the all-task dispositions.
Create the closure tier without a candidate change:

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

Both commands derive a temporary public trust root from the external signing-key handle.
The handle can be a private key or an agent-backed Ed25519 public key.
The commands compare the candidate-tracked `ALLOWED_SIGNERS` only as metadata.
They never use that file to authenticate the candidate commit or bundle.

The supplied decision already has the detached `galadriel-release-decision` signature.
Finalization retains those exact bytes and does not create a second self-referential decision.
It stages, verifies, and flushes the complete tier before one atomic no-replace same-parent rename.
Thus, the requested path never contains a partial result.
Failures before publication leave the path absent.

Status 3 means that the rename committed a complete output.
It also means that a subsequent parent-directory durability sync, temporary-input cleanup, or result report failed.
A cleanup failure still emits a machine-readable `COMMITTED_WITH_CLEANUP_WARNING` result.
That result names the complete output.
Before use, independently verify the retained bundle.
Resolve each retained snapshot path.

Atomic no-replace publication requires macOS `renamex_np` or a Linux libc that exposes `renameat2`.
Other platforms fail closed before publication.
Do not replace finalization with a check-then-rename sequence.

Finalization also writes `LOCAL-CONVERGENCE.json`.
It writes the detached `galadriel-local-convergence` signature.
The adapted schema preserves the supplied 116-task and ten-wave gates.
It also binds the approved 0.9.0 candidate.

The validator requires complete tracked-file review.
It requires exact ordered task and wave coverage.
It requires artifact byte identities.
It also requires explicit requirements for these projects and boundaries:

- pid-rs
- NCP
- Crebain
- Haldir
- Prisoma
- Engram and Paper2Brain
- ROS and ROS 2
- external authority

`LOCAL_PIN_PASS` covers the exact locally qualified pid-rs and NCP build pins.
`ready_for_cross_repo_reconciliation` means only that optional reciprocal work can start.
It is not another repository GO or deployment qualification.

`FILE_REVIEW_LEDGER.csv` contains one row for each tracked path.
Each row has immutable Git and SHA-256 identities, language, known generator, criticality, and a reviewer-role assignment.
Its review fields start as `UNREVIEWED`.
An assignment does not prove completion.
Each packet covers the complete declared line range.
For binary or data files, it covers the complete byte range.

A reviewer must record findings from the exact blob.
Binary, symbolic-link, generated, and data paths remain separate review items.
External comments remain open until an identified human records them.

`verify_evidence_manifest.py` verifies a strict JSON artifact manifest.
It does not follow paths outside the selected root.
It rejects duplicate keys, duplicate paths, non-regular artifacts, and digest or size drift.

<!-- BEGIN RELEASE-ASSET-PACKAGER -->
## Deterministic GitHub release evidence assets

`package_release_assets.py` converts the exact completed qualification and closure directories into a public four-file upload set.
It does not change either tier:

- `galadriel-0.9.0-qualification.tar`
- `galadriel-0.9.0-closure.tar`
- `galadriel-0.9.0-release-asset-map.json`
- `galadriel-0.9.0-release-asset-map.json.sig`

The map is the authoritative tier-to-asset-name map.
For each tier, use its map row.
Verify the recorded filename, root prefix, digest, size, and complete file inventory.
Do not infer a tier from attachment order or an opaque download URL.

The two uncompressed tar files have distinct fixed root prefixes.
They retain each internal directory and regular file.
This inventory includes each tier root `SHA256SUMS`.
The tar files use canonical metadata and explicit strict UTF-8 member-name encoding.
They also use lexical member order.
Each tar must be strictly smaller than 2 GiB.

The upload set contains exactly four assets, below the GitHub limit of 1,000 uploads.

The packager rejects each input name that has a backslash.
This rule makes `Portable Operating System Interface (POSIX)`, Windows, and archive path interpretations unambiguous.
POSIX permits that byte in a filename.
The independently supplied `ALLOWED_SIGNERS` trust root has a maximum size of 4 KiB.
If the 2 GiB or 4 KiB bound fails, prepare replacement evidence tiers or a narrower reviewed trust root before packaging.
The packager never rewrites finalized evidence.

Before packaging, independently verify the candidate commit and annotated signed tag with the release trust root.
Supply the full commit, tree, tag-object, and peeled tag-target identifiers.
The packager requires the tag target to equal the candidate commit.
It binds all these identifiers into the signed map:

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

The map always identifies release `0.9.0` and author `Sepehr Mahmoudian`.
Its DOI and Zenodo fields are null.
Its detached SSH signature uses the literal `galadriel-release-assets` namespace.
It also uses the established release principal.
Never copy private signing material.

The `build` command snapshots both input trees through bounded descriptors.
The descriptors do not block or follow links.
The command rejects links, special files, path ambiguity, overlap, and ordinary changes during a run.
It verifies the completed temporary tree itself.
It uses the same atomic no-replace publication mechanism as release finalization.

Exit status 3 means that the atomic rename can have committed a complete output.
It also means that durability remains uncertain.
Retain the output.
Verify it independently.
Before upload, resolve the parent-directory durability uncertainty.
Do not repeat or delete the output without verification.

The audit qualifies release asset construction and canonical-tar verification with `CPython 3.14.6`.
A different interpreter can emit different PAX bytes and fail closed.
Use the pinned interpreter for public release verification.

Verify downloaded assets against an independently obtained allowed-signers trust root.
Supply the explicit expected identities:

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
  --assets /downloaded/galadriel-0.9.0-github-assets \
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --expected-candidate "$candidate" \
  --expected-tree "$tree" \
  --expected-tag-name "$tag" \
  --expected-tag-object "$tag_object" \
  --expected-tag-target "$tag_target"
```

Verification authenticates the snapshotted map bytes before it uses any row.
It requires canonical duplicate-free JSON and the exact four-file asset set.
It checks each bound identity and inventory row.
Then, it generates each canonical tar stream again.
It requires equal metadata, content, order, inventory, and complete bytes.

It rejects compressed, appended, reordered, duplicated, linked, special, missing, extra, or oversized inputs.
It also rejects an input that changes during verification.
The candidate-tracked `release/0.9.0/audit/ALLOWED_SIGNERS` is comparison metadata only.
A verifier can compare it byte-for-byte with the independent trust root.
The verifier must not let the candidate authenticate itself.

`extract`, also named `reconstruct`, performs the same verification.
It writes regular files manually into a new mode-0700 temporary directory.
It never calls `extractall` or follows archive links.
It creates each file exclusively.
It publishes the two fixed-prefix trees only after complete verification:

```bash
set -euo pipefail
test "$(python3 -c 'import platform; print(platform.python_implementation(), platform.python_version())')" = "CPython 3.14.6"
candidate="$(git rev-parse 'HEAD^{commit}')"
tree="$(git rev-parse "$candidate^{tree}")"
tag=v0.9.0
tag_object="$(git rev-parse "$tag^{tag}")"
tag_target="$(git rev-parse "$tag^{}")"
test "$tag_target" = "$candidate"

python3 repo_work/package_release_assets.py reconstruct \
  --assets /downloaded/galadriel-0.9.0-github-assets \
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --out /new/path/galadriel-0.9.0-reconstructed \
  --expected-candidate "$candidate" \
  --expected-tree "$tree" \
  --expected-tag-name "$tag" \
  --expected-tag-object "$tag_object" \
  --expected-tag-target "$tag_target"
```

No mode changes GitHub state.
After verification, upload all four files.
GitHub automatically generates a “Source code” zip and tarball as convenience snapshots.
They are not part of this four-file upload set.
The release-asset map does not authenticate them.
They must not replace either evidence tar.

After reconstruction, authenticate the tier manifests under two distinct literal SSH namespaces.
The namespaces are `galadriel-qualification-manifest` and `galadriel-closure-manifest`.
Validate each exact `SHA256SUMS` inventory.
`release/0.9.0/RELEASE-RUNBOOK.md` contains the normative commands and release principal.
<!-- END RELEASE-ASSET-PACKAGER -->
