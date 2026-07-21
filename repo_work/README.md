# Repository review utilities

These standard-library-only utilities implement the exact-checkout review workflow
required for the Galadriel 0.9 research release. They inventory evidence;
they never claim that a machine-generated row received human review.

Source readiness and release closure are separate. The checked-in
`task-closure-plan.json` is a byte-bound projection of all 116 handoff tasks and
contains only open source questions, requirements, counterfactuals, evidence
types, and explicit exclusions. It never contains generated completion findings.
Verify that source state with:

```bash
python3 repo_work/build_task_dispositions.py verify
python3 scripts/release_audit.py verify
```

Exact-file completion, task findings, the final twenty-lens review, and the
release decision are produced after the signed candidate exists and remain in an
external closure bundle.

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

The feature-graph gate reads `.ncp-consumer` once through a bounded, no-follow,
nonblocking regular-file descriptor. It binds the exact PID, NCP, Zenoh, and Tokio
feature sets used by every profile in which those dependencies are security relevant.

For qualification bundles, `audit_tracked_files.py --out` and
`scan_claim_language.py --out` may point outside the checkout. Each output must be
new, so a prior review cannot be overwritten or silently mixed with another cut.

Reproduce the frozen, unmodified baseline separately from a dirty candidate
checkout (the output directory must not already exist):

```bash
python3 repo_work/reproduce_baseline.py \
  --repo . \
  --commit 94e2f8cc01f352d2bf899b7f656997f143a2588f \
  --out release/0.9.0/evidence/baseline-94e2f8cc
```

The runner uses a detached temporary worktree and a temporary Cargo target
directory. It records the exact commit/tree, tool identities, command arguments,
combined output, exit codes, timestamps, Cargo metadata, and artifact digests.

Freeze the complete supplied master handoff and exact baseline inputs only after the
release input records are final. Generate into a new staging directory: the tool refuses
to overwrite a manifest, signer file, or pre-existing signature. Verify the staged bytes
before replacing the tracked generated artifacts and regenerating the audit inventory:

```bash
handoff_root=/path/to/SEPAHEAD_V1_0_CURRENT_HEAD_MAX_EFFORT_MASTER_HANDOFF
freeze_dir="$(mktemp -d "${TMPDIR:-/tmp}/galadriel-0.9.0-freeze.XXXXXX")"
python3 repo_work/freeze_audit_inputs.py \
  --repo . \
  --handoff-root "$handoff_root" \
  --out "$freeze_dir/FROZEN-AUDIT-INPUTS.json" \
  --allowed-signers "$freeze_dir/ALLOWED_SIGNERS"
ssh-keygen -Y sign \
  -f "$(git config --get user.signingkey)" \
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

The semantic verifier checks canonical manifest bytes, the detached signature,
the exact ordered release-input set and current digests, baseline object bindings,
handoff cross-bindings, and signer metadata. Supplying `--handoff-root` additionally
re-inventories every external handoff entry. CI and portable qualification omit that
external path but still validate the retained handoff structure and the declared
child-archive and task-ledger digests. The recorded origin and tag list are historical
discovery inputs; verification validates their shape without comparing them to mutable
live refs. Release-input digests intentionally bind the current working-tree bytes during
the pre-commit freeze; candidate qualification later requires a clean checkout at the
exact signed commit before accepting those same bytes.

For the first trust-file bootstrap, independently inspect the staged public key and
install `ALLOWED_SIGNERS` only when no tracked trust file exists. Any later key rotation
is a release-boundary change: replace the tracked public key deliberately, regenerate and
re-sign the frozen manifest, and restart candidacy and every candidate-bound check. The
public-key entry is intentionally namespace-agnostic because its byte-identical external
counterpart authenticates signed Git commits and several release bundles. Every consumer
pins its own literal namespace in Git or the release tooling; adding another consumer
requires review. The file must not be treated as a general application trust policy.

Private signing material is never copied into the repository. `ALLOWED_SIGNERS`
contains only the public key needed to reproduce signature verification; the
`--signing-key` handle may itself be that public key when its private half is
available through `ssh-agent`.

For closure finalization, prefer that agent-backed public-key handle and pass
`--snapshot-dir` to a secure external filesystem with at least 8 GiB plus review-
input capacity. The finalizer authenticates and snapshots each signed input once,
reports any failed temporary cleanup with its exact path, and never treats an
abandoned staging directory as a valid closure tier.

Public-API verification invokes `cargo-public-api` through the exact
`nightly-2026-06-16` rustdoc toolchain and rejects a different rustc commit.

After all four `mutation-diff` jobs pass for the exact candidate, download and
inspect their four artifact directories. Shard `2/4` also contains two focused
direct-test runs for synchronization mutants that intentionally block unrelated
full-suite tests when active. Assemble all six checked outcome records and their
run receipt without rewriting the candidate or trusting a candidate-provided key:

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

The workflow disables ambient cargo-mutants configuration and validates the two
focused outputs before the broad shard runs. The assembler requires each job's
exact candidate/tree record, canonical frozen-baseline diff and digest, one
successful non-vacuous Cargo baseline, at least one caught mutant per shard, and
no missed or timed-out mutant. It also binds the focused runs to the exact Cargo
build/test commands, process outcomes, complete package/file/function/span mutant
descriptors, and named non-blocking tests. It copies the six checked
`outcomes.json` files and their exact-run receipt into a signed external evidence
directory.

Qualify a final clean signed `main` commit into a new directory outside the
checkout. The deep form runs the pinned hostile-input campaigns as well as the
full build, test, documentation, feature, release, dependency, source-inventory,
evidence, source-archive, SBOM, and checksum gates:

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

The retained `.crate` files are reproducible unpublished-source packages, not a
crates.io publication claim. Cargo prepares them twice in disposable exact-commit
clones using offline path overrides for the locked unpublished workspace/Git
dependencies. Per-package generated lockfiles are excluded; the exact candidate
`Cargo.lock` remains in the signed full source archive.

The qualifier works in a detached temporary worktree and refuses a dirty subject,
wrong branch/commit, unsigned commit, existing output directory, stale audit, or
post-run source drift. It also regenerates the complete core and PID Rust API
inventories with exactly `cargo-public-api 0.52.0` and rejects byte-level drift
from the retained snapshots. A recorded run is author-operated evidence, not an
independent clean-room or deployment qualification.

Its signed manifest covers every semantic artifact while excluding only the manifest,
its detached signature, and the final `SHA256SUMS` control file. That checksum then
enumerates every other retained file, including the manifest/signature pair. Finalization
requires exactly those signed rows plus the three control files, snapshots them once,
and recomputes `SHA256SUMS`; an unlisted regular file, symlink, FIFO, special file, or
empty directory, as well as a mid-copy inventory change, aborts before closure
publication.

After intentionally refreshing an accepted snapshot, regenerate its derived core
comparison with `python3 repo_work/check_public_api.py --refresh-diff`. The command
first proves that both retained snapshots exactly match source and the pinned tool;
it never rewrites either snapshot, and its unified diff omits mutable file timestamps.

After the exact file ledger and reviewer inputs are completed, sign the T114 review,
then the candidate-bound v3 T115 decision, then the all-task dispositions. Create the
closure tier without modifying the candidate:

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

Both commands derive an ephemeral public trust root from the external signing-key
handle (a private key or an agent-backed Ed25519 public key).
The candidate's tracked `ALLOWED_SIGNERS` is checked only as matching metadata; it
is never trusted to authenticate its own commit or bundle.

The supplied decision already carries the detached `galadriel-release-decision`
signature; finalization retains those exact bytes instead of generating a second,
self-referential decision. It stages, verifies, and flushes the whole tier before one
atomic no-replace same-parent rename, so the requested path is never a partial
result. Pre-publication failures leave it absent. Status 3 means the rename committed
a complete output but the later parent-directory durability sync, temporary-input
cleanup, or result report failed. A cleanup failure still emits a machine-readable
`COMMITTED_WITH_CLEANUP_WARNING` result naming the complete output. Independently
verify that retained bundle and resolve any retained snapshot path before use.

Atomic no-replace publication requires macOS `renamex_np` or a Linux libc exposing
`renameat2`. Other platforms fail closed before publication; finalization must not be
replaced with a check-then-rename sequence.

Finalization also writes `LOCAL-CONVERGENCE.json` and its detached
`galadriel-local-convergence` signature. The adapted schema preserves the supplied
116-task and ten-wave gates while binding the approved 0.9.0 candidate. The
validator requires complete tracked-file review, exact ordered task/wave coverage,
artifact byte identities, and explicit pid-rs, NCP, Crebain, Haldir, Prisoma,
Engram/Paper2Brain, ROS / ROS 2, and external-authority requirements. `LOCAL_PIN_PASS`
covers exact locally qualified pid-rs/NCP build pins.
`ready_for_cross_repo_reconciliation` means only that optional reciprocal work may
begin; it is not another repository's GO or deployment qualification.

`FILE_REVIEW_LEDGER.csv` contains one row per tracked path with immutable Git and
SHA-256 identities, language, known generator, criticality, and a reviewer-role
assignment. Its review fields start as `UNREVIEWED`; assignment is not evidence of
completion. Each packet covers the complete declared line range (or complete byte
range for binary/data), and a reviewer must fill findings from the exact blob.
Binary, symlink, generated, and data paths remain separate review items. External
comments remain open unless an identified human actually records them.

`verify_evidence_manifest.py` verifies a strict JSON artifact manifest without
following paths outside the selected root. It rejects duplicate keys, duplicate
paths, non-regular artifacts, and digest/size drift.

<!-- BEGIN RELEASE-ASSET-PACKAGER -->
## Deterministic GitHub release evidence assets

`package_release_assets.py` converts the exact, already completed qualification and
closure directories into a public four-file upload set without changing either tier:

- `galadriel-0.9.0-qualification.tar`
- `galadriel-0.9.0-closure.tar`
- `galadriel-0.9.0-release-asset-map.json`
- `galadriel-0.9.0-release-asset-map.json.sig`

The map is the authoritative tier-to-asset-name mapping. Consumers resolve a tier
through its map row and verify the recorded filename, root prefix, digest, size, and
complete file inventory; they must not infer meaning from attachment order or an
opaque download URL. The two uncompressed tar files have distinct fixed root prefixes,
retain every internal directory and regular file (including each tier's root
`SHA256SUMS`), and use canonical metadata, explicit strict UTF-8 member-name encoding,
and lexical member order. Each tar must be strictly smaller than 2 GiB. The upload set
contains exactly four assets, well below GitHub's 1,000-upload limit.

To keep POSIX, Windows, and archive path interpretations unambiguous, any input name
containing a backslash is rejected even though POSIX permits that byte in a filename.
The independently supplied `ALLOWED_SIGNERS` trust root is limited to 4 KiB. Prepare
replacement evidence tiers or a narrower reviewed trust root before packaging if either
bound is exceeded; the packager never rewrites finalized evidence.

First independently verify the candidate commit and annotated signed tag using the
release trust root. Supply the resulting full commit, tree, tag-object, and peeled
tag-target IDs; the packager requires the tag target to equal the candidate commit and
binds all of them into the signed map:

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

The map always identifies release `0.9.0`, author `Sepehr Mahmoudian`, and null DOI
and Zenodo fields. Its detached SSH signature uses the literal
`galadriel-release-assets` namespace and the established release principal. Private
signing material is never copied. Build snapshots both input trees through bounded,
nonblocking, no-follow descriptors; rejects links, special files, path ambiguity,
overlap, or ordinary mid-run change; self-verifies the completed staging tree; and
publishes it with the same atomic no-replace mechanism as release finalization.
Exit status 3 has the same committed-with-durability-warning meaning: the requested
output may already be complete after the atomic rename. Retain it, verify it
independently, and resolve the parent-directory durability uncertainty before upload;
do not blindly rerun or delete it.

Release asset construction and canonical-tar verification are qualified with the
audit-pinned `CPython 3.14.6`. A different interpreter may emit different PAX bytes and
therefore fail closed; use the pinned interpreter for public release verification.

Verify downloaded assets against an independently obtained allowed-signers trust root
and explicit expected identities:

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

Verification authenticates snapshotted map bytes before trusting any rows, requires
canonical duplicate-free JSON and the exact four-file asset set, checks every bound
identity and inventory row, then regenerates each canonical tar stream and requires its
metadata, content, order, inventory, and complete bytes to match. It rejects compressed,
appended, reordered, duplicated, linked, special, missing, extra, oversized, or changing
inputs. The candidate-tracked `release/0.9.0/audit/ALLOWED_SIGNERS` is comparison
metadata only: a verifier may compare it byte-for-byte with the independent trust root,
but must never let the candidate authenticate itself.

`extract` (alias `reconstruct`) performs the same verification while manually writing
regular files into a new mode-0700 staging directory. It never calls `extractall`, never
follows archive links, creates files exclusively, and publishes the two fixed-prefix
trees only after complete verification:

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

No mode performs a GitHub mutation. Upload all four files only after verification.
GitHub's automatically generated “Source code” zip and tarball are separate convenience
snapshots: they are not members of this four-file upload set, are not authenticated by
the release-asset map, and must not substitute for either evidence tar.
After reconstruction, authenticate the tier manifests under the distinct literal SSH
namespaces `galadriel-qualification-manifest` and `galadriel-closure-manifest`, and
validate each exact `SHA256SUMS` inventory. The normative commands and release principal
are in `release/0.9.0/RELEASE-RUNBOOK.md`.
<!-- END RELEASE-ASSET-PACKAGER -->
