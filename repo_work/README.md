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
python3 repo_work/check_public_api.py
python3 repo_work/audit_tracked_files.py --repo . --out audit/generated
python3 repo_work/make_review_packets.py audit/generated/FILE_REVIEW_LEDGER.csv --lanes 3
python3 repo_work/scan_claim_language.py --repo . --out audit/generated/CLAIM_LANGUAGE.json
```

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

Freeze the complete supplied master handoff and exact baseline inputs after the
release input records are final, then sign and verify the immutable bytes:

```bash
python3 repo_work/freeze_audit_inputs.py \
  --repo . \
  --handoff-root /path/to/SEPAHEAD_V1_0_CURRENT_HEAD_MAX_EFFORT_MASTER_HANDOFF \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json \
  --allowed-signers release/0.9.0/audit/ALLOWED_SIGNERS
ssh-keygen -Y sign \
  -f "$(git config --get user.signingkey)" \
  -n galadriel-release-audit \
  release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json
ssh-keygen -Y verify \
  -f release/0.9.0/audit/ALLOWED_SIGNERS \
  -I sepmhn@gmail.com \
  -n galadriel-release-audit \
  -s release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json.sig \
  < release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json
```

Private signing material is never copied into the repository. `ALLOWED_SIGNERS`
contains only the public key needed to reproduce signature verification; the
`--signing-key` handle may itself be that public key when its private half is
available through `ssh-agent`.

Public-API verification invokes `cargo-public-api` through the exact
`nightly-2026-06-16` rustdoc toolchain and rejects a different rustc commit.

After all four `mutation-diff` jobs pass for the exact candidate, download and
inspect their four artifact directories. Shard `2/4` also contains two focused
direct-test runs for synchronization mutants that intentionally block unrelated
full-suite tests when active. Assemble all six checked outcome records and their
run receipt without rewriting the candidate or trusting a candidate-provided key:

```bash
python3 repo_work/prepare_mutation_evidence.py \
  --repo . \
  --candidate "$(git rev-parse HEAD)" \
  --out /new/path/galadriel-0.9.0-mutation-evidence \
  --signing-key "$(git config --get user.signingkey)" \
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
python3 repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$(git config --get user.signingkey)" \
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

After intentionally refreshing an accepted snapshot, regenerate its derived core
comparison with `python3 repo_work/check_public_api.py --refresh-diff`. The command
first proves that both retained snapshots exactly match source and the pinned tool;
it never rewrites either snapshot, and its unified diff omits mutable file timestamps.

After the exact file ledger and reviewer inputs are completed and signed, create
the closure tier and separately signed decision without modifying the candidate:

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
  --decision-input /reviewed/path/release-decision-input.json \
  --signing-key "$(git config --get user.signingkey)" \
  --out /new/path/galadriel-0.9.0-closure
```

Both commands derive an ephemeral public trust root from the external signing-key
handle (a private key or an agent-backed Ed25519 public key).
The candidate's tracked `ALLOWED_SIGNERS` is checked only as matching metadata; it
is never trusted to authenticate its own commit or bundle.

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
