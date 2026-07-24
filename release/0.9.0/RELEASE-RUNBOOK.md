# Galadriel 0.9.0 publication, rollback, and withdrawal runbook

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| CI | continuous integration |
| CPU | central processing unit |
| DOI | digital object identifier |
| JSON | JavaScript Object Notation |
| NCP | Neuro-Cybernetic Protocol |
| ROS | Robot Operating System |
| SBOM | software bill of materials |
| SHA-256 | Secure Hash Algorithm 256 |
| SSH | Secure Shell |
| UTC | Coordinated Universal Time |
| URLs | Uniform Resource Locators |
| ZIP | ZIP archive format |

Owner and release author: Sepehr Mahmoudian

Channel: review-gated GitHub research source release only.
There is no crates.io publication or project DOI.
There is no Zenodo record, deployment qualification, or production-support promise.

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

Only the release operator can merge, tag, publish, delete references, or change repository settings.
A delegated agent can prepare and verify a milestone.
The release operator must accept that milestone before promotion.

## Candidate freeze

Keep the threat register at `LIVING_UNTIL_CANDIDATE_FREEZE` during implementation.
Stage the final release inputs before you generate the active signed freeze pair.
Only the release operator can set the register to `FROZEN_AT_CANDIDATE`.

The signed audit-input manifest is the only pre-commit evidence exception.
It binds exact stage-zero index blobs and external inputs.
It does not bind a candidate commit or tree.
The next signed commit creates the exact candidate identity.

Install the active pair at these paths:

- `release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json`
- `release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json.sig`

A later tracked change reopens the freeze.
Generate a new signed pair.
Create a new signed candidate.
Restart every candidate-bound check.

## Immutable entry conditions

1. Inspect the fetch and push URLs for `origin` without logging them.
   Require exactly one fetch URL and one push URL.
   Require each URL to name the canonical credential-free Galadriel repository.
   Fetch `main` from that origin.
   Require `main` and `origin/main` to resolve to the same signed commit.
   Require the worktree to be clean.

   The qualifier and finalizer repeat this refresh automatically.
   They use the literal public URL and exact `main` refspec.
   They reject local Git settings that can redirect the fetch, run a helper, or weaken object checks.
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
   Mutation evidence contains exactly 13 artifacts.
   These artifacts are seven outcome files, five run receipts, and one retained `git.diff`.
   Each of the four broad outcome files has one broad shard receipt.
   The three focused outcome files share one focused receipt.
   All four broad shards and all three focused outcomes are exact-candidate gates.

   The observational mutation-baseline job remains residual evidence.
   It is not a successful release gate.

   The acceptance-estimation outcome has 23 caught mutants and three exact compile-unviable mutants.
   It has no missed, timed-out, or surviving mutant.
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

Run from a fresh temporary clone of the candidate.
Use Rust and Cargo 1.89.0 for this command block.
Use the exact pinned tools and external RustSec database from the CI workflow:

```bash
set -euo pipefail
export CARGO_TERM_COLOR=always
export RUSTFLAGS='-D warnings'
candidate="$(git rev-parse 'HEAD^{commit}')"
PYTHONPATH=repo_work python3 -c \
  'import sys; from pathlib import Path; from release_assurance import refresh_canonical_origin_main; refresh_canonical_origin_main(Path("."), sys.argv[1])' \
  "$candidate"
test "$(git branch --show-current)" = main
test "$(git status --porcelain=v1)" = ""
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
cargo fetch --locked
python3 scripts/secure_deployment.py check
python3 -m unittest -v \
  scripts.tests.test_release_audit \
  repo_work.tests.test_package_release_assets \
  repo_work.tests.test_review_tools \
  repo_work.tests.test_task_dispositions \
  repo_work.tests.test_release_assurance \
  repo_work.tests.test_finalize_qualification \
  repo_work.tests.test_qualification_artifacts \
  repo_work.tests.test_host_process_bounds
python3 repo_work/build_task_dispositions.py verify
python3 repo_work/local_convergence.py schema --repo .
python3 repo_work/freeze_audit_inputs.py verify \
  --repo . \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json \
  --allowed-signers release/0.9.0/audit/ALLOWED_SIGNERS
python3 scripts/release_audit.py verify
python3 repo_work/check_public_api.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python3 repo_work/check_feature_graph.py
cargo check -p galadriel-cli --no-default-features --locked
cargo check -p galadriel-cli --no-default-features --features pid --locked
cargo check -p galadriel-cli --no-default-features --features ncp --locked
cargo check -p galadriel-cli --no-default-features --features ncp-live --locked
cargo test --workspace --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
python3 repo_work/check_vulnerable_features.py
cargo fetch --locked --manifest-path fuzz/Cargo.toml
cargo deny --offline --all-features --locked check
cargo deny --offline --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```

The supply-chain commands require the clean detached RustSec clone from the CI materialization step.
The release input pins that database identity at the 2026-07-23 inspection cut.
A qualification result remains bound to that pinned input.

Then, activate Rust and Cargo 1.97.1.
Run the current-stable job commands:

```bash
set -euo pipefail
export CARGO_TERM_COLOR=always
export RUSTFLAGS='-D warnings'
cargo fetch --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Use `nightly-2026-06-16` and `cargo-public-api 0.52.0` for the public API gate.
The complete rehearsal covers all commands in the three CI jobs.
Do not describe a smaller subset as the complete CI mirror.

Generate the source archive in two runs from the exact qualification clone.
Require byte-identical results from those runs.
Generate package archives and software bills of materials in two separate standalone clones.
Require byte-identical results from each pair of clones.
Generate each license and vulnerability report one time.
Retain all provenance and checksums in an empty directory outside the checkout.

The archive prefix is exactly `galadriel-0.9.0/`.
Archive content must equal `git ls-files`.
The archive command disables Git replacement objects.
It pins `tar.umask=0022` and `core.attributesFile=/dev/null`.
The validator binds each entry type, mode, owner, time, and content to the Git tree.
Only documented GitHub archive metadata can differ.

## Assemble exact-candidate mutation evidence

Download the four successful `mutation-diff` artifact directories for the exact candidate.
Keep their order from shard `0/4` through shard `3/4`.
Use the agent-backed Ed25519 public-key handle from `user.signingkey`.
Require that handle to match the independent allowed-signers file.

```bash
set -euo pipefail
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"

python3 repo_work/prepare_mutation_evidence.py \
  --repo . \
  --candidate "$(git rev-parse HEAD)" \
  --out /new/path/galadriel-0.9.0-mutation-evidence \
  --signing-key "$signing_key" \
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --shard 0/4=/downloaded/mutation-diff-results-1-of-4 \
  --shard 1/4=/downloaded/mutation-diff-results-2-of-4 \
  --shard 2/4=/downloaded/mutation-diff-results-3-of-4 \
  --shard 3/4=/downloaded/mutation-diff-results-4-of-4
```

The assembler verifies the exact commit, tree, diff, workflow run, and shard order.
It verifies all four broad outcomes and all three focused outcomes.
It signs one new mutation manifest outside the repository.
It does not convert the observational mutation baseline into a gate.

## Qualify the candidate

The qualification command must include all required external inputs.
These inputs include the tracked evidence configuration and signed mutation pair.
They also include the independent trust root and pinned external advisory database.
Use an agent-backed Ed25519 public-key handle for `--signing-key`.
Require that handle to match the independently obtained allowed-signers file.

The qualifier fetches the locked workspace graph and the locked fuzz graph.
Both fetches complete before the offline metadata and dependency-policy gates.
It uses the exact 16-key base environment in `docs/DEPENDENCY-POLICY.md`.
It isolates `HOME`, `CARGO_HOME`, `CARGO_TARGET_DIR`, and `TMPDIR` in a private root.
It denies candidate reads from the original external RustSec clone.
It permits reads from only the installed detached database copies.

It removes ambient credentials, proxies, wrappers, loader variables, and compiler flags.
It rejects a file, directory, or link at each Cargo configuration path.
It checks before and after each retained command.

The signed qualification record binds this environment policy.

The evidence command must create exactly six flat regular files.
These files are `SHA256SUMS`, `config.json`, `manifest.json`, `report.md`, `summary.json`, and `trials.jsonl`.
Each file has a 1 GiB limit.
The complete set has a 4 GiB limit.
The host snapshot does not follow links or open blocking special files.
It compares source, snapshot, quarantine, and installed identities.

It parses only bounded JSON bytes captured from the verified snapshot.
Only a run that uses `--deep` can have qualification status `PASS`.

```bash
set -euo pipefail
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"
candidate="$(git rev-parse 'HEAD^{commit}')"
PYTHONPATH=repo_work python3 -c \
  'import sys; from pathlib import Path; from release_assurance import refresh_canonical_origin_main; refresh_canonical_origin_main(Path("."), sys.argv[1])' \
  "$candidate"

python3 repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --require-branch main \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$signing_key" \
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --advisory-db /independent/path/advisory-db \
  --mutation-evidence /path/to/exact-candidate-mutation.json \
  --mutation-evidence-signature /path/to/exact-candidate-mutation.json.sig \
  --evidence-config evidence/galadriel-0.9-candidate.json \
  --deep --keep-going
```

A passing schema v3 tier must retain exactly 22 auxiliary command receipts.
It must retain exactly 15 two-run reproducibility comparisons.
The comparisons cover one source archive, seven package archives, and seven software bills of materials.

Each command uses a stop-before-exec gate and fixed resource limits.
macOS does not provide atomic recursive descendant tracking.
A short-lived reparented process can exit between scans.
The process scan detects a detached process that remains active.

The inherited sandbox and resource limits apply before candidate execution.
A sandboxed process can request work from an existing external service.
The process scan cannot attribute that external service work.

The license inventory covers the exact 382-package `CARGO_DENY_HOST_FILTERED_GRAPH` scope.
It does not cover all 437 packages for every target.

Create the signed T114 review and detached-signed canonical version 3 decision.
Create the signed ordered task dispositions.
Then finalize into a previously absent path:

```bash
set -euo pipefail
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"
candidate="$(git rev-parse 'HEAD^{commit}')"
PYTHONPATH=repo_work python3 -c \
  'import sys; from pathlib import Path; from release_assurance import refresh_canonical_origin_main; refresh_canonical_origin_main(Path("."), sys.argv[1])' \
  "$candidate"

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
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --snapshot-dir /external/operator-only/path/with-at-least-8-GiB-free \
  --out /new/path/galadriel-0.9.0-closure
```

The finalizer takes one snapshot of the signed qualification tier before semantic use.
The selected file system must hold the bounded 8 GiB tier and review inputs.
Use an agent-backed Ed25519 public-key handle for `--signing-key`.
Keep that handle outside the repository, qualification tier, output, and snapshot root.
Require that handle to match the independently obtained allowed-signers file.

The finalizer rejects a private-key path.
It validates the external public handle before snapshot creation.
It stores only the canonical public fields in the temporary snapshot.
A finalizer snapshot never contains private signing material.
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

   Use the same guarded public refresh that qualification and finalization use:

   ```bash
   set -euo pipefail
   candidate="$(git rev-parse 'HEAD^{commit}')"
   PYTHONPATH=repo_work python3 -c \
     'import sys; from pathlib import Path; from release_assurance import refresh_canonical_origin_main; refresh_canonical_origin_main(Path("."), sys.argv[1])' \
     "$candidate"
   test "$(git rev-parse 'HEAD^{commit}')" = "$candidate"
   test "$(git rev-parse 'origin/main^{commit}')" = "$candidate"
   test -z "$(git status --porcelain=v1 --untracked-files=all)"
   ```
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

   # user.signingkey must name an agent-backed Ed25519 public-key handle.
   python3 repo_work/package_release_assets.py build \
     --qualification-root /exact/path/galadriel-0.9.0-qualification \
     --closure-root /exact/path/galadriel-0.9.0-closure \
     --out /new/path/galadriel-0.9.0-github-assets \
     --signing-key "$signing_key" \
     --allowed-signers /independent/path/ALLOWED_SIGNERS \
     --candidate-commit "$candidate" \
     --candidate-tree "$tree" \
     --tag-name "$tag" \
     --tag-object "$tag_object" \
     --tag-target "$tag_target"
   ```

   Exit status 3 means that the no-replace rename committed a complete output.
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
   Use the audit-pinned `CPython 3.14.6` for asset construction, verification, and reconstruction.
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

   Reconstruction already authenticates both tier manifests with the independent trust root.
   It also verifies both exact candidate identities, complete inventories, and `SHA256SUMS` files.
   Independently repeat these checks with the commands below.
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
   Stop if the UTC date is later than `2026-07-24`.
   Update every declared release date.
   Create and qualify a new candidate.

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
   Confirm that `WITHDRAWN-RELEASES.md` preserves the legacy identities.
   The recorded cleanup set has one obsolete tag and two obsolete release-work branches.
   The recorded cleanup set has zero GitHub releases.

   Preserve the complete reachable Git history for all three obsolete references.
   The bundle preserves each tracked evidence file that is reachable from these references.
   Use a new private directory outside the checkout.
   Verify every remote identity before bundle creation.

   ```bash
   set -euo pipefail
   legacy_dir=/new/external/path/galadriel-0.9.0-obsolete-reference-preservation
   legacy_bundle="$legacy_dir/galadriel-obsolete-references.bundle"
   legacy_verify="$legacy_dir/verification.git"
   legacy_tag=research-snapshot-v0.1.0
   legacy_tag_object=ca1b2c69a0a6e04223fbbc07820b8226d918e275
   legacy_tag_target=1205ce56a461036769ad29d4af93ceafd83da1db
   phase_branch=release/0.9-phase-2
   phase_tip=bcb1c0734aa3581b86b08d5960f96c13e1e81066
   work_branch=wip/release-0.9.0-20260715
   work_tip=f541f3eda7cfdc81a3277c3d6fecc91245179f24

   test ! -e "$legacy_dir"
   mkdir -m 700 "$legacy_dir"

   test "$(git ls-remote --exit-code origin "refs/tags/$legacy_tag" | cut -f1)" = \
     "$legacy_tag_object"
   test "$(git ls-remote --exit-code origin "refs/tags/$legacy_tag^{}" | cut -f1)" = \
     "$legacy_tag_target"
   test "$(git ls-remote --exit-code --heads origin "refs/heads/$phase_branch" | cut -f1)" = \
     "$phase_tip"
   test "$(git ls-remote --exit-code --heads origin "refs/heads/$work_branch" | cut -f1)" = \
     "$work_tip"

   git fetch --no-tags origin \
     "refs/tags/$legacy_tag:refs/tags/$legacy_tag" \
     "refs/heads/$phase_branch:refs/remotes/origin/$phase_branch" \
     "refs/heads/$work_branch:refs/remotes/origin/$work_branch"

   test "$(git rev-parse "refs/tags/$legacy_tag^{tag}")" = "$legacy_tag_object"
   test "$(git rev-parse "refs/tags/$legacy_tag^{}")" = "$legacy_tag_target"
   test "$(git rev-parse "refs/remotes/origin/$phase_branch")" = "$phase_tip"
   test "$(git rev-parse "refs/remotes/origin/$work_branch")" = "$work_tip"

   git bundle create "$legacy_bundle" \
     "refs/tags/$legacy_tag" \
     "refs/remotes/origin/$phase_branch" \
     "refs/remotes/origin/$work_branch"
   chmod 600 "$legacy_bundle"
   git bundle verify "$legacy_bundle"

   test "$(git bundle list-heads "$legacy_bundle" "refs/tags/$legacy_tag")" = \
     "$legacy_tag_object refs/tags/$legacy_tag"
   test "$(git bundle list-heads "$legacy_bundle" "refs/remotes/origin/$phase_branch")" = \
     "$phase_tip refs/remotes/origin/$phase_branch"
   test "$(git bundle list-heads "$legacy_bundle" "refs/remotes/origin/$work_branch")" = \
     "$work_tip refs/remotes/origin/$work_branch"

   git clone --mirror "$legacy_bundle" "$legacy_verify"
   test "$(git -C "$legacy_verify" rev-parse "refs/tags/$legacy_tag^{tag}")" = \
     "$legacy_tag_object"
   test "$(git -C "$legacy_verify" rev-parse "refs/tags/$legacy_tag^{}")" = \
     "$legacy_tag_target"
   test "$(git -C "$legacy_verify" rev-parse "refs/remotes/origin/$phase_branch")" = \
     "$phase_tip"
   test "$(git -C "$legacy_verify" rev-parse "refs/remotes/origin/$work_branch")" = \
     "$work_tip"
   git -C "$legacy_verify" fsck --strict

   (
     cd "$legacy_dir"
     shasum -a 256 galadriel-obsolete-references.bundle \
       > galadriel-obsolete-references.bundle.sha256
     chmod 600 galadriel-obsolete-references.bundle.sha256
     shasum -a 256 -c galadriel-obsolete-references.bundle.sha256
   )
   ```

   Retain the verified bundle, checksum, and mirror outside the checkout.
   Stop if any identity, bundle, checksum, or object check fails.
   Delete only those three obsolete Git references.
   Delete the local and remote references.

   Do not delete the external preservation directory.
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
