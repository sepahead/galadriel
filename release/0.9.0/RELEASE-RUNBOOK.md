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
| URL | Uniform Resource Locator |
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

## Date-bound candidate entry

The source preparation state is `UNPUBLISHED_CANDIDATE` with no candidate release date.
The source declares one unpublished candidate with no release date.
This state is suitable for implementation and review only.
It cannot enter candidate freeze or qualification.

Before candidate freeze, the release operator **SHALL** select one Coordinated
Universal Time (UTC) candidate release date. The operator **SHALL** update
`release/0.9.0/audit-inputs.json` to `DATE_BOUND_CANDIDATE` with that date.
The operator **SHALL** update every declared date and every mode-dependent source
preparation marker in the same change. The release audit **SHALL** pass in the
date-bound mode before freeze starts.

The operator **SHALL** then enter candidate freeze. The freeze transaction
generates and stages the active signed pair before the next signed commit creates
the exact candidate identity. Qualification follows that commit. Local tag
creation, asset construction, remote push, upload, and publication **SHALL** use
only that frozen and qualified date-bound candidate.

If the selected date changes before local tag creation, update the source
metadata and restart at this section. Repeat candidate freeze and every
candidate-bound qualification and review gate. Once a local `v0.9.0` tag exists,
never move, recreate, or reuse it, even if it was not pushed. Record its
disposition and use the applicable new-version or withdrawal procedure.

## Candidate freeze

Keep the threat register at `LIVING_UNTIL_CANDIDATE_FREEZE` during implementation.
Stage the final release inputs before you generate the active signed freeze pair.
Only the release operator can set the register to `FROZEN_AT_CANDIDATE`.

The signed audit-input manifest is the only pre-commit evidence exception.
It uses schema `galadriel.frozen-audit-inputs.v2`.
It binds each release-input path, Git mode, blob identifier, SHA-256 value, and size.
One bounded index capture supplies the source semantics and complete release-tool coverage.
The external handoff inventory binds each regular-file mode.
It does not bind a candidate commit or tree.
The next signed commit creates the exact candidate identity.

Install the active pair at these paths:

- `release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json`
- `release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json.sig`

Use one bounded transaction to install the pair and generate the audit manifest.
Use an independently obtained `ALLOWED_SIGNERS` file for each strict verification.
Use the tracked signer file only as a consistency check.
The frozen release-input set includes the requirements ledger.
It excludes the active pair and the audit manifest.
The audit manifest inventories the staged pair and excludes only itself.
It uses schema `galadriel.release-audit-manifest.v2`.
Each artifact row binds its path, Git mode, blob identifier, SHA-256 value, size, and purpose.
Its semantic checks use bytes from one bounded stage-zero index capture.
One held-root transaction compares the worktree with those captured identities.
The signed candidate commit binds the complete tracked result.
Generate and stage the requirements ledger before you generate the pair.
Record its staged blob identifier.
Stage the installed pair before you generate the audit manifest again.
The second generation MUST NOT change the requirements-ledger blob.
Stage the audit manifest after this check.
Reject each untracked, nonignored path.
Then, run strict freeze verification and release-audit verification.

A release-input change during this transaction MUST abort the transaction.
Generate a new signed pair after such a change.
After the final generated inventory is staged, a tracked change reopens the freeze.
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

   The release audit binds each frozen focused mutant to its tracked source span.
   Pinned cargo-mutants enumerates each selected set before the focused run.
   The enumerated identities MUST equal the frozen source spans and transformations.

   The acceptance-estimation outcome has 23 caught mutants and three exact compile-unviable mutants.
   It has no missed, timed-out, or surviving mutant.
   All supply-chain and frozen-input semantic gates also pass.
   The release-audit, source-inventory, and author-operated isolated qualification gates also pass.
5. Release notes and `CITATION.cff` identify version 0.9.0 and agree on scope.
   Cargo metadata, schemas, and the application programming interface (API) snapshot also agree.
   The changelog, support policy, and GitHub metadata also agree.
6. The signed finalization manifest records exact artifacts and checksums.
   It records review dispositions, negative results, and residual risks.
   It records `NARROWED_GO` for this source release.
   It preserves every failed acceptance criterion and its exact disposition.
   A `NO_GO` decision stops publication.
   A `GO` decision is prohibited while an acceptance criterion fails.
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

Before any local `v0.9.0` tag exists, an entry-condition change **SHALL** abort
the flow. Update the source as needed, reopen candidate freeze, create a new
signed `main` candidate, and repeat every qualification, review, and artifact
gate.

After any local `v0.9.0` tag exists, even if unpushed, do not repair the
candidate or continue the same version.
Never move, recreate, or reuse that tag.
Record its disposition, stop, and follow the applicable new-version or withdrawal
procedure.

## Rehearsal without publication

Run from a fresh temporary clone of the candidate.
Use Rust and Cargo 1.89.0 for this command block.
Use the CI-pinned tools, the release-input pkgconf executable, and the external RustSec database:

```bash
set -euo pipefail
export CARGO_TERM_COLOR=always
export RUSTFLAGS='-D warnings'
pinned_pkgconf_root=/opt/homebrew/Cellar/pkgconf/3.0.3
pkg_config_executable="$pinned_pkgconf_root/bin/pkgconf"
release_python=repo_work/verify_release_python_runtime.sh
while IFS='|' read -r path expected_mode expected_size expected_sha256; do
  test -f "$path"
  test ! -L "$path"
  test "$(/usr/bin/stat -f '%Lp|%z|%l' "$path")" = \
    "$expected_mode|$expected_size|1"
  observed_sha256="$(/usr/bin/env -i OPENSSL_CONF=/dev/null /usr/bin/openssl dgst -sha256 -r "$path")"
  test "${observed_sha256%% *}" = "$expected_sha256"
done <<'PINNED_NATIVE_INPUTS'
/opt/homebrew/Cellar/pkgconf/3.0.3/bin/pkgconf|555|74928|d1c437b9ad16182ee781175ae4e69b439a91c6c6747a7cd50f878514212730e4
PINNED_NATIVE_INPUTS
test "$(/usr/bin/readlink "$pinned_pkgconf_root/bin/pkg-config")" = pkgconf
"$release_python" -B -E -s -S -c \
  'import sys; sys.path.insert(0, "repo_work"); from pathlib import Path; from qualify_candidate import validate_pinned_pkg_config_executable; validate_pinned_pkg_config_executable(Path(sys.argv[1]))' \
  "$pkg_config_executable"
"$release_python" -B -E -s -S -c \
  'import sys; sys.path.insert(0, "repo_work"); from pathlib import Path; from qualify_candidate import pinned_cpython_runtime_executable_files, pinned_cpython_runtime_library_files, pinned_cpython_runtime_tree_identity, validate_pinned_cpython_launcher; validate_pinned_cpython_launcher(Path(sys.executable)); pinned_cpython_runtime_executable_files(); pinned_cpython_runtime_library_files(); pinned_cpython_runtime_tree_identity()'
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
"$release_python" -B -E -s -S -c \
  'import sys; sys.path.insert(0, "repo_work"); from qualify_candidate import pinned_rust_toolchain_runtime_identity; pinned_rust_toolchain_runtime_identity({"RUSTUP_HOME": sys.argv[1]})' \
  "$rustup_home"
candidate="$(git rev-parse 'HEAD^{commit}')"
"$release_python" -B -E -s -S -c \
  'import sys; sys.path.insert(0, "repo_work"); from pathlib import Path; from release_assurance import refresh_canonical_origin_main; refresh_canonical_origin_main(Path("."), sys.argv[1])' \
  "$candidate"
test "$(git branch --show-current)" = main
test "$(git status --porcelain=v1)" = ""
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
cargo fetch --locked
"$release_python" -B -E -s -S scripts/secure_deployment.py check
"$release_python" -B -E -s -S -m unittest -v \
  scripts.tests.test_release_audit \
  repo_work.tests.test_release_audit_snapshot \
  repo_work.tests.test_evidence_batch_transaction \
  repo_work.tests.test_file_mode_identity \
  repo_work.tests.test_package_release_assets \
  repo_work.tests.test_review_tools \
  repo_work.tests.test_task_dispositions \
  repo_work.tests.test_release_assurance \
  repo_work.tests.test_candidate_evidence_bundle \
  repo_work.tests.test_qualify_candidate_evidence \
  repo_work.tests.test_finalize_qualification \
  repo_work.tests.test_qualification_artifacts \
  repo_work.tests.test_host_process_bounds
test -z "$(find scripts repo_work -type d -name __pycache__ -print -quit)"
test -z "$(find scripts repo_work -type f -name '*.pyc' -print -quit)"
"$release_python" -B -E -s -S repo_work/build_task_dispositions.py verify
"$release_python" -B -E -s -S repo_work/local_convergence.py schema --repo .
"$release_python" -B -E -s -S repo_work/freeze_audit_inputs.py verify-lifecycle \
  --repo . \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json \
  --allowed-signers release/0.9.0/audit/ALLOWED_SIGNERS
"$release_python" -B -E -s -S repo_work/freeze_audit_inputs.py verify \
  --repo . \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json \
  --allowed-signers /independent/path/ALLOWED_SIGNERS
"$release_python" -B -E -s -S scripts/release_audit.py verify
"$release_python" -B -E -s -S repo_work/check_public_api.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
"$release_python" -B -E -s -S repo_work/check_feature_graph.py
cargo check -p galadriel-cli --no-default-features --locked
cargo check -p galadriel-cli --no-default-features --features pid --locked
cargo check -p galadriel-cli --no-default-features --features ncp --locked
cargo check -p galadriel-cli --no-default-features --features ncp-live --locked
cargo test -p galadriel-cli --no-default-features --locked
cargo test -p galadriel-cli --no-default-features --features pid --locked
cargo test -p galadriel-cli --no-default-features --features ncp --locked
cargo test -p galadriel-cli --no-default-features --features ncp-live --locked
cargo test --workspace --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
"$release_python" -B -E -s -S repo_work/check_vulnerable_features.py
cargo fetch --locked --manifest-path fuzz/Cargo.toml
cargo deny --offline --all-features --locked check
inventory_root="$(mktemp -d)"
trap 'rm -rf "$inventory_root"' EXIT
cargo metadata \
  --locked \
  --offline \
  --all-features \
  --format-version=1 \
  > "$inventory_root/cargo-metadata.json" \
  2> "$inventory_root/cargo-metadata.stderr"
test ! -s "$inventory_root/cargo-metadata.stderr"
cargo deny \
  --offline \
  --all-features \
  --locked \
  list \
  --metadata-path "$inventory_root/cargo-metadata.json" \
  --format json \
  --layout crate \
  > "$inventory_root/license-inventory.json" \
  2> "$inventory_root/license-inventory.stderr"
test ! -s "$inventory_root/license-inventory.stderr"
"$release_python" -B -E -s -S repo_work/qualification_artifacts.py \
  --metadata "$inventory_root/cargo-metadata.json" \
  --lockfile Cargo.lock \
  --license-inventory "$inventory_root/license-inventory.json"
cargo deny --offline --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```

The native launcher uses privileged Bash startup and root-owned macOS tools.
It removes each `DYLD_`, `LD_`, and `PYTHON` selector before Python startup.
It binds the launcher, framework executables, declared dynamic libraries, Homebrew links, and complete CPython version tree.
It then replaces itself with the pinned interpreter under fixed `-B -E -s -S` flags.
The `-B` flag prevents Python from writing `.pyc` files when it imports source modules.
It removes its private verification state before it replaces itself.
It restores the caller's umask before Python starts.
The Python process independently measures the same runtime and records it.
The separate native file check binds the execution-denied pkgconf file.
These checks record declared host inputs.
They do not authenticate a hostile host or the macOS runtime.
Each later `release_python` invocation repeats the complete native check.

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

Each exact mutation command uses environment schema `galadriel.mutation-environment.v2`.
The command requires the Linux process file system (`procfs`), process file descriptors, and serialized child-subreaper ownership.
It starts behind a stop-before-exec gate.
It reaps the root only after the tracked candidate tree becomes extinct.
It fails before process creation when a required host control is unavailable.
It verifies the default disposition of the child-status signal (`SIGCHLD`) at each containment checkpoint.
It also verifies the active child-subreaper state.
A control change poisons the process and prevents verified success.
The runner cleans a stable process file descriptor (`pidfd`) identity when it can prove extinction.
It cannot signal an identity that escaped before stable capture during a subreaper control gap.
A control change that starts and ends between checkpoints is not observable.
The contract therefore requires exclusive single-threaded ownership by the trusted runner.
An uninterruptible process can outlive the stop deadline and fails the run.
This cleanup control is not a control group, container, or deployment-isolation boundary.

```bash
set -euo pipefail
release_python=repo_work/verify_release_python_runtime.sh
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"

"$release_python" -B -E -s -S repo_work/prepare_mutation_evidence.py \
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
The qualifier tests all four feature-isolated CLI profiles.
It executes assertions for absent optional features.
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

The summary uses schema `galadriel.evidence.summary.v3`.
The manifest uses schema `galadriel.evidence.manifest.v3`.
Acceptance uses profile `galadriel-0.9-frozen-acceptance-metrics-v3`.
Bootstrap uses profile `splitmix64-rejection-group-metric-v1`.
The bootstrap profile uses SplitMix64 with unbiased rejection sampling over complete tracks.

The qualifier runs a separate `candidate-evidence-build` command.
It builds `galadriel-evidence` with the release profile and the locked graph.
The host creates a private directory with mode `0700`.
It copies the executable into that directory with mode `0500`.
The copy uses no-follow descriptors and binds the complete executable identity.

The qualifier then runs the exact snapshot directly.
The manifest runner digest must match that snapshot.

The host parses only bounded bytes captured from the verified snapshot.
It streams all trial records in exact order.
It derives the accepted configuration from the frozen tracked input.

It independently rebuilds the complete summary and report.
It verifies the manifest and exact checksum document.
It binds all identities to the exact candidate commit and tree.
It evaluates acceptance only from the rebuilt holdout summary.
Finalization repeats this semantic replay against the signed outer inventory.
Only a run that uses `--deep` can have qualification status `PASS`.
The deep run tests the fuzz harness and its semantic seed canaries.
It checks every fuzz target before execution.
It runs 5,000 cases for the NCP decoder, detector boundary, and lifecycle state targets.
Each target reads tracked semantic seeds.
Each target uses one fixed pseudorandom seed.
Each target writes mutations only to the private qualification root.
One direct Cargo command builds all fuzz binaries with `--locked` and `--offline`.
The command uses the pinned nightly compiler and frozen sanitizer flags.
The host validates and copies each binary to a private mode-`0500` path.
The verifier requires `LC_LOAD_DYLIB` for each library and one `/usr/lib/dyld` linker command.
It rejects lazy, weak, re-exported, and upward library loads.
Each campaign executes its exact snapshot directly.
The record binds both lockfiles and the pinned AddressSanitizer runtime.

```bash
set -euo pipefail
release_python=repo_work/verify_release_python_runtime.sh
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"
candidate="$(git rev-parse 'HEAD^{commit}')"
"$release_python" -B -E -s -S -c \
  'import sys; sys.path.insert(0, "repo_work"); from pathlib import Path; from release_assurance import refresh_canonical_origin_main; refresh_canonical_origin_main(Path("."), sys.argv[1])' \
  "$candidate"

"$release_python" -B -E -s -S repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --require-branch main \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$signing_key" \
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --advisory-db /independent/path/advisory-db \
  --pkg-config /opt/homebrew/Cellar/pkgconf/3.0.3/bin/pkgconf \
  --mutation-evidence /path/to/exact-candidate-mutation.json \
  --mutation-evidence-signature /path/to/exact-candidate-mutation.json.sig \
  --evidence-config evidence/galadriel-0.9-candidate.json \
  --deep --keep-going
```

A passing schema v3 tier must retain exactly 22 auxiliary command receipts.
It must retain exactly 15 two-run reproducibility comparisons.
The comparisons cover one source archive, seven package archives, and seven software bills of materials.

Each command uses a stop-before-exec gate and fixed resource limits.
The host requires macOS `kqueue` and `/usr/bin/sandbox-exec`.
It fails before candidate execution if either control is absent.
The qualifier installs one mode-0500 dispatch for 19 required command names.
It verifies every dispatch target before and after each bounded process.
The dispatch binds direct Apple developer Git and its developer tools.
The `cc` and `clang` entries resolve to one private mode-`0500` driver.
The driver executes the pinned Clang and applies the fixed SDK after caller arguments.
The qualifier binds the SDK root link and `SDKSettings.json` around each process.
It does not attest every SDK file or the complete Apple compiler supply chain.
It binds three executable files in the `CPython 3.14.6` runtime inventory.
It binds the complete CPython version tree before and after qualification.
It verifies all three executable files and six non-system libraries around each process.
Retained Python commands use `-B -E -s -S`.
The outward Homebrew `site-packages` link remains unreadable and outside `sys.path`.
It binds the exact Rustup settings file before and after qualification.
It binds `bin`, `lib`, and `libexec` for all three selected Rust toolchains.
The sandbox grants those roots instead of the complete Rustup home.
It excludes the unused Rust `etc` and `share` roots from candidate reads.

These inventories detect a change that persists to a checkpoint.
They do not make the user-owned Homebrew or Rustup trees immutable.
A concurrent process under the same operating-system user can replace a path between checkpoints.
The sandbox prevents candidate writes but does not control that external process.
Use a separately protected, read-only toolchain for stronger execution-byte assurance.

The operator supplies the exact `pkgconf 3.0.3` executable through `--pkg-config`.
The argument must use the fixed absolute release-input path.
The path cannot be in the checkout or be a symbolic link.
The qualifier verifies the 74,928-byte executable and its SHA-256 identity.
It verifies mode `0555` and repeats the file check after each bounded process.
The sandbox denies each same-name tool shim in the four system `PATH` roots.
It permits the exact selected target after these same-name denials.
It does not deny every differently named executable in an allowed operating-system or runtime root.
Those executables and external-service behavior remain trusted host inputs.
The candidate file, write, network, and signal restrictions still apply.
It does not grant read bindings for execution-denied CMake or pkgconf.
It does not grant the complete Homebrew or Anaconda prefix.
It permits the pinned launcher and application trampoline under Homebrew.
It denies the framework file as a direct process target.
It keeps CMake and pkgconf in the 19-name dispatch but denies their execution.
Neither exact locked graph declares their Cargo helper package.
Qualification fails closed if a future dependency needs either tool.
Critical host Git and SSH operations pin direct Apple developer Git, `/usr/bin/ssh-add`, and `/usr/bin/ssh-keygen`.
The host verifies each root-owned no-follow identity before and after execution.
It pins `sandbox-exec` to `/usr/bin/sandbox-exec` and its expected byte identity.
It records the resolved path, owner, group, and mode.
It removes dynamic-loader and toolchain selectors from host command environments.
The record binds declared non-system runtime inputs only.
It does not prove universal runtime closure.
It does not bind transitive operations performed by candidate-built code.

The candidate sandbox denies signal operations by default.
It permits signals only to self and children.

The qualifier signals only the original process group before it reaps the root.
It does not send a signal to an escaped numeric process identifier.
An observed escaped sandbox identity fails the run.
After root reap, it uses only read-only extinction checks.
macOS does not provide atomic recursive descendant tracking.
A short-lived reparented process can exit between scans.
The sandbox-identity scan detects an active detached process that retains that identity.

The inherited sandbox and resource limits apply before candidate execution.
A sandboxed process can request work from an existing external service.
The process scan cannot attribute that external service work.

The license inventory covers the exact 382-package `CARGO_DENY_HOST_FILTERED_GRAPH` scope.
It does not cover all 437 packages for every target.

The frozen evidence design uses 100 holdout tracks for each condition.
`GLD-090-ACC-001` has a zero-event upper Garwood bound of `0.3689904` episodes per hour.
Its limit is `0.10` episodes per hour.
It needs at least 369 tracks.

`GLD-090-ACC-006` has a minimum Hoeffding radius of `0.1358102`.
Its limit is `0.05`.
It needs at least 738 tracks.

The current condition grid and 25,000,000-observation ceiling permit at most 248 holdout tracks.
Thus, the frozen suite cannot pass these two criteria.
Preserve both failures in `candidate-acceptance.json`.

Executable qualification and candidate acceptance are separate results.
Passing executable gates with failed acceptance gives `release_gate=NARROWED_REVIEW_REQUIRED`.
The qualifier does not make the publication decision.
The signed human decision must select `NARROWED_GO` or `NO_GO`.
For publication, it must select `NARROWED_GO`.
It must map each failed criterion to removed claim `CLM-007` and a residual risk.
It must retain every other failed criterion in the same way.
It cannot select `GO`.

Create the signed T114 review and detached-signed canonical version 3 decision.
Create the signed ordered task dispositions.
Then finalize into a previously absent path:

```bash
set -euo pipefail
release_python=repo_work/verify_release_python_runtime.sh
signing_key="$(git config --get user.signingkey)"
test -n "$signing_key"
candidate="$(git rev-parse 'HEAD^{commit}')"
"$release_python" -B -E -s -S -c \
  'import sys; sys.path.insert(0, "repo_work"); from pathlib import Path; from release_assurance import refresh_canonical_origin_main; refresh_canonical_origin_main(Path("."), sys.argv[1])' \
  "$candidate"

"$release_python" -B -E -s -S repo_work/finalize_release.py \
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

Atomic publication needs macOS `renameatx_np` or Linux `renameat2` support.
The finalizer uses held directory descriptors for the rename.
An unsupported platform fails closed before publication.
Status 3 means that the rename committed a complete output.

The tool did not confirm at least one of durability, cleanup, or result output.
A cleanup failure also reports `publication_status: COMMITTED_WITH_CLEANUP_WARNING` and the output path.
Retain that output.

Status 4 means that the rename completed without confirmed destination identity or tree completeness.
Do not describe the requested path as a complete output.
Preserve the parent directory.
Stop publication and investigate the path identities.

Resolve each reported snapshot path.
Run the independent verification below before you use or remove the output.

After finalization, independently verify the signed convergence record against
the retained closure artifacts and exact candidate:

```bash
release_python=repo_work/verify_release_python_runtime.sh
"$release_python" -B -E -s -S repo_work/local_convergence.py verify \
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
   release_python=repo_work/verify_release_python_runtime.sh
   candidate="$(git rev-parse 'HEAD^{commit}')"
   "$release_python" -B -E -s -S -c \
     'import sys; sys.path.insert(0, "repo_work"); from pathlib import Path; from release_assurance import refresh_canonical_origin_main; refresh_canonical_origin_main(Path("."), sys.argv[1])' \
     "$candidate"
   test "$(git rev-parse 'HEAD^{commit}')" = "$candidate"
   test "$(git rev-parse 'origin/main^{commit}')" = "$candidate"
   test -z "$(git status --porcelain=v1 --untracked-files=all)"
   ```
2. Require the current UTC date to equal the declared candidate release date
   before local tag creation.
   If it does not match, stop before tag creation.
   Return to date-bound candidate entry, update the source metadata, and qualify
   a new candidate through the complete freeze and review sequence.
   Create signed annotated tag `v0.9.0` at that exact qualified commit.
   Use a professional message that identifies the source-only research scope.
   Derive the complete candidate, tree, tag-object, and peeled tag-target identifiers.
   Require the tag target to equal the candidate.
   Verify the commit and tag with an independently obtained allowed-signers trust root.
   Once the local tag exists, never move, recreate, or reuse it, even if it is
   never pushed. Record the disposition and use a new version or the withdrawal
   procedure after any later failure.
   Do not change source after tag creation.
3. Build the upload set in a previously absent directory.
   Preserve the two completed evidence roots as separate deterministic tar roots.
   The signed map binds both tar byte identities.
   It also binds all candidate, tree, and tag identities.
   Verification enforces the exact map, signature, and tar file set:

   ```bash
   set -euo pipefail
   release_python=repo_work/verify_release_python_runtime.sh
   test "$("$release_python" -B -E -s -S -c 'import platform; print(platform.python_implementation(), platform.python_version())')" = "CPython 3.14.6"
   candidate="$(git rev-parse 'HEAD^{commit}')"
   tree="$(git rev-parse "$candidate^{tree}")"
   tag=v0.9.0
   tag_object="$(git rev-parse "$tag^{tag}")"
   tag_target="$(git rev-parse "$tag^{}")"
   test "$tag_target" = "$candidate"
   signing_key="$(git config --get user.signingkey)"
   test -n "$signing_key"

   # user.signingkey must name an agent-backed Ed25519 public-key handle.
   "$release_python" -B -E -s -S repo_work/package_release_assets.py build \
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

   Exit status 4 means that the rename completed without confirmed output integrity.
   Stop asset publication.
   Preserve the parent directory and investigate the path identities.

   The directory must contain exactly:

   - `galadriel-0.9.0-qualification.tar`
   - `galadriel-0.9.0-closure.tar`
   - `galadriel-0.9.0-release-asset-map.json`
   - `galadriel-0.9.0-release-asset-map.json.sig`

   Verify that exact set before upload.
   Use the independent trust root and not the candidate copy:

   ```bash
   set -euo pipefail
   release_python=repo_work/verify_release_python_runtime.sh
   test "$("$release_python" -B -E -s -S -c 'import platform; print(platform.python_implementation(), platform.python_version())')" = "CPython 3.14.6"
   candidate="$(git rev-parse 'HEAD^{commit}')"
   tree="$(git rev-parse "$candidate^{tree}")"
   tag=v0.9.0
   tag_object="$(git rev-parse "$tag^{tag}")"
   tag_target="$(git rev-parse "$tag^{}")"
   test "$tag_target" = "$candidate"

   "$release_python" -B -E -s -S repo_work/package_release_assets.py verify \
     --assets /new/path/galadriel-0.9.0-github-assets \
     --allowed-signers /independent/path/ALLOWED_SIGNERS \
     --expected-candidate "$candidate" \
     --expected-tree "$tree" \
     --expected-tag-name "$tag" \
     --expected-tag-object "$tag_object" \
     --expected-tag-target "$tag_target"
   ```

4. Before the first remote tag mutation, inspect local push hooks, repository
   rulesets, installed GitHub Apps, external hooks, installed automation, and
   existing tags and releases.
   Require the canonical repository to have no `v0.9.0` tag or release.
   Require that no tag-triggered, branch-push-triggered, draft- or release-triggered,
   or asset-triggered integration can publish or promote a release, replace an
   asset, mutate source, create a DOI or Zenodo record, or publish a package.
   Record the inspected identities and result. Stop on missing access or an
   ambiguous or mutating integration.
5. Push only the exact `main` and `v0.9.0` identities.
   Verify the remote commit, annotated tag object, peeled target, and both signatures again.
   Repeat the hooks, Apps, installed-automation, tag, and release inspection
   immediately after the push. Require exactly the intended tag and no release.
   No process may create a DOI, Zenodo record, package publication, replacement asset, or second release.
6. Resolve and byte-compare all six tag-bound release-body links and all three
   public JSON Schema identifiers after the canonical remote tag push and before
   draft creation or release publication.
   A local tag is insufficient. Each public resource **SHALL** resolve only from
   the immutable tag in the canonical repository.

   GitHub `blob` links return Hypertext Markup Language (HTML).
   Resolve each exact body link, then compare its raw tag URL with the tagged Git
   blob. For each schema, require its `$id` to equal the exact raw tag URL and
   compare those bytes with the tagged Git blob. Also compare each tagged blob
   with the unchanged local source.

   ```bash
   set -euo pipefail
   release_python=repo_work/verify_release_python_runtime.sh
   tag=v0.9.0
   verification_dir="$(mktemp -d)"
   trap 'rm -rf "$verification_dir"' EXIT

   body_paths=(
     "release/0.9.0/ecosystem-cut.json"
     "release/0.9.0/claims.json"
     "docs/ADVISORY-BOUNDARY.md"
     "docs/ECOSYSTEM-CONNECTIONS.md"
     "release/0.9.0/RELEASE-RUNBOOK.md"
     "CITATION.cff"
   )
   body_links=(
     "https://github.com/sepahead/galadriel/blob/v0.9.0/release/0.9.0/ecosystem-cut.json"
     "https://github.com/sepahead/galadriel/blob/v0.9.0/release/0.9.0/claims.json"
     "https://github.com/sepahead/galadriel/blob/v0.9.0/docs/ADVISORY-BOUNDARY.md"
     "https://github.com/sepahead/galadriel/blob/v0.9.0/docs/ECOSYSTEM-CONNECTIONS.md"
     "https://github.com/sepahead/galadriel/blob/v0.9.0/release/0.9.0/RELEASE-RUNBOOK.md"
     "https://github.com/sepahead/galadriel/blob/v0.9.0/CITATION.cff"
   )
   test "${#body_paths[@]}" -eq 6
   test "${#body_links[@]}" -eq "${#body_paths[@]}"

   for index in "${!body_paths[@]}"; do
     path="${body_paths[$index]}"
     link="${body_links[$index]}"
     test "$link" = "https://github.com/sepahead/galadriel/blob/$tag/$path"
     curl --fail --silent --show-error --location \
       --output /dev/null "$link"
     git show "$tag:$path" > "$verification_dir/expected"
     cmp -s "$path" "$verification_dir/expected"
     curl --fail --silent --show-error --location \
       --output "$verification_dir/downloaded" \
       "https://raw.githubusercontent.com/sepahead/galadriel/$tag/$path"
     cmp -s "$verification_dir/expected" "$verification_dir/downloaded"
   done

   schema_paths=(
     "release/0.9.0/local-convergence-schema.json"
     "crates/galadriel-ncp/schemas/galadriel-pid-envelope-v1.schema.json"
     "crates/galadriel-ncp/schemas/galadriel-monitor-envelope-v1.schema.json"
   )
   test "${#schema_paths[@]}" -eq 3

   for path in "${schema_paths[@]}"; do
     schema_id="$("$release_python" -B -E -s -S -c \
       'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["$id"])' \
       "$path")"
     test "$schema_id" = \
       "https://raw.githubusercontent.com/sepahead/galadriel/$tag/$path"
     git show "$tag:$path" > "$verification_dir/expected"
     cmp -s "$path" "$verification_dir/expected"
     curl --fail --silent --show-error --location \
       --output "$verification_dir/downloaded" "$schema_id"
     cmp -s "$verification_dir/expected" "$verification_dir/downloaded"
   done

   rm -rf "$verification_dir"
   trap - EXIT
   ```

   These are tagged source checks, not release-asset checks. Keep anonymous
   release-asset download checks after publication.
7. Before draft creation, query the authenticated GitHub viewer with `GET /user`.
   Require viewer `login` to equal `sepahead` and viewer `id` to equal
   the integer `10104569`.
   Create the **draft** GitHub release from `v0.9.0` only after this check passes.
   Use the literal title `Galadriel 0.9.0`.
   Use the exact tracked `RELEASE-NOTES.md` body.
   Require the draft API `id` to be a positive integer and its `node_id` to be
   non-empty text. Record both values immediately after creation.

   Upload the four named files without replacement.
   For each of the exact four API assets, require and record this identity tuple:

   - positive integer `id`
   - non-empty `node_id`
   - exact `name` and local byte `size`
   - `state=uploaded`
   - `uploader.login=sepahead` and integer `uploader.id=10104569`
   - API digest when the API supplies one

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
8. Download all four draft assets through the authenticated GitHub path.
   Use a new empty directory.
   Require each downloaded file to equal its local upload source byte-for-byte.
   Run `verify` and reconstruct both path-preserving tiers atomically.
   Use the audit-pinned `CPython 3.14.6` for asset construction, verification, and reconstruction.
   A different interpreter is outside the qualified deterministic representation:

   ```bash
   set -euo pipefail
   release_python=repo_work/verify_release_python_runtime.sh
   test "$("$release_python" -B -E -s -S -c 'import platform; print(platform.python_implementation(), platform.python_version())')" = "CPython 3.14.6"
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

   "$release_python" -B -E -s -S repo_work/package_release_assets.py reconstruct \
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
   If reconstruction reports status 4, preserve its parent directory and stop.

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

   "$release_python" -B -E -s -S -c \
     'import sys; sys.path.insert(0, "repo_work"); from pathlib import Path; from finalize_release import verify_sha256sums; roots = sys.argv[1:]; len(roots) == 2 or sys.exit("expected exactly two tier roots"); tuple(verify_sha256sums(Path(root)) for root in roots)' \
     "$qualification_root" "$closure_root"
   ```

   The outer signed map proves the exact reconstructed inventory.
   The checksum verifier independently requires one `SHA256SUMS` row for each other file.
   Repeat the `local_convergence.py verify` command against the reconstructed closure.
   Extract the qualification `galadriel-0.9.0.tar.gz` file into a second fresh directory.
   Run the locked build, test, and documentation gates from that downloaded source.
9. Before publication, require every authenticated-download check above to pass.
   Immediately before manual publication, query the authenticated GitHub API again.
   Query `GET /repos/sepahead/galadriel/releases/{recorded_numeric_id}`.
   Require the API `id` and `node_id` to equal the recorded draft values.
   Require `author.login` to equal `sepahead` and `author.id` to equal
   the integer account ID `10104569`.
   Require `tag_name` to equal `v0.9.0`.
   Require `name` to equal `Galadriel 0.9.0`.
   JSON-decode the API `body` without normalization and require a string.
   Encode that string as UTF-8 without normalization.
   Require the result to equal the complete tracked
   `release/0.9.0/RELEASE-NOTES.md` file byte-for-byte, including its terminal LF.
   Require the API to still report the intended release as `draft=true`.
   Require `prerelease=false` and `published_at=null`.
   Require exactly the four intended asset names and sizes.
   Require every API asset identity tuple to equal its recorded post-upload tuple.
   Require each asset uploader to remain `sepahead` with numeric account ID
   `10104569`. No replacement is permitted.
   Re-download all four assets through the authenticated GitHub path into a new
   empty directory.
   Require each authenticated download to equal its local upload source byte-for-byte.
   Require no unexpected second release, package publication, DOI, or Zenodo side effect.
   Immediately before publication, require the current UTC date to equal the
   declared candidate release date.
   Require `HEAD`, remote `main`, and the peeled `v0.9.0` target to remain the same
   exact qualified commit.
   Require no source change after tag creation.
   If any condition fails after tag creation, do not move or reuse the tag.
   Stop publication, record the candidate disposition, and restart under the
   applicable new-version or withdrawal procedure.

   Require the manual publication action below to operate on the release object
   with the recorded numeric API `id`. Stop if this binding cannot be proved.

   Publish only the draft with the recorded API `id`, and only after all preceding gates pass.
10. Immediately after publication, query `GET /repos/sepahead/galadriel/releases/{recorded_numeric_id}`.
   Require the published `id` and `node_id` to equal the recorded draft values.
   Repeat the exact author, tag, name, decoded-body byte, asset-set, asset-identity,
   and asset-uploader comparisons from step 9.
   Require `draft=false` and `prerelease=false`.
   Require `published_at` to be a valid non-null UTC timestamp whose UTC date
   equals the declared candidate release date.
   After publication, require no unexpected second release, package publication,
   DOI, or Zenodo side effect.

   Only after these checks pass, verify anonymous downloads.
   Download the four public assets anonymously into another empty directory.
   Compare the four files with the local upload sources.

   Repeat exact-set verification and reconstruction.
   Repeat the internal signature and checksum checks.
   Repeat the fresh-source build.
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
11. Confirm that the version and date are exact.
   Require exactly four attached assets.

   Require no DOI, Zenodo, crates.io, deployment, or production claim.
   Retain the branch, signed tag, and release evidence.
   Retain download, signature, reconstruction, fresh-build, and cleanup evidence.

## Rollback and withdrawal

Do not move or reuse `v0.9.0`.
Only an incorrect release title or body is editable publication metadata in this
procedure. Correct that text and record the edit.
Do not change the release ID, author, tag, publication history, or assets.
If the release ID, author, tag, publication history, or any asset identity is
wrong, follow the full withdrawal procedure below.
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
