# Maintainer verification and release workflows

[AGENTS.md](../AGENTS.md) owns the current operating contract.
This guide retains its detailed qualification, freeze, verification, and publication procedures.
Run commands from the repository root.
The exact source toolchain and validation contracts control these procedures.

The living source ledger remains at 107 `OPEN` and nine `NOT_CLAIMED` requirements.
There is no active candidate freeze pair or release date.
A documentation check or independent adapter source gate cannot close those requirements.
These procedures are requirements, not a statement that the release operator executed them.

The independent local adapter also needs its own
[source gate](../crates/galadriel-local-adapter/README.md#independent-source-gate).
Root workspace commands exclude it.
Use `.github/workflows/ci.yml` and `.github/workflows/local-adapter.yml` for the complete applicable command set.
Keep the source, installed artifact, scientific, and publication decisions separate.

## Candidate freeze

Keep the threat register at `LIVING_UNTIL_CANDIDATE_FREEZE` during implementation.
Only the release operator can change it to `FROZEN_AT_CANDIDATE`.
Make that change only with the final staged release inputs.
Before the threat register enters `FROZEN_AT_CANDIDATE`, the source **SHALL** be
`DATE_BOUND_CANDIDATE` with one ISO `candidate_release_date`.
Every mode and date marker **SHALL** match that date-bound state.
`DATE_BOUND_CANDIDATE` with `LIVING_UNTIL_CANDIDATE_FREEZE` is the permitted
transition before freeze.

The signed audit-input manifest is the only permitted pre-commit evidence record.
It uses schema `galadriel.frozen-audit-inputs.v2`.
It binds each release-input path, Git mode, blob identifier, SHA-256 value, and size.
It derives source semantics and release-tool coverage from the same bounded index capture.
It binds each external handoff regular-file mode.
It does not bind a candidate commit or tree.
The next signed commit creates the candidate identity.

Install the active pair at these paths:

- `release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json`
- `release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json.sig`

Treat pair installation and audit-manifest generation as one bounded candidate-construction transaction.
Generate and stage the requirements ledger before you generate the pair.
Stage the installed pair before you generate the audit manifest.
The second generation MUST NOT change the frozen requirements ledger.
Stage the audit manifest.
Then, verify the signed pair and generated inventory before the candidate commit.

The generated audit manifest uses schema `galadriel.release-audit-manifest.v2`.
It binds each artifact path, Git mode, blob identifier, SHA-256 value, size, and purpose.
Its semantic checks use bytes from one bounded stage-zero index capture.
One held-root transaction proves that the worktree has the same regular-file identities.

A release-input change during this transaction MUST abort the transaction.
Create a new signed pair after such a change.
After the final generated inventory is staged, any tracked change reopens the freeze.
Create a new signed pair and a new signed candidate.
Then, restart every candidate-bound check.

Use `verify-lifecycle` during implementation.
It requires the active pair to be absent while the threat register is living.
It verifies the active signed pair after the threat register is frozen.
Use the strict `verify` action for the release-candidate procedure.


## Evidence and release work

Bind retained results to the exact commit and tree.
Record the command, tool, configuration, input, and exit status.
Create qualification output outside the checkout.
Create closure output outside the checkout.
Use a new output directory for each run.
Do not edit signed evidence.

Run candidate-controlled qualification commands with the exact 16-key base environment in the qualification contract.
Isolate `HOME`, `CARGO_HOME`, `CARGO_TARGET_DIR`, and `TMPDIR` in the private qualification root.
Reject a file, directory, or link at each Cargo configuration path before and after each retained command.
Do not pass ambient credentials, proxies, wrappers, loader variables, or compiler flags to candidate-controlled commands.

Do not omit a negative result.
Do not convert observational evidence into a successful gate.

Treat external model review as advisory design input.
External model review MUST NOT certify a claim or release.
It MUST NOT certify a security property or deployment.

Use an independently obtained allowed-signers file.
Do not let a candidate authenticate itself with its tracked trust file.
Keep private signing material outside the repository.

Use an agent-backed Ed25519 public-key handle for release-tool signing.
Keep that handle outside the repository, evidence tier, output, and snapshot root.
Require that handle to match the independent allowed-signers file.
Use the SSH namespace in the release runbook.

Require exactly one credential-free canonical fetch URL and push URL for `origin`.
Fetch canonical `main` before you compare `HEAD` with `origin/main`.

Follow `release/0.9.0/RELEASE-RUNBOOK.md` for release work.
Preserve an obsolete release identity before you remove its reference.
Remove obsolete references only after public release verification passes.
Never move or reuse `v0.9.0`.

The qualification record schema is `galadriel.candidate-qualification.v3`.
Supply `--allowed-signers` from an independent trust root.
Supply `--advisory-db` from the exact pinned external RustSec clone.
Do not expose the original RustSec clone to candidate commands.
Expose only the installed detached database copies.

The release input pins that RustSec identity at the 2026-07-23 inspection cut.
A qualification result remains bound to that pinned input.

The qualification tier must contain exactly 22 auxiliary command receipts.
It must contain 15 two-run reproducibility comparisons.
These comparisons cover one source archive, seven package archives, and seven software bills of materials.

Candidate evidence must contain the exact six-file flat set in the release contract.
Apply the 1 GiB per-file limit and 4 GiB aggregate limit.
Use summary schema `galadriel.evidence.summary.v3`.
Use manifest schema `galadriel.evidence.manifest.v3`.
Use acceptance profile `galadriel-0.9-frozen-acceptance-metrics-v3`.
Use bootstrap profile `splitmix64-rejection-group-metric-v1`.
The bootstrap profile samples complete tracks with SplitMix64 and unbiased rejection sampling.

Build the release evidence runner in a separate retained command.
Create a private directory with mode `0700`.
Copy the executable into it through no-follow descriptors with mode `0500`.
Execute that exact snapshot directly.
Bind its digest and the exact candidate commit and tree.

Use only bounded bytes captured from the verified host snapshot.
Stream and validate every ordered trial.
Independently rebuild the complete summary and report.
Verify the accepted configuration, manifest, and exact checksum document.
Evaluate acceptance only from the rebuilt holdout summary.
Repeat the complete semantic replay during finalization.

Only a run that uses `--deep` can have qualification status `PASS`.

Preserve structural acceptance failures.
The frozen design cannot pass `GLD-090-ACC-001` or `GLD-090-ACC-006` at 100 tracks.
These criteria need at least 369 and 738 tracks.
The frozen grid and observation ceiling permit at most 248 holdout tracks.
Do not weaken a threshold or resource bound to hide this result.

An executable qualification can pass while acceptance fails.
Record that combination as `NARROWED_REVIEW_REQUIRED`.
Only a signed human decision can select `NARROWED_GO` or `NO_GO`.
Map each failed criterion to removed claim `CLM-007` and one residual risk.
Do not select `GO` while an acceptance criterion fails.

Each retained command uses a stop-before-exec launch gate.
It applies fixed CPU, core-file, output-file, open-file, and stream limits.
Qualification requires macOS `kqueue` and `/usr/bin/sandbox-exec`.
It MUST fail before candidate execution if either control is absent.
It installs one mode-0500 dispatch for the 19 required command names.
It resolves each name before and after every bounded process.
The dispatch binds direct Apple developer Git and the selected developer tools.
It also binds the running `CPython 3.14.6` executable.
The sandbox denies direct execution of `/usr/bin/git` and `/usr/bin/python3`.
Critical host Git and SSH operations must pin direct Apple developer Git, `/usr/bin/ssh-add`, and `/usr/bin/ssh-keygen`.
Verify each root-owned no-follow executable identity before and after use.
Pin `sandbox-exec` to `/usr/bin/sandbox-exec` and its expected byte identity.
Record its resolved path, owner, group, and mode.
Remove dynamic-loader and toolchain selectors from host command environments.

The candidate sandbox denies signal operations by default.
It permits signals only to self and children.

The qualifier signals only the original process group while its root identity remains waitable.
It does not send a signal to an escaped numeric process identifier.
An observed escaped sandbox identity fails the run.
After root reap, the qualifier performs read-only extinction checks.
macOS does not provide atomic recursive descendant tracking.
A short-lived reparented process can exit between scans.
The sandbox-identity scan detects an active detached process that retains that identity.

The inherited sandbox and resource limits apply before candidate execution.
A sandboxed process can request work from an existing external service.
The process scan cannot attribute that external service work.

The license inventory scope is `CARGO_DENY_HOST_FILTERED_GRAPH`.
It contains exactly 382 host-filtered packages from the validated 437-package Cargo graph.
It is not a complete all-target license inventory.

Use `CPython 3.14.6` for canonical release-asset construction, verification, and reconstruction.
Require the asset tool to authenticate both internal tier signatures.
Require it to bind both tiers to the expected candidate commit and tree.
Require it to verify both complete manifest inventories and `SHA256SUMS` files.


## Required verification

Run focused tests while you edit.
Run the complete CI mirror for a code or contract change.
Use `.github/workflows/ci.yml` as the exact command source.

At minimum, run these repository gates:

```bash
python3 -B -E -s -S scripts/secure_deployment.py check
python3 -B -E -s -S repo_work/build_task_dispositions.py verify
python3 -B -E -s -S repo_work/local_convergence.py schema --repo .
python3 -B -E -s -S repo_work/freeze_audit_inputs.py verify-lifecycle \
  --repo . \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json \
  --allowed-signers release/0.9.0/audit/ALLOWED_SIGNERS
python3 -B -E -s -S scripts/release_audit.py verify
python3 -B -E -s -S repo_work/check_public_api.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python3 -B -E -s -S repo_work/check_feature_graph.py
cargo test --workspace --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
cargo fetch --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml
cargo deny --offline --all-features --locked check
cargo deny --offline --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```

For a frozen candidate, also run this strict audit-input gate:

```bash
python3 -B -E -s -S repo_work/freeze_audit_inputs.py verify \
  --repo . \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS-0.9.0.json \
  --allowed-signers /independent/path/ALLOWED_SIGNERS
```

The `verify-lifecycle` command above uses the tracked file only as a CI consistency check.
It does not authenticate the candidate.

Run the complete Python test command from `.github/workflows/ci.yml`.
Run each feature-isolated CLI check from that workflow.
Run the fuzz-workspace dependency check from that workflow.
Run the vulnerable-feature check from that workflow.

Run both current-stable Rust commands from that workflow.
Run both offline supply-chain commands from that workflow.
Materialize both locked dependency graphs before the offline supply-chain commands.

Do not describe the minimum command block above as the complete CI mirror.
The complete mirror includes every command in all three CI jobs.

Use Rust `1.89.0` for the workspace gate.
Use Rust and Cargo `1.97.1` for the current-stable gate.
Use `nightly-2026-06-16` for the public API gate.
Use `cargo-public-api 0.52.0` for that gate.

Run the exact fuzz and mutation jobs for a release candidate.
Require all four exact-candidate broad mutation shards to pass.
Require all three focused mutation outcomes to pass.
Treat the observational mutation-baseline job as residual evidence.

Exact mutation commands use environment schema `galadriel.mutation-environment.v2`.
They require the Linux process file system (`procfs`), process file descriptors, and serialized child-subreaper ownership.
They MUST fail before process creation when a required control is absent.
They MUST reap the root after tracked candidate-tree extinction.
They verify the default disposition of the child-status signal (`SIGCHLD`) at each containment checkpoint.
They also verify the active child-subreaper state.
A control change poisons the process and prevents verified success.
The runner cleans a stable process file descriptor (`pidfd`) identity when it can prove extinction.
It cannot signal an identity that escaped before stable capture during a subreaper control gap.
A control change that starts and ends between checkpoints is not observable.
The contract therefore requires exclusive single-threaded ownership by the trusted runner.
Treat an uninterruptible process past the stop deadline as a failed run.
Do not describe this cleanup as a control group, container, or deployment-isolation boundary.

Generic trusted host commands cover the root and original process group only.
They do not track a descendant that creates another session.
Do not use that mode for a candidate-controlled command.

Do not describe the deep workflow as passed when an observational job fails.
Do not claim that a skipped gate passed.


## Collaboration and Git

Claim file ownership before parallel work starts.
Use separate files or isolated worktrees for parallel changes.
Report a path conflict before you edit it.
Re-read a shared file before you apply a patch.
Review each returned change against the initial commit.
Run decisive tests again in the integrated tree.

Commit one coherent verified milestone at a time.
Sign every commit.
Use Sepehr Mahmoudian as the sole commit author.
Use a concise professional imperative subject.
Do not add automated attribution.

A matching author or signer label is only a consistency check.
It does not authenticate a commit or evidence file.
Use the required cryptographic signature and independent trust root for authentication.

Do not add a co-author trailer.
Do not force-push `main`.

Push accepted milestones to the active remote review branch.
Push the accepted exact candidate to `origin/main`.
Confirm that local `HEAD` equals `origin/main` after promotion.

Only the release operator can merge, tag, publish, delete references, or change repository settings.
A delegated agent MUST NOT do those actions.
