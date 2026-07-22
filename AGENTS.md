# Galadriel repository instructions

These instructions apply to every change in this repository.

Use this file as the operational guide.
Use the linked contracts as the technical source of truth.

## Read before work

Run these commands before you change a file:

```bash
git rev-parse 'HEAD^{commit}'
git rev-parse 'HEAD^{tree}'
git status --short --branch
```

Read these files before any change:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `RELEASE-POLICY.md`
- `SUPPORT.md`

Read the documents that own the changed surface.

| Change area | Required documents |
| --- | --- |
| Core types, detector logic, fusion, or configuration | `docs/CORE-CONTRACT.md`, `docs/CONFIGURATION-CONTRACT.md`, `docs/STATE-MACHINE.md`, and `docs/STATISTICAL-CONTRACT.md` |
| Claims, public API, or release scope | `docs/CLAIMS.md`, `docs/API-SURFACE.md`, and `release/0.9.0/README.md` |
| PID research code | `docs/PID_RS_1_0_MIGRATION.md`, `docs/EVALUATION.md`, and `docs/JUSTIFICATION.md` |
| NCP, JSONL, Zenoh, producer, or live receiver code | `docs/PRODUCER-CONTRACT.md`, `docs/SECURE-DEPLOYMENT.md`, and `docs/ECOSYSTEM-CONNECTIONS.md` |
| Advisory or downstream behavior | `docs/ADVISORY-BOUNDARY.md` and `docs/ECOSYSTEM-CONNECTIONS.md` |
| Evidence, qualification, tags, assets, or publication | `release/0.9.0/RELEASE-RUNBOOK.md` and `repo_work/README.md` |

Treat each commit as an exact candidate identity.
Do not use a mutable branch name as retained evidence.
Restart candidate-bound checks after each tracked change.

## Release identity

The release version is `0.9.0`.
The release channel is a GitHub research source release.
Sepehr Mahmoudian is the release author and commit author.
The canonical GitHub owner is `sepahead`.
Every workspace package must keep `publish = false`.
Do not publish a crate to crates.io.

No project DOI exists.
No project Zenodo record exists.
Do not add either identifier until the author supplies it.

Do not claim production support without exact evidence.
Do not claim field validation without exact evidence.
Do not claim deployment qualification without exact evidence.
Do not claim independent replication without exact evidence.

## Architecture invariants

Galadriel is advisory instrumentation.
Galadriel is not an authority service.
A Galadriel result MUST NOT create or widen authority.
`Nominal` MUST NOT create permission.
`InsufficientEvidence` MUST NOT become `Nominal`.
Invalid input or invalid configuration MUST return an error.

Missing, stale, incompatible, or incomplete evidence MUST fail closed.

A cross-channel assessment MUST bind one track and one exact sequence.
It MUST bind a common projection and physical frame.
It MUST bind the projection context and frozen prior.
It MUST preserve session, producer, epoch, and lifecycle identity.
Equal dimensions alone do not prove comparability.

PID evidence is an optional research diagnostic.
PID evidence MUST NOT repair a failed core prerequisite.
PID evidence MUST NOT override signed-correlation evidence.
PID evidence MUST NOT create authority.

The default build must remain pure and small.
The default CLI MUST NOT resolve PID or NCP integration crates.
The `pid`, `ncp`, and `ncp-live` features MUST remain off by default.
The `ncp-live` feature can add Zenoh and Tokio only in its declared graph.
All Rust targets MUST remain free of unsafe code.
Bound input size and work before the processor starts high-cost work.

Preserve negative results, abstention, and unsupported states.

## Ecosystem boundaries

Use `required`, `optional`, and `absent` only for the named mode.

| Project | Version 0.9.0 relationship |
| --- | --- |
| pid-rs | It is optional in the default build. Its exact pin is required for PID, evaluation, and justification paths. |
| NCP | It is optional in the default build. Its exact NCP wire 0.8 pin is required for NCP paths. |
| Crebain | It is an optional reference producer. Galadriel has no Cargo dependency on Crebain. |
| Haldir | It has no version 0.9.0 runtime edge. It is a prospective record-only consumer. |
| Prisoma | It has no version 0.9.0 runtime edge. It is a prospective immutable offline consumer. |
| Engram and Paper2Brain | They have no integration edge. The `engram/ncp` value is an example realm string. |
| ROS and ROS 2 | They have no binding, topic, service, action, bridge, node, or bag import. |
| External authority | Galadriel has no command, control, credential, lease, watchdog, or authority path. |

The exact pid-rs revision is `1cd2424f7967e1752dcc8e53859e8fdad3566f51`.
The exact NCP revision is `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`.
Galadriel uses NCP wire 0.8.
Do not infer NCP wire 1.0 compatibility.

Live use needs an authorized producer that conforms to the producer contract.
That producer does not have to be Crebain.
If Haldir gains a policy effect, that effect requires separate admission.
Such an effect MUST remain restrict-only.
Shared PID or NCP code does not prove Prisoma compatibility.
It does not prove independent replication.

Keep the declared graph acyclic.
Do not add an evidence-to-command feedback loop.
Do not change a peer repository for convenience.
Check for concurrent work before an approved peer-repository change.

## Implementation rules

Inspect the applicable type, implementation, tests, schema, and documentation.
Preserve unrelated work in a dirty worktree.
Use `rg` for repository search.
Use `apply_patch` for manual file edits.
Do not use destructive Git commands.
Do not weaken a guard to make a test pass.

Keep pure domain logic separate from external effects.
External effects include transports, clocks, files, processes, and deployment actions.
Represent identity, time, units, frame, estimand, schema, and profile explicitly.
Represent session, lifecycle, and authority explicitly.
Reject duplicate keys and unsafe integers.
Reject non-finite values and ambiguous defaults.

Reject unknown required semantics.

Add a negative test for each new accept path.
Add a positive test for each new fail-closed path.
Test feature-disabled behavior when an optional feature changes.
Change a generated artifact through its declared generator.
Do not hand-edit retained generated evidence.

## Protected records

Do not edit these historical or generated records:

- `.superstack/build-context.md`
- `.superstack/security-reports/galadriel-2026-07-10.md`
- `.superstack/security-reports/history.md`
- `.superstack/galadriel-review-2026-07-10.html`
- `evidence/results/post-audit-v1-8a0084f/report.md`
- `release/0.9.0/evidence/ACCEPTANCE-CRITERIA.md`
- `release/0.9.0/reviews/phase-1.md`
- `release/0.9.0/WITHDRAWN-RELEASES.md`

Preserve tracked contract, fixture, schema, and evidence JSON files.
Change one only when a technical requirement needs the change.
Preserve license files byte-for-byte.

## Evidence and release work

Bind retained results to the exact commit and tree.
Record the command, tool, configuration, input, and exit status.
Create qualification output outside the checkout.
Create closure output outside the checkout.
Use a new output directory for each run.
Do not edit signed evidence.

Do not omit a negative result.
Do not convert observational evidence into a successful gate.

Treat external model review as advisory design input.
External model review MUST NOT certify a claim or release.
It MUST NOT certify a security property or deployment.

Use an independently obtained allowed-signers file.
Do not let a candidate authenticate itself with its tracked trust file.
Keep private signing material outside the repository.
Use the SSH namespace in the release runbook.

Follow `release/0.9.0/RELEASE-RUNBOOK.md` for release work.
Preserve an obsolete release identity before you remove its reference.
Remove obsolete references only after public release verification passes.
Never move or reuse `v0.9.0`.

## Secrets

The local `.env` file MUST remain ignored.
Do not stage `.env` or a variant that contains a secret.
Do not print a secret value.
Do not put a secret in a command argument.
Do not put a secret in a log, prompt, document, commit, or evidence file.
Pass an approved secret through the process environment.

Use only environment variable names in diagnostics.
Stop the affected operation if output contains a secret.
Rotate an exposed credential before you continue.
Use the private process in `SECURITY.md` to report a vulnerability.

## Required verification

Run focused tests while you edit.
Run the complete CI mirror for a code or contract change.
Use `.github/workflows/ci.yml` as the exact command source.

At minimum, run these repository gates:

```bash
python3 scripts/secure_deployment.py check
python3 repo_work/build_task_dispositions.py verify
python3 repo_work/local_convergence.py schema --repo .
python3 repo_work/freeze_audit_inputs.py verify \
  --repo . \
  --out release/0.9.0/audit/FROZEN-AUDIT-INPUTS.json \
  --allowed-signers release/0.9.0/audit/ALLOWED_SIGNERS
python3 scripts/release_audit.py verify
python3 repo_work/check_public_api.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python3 repo_work/check_feature_graph.py
cargo test --workspace --all-features --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
cargo deny --all-features --locked check
```

Run the complete Python test command from `.github/workflows/ci.yml`.
Run each feature-isolated CLI check from that workflow.
Run the fuzz-workspace dependency check from that workflow.

Use Rust `1.89.0` for the workspace gate.
Use `nightly-2026-06-16` for the public API gate.
Use `cargo-public-api 0.52.0` for that gate.
Run the exact fuzz and mutation jobs for a release candidate.
Require all four exact-candidate mutation shards to pass.
Treat the observational mutation baseline as residual evidence.

Do not describe the deep workflow as green when an observational job fails.
Do not claim that a skipped gate passed.

## Documentation rules

Write documentation in the project ASD-STE100 Issue 9 style.
Use short active sentences.
Put one instruction in each sentence.
Use one topic in each descriptive sentence.
Use American English word forms.
Do not use contractions.

Do not use semicolons.
Define an abbreviation at first use.
Use one term for one concept.
Use the same technical term in each document.
Use `MUST` and `MUST NOT` only for normative boundaries.

Keep a procedure sentence at 20 words or fewer when practical.
Keep a descriptive sentence at 25 words or fewer when practical.
Keep a paragraph at six sentences or fewer.
Use a vertical list for complex information.

State the exact scope of each result.
State the exact evidence tier of each result.
State what the result does not prove.
Qualify words such as `safe`, `secure`, `validated`, and `verified`.
Qualify words such as `stable`, `qualified`, and `production`.

Do not change exact data for editorial reasons.
Exact data includes code, commands, identities, hashes, schemas, and citations.
It also includes equations, thresholds, units, and evidence records.

A style checker is only an aid.
An informed writer remains responsible for the text.
Check each changed command and link.
Keep all affected documents consistent.
Do not include credentials, private conversation, or personal context.

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

Do not add a co-author trailer.
Do not force-push `main`.

Push accepted milestones to the active remote review branch.
Push the accepted exact candidate to `origin/main`.
Confirm that local `HEAD` equals `origin/main` after promotion.

Only the release operator can merge, tag, publish, or change repository settings.
A delegated agent MUST NOT do those actions.

## Completion check

Confirm that the worktree is clean.
Confirm that all affected gates pass.
Confirm that all affected claims and documents agree.
Confirm that the repository tracks no secret.
Confirm that retained output contains no secret.

Confirm that signed evidence binds the current candidate.
Confirm that the signed candidate exists on `origin/main`.
