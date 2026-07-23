# Galadriel 0.9.0 release record

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| DOI | digital object identifier |
| HTML | Hypertext Markup Language |
| JSON | JavaScript Object Notation |
| NCP | Neuro-Cybernetic Protocol |
| PID | partial information decomposition |
| ROS | Robot Operating System |
| SHA-256 | Secure Hash Algorithm 256 |
| SSH | Secure Shell |
| URLs | Uniform Resource Locators |
| ZIP | ZIP archive format |

This directory contains the auditable release record for Galadriel's Mirror 0.9.0.
The release author is **Sepehr Mahmoudian**.
The publication channel is a review-gated GitHub research source release.
This release does not claim crates.io publication, a DOI, or a Zenodo record.

[`handoff-source.json`](handoff-source.json) identifies the current external handoff.
It records the exact archive and task-ledger digests.
The repository does not contain the superseded handoff copy.
Inherited prose supplies provenance and not new evidence.

[`tasks.json`](tasks.json) contains the current 116-task projection.
[`VERSION-ADAPTATION.md`](VERSION-ADAPTATION.md) maps the 1.0 design target to version 0.9.0.
This adaptation does not weaken a technical, safety, or evidence obligation.

**GLD-090-AUD-001:** The release **SHALL** generate a canonical audit manifest.
The manifest **SHALL** cover each qualification input in these groups:

- repositories
- toolchains
- Git dependencies
- datasets, fixtures, and evidence
- normative documents
- external sources

Each local artifact **SHALL** record its path, byte length, purpose, and SHA-256 value.
A mutable or abbreviated repository identity **SHALL NOT** qualify.

The audit manifest excludes only itself from its tracked-file inventory.
A file cannot contain its own cryptographic digest.
The generator records and enforces this exact exclusion.
It includes `requirements-ledger.json` and all other tracked paths.
The signed full-source archive separately binds the audit manifest bytes.

**GLD-090-LED-001:** The requirement ledger **SHALL** contain exactly T000 through T115.
It **SHALL** keep dependency order.
A `COMPLETE` task **SHALL** have normative `SHALL` requirements and retained evidence.
It **SHALL** also have all twenty handoff lenses and a residual-risk disposition.
Prose alone **SHALL NOT** close a task.

## Release records

- `RELEASE-NOTES.md` contains the review-gated GitHub release text.
  It preserves each unavailable deployment, integration, archival, and policy-use claim.
- `audit-inputs.json` contains the reviewed input inventory.
  `audit-manifest.json` is the generated repository inventory.
- `claims.json` separates implemented, validated, deployment-qualified, and unclaimed behavior.
  This release has no deployment-qualified claim.
- `handoff-source.json` identifies the immutable source package.
  `tasks.json` contains the current task-index projection.
- `task-closure-plan.json` records the required task closure.
  `task-dispositions.json` and `requirements-ledger.json` record its source state.
  These records do not represent future review as complete.
- `ecosystem-cut.json` records each inspected peer object and each relationship direction.
  It records build and runtime optionality, the graph rationale, and the acyclic boundary.
  It also records the Haldir supersession and dated Paper2Brain observation.
  Paper2Brain remains an explicit integration non-edge.
  Mutable heads record provenance only.
  The two Cargo revisions are the only dependency pins.
- `local-convergence-schema.json` adapts the supplied convergence schema to version 0.9.0.
  Finalization creates a signed exact-candidate `LOCAL-CONVERGENCE.json` file.
  Creation occurs only after all 116 dispositions and ten wave acceptances pass.
  Complete file review and all retained artifacts must also pass.
  The record must state the fixed local cross-repository requirements.
- Exact pid-rs and NCP pin graphs receive local qualification.
- Crebain remains an optional reference producer.
- Haldir remains a prospective record-only consumer.
- Prisoma remains a prospective immutable offline consumer.
- Engram, Paper2Brain, ROS, and external authority remain absent edges.
- Reciprocal and deployed relationships remain absent or unclaimed.
- If reciprocal reconciliation starts, it can use `LOCAL-CONVERGENCE.json` as an entry point.
  The record does not prove acceptance by another repository.
- `repo_work/package_release_assets.py` creates two deterministic path-preserving tar files.
  It also creates a canonical asset map and detached `galadriel-release-assets` signature.
  The signed map binds both tar byte identities to the exact candidate and tree.
  It binds the signed tag object and target, the author, and null DOI and Zenodo fields.
  Verification enforces the exact four-file upload set.
- `api/` contains the public source API baseline and accepted 0.9.0 surface.
- `evidence/` contains complete command output instead of pass or fail summaries.
- `reviews/` contains the phase record, review method, and incomplete comment template.
  The final twenty-lens review is a separately signed post-commit input.
- `reviews/REVIEW-COMMENTS.md` is an incomplete comment interface bound to the eventual exact candidate.
  It does not claim that an external person reviewed or approved the release.

Generate and verify deterministic audit artifacts with these commands:

```console
python3 scripts/release_audit.py generate
python3 scripts/release_audit.py verify
```

## Candidate qualification

Create the exact signed source commit before qualification.
Run qualification from that immutable commit.
Use a new output directory outside the checkout.

The mutation evidence contains exactly 13 artifacts.
These artifacts are seven outcome files, five run receipts, and one retained `git.diff`.
Each of the four broad outcome files has one broad shard receipt.
The three focused outcome files share one focused receipt.
All four broad shards and all three focused outcomes are exact-candidate gates.

The observational mutation-baseline job is residual evidence.
It is not a successful release gate.
The acceptance-estimation scope has exactly 26 mutants.
It requires 23 caught mutants and three exact compile-unviable replacements.
It permits no missed, timed-out, or surviving mutant.

The qualifier fetches the locked workspace graph and the locked fuzz graph.
Both fetches complete before the offline metadata and dependency-policy gates.
It uses the exact 16-key base environment in `docs/DEPENDENCY-POLICY.md`.
It isolates home, Cargo, target, and temporary state in the private qualification root.
It does not pass ambient credentials, proxies, wrappers, loader variables, or compiler flags.
It rejects a file, directory, or link at each Cargo configuration path.

It checks before and after each retained command.

The signed qualification record binds this environment policy.

The qualifier refreshes public `main` before each candidate comparison.
It repeats the refresh before it returns.
It uses the literal public repository URL and exact `main` refspec.
It rejects local Git settings that can redirect or weaken the fetch.

The evidence command must create exactly six flat regular files.
These files are `SHA256SUMS`, `config.json`, `manifest.json`, `report.md`, `summary.json`, and `trials.jsonl`.
Each file has a 1 GiB limit.
The complete set has a 4 GiB limit.
The host snapshots the set without following links.
It compares source, quarantine, snapshot, and installed bytes.

It parses only bounded JSON bytes captured from the verified snapshot.
Only a run that uses `--deep` can have qualification status `PASS`.

The qualification record uses schema `galadriel.candidate-qualification.v3`.
The run needs these external inputs:

- an agent-backed Ed25519 public-key handle
- an independently obtained allowed-signers file
- the exact pinned external RustSec advisory database
- the signed exact-candidate mutation pair
- the tracked evidence configuration

```console
python3 repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --require-branch main \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$(git config --get user.signingkey)" \
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --advisory-db /independent/path/advisory-db \
  --mutation-evidence /path/to/exact-candidate-mutation.json \
  --mutation-evidence-signature /path/to/exact-candidate-mutation.json.sig \
  --evidence-config evidence/galadriel-0.9-candidate.json \
  --deep --keep-going
```

A passing tier must retain exactly 22 auxiliary command receipts.
It must compare one source archive, seven package archives, and seven software bills of materials twice.
These 15 comparisons require byte-identical results.

Each command uses a stop-before-exec gate and fixed resource limits.
macOS does not provide atomic recursive descendant tracking.
A short-lived reparented process can exit between scans.
The process scan detects a detached process that remains active.

The inherited sandbox and resource limits apply before candidate execution.
A sandboxed process can request work from an existing external service.
The process scan cannot attribute that external service work.

The license inventory covers the exact 382-package `CARGO_DENY_HOST_FILTERED_GRAPH` scope.
It does not cover all 437 packages for every target.

The release input pins the external RustSec database identity at the 2026-07-23 inspection cut.
The inventory contains 1,187 entries.
Its SHA-256 value is `bfc26634ed164598c75c91fc462f0fa527b73634859faeb9476f2631bf529619`.
A qualification result remains bound to that pinned input.

Use this exact post-commit evidence order:

1. Sign the final twenty-lens review.
2. Create and sign the candidate-bound version 3 release decision.
3. Bind that decision to the review and its signature.
4. Create and sign the ordered task dispositions.
5. Cite the retained review and decision for tasks T114 and T115.

`repo_work/finalize_release.py` verifies and copies the exact input bytes.
It stages the complete closure and flushes it.
It publishes the closure with one same-parent rename.
These records remain outside the candidate checkout.
Their creation cannot change the source identity.

A pre-publication failure leaves the requested output absent.
Use `--snapshot-dir` to select an existing non-link directory outside the repository and qualification tier.
Restrict directory access to the release operator.
The bounded qualification snapshot can use up to 8 GiB plus review inputs.
Use an agent-backed Ed25519 public-key handle.

Keep the handle outside the repository, qualification tier, output, and snapshot root.
Require the handle to match the independently obtained allowed-signers file.

The finalizer snapshots only the canonical public fields.
It never snapshots private signing material.

The rename is the commit point.
Status 3 means that the tool retained a complete output.
It also means that the tool did not confirm durability or the result report.
An independent verifier must check that bundle before use.

## Publication assets

Create the signed annotated `v0.9.0` tag after finalization.
Publish exactly these four assurance assets:

- `galadriel-0.9.0-qualification.tar`
- `galadriel-0.9.0-closure.tar`
- `galadriel-0.9.0-release-asset-map.json`
- `galadriel-0.9.0-release-asset-map.json.sig`

Build these files only with `repo_work/package_release_assets.py build`.
Download all four files before publication verification.
Use an independently obtained allowed-signers trust root.
Verify the complete four-file set with the same tool.

Use `extract` and `reconstruct` to recover the original tier roots.
These actions do not trust an archive path.
Build, verification, and reconstruction authenticate both internal tier signatures.
They bind each tier to the expected candidate commit and tree.
They verify each complete signed inventory and `SHA256SUMS` file.
Verify `LOCAL-CONVERGENCE.json` against the exact candidate.

GitHub creates source ZIP and tar archives automatically.
Use them only as convenience snapshots.
They are not members of the signed asset map.
They do not replace either evidence tar file.
`RELEASE-RUNBOOK.md` contains the normative draft-first procedure.

The internal tier signatures use principal `sepmhn@gmail.com`.
They use these literal SSH namespaces:

- `galadriel-qualification-manifest`
- `galadriel-closure-manifest`

The outer asset-map namespace is `galadriel-release-assets`.
The runbook gives the exact independent-trust-root commands.

## Public verification

Post-publication verification resolves all six immutable release-body `blob` links.
It compares each raw file with the applicable tagged Git blob.
It also checks schema `$id` URLs for these schemas:

- local convergence
- PID envelope
- monitor envelope

The verifier compares schema bytes with their tagged Git blobs.
It does not represent an HTML `blob` response as source bytes.

The release title must be `Galadriel 0.9.0`.
The release body must equal the complete tracked `RELEASE-NOTES.md` file.
Do not infer the release body from its Markdown title.

Canonical asset construction, verification, and reconstruction use the audit-pinned `CPython 3.14.6`.
Compare authenticated and anonymous downloads with all four local source files.
This check remains mandatory when GitHub omits an API digest.

The verifier rejects these conditions:

- stale output
- duplicate JSON keys
- mutable Git dependencies
- prose-only task closure
- incomplete twenty-lens reviews
- incorrect author or version metadata
- a project DOI or Zenodo claim
