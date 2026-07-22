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

This directory contains the auditable release record for Galadriel's Mirror 0.9.0.
The release author is **Sepehr Mahmoudian**.
The publication channel is a GitHub source release.
This release does not claim crates.io publication, a DOI, or a Zenodo identifier.

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

- `RELEASE-NOTES.md` contains the reviewed GitHub release text.
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
  It also records the Haldir supersession and explicit non-edges.
  Mutable heads record provenance only.
  The two Cargo revisions are the only dependency pins.
- `local-convergence-schema.json` adapts the supplied convergence schema to version 0.9.0.
  Finalization creates a signed exact-candidate `LOCAL-CONVERGENCE.json` file.
  Creation occurs only after all 116 dispositions and ten wave acceptances pass.
  Complete file review and all retained artifacts must also pass.
  The record must state the fixed local cross-repository requirements.
- Exact pid-rs and NCP pin graphs receive local qualification.
  Crebain, Haldir, and Prisoma remain optional or prospective.
  Engram, Paper2Brain, ROS, and external authority remain absent edges.
  Reciprocal and deployed relationships remain absent or unclaimed.
- If reciprocal reconciliation starts, it can use `LOCAL-CONVERGENCE.json` as an entry point.
  The record does not prove acceptance by another repository.
- `repo_work/package_release_assets.py` creates two deterministic path-preserving tar files.
  It also creates a canonical asset map and detached `galadriel-release-assets` signature.
  The signed map binds both tar byte identities to the exact candidate and tree.
  It binds the signed tag object and target, the author, and null DOI and Zenodo fields.
  Verification enforces the exact four-file upload set.
- `api/` contains the public source API baseline and accepted 0.9.0 surface.
- `evidence/` contains complete command output instead of pass or fail summaries.
- `reviews/` contains the phase and final multi-lens review records.
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

The qualification run needs two signed inputs:

- the signing key
- the exact-candidate mutation manifest

```console
python3 repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --require-branch main \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$(git config --get user.signingkey)" \
  --mutation-evidence /path/to/exact-candidate-mutation.json \
  --mutation-evidence-signature /path/to/exact-candidate-mutation.json.sig \
  --evidence-config evidence/galadriel-0.9-candidate.json \
  --deep --keep-going
```

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
Use `--snapshot-dir` to select a secure external file system with sufficient space.
The bounded qualification snapshot can use up to 8 GiB plus review inputs.
Prefer an agent-backed Ed25519 public-key handle.
This method avoids a snapshot of private key bytes.

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
Verify each recovered `SHA256SUMS` file.
Verify the qualification and closure signatures.
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

Canonical tar creation and regeneration use the audit-pinned `CPython 3.14.6`.
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
