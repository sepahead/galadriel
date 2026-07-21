# Galadriel 0.9.0 release record

This directory is the auditable release record for Galadriel's Mirror 0.9.0.
The release author is **Sepehr Mahmoudian**. It is
a GitHub source release: no crates.io publication, DOI, or Zenodo identifier is
claimed.

[`handoff-source.json`](handoff-source.json) records the exact current external
handoff archive and task-ledger digests. The superseded handoff formerly embedded
here was removed: inherited prose is provenance, not fresh proof. The current
116-task projection is [`tasks.json`](tasks.json), and
[`VERSION-ADAPTATION.md`](VERSION-ADAPTATION.md) maps its 1.0 design target onto
0.9.0 without weakening technical, safety, or evidence obligations.

**GLD-090-AUD-001:** The release **SHALL** generate a canonical audit manifest
covering every repository, toolchain, Git dependency, dataset/fixture/evidence
input, normative document, and external source used for qualification. Each local
artifact **SHALL** carry its path, byte length, purpose and SHA-256; mutable or
abbreviated repository identities **SHALL NOT** qualify.

The manifest itself is the sole tracked-file exclusion from its artifact list,
because a file cannot contain its own cryptographic digest. This exclusion is
machine-recorded and enforced exactly; `requirements-ledger.json` and every other
tracked path remain covered. The qualifier's signed full-source archive separately
binds the manifest bytes.

**GLD-090-LED-001:** The requirement ledger **SHALL** contain exactly T000–T115 in
dependency order. `COMPLETE` **SHALL** require normative SHALL-language, retained
tests/evidence, all twenty current-handoff lenses, and a residual-risk disposition;
prose alone **SHALL NOT** close a task.

Normative and generated artifacts:

- `RELEASE-NOTES.md` is the reviewed GitHub release text and preserves every
  unavailable deployment, reciprocal-integration, archival, and policy-use claim.
- `audit-inputs.json` is the reviewed input inventory; `audit-manifest.json` is
  generated from it and the repository.
- `claims.json` separates implemented, validated, deployment-qualified, and
  explicitly unclaimed behavior. There are intentionally no
  deployment-qualified claims.
- `handoff-source.json` identifies the immutable source package; `tasks.json` is
  the current task-index projection. `task-closure-plan.json`,
  `task-dispositions.json`, and `requirements-ledger.json` are source-state
  records: they preserve the exact post-commit work still required and do not
  represent future review as complete.
- `ecosystem-cut.json` records each inspected sibling object, relationship direction,
  build/runtime optionality, rationale, and explicit supersession. Mutable heads are
  provenance only; the two Cargo revisions are the only dependency pins.
- `local-convergence-schema.json` is the explicit 0.9.0 adaptation of the supplied
  convergence schema. Finalization emits a separately signed, exact-candidate
  `LOCAL-CONVERGENCE.json` only after all 116 dispositions, ten wave acceptances,
  complete file review, and retained artifacts pass, and after the fixed local
  cross-repository requirements are explicitly recorded. Exact pid-rs/NCP pin graphs
  are locally qualified; reciprocal and deployed compatibility remains unclaimed.
  The record is an entry point for any later reciprocal reconciliation, not evidence
  that another repository accepted this candidate.
- `api/` retains the public-source API baseline and accepted 0.9.0 surface.
- `evidence/` retains complete command output rather than pass/fail summaries.
- `reviews/` contains the phase and final multi-lens review records.
- `reviews/REVIEW-COMMENTS.md` is an uncompleted, non-signoff comment interface
  bound to the eventual exact candidate; it does not claim that any external
  person has reviewed or approved the release.

Regenerate and verify deterministic artifacts with:

```console
python3 scripts/release_audit.py generate
python3 scripts/release_audit.py verify
```

After the exact signed source commit exists, qualification runs from that immutable
commit into a new directory outside the checkout. A successful invocation requires
the signing key and the separately signed exact-candidate mutation manifest:

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

The post-commit order is exact: sign the final twenty-lens review; sign the canonical
candidate-bound v3 release decision that hashes that review and its signature; then
sign task dispositions whose T114 and T115 evidence cites those retained inputs.
`repo_work/finalize_release.py` snapshots and verifies those exact bytes, stages the
complete closure, flushes it, and publishes it by one same-parent rename. These
records remain outside the candidate so creating them cannot retroactively change
its source identity. A pre-publication failure leaves the requested output absent.
Use its optional `--snapshot-dir` to select a secure external filesystem with room
for the bounded 8 GiB qualification snapshot plus review inputs; prefer an
agent-backed Ed25519 public-key handle so private key bytes need not be snapshotted.
The rename is the commit point; status 3 means a complete output was retained but
parent-directory durability or result reporting was not confirmed, so the retained
bundle must be independently verified before use.

The verifier rejects stale output, duplicate JSON keys, mutable Git dependencies,
prose-only task closure, incomplete twenty-lens reviews, incorrect author/version
metadata, and an accidental project DOI or Zenodo claim.
