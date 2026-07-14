# Galadriel 0.9.0 release record

This directory is the auditable release record for the first supervisor-review
release of Galadriel's Mirror. The release author is **Sepehr Mahmoudian**. It is
a GitHub source release: no crates.io publication, DOI, or Zenodo identifier is
claimed.

The `handoff/` directory preserves every supplied 1.0 handoff file byte-for-byte.
[`VERSION-ADAPTATION.md`](VERSION-ADAPTATION.md) is the controlling decision that
maps those requirements onto 0.9.0 without weakening their technical, safety, or
evidence obligations.

**GLD-090-AUD-001:** The release **SHALL** generate a canonical audit manifest
covering every repository, toolchain, Git dependency, dataset/fixture/evidence
input, normative document, and external source used for qualification. Each local
artifact **SHALL** carry its path, byte length, purpose and SHA-256; mutable or
abbreviated repository identities **SHALL NOT** qualify.

**GLD-090-LED-001:** The requirement ledger **SHALL** contain exactly T000–T119 in
dependency order. `COMPLETE` **SHALL** require normative SHALL-language, retained
tests/evidence, a ten-lens review and residual-risk disposition; prose alone **SHALL
NOT** close a task.

Normative and generated artifacts:

- `audit-inputs.json` is the reviewed input inventory; `audit-manifest.json` is
  generated from it and the repository.
- `claims.json` separates implemented, validated, deployment-qualified, and
  explicitly unclaimed behavior. There are intentionally no
  deployment-qualified claims.
- `handoff/tasks.json` is a lossless task-index projection of the supplied YAML;
  `task-dispositions.json` contains reviewed closures and
  `requirements-ledger.json` is generated from both.
- `api/` retains the public-source API baseline and eventual 0.9.0 surface.
- `evidence/` retains complete command output rather than pass/fail summaries.
- `reviews/` contains the phase and final multi-lens review records.

Regenerate and verify deterministic artifacts with:

```console
python3 scripts/release_audit.py generate
python3 scripts/release_audit.py verify
```

The verifier rejects stale output, duplicate JSON keys, mutable Git dependencies,
prose-only task closure, incomplete ten-lens reviews, incorrect author/version
metadata, and an accidental project DOI or Zenodo claim.
