# Withdrawn and obsolete remote identities

This record preserves identities before remote deletion. Deletion prevents an old
research snapshot from being confused with the reviewed 0.9.0 source release; it
does not rewrite a recorded object identity. Branch-only objects and their evidence
must be preserved externally before their sole refs are deleted.

## `research-snapshot-v0.1.0`

- status: withdrawal approved; tag deletion permitted only after the replacement
  `v0.9.0` release and freshly downloaded copies of every published asset verify
- tag kind: signed annotated Git tag
- signature verification: GitHub reported `verified=true`, reason `valid`, at
  `2026-07-12T00:35:02Z`; the embedded SSH signature uses the author's Ed25519 key
- tag object: `ca1b2c69a0a6e04223fbbc07820b8226d918e275`
- target commit: `1205ce56a461036769ad29d4af93ceafd83da1db`
- original message: `Non-production research snapshot v0.1.0`
- GitHub release: none existed at the 2026-07-14 audit
- withdrawal reason: this pre-contract research snapshot predates the current
  0.9.0 claims, evidence, API, protocol, and release-governance boundaries; retaining
  a public release tag would make its qualification status easy to misread
- preserved history: the target commit remains reachable in repository history
- replacement: signed `v0.9.0` research source release, only after final gates
- DOI/Zenodo effect: none; neither the withdrawn tag nor 0.9.0 has a project DOI or
  Zenodo record at this stage

No GitHub releases, drafts, or prereleases existed when this inventory was made.
Any newly discovered legacy release must be added here with its immutable identity
and withdrawal reason before deletion.

## `release/0.9-phase-2` branch

- status: obsolete release-work branch; deletion pending final 0.9.0 publication
- branch tip: `bcb1c0734aa3581b86b08d5960f96c13e1e81066`
- branch-tip tree: `11df88fd7ebeb4dedabc30b27c44ac27b3223b33`
- branch-tip subject: `chore(progress): checkpoint Phase 2 typed contracts`
- branch-tip author and committer: `Sepehr Mahmoudian <sepmhn@gmail.com>`
- branch-tip committed: `2026-07-14T11:00:05Z`
- branch-tip commit signature: valid SSH signature by Sepehr Mahmoudian; GitHub
  reported `verified=true`, reason `valid`, at `2026-07-14T11:00:49Z`
- signature key: Ed25519 fingerprint
  `SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU`
- replacement: the protected, signed `main` candidate and `v0.9.0` tag
- deletion boundary: record and verify the final remote identities and preserve the
  branch-only commit externally first; deleting the ref does not rewrite candidate
  or `main` history, but it removes durable reachability for later object recovery

## `wip/release-0.9.0-20260715` branch

- status: superseded release-work branch; deletion pending verified 0.9.0 publication
- branch tip: `f541f3eda7cfdc81a3277c3d6fecc91245179f24`
- branch-tip tree: `47aa9b75e988deb8e6f7e290365987a81db1fe9d`
- branch-tip subject: `chore: ignore Python tool caches`
- branch-tip author and committer: `Sepehr Mahmoudian <sepmhn@gmail.com>`
- branch-tip committed: `2026-07-15T17:24:21Z`
- branch-tip commit signature: valid SSH signature by Sepehr Mahmoudian; GitHub
  reported `verified=true`, reason `valid`, at `2026-07-15T17:24:47Z`
- signature key: Ed25519 fingerprint
  `SHA256:3gaatfl4IVnuBX4D60Jxw9oVIrvEE1ZphK8IuEyrfPU`
- replacement: the protected, signed `main` candidate and `v0.9.0` tag include the
  useful ignore rules and supersede this branch's older release-date metadata
- deletion boundary: preserve the branch-only commit externally and verify the
  final remote identity immediately before deleting the ref
