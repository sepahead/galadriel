# Withdrawn and obsolete remote identities

This record preserves identities before remote deletion. Deletion prevents an old
research snapshot from being confused with the reviewed 0.9.0 source release; it
does not erase the commit or its historical evidence.

## `research-snapshot-v0.1.0`

- status: withdrawal approved; tag deletion pending final 0.9.0 candidate commit
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
- branch-tip commit signature: absent
- replacement: the protected, signed `main` candidate and `v0.9.0` tag
- deletion boundary: record and verify the final remote identities first; deleting
  this movable branch does not delete its commit or authorize history rewriting
