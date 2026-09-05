# Galadriel agent contract

Galadriel develops advisory statistical monitoring for multi-sensor fusion and tampering research.
This file defines the operating contract for maintainers and coding agents.
Every completion claim must name its tested scope and remaining limitations.
Current requirements, historical observations, and proposed capabilities remain separate.

## Read before changing

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [RELEASE-POLICY.md](RELEASE-POLICY.md), and [SUPPORT.md](SUPPORT.md).
Record the exact commit, tree, staged changes, and unstaged changes before editing.
Then read the documents that own the affected surface:

| Surface | Owning documents |
| --- | --- |
| Core types, detector, fusion, configuration | [Core contract](docs/CORE-CONTRACT.md), [Configuration](docs/CONFIGURATION-CONTRACT.md), [Statistics](docs/STATISTICAL-CONTRACT.md), [State machine](docs/STATE-MACHINE.md) |
| Public claims and API scope | [Claims](docs/CLAIMS.md), [API policy](docs/API-SURFACE.md), [Release record](release/0.9.0/README.md) |
| Scalar library and local NCP owner | [Adapter guide](crates/galadriel-local-adapter/README.md), its [source profile](crates/galadriel-local-adapter/source-profile.json), [Dependency policy](docs/DEPENDENCY-POLICY.md) |
| Retained wire-0.8, JSONL, Zenoh, producers | [Producer contract](docs/PRODUCER-CONTRACT.md), [Secure deployment](docs/SECURE-DEPLOYMENT.md), [Ecosystem record](docs/ECOSYSTEM-CONNECTIONS.md) |
| MI companion and offline PID | [PID migration](docs/PID_RS_1_0_MIGRATION.md), [Evaluation](docs/EVALUATION.md), [Justification](docs/JUSTIFICATION.md) |
| Downstream advisory use | [Advisory boundary](docs/ADVISORY-BOUNDARY.md), [Ecosystem record](docs/ECOSYSTEM-CONNECTIONS.md) |
| Evidence, qualification, assets, publication | [Maintainer workflows](docs/MAINTAINER_WORKFLOWS.md), [Dependency policy](docs/DEPENDENCY-POLICY.md), [Release runbook](release/0.9.0/RELEASE-RUNBOOK.md), [Review utilities](repo_work/README.md) |
| Historical review relocation | [Archive guide](docs/history/2026-07-10-review/README.md), [Exact identity map](docs/history/2026-07-10-review/relocation.json) |

Inspect the owning schema, implementation, tests, and current evidence before editing.
Use an exact commit as retained identity. A mutable branch name is insufficient.

## Working method

1. Preserve unrelated work and another contributor's active scope.
2. Inventory branches and worktrees before recovery work.
3. Compare five to ten credible approaches before a material design decision.
4. State each approach's assumptions, benefits, failure modes, and decisive experiment.
5. Use independent reviews for separable scientific, security, ownership, and release decisions.
6. Select the strongest compatible design and record unresolved objections.
7. Implement generic, schema-driven behavior.
8. Add a negative control for every new accept path.
9. Add a positive control for every new rejection path.
10. Run the complete applicable gate before presenting a milestone for publication.

A majority vote cannot override a failed scientific or provenance requirement.
External model review is advisory design input. It cannot certify a claim, security property, or release.
Do not branch on sample names, titles, authors, fixture paths, or expected outcomes.
Freeze the source roster, inputs, selection method, seeds, exclusions, and unavailable inputs before inspecting outcomes.
Keep random samples separate from selected challenges and synthetic controls.
Retain failed trials and negative results. Do not replace difficult cases to improve scores.

Recover useful work at the hunk or component level.
Record retained, integrated, superseded, and rejected work with reasons.
Remove a branch or worktree only after preserving its useful changes and audit evidence.
Edit only assigned paths during delegated work.
Report an ownership conflict before editing a shared file.

## Scientific and authority boundaries

- Galadriel is advisory instrumentation, not an authority service.
- An anomaly does not establish tampering, sensor truth, intent, or an attack mechanism.
- Channel attribution identifies statistical inconsistency only. Coordinated consistency-preserving disturbances can remain invisible.
- `Nominal` cannot create permission. `InsufficientEvidence` cannot become `Nominal`.
- Invalid input or configuration returns an error. Do not convert it into a verdict.
- Missing, stale, incompatible, incomplete, or insufficient evidence must retain its explicit unavailable state.
- Preserve `calibrated_posterior = false`. Configuration identities do not validate statistical assumptions.
- NIS and degrees of freedom are dimensionless. Covariance, association, sampling, and uncensored observation assumptions need independent justification.
- Repeated-window results do not imply mission-wide false-alert control. CUSUM state is not a calibrated p-value.
- Cross-channel evidence must bind one track and exact sequence, physical frame, projection context, and frozen pre-update prior.
- Equal dimensions do not prove comparability. Never substitute native mixed-frame residuals or align unequal tails by ordinal position.
- A common projection declaration is producer provenance metadata. It is not cryptographic authentication or proof of physical truth.
- Missingness is not random by default. Association misses and rejected updates can censor large anomalies.
- Library calls cannot infer all-modal silence. Preserve the separate heartbeat and deadline contract for the retained live receiver.
- A dyad cannot support signed-correlation outlier attribution. Preserve unique strict-majority and axis-family requirements.
- Preserve negative results, abstention, unavailable estimands, unsupported states, and every unchanged acceptance threshold.

Accepted whole-stream reports require `AssessmentScope` and sealed `AssessmentBinding`.
The terminal sequence and timestamp must match the input stream.
The remaining labels are validated caller declarations, not authenticated producer identity.
The binding covers the complete scope, suite, and ordered observations.
It cannot be attached to replacement reports or used as a cryptographic signature.

Raw JSONL replay remains unbound and diagnostic-only.
It cannot create a `DefaultReport` or `DependenceAssessmentReport`.
The retained lifecycle adapter derives scope from the admitted producer and exact position.
Every evaluated report must match its lifecycle receipt.
Unsigned in-memory receipts are not a durable journal.

## Optional integrations

The default build remains pure and small.
Keep `dependence`, `ncp`, and `ncp-live` off by default.
The root workspace has exactly seven members.
Its historical lock retains four Git package pins:

| Packages | Exact source revision |
| --- | --- |
| `pid-core`, `pid-runlog` | `1cd2424f7967e1752dcc8e53859e8fdad3566f51` |
| `ncp-core`, `ncp-zenoh` | `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e` |

Those NCP packages use wire `0.8`.
Their pin does not prove compatibility with a different contract, current producer, or remote deployment.
The example `engram/ncp` realm does not create an application integration.
Galadriel has no ROS binding, Haldir runtime edge, or command-authority path.

The independent `galadriel-local-adapter` workspace remains excluded from root Cargo commands.
Its default library has no NCP dependency.
Its optional `ncp-local` feature uses only SDK `1.0.0` at `de751d499b5e07d1c95a072e08255083d77cb38b`.
Use its explicit manifest path and separate source gate.
Do not replace either immutable dependency with a sibling path or broad compatibility tunnel.

The scalar adapter invokes the actual `SubsetMagnitudeV0_9` engine.
It does not fabricate modalities, covariance, signed projection, PID, or producer sequence values.
Its named detector needs at least 32 samples and two modalities.
One Visual channel with three dimensions remains insufficient.
The local application's one-to-three-entity scope does not become a many-sensor or city-array interface.

Preserve whole-frame validation before ingestion, exact consecutive sequences, explicit missing slots, and retirement after availability or continuity loss.
Keep initial birth, active report, and retired window distinct.
The process owns record-only assessments and retained responses.
The supervisor owns authentic process custody, request joins, deadlines, and bounded termination.
Result acknowledgment is separate from durable capture.
Retried retained responses must not repeat detector ingestion.

The runtime dependence companion uses pairwise MI, not PID.
It retains the exact unchanged core verdict and never enters fusion.
Do not add noise, conceal unavailable pairs, or call deterministic deletion extrema confidence intervals.
Offline categorical MGW and continuous Ehrlich PID are distinct functionals with fixed sources and a target.
Shared PID code does not establish independent replication.
No optional research or transport path can create authority.

## Implementation and resource rules

Use `rg` for repository search and `apply_patch` for manual edits.
Do not use destructive Git commands or weaken a guard to make a test pass.
Keep pure domain logic separate from clocks, files, processes, transports, and deployment effects.
Represent identity, time, units, frame, estimand, schema, profile, session, lifecycle, and authority explicitly.
Reject unknown required semantics, duplicate JSON keys, unsafe integers, non-finite values, and ambiguous defaults.
Bound input size and work before expensive processing.
All Rust targets must remain free of unsafe code.
Test disabled-feature behavior when changing an optional feature.

The live payload bound applies after the pinned transport materializes callback bytes.
Do not call it a broker or operating-system memory ceiling.
Secure configuration is not external mTLS/ACL qualification or exclusive router-certificate pinning.
Local puts and valid receipt hashes do not establish receiver delivery or physical truth.

## Release and preservation

The source version is `0.9.0` through a review-gated GitHub research source release process.
Source preparation state for this tree: `UNPUBLISHED_CANDIDATE` with no candidate release date.
Keep every package at `publish = false`.
No project DOI or Zenodo record exists.
Do not add either identifier without author-supplied evidence.

Keep the threat register at `LIVING_UNTIL_CANDIDATE_FREEZE` during implementation.
Only the release operator can set `FROZEN_AT_CANDIDATE` with the final staged release inputs.
Before the threat register enters `FROZEN_AT_CANDIDATE`, the source **SHALL** be
`DATE_BOUND_CANDIDATE` with one ISO `candidate_release_date`.
Every mode and date marker **SHALL** match that date-bound state.
`DATE_BOUND_CANDIDATE` with `LIVING_UNTIL_CANDIDATE_FREEZE` is the permitted
transition before freeze.

The source ledger retains 107 `OPEN` and nine `NOT_CLAIMED` requirements.
The independent adapter source gate cannot change those dispositions, create a release date, or authorize installed or scientific completion.
Restart candidate-bound checks after any tracked change.
Use the exact freeze, signature, tool, resource, and publication procedures in [MAINTAINER_WORKFLOWS.md](docs/MAINTAINER_WORKFLOWS.md).
Never move or reuse `v0.9.0`.

The former `.superstack` records are preserved byte-for-byte in [the historical review archive](docs/history/2026-07-10-review/README.md).
Do not recreate the active folder or edit its archived four-file evidence set.
Preserve the original path, commit, blob, size, and SHA-256 mapping.
Relocation does not refresh the reviews or grant current qualification.

Keep these historical or generated records unchanged except through their explicit owning procedure:

- `evidence/results/post-audit-v1-8a0084f/report.md`
- `release/0.9.0/evidence/ACCEPTANCE-CRITERIA.md`
- `release/0.9.0/reviews/phase-1.md`
- `release/0.9.0/WITHDRAWN-RELEASES.md`
- Historical signed inputs, receipts, source bindings, and archived review bytes

Preserve license files byte-for-byte.
Do not rewrite contract, fixture, schema, or evidence JSON as style work.
Generate current projections through their declared generators.
The living source inventory must cover every current tracked file except its declared self-exclusion.
Do not rewrite immutable historical inventories when paths move.

## Validation, language, and handoff

Run focused checks during implementation.
Use `.github/workflows/ci.yml` and `.github/workflows/local-adapter.yml` for the complete applicable command set.
The exact command and qualification details remain in [MAINTAINER_WORKFLOWS.md](docs/MAINTAINER_WORKFLOWS.md).
Do not describe a focused subset as the full CI mirror.
Do not call a failed, skipped, observational, or unavailable gate passed.

Use the project ASD-STE100 Issue 9 style, without claiming complete dictionary compliance.
Use American English, active voice, one term per concept, and one instruction per procedural sentence.
Keep procedural sentences within 20 words and descriptive sentences within 25 words when practical.
Define abbreviations, mathematical symbols, units, assumptions, and operating bounds.
Preserve exact identifiers, thresholds, commands, historical wording, and legal meaning.
Keep SVGs self-contained, readable, and accessible with adjacent prose alternatives.
Inspect their rendered layout at normal, enlarged, and phone widths.

Never stage secrets or place them in prompts, command arguments, logs, documents, commits, or evidence.
Use the private reporting process in [SECURITY.md](SECURITY.md).
Candidate-controlled qualification commands must not receive ambient credentials or secret values.

Record exact source identity, commands, tools, inputs, exit status, and evidence limitations.
Keep qualification output outside the checkout in a fresh owned directory.
Preserve unrelated work and staged state at handoff.
Do not add AI attribution or co-author trailers.
Only the release operator can merge, publish, tag, delete references, or change repository settings.
A delegated agent prepares a concrete reviewed result and does not attempt those actions.
