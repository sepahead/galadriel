# Galadriel 0.9.0

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| AUC | area under the receiver operating characteristic curve |
| ASCII | American Standard Code for Information Interchange |
| CLI | command-line interface |
| CUSUM | cumulative sum |
| DOI | digital object identifier |
| JSON | JavaScript Object Notation |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |
| ROS | Robot Operating System |
| SHA-256 | Secure Hash Algorithm 256 |
| TLS | Transport Layer Security |
| URL | Uniform Resource Locator |
| ZIP | ZIP archive format |

Release author: Sepehr Mahmoudian

Source preparation state at generation: UNPUBLISHED CANDIDATE

Candidate release date at generation: NOT SET

Intended channel: review-gated GitHub research source release

Version 0.9.0 provides the author-reviewed, machine-assisted research source for Galadriel's Mirror through the stated channel.
It provides a fail-closed implementation for cross-sensor statistical consistency monitoring in Rust.
The default core contains pure domain logic.
Partial information decomposition (PID) and Neuro-Cybernetic Protocol (NCP) integrations need explicit activation.

## What is included

### Detector and integration changes

- The magnitude assessment uses normalized innovation squared (NIS) and cumulative sum (CUSUM) methods.
- The consistency assessment uses signed correlation.
- Bounded multi-axis fusion reports insufficient evidence and evidence conflicts explicitly.
- A finite degenerate projection axis returns insufficient evidence.
- That axis withholds all channel corroboration values.
- It cannot suppress independent magnitude evidence.
- Accepted whole-stream assessment now requires `AssessmentScope`.
- The scope binds producer, session, epoch, stream, state generation, terminal sequence,
  terminal timestamp, and clock domain.
- Core checks the terminal sequence and terminal-frame timestamp against the stream.
- Assessment binding v2 binds the scope, release suite, and exact ordered observations.
- Scope labels provide internal identity integrity. They do not authenticate a producer.
- Optional PID analysis abstains before it adds observation noise to a degenerate column.
- Raw JSONL replay is unbound and diagnostic-only.
- Raw replay cannot create a sealed core or PID whole-stream report.
- Offline and optional live sidecar ingestion enforce common-projection and frozen-prior boundaries.
- They also enforce configuration, session, producer, lifecycle, and replay boundaries.
- Session and producer fields use the Galadriel core identity grammar.
- The pre-release schemas narrowed these fields from generic NCP segments to that grammar.
- Authorized producers must use the narrower grammar before live operation.
- Identity constructors reject oversized or noncanonical input before retained-state allocation or subscription effects.
- Identity errors no longer retain the rejected text.
- The runtime overflow guard covers frame, reorder, steady-heartbeat, and initial-heartbeat deadlines.
- Live standard output uses `galadriel.observe.lifecycle.v1`.
- Each JSON line includes `calibrated_posterior=false`, one receipt, and ordered assessments.
- The CLI emits a new rejection or fault receipt before it exits with failure.
- Receipt verification rejects bounded detector-impossible assessment shapes.
- Receipt verification does not authenticate or durably retain the record.
- These source changes are incompatible with earlier development snapshots.
- Optional PID diagnostics use pid-rs revision `1cd2424f7967e1752dcc8e53859e8fdad3566f51`.
- Optional NCP wire 0.8 integration uses revision `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`.
- The `ncp-live` feature also activates the pinned Zenoh adapter and Tokio.
- Direct `galadriel-ncp` feature `zenoh` activates the same live stack.

### Release assurance

- Release tools check the feature graph, public API, and security profile.
- The active audit-input pair uses schema `galadriel.frozen-audit-inputs.v2`.
- It binds each path, Git mode, blob identifier, SHA-256 value, and size.
- One bounded index capture supplies source semantics and release-tool coverage.
- It also binds each external handoff regular-file mode.
- The generated audit manifest uses schema `galadriel.release-audit-manifest.v2`.
- Each artifact row binds its path, Git mode, blob identifier, SHA-256 value, size, and purpose.
- All audit semantics use one bounded index capture and one held-root worktree transaction.
- Candidate construction stages the requirements ledger, signed pair, and audit manifest in that order.
- Release-input drift aborts that transaction and requires a new signed pair.
- Release tools also check supply-chain policy, fuzz results, mutations, source inventory, and signed inputs.
- Focused mutation evidence covers the acceptance-estimation functions that the broad gate excludes.
- Mutation evidence retains seven outcome files, five run receipts, and one `git.diff`.
- Four receipts bind the broad shards.
- One receipt binds the three focused outcomes.
- All four broad shards and all three focused outcomes are exact-candidate gates.
- The observational mutation-baseline job is residual evidence, not a successful gate.
- Exact mutation commands use environment schema `galadriel.mutation-environment.v2`.
- They require the Linux process file system (`procfs`), process file descriptors, and serialized child-subreaper ownership.
- They use a stop-before-exec gate and reap the root after candidate-tree extinction.
- They fail before process creation when a required host control is unavailable.
- They verify the default disposition of the child-status signal (`SIGCHLD`) at each containment checkpoint.
- They also verify the active child-subreaper state.
- Control drift poisons the process and prevents verified success.
- The runner cleans stable process file descriptor (`pidfd`) identities when extinction remains provable.
- A control change that starts and ends between checkpoints is not observable.
- The contract requires exclusive single-threaded ownership by the trusted runner.
- An uninterruptible process can outlive the stop deadline and fails the run.
- This cleanup control is not a control group, container, or deployment-isolation boundary.
- Qualification records use schema `galadriel.candidate-qualification.v3`.
- A passing qualification must retain exactly 22 auxiliary command receipts.
- A passing qualification must compare one source archive, seven package archives, and seven software bills of materials twice.
- Each qualification command must use a stop-before-exec gate and fixed resource limits.
- Qualification requires macOS `kqueue` and `/usr/bin/sandbox-exec`.
- One mode-0500 dispatch binds 19 required command names.
- It binds direct Apple developer Git, its developer tools, and `CPython 3.14.6`.
- The sandbox denies direct execution of `/usr/bin/git` and `/usr/bin/python3`.
- The qualifier signals only the original process group before it reaps the root.
- It does not signal an escaped numeric process identifier.
- An observed escaped sandbox identity fails the run.
- After root reap, it uses only read-only extinction checks.
- macOS does not provide atomic recursive descendant tracking.
- A short-lived reparented process can exit between scans.
- The sandbox-identity scan detects an active detached process that retains that identity.
- The inherited sandbox and resource limits apply before candidate execution.
- A sandboxed process can request work from an existing external service.
- The process scan cannot attribute that external service work.
- The release input pins the external RustSec database identity at the 2026-07-23 inspection cut.
- The pinned RustSec inventory contains 1,187 entries.
- Its SHA-256 value is `bfc26634ed164598c75c91fc462f0fa527b73634859faeb9476f2631bf529619`.
- The current-stable checks use Rust and Cargo 1.97.1.
- Canonical asset construction, verification, and reconstruction use CPython 3.14.6.
- Qualification uses the exact 16-key base environment and isolated writable tool state.
- Qualification rejects a file, directory, or link at each Cargo configuration path.
- Qualification refreshes public `main` through the literal repository URL and exact refspec.
- It rejects local Git settings that can redirect the fetch, run a helper, or weaken object checks.
- Candidate evidence has an exact six-file flat inventory.
- Each candidate-evidence file has a 1 GiB limit.
- The complete candidate-evidence set has a 4 GiB limit.
- The host compares the source, private snapshot, quarantine, and installed evidence.
- Candidate summaries use schema `galadriel.evidence.summary.v3`.
- Candidate manifests use schema `galadriel.evidence.manifest.v3`.
- Acceptance uses profile `galadriel-0.9-frozen-acceptance-metrics-v3`.
- Bootstrap uses profile `splitmix64-rejection-group-metric-v1`.
- The bootstrap profile uses SplitMix64 with unbiased rejection sampling over complete tracks.
- The qualifier builds the evidence runner in a separate command.
- It creates a private directory with mode `0700`.
- It copies the runner into that directory through no-follow descriptors with mode `0500`.
- It executes that exact snapshot directly.
- The manifest binds the exact runner digest, candidate commit, and candidate tree.
- The host parses only bounded bytes captured from the verified snapshot.
- It streams each ordered trial and rebuilds the complete summary and report.
- It verifies the accepted configuration, manifest, and exact checksum document.
- It evaluates acceptance only from the rebuilt holdout summary.
- Finalization repeats the replay against the signed outer inventory.
- Only a deep qualification run can have qualification status `PASS`.
- Critical host Git and SSH operations pin direct Apple developer Git, `/usr/bin/ssh-add`, and `/usr/bin/ssh-keygen`.
- The host verifies each root-owned no-follow identity before and after execution.
- It pins `sandbox-exec` to `/usr/bin/sandbox-exec` and its expected byte identity.
- It records the resolved path, owner, group, and mode.
- The candidate sandbox denies signal operations by default.
- It permits signals only to self and children.
- The frozen 100-track design cannot pass `GLD-090-ACC-001` or `GLD-090-ACC-006`.
- These criteria need at least 369 and 738 tracks.
- The current grid and work ceiling permit at most 248 holdout tracks.
- An otherwise passing qualification therefore records `NARROWED_REVIEW_REQUIRED`.
- A signed human decision must select `NARROWED_GO` or `NO_GO`.
- `GO` is prohibited while an acceptance criterion fails.
- Source-archive verification binds type, mode, owner, time, and content to the exact Git tree.
- Qualification and closure tools retain exact-candidate evidence.
- Supply-chain reports bind each command to its correct output stream.
- The pinned `cargo-deny` license summary uses standard error and requires empty standard output.
- The license inventory covers the 382-package host-filtered graph.
- It is not a complete all-target inventory of the 437-package Cargo graph.
- `cargo-audit` JSON uses standard output and retains standard error as diagnostics.
- Finalization verifies each declared stream contract and its diagnostics.
- Exploratory sweeps report both directions and empty partitions.
- Alarm-ranked area under the curve (AUC) calculations account for ties.
- Bounded maneuver studies sample their complete registered windows.

## Evidence scope

A passing qualification result covers the exact source candidate and recorded host contract.
It can coexist with a failed candidate acceptance result.
That combination requires a signed narrowed publication decision.
It does not prove deployment qualification, production support, archival preservation, or independent replication.

## Ecosystem activation

### pid-rs

pid-rs is optional in the default command-line interface (CLI) build.
These paths require pid-rs:

- `galadriel-pid`
- `galadriel-eval`
- `galadriel-justify`
- the CLI `pid` feature

### NCP

NCP is optional in the default CLI build.
`galadriel-ncp`, `galadriel-eval`, and the CLI `ncp` feature require NCP.
CLI `ncp-live` or direct `galadriel-ncp` feature `zenoh` adds the transport dependencies.
Galadriel remains pinned to immutable NCP `v0.8.0` and wire `0.8`.
Its implemented sidecars are historical NCP 1.0 migration input.
They are not native-1.0 role evidence.

The 2026-08-03 NCP status inspection is bound to
[commit `1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd`](https://github.com/sepahead/NCP/commit/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd).
That commit is the unreleased and release-blocked `1.0.0-rc.1` candidate.
It uses wire `1.0` and compact `CONTRACT_HASH` `163acc57d8a62b66`.
The latest immutable NCP release remains `v0.8.0` and uses a different wire.

The pinned [NCP task ledger](https://github.com/sepahead/NCP/blob/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd/evidence/implementation/task-ledger.v1.json)
records `G03` as `OPEN`.
`G03` depends on `X02`, which is also `OPEN`, so `G03` is not dependency-ready.
The two external role qualifications have no exact evidence and remain **NOT RUN**.

The pinned [NCP ecosystem blueprint](https://github.com/sepahead/NCP/blob/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd/docs/handoff/NCP_V1_0_ECOSYSTEM_FINALIZATION_BLUEPRINT.md)
defines the role boundary.
The `Galadriel NCP observer` requires a read-only observer principal and an exact
bounded grant.
It cannot publish, mutate lifecycle state, claim authority, or issue an ESTOP.
The release-facing `Galadriel raw-advisory publisher` is the blueprint's
`Galadriel assessor` surface.
It requires a separate principal and a default-off push-only raw-evidence path.
Its payload contains raw verdict and evidence provenance with an optional
non-authoritative requested effect.
It cannot reuse observer credentials, self-admit, derive `StateUnusable`, grant
or widen authority, or encode an authoritative effect, `ALLOW`, or command.
No native-1.0 raw-advisory publisher exists.
Galadriel 0.9 records native-1.0 integration as `NOT_CLAIMED`.
That Galadriel claim tier is separate from NCP's external **NOT RUN** gate state.

### Crebain

Crebain is an optional reference producer.
Galadriel has no Cargo dependency on Crebain.
Live use needs an authorized producer that conforms to the producer contract.
That producer does not have to be Crebain.

### Haldir

Haldir is a prospective record-only consumer.
Galadriel has no Haldir dependency, adapter, route, or runtime edge.
The retained 2026-07-23 inspection-cut object is `590ba767b32a27d9dd61a2462968306c1052434e`.
That object descends from the 2026-07-22 observation.
Its intervening changes affect audit, evidence, and release tooling only.
It creates no runtime or conformance edge.

Future use must start in a record-only mode.
It must have separate admission and remain restrict-only.

### Prisoma

Prisoma is a prospective offline consumer.
Galadriel has no Prisoma dependency, named-sidecar route, or runtime edge.
A future immutable offline comparison has no 0.9.0 qualification evidence.

### Engram and Paper2Brain

Use these application names as realm context only.
Galadriel has no dependency or runtime edge to them.
`engram/ncp` is an example realm value.
The 2026-07-23 read-only Paper2Brain observation records remote `main` at
`24e74b781a5bf8af069f69cbc2d0c42d89008211`.
This mutable observation is not a dependency pin or application integration.

### ROS and ROS 2

Galadriel has no Robot Operating System (ROS) middleware edge.
It has no ROS dependency, binding, topic, bridge, node, or bag import.
This release makes no ROS compatibility claim.

### External authority

Galadriel has no command edge to an authority service or controller.
It has no command, credential, lease, watchdog, or authority path.
Advisory evidence cannot grant or widen permission.

The ecosystem graph is acyclic.
Optional libraries and a producer that conforms point into Galadriel.
Only prospective evidence-consumer relationships point outward.
No command or feedback edge returns to an upstream component.

Six absolute `v0.9.0` links in these notes are publication targets.
They resolve only after the release operator pushes the immutable tag to the canonical repository.
The publication procedure checks all six after that push and before release publication.

[`ecosystem-cut.json`](https://github.com/sepahead/galadriel/blob/v0.9.0/release/0.9.0/ecosystem-cut.json) records the exact objects.
It separates the immutable 2026-08-03 NCP release-status snapshot from Galadriel's wire-0.8 dependency pin.
It also records the four dated Haldir observations and the dated Paper2Brain observation.
Mutable inspected heads record provenance only.
They are not release pins or reciprocal acceptance.

## Deliberate limits

- Evidence is author-operated. The publication channel is review-gated.
- It does not claim production support or deployment performance.
- It does not claim controller authorization or independent replication.
- It does not claim reciprocal final-candidate integration.
- It does not claim a deployed producer or consumer campaign.
- It does not claim a real-router mutual TLS or access control list campaign.
- It does not claim qualification of a downstream policy effect.
- Galadriel results are advisory.
- `Nominal` cannot grant or widen authority.
- Evidence that is missing, stale, in conflict, or insufficient fails closed.
- The pinned Zenoh client does not prove exclusive router certificate selection.
- A deployment must apply the documented router authentication control.
- Current calibration evidence is diagnostic.
- It does not qualify the monitor for restrictive operational policy use.

See these records for claim boundaries:

- [`claims.json`](https://github.com/sepahead/galadriel/blob/v0.9.0/release/0.9.0/claims.json)
- [`docs/ADVISORY-BOUNDARY.md`](https://github.com/sepahead/galadriel/blob/v0.9.0/docs/ADVISORY-BOUNDARY.md)
- [`docs/ECOSYSTEM-CONNECTIONS.md`](https://github.com/sepahead/galadriel/blob/v0.9.0/docs/ECOSYSTEM-CONNECTIONS.md)

## Verification and citation

Publication requires a signed annotated `v0.9.0` tag.
The tag must identify the exact signed `main` candidate.

The attached assurance set has exactly four files:

- `galadriel-0.9.0-qualification.tar`
- `galadriel-0.9.0-closure.tar`
- `galadriel-0.9.0-release-asset-map.json`
- `galadriel-0.9.0-release-asset-map.json.sig`

Verify the `galadriel-release-assets` signature with an independent trust root.
Verify the candidate, tree, tag, and tar inventories in the signed map.
Reconstruct both tiers with the release tool.
The tool authenticates both internal signatures during build, verification, and reconstruction.
It binds both tiers to the expected candidate commit and tree.
It verifies each complete signed inventory and `SHA256SUMS` file.

GitHub generates source ZIP and tar links automatically.
Use those links only as convenience snapshots.
Do not use them as signed assurance assets.
[`RELEASE-RUNBOOK.md`](https://github.com/sepahead/galadriel/blob/v0.9.0/release/0.9.0/RELEASE-RUNBOOK.md) gives the complete draft-first procedure.

Use [`CITATION.cff`](https://github.com/sepahead/galadriel/blob/v0.9.0/CITATION.cff) for source citation metadata.
Always cite source version 0.9.0 and the exact Git commit used for results.
Do not infer GitHub publication, a DOI, or a Zenodo record from the citation file.
After publication, the immutable signed tag is an additional stable locator.
Version 0.9.0 has no project DOI or Zenodo record.
