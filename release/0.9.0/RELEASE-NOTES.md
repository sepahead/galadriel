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
| ZIP | ZIP archive format |

Release author: Sepehr Mahmoudian

Release date: 2026-07-23

Channel: review-gated GitHub research source release

Galadriel 0.9.0 is the first review-gated research source release of Galadriel's Mirror.
It provides fail-closed cross-sensor statistical consistency monitoring in Rust.
The default core is pure.
Partial information decomposition (PID) and Neuro-Cybernetic Protocol (NCP) integrations need explicit activation.

## What is included

- The magnitude assessment uses normalized innovation squared (NIS) and cumulative sum (CUSUM) methods.
- The consistency assessment uses signed correlation.
- Bounded multi-axis fusion reports insufficient evidence and evidence conflicts explicitly.
- Offline and optional live sidecar ingestion enforce common-projection and frozen-prior boundaries.
- They also enforce configuration, session, producer, lifecycle, and replay boundaries.
- Session and producer fields use the Galadriel core identity grammar.
- The pre-release schemas narrowed these fields from generic NCP segments to that grammar.
- Authorized producers must use the narrower grammar before live operation.
- Identity constructors reject oversized or noncanonical input before retained-state allocation or subscription effects.
- Identity errors no longer retain the rejected text.
- These source changes are incompatible with earlier development snapshots.
- Optional PID diagnostics use pid-rs revision `1cd2424f7967e1752dcc8e53859e8fdad3566f51`.
- Optional NCP wire 0.8 integration uses revision `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`.
- The `ncp-live` feature also activates the pinned Zenoh adapter and Tokio.
- Release tools check the feature graph, public API, and security profile.
- Release tools also check supply-chain policy, fuzz results, mutations, source inventory, and signed inputs.
- Focused mutation evidence covers the acceptance-estimation functions that the broad gate excludes.
- Mutation evidence retains seven outcome files, five run receipts, and one `git.diff`.
- Four receipts bind the broad shards.
- One receipt binds the three focused outcomes.
- All four broad shards and all three focused outcomes are exact-candidate gates.
- The observational mutation-baseline job is residual evidence, not a successful gate.
- Qualification records use schema `galadriel.candidate-qualification.v3`.
- A passing qualification must retain exactly 22 auxiliary command receipts.
- A passing qualification must compare one source archive, seven package archives, and seven software bills of materials twice.
- Each qualification command must use a stop-before-exec gate and fixed resource limits.
- macOS does not provide atomic recursive descendant tracking.
- A short-lived reparented process can exit between scans.
- The process scan detects a detached process that remains active.
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
- It parses only bounded JSON bytes captured from the verified snapshot.
- Only a deep qualification run can have qualification status `PASS`.
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
The `ncp-live` feature adds the transport dependencies.

### Crebain

Crebain is an optional reference producer.
Galadriel has no Cargo dependency on Crebain.
A live deployment needs an authorized producer that conforms to the producer contract.
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
A future immutable offline comparison remains unqualified.

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

[`ecosystem-cut.json`](https://github.com/sepahead/galadriel/blob/v0.9.0/release/0.9.0/ecosystem-cut.json) records the exact objects.
It also records the four dated Haldir observations and the dated Paper2Brain observation.
Mutable inspected heads record provenance only.
They are not release pins or reciprocal acceptance.

## Deliberate limits

- This is an author-operated, review-gated research source release.
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

Use [`CITATION.cff`](https://github.com/sepahead/galadriel/blob/v0.9.0/CITATION.cff) for citation metadata.
Cite version 0.9.0 and the exact Git commit used for results.
This release has no project DOI or Zenodo record.
