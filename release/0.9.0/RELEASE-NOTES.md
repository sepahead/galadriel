# Galadriel 0.9.0

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| DOI | digital object identifier |
| JSON | JavaScript Object Notation |
| ROS | Robot Operating System |
| TLS | Transport Layer Security |

Release author: Sepehr Mahmoudian

Release date: 2026-07-22

Channel: GitHub source release

Galadriel 0.9.0 is the first reviewed research source release of Galadriel's Mirror.
It provides fail-closed cross-sensor statistical consistency monitoring in Rust.
The default core is pure.
Partial information decomposition (PID) and Neuro-Cybernetic Protocol (NCP) integrations need explicit activation.

## What is included

- The magnitude assessment uses normalized innovation squared (NIS) and cumulative sum (CUSUM) methods.
- The consistency assessment uses signed correlation.
- Bounded multi-axis fusion reports insufficient evidence and evidence conflicts explicitly.
- Offline and optional live sidecar ingestion enforce common-projection and frozen-prior boundaries.
- They also enforce configuration, session, producer, lifecycle, and replay boundaries.
- Optional PID diagnostics use pid-rs revision `1cd2424f7967e1752dcc8e53859e8fdad3566f51`.
- Optional NCP wire 0.8 integration uses revision `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`.
- The `ncp-live` feature also activates the pinned Zenoh adapter and Tokio.
- Release tools check the feature graph, public API, and security profile.
- Release tools also check supply-chain policy, fuzz results, mutations, source inventory, and signed inputs.
- Qualification and closure tools retain exact-candidate evidence.
- Supply-chain reports bind each command to its correct output stream.
- The pinned `cargo-deny` license summary uses standard error and requires empty standard output.
- `cargo-audit` JSON uses standard output and retains standard error as diagnostics.
- Finalization verifies each declared stream contract and its diagnostics.
- Exploratory sweeps report both directions and empty partitions.
- Alarm-ranked area under the curve (AUC) calculations account for ties.
- Bounded maneuver studies sample their complete registered windows.

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

Haldir is a prospective downstream consumer.
Galadriel has no Haldir dependency, adapter, route, or runtime edge.
The latest inspected head is `c0e4b3d156500684329a92bcb16e0609894fd738`.
That head activates repository-inventory evidence without a runtime or conformance change.
Future use must start in a record-only mode.
It must have separate admission and remain restrict-only.

### Prisoma

Prisoma is a prospective offline consumer.
Galadriel has no Prisoma dependency, named-sidecar route, or runtime edge.
A future immutable offline comparison remains unqualified.

### Engram and Paper2Brain

Use these projects as realm context only.
Galadriel has no dependency or runtime edge to them.
`engram/ncp` is an example realm value.
Paper2Brain remains unpublished inventory and is not an application integration.

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
It also records the three dated Haldir observations.
Mutable inspected heads record provenance only.
They are not release pins or reciprocal acceptance.

## Deliberate limits

- This is an author-operated research source release.
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
Verify their internal signatures and `SHA256SUMS` files.

GitHub generates source ZIP and tar links automatically.
Use those links only as convenience snapshots.
Do not use them as signed assurance assets.
[`RELEASE-RUNBOOK.md`](https://github.com/sepahead/galadriel/blob/v0.9.0/release/0.9.0/RELEASE-RUNBOOK.md) gives the complete draft-first procedure.

Use [`CITATION.cff`](https://github.com/sepahead/galadriel/blob/v0.9.0/CITATION.cff) for citation metadata.
Cite version 0.9.0 and the exact Git commit used for results.
This release has no project DOI or Zenodo record.
