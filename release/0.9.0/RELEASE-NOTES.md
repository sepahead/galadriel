# Galadriel 0.9.0

Release author: Sepehr Mahmoudian

Release date: 2026-07-21

Channel: GitHub source release

Galadriel 0.9.0 is the first reviewed research source release of Galadriel's Mirror.
It provides fail-closed cross-sensor statistical-consistency monitoring in Rust, with a
pure default core and explicitly activated PID and NCP integrations.

## What is included

- Typed NIS/CUSUM magnitude assessment, signed-correlation consistency assessment,
  bounded multi-axis fusion, and explicit insufficient/conflicting-evidence outcomes.
- Strict common-projection, frozen-prior, configuration-digest, session, producer,
  lifecycle, and replay boundaries for offline and optional live sidecar ingestion.
- Optional PID research diagnostics pinned to pid-rs revision
  `1cd2424f7967e1752dcc8e53859e8fdad3566f51`.
- Optional NCP wire-0.8 integration pinned to revision
  `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`; the `ncp-live` feature additionally
  activates the pinned Zenoh transport adapter and Tokio.
- Exact feature-graph, public-API, security-profile, supply-chain, fuzz, mutation,
  source-inventory, signed-input, qualification, and closure-verification tooling.

## Ecosystem activation

| Project | 0.9.0 relationship | Activation and reason |
| --- | --- | --- |
| pid-rs | Optional linked dependency | Absent from the default CLI; required by `galadriel-pid`, `galadriel-eval`, `galadriel-justify`, and the CLI `pid` feature. |
| NCP | Optional linked/wire dependency | Absent from the default CLI; required by `galadriel-ncp`, `galadriel-eval`, and CLI `ncp`; `ncp-live` adds transport. |
| Crebain | Optional reference producer | No Cargo dependency. A live deployment needs a contract-conforming authorized producer, but it need not be Crebain. |
| Haldir | Prospective downstream consumer | No dependency, adapter, route, or runtime edge. Any future use must start record-only and remain independently admitted and restrict-only. |
| Prisoma | Prospective offline consumer | No dependency, named-sidecar route, or runtime edge; a future immutable offline comparison remains unqualified. |

The exact objects and the two dated Haldir observations are retained in
[`ecosystem-cut.json`](ecosystem-cut.json). Mutable inspected heads are provenance, not
release pins or reciprocal acceptance.

## Deliberate limits

- This is an author-operated research source release, not a production-support,
  deployment-performance, controller-authorization, or independent replication claim.
- No reciprocal final-candidate integration, deployed producer/consumer campaign,
  real-router mTLS/ACL campaign, or downstream policy-effect qualification is claimed.
- Galadriel verdicts are advisory. `Nominal` cannot grant or widen authority, and
  missing, stale, conflicting, or insufficient evidence fails closed.
- The pinned Zenoh client does not by itself establish exclusive router certificate
  pinning; deployments must apply the documented router-authentication mitigation.
- The current retained calibration evidence is diagnostic and does not qualify the
  monitor for restrictive operational policy use.

See [`claims.json`](claims.json),
[`../../docs/ADVISORY-BOUNDARY.md`](../../docs/ADVISORY-BOUNDARY.md), and
[`../../docs/ECOSYSTEM-CONNECTIONS.md`](../../docs/ECOSYSTEM-CONNECTIONS.md) for the
claim-by-claim boundaries.

## Verification and citation

Publication requires a signed annotated `v0.9.0` tag over the exact signed `main`
candidate. Only the qualified source archive, package/SBOM and assurance records,
signed closure manifests, and checksums may be attached. Verify the tag, signatures,
and `SHA256SUMS` before using any published asset; the full operator sequence is in
[`RELEASE-RUNBOOK.md`](RELEASE-RUNBOOK.md).

Use [`../../CITATION.cff`](../../CITATION.cff) with version 0.9.0 and the exact Git
commit used for results. This release intentionally has no project DOI or Zenodo record.
