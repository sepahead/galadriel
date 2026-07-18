# Ecosystem connections

Status: dated read-only coordination record for Galadriel 0.9.0. This document separates
dependency identity, component compatibility, and deployed qualification. An inspected
external head is provenance for the inspection, not a permanent dependency or a claim
that another repository has accepted the final Galadriel release object.

## Exact inspection cut

The 2026-07-18 inspection used these repository objects:

| Repository | Inspected object | Meaning for Galadriel 0.9.0 |
| --- | --- | --- |
| NCP | `10492c81ac671ef1909962a9f1fede33781b9933` | Mutable upstream head inspected for topology; not the dependency pin. |
| Crebain | `0a58a5b8dd799884ddb06f1308b1748216fab322` | Mutable producer head inspected for component alignment; not a reciprocal Galadriel pin. |
| Haldir | remote `main` `0e94f61cfd5c78482198a765157571746a256181` | Downstream design/status inspection only; no runtime edge exists. |
| Prisoma | `63cff105e0e40281376e6f827d7782e9b351961a` | Downstream design/status inspection only; no runtime edge exists. |

External heads can change after this cut. Galadriel's local audit binds only tracked
release inputs and exact dependency revisions. Frozen evidence in another repository is
not silently rewritten to follow a newer Galadriel candidate.

## NCP: exact wire-0.8 dependency

Galadriel's optional NCP features resolve `ncp-core` and `ncp-zenoh` to commit
`2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`. NCP's annotated `v0.8.0` tag object is
`54008b16ea0c195a4ccc9691cb533dd1153bf7f0`; it peels to that commit and tree
`488b4add0c43417681c7d87d73e433d46bfa5b78`. The tag and commit are exact by object
identity but do not contain a Git signature.

The inspected NCP head is an unreleased, incompatible wire-1.0 candidate. Its extension
and ecosystem ADRs remain proposed and have no normative effect. Current Galadriel routes
`sensor/galadriel-pid` and `sensor/galadriel-monitor` are project-owned named-sensor
surfaces under wire 0.8; they are not native wire-1.0 extensions. No 1.0 compatibility is
claimed.

## Crebain: component alignment without reciprocal qualification

The inspected Crebain component and Galadriel agree on:

- exact observation and monitor routes;
- schema `1.0`, NCP wire `0.8`, and contract hash `d1b50a2d8a265276`;
- a 64 KiB envelope ceiling, monitor taxonomy, and registry bounds; and
- a byte-identical 3,053-byte registry fixture with raw SHA-256
  `506ce1437acc20ee5d36fd1e3551dd020095cc4d30d22d959c5df3cca81715a6` and canonical
  SHA-256 `7644ec2bbf0e400303aaad62c647eea36bd919913f1a28a81c52c13e00dd45ba`.

Those facts prove component and fixture alignment. They do not prove current reciprocal
qualification. Crebain's formal 0.9 boundary freezes Galadriel
`94e2f8cc01f352d2bf899b7f656997f143a2588f` and explicitly does not silently adopt
later heads. Its older ecosystem baseline records another historical Galadriel object.
There is no retained final-candidate pin, complete current consumer-configuration
identity, or secured current-binary multi-process campaign. All cross-repository release
claims therefore remain `NOT_CLAIMED` or pending as recorded in the release ledger.

## Haldir: prospective record-only consumer

The inspected Haldir object directly pins NCP 0.8 but contains no Galadriel dependency,
import, deployed route, subscriber, publisher, or adapter. Its frozen audit cut records
Galadriel `94e2f8cc01f352d2bf899b7f656997f143a2588f` as an input, not as independently
verified compatibility. Its Galadriel integration phase remains not started.

A future Haldir adapter may only receive bounded advisory evidence. It must first record
raw Galadriel output without policy effect, then independently admit any later
restrict-only profile. `StateUnusable` and policy eligibility are Haldir-owned conclusions
over independently authenticated evidence; they must never be accepted as fields asserted
by Galadriel. No Galadriel verdict, including `Nominal`, may create or widen authority.

## Prisoma: prospective offline covariate only

Prisoma has no Galadriel dependency or adapter. Its optional NCP 0.8 observer accepts only
the exact base session keys `sensor`, `command`, and `observation`; an existing negative
test rejects named sensor subkeys. It therefore cannot accidentally consume Galadriel's
two named sidecar routes. Prisoma's living overlay records an older Galadriel audit object
and classifies the relationship as E0.

Any future importer must be offline and immutable. It must bind exact Galadriel source and
configuration/profile identities, session/epoch, source window, and receipt time; reject
stale, replayed, malformed, and post-treatment inputs; preserve abstention; and remain
unable to invoke the Agent Bridge or alter treatment/result logic. Because both projects
use `pid-rs`, their PID outputs are correlated evidence rather than independent
replication.

## Qualification boundary

None of the inspected external objects closes current reciprocal integration. A future
claim requires, at minimum, exact final release pins, signed envelope/application identity,
stale/replay/session mismatch coverage, bounded-flood behavior, absent/crashed-producer
equivalence, negative authority proofs, and retained external secured interoperability
evidence. Until those artifacts exist and are independently admitted, Galadriel 0.9.0
claims only its local implementation and component-level evidence.
