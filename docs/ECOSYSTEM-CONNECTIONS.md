# Ecosystem connections

Status: dated read-only coordination record for Galadriel 0.9.0. This document separates
dependency identity, component compatibility, and deployed qualification. An inspected
external head is provenance for the inspection, not a permanent dependency or a claim
that another repository has accepted the final Galadriel release object.

The exact dated identities behind this prose are retained in the
[machine-readable 0.9.0 ecosystem cut](../release/0.9.0/ecosystem-cut.json).

## Dependency and activation matrix

“Required” is scoped to the named build or operating mode; it does not mean every
Galadriel build needs that project.

| Project | Direction | Required, optional, or absent | Why Galadriel connects to it |
| --- | --- | --- | --- |
| `pid-rs` | Upstream Rust library | Absent from the default CLI build. Its pinned `pid-core` crate is required by `galadriel-pid`, `galadriel-justify`, the evaluation workspace member, and the CLI `pid` feature; `pid-core` transitively resolves `pid-runlog` from the same revision. It is linked code, not an external runtime service. | Supplies the restricted-domain KSG mutual-information and PID primitives used only for additive research diagnostics. |
| NCP | Upstream Rust libraries and wire/transport contract | Absent from the default CLI build. `ncp-core` is required by `galadriel-ncp`, the evaluation member, and the CLI `ncp` feature; `ncp-live` additionally requires `ncp-zenoh`, Zenoh, and Tokio. | Supplies wire-0.8 key/version/contract helpers and the optional Zenoh bus. Galadriel owns its sidecar envelopes, bounded offline JSONL, and operational receiver. |
| Crebain | External upstream producer relationship | No Cargo dependency and not required for demo, simulation, evaluation, or offline replay. A live deployment needs an authorized contract-conforming producer, but the code does not require that producer to be Crebain. | The inspected Crebain component is the reference producer for Galadriel's observation and monitor sidecars and retained registry fixture. |
| Haldir | Prospective downstream consumer | No dependency, adapter, route, or runtime edge in 0.9.0. It is neither a required nor an enabled optional component. | Documents how a future authorization consumer could record evidence and apply only independently admitted, restrict-only effects. |
| Prisoma | Prospective downstream offline consumer | No dependency, adapter, route, or runtime edge in 0.9.0. It is neither a required nor an enabled optional component. | Documents a possible future immutable covariate/comparator import and why shared NCP or PID dependencies do not establish compatibility or independence. |

The default `cargo build` selects only the `galadriel-core`, `galadriel-sim`, and
feature-empty CLI workspace members, together with their ordinary registry dependencies.
`cargo test --workspace --all-features` deliberately exercises the optional PID and NCP
surfaces as well, so it resolves their immutable library pins even though a default
end-user build does not. The release feature-graph gate also selects `galadriel-eval` and
`galadriel-justify` directly, proving their documented NCP and PID dependency edges rather
than inferring those edges from the CLI graph.

## Exact inspection cut

The 2026-07-18 inspection used these repository objects:

| Repository | Inspected object | Meaning for Galadriel 0.9.0 |
| --- | --- | --- |
| pid-rs | `1cd2424f7967e1752dcc8e53859e8fdad3566f51` | Immutable `pid-core` library pin; its manifest declares 1.0.0, but no public v1 tag or published 1.x artifact is claimed. |
| NCP | `10492c81ac671ef1909962a9f1fede33781b9933` | Mutable upstream head inspected for topology; not the dependency pin. |
| Crebain | `0a58a5b8dd799884ddb06f1308b1748216fab322` | Mutable producer head inspected for component alignment; not a reciprocal Galadriel pin. |
| Haldir discovery observation | remote `main` `0e94f61cfd5c78482198a765157571746a256181` | Mutable downstream design/status observation; no dependency, adapter, route, or runtime edge was found. |
| Haldir later reinspection | remote `main` `dd3d8a1c993721f89a1edb04dec5247761c694ad` | Later 2026-07-18 observation of the same mutable branch; it supersedes only the discovery-head reference and does not replace frozen evidence. |
| Prisoma | `63cff105e0e40281376e6f827d7782e9b351961a` | Downstream design/status inspection only; no runtime edge exists. |

Haldir history retains both observations and places
`0e94f61cfd5c78482198a765157571746a256181` in the ancestry of
`dd3d8a1c993721f89a1edb04dec5247761c694ad`. The intervening commits activate
current-head qualification, freeze the CH-T001 repository-inventory qualification, and
implement the create-once repository inventory. They explain the branch-head movement;
they do not establish a Galadriel dependency or integration.

External heads can change after this cut. Galadriel's local audit binds only tracked
release inputs and exact dependency revisions. The later Haldir observation supersedes
the mutable discovery-head reference only: it does not rewrite the earlier observation,
Haldir's frozen audit material, Galadriel's frozen evidence, or any historical object.

## pid-rs: optional in the default build, required by PID research crates

Galadriel pins `pid-core` to
`1cd2424f7967e1752dcc8e53859e8fdad3566f51` and enables that revision's
`experimental-pipelines` feature. That expands to `experimental-continuous` and
`research-mixed-dimension-pid3`; the upstream default set is empty and Galadriel does
not enable `parallel`. `pid-core` has an unconditional `pid-runlog` dependency, so those
graphs also resolve `pid-runlog` 1.0.0 from the same immutable revision. The dependency is
not present in the default CLI graph. It becomes
a compile-time requirement when building `galadriel-pid`,
`galadriel-justify`, `galadriel-eval`, or the CLI `pid` feature. It does not require a
separate process, network connection, or sibling checkout at runtime.

The connection exists to compute geometry-gated mutual information and shared-exclusion
PID atoms as additive research evidence. It cannot repair unavailable core evidence,
create consensus, or override contradictory signed correlation. The pinned manifest
declares version 1.0.0, but Galadriel does not claim an upstream v1 tag or published 1.x
artifact. The exact API adaptation and remaining restricted-domain assumptions are in
[`PID_RS_1_0_MIGRATION.md`](PID_RS_1_0_MIGRATION.md).

## NCP: exact wire-0.8 dependency

The default CLI does not resolve NCP. Building `galadriel-ncp`, `galadriel-eval`, or the
CLI `ncp` feature requires `ncp-core`; the CLI `ncp-live` feature additionally requires
`ncp-zenoh`, Zenoh, and Tokio. The offline `ncp` path parses bounded JSONL and needs no
router, while `ncp-live` is the operational transport path.

The exact live routes are `{realm}/session/{epoch}/sensor/galadriel-pid` and
`{realm}/session/{epoch}/sensor/galadriel-monitor`.
`OperationalLiveReceiver` subscribes to those two project-owned sidecars; it does not
subscribe to `{realm}/session/{epoch}/observation`, and neither sidecar is a normative
base-plane `SensorFrame`.

Both NCP crates resolve to commit
`2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`. NCP's annotated `v0.8.0` tag object is
`54008b16ea0c195a4ccc9691cb533dd1153bf7f0`; it peels to that commit and tree
`488b4add0c43417681c7d87d73e433d46bfa5b78`. The tag and commit are exact by object
identity but do not contain a Git signature.

The pinned NCP crates have empty upstream default feature sets. `ncp-core` also declares
opt-in `schema` and `ts` aliases; neither is selected in Galadriel's audited offline,
live, or evaluation graphs. Galadriel pins Zenoh 1.9.0 with its defaults disabled; the live graph retains `shared-memory` and its
`zenoh-shm` companion plus the TCP, TLS, and UDP transport features selected by
`ncp-zenoh`. Those compile-time selections still do not configure a router, grant a
publisher identity, or prove an active ACL.

Galadriel's `.ncp-consumer` uses the revision-bound `cargo_rev` and `cargo_lock_rev`
rows. NCP commit `205384508d619923e05aef192bedaeb57cf665fc` is the first checker revision
that recognizes those row kinds, and the inspected head contains it. The runtime pin
`v0.8.0` predates that tooling change: its checker can skip both Galadriel rows and report
success without validating this descriptor. Coordinated pin checking must therefore use
tooling at or after that exact minimum commit. Galadriel independently rejects a
zero-row, legacy, unknown, partial, or drifted descriptor in its feature-graph gate; this
tooling requirement does not upgrade the runtime wire or crate pin beyond 0.8.0.
That local read is bounded, no-follow, and nonblocking. The same gate pins the resolved
Tokio feature set for `ncp-live` and `--all-features`, so an unreviewed capability such
as process spawning cannot enter those graphs silently.
That gate emits the minimum tooling commit, both descriptor rows, and the qualified NCP
pin in its machine-readable report, keeping checker compatibility distinct from runtime
dependency identity in retained evidence.

The inspected NCP head is an unreleased, incompatible wire-1.0 candidate. Its extension
and ecosystem ADRs remain proposed and have no normative effect. Current Galadriel routes
`sensor/galadriel-pid` and `sensor/galadriel-monitor` are project-owned named-sensor
surfaces under wire 0.8; they are not native wire-1.0 extensions. No 1.0 compatibility is
claimed.

## Crebain: component alignment without reciprocal qualification

Crebain is not a Cargo dependency and is not required for Galadriel's default build,
simulation, evaluation, or offline replay. A live observer requires an independently
authorized producer that satisfies the frozen sidecar contract; Galadriel does not
hard-code Crebain as the only possible producer.

The inspected Crebain sender is doubly opt-in: its off-by-default Cargo `ncp` feature
must be compiled, and runtime publication additionally requires
`CREBAIN_GALADRIEL_ENABLE=1`. Crebain's standard release omits that feature. A successful
local publish call still does not prove Galadriel receiver acceptance or reciprocal
qualification.

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

Haldir is not part of any Galadriel build or runtime mode. Both the discovery object
`0e94f61cfd5c78482198a765157571746a256181` and its later inspected descendant
`dd3d8a1c993721f89a1edb04dec5247761c694ad` directly pin NCP 0.8 but contain no
Galadriel dependency, import, deployed route, subscriber, publisher, or adapter. The
later object adds Haldir qualification and repository-inventory work; it does not change
that boundary. Haldir's frozen audit cut records Galadriel
`94e2f8cc01f352d2bf899b7f656997f143a2588f` as an input, not as independently
verified compatibility. Its Galadriel integration phase remains not started.

A future Haldir adapter may only receive bounded advisory evidence. It must first record
raw Galadriel output without policy effect, then independently admit any later
restrict-only profile. `StateUnusable` and policy eligibility are Haldir-owned conclusions
over independently authenticated evidence; they must never be accepted as fields asserted
by Galadriel. No Galadriel verdict, including `Nominal`, may create or widen authority.

## Prisoma: prospective offline covariate only

Prisoma is not part of any Galadriel build or runtime mode and has no Galadriel dependency
or adapter. Its optional NCP 0.8 observer accepts only
the exact base session keys `sensor`, `command`, and `observation`; an existing negative
test rejects named sensor subkeys. It therefore cannot accidentally consume Galadriel's
two named sidecar routes. Prisoma's living overlay records an older Galadriel audit object
and classifies the relationship as E0.

Any future importer must be offline and immutable. It must bind exact Galadriel source and
configuration/profile identities, session/epoch, source window, and receipt time; reject
stale, replayed, malformed, and post-treatment inputs; preserve abstention; and remain
unable to invoke the Agent Bridge or alter treatment/result logic. Because both projects
use `pid-rs`, their outputs do not constitute independent-implementation replication.
That common implementation dependency does not itself prove statistical dependence
between outputs; any such dependence must be measured from the actual inputs,
configuration, and results.

## Qualification boundary

None of the inspected external objects closes current reciprocal integration. A future
claim requires, at minimum, exact final release pins, signed envelope/application identity,
stale/replay/session mismatch coverage, bounded-flood behavior, absent/crashed-producer
equivalence, negative authority proofs, and retained external secured interoperability
evidence. Until those artifacts exist and are independently admitted, Galadriel 0.9.0
claims only its local implementation and component-level evidence.
