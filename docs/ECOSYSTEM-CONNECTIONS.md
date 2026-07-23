# Ecosystem connections

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| ADRs | architecture decision records |
| API | application programming interface |
| CLI | command-line interface |
| JSONL | JavaScript Object Notation Lines |
| KSG | Kraskov-Stögbauer-Grassberger |
| NCP | Neuro-Cybernetic Protocol |
| PID | partial information decomposition |
| ROS / ROS 2 | Robot Operating System / Robot Operating System 2 |
| SHA-256 | Secure Hash Algorithm 256 |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| TTLs | time-to-live values |
| UDP | User Datagram Protocol |

Status: dated read-only coordination record for Galadriel 0.9.0. This document
separates dependency identity, component compatibility, and deployed
qualification.

An inspected external head records the inspection source. It is not a permanent
dependency. It does not show that another repository accepted the final Galadriel
release object.

The
[machine-readable 0.9.0 ecosystem cut](../release/0.9.0/ecosystem-cut.json)
retains the exact dated identities.

## Dependency and activation matrix

"Required" applies only to the named build or operating mode. It does not mean
that every Galadriel build needs the project.

| Project | Direction | Status | Purpose |
|---|---|---|---|
| `pid-rs` | Upstream Rust library | Absent from the default CLI build. Its pinned `pid-core` crate is required by `galadriel-pid`, `galadriel-justify`, the evaluation member, and the CLI `pid` feature. `pid-core` resolves `pid-runlog` from the same revision. This connection is linked code, not a runtime service. | Supplies restricted-domain KSG mutual-information and PID primitives for additive research diagnostics. |
| NCP | Upstream Rust libraries and wire or transport contract | Absent from the default CLI build. `ncp-core` is required by `galadriel-ncp`, the evaluation member, and the CLI `ncp` feature. `ncp-live` also requires `ncp-zenoh`, Zenoh, and Tokio. | Supplies wire-0.8 key, version, and contract helpers. It also supplies the optional Zenoh bus. Galadriel owns its sidecar envelopes, bounded JSONL path, and receiver. |
| Crebain | External upstream producer relationship | No Cargo dependency. It is not required for demos, simulation, evaluation, or offline replay. Live use needs an authorized conforming producer. That producer does not have to be Crebain. | Serves as the inspected reference producer for observation and monitor sidecars and the retained registry fixture. |
| Haldir | Prospective downstream consumer | No dependency, adapter, route, or runtime edge in 0.9.0. It is neither required nor an enabled option. | Shows how a future authorization consumer can record evidence. Any later effect must be independently admitted and restrict-only. |
| Prisoma | Prospective downstream offline consumer | No dependency, adapter, route, or runtime edge in 0.9.0. It is neither required nor an enabled option. | Shows a possible immutable covariate or comparator import. Shared NCP or PID dependencies do not establish compatibility or independence. |
| Engram and Paper2Brain | External application names and realm context | No dependency, API, process, adapter, route, or runtime edge. `engram/ncp` is an example realm string, not an application binding. | Separates the realm example from NCP, which is the linked wire and transport interface. The dated Paper2Brain observation records provenance only. |
| ROS / ROS 2 | External robotics middleware | No dependency, message binding, topic, service, action, bridge, node, bag importer, or runtime edge. | Records that a future robotics adapter is a new and separately qualified interface. Sensor terms do not imply this interface. |
| External authority or controller | Prospective downstream policy or control boundary | No command, control, credential, lease, watchdog, or authority path. It is neither required nor enabled. | Preserves advisory-only behavior. A future consumer can record evidence. It can apply only an independently admitted restrict-only policy. |

Galadriel is the center node and has no self-edge. The directed relationship graph
is:

```text
pid-rs -> Galadriel
NCP -> Galadriel
optional conforming producer -> Galadriel
Galadriel -> prospective Haldir or Prisoma consumer
```

Engram/Paper2Brain, ROS, and external authority are explicit non-edges. No edge
returns to an upstream producer or library. Thus, the graph is acyclic and
has no evidence-to-command feedback loop.

The default `cargo build` selects `galadriel-core`, `galadriel-sim`, and the
feature-empty CLI workspace member. It also selects their ordinary registry
dependencies.

`cargo test --workspace --all-features` tests the optional PID and NCP surfaces.
Thus, it resolves their immutable library pins. A default end-user build
does not resolve these pins.

The release feature-graph gate also selects `galadriel-eval` and
`galadriel-justify` directly. This selection proves their documented NCP and PID
dependency edges. It does not infer them from the CLI graph.

## Exact inspection cut

The inspection register uses these repository objects. Rows without a newer date
were observed on 2026-07-18.

| Repository | Inspected object | Meaning for Galadriel 0.9.0 |
|---|---|---|
| pid-rs | `1cd2424f7967e1752dcc8e53859e8fdad3566f51` | Immutable `pid-core` library pin. Its manifest declares 1.0.0. No public v1 tag or published 1.x artifact is claimed. |
| NCP | `10492c81ac671ef1909962a9f1fede33781b9933` | Mutable upstream head inspected for topology. It is not the dependency pin. |
| Crebain | `0a58a5b8dd799884ddb06f1308b1748216fab322` | Mutable producer head inspected for component alignment. It is not a reciprocal Galadriel pin. |
| Haldir discovery observation | remote `main` `0e94f61cfd5c78482198a765157571746a256181` | Mutable downstream design and status observation. No dependency, adapter, route, or runtime edge was found. |
| Haldir later reinspection | remote `main` `dd3d8a1c993721f89a1edb04dec5247761c694ad` | Later 2026-07-18 observation of the same mutable branch. It replaces only the discovery-head reference, not frozen evidence. |
| Haldir 2026-07-22 retained reinspection | remote `main` `c0e4b3d156500684329a92bcb16e0609894fd738` | A retained descendant observation. Its CH-T001 activation adds repository inventory and release evidence. It records no runtime or external-conformance change. |
| Haldir 2026-07-23 reinspection | remote `main` `590ba767b32a27d9dd61a2462968306c1052434e` | A retained descendant observation. Its intervening changes affect audit, evidence, and release tooling only. It records no runtime or external-conformance change. |
| Prisoma | `63cff105e0e40281376e6f827d7782e9b351961a` | Downstream design and status inspection only. No runtime edge exists. |
| Paper2Brain | remote `main` `24e74b781a5bf8af069f69cbc2d0c42d89008211` | Mutable application inventory inspected on 2026-07-23. No Galadriel dependency, API, process, route, adapter, or runtime edge exists. |

The local source inventory records three more non-edges.
Engram has only the example realm-label relationship.
ROS and ROS 2 have no code or runtime edge.
External authority also has no code or runtime edge.

The Paper2Brain object is inspection provenance.
It is not a repository dependency pin.

The release inspection cut retains all four Haldir observations. Commit
`0e94f61cfd5c78482198a765157571746a256181` is an ancestor of
`dd3d8a1c993721f89a1edb04dec5247761c694ad`. That commit is an ancestor of
`c0e4b3d156500684329a92bcb16e0609894fd738`. That commit is an ancestor of
`590ba767b32a27d9dd61a2462968306c1052434e`.

The first interval activates current-head qualification. It also starts CH-T001
repository-inventory work. The second interval completes and activates this
evidence-only task. Its retained downstream-conformance disposition records no
runtime-surface or external-conformance change.

Branch movement does not create a Galadriel dependency or integration. External
heads can change after this cut. Galadriel binds only tracked release inputs and
exact dependency revisions.

Each newer Haldir observation replaces only the preceding mutable-head reference.
It does not rewrite an earlier observation. It also does not rewrite Haldir frozen
audit material, Galadriel frozen evidence, or any historical object.

## pid-rs connection

The default build does not include pid-rs. PID research crates require it.
Galadriel pins `pid-core` to
`1cd2424f7967e1752dcc8e53859e8fdad3566f51`. It enables the
`experimental-pipelines` feature.

That feature enables `experimental-continuous` and
`research-mixed-dimension-pid3`. The upstream default feature set is empty.
Galadriel does not enable `parallel`.

`pid-core` has an unconditional `pid-runlog` dependency. These graphs also resolve
`pid-runlog` 1.0.0 from the same immutable revision. A build requires this pin in
these cases:

- `galadriel-pid`
- `galadriel-justify`
- `galadriel-eval`
- CLI `pid` feature

The connection does not require another process, network connection, or sibling
checkout at runtime.

The connection computes geometry-gated mutual information and shared-exclusion
PID atoms. This evidence is additive research evidence. It cannot repair
unavailable core evidence, create consensus, or override contradictory signed
correlation.

The pinned manifest declares version 1.0.0. Galadriel does not claim an upstream
v1 tag or published 1.x artifact.
[`PID_RS_1_0_MIGRATION.md`](PID_RS_1_0_MIGRATION.md) defines the exact API
adaptation and remaining restricted-domain assumptions.

## NCP connection

The default CLI does not resolve NCP. These selections require `ncp-core`:

- `galadriel-ncp`
- `galadriel-eval`
- CLI `ncp` feature

The CLI `ncp-live` feature also requires `ncp-zenoh`, Zenoh, and Tokio. The
offline `ncp` path parses bounded JSONL and needs no router. `ncp-live` provides
the operational transport path.

The exact live routes are:

```text
{realm}/session/{epoch}/sensor/galadriel-pid
{realm}/session/{epoch}/sensor/galadriel-monitor
```

`OperationalLiveReceiver` subscribes only to these project-owned sidecars. It
does not subscribe to `{realm}/session/{epoch}/observation`. Neither sidecar is a
normative base-plane `SensorFrame`.

Both NCP crates resolve to
`2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`. The annotated `v0.8.0` tag object
is `54008b16ea0c195a4ccc9691cb533dd1153bf7f0`. It resolves to that commit and tree
`488b4add0c43417681c7d87d73e433d46bfa5b78`. The tag and commit have exact object
identities. They have no Git signature.

The pinned NCP crates have empty upstream default feature sets. `ncp-core` also
declares the optional `schema` and `ts` aliases. Galadriel does not select them in
offline, live, or evaluation graphs.

Galadriel pins Zenoh 1.9.0 with defaults disabled. The live graph retains
`shared-memory` and its `zenoh-shm` companion. It also retains TCP, TLS, and UDP
transport features from `ncp-zenoh`.

These compile-time selections do not configure a router. They do not grant a
publisher identity or prove an active ACL.

Galadriel `.ncp-consumer` uses the revision-bound `cargo_rev` and `cargo_lock_rev`
rows. NCP commit `205384508d619923e05aef192bedaeb57cf665fc` is the first checker
revision that recognizes these row types. The inspected head includes that
commit.

The runtime pin `v0.8.0` predates the tooling change. Its checker can skip both
Galadriel rows and report success. Thus, coordinated pin checks must use
tooling at or after the minimum checker commit.

The Galadriel feature-graph gate rejects these descriptor states:

- zero-row
- legacy
- unknown
- partial
- drifted

This tooling requirement does not upgrade the runtime wire or crate pin beyond
0.8.0. The local descriptor read is bounded, no-follow, and nonblocking. The same
gate pins the Tokio feature set for `ncp-live` and `--all-features`. Thus, an
unreviewed capability such as process spawning cannot silently enter these
graphs.

The gate emits this information in its machine-readable report:

- minimum tooling commit
- both descriptor rows
- qualified NCP pin

This report separates checker compatibility from runtime dependency identity.

The inspected NCP head is an unreleased and incompatible wire-1.0 candidate. Its
extension and ecosystem ADRs remain proposals without normative effect. Current
Galadriel named-sensor routes are project-owned wire-0.8 surfaces. They are not
native wire-1.0 extensions. Galadriel claims no NCP 1.0 compatibility.

## Crebain connection

Crebain has component alignment without reciprocal qualification. It is not a
Cargo dependency. It is not required for default builds, simulation, evaluation,
or offline replay.

A live observer needs an independently authorized producer that satisfies the
frozen sidecar contract. Galadriel does not require that producer to be Crebain.

The inspected Crebain sender has two opt-in gates. The build must select its
off-by-default Cargo `ncp` feature. Runtime publication also requires
`CREBAIN_GALADRIEL_ENABLE=1`. The standard Crebain release does not include that
feature.

A successful local publication does not prove Galadriel receiver acceptance or
reciprocal qualification.

The inspected components agree on these items:

- exact observation and monitor routes
- schema `1.0`
- NCP wire `0.8`
- contract hash `d1b50a2d8a265276`
- 64 KiB envelope ceiling
- monitor taxonomy and registry bounds
- byte-identical 3,053-byte registry fixture
- raw SHA-256
  `506ce1437acc20ee5d36fd1e3551dd020095cc4d30d22d959c5df3cca81715a6`
- canonical SHA-256
  `7644ec2bbf0e400303aaad62c647eea36bd919913f1a28a81c52c13e00dd45ba`

These facts prove component and fixture alignment. They do not prove current
reciprocal qualification.

The formal Crebain 0.9 boundary freezes Galadriel
`94e2f8cc01f352d2bf899b7f656997f143a2588f`. It does not silently accept newer
heads. Its older ecosystem baseline records another historical Galadriel object.

The evidence has no final-candidate reciprocal pin. It also lacks complete current
consumer-configuration identity and a secured current-binary multi-process
campaign. Thus, all cross-repository release claims remain `NOT_CLAIMED` or
pending in the release ledger.

## Haldir connection

Haldir is a prospective record-only consumer. It is not part of a Galadriel build
or runtime mode.

The four Haldir objects retained in the inspection cut directly pin NCP 0.8. They contain no
Galadriel dependency, import, deployed route, subscriber, publisher, or adapter.
The descendants add and activate qualification, inventory, and release evidence.
They do not change this boundary.

The 2026-07-23 mutable observation changes no runtime or conformance surface.

The Haldir frozen audit cut records Galadriel
`94e2f8cc01f352d2bf899b7f656997f143a2588f` as an input. This record is not
independently verified compatibility. The Galadriel integration phase has not
started.

A future Haldir adapter can receive only bounded advisory evidence. First, it must
record raw output without policy effect. It must independently admit a future
restrict-only profile.

`StateUnusable` and policy eligibility are Haldir-owned conclusions over
independently authenticated evidence. Haldir must never accept them as Galadriel
fields. No verdict can create or widen authority. This rule applies to `Nominal`.

## Prisoma connection

Prisoma is a prospective offline covariate only. It is not part of a Galadriel
build or runtime mode. It has no Galadriel dependency or adapter.

Its optional NCP 0.8 observer accepts only these exact base session keys:

- `sensor`
- `command`
- `observation`

An existing negative test rejects named sensor subkeys. Thus, Prisoma cannot
consume the two Galadriel sidecar routes by mistake. Its living overlay records an
older Galadriel audit object. The inspected tier records intention or adjacency only.

A future importer must be offline and immutable. It must bind exact Galadriel
source, configuration, profile, session, epoch, source window, and receipt time.
It must reject stale, replayed, malformed, and post-treatment inputs. It must
preserve abstention. It must not invoke the Agent Bridge or change treatment and
result logic.

Both projects use `pid-rs`. Thus, their outputs are not
independent-implementation replication. This common dependency alone does not
prove statistical dependence. Measure dependence from actual inputs,
configuration, and results.

## Engram/Paper2Brain non-edge

`engram/ncp` appears in examples, tests, and the rendered reference deployment. It
is a multi-segment NCP realm. Realm validation treats it as data. Operators can
select another valid realm.

Galadriel has no Paper2Brain dependency, import, API, process, route, adapter, or
runtime discovery path. The release inventory retains the dated remote-head
observation and an absent-edge declaration.

## ROS / ROS 2 non-edge

The workspace has no ROS client dependency or message definition. It has no
topic, service, action, node, launch file, bag reader, or bridge. Sensor and track
terms do not imply ROS compatibility.

A future ROS adapter needs these items before a compatibility claim:

- versioned schema
- timing and frame semantics
- bounded decoding
- replay and staleness rules
- feature isolation
- negative tests
- independent qualification

## External authority non-edge

Galadriel owns no command credential or control route. It cannot issue, widen,
refresh, or restore authority, leases, limits, TTLs, capabilities, or watchdog
state.

A future consumer must start in record-only mode. The consumer must independently
admit each future restrict-only effect. `Nominal` is evidence, never permission.
The command path must remain available without Galadriel.
Its governance must remain independent of Galadriel.

## Qualification boundary

No inspected external object completes current reciprocal integration. A future
claim requires at least these items:

- exact final release pins
- signed envelope and application identity
- stale, replay, and session-mismatch tests
- bounded-flood behavior
- absent or crashed producer equivalence
- negative authority proofs
- retained external secured interoperability evidence

Until independent admission of this evidence, Galadriel 0.9.0 claims only its
local implementation and component-level evidence.
