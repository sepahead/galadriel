# Ecosystem connections

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| ADRs | architecture decision records |
| API | application programming interface |
| CLI | command-line interface |
| JSONL | JavaScript Object Notation Lines |
| KSG | Kraskov–Stögbauer–Grassberger |
| mTLS | mutual Transport Layer Security |
| NCP | Neuro-Cybernetic Protocol |
| PID | partial information decomposition |
| ROS / ROS 2 | Robot Operating System / Robot Operating System 2 |
| SHA-256 | Secure Hash Algorithm 256 |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| TTLs | time-to-live values |
| UDP | User Datagram Protocol |

Status: dated read-only coordination record for Galadriel 0.9.0.
This document separates dependency identity, component compatibility, and
deployment qualification.

An inspected external head records the inspection source. It is not a permanent
dependency. It does not show that another repository accepted the final Galadriel
release object.

The
[machine-readable 0.9.0 ecosystem cut](../release/0.9.0/ecosystem-cut.json)
retains the exact dated identities.

## Dependency and activation matrix

`required` applies only to the named build or operating mode. It does not mean
that every Galadriel build needs the project.

| Project | Direction | Status | Purpose |
|---|---|---|---|
| `pid-rs` | Upstream Rust library | Absent from the default CLI build. Its pinned `pid-core` crate is required by `galadriel-dependence`, `galadriel-justify`, the evaluation member, and the CLI `dependence` feature. No resolved Galadriel feature profile contains `pid-runlog`. This connection is linked code, not a runtime service. | Supplies stable budgeted report-first KSG for the opt-in in-process/library MI companion and separate categorical MGW and continuous Ehrlich–Schick-Poland–Makkeh–Lanfermann–Wollstadt–Wibral PID primitives for offline studies. |
| NCP | Upstream Rust libraries and wire or transport contract | Absent from the default CLI build. `ncp-core` is required by `galadriel-ncp`, the evaluation member, and the CLI `ncp` feature. CLI `ncp-live` or direct `galadriel-ncp` feature `zenoh` also requires `ncp-zenoh`, Zenoh, and Tokio. | Supplies wire-0.8 key, version, and contract helpers. It also supplies the optional Zenoh bus. Galadriel owns its sidecar envelopes, bounded JSONL path, and receiver. |
| Crebain | External upstream producer and offline-fixture relationship | No Cargo dependency. It is not required for default demos, simulation, evaluation, replay, or live operation. Live use needs an authorized conforming producer. That producer need not be Crebain. `galadriel-justify` separately embeds one exact fixture as data. | Supplies a bounded 64-row, physically parameterized synthetic encoding of canonical AND2/AND3 laws. The target is generated from latent ENU truth without consulting sensor projections, fusion, Galadriel, or PID. It is external to fusion/PID, not producer-independent field truth. |
| Haldir | Prospective downstream record-only consumer | No dependency, adapter, route, or runtime edge in 0.9.0. It is neither required nor an enabled option. | A future record may append advisory evidence only. Authorization and plant-command outputs must be identical with and without that record. Galadriel evidence cannot grant, revoke, restrict, or exercise authority. |
| Prisoma | Prospective downstream immutable offline consumer | No dependency, adapter, route, or runtime edge in 0.9.0. It is neither required nor an enabled option. | Shows a possible immutable covariate or comparator import. Shared NCP or PID dependencies do not establish compatibility or independence. |
| Engram and Paper2Brain | External application names and realm context | No dependency, API, process, adapter, route, or runtime edge. `engram/ncp` is an example realm string, not an application binding. | Separates the realm example from NCP, which is the linked wire and transport interface. The dated Paper2Brain observation records provenance only. |
| ROS / ROS 2 | External robotics middleware | No dependency, message binding, topic, service, action, bridge, node, bag importer, or runtime edge. | Records that a future robotics adapter is a new and separately qualified interface. Sensor terms do not imply this interface. |
| External authority or controller | Explicit non-edge | No command, control, credential, lease, watchdog, or authority path. It is neither required nor enabled. | Preserves advisory-only behavior. A separate future consumer may record evidence, but this release authorizes no evidence-dependent policy effect. |

Galadriel is the center node and has no self-edge.
The active dependency and input graph is:

```text
pid-rs -> Galadriel                  dependence, evaluation, and offline justification paths
NCP -> Galadriel                     NCP paths
authorized conforming producer -> Galadriel   live use
CREBAIN exact fixture -> Galadriel            offline categorical MGW study only
```

Haldir is a prospective record-only consumer with no version 0.9.0 runtime edge.
Prisoma is a prospective immutable offline consumer with no such runtime edge.
Engram, Paper2Brain, ROS, and external authority are explicit non-edges.
No edge returns to an upstream producer or library.
The active graph is therefore acyclic.
It has no evidence-to-command feedback loop.

The default `cargo build` selects `galadriel-core`, `galadriel-sim`, and the
feature-empty CLI workspace member. It also selects their ordinary registry
dependencies.

`cargo test --workspace --all-features` tests the optional dependence, PID-study, and NCP surfaces.
This command resolves their immutable library pins.
A default end-user build does not resolve these pins.

The release feature-graph gate also selects `galadriel-eval` and
`galadriel-justify` directly. This selection proves their documented NCP and pid-rs
dependency edges. It does not infer them from the CLI graph.

## Retained audit-input cut

`release/0.9.0/audit-inputs.json` contains a separate retained input cut.
Its `audit_date` identifies the audit record.
It does not claim that each object was the mutable peer head on that date.

| Repository | Retained audit-input object | Relation to the dated inspection cut |
|---|---|---|
| Crebain | `4c311900ade5668200a48d56fb191be1916b884a` | Historical compatibility fixture. `ECO-004` records the later mutable-head observation. `ECO-016` binds the separate immutable drone-fixture source. |
| Haldir | `5f7d183625a982741c51958e2d10bc12bb628ca0` | Retained T000 exact-commit snapshot. `ECO-005` starts the later mutable-head observation chain. |
| Prisoma | `0968128062f30da5c04f3f31c23f6ce8e0d95d36` | Retained frozen-baseline inventory. `ECO-007` starts the later mutable-head observation chain. `ECO-017` is its current reinspection. |
| Paper2Brain | `9845c31bc5bae4746120858037b27f9c9ed2f445` | Retained application inventory. `ECO-013` records the later mutable-head observation. |

The dated observations do not replace these retained inputs.
The retained inputs do not create a dependency, adapter, route, or runtime edge.
`ECO-018` supersedes the active pid-rs dependency selection recorded by
`ECO-001`. It does not rewrite that historical observation or the producer's
immutable CREBAIN preregistration.

## Exact inspection cut

The inspection register uses these repository objects. Rows without a newer date
were observed on 2026-07-18.

| Repository | Inspected object | Meaning for Galadriel 0.9.0 |
|---|---|---|
| pid-rs historical selection | `1cd2424f7967e1752dcc8e53859e8fdad3566f51` | Superseded dependency observation retained because the immutable CREBAIN producer preregistration and historical 0.4-to-1.0 migration name this evaluator. It is not the current Cargo selection. |
| pid-rs selected dependency | `bc3aa80fb6025e709c2906a08bce25a4fac40578` | Clean, remote-reachable immutable `pid-core` 0.9.0 selection recorded by `ECO-018`. No resolved Galadriel profile includes `pid-runlog`. |
| NCP | `10492c81ac671ef1909962a9f1fede33781b9933` | Mutable upstream head inspected for topology. It is not the dependency pin. |
| Crebain | `0a58a5b8dd799884ddb06f1308b1748216fab322` | Mutable producer head inspected for component alignment. It is not a reciprocal Galadriel pin. |
| CREBAIN exact fixture source | immutable commit `6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d` | Clean remote commit that generated the embedded 64-row drone fixture. It adds an offline data edge only. |
| Haldir discovery observation | remote `main` `0e94f61cfd5c78482198a765157571746a256181` | Mutable downstream design and status observation. No dependency, adapter, route, or runtime edge was found. |
| Haldir later reinspection | remote `main` `dd3d8a1c993721f89a1edb04dec5247761c694ad` | Later 2026-07-18 observation of the same mutable branch. It replaces only the discovery-head reference, not frozen evidence. |
| Haldir 2026-07-22 retained reinspection | remote `main` `c0e4b3d156500684329a92bcb16e0609894fd738` | A retained descendant observation. Its CH-T001 activation adds repository inventory and release evidence. It records no runtime or external-conformance change. |
| Haldir 2026-07-23 reinspection | remote `main` `590ba767b32a27d9dd61a2462968306c1052434e` | A retained descendant observation. Its intervening changes affect audit, evidence, and release tooling only. It records no runtime or external-conformance change. |
| Haldir 2026-08-18 record-only review | signed review commit `c19f9011e4919a5bc67fab5f90d6c8eefed4455b` | Defines fixed-input authorization and plant-command noninterference plus a prospective record-only audit seam. It is not merged `main`, an implemented adapter, or runtime qualification. |
| Prisoma discovery observation | `63cff105e0e40281376e6f827d7782e9b351961a` | Downstream design and status inspection only. No runtime edge exists. |
| Prisoma 2026-08-14 reinspection | remote `main` `efcad9943af818913702f11c47ed0c280a2a1f13` | Committed first-principles provenance/estimand redesign. It supersedes only the mutable-head reference and adds no dependency, adapter, route, or runtime edge. |
| Prisoma 2026-08-17 reinspection | remote `main` `85f55c99564d1899f2e34c8412c41aaa9fc8f6c3` | Clean committed PID method-selection/publication contract and bounded pid-rs handoff. It supersedes only the preceding mutable-head reference and adds no dependency, adapter, route, or runtime edge. |
| Paper2Brain | remote `main` `24e74b781a5bf8af069f69cbc2d0c42d89008211` | Mutable application inventory inspected on 2026-07-23. No Galadriel dependency, API, process, route, adapter, or runtime edge exists. |

The local source inventory records three more non-edges.
Engram has only the example realm-label relationship.
ROS and ROS 2 have no code or runtime edge.
External authority also has no code or runtime edge.

The Paper2Brain object is inspection provenance.
It is not a repository dependency pin.

The release inspection cut retains all five Haldir observations.
Commit
`0e94f61cfd5c78482198a765157571746a256181` is an ancestor of
`dd3d8a1c993721f89a1edb04dec5247761c694ad`.
That commit is an ancestor of
`c0e4b3d156500684329a92bcb16e0609894fd738`.
That commit is an ancestor of
`590ba767b32a27d9dd61a2462968306c1052434e`.
That commit is an ancestor of signed review commit
`c19f9011e4919a5bc67fab5f90d6c8eefed4455b`.

The first interval activates current-head qualification.
It also starts CH-T001 repository-inventory work.
The second interval completes and activates this evidence-only task.
Its retained downstream-conformance disposition records no runtime-surface or
external-conformance change.
The third interval updates retained evidence and release tooling only.
It adds no runtime surface or external-conformance claim.
The final interval adds a design-only record path and a formal noninterference
contract. It adds no runtime route, policy input, or command edge.

Branch movement does not create a Galadriel dependency or integration. External
heads can change after this cut. Galadriel binds only tracked release inputs and
exact dependency revisions.

Each newer Haldir observation replaces only the preceding mutable-head reference.
It does not rewrite an earlier observation. It also does not rewrite Haldir frozen
audit material, Galadriel frozen evidence, or any historical object.

The two Prisoma reinspections form `ECO-007 → ECO-015 → ECO-017`. Only the last
is the current mutable-head reference. They do not rewrite an earlier observation
or the retained frozen-baseline input. `ECO-016` separately supersedes the
mutable CREBAIN head in `ECO-004` with the exact immutable source of the embedded
fixture. That commit identity does not turn the data edge into a runtime edge.
`ECO-018` separately supersedes only the active pid-rs selection in `ECO-001`.
It preserves the older object as historical preregistration and migration
provenance.
`ECO-019` supersedes only the mutable Haldir reference in `ECO-012`. It records
a signed review-branch object, not merged `main` or an implemented route.

## pid-rs connection

The default build does not include pid-rs. Dependence and offline PID-study crates require it.
Galadriel selects `pid-core` 0.9.0 at
`bc3aa80fb6025e709c2906a08bce25a4fac40578`. `galadriel-dependence`
and `galadriel-eval` select only the stable default surface.
`galadriel-justify` alone enables `experimental-continuous` for its explicit
offline Ehrlich PID2 study. No Galadriel path enables `experimental-pipelines`,
mixed-dimensional PID3, or `parallel`.

No resolved Galadriel feature profile contains `pid-runlog`.
A build requires this pin in these cases:

- `galadriel-dependence`
- `galadriel-justify`
- `galadriel-eval`
- CLI `dependence` feature

The connection does not require another process, network connection, or sibling
checkout at runtime.

The opt-in in-process/library connection computes geometry-gated report-first
pairwise MI through `ksg_mi_report_with_budget` and retains it outside the
accepted default core report. Its retained preflight and executed report use the same
explicit single-thread resource budget. Galadriel's graph work ceiling is a
separate aggregate bound. Its executable
integrations are the synthetic demo, evaluation, and benchmark; `replay`,
`observe`, and NCP do not invoke it. Offline justification separately
computes categorical MGW and continuous Ehrlich PID atoms for fixed source-target
questions. These functionals are not aliases or fallbacks. Neither path can
repair unavailable core evidence or override contradictory signed correlation.

The selected manifest declares `pid-core` version 0.9.0. Revision `1cd2424f…`
survives only in the immutable producer preregistration and historical migration
frame. Galadriel does not execute it as a second dependency.
[`PID_RS_1_0_MIGRATION.md`](PID_RS_1_0_MIGRATION.md) defines the exact API
adaptation and remaining restricted-domain assumptions.

## NCP connection

The default CLI does not resolve NCP. These selections require `ncp-core`:

- `galadriel-ncp`
- `galadriel-eval`
- CLI `ncp` feature

CLI `ncp-live` or direct `galadriel-ncp` feature `zenoh` also requires
`ncp-zenoh`, Zenoh, and Tokio.
The offline `ncp` path parses bounded JSONL and needs no router.
`ncp-live` provides the operational transport path.

The offline replay input contains `PidObservation` records only.
It does not contain complete producer and lifecycle provenance.
The CLI therefore labels its output as unbound and diagnostic-only.
It does not fabricate an `AssessmentScope`.
It does not produce accepted lifecycle evidence or a lifecycle receipt.

The exact live routes are:

```text
{realm}/session/{epoch}/sensor/galadriel-pid
{realm}/session/{epoch}/sensor/galadriel-monitor
```

`OperationalLiveReceiver` subscribes only to these project-owned sidecars. It
does not subscribe to `{realm}/session/{epoch}/observation`. Neither sidecar is a
normative base-plane `SensorFrame`.

The live assembler admits only complete frames to `LifecycleDetector`.
The detector derives one assessment scope from the validated producer and exact
admitted position.
Each evaluated report carries the same producer and position as its receipt.
The receipt assessment digest binds the complete ordered assessment vector.

The live CLI emits this pair in `galadriel.observe.lifecycle.v1` records.
Each record sets `calibrated_posterior` to `false`.
This record is local advisory output, not an NCP wire message.
The scope and receipt establish internal identity consistency.
They do not authenticate the producer or provide durable storage.

Both NCP crates resolve to
`2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`. The annotated `v0.8.0` tag object
is `54008b16ea0c195a4ccc9691cb533dd1153bf7f0`.
It resolves to that commit and tree
`488b4add0c43417681c7d87d73e433d46bfa5b78`.
The tag and commit have exact object identities.
They have no Git signature.

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

The runtime pin `v0.8.0` predates the tooling change.
Its checker can skip both Galadriel rows and report success.
Coordinated pin checks **MUST** use tooling at or after the minimum checker
commit.

The Galadriel feature-graph gate rejects these descriptor states:

- zero-row
- legacy
- unknown
- partial
- drifted

This tooling requirement does not upgrade the runtime wire or crate pin beyond
0.8.0.
The local descriptor read is bounded, no-follow, and nonblocking.
The same gate pins the Tokio feature set for `ncp-live` and `--all-features`.
An unreviewed capability such as process spawning cannot silently enter these
graphs.

The gate emits this information in its machine-readable report:

- minimum tooling commit
- both descriptor rows
- qualified NCP pin

This report separates checker compatibility from runtime dependency identity.

The 2026-08-03 NCP status inspection is bound to
[commit `1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd`](https://github.com/sepahead/NCP/commit/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd).
That commit is the unreleased and release-blocked `1.0.0-rc.1` candidate.
It uses wire `1.0` and compact `CONTRACT_HASH` `163acc57d8a62b66`.
The latest immutable NCP release is `v0.8.0`, which uses a different wire.
This dated status does not replace the inspection object or dependency pin above.
Current Galadriel named-sensor routes are project-owned wire-0.8 surfaces.
They are not native wire-1.0 extensions.
They are historical NCP 1.0 migration input, not native-1.0 role evidence.

The pinned [NCP task ledger](https://github.com/sepahead/NCP/blob/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd/evidence/implementation/task-ledger.v1.json)
records `G03` as `OPEN`.
`G03` depends on `X02`, which is also `OPEN`, so `G03` is not dependency-ready.
These exact external Galadriel qualifications have no evidence and remain **NOT RUN**:

- `Galadriel NCP observer`
- `Galadriel raw-advisory publisher`

The pinned [NCP ecosystem blueprint](https://github.com/sepahead/NCP/blob/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd/docs/handoff/NCP_V1_0_ECOSYSTEM_FINALIZATION_BLUEPRINT.md)
defines the role boundary.
The observer requires a read-only principal and an exact bounded grant.
It cannot publish, mutate lifecycle state, claim authority, or issue an ESTOP.
The release-facing raw-advisory publisher is the blueprint's `Galadriel assessor`
surface.
It requires a separate principal and a default-off push-only raw-evidence path.
Its payload contains raw verdict and evidence provenance with an optional
non-authoritative requested effect.
It cannot reuse observer credentials, self-admit, derive `StateUnusable`, grant
or widen authority, or encode an authoritative effect, `ALLOW`, or command.
No native-1.0 raw-advisory publisher exists.
Galadriel 0.9 records native-1.0 integration as `NOT_CLAIMED`.
That claim tier is separate from NCP's external **NOT RUN** gate state.

## Crebain connection

Crebain has component alignment without reciprocal qualification. It is not a
Cargo dependency. It is not required for default builds, simulation, evaluation,
or offline replay.

A live observer needs an independently authorized producer that satisfies the
frozen sidecar contract. Galadriel does not require that producer to be Crebain.

The inspected Crebain sender has two opt-in gates.
The build requires its off-by-default Cargo `ncp` feature.
Runtime publication also requires
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

The evidence has no final-candidate reciprocal pin.
It also lacks complete current consumer-configuration identity.
It lacks a current-binary multi-process mTLS and ACL campaign.
All Galadriel cross-repository release claims therefore remain `NOT_CLAIMED` or
pending in the Galadriel release ledger.
This state does not satisfy an NCP role gate.

### Bounded offline drone-fixture edge

A separate 2026-08-17 observation binds CREBAIN commit
`6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d` as the producer of
`src-tauri/tests/fixtures/crebain_drone_mgw_v1.json`. The exact file is 64,218
bytes with SHA-256
`82a837415b56c3646386a5c3e6fe28a492906c164edc461249bab7844aa4ebda`.
Its analysis-manifest SHA-256 is
`4b0381beee855e7d624066ab04cfdc07920c6182951315b65ba48d99c1e86f90`.
Galadriel embeds those bytes in `galadriel-justify`, checks each declared source
symbol against its named pre-fusion coordinate, reconstructs each target from
the retained latent ENU row, and evaluates categorical MGW PID2/PID3 through the
selected budgeted pid-core routes. The producer generated the targets without
reading source-symbol fields, projections, fusion output, Galadriel, or PID.
This is target separation from the evaluated stack, not producer-independent
field truth.

The compact fixture retains a row timestamp, three pre-fusion sensor objects,
and a six-field legacy fusion summary: prior identifier, input count, expected
count, projection count, truncation, and degradation. It does not retain three
independent sensor timestamps, complete projection receipts, a full fusion
output, or sufficient hidden state to prove state isolation. Repeated cells
therefore support bounded-summary fresh-instance reproducibility and custody,
not 64 independent flight samples.

This creates only `CREBAIN fixture → Galadriel offline study`. It adds no Cargo,
wire, process, replay, NCP, fusion, or control edge. CREBAIN does not consume the
result. The fixture declares and exactly balances one deterministic categorical
conformance law; the raw-row route remains an empirical-PMF sample estimator,
whose estimate coincides with that law only on this fixture. This is not reciprocal
deployment qualification, population inference, continuous-PID eligibility, recorded
flight performance, or a Haldir authority path. See
[`CREBAIN-DRONE-MGW-STUDY.md`](CREBAIN-DRONE-MGW-STUDY.md).

## Haldir connection

Haldir is a prospective record-only consumer. It is not part of a Galadriel build
or runtime mode.

The first four Haldir objects retained in the inspection cut directly pin NCP
0.8. The fifth is the signed record-only design review. None contains a
Galadriel dependency, deployed route, subscriber, publisher, or adapter.
The descendants add and activate qualification, inventory, and release evidence.
They do not change this boundary.

The 2026-07-23 mutable observation changes no runtime or conformance surface.
The 2026-08-18 review commit formalizes noninterference without implementing a
consumer.

The Haldir frozen audit cut records Galadriel
`94e2f8cc01f352d2bf899b7f656997f143a2588f` as an input. This record is not
independently verified compatibility. The Galadriel integration phase has not
started.

A future Haldir adapter can receive only bounded advisory evidence.
It **MUST** record output without policy effect: authorization and plant-command
outputs **MUST** remain identical when the record is present, absent, malformed,
or unavailable. This record path cannot grant, revoke, restrict, or exercise
authority. Any policy-effect proposal is a different, separately admitted
contract and is not a continuation of this interface.

`StateUnusable` and policy eligibility would be Haldir-owned conclusions only
under a different, separately admitted future policy contract. The record-only
path **MUST NOT** derive them from Galadriel evidence, and Haldir **MUST NOT**
accept them as Galadriel fields.
No verdict can create or widen authority.
This rule applies to `Nominal`.

## Prisoma connection

Prisoma is a prospective offline covariate only. It is not part of a Galadriel
build or runtime mode. It has no Galadriel dependency or adapter.

Its optional NCP 0.8 observer accepts only these exact base session keys:

- `sensor`
- `command`
- `observation`

An existing negative test rejects named sensor subkeys.
Prisoma therefore cannot consume the two Galadriel sidecar routes by mistake.
Its living overlay records an older Galadriel audit object.
The inspected tier records intention or adjacency only.

A future importer **MUST** be offline and immutable.
It **MUST** bind exact Galadriel source, configuration, profile, session, epoch,
source window, and receipt time.
It **MUST** reject stale, replayed, malformed, and post-treatment inputs.
It **MUST** preserve abstention.
It **MUST NOT** invoke the Agent Bridge.
It **MUST NOT** change treatment or result logic.

Both projects use `pid-rs`.
Their outputs are not independent-implementation replication.
This common dependency alone does not prove statistical dependence.
Measure dependence from actual inputs, configuration, and results.

## Engram/Paper2Brain non-edge

`engram/ncp` appears in examples, tests, and the rendered reference deployment. It
is a multi-segment NCP realm. Realm validation treats it as data. Operators can
select another valid realm.

Galadriel has no Paper2Brain dependency, import, API, process, route, adapter, or
runtime discovery path. The release inventory retains the dated remote-head
observation and an absent-edge declaration.

## ROS / ROS 2 non-edge

The workspace has no ROS client dependency or message definition.
It has no topic, service, action, node, launch file, bag reader, or bridge.
Sensor and track terms do not imply ROS compatibility.

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

A future consumer **MUST** remain record-only under this contract.
Adding or removing its record **MUST NOT** alter authorization or plant commands.
`Nominal` is evidence, never permission.
The command path **MUST** remain available without Galadriel.
Its governance **MUST** remain independent of Galadriel.

## Qualification boundary

No inspected external object completes current reciprocal integration. A future
claim requires at least these items:

- exact final release pins
- signed envelope and application identity
- stale, replay, and session-mismatch tests
- bounded-flood behavior
- absent or crashed producer equivalence
- negative authority proofs
- retained external multi-process mTLS and ACL interoperability evidence

Until independent admission of this evidence, Galadriel 0.9.0 claims only its
local implementation and component-level evidence.
