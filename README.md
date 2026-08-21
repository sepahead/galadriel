<p align="center">
  <img src="assets/galadriel-logo.svg" alt="Galadriel's Mirror — a sentinel shield with a visor that carries a sweeping red scanning eye. Three fiber-optic sensor channels enter it from below." width="200" height="200" />
</p>

# Galadriel's Mirror

<p align="center"><strong>Experimental, fail-closed cross-sensor consistency monitoring for multi-sensor fusion.</strong></p>

<p align="center">
  <a href="https://github.com/sepahead/galadriel/actions/workflows/ci.yml"><img src="https://github.com/sepahead/galadriel/actions/workflows/ci.yml/badge.svg" alt="continuous integration"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0">
  <img src="https://img.shields.io/badge/rust-1.89%2B-orange.svg" alt="Rust 1.89+">
  <img src="https://img.shields.io/badge/source%20state-unpublished%20candidate-orange.svg" alt="source preparation state: unpublished candidate">
  <img src="https://img.shields.io/badge/status-research%20review-orange.svg" alt="status: research review">
  <img src="https://img.shields.io/badge/unsafe-forbidden-success.svg" alt="unsafe forbidden">
</p>

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| API | application programming interface |
| ASCII | American Standard Code for Information Interchange |
| CA | certificate authority |
| CLI | command-line interface |
| CN | certificate common name |
| CUSUM | cumulative sum |
| DOA | direction of arrival |
| DOI | digital object identifier |
| JSON | JavaScript Object Notation |
| JSONL | JavaScript Object Notation Lines |
| KSG | Kraskov–Stögbauer–Grassberger |
| LiDAR | light detection and ranging |
| MI | mutual information |
| mTLS | mutual Transport Layer Security |
| MSRV | minimum supported Rust version |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |
| PID2 | two-source partial information decomposition |
| PID3 | three-source partial information decomposition |
| ROS / ROS 2 | Robot Operating System / Robot Operating System 2 |
| SBOM | software bill of materials |
| SPKI | Subject Public Key Info |
| SSH | Secure Shell |
| TLS | Transport Layer Security |
| WebPKI | Web Public Key Infrastructure |

Galadriel checks whether several sensors that observe one track still agree.
It combines per-channel right-tail Normalized Innovation Squared (NIS), a
two-arm CUSUM, and signed cross-channel correlation. The lower CUSUM arm is
inert on fusion-core rows with `dof=3`. The validated interface also admits
other degrees of freedom and retains the general two-arm recurrence.
The correlation keeps its sign and uses a producer-attested projection.
An optional pairwise-MI companion explores nonlinear dependence without changing the
accepted core verdict. Separate offline studies evaluate categorical and continuous PID.

Here, "signed" identifies the correlation sign.
"Attested" identifies a producer provenance claim.
Neither term identifies a cryptographic signature.

[![Galadriel operational evidence flow, descriptive research routes, and authority firewall](assets/system-boundary.svg)](assets/system-boundary.svg)

**Evidence flow and authority boundary.** The upper solid route is the implemented
operational path. Observation and monitor sidecars must pass the bounded assembler
and typed lifecycle gate. The per-channel magnitude lane and the signed-consistency
lane then feed conservative fusion. The dashed pairwise KSG-MI branch starts from
the same admitted common projection. It produces a companion report and never
enters fusion. The lower dashed route starts from one fixed source-target question
and keeps categorical Makkeh–Gutknecht–Wibral PID separate from continuous Ehrlich
PID2. The red barrier is a one-way non-edge: no research result changes a fused
verdict, authorization decision, or plant command. `Nominal` is evidence, never
permission.

[Open the full-size evidence-flow figure.](assets/system-boundary.svg)

### Grounded offline categorical PID fixture

CREBAIN supplies one byte-bound, physically parameterized **synthetic** drone
fixture for a narrow offline question. Its information-theoretic content is the
canonical uniform logic-gate law

\[
V,R,A\overset{\mathrm{ind}}{\sim}\operatorname{Bernoulli}(1/2),\qquad
T_H=V\land R,\qquad T_V=V\land R\land A.
\]

Visual, radar, and acoustic symbols are reconstructed from ordered pre-fusion
measurements. After constructing sensor-observation objects and source symbols,
the producer derives targets from preregistered latent ENU coordinates and then
runs fusion. Target derivation reads neither serialized source fields, sensor
projections, fusion output, a Galadriel verdict, nor a PID result. The targets are
therefore dataflow-independent of those objects and external to fusion, Galadriel,
and PID—not temporally prior to sensor-object construction or producer-independent
field truth. The 64 rows are eight fresh-engine repetitions
of each three-bit cell. They preserve the same finite probability law and test
only bounded-summary fresh-instance reproducibility. They are not 64 independent
flights and do not retain a complete fusion replay.

A typed, append-only errata receipt preserves the fixture bytes while correcting
three producer-source interpretations: the frozen target-origin timing and
externality wording, omission of the two-arm CUSUM as an operational object
distinct from NIS and signed correlation, and the legacy fusion-summary fields.
On the fusion core's `dof=3` route, the CUSUM lower arm is inert. Other admitted
degrees of freedom retain the general two-arm recurrence. In particular,
`projection_count=3` is an admitted-observation count, not proof of three present
projections. `common_projection_prior_id=2` proves at least one projection and
prior-two agreement only among projections that are present. These corrections do
not change the categorical law or any PID value.

[![Synthetic latent ENU targets, ordered pre-fusion sources, exact fixture custody, categorical MGW PID2 and PID3, algebra checks, and the Haldir record-only firewall](assets/crebain-drone-mgw-pipeline.svg)](assets/crebain-drone-mgw-pipeline.svg)

**Grounded categorical MGW pipeline.** Galadriel verifies the exact CREBAIN
fixture and manifest digests, reconstructs every source and target from the
declared synthetic geometry, and calls only pid-core 0.9.0 at clean read-only
revision `bc3aa80fb6025e709c2906a08bce25a4fac40578`, through
`discrete_sxpid2_with_budget` and `discrete_sxpid3_with_budget`. This is a
reviewed post-preregistration sample-estimator implementation adaptation: CREBAIN's immutable manifest
still binds revision `1cd2424f7967e1752dcc8e53859e8fdad3566f51` and the earlier
unbudgeted entry-point names. The wire model keeps four roles distinct: paper
functional `functional.shared-exclusions.mgw-categorical`, raw-row empirical-PMF
sample-estimator route `route.shared-exclusions.mgw-empirical-pmf`, upstream
implementation-method/catalog identity `shared-exclusions.categorical`, and the
two concrete budgeted pid-core entry points. Raw rows produce a plug-in empirical
PMF estimate; they do not evaluate a separately declared population law. Exact
cell balance makes that empirical PMF coincide with the declared canonical law
for this fixture only. The categorical MGW functional, source order, targets,
units, and signed outputs are unchanged, and no population inference is made.

The horizontal PID2 result is primary. The 18-atom volumetric PID3 result is
exploratory and does not close pid-rs's separate open 108-coordinate assurance
program (18 antichains × cumulative/atom × informative/misinformative/net).
All values are nats. Negative net atoms remain valid and are never clamped. A
separate 80-digit event-union/Möbius calculation recomputes the 66 **averaged
atom** components—4 PID2 plus 18 PID3 atoms, each with three components—and ten
subset mutual informations. This is a dependency-disjoint implementation in the
same repository, not an independent human or organizational replication. The
current canonical oracle SHA-256 is
`5aa7a1d92d4aaad9c056ede8a75bdc40abc1fa76634b02bba20aac5cc3913c19`.
The largest observed Rust/Decimal difference is below `1.97e-16` nats.
Pointwise results are retained and internally reconstructed, but are not
separately recomputed by the Decimal route. This exact-law result makes no
drone-performance claim and has no effect on fusion, verdicts, or Haldir.
Its 18-row eligibility matrix keeps the MGW functional, empirical-PMF
sample-estimator route, upstream implementation method, concrete pid-core entry points,
`I_min`, two-source BROJA, Schick-Poland, continuous Ehrlich, KSG,
co-/O-information, NIS, the selected two-arm CUSUM, signed correlation, and the two
infomorphic objective families distinct. Inapplicability or failure never selects
another row as a fallback.

[Read the equations, complete tables, method comparison, twenty-lens audit, and
research to-do list.](docs/CREBAIN-DRONE-MGW-STUDY.md)

The JSON output is governed by a closed Draft 2020-12
[machine schema](crates/galadriel-justify/schemas/crebain-drone-mgw-study-v3.schema.json)
with `additionalProperties: false`, explicit required fields, enums, and fixed
cardinalities at every object boundary. A standard-library checker rejects
duplicate keys, non-finite or oversized numbers, unknown schema keywords,
unresolved references, open nested objects, and schema-receipt mismatches. The
schema fixes the version 3 wire contract. The unpublished version 2 draft was
retired because it conflated functional, sample-estimator, implementation-method,
and entry-point roles; it is not a valid alternate contract. Rust custody/algebra checks and the Decimal route
remain separate semantic and numerical obligations.

Deep quality also carries a bounded exact-head mutation gate for the seven
CREBAIN contract functions. Its frozen selected set contains 155 transformations.
The required outcome is 152 caught mutants, three exact compile-unviable
function-return substitutions, and no missed, timed-out, or surviving mutant.
The local repair reference has that outcome. The final candidate must reproduce
it under cargo-mutants 27.1.0 and Rust 1.89.0 before publication.

## Run the source demo

```bash
cargo run --locked --bin galadriel -- demo --frames 128 --seed 7
```

Representative output from that exact command follows. The traces are shortened.

```text
═══ GALADRIEL'S MIRROR · cross-sensor consistency monitor ═══
┌─ CLEAN — corroborated airspace picture
│  visual    μ=2.93  ● consistent
└▷ VERDICT: NOMINAL
┌─ PHANTOM DOA — targeted single-channel spoof (acoustic)
│  acoustic  μ=66.68 ● ANOMALOUS
└▷ VERDICT: ATTRIBUTED-INCONSISTENCY (spoof-like evidence; cause unclassified) [acoustic]
┌─ BROADBAND JAM — correlated all-channel denial
└▷ VERDICT: BROAD-DEGRADATION (jam-like evidence; cause unclassified)
┌─ SYNTHETIC MOMENT-MATCHED SPOOF
│  baseline: NOMINAL — blind (NIS stays in-covariance)
└▷ correlation: ATTRIBUTED-INCONSISTENCY [acoustic]
```

The demo uses synthetic common-frame observations.
It shows code paths. It does not show field performance.

## Ecosystem boundaries

Galadriel has one local evidence path and no command-authority path.
A dependency pin alone does not prove an authorized or current cross-repository integration.
A shared transport or historical fixture also does not prove such an integration.

| Project | Direction | Required or optional | Why connected | Explicit 0.9.0 boundary |
| --- | --- | --- | --- | --- |
| [pid-rs](https://github.com/sepahead/pid-rs) | Upstream algorithm library | The default CLI build does not use it. `galadriel-dependence`, justification, and evaluation require its exact `pid-core` pin. The CLI `dependence` feature also requires the pin. It is linked code, not a runtime service. No resolved Galadriel feature profile includes `pid-runlog`. | Stable report-first KSG supports the opt-in in-process/library MI companion. Its executable integrations are the synthetic demo, evaluation, and benchmark. `replay`, `observe`, and NCP do not invoke it. Categorical Makkeh–Gutknecht–Wibral and related-but-distinct continuous Ehrlich–Schick-Poland–Makkeh–Lanfermann–Wollstadt–Wibral PID support separate offline studies. | The selected clean, remote-reachable pin is pid-core 0.9.0 at `bc3aa80fb6025e709c2906a08bce25a4fac40578`. CREBAIN's immutable preregistration separately records `1cd2424f7967e1752dcc8e53859e8fdad3566f51`. Galadriel records the post-preregistration API adaptation rather than rewriting that history. |
| [NCP](https://github.com/sepahead/NCP) | Upstream wire and transport libraries | The default CLI build does not use it. `galadriel-ncp`, evaluation, and CLI `ncp` require `ncp-core`. CLI `ncp-live` or direct `galadriel-ncp` feature `zenoh` also pulls `ncp-zenoh`, Zenoh, and Tokio. | It supplies wire-0.8 key, version, and contract helpers. It also supplies the optional Zenoh bus. Galadriel owns its sidecar envelopes, bounded offline JSONL, and operational receiver. | Both NCP crates pin `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`. This pin does not prove remote authorization, ACL enforcement, or wire-1.0 compatibility. |
| [Crebain](https://github.com/sepahead/crebain) | External upstream producer and offline-fixture relationship | There is no Cargo dependency. The default demo, simulation, evaluation, replay, and live path do not require Crebain. Live operation needs an authorized contract-conforming producer. That producer need not be Crebain. `galadriel-justify` separately embeds one exact CREBAIN drone fixture as data. | It supplies the inspected reference component for the observation/monitor sidecar contract and a 64-row synthetic canonical AND2/AND3 law under drone-labeled coordinates. Galadriel validates its bounded six-field, three-observation summaries before offline MGW PID2/PID3 evaluation. The legacy fields do not prove three present projections. | Fixture producer commit `6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d`, SHA-256 `82a837415b56c3646386a5c3e6fe28a492906c164edc461249bab7844aa4ebda`. This proves one bounded offline conformance law, not full fusion replay, state isolation, reciprocal deployment qualification, field validity, drone performance, or a runtime feedback edge. |
| [Haldir](https://github.com/sepahead/haldir) | Prospective record-only consumer | Version 0.9.0 has no dependency, adapter, route, or runtime edge. | A future adapter may retain a versioned advisory reference for audit only. For fixed admitted authority input, authorization, trusted-state policy, and plant-command outputs must be identical across PID record states. Audit records may vary. This software-path claim does not assert operator-behavior noninterference. | The integration phase has not started. There is no runtime evidence. |
| [Prisoma](https://github.com/sepahead/prisoma) | Prospective downstream offline comparator and covariate consumer | Version 0.9.0 has no dependency, adapter, route, or runtime edge. | It documents a possible future immutable offline covariate import. The inspected historical wire-0.8 surface keeps Galadriel sidecars outside its base `SensorFrame` routes. | The inspected relationship records intention or adjacency only. Shared NCP and PID dependencies do not imply schema compatibility or independent-implementation replication. |
| Engram and Paper2Brain | External application names and realm context | There is no dependency, API, process, route, adapter, or runtime edge. The literal `engram/ncp` is a configurable example realm. It is not an application integration. | It makes the example deployment namespace concrete. NCP remains the actual library, key, and transport interface. | A 2026-07-23 read-only Paper2Brain observation records provenance only. Galadriel claims no integration, compatibility, or deployment qualification. |
| ROS / ROS 2 | External robotics middleware | Version 0.9.0 has no dependency, message binding, topic, service, action, bridge, node, or runtime edge. | It identifies an ecosystem boundary that a future adapter MUST define and qualify explicitly. | Galadriel claims no ROS compatibility, bag import, or live bridge. |
| External authority or controller | Prospective downstream policy and control boundary | There is no command, control, lease, watchdog, credential, or authority path. | A future consumer may record advisory evidence. Any policy or control logic is a separately admitted system and must not be smuggled through Galadriel's PID record path. | Galadriel cannot grant, deny, restrict, widen, refresh, restore, or exercise authority. `Nominal` is never permission. |

Galadriel is the sole center of this relationship view and has no self-edge.
The declared directed graph includes `pid-rs → Galadriel` and `NCP → Galadriel`.
Live mode requires an authorized contract-conforming producer.
This producer points into Galadriel.
The prospective edges are `Galadriel → Haldir/Prisoma`.

The Engram/Paper2Brain, ROS, and external-authority entries are explicit non-edges.
No edge points back to an upstream producer or library.
Thus, the 0.9.0 graph is acyclic and contains no command loop.

The read-only coordination inspection on 2026-07-18 recorded exact repository heads.
It recorded NCP `10492c81ac671ef1909962a9f1fede33781b9933`.
It recorded Crebain `0a58a5b8dd799884ddb06f1308b1748216fab322`.
It recorded Haldir remote `main` at `0e94f61cfd5c78482198a765157571746a256181`.
It recorded Prisoma `63cff105e0e40281376e6f827d7782e9b351961a`.

A 2026-08-14 read-only Prisoma reinspection first recorded committed remote
`main` `efcad9943af818913702f11c47ed0c280a2a1f13`. A 2026-08-17
reinspection then recorded clean remote `main`
`85f55c99564d1899f2e34c8412c41aaa9fc8f6c3`, containing its PID
method-selection/publication contract and bounded pid-rs handoff. It supersedes
only that preceding mutable-head reference. Neither redesign creates a
Galadriel dependency, adapter, route, or runtime edge.

The same cut binds immutable CREBAIN fixture-source commit
`6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d`. That exact data-producing
commit supersedes only the earlier mutable producer-head reference. It is not a
Cargo dependency, reciprocal qualification, or live edge.

A second read-only Haldir inspection on 2026-07-18 observed another remote `main` head.
That head was `dd3d8a1c993721f89a1edb04dec5247761c694ad`.
Git ancestry shows that this object descends from the discovery object.
The path includes Haldir current-head qualification and repository-inventory work.
The second observation supersedes only the mutable Haldir discovery-head reference.
It does not rewrite either observation, frozen or historical evidence, or a Galadriel release input.

A retained reinspection on 2026-07-22 found Haldir remote `main` at `c0e4b3d156500684329a92bcb16e0609894fd738`.
This object descends from both earlier observations.
Its CH-T001 changes between the observed heads activate repository-inventory and release evidence only.
Haldir's retained downstream disposition records no runtime-surface or external-conformance change.
This retained inspection-cut object remains mutable provenance.
It is not a Galadriel pin, adapter, route, or reciprocal acceptance.

A later read-only observation on 2026-07-23 found Haldir remote `main` at `590ba767b32a27d9dd61a2462968306c1052434e`.
This object descends from the retained inspection-cut object.
The intervening changes affect audit, evidence, and release tooling only.
They do not create a Haldir runtime edge or external-conformance change.
The refreshed inspection cut retains this mutable provenance.

A 2026-08-18 observation binds signed Haldir review commit
`c19f9011e4919a5bc67fab5f90d6c8eefed4455b` on
`review/galadriel-pid-record-only-clean`. It defines fixed-input authorization and
plant-command noninterference plus a prospective record-only audit seam. It is
not merged Haldir `main`, an implemented route, or runtime qualification.

A 2026-07-23 read-only observation found Paper2Brain remote `main` at
`24e74b781a5bf8af069f69cbc2d0c42d89008211`.
The observation found no Galadriel dependency, API, process, route, adapter, or runtime edge.
It is not a dependency pin or reciprocal acceptance.

The release audit retains a separate peer input cut.
It includes historical Crebain, Haldir, Prisoma, and Paper2Brain objects.
Those objects are not claims about the later mutable heads.
[`docs/ECOSYSTEM-CONNECTIONS.md`](docs/ECOSYSTEM-CONNECTIONS.md) gives the exact
cross-reference.

These mutable repository heads are inspection provenance, not reciprocal compatibility pins.
The 2026-08-03 NCP status inspection is bound to
[commit `1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd`](https://github.com/sepahead/NCP/commit/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd).
That commit is the unreleased and release-blocked `1.0.0-rc.1` candidate.
It uses wire `1.0` and compact `CONTRACT_HASH` `163acc57d8a62b66`.
The latest immutable NCP release is `v0.8.0`, which uses a different wire.
Galadriel remains pinned to that release and has no native-1.0 migration.
Wire `1.0` is incompatible with the current named wire-0.8 sidecars.
These sidecars are historical NCP 1.0 migration input, not native-1.0 role evidence.

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
Crebain retains component-level schema-v1 alignment.
Crebain freezes Galadriel `94e2f8cc01f352d2bf899b7f656997f143a2588f` only as an audit input.

None of the retained Haldir objects contains a Galadriel adapter or runtime edge.
Prisoma has no direct sidecar path.
The `engram/ncp` realm string creates no Paper2Brain edge.
The source tree contains no ROS or external-authority adapter.
Galadriel 0.9 classifies native-1.0 integration as `NOT_CLAIMED`.
That Galadriel claim tier is separate from NCP's external **NOT RUN** gate state.
Current reciprocal integration and final cross-repository qualification remain `NOT_CLAIMED`.

The canonical [machine-readable inspection cut](release/0.9.0/ecosystem-cut.json) binds the same objects.
It also binds local absence declarations, relationship classes, optionality, rationale, and the acyclic boundary.
It binds the ordered Haldir supersession and Paper2Brain observation.
It classifies the immutable 2026-08-03 NCP release-status snapshot separately
from Galadriel's unchanged wire-0.8 dependency pin.

[`docs/PRODUCER-CONTRACT.md`](docs/PRODUCER-CONTRACT.md) defines the exact route and lifecycle rules.
[`docs/ADVISORY-BOUNDARY.md`](docs/ADVISORY-BOUNDARY.md) defines the downstream-effect rules.
[`docs/ECOSYSTEM-CONNECTIONS.md`](docs/ECOSYSTEM-CONNECTIONS.md) records the dated evidence and claim-by-claim interpretation.
Current external repository heads can move independently.
Version 0.9.0 claims only the dependency revisions and local evidence named here.

## Evidence status

Run the versioned study with the single locked command in [`docs/POST-AUDIT-EVIDENCE.md`](docs/POST-AUDIT-EVIDENCE.md).
Publication runs refuse a dirty worktree.
They write a checksummed manifest beside the machine-readable trials.
The clean-source reference artifact is [`evidence/results/post-audit-v1-8a0084f`](evidence/results/post-audit-v1-8a0084f).
Commit `8a0084f` generated it with `dirty=false`.

- One command makes the post-audit runner record its Git commit and toolchains.
  It also records the complete configuration, fixed seed domains, per-trial outcomes, holdout summaries, and checksums.
- The retained `8a0084f` diagnostic artifact uses its historical trial-v1 numeric-seed wire.
  New runner output uses trial v3.
  Trial v3 uses exact decimal-string seeds and fixed-width hexadecimal seeds.
  The software does not silently combine the two schemas.
- Synthetic stream studies report false-alert episodes per track-hour and mission false-alert probability separately.
  They also report run length, conditional delay, abstention, attribution, autocorrelation, covariance-scale sensitivity, and provenance rejection separately.
- The bundled Crebain fixture supports only bounded parsing and basic NIS baseline checks.
  It is approximately 15.8 seconds long and has no attested common projection.
  Thus, recorded full-detector stream metrics are explicitly `not_estimable`.
  Synthetic numbers never replace these metrics.
- Galadriel contains the bounded consumer for an opt-in common-projection and lifecycle producer.
  Crebain `4c311900ade5668200a48d56fb191be1916b884a` is part of a retained historical compatibility fixture.
  Galadriel `81437d807ca83b66b45c8353968948e540072d97` is the other part.
  This fixture is not a reciprocal pin of the 0.9.0 candidate.

  Current cross-repository qualification is `NOT_CLAIMED`.
  In-process tests remain component evidence.
  They are not a receiver-verified external mTLS/ACL deployment or field study.

The artifact is a diagnostic result, not an acceptance result.
In its clean synthetic arm, the current default reports 26.26 alert episodes per track-hour.
It reports a 0.9167 mission probability of at least one alert.

The `phi=0.5` autocorrelated arm reports 102.95 alert episodes per track-hour.
The `phi=0.85` arm reports 262.57 episodes per track-hour.
Ordinary acoustic missingness causes 99.35% fused monitoring abstention.
These results expose repeated-look and availability calibration work.
Complete this work before operational use.

> **Honest scope.** Galadriel detects statistical inconsistency, not truth.
> It cannot prove that an attributed channel is malicious.
> It cannot detect an attacker that preserves cross-channel consistency.
> It MUST NOT silently veto a control path.
> Reports are advisory evidence, not calibrated posteriors.

> **Current integration status.** Galadriel implements the strict two-route consumer.
> It also implements registry pin capability, a lifecycle adapter, and a bounded operational receiver.
> The project retains the previously paired Crebain and Galadriel revisions only as a historical compatibility fixture.
> They do not identify or qualify this candidate.
>
> A current reciprocal pin and final cross-repository qualification are `NOT_CLAIMED`.
> A real-router certificate and ACL campaign is also `NOT_CLAIMED`.
> Recorded stream calibration is `NOT_CLAIMED`.
> Historical captures remain `not_estimable`.
> A prospective deployment remains responsible for fresh, non-reused epochs.

> **TLS trust limitation.** The pinned Zenoh 1.9 client trusts built-in public WebPKI roots.
> It also trusts the configured deployment CA.
> Exclusive router-certificate or CA pinning is `NOT_CLAIMED`.
> Use a private router name that a public authority cannot issue.
> Control name resolution or use an external exact-certificate or SPKI pinning layer.
> See the [deployment security runbook](docs/SECURE-DEPLOYMENT.md#tls-server-authentication-limitation).

[`docs/ADVISORY-BOUNDARY.md`](docs/ADVISORY-BOUNDARY.md) specifies the boundary for a prospective downstream record consumer.
The PID evidence path is non-authoritative and record-only: it changes neither an authorization result nor a plant command.

[`docs/PAPER.md`](docs/PAPER.md) documents the research background.
[`docs/JUSTIFICATION.md`](docs/JUSTIFICATION.md) and [`docs/EVALUATION.md`](docs/EVALUATION.md) document the study design.

## What the core requires

Galadriel consumes `PidObservation` records that contain NIS and degrees of freedom.
That pre-release public type name is a historical compatibility name; the record is a
fusion observation, not a PID tuple or PID estimate.
Cross-sensor analysis also requires an optional `consistency_projection`.
This projection contains a bounded signed vector.
It also contains nonzero physical-frame, projection-context, and frozen-prior identifiers.

Accepted whole-stream analysis also requires one `AssessmentScope`.
The scope contains these validated coordinates:

- producer identity
- session identity
- epoch identity
- stream identity
- state generation
- terminal sequence
- terminal timestamp in milliseconds
- clock domain

The terminal sequence MUST equal the largest sequence in the input stream.
The terminal timestamp MUST equal the largest timestamp at that sequence.
`assess_default` and the optional dependence `assess_with_dependence` entry point reject a mismatch.

A direct caller declares the scope.
The core validates its representation and terminal coordinates.
The scope does not authenticate the caller or prove producer authorship.
The NCP lifecycle adapter supplies the admitted producer and position for its
accepted path.

Native `innovation` and `innovation_cov` fields remain diagnostic.
The detector never uses them as a cross-modal fallback.
The detector requires these conditions:

- Each assessment contains one track.
- Sequence numbers increase strictly and remain unique for each track and modality.
- Observations are finite and valid, with stable degrees of freedom.
- Cross-channel windows have exact sequence alignment.
- Projection dimensions, frame identifiers, and context identifiers match across modalities.
- Each sequence has one matching frozen-prior identifier. No other sequence reuses that identifier.
- All configured modalities supply enough fresh observations.

Invalid configuration or input returns `Err(...)`.
The detector does not convert an error into a verdict.
Missing, stale, geometrically incomparable, lifecycle-incomplete, or statistically insufficient evidence causes an explicit abstention or `InsufficientEvidence`.
It does not cause `Nominal`.
The legacy `CREBAIN_PID_JSONL` capture remains a baseline-only path.

Lifecycle-complete operational evidence requires a separately qualified two-route producer and Galadriel's assembler.
Galadriel claims no current reciprocal producer qualification.
The consumer never infers a successful lifecycle stage from a missing record.

## Detector layers

The overview below states what executes. The proposed
[method and profile decision record](docs/METHOD-SELECTION-DECISIONS.md) explains
why each object was selected, which alternatives were rejected or deferred, why
the numeric profiles remain uncalibrated, and which evidence can reopen a choice.

[![Three-column derivation of magnitude evidence, signed-correlation consensus, and conservative fusion](assets/detector-evidence.svg)](assets/detector-evidence.svg)

**Detector mathematics and decision algebra.** Column A derives per-channel
magnitude evidence from right-tail NIS and a two-arm CUSUM whose lower arm is
inert on the fusion core's `dof=3` route. The general validated interface keeps
both recurrences. Column B derives one signed-correlation graph, applies the family-adjusted
Fisher threshold, and admits only one unique largest positive clique whose size
is a strict majority.
The Fisher reference is conditional on the declared independent and identically
distributed bivariate-normal row model; Galadriel does not prove that declaration.
Column C applies the deterministic fusion precedence and binds the result to the
complete scope, release suite, and ordered observations. Invalid representation
returns `Err(...)`. An unavailable estimand returns `InsufficientEvidence`.
Pairwise MI and PID are absent from this fusion.

[Open the full-size detector figure.](assets/detector-evidence.svg)

### NIS/CUSUM magnitude layer

For each track and modality, the detector compares a sliding NIS window with its
right-tail chi-square reference. The effective upper CUSUM arm monitors sustained
inflation. The retained lower field does not supply suppression sensitivity at
the fusion core's `dof=3` operating point. It can move for admitted `dof>=4`.
Per-assessment channel tests control the family-wise significance budget.
A report is `Nominal` only when every configured channel is fresh, ready, and consistent.

| Evidence | Verdict |
|---|---|
| all configured channels ready and consistent | `Nominal` |
| minority of channels anomalous while peers remain usable | `AttributedInconsistency { channels }` |
| most/all channels inflated together | `BroadDegradation` |
| positive but non-attributable or lower-direction evidence | `UnclassifiedAnomaly { channels }` |
| too little, stale, missing, or incompatible evidence | `InsufficientEvidence` |
| invalid input or configuration | `Err(...)` |

### Signed-correlation consistency layer

The default consistency layer uses signed Pearson correlation and family-wise significance.
It requires one unique largest positive-consensus clique whose size is a strict majority.
The layer does not accept negative correlation as corroboration.
A dyad is the complete graph when two channels are requested. It can support
minority attribution only in the exact 2-of-3 case. It is not a strict majority
when four or more channels are requested.
A tied clique or a collection without coherent positive consensus also cannot support it.

The detector assesses every producer-declared projection axis.
It applies a Bonferroni split to the significance budget across axes and channel pairs.
Different positive channel attributions across axes produce `UnclassifiedAnomaly`.
A positive axis beside an insufficient axis also produces `UnclassifiedAnomaly`.
These conditions do not produce `AttributedInconsistency`.

A finite degenerate projection column makes its pairwise estimand unavailable.
The related correlation axis returns `InsufficientEvidence`.
It withholds all channel corroboration values for that axis.
The optional MI companion abstains before estimation when a column or pair is not
eligible. Galadriel adds no noise or tie-breaking transform. These conditions do not
discard independent magnitude evidence.

`galadriel_core::assess_default(&scope, &stream, &suite)` fuses magnitude and
consistency evidence.
It does not turn an unavailable consistency assessment into `Nominal`.
Its sealed `DefaultReport` carries an opaque `AssessmentBinding` over the complete accepted `ReleaseSuite`.
The version 2 binding also covers the complete scope.
It covers every field of every ordered input observation.
The magnitude and correlation components MUST carry that exact binding.

The report serializes the scope once as top-level field `assessment_scope`.
Callers can verify the binding against the exact scope, stream, and suite.
The binding identifies those inputs. It does not authenticate them.
Different bindings can carry equal detector verdicts.
The binding does not require each observation to change an estimator or verdict.

Unbound component helpers produce diagnostic tuples only. They cannot create an accepted report.

### Dependence companion and offline PID studies

The optional `dependence` feature adds a geometry-gated, report-first pairwise KSG-MI
graph. Its threshold and strict-majority clique are project-defined descriptive
heuristics. They have no null calibration or security-error theorem. The companion
reports `NoSeparationAtConfiguredThreshold`, `SeparatedFromMajorityGraph`, or
`Unavailable`; these are not `Nominal`, attack, or causal-mechanism labels.

The caller must declare the continuous population, observation, and sampling model.
Galadriel checks that the declarations are present and bounded; it does not prove them.
It requires a declared common coordinate gauge, applies the fixed identity transform,
adds no noise, and abstains on exact ties or rejected geometry. Optional exhaustive
stability enumerates every circular block start, reruns every pair and graph rule, and reports literal
minima and maxima. It is not a confidence interval, p-value, or false-alarm guarantee.

`assess_with_dependence` returns the exact unchanged accepted `DefaultReport` plus
companion MI reports and a binding over the exact scope, stream, and suite. MI never
enters `FusedVerdict` or `ConsistencyEvidence`.

Real PID is confined to offline `galadriel-justify` questions with fixed source and
target identities. The categorical Makkeh–Gutknecht–Wibral functional and the
related-but-distinct continuous Ehrlich construction are not aliases. A local kNN-MI
CUSUM heuristic is neither construction. See the [pid-rs dependency adaptation
record](docs/PID_RS_1_0_MIGRATION.md).

## Project status

**Source preparation state for this tree: unpublished pre-1.0 research candidate.**
Version 0.9.x freezes the `galadriel-core` source surface.
Other crates and wire adapters remain experimental.
Every workspace package sets `publish = false`.
The intended publication channel is a review-gated GitHub research source release.
At this source-generation state, no `v0.9.0` tag or GitHub release was recorded.
This source process does not publish a workspace package to crates.io.

Unit, property, integration, and synthetic study tests exercise the implementation.
Current evidence does not support a field-validated or production-ready claim.
The normative [claims matrix](docs/CLAIMS.md) states the exact boundary.
The [statistical contract](docs/STATISTICAL-CONTRACT.md) and [threat model](docs/THREAT-MODEL.md) also state it.
The [API policy](docs/API-SURFACE.md) completes this boundary.

No project DOI exists.
No project Zenodo record exists.

Author and maintainer: **Sepehr Mahmoudian**.

| Crate | Role | Evidence scope |
|---|---|---|
| [`galadriel-core`](crates/galadriel-core) | NIS/CUSUM, signed correlation, fused assessment | Local implementation tests |
| [`galadriel-sim`](crates/galadriel-sim) | synthetic scenarios and injections | Synthetic only |
| [`galadriel-cli`](crates/galadriel-cli) | `demo`, `replay`, and strict `observe` driver | Operator prototype. The live path has component tests. |
| [`galadriel-dependence`](crates/galadriel-dependence) | Geometry-gated pairwise KSG-MI companion | Optional descriptive research path; never fused |
| [`galadriel-ncp`](crates/galadriel-ncp) | strict codecs, pinned registry, monitor tap, assembler, lifecycle gate, operational Zenoh receiver | Unit, golden, and in-process Zenoh tests. No external deployment evidence. |
| [`galadriel-eval`](crates/galadriel-eval) | Monte Carlo evaluation and cost bench | Synthetic only |
| [`galadriel-justify`](crates/galadriel-justify) | canonical forced-versus-justified studies | Synthetic/theoretical only |

The workspace MSRV is **Rust 1.89**.
The current-stable Clippy and test gate uses Rust and Cargo 1.97.1.
Mutable test totals and benchmark values are not project-status claims.

## CLI features and workspace dependencies

The table describes activation from the default-member CLI.
A direct build of `galadriel-dependence`, `galadriel-justify`, or `galadriel-eval` still resolves `pid-core`.
A direct build of `galadriel-ncp` or `galadriel-eval` resolves `ncp-core` without a CLI feature.
A direct `galadriel-ncp` build with feature `zenoh` also resolves `ncp-zenoh`, Zenoh, and Tokio.
Workspace-wide builds deliberately include those crates.

| Feature | Pulls | Adds |
|---|---|---|
| default | no sibling integration crates | core, simulator, CLI |
| `dependence` | Exact `pid-core` 0.9.0 Git revision `bc3aa80…`. Only its stable default surface is selected. `parallel` and research features remain off. | Descriptive report-first pairwise KSG-MI companion. It does not change the default verdict or imply a pid-rs 1.x release. |
| `ncp` | `ncp-core` | Bounded JSONL ingest. NCP 0.8 key helpers. Strict observation and producer-monitor envelopes. The CLI `replay` subcommand. |
| `ncp-live` | `ncp-zenoh`, exact `zenoh` 1.9 guard types, `tokio` | strict `observe` command plus bounded two-route receiver, deadlines, lifecycle gate, and health state |

Raw JSONL replay does not contain the required producer, lifecycle, and clock
scope. The `replay` command therefore uses unbound component helpers.
It labels each terminal result `diagnostic-only`.
It does not call either accepted whole-stream assessment entry point.

The synthetic demo uses `ScenarioConfig::assessment_scope`.
That function derives deterministic synthetic labels and terminal coordinates.
It rejects a zero-frame scenario because that scenario has no terminal scope.
Those labels identify a simulation. They do not claim operational provenance.

The pinned `ncp-core` manifest also declares opt-in `schema` and `ts` aliases.
The retained offline, live, and evaluation dependency graphs select neither alias.

Exact Git revisions pin the public `pid-rs` repository and NCP's `ncp-core` and `ncp-zenoh` crates.
The selected pid-rs revision declares `pid-core` 0.9.0. The historical
`1cd2424…`/1.0.0 observation survives only in explicitly labeled migration and
CREBAIN preregistration evidence and is not the current dependency.
The NCP revision corresponds to public tag `v0.8.0`.
A fresh clone needs no sibling checkout, private repository token, or global Git credential rewrite.

For prospective live use, use only the rendered observer configuration.
Supply the same exact epoch and registry pin to the intended external producer deployment.
Run this command:

```bash
export NCP_ZENOH_CONFIG=/secure/config/galadriel-epoch/zenoh-observer.json5
cargo run --locked --features ncp-live --bin galadriel -- observe \
  --realm engram/ncp \
  --epoch "$GALADRIEL_DEPLOYMENT_EPOCH" \
  --producer-id "$GALADRIEL_PRODUCER_ID" \
  --registry "$GALADRIEL_REGISTRY_PATH" \
  --registry-sha256 "$GALADRIEL_REGISTRY_DIGEST"
```

The renderer's checksummed `galadriel-handoff.json` binds the realm, epoch, producer, and registry tuple.
It binds that tuple to the two authorized certificate CNs.
Verify the complete digest manifest before you start either process.
Use the handoff as the deployment configuration record.

The command reports lifecycle abstentions as evidence insufficiency.
It emits one complete JSON record when a delivered frame creates a new lifecycle receipt.
The record has schema `galadriel.observe.lifecycle.v1`.
It contains exactly these four top-level fields:

- `schema`
- `calibrated_posterior`, which is always `false`
- `receipt`, which is the complete lifecycle receipt
- `assessments`, which is the complete ordered assessment vector

Each evaluated nested report contains one `assessment_scope`.
Its producer and position match the receipt.
The assessment vector is empty when a rejected or faulted receipt has no assessment.
The record preserves the receipt-to-assessment connection.
The command uses fallible writes and flushes standard output after each record batch.
It completes that flush before it reports a following terminal error.
The command does not sign or durably retain this output.
The receipt digest does not authenticate a writer.

It exposes terminal health on exit.
It stops on the first ingress, assembly, or liveness fault.
[`docs/SECURE-DEPLOYMENT.md`](docs/SECURE-DEPLOYMENT.md) defines configuration generation and external authorization drills.

The operational receiver subscribes one shared Zenoh session to two exact keys.
The keys are `{realm}/session/{epoch}/sensor/galadriel-{pid,monitor}`.
Both callbacks serialize through one bounded nonblocking ingress.
The assembler enforces route provenance and contiguous monitor sequencing.

It enforces observation replay limits and registry, context, and prior identity.
It also enforces producer accounting, frame and reorder deadlines, and heartbeat silence.
Its first terminal fault invalidates queued events.
After this fault, no subsequent `FrameReady` crosses the boundary.

The fixed defaults give 30 seconds for the first heartbeat after transport activation.
Then, they require the declared one-second cadence within a three-second receipt deadline.
Replay high-water state never evicts within an epoch.
Operators MUST monitor the CLI's prior-identity and observation-stream utilization.
They MUST coordinate a new epoch before a cap.
Live library callers MUST use a Tokio runtime with its time driver enabled.

After assembly, `LifecycleDetector` admits explicit typed `StreamPosition`s.
Exact successors advance normally.
Continuity changes require a generation-advancing reset.
Rollover requires an unseen epoch at sequence and generation zero.
`reset_at`, `timeout_at`, and `rollover_at` return bounded hash-linked `LifecycleReceipt`s.

For an accepted frame, the lifecycle adapter creates one `AssessmentScope` from
the admitted producer and exact current position. It passes that scope to each
track assessment. It rejects an evaluated result if its scope differs from the
receipt producer or position.

Duplicate, replay, gap, and generation violations cause rejection and latch the state.
The legacy frame convenience path derives a local position from frozen sidecar v1 fields.
Thus, these receipts do not claim new NCP wire fields.
Assessment receipts bind the complete serialized reports.
Fault receipts bind the exact returned reason.

Standalone receipt decoding has a 16 KiB strict-JSON integrity gate.
It does not authenticate the writer or make the receipts durable.
Receipts remain in-memory audit evidence, not a durable journal.
See [`docs/STATE-MACHINE.md`](docs/STATE-MACHINE.md).

Every live payload uses a strict `galadriel_pid_observation` schema `1.0` envelope.
The envelope carries `ncp_version`, advisory `contract_hash`, `session_id`, and `producer_id`.
The two identities use the canonical Galadriel core ASCII grammar.
The runtime rejects a generic NCP-valid value that does not use this grammar.

The envelope also carries the historical Crebain-compatible `observation` shape.
[`galadriel-pid-envelope-v1.schema.json`](crates/galadriel-ncp/schemas/galadriel-pid-envelope-v1.schema.json) defines the exact contract for an external producer.
This file is a frozen producer-conformance schema.
The runtime `SidecarEnvelope` validation gate is the authoritative consumer-acceptance check.

The observation tap and assembler reject incompatible versions and undeclared fields.
They reject malformed metadata, cross-session or cross-producer payloads, and unsafe JSON integers.
They also reject invalid observations and replay or sequence violations.
Contract-hash drift is advisory and counted.

The standalone observation tap exposes explicit `Secure` and `QuietDevelopment` modes.
It also exposes bounded handoff APIs.
The `observe` command always calls `OperationalLiveReceiver::open_secure`.
It requires an externally pinned registry digest.

`LiveLimits::max_payload_bytes` bounds decoding after NCP callback delivery.
The pinned `ncp-zenoh` callback first materializes an owned payload.
A prospective deployment still needs a transport or broker message-size ceiling to bound receive-memory pressure.
Subscriber silence can mean no traffic, a realm or key mismatch, ACL denial, or producer failure.

Producers MUST use a fresh deployment-supplied session identifier for every process epoch.
Monitor heartbeats make all-modal silence visible after the finite initial grace.
They also make it visible after the configured steady monotonic deadline.

Producer lifecycle and liveness use a separate strict `galadriel_producer_event` schema `1.0`.
It uses `{realm}/session/{epoch}/sensor/galadriel-monitor`.
[`galadriel-monitor-envelope-v1.schema.json`](crates/galadriel-ncp/schemas/galadriel-monitor-envelope-v1.schema.json) freezes its bounded codec.
It also freezes adjacent-tagged heartbeat, outcome, miss, and frame-summary types.
The monitor tap, pinned registry, fail-closed assembler, lifecycle adapter, and operational receiver implement the Galadriel consumer boundary.
[`docs/PRODUCER-CONTRACT.md`](docs/PRODUCER-CONTRACT.md) describes this boundary.

The retained Crebain and Galadriel commit pair is a historical component fixture only.
Its accepted example identities remain valid under the stricter consumer grammar.
Version 0.9.0 has no accepted reciprocal producer pin or final cross-repository qualification.
Local evidence does not attest the active ACL of a remote router.
It also does not calibrate the detector.

These sidecar payloads belong to this project.
They are not normative NCP `SensorFrame`s.
A conforming producer MUST build the two exact named-sensor keys.
It MUST publish the serialized envelopes through `ZenohBus::put(..., Plane::Perception)`.
It MUST NOT call `put_sensor_named`.
That publisher gate correctly accepts only a complete NCP `sensor_frame`.

## Building and testing

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
cargo fetch --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml
cargo deny --offline --all-features --locked check
cargo deny --offline --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```

The workspace MSRV is **1.89**.
Crate targets forbid unsafe code.

## Honest limitations

- **Statistics-preserving attacks remain invisible.**
  A perturbation can preserve every statistic that Galadriel evaluates.
  Galadriel cannot identify that perturbation from those statistics.
  The [frustum attack](https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton) preserves camera and LiDAR semantic consistency.
  The cited result does not establish preservation of every Galadriel estimand.
- **Consistency is not truth.**
  A decoupled channel can represent a spoof or a true channel-specific event.
  It can also represent a coordinate mismatch or estimator artifact.
- **Historical Crebain captures have no consistency projection.** The retained historical
  opt-in producer fixture computed a registered Cartesian projection from one frozen prior.
  It does not qualify a current producer.
  Older JSONL fixtures remain baseline-only.
  Galadriel never falls back to their native mixed-frame vectors.
- **Gating censors evidence.**
  Association and chi-square rejection can turn the largest attacks into missing observations.
  Missingness is informative, not random.
- **Lifecycle absence is not health.**
  Explicit misses and rejections immediately break the affected statistical suffix.
  All-modal silence becomes a heartbeat fault in the operational receiver.
  Transport authentication still cannot prove physical truth.
- **Advisory attribution has no enforcement authority.**
  Authentication, ACLs, mTLS, and a safety governor remain separate requirements.
  A separately admitted control policy is also a separate requirement.

## Producer and integration boundary

Galadriel 0.9.0 implements its local consumer contract.
This contract includes bounded live taps, cross-route assembly, and pinned-registry admission.
It also includes lifecycle abstention, strict observer configuration, and component and in-process test paths.
The historical Crebain and Galadriel pair forms an earlier component compatibility fixture.
It does not close the current candidate across repositories.

The current reciprocal producer pin remains an explicit exclusion.
Final cross-repository qualification also remains an explicit exclusion.
A retained multi-process mTLS/ACL allow-and-deny campaign remains excluded.
Recorded pre-gate calibration remains excluded.

API or publication promotion beyond this review-gated research source release remains excluded.
See the [deployment security runbook](docs/SECURE-DEPLOYMENT.md) for the external procedure.
Do not count these exclusions as implementation success.

## Release verification boundary

Exact-candidate qualification uses schema `galadriel.candidate-qualification.v3`.
It requires an independently obtained allowed-signers file.
It also requires a clean external clone of the pinned RustSec advisory database.
It uses the exact 16-key base environment in `docs/DEPENDENCY-POLICY.md`.

All four broad mutation shards and all three focused outcomes are exact-candidate gates.
The observational mutation-baseline job remains residual evidence.
It is not a successful release gate.

A passing signed qualification tier MUST retain exactly 22 auxiliary command receipts.
Each receipt binds its command, sandbox, exit status, log, and output streams.
Each command also uses a stop-before-exec gate and fixed resource limits.
Qualification requires macOS `kqueue` and `/usr/bin/sandbox-exec`.
It uses one mode-0500 dispatch for 19 required command names.
The dispatch binds direct Apple developer Git, its developer tools, and `CPython 3.14.6`.
The sandbox denies direct execution of `/usr/bin/git` and `/usr/bin/python3`.
Critical host Git and SSH operations pin direct Apple developer Git, `/usr/bin/ssh-add`, and `/usr/bin/ssh-keygen`.
The host verifies each root-owned no-follow identity before and after execution.
It pins `sandbox-exec` to `/usr/bin/sandbox-exec` and its expected byte identity.
It records the resolved path, owner, group, and mode.
It removes dynamic-loader and toolchain selectors from the host command environment.

The candidate sandbox denies signal operations by default.
It permits signals only to the candidate process itself or its children.

The qualifier signals only the original process group while its root remains waitable.
It does not send a signal to an escaped numeric process identifier.
An observed escaped sandbox identity fails the run.
After root reap, it performs only read-only extinction checks.
macOS does not provide atomic recursive descendant tracking.
A short-lived reparented process can exit between scans.
The sandbox-identity scan detects an active detached process while it retains
that identity.

The inherited sandbox and resource limits apply before candidate execution.
A sandboxed process can request work from an existing external service.
The process scan cannot attribute that external service work.

Candidate evidence uses summary schema `galadriel.evidence.summary.v3`.
It uses manifest schema `galadriel.evidence.manifest.v3`.
It uses acceptance profile `galadriel-0.9-frozen-acceptance-metrics-v3`.
It uses bootstrap profile `splitmix64-rejection-group-metric-v1`.

Qualification builds the evidence runner separately.
The host creates a private directory with mode `0700`.
It copies the executable into that directory with mode `0500`.
The host executes that exact snapshot directly.
The manifest binds its digest and the exact candidate commit and tree.

The host then replays all six evidence files semantically.
It streams each trial and rebuilds the complete summary and report.
It verifies the accepted configuration, manifest, and checksum document.
It evaluates acceptance only from the rebuilt holdout summary.
Finalization repeats the same replay against the signed outer inventory.

The frozen 100-track design cannot pass `GLD-090-ACC-001` or `GLD-090-ACC-006`.
Their necessary track counts are 369 and 738.
The frozen work ceiling permits at most 248 holdout tracks with the current grid.
[`docs/POST-AUDIT-EVIDENCE.md`](docs/POST-AUDIT-EVIDENCE.md#frozen-acceptance-feasibility) gives the exact interval values.

Thus, an otherwise passing qualification records `NARROWED_REVIEW_REQUIRED`.
A signed human decision must select `NARROWED_GO` or `NO_GO`.
It cannot select `GO` while acceptance fails.

These checks establish internal contract agreement for one exact candidate.
They do not prove field calibration, deployment qualification, or independent replication.

A passing qualification tier MUST retain 15 two-run comparisons.
They cover one source archive, seven unpublished package archives, and seven SBOM documents.
Semantic checks bind source and package members to the candidate tree.
They also close SBOM fields against the validated `Cargo.lock` graph.
The license inventory is the exact 381-package `CARGO_DENY_HOST_FILTERED_GRAPH` subset of that 436-package graph.
See [`docs/DEPENDENCY-POLICY.md`](docs/DEPENDENCY-POLICY.md) for the exact checks.

These checks are author-operated on the recorded host.
They do not establish independent or cross-platform reproduction.
They do not qualify a deployment, deployed binary, security property, or permanent archive.

The release input pins the exact external RustSec origin, commit, tree, and inventory.
A qualification result remains bound to that pinned input.
[`docs/DEPENDENCY-POLICY.md`](docs/DEPENDENCY-POLICY.md) gives the exact identity.

The 0.9.0 publication procedure attaches two deterministic path-preserving evidence tar files.
It also attaches their canonical asset map and detached SSH signature.
The map binds qualification and closure bytes to the exact candidate and tree.
It also binds the signed `v0.9.0` tag object and target.
It identifies Sepehr Mahmoudian and contains explicit null DOI and Zenodo fields.

Use `repo_work/package_release_assets.py` to verify and reconstruct the four-file set.
The tool authenticates both internal tier signatures during build, verification, and reconstruction.
It binds each tier to the expected candidate commit and tree.
It also verifies each complete manifest inventory and `SHA256SUMS` file.

Get the trust root independently before you use the retained evidence.
GitHub's automatically generated source zip and tar links are convenience snapshots.
They are not signed assurance assets.

The [`0.9.0 release runbook`](release/0.9.0/RELEASE-RUNBOOK.md) gives the complete sequence.
The sequence covers the draft, downloads, signature, checksum, and fresh build.
It includes authenticated and anonymous downloads.

## Documentation

- [`docs/CLAIMS.md`](docs/CLAIMS.md) — normative 0.9.0 claim tiers and non-claims.
- [`docs/CORE-CONTRACT.md`](docs/CORE-CONTRACT.md) — typed domain, outcome, failure,
  and exact assessment-provenance contract.
- [`docs/CONFIGURATION-CONTRACT.md`](docs/CONFIGURATION-CONTRACT.md) — immutable
  accepted configuration, named profiles, capability choices, identities, and bounds.
- [`docs/STATISTICAL-CONTRACT.md`](docs/STATISTICAL-CONTRACT.md) — exact report-field
  estimands, verdict functionals, and repeated-look boundary.
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — adversaries, trust boundaries,
  required fail-closed behavior, and residual risks.
- [`docs/API-SURFACE.md`](docs/API-SURFACE.md) — stable core and experimental surfaces.
- [`docs/MIGRATION-0.9.md`](docs/MIGRATION-0.9.md) — source migration to typed 0.9
  identity, lifecycle, result, and dependence-companion APIs.
- [`docs/STATE-MACHINE.md`](docs/STATE-MACHINE.md) — positioned lifecycle admission,
  explicit reset/timeout/rollover, and bounded hash-linked receipts.
- [`docs/DEPENDENCY-POLICY.md`](docs/DEPENDENCY-POLICY.md) — immutable qualification
  pins, locked registry graph, and upstream release-claim boundary.
- [`docs/MOTIVATION.md`](docs/MOTIVATION.md) — threat basis and scope.
- [`docs/PAPER.md`](docs/PAPER.md) — research argument and current evidence boundary.
- [`docs/JUSTIFICATION.md`](docs/JUSTIFICATION.md) — when pairwise MI or a separately
  specified PID study can add information.
- [`docs/PID_RS_1_0_MIGRATION.md`](docs/PID_RS_1_0_MIGRATION.md) — retained
  preregistration history and exact pinned-source adaptation of the distinct MI
  and PID APIs and estimands.
- [`docs/EVALUATION.md`](docs/EVALUATION.md) — reproducible synthetic methodology.
- [`docs/PRODUCER-CONTRACT.md`](docs/PRODUCER-CONTRACT.md) — frozen observation and
  lifecycle/liveness wire contract plus operational acceptance boundary.
- [`docs/SECURE-DEPLOYMENT.md`](docs/SECURE-DEPLOYMENT.md) — exact-epoch mTLS/ACL profile,
  runnable observer, health sequence, and external acceptance drills.
- [`docs/POST-AUDIT-EVIDENCE.md`](docs/POST-AUDIT-EVIDENCE.md) — one-command,
  checksummed streaming evidence artifact.
- [`docs/RELATED-WORK.md`](docs/RELATED-WORK.md) — alternative and complementary methods.
- [`docs/METHOD-SELECTION-DECISIONS.md`](docs/METHOD-SELECTION-DECISIONS.md) — selected methods, exact profile rationale, alternatives, evidence ceilings, and reopen conditions.
- [`docs/ADVISORY-BOUNDARY.md`](docs/ADVISORY-BOUNDARY.md) — non-authoritative downstream
  use that does not widen authority, and prohibited control connections.
- [`docs/ECOSYSTEM-CONNECTIONS.md`](docs/ECOSYSTEM-CONNECTIONS.md) — dated exact-cut
  provenance and the required, optional, prospective, or absent pid-rs, NCP, Crebain,
  Haldir, Prisoma, Engram/Paper2Brain, ROS, and external-authority relationships.
- [`release/0.9.0/README.md`](release/0.9.0/README.md) — auditable handoff, ledger,
  claims, evidence, and version-adaptation record.

## License

Galadriel is licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
You can select either license.
Galadriel is part of the [`sepahead`](https://github.com/sepahead) ecosystem.
