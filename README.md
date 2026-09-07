<p align="center">
  <img src="assets/galadriel-logo.svg" alt="Galadriel's Mirror: a shield with a red eye and three incoming sensor channels." width="200" height="200" />
</p>

<p align="center"><a href="assets/archive/logos/README.md">Logo design archive</a></p>

# Galadriel's Mirror

<p align="center"><strong>Advisory sensor-consistency monitoring for tampering research.</strong></p>

<p align="center">
  <a href="https://github.com/sepahead/galadriel/actions/workflows/ci.yml"><img src="https://github.com/sepahead/galadriel/actions/workflows/ci.yml/badge.svg" alt="continuous integration"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0">
  <img src="https://img.shields.io/badge/rust-1.89%2B-orange.svg" alt="Rust 1.89+">
  <img src="https://img.shields.io/badge/source%20state-unpublished%20candidate-orange.svg" alt="source preparation state: unpublished candidate">
</p>

Galadriel checks whether sensors observing the same track remain statistically consistent.
It reports magnitude anomalies, signed cross-channel disagreement, and insufficient evidence.
These reports support inspection and experiments with possible sensor tampering.
They do not establish sensor truth, malicious intent, or the cause of a disagreement.

Galadriel runs as a standalone Rust library and command-line tool.
Optional adapters connect selected evidence sources.
No report grants permission, changes a controller, or vetoes an action.
`Nominal` is evidence, never authority.

**Source preparation state for this tree: unpublished pre-1.0 research candidate.**
The package version remains `0.9.0`, with publication to crates.io disabled.
At this source-generation state, no `v0.9.0` tag or GitHub release was recorded.
The source ledger retains **107 `OPEN` and nine `NOT_CLAIMED` requirements**.
A component source gate does not close the research release or qualify a deployment.

## Start with the standalone demo

Use the pinned Rust toolchain and run from the repository root:

```bash
git clone https://github.com/sepahead/galadriel.git
cd galadriel
cargo run --locked --bin galadriel -- demo --frames 128 --seed 7
```

The demo constructs synthetic common-frame observations and exercises the actual detector.
Its scenario names describe constructed clean, channel-perturbation, broad-degradation, and moment-matched inputs.
A detector verdict does not independently prove those causes.

The default command requires no running ecosystem peer.
Its selected build graph excludes the optional PID and transport libraries.

| Workflow | Purpose | Evidence boundary |
| --- | --- | --- |
| [Standalone core](crates/galadriel-core/README.md) | Typed observations, magnitude, signed consistency, sealed reports | Caller-declared source labels and statistical assumptions need independent justification |
| [Scalar library](crates/galadriel-local-adapter/README.md) | Bounded NIS streams using the actual exploratory magnitude engine | Magnitude diagnostic, not a complete signed-consistency report |
| [Local NCP process](crates/galadriel-local-adapter/README.md#optional-private-pipe-owner) | Private-pipe, record-only assessment of an exact body response | Current application supplies one Visual modality per entity and retains insufficiency |
| [Retained wire-0.8 workflows](docs/WORKFLOWS.md#cli-features-and-workspace-dependencies) | Sidecars, diagnostic JSONL replay, optional Zenoh receiver | Separate historical transport; deployment and calibration remain unqualified |
| [Optional MI and offline PID](docs/PID_RS_1_0_MIGRATION.md) | Explicit dependence questions and synthetic studies | These methods do not alter the core verdict or prove attack mechanisms |

## How evidence becomes a report

<picture>
  <source media="(max-width: 700px)" srcset="assets/architecture-mobile.svg">
  <img src="assets/architecture.svg" alt="Separate full-core and scalar-monitor paths validate evidence, retain insufficiency, and produce advisory reports without command authority." width="1200">
</picture>

**Text alternative.** The full core validates a track, exact sequence, scope, and comparable sensor projections.
Magnitude and signed-consistency evidence enter conservative fusion.
The independent scalar adapter uses magnitude evidence only.
Its current NCP application lacks the second modality and signed projection required for a complete assessment.
Both paths preserve missingness and return advisory results.
Optional mutual information (MI) accompanies the unchanged core report.
Partial information decomposition (PID) remains an offline study.

[Open the wide SVG](assets/architecture.svg) · [Open the mobile SVG](assets/architecture-mobile.svg) · [Read the detector mathematics](docs/STATISTICAL-CONTRACT.md)

The figures use native vector text and shapes.
Open an original SVG for a larger view.
The hosting application controls its own image zoom behavior.

### A small numerical example

Let `r` be an innovation: the measured value minus the predicted value.
Let `S` be its innovation covariance, and let `d` be its declared degrees of freedom.
Normalized innovation squared (NIS) is

```text
q = rᵀ S⁻¹ r
```

For `r = [2, 0, 0]` meters and `S = diag(4, 1, 1)` square meters, `q = 1`.
The units cancel, so `q` and `d = 3` are dimensionless.
This constructed example explains the calculation. It is not a recorded measurement.

The reference `q ~ χ²(d)` requires justified covariance, association, and observation assumptions.
A chi-square window-sum reference also requires the declared temporal sampling law.
Galadriel validates representation and bounds. It does not establish those assumptions.
Cumulative sum (CUSUM) evidence records sustained changes without a calibrated p-value.
Repeated inspection does not inherit a mission-wide false-alert guarantee.

Signed correlation needs a common physical frame, projection context, and frozen pre-update prior at each exact sequence.
Its sign distinguishes positive agreement from negative correlation.
A producer's projection declaration is provenance metadata, not cryptographic or physical proof.
The detector never substitutes mixed native residuals when the common projection is absent.
The [statistical contract](docs/STATISTICAL-CONTRACT.md) and [detector SVG](assets/detector-evidence.svg) define the complete calculation and fusion rules.

### Reading outcomes

| Outcome | Meaning |
| --- | --- |
| `Nominal` | Every required component is ready and consistent under its declared model |
| `AttributedInconsistency` | Statistical inconsistency is assigned to named channels; its physical cause remains unclassified |
| `BroadDegradation` | The configured evidence indicates widespread degradation |
| `UnclassifiedAnomaly` | Positive anomaly evidence lacks the conditions for a narrower classification |
| `InsufficientEvidence` | Required fresh, comparable, or statistically usable evidence is unavailable |
| `Err(...)` | The input or configuration is invalid |

An anomaly is not proof of tampering.
Channel attribution does not identify an attacker or causal mechanism.
A coordinated perturbation can preserve every evaluated statistic and remain invisible.
Every report retains `calibrated_posterior = false`.

## Missing evidence stays missing

The named scalar detector requires at least 32 samples and **two modalities**.
Its window holds 64 samples per modality.
Three coordinates from one Visual sensor are one modality, not three independent sensors.
The current scalar NCP application therefore preserves `InsufficientEvidence` for its one-Visual input.

Available zero is a measurement. An unavailable observation is a different state.
Association misses and rejected updates can censor the strongest disturbances.
Galadriel cannot replace them with zeros or fabricate a covariance or signed projection.

The scalar library clears and retires a window when an expected channel becomes unavailable.
The local owner reports an initial birth as `not_ready` without a detector report.
After activation, unavailable evidence retires that entity until a fresh monitor generation is prepared.
The [adapter contract](crates/galadriel-local-adapter/README.md#missingness-and-failure) defines exact sequence and failure rules.

Missing calls do not advance a library clock.
The retained live receiver uses explicit heartbeats and bounded deadlines to detect all-channel silence.
Neither lifecycle integrity nor transport authentication proves physical truth.

## Selectable NCP integration

The Neuro-Cybernetic Protocol (NCP) is optional.
The independent local package compiles the `monitor` role under `galadriel.scalar-nis-record-only.v1`.
Its `ncp-local` feature selects SDK `1.0.0` at public revision `de751d499b5e07d1c95a072e08255083d77cb38b`.
The historical seven-member workspace retains its separate wire-0.8 dependencies.

```bash
cargo build --locked \
  --manifest-path crates/galadriel-local-adapter/Cargo.toml \
  --features ncp-local --bin galadriel-ncp-local
```

The supervisor launches this process with fresh run and generation identities and private standard-input/output pipes.
Preparation binds the expected body generation.
Each assessment verifies a committed body response, exact plan, roster, step, time, and supplied-byte digest.
It preserves actual source diagnostics and the core engine's report.
One exact response remains retained until acknowledgment.
An exact retry does not ingest the frame twice.

This application admits one through three entities and at most 1,024 steps.
It is record-only and accepts no command capability.
The supervisor owns process custody, deadlines, termination, and request-to-response joins.
Response integrity does not authenticate the physical producer or make a receipt durable.

Select this adapter only in a composition that satisfies its exact input contract.
It does not require every ecosystem project as a dependency.
It requires the named scalar body response and cannot directly consume CREBAIN's city RGB, pressure, or thermal arrays.
Those arrays do not automatically supply comparable innovations or signed projections.

| Project | Relationship | Current limit |
| --- | --- | --- |
| [CREBAIN](https://github.com/sepahead/crebain) | Optional evidence producer; current local application consumes its scalar-body response shape | No Cargo dependency on CREBAIN; city multimodal detector integration remains unqualified |
| [NCP](https://github.com/sepahead/NCP) | Optional local contract library or separate retained wire-0.8 libraries | Galadriel owns no broker or controller |
| [pid-rs](https://github.com/sepahead/pid-rs) | Optional algorithm library for MI and offline PID | Shared library code does not establish independent replication |
| [Prisoma](https://github.com/sepahead/prisoma) | A separately owned capture or experiment consumer can retain advisory records | Galadriel owns no store or embodied experiment runner |
| [Engram](https://github.com/sepahead/engram) | Optional external neural controller and supervisor in a separately qualified composition | No neural simulator or general Engram integration is provided here |
| [Haldir](https://github.com/sepahead/haldir) | Prospective separately admitted downstream policy | No Galadriel-to-Haldir runtime or authority edge exists |

The [dated ecosystem record](docs/ECOSYSTEM-CONNECTIONS.md) retains earlier revisions and explicit non-edges.
The [local adapter guide](crates/galadriel-local-adapter/README.md) owns the newer narrow component interface.
Neither record closes final cross-repository qualification.

<details>
<summary>Exact retained ecosystem inspection identities</summary>

The unchanged [inspection cut](release/0.9.0/ecosystem-cut.json) records these historical objects and explicit non-edges.
Only its dependency rows are Cargo pins.
The other rows do not identify current peer heads or grant reciprocal compatibility.
The newer local SDK revision above is a separate component dependency.

| Project and observation | Exact retained object |
| --- | --- |
| pid-rs dependency | `1cd2424f7967e1752dcc8e53859e8fdad3566f51` |
| NCP wire-0.8 dependency | `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e` |
| NCP design inspection, July 18 | `10492c81ac671ef1909962a9f1fede33781b9933` |
| Crebain inspection, July 18 | `0a58a5b8dd799884ddb06f1308b1748216fab322` |
| Haldir discovery, July 18 | `0e94f61cfd5c78482198a765157571746a256181` |
| Haldir later inspection, July 18 | `dd3d8a1c993721f89a1edb04dec5247761c694ad` |
| Prisoma inspection, July 18 | `63cff105e0e40281376e6f827d7782e9b351961a` |
| Engram/Paper2Brain example realm | No integration object in that cut |
| ROS / ROS 2 | No interface in that cut |
| External authority | No command edge |
| Haldir inspection, July 22 | `c0e4b3d156500684329a92bcb16e0609894fd738` |
| Haldir inspection, July 23 | `590ba767b32a27d9dd61a2462968306c1052434e` |
| Paper2Brain inspection, July 23 | `24e74b781a5bf8af069f69cbc2d0c42d89008211` |
| NCP status inspection, August 3 | `1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd` |
| Prisoma inspection, August 14 | `efcad9943af818913702f11c47ed0c280a2a1f13` |

All observation dates are in 2026.
The detailed [ecosystem record](docs/ECOSYSTEM-CONNECTIONS.md) preserves the supersession order and missing evidence.

</details>

## Evidence and limits

The retained [post-audit study](docs/POST-AUDIT-EVIDENCE.md) is diagnostic evidence from exact historical inputs.
Its clean synthetic arm reports 26.26 alert episodes per track-hour and a 0.9167 mission probability of at least one alert.
Autocorrelation increases those observed rates.
Ordinary acoustic missingness causes 99.35% fused abstention in its recorded arm.
These results expose calibration and availability limits, not accepted operational performance.

The historical CREBAIN capture lasts approximately 15.8 seconds and lacks the required common projection.
It supports bounded parsing and basic NIS checks only.
Full-detector recorded-stream metrics remain `not_estimable`.
Synthetic results cannot fill that gap.

The frozen acceptance design retains structural failures.
Two criteria require at least 369 and 738 tracks.
The frozen grid permits at most 248 holdout tracks.
A passing execution can therefore still require `NARROWED_REVIEW_REQUIRED`.
No documentation or component source gate changes those thresholds or grants `GO`.

Current claims exclude field calibration, accepted operational rates, production support, and deployment-qualified attack coverage.
External certificate/ACL campaigns, downstream policy integration, and complete native ecosystem qualification remain separate gates.
Read the [claims matrix](docs/CLAIMS.md), [security policy](SECURITY.md), and [release record](release/0.9.0/README.md) before assigning a stronger meaning.

## Development and documentation

```bash
cargo test --locked -p galadriel-core --no-default-features
cargo test --locked \
  --manifest-path crates/galadriel-local-adapter/Cargo.toml \
  --features ncp-local
```

These are focused component checks.
The [maintainer workflow](docs/MAINTAINER_WORKFLOWS.md) preserves the complete repository and release-gate instructions.
Consider both root and optional adapter workflows for affected changes.
Rust `1.89.0` is the workspace minimum.
The current-stable gate pins `1.97.1`.
All Rust targets forbid unsafe code.

| Read next | Purpose |
| --- | --- |
| [Workflow guide](docs/WORKFLOWS.md) | Detailed standalone, detector, historical transport, and evidence procedures |
| [Core contract](docs/CORE-CONTRACT.md) · [Configuration](docs/CONFIGURATION-CONTRACT.md) | Typed data, accepted profiles, identity, and bounds |
| [Statistical contract](docs/STATISTICAL-CONTRACT.md) · [Evaluation](docs/EVALUATION.md) | Mathematical assumptions, estimands, and experiments |
| [Local adapter](crates/galadriel-local-adapter/README.md) | Scalar library, private-pipe owner, and exact source gate |
| [Producer contract](docs/PRODUCER-CONTRACT.md) · [State machine](docs/STATE-MACHINE.md) | Comparable observations and lifecycle handling |
| [Agent contract](AGENTS.md) · [Contributing](CONTRIBUTING.md) | Maintainer and coding-agent instructions |
| [Historical review archive](docs/history/2026-07-10-review/README.md) | Unchanged former `.superstack` records and original source identities |

Author and maintainer: **Sepehr Mahmoudian**.
No project DOI or Zenodo record exists.
Galadriel is licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your choice.
