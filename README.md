<p align="center">
  <img src="assets/galadriel-logo.svg" alt="Galadriel's Mirror — a sentinel shield whose visor carries a sweeping red scanning eye; three fiber-optic sensor channels stream into it from below." width="200" height="200" />
</p>

<h1 align="center">galadriel</h1>

<p align="center"><strong>Galadriel's Mirror</strong> — an experimental cross-sensor consistency monitor for multi-sensor fusion.</p>

<p align="center">
  <a href="https://github.com/sepahead/galadriel/actions/workflows/ci.yml"><img src="https://github.com/sepahead/galadriel/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0">
  <img src="https://img.shields.io/badge/rust-1.88%2B-orange.svg" alt="Rust 1.88+">
  <img src="https://img.shields.io/badge/status-research%20prototype-orange.svg" alt="status: research prototype">
  <img src="https://img.shields.io/badge/unsafe-forbidden-success.svg" alt="unsafe forbidden">
</p>

Galadriel asks whether several sensors observing one track still agree. It combines
per-channel Normalized Innovation Squared (NIS) evidence with signed cross-channel
correlation. An optional PID path adds sign-invariant mutual-information evidence for
research into nonlinear or synergistic dependence.

> **Honest scope.** Galadriel detects statistical inconsistency, not truth. It cannot
> prove that an attributed channel is malicious, cannot detect an attacker that preserves
> cross-channel consistency, and must not silently veto a control path. Its reports are
> advisory and are not calibrated posteriors.

> **Current integration status.** The bundled crebain fixture proves bounded JSONL
> parsing and exercises the NIS baseline. It does **not** validate production
> cross-sensor correlation or PID. Normal crebain captures omit the attested common
> projection; native radar residuals are polar while other residuals are Cartesian, sequential filter
> updates do not share one frozen prior, and association/gating suppresses rejected
> measurements. With those preconditions absent, correlation and fused assessment
> correctly remain `InsufficientEvidence`.

The research background and synthetic study design are documented in
[`docs/PAPER.md`](docs/PAPER.md), [`docs/JUSTIFICATION.md`](docs/JUSTIFICATION.md), and
[`docs/EVALUATION.md`](docs/EVALUATION.md). Those documents describe synthetic evidence,
not field validation or production readiness.

## Quickstart

```bash
cargo run --bin galadriel -- demo
```

The demo generates synthetic, common-frame observations. It demonstrates behavior; it
does not show that current crebain residuals satisfy the detector's estimand.

## What the core requires

Galadriel consumes `PidObservation` records containing NIS and degrees of freedom.
Cross-sensor analysis additionally requires an optional `consistency_projection`:
a bounded signed vector plus non-zero physical-frame, projection-context, and frozen-prior
identifiers. Native `innovation` / `innovation_cov` fields remain diagnostic and are never
used as a cross-modal fallback. The detector requires:

- one track per assessment;
- strictly increasing, unique sequence numbers per track and modality;
- finite, valid observations with stable degrees of freedom;
- exact sequence alignment for cross-channel windows;
- matching projection dimension, frame ID, and context ID across modalities;
- one matching frozen-prior ID per sequence, never reused at another sequence;
- enough fresh observations from all configured modalities.

Invalid configuration or input returns `Err(...)`; it is not converted into a verdict.
Missing, stale, geometrically incomparable, or statistically insufficient evidence
returns `InsufficientEvidence`, not `Nominal`.

Crebain can emit JSONL when `CREBAIN_PID_JSONL` is set, but its normal runtime path only
enables the basic emitter. It does not emit the producer-attested common projection
needed for correlation/PID. Its successful-update-only stream is also downstream of
association and a chi-square gate, so missing or rejected measurements are censored
rather than represented. The current seam is suitable for contract and baseline smoke
testing, not for estimating production cross-modal dependence.

## Detector layers

### NIS/CUSUM magnitude layer

For each track and modality, a sliding NIS window is compared with its chi-square
reference and monitored for sustained shifts. Per-assessment channel tests control the
family-wise significance budget. A report is `Nominal` only when every configured
channel is fresh, ready, and consistent.

| Evidence | Verdict |
|---|---|
| all configured channels ready and consistent | `Nominal` |
| minority of channels anomalous while peers remain usable | `Spoof { channels }` |
| most/all channels inflated together | `Jam` |
| positive but non-attributable or lower-direction evidence | `Anomaly` |
| too little, stale, missing, or incompatible evidence | `InsufficientEvidence` |
| invalid input or configuration | `Err(...)` |

### Signed-correlation consistency layer

The default consistency layer uses signed Pearson correlation, family-wise
significance, and a unique strict-majority positive-consensus clique. Negative
correlation is not accepted as corroboration. A dyad, a tied clique, or a collection
with no coherent positive consensus cannot support outlier attribution.

Every producer-declared projection axis is assessed. The significance budget is
Bonferroni-split across axes and channel pairs. Different positive channel attributions
across axes, or a positive axis beside an insufficient axis, become `Anomaly` rather
than a confident `Spoof`.

`galadriel_core::assess_default` fuses magnitude and consistency evidence without
turning an unavailable consistency assessment into `Nominal`.

### PID research layer

The optional `pid` feature adds geometry-gated KSG mutual information and
shared-exclusions PID atoms. MI/PID is sign-invariant and therefore **additive**: it
cannot repair missing geometry, create a consensus from a dyad, or override
contradictory signed correlation. Canonical synthetic studies show regimes where this
evidence may be useful; they do not show that those regimes occur in crebain output.

## Project status

**Version `0.1.0`, pre-1.0, research prototype.** The API is not frozen, there is no
tagged release, and every workspace package currently sets `publish = false`. Unit,
property, integration, and synthetic-study tests exercise the implementation, but no
current evidence supports calling it field-validated or production-ready.

| Crate | Role | Evidence level |
|---|---|---|
| [`galadriel-core`](crates/galadriel-core) | NIS/CUSUM, signed correlation, fused assessment | Tested research core |
| [`galadriel-sim`](crates/galadriel-sim) | synthetic scenarios and injections | Synthetic only |
| [`galadriel-cli`](crates/galadriel-cli) | `demo` / `replay` driver | Operator prototype |
| [`galadriel-pid`](crates/galadriel-pid) | KSG-MI / PID evidence | Optional research path |
| [`galadriel-ncp`](crates/galadriel-ncp) | bounded JSONL ingest; versioned named-sensor envelope; optional Zenoh subscriber | Payload/ingest tested; no live Crebain publisher or deployment evidence |
| [`galadriel-eval`](crates/galadriel-eval) | Monte Carlo evaluation and cost bench | Synthetic only |
| [`galadriel-justify`](crates/galadriel-justify) | canonical forced-vs-justified studies | Synthetic/theoretical only |

The workspace MSRV is **Rust 1.88**. Mutable test totals and benchmark values are not
treated as project-status claims.

## Features and dependencies

| Feature | Pulls | Adds |
|---|---|---|
| default | no sibling integration crates | core, simulator, CLI |
| `pid` | `pid-core` | KSG-MI/PID research layer |
| `ncp` | `ncp-core` | bounded JSONL ingest; NCP 0.7 key helpers and versioned sidecar envelope; the CLI `replay` subcommand |
| `ncp-live` | `ncp-zenoh`, `tokio` | read-only named-perception subscriber with explicit secure/development mode and bounded sequence state |

The public `pid-rs` repository and NCP's `ncp-core`/`ncp-zenoh` crates are pinned by
immutable public tags and exact lockfile commits (`v0.4.0` and `v0.7.1`, respectively).
A fresh clone requires no sibling checkout, private repository token, or global Git
credential rewrite.

The live subscriber uses NCP's named perception route,
`{realm}/session/{id}/sensor/galadriel-pid`, built through
`Keys::try_sensor_named(id, "galadriel-pid")`. NCP's hardened ACL already covers that route
with its least-privilege sensor-plane rules: an authenticated plant/producer may publish
and an authenticated observer may subscribe. Galadriel does not yet have a production
Crebain publisher or an end-to-end mTLS deployment test, so compilation is still not live
integration evidence.

Every live payload is a strict `galadriel_pid_observation` schema `1.0` envelope carrying
`ncp_version`, advisory `contract_hash`, `session_id`, `producer_id`, and the existing
Crebain-compatible `observation`; the exact independent-producer contract is
[`galadriel-pid-envelope-v1.schema.json`](crates/galadriel-ncp/schemas/galadriel-pid-envelope-v1.schema.json)
(a descriptive snapshot — the runtime `SidecarEnvelope` validation gate is normative).
The tap rejects incompatible versions, undeclared fields, malformed
metadata, cross-session/cross-producer payloads, unsafe JSON integers, invalid observations,
and replay/sequence violations. Contract-hash drift is accepted per NCP policy but counted
for operators. Callers must choose `TransportMode::Secure` (strict mTLS client config) or
explicitly acknowledge `TransportMode::QuietDevelopment`; there is no implicit security
default. Subscriber silence can still mean no traffic, a realm/key mismatch, ACL denial,
or producer failure. Producers must use a fresh session ID for every process epoch, and
all-modal silence still requires a heartbeat.

This is a project-owned sidecar payload, not a normative NCP `SensorFrame`. A future
Crebain producer therefore builds the key with
`bus.keys().try_sensor_named(session_id, "galadriel-pid")` and publishes the serialized
envelope through `ZenohBus::put(..., Plane::Perception)`. It must not call
`put_sensor_named`, whose publisher gate correctly accepts only a complete NCP
`sensor_frame`.

## Building and testing

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo build -p galadriel-core --no-default-features --locked
cargo deny --all-features --locked check
```

The workspace MSRV is **1.88**. Crate targets forbid unsafe code.

## Honest limitations

- **Consistency-preserving attacks remain invisible.** The
  [frustum attack](https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton)
  is a concrete example of an attack that preserves camera/LiDAR consistency.
- **Consistency is not truth.** A decoupled channel can represent a spoof, a true
  channel-specific event, a coordinate mismatch, or an estimator artifact.
- **Current crebain output has no consistency projection.** Radar's native innovation is
  polar while visual/acoustic innovations are Cartesian; sequential updates use
  different priors. Galadriel therefore ignores those native vectors for consistency.
- **Gating censors evidence.** Association and chi-square rejection can turn the largest
  attacks into missing observations. Missingness is informative, not random.
- **No input means no detector call.** Per-channel silence can be noticed when another
  channel advances assessment time. All-modal silence requires an external producer or
  transport heartbeat.
- **Advisory attribution is not enforcement.** Authentication, ACLs, mTLS, a safety
  governor, and an independently reviewed control policy remain separate requirements.

## Producer and integration roadmap

The next milestone is an honest producer contract and recorded evaluation, not a
release label:

1. Emit `consistency_projection` for all modalities from a **common frozen prior**, in
   one documented **common coordinate frame**, with stable frame/context IDs and a
   unique shared prior ID per sequence.
2. Emit association/gate misses and rejected updates so selection bias and liveness are
   observable.
3. Add producer **heartbeats** and use a fresh NCP **session identifier** for every
   process epoch. The live schema and restart identity are now explicit; the producer
   implementation is still absent.
4. Provide a supported normal-runtime option for the common projection (and optional
   native innovation/covariance diagnostics); `CREBAIN_PID_JSONL` alone does not.
5. Evaluate recorded, pre-gate data and report producer selection effects separately
   from detector errors.
6. Add the Crebain NCP named-sensor publisher under the existing least-privilege
   sensor-plane ACL, then test traffic, denial, restart, decode-failure, and
   all-modal-silence behavior end to end over mTLS.
7. Keep packages `publish = false` until the producer contract, recorded evidence, and
   API stability receive an explicit release review.

## Documentation

- [`docs/MOTIVATION.md`](docs/MOTIVATION.md) — threat grounding and scope.
- [`docs/PAPER.md`](docs/PAPER.md) — research argument and current evidence boundary.
- [`docs/JUSTIFICATION.md`](docs/JUSTIFICATION.md) — when MI/PID can add information.
- [`docs/EVALUATION.md`](docs/EVALUATION.md) — reproducible synthetic methodology.
- [`docs/RELATED-WORK.md`](docs/RELATED-WORK.md) — competing and complementary methods.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option. Part of the [`sepahead`](https://github.com/sepahead) ecosystem.
