# Local scalar magnitude adapter

Status: experimental scalar library and optional local NCP process owner.
Full ecosystem and release qualification remain separate.

This independent Cargo workspace reuses the existing `galadriel-core` package.
Its package version remains `0.9.0`, and crate publication is disabled.
The root workspace excludes this package and retains its original seven members.
Root workspace commands do not test or build this adapter.

This crate invokes Galadriel's actual `SubsetMagnitudeV0_9` detector.
It accepts scalar normalized innovation squared (NIS) evidence and declared degrees of freedom.
It fabricates no covariance, signed projection, modality, or partial information decomposition (PID) value.

A report retains the actual engine's research classification and configuration identity.
It is a magnitude diagnostic, not a whole-stream `DefaultReport`.
It carries no authenticated producer binding or command authority.
`calibrated_posterior` remains `false`.

## Preparation and use

Prepare one track, clock domain, first sequence, ordered modality roster, and validated detector configuration.
Each roster entry binds a modality and positive degrees of freedom.
Use a separately bounded roster of monitor instances for multiple tracks.
The caller must preserve each instance's external source and generation binding.

```rust
use galadriel_core::{ClockDomain, DetectorConfig, Modality, Sequence, TimestampMillis, TrackId};
use galadriel_local_adapter::{NisEvidenceParams, ScalarChannelParams, ScalarMonitor};

let mut monitor = ScalarMonitor::prepare(
    TrackId::new(7)?,
    ClockDomain::SimulationTime,
    Sequence::new(0)?,
    &[ScalarChannelParams { modality: Modality::Radar, dof: 3 }],
    DetectorConfig::standalone_advisory_v0_9()?,
)?;
let assessment = monitor.assess_frame(
    Sequence::new(0)?,
    TimestampMillis::new(0)?,
    &[Some(NisEvidenceParams { nis: 3.0, dof: 3 })],
)?;
assert!(!assessment.calibrated_posterior());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example scalar is a synthetic component input.
It does not represent a CREBAIN measurement.
The unchanged named detector needs at least 32 samples and two modalities.
A single modality cannot produce complete nominal evidence.

The named detector uses a 64-sample window and a maximum sequence gap of one.
Its inter-sample limit is 10,000 milliseconds.
Its complete parameters remain in `docs/CONFIGURATION-CONTRACT.md`.
The adapter requires exact consecutive sequence numbers even when a custom detector permits a larger gap.

## Missingness and failure

Each frame contains one explicit availability slot per prepared channel.
`Some` supplies actual scalar evidence. `None` declares unavailable evidence.
Available zero is a measurement. Missing evidence never becomes zero.

The adapter validates every present scalar before it changes detector state.
`validate_frame` provides the same complete preflight without mutation or position reservation.
The protocol owner can use it before the execution boundary.
Wrong arity, non-finite NIS, negative NIS, or changed dimensions reject the complete frame before ingestion.
Corrected input can reuse that unconsumed position.

A missing channel returns a sealed abstention with the exact unavailable modalities.
It clears and retires the monitor's statistical window.
Later calls fail until the caller prepares a new instance under a fresh external generation.
This library does not authenticate that external generation.

Sequence gaps, replay, timestamp regression, excessive timestamp gaps, and unexpected engine failures also retire the instance.
Cancellation and transport failures belong to the external NCP owner.
The library does not infer silence from missing calls or read a wall clock.

## Mathematical boundary

For innovation vector `r` and innovation covariance `S`, NIS is `q = rᵀ S⁻¹ r`.
Both `q` and its degrees of freedom `d` are dimensionless.
The reference `q ~ χ²(d)` requires a justified covariance, association, and observation model.
The window-sum reference additionally requires the declared temporal sampling assumptions.
Galadriel validates representation. It does not establish those assumptions.

The scalar adapter assesses only magnitude and cumulative-sum evidence.
It cannot assess signed cross-channel consistency without the required common projection.
It does not reinterpret missing projection evidence as a complete detector result.
Its configuration digest establishes identity, not scientific validity.

## Bounds and checks

One monitor accepts one track and one through six unique modalities.
Preparation costs `O(m)` time and memory for `m` modalities.
The detector retains at most `m × window_len` scalar observations.
One frame stages at most six scalar observations before mutation.
Retained samples and per-frame work do not grow with completed experiment length.
These structural bounds are not platform timing or allocator measurements.

```bash
cargo test --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml --no-default-features
cargo clippy --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml --no-default-features --all-targets -- -D warnings
```

Tests compare the adapter with the actual core engine.
Separate synthetic two-modality controls exercise nominal and anomalous paths.
Negative controls cover missingness, invalid numbers, changed dimensions, replay, gaps, clock discontinuity, and exhaustion.
These component checks do not qualify NCP transport, real producer semantics, field calibration, or Haldir gating.

## Optional private-pipe owner

The `ncp-local` feature adds the `galadriel-ncp-local` binary and the `ncp_local::local_owner` library constructor.
It uses the standalone `ncp-local` Rust SDK.
This SDK contains the bounded local contract and has no Zenoh dependency.
The historical `galadriel-ncp` consumer retains its separate NCP 0.8 dependency.
The default library has no NCP dependency.
The existing Galadriel wire-0.8 sidecar and Zenoh profiles remain separate.

```bash
cargo build --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml --features ncp-local --bin galadriel-ncp-local
```

The supervisor launches the binary with `--run-id UUID --generation UUID`.
Each value must be a fresh, canonical UUID version 4.
The binary uses inherited standard input and standard output as private protocol pipes.
Standard output contains only length-prefixed NCP frames.
The compiled role is `monitor`.
The binary accepts no endpoint, role override, shell command, or executable selector.

Preparation uses shared NCP `PrepareData` and `RunPlan` types.
The exact application profile is `galadriel.scalar-nis-record-only.v1`.
The closed configuration contains only `body_generation`, which binds the expected body process generation.
The body and monitor generations must differ.
The plan admits one through three entities, at most 1,024 steps, and only direct simulation with record-only monitoring.
Unsupported gated, advisory-control, or calibrated-posterior selections fail before preparation.

Each `assess` body contains only `body_response`, the complete committed body `step` response.
Before ingestion, the owner checks its schema, role, run, generation, profile, sequence, outcome, and complete response digest.
It then validates the complete shared `BodyResult`, snapshot, plan, roster, time, and source diagnostics.
Later body results must join the preceding accepted snapshot digest.
The supervisor retains responsibility for authentic process custody and the original request-to-response join.
Local digest verification establishes supplied-byte integrity, not producer authentication.

Each entity owns one scalar monitor instance.
The actual producer track identifier and fusion sequence enter that instance unchanged.
The source sensor and track remain fixed after its first observation.
The producer fusion sequence must advance by exactly one.
Body steps and producer fusion sequences remain distinct identifiers.
Integer microseconds convert exactly to milliseconds under the shared plan.

An initial birth or unavailable update returns `not_ready` and no detector report.
The first actual update creates the detector at its actual producer sequence.
Birth or unavailable evidence after activation permanently retires that entity's window.
Later updates return `retired` with no report until a fresh monitor generation is prepared.
No fabricated observation or producer sequence performs this retirement.

The output schema is `galadriel.local.assessment.v1`.
It binds the plan, body response digest, snapshot digest, step, and sample time.
It includes the actual ordered source diagnostics and serialized detector reports.
Classification and configuration identity remain explicit, and `calibrated_posterior` remains `false`.
The top-level configuration digest identifies the detector parameters.
Each engine report's `config_identity` also binds the selected exploratory research capability.
Those two digests intentionally identify different objects.
One Visual channel with three declared dimensions cannot satisfy the unchanged two-modality minimum.
Its actual engine report therefore retains `InsufficientEvidence`.

`finish` requires exactly `plan_digest` and `completed_steps`, joined to the prepared plan and exact terminal count.
`abort` accepts an empty object only.
Abort, pipe loss, malformed framing, or output failure retires the endpoint through the shared NCP owner.
The supervisor must enforce child-process deadlines and bounded termination.
This binary does not measure or enforce a wall-clock execution deadline.

The shared NCP owner retains one exact response until its digest is acknowledged.
An exact retry returns the retained bytes without repeating detector ingestion.
An unacknowledged result blocks the next mutation.
The maximum local frame is 65,536 bytes, excluding its four-byte big-endian length prefix.
Detector storage remains bounded by three single-channel, 64-sample windows.

The manifest pins public NCP source at `de751d499b5e07d1c95a072e08255083d77cb38b`.
The independent lock and source gate verify that exact optional SDK dependency.
No remote transport, signature, physical validity, Haldir gate, or complete release qualification follows from this component interface.

```bash
cargo test --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml --features ncp-local
cargo clippy --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml --features ncp-local --all-targets -- -D warnings
```

## Independent source gate

`source-profile.json` owns the source scope and exact NCP SDK identity.
`Cargo.lock` owns the resolved dependency versions and checksums.
`deny.toml` admits only the independent graph's reviewed licenses and sources.
It contains no advisory exceptions.
The root lock retains its separate historical PID and wire-0.8 identities.

The source verifier rejects a development sibling SDK path.
It requires the selected full Git revision in the manifest, lock, and resolved native graph.
Its pure graph must exclude NCP.
Both graphs must reuse the actual core from this source tree.
PID, Zenoh, Tokio, and broad NCP packages cannot enter either graph.
The verifier checks the exact adapter file roster and reports each source digest.
These checks identify supplied source and Cargo metadata; they do not attest loaded code or scientific validity.

Run these commands from the repository root:

```bash
cargo fetch --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml
adapter_metadata="$(mktemp -d)"
cargo metadata --locked --offline --format-version=1 \
  --manifest-path crates/galadriel-local-adapter/Cargo.toml \
  --no-default-features > "$adapter_metadata/pure.json"
cargo metadata --locked --offline --format-version=1 \
  --manifest-path crates/galadriel-local-adapter/Cargo.toml \
  --no-default-features --features ncp-local > "$adapter_metadata/native.json"
python3 -B -E -s -S -m unittest discover \
  -s crates/galadriel-local-adapter -p test_verify_source.py -v
python3 -B -E -s -S crates/galadriel-local-adapter/verify_source.py \
  --pure-metadata "$adapter_metadata/pure.json" \
  --native-metadata "$adapter_metadata/native.json"
```

Retain the metadata and verifier output with the exact source commit.
The native workflow also checks formatting, Clippy, tests, documentation, release compilation, and dependency policy.
Both Rust toolchains run the unchanged core's own tests with its empty feature selection.
It uses the existing pinned RustSec database and Rust toolchains.
A separate root archive must build with this adapter absent.
The native checkout must build without any sibling NCP source directory.
Existing native tests run the actual private-pipe binary and core detector.
The source-policy tests use clearly identified synthetic metadata for hostile-input controls.
Those synthetic records cannot substitute for the actual Cargo graphs.

All applicable original repository checks still apply.
The living source inventory includes every adapter source, test, lock, manifest, policy, and workflow.
The source gate cannot change the historical 107 `OPEN` or nine `NOT_CLAIMED` requirements.
It cannot create a freeze, release date, tag, calibrated result, or native installation receipt.
