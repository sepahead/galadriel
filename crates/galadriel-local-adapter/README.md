# Local scalar magnitude adapter

Status: experimental scalar library and optional reader of CREBAIN NCP 2 loop runs.
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
A caller can use it before it commits to a frame.
Wrong arity, non-finite NIS, negative NIS, or changed dimensions reject the complete frame before ingestion.
Corrected input can reuse that unconsumed position.

A missing channel returns a sealed abstention with the exact unavailable modalities.
It clears and retires the monitor's statistical window.
Later calls fail until the caller prepares a new instance under a fresh external generation.
This library does not authenticate that external generation.

Sequence gaps, replay, timestamp regression, excessive timestamp gaps, and unexpected engine failures also retire the instance.
Cancellation and transport failures belong to the caller.
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

## Optional NCP 2 loop reader

The `ncp-loop` feature adds the `galadriel-ncp-loop` binary and the `ncp_loop::assess_run` library function.
It uses the NCP 2 Rust core, package `sepahead-ncp-core` (library `ncp`), version `2.0.0`.
The separate `galadriel-ncp` consumer keeps its own NCP 1.0.0-rc.1 candidate dependency.
The default library has no NCP dependency.
The Galadriel wire-1.0 sidecar and Zenoh profiles remain separate.

```bash
cargo build --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml --features ncp-loop --bin galadriel-ncp-loop
galadriel-ncp-loop assess RUN_DIR
```

CREBAIN's `crebain-ncp-loop` runs controllers and simulated drone worlds, each in its own NCP 2 session.
It writes `manifest.json` and one transcript for each session into a run directory.
The reader assesses such a directory after the run; it opens no listener, network connection, or subprocess.
It prints one JSON report.

For each world of the manifest, the reader checks the world transcript before it uses a value:

- The file has at most 256 MiB, and the NCP 2 transcript verifier accepts it.
- A transcript of version 2 ends with its end record.
- It holds one complete client session: `open`, `prepare`, one `step` for each tick, `finish`, and `close`, each with an `ok` response to its own request.
- The session opens `crebain.body` with the manifest's body contract.
- `prepare` names the manifest's drones, steps, and tick, and each step continues the state chain: it names the state digest that the previous result produced.
- The innovations of each step name the step and list the world's drones in order.

Any failed check refuses the whole run.
The transcripts are not signed, so these checks establish the integrity of the supplied files, not their producer.

Each drone owns one scalar monitor instance for one Visual channel with three degrees of freedom.
A drone's track waits until the kernel reports its first observed innovation.
The producer's fusion track and fusion sequence then enter the monitor unchanged, and the sensor and track stay fixed.
A step whose innovation is unavailable after activation retires that track for the rest of the run.
Later steps report the retired window with no detector report.
No observation or sequence is made up for a missing innovation.

The output schema is `galadriel.ncp-loop.assessment.v1`, with application profile `galadriel.scalar-nis-loop.v1`.
It names each world transcript by its SHA-256 digest and each step by its tick, simulated time, and state digest.
It includes each drone's observed NIS, track status, abstention reason, adapter identity, and serialized detector report.
Classification and configuration identity remain explicit, and `calibrated_posterior` remains `false`.
One Visual channel with three declared dimensions cannot satisfy the unchanged two-modality minimum.
Its actual engine report therefore retains `InsufficientEvidence`.
A run has at most 1,024 steps, and detector storage stays bounded by one 64-sample window for each drone.

The manifest pins `sepahead-ncp-core` `2.0.0` from public NCP source at `2e24ef5b89feb3f1e4f4972e290201d93e2d0a8d`, which implements revision 4 of the NCP 2 specification.
The independent lock and source gate verify that exact optional dependency.
No remote transport, signature, physical validity, Haldir gate, or complete release qualification follows from this component interface.

The tests assess three recorded CREBAIN runs in [`tests/fixtures`](tests/fixtures/README.md): a clean run, a run with a sensor offset and a missing measurement, and a run with two worlds and five drones.
They also refuse a changed transcript byte, a missing end record, a manifest that does not match the run, and a controller transcript in place of a world transcript.

```bash
cargo test --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml --features ncp-loop
cargo clippy --locked --manifest-path crates/galadriel-local-adapter/Cargo.toml --features ncp-loop --all-targets -- -D warnings
```

## Independent source gate

`source-profile.json` owns the source scope and exact NCP SDK identity.
`Cargo.lock` owns the resolved dependency versions and checksums.
`deny.toml` admits only the independent graph's reviewed licenses and sources.
It contains no advisory exceptions.
The root lock keeps its separate PID and NCP 1.0.0-rc.1 identities.

The source verifier rejects a development sibling SDK path.
It requires the selected full Git revision in the manifest, lock, and resolved native graph.
Its pure graph must exclude NCP.
Both graphs must reuse the actual core from this source tree.
PID, Zenoh, Tokio, and the NCP 1 packages `ncp-core`, `ncp-zenoh`, and `ncp-local` cannot enter either graph.
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
  --no-default-features --features ncp-loop > "$adapter_metadata/native.json"
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
The native tests assess the recorded CREBAIN runs with the actual core detector.
The source-policy tests use clearly identified synthetic metadata for hostile-input controls.
Those synthetic records cannot substitute for the actual Cargo graphs.

All applicable original repository checks still apply.
The living source inventory includes every adapter source, test, lock, manifest, policy, and workflow.
The source gate cannot change the historical 107 `OPEN` or nine `NOT_CLAIMED` requirements.
It cannot create a freeze, release date, tag, calibrated result, or native installation receipt.
