# galadriel-core

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| CUSUM | cumulative sum |
| MSRV | minimum supported Rust version |
| NIS | normalized innovation squared |

This crate contains the Rust core of Galadriel's Mirror.
The crate forbids unsafe Rust code.
Galadriel's Mirror is an experimental cross-sensor consistency monitor for multi-sensor fusion.

The crate supplies these capabilities:

- It validates `PidObservation` and `Modality` types.
- It supports an optional bounded `ConsistencyProjection` with frame, context, and frozen-prior provenance.
- It keeps bounded NIS windows for each track and modality.
- It supplies chi-square distribution functions through `statrs`.
- It supplies windowed-NIS magnitude evidence with per-assessment family-wise control.
- It supplies historical CUSUM evidence without a calibrated p-value.
- It calculates signed Pearson correlation with one unique strict-majority positive-consensus clique.
- Its fail-closed fusion preserves `InsufficientEvidence` and `UnclassifiedAnomaly`.
- It does not fabricate `Nominal`.
- It requires an `AssessmentScope` for each accepted whole-stream report.
- It seals whole-stream reports and binds them canonically to the complete release suite.
- It also binds each report to every exact ordered observation field.
- It binds producer, session, epoch, stream, state generation, terminal sequence,
  terminal timestamp, and clock domain.

```rust
use galadriel_core::{
    assess_default, AssessmentScope, ClockDomain, Modality, PidObservation, ProducerId,
    ReleaseSuite, Sequence, StreamPosition, TimestampMillis, TrackId,
};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let modalities = [Modality::Visual, Modality::Radar];
let suite = ReleaseSuite::standalone_advisory_v0_9(&modalities)?;
let track = TrackId::new(1)?;
let timestamp = TimestampMillis::new(0)?;
let sequence = Sequence::new(0)?;
let mut stream = Vec::new();
for modality in modalities {
    stream.push(PidObservation::try_scalar(
        track, timestamp, sequence, modality, 3.1, 3,
    )?);
}
let position = StreamPosition::try_new(
    "example-session",
    "example-epoch",
    "example-stream",
    0,
    sequence.get(),
    timestamp.get(),
    ClockDomain::SimulationTime,
)?;
let scope = AssessmentScope::new(ProducerId::new("example-producer")?, position);
let report = assess_default(&scope, &stream, &suite)?;
assert!(report
    .assessment_binding()
    .verifies(&scope, &stream, &suite));
# Ok(())
# }
```

`Mirror` is the magnitude component.
A magnitude-only nominal result remains an unavailable typed `AssessmentOutcome`.
It remains unavailable until the signed-consistency prerequisite runs.
Use `assess_default` for a sealed accepted default report.
Supply a scope with producer, session, epoch, stream, state generation, terminal
sequence, terminal timestamp, and clock domain.
The terminal sequence and terminal-frame timestamp MUST match the stream.

You can compare its opaque `AssessmentBinding` with the exact scope, stream, and
suite. You can also verify it against those three inputs.
Different bindings can carry equal detector verdicts.
The binding does not require each observation to change an estimator or verdict.

The binding uses domain `galadriel-assessment-binding-v2`.
The report serializes its complete scope once as `assessment_scope`.

Public API callers cannot construct it or attach it to replacement component reports.

The scope contains validated caller-declared labels.
It does not authenticate the caller or producer.

Invalid input or configuration returns `Err(...)`.
Missing, stale, or insufficient evidence returns `InsufficientEvidence`.
A finite degenerate projection column is an unavailable estimand.
It returns `InsufficientEvidence` without discarding magnitude evidence.
It withholds all channel corroboration values for that axis.
Cross-channel analysis consumes only the producer-attested common projection.
Here, "attested" identifies a producer provenance claim.
It does not identify cryptographic authentication.

It evaluates every active axis with a shared multiple-testing budget.
It never falls back to native innovations.

Direct extraction scans at most 400,000 observations.
It retains at most 65,536 frames.

This crate is a pre-1.0 research component.
The workspace MSRV is Rust 1.89.
This crate sets `publish = false`.
It is not a field-validated safety or enforcement layer.
The crate is licensed under MIT OR Apache-2.0.
