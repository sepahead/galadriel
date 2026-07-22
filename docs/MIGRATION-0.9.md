# Migration from the 0.1 research application programming interface (API) to 0.9.0

## Abbreviations

| Short form | Meaning |
|---|---|
| NCP | Neuro-Cybernetic Protocol |
| SHA-256 | Secure Hash Algorithm 256 |

Galadriel 0.9.0 deliberately breaks ambiguous pre-1.0 behavior.
This change affects the application programming interface (API).
Callers must make identity, lifecycle, configuration, and failure semantics explicit.
Compatibility adapters can translate only a source with known meaning.

Partial Information Decomposition (PID) remains an optional research path.

## Domain values

Raw `u64` values no longer give sufficient evidence of semantic identity.
Convert them at the boundary with these types:

- `TrackId`
- `ProjectionFrameId`
- `ProjectionContextId`
- `FrozenPriorId`
- `Sequence`
- `StateGeneration`
- `TimestampMillis`

The decoder rejects values above the exact JavaScript Object Notation (JSON) integer ceiling.
It does not round these values.
Zero remains valid for ordinals and timestamps.
Zero also remains valid for `TrackId`.
The frozen Galadriel and Crebain observation schema v1 admitted that value.
Adapters must not silently reinterpret this established sidecar value.

Zero is invalid for `ProjectionFrameId`, `ProjectionContextId`, and `FrozenPriorId`.

Session, epoch, stream, and producer labels now use separate validated types.
The accepted grammar uses a bounded set of American Standard Code for Information Interchange (ASCII) characters.
Do not normalize a legacy Unicode NCP identifier.
Normalization can merge identities.
Start a fresh epoch with a conforming identifier.
Alternatively, retain the capture as unqualified evidence.

`ClockDomain` is a closed enum.
Label an existing millisecond timestamp as `unix_utc`, `monotonic_process`, `simulation_time`, or `tai`.
Callers cannot create an open string or infer a clock from magnitude.

## Lifecycle

Earlier versions implicitly cleared history after some continuity changes.
These changes included large sequence or time gaps, frame changes, context changes, registry changes, and track removal.

The accepted 0.9 lifecycle uses typed `StreamPosition` admission and hash-linked receipts.
Exact successors advance normally.
A continuity boundary requires a generation-advancing reset.
A fresh epoch must start at sequence zero and generation zero.

`LifecycleDetector::{reset_at, timeout_at, rollover_at}` records these explicit transitions.
Forward gaps, regressions, missing resets, reused epochs, and incorrect generations cause rejection.
They do not clear state.
Successful frame receipts bind the accepted release-suite identity.
This rule also applies to zero-track or fully abstained frames.

Evaluated assessment digests cover the complete serialized report.
They include numeric baseline and correlation details.
Terminal transitions are `Faulted { reason }`.
They bind the exact returned reason instead of a reason-free marker.

`LifecycleDetector::assess_positioned_frame` is the fully typed adapter boundary.
The older `assess_frame` convenience path delegates through `assess_frame_transition`.
It derives a project-local position from frozen sidecar v1 fields.
It does not add reset or rollover fields to the NCP wire.

The deprecated `clear_histories` operation is for diagnostic teardown only.
It cannot represent an accepted protocol reset.
Receipts contain bounded in-memory evidence.
They do not form a durable journal.
A standalone receipt can use the 16 KiB-inclusive strict-JSON `decode_and_verify` gate.
This gate checks the internal digest.

It does not authenticate the writer or prove chain retention.
See `STATE-MACHINE.md`.

## Result handling

Do not convert each non-nominal condition into an error or Boolean alarm.
`AssessmentOutcome::InsufficientEvidence` is a successful fail-closed assessment.
Positive anomaly evidence is also a successful assessment.
`AssessmentFailure` is only for these typed failures:

- invalid input
- authentication or authorization failure
- compatibility failure
- temporal or identity failure
- resource failure
- backend failure
- internal failure

The unversioned `Verdict` and `MirrorReport` serialization representation is a pre-0.9 migration input.
The causal aliases `spoof`, `jam`, and `anomaly` are also pre-0.9 migration inputs.
`MirrorReport` is now output-only and has no `Deserialize` implementation.
Its fields are private.
Consumers use read-only getters.
Normal 0.9 decoding cannot manufacture an accepted report.

Any historical conversion must be an explicit offline migration.
The migration must retain the original bytes and digest.

Release code now constructs `ReleaseSuite::standalone_advisory_v0_9(modalities)`.
It passes that accepted composition to `Mirror::from_release_suite` or `assess_default(stream, &suite)`.
Version 0.9 removes these interfaces:

- `Mirror::new`
- `Mirror::with_modalities`
- the raw detector and correlation argument list
- the empty-vector mode sentinel

Explicit subset-only research uses `ExploratoryResearchProfile::SubsetMagnitudeV0_9.capability()`.
It also uses `Mirror::for_exploratory_subset`.

`assess_default` returns a sealed `DefaultReport`.
This report has an opaque `AssessmentBinding` over the complete suite and each exact ordered observation field.
Bound magnitude and correlation components must share that binding.
Component constructors and `combine_correlation_axes` remain unbound diagnostic compatibility paths.
They cannot create an accepted report.

## Optional PID research

Enabling `galadriel-pid` does not activate PID work.
It also does not add PID to the release suite.
Whole-stream PID analysis requires a separate accepted capability:

```rust,ignore
let suite = PidResearchSuite::circular_delete_block_v0_9(&modalities)?;
let report = galadriel_pid::assess_stream(&stream, &suite)?;
```

Use `PidResearchSuite::point_estimate_only_v0_9` only for explicitly unconfirmed research.
Custom accepted release and PID components use `PidResearchSuite::try_new(PidResearchSuiteParams { .. })`.
The call rejects an already axis-derived `PidConfig`.
This rule prevents a second division of a family budget.

Version 0.9 removes the former `assess_stream(stream, modalities, detector, pid)` argument list.
It also removes the `assess_stream_with_correlation` argument list.
Custom correlation semantics now belong in the embedded `ReleaseSuite` before PID suite composition.

These accepted and report types have private fields:

- `PidConfig`
- `PidEstimatorEvidence`
- `ChannelPid`
- `PidReport`
- `AxisPidReport`
- `PidResearchSuite`
- `FusedReport`

Consumers use getters.
`FusedReport::{verdict, baseline, correlations, pids, note, suite_identity, classification, assessment_binding}` replaces direct field access.
`fuse` and `fuse_axes_diagnostics` return explicitly unbound diagnostic tuples after configuration checks.
Only whole-stream-bound components can enter `fuse_axes` and create a sealed report.
Ordinary callers use `assess_stream`.

PID reports carry the canonical `PidConfigDigest` through estimator evidence.
Fused reports carry `PidResearchSuiteDigest` and `PidAssessmentBinding`.
These values are domain-separated SHA-256 identities over complete accepted values.

The identity material includes named or custom composition and the confirmation payload.
It includes axis-family derivation, resource ceilings, and the exact `pid-core` revision and estimator semantics.
These digests identify configuration.
They do not authenticate it or establish field calibration.
