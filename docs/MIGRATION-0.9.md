# Migration from the 0.1 research API to 0.9.0

Galadriel 0.9.0 deliberately breaks ambiguous pre-1.0 behavior. Callers must make
identity, lifecycle, configuration, and failure semantics explicit; compatibility
adapters may translate only when the source meaning is known.

## Domain values

Raw `u64` values are no longer sufficient evidence of semantic identity. Convert
at the boundary with `TrackId`, `ProjectionFrameId`, `ProjectionContextId`,
`FrozenPriorId`, `Sequence`, `StateGeneration`, and `TimestampMillis`. Values above
the exact JSON integer ceiling are rejected rather than rounded. Zero remains valid
for ordinals and timestamps. It also remains valid for `TrackId`, because the frozen
Galadriel/Crebain observation schema v1 admitted zero; adapters must not silently
reinterpret that established sidecar value. Zero is rejected for `ProjectionFrameId`,
`ProjectionContextId`, and
`FrozenPriorId`.

Session, epoch, stream, and producer labels now use separate validated types. The
accepted grammar is bounded ASCII. A legacy Unicode NCP identifier cannot be
normalized safely because normalization could merge identities; start a fresh
epoch with a conforming identifier or retain the capture as unqualified evidence.

`ClockDomain` is a closed enum. Existing millisecond timestamps must be labeled as
`unix_utc`, `monotonic_process`, `simulation_time`, or `tai`; callers may not invent
an open string or infer a clock from magnitude.

## Lifecycle

Large sequence/time gaps, frame/context/registry changes, and track removal formerly
cleared history implicitly. Accepted 0.9 lifecycle flow now uses typed
`StreamPosition` admission and hash-linked receipts. Exact successors advance
normally; a continuity boundary requires a generation-advancing reset, while a fresh
epoch must begin at sequence/generation zero.
`LifecycleDetector::{reset_at, timeout_at, rollover_at}` record those explicit
transitions. Forward gaps, regressions, missing resets, reused epochs, and bad
generations reject rather than clearing state. Successful frame receipts bind the
accepted release-suite identity even for zero-track or fully abstained frames. Evaluated
assessment digests cover the complete serialized report, including numeric baseline and
correlation details; terminal transitions are `Faulted { reason }` and bind the exact
returned reason rather than a reason-free marker.

`LifecycleDetector::assess_positioned_frame` is the fully typed adapter boundary.
The older `assess_frame` convenience path delegates through
`assess_frame_transition` and derives a project-local position from frozen sidecar
v1 fields; it does not add reset/rollover fields to the NCP wire. The deprecated
`clear_histories` operation is diagnostic teardown only and cannot represent an
accepted protocol reset. Receipts are bounded in-memory evidence, not a durable
journal. A standalone receipt may be decoded through the 16 KiB-inclusive strict-JSON
`decode_and_verify` gate, which checks its internal digest but does not authenticate its
writer or prove chain retention; see `STATE-MACHINE.md`.

## Result handling

Do not collapse every non-nominal condition into an error or Boolean alarm.
`AssessmentOutcome::InsufficientEvidence` is a successful fail-closed assessment;
positive anomaly evidence is also a successful assessment. `AssessmentFailure`
is reserved for typed invalid, authentication/authorization, compatibility,
temporal/identity, resource, backend, or internal failures.

The unversioned `Verdict`/`MirrorReport` serde representation and the causal aliases
`spoof`, `jam`, and `anomaly` are pre-0.9 migration inputs only. `MirrorReport` is
now output-only and has no `Deserialize` implementation; its fields are private and
consumers use read-only getters. Normal 0.9 decoding therefore cannot manufacture
an accepted report. Any historical conversion must be an explicit offline migration
that retains the original bytes and digest.

Release code now constructs `ReleaseSuite::standalone_advisory_v0_9(modalities)`
and passes that accepted composition to `Mirror::from_release_suite` or
`assess_default(stream, &suite)`. The former `Mirror::new`,
`Mirror::with_modalities`, raw detector/correlation argument list, and empty-vector
mode sentinel are removed. Explicit subset-only research uses
`ExploratoryResearchProfile::SubsetMagnitudeV0_9.capability()` and
`Mirror::for_exploratory_subset`.

`assess_default` returns a sealed `DefaultReport` with an opaque
`AssessmentBinding` over the complete suite and every exact ordered observation
field. Bound magnitude/correlation components must share it. Component constructors
and `combine_correlation_axes` remain unbound diagnostic compatibility paths and
cannot mint an accepted report.

## Optional PID research

Enabling `galadriel-pid` no longer activates PID work or adds PID to the release
suite. Whole-stream PID analysis requires a distinct accepted capability:

```rust,ignore
let suite = PidResearchSuite::circular_delete_block_v0_9(&modalities)?;
let report = galadriel_pid::assess_stream(&stream, &suite)?;
```

Use `PidResearchSuite::point_estimate_only_v0_9` only for explicitly unconfirmed
research. Custom accepted release and PID components cross
`PidResearchSuite::try_new(PidResearchSuiteParams { .. })`; an already axis-derived
`PidConfig` is rejected so a family budget cannot be divided twice. The former
`assess_stream(stream, modalities, detector, pid)` and
`assess_stream_with_correlation` argument lists are removed. Custom correlation
semantics now belong in the embedded `ReleaseSuite` before PID suite composition.

`PidConfig`, `PidEstimatorEvidence`, `ChannelPid`, `PidReport`, `AxisPidReport`,
`PidResearchSuite`, and `FusedReport` have private accepted/report fields. Consumers
use getters; `FusedReport::{verdict, baseline, correlations, pids, note,
suite_identity, classification, assessment_binding}` replaces direct field access.
`fuse` and `fuse_axes_diagnostics` return explicitly unbound diagnostic tuples after
configuration checks. Only whole-stream-bound components may enter `fuse_axes` to
create a sealed report; ordinary callers should use `assess_stream`.

PID reports carry the canonical `PidConfigDigest` through estimator evidence, and
fused reports carry `PidResearchSuiteDigest` plus `PidAssessmentBinding`. These are
domain-separated SHA-256
identities over complete accepted values; named versus custom composition,
confirmation payload, axis-family derivation, resource ceilings, and the exact
`pid-core` revision/selected estimator semantics are identity material. These
digests identify configuration; they do not authenticate it or establish field
calibration.
