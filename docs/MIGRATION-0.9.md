# Migration from the 0.1 research application programming interface (API) to 0.9.0

## Abbreviations

| Short form | Meaning |
|---|---|
| NCP | Neuro-Cybernetic Protocol |
| SHA-256 | Secure Hash Algorithm 256 |

Galadriel 0.9.0 deliberately breaks ambiguous pre-1.0 behavior.
This change affects the application programming interface (API).
Callers **MUST** make identity, lifecycle, configuration, and failure semantics
explicit.
Compatibility adapters can translate only a source with known meaning.

Pairwise MI remains an optional companion; PID remains a separate offline research path.

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
- `AssessmentScope`

The decoder rejects values above the exact JavaScript Object Notation (JSON)
integer ceiling.
It does not round these values.
Zero remains valid for ordinals and timestamps.
Zero also remains valid for `TrackId`.
The frozen Galadriel and Crebain observation schema v1 admitted that value.
Adapters **MUST NOT** silently reinterpret this established sidecar value.

Zero is invalid for `ProjectionFrameId`, `ProjectionContextId`, and `FrozenPriorId`.

Session, epoch, stream, and producer labels now use separate validated types.
The accepted grammar uses a bounded set of American Standard Code for Information
Interchange (ASCII) characters.
Do not normalize a legacy Unicode NCP identifier.
Normalization can merge identities.
Start a fresh epoch with a conforming identifier.
Alternatively, retain the capture as unqualified evidence.

`ClockDomain` is a closed enum.
Label an existing millisecond timestamp as `unix_utc`, `monotonic_process`,
`simulation_time`, or `tai`.
Callers cannot create an open string or infer a clock from magnitude.

## Lifecycle

Earlier versions implicitly cleared history after some continuity changes.
These changes included large sequence or time gaps.
They also included frame, context, registry, and track changes.

The accepted 0.9 lifecycle uses typed `StreamPosition` admission and hash-linked receipts.
Exact successors advance normally.
A continuity boundary requires a generation-advancing reset.
A fresh epoch **MUST** start at sequence zero and generation zero.

`LifecycleDetector::{reset_at, timeout_at, rollover_at}` records these explicit
transitions.
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

The unversioned `Verdict` and `MirrorReport` serialization representation is a
pre-0.9 migration input.
The causal aliases `spoof`, `jam`, and `anomaly` are also pre-0.9 migration
inputs.
`MirrorReport` is now output-only and has no `Deserialize` implementation.
Its fields are private.
Consumers use read-only getters.
Normal 0.9 decoding cannot manufacture an accepted report.

Any historical conversion **MUST** be an explicit offline migration.
The migration **MUST** retain the original bytes and digest.

Release code now constructs
`ReleaseSuite::standalone_advisory_v0_9(modalities)`.
It also constructs an `AssessmentScope` from one validated producer and one
exact `StreamPosition`.

```rust,ignore
let position = StreamPosition::try_new(
    "session-a",
    "epoch-a",
    "fusion-stream",
    0,
    terminal_sequence,
    terminal_timestamp_ms,
    ClockDomain::MonotonicProcess,
)?;
let scope = AssessmentScope::new(ProducerId::new("producer-a")?, position);
let report = assess_default(&scope, &stream, &suite)?;
```

The scope position contains session, epoch, stream, state generation, terminal
sequence, terminal timestamp, and clock domain. The accepted call also binds the
producer identity. The terminal sequence **MUST** equal the largest stream
sequence. The terminal timestamp **MUST** equal the largest timestamp at that
sequence.

These labels are caller-declared provenance. They do not authenticate the caller
or prove that the producer emitted the stream.

Code can still pass the accepted composition to `Mirror::from_release_suite` for
the magnitude component. That path does not create an accepted whole-stream
report.
Version 0.9 removes these interfaces:

- `Mirror::new`
- `Mirror::with_modalities`
- the raw detector and correlation argument list
- the empty-vector mode sentinel

Explicit subset-only research uses
`ExploratoryResearchProfile::SubsetMagnitudeV0_9.capability()`.
It also uses `Mirror::for_exploratory_subset`.

`assess_default` returns a sealed `DefaultReport`.
This report has an opaque `AssessmentBinding`.
The binding uses domain `galadriel-assessment-binding-v2`.
It covers the complete scope, suite, and each exact ordered observation field.
Bound magnitude and correlation components **MUST** share that binding.
Component constructors and `combine_correlation_axes` remain unbound diagnostic
compatibility paths.

These component paths cannot create an accepted report.

Use `DefaultReport::assessment_scope` to read the report scope.
Use `AssessmentBinding::scope` to read the binding scope.
Call `AssessmentBinding::verifies(&scope, &stream, &suite)` for exact
verification.

## Optional dependence research

The pre-release rename is intentionally breaking. There are no aliases that keep
the scientifically incorrect PID vocabulary alive:

| Removed development surface | 0.9 candidate surface | Migration |
|---|---|---|
| package `galadriel-pid` | `galadriel-dependence` | Change the dependency name. |
| Rust import `galadriel_pid` | `galadriel_dependence` | Change imports and use the report-first MI graph types. |
| CLI feature `pid` | `dependence` | Select `--features dependence` only for the synthetic demo or library integration. |
| `PidConfig`, `PidReport`, `PidVerdict`, `assess_stream`, and atom rows | No compatibility alias | Re-specify a symmetric MI graph question or move a real fixed-target PID question to `galadriel-justify`. |
| `replay --max-pid-tracks` and terminal PID replay output | Removed with no MI replacement | Raw JSONL lacks the law, projection, lifecycle, and episode receipts required by the MI companion. |

Frozen wire and historical names are different: `PidObservation`, the NCP
`sensor/galadriel-pid` route and `galadriel_pid_observation` kind, the v1 schema
filename, and `CREBAIN_PID_JSONL` remain compatibility identifiers. They do not
mean that the payload or runtime path is a PID tuple.

Enabling `galadriel-dependence` does not activate MI work.
It also does not add MI or PID to the release suite or fused verdict.
Whole-stream companion analysis requires a separate accepted capability and an
explicit continuous-law declaration:

```rust,ignore
let law = ContinuousLawDeclaration::try_iid(population, observation, sampling, coordinate_gauge)?;
let suite = DependenceResearchSuite::exhaustive_circular_delete_block_v0_9(
    &modalities,
    law,
)?;
let report = galadriel_dependence::assess_with_dependence(&scope, &stream, &suite)?;
```

Use `DependenceResearchSuite::point_estimate_only_v0_9` only for explicitly
descriptive research. Custom release and MI components use
`DependenceResearchSuite::try_new(DependenceResearchSuiteParams { .. })`.
Construction checks the complete multi-axis work product. MI has no family alpha.

Version 0.9 removes the former PID-named runtime graph and atom rows. The graph
question is symmetric pairwise dependence, so no PID source/target tuple is
fabricated. Custom correlation semantics remain in the embedded `ReleaseSuite`.

These accepted and report types have private fields:

- `MiConsensusConfig`
- `MiAcceptedConfigEvidence`
- `MiKsgEvaluatorConfigEvidence`
- `MiEstimatorEvidence`
- `PairMiReport`
- `MiConsensusReport`
- `AxisMiConsensusReport`
- `DependenceResearchSuite`
- `DependenceAssessmentReport`

Consumers use getters.
`DependenceAssessmentReport` exposes the unchanged `default_report`, descriptive
`mi_axes`, suite identity, classification, scope, and binding. There is no MI
fusion function. Ordinary callers use `assess_with_dependence`.

Each produced axis has a `ProjectionAxisReceipt` containing the producer frame,
projection context, axis identity, modality order, full extracted suffix length,
and the exact ordered sequence and timestamp bounds for every selected tail row.
The inner `RowSetReceipt` separately binds all binary64 column values. Direct
`DeclaredMiInput` can only record caller-asserted alignment; use the core-bound
route when validated sequence/lifecycle provenance is required. Construction
retains at most the newest `MAX_MI_WINDOW` rows per channel before finite-value
validation; no accepted configuration can analyze an earlier prefix, so direct
input validation and cloning share the public 512-row ceiling.

MI reports carry the canonical `MiConsensusConfigDigest` through estimator evidence.
Companion reports carry `DependenceResearchSuiteDigest` and
`DependenceAssessmentBinding`.
These values are domain-separated SHA-256 identities over complete accepted values.

`DependenceAssessmentBinding` contains the core version 2 binding.
Thus, it contains the exact `AssessmentScope`.

The identity material includes named or custom composition and stability choice.
It includes multi-axis work ceilings, the declared law, and no-noise transform identity.
It also includes the exact `pid-core` revision and estimator semantics.
These digests identify configuration.
They do not authenticate it or establish field calibration.

Estimator JSON is no longer only an opaque digest plus a profile label. It
serializes every accepted graph value and ceiling, plus the fixed KSG `k`, metric,
tie rule, support declaration, negative-value policy, geometry/backend contract,
and upstream estimand revisions. Point-fit and deletion-replay resource rejection
have separate typed dispositions and are not reported as scientific instability.

Offline `galadriel-justify` retains real PID questions. Categorical
Makkeh–Gutknecht–Wibral and continuous
Ehrlich–Schick-Poland–Makkeh–Lanfermann–Wollstadt–Wibral PID use distinct functionals and
must name fixed sources, a target, law, transforms, gauges, row relation, and
software identity. They are not fallback implementations for the opt-in MI
graph. `PidQuestionSpec` and its smaller pinned-dependency envelope make the
functional/estimator-route distinction explicit in each offline study result. Its
version 3 schema also binds the exact generated law and finite-sample selection,
the complete typed lattice-coordinate/component family, direct-versus-derived
construction, root PID aggregate map, units, and coupled/permutation arm roles.
`JustificationStudyProtocol` separately identifies Pearson, pairwise MI, and the
project-defined joint contrast `Q`; `Q` is not a PID atom. It maps every non-PID
aggregate and binds the paired bootstrap/RNG seed and percentile protocol without
claiming a multiplicity guarantee or source/build identity. The aggregate results
seal their fields and can recompute report-derived summaries bit-for-bit. Upstream
pid-core errors retain their typed source through `JustificationError`.
Each offline PID result also retains the explicit single-thread
`PidStudyResourceContract` used by its `_with_budget` estimator calls. This is a
per-call ceiling, not an aggregate peak-memory or wall-clock guarantee.
