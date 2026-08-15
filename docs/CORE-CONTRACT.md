# Galadriel core contract for 0.9.0

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| ASCII | American Standard Code for Information Interchange |
| JSON | JavaScript Object Notation |
| NCP | Neuro-Cybernetic Protocol |
| PID | partial information decomposition |
| UTF-8 | 8-bit Unicode Transformation Format |

Status: normative for the stable `galadriel-core` source API selected for 0.9.x.
This contract defines representation and failure semantics. It does not assert
producer authenticity, calibrated field performance, malicious intent, or
authority for control.

## Validated domain identities

**GLD-090-DOM-001 — non-interchangeable identities.** These identities **SHALL**
use distinct Rust types:

- track
- producer
- session
- epoch
- stream
- projection frame
- projection context
- frozen prior
- sequence
- state generation
- timestamp
- clock domain

Each type **SHALL** have a private representation. A raw integer or string
**SHALL NOT** become an accepted domain value before validation. Its fallible
constructor or deserializer performs this validation.

**GLD-090-DOM-002 — bounded canonical representation.** Numeric identifiers,
counters, and millisecond timestamps use JSON numbers. These values **SHALL** be
in `0..=9_007_199_254_740_991`. `TrackId` **SHALL** preserve this complete range.
The range includes zero. The frozen Galadriel and Crebain observation schema v1
requires this range.

Projection frame, projection context, and frozen-prior identifiers **SHALL** also
be nonzero. Text identities **SHALL** contain 1 through 64 UTF-8 bytes. They
**SHALL** start and end with an ASCII alphanumeric character. They **SHALL**
contain only ASCII alphanumeric characters and `-_.:`.

The decoder **SHALL** reject unknown clock domains. The closed domains are
`unix_utc`, `monotonic_process`, `simulation_time`, and `tai`.

**GLD-090-DOM-003 — explicit stream coordinates.** A stream position **SHALL**
bind session, epoch, stream, state generation, sequence, timestamp, and clock
domain. An ordinary successor **SHALL** increment the sequence exactly once. It
also requires a strictly newer timestamp.

An explicit reset **SHALL** increment sequence and state generation exactly once.
Only an epoch rollover **SHALL** change the epoch identity. The rollover restarts
sequence and state generation at zero. Exhaustion **SHALL** fail without wrapping
or saturation.

**GLD-090-DOM-004 — closed modality vocabulary.** Modality **SHALL** remain these
six closed values:

- `visual`
- `thermal`
- `acoustic`
- `radar`
- `lidar`
- `radiofrequency`

The decoder **SHALL** reject unknown values. It **SHALL** also reject duplicate
members of a semantic modality set. Collection order **SHALL NOT** change the
meaning. Accepted sets use the declared modality order.

The text grammar is stricter than the pre-0.9 NCP helper. That helper accepted
arbitrary Unicode path segments. This change is a pre-1.0 compatibility break.
Adapters **MUST** reject or explicitly migrate a legacy identity. They **MUST NOT**
silently normalize it.

A syntactically valid identity remains a label. It does not prove who issued the
identity. The adapter and deployment profile supply authentication and registry
binding.

**GLD-090-DOM-005 — accepted assessment scope.** Every accepted whole-stream
assessment **MUST** receive one `AssessmentScope`. The scope contains one
validated `ProducerId` and one exact `StreamPosition`.

The scope binds these eight coordinates:

- producer identity
- session identity
- epoch identity
- stream identity
- state generation
- terminal sequence
- terminal timestamp in milliseconds
- clock domain

The terminal sequence **MUST** equal the largest sequence in the assessed
stream. The terminal timestamp **MUST** equal the largest timestamp at that
terminal sequence. A mismatch is invalid input and returns an error.

The scope is caller-declared provenance. Its types validate representation and
identity separation. They do not authenticate the caller or prove that the
named producer emitted the observations. An adapter or deployment supplies that
assurance separately.

## Assessment result taxonomy

**GLD-090-RES-001 — coherent outcome.** A completed assessment **SHALL** produce
exactly one of these outcomes:

- nominal evidence
- attributed inconsistency
- broad degradation
- unclassified anomaly
- insufficient evidence

Attributed inconsistency **SHALL** contain a nonempty and unique modality set.
Unclassified anomaly and insufficient evidence **SHALL** contain nonempty closed
reason codes.

**GLD-090-RES-002 — readiness invariant.** Nominal, attributed inconsistency, and
broad degradation **SHALL** imply `ready`. Insufficient evidence **SHALL** use a
non-ready availability. This availability is `collecting`, `unavailable`, `stale`,
`timed_out`, or `incompatible`. Insufficient evidence **SHALL NOT** be
constructible as nominal.

**GLD-090-RES-003 — failure separation.** These conditions **SHALL** be
distinct machine failure classes:

- invalid input
- unauthenticated input
- unauthorized operation
- incompatible semantics
- stale input
- duplicate input
- reordered input
- replayed input
- resource exhaustion
- backend fault
- internal fault

The machine **SHALL NOT** return insufficient evidence or positive anomaly
evidence as one of these failures.

The `outcome` module implements this algebra. `MirrorReport` remains a sealed
magnitude diagnostic for source migration. Its release-classified
`validated_outcome()` cannot expose magnitude-only `Nominal` as a completed suite
result.

`assess_default` is the accepted default path. It runs the magnitude and
signed-correlation prerequisites under one accepted `ReleaseSuite`. It returns a
sealed `DefaultReport` only after both prerequisites run.

## Exact assessment provenance

**GLD-090-RES-004 — whole-input binding.** Every accepted whole-stream default
report **SHALL** carry an opaque `AssessmentBinding`. The binding covers the
complete `AssessmentScope` and canonical release-suite identity. It also covers
every field of every ordered `PidObservation`.

`PidObservation` is a retained historical compatibility name. The type contains
fusion-observation inputs, not a PID source-target tuple or PID estimate.

The input includes optional native research data and the complete consistency
projection. Every bound magnitude and correlation component **SHALL** carry the
same binding.

The binding uses domain `galadriel-assessment-binding-v2`. It hashes the eight
scope coordinates before the suite and ordered observations. A `DefaultReport`
serializes the complete scope once as top-level field `assessment_scope`.

**GLD-090-RES-005 — no report substitution.** Component constructors and legacy
fusion helpers MAY produce unbound diagnostic reports. An unbound or mixed-bound
component family **SHALL NOT** mint a sealed accepted report.

`AssessmentBinding` construction remains private. Callers can inspect its digest,
suite identity, observation count, and scope. They can verify it only against an
exact scope, stream, and suite.

The binding identifies the submitted input. Different bindings can carry equal
detector verdicts. The binding does not require each observation to change an
estimator or verdict.

The optional dependence layer adds `DependenceAssessmentBinding`. It binds the
exact core assessment binding to the complete `DependenceResearchSuite` identity.
`DependenceAssessmentReport` **MUST** retain the exact authoritative
`DefaultReport`; its MI axes are companion evidence only and **MUST NOT** modify
`FusedVerdict` or `ConsistencyEvidence`.

These digests establish exact input and configuration identity. They do not
establish authentication, calibration, or physical truth.
