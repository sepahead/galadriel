# Galadriel core contract for 0.9.0

Status: normative for the stable `galadriel-core` source API selected for 0.9.x.
This contract defines representation and failure semantics; it does not assert
producer authenticity, calibrated field performance, malicious intent, or safe
control authority.

## Validated domain identities

**GLD-090-DOM-001 — non-interchangeable identities.** Track, producer, session,
epoch, stream, projection frame, projection context, frozen prior, sequence, state
generation, timestamp, and clock domain **SHALL** have distinct Rust types with
private representation. A raw integer or string **SHALL NOT** become an accepted
domain value without its fallible constructor or deserializer running.

**GLD-090-DOM-002 — bounded canonical representation.** Numeric identifiers,
counters, and millisecond timestamps serialized as JSON numbers **SHALL** be in
`0..=9_007_199_254_740_991`. `TrackId` **SHALL** preserve that complete range,
including zero, because it is part of the frozen NCP v1 wire contract. Projection
frame, projection context, and frozen-prior identifiers **SHALL** additionally be
nonzero. Text identities **SHALL** be 1–64 UTF-8 bytes, begin and end with an ASCII
alphanumeric, and contain only ASCII alphanumerics plus `-_.:`. Unknown clock
domains **SHALL** be rejected; the closed domains are `unix_utc`,
`monotonic_process`, `simulation_time`, and `tai`.

**GLD-090-DOM-003 — explicit stream coordinates.** A stream position **SHALL**
bind session, epoch, stream, state generation, sequence, timestamp, and clock
domain. Ordinary successors **SHALL** increment sequence exactly once and require a
strictly newer timestamp. An explicit reset **SHALL** increment both sequence and
state generation exactly once. Only epoch rollover **SHALL** change epoch identity
and restart sequence and state generation at zero. Exhaustion **SHALL** fail without
wrapping or saturation.

**GLD-090-DOM-004 — closed modality vocabulary.** Modality **SHALL** remain the six
closed values `visual`, `thermal`, `acoustic`, `radar`, `lidar`, and
`radiofrequency`. Unknown values and duplicate members of a semantic modality set
**SHALL** be rejected. Collection order **SHALL NOT** alter meaning; accepted sets
use the declared modality order.

The textual grammar is intentionally stricter than the pre-0.9 NCP helper, which
accepted arbitrary Unicode path segments. This is a pre-1.0 compatibility break:
adapters must reject or explicitly migrate a legacy identity rather than normalize
it silently. A syntactically valid identity remains a label, not proof of who issued
it; authentication and registry binding belong to the adapter and deployment
profile.

## Assessment result taxonomy

**GLD-090-RES-001 — coherent outcome.** A completed assessment **SHALL** produce
exactly one of nominal evidence, attributed inconsistency, broad degradation,
unclassified anomaly, or insufficient evidence. Attributed inconsistency **SHALL**
carry a nonempty unique modality set. Unclassified anomaly and insufficient
evidence **SHALL** carry nonempty closed reason codes.

**GLD-090-RES-002 — readiness invariant.** Nominal, attributed inconsistency, and
broad degradation **SHALL** imply `ready`. Insufficient evidence **SHALL** use a
non-ready availability (`collecting`, `unavailable`, `stale`, `timed_out`, or
`incompatible`) and **SHALL NOT** be constructible as nominal.

**GLD-090-RES-003 — failure separation.** Invalid input, unauthenticated input,
unauthorized operation, incompatible semantics, stale/duplicate/reordered/replayed
input, resource exhaustion, backend fault, and internal fault **SHALL** be distinct
machine failure classes. Insufficient evidence and positive anomaly evidence
**SHALL NOT** be returned as those failures.

The `outcome` module implements this algebra. `MirrorReport` remains a sealed
magnitude diagnostic for source migration, but its release-classified
`validated_outcome()` cannot expose magnitude-only `Nominal` as a completed suite
result. `assess_default` is the accepted default path: it returns a sealed
`DefaultReport` only after the magnitude and signed-correlation prerequisites have
run under one accepted `ReleaseSuite`.

## Exact assessment provenance

**GLD-090-RES-004 — whole-input binding.** Every accepted whole-stream default
report **SHALL** carry an opaque `AssessmentBinding` over the complete canonical
release-suite identity and every field of every ordered `PidObservation`, including
optional native research data and the complete consistency projection. Every bound
magnitude and correlation component **SHALL** carry that same binding.

**GLD-090-RES-005 — no report substitution.** Component constructors and legacy
fusion helpers MAY produce unbound diagnostic reports, but an unbound or mixed-bound
component family **SHALL NOT** mint a sealed accepted report. `AssessmentBinding`
construction remains private; callers may inspect its digest, suite identity, and
observation count or verify it against an exact stream and suite.

The optional PID layer adds `PidAssessmentBinding`, which hashes the core release
binding together with the complete `PidResearchSuite` identity. A sealed PID
`FusedReport` is returned only when its baseline, every signed-correlation axis, and
every PID axis share the expected nested binding. These digests establish exact
input/configuration identity, not authentication, calibration, or physical truth.
