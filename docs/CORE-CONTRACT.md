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
`0..=9_007_199_254_740_991`; semantic numeric identifiers **SHALL** additionally be
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

The current `outcome` types establish this target algebra. Legacy detector reports
remain migration inputs until T014–T018 connect the event machine and versioned
report envelope; their existence does not weaken these requirements or make them
part of the final frozen surface.

