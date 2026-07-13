# Producer Observation and Lifecycle Contract

Status: Accepted ADR; Galadriel component implementation complete, reciprocal producer
closeout and deployment evidence blocking. The frozen contracts, Crebain producer baseline,
pinned registry, Galadriel assembler/lifecycle receiver, and exact-epoch configuration
profile exist and are tested. Crebain must still consume the deployment-supplied epoch,
commit the shared fixture, and pin the merged Galadriel revision. This is not evidence that
a remote router loaded the ACL, certificates were authorized correctly, or detector
thresholds are operationally calibrated.

## Decision

Galadriel and its producer use two project-owned, observation-only sensor routes
with different responsibilities:

| Route | Payload | Responsibility |
| --- | --- | --- |
| `{realm}/session/{epoch}/sensor/galadriel-pid` | Frozen `SidecarEnvelope` schema v1 | One real, accepted per-measurement observation suitable for the existing detectors |
| `{realm}/session/{epoch}/sensor/galadriel-monitor` | Strict monitor envelope schema v1 | Measurement lifecycle outcomes, fusion-frame closure, and producer liveness |

The observation route MUST remain byte- and schema-compatible with
`galadriel-pid-envelope-v1.schema.json`. Monitor events MUST NOT be added to that
route. The monitor route MUST use an independently versioned, strict,
project-owned schema and MUST NOT be presented as an NCP normative message.

The operational profile joins the two routes and fails closed. A v1 observation
alone remains valid input for Galadriel's existing baseline/replay behavior, but it
is not sufficient evidence for lifecycle-complete, cross-modal operational
assessment.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY in this
document are normative.

## Context and current state

The existing v1 sidecar is deliberately narrow. Its strict `SidecarEnvelope`
contains `kind = "galadriel_pid_observation"`, `schema_version = "1.0"`, NCP
version/hash provenance, `session_id`, `producer_id`, and one `PidObservation`.
The live consumer subscribes to the named sensor route
`{realm}/session/{epoch}/sensor/galadriel-pid`. The historical `-pid` name is
frozen even though the primary statistics are NIS/CUSUM and signed consistency
correlation.

That payload can represent an accepted measurement update. It cannot represent
an association miss, gate rejection, update failure, empty fusion frame, frame
completion, queue loss, or an independent heartbeat. The current live
`RejectionReason` type reports receiver-side payload, decode, and replay failures;
it is not a producer measurement-lifecycle vocabulary and MUST NOT be overloaded
for that purpose. Likewise, a `payloads_received` counter proves only that some
traffic arrived; it is not producer liveness.

The command-line application now provides `observe` behind `ncp-live`. It loads an
externally digest-pinned registry, opens the strict secure Zenoh client, joins both
exact routes through one serialized bounded ingress, advances all declared
deadlines, and passes only lifecycle-complete frames into the detector adapter.
Explicit misses/rejections immediately abstain and clear the affected suffix.

The matching opt-in Crebain runtime baseline snapshots the predicted track set before
association/update, calculates registered Cartesian projections from that one
prior, records bounded opportunity outcomes, publishes summaries through ordered
queues, and runs an independent heartbeat. At this revision it still mints its epoch
internally; the reciprocal refresh must require the deployment value, commit the shared
registry fixture, and pin the merged consumer implementation. Historical JSONL captures
remain successful-update-only and are not upgraded by this implementation.

Existing evidence is synthetic, golden, unit/property, or in-process transport
evidence. The real multi-process allow/deny, wrong/no-certificate, restart, loss,
and all-silence campaign remains an external acceptance gate. This ADR defines
both the implemented contract and that still-open deployment evidence boundary.

## Route and publication rules

Both routes are scoped to exactly one realm and producer epoch. Publishers MUST
construct the exact named sensor keys shown above. A publisher MUST use the raw
perception-plane byte publication API for these project-owned envelopes; it MUST
NOT wrap either payload in a normative NCP `SensorFrame` or publish it through an
API that enforces that wrapper.

The observation route is frozen as follows:

- The envelope discriminator, schema version, field names, optional-field
  behavior, and nested `PidObservation` representation MUST NOT change in place.
- Only real accepted observations that satisfy the existing semantic validator
  may be published. A miss, rejection, failure, heartbeat, or frame summary MUST
  NOT be encoded as a `PidObservation`.
- An incompatible change requires a new route/schema version and a coordinated
  producer/consumer migration. It MUST NOT be smuggled into v1 through a new
  discriminator or tagged union.

The monitor route is a separate compatibility boundary. Its Rust types and JSON
Schema are frozen together with golden examples and negative fixtures. Its bounded
decoder rejects unknown fields and unknown tagged-union variants. Schema evolution
MUST follow explicit compatibility/versioning rules; an incompatible shape requires
a new schema version rather than permissive best-effort decoding.

JSON Schema validation is necessary but not sufficient for canonical wire input.
In particular, JSON Schema treats integer-valued `1.0` and `1e0` tokens as integers,
while the bounded Rust decoder requires the canonical integer token form accepted by
its `u32`/`u64` fields. Application semantic validation also enforces UTF-8 byte
ceilings and cross-field invariants that the schema cannot express.

## Epoch and sequence identity

`epoch` is the sidecar `session_id`. It MUST be a valid NCP path segment, contain
1 through 64 UTF-8 bytes, and equal the `session_id` carried by every envelope on
both routes. It is an application-owned producer-process epoch, not an assertion
that the sidecar participates in an NCP control-plane session-generation service.

An epoch MUST be:

- stable for the lifetime of one producer process epoch;
- freshly minted before any counter or replay state is reset; and
- never reused by a later producer process epoch, even after a crash or rollback.

Observation, fusion, and monitor sequences MAY restart only after a fresh epoch is
minted. A consumer MUST subscribe to an exact epoch path, partition all replay and
assembly state by epoch, reset that state on an epoch change, and retire the old
subscription according to a bounded handover policy. Reusing an epoch after a
sequence reset is a protocol fault, not an operational recovery mechanism.

All numeric identifiers transmitted as JSON integers MUST be non-negative and no
larger than `2^53 - 1`. Sequence counters MUST be monotonic under the rules stated
for their event type. Exhausting a counter requires a fresh epoch; wrapping or
silently saturating it is forbidden.

## Common consistency projection

Cross-modal consistency MUST use a signed position residual in one registered,
three-dimensional Cartesian ENU/world frame, in meters:

```text
r[c,t] = z_ENU[c,t] - h_ENU[c](x_minus[t])
```

Here `c` is a modality, `t` is a fusion sequence, `x_minus[t]` is the immutable
predicted track prior, and `h_ENU[c]` projects that same prior into the registered
ENU/world observation space for modality `c`.

The producer MUST snapshot the predicted state, covariance, track set, and
projection context after prediction and before association, gating, or the first
sequential sensor update. Every modality at one fusion sequence MUST derive its
`consistency_projection` from that same immutable snapshot. Later sequential
updates MUST NOT alter the residual used for another modality at that sequence.
The projected residual is distinct from the modality-native innovation and MUST
NOT fall back to it.

In particular, radar range/azimuth/elevation and any other modality-native
measurement MUST be transformed through the registered calibration and extrinsic
chain into the common Cartesian frame before subtraction. Angle/range components
MUST NOT be placed into Cartesian projection axes. Active projection axes MUST
have a stable order and inactive axes MUST remain zero as required by the frozen
v1 observation schema.

If a measurement or predicted track cannot be mapped validly into the registered
common frame, the producer MUST emit an explicit monitor outcome such as
`incomparable_projection`, MUST NOT fabricate projection values, and MUST mark the
affected frame ineligible for cross-modal consistency assessment.

### Frame and context registry

Every nonzero `frame_id` and `context_id` is a reference into a version-controlled,
deployment-pinned registry. The registry is part of the evidence contract, not an
informal naming convention.

A frame entry MUST define at least:

- the ENU/world frame name, origin and datum;
- axis order, direction, handedness, and units;
- the transform chain and its authority; and
- its validity interval or other applicability constraints.

A context entry MUST define at least:

- projection algorithm and version;
- output dimension and axis order;
- sensor calibration and extrinsic identifiers plus content digests;
- covariance and linearization semantics;
- the enabled modality set; and
- the producer software/configuration digest that fixes those semantics.

Registry identifiers are immutable. An identifier MUST never be reassigned to new
semantics; any semantic change requires a new identifier. The producer and
consumer MUST pin the same registry version/content digest. Each frame summary
MUST bind the registry digest used for the frame. An unknown identifier, digest
mismatch, expired applicability interval, or inconsistent frame/context binding
MUST fail closed.

### Global prior identity

`prior_id` identifies the immutable whole-frame predicted snapshot set. Within one
epoch it is global, not namespaced by track, modality, `frame_id`, or `context_id`.
It MUST be nonzero and obey this mapping:

```text
prior_id -> exactly one fusion_seq within an epoch
```

The same `prior_id` MAY repeat across tracks and modalities at that one sequence
because all of them attest to the same frozen prediction boundary. It MUST NOT
appear at another sequence, even after a frame/context change or a partial frame
failure. A consumer MUST retain a bounded epoch-level high-water/index sufficient
to reject reuse; changing provenance MUST NOT make reuse acceptable. A fresh
epoch starts a new namespace.

## Monitor wire contract

The monitor route carries one strict envelope per event. Its version-1 envelope
MUST contain:

- `kind = "galadriel_producer_event"`;
- `schema_version = "1.0"`;
- `ncp_version` in the exact canonical spelling pinned by the frozen schema and
  `contract_hash` with the same advisory compatibility semantics as the
  observation sidecar;
- `session_id` and `producer_id`, matching the key and configured peer identity;
- `event_seq`, an epoch-global JSON-safe integer that starts at 1, increments once
  for every attempted monitor event, and is assigned before queue admission; and
- `event`, an adjacent-tagged union of `modality_outcome`, `modality_miss`,
  `frame_summary`, or `heartbeat`.

The corresponding Rust types and JSON Schema are frozen together. A producer or
consumer is conformant only when it also follows the sequencing, assembly, epoch,
queue, registry, and security rules in this ADR.

Every string, collection, count, and encoded event MUST have a finite maximum in
both JSON Schema and application validation. At minimum, the implementation MUST
define and test `MAX_MONITOR_EVENT_BYTES`, identifier/string limits,
`MAX_FRAME_ITEMS`, `MAX_MONITOR_QUEUE_EVENTS`, and `MAX_ACTIVE_TRACKS`.
Deployments MAY configure smaller limits, never larger wire limits under the same
schema. All floating-point values MUST be finite. A limit violation is an explicit
overflow/protocol fault; silent truncation is forbidden. A
`FrameSummary.truncated = true` value is an explicit degraded fault declaration
and never makes partial accounting acceptable.

### Outcome event

`modality_outcome` records one bounded association/update opportunity for one
fusion sequence and modality. It identifies its track and distinguishes:

- `updated`;
- `gate_rejected`;
- `assignment_rejected`;
- `update_rejected`;
- `track_birth`;
- `unsupported_filter`; and
- `incomparable_projection`.

`modality_miss` separately closes an expected active-track/modality pair as
`no_measurement`, `no_candidate`, `no_in_gate_candidate`, `not_assigned`, or
`track_not_eligible`. A miss never carries fabricated gate, NIS, or projection
values.

The outcome carries `fusion_seq`, `fusion_timestamp_ms`, `frame_id`, `context_id`,
`prior_id`, `track_id`, modality, a bounded deterministic `attempt_index`, an
optional bounded `measurement_index`, pair-level candidate/in-gate counts repeated
on every attempt outcome, and the typed disposition. Consequently, one
`gate_rejected` attempt may report a nonzero `in_gate_count` when another candidate
for that track/modality pair passed the gate. Every outcome that claims candidate gating (`updated`,
`gate_rejected`, `assignment_rejected`, `update_rejected`, or
`incomparable_projection`) MUST carry finite gate evidence computed from the
contractually correct inputs. `updated` MUST also carry its valid common-frame
projection; when that projection cannot be attested, the producer MUST use
`incomparable_projection`. Other quantities MUST be present only when actually
computed. Canonical producer output MUST omit undefined optional quantities, never
zero-fill or synthesize them. For compatibility, the frozen decoder and schema also
accept an explicit JSON `null` and normalize it to the same absent value; producers
MUST still emit the canonical omitted form.
Gate evidence names `mahalanobis` versus the explicitly non-chi-square
`normalized_euclidean_fallback` method.

Each outcome MUST state `v1_expected`. It is true only when exactly one
corresponding accepted observation is required on the frozen route. Because the
v1 consumer permits at most one consistency observation for a
`(epoch, fusion_seq, track_id, modality)` key, only one accepted attempt for that
key may set `v1_expected = true`. Additional returns/opportunities MUST remain
bounded monitor outcomes with deterministic attempt identities and MUST NOT create
ambiguous duplicate v1 records.

The producer MUST use one documented deterministic enumeration/aggregation rule
for opportunities. It MUST emit an outcome for every opportunity covered by that
rule, including negative outcomes. The rule and all caps MUST be part of the
registry/configuration digest so that missingness and selection can be audited.

The version-1 cardinality rule is fixed. The Cartesian ledger uses the active-track
set frozen immediately after prediction and before association/update. For every
track in that snapshot and every expected modality, the producer emits every
bounded attempt outcome first. It then emits
exactly one `modality_miss` only when no attempt reached an assigned/filter
terminal disposition. The reason is deterministic: use `track_not_eligible` if
eligibility failed; otherwise use the deepest stage reached—`no_measurement`,
`no_candidate`, `no_in_gate_candidate`, then `not_assigned`. Thus
`gate_rejected` outcomes are
followed by one aggregate `no_in_gate_candidate` miss when no other candidate
passed, and `assignment_rejected` outcomes are followed by one aggregate
`not_assigned` miss when nothing was selected. An `updated`, `update_rejected`,
`unsupported_filter`, or `incomparable_projection` terminal outcome suppresses
the miss for that pair. A producer MUST NOT emit any other outcome/miss
combination for the pair. `FrameSummary.outcome_count` counts both event types.
`no_candidate` requires at least one frame input; when `input_count` is zero, a
non-eligibility miss MUST be `no_measurement`. Frozen pair ledgers are emitted in
strict `(track_id, registered modality order)` order, with attempt and measurement
indices increasing inside a pair and its optional aggregate miss last.
`track_birth` is a measurement-level outcome outside that pre-association Cartesian
ledger. Births follow all frozen-pair records in strict
`(measurement_index, track_id, registered modality order)` order; birth track IDs
and measurement indices are unique within the frame. A track born during the frame
neither creates nor suppresses a miss until it belongs to the next frame's frozen
active-track set.

### Frame summary

A `frame_summary` is the sole normal closure record for a `fusion_seq`. It MUST be
emitted even for zero-track and zero-observation frames. It MUST include:

- the epoch, fusion sequence, `frame_id`, `context_id`, and `prior_id`;
- the registry version/content digest;
- the expected modality set;
- bounded active-track, input, total outcome/miss, and `v1_expected` counts; and
- explicit `degraded` and `truncated` fault flags.

The summary's `active_track_count` is the post-processing track count. It does not
change the pre-association snapshot used to determine this frame's miss cardinality.

The summary MUST be calculated from the immutable frame ledger after no more
outcomes can be added. It MUST NOT retroactively turn an absent outcome or v1
observation into success. A second, conflicting closure for the same sequence is a
protocol fault.

A summary tells the consumer when the producer considers a frame complete; it
does not prove lossless transport. Contiguous `event_seq`, exact outcome counts,
and cross-route joins remain mandatory.

### Independent heartbeat

A `heartbeat` MUST be produced by a task and cadence independent of sensor input,
track count, association success, and the fusion-frame loop. It MUST continue
during zero-track and zero-observation periods. It includes producer wall time and
monotonic uptime, the last completed `fusion_seq` if any, active-track count,
declared interval/deadline, an epoch-degraded flag, and bounded queue depth,
capacity, drop, and publication counters.

The consumer MUST judge heartbeat freshness from its own monotonic receipt time
and a configured deadline. Producer wall-clock time is diagnostic only. A
heartbeat proves only that the authenticated producer and monitor path are alive;
it is not a sensor observation, cannot close a frame, and cannot repair an event
gap. Heartbeat publication SHOULD have a separate bounded queue/lane so ordinary
data saturation cannot silently suppress liveness.

## Cross-route assembly and fail-closed behavior

The operational consumer assembles by epoch and fusion sequence, then joins
outcomes to v1 observations by:

```text
(epoch, fusion_seq, track_id, modality)
```

The monitor `attempt_index` or measurement identifier disambiguates multiple
opportunities; the unique accepted opportunity with `v1_expected = true` maps to
the single v1 key. Envelope producer/session provenance, observation sequence,
frame/context/prior identity, and registry digest MUST agree.

A frame is eligible for operational assessment only after:

1. its frame summary has arrived;
2. every declared monitor outcome has arrived exactly once;
3. every outcome with `v1_expected = true` has exactly one matching v1 record;
4. no unexpected or duplicate v1 record exists for the frame; and
5. all identity, registry, sequence, projection, count, and digest checks pass.

A v1 observation received without monitor closure MAY be archived or processed by
an explicitly selected baseline/replay profile, but it MUST NOT be described as
lifecycle-complete operational evidence. A monitor `updated` outcome whose v1
record is absent is likewise incomplete.

The consumer MUST use bounded out-of-order buffers and a finite assembly deadline.
Wrong session/producer provenance, duplicate or regressed `event_seq`, any event
gap, timeout, missing outcome/summary/v1 observation, unknown registry entry,
prior reuse, inconsistent frame/context, unexpected observation, digest/count
mismatch, or buffer overflow MUST produce a typed protocol or availability fault.
The affected frame and any correlation suffix whose completeness is uncertain
MUST be invalidated/reset. Such a fault yields `Insufficient` or `Rejected`, never
`Nominal`. A later heartbeat MUST NOT repair it.

Replay high-water marks MUST survive ordinary per-frame eviction for the epoch.
Consumer eviction MUST NOT make an otherwise incomplete frame eligible. On epoch
retirement, state may be discarded only under a documented retention policy after
the old subscription can no longer contribute accepted evidence. Because bounded
prior-identity and `(track, modality)` replay maps cannot safely evict while the epoch
remains admissible, deployments MUST expose their utilization and coordinate a new,
never-reused epoch before either limit is exhausted. Capacity exhaustion is terminal,
not an automatic rollover signal that may be repaired in place.

## Producer queues and backpressure

Fusion and sensor callbacks MUST NOT block on network or disk publication. The
producer MUST hand off to bounded observation, monitor, and heartbeat queues.
Frame summaries and heartbeats SHOULD use independent capacity/priority lanes so
an observation burst cannot hide frame closure or liveness, while preserving the
ordering needed for `event_seq` validation.

All monitor lanes MUST merge through an ordered publication barrier. Priority MUST
NOT reorder surviving events across their assigned `event_seq`; an intentionally
dropped event remains visible as a gap when a later event arrives.

The producer MUST assign monitor `event_seq` before enqueue. A full queue therefore
creates a visible sequence gap rather than an undetectable omission. Queue policy
MUST be deterministic and documented. The default SHOULD preserve already queued
events and drop the newest attempted event. It MUST NOT use an unbounded queue,
silently block the fusion loop, silently retry forever, or fabricate a successful
summary after loss.

Any queue overflow or publication failure MUST:

- increment monotonic, non-resetting-within-epoch counters;
- place the epoch in a degraded state;
- be exposed by the heartbeat and next deliverable frame summary; and
- make every potentially affected frame ineligible until a fresh epoch if the
  missing event range cannot be proven and bounded.

The consumer's transport callback MUST also use a bounded, non-blocking handoff.
Its assembler MUST cap active epochs, frames, tracks, outcomes, bytes, and reorder
distance, with explicit timeout/overflow metrics. Drop-newest behavior is
acceptable only when it invalidates the affected evidence and surfaces a fault;
eviction MUST NOT silently restore eligibility.

## Security and identity boundary

`producer_id` and `session_id` inside JSON are claims, not signatures. Operational
acceptance requires transport authentication and authorization that binds those
claims to the publisher.

The deployment MUST use mutually authenticated TLS and default-deny ACLs. The
producer certificate identity/CN (or an equivalently strong authenticated
principal) MUST be mapped to the configured `producer_id` and authorized to PUT
only key expressions that bind its allowed realm/epoch and the two exact sensor
names; it MUST NOT receive a broader `sensor/**` grant. Envelope identity MUST
match the route and configured principal. An observer MUST use separate read-only
credentials authorized only to SUBSCRIBE; it MUST NOT be able to PUT, issue
commands, take leases, or invoke control/action routes.

A generic wildcard `robot` role is insufficient by itself to bind an application
`producer_id` or epoch in a multi-producer fleet. Deployments MUST specialize the
identity-to-key mapping and prove it with positive and negative authorization
tests. A consumer constructed from a host-provided bus inherits that host's
security posture; construction alone does not prove mTLS or ACL enforcement.
Secure mode MUST be explicit and fail closed.

The Zenoh transport receive maximum message size MUST be configured so an
oversized message is rejected before excessive allocation. Application-level
event-size limits remain required after transport framing; neither substitutes for
the other. Credentials and private keys MUST never appear in payloads, logs,
fixtures, or evidence bundles.

The routes are observation-only. This ADR grants no authority for producer or
consumer commands, actions, leases, or vehicle control.

## Acceptance matrix

No implementation is conformant or deployable until all five lenses have durable,
reviewable evidence.

| Lens | Required evidence | Acceptance condition | Failure semantics |
| --- | --- | --- | --- |
| Protocol and correctness | Frozen Rust/JSON schemas and goldens; registry fixtures; common-prior and radar-to-ENU tests; prior reuse across frame/context rejection; exact event counts/joins; safe-integer, unknown-field, fuzz, and property tests | Independent producer and consumer agree on valid fixtures and reject every invalid invariant without panic or ambiguity | Typed protocol fault; affected frame/suffix is ineligible, never `Nominal` |
| Statistics and evidence | Recorded pre-gate opportunities and every lifecycle stage; modality/stage exposure and missingness; pre/post-gate comparisons; no fabricated statistics; repeated-look/autocorrelation calibration; errors separated from genuine insufficiency | Review can reconstruct selection/censoring and show that detector inputs use the frozen common prior and calibrated interpretation | Report `Insufficient`/selection bias or explicit statistical invalidity; do not infer health from absent/rejected samples |
| Reliability and security | Loss, reorder, duplicate, restart, heartbeat-silence, queue-saturation, timeout, and message-size tests; real multi-process mTLS/ACL positive, wrong-cert, no-cert, wrong-identity, and observer-write/control-negative tests | Every injected fault is detected within a declared bound and unauthorized publication/control is denied at the transport boundary | Availability/security alarm, epoch degradation or rejection, and no promotion to operational evidence |
| Integration and operations | Normal-runtime producer and live consumer service; fresh epoch mint/discovery/re-subscribe/reset; real router/process tests; metrics, alerts, runbook, and traffic/denial/restart/decode/all-silence exercises | An operator can distinguish healthy idle, sensor silence, producer death, transport loss, decode failure, incomplete frame, and denied peer | Explicit observable state and bounded recovery; ambiguous silence fails closed |
| Maintainability and testing | Versioned code and schemas; cross-repository conformance corpus/goldens; one authoritative type definition or an explicit coordinated bump process; CI fuzz/property/integration suites; issue ownership and API/docs review | Contract drift breaks CI, incompatible changes require review/versioning, and every invariant has an owner and regression test | Release is blocked; no ad hoc permissive decoder or undocumented compatibility exception |

Evidence MUST record exact software revisions, registry/configuration digests,
schema versions, router/security configuration, test commands, and results. A
synthetic JSONL/replay test is useful protocol/statistics evidence but MUST NOT be
used as proof of live routing, independent heartbeat behavior, backpressure, or
mTLS/ACL enforcement.

## Rejected alternatives

### Tagged union on the v1 observation route

Adding lifecycle tags or monitor variants to the v1 envelope is rejected. The v1
schema and decoder are strict, the live tap expects one observation, and existing
sequence/detector state is observation-specific. A union would break current
producer/consumer/schema compatibility or tempt permissive decoding, and could
feed lifecycle events into the statistical observation stream. A separate monitor
route preserves the frozen v1 contract and gives lifecycle evolution its own
version boundary.

Overloading the receiver-side `RejectionReason` enum is rejected for the same
reason: receiver decode/replay disposition and producer measurement lifecycle are
different evidence with different trust boundaries.

### Fabricated observation or frame for absence

Synthesizing a `PidObservation`, NIS, residual, prior, empty “successful” frame, or
heartbeat when a measurement missed, failed gating, could not project, or was lost
is rejected. Fabricated samples can warm detector windows, create false
cross-modal correlation, yield `Nominal`, and conceal selection bias. Consumer
timeouts also cannot invent producer evidence. Absence and failure remain explicit
monitor outcomes and fail closed.

## Consequences and implementation order

The separate route costs an additional schema, publisher lane, consumer assembler,
and cross-route operational state. In return, existing v1 users remain compatible,
negative measurement evidence becomes auditable, idle liveness is distinguishable
from observations, and transport loss cannot silently masquerade as a statistically
healthy frame.

Implementation proceeded in this order:

1. **Galadriel complete; reciprocal pin pending:** monitor Rust/JSON types, limits, typed
   reason taxonomy, canonical registry, opportunity policy, and Galadriel-side golden.
2. **Complete:** immutable predicted-prior snapshot, registered Cartesian residuals
   before sequential updates, and bounded opportunity outcomes in Crebain.
3. **Producer baseline complete; reciprocal refresh pending:** bounded publisher lanes,
   pre-enqueue sequencing, summaries, and independent heartbeat; replace its internal epoch
   mint with the exact deployment-supplied value and pin this merged Galadriel revision.
4. **Complete:** live monitor tap, fail-closed assembler, lifecycle adapter, and
   two-route operational receiver/CLI.
5. **Complete at component level:** exact-epoch secure configuration generator,
   health counters, static mutation checks, runbook, and in-process fault tests.
6. **Open external gate:** execute and retain all five acceptance-lens suites on a
   real secured multi-process deployment, then run a recorded pre-gate calibration
   study independent of threshold fitting.

Until step 6 and the acceptance matrix are satisfied, the operational components
remain a research prototype. No deployment, remote ACL, field-performance, or
calibrated-posterior claim is justified.
