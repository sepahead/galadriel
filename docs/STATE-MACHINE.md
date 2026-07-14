# Deterministic Stream State Machine

Status: normative target specification for release 0.9.0 tasks T014 and T015.
The identifiers in this document are stable proposed requirement identifiers. This
document does not, by itself, claim that the current implementation conforms; code,
tests, retained evidence, and the release ledger must agree before either task can be
marked complete.

`SHALL`, `SHALL NOT`, `SHOULD`, and `MAY` are normative. A rejection means a typed
error and no committed core-state mutation. “Epoch” below is a statistical and
anti-replay boundary; it is not a claim about an NCP 1.0 product release.

## Requirements

**GLD-090-STM-001 — closed state algebra.** Each detector track stream **SHALL** be
in exactly one of `Empty`, `Collecting`, `Ready`, `Unavailable`, or `TimedOut`.
Implementations **SHALL NOT** represent these states by an open string, a collection
of independently mutable Booleans, or an unlisted sentinel.

**GLD-090-STM-002 — closed event algebra.** The only events that may change or
confirm this state are `Observation`, `Miss`, `OpportunityRejected`, `Heartbeat`,
`Timeout`, `Reset`, and `EpochRollover`. Unknown event kinds and unknown required
semantics **SHALL** be rejected before state mutation.

**GLD-090-STM-003 — identity binding.** Every event **SHALL** bind to one exact
producer, session, epoch, detector stream, and, except for epoch-wide events, track.
Evidence from different identity tuples **SHALL NOT** share retained statistical
history.

**GLD-090-STM-004 — deterministic sequencing.** Source event order, per-track
fusion order, reset generation, and transition-receipt order **SHALL** be explicit,
bounded, and checked. Replay, regression, an unauthorized gap, or counter exhaustion
**SHALL NOT** be interpreted as a fresh sample or an implicit reset.

**GLD-090-STM-005 — validate then commit.** An event **SHALL** be fully validated
and its candidate next state and receipt **SHALL** be constructed before the current
state is replaced. A rejected event **SHALL** leave the committed state, retained
samples, generation, high-water marks, deadline, counters, and receipt chain
byte-for-byte unchanged.

**GLD-090-STM-006 — transition table.** Every valid state/event pair **SHALL** have
the result defined in the exhaustive table below. Implementations **SHALL NOT** add
an implicit transition based on arrival route, caller, verdict, or human-readable
note.

**GLD-090-STM-007 — missingness.** A `Miss` or `OpportunityRejected` **SHALL**
invalidate the affected track’s complete-frame statistical suffix and produce
`Unavailable`. It **SHALL NOT** be imputed as zero NIS, a nominal observation, an
anomaly, or evidence of malicious intent.

**GLD-090-STM-008 — liveness separation.** `Heartbeat` **SHALL** update only
epoch-liveness metadata and **SHALL NOT** add a statistical sample, make a stream
ready, repair missingness, refresh an independent plant watchdog, or recover a
terminal epoch. A due `Timeout` **SHALL** fail closed.

**GLD-090-RST-001 — explicit reset.** Statistical history **SHALL NOT** be cleared
because a sequence, timestamp, projection context, expected-modality set, or track
lifecycle changed. Such a change **SHALL** require an accepted `Reset` or a fresh
`EpochRollover`, except that an accepted `Miss`, `OpportunityRejected`, or `Timeout`
is itself the explicit suffix-invalidating event specified here.

**GLD-090-RST-002 — reset receipt.** Every accepted `Reset` **SHALL** produce a
versioned receipt that proves the old and new generation, reason, scope, resume
position, discarded-state bounds, and before/after state digests. A Boolean
`history_reset` flag is insufficient evidence by itself.

**GLD-090-RST-003 — generation exhaustion.** Reset generation **SHALL** be a
JSON-safe integer in `0..=9_007_199_254_740_991`. A reset at the maximum **SHALL**
be rejected without mutation and **SHALL** require `EpochRollover`; it **SHALL NOT**
wrap, saturate, reuse a generation, or silently clear state.

**GLD-090-EPC-001 — explicit epoch rollover.** `EpochRollover` **SHALL** close the
old epoch, select a previously unused epoch identity, reset generation to zero, reset
source and receipt sequence expectations, and start every stream in `Empty`. Events
from the closed epoch **SHALL** remain inadmissible.

**GLD-090-EPC-002 — rollover receipt.** Every accepted rollover **SHALL** produce a
versioned receipt binding the final old-epoch state and counters to the initial
new-epoch state and counters. Rollover **SHALL NOT** erase the audit record of the old
epoch.

**GLD-090-BND-001 — bounded work and storage.** Configuration **SHALL** impose the
track, modality, history, staging, byte, replay-index, and deadline bounds described
below. Capacity exhaustion **SHALL** fail closed and **SHALL NOT** evict an arbitrary
live stream to admit new evidence.

**GLD-090-TST-001 — model coverage.** Tests **SHALL** exercise every cell of the
state/event matrix, every event precondition, exact and just-over boundaries,
malformed and adversarial inputs, and the no-mutation property for every rejection.

**GLD-090-NCP-001 — adapter boundary.** An NCP adapter **SHALL** prove lifecycle
closure and normalize raw producer records before emitting a core event. A raw
attempt record, partial frame, contract advisory, or heartbeat **SHALL NOT** be
misrepresented as a complete statistical observation. The current monitor schema’s
`v1` name **SHALL NOT** be described as a released NCP 1.0 integration.

## Identity, context, and positions

The machine is per logical track stream:

```text
StreamKey = (
  producer_id,
  session_id,
  epoch_id,
  stream_id,
  track_id
)
```

- `producer_id` identifies the authenticated producer principal.
- `session_id` identifies the bounded transport/control session.
- `epoch_id` is unique within that producer/session lineage and is never reused.
- `stream_id` identifies one immutable detector profile and route binding.
- `track_id` identifies one producer track within the epoch. Reuse after a track
  birth/restart requires a new stream identity or an explicit reset.

For the current 0.9 NCP adapter, which carries `session_id` and `producer_id` but no
separate epoch field, the only conforming mapping is `epoch_id := session_id`; a
rollover therefore requires a fresh `session_id`. This compatibility mapping does
not weaken the distinct domain types required by the core contract.

Each reset generation freezes the following context:

- the exact, canonical, nonempty expected-modality set;
- detector and correlation profile digests and their readiness thresholds;
- degrees of freedom for each modality;
- the registered physical frame and projection-context binding required by the
  selected profile; and
- the initial or explicitly resumed fusion position.

Changing any frozen field requires `Reset` or `EpochRollover`. A frozen-prior
identifier may be shared by modalities in one fusion frame, but it **SHALL** be
nonzero, bound to that frame, and never reused at another fusion sequence in the
same epoch.

Three independent counters are retained:

1. Upstream `event_seq` is global to the producer epoch, starts at one, and is
   contiguous across monitor events, including heartbeats. Reordering may be staged
   only within configured count, distance, byte, and time bounds.
2. Per-track `fusion_seq` is the statistical stream position. In ordinary operation
   the next committed `Observation`, `Miss`, or `OpportunityRejected` must equal the
   checked successor of the previous committed position. A reset may authorize one
   explicit forward resume position; it may never authorize replay or regression.
3. `receipt_seq` is global to the core epoch, starts at one, and advances exactly
   once per non-idempotent accepted core transition in deterministic order.

When one lifecycle-complete frame produces transitions for multiple tracks, the
adapter orders them by ascending validated track identifier; modality evidence inside
one track is already in canonical modality order. Host map iteration order never
selects transition or receipt order.

All serialized counters, identifiers, millisecond timestamps, and generations
**SHALL** be integers in `0..=9_007_199_254_740_991`. Positive identifiers **SHALL**
also reject zero. If `event_seq`, `fusion_seq`, `receipt_seq`, or generation has no
representable successor, the epoch **SHALL** stop accepting events that require one
and require rollover. An `EpochRollover` is an authenticated control-plane operation
outside the exhausted old event sequence.

The first permissible fusion position is an immutable epoch-profile value, so both
zero-based and one-based producers can be represented without guessing. Consecutive
frame timestamps **SHALL** increase strictly. A forward time gap above the configured
maximum requires reset; equality/regression is rejected and cannot be repaired inside
the same epoch by relabeling old data.

## Closed states

The state is a tagged value, not a verdict:

| State | Required invariant |
| --- | --- |
| `Empty` | No retained complete-frame sample exists for this generation. Anti-replay high-water marks and receipts remain retained. |
| `Collecting` | `1 <= retained_complete_frames < readiness_min`; every retained frame is contiguous, validated, and complete for the frozen profile. |
| `Ready` | `readiness_min <= retained_complete_frames <= history_capacity`; every enabled detector has sufficient complete contiguous evidence. An anomaly verdict does not change this state. |
| `Unavailable` | The latest committed track position explicitly lacks assessable evidence for at least one expected modality. The retained statistical suffix is empty and typed reasons are nonempty. |
| `TimedOut` | A receiver-owned deadline expired. The retained statistical suffix is empty, the timeout receipt is retained, and no same-epoch data event can recover the stream. |

`history_capacity` is the maximum history needed by the selected immutable detector
profile. For the current default fused path it is
`max(detector.window_len, correlation.window)`. `readiness_min` is the largest minimum
sample count among enabled components. Reaching `Ready` says only that assessment is
eligible; it does not mean `Nominal`, calibrated, truthful, safe, or deployment
qualified.

An NCP assembler additionally has the orthogonal closed adapter condition
`Healthy | Faulted`. A protocol, provenance, resource, or declared-loss fault moves
the adapter to terminal `Faulted`, suppresses later core events, and requires a fresh
epoch. `Faulted` is intentionally not fabricated into one of the five statistical
states. Its fault receipt must identify the earliest affected fusion position.

## Normalized events and preconditions

All events must first satisfy the identity, version, integer-domain, canonical
encoding, authentication/authorization, source-order, resource, and deadline checks
applicable to their route. An event received exactly at a receiver-owned deadline is
late: the admissible interval is half-open, `received_at < deadline`, and `Timeout`
wins at equality.

### `Observation`

`Observation` is the normalized, lifecycle-complete evidence unit for one track and
fusion frame. It contains exactly one assessable observation for every modality
required by the frozen detector profile, in canonical modality order. Each member
must validate numerically and must agree on track, fusion sequence, fusion timestamp,
physical frame, projection context, and frozen-prior identity. The complete set must
be proven by a healthy frame closure record.

Partial route input is staging, not an `Observation`. Staging the first raw record
**SHALL NOT** mutate the committed statistical state. If the profile enables only a
baseline that does not require common projections, “assessable” follows that frozen
profile; an adapter may not change the rule from frame to frame.

On acceptance, the complete frame is appended, the oldest frame is removed only if
the fixed history capacity would otherwise be exceeded, and readiness is recomputed
from the resulting bounded suffix. A changed context, modality set, degrees of
freedom, unauthorized sequence gap, excessive timestamp gap, duplicate, or replay is
`ResetRequired` or a typed invalid-input error; it is never an implicit channel reset.

### `Miss`

`Miss` is emitted only after lifecycle closure proves that at least one expected
track/modality pair had no result. Its nonempty, canonically ordered reason set is
drawn from the closed reasons `NoMeasurement`, `NoCandidate`,
`NoInGateCandidate`, `NotAssigned`, and `TrackNotEligible`. It consumes the declared
fusion position, clears the entire track’s statistical suffix, and records the exact
unavailable modalities and reasons.

### `OpportunityRejected`

`OpportunityRejected` is emitted only after lifecycle closure proves that a
track/modality opportunity did not yield assessable evidence. Its closed reason set
is `GateRejected`, `AssignmentRejected`, `UpdateRejected`, `UnsupportedFilter`, or
`IncomparableProjection`.

Raw per-candidate rejections are not independently applied to this state machine. If
another attempt for the same track/modality/frame produces the accepted update and
matching observation required by the frozen profile, the adapter emits
`Observation` for that pair and retains the rejected attempts only as provenance.
Otherwise it emits one normalized `OpportunityRejected`. `TrackBirth` is not an
observation or rejection for a frozen existing track; it creates a new stream or
requires `Reset(reason = TrackLifecycleRestart)` before later evidence is admitted.

### `Heartbeat`

An accepted heartbeat must have the next upstream event sequence, the exact declared
interval/deadline profile, strictly increasing producer uptime, nondecreasing
cumulative publication counters, zero declared loss, and a last-fusion cursor equal
to the latest lifecycle-complete summary preceding it in source order. It advances
the receiver-owned liveness deadline from local receipt time. Producer wall-clock
time does not set or extend that deadline.

### `Timeout`

`Timeout` is receiver generated when the earliest applicable heartbeat, reorder, or
incomplete-frame deadline is due. Its typed reason, local monotonic detection offset,
deadline offset, and earliest affected fusion sequence are retained. It clears the
statistical suffix of every active track, makes the epoch terminal for existing and
new data streams, and produces one epoch-wide receipt. Repeating the same timeout is
idempotent and returns the original receipt; it does not advance counters.

### `Reset`

A reset is scoped to one `StreamKey`, carries a closed reason, names the expected
current generation, declares `new_generation = current_generation + 1`, and declares
the next permissible fusion position. The reasons are `OperatorRequested`,
`TrackLifecycleRestart`, `SequenceDiscontinuity`, `TimestampDiscontinuity`,
`ProjectionContextChanged`, `ExpectedModalitiesChanged`, and `SourceRecovery`.

The resume position must be greater than every committed high-water mark. Without a
forward discontinuity it must be the checked successor; with a declared forward
discontinuity it is the one exact position authorized by the receipt. Reset clears
samples and an `Unavailable` marker, but preserves anti-replay high-water marks,
immutable producer/session/epoch/stream identity, the receipt chain, and any
independent terminal adapter fault. Reset cannot recover `TimedOut` or `Faulted`.

### `EpochRollover`

Rollover is epoch-wide and atomic across all streams. It requires authenticated
authority, a previously unused new epoch identity, a final snapshot of the old
epoch, and an explicit new initial fusion position and frozen configuration digest.
It closes the old epoch even if the old state was `TimedOut` or the adapter was
`Faulted`, creates an empty new epoch with generation zero, and expects upstream and
receipt sequences to start at one. Failure to initialize every new stream leaves the
old epoch unchanged and closed/open exactly as it was before the request.

The rollover receipt is receipt one of the new epoch and chains to the final receipt
digest (or explicit genesis marker) of the old epoch. It therefore remains possible
when the old epoch's source or receipt sequence is exhausted and does not require an
unrepresentable successor in the old epoch.

## Exhaustive transition table

The table assumes every event-specific precondition above is satisfied. `Reject`
always means a typed error and no committed mutation. `C/R` means `Collecting` unless
the new bounded suffix reaches `readiness_min`, in which case it means `Ready`.
`same` means the statistical state is unchanged even though a liveness receipt may
be appended. `E(g+1)` and `E(new)` mean `Empty` in the next reset generation or a
new epoch, respectively.

| Current state | `Observation` | `Miss` | `OpportunityRejected` | `Heartbeat` | `Timeout` | `Reset` | `EpochRollover` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Empty` | `C/R` (M01) | `Unavailable` (M02) | `Unavailable` (M03) | `same` (M04) | `TimedOut` (M05) | `E(g+1)` (M06) | `E(new)` (M07) |
| `Collecting` | `C/R` (M08) | `Unavailable` (M09) | `Unavailable` (M10) | `same` (M11) | `TimedOut` (M12) | `E(g+1)` (M13) | `E(new)` (M14) |
| `Ready` | `Ready` (M15) | `Unavailable` (M16) | `Unavailable` (M17) | `same` (M18) | `TimedOut` (M19) | `E(g+1)` (M20) | `E(new)` (M21) |
| `Unavailable` | `C/R` (M22) | `Unavailable` (M23) | `Unavailable` (M24) | `same` (M25) | `TimedOut` (M26) | `E(g+1)` (M27) | `E(new)` (M28) |
| `TimedOut` | `Reject: EpochTerminal` (M29) | `Reject: EpochTerminal` (M30) | `Reject: EpochTerminal` (M31) | `Reject: EpochTerminal` (M32) | `TimedOut`, idempotent (M33) | `Reject: EpochTerminal` (M34) | `E(new)` (M35) |

Additional deterministic rules apply to the accepting cells:

- `Observation` from `Unavailable` starts a new suffix because the preceding
  missingness event already performed and receipted the invalidation; no evidence
  from before that event is retained.
- `Miss` or `OpportunityRejected` from `Unavailable` replaces the current typed
  reason/position with the newer contiguous one while keeping history empty.
- `Heartbeat` never changes retained-frame count, readiness, generation, verdict, or
  the position expected from the next track evidence event.
- `Timeout` records the original pre-timeout state and clears history exactly once.
- `Reset` from `Empty` is not collapsed into a no-op: it increments generation and
  emits a receipt, unless generation is exhausted.
- `EpochRollover` never reuses the old epoch identity and never carries old samples
  into the new epoch.

## Receipts and auditability

Every non-idempotent accepted transition produces a versioned transition receipt.
The representation is defined with the report schemas, but it must contain at least:

```text
schema_version
receipt_seq
event_kind
event_digest
producer_id, session_id, epoch_id, stream_id, optional track_id
source_event_seq_start, source_event_seq_end
fusion_seq or explicit absence
generation_before, generation_after
state_before, state_after
retained_frames_before, retained_frames_after
reason_codes
local_receipt_offset_ms
previous_receipt_digest
state_digest_before, state_digest_after
```

The event and state digests are domain-separated canonical digests. A receipt digest
cannot hash itself. Human-readable notes are optional and never participate in a
decision or replace a typed reason.

A reset receipt additionally contains reset scope, reset reason, discarded track,
modality, frame, and sample counts, last committed fusion position, authorized resume
position, old/new frozen-context digests, and the checked generation increment. A
rollover receipt additionally contains old/new epoch identities, old terminal
condition, final upstream/fusion/receipt counters, old final receipt digest, new
profile digest, new initial fusion position, `new_generation = 0`, and
`new_next_event_seq = new_next_receipt_seq = 1`.

Receipts are append-only evidence. Reset or rollover may release bounded live sample
storage after the receipt commits, but it must not delete retained receipts required
by the release/evidence policy. If durable receipt persistence or digest construction
fails, the transition fails atomically.

## Atomicity and failure behavior

Processing follows one transaction:

1. Decode into the closed event type under a byte bound.
2. Validate version, required fields, identities, authorization, counters, source
   order, deadline admissibility, frozen context, numeric domains, and capacity.
3. Normalize complete lifecycle evidence without exposing partial state.
4. Compute the candidate bounded next state and complete receipt.
5. Persist/append the receipt as required by the active evidence policy.
6. Replace the committed state once.

Steps 1–5 may allocate only within validated bounds. Any error before step 6 returns
the original committed snapshot. Rust implementations should construct a candidate
value and move it into place only after every fallible operation succeeds; mutating
the live value and attempting to roll it back is not the conformance model.

An NCP assembler terminal fault is different from a rejected core event. The adapter
accepts a typed fault transition, latches the first fault, clears bounded staging,
suppresses later `FrameReady` output, and emits an `AssemblyFault`-equivalent receipt.
Because no normalized core event crossed the boundary, the committed core stream is
not advanced. Recovery requires `EpochRollover`, not retrying late input.

## Resource and complexity bounds

Let `T` be the configured maximum tracks, `M` the frozen expected modalities, `H`
the history capacity, and `A` the enabled common-projection axes. The current owned
domains bound `M <= 6`, `A <= 3`, `H <= 65_536`, aggregate retained core NIS samples
using the conservative configured bound
`T * 6 * detector.window_len <= 1_000_000`, and lifecycle-retained observations to at
most `1_000_000`.

The following worst-case bounds are normative for the selected profile:

| Operation | Time | Additional live storage |
| --- | --- | --- |
| Validate/append normalized `Observation` | `O(M)` excluding assessment | `O(M)` before bounded eviction |
| Default fused assessment | `O(M*H + A*M^2*H)` | `O(M*H)` bounded working/retained data |
| `Miss` / `OpportunityRejected` / per-stream `Reset` | `O(M*H)` to drop bounded history | `O(1)` after clear, excluding receipt |
| `Heartbeat` | `O(1)` | `O(1)` |
| Epoch-wide `Timeout` / `EpochRollover` | `O(T*M*H)` with eager release | `O(T)` bounded receipts/stream metadata |

The implementation may improve these asymptotics but may not weaken validation or
retain unbounded state. Identifiers are at most 64 encoded bytes in the current NCP
adapter. Current compiled NCP hard ceilings are 1,024 open frames, 8,192 reordered
monitor events, 64 MiB aggregate buffered evidence, 1,000,000 prior identities,
65,536 observation replay streams, 8,192 frame items, 1,024 active tracks, and 65,536
bytes per observation or monitor payload. Deployment-selected limits may be lower and
must also satisfy the pinned registry. Reaching a limit is a typed terminal adapter
fault; arbitrary eviction, unbounded growth, or silent truncation is forbidden.

## Exhaustive test matrix and required properties

One model-level parameterized suite must implement cases M01–M35 from the transition
table. Each case asserts the exact next state, generation, retained-frame count,
fusion high-water mark, receipt count, and receipt fields. Rejecting cases also assert
byte equality and digest equality of the entire pre/post committed snapshot. M33
asserts that repeated timeout returns the first timeout receipt without advancing any
counter.

The matrix must be supplemented by these named test families:

- **Event preconditions:** for every event and every starting state, vary one of
  wrong producer/session/epoch/stream/track, unknown type/version/reason, malformed
  value, wrong frozen context, duplicate/replayed/regressed position, upstream event
  gap, receipt gap, and expired deadline; assert typed rejection and no mutation.
- **Observation completeness:** permute modality arrival order and raw attempt order;
  every permutation of the same complete ledger must yield the same normalized event,
  receipt, and state. Drop, duplicate, or alter one member and assert no partial core
  commit.
- **Missingness:** cover every miss and rejection reason, multiple unavailable
  modalities, an early rejected attempt followed by a valid update, and an accepted
  update followed by irrelevant rejected attempts. Missingness must never yield
  `Nominal` or retain a pre-gap sample.
- **Readiness boundaries:** test `readiness_min - 1`, `readiness_min`,
  `history_capacity`, and one additional observation; the final case must evict only
  the oldest complete frame and remain bounded.
- **Sequence boundaries:** test the configured first fusion position, exact successor,
  duplicate, regression, unauthorized gap, explicitly reset forward-resume position,
  JSON-safe maximum, and attempted successor of the maximum.
- **Timestamp/deadline boundaries:** test strictly before, exactly at, and strictly
  after each deadline; zero/equal/regressed timestamps; the maximum admitted forward
  gap; and one millisecond above it.
- **Reset boundaries:** test generation zero, maximum minus one to maximum, reset at
  maximum, every reset reason, stale expected generation, invalid resume position,
  and durable-receipt failure. Only the maximum-minus-one case may reach the maximum.
- **Rollover isolation:** test rollover from all five states and from adapter
  `Faulted`; reused epoch identity, partial new-epoch initialization, and late old
  events must not alter either epoch. A valid new epoch starts empty at generation
  zero with both next sequence values equal to one.
- **Metamorphic properties:** inserting valid heartbeats changes no statistical
  report; replacing a miss with an equivalent terminal rejection changes only typed
  reason provenance; batching versus single-event application is identical; and no
  suffix includes observations from both sides of an invalidating event.
- **Resource boundaries:** exercise every selected limit exactly and at limit plus
  one, including aggregate multiplication-overflow cases. Exact limits are admissible;
  excess fails closed without arbitrary eviction.
- **Adversarial lifecycle:** cover cross-route provenance mismatch, prior reuse,
  observation replay, summary contradiction, declared loss, monitor reorder timeout,
  incomplete-frame timeout, heartbeat regression, heartbeat silence, and late input
  after terminal fault.

Property tests must generate arbitrary valid state/event sequences and compare the
implementation with a small pure reference model. After every prefix they must assert
the state invariants, bounded storage, strictly chained receipts, and the rule that a
`Ready` suffix never crosses `Miss`, `OpportunityRejected`, `Timeout`, `Reset`, or
`EpochRollover`.

## Current 0.9 integration gaps

This section records implementation facts and is not a waiver of the requirements:

- `galadriel-core::Mirror::ingest` currently replaces a channel window implicitly
  after a large sequence or timestamp gap. `Mirror::remove_track` and `Mirror::clear`
  also clear state without a receipt. These behaviors do not yet satisfy
  GLD-090-RST-001/002.
- `galadriel-ncp::LifecycleDetector` currently clears history automatically on a
  session/producer change, context change, modality change, nonconsecutive sequence,
  excessive forward timestamp gap, miss, or `clear_histories`. Its
  `history_reset: bool` reports only some of those cases and is not an auditable reset
  receipt.
- The NCP assembler correctly owns one exact `(session_id, producer_id)` epoch,
  enforces global monitor ordering and JSON-safe event-sequence exhaustion, latches a
  first terminal fault, and refuses late repair. It has no distinct `epoch_id`,
  `stream_id`, reset generation, `Reset`, or `EpochRollover` wire event/receipt.
- `AssembledFrame` retains frame identity and lifecycle evidence but does not expose
  the source monitor `event_seq` range needed to bind downstream transition receipts
  to exact producer order.
- Core observation identities and timestamps are presently raw `u64`; core validation
  reserves only `u64::MAX`, whereas NCP wire validation already enforces the smaller
  JSON-safe maximum. One domain rule must be selected and enforced before serialized
  receipts are stable.
- Raw NCP outcomes are per attempt and may contain rejections before a later accepted
  update. The adapter needs the frame-normalization rule above; directly translating
  each raw rejection would incorrectly invalidate valid evidence.
- The local monitor schema is named `v1`, but the release evidence does not establish
  a released NCP 1.0 dependency. This document therefore specifies only the local
  0.9 adapter contract and leaves NCP 1.0 compatibility `NOT_CLAIMED`.

Until these gaps are implemented and the required evidence is retained, T014 and
T015 remain open even though this normative target is complete.
