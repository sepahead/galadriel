# Typed lifecycle admission and receipts

Status: implemented Galadriel 0.9 adapter contract. This document describes the
typed lifecycle boundary in `galadriel-core::StreamPosition` and
`galadriel-ncp::LifecycleDetector`. It does not claim durable receipt persistence,
an authenticated lifecycle control plane, a released NCP 1.0 integration, external
deployment qualification, or field calibration.

`SHALL` and `SHALL NOT` below describe the accepted 0.9 path. Compatibility entry
points are identified explicitly and do not add fields to the frozen sidecar v1
wire format.

## 1. Typed position and logical lanes

**GLD-090-STM-001 — explicit coordinates.** Accepted lifecycle admission **SHALL**
use a `StreamPosition` that binds distinct typed session, epoch, stream, state-
generation, sequence, timestamp, and clock-domain values. Raw strings and integers
cross their fallible domain constructors before they reach the detector.

**GLD-090-STM-002 — bounded lanes.** `LifecycleDetector` **SHALL** partition state
by typed `ProducerId` plus the position's core session and stream identity. Evidence
from different logical lanes **SHALL NOT** share retained statistical history.

**GLD-090-STM-003 — strict progression.** Within one epoch, ordinary frame
admission **SHALL** require the exact next sequence, a strictly increasing timestamp,
the same clock domain, and the required state generation. A duplicate, replay,
conflicting replay, older unretained position, forward gap, timestamp regression,
bad generation, or missing reset **SHALL** be rejected and latched; none is an
implicit fresh sample.

The logical lane key deliberately excludes epoch identity so an explicit rollover
can replace an epoch without creating a second lane. The lane retains its active
`StreamPosition`, bounded track histories, frame/context/modality continuity,
registry identity, recent frame fingerprints, and a non-evicting set of epoch
identities already used by that logical stream.

The current bounds are:

| Retained state | 0.9 bound | Exhaustion behavior |
| --- | ---: | --- |
| logical lifecycle lanes | configuration-derived, hard maximum 64 | reject and latch; do not evict another lane |
| aggregate retained observations | 983,040 | configuration/admission failure |
| recent frame fingerprints per lane | 4,096 | oldest fingerprint may leave the diagnostic cache; an older arrival is then conservatively `Reordered` |
| used epoch identities per lane | 1,024 | reject and latch; never forget an epoch to permit reuse |
| in-memory receipts | 65,536 | evict the oldest receipt while advancing the public anchor and eviction count |

The fixed modality domain remains the six values in `galadriel-core`. Accepted
release-suite construction supplies a nonempty canonical expected-modality set;
the lifecycle adapter checks aggregate history before retaining observations.

## 2. Accepted transition algebra

`LifecycleTransition` is the closed receipt vocabulary:

- `Initialized` — first accepted position for one logical lane;
- `Advanced` — exact same-generation successor;
- `Reset { reasons }` — exact successor in the next state generation;
- `EpochRolledOver { previous_epoch_id }` — unseen epoch at sequence and generation
  zero;
- `Rejected { reason }` — typed lifecycle/order rejection; and
- `Faulted { reason }` — structurally valid admission reached an adapter, detector,
  or receipt fault, with the exact returned display reason.

There is no separate public `Empty | Collecting | Ready | Unavailable | TimedOut`
lifecycle state enum in 0.9. Readiness remains a property of the sealed statistical
reports and retained suffix; timeout control is represented by a typed reset reason.
Documentation and consumers **SHALL NOT** infer a larger public state algebra from
internal track history.

### First position

A previously unseen logical lane accepts a valid position only at state generation
zero. The initial sequence need not be zero, allowing an explicitly positioned late
join. Initialization creates the lane and produces a receipt before the result is
returned.

### Ordinary advance

For the active epoch, a frame with the exact next sequence, increasing timestamp,
unchanged continuity context, and unchanged state generation is `Advanced`.
`LifecycleDetector::assess_positioned_frame` binds the position epoch to the
assembled sidecar `session_id` and binds position sequence/timestamp to the
assembled frame before statistical assessment.

### Reset

**GLD-090-RST-001 — generation-advancing reset.** A physical-frame change,
projection-context change, projection-registry digest change,
expected-modality-set change, or inter-sample deadline excess **SHALL** require the
next state generation. Supplying the old generation is `MissingReset`; skipping or
reusing a generation is a typed mismatch.

An explicit caller-selected reset may also advance the generation when no automatic
continuity reason is present. The admitted reason set is closed and nonempty:
`Explicit`, `Timeout`, `ProjectionFrameChanged`, `ProjectionContextChanged`,
`ProjectionRegistryChanged`, `ExpectedModalitiesChanged`, or
`InterSampleDeadlineExceeded { gap_ms, maximum_ms }`. A detector-created reason set
contains at most five canonical reasons; explicit and timeout control operations
produce singleton sets.

`reset_at` and `timeout_at` accept only the exact position returned by
`StreamPosition::checked_reset` from the active position. They consume one sequence,
increment generation exactly once, require a newer timestamp, clear retained
statistical suffixes, and commit a receipt without fabricating an assessment.
Generation exhaustion fails in the domain constructor; it never wraps or saturates.

`timeout_at` does not observe a clock or infer silence. It receipts a timeout already
established by the caller's external deadline authority. Transport heartbeat,
reorder, and incomplete-frame timers remain responsibilities of the live receiver
and assembler.

### Epoch rollover

**GLD-090-EPC-001 — fresh epoch.** `rollover_at` **SHALL** preserve the logical
producer/session/stream and clock domain, select an epoch not previously used in
that lane, and begin it at sequence zero and state generation zero. It clears track
history, frame continuity, and recent-frame fingerprints while retaining the
non-evicting used-epoch set and the global receipt chain.

An `A -> B -> A` epoch sequence is rejected while the detector lives. Reaching the
used-epoch bound faults rather than evicting old identities. A rollover is not an
automatic response to replay-map or counter exhaustion and is not proof that an
external peer authorized the new epoch.

### Rejection and terminal fault

Lifecycle/order rejections produce `Rejected { reason }`; structural, assessment,
or receipt failures produce `Faulted { reason }`. Both the typed rejection and the
exact returned fault-reason string are bound into the receipt chain when receipt
construction succeeds. The first error is latched, retained statistical history is
cleared, and later calls return that fault. The 0.9 detector instance has no same-
instance recovery after a latched fault; recovery requires an externally coordinated
fresh detector/epoch rather than late repair.

This fail-closed behavior intentionally differs from a transactional database
claim: a rejection appends audit evidence and terminally clears statistical
history. It never advances a valid assessment or yields `Nominal`.

## 3. Lifecycle-complete assessment

`CrossRouteAssembler` first proves route, producer/session, monitor order,
frame-summary, observation-count, registry, projection, prior, deadline, and replay
invariants. Partial route data is staging and never reaches `LifecycleDetector` as
a complete frame.

After typed admission, `LifecycleDetector` evaluates frozen tracks in deterministic
track order:

- if every expected modality has exactly one assessable common projection, the
  bounded contiguous suffix is passed to `assess_default` under an accepted
  `ReleaseSuite` and yields `LifecycleAssessment::Evaluated`;
- if any expected modality is explicitly missing, rejected, unsupported, or
  incomparable, the complete affected track suffix is cleared and the adapter
  yields `LifecycleAssessment::Abstained` with the canonical unavailable modalities.

Missingness is not imputed as zero NIS, a nominal observation, an anomaly, or an
attack cause. A later valid frame begins a new suffix; observations from opposite
sides of the explicit absence cannot share one detector window.

The assessment receipt binds the accepted `ReleaseSuite` identity unconditionally,
including for zero-track and fully abstained frames, followed by the complete deterministic
JSON serialization of every ordered `LifecycleAssessment`. Evaluated entries therefore
bind every serialized numeric/detail field of the sealed baseline and correlation reports,
not only their disposition or fused verdict. `verifies_assessments` recomputes that exact
suite-plus-assessment digest. Exact numeric reports are recomputable only when a publication
policy separately retains the complete receipt-linked frame evidence and immutable suite;
the assessment digest alone is not a substitute for that evidence.

## 4. Receipt contract

**GLD-090-RST-002 — typed receipt.** Every accepted, rejected, or faulted lifecycle
decision that can be encoded produces a `LifecycleReceipt` with:

- a JSON-safe global receipt index;
- the immediately preceding receipt digest;
- its own domain-separated SHA-256 digest;
- typed producer identity and complete `StreamPosition`;
- the closed `LifecycleTransition`;
- an optional digest of the complete assembled frame; and
- an optional digest of assessment dispositions.

`LifecycleReceipt::verifies` recomputes its canonical digest.
`LifecycleReceipt::follows` verifies two adjacent chain members. The chain is global
to one detector instance and deterministic across its accepted call order.

Receipts have a frozen strict-JSON representation. `LifecycleReceipt::decode_and_verify`
accepts at most 16,384 encoded bytes inclusive, rejects malformed, wrong-shape, or digest-
mismatched input, and returns a receipt only after its embedded digest verifies. This is
internal integrity under the frozen encoding, not authentication of the writer, chain
membership, durability, or an external signature/MAC. The interoperability vector is
[`crates/galadriel-ncp/tests/fixtures/lifecycle-receipt-v0.9.json`](../crates/galadriel-ncp/tests/fixtures/lifecycle-receipt-v0.9.json).

Receipt retention is bounded memory, not durable storage. Once 65,536 receipts are
held, the oldest is evicted; `receipt_anchor` exposes the digest immediately before
the new oldest entry and `evicted_receipts` exposes the count. The final release or
deployment policy remains responsible for durable persistence if it needs an audit
journal. Galadriel 0.9 makes no crash-consistency, fsync, external signature, or
independent archive claim for lifecycle receipts.

## 5. Frozen sidecar v1 compatibility mapping

The sidecar v1 frame carries `producer_id`, an epoch-scoped `session_id`, fusion
sequence, and fusion timestamp, but no distinct core session, epoch, stream, state-
generation, or clock-domain fields. `assess_frame_transition` therefore derives a
project-local compatibility position:

```text
core session  := producer_id
core epoch    := sidecar session_id
core stream   := "galadriel-fusion"
clock domain  := monotonic_process
sequence/time := assembled fusion sequence/timestamp
generation    := retained continuity state
```

`assess_frame` delegates through that mapping and discards only the returned receipt
from its convenience return value; the receipt remains in the detector's bounded
chain. This is compatibility behavior, not a claim that sidecar v1 or NCP 0.8 has a
generic reset/rollover control message. The local schema name `v1` is not a released
NCP 1.0 integration.

`clear_histories` remains deprecated and diagnostic-only. Because it has no typed
producer position, it cannot represent an accepted reset and must not be used to
continue the same operational stream generation.

## 6. Explicit exclusions

The implemented state boundary does not establish:

- producer authenticity or authorization for caller-supplied positioned events;
- current reciprocal Crebain integration or final cross-repository qualification;
- durable, signed, independently archived, or crash-consistent receipts;
- automatic wall-clock timeout detection inside `LifecycleDetector`;
- same-instance recovery after a latched lifecycle fault;
- NCP 1.0 compatibility or any upstream 1.0 product release;
- platform timing, real-router mTLS/ACL enforcement, field performance, or detector
  calibration; or
- permission for a verdict to affect control authority.

Those exclusions remain `NOT_CLAIMED`. The lifecycle adapter supplies bounded,
typed, replay-conscious evidence admission for a research advisory monitor; it does
not authenticate physical truth or turn statistical consistency into a safety
decision.
