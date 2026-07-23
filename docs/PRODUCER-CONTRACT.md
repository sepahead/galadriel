# Producer observation and lifecycle contract

## Abbreviations

| Short form | Meaning |
|---|---|
| ACLs | access control lists |
| ADR | architecture decision record |
| API | application programming interface |
| ASCII | American Standard Code for Information Interchange |
| CA | certificate authority |
| CI | continuous integration |
| CLI | command-line interface |
| CN | certificate common name |
| CUSUM | cumulative sum |
| ENU | east-north-up |
| JSON | JavaScript Object Notation |
| JSONL | JavaScript Object Notation Lines |
| mTLS | mutual Transport Layer Security |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| SHA-256 | Secure Hash Algorithm 256 |
| SPKI | Subject Public Key Info |
| TLS | Transport Layer Security |
| UTF-8 | 8-bit Unicode Transformation Format |
| WebPKI | Web Public Key Infrastructure |

Status: accepted Galadriel-side ADR. Local consumer components are implemented.
Deployment evidence is excluded.

These Galadriel components exist and have component tests:

- strict contracts
- pinned-registry capability
- assembler
- typed lifecycle adapter
- exact-epoch configuration profile

Crebain `4c311900ade5668200a48d56fb191be1916b884a` and Galadriel
`81437d807ca83b66b45c8353968948e540072d97` are a historical compatibility
fixture. They do not pin this candidate.

These evidence classes are `NOT_CLAIMED`:

- current reciprocal integration
- final cross-repository qualification
- remote-router enforcement
- operational calibration

The read-only Crebain inspection from 2026-07-18 used
`0a58a5b8dd799884ddb06f1308b1748216fab322`. It confirmed component-level
alignment for these items:

- two exact routes
- schema `1.0`
- NCP wire `0.8`
- contract hash `d1b50a2d8a265276`
- 64 KiB envelope ceiling
- monitor taxonomy
- registry bounds
- 3,053-byte retained registry fixture

The fixture has raw SHA-256
`506ce1437acc20ee5d36fd1e3551dd020095cc4d30d22d959c5df3cca81715a6`. Its
canonical SHA-256 is
`7644ec2bbf0e400303aaad62c647eea36bd919913f1a28a81c52c13e00dd45ba`.

This inspection establishes byte and schema fixture compatibility only. The
formal Crebain 0.9 boundary still freezes Galadriel
`94e2f8cc01f352d2bf899b7f656997f143a2588f`. It does not pin the final Galadriel
0.9.0 release object. It also does not supply the secured multi-process campaign.

Current reciprocal pins and deployed secured interoperability are separate unmet
evidence classes. See
[`ECOSYSTEM-CONNECTIONS.md`](ECOSYSTEM-CONNECTIONS.md).

## Decision

The Galadriel consumer contract defines two project-owned observation-only sensor
routes. A conforming producer uses both routes for different responsibilities.

| Route | Payload | Responsibility |
|---|---|---|
| `{realm}/session/{epoch}/sensor/galadriel-pid` | Frozen `SidecarEnvelope` schema v1 | At most one real accepted observation for each `(track, modality, frame)`. The observation must be suitable for existing detectors. |
| `{realm}/session/{epoch}/sensor/galadriel-monitor` | Strict monitor envelope schema v1 | Measurement lifecycle outcomes, fusion-frame closure, and producer liveness. |

The observation route MUST remain byte-compatible and schema-compatible with
[`galadriel-pid-envelope-v1.schema.json`](../crates/galadriel-ncp/schemas/galadriel-pid-envelope-v1.schema.json).
Monitor events MUST NOT enter that route.

The monitor route MUST use a separate strict project-owned schema with its own
version. It MUST NOT be described as a normative NCP message.

The operational profile joins both routes and fails closed. One v1 observation is
still valid for existing baseline and replay behavior. It is not sufficient for a
lifecycle-complete cross-modal operational assessment.

The words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are normative in
this document.

## Context and current state

The existing v1 sidecar is deliberately narrow. Its strict `SidecarEnvelope`
contains these fields:

- `kind = "galadriel_pid_observation"`
- `schema_version = "1.0"`
- NCP version and hash provenance
- `session_id`
- `producer_id`
- one `PidObservation`

The live consumer subscribes to
`{realm}/session/{epoch}/sensor/galadriel-pid`. The historical `-pid` name is
frozen. Primary statistics are NIS, CUSUM, and signed consistency correlation.

The payload can represent an accepted measurement update. It cannot represent any
of these events:

- association miss
- gate rejection
- update failure
- empty fusion frame
- frame completion
- queue loss
- independent heartbeat

The live `RejectionReason` type describes receiver-side payload, decode, and replay
failures. It is not a producer lifecycle vocabulary. A producer MUST NOT use it
for that purpose.

A `payloads_received` counter shows only that some traffic arrived. It does not
show producer liveness.

The command-line application provides `observe` behind `ncp-live`. It loads an
externally digest-pinned registry and opens the strict secure Zenoh client. It
joins both exact routes through one serialized bounded input. It advances all
declared deadlines and sends only complete lifecycle frames to the detector
adapter.

Explicit misses and rejections cause immediate abstention. They also clear the
affected suffix.

The producer design requires a runtime to complete these actions:

1. Snapshot the predicted track set before association and update.
2. Calculate registered Cartesian projections from that one prior.
3. Record bounded opportunity outcomes.
4. Publish summaries through ordered queues.
5. Run an independent heartbeat.

The retained Crebain and Galadriel commit pair is a historical compatibility
fixture for this design. It is not the current candidate. Historical JSONL
captures contain only successful updates. New implementations do not change
that evidence.

Existing evidence is synthetic, golden, unit, property, or in-process transport
evidence. An external acceptance gate still needs a real multi-process campaign.
The campaign must cover allow and deny behavior, certificates, restarts, loss, and
all-silence conditions.

This ADR defines the implemented Galadriel consumer contract. It excludes
producer, cross-repository, and deployment evidence.

## Route and publication rules

Both routes belong to exactly one realm and producer epoch. Publishers MUST use
the exact named sensor keys above. A publisher MUST use the raw perception-plane
byte publication API for these project-owned envelopes.

A publisher MUST NOT wrap either payload in a normative NCP `SensorFrame`. It
MUST NOT publish through an API that requires that wrapper.

The observation route is frozen:

- The envelope discriminator, schema version, field names, optional-field
  behavior, and nested `PidObservation` representation MUST NOT change in place.
- The producer can publish only real accepted observations that pass the existing
  semantic validator.
- A producer MUST NOT encode a miss, rejection, failure, heartbeat, or frame
  summary as a `PidObservation`.
- An incompatible change needs a new route and schema version. It also needs a
  coordinated producer and consumer migration.
- A producer MUST NOT hide an incompatible change in v1 with a new discriminator
  or tagged union.

The monitor route is a separate compatibility boundary. Its Rust types, JSON
Schema, golden examples, and negative fixtures are frozen together. The bounded
decoder rejects unknown fields and unknown tagged-union variants.

Schema evolution MUST use explicit compatibility and version rules. An
incompatible shape requires a new schema version. It cannot use permissive
best-effort decoding.

JSON Schema validation is necessary but not sufficient for canonical wire input.
JSON Schema treats integer-valued `1.0` and `1e0` tokens as integers. The bounded
Rust decoder requires canonical integer tokens for `u32` and `u64` fields.

Application validation also checks UTF-8 byte ceilings and cross-field invariants.
The schema cannot express all these requirements.

## Epoch and sequence identity

`epoch` is the sidecar `session_id`. Both `session_id` and `producer_id` MUST use
the Galadriel core identity grammar. Each value MUST contain 1 through 64 ASCII
bytes. It MUST start and end with an ASCII letter or digit. Its other characters
MUST be ASCII letters, digits, hyphens, underscores, periods, or colons. A value
that is only a valid generic NCP path segment is not sufficient.

The pre-release 0.9.0 schemas narrowed these fields from the earlier draft grammar.
This change occurred before the first public 0.9.0 release.
An authorized producer MUST use the narrower grammar before live operation.

Every envelope on both routes MUST contain the same `session_id`.

The epoch is an application-owned producer-process epoch. It does not assert
membership in an NCP control-plane session-generation service.

An epoch MUST be:

- stable for one producer process epoch
- freshly created before a counter or replay-state reset
- never reused by a new producer process epoch after a crash or rollback

Observation, fusion, and monitor sequences MAY restart only after a fresh epoch.
A consumer MUST subscribe to an exact epoch path. It MUST partition replay and
assembly state by epoch. It MUST reset that state after an epoch change. It MUST
retire the old subscription with a bounded handover policy.

An epoch reuse after a sequence reset is a protocol fault. It is not a recovery
method.

All numeric JSON identifiers MUST be nonnegative and at most `2^53 - 1`. Sequence
counters MUST follow the monotonic rules for their event type. Counter exhaustion
requires a fresh epoch. Wrapping and silent saturation are prohibited.

## Common consistency projection

Cross-modal consistency MUST use a signed position residual in one registered
three-dimensional Cartesian ENU or world frame. Values use meters.

```text
r[c,t] = z_ENU[c,t] - h_ENU[c](x_minus[t])
```

Here, `c` is a modality and `t` is a fusion sequence.

`x_minus[t]` is the immutable predicted track prior.

`h_ENU[c]` projects that same prior into the registered observation space for
modality `c`.

The producer MUST snapshot these items after prediction. It does this before
association, the gate calculation, or the first sequential sensor update.

- predicted state
- covariance
- track set
- projection context

Every modality at one fusion sequence MUST derive `consistency_projection` from
that same immutable snapshot. A subsequent sequential update MUST NOT change the
residual for another modality at the sequence.

The projected residual differs from the modality-native innovation. It MUST NOT
fall back to that innovation.

The producer MUST transform radar range, azimuth, and elevation through the
registered calibration and extrinsic chain. The same rule applies to other native
measurements. The transformation occurs before subtraction in the common
Cartesian frame.

The producer MUST NOT put angle or range components in Cartesian projection axes.
Active axes MUST have stable order. Inactive axes MUST remain zero as required by
the frozen v1 observation schema.

If a valid common-frame mapping is unavailable, the producer MUST emit an explicit
monitor outcome. For example, it can emit `incomparable_projection`. It MUST NOT
create projection values. It MUST mark the affected frame ineligible for
cross-modal consistency assessment.

### Frame and context registry

Every nonzero `frame_id` and `context_id` refers to a version-controlled and
deployment-pinned registry. The registry is part of the evidence contract. It is
not an informal naming convention.

A frame entry MUST define at least:

- ENU or world frame name, origin, and datum
- axis order, direction, handedness, and units
- transform chain and its authority
- validity interval or other applicability limits

A context entry MUST define at least:

- projection algorithm and version
- output dimension and axis order
- sensor calibration and extrinsic identifiers with content digests
- covariance and linearization semantics
- enabled modality set
- producer software and configuration digest that fixes these semantics

Registry identifiers are immutable. An identifier MUST NOT receive new semantics.
A semantic change requires a new identifier.

Producer and consumer MUST pin the same registry version and content digest. Each
frame summary MUST bind the frame registry digest. Unknown identifiers and digest
mismatches MUST fail closed. Expired applicability and inconsistent frame-context
bindings MUST also fail closed.

### Global prior identity

`prior_id` identifies the immutable predicted snapshot set for a complete frame.
It is global within one epoch. Track, modality, `frame_id`, and `context_id` do not
create separate namespaces.

It MUST be nonzero and follow this mapping:

```text
prior_id -> exactly one fusion_seq within an epoch
```

The same `prior_id` MAY occur across tracks and modalities at that one sequence.
They all attest to the same frozen prediction boundary.

The identifier MUST NOT occur at another sequence. A frame or context change does
not permit reuse. A partial frame failure also does not permit reuse.

A consumer MUST retain a bounded epoch-level high-water index that rejects reuse.
Changed provenance MUST NOT make reuse acceptable. A fresh epoch starts a new
namespace.

## Monitor wire contract

The monitor route carries one strict envelope per event. Its version-1 envelope
MUST contain:

- `kind = "galadriel_producer_event"`
- `schema_version = "1.0"`
- the canonical `ncp_version` spelling from the frozen schema
- `contract_hash` with the observation-sidecar advisory compatibility semantics
- `session_id` and `producer_id` that match the key and peer identity
- epoch-global `event_seq`
- an adjacent-tagged `event` union

`event_seq` is a JSON-safe integer. It starts at 1 and increments for each
attempted monitor event. The producer assigns it before queue admission.

The `event` union contains these variants:

- `modality_outcome`
- `modality_miss`
- `frame_summary`
- `heartbeat`

The Rust types and JSON Schema are frozen together. Conformance also requires the
sequence, assembly, epoch, queue, registry, and security rules in this ADR.

Every string, collection, count, and encoded event MUST have a finite maximum.
Both JSON Schema and application validation must enforce the limits. At minimum,
the implementation MUST define and test:

- `MAX_MONITOR_EVENT_BYTES`
- identifier and string limits
- `MAX_FRAME_ITEMS`
- `MAX_MONITOR_QUEUE_EVENTS`
- `MAX_ACTIVE_TRACKS`

A deployment MAY use smaller limits. It cannot use larger wire limits under the
same schema. All floating-point values MUST be finite.

A limit violation is an explicit overflow or protocol fault. Silent truncation is
prohibited. `FrameSummary.truncated = true` declares an explicit degraded fault.
It never makes partial accounting acceptable.

### Outcome event

`modality_outcome` records one bounded association or update opportunity. It
belongs to one fusion sequence and modality. It identifies its track and one of
these dispositions:

- `updated`
- `gate_rejected`
- `assignment_rejected`
- `update_rejected`
- `track_birth`
- `unsupported_filter`
- `incomparable_projection`

`modality_miss` closes an expected active-track and modality pair. It uses one of
these reasons:

- `no_measurement`
- `no_candidate`
- `no_in_gate_candidate`
- `not_assigned`
- `track_not_eligible`

A miss never contains invented gate, NIS, or projection values.

An outcome contains these values:

- `fusion_seq`
- `fusion_timestamp_ms`
- `frame_id`
- `context_id`
- `prior_id`
- `track_id`
- modality
- bounded deterministic `attempt_index`
- optional bounded `measurement_index`
- pair-level candidate count
- pair-level in-gate count
- typed disposition

Each attempt outcome repeats the pair-level counts. Thus, a `gate_rejected`
attempt can report a nonzero `in_gate_count`. Another candidate for the same pair
can have passed the gate.

Each outcome that claims candidate gating MUST contain finite gate evidence from
the correct contractual inputs. This rule applies to `updated`, `gate_rejected`,
`assignment_rejected`, `update_rejected`, and `incomparable_projection`.

`updated` MUST also contain its valid common-frame projection. If the producer
cannot attest that projection, it MUST use `incomparable_projection`.

Other quantities MUST appear only when they were calculated. Canonical output
MUST omit undefined optional values. It MUST NOT fill them with zero or invented
values.

The frozen decoder and schema also accept explicit JSON `null` for compatibility.
They normalize it to the absent value. Producers MUST still emit the canonical
omitted form.

Gate evidence names either `mahalanobis` or
`normalized_euclidean_fallback`. The fallback is explicitly not chi-square.

Each outcome MUST state `v1_expected`. It is true only when the frozen route
requires exactly one matching accepted observation.

The v1 consumer permits at most one consistency observation for an
`(epoch, fusion_seq, track_id, modality)` key. Thus, only one accepted
attempt for that key can set `v1_expected = true`.

Other returns and opportunities MUST remain bounded monitor outcomes. They
need deterministic attempt identities. They MUST NOT create ambiguous duplicate
v1 records.

The producer MUST use one documented deterministic rule to enumerate and
aggregate opportunities. It MUST emit positive and negative outcomes for every
opportunity in that rule. The registry or configuration digest MUST
include the rule and all limits. Thus, an audit can examine missingness and
selection.

The version-1 cardinality rule is fixed. The Cartesian ledger uses the active
track set frozen after prediction and before association or update. For each
frozen track and expected modality, the producer emits every bounded attempt
outcome first.

It then emits exactly one `modality_miss` when no attempt reached an assigned or
filter terminal disposition. The producer selects the reason deterministically:

1. Use `track_not_eligible` when eligibility failed.
2. Otherwise, use the deepest stage reached in this order:
   `no_measurement`, `no_candidate`, `no_in_gate_candidate`, `not_assigned`.

When no other candidate passed, `gate_rejected` outcomes have one aggregate
`no_in_gate_candidate` miss. When nothing was selected,
`assignment_rejected` outcomes have one aggregate `not_assigned` miss.

Any of these terminal outcomes suppresses the miss for the pair:

- `updated`
- `update_rejected`
- `unsupported_filter`
- `incomparable_projection`

A producer MUST NOT emit another outcome and miss combination for the pair.
`FrameSummary.outcome_count` counts outcomes and misses.

`no_candidate` requires at least one frame input. When `input_count` is zero, a
non-eligibility miss MUST be `no_measurement`.

The producer emits frozen pair ledgers in strict
`(track_id, registered modality order)` order. Attempt and measurement indices
increase within a pair. Its optional aggregate miss is last.

`track_birth` is a measurement-level outcome outside the pre-association
Cartesian ledger. Births follow all frozen-pair records. They use strict
`(measurement_index, track_id, registered modality order)` order.

Birth track identifiers and measurement indices are unique within the frame. A
track born in the frame does not create or suppress a miss. It enters the frozen
active-track set in the next frame.

### Frame summary

A `frame_summary` is the only normal closure record for a `fusion_seq`. The
producer MUST emit it for zero-track and zero-observation frames.

It MUST contain:

- epoch, fusion sequence, `frame_id`, `context_id`, and `prior_id`
- registry version and content digest
- expected modality set
- bounded active-track count
- bounded input count
- bounded total outcome and miss count
- bounded `v1_expected` count
- explicit `degraded` and `truncated` fault flags

`active_track_count` is the track count after processing. It does not change the
pre-association snapshot that defines miss cardinality.

The producer MUST calculate the summary from the immutable frame ledger after
outcomes are final. It MUST NOT convert an absent outcome or v1 observation into
success. A second conflicting closure for one sequence is a protocol fault.

A summary shows when the producer considers a frame complete. It does not prove
lossless transport. Contiguous `event_seq`, exact counts, and cross-route joins
remain mandatory.

### Independent heartbeat

A task independent of sensor input and the fusion loop MUST produce heartbeats.
Its cadence also remains independent of track count and association success. It
MUST continue during zero-track and zero-observation periods.

It contains:

- producer wall time
- monotonic uptime
- last completed `fusion_seq`, if present
- active-track count
- declared interval and deadline
- epoch-degraded flag
- bounded queue depth and capacity
- bounded drop and publication counters

The consumer MUST judge freshness from its monotonic receipt time and configured
deadline. Producer wall time is diagnostic only.

A heartbeat shows only that the authenticated producer and monitor path are alive.
It is not a sensor observation. It cannot close a frame or repair an event gap.

Heartbeat publication SHOULD use a separate bounded queue or lane. Ordinary data
saturation must not silently suppress liveness.

## Cross-route assembly and fail-closed behavior

The operational consumer assembles by epoch and fusion sequence. It then joins
outcomes to v1 observations with this key:

```text
(epoch, fusion_seq, track_id, modality)
```

The monitor `attempt_index` or measurement identifier separates multiple
opportunities. The unique accepted opportunity with `v1_expected = true` maps to
the single v1 key.

These values MUST agree:

- envelope producer and session provenance
- observation sequence
- frame, context, and prior identity
- registry digest

A frame is eligible for operational assessment only after all these conditions
hold:

1. The frame summary arrived.
2. Every declared monitor outcome arrived exactly once.
3. Each `v1_expected = true` outcome has exactly one matching v1 record.
4. The frame has no unexpected or duplicate v1 record.
5. All identity, registry, sequence, projection, count, and digest checks pass.

A consumer MAY archive or process a v1 observation without monitor closure. This
operation requires an explicit baseline or replay profile. The observation MUST
NOT be described as lifecycle-complete operational evidence. A monitor `updated`
outcome without its v1 record is also incomplete.

The consumer MUST use bounded out-of-order buffers and a finite assembly deadline.
Any of these conditions MUST cause a typed protocol or availability fault:

- wrong session or producer provenance
- duplicate or regressed `event_seq`
- event gap
- timeout
- missing outcome, summary, or v1 observation
- unknown registry entry
- prior reuse
- inconsistent frame or context
- unexpected observation
- digest or count mismatch
- buffer overflow

The consumer MUST invalidate or reset the affected frame and uncertain correlation
suffix. This fault gives `Insufficient` or `Rejected`, never `Nominal`. A
subsequent heartbeat MUST NOT repair it.

Replay high-water marks MUST survive ordinary per-frame eviction for the epoch.
Consumer eviction MUST NOT make an incomplete frame eligible. An epoch-retirement
policy can discard state only after the old subscription cannot contribute
accepted evidence.

Bounded prior and track-modality replay maps cannot safely evict while the epoch
remains admissible. Deployments MUST expose their use. They MUST coordinate a new
unused epoch before either map becomes full.

Capacity exhaustion is terminal. It is not an automatic rollover signal and
cannot be repaired in place.

## Producer queues and backpressure

Fusion and sensor callbacks MUST NOT block on network or disk publication. The
producer MUST hand off to bounded observation, monitor, and heartbeat queues.

Frame summaries and heartbeats SHOULD use separate capacity or priority lanes.
This design prevents an observation burst from hiding closure or liveness. It must
preserve the order required for `event_seq` validation.

All monitor lanes MUST merge through an ordered publication barrier. Priority
MUST NOT reorder surviving events across their assigned `event_seq`. A dropped
event remains visible as a gap when an event with a larger sequence arrives.

The producer MUST assign `event_seq` before enqueue. Thus, a full queue creates a
visible gap instead of an undetected omission.

Queue policy MUST be deterministic and documented. By default, it SHOULD preserve
queued events and drop the newest attempted event. It MUST NOT use an unbounded
queue. It MUST NOT silently block the fusion loop, retry forever, or create a
successful summary after loss.

Any queue overflow or publication failure MUST:

- increment monotonic counters that do not reset within the epoch
- put the epoch in a degraded state
- appear in the heartbeat and next deliverable frame summary
- make all potentially affected frames ineligible when the missing range cannot
  be proved and bounded

The consumer transport callback MUST also use a bounded nonblocking handoff. Its
assembler MUST limit active epochs, frames, tracks, outcomes, bytes, and reorder
distance. It must also expose timeout and overflow metrics.

Drop-newest behavior is acceptable only when it invalidates affected evidence and
shows a fault. Eviction MUST NOT silently restore eligibility.

## Security and identity boundary

`producer_id` and `session_id` in JSON are claims, not signatures. Operational
acceptance requires transport authentication and authorization. These controls
must bind the claims to the publisher.

The deployment MUST use mutually authenticated TLS and default-deny ACLs. It MUST
map the producer certificate identity or CN to the configured `producer_id`. An
equally strong authenticated principal can replace that identity.

The producer principal can PUT only key expressions for its allowed realm, epoch,
and two exact sensor names. It MUST NOT receive a broader `sensor/**` grant.
Envelope identity MUST match the route and configured principal.

An observer MUST use separate read-only credentials. They can only SUBSCRIBE. The
observer MUST NOT be able to PUT, issue commands, take leases, or use control and
action routes.

A generic wildcard `robot` role cannot by itself bind an application `producer_id`
or epoch in a multi-producer fleet. Deployments MUST specialize the
identity-to-key mapping. Positive and negative authorization tests must prove the
mapping.

A consumer on a host-provided bus inherits the host security posture. Construction
alone does not prove mTLS or ACL enforcement. Secure mode MUST be explicit and
fail closed.

Zenoh 1.9 authenticates the router against built-in public WebPKI roots and the
deployment CA. The deployment CA is not an exclusive server pin.

Conformance needs one more control. Use a private router hostname that
cannot receive a public certificate, with controlled name resolution. Otherwise,
use an external layer that enforces the exact router certificate or SPKI.

The configured client-authentication CA still constrains router-side client
certificate mTLS. See
[`SECURE-DEPLOYMENT.md`](SECURE-DEPLOYMENT.md#tls-server-authentication-limitation).
Exclusive router pinning by the local profile alone is `NOT_CLAIMED`.

The deployment MUST configure the Zenoh maximum receive message size. The
transport MUST reject an oversized message before excessive allocation.
Application event-size limits remain necessary after transport framing. Neither
limit replaces the other.

Credentials and private keys MUST NOT occur in payloads, logs, fixtures, or
evidence bundles.

The routes are observation-only. This ADR grants no authority for commands,
actions, leases, or vehicle control.

## Acceptance matrix

An implementation is not conformant or deployable before all five lenses have
durable and reviewable evidence.

| Lens | Required evidence | Acceptance condition | Failure behavior |
|---|---|---|---|
| Protocol and correctness | Frozen Rust and JSON schemas with golden files. Registry fixtures. Common-prior and radar-to-ENU tests. Prior-reuse rejection across frame and context. Exact event counts and joins. Safe-integer, unknown-field, fuzz, and property tests. | Independent producer and consumer agree on valid fixtures. They reject each invalid invariant without panic or ambiguity. | Typed protocol fault. The affected frame and suffix are ineligible, never `Nominal`. |
| Statistics and evidence | Pre-gate opportunities and each lifecycle stage. Modality and stage exposure. Missingness and pre-gate to post-gate comparisons. No invented statistics. Repeated-look and autocorrelation calibration. Separation of errors from genuine insufficiency. | A review can reconstruct selection and censoring. It shows that detector input uses the frozen common prior and calibrated interpretation. | Report `Insufficient`, selection bias, or explicit statistical invalidity. Do not infer health from absent or rejected samples. |
| Reliability and security | Loss, reorder, duplicate, restart, heartbeat-silence, saturation, timeout, and message-size tests. Real multi-process mTLS and ACL tests for valid, wrong, and absent certificates. Wrong-identity, observer-write, and observer-control negative tests. | Detect each injected fault within a declared limit. Deny unauthorized publication and control at the transport boundary. | Availability or security alarm with epoch degradation or rejection. Do not promote the input to operational evidence. |
| Integration and operations | Normal producer and live consumer services. Fresh epoch creation, discovery, resubscription, and reset. Real router and process tests. Metrics, alerts, and a runbook. Traffic, denial, restart, decode, and all-silence exercises. | An operator can distinguish idle health, sensor silence, producer death, transport loss, decode failure, incomplete frames, and denied peers. | Explicit observable state and bounded recovery. Ambiguous silence fails closed. |
| Maintainability and testing | Versioned code and schemas. Cross-repository conformance data and golden files. One authoritative type definition or an explicit coordinated version-bump process. CI fuzz, property, and integration tests. Issue ownership and API and documentation review. | Contract drift breaks CI. Incompatible changes require review and versioning. Each invariant has an owner and regression test. | Block the release. Do not allow a permissive decoder or undocumented compatibility exception. |

Evidence MUST record exact software revisions, registry and configuration digests,
schema versions, router security configuration, test commands, and results.

A synthetic JSONL or replay test is useful protocol and statistics evidence. It
MUST NOT prove live routing, independent heartbeat behavior, backpressure, or
mTLS and ACL enforcement.

## Rejected alternatives

### Tagged union on the v1 observation route

The design rejects lifecycle tags or monitor variants on the v1 route. The v1
schema and decoder are strict. The live tap expects one observation. Existing
sequence and detector state is specific to observations.

A union breaks current compatibility or encourages permissive decoding. It
could send lifecycle events into the statistical stream. A separate monitor route
preserves the frozen v1 contract. It gives lifecycle evolution a separate version
boundary.

The design also rejects producer lifecycle use of `RejectionReason`. Receiver
decode and replay disposition differs from producer measurement lifecycle. They
have different trust boundaries.

### Fabricated observation or frame for absence

The design rejects an invented `PidObservation`, NIS, residual, prior, successful
empty frame, or heartbeat. This rule applies when a measurement is absent, fails
gating, cannot project, or is lost.

Invented samples can warm detector windows and create false cross-modal
correlation. They can produce `Nominal` and hide selection bias. Consumer
timeouts also cannot create producer evidence.

Absence and failure remain explicit monitor outcomes. They fail closed.

## Consequences and implementation order

The separate route needs an extra schema, publisher lane, consumer assembler, and
cross-route state. It preserves compatibility for existing v1 users. It makes
negative measurement evidence auditable.

The route also separates idle liveness from observations. Transport loss cannot
silently look like a statistically healthy frame.

The release disposition is:

1. **Implemented locally:** monitor Rust and JSON types, limits, and typed reason
   taxonomy. Also included are registry parsing, pin capability, and opportunity
   policy. Live monitor tap, assembler, lifecycle adapter, two-route receiver,
   CLI, exact-epoch secure configuration, counters, and in-process fault tests are
   also implemented.
2. **Historical fixture:** the two old commit identities record an earlier
   byte-identical registry and compatibility exercise. They supply provenance,
   not current qualification evidence.
3. **Not claimed:** a reciprocal current producer pin or final cross-repository
   qualification.
4. **External gate:** run and retain all five acceptance lenses on a secured
   multi-process deployment. Then complete a recorded pre-gate calibration study
   that is independent of threshold fitting.

The operational components remain a research prototype until the external gate
and acceptance matrix are complete. No deployment, remote ACL, field performance,
or calibrated-posterior claim is justified.
