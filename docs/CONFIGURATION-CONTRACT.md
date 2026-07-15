# Configuration construction and capability contract

Status: **normative implemented contract** for Galadriel 0.9.0. The accepted
configuration boundaries described below are present across the core, PID,
simulation, evaluation/evidence, NCP registry/assembler, live-ingress, and secure-
transport surfaces. This document describes source semantics; final candidate
qualification and retained release evidence are separate gates and are not implied
by the existence of these APIs.

In this document an **accepted configuration** is a value that a detector,
generator, evaluator, adapter, or transport/runtime component may retain or use.
A **parameter value** is untrusted, possibly incomplete input that has not crossed
that boundary. A source release profile is a reproducible set of shipped values;
it is not a field calibration, a deployment qualification, or permission to affect
control authority.

## Normative requirements

**GLD-090-CFG-001 (validated construction):** Every accepted statistical,
simulation, evaluation, evidence, resource, deadline, registry-policy, and live
ingress configuration **SHALL** be created through a fallible construction or
conversion boundary. That boundary **SHALL** validate every local invariant before
returning the accepted type. A public `validate(&self)` method on a freely
constructible value does not satisfy this requirement.

**GLD-090-CFG-002 (immutable accepted values):** Every accepted configuration
**SHALL** have private fields and **SHALL NOT** expose setters, `&mut` field access,
interior mutability, unchecked public constructors, or public struct-literal
construction. Once accepted, a value may be borrowed, moved, or cloned exactly;
any semantic change **SHALL** create a new accepted value through a fallible
boundary. A runtime **SHALL** retain only the accepted value, never its mutable
builder or raw parameters.

**GLD-090-CFG-003 (raw parameters cannot confer validity):** Mutable builders or
public-field `*Params`/`*File` records MAY represent untrusted input, but their names
**SHALL** identify them as parameters rather than configurations. They **SHALL NOT**
implement a marker or trait accepted by detector/runtime entry points. Conversion
to an accepted configuration **SHALL** consume or immutably borrow the complete
parameter set and return `Result<AcceptedConfig, TypedConfigError>`.

**GLD-090-CFG-004 (whole-value and aggregate validation):** Construction **SHALL**
validate field ranges, cross-field relationships, finite floating-point domains,
checked integer arithmetic, allocation ceilings, and conservative work ceilings.
Composition boundaries **SHALL** repeat the preflight for costs that depend on more
than one accepted value, such as detector window versus correlation window,
track/modality cardinality, active projection axes, estimator fits, bootstrap
replicates, queue relationships, and deadline ordering. No allocation, state
mutation, subscription, input read, estimator invocation, or worker creation may
precede the relevant aggregate preflight.

**GLD-090-CFG-005 (fallible derivation):** Statistical family-budget adjustment,
profile override, axis-count correction, and any other derived configuration
**SHALL** use a named fallible operation returning a new accepted value. Code
**SHALL NOT** clone an accepted configuration, mutate `family_alpha` or another
field, and validate later. A zero axis count, arithmetic underflow/overflow, or an
unresolvable tail rank **SHALL** return a typed configuration error without
partially running an assessment.

**GLD-090-CFG-006 (explicit profiles):** User-facing and evidence-producing call
sites **SHALL** select a named, versioned profile. `Default::default()` **SHALL NOT**
silently select between release and research semantics. If `Default` is retained
temporarily for source compatibility, it **SHALL** be documented and tested as an
exact alias of one named profile, and release/evidence code **SHALL NOT** call it.
Profile resolution itself **SHALL** use the same validation path as custom
parameters.

**GLD-090-CFG-007 (strict decoded parameters):** Any configuration decoded from
JSON or another schema **SHALL** decode into a raw parameter type with a declared
schema/profile version, reject unknown fields and unknown enum variants, reject
duplicate object keys at the ingest boundary, and reject missing required
semantics. `serde(default)`, `#[serde(other)]`, a flattened extension map, or
silently ignored fields **SHALL NOT** supply scientific, security, resource, or
authority semantics. The decoded parameter value **SHALL** then cross the same
fallible accepted-configuration boundary as native Rust input. An accepted
configuration **SHALL NOT** derive `Deserialize` in a way that bypasses validation.

**GLD-090-CFG-008 (typed failure):** Configuration rejection **SHALL** be distinct
from invalid observation input, insufficient evidence, anomaly evidence, and
internal faults. Library constructors **SHALL** return a crate-owned typed error;
they **SHALL NOT** panic, use `unwrap`/`expect`, or erase the category into
`String`, `io::Error`, `ZenohError`, or `anyhow::Error`. Binary boundaries MAY add
context after preserving the typed source.

**GLD-090-CFG-009 (observable identity):** Reports and retained evidence **SHALL**
identify the selected named profile and the canonical digest of the complete
accepted configuration. Research/release classification, confirmation mode,
resource ceilings, and derivation such as an axis-family split **SHALL** be in the
digest preimage. Human-readable `Debug` output is not a canonical identity.
Canonical identities are exposed by the accepted core/PID, simulator/evaluator, evidence,
assembler, registry-policy, JSONL/live, and secure-configuration boundaries. A
digest identifies accepted bytes and semantics; it does not authenticate them.

**GLD-090-CFG-010 (documented cost):** Each accepted configuration type and each
composition constructor **SHALL** document construction complexity, construction
allocation, and the worst-case retained-state/work expression it admits. Ceilings
**SHALL** use checked arithmetic and fixed product limits; validating each factor
independently is insufficient.

**GLD-090-CAP-001 (no Boolean blindness):** A Boolean **SHALL NOT** configure a
mode, algorithm, policy, capability, ownership/lifecycle choice, security
exception, or behavior with mode-specific parameters. Such a choice **SHALL** be
a closed enum or a capability type whose variants carry exactly the parameters
that apply. Match statements **SHALL** be exhaustive. Unknown serialized variants
**SHALL** be rejected.

**GLD-090-CAP-002 (PID confirmation):** `PidConfig` **SHALL NOT** contain a
bootstrap mode Boolean. Confirmation is represented by a closed value equivalent
to:

```rust,ignore
pub enum PidConfirmationParams {
    PointEstimateOnly,
    CircularDeleteBlock {
        resamples: usize,
        block_size: usize,
        family_alpha: f64,
    },
}
```

The accepted form **SHALL** have private payload fields or validated payload
newtypes. `resamples`, `block_size`, and confirmation `family_alpha` **SHALL NOT**
exist in the point-estimate variant, so ignored or contradictory combinations are
unrepresentable. The point-estimate variant **SHALL** remain explicitly research
only and its reports **SHALL** identify that attribution is unconfirmed.

**GLD-090-CAP-003 (research capability separation):** The standalone release
suite **SHALL** contain the NIS/CUSUM and signed-correlation configurations and
**SHALL NOT** contain an optional PID Boolean. Enabling the Cargo feature exposes
research APIs but does not select them. A caller **SHALL** explicitly construct a
`PidResearchProfile`/research-suite value before PID work can run; that value
**SHALL NOT** be interchangeable with the release-suite type.

**GLD-090-CAP-004 (security and override choices):** Registry-pin proof,
dirty-tree publication permission, credential-file permission policy, transport
bus ownership, identity-validation role, and joint bootstrap-bound extremum
selection **SHALL** use named enums or capabilities. The 0.9 implementation uses
the pinned-registry and secure-config typestates plus the closed choices listed
below. A privileged override capability **SHALL** be created only at the explicit
CLI/policy boundary and **SHALL** be recorded in evidence.

**GLD-090-CAP-005 (legitimate predicates):** Boolean values MAY remain when they
are observations or inherently binary presentation predicates with no dependent
parameters: for example `dirty`, `degraded`, `decoupled`, `ready`, and terminal
color rendering. Fixed foreign-protocol assertions such as “mTLS must equal true”
MAY be decoded as Booleans, but they **SHALL NOT** be used as Galadriel's internal
mode type. This exception does not permit a Boolean to collapse future semantic
states.

**GLD-090-CAP-006 (declared modality capability):** A release detector suite
**SHALL** carry a validated, non-empty expected-modality set whose cardinality is
compatible with `min_channels`. The empty-vector sentinel used by exploratory
`Mirror::new` **SHALL NOT** select release behavior. Subset-only exploratory
assessment MAY remain available through an explicitly named research capability
or constructor, but its type/value **SHALL NOT** be interchangeable with a release
suite that can report cross-sensor nominal evidence.

## Required type and profile boundaries

All entries in this table are implemented 0.9 boundaries. Public-field parameter
records remain deliberately mutable and untrusted; only the private accepted type
in the first column crosses the corresponding runtime boundary.

| Accepted type or boundary | Classification | Implemented 0.9 boundary |
|---|---|---|
| `DetectorConfig` | release statistical component | Private accepted fields; `DetectorParams` crosses `try_new`/`TryFrom`; read-only getters, named profile resolution, aggregate state budgets, and a canonical identity. |
| `CorrConfig` | release statistical component | Private accepted fields and typed construction; `try_for_axis_family(axis_count)` returns a new identity-bound configuration without mutation. |
| `PidConfig` | optional research statistical component | Private accepted fields; explicit research profiles; closed `PidConfirmation`; fallible family derivation; no mode Boolean or dormant confirmation payload. |
| `Cusum` and `NisWindow` construction | validated detector subcomponents/state | Private fields and fallible construction. Release use derives their values from accepted detector configuration. Direct public construction remains component-research use. CUSUM construction is `O(1)`; window reservation is `O(capacity)`. The detector aggregate includes each window's fixed 272-byte exact-sum cache. |
| upstream PID estimator configs (`IntrinsicDimConfig`, `DistanceConcentrationConfig`, `KsgConfig`, `Pid2Config`, `Jitter`) | pinned foreign research subcomponents | Derive one exact, documented set from the accepted PID research config. Do not let an upstream `Default` silently change a named Galadriel profile; include the selected upstream semantics and revision in profile identity. |
| `ReleaseSuite` | release composition | Distinct PID-free accepted type containing detector, correlation, a canonical nonempty expected-modality set, and axis/family policy; construction checks combined readiness, retained state, and work. |
| `PidResearchSuite` | research composition | Distinct accepted type containing a release suite plus explicit PID research configuration; construction preflights the maximum three-axis confirmation work before analysis. |
| `ScenarioConfig` | research generator | Mutable `ScenarioParams` converts once to immutable `ScenarioConfig`; accessors borrow accepted values, and construction validates modalities, identities, timestamps, variances, observation count, and canonical digest. |
| `EvalConfig` / `EvalSuiteConfig` | research evaluation | Mutable raw parameters convert to immutable accepted values; named research profiles and aggregate suite construction preflight grids, latency prefixes, observations, bootstrap comparisons, and PID work. |
| evidence runner DTOs and `ValidatedEvidenceConfig` | evidence/research input | Strict raw file DTOs convert once to an immutable internal accepted value containing a `ReleaseSuite`, bounded owned vectors, a contained hash-verified fixture, work estimates, and a canonical digest. The runner does not retain the raw DTO. |
| `AssemblerLimits` | operational runtime resource/deadline policy | Private accepted fields, `AssemblerParams`, `AssemblerProfile::BoundedV0_9`, read-only getters, hard/aggregate bounds, deadline ordering, clock preflight, and canonical identity. |
| `RegistryOpportunityPolicy` | deployment-pinned capability | Private accepted fields and typed construction with wire maxima. `RegistryVerifier` yields only this validated policy. |
| registry `OpportunityPolicy`, `DeploymentRegistry`, and `PinnedDeploymentRegistry` | strict decoded deployment input | Closed-schema decoding produces tooling data; exact digest verification produces the opaque pin capability. Only `PinnedDeploymentRegistry` implements the operational `RegistryVerifier`. |
| `JsonlLimits` | bounded offline runtime | Private accepted fields, typed failure, fixed ceilings, aggregate checks, a named profile, and canonical identity. |
| `HandoffConfig` | bounded live runtime | Private accepted fields, typed construction, named bounded profile, aggregate queue-byte check, and closed drop-newest policy. |
| `LiveLimits` | bounded live runtime | Private accepted fields, typed failure, hard maxima for payload bytes, retained replay streams, advance distance, aggregate work, and a canonical identity. |
| `MonitorLiveConfig` | bounded live runtime | Private accepted fields, named profile, relationship/deadline checks, and canonical identity. |
| `OperationalLiveConfig` | bounded live runtime | Private accepted fields, named profile, hard ingress ceiling, typed failure, and canonical identity. |
| secure foreign `ZenohConfig` admission | security configuration capability | A standalone strict-JSON file is read through an inclusive 256 KiB pre-parse cap; nested `__config__` includes are rejected; each credential file has an inclusive 1 MiB validation-time cap. Single-load validation returns opaque `SecureZenohCapability`; `CredentialMaterialKind` governs role-specific permission checks and the capability records a canonical security identity. |

### Named profiles

The required profile taxonomy is closed for 0.9.0:

- `ReleaseProfile::StandaloneAdvisoryV0_9` selects the shipped NIS/CUSUM and
  signed-correlation composition for an explicit modality set. PID is absent. The
  word `Release` identifies reproducible source-release behavior only; the profile
  remains uncalibrated and deployment qualification remains `NOT_CLAIMED`.
- `PidResearchProfile::CircularDeleteBlockV0_9` selects the current seeded
  observation-noise model and explicit circular delete-block confirmation.
- `PidResearchProfile::PointEstimateOnlyV0_9` is a separate, explicitly
  unconfirmed research profile. It is not an override on the release profile.
- `ScenarioResearchProfile::SyntheticV0_9` and
  `EvaluationResearchProfile::SyntheticV0_9` independently select bounded
  simulator and evaluation defaults. Evidence studies may use custom parameters,
  but must record the resulting accepted configuration rather than mislabel it as
  either profile.
- `JsonlProfile`, `HandoffProfile`, `LiveLimitsProfile`, `AssemblerProfile`,
  `MonitorLiveProfile`, and `OperationalLiveProfile` each select their own bounded
  0.9 runtime policy. A core `ReleaseProfile` does not silently select transport or
  adapter behavior.

The `StandaloneAdvisoryV0_9` statistical values are the current intended shipped
values and must be represented exactly: detector window `64`, minimum samples
`32`, minimum channels `2`, maximum sequence gap `1`, timestamp skew `1_000 ms`,
inter-sample gap `10_000 ms`, tracks `1_024`, `nis_alpha=0.01`,
`cusum_slack=3/sqrt(6)`, `cusum_threshold=15/sqrt(6)`, and
`jam_fraction=0.6`; correlation window `128`, minimum samples `64`,
`decouple_ratio=0.4`, `corr_floor=0.15`, and `family_alpha=0.01`. These numbers
are not calibrated field-performance claims.

The `CircularDeleteBlockV0_9` research profile must likewise identify all current
parameters: window `128`, minimum samples `64`, observation-noise standard
deviation `1e-4`, seed `1`, geometry `k=5`, `id_max=10`, `cv_min=0.01`,
`nn_ratio_max=0.999`, `decouple_ratio=0.4`, `mi_floor=0.03`, and confirmation
`CircularDeleteBlock { resamples: 100, block_size: 8, family_alpha: 0.10 }`.
The point-estimate profile shares only the parameters that actually apply and has
no dormant confirmation payload.

## Validation and cost contract

### Statistical components

- `DetectorConfig` construction must preserve the existing scalar domains and
  must check
  `max_tracks * Modality::ALL.len() * window_len <= 1_000_000` with checked
  arithmetic. Construction is `O(1)` time and `O(1)` retained memory.
- `CorrConfig` construction is `O(1)`/`O(1)`. An assessment preflight must check
  `pairs(channel_count) * min(input_tail, window) <= 1_000_000` before matrix
  allocation or pair evaluation. The active six-modality ceiling keeps exhaustive
  clique enumeration bounded; any modality-domain increase requires a new work
  review rather than inheriting this assumption.
- `PidConfig` construction is `O(1)`/`O(1)`. Its work estimate must include all
  mandatory pair, atom, and confirmation-edge scans and remain at or below
  `200_000_000` quadratic scan-equivalent fit units. Confirmation diversity,
  delete-block remainder, tail-rank resolvability, and `resamples <= window` are
  constructor invariants of the confirmation variant.
- Multi-axis derivation must divide family budgets once, validate the result, and
  create one immutable derived config shared by the axis loop. Axis count and the
  derived value are part of configuration identity.
- Lifecycle composition must check
  `max(window_len, corr.window) * max_tracks * Modality::ALL.len() <= 983_040`
  before retaining track history. Individual component validity does not imply
  this bundle invariant.

### Simulation and evaluation

- Scenario construction is `O(m)` for `m` modalities and may allocate only the
  accepted modality collection. It must validate `frames * m <= 1_000_000`, all
  timestamp arithmetic, unique modalities, and finite nondegenerate variances
  before stream allocation.
- Evaluation construction/preflight must use checked arithmetic for every grid,
  trial, prefix, pair, estimator, and output product. The existing suite ceilings
  of `100_000_000` generated observations, `100_000_000` latency-prefix visits,
  and `300_000_000_000` PID quadratic fit units are upper bounds, not targets.
- A maneuver-lag grid must contain 1..=10,000 unique values. Magnitude must be
  finite and positive with a finite square; duration must be nonzero. For the
  current visual/acoustic/radar study, every half-open maneuver window must satisfy
  `floor(frames/3) + 3 * lag_step + duration <= frames` with checked arithmetic.
  Per-study work also requires `trials * lag_count <= 50,000` and
  `trials * frames * 3 * lag_count <= 100,000,000` before generation.
- Evidence configuration conversion is `O(a+c)` for the bounded autocorrelation
  and covariance-scale lists and may retain only their owned bounded copies. It
  must preserve the existing ceilings of `25_000_000` generated observations,
  `500_000_000` correlation pair-samples, `2_000_000` trace assessments, and
  `50_000_000` bootstrap track draws.

### Runtime resources

- JSONL line, record, and aggregate-byte values must be checked together before
  allocating a reader/output buffer. A single record cannot exceed either its line
  limit or the aggregate limit. Release defaults remain `64 KiB`, `100_000`
  records, and `64 MiB` total.
- Every live payload, stream table, handoff, reorder table, assembler table, and
  raw operational queue must have both a nonzero configured bound and a fixed
  process ceiling. Products or sums representing simultaneous retention must be
  checked as aggregate budgets, not inferred from independent field maxima.
- Duration construction must reject zero, sub-millisecond values where the wire
  is millisecond-exact, invalid ordering, values above wire/runtime ceilings, and
  values that cannot be added to the monotonic start anchor.
- Validation of foreign transport configuration does not bound bytes already
  materialized by the transport. The release capability therefore also requires
  the documented Zenoh receive-size ceiling; application `LiveLimits` alone is
  insufficient.

## Closed choices and Boolean disposition

| Audited legacy choice | Implemented 0.9 disposition |
|---|---|
| `PidConfig.bootstrap` | Removed. `PidConfirmation::{PointEstimateOnly, CircularDeleteBlock(..)}` carries only applicable validated settings. |
| PID `joint_margin_interval(..., select_maximum)` | Replaced by exhaustive `JointBoundExtremum::{Minimum, Maximum}`. |
| secure credential `require_private_mode` | Replaced by `CredentialMaterialKind::{TrustAnchor, PublicCertificate, PrivateKey}`. |
| evidence CLI dirty override | Parsed once into `PublicationSourcePolicy::{RequireClean, PermitDirtyWithAudit}` and recorded in the manifest. |
| registry pin flag | Replaced by `DeploymentRegistry` versus opaque `PinnedDeploymentRegistry`; only the pinned type implements `RegistryVerifier`. |
| live/monitor-live bus ownership flag | Replaced by `BusOwnership::{Owned, HostOwned}` and ownership-specific construction/cleanup. |
| monitor identity selector | Replaced by `IdentityRole::{Session, Producer}`. |
| release versus optional PID | Separated into `ReleaseSuite` and `PidResearchSuite`; a Cargo feature exposes APIs but selects no research execution. |
| correlation/PID family budget per axis | Implemented as named fallible derivation returning a new immutable identity. |
| `color` presentation flag | May remain Boolean: it is an inherently binary display predicate with no scientific/security payload. |
| report/state facts (`ready`, `elevated`, `decoupled`, `degraded`, `dirty`, ownership cleanup facts) | Not configuration under this task. They may remain Boolean, subject to the result/state-machine contracts. |
| Zenoh fields that are required to equal literal true/false | May remain foreign-protocol Booleans at decode; Galadriel must expose only the validated secure-profile capability internally. |
| `TransportMode`, `HandoffOverflowPolicy`, `AdvisoryPolicy`, and `Authorization` | Preserved as named closed choices. |

## Rust API shape

An implementation may use a builder or raw params, but the accepted boundary must
have this shape:

```rust,ignore
pub struct DetectorConfig {
    // private, no interior mutability
}

#[derive(Debug, Clone)]
pub struct DetectorParams {
    // untrusted parameter fields; never accepted by Mirror
}

impl TryFrom<DetectorParams> for DetectorConfig {
    type Error = DetectorConfigError;

    fn try_from(params: DetectorParams) -> Result<Self, Self::Error> {
        // validate complete scalar, cross-field, and aggregate invariants first
        # unimplemented!()
    }
}

impl DetectorConfig {
    pub fn window_len(&self) -> usize { # unimplemented!() }
    pub fn max_tracks(&self) -> usize { # unimplemented!() }
    // remaining read-only getters
}
```

Small `Copy` accepted configs may return getters by value; owned collections must
return borrowed slices/strings. Builders may consume `self` or use `&mut self`, but
`build` must return a distinct accepted type. An accepted type must not expose a
builder conversion that loses which named profile seeded it without recording a
custom-profile identity.

Per-crate configuration errors should use closed `thiserror` enums with variants
for invalid field/domain, inconsistent fields, arithmetic overflow, resource/work
ceiling, unknown profile/schema, and unsupported research/release composition.
Errors should carry bounded typed facts rather than allocate an unbounded copy of
attacker-controlled configuration text.

## Implemented migration disposition

The 2026-07 audit found public accepted-config literals, delayed validation,
clone-and-mutate family adjustment, Boolean mode/capability choices, and unpinned
registry admission. The 0.9 implementation closes those source-level defects:

- raw `*Params` and strict file DTOs remain mutable only before acceptance;
- accepted configs and suites have private fields, typed fallible construction,
  read-only accessors, fixed/aggregate resource checks, and canonical identities;
- named profiles resolve through the same validation path as custom input;
- correlation and PID axis-family adjustment creates a new accepted identity;
- simulation, evaluation, and evidence execution retain accepted values rather
  than raw DTOs;
- assembler, JSONL, live, monitor-live, and operational-live policies have named
  bounded profiles and typed errors;
- registry admission uses `PinnedDeploymentRegistry` typestate, and secure Zenoh
  admission returns `SecureZenohCapability`; and
- semantic modes, roles, ownership, and privileged choices use closed types.

Compatibility conveniences that remain do not weaken the accepted boundary:
test-only `Default` implementations resolve named profiles; the evidence CLI's
`--allow-dirty` spelling is immediately converted to a closed source policy and is
recorded; protocol/report facts may remain Boolean; and raw parameter literals are
permitted in negative tests because they cannot enter runtime APIs directly.

## Mandatory verification

The final candidate must retain the following evidence; this document does not
substitute for those gates.

### Positive, negative, boundary, and adversarial tests

- One focused unit test per constructor error variant and per inclusive/exclusive
  boundary, including zero, maximum, maximum plus one, `NaN`, both infinities,
  subnormal probabilities, checked-product overflow, and invalid cross-field
  combinations.
- Positive tests for every named profile, proving exact getter values and stable
  profile identity; no test may establish validity by calling a public `validate`
  method on a freely constructed accepted type.
- Aggregate tests for detector/lifecycle retained state, correlation pair-samples,
  PID fit units and confirmation tail ranks, scenario observations/timestamps,
  evaluation grids/prefixes, JSONL bytes/records, queue sums/relationships, registry
  opportunity caps, and duration/clock-anchor arithmetic.
- Malformed schema tests for an unknown top-level field, unknown nested field,
  unknown profile/enum variant, duplicate key, missing required field, wrong
  version, out-of-range integer, and a valid raw document whose cross-field or
  aggregate validation fails.
- Adversarial tests proving rejection occurs before allocation/state mutation,
  subscription, estimator entry, or evidence-file creation.
- Regression tests proving the release and confirmed-PID research profile outputs
  remain bit-for-bit identical to approved vectors where semantics are unchanged.

### Compile-fail and API tests

Use an external-crate harness (for example `trybuild`) to prove that callers cannot:

- construct any accepted configuration with a struct literal;
- mutate a field or obtain mutable field access after construction;
- pass raw params/builders to `Mirror`, correlation, PID, lifecycle, JSONL, or live
  runtime entry points;
- configure PID with a Boolean or provide confirmation-only parameters to the
  point-estimate variant;
- pass a PID research-suite value where a release-suite value is required; or
- fabricate a validated registry/security/dirty-tree capability.

The positive external fixture must build every supported accepted config through
the documented profile/builder path. `cargo public-api` and a retained API scan
must show no public fields on accepted configs, no public unchecked constructors,
no `bootstrap: bool`, and no accidental public raw-param acceptance. The scan must
cover all workspace features and the separately rooted fuzz workspace.

### Property and fuzz tests

- Generate arbitrary raw parameter records and assert that every `Ok` value
  satisfies all documented local and aggregate invariants through getters.
- Assert builder setter order does not change the accepted value or canonical
  identity when the final parameters are equal.
- Assert every fallible derivation returns either a fully valid new value or a
  typed error and leaves the source value unchanged.
- Assert resource estimates are monotone over admitted positive bounds, except
  that checked overflow or a fixed ceiling produces an error.
- Assert profile resolution is deterministic and exact across repeated runs and
  supported targets.
- Fuzz strict decoded params, constructor boundaries, axis-family derivation, and
  aggregate preflights. Inputs that fail must not panic or perform unbounded work.

### Gates and retained evidence

At minimum run and retain complete results for formatting, all-target/all-feature
Clippy with warnings denied, workspace tests, doc tests, no-default core build,
fuzz-manifest check, bounded fuzz smoke, `cargo public-api`, schema/config tests,
and the release auditor. The exact candidate, toolchain, commands, vectors, API
diff, review, and residual risks must be bound in release evidence. Green
compilation without compile-fail, property, malformed-input, aggregate, and API-scan
coverage is insufficient.

No source-level public-mutable-accepted-config or Boolean capability blocker is
known in the audited 0.9 interfaces. That statement is deliberately narrower than
release qualification: an exact clean candidate still needs the retained gates
above, and platform timing, external transport enforcement, independent review,
field calibration, and NCP 1.0 compatibility remain outside this contract.

## Residual risks after implementation

Even complete conformance to this contract cannot establish statistical
calibration, sensor truth, malicious intent, transport authentication, or field
performance. Private Rust fields prevent accidental API bypass, not a modified
binary or privileged configuration substitution. Conservative work expressions
bound modeled operations but do not prove platform-specific latency or allocator
behavior. Strict schemas prevent silent semantic extension but do not authenticate
the file. Profile digests provide identity, not trust, until a deployment binds
them to signed artifacts and authenticated epochs. Research PID behavior remains
dependent on the exact pinned upstream implementation and its stated restricted
domain. Increasing the modality domain, estimator set, wire profile, or hard
resource ceilings requires a new aggregate analysis and compatibility review.
