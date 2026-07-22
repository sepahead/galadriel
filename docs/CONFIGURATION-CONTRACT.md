# Configuration construction and capability contract

## Abbreviations

| Short form | Meaning |
|---|---|
| APIs | application programming interfaces |
| CLI | command-line interface |
| CUSUM | cumulative sum |
| DTOs | data transfer objects |
| JSON | JavaScript Object Notation |
| JSONL | JavaScript Object Notation Lines |
| mTLS | mutual Transport Layer Security |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |

Status: **normative implemented contract** for Galadriel 0.9.0. The accepted
boundaries cover these surfaces:

- core and PID
- simulation
- evaluation and evidence
- NCP registry and assembler
- live input
- secure transport

This document defines source semantics. Final-candidate qualification and retained
release evidence are separate gates. The APIs do not imply that these gates are
complete.

An **accepted configuration** is a value that a component can retain or use. The
component can be a detector, generator, evaluator, adapter, transport, or runtime.

A **parameter value** is untrusted and possibly incomplete input. It has not
crossed the accepted boundary.

A source release profile is a reproducible set of shipped values. It is not field
calibration or deployment qualification. It does not permit an effect on control
authority.

## Normative requirements

**GLD-090-CFG-001 (validated construction):** Every accepted configuration
**SHALL** use a fallible construction or conversion boundary. This requirement
applies to statistical, simulation, evaluation, evidence, resource, deadline,
registry-policy, and live-input configurations.

The boundary **SHALL** validate every local invariant before it returns the
accepted type. A public `validate(&self)` method on a freely constructible value
does not meet this requirement.

**GLD-090-CFG-002 (immutable accepted values):** Every accepted configuration
**SHALL** have private fields. It **SHALL NOT** expose any of these interfaces:

- setters
- `&mut` field access
- interior mutability
- unchecked public constructors
- public struct-literal construction

After acceptance, code can borrow, move, or clone a value exactly. A semantic
change **SHALL** create a new accepted value through a fallible boundary. A
runtime **SHALL** retain only the accepted value. It never retains its mutable
builder or raw parameters.

**GLD-090-CFG-003 (raw parameters cannot confer validity):** Mutable builders and
public-field `*Params` or `*File` records MAY represent untrusted input. Their
names **SHALL** identify them as parameters, not configurations. They
**SHALL NOT** implement a marker or trait that detector or runtime entry points
accept.

Conversion to an accepted configuration **SHALL** use the complete parameter set.
It can consume or immutably borrow that set. It **SHALL** return
`Result<AcceptedConfig, TypedConfigError>`.

**GLD-090-CFG-004 (whole-value and aggregate validation):** Construction
**SHALL** validate all these properties:

- field ranges
- cross-field relationships
- finite floating-point domains
- checked integer arithmetic
- allocation ceilings
- conservative work ceilings

Composition boundaries **SHALL** repeat preflight checks for costs that depend on
multiple accepted values. Examples include:

- detector window and correlation window
- track and modality cardinality
- active projection axes
- estimator fits and bootstrap replicates
- queue relationships
- deadline order

The relevant preflight must finish before allocation, state change, subscription,
input read, estimator use, or worker creation.

**GLD-090-CFG-005 (fallible derivation):** Derived configurations **SHALL** use a
named fallible operation that returns a new accepted value. This applies to
family-budget adjustment, profile overrides, axis-count correction, and all other
derivations.

Code **SHALL NOT** clone an accepted configuration, change `family_alpha` or
another field, and then validate the change. A zero axis count, arithmetic error, or
unresolvable tail rank **SHALL** return a typed configuration error. The system
does not run a partial assessment.

**GLD-090-CFG-006 (explicit profiles):** User-facing and evidence-producing call
sites **SHALL** select a named and versioned profile. `Default::default()`
**SHALL NOT** silently select between release and research semantics.

Source compatibility can temporarily retain `Default`. In that case, tests and
documents **SHALL** identify it as an exact alias of one named profile. Release
and evidence code **SHALL NOT** call it. Profile resolution **SHALL** use the same
validation path as custom parameters.

**GLD-090-CFG-007 (strict decoded parameters):** JSON or other schemas **SHALL**
decode configuration into a raw parameter type. That type has a declared schema
or profile version.

The decoder **SHALL** reject these inputs:

- unknown fields
- unknown enum variants
- duplicate object keys
- missing required semantics

`serde(default)`, `#[serde(other)]`, flattened extension maps, and ignored fields
**SHALL NOT** supply scientific, security, resource, or authority semantics. The
decoded parameters **SHALL** use the native fallible accepted-configuration
boundary. An accepted configuration **SHALL NOT** derive `Deserialize` in a way
that bypasses validation.

**GLD-090-CFG-008 (typed failure):** Configuration rejection **SHALL** remain
distinct from these conditions:

- invalid observation input
- insufficient evidence
- anomaly evidence
- internal faults

Library constructors **SHALL** return a crate-owned typed error. They
**SHALL NOT** panic or use `unwrap` or `expect`. They **SHALL NOT** erase the
category into `String`, `io::Error`, `ZenohError`, or `anyhow::Error`. Binary
boundaries MAY add context after they preserve the typed source.

**GLD-090-CFG-009 (observable identity):** Reports and retained evidence
**SHALL** identify the named profile. They **SHALL** also contain a canonical
digest of the complete accepted configuration.

The digest preimage **SHALL** include research or release classification,
confirmation mode, resource ceilings, and axis-family derivation. Human-readable
`Debug` output is not a canonical identity.

These accepted boundaries expose canonical identities:

- core and PID
- simulator and evaluator
- evidence runner
- assembler and registry policy
- JSONL and live input
- secure configuration

A digest identifies accepted bytes and semantics. It does not authenticate them.

**GLD-090-CFG-010 (documented cost):** Each accepted configuration type and
composition constructor **SHALL** document three properties:

- construction complexity
- construction allocation
- worst-case retained-state or work expression

Ceilings **SHALL** use checked arithmetic and fixed product limits. Independent
factor validation is not sufficient.

**GLD-090-CAP-001 (no Boolean blindness):** A Boolean **SHALL NOT** configure a
mode, algorithm, policy, capability, lifecycle choice, ownership choice, security
exception, or parameterized behavior.

Such a choice **SHALL** use a closed enum or capability type. Each variant carries
only its applicable parameters. Match statements **SHALL** be exhaustive. The
decoder **SHALL** reject unknown serialized variants.

**GLD-090-CAP-002 (PID confirmation):** `PidConfig` **SHALL NOT** contain a
bootstrap-mode Boolean. A closed value represents confirmation:

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
newtypes. The point-estimate variant **SHALL NOT** contain `resamples`,
`block_size`, or confirmation `family_alpha`. Thus, ignored or contradictory
combinations cannot be represented.

The point-estimate variant **SHALL** remain explicitly research only. Its reports
**SHALL** identify the attribution as unconfirmed.

**GLD-090-CAP-003 (research capability separation):** The standalone release
suite **SHALL** contain NIS, CUSUM, and signed-correlation configurations. It
**SHALL NOT** contain an optional PID Boolean.

The Cargo feature exposes research APIs. It does not select them. A caller
**SHALL** construct an explicit `PidResearchProfile` or research-suite value
before PID work. This value **SHALL NOT** be interchangeable with the release
suite.

**GLD-090-CAP-004 (security and override choices):** Named enums or capabilities
**SHALL** represent these choices:

- registry-pin proof
- dirty-tree publication permission
- credential-file permission policy
- transport bus ownership
- identity-validation role
- joint bootstrap-bound extremum

Version 0.9 uses pinned-registry and secure-configuration typestates. It also uses
the closed choices below. Only the explicit CLI or policy boundary **SHALL**
create a privileged override capability. Evidence **SHALL** record it.

**GLD-090-CAP-005 (legitimate predicates):** A Boolean MAY represent an
observation or an inherently binary display predicate without dependent
parameters. Examples are `dirty`, `degraded`, `decoupled`, `ready`, and terminal
color rendering.

A fixed foreign-protocol assertion MAY also use a Boolean. For example, a foreign
protocol can require mTLS to equal true. Such a Boolean **SHALL NOT** become an internal
Galadriel mode type. This exception does not permit a Boolean to hide future
semantic states.

**GLD-090-CAP-006 (declared modality capability):** A release detector suite
**SHALL** contain a validated and nonempty expected-modality set. Its cardinality
must be compatible with `min_channels`.

The empty-vector sentinel in exploratory `Mirror::new` **SHALL NOT** select
release behavior. Subset-only exploratory assessment MAY remain available through
an explicit research capability or constructor. Its type or value **SHALL NOT**
be interchangeable with a release suite that can report cross-sensor nominal
evidence.

## Required type and profile boundaries

This table lists implemented 0.9 boundaries. Public parameter records
remain mutable and untrusted. Only the private accepted type can cross the related
runtime boundary.

| Accepted type or boundary | Classification | Implemented 0.9 boundary |
|---|---|---|
| `DetectorConfig` | release statistical component | Private accepted fields. `DetectorParams` crosses `try_new` or `TryFrom`. The type has read-only getters, named profile resolution, aggregate state budgets, and a canonical identity. |
| `CorrConfig` | release statistical component | Private accepted fields and typed construction. `try_for_axis_family(axis_count)` returns a new identity-bound configuration without mutation. |
| `PidConfig` | optional research statistical component | Private accepted fields and explicit research profiles. It uses closed `PidConfirmation` and fallible family derivation. It has no mode Boolean or dormant confirmation payload. |
| `Cusum` and `NisWindow` construction | validated detector subcomponents and state | Private fields and fallible construction. Release use derives values from accepted detector configuration. Direct public construction remains component-research use. CUSUM construction is `O(1)`. Window reservation is `O(capacity)`. Each window has a fixed 272-byte exact-sum cache. |
| upstream PID estimator configs (`IntrinsicDimConfig`, `DistanceConcentrationConfig`, `KsgConfig`, `Pid2Config`, `Jitter`) | pinned foreign research subcomponents | Derive one exact documented set from accepted PID research configuration. An upstream `Default` must not silently change a named profile. Include upstream semantics and revision in profile identity. |
| `ReleaseSuite` | release composition | Distinct PID-free accepted type. It contains detector, correlation, canonical nonempty modalities, and axis-family policy. Construction checks readiness, retained state, and work. |
| `PidResearchSuite` | research composition | Distinct accepted type with a release suite and explicit PID research configuration. Construction checks maximum three-axis confirmation work before analysis. |
| `ScenarioConfig` | research generator | Mutable `ScenarioParams` converts once to immutable `ScenarioConfig`. Accessors borrow accepted values. Construction validates modalities, identities, timestamps, variances, observation count, and canonical digest. |
| `EvalConfig` or `EvalSuiteConfig` | research evaluation | Mutable parameters convert to immutable accepted values. Named profiles and aggregate suite construction check grids, latency prefixes, observations, bootstrap comparisons, and PID work. |
| evidence runner DTOs and `ValidatedEvidenceConfig` | evidence and research input | Strict file DTOs convert once to an immutable accepted value. It contains a `ReleaseSuite`, bounded vectors, a hash-verified fixture, work estimates, and canonical digest. The runner does not retain the DTO. |
| `AssemblerLimits` | operational runtime resource and deadline policy | Private fields, `AssemblerParams`, and `AssemblerProfile::BoundedV0_9`. It has read-only getters, hard and aggregate bounds, deadline order, clock checks, and canonical identity. |
| `RegistryOpportunityPolicy` | deployment-pinned capability | Private accepted fields and typed construction with wire maxima. `RegistryVerifier` alone produces this validated policy. |
| registry `OpportunityPolicy`, `DeploymentRegistry`, and `PinnedDeploymentRegistry` | strict decoded deployment input | Closed-schema decoding produces tooling data. Exact digest verification produces the opaque pin capability. Only `PinnedDeploymentRegistry` implements operational `RegistryVerifier`. |
| `JsonlLimits` | bounded offline runtime | Private accepted fields, typed failure, fixed ceilings, aggregate checks, named profile, and canonical identity. |
| `HandoffConfig` | bounded live runtime | Private accepted fields, typed construction, named bounded profile, aggregate queue-byte check, and closed drop-newest policy. |
| `LiveLimits` | bounded live runtime | Private accepted fields, typed failure, and canonical identity. Hard limits cover payload bytes, replay streams, advance distance, and aggregate work. |
| `MonitorLiveConfig` | bounded live runtime | Private accepted fields, named profile, relationship and deadline checks, and canonical identity. |
| `OperationalLiveConfig` | bounded live runtime | Private accepted fields, named profile, hard input ceiling, typed failure, and canonical identity. |
| secure foreign `ZenohConfig` admission | security configuration capability | Read a standalone strict-JSON file through an inclusive 256 KiB pre-parse limit. Reject nested `__config__` includes. Each credential file has an inclusive 1 MiB validation limit. Single-load validation returns opaque `SecureZenohCapability`. `CredentialMaterialKind` controls role-specific permission checks. The capability records canonical security identity. |

Each detector aggregate includes every window's fixed 272-byte exact-sum cache.

### Named profiles

The required profile taxonomy is closed for 0.9.0:

- `ReleaseProfile::StandaloneAdvisoryV0_9` selects shipped NIS, CUSUM, and
  signed-correlation behavior for an explicit modality set. PID is absent. The
  word `Release` means reproducible source-release behavior only. The profile is
  uncalibrated. Deployment qualification remains `NOT_CLAIMED`.
- `PidResearchProfile::CircularDeleteBlockV0_9` selects the current seeded
  observation-noise model and circular delete-block confirmation.
- `PidResearchProfile::PointEstimateOnlyV0_9` is a separate unconfirmed research
  profile. It is not an override on the release profile.
- `ScenarioResearchProfile::SyntheticV0_9` selects bounded simulator defaults.
- `EvaluationResearchProfile::SyntheticV0_9` independently selects bounded
  evaluation defaults.
- Evidence studies can use custom parameters. They must record the accepted
  configuration. They must not label it as either named synthetic profile.
- `JsonlProfile`, `HandoffProfile`, `LiveLimitsProfile`, `AssemblerProfile`,
  `MonitorLiveProfile`, and `OperationalLiveProfile` select separate bounded 0.9
  runtime policies.
- A core `ReleaseProfile` does not silently select transport or adapter behavior.

`StandaloneAdvisoryV0_9` uses these exact values:

- detector window `64`
- minimum samples `32`
- minimum channels `2`
- maximum sequence gap `1`
- timestamp skew `1_000 ms`
- inter-sample gap `10_000 ms`
- tracks `1_024`
- `nis_alpha=0.01`
- `cusum_slack=3/sqrt(6)`
- `cusum_threshold=15/sqrt(6)`
- `jam_fraction=0.6`
- correlation window `128`
- correlation minimum samples `64`
- `decouple_ratio=0.4`
- `corr_floor=0.15`
- `family_alpha=0.01`

These values do not make calibrated field-performance claims.

`CircularDeleteBlockV0_9` identifies these exact parameters:

- window `128`
- minimum samples `64`
- observation-noise standard deviation `1e-4`
- seed `1`
- geometry `k=5`
- `id_max=10`
- `cv_min=0.01`
- `nn_ratio_max=0.999`
- `decouple_ratio=0.4`
- `mi_floor=0.03`
- confirmation
  `CircularDeleteBlock { resamples: 100, block_size: 8, family_alpha: 0.10 }`

The point-estimate profile shares only applicable parameters. It has no dormant
confirmation payload.

## Validation and cost contract

### Statistical components

- `DetectorConfig` construction must preserve the existing scalar domains. It
  must check
  `max_tracks * Modality::ALL.len() * window_len <= 1_000_000` with checked
  arithmetic. Construction takes `O(1)` time and `O(1)` retained memory.
- `CorrConfig` construction takes `O(1)` time and `O(1)` memory. Assessment preflight
  must check
  `pairs(channel_count) * min(input_tail, window) <= 1_000_000`. Complete this
  check before matrix allocation or pair evaluation.
- The active six-modality limit bounds exhaustive clique enumeration. A larger
  modality domain needs a new work review.
- `PidConfig` construction takes `O(1)` time and `O(1)` memory. Its estimate includes all
  required pair, atom, and confirmation-edge scans. It must not exceed
  `200_000_000` quadratic scan-equivalent fit units.
- The confirmation variant constructor checks confirmation diversity,
  delete-block remainder, tail-rank resolution, and `resamples <= window`.
- Multi-axis derivation divides family budgets once and validates the result. It
  creates one immutable derived config for the axis loop. Axis count and the
  derived value form part of configuration identity.
- Lifecycle composition must check
  `max(window_len, corr.window) * max_tracks * Modality::ALL.len() <= 983_040`.
  Complete this check before retaining track history. Valid components do not
  automatically make the bundle valid.

### Simulation and evaluation

- Scenario construction is `O(m)` for `m` modalities. It can allocate only the
  accepted modality collection.
- Before stream allocation, validate `frames * m <= 1_000_000`. Also validate all
  timestamp arithmetic, unique modalities, and finite nondegenerate variances.
- Evaluation construction and preflight use checked arithmetic for each grid,
  trial, prefix, pair, estimator, and output product.
- Existing suite ceilings are upper limits, not targets. They are `100_000_000`
  generated observations, `100_000_000` latency-prefix visits, and
  `300_000_000_000` PID quadratic fit units.
- A maneuver-lag grid contains `1..=10,000` unique values.
- Magnitude is finite and positive, with a finite square.
- Evaluation duration is at least two frames. Thus, the sampled half-open
  triangle has nonzero exposure.
- The low-level simulator retains duration zero only as an explicit disabled or
  no-operation form.
- For the visual, acoustic, and radar study, every half-open window satisfies
  `floor(frames/3) + 3 * lag_step + duration <= frames` with checked arithmetic.
- Per-study preflight also requires `trials * lag_count <= 50,000` and
  `trials * frames * 3 * lag_count <= 100,000,000`.
- Evidence configuration conversion is `O(a+c)` for bounded autocorrelation and
  covariance-scale lists. It can retain only bounded owned copies.
- Evidence checks keep these ceilings: `25_000_000` generated observations,
  `500_000_000` correlation pair-samples, `2_000_000` trace assessments, and
  `50_000_000` bootstrap track draws.

### Runtime resources

- Check JSONL line, record, and aggregate-byte values together before buffer
  allocation. A record cannot exceed its line limit or aggregate limit. Release
  defaults are `64 KiB`, `100_000` records, and `64 MiB` total.
- Every payload and state table needs a nonzero configured limit and fixed process
  ceiling. This applies to live payloads, replay streams, handoffs, reorder tables,
  assembler tables, and raw operational queues.
- Check products and sums that describe simultaneous retention as aggregate
  budgets. Do not infer them from separate field maxima.
- Duration construction rejects zero and sub-millisecond values when the wire is
  millisecond-exact. It rejects invalid order and values above wire or runtime
  ceilings. It also rejects a value that cannot be added to the monotonic start
  anchor.
- Validation of foreign transport configuration does not bound bytes that the
  transport already materialized. The release capability also requires the
  documented Zenoh receive-size ceiling. Application `LiveLimits` alone is not
  sufficient.

## Closed choices and Boolean disposition

| Audited legacy choice | Implemented 0.9 disposition |
|---|---|
| `PidConfig.bootstrap` | Removed. `PidConfirmation::{PointEstimateOnly, CircularDeleteBlock(..)}` contains only applicable validated settings. |
| PID `joint_margin_interval(..., select_maximum)` | Replaced by exhaustive `JointBoundExtremum::{Minimum, Maximum}`. |
| secure credential `require_private_mode` | Replaced by `CredentialMaterialKind::{TrustAnchor, PublicCertificate, PrivateKey}`. |
| evidence CLI dirty override | Parsed once into `PublicationSourcePolicy::{RequireClean, PermitDirtyWithAudit}` and recorded in the manifest. |
| registry pin flag | Replaced by `DeploymentRegistry` and opaque `PinnedDeploymentRegistry`. Only the pinned type implements `RegistryVerifier`. |
| live and monitor-live bus ownership flag | Replaced by `BusOwnership::{Owned, HostOwned}` and ownership-specific construction and cleanup. |
| monitor identity selector | Replaced by `IdentityRole::{Session, Producer}`. |
| release versus optional PID | Separated into `ReleaseSuite` and `PidResearchSuite`. A Cargo feature exposes APIs but selects no research execution. |
| correlation and PID family budget per axis | Implemented as a named fallible derivation that returns a new immutable identity. |
| `color` presentation flag | Can remain Boolean. It is an inherently binary display predicate without scientific or security data. |
| report and state facts | `ready`, `elevated`, `decoupled`, `degraded`, `dirty`, and ownership cleanup facts are not configuration. They can remain Boolean under result and state contracts. |
| Zenoh fields that must equal literal true or false | Can remain foreign-protocol Booleans at decode. Galadriel exposes only the validated secure-profile capability internally. |
| `TransportMode`, `HandoffOverflowPolicy`, `AdvisoryPolicy`, and `Authorization` | Preserved as named closed choices. |

## Rust API shape

An implementation can use a builder or raw parameters. The accepted boundary has
this shape:

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

Small `Copy` accepted configs can return getters by value. Owned collections must
return borrowed slices or strings. Builders can consume `self` or use `&mut self`.
Their `build` operation must return a distinct accepted type.

An accepted type must not have a builder conversion that loses its profile
source. A conversion can preserve it by recording a custom-profile identity.

Each crate should use a closed `thiserror` enum for configuration errors. Variants
should cover these conditions:

- invalid field or domain
- inconsistent fields
- arithmetic overflow
- resource or work ceiling
- unknown profile or schema
- unsupported research and release composition

Errors should contain bounded typed facts. They should not allocate an unbounded
copy of attacker-controlled configuration text.

## Implemented migration disposition

The 2026-07 audit found these defects:

- public accepted-configuration literals
- delayed validation
- clone-and-change family adjustment
- Boolean mode and capability choices
- unpinned registry admission

The 0.9 implementation closes these source-level defects:

- Raw `*Params` and strict file DTOs remain mutable only before acceptance.
- Accepted configs and suites have private fields and typed fallible construction.
- They have read-only accessors, fixed and aggregate checks, and canonical
  identities.
- Named profiles use the same validation path as custom input.
- Correlation and PID axis-family adjustment creates a new accepted identity.
- Simulation, evaluation, and evidence code retains accepted values, not raw DTOs.
- Assembler, JSONL, live, monitor-live, and operational-live policies have named
  bounded profiles and typed errors.
- Registry admission uses `PinnedDeploymentRegistry` typestate.
- Secure Zenoh admission returns `SecureZenohCapability`.
- Semantic modes, roles, ownership, and privileged choices use closed types.

Remaining compatibility interfaces do not weaken the accepted boundary:

- Test-only `Default` implementations resolve named profiles.
- The evidence CLI converts `--allow-dirty` immediately to a closed source policy
  and records it.
- Protocol and report facts can remain Boolean.
- Negative tests can use raw parameter literals because runtime APIs reject them.

## Mandatory verification

The final candidate must retain this evidence. This document does not
replace these gates.

### Positive, negative, boundary, and adversarial tests

- Add one focused unit test for each constructor error variant. Test each
  inclusive and exclusive boundary.
- Include zero, maximum, maximum plus one, `NaN`, both infinities, subnormal
  probabilities, product overflow, and invalid field combinations.
- Test every named profile. Prove exact getter values and stable profile identity.
- Do not establish validity with public `validate` on a freely constructed
  accepted type.
- Test aggregate detector and lifecycle state, correlation pair-samples, PID fit
  units, and confirmation tail ranks.
- Test scenario observations and timestamps, evaluation grids and prefixes, JSONL
  limits, queue relationships, and registry opportunity limits.
- Test duration and clock-anchor arithmetic.
- Test unknown top-level and nested fields, unknown profiles and enum variants,
  duplicate keys, missing fields, and wrong versions.
- Test an out-of-range integer and a structurally valid document that fails an
  aggregate or cross-field check.
- Prove that rejection occurs before allocation, state change, subscription,
  estimator use, or evidence-file creation.
- Prove bit-for-bit equality with approved vectors for unchanged release and
  confirmed-PID semantics.

### Compile-fail and API tests

Use an external-crate harness, such as `trybuild`. Prove that callers cannot:

- construct an accepted configuration with a struct literal
- change a field or get mutable field access after construction
- pass raw parameters or builders to `Mirror`, correlation, PID, lifecycle,
  JSONL, or live runtime entry points
- configure PID with a Boolean
- give confirmation-only values to the point-estimate variant
- pass a PID research suite where a release suite is required
- create a validated registry, security, or dirty-tree capability

The positive external fixture must build every supported accepted configuration
through its documented profile or builder path.

`cargo public-api` and a retained API scan must show these properties:

- no public fields on accepted configurations
- no public unchecked constructors
- no `bootstrap: bool`
- no accidental acceptance of raw parameters

The scan must cover all workspace features and the separate fuzz workspace.

### Property and fuzz tests

- Generate raw parameter records. Verify that every `Ok` value satisfies all
  documented local and aggregate invariants through getters.
- Verify that builder setter order does not change the accepted value or identity
  when final parameters match.
- Verify that each derivation returns a valid new value or typed error. The source
  value must remain unchanged.
- Verify that resource estimates are monotonic over admitted positive bounds.
  Checked overflow or a fixed ceiling can produce an error.
- Verify deterministic and exact profile resolution across repeated runs and
  supported targets.
- Fuzz strict parameters, constructor boundaries, axis derivation, and aggregate
  preflight. Rejected inputs must not panic or cause unbounded work.

### Gates and retained evidence

Retain complete results for at least these gates:

- formatting
- all-target and all-feature Clippy with warnings denied
- workspace tests
- documentation tests
- no-default core build
- fuzz-manifest check
- bounded fuzz smoke
- `cargo public-api`
- schema and configuration tests
- release auditor

Bind the exact candidate, toolchain, commands, vectors, API diff, review, and
residual risks in release evidence. Green compilation alone is not sufficient.
The evidence must include compile-fail, property, malformed-input, aggregate, and
API-scan coverage.

No audited 0.9 interface has a known source-level blocker for public mutable
accepted configuration or Boolean capabilities. This statement is narrower than
release qualification.

An exact clean candidate still needs the retained gates. These items remain
outside this contract:

- platform timing
- external transport enforcement
- independent review
- field calibration
- NCP 1.0 compatibility

## Residual risks after implementation

Conformance to this contract does not establish statistical calibration, sensor
truth, malicious intent, transport authentication, or field performance.

Private Rust fields prevent accidental API bypass. They do not stop a modified
binary or privileged configuration replacement. Conservative work formulas bound
modeled operations. They do not prove platform latency or allocator behavior.

Strict schemas prevent silent semantic extension. They do not authenticate a
file. Profile digests identify configuration, not trust. Trust needs signed artifacts
and authenticated epochs.

Research PID behavior depends on the exact pinned upstream implementation and its
restricted domain. A change to these items needs a new aggregate analysis and
compatibility review:

- modality domain
- estimator set
- wire profile
- hard resource ceilings
