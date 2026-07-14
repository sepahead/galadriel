# Configuration construction and capability contract

Status: **normative target; implementation OPEN** for Galadriel 0.9.0 tasks
T012 and T013. This document deliberately does not claim that the current Rust
API conforms. The audited implementation gaps are listed below and remain release
blockers until code, tests, retained evidence, and the requirement ledger agree.

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
Canonical serialization and digest mechanics are completed under T017; their
absence does not weaken the construction rules here.

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

**GLD-090-CAP-002 (PID confirmation):** `PidConfig::bootstrap: bool` **SHALL** be
removed. Confirmation **SHALL** be represented by a closed value equivalent to:

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
selection **SHALL** use named enums/capabilities rather than
`deployment_pin_verified`, `allow_dirty`, `require_private_mode`, `owns_bus`,
`session`, or `select_maximum` Boolean parameters. A privileged override
capability **SHALL** be created only at the explicit CLI/policy boundary and
**SHALL** be recorded in evidence.

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

All entries in this table are in scope. “Required target” describes the interface
that must exist before T012/T013 can be complete; it is not a claim about the
current code.

| Accepted type or boundary | Classification | Required target |
|---|---|---|
| `DetectorConfig` | release statistical component | Private fields; `TryFrom<DetectorParams>` or a fallible builder; scalar getters; no setters; fallible profile resolution. |
| `CorrConfig` | release statistical component | Same pattern; provide a named `try_for_axis_family(axis_count)` derivation instead of `family_alpha` mutation. |
| `PidConfig` | optional research statistical component | Private fields; research-only builder/profile; `PidConfirmation` enum; getters; fallible family derivation; no `bootstrap` Boolean. |
| `Cusum` and `NisWindow` construction | validated detector subcomponents/state | Preserve private fields and fallible construction. The release path derives their parameters only from an accepted `DetectorConfig`; direct public construction is explicitly component-research use. Document `O(1)` CUSUM construction and `O(capacity)` window reservation. |
| upstream PID estimator configs (`IntrinsicDimConfig`, `DistanceConcentrationConfig`, `KsgConfig`, `Pid2Config`, `Jitter`) | pinned foreign research subcomponents | Derive one exact, documented set from the accepted PID research config. Do not let an upstream `Default` silently change a named Galadriel profile; include the selected upstream semantics and revision in profile identity. |
| release detector-suite configuration | release composition | A distinct accepted type containing detector, correlation, expected modalities, and axis/family policy; validate combined readiness, retained state, and family budgets; PID is absent. |
| PID research-suite configuration | research composition | A distinct accepted type containing the release components plus explicit PID research configuration; validate total multi-axis/bootstrap work before analysis. |
| `ScenarioConfig` | research generator | Rename freely mutable input to `ScenarioParams`; construct immutable `ScenarioConfig` fallibly; expose `modalities()` as a slice; validate unique bounded modalities, timestamps, and total observations. |
| `EvalConfig` | research evaluation | Raw params plus immutable accepted value; named research profile; preflight full grid, latency, observation, and PID work before trials. |
| evidence runner configuration (`EvidenceConfig`, `DetectorConfigFile`, `CorrConfigFile`, `RecordedFixtureConfig`) | evidence/research input | Keep strict file DTOs explicitly raw; convert once to an immutable `ValidatedEvidenceConfig` containing accepted detector/correlation configs and a verified fixture reference. The runner must not retain or mutate the DTO. |
| `AssemblerLimits` | operational runtime resource/deadline policy | Private fields; fallible builder/profile; getters; validate all fixed limits, exact-millisecond durations, deadline ordering, clock representability, and combined buffer policy before subscription. |
| `RegistryOpportunityPolicy` | deployment-pinned capability | Private fields; typed fallible construction with fixed maxima; a `RegistryVerifier` returns only this validated capability. Tests and third-party verifier implementations cannot use literals. |
| registry `OpportunityPolicy` and `DeploymentRegistry` | strict decoded deployment input | Continue closed-schema decoding, but split unpinned tooling output from a `PinnedDeploymentRegistry` capability; only the pinned type implements `RegistryVerifier`. Expose only a validated opportunity capability to assembly. Unknown fields/variants remain errors. |
| `JsonlLimits` | bounded offline runtime | Retain private fields/fallible construction; use a typed config error; add fixed release ceilings and checked aggregate relationships; select a named profile rather than an implicit default in release paths. |
| `HandoffConfig` | bounded live runtime | Retain private fields/fallible construction; select a named profile in production paths; preserve the closed `HandoffOverflowPolicy`. |
| `LiveLimits` | bounded live runtime | Retain private fields/fallible construction; add hard maxima for payload bytes, retained streams, and advance distance; return a typed config error rather than `ZenohError`. |
| `MonitorLiveConfig` | bounded live runtime | Retain private fields and fallible derivation; preserve handoff/reorder relationship checks and deadline ceilings; select a named runtime profile. |
| `OperationalLiveConfig` | bounded live runtime | Retain private fields/fallible construction and hard ingress ceiling; select a named runtime profile. |
| secure foreign `ZenohConfig` admission | security configuration capability | Parse once, validate the complete closed Galadriel profile, then return a wrapper/capability proving local validation of that exact value. Credential material kind replaces the private-mode Boolean. |

### Named profiles

The required profile taxonomy is closed for 0.9.0:

- `ReleaseProfile::StandaloneAdvisoryV0_9` selects the shipped NIS/CUSUM,
  signed-correlation, JSONL, and bounded operational defaults. PID is absent. The
  word `Release` identifies reproducible source-release behavior only; the profile
  remains uncalibrated and deployment qualification remains `NOT_CLAIMED`.
- `PidResearchProfile::CircularDeleteBlockV0_9` selects the current seeded
  observation-noise model and explicit circular delete-block confirmation.
- `PidResearchProfile::PointEstimateOnlyV0_9` is a separate, explicitly
  unconfirmed research profile. It is not an override on the release profile.
- `EvaluationResearchProfile::SyntheticV0_9` selects the bounded simulator and
  evaluation defaults. Evidence studies may use custom parameters, but must record
  the resulting accepted configuration rather than mislabel it as this profile.

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
  `max(window_len, corr.window) * max_tracks * Modality::ALL.len() <= 1_000_000`
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

| Current Boolean or choice | Required disposition |
|---|---|
| `PidConfig.bootstrap` | Replace with `PidConfirmation::{PointEstimateOnly, CircularDeleteBlock { .. }}`; delete dormant top-level confirmation fields. |
| PID `joint_margin_interval(..., select_maximum)` | Replace with an exhaustive `JointBoundExtremum::{Minimum, Maximum}` parameter. |
| secure credential `require_private_mode` | Replace with a closed credential-material/permission policy such as `CredentialMaterialKind::{TrustAnchor, ClientCertificate, PrivateKey}`. |
| evidence CLI `allow_dirty` | Convert immediately to `PublicationSourcePolicy::{RequireClean, PermitDirtyWithAudit}` or a minted override capability; record its use. |
| registry `deployment_pin_verified` | Replace with unpinned/pinned registry types; verifying a digest consumes/borrows the unpinned value and returns a `PinnedDeploymentRegistry`; only the pinned capability crosses the operational verifier boundary. |
| live/monitor-live `owns_bus` | Replace the Boolean constructor argument/state choice with `BusOwnership::{TapOwned, HostOwned}` or distinct constructors/owner wrappers whose cleanup behavior is exhaustive. |
| monitor identity `session: bool` | Replace with `IdentityRole::{Session, Producer}` so the error category cannot be inverted at a call site. |
| release versus optional PID | Separate release/research suite types and explicit research profile; a feature flag is availability, not selection. |
| correlation/PID family budget per axis | Named fallible derivation, not clone-and-mutate. |
| `color` presentation flag | May remain Boolean: it is an inherently binary display predicate with no scientific/security payload. |
| report/state facts (`ready`, `elevated`, `decoupled`, `degraded`, `dirty`, ownership cleanup facts) | Not configuration under this task. They may remain Boolean, subject to the result/state-machine contracts. |
| Zenoh fields that are required to equal literal true/false | May remain foreign-protocol Booleans at decode; Galadriel must expose only the validated secure-profile capability internally. |
| existing `TransportMode`, `HandoffOverflowPolicy`, `AdvisoryPolicy`, and `Authorization` | Preserve as named closed choices; do not regress them to Boolean flags. |

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

## Migration matrix from the audited tree

The locations below were inspected on 2026-07-14. Line numbers are intentionally
omitted because concurrent phase work may move them; the named functions/tests and
files are the migration anchors. “Literal” excludes the type definition and impl
headers.

| Type / pattern | Audited construction and mutation sites | Required migration |
|---|---|---|
| `DetectorConfig` (15 literals) | `galadriel-eval/src/evidence_main.rs`; eval detector bench; core config and decision tests; NCP lifecycle tests. Fuzzing mutates three temporal fields. Defaults are used throughout CLI, core fusion/decision, eval, PID fusion, lifecycle, and the detector fuzzer. | Convert file DTO/builder/profile through `TryFrom`; replace literals and mutation tests with raw params/builder cases; use getters; select the release profile explicitly in production/evidence paths. |
| `CorrConfig` (12 literals) | Evidence DTO conversion; core fusion and correlation tests; eval bench; PID fusion tests; NCP lifecycle tests. `family_alpha` is cloned and mutated in core fusion, PID fusion, CLI replay, and the evidence runner. | Convert literals to builder/params; replace all four mutations with the fallible axis-family derivation; use getters. |
| `PidConfig` (12 literals) | Eval bench; PID engine tests; PID fusion tests. Engine tests repeatedly mutate window, sample, confirmation, and family fields. Defaults are used by CLI/eval/research helpers. | Introduce research profiles and `PidConfirmation`; migrate invalid cases to params/builder tests; replace field reads with getters and family mutation with derivation. |
| detector subcomponent constructors | `Cusum::new` is called by channel-state construction and CUSUM tests; `NisWindow::new` is called by channel-state construction, baseline helpers, and window tests. | Keep their fallible boundaries; ensure release construction is downstream of suite preflight and errors remain typed. Direct component tests remain valid and must cover allocation failure/bounds. |
| foreign PID config constructors/defaults | PID analysis uses intrinsic-dimension and concentration defaults, regular-full-dimensional KSG/PID2 constructors, and seeded `Jitter::new`. | Centralize them in the named PID research-profile derivation or assert exact getters/provenance; remove scattered upstream-default selection from analysis code. |
| `ScenarioConfig` (30 literals) | CLI demo/replay helpers; simulator scenario and injection tests; eval scenario builder/bench; PID engine/fusion tests. | Rename literal-friendly input to `ScenarioParams` or use a builder; fallibly build the immutable accepted scenario; replace `modalities` ownership reads with slice getters. |
| `EvalConfig` (14 literals) | Eval binary and eval-library tests/studies. | Use a named research profile plus fallible overrides; preserve whole-suite preflight in the accepted construction/composition path. |
| evidence DTOs (one complete test literal plus JSON decode) | `evidence_main::tiny_config`, malformed/config-bound tests, `serde_json::from_slice`. Some tests mutate nested raw fields after creation. | DTO mutation may remain only as pre-validation test setup; production converts once to `ValidatedEvidenceConfig` and uses only that immutable value. |
| `AssemblerLimits` (19 literals) | Assembler unit/adversarial/boundary tests and operational Zenoh E2E helper. Validation is deferred to `CrossRouteAssembler::new`. | Private fields and fallible builder/profile; migrate negative literals to raw params; expose getters; preserve composition/clock-anchor validation before subscriptions. |
| `RegistryOpportunityPolicy` (11 literals) | Registry adapter, CLI/test verifiers, assembler tests, monitor-live test verifier, operational E2E verifier. | Private validated capability with constructor/getters; make the verifier trait return only this type; migrate policy-boundary tests through raw params. |
| `JsonlLimits` | No external literals; constructor/default uses occur in NCP JSONL code/tests and `ncp_decode` fuzzing. | Preserve fallible API but use typed error and fixed ceilings; explicit release profile in normal paths; fuzz raw params at all boundaries. |
| `HandoffConfig` / `LiveLimits` | No field literals; live code/tests/E2E use constructors/defaults. | Select named runtime profile; add `LiveLimits` hard maxima and typed error; retain immutable getters. |
| `MonitorLiveConfig` / `OperationalLiveConfig` | No field literals; live constructors, derivation, unit tests, and Zenoh E2E use validated APIs/defaults. | Preserve the validated shape; replace implicit production defaults with named runtime profile; keep fallible deadline derivation. |
| Boolean helper/capability choices | PID joint-bound helpers, secure credential tuple, evidence CLI arguments, monitor identity validation, registry pin state, and sidecar/monitor bus ownership. | Replace with the closed types in GLD-090-CAP-004; update exhaustive-match and cleanup tests. |
| Module-internal `Self { .. }` and `Default` bodies | Detector, correlation, PID, scenario, evaluation, assembler, JSONL, handoff, live, monitor-live, and operational-live modules materialize values internally. | Funnel accepted values through one private checked materialization path per type. A named profile may supply params, but must not maintain a second unchecked literal path. |

Migration must include every public field read, not just literals. In particular,
the evidence runner, CLI, evaluation cost model, PID evidence builder, fusion
layers, lifecycle retention preflight, tests, benches, fuzz targets, and rustdoc
examples currently read fields directly. They must use getters or accepted
composition methods so making fields private does not lead to a parallel unchecked
representation.

## Mandatory verification

T012 and T013 remain OPEN until all of the following evidence exists.

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
and the release auditor. The T012/T013 ledger entries must name the exact commit,
toolchain, commands, vectors, API diff, review, and residual risks. Green
compilation without the compile-fail, property, malformed-input, aggregate, and
API-scan evidence is insufficient.

## Current implementation blockers

The following findings are present in the audited tree; therefore this document
does not assert conformance:

1. `DetectorConfig`, `CorrConfig`, and `PidConfig` have public fields, public
   literals, public post-construction mutation, and a separate optional
   `validate()` call. Invalid values can exist as those accepted-looking types.
2. `ScenarioConfig` and `EvalConfig` have the same public-field/literal pattern.
   Their generators/runners validate at use, not at type construction.
3. `AssemblerLimits` and `RegistryOpportunityPolicy` have public fields.
   Assembler validation is deferred to `CrossRouteAssembler::new`, and verifier
   implementations can fabricate opportunity policies without a policy
   constructor.
4. `PidConfig::bootstrap` permits meaningless combinations: confirmation fields
   remain present when disabled, while enabled mode gains additional invariants.
5. Core fusion, PID fusion, CLI replay, and the evidence runner clone a
   correlation/PID config and mutate `family_alpha` for axes before later
   validation.
6. Detector, correlation, PID, scenario, evaluation, and several runtime paths
   use implicit `Default` selection; there is no closed source-level distinction
   between the release suite and PID research suite.
7. The evidence file DTO converts infallibly to public-field detector/correlation
   values and validates later. There is no distinct immutable accepted evidence
   configuration retained by the runner.
8. `LiveLimits` checks only nonzero values and has no hard maxima for its three
   caller-controlled bounds. It also returns `ZenohError`; `JsonlLimits` returns
   `io::Error`, and lifecycle configuration erases typed component errors into
   strings.
9. `select_maximum`, `require_private_mode`, `allow_dirty`, monitor identity's
   `session` selector, live/monitor-live `owns_bus`, and registry
   `deployment_pin_verified` are Boolean mode, ownership, role, or capability
   choices. They have not been replaced by closed semantic types or typestate.
10. There are no external compile-fail tests proving immutability/non-fabrication,
    no property suite for constructor closure, and no retained API scan enforcing
    the configuration surface.
11. Accepted configuration/profile canonical identities are not yet serialized
    and bound into every report/evidence record; that dependency continues into
    T017.
12. Construction allocation/complexity and bundle-level work contracts are not
    uniformly documented on the Rust API.

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
