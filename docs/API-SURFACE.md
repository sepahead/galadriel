# Application programming interface (API) and compatibility surface for 0.9.0

## Abbreviations

| Short form | Meaning |
|---|---|
| ASCII | American Standard Code for Information Interchange |
| MSRV | minimum supported Rust version |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |

Galadriel 0.9.0 uses the review-gated GitHub research source release channel.
All crates have `publish = false`.
This policy defines source compatibility in the 0.9 release line.
It makes no crates.io or long-term support promise.

**GLD-090-API-001:** `galadriel-core` is the only stable Rust source surface for
0.9.x. Its retained `cargo public-api` snapshot identifies the intentional API.
This API includes root re-exports, public modules, public types, public functions,
and documented invariants.
A 0.9.x removal or semantic widening **SHALL** have a recorded compatibility
disposition.
A breaking change **SHALL** also change the minor version.

**GLD-090-API-002:** These crates are experimental or supporting surfaces:

- `galadriel-cli`
- `galadriel-sim`
- `galadriel-eval`
- `galadriel-justify`
- `galadriel-dependence`
- `galadriel-ncp`

Their feature names and wire adapters are also experimental or supporting
surfaces. They **SHALL NOT** be described as stable 1.0 APIs or
deployment-qualified protocols.

The sidecar and monitor schemas accept only the Galadriel core identity grammar.
An accepted identity contains 1 through 64 ASCII bytes.
This rule is part of the supporting wire behavior for schema version 1.0.

**GLD-090-API-003:** Default features **SHALL** remain empty.
The optional `dependence`, `ncp`, and `ncp-live` features **SHALL NOT** enter the pure
default dependency graph.
`galadriel-core --no-default-features` **SHALL** continue to build at the pinned
minimum supported Rust version (MSRV).

**GLD-090-API-004:** Numerical implementation helpers outside the detector
contract **SHALL NOT** be public. The former public `chi2` module is private in
0.9.0. Callers use the typed NIS report. They do not depend on a specific
incomplete-gamma backend.

**GLD-090-API-005:** Accepted whole-stream reports **SHALL** remain sealed.
Callers can compare or inspect an `AssessmentBinding`. They can also verify it
against an exact `AssessmentScope`, stream, and `ReleaseSuite`. Callers cannot
construct the binding or attach it to replacement component reports. Unbound
component fusion APIs are diagnostic compatibility surfaces. They do not return
an accepted `DefaultReport`.

**GLD-090-API-006:** Version 0.9.0 adds a type-safe authority
snapshot construction path. The additions include these public types:

- `AuthoritySemanticsId`
- `AuthoritySnapshotParams`
- `VelocityLimit`
- `SlewLimit`
- `CommandTtlMillis`
- `LeaseExpiryMillis`
- `WatchdogEpoch`

The root module re-exports each new type. `AuthoritySnapshot::new_strict` creates
a bound snapshot. `semantics_id`, `velocity_limit`, `slew_limit`, `command_ttl`,
`lease_expiry`, and `watchdog` expose its typed values.

The exact `AuthoritySnapshot::new` signature remains callable. Its raw `u64`
getters also remain callable with their existing return types. The constructor is
deprecated because it creates an unbound legacy snapshot. Exact record-only
comparison of an unchanged legacy snapshot remains accepted.

Restrict-only validation now rejects every unbound legacy snapshot. It also
rejects mismatched authority semantics identities before it compares scalar
values. This change is an intentional fail-closed behavioral narrowing. It closes
unit, clock, profile, and same-type field ambiguity within version 0.9.0.

Version 0.9.0 contains no authority consumer and no implemented advisory
publisher. The preceding public version did not contain this surface. This
compatibility disposition incorporates the correction into version 0.9.0.
It does not require a minor-version change.

**GLD-090-API-007:** Release-suite and lifecycle composition now reject a
`CorrConfig` whose axis family was already derived. These entry points require
an underived base correlation config. Each assessment derives the family once
for its active projection axes.

The affected public inputs were constructible earlier in version 0.9.0 development.
They could not complete a projected assessment because that path derived the
family again and failed closed. The new constructor rejection moves the same
failure before suite or lifecycle state allocation.

**GLD-090-API-008:** The public
`MAX_RELEASE_LIFECYCLE_SAMPLE_UNITS` constant is now `983_040`.
The version 0.9.0 candidate previously used `8_000_000`.

`ReleaseSuite::try_new` now budgets all six modalities for every retained
lifecycle window. It previously budgeted only the submitted expected modalities.
The change can reject a custom suite that the earlier candidate accepted.
It also changes the reported lifecycle work, state-byte estimate, and suite
identity when the expected modality set has fewer than six values.

For the three-modality standalone profile, the identity changed from
`6e88f0907af330ddd0919738e241038e2bc912076bda873c90fdd63bab9c756a` to
`e54a80bbf77bd20ff18a07ef87c418cebe66857b7d83a74ade5a8227e2c960b4`.
The correction aligns core composition with the six-modality lifecycle
allocation bound. It closes a core-to-lifecycle admission mismatch before
publication.

The binding identifies the submitted input. Different bindings can carry equal
detector verdicts. It does not require each observation to change a verdict.

`AssessmentScope` is part of the stable root export. It contains one validated
`ProducerId` and one exact `StreamPosition`. Its public constructor and getters
are `AssessmentScope::new`, `producer_id`, and `position`.

These accepted core entry points require `&AssessmentScope` as their first
argument:

- `prepare_release_assessment`
- `assess_default`

```rust,ignore
pub fn prepare_release_assessment(
    scope: &AssessmentScope,
    stream: &[PidObservation],
    suite: &ReleaseSuite,
) -> Result<PreparedReleaseAssessment>;

pub fn assess_default(
    scope: &AssessmentScope,
    stream: &[PidObservation],
    suite: &ReleaseSuite,
) -> Result<DefaultReport>;
```

`PreparedReleaseAssessment::assessment_scope` and
`DefaultReport::assessment_scope` return the accepted scope.
`AssessmentBinding::scope` returns the same value.
`AssessmentBinding::verifies` requires the exact scope, stream, and suite.

```rust,ignore
pub fn verifies(
    &self,
    scope: &AssessmentScope,
    stream: &[PidObservation],
    suite: &ReleaseSuite,
) -> bool;
```

The optional `galadriel_dependence::assess_with_dependence` entry point also
requires `&AssessmentScope`. Its experimental
`DependenceAssessmentReport::assessment_scope` getter returns the scope from the
nested core binding. `authoritative_verdict` is exactly the unchanged core
verdict; no MI disposition enters it.

The scope labels provenance. It does not authenticate the caller or producer.
The accepted core entry points validate the terminal sequence and terminal-frame
timestamp against the stream.

The pre-change snapshot is
`release/0.9.0/api/galadriel-core.baseline.txt`. The accepted 0.9.0 snapshot is
`release/0.9.0/api/galadriel-core.0.9.0.txt`.

The optional dependence adapter has this audit-only snapshot:
`release/0.9.0/api/galadriel-dependence.0.9.0.txt`. This snapshot shows that
accepted MI configurations and sealed companion reports expose no public fields.
It does not make this experimental crate part of the stable surface.

The companion's versioned JSON snapshot retains `MiAcceptedConfigEvidence` for
every named or custom graph value and `MiKsgEvaluatorConfigEvidence` for the
fixed KSG evaluator contract. It also retains complete immutable upstream KSG
reports, canonical hexadecimal digests, and a `ProjectionAxisReceipt` for each
produced axis. That receipt binds
the producer projection frame/context, axis and modality order, extracted suffix
length, and every selected row's sequence and timestamp bounds. The inner
`RowSetReceipt` separately binds the exact binary64 columns. The current types
implement serialization for evidence export; they do not promise a stable
deserialization or wire-input schema.

The selected implementation is `pid-core` 0.9.0 at
`bc3aa80fb6025e709c2906a08bce25a4fac40578`. Each point fit calls
`ksg_mi_report_with_budget`. Its preflight and execution use the same explicit
single-thread `ResourceBudget`. No resolved Galadriel feature profile includes
`pid-runlog`. The older `1cd2424f…` selection appears only in the immutable
CREBAIN producer preregistration and historical migration record.

Offline `galadriel-justify` exposes `PidFunctionalIdentity`, role-typed
`PidReferenceEdge` values, `PidStudyRoute`, `PidQuestionSpec`,
`PidDependencyIdentity`, `PidInputLawSpec`, `PidOutputCoordinateSpec`,
`PidAggregateOutputSpec`, `PidTrialArmSpec`, `StudyAggregateOutputSpec`,
`JustificationStudyProtocol`, and typed `JustificationError`. The version 3
question/study schemas distinguish the categorical
Makkeh–Gutknecht–Wibral functional from the related continuous
Ehrlich–Schick-Poland–Makkeh–Lanfermann–Wollstadt–Wibral construction and bind the exact
sample-evaluator route. They name the original Williams–Beer antichain lattice,
the later Gutknecht–Wibral–Makkeh part-whole derivation, and functionals that are
not evaluated rather than conflating those roles. Each question serializes its
exact generated law and finite-sample conditioning, every lattice coordinate and
component, the direct-versus-derived construction, within-trial aggregation,
root aggregate-field mapping, and coupled-versus-permutation-control arm role.
AUC/interval fields are dimensionless and cannot inherit atom units. Each retained
upstream trial explicitly remains in nats. The sibling study protocol maps every
non-PID root field and binds its paired-index bootstrap, seed domains, percentile
selection, interval scope, and lack of a multiplicity guarantee. The result does
not bind the exact resolved RNG crate bytes or Galadriel source tree; those remain
publication-bundle requirements. The fixed question's dependency-selection
envelope is deliberately smaller than a build identity. Each produced study
separately retains `PidExecutionIdentity`, reconciles pid-core's
`SoftwareIdentity` to the exact package/version/revision, and requires a clean
`pid-core` package subtree at the selected WorkspaceGit commit. This remains
smaller than whole-repository cleanliness or binary attestation. Each study also
retains `PidStudyResourceContract`: every pid-core evaluation uses the same
explicit one-thread per-call `ResourceBudget`, while the separate aggregate
study preflight remains the bound on composed quadratic work. Neither receipt is
an end-to-end peak-memory, allocation-success, or wall-clock guarantee. Categorical and
continuous aggregate result fields are private. Getters expose them and a
coherence method recomputes
every upstream-report-derived aggregate. Pearson remains outside that verifier
because the result does not retain its exact input rows.

The same audit-only crate now exposes `crebain_mgw` and the standalone
`galadriel-crebain-mgw` binary. Its sealed `CrebainMgwQuestionSpec`,
`FixtureIdentity`, `FixtureValidation`, `MethodEligibility`, `AlgebraChecks`, and
`CrebainDroneMgwStudy` types describe one exact embedded categorical AND2/AND3
law. The binary accepts no external data path. It emits complete JSON by default
or a Markdown rendering with `--format markdown`. This is not a stable input/wire
schema, a runtime adapter, or part of `galadriel-core`. The output schema is
versioned independently as `galadriel.crebain-drone-mgw-study.v2`. Its closed
Draft 2020-12 document is
`crates/galadriel-justify/schemas/crebain-drone-mgw-study-v2.schema.json`. The
study embeds its exact digest/byte receipt, and
`repo_work/check_crebain_mgw_schema.py` validates both shape and byte binding.
Public accessors do not authorize callers to construct, deserialize, or
reinterpret a result. Only the byte-bound validation/evaluation path can produce
one. The dependency-disjoint, separately implemented 80-digit Decimal route
checks the 66 averaged atom components and ten mutual informations, not the
retained pointwise atoms. This is not independent human or organizational
replication. The study is record-only research evidence: it cannot affect
fusion or Haldir
authorization or plant-command outputs.

The fixture-facing API treats `fusion_receipt` as a six-field legacy summary
(prior identifier, input/expected/projection counts, truncation, and
degradation). It does not expose that object as three complete projection
receipts, a full fusion replay, or proof of state isolation. The target receipt
states that latent-truth generation is dataflow-separated from projection,
fusion, verdict, and PID. It does not claim producer-independent field truth.

The preceding public version was 0.1.0.
That version was explicitly a research prototype.
Version 0.9.0 can therefore remove an accidental surface.
`GaladrielError` is now non-exhaustive and includes a distinct `InternalFault`
category; impossible dependency-adapter failures no longer masquerade as caller
configuration rejection.
New 0.9.x releases use the accepted snapshot as their compatibility baseline.
Serialization schemas have separate versions.
A public Rust type does not make its serialization schema stable.
