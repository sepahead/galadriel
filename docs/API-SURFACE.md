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
- `galadriel-pid`
- `galadriel-ncp`

Their feature names and wire adapters are also experimental or supporting
surfaces. They **SHALL NOT** be described as stable 1.0 APIs or
deployment-qualified protocols.

The sidecar and monitor schemas accept only the Galadriel core identity grammar.
An accepted identity contains 1 through 64 ASCII bytes.
This rule is part of the supporting wire behavior for schema version 1.0.

**GLD-090-API-003:** Default features **SHALL** remain empty.
The optional `pid`, `ncp`, and `ncp-live` features **SHALL NOT** enter the pure
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

The optional `galadriel-pid::assess_stream` entry point also requires
`&AssessmentScope`. Its experimental `FusedReport::assessment_scope` getter
returns the scope from the nested core binding.

The scope labels provenance. It does not authenticate the caller or producer.
The accepted core entry points validate the terminal sequence and terminal-frame
timestamp against the stream.

The pre-change snapshot is
`release/0.9.0/api/galadriel-core.baseline.txt`. The accepted 0.9.0 snapshot is
`release/0.9.0/api/galadriel-core.0.9.0.txt`.

The optional PID adapter has this audit-only snapshot:
`release/0.9.0/api/galadriel-pid.0.9.0.txt`. This snapshot shows that accepted PID
configs and sealed reports expose no public fields. It does not make this
experimental crate part of the stable surface.

The preceding public version was 0.1.0.
That version was explicitly a research prototype.
Version 0.9.0 can therefore remove an accidental surface.
New 0.9.x releases use the accepted snapshot as their compatibility baseline.
Serialization schemas have separate versions.
A public Rust type does not make its serialization schema stable.
