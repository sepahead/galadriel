# 0.9.0 application programming interface (API) and compatibility surface

## Abbreviations

| Short form | Meaning |
|---|---|
| ASCII | American Standard Code for Information Interchange |
| MSRV | minimum supported Rust version |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |

Galadriel 0.9.0 is a review-gated GitHub research source release.
All crates have `publish = false`.
This policy defines source compatibility in the 0.9 release line.
It makes no crates.io or long-term support promise.

**GLD-090-API-001:** `galadriel-core` is the only stable Rust source surface for
0.9.x. Its retained `cargo public-api` snapshot identifies the intentional API.
This API includes root re-exports, public modules, public types, public functions,
and documented invariants. A 0.9.x removal or semantic widening **SHALL** require
a recorded compatibility disposition. A breaking change **SHALL** also require a
minor-version change.

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

**GLD-090-API-003:** Default features **SHALL** remain empty. The optional `pid`,
`ncp`, and `ncp-live` features **SHALL NOT** enter the pure default dependency
graph. `galadriel-core --no-default-features` **SHALL** continue to build at the
pinned MSRV.

**GLD-090-API-004:** Numerical implementation helpers outside the detector
contract **SHALL NOT** be public. The former public `chi2` module is private in
0.9.0. Callers use the typed NIS report. They do not depend on a specific
incomplete-gamma backend.

**GLD-090-API-005:** Accepted whole-stream reports **SHALL** remain sealed.
Callers can compare or inspect an `AssessmentBinding`. They can also verify it
against an exact stream and `ReleaseSuite`. Callers cannot construct the binding
or attach it to replacement component reports. Unbound component fusion APIs are
diagnostic compatibility surfaces. They do not return an accepted
`DefaultReport`.

The pre-change snapshot is
`release/0.9.0/api/galadriel-core.baseline.txt`. The accepted 0.9.0 snapshot is
`release/0.9.0/api/galadriel-core.0.9.0.txt`.

The optional PID adapter has this audit-only snapshot:
`release/0.9.0/api/galadriel-pid.0.9.0.txt`. This snapshot shows that accepted PID
configs and sealed reports expose no public fields. It does not make this
experimental crate part of the stable surface.

The preceding public version was 0.1.0 and was explicitly a research prototype.
Thus, 0.9.0 can remove an accidental surface. New 0.9.x releases use the
accepted snapshot as their compatibility baseline. Serialization schemas have
separate versions. A public Rust type does not make its serialization schema
stable.
