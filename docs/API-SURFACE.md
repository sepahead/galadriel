# 0.9.0 API and compatibility surface

Galadriel 0.9.0 is a GitHub source release. All crates remain `publish = false`;
this policy defines source compatibility within the release line and makes no
crates.io or long-term-support promise.

**GLD-090-API-001:** `galadriel-core` is the only stable Rust source surface for
0.9.x. Its root re-exports, public modules, public types, public functions and
documented invariants in the retained `cargo public-api` snapshot **SHALL** be
treated as intentional. Any 0.9.x removal or semantic widening **SHALL** require a
recorded compatibility disposition and a minor-version change when breaking.

**GLD-090-API-002:** `galadriel-cli`, `galadriel-sim`, `galadriel-eval`,
`galadriel-justify`, `galadriel-pid`, and `galadriel-ncp`, including their feature
names and wire adapters, are experimental/supporting surfaces. They **SHALL NOT**
be advertised as stable 1.0 APIs or deployment-qualified protocols.

**GLD-090-API-003:** Default features **SHALL** remain empty. Optional `pid`, `ncp`
and `ncp-live` features **SHALL NOT** enter the pure default dependency graph.
`galadriel-core --no-default-features` shall continue to build at the pinned MSRV.

**GLD-090-API-004:** Numerical implementation helpers that are not part of the
detector contract **SHALL NOT** be public. The former public `chi2` module is
private in 0.9.0; callers consume the typed NIS report rather than depending on a
particular incomplete-gamma backend.

**GLD-090-API-005:** Accepted whole-stream reports **SHALL** remain sealed.
`AssessmentBinding` may be compared, inspected, or verified against an exact stream
and `ReleaseSuite`, but callers cannot construct it or attach it to replacement
component reports. Unbound component fusion APIs are diagnostic compatibility
surfaces and do not return an accepted `DefaultReport`.

The pre-change snapshot is
`release/0.9.0/api/galadriel-core.baseline.txt`; the accepted 0.9.0 snapshot is
`release/0.9.0/api/galadriel-core.0.9.0.txt`. The optional PID adapter also has an
audit-only snapshot at `release/0.9.0/api/galadriel-pid.0.9.0.txt`; retaining it
proves that accepted PID configs and sealed reports expose no public fields, but
does not promote that experimental crate to the stable surface. Because the preceding public
version was 0.1.0 and explicitly a research prototype, 0.9.0 may remove accidental
surface. Subsequent 0.9.x releases use the accepted snapshot as the compatibility
baseline. Serialization schemas are separately versioned and do not become stable
merely because a Rust type is public.
