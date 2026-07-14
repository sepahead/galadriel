# Phase 1 ten-lens review: identity, claims and contract

Date: 2026-07-14

Reviewer/author: Sepehr Mahmoudian

Tasks: T000–T009

Decision: phase component and full workspace gates pass

Post-push remediation: GitHub PR #23 detected that the standalone fuzz workspace
still required the pre-release `0.1.0` package versions. Both fuzz manifest and
lockfile now use `0.9.0`, the audit includes and validates them, and the exact CI
dependency-policy and two 5,000-run fuzz commands pass in
`evidence/phase-1-ci-remediation.log`. The same review corrected two documentation
mismatches found independently: the tested CUSUM boundary is inclusive (`>=`), and
the overflow-safe window mean remains the true finite mean rather than a quotient
of the saturated sum. Neither correction changes runtime behavior or claim tier.
The first remote mutation run then exposed 15 surviving authority-test mutants,
covering getter constants, authorization conjunction, and strict-versus-inclusive
limit boundaries. Two focused tests now close those omissions. Against signed code
commit `c67506e683116bd9a022377a5fe74b3c1e3edbd7`, cargo-mutants 27.1.0 reports
33 mutants tested: 30 caught, three unviable, zero missed or timed out; the complete
result is retained in `evidence/phase-1-mutation-remediation.log`.

Reviewed inputs include all ten unaltered handoff artifacts, all current repository
source/docs/tests, the baseline public API, Cargo metadata/lockfile, CI/security
configuration, retained evidence, and the exact ecosystem revisions in
`audit-inputs.json`. This review does not convert component evidence into a
deployment claim.

## Correctness and invariants

The release identity is consistently 0.9.0 and author identity is Sepehr Mahmoudian.
The 120-task sequence is machine-checked as contiguous with the exact dependency
chain. Report estimands and ordered verdict functionals are frozen in
`STATISTICAL-CONTRACT.md`. The authority validator accepts equality/restriction and
rejects every modeled widening. Remaining correctness risk is explicitly outside
phase 1: later phases must reconcile the exploratory `Mirror::new` behavior and
sequential/default-profile calibration before a release decision.

## Safety and failure behavior

Claims distinguish implementation from validation and contain zero
deployment-qualified entries. Missing evidence is represented as `OPEN` or
`NOT_CLAIMED`; the verifier prohibits prose-only completion. Advisory handling is
record-only initially and restrict-only only after independent admission; neither
mode can grant authority. The principal residual is denial of service through a
future restrict-only consumer, which remains unimplemented and unclaimed.

## Security and adversarial behavior

The threat model covers spoofing, coordinated compromise, statistics-matching
evasion, missingness, timing/replay, route/session confusion, malformed input,
resource exhaustion, races, dependency substitution and evidence tampering.
Negative tests reject duplicate JSON keys, malformed revisions, DOI substitution,
capability substitution, watchdog refresh and limit/authorization widening.
Actual-binary mTLS/ACL effectiveness remains unproved and is explicitly
`NOT_CLAIMED`.

## Determinism and reproducibility

Canonical JSON uses sorted keys, UTF-8 and a terminal newline; a metamorphic test
proves order independence and encode/decode idempotence. All Git dependencies,
baseline repository/tree, toolchains, fixtures, datasets and handoff inputs have
exact identities/hashes. Registry packages are Cargo.lock/checksum pinned. The
baseline was produced on one macOS arm64 host; clean-room and platform reproduction
remain later release gates rather than implied results.

## Performance and bounded resources

The release auditor streams file hashing in 1 MiB chunks and performs bounded work
over a fixed repository inventory. The authority validator is constant-time with
fixed-size state. No phase-1 change enlarges detector runtime state. CPU/memory
benchmarks and worst-case deployment envelopes remain later tasks and no performance
claim is introduced here.

## API, schema and compatibility

Only `galadriel-core` is selected as stable source API for 0.9.x. The before/after
`cargo public-api` inventories show the intentional authority API addition and the
removal of the accidental public chi-square implementation module. Supporting
crates/features/wires remain experimental. JSON inputs reject duplicate keys and
the release schemas reject unknown status/tier values. A later accepted 0.9.0 API
snapshot is required after all code phases; this phase snapshot is not the final
release diff.

## Observability and provenance

The audit manifest retains path, byte length and SHA-256 for every enumerated
artifact, exact repository/dependency identities, toolchain identities, external
references, claim tiers and ledger counts. Complete command logs are retained, not
only summaries. Human `note` fields are explicitly non-normative. A GitHub-only
release is less durable than an independent archive; DOI/Zenodo are intentionally
absent until the author creates them later.

## Testing and independent evidence

Eight standard-library auditor tests cover positive integration, malformed input,
boundaries, adversarial substitutions and deterministic metamorphic behavior. The
core suite now contains 104 unit/property tests plus a compile-fail doctest; phase-1
clippy/docs/no-default builds pass. The complete 0.9.0 workspace all-features suite,
documentation, root/fuzz supply-chain policies and bounded fuzz smoke also pass;
root `cargo deny` reports non-fatal duplicate/yanked transitive warnings that remain
inputs to the later supply-chain phase. These are maintainer-run component results,
not independent field evidence.

## Documentation and operator usability

The release record explains source-handoff preservation, version adaptation,
claims, estimands, threats, API, dependencies, support and change control. README
links the controlling documents and plainly labels 0.9.0 supervisor-review status.
Security reporting has a private channel and exact contact. Publication/runbook and
withdrawal operator drills remain later tasks.

## Ecosystem composition and governance

NCP and pid-rs selected revisions are immutable; their broader 1.x release claims
are not inferred. Crebain has reciprocal component evidence only. Haldir, Prisoma
and Paper2Brain are inventories, not claimed integrations. Protected `main` is the
candidate line under the owner's explicit instruction, with signed professional
commits and limited cross-repository authority. Remote ecosystem heads may advance;
the recorded hashes are an audit snapshot, not floating qualifications.

## Residual-risk disposition

Phase 1 introduces no deployment claim. The current repeated-look false-alert and
ordinary-missingness evidence remains unacceptable for policy use; no secured
external campaign, recorded projected-stream calibration, downstream adapter,
crates.io publication, DOI or archive exists. Those facts are visible in the claims
matrix and remain blocking or `NOT_CLAIMED` according to their later ledger tasks.
