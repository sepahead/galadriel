# pid-rs 0.4 to 1.0 migration

## Abbreviations

| Short form | Meaning |
|---|---|
| PID2 | two-source partial information decomposition |
| SHA-256 | Secure Hash Algorithm 256 |
| SxPID | shared-exclusions partial information decomposition |

Galadriel pins immutable pid-rs revision `1cd2424f7967e1752dcc8e53859e8fdad3566f51`.
Its `pid-core` manifest declares version 1.0.0.
The retained 2026-07-22 inspection found no public v1 tag or released upstream 1.x artifact.
The term “1.0” below identifies the pinned source and application programming interface (API) migration.
It does not identify a published dependency release.

The pin contains commit `91cd811a27b15de60c5cdb08d5516bf3471883ce`.
It also contains the same-day correctness and continuous integration (CI) follow-up commits.
The prior pin used pid-core 0.4.0 at `ad489f5bf5e15c164c599d069a6bee0f338c0e48`.

The pid-rs project supplies Partial Information Decomposition (PID) APIs.
It also supplies Kraskov–Stögbauer–Grassberger (KSG) estimators.

This is an explicit scientific and API migration, not only a dependency update.
The original 0.4-to-1.0 reproduction below remains historical evidence. The
current 2026-08-14 architecture supersedes its former runtime PID composition:

- The minimum supported Rust version (MSRV) moves from Rust 1.88 to 1.89.
- `galadriel-dependence` uses only pid-rs's stable report-first KSG surface. It
  does not enable continuous PID, mixed-dimensional PID3, or pipeline features.
- Every MI configuration requires caller-declared population, observation, and
  sampling models. Galadriel validates the declaration representation but does
  not prove it.
- The caller declares a common coordinate gauge. Galadriel applies the fixed
  identity transform and adds no jitter or Gaussian noise. Exact ties abstain.
- Every edge retains the complete upstream KSG report, including support,
  estimand, assumptions, warnings, provenance, resource estimate, units, and
  exact revision.
- Every graph report also serializes all accepted graph parameters and the fixed
  KSG evaluator configuration, so an unavailable graph remains self-describing.
- Resource rejection at the point fit or during a deletion replay remains a
  distinct typed outcome; it is not relabeled scientific instability.
- The opt-in in-process/library graph is a project-defined symmetric pairwise-MI
  composition. It is not PID and has no target. Its event never changes the
  default fused verdict. In 0.9 only the synthetic demo, evaluation, and benchmark
  execute it; `replay`, `observe`, and NCP do not.
- Exhaustive circular deletion reruns retained-row validation, geometry, all pair reports,
  global threshold, clique, and attribution for every start. Its margin envelope
  is deterministic sensitivity evidence, not a bootstrap confidence interval.
- `galadriel-justify` separately enables `experimental-continuous` for complete
  Ehrlich PID2 reports. It also uses stable categorical Makkeh–Gutknecht–Wibral
  SxPID. These are distinct functionals and fixed offline questions.
- The scope binds producer, session, epoch, stream, state generation, terminal
  sequence, terminal timestamp, and clock domain before companion work starts.
- `DependenceAssessmentBinding` nests the exact core version-2 binding and the
  complete dependence-suite identity. It authenticates neither the caller nor
  the scientific declarations.

### Concrete upstream resource-composition handoff

The selected pid-rs revision has one narrower defect that Galadriel does not
paper over. `pid2_report_resource_estimate` preflights the joined-source MI term
through the cheaper internal x-blocks estimator (one triangular pair pass), but
`pid2_isx_report` executes an explicit joined-source `ksg_mi_report` whose
estimator and three support diagnostics retain four triangular passes. The
aggregate therefore accounts for 10 triangular passes while the four executed
constituent reports account for 13.

For `n=600`, the difference is `3 * 600 * 599 / 2 = 539,100` pair-distance
evaluations per PID2 report. A 250-trial coupled/control study executes 500
reports, so trusting the aggregate would omit 269,550,000 evaluations.
Galadriel now composes the three executed report-first KSG constituents plus the
Ehrlich shared-exclusions constituent with checked `u128` arithmetic and locks
that count against an actual report's four retained constituent resource
estimates. It deliberately does not treat the smaller aggregate as the executed
work receipt.

The pid-rs handoff is specific: make the report preflight and execution use the
same joined-source route, add checked `ResourceEstimate` composition, and retain
a hostile control equating the aggregate with the sum of the reports that are
actually executed. This belongs alongside Prisoma's complete extension brief;
it is not a request for another PID functional or comparator.

## Fixed-seed reproduction

The from-side used Galadriel commit `9bd2cb0756009986d1a1a0e429614a1cbbe42ed5`.
It also used the deterministic comparison-control patch below and the 0.4 dependency pin.
The to-side used the 1.0 migration tree.

Both sides ran on the same Apple M4 Max and Darwin 25.5 host.
They used exact rustup toolchain `cargo 1.96.0` and `rustc 1.96.0 (ac68faa20)`.
The test command used the Cargo test profile.
The reproduction executable used the release profile.

The from-side declares Rust 1.88 as its minimum supported Rust version.
The to-side declares Rust 1.89.
These versions are not the toolchains used for this reproduction.
The final migration commit must pass the separate pinned-1.89 CI gate.

Pull request (PR) #16 squash-landed the migrated implementation on `main`.
The commit is `86577db18b4247662c2a87882a310efaaa5322ca`.
Its tree is `a7b9fb42ac78b7a7a58735eb7b1f505767f5f6ab`.
Its Cargo.lock SHA-256 is `181a4bdc79478e623e23950c66b5d13fcd5543131507bf219065cc1e22f38161`.

The paired compatibility run came from the audited PR source snapshot.
Its commit is `c0f0d45e6ab8d6440ea9ba643929617399e0ee31`.
Its tree is `b0dda8c7163b81f45023cfd62b6cb36d0335e5e7`.

The landed tree contains that migration and subsequent evidence-binding hardening.
It also contains CI and mutation-test hardening follow-up commits.
Its Cargo.lock is byte-identical.
This post-landing provenance repair changes only evidence and documentation.

The original exclusive-or (XOR) output was not process-reproducible.
Local plug-in entropy used randomized `HashMap` iteration for a floating-point reduction.
Both comparison sides now use the same ordered `BTreeMap` reduction in the final tree.

The base checkout used only the checked-in comparison-control patch.
That file is `evidence/pid-rs-0.4-deterministic-control.patch`.
Its SHA-256 is `070d7b61ae773c9fb5d73cab9ba23c642d17110adaf63556e285748cbb20f479`.
The complete standard-output streams now have the same hash.
That hash is `495293442347f13710d6d928e12fdc8c8faf3f1d29bb8d19f06131f5a402fca7`.

Current source verification uses:

```text
cargo +1.96.0 test --locked -p galadriel-dependence -p galadriel-justify
cargo +1.96.0 run --locked --release -p galadriel-justify -- 20
```

The historical comparison table reports mutual information (MI) and area under the receiver operating characteristic curve (AUC).
The comparison uses seed 7 and 20 paired trials.
It uses `n=400` for the pairwise study and `n=600` for the synergy studies.
It uses the fixed sequential and autocorrelation settings of the command-line interface (CLI).
These small synthetic trials provide basic compatibility-test evidence.
They are not an operational false-alert or detection-rate estimate.

| Output | pid-rs 0.4 | pid-rs 1.0 | Disposition |
|---|---:|---:|---|
| Linear pairwise MI mean (nats) | 0.801 | 0.801 | Reproduced |
| Linear MI AUC | 1.000 | 1.000 | Reproduced |
| Nonlinear pairwise MI mean (nats) | 0.410 | 0.410 | Reproduced |
| Nonlinear MI AUC | 1.000 | 1.000 | Reproduced |
| Discrete XOR pairwise-MI AUC | 0.531 `[0.339, 0.714]` | 0.531 `[0.339, 0.714]` | Reproduced after deterministic reduction fix |
| Discrete XOR joint/SxPID AUC | 1.000 / 1.000 | 1.000 / 1.000 | Reproduced |
| Discrete XOR mean synergy/redundancy (bits) | +0.414 / -0.583 | +0.414 / -0.583 | Reproduced |
| Continuous parity pairwise MI AUC | 0.620 | 0.620 | Reproduced |
| Continuous parity joint/SxPID AUC | 1.000 / 1.000 | 1.000 / 1.000 | Reproduced |
| Continuous parity joint MI / synergy (nats) | 0.499 / 0.468 | 0.499 / 0.468 | Reproduced |
| Sequential tables | baseline output | identical reported output | Reproduced |
| Autocorrelation-null table | baseline output | identical reported output | Reproduced |

Randomized local entropy-reduction order caused the earlier apparent discrete difference.
The migrated categorical pid-rs API did not cause it.
Ordered reduction makes both standard-output streams byte-identical.
A regression test now runs the fixed-seed synergy report twice.
It requires exact equality.
The exact closed-form SxPID atom assertions still pass.

The pid-rs 1.0 `NegativeHandling::Allow` setting preserves finite signed-negative KSG estimates.
Galadriel treats these values as valid low-dependence evidence.
It does not treat them as estimator failure.

Current tests lock the point-graph and exhaustive-deletion boundary. A retained
separation must recur under every deletion start; otherwise the graph disposition
is `Unavailable`. No resample, alpha, or interval field exists.

The accepted companion report carries one `DependenceAssessmentBinding`. This
binding nests the core `galadriel-assessment-binding-v2` identity, which covers
the exact scope, release suite, and ordered stream. The outer binding also covers
the complete dependence research suite. The report retains the exact unchanged
`DefaultReport`; no MI event can create, erase, or relabel its verdict.

The scope is caller-declared provenance at the direct library boundary.
It does not authenticate the caller or prove producer authorship.

## Remaining scientific boundary

This migration establishes source and API compatibility.
It also establishes continuity for the stated synthetic comparison.
It does not prove these properties of Crebain residuals:

- regular full-dimensional support
- approximate independence and identical distribution
- adequate sampling
- robustness to declared observation representation and preprocessing choices
- calibration for the selected windows

The MI companion remains opt-in, symmetric, descriptive, and non-authoritative.
It cannot widen authority. Its row receipt proves byte identity, not episode
truth, population support, or independence. A representative streaming
qualification and locked holdout remain necessary before any operational policy
can consume its event.

PID remains offline. Each study must fix the source tuple and external target and
must name the categorical MGW or continuous Ehrlich functional, evaluator,
gauges, law, transform relation, row relation, units, and software identity.
Galadriel's version 2 question records additionally bind the exact generated law
and finite-sample selection, the original Williams–Beer lattice separately from
the evaluated functional, every output coordinate/component/construction, the
coupled and within-trial permutation arm roles, and exact root-field statistics
and units. The sibling protocol binds the paired bootstrap seed/quantile rules but
does not replace a source/tree/toolchain publication identity.
Negative shared-exclusions atoms remain meaningful signed associative terms; they
must not be clamped or labeled causal mechanisms.
