# pid-rs 0.4 to 1.0 migration

## Abbreviations

| Short form | Meaning |
|---|---|
| PID2 | two-source partial information decomposition |
| SHA-256 | Secure Hash Algorithm 256 |
| SxPID | shared-exclusions partial information decomposition |

Galadriel pins immutable pid-rs revision `1cd2424f7967e1752dcc8e53859e8fdad3566f51`.
Its `pid-core` manifest declares version 1.0.0.
At this snapshot, pid-rs has no public v1 tag or released upstream 1.x artifact.
The term “1.0” below identifies the pinned source and application programming interface (API) migration.
It does not identify a published dependency release.

The pin contains commit `91cd811a27b15de60c5cdb08d5516bf3471883ce`.
It also contains the same-day correctness and continuous integration (CI) follow-up commits.
The prior pin used pid-core 0.4.0 at `ad489f5bf5e15c164c599d069a6bee0f338c0e48`.

The pid-rs project supplies Partial Information Decomposition (PID) APIs.
It also supplies Kraskov–Stögbauer–Grassberger (KSG) estimators.

This change is an explicit scientific and API migration.
It is not only a dependency update.

- The minimum supported Rust version (MSRV) moves from Rust 1.88 to 1.89.
- Continuous PID APIs are off by default and explicitly experimental in pid-rs 1.0.
- KSG defaults now fail closed until the caller declares a support contract.
- Galadriel's point gate uses the report-first KSG API.
  It requires the returned `conditional_continuous` and `restricted_domain` classification.
- The pid-rs 1.0 `NegativeHandling::Allow` default preserves finite signed-negative KSG estimates.
  Galadriel accepts them as low-dependence evidence.
  It rejects only non-finite estimator output.
- Circular delete-block replicates use the raw scalar API under the same declared support contract.
  This choice bounds edge-by-resample work.
  The replicates are an experimental pipeline.
  They do not silently inherit the point-report status.
  Resource preflight conservatively counts four quadratic scan units for each raw KSG confirmation edge.
  It does not count one estimator call as one scan.
- Continuous shared-exclusions PID2 atoms remain advisory.
  They have the `experimental_restricted_domain` label.
- The seeded Gaussian perturbation is an observation-noise model that changes the estimand.
  It is not a general tie repair.
- Each `PidReport` carries the exact pid-rs version and revision.
  It also carries estimators, scientific classifications, support declaration, noise model, scale, seed, and geometry `k`.
- Each successful point-gate pair retains typed method and scientific status.
  It retains the estimand, assumption ledger, warnings, provenance hashes, support contract, and resource estimate.
  These values come from the upstream report-first API.

## Fixed-seed reproduction

The from-side used Galadriel commit `9bd2cb0756009986d1a1a0e429614a1cbbe42ed5`.
It also used the deterministic comparison-control patch below and the 0.4 dependency pin.
The to-side used the 1.0 migration tree.

Both sides ran on the same Apple M4 Max and Darwin 25.5 host.
They used exact rustup toolchain `cargo 1.96.0` and `rustc 1.96.0 (ac68faa20)`.
The test command used the Cargo test profile.
The reproduction executable used the release profile.

Rust 1.88 and 1.89 are the respective declared MSRVs.
They are not the toolchains used for this reproduction.
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

```text
cargo +1.96.0 test --locked -p galadriel-pid -p galadriel-justify
cargo +1.96.0 run --locked --release -p galadriel-justify -- 20
```

The table reports mutual information (MI) and area under the receiver operating characteristic curve (AUC).
The comparison uses seed 7 and 20 paired trials.
It uses `n=400` for the pairwise study and `n=600` for the synergy studies.
It uses the fixed sequential and autocorrelation settings of the command-line interface (CLI).
These small synthetic trials are compatibility smoke evidence.
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

Tests lock both sides of the point and confirmation boundary.
Bootstrap cannot create an attribution that is absent from the point gate.
Fixed-seed decouplings remain positively isolated.
The default bootstrap configuration confirms at least one decoupling with a negative upper confidence endpoint.

A separate test covers positive PID evidence beside an insufficient PID axis.
The result becomes `UnclassifiedAnomaly` when no complete signed result independently establishes the same attribution.
Matching partial PID evidence cannot erase a complete signed default when all signed-correlation axes independently agree.

## Remaining scientific boundary

This migration establishes source and API compatibility.
It also establishes synthetic continuity.
It does not prove these properties of Crebain residuals:

- regular full-dimensional support
- approximate independence and identical distribution
- adequate sampling
- insensitivity to observation-noise scale
- calibration for the selected windows

PID remains opt-in, sign-invariant, and advisory.
It cannot widen authority.
A representative calibration and locked-holdout campaign remains necessary before an operational policy can consume PID evidence.
