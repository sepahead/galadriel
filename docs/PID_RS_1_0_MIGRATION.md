# pid-rs 0.4 to 1.0 migration

Galadriel now pins `pid-core` 1.0.0 at immutable pid-rs revision
`1cd2424f7967e1752dcc8e53859e8fdad3566f51`. pid-rs has no public v1 tag at this
snapshot; the pin contains release commit `91cd811a27b15de60c5cdb08d5516bf3471883ce`
and its same-day correctness and CI follow-ups. The prior pin was pid-core 0.4.0 at
`ad489f5bf5e15c164c599d069a6bee0f338c0e48`.

This is an explicit scientific/API migration, not a dependency-only bump:

- the workspace MSRV moves from Rust 1.88 to 1.89;
- continuous PID APIs are default-off and explicitly experimental in pid-rs 1.0;
- KSG defaults now fail closed until the caller declares a support contract;
- Galadriel's point gate uses the report-first KSG API and requires the returned
  `conditional_continuous` / `restricted_domain` classification;
- pid-rs 1.0's `NegativeHandling::Allow` default preserves finite signed-negative
  KSG estimates; Galadriel accepts them as low-dependence evidence and rejects only
  non-finite estimator output;
- circular delete-block replicates use the raw scalar API under the same declared
  support contract to keep edge-by-resample work bounded, and are labeled an
  experimental pipeline rather than silently inheriting the point-report status;
  resource preflight conservatively counts four quadratic scan units per raw KSG
  confirmation edge rather than treating one estimator call as one scan;
- continuous shared-exclusions PID2 atoms remain advisory and are labeled
  `experimental_restricted_domain`;
- the seeded Gaussian perturbation is recorded as an observation-noise model that
  changes the estimand. It is not described as a generic tie repair;
- every `PidReport` carries the exact pid-rs version/revision, estimators, scientific
  classifications, support declaration, noise model/scale, seed, and geometry `k`;
- every successful point-gate pair also retains typed method/scientific status,
  estimand, assumption ledger, warnings, provenance hashes, support contract, and
  resource estimate from the upstream report-first API.

## Fixed-seed reproduction

The from-side used Galadriel commit
`9bd2cb0756009986d1a1a0e429614a1cbbe42ed5` plus the deterministic comparison-control
patch below and the 0.4 dependency pin. The to-side used the 1.0 migration tree. Both
ran on the same Apple M4 Max / Darwin 25.5 host with exact rustup toolchain
`cargo 1.96.0` / `rustc 1.96.0 (ac68faa20)`. The test command used Cargo's test
profile; the reproduction executable used the release profile. Rust 1.88 and 1.89 are the
respective declared MSRVs, not the toolchains used for this reproduction; the final
migration commit must pass the separate pinned-1.89 CI gate.

The migrated implementation is bound to commit
`c0f0d45e6ab8d6440ea9ba643929617399e0ee31`, tree
`b0dda8c7163b81f45023cfd62b6cb36d0335e5e7`, and Cargo.lock SHA-256
`181a4bdc79478e623e23950c66b5d13fcd5543131507bf219065cc1e22f38161`.
The follow-up binding commit changes only this record and migration documentation.

The original XOR output was not process-reproducible because local plug-in entropy
used randomized `HashMap` iteration for a floating-point reduction. Both comparison
sides therefore use the same ordered `BTreeMap` reduction now present in the final
tree; the base checkout was patched only with the checked-in
`evidence/pid-rs-0.4-deterministic-control.patch` comparison control (SHA-256
`070d7b61ae773c9fb5d73cab9ba23c642d17110adaf63556e285748cbb20f479`).
The complete stdout stream hashes identically on both sides as
`495293442347f13710d6d928e12fdc8c8faf3f1d29bb8d19f06131f5a402fca7`.

```text
cargo +1.96.0 test --locked -p galadriel-pid -p galadriel-justify
cargo +1.96.0 run --locked --release -p galadriel-justify -- 20
```

The comparison uses seed 7, 20 paired trials, `n=400` for the pairwise study,
`n=600` for the synergy studies, and the CLI's fixed sequential/autocorrelation
settings. These small synthetic trials are compatibility smoke evidence, not an
operational false-alert or detection-rate estimate.

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

The earlier apparent discrete delta was traced to randomized local entropy-reduction
order, not the migrated categorical pid-rs API. Ordered reduction makes both stdout
streams byte-identical, and a regression test now runs the fixed-seed synergy report
twice and requires exact equality. The exact closed-form SxPID atom assertions still
pass. pid-rs 1.0 deliberately preserves finite signed-negative KSG estimates under
`NegativeHandling::Allow`; Galadriel treats them as valid low-dependence evidence rather
than estimator failure. Tests lock both sides of the point/confirmation boundary:
bootstrap cannot create an attribution absent from the point gate, while fixed-seed
decouplings remain positively isolated and at least one is confirmed with the default
bootstrap configuration and a negative upper confidence endpoint. A separate test proves
that positive PID evidence beside an insufficient PID axis becomes
`UnclassifiedAnomaly` when no complete signed result independently establishes the same
attribution. When all signed-correlation axes independently agree, matching partial PID
evidence cannot erase that complete signed default.

## Remaining scientific boundary

This migration establishes source/API compatibility and synthetic continuity only. It
does not prove that CREBAIN residuals are regular full-dimensional, approximately i.i.d.,
adequately sampled, insensitive to observation-noise scale, or calibrated for the selected
windows. PID remains opt-in, sign-invariant, advisory, and unable to widen authority. A
representative calibration/locked-holdout campaign is still required before any operational
policy may consume it.
