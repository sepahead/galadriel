# Post-audit evidence runner

`galadriel-evidence` is the bounded, reproducible evidence path for the streaming
NIS baseline and the product-default signed-correlation fusion. From the repository
root, run:

```sh
cargo run --locked -p galadriel-eval --release --bin galadriel-evidence -- \
  --config evidence/post-audit-v1.json \
  --out target/evidence/post-audit-v1
```

The output directory must not already exist. This prevents a new run from silently
mixing with or overwriting earlier evidence. Publication runs also require a clean
Git worktree. `--allow-dirty` exists only for development smoke runs and is recorded
in the manifest.

## Published research snapshot

The repository includes a clean-source reference run at
[`evidence/results/post-audit-v1-8a0084f`](../evidence/results/post-audit-v1-8a0084f).
Its manifest binds the artifacts to commit `8a0084f`, records `dirty=false`, and hashes
the configuration, lockfile, recorded fixture, runner binary, and every output file.

This is not a pass/fail acceptance artifact. The independent clean arm reports 26.26
alert episodes/hour and a 0.9167 mission probability of any alert; positive
autocorrelation increases the episode rate further, and ordinary acoustic missingness
produces 99.35% fused monitoring abstention. The result therefore demonstrates that the
current pointwise defaults are not stream-calibrated for operational use.

## Artifact contract

One command writes:

- `config.json`: the complete, normalized run configuration;
- `trials.jsonl`: one machine-readable record per track and detector, including
  the seed, truth, run-length verdict trace, alert episodes, abstentions, extraction
  status, pre-onset-alert flag, conditional delay, attribution result, and lossless
  hexadecimal forms of every `u64` seed and track identifier;
- `summary.json`: calibration diagnostics and holdout results kept in separate
  arrays, with point estimates and boundary-safe 95% intervals;
- `report.md`: a compact holdout report and interpretation limits;
- `manifest.json`: Git commit and dirty state, Rust/Cargo toolchains, build profile,
  input and binary hashes, platform, study scope, and record counts; and
- `SHA256SUMS`: checksums for every artifact above.

Relative fixture paths are resolved against the configuration file's directory.
The runner rejects unknown configuration fields, invalid ranges, excessive work,
and a fixture whose SHA-256 does not match the declared value.

## Study design

Every synthetic track has a disjoint deterministic seed domain for calibration and
holdout. Detector thresholds are fully declared before either partition is run.
Calibration results are descriptive diagnostics in this first vertical slice; they
do not tune the thresholds and are never pooled with holdout results.

The clean stream uses three modalities and producer-attested common signed residual
projections. It exercises independent and AR(1) residual streams, declared-covariance
scales, and ordinary acoustic missingness. Holdout-only perturbations include a loud
acoustic NIS shift, an in-covariance acoustic decoupling, a broad all-modality NIS
shift, missing projections, and contradictory prior provenance.

The covariance sensitivity grid must include the exact `1.0` reference, and every
non-reference scale must differ from it by at least `0.01` (a one-percent declared
covariance shift). Exact normalized IEEE-754 bits are part of each floating-point
condition identifier, so close valid arms cannot collide. Hexadecimal seed and
track strings are the lossless form for JavaScript and other consumers whose JSON
number path cannot represent every `u64` exactly.

False-alert evidence is reported as alert episodes per pooled exposure hour,
mission probability of any alert, and finite-horizon restricted ARL0 with its
censoring fraction. Attack detection delay and exact channel attribution are
conditional on no pre-onset alert; delay and attribution are additionally
conditional on detection. Abstention is the pooled fraction of assessments whose
outcome is `insufficient_evidence` or `rejected_input`. Invalid provenance produces
the latter explicit trace outcome; a merely absent projection remains insufficient.
The headline abstention metric uses post-warm-up monitoring assessments only.
Per-trial records separately retain startup and monitoring numerators, denominators,
and fractions, plus realized observation and missing-frame counts per modality.

The configured `nominal_only` alert-episode reset policy means an active alert
persists across insufficient or rejected-input assessments for episode counting.
Only a subsequent explicit nominal assessment clears it. This avoids turning an
evidence outage into artificial alert recoveries and repeat episodes.

Bootstrap resampling always samples complete tracks. It never resamples frames as
if autocorrelated observations were independent. Track-level proportions use Wilson
score intervals, and episode rates use exact Garwood Poisson intervals with their
homogeneous-rate assumption labeled. When at least 80% of requested whole-track
bootstrap replicates are usable, the runner conservatively envelopes those analytic
intervals with the bootstrap interval. Restricted ARL0 and post-warm-up abstention
also use distribution-free bounded-track Hoeffding intervals, preventing all-censored
or all-zero samples from collapsing to false population certainty. Delay uses the
whole-track bootstrap directly. Sparse delay medians keep a descriptive point value
but are explicitly marked `not_estimable_sparse` without a confidence interval.
The configuration requires at least 200 requested bootstrap resamples and declares
the minimum detected-track count for an inferential delay interval.

The default clean holdout contains 24 tracks of 359.9 seconds per condition: about
2.40 track-hours per condition and 14.40 hours across six distinct sensitivity
conditions. The per-condition exposure is printed in the report and must not be
overstated or pooled across different stress conditions as though it were one
homogeneous operating environment.

## Recorded fixture boundary

The checked-in Crebain capture is hash-pinned but lasts only about 15.8 seconds and
contains no producer-attested consistency projection. With the default one-hour
minimum, the runner records it as `not_estimable` with
`insufficient_duration` and `missing_consistency_projection` reasons. It is useful
for parser, provenance, and fail-closed abstention smoke coverage only. The report
does not extrapolate a false-alert rate, operational availability, or detection
claim from it. Missing projection invalidates the default fused evidence only; the
baseline trial remains independently usable if a future hash-pinned capture meets
the configured duration threshold.

## Interpretation boundary

The synthetic results are controlled stress tests, not a deployed residual
population. The configured per-assessment family alpha is not a stream-level false
alert guarantee. PID is intentionally absent: this repository revision exposes PID
as a terminal whole-replay experiment, so assigning it a streaming cadence here
would create evidence for behavior the product does not implement.
