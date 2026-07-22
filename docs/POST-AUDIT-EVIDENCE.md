# Post-audit evidence runner

## Abbreviations

| Short form | Meaning |
|---|---|
| SHA-256 | Secure Hash Algorithm 256 |

`galadriel-evidence` is the bounded and reproducible evidence path for two product detectors.
They are the streaming Normalized Innovation Squared (NIS) baseline and the default signed-correlation fusion.
Run this command from the repository root:

```sh
cargo run --locked -p galadriel-eval --release --bin galadriel-evidence -- \
  --config evidence/post-audit-v1.json \
  --out target/evidence/post-audit-v1
```

The output directory must not exist before the run.
This rule prevents a new run from mixing with earlier evidence or overwriting it.
Publication runs also require a clean Git worktree.
Use `--allow-dirty` only for development smoke runs.
The manifest records this option.

The command-line interface (CLI) immediately converts the option to `PublicationSourcePolicy::{RequireClean, PermitDirtyWithAudit}`.
The accepted runner does not retain a configuration Boolean.

## Published research snapshot

The repository includes a clean-source reference run at [`evidence/results/post-audit-v1-8a0084f`](../evidence/results/post-audit-v1-8a0084f).
Its manifest binds the artifacts to commit `8a0084f`.
It records `dirty=false`.
It hashes the configuration, lockfile, recorded fixture, runner binary, and each output file.

That retained diagnostic snapshot uses the historical trial-v1 numeric-seed wire.
It is not a trial-v3 artifact.
The current runner's exact-string schema applies only to newly generated output.

This snapshot is not a pass or fail acceptance artifact.
The independent clean arm reports 26.26 alert episodes/hour.
It reports a 0.9167 mission probability of any alert.
Positive autocorrelation further increases the episode rate.
Ordinary acoustic missingness produces 99.35% fused monitoring abstention.
Thus, the current pointwise defaults are not stream-calibrated for operational use.

## Artifact contract

One command writes these files:

- `config.json` contains the complete normalized accepted run configuration.
  `base_seed` and `base_seed_decimal` contain the same canonical unsigned-decimal string.
  `base_seed_hex` contains its fixed-width lowercase `0x` form with 16 hexadecimal digits.
- `trials.jsonl` contains one `galadriel.evidence.trial.v3` record for each track and detector.
  Each record includes truth, run-length verdict trace, alert episodes, abstentions, and extraction status.
  It also includes the pre-onset-alert flag, conditional delay, and attribution result.
  Synthetic rows encode `seed` as an exact unsigned-decimal JavaScript Object Notation (JSON) string.
  They encode `seed_hex` as fixed-width lowercase hexadecimal.
  Recorded-fixture rows use `null` for both fields.
  `track_id` remains a JSON-safe integer.

  `track_id_hex` is its fixed-width hexadecimal mirror.
- `summary.json` keeps calibration diagnostics and holdout results in separate arrays.
  It includes point estimates and boundary-safe 95% intervals.
- `report.md` contains a compact holdout report and interpretation limits.
- `manifest.json` records the Git commit, dirty state, Rust toolchain, Cargo toolchain, and build profile.
  It also records input hashes, binary hashes, platform, study scope, and record counts.
- `SHA256SUMS` contains checksums for each artifact above.

The runner resolves relative fixture paths from the configuration file directory.
It rejects unknown configuration fields, invalid ranges, excessive work, and duplicate keys.
It also rejects a fixture when its SHA-256 does not match the declared value.

The runner consumes the raw data transfer object (DTO) once.
It creates an immutable accepted configuration.
This configuration contains the release suite, bounded vectors, verified fixture bytes, work estimates, and a canonical digest.

New candidate input files must write `base_seed` as an exact unsigned-decimal JSON string.
The strict decoder still accepts a JSON unsigned-integer token for the retained historical configuration.
It normalizes each newly serialized accepted configuration to the string form above.
That compatibility path does not make binary64 parsing safe.
JavaScript and similar consumers must use the decimal or hexadecimal string fields.

## Study design

Each synthetic track has a separate deterministic seed domain for calibration and holdout.
Detector thresholds are fully declared before either partition runs.
Calibration results are descriptive diagnostics in this first vertical slice.
They do not tune the thresholds.
The runner never pools them with holdout results.

The clean stream uses three modalities and producer-attested common signed residual projections.
It exercises independent residual streams and first-order autoregressive (AR(1)) residual streams.
It also exercises declared-covariance scales and ordinary acoustic missingness.

Holdout-only perturbations include these conditions:

- a loud acoustic NIS shift
- an in-covariance acoustic decoupling
- a broad all-modality NIS shift
- missing projections
- contradictory prior provenance

The covariance sensitivity grid must include the exact `1.0` reference.
Each non-reference scale must differ from it by at least `0.01`.
This difference is a one-percent declared covariance shift.
Exact normalized IEEE-754 bits are part of each floating-point condition identifier.
This representation prevents close valid arms from colliding.

Hexadecimal seed and track mirrors remain available.
Trial schema v3 already uses a lossless decimal string for its primary `seed`.
The accepted configuration also provides lossless decimal and hexadecimal base-seed strings.
Numeric track identifiers use Galadriel's separate JSON-safe integer domain.

False-alert evidence includes alert episodes per pooled exposure hour.
It includes the mission probability of any alert.
It also includes finite-horizon restricted average run length under the null (ARL0) and its censoring fraction.

Attack detection delay and exact channel attribution are conditional on no pre-onset alert.
Delay and attribution are also conditional on detection.
Abstention is the pooled fraction of assessments with `insufficient_evidence` or `rejected_input` outcomes.
Invalid provenance produces the explicit `rejected_input` trace outcome.
An absent projection remains insufficient.

The headline abstention metric uses only post-warm-up monitoring assessments.
Per-trial records retain separate startup and monitoring numerators, denominators, and fractions.
They also retain realized observation and missing-frame counts for each modality.

The configured `nominal_only` policy controls alert-episode reset.
An active alert persists across insufficient or rejected-input assessments for episode counting.
Only a subsequent explicit nominal assessment clears the alert.
This rule prevents evidence outages from creating artificial alert recoveries and repeat episodes.

Bootstrap resampling always samples complete tracks.
It never resamples frames as if autocorrelated observations were independent.
Per-track binomial proportions use Wilson score intervals.
The pooled post-warm-up abstention estimate is the exception.

Episode rates use exact Garwood Poisson intervals.
The report labels their homogeneous-rate assumption.
The runner conservatively envelopes analytic intervals with a bootstrap interval when at least 80% of requested replicates are usable.
The resampling unit is the complete track.

Restricted ARL0 and post-warm-up abstention also use distribution-free bounded-track Hoeffding intervals.
These intervals prevent all-censored or all-zero samples from producing false population certainty.
Delay uses the whole-track bootstrap directly.
Sparse delay medians keep a descriptive point value.
They use `not_estimable_sparse` and have no confidence interval.

The configuration requires at least 200 requested bootstrap resamples.
It also declares the minimum detected-track count for an inferential delay interval.

The default clean holdout has 24 tracks of 359.9 seconds for each condition.
This duration is about 2.40 track-hours for each condition.
It is 14.40 hours across six distinct sensitivity conditions.
The report prints the exposure for each condition.
Do not overstate or pool exposure across stress conditions as one homogeneous operating environment.

## Recorded fixture boundary

A hash pins the checked-in Crebain capture.
It lasts only about 15.8 seconds.
It has no producer-attested consistency projection.

The runner uses a default minimum duration of one hour.
It records the fixture as `not_estimable`.
It gives `insufficient_duration` and `missing_consistency_projection` as reasons.
The fixture supports parser, provenance, and fail-closed abstention smoke coverage only.

The report does not extrapolate a false-alert rate from this fixture.
It does not extrapolate operational availability or a detection claim.
Missing projection invalidates only the default fused evidence.
The baseline trial remains independently usable if a future hash-pinned capture meets the configured duration threshold.

## Interpretation boundary

The simulator produces controlled synthetic stress tests.
They do not represent a deployed residual population.
The configured per-assessment family alpha is not a stream-level false-alert guarantee.

The runner intentionally excludes Partial Information Decomposition (PID).
This repository revision exposes PID as a terminal whole-replay experiment.
Adding a streaming cadence creates evidence for behavior that the product does not implement.
