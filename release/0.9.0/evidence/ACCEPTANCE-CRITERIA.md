# Galadriel 0.9 candidate-evidence acceptance criteria

Owner: **Sepehr Mahmoudian**

Declared: 2026-07-14, before the 0.9 candidate evidence run

Scope: synthetic and retained-fixture evidence only

These criteria decide whether Galadriel 0.9 may make a bounded synthetic
validation claim. They do not qualify a deployment, establish physical sensor
truth, infer malicious intent, or authorize control action. A failed criterion is
published as a negative result and removes or narrows the affected claim; it is
not repaired by silently changing this threshold, excluding a valid trial, or
selecting another seed.

## Non-blind declaration

This declaration is not a blind preregistration. The earlier retained
`post-audit-v1-8a0084f` results were known when these thresholds were written.
Those results showed approximately 26 false-alert episodes/hour on the clean
independent arm, mission false-alarm probability near 0.92, and fused abstention
near 0.99 under the modeled ordinary-missingness arm. They are unacceptable and
remain public. The 0.9 candidate run uses a new named configuration identity and
seed partition; it may test whether correctness changes alter the result, but it
may not erase the earlier failure region.

## Frozen decision rules

All confidence limits are two-sided 95% intervals unless the retained evidence
schema explicitly labels a one-sided bound. Episode rates use the exact Garwood
Poisson interval under the declared homogeneous-rate model, conservatively
enveloped by a whole-track bootstrap when its predeclared usable-replicate rule is
met. Binary probabilities use Wilson score intervals. Bootstrap seeds are
deterministic and recorded. The pooled post-warm-up abstention estimand uses a
distribution-free weighted-track Hoeffding interval over independent bounded
track fractions, so dependent assessments within a track are not treated as
independent Bernoulli trials. A criterion passes only when its conservative
bound passes; point-estimate-only success is insufficient.

| ID | Estimand and eligible arm | Acceptance rule |
|---|---|---|
| GLD-090-ACC-001 | Clean-null false-alert episodes per eligible recorded hour, with episodes separated by the declared reset policy | upper 95% bound **≤ 0.10 episodes/hour** |
| GLD-090-ACC-002 | Probability of at least one false alert in the declared 3,600-frame clean mission (359.9 s first-to-last timestamp span) | upper 95% Wilson bound **≤ 0.05** |
| GLD-090-ACC-003 | Detection probability after attack onset for each individually claimed loud-bias, broadband-inflation, and full moment-matched-decoupling arm | lower 95% Wilson bound **≥ 0.90** for every claimed arm |
| GLD-090-ACC-004 | Conditional time to first alert among detected eligible attack tracks | empirical 95th percentile **≤ 10,000 ms**, with the undetected fraction reported separately under ACC-003 |
| GLD-090-ACC-005 | Attribution error among eligible tracks for which the generator defines one unique altered modality and the detector emits an attribution | upper 95% Wilson bound **≤ 0.10**; coverage/abstention is reported separately and cannot be discarded |
| GLD-090-ACC-006 | Pooled fused abstention fraction on complete, projection-valid clean tracks after warm-up | upper 95% weighted-track Hoeffding bound **≤ 0.05** |
| GLD-090-ACC-007 | Pooled fused abstention fraction under the declared ordinary independent-missingness model after warm-up | upper 95% weighted-track Hoeffding bound **≤ 0.50** |

### Exact detector and condition resolution

The clean reference for ACC-001, ACC-002, and ACC-006 is the unique holdout
`clean_autocorrelation` condition with `phi = 0` and `covariance_scale = 1`.
ACC-001 and ACC-002 must pass separately for `nis_baseline` and
`default_correlation_fusion`; ACC-006 applies to `default_correlation_fusion`.
ACC-007 applies to `default_correlation_fusion` on the unique
`ordinary_missingness` holdout condition.

ACC-003 and ACC-004 must pass for both detectors on the loud-acoustic and
broad-degradation holdout arms. They apply only to
`default_correlation_fusion` on the moment-matched stealthy-acoustic arm because
the NIS baseline is the predeclared negative control for that construction.
ACC-005 applies to `default_correlation_fusion` on both unique-acoustic targeted
arms. Baseline attribution remains reported, but no baseline success is required
for the moment-matched arm.

Every required metric must be unique, `estimated`, based on at least
`min_metric_eligible_tracks`, and carry the applicable conservative confidence
bound. A missing, duplicate, ineligible, or non-estimable metric fails its
criterion. The evaluator records every component comparison; it does not average
detectors, conditions, or bounds to manufacture a pass.

The moment-matched-decoupling arm may be removed from an affirmative detection
claim if it fails ACC-003, but its negative result and attack definition remain in
the retained report. Weak-decoupling sweeps, autocorrelation, covariance-scale,
colluding-majority, common-mode, frame/unit swap, stale-prior, route-confusion,
and gating-censorship arms are sensitivity/failure-region campaigns. They require
complete reporting but have no post-hoc pass threshold in 0.9 unless a separate
dated declaration precedes their run.

## Eligibility and missing data

- Trial, seed, condition, track identity, configuration digest, and generator
  digest are fixed before observations are generated.
- Calibration and holdout seed domains are disjoint. Only the holdout partition
  contributes to acceptance decisions.
- A track is metric-eligible only under the rules encoded before execution.
  Parser, provenance, reset, internal, or resource faults remain counted and are
  reported by category; they may not be converted to nominal evidence or dropped.
- Detection delay is conditional by definition, so ACC-003 prevents fast results
  on a small detected subset from masking widespread non-detection.
- Attribution error and attribution coverage are both reported. An abstention is
  not an attribution error, and it is not a success.
- Confidence procedures, bootstrap count, minimum eligible-track count, mission
  duration, assessment cadence, and episode-reset semantics are configuration
  inputs included in the canonical evidence digest.

## Planned candidate design

The candidate input will retain at least 20 calibration tracks and 100 holdout
tracks per applicable condition, 3,600 frames/track, 100 ms/frame (a 359.9 s
first-to-last timestamp span), assessment every 10 frames, attack onset at frame
1,800, a 3,600-frame mission, and at least
1,000 deterministic bootstrap resamples. The accepted configuration constructor
must prove the complete observation, correlation, assessment, and bootstrap work
budgets before creating an output directory. The final JSON configuration and its
SHA-256 digest are added to the signed candidate manifest before execution.

If resource preflight rejects that design, the run is `NO_RUN`; the sample size is
not reduced silently. Any revised design requires a new dated criteria document
that retains this one and explains the change.

### Pre-run resolution audit

The checked candidate configuration provides 100 holdout tracks with a 359.9 s
first-to-last timestamp span for each clean detector condition, or approximately
9.9972 eligible track-hours per detector before any exclusion. Even with zero
alert episodes, the declared two-sided 95% Garwood upper limit is approximately
`3.688879 / 9.9972 = 0.368990` episodes/hour. Therefore
this design cannot pass ACC-001's `0.10` upper-bound rule. This is a retained
negative design result, not permission to weaken the threshold, switch intervals,
pool calibration data, or increase exposure after seeing outcomes. The run remains
useful for the other criteria and failure-region estimates; ACC-001 must be marked
`FAIL` and the affected rate claim removed for 0.9.0.

## Release disposition

- All seven rules passing permits a `VALIDATED` claim only for the exact synthetic
  models, fixture, configuration, code commit, toolchain, and host evidence.
- Any failure produces `NARROWED_GO` or `NO_GO` for the affected claim. Operational
  thresholds remain `NOT_CLAIMED` regardless of synthetic success.
- No result in this study creates a DOI/Zenodo record, a crates.io publication, a
  production-support promise, or deployment authority.
