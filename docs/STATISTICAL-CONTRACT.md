# Statistical contract and estimands

This document is normative for reports from Galadriel 0.9.0. An estimand is the
exact population quantity or decision function. This term does not imply that a
deployment satisfies the identification assumptions.

## General contract

**GLD-090-STAT-001:** Every reported scalar **SHALL** use the definition in this
document. Every decision **SHALL** be a deterministic function of validated inputs
and the immutable active configuration. A human-readable `note` **SHALL NOT** be
parsed as a stable statistic or policy signal.

**GLD-090-STAT-002:** Every verdict **SHALL** describe statistical consistency
evidence. It **SHALL NOT** describe sensor truth, malicious intent, a causal
attack class, or a posterior probability. `calibrated_posterior` is always false.

**GLD-090-STAT-003:** Cross-modal estimands **SHALL** use observations with these
common properties:

- one track
- equal fusion sequence
- one producer-declared physical frame
- one projection context
- one frozen pre-update prior for each sequence

The calculation **SHALL NOT** substitute native residual coordinates, unequal
ordinal tails, post-update priors, or censored successful-update-only captures.

Let `y` be the pre-update innovation. Let `S` be its innovation covariance. An
input NIS is `q = yᵀ S⁻¹ y`. The model reference is `q ~ χ²(d)` for declared
degrees of freedom `d`.

This reference requires correct covariance, association, linearization, model
adequacy, and an uncensored observation opportunity. Galadriel validates
representation and bounds. It does not validate these physical assumptions.

The window-sum reference has one more requirement. Under the null, the model must
make the retained `qᵢ` values independent. An independently justified model can
replace this assumption if its sum has the stated χ² distribution.

Bonferroni control across channels does not remove the within-channel
serial-dependence assumption.

## Magnitude report

For one modality, use the retained contiguous window `q₁,…,qₙ`.

- `n` is the exact retained sample count.
- `dof` is the immutable `d` for that track and modality epoch.
- `sum_nis = min(Σ qᵢ, f64::MAX)`.
- If the sum is representable, `mean_nis = sum_nis / n`.
- Otherwise, scale each sample by the window maximum before summation. This method
  keeps the finite mathematical mean representable.
- Both values are `0` for an absent expected channel.
- Saturation prevents a finite extreme anomaly from becoming a numeric error.
- `p_right = Pr[X ≥ sum_nis]` for `X ~ χ²(n d)`. Evaluate it directly as an
  upper tail. For `n=0`, it is `1`.
- The per-channel threshold is `nis_alpha / C`. Here, `C` is the number of known
  or expected channels in that assessment.
- `elevated` is exactly `n>0 && p_right < nis_alpha/C`. Equality is not elevated.

The two CUSUM inputs are `x=q/sqrt(2d)` and target `μ=d/sqrt(2d)`. Both arms start
at zero. After each sample, update the arms as follows:

```text
hi=max(0, hi+x-μ-k)
lo=max(0, lo+μ-x-k)
```

The configured slack is `k`. An arm alarms when its accumulator is greater than
or equal to threshold `h`. A component reset sets both arms to zero.

Ordinary threshold alarms describe the current arms. They can decay and are not
separately latched. An exact arm update can exceed `f64::MAX`. In that case, the
arm stays at `f64::MAX` until reset. The system cannot retain the unbounded excess
for a subsequent opposing update.

`cusum_high_alarm` and `cusum_low_alarm` are exactly the resulting arm predicates.
The state is historical sequential evidence. It is not a p-value.

- `last_seq` and `last_timestamp_ms` are the newest accepted identities.
- `fresh` requires an existing difference between assessment sequence and
  `last_seq`. That difference must be at most `max_seq_gap`.
- `ready` means
  `n >= min_samples && fresh && last_seq == assessment_seq`.
- A complete assessment requires every known or expected channel to be ready.
- It also requires at least `min_channels`.
- The newest timestamp span must not exceed `max_timestamp_skew_ms`.

`ChannelReport::high_anomalous` is
`ready && (elevated || cusum_high_alarm)`. `anomalous` also includes the low CUSUM
arm.

`MirrorReport.track_id` and `seq` identify the requested assessment. The report
sorts `channels` by modality. `note` is explanatory and non-normative.

Magnitude verdicts use this exact order:

1. Return `UnclassifiedAnomaly` when a ready anomaly exists with incomplete
   evidence, or when a low arm alarms.
2. Otherwise, return `InsufficientEvidence` when complete evidence is absent.
3. Otherwise, return `Nominal` when no high anomaly exists.
4. Otherwise, return `BroadDegradation` when at least two high anomalies satisfy
   `high_count >= jam_fraction * ready_count`.
5. Otherwise, return `AttributedInconsistency {channels}` for the sorted
   high-anomaly set.

“Attributed” locates evidence. It does not identify a cause.

`Mirror::from_release_suite` consumes a validated and nonempty expected-modality
capability. Subset-only analysis requires `Mirror::for_exploratory_subset` and an
`ExploratorySubsetResearch` capability. The report classifies this analysis as
research. It is not interchangeable with the release-suite path.

`MirrorReport` and `ChannelReport` are sealed output-only values. They serialize
diagnostics. They do not deserialize, expose mutable fields, or have unchecked
public constructors.

Each channel contains `dof`, `sum_nis`, and its effective `channel_alpha`. Each
magnitude report contains the release or research classification. It also contains
the canonical digest of the complete accepted detector or suite.

Assessment creates the private typed `AssessmentOutcome`. Fusion retains this
value instead of reconstructing it from report material. `validated_outcome()`
marks a release-classified magnitude-only `Nominal` as unavailable. It remains
unavailable until the signed-consistency prerequisite is complete.

## Signed-correlation report

For each valid projection axis and aligned pair, `pearson` is the sample signed
Pearson correlation. The columns must be finite and non-degenerate. Center and
scale each range independently before calculation.

`CorrChannel.n` is the common tail length. `corroboration` is the largest signed
pair correlation for that channel. It is `None` when the pairwise estimand is not
available. `decoupled` identifies membership outside the one admitted consensus
clique.

The pair family threshold is the maximum of these values:

- configured `corr_floor`
- `decouple_ratio * max_pair_rho`
- the one-sided Fisher-z threshold with `family_alpha / pair_count`

A verdict requires all these conditions:

- at least three unique modalities
- equal lengths
- sufficient samples
- finite and non-degenerate columns
- a usable threshold
- exactly one all-pairs positive clique that contains a strict majority

An outsider can have a threshold-clearing bridge to that clique. This condition
makes attribution ambiguous. `Nominal` means that the unique clique contains all
requested channels. `Decoupled` identifies each unbridged outsider. All other
admissible but unidentifiable states are `InsufficientEvidence`. `note` is
explanatory only.

In the default multi-axis report, `AxisCorrelationReport.axis` identifies the
zero-based producer projection coordinate. Its `report` contains the preceding
estimand. The family budget is divided across active axes.

Positive axes can disagree. A positive axis can also occur with an insufficient
axis. Fusion classifies either condition as unclassified evidence.

An axis report from `prepare_release_assessment` also contains the exact
whole-stream `AssessmentBinding`. `single_axis` and `try_new` remain explicitly
unbound compatibility diagnostics. They cannot replace an axis in an accepted
report.

## Fused report

`MagnitudeEvidence` records the state of each consistency-attributed channel. The
state is `InCovariance`, `Elevated`, a `Mixed` set, or unavailable
(`Insufficient`).

`ConsistencyEvidence` is a typed state. It is `Intact`, nonempty `Decoupled`,
`Insufficient`, or `Conflicted`. It cannot encode confident positive evidence and
insufficiency at the same time.

`FusedVerdict` deterministically combines the full `MirrorReport` and consistency
evidence. Apply these rules:

- Conflicting positive attributions become `UnclassifiedAnomaly`.
- Dual insufficiency becomes `InsufficientEvidence`.
- Positive consistency evidence becomes `AttributedInconsistency` with its
  magnitude class.
- Otherwise, preserve the magnitude verdict.
- As one exception, nominal magnitude with insufficient consistency remains
  insufficient.

`DefaultReport` retains the verdict and entire magnitude report. It also retains
each axis report, a non-normative note, complete suite identity, classification,
and one shared opaque `AssessmentBinding`.

The core binding is a domain-separated SHA-256 identity. It covers the canonical
complete `ReleaseSuite` and every field of each ordered input observation. The
fields include track, timestamp, sequence, modality, NIS, and degrees of freedom.
They also include optional innovation, optional covariance, and all projection
values and provenance fields.

Callers can compare the binding or verify it against an exact stream and suite.
They cannot create one or attach it to replacement reports.
`combine_correlation_axes` can return an unbound diagnostic tuple when all inputs
are unbound. It rejects mixed bindings. It does not return a sealed
`DefaultReport`.

## Optional PID research report

PID is not part of the stable core surface or a deployment claim. When compiled,
pairwise `estimate_nats` is the upstream report-first KSG mutual-information point
estimate. It applies to the declared regular, full-dimensional, continuous support
contract. `n_samples` and `k` are the actual estimator inputs.

The attached interpretation **SHALL NOT** be dropped when a scalar is retained.
It includes this information:

- typed support
- method and scientific status
- assumption ledger
- warnings
- provenance hashes
- preprocessing, observation, and sampling descriptions
- resource estimate

For each channel, `corroboration` is its best safely estimated pairwise MI in
nats.

`redundancy` and `synergy` are experimental shared-exclusions PID2 atoms in nats.

`gate_ok` and `gate_note` record estimator admissibility.

`ci` is the circular delete-block interval for the worst candidate-to-consensus
confirmation margin.

The configured clique and confirmation procedure alone can admit `decoupled`.

`PidVerdict` has three meanings.

`Nominal` means all requested channels are admitted.

`Decoupled` means a strict minority is confirmed outside.

`InsufficientEvidence` means no defensible attribution is available.

PID atoms are diagnostics. They are not a posterior or a standalone causal
verdict.

PID work requires an explicit accepted `PidResearchSuite`. It contains a PID-free
`ReleaseSuite` and one underived `PidConfig`. Construction checks the worst-case
three-axis quadratic-fit product before it reads observations. The system checks
the actual axis family and divides it exactly once before estimator use.

`PidConfigDigest` includes all accepted scalar values. It includes the confirmation
variant and applicable payload. It also includes named or custom classification,
axis-family derivation, fixed resource ceilings, and exact upstream semantics and
revision. Each `PidReport` carries that identity through sealed estimator
evidence.

These types are sealed output values:

- `PidEstimatorEvidence`
- `ChannelPid`
- `PidReport`
- `AxisPidReport`
- `FusedReport`

PID fusion checks one accepted research suite against the baseline and all
correlation and PID axes. Mixed identities are errors. Duplicate, non-contiguous,
or out-of-range axes are also errors, not evidence.

The fused PID report contains suite identity and classification. It retains the
magnitude, signed-correlation, and PID axes. It adds `PidAssessmentBinding`, which
binds the core assessment to the complete PID research suite.

Sign-invariant PID cannot erase positive signed-correlation evidence. A PID
nominal result cannot repair unavailable signed-correlation evidence. Complete
and conflict-free signed attribution can remain advisory evidence when optional
PID axes are insufficient. The report retains the incomplete PID evidence.

## Repeated use and missingness

The current window p-value controls one modeled assessment family. It does not
control an unlimited stream. Overlapping windows and persistent CUSUM state create
repeated looks. Censoring from association and gates is not missing at random.
Sensor silence is also not missing at random.

Thus, 0.9.0 **SHALL NOT** describe any of these values as a mission-level
false-alert guarantee:

- `nis_alpha`
- `family_alpha`
- bootstrap intervals
- synthetic rates
- a single assessment

The operational source profile remains research and advisory. Mission-level
operational qualification is `NOT_CLAIMED`.
