# Statistical contract and estimands

This document is normative for the reports emitted by Galadriel 0.9.0. The word
“estimand” identifies the exact population quantity or decision functional; it
does not imply that the assumptions required to identify it hold in a deployment.

## General contract

**GLD-090-STAT-001:** Every reported scalar **SHALL** have the definition below,
and every decision **SHALL** be a deterministic function of validated inputs and
the immutable active configuration. A human-readable `note` **SHALL NOT** be
parsed as a stable statistic or policy signal.

**GLD-090-STAT-002:** Every verdict **SHALL** describe statistical consistency
evidence, not sensor truth, malicious intent, a causal attack class, or a posterior
probability. `calibrated_posterior` is always false.

**GLD-090-STAT-003:** Cross-modal estimands **SHALL** use observations for one
track, equal fusion sequence, one producer-declared physical frame and projection
context, and one frozen pre-update prior per sequence. Native residual coordinates,
unequal ordinal tails, post-update priors, and censored successful-update-only
captures **SHALL NOT** be substituted.

Let `y` be the pre-update innovation and `S` its innovation covariance. An input
NIS is `q = yᵀ S⁻¹ y`. The model reference is `q ~ χ²(d)` for declared
degrees of freedom `d`; this reference requires correct covariance, association,
linearization/model adequacy and an uncensored observation opportunity. Galadriel
validates representation and bounds, not those physical assumptions.
The window-sum reference additionally requires the retained `qᵢ` values to be
independent under the null (or an independently justified model under which their
sum has the stated χ² distribution). Bonferroni control across channels does not
remove this within-channel serial-dependence assumption.

## Magnitude report

For one modality's retained contiguous window `q₁,…,qₙ`:

- `n` is the exact retained sample count.
- `dof` is the immutable `d` declared for that track/modality epoch.
- `sum_nis = min(Σ qᵢ, f64::MAX)`. When the sum is representable,
  `mean_nis = sum_nis / n`; otherwise the mean is evaluated by scaling every
  sample by the window maximum before summation, so the finite mathematical mean
  remains representable. Both are `0` for an absent expected channel.
  Saturation prevents a finite extreme anomaly from becoming a numeric error.
- `p_right = Pr[X ≥ sum_nis]` for `X ~ χ²(n d)`, evaluated directly as an
  upper tail. For `n=0`, it is `1`.
- The per-channel threshold is `nis_alpha / C`, where `C` is the number of known
  or expected channels in that assessment. `elevated` is exactly
  `n>0 && p_right < nis_alpha/C`; equality is not elevated.
- The two CUSUM inputs are `x=q/sqrt(2d)` and target `μ=d/sqrt(2d)`. Both arms
  start at zero. After each sample, `hi=max(0, hi+x-μ-k)` and
  `lo=max(0, lo+μ-x-k)`, with configured slack `k`; an arm alarms when its
  accumulator is greater than or equal to threshold `h`. A component reset sets
  both arms back to zero. Ordinary threshold alarms describe the current arms and
  can decay; they are not separately latched. If an exact arm update exceeds
  `f64::MAX`, however, that arm is terminally saturated at `f64::MAX` until reset,
  because the otherwise unbounded excess cannot be retained for a later opposing
  update. `cusum_high_alarm` and `cusum_low_alarm` are exactly the resulting arm
  predicates. The state is historical sequential evidence, not a p-value.
- `last_seq` and `last_timestamp_ms` are the newest accepted identities;
  `fresh` means assessment sequence minus `last_seq` exists and is at most
  `max_seq_gap`.
- `ready` means
  `n >= min_samples && fresh && last_seq == assessment_seq`. A complete assessment
  additionally requires every known/expected channel ready, at least
  `min_channels`, and newest timestamps spanning no more than
  `max_timestamp_skew_ms`.

`ChannelReport::high_anomalous` is `ready && (elevated || cusum_high_alarm)`;
`anomalous` additionally includes the low CUSUM arm. `MirrorReport.track_id` and
`seq` identify the requested assessment; `channels` is sorted by modality;
`note` is explanatory, non-normative text.

Magnitude verdicts are exact:

- `UnclassifiedAnomaly` when any ready anomaly exists and complete evidence is
  absent or any low arm alarms.
- otherwise `InsufficientEvidence` when complete evidence is absent;
- otherwise `Nominal` when no high anomaly exists;
- otherwise `BroadDegradation` when at least two high anomalies also satisfy
  `high_count >= jam_fraction * ready_count`;
- otherwise `AttributedInconsistency {channels}` for the sorted high-anomaly set.

These branches are ordered. “Attributed” locates evidence; it does not identify a
cause. `Mirror::from_release_suite` consumes a validated, non-empty expected-modality
capability. Subset-only analysis is available only through
`Mirror::for_exploratory_subset` plus an `ExploratorySubsetResearch` capability and
is classified as research in the report. It is not interchangeable with the
release-suite path.

`MirrorReport` and `ChannelReport` are output-only sealed values. They serialize
diagnostics but do not deserialize, expose mutable fields, or offer unchecked public
constructors. Every channel includes `dof`, `sum_nis`, and its effective
`channel_alpha`; every magnitude report carries the release/research classification
and canonical digest of the complete accepted detector or suite. The private typed
`AssessmentOutcome` is created during assessment and retained for fusion rather
than reconstructed from report material. A release-classified magnitude-only
`Nominal` is exposed by `validated_outcome()` as unavailable until the signed-
consistency prerequisite has completed.

## Signed-correlation report

For each valid projection axis and pair of aligned finite non-degenerate columns,
`pearson` is the sample signed Pearson correlation after independent range-centering
and scaling. `CorrChannel.n` is the common tail length and `corroboration` is the
largest signed pair correlation for that channel. It is `None` when the pairwise
estimand cannot be formed. `decoupled` names membership outside the one admitted
consensus clique.

The pair family threshold is the maximum of configured `corr_floor`,
`decouple_ratio * max_pair_rho`, and the one-sided Fisher-z threshold using
`family_alpha / pair_count`. A verdict requires at least three unique modalities,
equal lengths, sufficient samples, finite non-degenerate columns, a usable
threshold, and exactly one all-pairs positive clique containing a strict majority.
An outsider with any threshold-clearing bridge to that clique makes attribution
ambiguous. `Nominal` means all requested channels are in the unique clique;
`Decoupled` names every unbridged outsider; all other admissible but unidentifiable
states are `InsufficientEvidence`. `note` is explanatory only.

In the default multi-axis report, `AxisCorrelationReport.axis` is the zero-based
producer projection coordinate and `report` is the preceding estimand with the
family budget divided across active axes. Disagreement between positive axes, or a
positive axis alongside an insufficient axis, is fused as unclassified evidence.
An axis report produced by `prepare_release_assessment` also carries the exact
whole-stream `AssessmentBinding`. `single_axis`/`try_new` remain explicitly unbound
compatibility diagnostics and cannot be substituted into an accepted report.

## Fused report

`MagnitudeEvidence` records whether every consistency-attributed channel was
`InCovariance`, `Elevated`, a `Mixed` set, or unavailable (`Insufficient`).
`ConsistencyEvidence` is a typed state: `Intact`, non-empty `Decoupled`,
`Insufficient`, or `Conflicted`. It cannot simultaneously encode a confident
positive and sufficiency.

`FusedVerdict` is the deterministic composition of the full `MirrorReport` and
consistency evidence. Conflicting positive attributions become
`UnclassifiedAnomaly`; dual insufficiency becomes `InsufficientEvidence`; positive
consistency evidence becomes `AttributedInconsistency` with its magnitude class;
otherwise the magnitude verdict is preserved, except nominal magnitude plus
insufficient consistency remains insufficient. `DefaultReport` retains that
verdict, the entire magnitude report, every axis report, a non-normative note, the
complete suite identity/classification, and one opaque `AssessmentBinding` shared
by every component.

The core binding is a domain-separated SHA-256 identity over the canonical complete
`ReleaseSuite` plus every field of every ordered input observation. It includes
track, timestamp, sequence, modality, NIS, degrees of freedom, optional innovation,
optional covariance, and every consistency-projection value and provenance field.
Callers can compare it or verify it against an exact stream/suite, but cannot mint
one or attach it to replacement reports. `combine_correlation_axes` may return an
unbound diagnostic tuple when every input is unbound; it rejects mixed bindings and
does not return a sealed `DefaultReport`.

## Optional PID research report

PID is not part of the stable core surface or a deployment claim. When compiled,
pairwise `estimate_nats` is the upstream report-first KSG mutual-information point
estimate for the declared regular full-dimensional continuous support contract;
`n_samples` and `k` are the actual estimator inputs. The attached typed support,
method/scientific status, assumption ledger, warnings, provenance hashes,
preprocessing/observation/sampling descriptions and resource estimate are part of
the interpretation and **SHALL NOT** be dropped when a scalar is retained.

For each channel, `corroboration` is its best safely estimated pairwise MI in nats;
`redundancy` and `synergy` are experimental shared-exclusions PID2 atoms in nats;
`gate_ok`/`gate_note` record estimator admissibility; and `ci` is the circular
delete-block interval for the worst candidate-to-consensus confirmation margin.
`decoupled` is admitted only by the configured clique and confirmation procedure.
`PidVerdict` means all requested channels admitted (`Nominal`), a strict minority
confirmed outside (`Decoupled`), or no defensible attribution
(`InsufficientEvidence`). PID atoms are diagnostics and never a posterior or a
standalone causal verdict.

PID work is entered only through an explicit accepted `PidResearchSuite`, which
contains a PID-free `ReleaseSuite` plus one underived `PidConfig`. Construction
checks the worst-case three-axis quadratic-fit product before observations are
read; the actual axis family is checked and divided exactly once before any
estimator invocation. `PidConfigDigest` includes every accepted scalar,
confirmation variant and applicable payload, named/custom classification,
axis-family derivation, fixed resource ceilings, and the exact selected upstream
revision and estimator semantics. Every `PidReport` carries that identity through
sealed estimator evidence.

`PidEstimatorEvidence`, `ChannelPid`, `PidReport`, `AxisPidReport`, and
`FusedReport` are sealed output values. PID fusion checks the baseline, every
correlation axis, and every PID axis against one accepted research suite; mixed
identities, mismatched/duplicate/non-contiguous axes, and out-of-range labels are
errors rather than evidence. The fused PID report carries the suite identity and
classification, retains the magnitude, signed-correlation, and PID axes, and adds
`PidAssessmentBinding`: a domain-separated binding of the core assessment to the
complete PID research suite.
Sign-invariant PID cannot erase positive signed-correlation evidence, and a PID
nominal result cannot repair unavailable signed-correlation evidence. A complete,
conflict-free signed attribution may remain reportable as advisory evidence when
some optional PID axes are insufficient; the incomplete PID evidence stays in the
report.

## Repeated use and missingness

The current window p-value controls one modeled assessment family, not an unlimited
stream. Overlapping windows and persistent CUSUM state create repeated looks.
Association/gating censoring and sensor silence are not missing-at-random. Therefore
0.9.0 **SHALL NOT** call `nis_alpha`, `family_alpha`, bootstrap intervals, synthetic
rates, or a single assessment a mission-level false-alert guarantee. The operational
source profile remains research/advisory; mission-level operational qualification is
`NOT_CLAIMED`.
