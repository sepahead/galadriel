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

## Magnitude report

For one modality's retained contiguous window `q₁,…,qₙ`:

- `n` is the exact retained sample count.
- `dof` is the immutable `d` declared for that track/modality epoch.
- `sum_nis = min(Σ qᵢ, f64::MAX)` and `mean_nis = sum_nis / n` for `n>0`
  (`0` for an absent expected channel in `ChannelReport`). Saturation prevents a
  finite extreme anomaly from becoming a numeric error.
- `p_right = Pr[X ≥ sum_nis]` for `X ~ χ²(n d)`, evaluated directly as an
  upper tail. For `n=0`, it is `1`.
- The per-channel threshold is `nis_alpha / C`, where `C` is the number of known
  or expected channels in that assessment. `elevated` is exactly
  `n>0 && p_right < nis_alpha/C`; equality is not elevated.
- The two CUSUM inputs are `x=q/sqrt(2d)` and target `μ=d/sqrt(2d)`. After each
  sample, `hi=max(0, hi+x-μ-k)` and `lo=max(0, lo+μ-x-k)`, with configured
  slack `k`; an arm alarms when its accumulator is strictly greater than threshold
  `h`. `cusum_high_alarm` and `cusum_low_alarm` are exactly those arm predicates.
  The state is historical sequential evidence, not a p-value.
- `last_seq` and `last_timestamp_ms` are the newest accepted identities;
  `fresh` means assessment sequence minus `last_seq` exists and is at most
  `max_seq_gap`.
- `ready` means `n >= min_samples && fresh`. A complete assessment additionally
  requires every known/expected channel ready, at least `min_channels`, and newest
  timestamps spanning no more than `max_timestamp_skew_ms`.

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
cause. The exploratory `Mirror::new` constructor has no expected-modality contract
and is not the release-qualified cross-sensor path; the default fused path uses an
explicit expected set.

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
verdict, the entire magnitude report, every axis report, and a non-normative note.

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
standalone causal verdict. The fused PID report keeps the magnitude, signed
correlation and PID axes; sign-invariant PID cannot erase signed-correlation or
insufficient-evidence findings.

## Repeated use and missingness

The current window p-value controls one modeled assessment family, not an unlimited
stream. Overlapping windows and persistent CUSUM state create repeated looks.
Association/gating censoring and sensor silence are not missing-at-random. Therefore
0.9.0 **SHALL NOT** call `nis_alpha`, `family_alpha`, bootstrap intervals, synthetic
rates, or a single assessment a mission-level false-alert guarantee. The operational
default profile remains unqualified until the sequential and missingness tasks in
the release ledger are closed with retained evidence.
