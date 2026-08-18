# Statistical contract and estimands

## Abbreviations

| Short form | Meaning |
|---|---|
| CUSUM | cumulative sum |
| KSG | Kraskov–Stögbauer–Grassberger |
| MI | mutual information |
| NIS | normalized innovation squared |
| PID | partial information decomposition |
| PID2 | two-source partial information decomposition |
| SHA-256 | Secure Hash Algorithm 256 |

This document is normative for reports from Galadriel 0.9.0. An estimand is the
exact population quantity or decision function. This term does not imply that a
deployment satisfies the identification assumptions.

[![Detector quantities summarized as a three-column decision graph](../assets/detector-evidence.svg)](../assets/detector-evidence.svg)

**Orientation figure — non-normative.** The left column follows the magnitude
route from NIS through the declared chi-square window reference and a two-arm
CUSUM. The middle column follows the signed-consistency route from every Pearson
pair through the family-adjusted Fisher threshold and the unique largest clique
whose size is a strict majority. The right column summarizes fusion and input binding. This figure is a
map of the contract. The numbered requirements and source definitions below
control if any wording or layout is less precise. Invalid input and unavailable
evidence remain different states, and neither MI nor PID enters core fusion.

[Open the orientation figure at full size.](../assets/detector-evidence.svg)

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

The selected 0.9 configuration fixes `k=3/sqrt(6)`. It does not fix `dof`.
Validated observations admit `dof` from 1 through 255. On the fusion core's
`dof=3` route, `mu=d/sqrt(2d)=k`, and the lower recurrence reduces to
`lo=max(0,lo-x)`. Since admitted NIS gives `x>=0` and the arm starts at zero, the
lower arm remains zero on that route. The same is true for `dof` 1 and 2 because
`mu<=k`. For `dof>=4`, `mu>k`, so a sufficiently small `x` can increase the
lower arm. The selected object is therefore genuinely two-arm over its complete
admitted domain. The fusion-core `dof=3` route has effective upper-shift
sensitivity only. Any claim about lower-shift performance requires a
dimension-specific calibration study and a qualified producer law.

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
Pearson correlation. Direct `pearson` calls require finite, non-degenerate
columns. Center and scale each range independently before calculation.

The correlation assessment accepts a finite degenerate projection column as an
unavailable estimand. It does not create a low edge from that column. The axis
returns `InsufficientEvidence`. It withholds all channel corroboration values for
that axis. Other detector evidence remains available.

`CorrChannel.n` is the common tail length. `corroboration` is the largest signed
pair correlation for that channel. It is `None` when any required pairwise
estimand is unavailable. `decoupled` identifies membership outside the one
admitted consensus clique.

The pair family threshold is the maximum of these values:

- configured `corr_floor`
- `decouple_ratio * max_pair_rho`
- the one-sided Fisher-z threshold with `family_alpha / pair_count`

A verdict requires all these conditions:

- at least three unique modalities
- equal lengths
- sufficient samples
- finite columns with a defined pairwise estimand
- a usable threshold
- one unique largest all-pairs positive clique that contains a strict majority

An outsider can have a threshold-clearing bridge to that clique. This condition
makes attribution ambiguous. Smaller subcliques do not count as tied largest
explanations. `Nominal` means that the unique largest clique contains all requested
channels. `Decoupled` identifies each unbridged outsider. All other
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

Accepted whole-stream preparation requires one `AssessmentScope`.
The scope terminal sequence **MUST** equal the largest input sequence.
Its terminal timestamp **MUST** equal the largest timestamp at that sequence.
A mismatch is invalid input and returns an error before report construction.

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
one `AssessmentScope`, and one shared opaque `AssessmentBinding`.

The serialized report contains the complete scope once.
Its top-level field name is `assessment_scope`.

The core binding uses domain `galadriel-assessment-binding-v2`.
It hashes the complete scope before the suite and observations.
The scope contains producer, session, epoch, stream, state generation, terminal
sequence, terminal timestamp, and clock domain.

The binding covers the canonical complete `ReleaseSuite`.
It also covers every field of each ordered input observation.
The fields include track, timestamp, sequence, modality, NIS, and degrees of
freedom. They also include optional innovation and optional covariance.
They include all projection values and provenance fields.

Callers can compare the binding or verify it against an exact scope, stream, and
suite. They cannot create one or attach it to replacement reports.
Different bindings can carry equal detector verdicts. The binding does not
require each observation to change an estimator or verdict.
The scope contains caller-declared provenance labels.
The binding does not authenticate those labels or prove physical provenance.

`combine_correlation_axes` can return an unbound diagnostic tuple when all inputs
are unbound. It rejects mixed bindings. It does not return a sealed
`DefaultReport`.

## Optional dependence companion and offline PID boundary

The optional in-process/library companion is not PID. Its current executable
integrations are the synthetic demo, evaluation harness, and benchmark; raw
`replay`, `observe`, and NCP ingestion do not invoke it. It evaluates one symmetric complete
graph of report-first pairwise KSG-MI estimates. Each `PairKsgEvidence` retains the
typed support contract, method and scientific status, estimand identity,
assumption ledger, warnings, provenance, preprocessing and sampling descriptions,
resource estimate, exact upstream revision, sample count, `k`, and nats units.
The selected dependency is `pid-core` 0.9.0 at
`bc3aa80fb6025e709c2906a08bce25a4fac40578`. Every point fit uses
`ksg_mi_report_with_budget`. Its retained preflight and execution use the same
explicit single-thread `ResourceBudget`. Galadriel's graph work ceiling is a
separate aggregate bound. No resolved Galadriel feature profile includes
`pid-runlog`.

The caller supplies `ContinuousLawDeclaration` text for the population law,
binary64 observation model, and sampling model. Construction validates only that
the text is nonempty and bounded. It does not prove those declarations. Galadriel
requires a declared common coordinate gauge and applies the fixed identity
transform to every edge. It adds no stochastic observation transform. Exact ties,
a degenerate column, rejected geometry, or any unavailable
pair withhold a complete graph estimate.

For each channel, `strongest_pair_mi_nats` is the maximum incident edge in the
complete estimated graph. The configured global reference is the maximum over all
edges. The threshold is
`max(mi_floor_nats, separation_ratio * global_reference)`. A retained separation
requires one unique largest strict-majority clique and a strict minority whose every edge
to that clique lies below the threshold.

`MiGraphDisposition` has these descriptive meanings:

- `NoSeparationAtConfiguredThreshold`: all requested channels belong to the one
  retained threshold graph.
- `SeparatedFromMajorityGraph`: the named strict minority lies outside the unique
  strict-majority clique.
- `Unavailable`: rows, geometry, pair evidence, reference strength, clique
  uniqueness, or deletion stability did not support either description.

Resource rejection is not scientific instability. A point graph distinguishes
`PairResourceRejected` from ordinary unavailable pair evidence. A deletion replay
that crosses a resource boundary yields
`ResourceRejectedDuringExhaustiveDeletion`; it is not relabeled
`UnstableUnderExhaustiveDeletion` and no stability claim is made.

None means nominal security, attack, causal mechanism, or calibrated hypothesis
rejection. The threshold has no null distribution or false-alarm theorem.

`ExhaustiveCircularDeleteBlock` enumerates every circular block start. Each
deletion reruns retained-row validation, geometry, every pair report, the global
reference, threshold, clique, and attribution. A retained separation must be
identical on every replay. `DeleteBlockStabilityEnvelope` contains literal margin
minima and maxima over that finite perturbation set. It is not a confidence
interval, p-value, bootstrap, family-alpha procedure, or coverage statement.

`RowSetReceipt` hashes exact modality order, row order, binary64 values, caller
episode label, and origin. The report separately binds and verifies the complete
MI configuration identity. Verification proves byte agreement only.
It does not prove episode membership, independence, or population support.
`DeclaredMiInput` retains only the newest `MAX_MI_WINDOW` rows per channel
before scanning values. This bounds direct-constructor validation and cloning by
the same public row ceiling the analyzer can use.

The core-bound route additionally retains the producer projection frame and
context, axis identity, full extracted suffix length, modality order, and the
exact ordered sequence/minimum-timestamp/maximum-timestamp triple for every row
selected by the MI tail. `ProjectionAxisReceipt` binds that material to the core
assessment and dependence-suite identity. The inner `RowSetReceipt` still binds
the exact numeric columns. Neither receipt authenticates the producer or assigns
physical meaning to an axis.

`MiEstimatorEvidence` serializes the functional, estimator, exact DOI, upstream
report route, graph composition and rule, tail rule, fixed-preprocessing and
no-noise relation, geometry protocol, warning policy, information units, and
exact pid-rs repository, version, and revision. Its `accepted_config` contains
every accepted custom or named graph parameter and all work/input ceilings. Its
`ksg_evaluator_config` contains the fixed `k`, metric, tie rule, negative-value
policy, support declaration, boundary, geometry model, exact-backend policy, and
estimand/estimator revisions. This material remains present when no pair succeeds.
Each successful pair additionally retains the complete immutable upstream KSG
report. These records are self-describing provenance, not a compatibility,
validity, or calibration certificate.

`DependenceResearchSuite` composes the release suite and one MI configuration
after checked multi-axis work preflight. `DependenceAssessmentReport` retains the
exact unchanged `DefaultReport` plus companion axes. Its binding covers scope,
stream, and suite. MI has no path into `FusedVerdict` or `ConsistencyEvidence`.

Categorical Makkeh–Gutknecht–Wibral shared-exclusions PID and the related but
distinct continuous Ehrlich–Schick-Poland–Makkeh–Lanfermann–Wollstadt–Wibral construction
are offline `galadriel-justify` study
functionals. Each question must fix source identities and order, a target fixed
before result inspection and separated from any accepted fused verdict,
functional and estimator identity, law, units, transformations, gauges,
row relation, and software identity. A hand-built local kNN-MI CUSUM is a
project-defined heuristic, not either PID construction.

The unit contract has two layers. Native pid-core evaluators and retained trial
reports are in nats. Categorical aggregate/display atom fields convert those
values once to bits; continuous aggregates remain in nats. Every serialized
trial envelope carries its native unit, so a bit-valued aggregate question cannot
silently relabel raw upstream nats.

`PidQuestionSpec` governs only named PID fields and retained PID trials. Its
version 3 schema serializes the exact generated law and finite-sample acceptance
rule; the complete two-source output family as typed quantity IDs, lattice
coordinates, direct-versus-derived atom constructions, component sets,
within-trial aggregation laws, and native units; each root PID aggregate field's
coordinate/component/statistic/unit; and the distinct interpretation of the
coupled-law and within-trial target-permutation arms. The continuous permutation
arm is an exchangeable descriptive randomization score, not an i.i.d.
independent-law or population-functional estimate. Functional identity alone is
not treated as one scalar identity.
`JustificationStudyProtocol` separately identifies Pearson, pairwise MI, and the
project-defined `Q = I(S1,S2;T) - max(I(S1;T), I(S2;T))` composition. `Q` is not a
PID atom. The protocol maps every non-PID root field to a quantity, statistic,
and unit. It also binds the paired-trial sampling unit, paired-index percentile
bootstrap identity, generator and bootstrap seed relations, order-statistic rule,
resample count, interval scope, and lack of a multiplicity guarantee. The exact
resolved RNG dependency bytes and Galadriel source tree remain external
publication-bundle requirements. Categorical MI and `Q` are mechanically derived from each retained
pid-core result. Sealed aggregate results expose a bitwise coherence verifier;
typed `JustificationError` retains the original Galadriel or pid-core error source.
Both categorical and continuous result roots retain the exact single-thread
`PidStudyResourceContract` used by every `_with_budget` evaluator call. This is a
per-call ceiling. The checked study preflight is the separate composed-work
contract, and neither claims an end-to-end allocation or wall-clock bound.

`PidQuestionSpec` makes those two implemented study questions nominally
distinct and records their complete defining teams and exact primary references.
Its `PidDependencyIdentity` is a mechanically checked package/version/Git
pin/feature selection envelope. Each produced study separately retains
`PidExecutionIdentity`, reconciles pid-core's build-context-dependent
`SoftwareIdentity`, and requires the selected WorkspaceGit revision and a clean
`pid-core` package subtree. Neither receipt is whole-repository cleanliness,
binary attestation, scientific validity, or numerical portability.

### Exact CREBAIN drone categorical law

`galadriel-crebain-mgw` is a separate offline evaluator over one exact embedded
CREBAIN fixture. It does not consume replay, NCP, an accepted `DefaultReport`,
or the dependence companion. Before PID evaluation it MUST verify:

- Exact fixture byte count and SHA-256.
- Exact recursively key-sorted analysis-manifest SHA-256.
- Source order `(visual, radar, acoustic)`.
- One unique episode identifier per row and the producer's fresh-engine declaration.
- A 1,000 ms prior and one 1,100 ms row-level observation timestamp.
- The six retained legacy fusion-summary fields: prior identifier, input count,
  expected count, projection count, truncation, and degradation.
- All eight source cells appearing exactly eight times in canonical order.
- Each declared source bit checked against its named pre-fusion coordinate.
- Horizontal/volumetric targets reconstructed from retained latent ENU truth.

The producer generated each target without reading source-symbol fields, sensor
projections, fusion output, Galadriel, or PID. This separates the target from
the evaluated fusion/PID stack. It does not make the target producer-independent
field truth. The compact fixture does not retain separate sensor timestamps,
complete three-projection receipts, a full fusion output, or sufficient hidden
state to prove state isolation.

The equal-weight categorical law is

\[
p(V,R,A)=1/8,\qquad T_H=VR,\qquad T_V=VRA.
\]

The eight repeats per cell test bounded-summary fresh-instance reproducibility
and exact custody. The evaluator MUST record no p-value, confidence interval,
resampling result, or claim of 64 independent experimental units. The primary
route is `discrete_sxpid2_with_budget` over `(V,R;T_H)`. The
`discrete_sxpid3_with_budget` route over `(V,R,A;T_V)` is exploratory. Both use
the same explicit resource-budget policy, and the aggregate receipt accounts
for all nine evaluator calls. The result MUST retain
every pointwise/averaged informative, misinformative, and signed net field in
nats. It MUST check both PID2 self-redundancy identities, PID2 joint
reconstruction, all seven PID3 down-set identities, exact analytic AND-law
mutual informations, and fixed-source informative-atom invariance under a
deterministic target rotation.

The dependency-disjoint, separately implemented 80-digit Decimal route compares
the 66 averaged atom components and ten subset mutual informations. It does not
recompute pointwise atoms and is not independent human or organizational
replication. The complete emitted JSON MUST validate against the
closed Draft 2020-12 v2 schema in
`crates/galadriel-justify/schemas/crebain-drone-mgw-study-v2.schema.json` and its
exact byte receipt through `repo_work/check_crebain_mgw_schema.py`.

KSG and continuous Ehrlich PID are inapplicable to this repeated atomic law.
`I_min` and BROJA are distinct unrequested comparators, never fallbacks.
Co-information/O-information, NIS, the selected two-arm CUSUM, signed correlation, and
infomorphic objectives remain separate quantities. None of those operational
diagnostics is evaluated by this fixture. No field in this study can enter
`FusedVerdict`, `ConsistencyEvidence`, or an authority decision. A future Haldir
record must leave authorization and plant-command outputs unchanged. PID cannot
grant, revoke, restrict, or exercise authority. The complete equations,
coordinates, method matrix, and claim ladder are in
[`CREBAIN-DRONE-MGW-STUDY.md`](CREBAIN-DRONE-MGW-STUDY.md).

## Repeated use and missingness

The current window p-value controls one modeled assessment family. It does not
control an unlimited stream. Overlapping windows and persistent CUSUM state create
repeated looks. Censoring from association and gates is not missing at random.
Sensor silence is also not missing at random.

Thus, 0.9.0 **SHALL NOT** describe any of these values as a mission-level
false-alert guarantee:

- `nis_alpha`
- `family_alpha`
- deterministic deletion envelopes or bootstrap intervals
- synthetic rates
- a single assessment

The operational source profile remains research and advisory. Mission-level
operational qualification is `NOT_CLAIMED`.
