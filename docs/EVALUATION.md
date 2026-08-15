# Synthetic evaluation plan and evidence boundary

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| AUC | area under the receiver operating characteristic curve |
| CLI | command-line interface |
| CUSUM | cumulative sum |
| FAR | false-alarm rate |
| JSONL | JavaScript Object Notation Lines |
| KSG | Kraskov–Stögbauer–Grassberger |
| MI | mutual information |
| mTLS | mutual Transport Layer Security |
| NIS | normalized innovation squared |
| PID | partial information decomposition |
| PID2 | two-source partial information decomposition |

This document describes the Galadriel evaluation method.
It also states what the current evidence does not establish.

> **Status after the 2026-07 correctness audit.**
> The evaluation harness uses synthetic data.
> The project removed numeric tables from the pre-audit detector.
> The implementation now validates inputs and joins channels by exact sequence.
> It uses signed correlation with a unique strict-majority consensus.
> It controls each assessment family and fails closed.
>
> The retained `post-audit-v1` streaming artifact gives exact results.
> These results cover the NIS and signed-correlation streaming detector subset.
>
> Those results cover false alerts, delay, abstention, and attribution.
> The broader comparative harness still needs a versioned post-audit report.
> Do not cite exact AUC, matched-operating-point, adaptive, maneuver, collusion,
> latency, or cost values before this report exists.

## 1. Questions that the harness can answer

The Monte Carlo harness compares detector behavior under explicit generated
models.
It can answer these questions:

1. Does an NIS magnitude layer react to loud single-channel bias and common-mode
   inflation?
2. Does signed cross-channel correlation detect a synthetic decoupling that
   preserves per-channel magnitude?
3. Does a pairwise-MI score add information in a nonlinear bivariate construction,
   and does a separately specified PID functional expose a synergistic construction?
4. How do window length, attack onset, decoupling strength, collusion,
   threshold-hugging, and benign lag affect accepted alarms and the separately
   labeled MI separation event?
5. What is the relative compute cost on the benchmark machine?

The harness cannot determine whether a deployed external producer satisfies
these models.
It cannot determine how operators respond.
It cannot establish authority for control use.

## 2. Synthetic model

The simulator generates multiple modalities from a shared latent process.
It uses a documented covariance and a common sequence.
A seed makes clean and attacked trials reproducible.
The simulator validates scenario configuration before generation.
It returns an error for an invalid, non-finite, degenerate, or overflowing
configuration.

`ScenarioConfig::assessment_scope(stream_id)` derives the accepted full-fusion
scope for a nonempty scenario. It rejects an empty scenario because no terminal
frame exists. It uses these deterministic synthetic coordinates:

- producer `galadriel-sim`
- session `scenario-v0.9`
- epoch equal to the scenario configuration digest
- the validated caller-supplied stream label
- state generation zero
- the scenario terminal sequence and timestamp
- clock domain `simulation_time`

The same accepted scenario and stream label produce the same scope.
The scope identifies synthetic provenance.
It does not authenticate a writer or establish operational provenance.

The synthetic attack families are:

- loud single-channel bias, which tests NIS and CUSUM evidence
- common-mode inflation, which tests jam-like magnitude evidence
- moment-matched decoupling, which changes signed dependence but preserves
  marginal channel magnitude
- collusion, which exposes the honest-majority boundary
- adaptive or threshold-hugging bias, which explores evasion near a configured
  operating point
- benign lag or maneuver proxies, which measure false alarms from timing or model
  mismatch
- canonical nonlinear and synergistic couplings, which separately test a
  bivariate MI score and fixed-source/fixed-target PID functionals beyond signed
  linear correlation

The simulator creates these controlled constructions.
They are not recordings of real attacks.

## 3. Detectors under comparison

### 3.1 Magnitude baseline

The baseline uses per-track and per-modality NIS windows.
It also uses CUSUM evidence.
A channel test has a chi-square reference only when its degrees of freedom remain
valid and stable.
The detector divides the configured assessment significance budget across channels.

### 3.2 Default fused detector

The default detector combines magnitude evidence with signed Pearson correlation.
The accepted full-fusion path passes its deterministic `AssessmentScope` to
`assess_default`.
The correlation assessment requires:

- one track
- an exact sequence intersection without duplicates
- finite channels of equal length
- a defined pairwise estimand for each verdict-eligible pair
- a family-wise-significant positive relation
- one unique strict-majority positive-consensus clique

Negative correlation is not corroboration.
A dyad cannot support minority attribution.
A degenerate column produces `InsufficientEvidence` for its axis.
It also makes the correlation evaluation score unavailable.
A missing or nonunique coherent majority also produces `InsufficientEvidence`.
The detector does not select a best peer.

The runtime full-fusion report analyzes each producer-attested
consistency-projection axis.
Here, producer-attested means a producer provenance claim.
It does not mean cryptographic authentication.
It divides the family budget across axes.
It fails closed when axis attributions conflict.
It also fails closed when positive evidence occurs with an insufficient axis.

The accepted report binds the complete synthetic scope, suite, and ordered
stream through assessment binding version 2.

### 3.3 Optional dependence companion

The opt-in in-process/library companion uses a complete geometry-gated graph of
report-first pairwise KSG-MI estimates. Its current executable integrations are
the synthetic demo, evaluation harness, and benchmark; `replay`, `observe`, and
the NCP path do not invoke it. It is not PID: the graph is symmetric and has no
external target. Its global threshold and strict-majority clique are
project-defined descriptive rules without null calibration.

The caller declares the continuous population, binary64 observation, and
sampling models. Galadriel checks their bounded representation but does not
prove them. It requires a declared common coordinate gauge, applies the fixed identity transform, and adds no
noise. A degenerate column, exact ties, rejected geometry, missing pair evidence,
ambiguous clique, weak reference, or unstable deletion replay produces an
explicit unavailable state.

Exhaustive circular deletion evaluates every start and reruns retained-row validation,
geometry, all edges, threshold, clique, and attribution. Its min/max margin
envelope is not a bootstrap interval or p-value. The companion event never
changes the authoritative core verdict.

The pinned pid-rs revision is
`1cd2424f7967e1752dcc8e53859e8fdad3566f51`. Its manifest declares version
1.0.0. The dependence crate uses only its stable report-first KSG surface. The
project claims no released upstream 1.x artifact.

Every graph report carries the complete accepted named/custom graph parameters
and a separate fixed KSG evaluator snapshot, even if the graph is unavailable.
Resource rejection during a point fit or deletion replay is typed separately
from scientific pair unavailability and deletion instability.

Real PID appears only in offline justification studies. The categorical
Makkeh–Gutknecht–Wibral functional and the continuous
Ehrlich–Schick-Poland–Makkeh–Lanfermann–Wollstadt–Wibral construction are distinct and
require fixed source and target identities. Neither is a fallback for an
unavailable MI graph.

### 3.4 Standalone component experiments

The harness pre-registers standalone component experiments to attested
consistency-projection axis 0.
These experiments include correlation rates, descriptive MI-graph event rates,
complete-pair MI scores, selection-conditional AUC, and sweeps. Every MI AUC
discloses its attack/clean retained counts, the correlation AUC on the identical
joint-complete subset, and worst/best AUC bounds over arbitrary rankings of
missing scores. PID studies are reported separately.
They also include adaptive, maneuver, collusion, and latency studies.

The experiments isolate comparable scalar estimands.
Do not present them as full-detector or all-axis performance.
Only the fused fields in the main report exercise each active projection axis.

### 3.5 Bounded maneuver design

The complete CLI suite fixes a benign `12σ` triangular maneuver of 90 frames.
The maneuver starts at `floor(frames/3)`.
The suite uses the lag grid `[0, 8, 16, 24, 32]`.
The current study uses three modalities.
Their lag multipliers are visual `0`, acoustic `2`, and radar `3`.

A lag `L` occupies half-open windows.
These windows end no later than `floor(F/3) + 3L + D`.
Here, `F` is capture length and `D` is maneuver duration.

Preflight requires this endpoint to be at most `F`.
The suite therefore observes the complete maneuver for each modality.
It does not right-censor the maneuver.
At the named profile values `F=300` and `D=90`, the largest registered lag ends
at frame 286.

The simulator samples the continuous triangle over `[start, start + D)`.
Its included start and excluded right endpoint are zero.
An even `D` samples the exact configured peak.
An odd `D` has two equal central samples.
Each sample is `(1 - 1/D)` times the peak parameter.

`EvalSuiteConfig::try_new` and direct `maneuver_far` calls enforce the same
pre-generation checks.
The lag grid **MUST** have 1 through 10,000 unique `u64` entries.
Magnitude **MUST** be finite and positive.
Its square **MUST** be finite.
Duration **MUST** be at least two frames.
Each checked window **MUST** fit.

The study also enforces two work limits with checked arithmetic.
It requires `trials * lag_count <= 50,000`.
It requires `trials * frames * 3 * lag_count <= 100,000,000`.
The study checks these limits before MI-work preflight.
These limits bound workload and require complete exposure.
They do not show that the proxy represents field maneuvers.

## 4. Metrics

Each result **MUST** identify the synthetic regime and seed policy.
It **MUST** also identify the trial count, window, operating point, and exact
commit.
Report at least:

- alarm/event-ranked AUC: core alarms rank above non-alarms; the descriptive MI
  graph separation event ranks above no separation; each then uses its separately
  available continuous score. MI AUC is explicitly selection-conditional, not a
  fixed-denominator classifier AUC
- retained counts, correlation on the identical MI-complete subset, and sharp
  worst/best MI-AUC bounds that make no missing-at-random assumption
- a paired bootstrap interval for detector AUC differences on identical complete cases
- accepted detection and false-alarm proportions with binomial intervals;
  describe MI only as separation/no-separation/unavailable event proportions
- accepted-alarm time only for trials without a pre-onset alarm; report MI only
  as an oracle-onset-segmented posthoc separation-event latency, including its
  71-frame first-eligibility delay before probe-step rounding. The MI rows reset
  at the known simulated onset, so this is not an online latency and is not
  directly comparable to the alarm columns
- reachability, which is the fraction of trials with a post-onset accepted alarm
  or separately named MI separation event
- separate inconclusive and error rates, without counting them as correct
- throughput with hardware, toolchain, build profile, and benchmark configuration

Pointwise confidence intervals from a parameter sweep are exploratory.
They do not prove that one detector wins somewhere across the scanned grid.
Such a claim needs a simultaneous or pre-registered comparison procedure.

The adaptive score study fits each axis-0 component threshold on a dedicated
clean calibration seed domain.
A separate clean holdout seed domain reports the observed FAR with a Wilson
interval.
The requested upper-tail quantile is a calibration target.
It does not guarantee the realized FAR.
It does not show that the two holdout FARs are identical.

## 5. Required acceptance checks

A regenerated synthetic report is useful only when all these conditions hold:

1. Clean trials exercise each configured channel.
   They do not depend on a pre-onset alarm.
2. The system rejects invalid input instead of scoring it.
   It marks a finite degenerate estimand as insufficient.
3. The system counts missing channels, sequence gaps, and ambiguous geometry as
   insufficient instead of nominal.
4. Each configured channel is assessable.
   A ready pair cannot hide a failed third channel.
5. The system never pools track identifiers into one dependence estimate.
6. The system does not treat signed-correlation sign flips as corroboration.
7. The system marks constant channels as unavailable and never adds noise to
   create an estimable continuous law.
8. The system does not replace a failed exhaustive deletion replay with an
   optimistic point-graph attribution.
9. Reports disclose multiplicity for multiple parameter scans.
10. Results distinguish detector failure from producer censoring or missingness.
11. Full fused reports analyze each active projection axis.
    Applicable family budgets include axis and channel-pair multiplicity.
    A standalone axis-0 experiment **MUST** label its narrower estimand.
    It **MUST NOT** call this the full detector.
12. Different positive channel attributions across axes produce
    `UnclassifiedAnomaly`.
    The system does not select a favorable `AttributedInconsistency` result after
    inspection.

### 5.1 Candidate evidence contract

Candidate evidence uses these exact identifiers:

- trial schema `galadriel.evidence.trial.v3`
- summary schema `galadriel.evidence.summary.v3`
- manifest schema `galadriel.evidence.manifest.v3`
- acceptance profile `galadriel-0.9-frozen-acceptance-metrics-v3`
- bootstrap profile `splitmix64-rejection-group-metric-v1`

The bootstrap profile samples complete tracks with SplitMix64 and unbiased rejection sampling.
The manifest binds the exact Git commit and tree.
It also binds the accepted configuration, source inputs, toolchain, and exact runner executable.

The qualification host does not trust the generated summary as an acceptance input.
It streams each trial record and reconstructs every summary row.
It renders the report again and verifies the checksum document.
It then evaluates the seven criteria from the reconstructed holdout summary.
Finalization repeats the same semantic replay.

This procedure checks internal evidence consistency.
It does not establish that a synthetic model represents operational data.

### 5.2 Frozen design limitation

The frozen design uses 100 holdout tracks for each condition.
Two interval criteria are structurally infeasible at this size.

- `GLD-090-ACC-001` cannot pass with zero events.
  Its upper 95% Garwood bound is `0.3689904` episodes per hour.
  The criterion requires at most `0.10`.
  The zero-event design needs at least 369 tracks.
- `GLD-090-ACC-006` has a minimum Hoeffding radius of `0.1358102`.
  The criterion requires an upper bound of at most `0.05`.
  The equal-weight design needs at least 738 tracks.

The 25,000,000-observation ceiling permits at most 248 holdout tracks with the frozen grid.
Thus, the current suite cannot reach either necessary size.
Preserve this negative result.
Do not change a threshold or ceiling to convert it into a pass.

An executable qualification can pass while candidate acceptance fails.
That combination produces `NARROWED_REVIEW_REQUIRED`.
A signed human decision must then select `NARROWED_GO` or `NO_GO`.
The decision must retain each failed criterion and its residual risk.
It cannot select `GO`.

## 6. Recorded-data gate

No synthetic or component result can validate a deployed Crebain integration.
Crebain is an optional reference producer.
A live producer does not have to be Crebain.
Two revisions identify a retained historical epoch and registry compatibility
fixture:

- Crebain `4c311900ade5668200a48d56fb191be1916b884a`
- Galadriel `81437d807ca83b66b45c8353968948e540072d97`

These revisions do not reciprocally pin this candidate.
Current cross-repository qualification is `NOT_CLAIMED`.
A recorded evaluation **MUST** capture and verify these items against the exact
current binaries:

- the normal runtime path enables `consistency_projection` for each requested modality
- physical-frame and projection-context identifiers and dimensions match across modalities
- one frozen-prior identifier matches each sequence, and the assessed run does not reuse it
- the producer emits association misses, gate rejections, and failed updates explicitly
- heartbeats identify all-modal silence
- session identifiers are stable and use a versioned schema with restart rules

The bundled historical fixture enabled native research fields for that fixture.
It contains no common projection attestation.
The system never substitutes its mixed native frames or sequential priors.
The fixture supports bounded parsing and basic NIS baseline checks.
The unbound correlation diagnostic returns `InsufficientEvidence`.
Raw replay has no complete assessment scope.
It cannot construct an accepted core or dependence companion report.

A valid recorded study **MUST** separate:

- pre-gate detector performance
- selection and censoring from association and gating
- benign maneuvers and track lifecycle changes
- transport loss, restarts, and clock or sequence discontinuities
- all-modal silence, which requires a separate producer heartbeat

## 7. Reproduce

```bash
# Versioned streaming evidence artifact (recommended publication path)
cargo run --locked -p galadriel-eval --release --bin galadriel-evidence -- \
  --config evidence/post-audit-v1.json \
  --out target/evidence/post-audit-v1

# Minimum-size inferential synthetic suite (still compute-intensive)
cargo run --locked -p galadriel-eval --release --bin galadriel-eval -- 20

# No argument uses the same minimum 20-trial default
cargo run --locked -p galadriel-eval --release --bin galadriel-eval

# Larger synthetic study. Choose and report the trial count explicitly.
cargo run --locked -p galadriel-eval --release --bin galadriel-eval -- 200

# Hypothesis and edge-case tests
cargo test -p galadriel-eval --locked
cargo test --workspace --all-features --locked

# Relative cost on the current machine
cargo bench --locked -p galadriel-eval --bench detectors
```

The CLI completes preflight before it prints a partial report.
Preflight checks generated-observation work, bootstrap rank work, and
latency-prefix visits.
It also checks a conservative quadratic MI estimator budget.

The MI budget includes geometry, report-first KSG fits, and every exhaustive
deletion start. Evaluation studies pre-register projection axis 0, so their
preflight budgets that axis at each scheduled latency probe, including the
complete capture frame. The separate library-level `DependenceResearchSuite`
preflights every producer-supplied projection axis.

Do not copy numeric output into project claims until the complete audited
workspace passes.
The report **MUST** also record the commit, toolchain, configuration, and
hardware.
Always label synthetic numbers as `synthetic`.
They are not operational false-alarm or detection rates.

## 8. Interpretation boundary

Galadriel is an advisory consistency monitor.
A synthetic true positive does not prove that a sensor lied.
A synthetic true negative does not cover a consistency-preserving adversary.
A benchmark does not authorize an automated control response.

Authentication, ACLs, and mTLS remain separate layers.
Safety governance remains a separate layer.
Independently validated system-level fault handling also remains a separate
layer.
