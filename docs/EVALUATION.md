# Evaluation — evidence plan and synthetic harness

This document describes how Galadriel is evaluated and, equally importantly, what the
current evidence does **not** establish.

> **Status after the 2026-07 correctness audit.** The evaluation harness is synthetic.
> Numeric tables from the pre-audit detector were removed because the implementation now
> validates inputs, joins channels by exact sequence, uses signed correlation with a
> unique strict-majority consensus, controls per-assessment families, and fails closed.
> The published `post-audit-v1` artifact supplies exact stream-level false-alert,
> delay, abstention, and attribution results for the NIS plus signed-correlation vertical
> slice. The broader comparative harness still needs a versioned post-audit report before
> any exact AUC, matched-operating-point, adaptive, maneuver, collusion, latency, or cost
> value from that suite is cited.

## 1. Questions the harness can answer

The Monte Carlo harness can compare detector behavior under explicitly generated models:

1. Does an NIS magnitude layer react to loud single-channel bias and common-mode
   inflation?
2. Does signed cross-channel correlation detect a synthetic decoupling that preserves
   per-channel magnitude?
3. Does MI/PID add information in a deliberately nonlinear or synergistic synthetic
   construction?
4. How do window length, attack onset, decoupling strength, collusion, threshold-hugging,
   and benign lag affect synthetic detection and latency?
5. What is the relative compute cost on the machine running the benchmark?

It cannot answer whether crebain's deployed residual stream satisfies those models, how
operators respond, or whether a verdict is safe to use for control.

## 2. Synthetic model

The simulator generates multiple modalities from a shared latent process, a documented
covariance, and a common sequence. Clean and attacked trials are reproducible from a seed.
Scenario configuration is validated before generation; invalid, non-finite, degenerate,
or overflowing configurations return an error.

The synthetic attack families are:

- **loud single-channel bias**, intended to be visible to NIS/CUSUM;
- **common-mode inflation**, intended to exercise jam-like magnitude evidence;
- **moment-matched decoupling**, intended to preserve a channel's marginal magnitude
  while changing its signed dependence;
- **collusion**, intended to expose the honest-majority boundary;
- **adaptive/threshold-hugging bias**, intended to explore evasion near a configured
  operating point;
- **benign lag/maneuver proxies**, intended to measure false alarms caused by timing or
  model mismatch;
- **canonical nonlinear and synergistic couplings**, intended to test whether MI/PID can
  add information unavailable to signed linear correlation.

These are controlled constructions, not recordings of real attacks.

## 3. Detectors under comparison

### 3.1 Magnitude baseline

The baseline uses per-track, per-modality NIS windows and CUSUM evidence. A channel test
has a chi-square reference only when degrees of freedom remain valid and stable. The
configured assessment-level significance budget is divided across channels.

### 3.2 Default fused detector

The default combines magnitude evidence with signed Pearson correlation. Correlation
assessment requires:

- one track;
- exact sequence intersection without duplicates;
- finite, non-degenerate channels of equal length;
- a family-wise-significant positive relation;
- one unique strict-majority positive-consensus clique.

Negative correlation is not corroboration. A dyad cannot support minority attribution.
No coherent or unique majority yields `InsufficientEvidence`, not a best-peer guess.
The runtime/full-fusion report analyzes every producer-attested consistency-projection
axis, divides the family budget across axes, and fails closed when axis attributions
conflict or positive evidence coexists with an insufficient axis.

### 3.3 Optional PID evidence

The PID path uses geometry-gated KSG mutual information and shared-exclusions atoms.
Because MI is sign-invariant, it is additive evidence rather than a substitute for the
signed-consensus gate. PID cannot convert missing geometry, degeneracy, an ambiguous
clique, or an unassessable channel into a nominal or attributed result. Bootstrap and
geometry configuration must be valid; otherwise the call fails or remains inconclusive.
Under pid-rs 1.0, the point gate explicitly declares regular full-dimensional continuous
support and records a `conditional_continuous/restricted_domain` status. PID2 atoms remain
`experimental_restricted_domain`. The configured seeded Gaussian perturbation is an
observation-noise model that changes the estimand, not a generic tie repair; its scale and
seed are carried in every PID report. The circular delete-block confirmation uses the
same support declaration but is classified as an experimental raw-scalar pipeline.

### 3.4 Standalone component experiments

The harness's standalone correlation and PID rates, AUCs, sweeps, adaptive study,
maneuver study, collusion study, and latency study are pre-registered to attested
consistency-projection **axis 0**. They isolate like-for-like scalar estimands and must not
be presented as full-detector or all-axis performance. Only the fused fields in the main
report exercise every active projection axis.

## 4. Metrics

Each result must identify the synthetic regime, seed policy, number of trials, window,
operating point, and exact commit. Report at least:

- alarm-ranked ROC-AUC (discrete alarms rank above non-alarms, then the continuous score)
  with a paired bootstrap interval for detector differences;
- detection and false-alarm proportions with binomial intervals;
- time to detect measured only when there was no pre-onset alarm;
- reachability: the fraction of trials in which a post-onset alarm occurs;
- inconclusive/error rates, reported separately rather than counted as correct;
- throughput with hardware, toolchain, build profile, and benchmark configuration.

Pointwise confidence intervals from a parameter sweep are exploratory. They do not prove
that one detector wins "somewhere" across the scanned grid without a simultaneous or
pre-registered comparison procedure.

The adaptive score study fits each axis-0 component threshold on a dedicated clean
calibration seed domain. A disjoint clean holdout seed domain reports the observed FAR
with a Wilson interval. The requested upper-tail quantile is a calibration target, not a
guaranteed realized FAR and not evidence that the two holdout FARs are identical.

## 5. Required acceptance checks

A regenerated synthetic report is useful only if all of these hold:

1. Clean trials exercise every configured channel and do not rely on a pre-onset alarm.
2. Invalid and degenerate input is rejected rather than scored.
3. Missing channels, sequence gaps, and ambiguous geometry are counted as insufficient,
   not nominal.
4. Every configured channel must be assessable; a convenient ready pair cannot hide a
   failed third channel.
5. Track IDs are never pooled into one dependence estimate.
6. Signed-correlation sign flips are not treated as corroboration.
7. Constant channels are rejected before the configured observation-noise model can
   manufacture dependence, and noise streams are not restarted identically per column.
8. Bootstrap failures and zero/invalid resample counts are not replaced with optimistic
   point estimates.
9. Multiple parameter scans disclose multiplicity.
10. Results distinguish detector failure from producer censoring or missingness.
11. Full fused/runtime reports analyze every active consistency-projection axis, and
    applicable family budgets include both axis and channel-pair multiplicity. A
    standalone axis-0 component experiment is acceptable only when labeled as that
    narrower estimand and never presented as the full detector.
12. Different positive channel attributions across axes are reported as
    `UnclassifiedAnomaly`, not selected post hoc as the most favorable
    `AttributedInconsistency` result.

## 6. Recorded-data gate

No synthetic result can validate current crebain integration. A recorded evaluation must
wait for a producer contract with:

- `consistency_projection` enabled for every requested modality in the normal runtime path;
- matching physical-frame/projection-context IDs and dimensions across modalities;
- one matching frozen-prior ID per sequence, not reused in the assessed run;
- association misses, gate rejections, and failed updates emitted explicitly;
- heartbeats for all-modal silence;
- stable session IDs and a versioned schema with restart rules.

The current bundled fixture was emitted with native research fields enabled specifically
for the fixture, but it contains no common projection attestation. Its mixed native frames
and sequential priors are never substituted. It proves bounded parsing and baseline smoke
behavior; correlation and fused assessment correctly remain `InsufficientEvidence`.

Even after the producer contract is fixed, a valid recorded study must separate:

- pre-gate detector performance;
- selection/censoring introduced by association and gating;
- benign maneuvers and track lifecycle changes;
- transport loss, restarts, and clock/sequence discontinuities;
- all-modal silence, which requires an external heartbeat.

## 7. Reproduce

```bash
# Versioned streaming evidence artifact (recommended publication path)
cargo run --locked -p galadriel-eval --release --bin galadriel-evidence -- \
  --config evidence/post-audit-v1.json \
  --out target/evidence/post-audit-v1

# Minimum-size inferential synthetic suite (still compute-intensive)
cargo run --locked -p galadriel-eval --release -- 20

# No argument uses the same minimum 20-trial default
cargo run --locked -p galadriel-eval --release

# Larger synthetic study; choose and report the trial count explicitly
cargo run --locked -p galadriel-eval --release -- 200

# Hypothesis and edge-case tests
cargo test -p galadriel-eval --locked
cargo test --workspace --all-features --locked

# Relative cost on the current machine
cargo bench -p galadriel-eval --bench detectors
```

Before printing any partial report, the CLI preflights generated-observation work,
bootstrap rank work, latency-prefix visits, and a conservative quadratic PID estimator
budget. The PID budget includes geometry/KSG fits, atom diagnostics, confirmation
resamples, all fused projection axes, and every scheduled latency probe (including the
complete capture frame).

Do not copy numeric output into project claims until the full audited workspace passes and
the report records the commit, toolchain, configuration, and hardware. Synthetic numbers
must always be labeled **synthetic**; they are not operational false-alarm or detection
rates.

## 8. Interpretation boundary

Galadriel is an advisory consistency monitor. A synthetic true positive does not prove a
sensor lied, a synthetic true negative does not cover a consistency-preserving adversary,
and a benchmark does not authorize an automated control response. Authentication, ACLs,
mTLS, safety governance, and independently validated system-level fault handling remain
separate layers.
