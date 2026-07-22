# Evaluation evidence plan and synthetic harness

This document describes the Galadriel evaluation method.
It also states what the current evidence does **not** establish.

> **Status after the 2026-07 correctness audit.** The evaluation harness uses synthetic data.
> The project removed numeric tables from the pre-audit detector.
> The implementation now validates inputs and joins channels by exact sequence.
> It uses signed correlation with a unique strict-majority consensus.
> It controls each assessment family and fails closed.
> The published `post-audit-v1` artifact gives exact streaming results for the Normalized Innovation Squared (NIS) and signed-correlation vertical slice.
>
> Those results cover false alerts, delay, abstention, and attribution.
> The broader comparative harness still needs a versioned post-audit report.
> Do not cite exact area-under-curve (AUC), matched-operating-point, adaptive, maneuver, collusion, latency, or cost values before this report exists.

## 1. Questions that the harness can answer

The Monte Carlo harness compares detector behavior under explicit generated models.
It can answer these questions:

1. Does an NIS magnitude layer react to loud single-channel bias and common-mode inflation?
2. Does signed cross-channel correlation detect a synthetic decoupling that preserves per-channel magnitude?
3. Does mutual information or Partial Information Decomposition (MI/PID) add information in a deliberately nonlinear or synergistic synthetic construction?
4. How do window length, attack onset, decoupling strength, collusion, threshold-hugging, and benign lag affect synthetic detection and latency?
5. What is the relative compute cost on the benchmark machine?

The harness cannot determine whether a deployed external producer satisfies these models.
It cannot determine how operators respond.
It cannot determine whether a verdict is safe for control use.

## 2. Synthetic model

The simulator generates multiple modalities from a shared latent process.
It uses a documented covariance and a common sequence.
A seed makes clean and attacked trials reproducible.
The simulator validates scenario configuration before generation.
It returns an error for an invalid, non-finite, degenerate, or overflowing configuration.

The synthetic attack families are:

- **loud single-channel bias**, which tests NIS and cumulative sum (CUSUM) evidence
- **common-mode inflation**, which tests jam-like magnitude evidence
- **moment-matched decoupling**, which preserves marginal channel magnitude while it changes signed dependence
- **collusion**, which exposes the honest-majority boundary
- **adaptive or threshold-hugging bias**, which explores evasion near a configured operating point
- **benign lag or maneuver proxies**, which measure false alarms from timing or model mismatch
- **canonical nonlinear and synergistic couplings**, which test whether MI/PID adds information that signed linear correlation does not contain

The simulator creates these controlled constructions.
They are not recordings of real attacks.

## 3. Detectors under comparison

### 3.1 Magnitude baseline

The baseline uses per-track and per-modality NIS windows and CUSUM evidence.
A channel test has a chi-square reference only when its degrees of freedom remain valid and stable.
The detector divides the configured assessment significance budget across channels.

### 3.2 Default fused detector

The default detector combines magnitude evidence with signed Pearson correlation.
The correlation assessment requires:

- one track
- an exact sequence intersection without duplicates
- finite, non-degenerate channels of equal length
- a family-wise-significant positive relation
- one unique strict-majority positive-consensus clique

Negative correlation is not corroboration.
A dyad cannot support minority attribution.
A missing or nonunique coherent majority produces `InsufficientEvidence`.
The detector does not select a best peer.

The runtime full-fusion report analyzes each producer-attested consistency-projection axis.
It divides the family budget across axes.
It fails closed when axis attributions conflict.
It also fails closed when positive evidence occurs with an insufficient axis.

### 3.3 Optional PID evidence

The PID path uses geometry-gated Kraskov–Stögbauer–Grassberger (KSG) mutual information and shared-exclusions atoms.
MI is sign-invariant.
Thus, it supplies additive evidence and does not replace the signed-consensus gate.

PID cannot change missing geometry or degeneracy into a nominal or attributed result.
It cannot change an ambiguous clique or unassessable channel into such a result.
Bootstrap and geometry configurations must be valid.
Otherwise, the call fails or remains inconclusive.

The pinned pid-rs revision has a manifest that declares version 1.0.0.
The point gate explicitly declares regular full-dimensional continuous support.
It records a `conditional_continuous/restricted_domain` status.
The project claims no released upstream 1.x artifact.
PID2 atoms remain `experimental_restricted_domain`.

The configured seeded Gaussian perturbation is an observation-noise model.
This model changes the estimand.
It is not a general tie repair.
Each PID report carries the scale and seed.
The circular delete-block confirmation uses the same support declaration.
It remains an experimental raw-scalar pipeline.

### 3.4 Standalone component experiments

The harness pre-registers standalone component experiments to attested consistency-projection **axis 0**.
These experiments include correlation and PID rates, area under the receiver operating characteristic curve (AUC), and sweeps.
They also include adaptive, maneuver, collusion, and latency studies.

The experiments isolate comparable scalar estimands.
Do not present them as full-detector or all-axis performance.
Only the fused fields in the main report exercise each active projection axis.

### 3.5 Bounded maneuver design

The complete command-line interface (CLI) suite fixes a benign `12σ` triangular maneuver of 90 frames.
The maneuver starts at `floor(frames/3)`.
The suite uses the lag grid `[0, 8, 16, 24, 32]`.
The current study uses three modalities.
Their lag multipliers are visual `0`, acoustic `2`, and radar `3`.

A lag `L` occupies half-open windows that end no later than `floor(F/3) + 3L + D`.
Here, `F` is capture length and `D` is maneuver duration.
Preflight requires this endpoint to be at most `F`.
Thus, the suite observes the complete maneuver for each modality.
It does not right-censor the maneuver.
At the named profile values `F=300` and `D=90`, the largest registered lag ends at frame 286.

The simulator samples the continuous triangle over `[start, start + D)`.
Its included start and excluded right endpoint are zero.
An even `D` samples the exact configured peak.
An odd `D` has two equal central samples at `(1 - 1/D)` times the peak parameter.

`EvalSuiteConfig::try_new` and direct `maneuver_far` calls enforce the same pre-generation checks.
The lag grid must have 1 through 10,000 unique `u64` entries.
Magnitude must be finite and positive, with a finite square.
Duration must be at least two frames.
Each checked window must fit.

The study also enforces two work limits with checked arithmetic.
It requires `trials * lag_count <= 50,000`.
It requires `trials * frames * 3 * lag_count <= 100,000,000`.
The study checks these limits before PID-work preflight.
These limits bound workload and require complete exposure.
They do not show that the proxy represents field maneuvers.

## 4. Metrics

Each result must identify the synthetic regime, seed policy, trial count, window, operating point, and exact commit.
Report at least:

- alarm-ranked AUC, where discrete alarms rank above non-alarms and then use the continuous score
- a paired bootstrap interval for detector AUC differences
- detection and false-alarm proportions with binomial intervals
- detection time only for trials without a pre-onset alarm
- reachability, which is the fraction of trials with a post-onset alarm
- separate inconclusive and error rates, without counting them as correct
- throughput with hardware, toolchain, build profile, and benchmark configuration

Pointwise confidence intervals from a parameter sweep are exploratory.
They do not prove that one detector wins somewhere across the scanned grid.
Such a claim needs a simultaneous or pre-registered comparison procedure.

The adaptive score study fits each axis-0 component threshold on a dedicated clean calibration seed domain.
A separate clean holdout seed domain reports the observed false-alarm rate (FAR) with a Wilson interval.
The requested upper-tail quantile is a calibration target.
It does not guarantee the realized FAR.
It does not show that the two holdout FARs are identical.

## 5. Required acceptance checks

A regenerated synthetic report is useful only when all these conditions hold:

1. Clean trials exercise each configured channel and do not depend on a pre-onset alarm.
2. The system rejects invalid and degenerate input instead of scoring it.
3. The system counts missing channels, sequence gaps, and ambiguous geometry as insufficient instead of nominal.
4. Each configured channel is assessable. A ready pair cannot hide a failed third channel.
5. The system never pools track identifiers into one dependence estimate.
6. The system does not treat signed-correlation sign flips as corroboration.
7. The system rejects constant channels before observation noise can create dependence. Noise streams do not restart identically for each column.
8. The system does not replace bootstrap failures or invalid resample counts with optimistic point estimates.
9. Reports disclose multiplicity for multiple parameter scans.
10. Results distinguish detector failure from producer censoring or missingness.
11. Full fused reports analyze each active projection axis. Applicable family budgets include axis and channel-pair multiplicity.
    A standalone axis-0 experiment must label its narrower estimand. It must not call this the full detector.
12. Different positive channel attributions across axes produce `UnclassifiedAnomaly`. The system does not select a favorable `AttributedInconsistency` result after inspection.

## 6. Recorded-data gate

No synthetic or component result can validate a deployed Crebain integration.
Two revisions identify a retained historical epoch and registry compatibility fixture:

- Crebain `4c311900ade5668200a48d56fb191be1916b884a`
- Galadriel `81437d807ca83b66b45c8353968948e540072d97`

These revisions do not reciprocally pin this candidate.
Current cross-repository qualification is `NOT_CLAIMED`.
A recorded evaluation must capture and verify these items against the exact current binaries:

- the normal runtime path enables `consistency_projection` for each requested modality
- physical-frame and projection-context identifiers and dimensions match across modalities
- one frozen-prior identifier matches each sequence, and the assessed run does not reuse it
- the producer emits association misses, gate rejections, and failed updates explicitly
- heartbeats identify all-modal silence
- session identifiers are stable and use a versioned schema with restart rules

The bundled historical fixture enabled native research fields for that fixture.
It contains no common projection attestation.
The system never substitutes its mixed native frames or sequential priors.
The fixture proves bounded parsing and baseline smoke behavior.
Correlation and fused assessment remain `InsufficientEvidence`.

A valid recorded study must separate:

- pre-gate detector performance
- selection and censoring from association and gating
- benign maneuvers and track lifecycle changes
- transport loss, restarts, and clock or sequence discontinuities
- all-modal silence, which requires an external heartbeat

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

The CLI completes preflight before it prints a partial report.
Preflight checks generated-observation work, bootstrap rank work, and latency-prefix visits.
It also checks a conservative quadratic PID estimator budget.
The PID budget includes geometry and KSG fits, atom diagnostics, and confirmation resamples.
It includes all fused projection axes and each scheduled latency probe, including the complete capture frame.

Do not copy numeric output into project claims until the complete audited workspace passes.
The report must also record the commit, toolchain, configuration, and hardware.
Always label synthetic numbers as **synthetic**.
They are not operational false-alarm or detection rates.

## 8. Interpretation boundary

Galadriel is an advisory consistency monitor.
A synthetic true positive does not prove that a sensor lied.
A synthetic true negative does not cover a consistency-preserving adversary.
A benchmark does not authorize an automated control response.

Authentication, access control lists (ACLs), and mutual Transport Layer Security (mTLS) remain separate layers.
Safety governance and independently validated system-level fault handling also remain separate layers.
