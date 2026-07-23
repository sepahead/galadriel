# When is Partial Information Decomposition justified, and when is it forced?

Galadriel includes an optional mutual-information and Partial Information Decomposition (MI/PID) path.
This document gives the decision rule for its use.
It does not present pre-audit synthetic numbers as current detector evidence.

> **Evidence status after the 2026-07 audit.** The canonical studies are synthetic or theoretical.
> [`PID_RS_1_0_MIGRATION.md`](PID_RS_1_0_MIGRATION.md) records a fixed-seed pid-rs 0.4 to 1.0 reproduction.
> The reproduction includes complete-channel geometry gates and an explicit observation-noise model.
> It also includes bounded circular delete-block settings and fail-closed fusion.
> This result is compatibility evidence, not calibration.
>
> It does not show that recorded Crebain residuals occupy a PID-justified regime.

## 1. Linear-Gaussian dependence: PID is forced

For jointly Gaussian scalar variables,

\[
I(X;Y) = -\tfrac{1}{2}\log(1-\rho^2).
\]

Mutual information is a monotone function of correlation **magnitude**.
At the population level, MI and an absolute-correlation score rank linear-Gaussian dependence identically.
A nonparametric Kraskov–Stögbauer–Grassberger (KSG) estimate adds finite-sample variance and compute cost.
It cannot add population information that the covariance does not contain.

This theorem supports a model-selection rule.
It does not make a claim about recorded data.
Current Crebain output has not shown one common-frame, common-prior, linear-Gaussian cross-modal residual process.

The runtime default is stricter than the analytical absolute-correlation comparison.
It uses **signed** correlation.
A sign flip is operationally inconsistent even when MI and `|rho|` do not change.
The sign-invariant PID path must never override that geometry.

## 2. Nonlinear dependence: MI can be justified

MI can add information when dependence is real but linear covariance does not represent it.
Canonical examples include a nonlinear magnitude relation.
They also include randomized sign coupling with zero population correlation and a constrained variable.

The synthetic study tests a validated KSG estimate.
It asks whether the estimate separates coupled windows from independent windows.
The study accounts for finite sample size, dimensionality, ties, and estimator uncertainty.
A positive result justifies MI research for that **specified coupling**.
It does not justify PID for arbitrary producer data.

## 3. Synergy: decomposition can be justified

Pairwise MI can also be blind.
In exclusive-or (XOR) or sign-parity constructions, neither source alone predicts the target.
The source pair does predict the target.
Joint information can reveal this relation.
PID then identifies redundant, unique, or synergistic parts.

This case is the strongest conceptual reason to use decomposition instead of pairwise MI.
It is also narrow.
The target variable, source geometry, estimator, and atom semantics must correspond to an actual system estimand.
A canonical XOR result does not show that a sensor-fusion residual stream contains operational synergy.

Galadriel reports shared-exclusions (`I^sx`) atoms as advisory research evidence.
That definition permits negative local or aggregate atoms.
The atoms are not probabilities, confidence values, or calibrated attack scores.

## 4. Sequential evidence

Windowed estimators have refill latency after a change.
Pointwise local-information statistics can, in principle, supply a cumulative sum (CUSUM) more quickly.
This use requires a clean reference or calibration distribution.
It also requires validation of false-alarm behavior.
The canonical sequential study motivates future work.
It is not the runtime streaming algorithm.

Do not cite it as current production latency.

## 5. The significance floor and its independent and identically distributed assumption

The runtime default accepts a positive cross-channel edge only after it passes a family-wise Fisher-z significance floor.
The standard error is `1/sqrt(n-3)`.
This error assumes independent and identically distributed (i.i.d.) bivariate-normal residual pairs.
Windowed residual series do not have to be independent in time.
The attested common-frozen-prior consistency residual has no whiteness guarantee.
See `PAPER.md` section 7.

The canonical autocorrelation-null study measures the effect under the null.
It uses two independent first-order autoregressive (AR(1)) channels.
Their population cross-correlation is exactly zero.
Their lag-1 coefficient is `phi`.
The study uses the detector's one-sided construction with the default window `n = 128`.

Bartlett's large-sample variance for this null is `var(rho_hat) ~ (1 + phi^2) / ((1 - phi^2) n)`.
The source is M. S. Bartlett, "Some Aspects of the Time-Correlation Problem in Regard to Tests of Significance."
It appeared in *Journal of the Royal Statistical Society* 98(3):536–543, 1935.
The approximation predicts these false-positive rates (FPRs) for the same construction:

| phi | predicted FPR at α=.05 | predicted FPR at α=.01 |
|----:|-----------------------:|-----------------------:|
| 0.3 | 0.066 | 0.017 |
| 0.5 | 0.101 | 0.036 |
| 0.7 | 0.168 | 0.087 |
| 0.9 | 0.297 | 0.226 |

The predicted direction is anti-conservative, and the effect is large.
At `phi = 0.9`, the approximation predicts activation more than twenty times too often for the nominal 1% floor.
The bounded repository study uses at most 1,000 trials for each `phi`.
It checks the direction without claiming high-precision Monte Carlo estimates.

Replacing `n` with Bartlett's effective sample size improves calibration for moderate persistence.
The value is `n_eff = n (1 - phi^2) / (1 + phi^2)`.
This method is not an exact finite-sample correction.

At `phi = 0.9`, `n_eff` is only about 13.4.
The deterministic 1,000-trial seed-7 study is conservative at this value.
It gives `FPR@.05 = .023` with Wilson interval `[.015,.034]`.
It gives `FPR@.01 = .001` with interval `[0,.006]`.

The tests require the moderate-persistence improvement.
They also require this high-persistence finite-sample limit.
They do not claim universal recalibration.

This result quantifies a **disclosed limitation** of the runtime default.
It does not change that default.
An operational correction must estimate `phi` from data.
That estimate has its own uncertainty.
Thus, the correction is a registered enhancement decision, not a documentation fix.

## 6. Operational decision rule

Use the least complex statistic that observes the registered estimand:

1. Use Normalized Innovation Squared (NIS) and CUSUM for validated per-channel magnitude changes.
2. Use signed correlation when comparable residuals have an expected positive linear consensus.
3. Add MI only when recorded evidence shows meaningful nonlinear dependence that signed correlation misses.
4. Add PID atoms only for a documented joint target and source synergy question. The estimator geometry must have enough data.
5. Return an error or `InsufficientEvidence` when these preconditions fail.

PID is additive and sign-invariant.
It cannot:

- repair mixed coordinate frames or sequentially changing priors
- create evidence for a missing, degenerate, non-finite, or short modality series
- create an honest majority from two channels
- resolve tied or contradictory consensus geometry
- change bootstrap failure into a low, optimistic score
- change a signed-correlation contradiction into corroboration

## 7. Required producer evidence

Before PID use, the selected conforming producer must emit:

- `consistency_projection` in the normal runtime path for each requested modality
- matching nonzero physical-frame and projection-context identifiers
- matching frozen-prior identifiers within each sequence, with no reuse across assessed sequences
- explicit association misses and gate rejections
- a heartbeat, stable session identity, and a versioned schema

The checked-in historical fixture intentionally enables native research fields.
It has no attested common projection.
Galadriel does not use its mixed-frame, sequential-prior innovations as a fallback.
The fixture proves parsing and baseline smoke behavior only.
Cross-correlation, PID, and fused attribution remain `InsufficientEvidence`.

## 8. Reproduce the canonical studies

```bash
cargo run --locked -p galadriel-justify --release
cargo test -p galadriel-justify --locked
```

Regenerated results must record the commit, toolchain, trial count, window, and seeds.
They must also record bootstrap settings and each inconclusive or error outcome.
Do not make exact numbers project claims before the audited implementation and tests pass.
After they pass, label the numbers as synthetic.
