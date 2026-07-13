# When is PID justified, and when is it forced?

Galadriel includes an optional mutual-information/Partial Information Decomposition
(MI/PID) path. This document states the decision rule for using it without presenting
pre-audit synthetic numbers as current detector evidence.

> **Evidence status (2026-07 audit).** The canonical studies are synthetic/theoretical.
> A fixed-seed pid-rs 0.4→1.0 reproduction is recorded in
> [`PID_RS_1_0_MIGRATION.md`](PID_RS_1_0_MIGRATION.md), with complete-channel geometry
> gates, explicit observation-noise modeling, bounded circular delete-block settings,
> and fail-closed fusion. It is compatibility evidence, not calibration; nothing here
> establishes that recorded Crebain residuals occupy a PID-justified regime.

## 1. Linear-Gaussian dependence: PID is forced

For jointly Gaussian scalar variables,

\[
I(X;Y) = -\tfrac{1}{2}\log(1-\rho^2).
\]

Mutual information is therefore a monotone function of the **magnitude** of correlation.
At the population level, MI and an absolute-correlation score rank linear-Gaussian
dependence identically. A nonparametric KSG estimate adds finite-sample variance and
compute cost; it cannot add population information that the covariance does not contain.

This theorem supports a model-selection rule, not a claim about recorded data. Current
crebain output has not been shown to be one common-frame, common-prior, linear-Gaussian
cross-modal residual process.

The runtime default is stricter than the analytical absolute-correlation comparison: it
uses **signed** correlation. A sign flip is operationally inconsistent even though MI and
`|rho|` are unchanged. The sign-invariant PID path must never override that geometry.

## 2. Nonlinear dependence: MI can be justified

MI can add information when dependence is real but not represented by linear covariance.
Canonical examples include a nonlinear magnitude relation or a randomized sign coupling
whose population correlation vanishes while one variable still constrains the other.

The synthetic study asks whether a validated KSG estimate separates coupled from
independent windows after accounting for finite sample size, dimensionality, ties, and
estimator uncertainty. A positive result justifies researching MI for that **specified
coupling**. It does not justify enabling PID for arbitrary producer data.

## 3. Synergy: decomposition can be justified

Pairwise MI can also be blind. In XOR-like or sign-parity constructions, neither source
alone predicts the target while the source pair does. Joint information can reveal this;
PID then asks which part is redundant, unique, or synergistic.

This is the strongest conceptual reason for decomposition rather than pairwise MI. It is
also a narrow one. The target variable, source geometry, estimator, and atom semantics must
all correspond to an actual system estimand. A canonical XOR result is not evidence that a
sensor-fusion residual stream contains operational synergy.

Galadriel reports shared-exclusions (`I^sx`) atoms as advisory research evidence. Negative
local or aggregate atoms are permitted by that definition and are not probabilities,
confidence values, or calibrated attack scores.

## 4. Sequential evidence

Windowed estimators incur refill latency after a change. Pointwise/local-information
statistics can in principle feed a sequential CUSUM more quickly, but only after a clean
reference/calibration distribution is defined and its false-alarm behavior is validated.
The canonical sequential study motivates future work; it is not the runtime streaming
algorithm and must not be quoted as current production latency.

## 5. The significance floor's i.i.d. assumption (autocorrelation null)

The runtime default accepts a positive cross-channel edge only past a family-wise Fisher-z
significance floor whose standard error, `1/sqrt(n-3)`, assumes the windowed residual pairs
are i.i.d. bivariate normal. Windowed residual series need not be independent in time, and
the attested common-frozen-prior consistency residual carries no whiteness guarantee (see
`PAPER.md` §7).

The canonical autocorrelation-null study measures the consequence under the null: two
**independent** AR(1) channels (population cross-correlation exactly zero, lag-1
coefficient `phi`), scored by the detector's own one-sided construction at the default
window `n = 128`. Bartlett's large-sample variance for this null,
`var(rho_hat) ~ (1 + phi^2) / ((1 - phi^2) n)` (M. S. Bartlett, "Some Aspects of the
Time-Correlation Problem in Regard to Tests of Significance," *Journal of the Royal
Statistical Society* 98(3):536–543, 1935), predicts the following asymptotic rates for the
same construction:

| phi | predicted FPR at α=.05 | predicted FPR at α=.01 |
|----:|-----------------------:|-----------------------:|
| 0.3 | 0.066 | 0.017 |
| 0.5 | 0.101 | 0.036 |
| 0.7 | 0.168 | 0.087 |
| 0.9 | 0.297 | 0.226 |

The predicted direction is anti-conservative and the effect is large: at `phi = 0.9` the
nominal 1% floor is expected to fire more than twenty times too often. The bounded,
repository-reproducible study (at most 1,000 trials per `phi`) checks that direction without
claiming high-precision Monte Carlo estimates. Replacing `n` with Bartlett's effective
sample size `n_eff = n (1 - phi^2) / (1 + phi^2)` substantially improves calibration for
moderate persistence. It is not an exact finite-sample correction: at `phi = 0.9`,
`n_eff` is only about 13.4 and the deterministic 1,000-trial seed-7 study is conservative
(`FPR@.05 = .023`, Wilson interval `[.015,.034]`; `FPR@.01 = .001`, interval `[0,.006]`).
The tests assert both the moderate-persistence improvement and this high-persistence
finite-sample limit instead of claiming universal recalibration.

This quantifies a **disclosed limitation** of the runtime default rather than changing it:
an operational correction must estimate `phi` from data, whose own uncertainty makes it a
registered enhancement decision, not a documentation fix.

## 6. Operational decision rule

Use the cheapest statistic that observes the registered estimand:

1. Use NIS/CUSUM for validated per-channel magnitude changes.
2. Use signed correlation when comparable residuals should form one positive linear
   consensus.
3. Add MI only when recorded evidence demonstrates meaningful nonlinear dependence that
   signed correlation misses.
4. Add PID atoms only when the joint target/source construction has a documented
   synergy question and enough data for the estimator geometry.
5. Return an error or `InsufficientEvidence` when those preconditions fail.

PID is additive and sign-invariant. It cannot:

- repair mixed coordinate frames or sequentially changing priors;
- create evidence for a modality whose series is missing, degenerate, non-finite, or too
  short;
- create an honest majority from two channels;
- resolve tied or contradictory consensus geometry;
- turn bootstrap failure into a low, optimistic score;
- convert a signed-correlation contradiction into corroboration.

## 7. Producer evidence required

Before deciding whether PID is justified for crebain, the producer must emit:

- `consistency_projection` in the normal runtime path for every requested modality;
- matching non-zero physical-frame and projection-context IDs;
- matching frozen-prior IDs within each sequence, unique across assessed sequences;
- explicit association misses and gate rejections;
- heartbeat, stable session identity, and a versioned schema.

The current fixture intentionally enables native research fields but has no attested
common projection. Galadriel does not fall back to its mixed-frame, sequential-prior
innovations. It proves parsing and baseline smoke behavior only; cross-correlation, PID,
and fused attribution remain `InsufficientEvidence`.

## 8. Reproduce the canonical studies

```bash
cargo run -p galadriel-justify --release
cargo test -p galadriel-justify --locked
```

Regenerated results must record the commit, toolchain, trial count, window, seeds,
bootstrap settings, and every inconclusive/error outcome. Exact numbers should not become
project claims until the audited implementation and tests pass. Even then they must be
labeled synthetic.
