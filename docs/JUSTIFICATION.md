# When is PID justified, and when is it forced?

Galadriel includes an optional mutual-information/Partial Information Decomposition
(MI/PID) path. This document states the decision rule for using it without presenting
pre-audit synthetic numbers as current detector evidence.

> **Evidence status (2026-07 audit).** The canonical studies are synthetic/theoretical.
> Exact results from the previous implementation were removed pending regeneration with
> validated inputs, domain-separated jitter, complete-channel geometry gates, validated
> bootstrap settings, and fail-closed fusion. Nothing here establishes that current
> crebain residuals occupy a PID-justified regime.

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

## 5. Operational decision rule

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

## 6. Producer evidence required

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

## 7. Reproduce the canonical studies

```bash
cargo run -p galadriel-justify --release
cargo test -p galadriel-justify --locked
```

Regenerated results must record the commit, toolchain, trial count, window, seeds,
bootstrap settings, and every inconclusive/error outcome. Exact numbers should not become
project claims until the audited implementation and tests pass. Even then they must be
labeled synthetic.
