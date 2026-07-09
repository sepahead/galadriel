# Evaluation — the PID engine vs the NIS baseline

**Question.** Does Galadriel's cross-sensor **Partial Information Decomposition
(PID)** engine detect an attack that its cheap **NIS χ² baseline** provably cannot,
without paying for it in false alarms?

**Answer (headline).** Yes, and the two are **complementary**. On a *moment-matched
stealthy spoof* — a false-data injection engineered to keep each channel's NIS inside
its own covariance — the baseline operates at chance (ROC-AUC **0.547**) while the PID
engine reaches AUC **0.999** and a **96.5%** detection rate at a **0%** false-alarm
rate. On pure-magnitude attacks (a loud bias spoof, a broadband jam) the ordering
flips: the baseline detects **100%** and PID is correctly silent, because those
attacks preserve cross-channel correlation and are the baseline's job. Neither
detector alone is sufficient; **together they cover the space.**

This document is generated from, and reproducible by, the `galadriel-eval` harness.

---

## 1. Setup

### 1.1 Sensor model

Each of three sensor channels *c* ∈ {visual, radar, acoustic} reports, per fusion
frame, a 3-D innovation `y_c = z_c − H x̂⁻` against the *a priori* track state. We
model a **shared latent** target deviation `m` (what an honest sensor tracks) plus
independent per-channel noise:

```
y_c = m + n_c,   m ~ N(0, ρσ²·I₃),   n_c ~ N(0, (1−ρ)σ²·I₃)
```

so that (a) every channel's marginal `NIS_c = y_cᵀ S⁻¹ y_c ~ χ²(3)` under the null,
and (b) any two honest channels are correlated at `ρ`. We use **ρ = 0.7, σ = 1,
300 frames**; the engine analyses the last 128 frames. Attacks begin at frame
`frames/3`, so the analysis window lies entirely in the attacked regime.

### 1.2 The four regimes

| regime | construction | what changes |
|---|---|---|
| **clean (null)** | `y_c = m + n_c` | nothing — the negative class |
| **loud bias spoof** | acoustic `y[0] += 8σ` from onset | NIS **inflated**, correlation preserved |
| **stealthy (moment-matched)** | acoustic tracks an *independent phantom* latent `p` of the same variance | NIS **unchanged** (still χ²(3)), correlation **broken** |
| **broadband jam** | every channel `y_c ×= 3` from onset | NIS **inflated** on all, correlation preserved |

The stealthy spoof is the adversary's *optimal* move against a magnitude detector: by
matching the moments it leaves the NIS distribution invariant, so a χ² test on any
single channel is, by construction, blind to it.

### 1.3 Detectors

- **Baseline** (`galadriel-core`): the streaming NIS χ² Mirror. **Alarm** = a `Spoof`
  or `Jam` verdict. **Score** = the strongest per-channel NIS surprise,
  `max_c −log₁₀ p_right(c)`, where `p_right` is the right-tail p-value of the windowed
  NIS sum under χ²(n·dof).
- **PID** (`galadriel-pid`): geometry-gated **pairwise KSG mutual information** as a
  corroboration score per channel (its best MI with any peer), plus the `I^sx`
  redundancy atom. **Alarm** = a `Spoof` verdict (a channel decoupled from the group).
  **Score** = the decoupling depth `1 − min_c corroboration / max_c corroboration`.

Both detectors use their default configuration; no per-regime tuning.

### 1.4 Metrics

Per regime, per detector, over *N* trials (independent seeds): the **detection rate**
(fraction alarming), the **false-alarm rate** (detection rate on the clean regime),
and the **ROC-AUC** of the continuous score against the clean scores, computed via the
Mann–Whitney identity `AUC = P(score_attack > score_clean)` (ties = ½).

---

## 2. Results

`cargo run -p galadriel-eval --release 200` — **200 trials per regime**, seeds
1000…1199:

```
Galadriel evaluation — 200 trials/regime · rho=0.7 · frames=300 · sigma=1
False-alarm rate (clean):   baseline 0.030   PID 0.000   fused 0.030

regime                       | base det | PID det | fused det | base AUC | PID AUC
------------------------------------------------------------------------------------
loud bias spoof              |    1.000 |   0.000 |     1.000 |    1.000 |   0.500
stealthy (moment-matched)    |    0.020 |   0.965 |     0.965 |    0.547 |   0.999
broadband jam                |    1.000 |   0.000 |     1.000 |    1.000 |   0.500
```

Reading the table:

- **Stealthy spoof — the headline.** Baseline detection **0.020** and AUC **0.547**
  (statistically indistinguishable from the chance value 0.5) confirm the baseline is
  blind, *as the construction guarantees*. PID detection **0.965** and AUC **0.999**
  show it recovers almost all of that lost detection power — this is the capability
  PID adds and the reason it earns its complexity.
- **Loud bias spoof & jam — complementarity.** Baseline AUC **1.000** on both; PID AUC
  **0.500** (silent). PID is a *correlation* detector: a constant bias shifts a
  channel's mean but leaves its fluctuation structure — and hence its cross-channel
  correlation — intact, and a uniform scale factor is an invertible transform that KSG
  mutual information is invariant to. So PID correctly declines to flag them; the
  baseline's magnitude test owns this half of the space.
- **False alarms.** Baseline **0.030**, PID **0.000** at the default operating points —
  PID adds its detection at no false-alarm cost in this study.
- **Fused detector — full coverage.** Combining the two (§3) detects **all three**
  attacks (1.000 / 0.965 / 1.000) at the baseline's **0.030** false-alarm rate: neither
  detector alone suffices, but together they cover the space.

---

## 3. Discussion

The result decomposes the attack space along one axis — **does the attack change a
channel's magnitude, or its cross-channel agreement?** — and shows the two detectors
partition it:

```
                      preserves correlation        breaks correlation
   inflates NIS   →   loud spoof / jam  (BASELINE)      (—)
   NIS unchanged  →        (clean)                stealthy spoof  (PID)
```

The baseline occupies the top-left; PID occupies the bottom-right; the top-right cell
(inflates NIS *and* breaks correlation) is caught by *both*. This is the motivation
for **fusing** the two into a single jam-vs-spoof verdict — implemented as `galadriel_pid::assess_stream` (the `fused det` column above): a stealthy
spoof with in-covariance NIS + a PID decoupling ⇒ *spoof*; an all-channel NIS inflation
with intact correlation ⇒ *jam*; both together ⇒ a loud spoof.

The scientific claim is deliberately narrow and honest: **PID does not make the
baseline obsolete, and the baseline does not make PID redundant.** PID closes one
specific, adversary-optimal blind spot of magnitude detection.

---

> **Scope — read this with [`JUSTIFICATION.md`](JUSTIFICATION.md).** The detector that
> closes the baseline's blind spot above need not be PID. Because this stealthy spoof is
> *linear-Gaussian*, a cheap **pairwise-correlation** consistency check
> (`galadriel_core::correlation`, in the pure default build) catches it **just as well**
> as the MI/PID engine — so PID is *not uniquely* responsible for the result. The
> justification study shows MI beats correlation only when the cross-channel dependence
> is **nonlinear or synergistic** (there, `corr AUC 0.66` vs `MI AUC 1.00`). On
> galadriel's linear residuals, **correlation is the right default; PID is the opt-in
> escalation** for nonlinear modalities, synergistic fusion, or a correlation-aware
> adversary. This evaluation demonstrates *cross-sensor consistency* beats magnitude —
> it does not, by itself, justify MI over correlation.

## 4. Honest limitations

- **Gaussian, stationary sim.** Real innovations are non-Gaussian and non-stationary
  under maneuver; the synthetic study over-states detectability of a *naive* injection
  and cannot reproduce phased-emitter DOA or adversarial-patch triangulation error.
- **Non-adaptive adversary.** The stealthy spoof matches the *first two moments*. A
  gradient-aware adversary that also matches the cross-channel dependence structure
  (a statistics-matching FDI) defeats PID and the baseline alike — a fundamental
  limit, not a tuning gap.
- **Scalar projection.** The engine keys off one signed innovation axis to stay in the
  estimator's trustworthy low-dimensional band; this discards directional structure a
  full-vector estimator (with far more samples) could use.
- **Advisory only.** Every verdict is `calibrated_posterior = false`. A redundancy
  collapse is equally consistent with a spoof, a genuinely-unique true detection, or an
  estimator artifact; the detector softens and attributes, it never enforces.
- **In-sim ground truth.** Detection rates here are on synthetic captures with known
  labels; field validation against instrumented crebain fusion is future work.

The pre-registered kill criterion still governs: if a cheap per-sensor / parity
statistic matches PID within CI on a given attack, ship the cheap statistic. This study
shows a regime where it provably does not.

---

## 5. Reproduce

```bash
# Full study (200 trials/regime; ~seconds in release):
cargo run -p galadriel-eval --release 200

# Fast pass:
cargo run -p galadriel-eval 40

# The hypothesis as a unit test (asserts PID>0.8 / baseline<0.2 detection on the
# stealthy spoof, PID AUC>0.85, baseline AUC<0.75, and both magnitude attacks caught):
cargo test -p galadriel-eval
```

Design provenance: the full, adversarially-reviewed method (threat model, estimand,
estimator gates) is `galadriels-mirror.md`.
