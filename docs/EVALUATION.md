# Evaluation — cross-sensor consistency vs the NIS baseline

**Question.** Does a Galadriel **cross-sensor consistency** check detect an attack that
its cheap **NIS χ² baseline** provably cannot, without paying for it in false alarms —
and, sharper, does that check have to be **Partial Information Decomposition (PID)**, or
does a one-line correlation suffice?

**Answer (headline).** Yes to the first, and — for this attack — *no, it need not be PID*.
On a *moment-matched stealthy spoof* — a false-data injection engineered to keep each
channel's NIS inside its own covariance — the baseline operates at chance (ROC-AUC
**0.547**), while **both** cross-sensor detectors recover it: the cheap **pure
correlation default** reaches AUC **1.000** and the **KSG-MI PID engine** AUC **0.999**,
each at a ≤3% false-alarm rate. On pure-magnitude attacks (a loud bias spoof, a
broadband jam) the baseline detects **100%** and the consistency detectors' *scores* are
correctly at chance, because those attacks preserve cross-channel correlation and are
the baseline's job. No single component suffices; **the fused detector covers the space.**

Two results, at two levels. **Operationally:** cross-sensor consistency beats magnitude
on the stealthy spoof. **Methodologically:** on this *linear-Gaussian* spoof the cheap
correlation check *matches* the MI engine (AUC 1.000 vs 0.999) — so here PID is
**forced, not justified**; it earns its cost only on the nonlinear/synergistic couplings
quantified in [`JUSTIFICATION.md`](JUSTIFICATION.md). This study is honest about that.

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
- **Correlation default** (`galadriel-core`, *pure* — no `pid-core`): the NIS baseline
  ⊕ a pairwise-`|ρ|` cross-sensor consistency check (`assess_default`). **Alarm** = a
  `Spoof`/`Jam` fused verdict. **Score** = the decoupling depth
  `1 − min_c |ρ|(c) / max_c |ρ|(c)` over each channel's best-peer correlation. This is
  the detector the **default build ships** — a complete detector with no heavy dependency.
- **PID** (`galadriel-pid`): the same structure with geometry-gated **pairwise KSG mutual
  information** substituted for `|ρ|` as the corroboration score, plus the `I^sx`
  redundancy atom. **Alarm** = a `Spoof` verdict (a channel decoupled from the group).
  **Score** = the decoupling depth over MI corroborations — *the identical formula*, so
  the correlation default and the PID engine are read off the same axis and are directly
  comparable.

All detectors use their default configuration; no per-regime tuning.

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
False-alarm rate (clean):   baseline 0.030   corr 0.030   PID 0.000   fused 0.030

regime                       | base det | corr det | PID det | fused det | base AUC | corr AUC | PID AUC
--------------------------------------------------------------------------------------------------------
loud bias spoof              |    1.000 |    1.000 |   0.000 |     1.000 |    1.000 |    0.500 |   0.500
stealthy (moment-matched)    |    0.020 |    1.000 |   0.965 |     0.965 |    0.547 |    1.000 |   0.999
broadband jam                |    1.000 |    1.000 |   0.000 |     1.000 |    1.000 |    0.500 |   0.500
```

Reading the table:

- **Stealthy spoof — the headline.** Baseline detection **0.020** and AUC **0.547
  [0.490, 0.603]** — the bootstrap CI **brackets 0.5**, confirming the baseline is blind,
  *as the construction guarantees*. Both cross-sensor detectors recover it: the
  **correlation default** at AUC **1.000 [1.000, 1.000]**, the **PID** engine at **0.999
  [0.999, 1.000]**. A **paired** bootstrap gives their difference as **ΔAUC +0.001, CI
  [+0.000, +0.001]** — the CI reaches 0, so they are a **statistical tie**; the tiny gap is
  not interpreted as an ordering (for linear-Gaussian data `MI = −½ln(1−ρ²)` is monotone in
  `ρ`, so the two detect the *same* structure, `|ρ|` exactly and KSG-MI with estimator
  variance). **This is the empirical face of `JUSTIFICATION.md` §1: MI/PID is forced, not
  justified, on this spoof** — same accuracy, ~100× the cost (§2.2).
- **Loud bias spoof & jam — complementarity.** Baseline AUC **1.000** on both; the
  consistency *scores* sit at AUC **0.500** (silent). A constant bias shifts a channel's
  mean but leaves its fluctuation structure — hence its cross-channel `|ρ|` and MI —
  intact, and a uniform scale factor is invertible so both correlation and MI are
  invariant to it. So the consistency *score* correctly declines to flag them; the
  baseline's magnitude test owns this half of the space. (The `corr det` **1.000** here
  comes from the *NIS component* of the fused default, not the correlation score — the
  pure default is itself a complete detector.)
- **False alarms.** Baseline **0.030**, correlation default **0.030**, PID **0.000** at
  the default operating points — the added detection costs no false alarms in this study.
- **Fused detector — full coverage.** The NIS ⊕ PID fusion (§3) detects **all three**
  attacks (1.000 / 0.965 / 1.000) at the baseline's **0.030** false-alarm rate; the pure
  NIS ⊕ correlation default (the `corr det` column) does the same (1.000 / 1.000 / 1.000)
  **with no `pid-core` dependency at all**.

### 2.1 Detection latency (time-to-detect)

AUC and detection rate score the *final* window; operationally, **how fast** a detector
fires after onset matters just as much. Re-running each detector on growing prefixes
(every 4 frames, 100 ms/frame) and taking the median frame of first alarm — with `reach`,
the fraction of trials that ever alarmed:

```
Detection latency — median frames from attack onset to first alarm
50 trials/regime · prefix step 4 frames · 100 ms/frame · '—' = never fires

regime                       |     baseline | corr default |          PID
--------------------------------------------------------------------------
loud bias spoof              |    4f (100%) |    4f (100%) |     — (  0%)
stealthy (moment-matched)    |   40f ( 30%) |   80f (100%) |   52f (100%)
broadband jam                |    4f (100%) |    4f (100%) |     — (  0%)
```

- **Magnitude attacks fire near-instantly.** The baseline (and the correlation default's
  NIS component) alarm within **~4 frames / 0.4 s** of a loud spoof or a jam — magnitude
  is visible the moment one inflated window accumulates. PID correctly never fires (0%);
  a bias/scale attack preserves the cross-channel structure it keys off.
- **Stealthy detection carries a real window-fill latency.** The cross-sensor detectors
  need enough *post-onset* decoupled frames inside their 128-frame window before the
  broken agreement is statistically legible: **52 frames (PID) / 80 frames (correlation
  default)** — 5–8 s. This is an intrinsic cost of the stealthy regime, not a tuning gap:
  a moment-matched spoof is *designed* to reveal itself slowly. It is caught **reliably**
  (100 % reach) but not instantly, and saying so is part of an honest evaluation.
- **A latency nuance (reported descriptively, not as an ordering).** Here PID's column
  trips ~28 frames *earlier* than the correlation column — but the two are **not** measured
  under the same wiring (the `corr` column is the fused NIS ⊕ correlation detector, the
  `PID` column the standalone engine), the numbers are ±4-frame quantized, and at the full
  window their accuracy is a statistical tie (§2, ΔAUC ≤ 0.001). We therefore do not read an
  ordering from the latency gap; reporting accuracy *and* latency honestly is the point.
- The baseline's **30 % reach** on the stealthy spoof (median 40 f *among only the trials
  it fired in*) is the occasional chance NIS excursion of the phantom latent, not reliable
  detection — contrast the **100 %** reach of the cross-sensor detectors.

### 2.2 Detector cost (throughput)

Accuracy and latency are two of three axes; the third is **compute cost**. A criterion
micro-benchmark (`benches/detectors.rs`) prices each detector on the same 300-frame,
3-channel stealthy-spoof workload. Indicative single-machine timings (release, per
full-stream assessment — absolute numbers are hardware-dependent; the *ratios* are the
point):

```
detector                       |  time/assessment |  vs default
----------------------------------------------------------------
baseline (NIS χ²)              |           ~19 µs |      0.9×
correlation default (NIS ⊕|ρ|) |           ~22 µs |      1.0×  (reference)
PID engine (KSG-MI)            |         ~2160 µs |      ~99×
fused (NIS ⊕ PID)              |         ~2180 µs |     ~100×
```

- **The correlation default is essentially free.** Adding the pairwise-`|ρ|` consistency
  check costs ~15 % over the bare NIS baseline — both are tens of microseconds, trivially
  real-time at any sensible fusion rate.
- **The PID escalation costs ~100× the default.** The KSG mutual-information estimator
  (a k-NN search per channel pair) is three orders of magnitude slower. On the
  linear-Gaussian stealthy spoof — where §2 shows it delivers the *same* AUC as
  correlation — that is **~100× the compute for zero accuracy gain**. This is the cost
  face of [`JUSTIFICATION.md`](JUSTIFICATION.md): run the cheap default, and pay the 100×
  only where the dependence is genuinely nonlinear/synergistic and the escalation actually
  buys something.
- The fused detector is KSG-dominated (the µs-scale NIS pass is lost in the noise), so it
  costs the same order as PID alone.

Reproduce: `cargo bench -p galadriel-eval --bench detectors`.

### 2.3 The detection boundary (decoupling sweep)

§2 used a *fully* decoupled spoof. Sweeping the decoupling strength `d` (the compromised
channel tracks `√(1−d)·truth + √d·phantom`, staying moment-matched while its honest
correlation scales as `√(1−d)`) traces the operating boundary (200 trials, bootstrap CIs):

```
   d  |  corr AUC [95% CI]     |  PID AUC [95% CI]
------------------------------------------------------
 1.00 |  1.000 [1.000, 1.000]  |  0.999 [0.998, 1.000]
 0.60 |  1.000 [0.999, 1.000]  |  0.908 [0.874, 0.938]   <- CIs separate
 0.40 |  0.959 [0.938, 0.977]  |  0.767 [0.718, 0.811]
 0.20 |  0.710 [0.658, 0.760]  |  0.636 [0.578, 0.688]
 0.05 |  0.512 [0.453, 0.567]  |  0.475 [0.419, 0.529]
```

Both degrade smoothly to chance as the spoof weakens, but **correlation does not merely
tie PID off the best case — through the mid-boundary `d ∈ [0.2, 0.8]` it strictly beats it**:
the *paired* corr−PID ΔAUC bootstrap (the powerful test, consistent with §2) lies wholly
above 0 there (e.g. `d=0.6`: ΔAUC +0.092 [+0.062, +0.127]). At the extremes they tie — `d=1`
(ΔAUC ≤0.001) and `d ≤ 0.1` where both have collapsed to chance. Sample `|ρ|` is the
efficient dependence statistic for Gaussian data; KSG-MI is a nonparametric estimator whose
finite-sample variance dominates once the effect is small. So on linear-Gaussian residuals
MI/PID is not just *forced* — through the discriminable mid-boundary it is strictly **worse**.
This is the degradation curve the accuracy study's single (full-decouple) point could not show.

### 2.4 Where consistency breaks — the honest-majority failure

Cross-sensor consistency assumes an **honest majority**. When it is violated — **2 of 3**
channels collude on a *shared* phantom (radar + acoustic track one lie), visual honest — the
two liars mutually corroborate and become the false consensus (200 trials):

```
correlation flags the HONEST channel:  1.000 [0.981, 1.000]   (fires: 1.000)
PID         flags the HONEST channel:  0.975 [0.943, 0.989]
```
(Wilson 95 % CIs.)

The detector **inverts** — it fires, but accuses the *innocent* channel (correlation every
time, PID 97.5 %). This is **structural**: consensus-based consistency cannot distinguish a
true majority from a colluding one, so neither correlation nor PID escapes it. The honest
scope: consistency detection needs `f < C/2`; beyond that the backstop is structural —
cryptographic channel authentication against an external spoofer, plus hardware attestation /
physical diversity for a genuinely owned sensor — not a smarter statistic.

---

## 3. Discussion

The result decomposes the attack space along one axis — **does the attack change a
channel's magnitude, or its cross-channel agreement?** — and shows the two detectors
partition it:

```
                      preserves correlation           breaks correlation
   inflates NIS   →   loud spoof / jam  (BASELINE)          (—)
   NIS unchanged  →        (clean)              stealthy spoof  (CONSISTENCY: corr | PID)
```

The baseline occupies the top-left; a **cross-sensor consistency** detector occupies the
bottom-right; the top-right cell (inflates NIS *and* breaks correlation) is caught by
*both*. This is the motivation for **fusing** magnitude with consistency into a single
jam-vs-spoof verdict — the shared, source-agnostic 2×2 in `galadriel_core::fusion`. Two
wirings ship: the pure **`assess_default`** (NIS ⊕ correlation, no `pid-core`) and the
**`assess_stream`** escalation (NIS ⊕ PID). Both read: a stealthy spoof with
in-covariance NIS + a consistency decoupling ⇒ *spoof*; an all-channel NIS inflation with
intact correlation ⇒ *jam*; both together ⇒ a loud spoof.

The scientific claim is deliberately narrow and honest: **cross-sensor consistency does
not make the baseline obsolete, and the baseline does not make it redundant.** Consistency
closes one specific, adversary-optimal blind spot of magnitude detection — and on *this*
linear spoof the cheap correlation form of it is enough (the `corr AUC` column); PID is
the escalation for when it is not.

---

> **Scope — read this with [`JUSTIFICATION.md`](JUSTIFICATION.md).** The `corr AUC`
> column *is* the proof that the detector closing the baseline's blind spot need not be
> PID: because this stealthy spoof is *linear-Gaussian*, the cheap **pairwise-correlation**
> consistency check (`galadriel_core::correlation`, in the pure default build) catches it
> at **AUC 1.000** — matching, even edging, the MI/PID engine's 0.999. PID is *not
> uniquely* responsible for the result. The justification study shows MI beats correlation
> only when the cross-channel dependence is **nonlinear** (`corr AUC 0.66` vs `MI 1.00`)
> or **synergistic** (`corr` *and* pairwise `MI` both 0.54 vs joint synergy 1.00). On
> galadriel's linear residuals, **correlation is the right default; PID is the opt-in
> escalation** for nonlinear modalities, synergistic fusion, or a correlation-aware
> adversary. This evaluation demonstrates *cross-sensor consistency* beats magnitude — it
> does not, by itself, justify MI over correlation, and the table now says so in a column.

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
# Full study (200 trials/regime; the detection/AUC report + the §2.1 latency table):
cargo run -p galadriel-eval --release 200

# Fast pass:
cargo run -p galadriel-eval 40

# The hypotheses as unit tests: (1) on the stealthy spoof the baseline is blind
# (<0.2 detection / AUC <0.75) while PID *and* the pure correlation default both clear
# >0.8 detection & AUC >0.85, and both magnitude attacks are caught by the fused
# detector; (2) latency tracks attack ownership — the cross-sensor detectors reach the
# stealthy spoof (100% reach) while the baseline owns the loud spoof:
cargo test -p galadriel-eval
```

Design provenance: the full, adversarially-reviewed method (threat model, estimand,
estimator gates) is `galadriels-mirror.md`.
