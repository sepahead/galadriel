# Forced or Justified? Mutual Information vs. Correlation for Cross-Sensor Spoof Detection in Counter-UAS Fusion

**Sepehr Mahmoudian**
*sepahead — [github.com/sepahead/galadriel](https://github.com/sepahead/galadriel)*

*Working paper / preprint — v0.4, 2026. Artifact: the `galadriel` repository. The
accuracy, latency, cost, and justification numbers in this paper are reproduced by
`cargo run -p galadriel-eval --release`, `cargo bench -p galadriel-eval --bench detectors`,
and `cargo run -p galadriel-justify --release`.*

> **Statistical scope (read first).** Headline AUCs now carry **percentile-bootstrap 95 %
> confidence intervals** (resampling each class; the corr-vs-PID comparison uses a *paired*
> bootstrap). Fine-grained gaps are read *through* the CIs: the stealthy-spoof corr-vs-PID
> difference is ΔAUC ≤ 0.001 with a CI reaching 0 (a **tie**, §5.1), and the two "at chance"
> claims (baseline AUC 0.547; synergy pairwise AUC 0.544) are confirmed by CIs that **bracket
> 0.5**. Detection rates/latencies are still bare point estimates. All detection numbers are
> against a **non-adaptive** adversary (§2).

---

## Abstract

Multi-sensor fusion for counter-UAS and embodied-agent perception is a soft target for
**false-data injection (FDI)**: an adversary who compromises or spoofs one sensor channel
(a phantom acoustic bearing, an adversarial-patch camera, a spoofed radar return) can pull
a fused track off the true target while every *individual* channel still looks statistically
healthy. A natural defense is **cross-sensor consistency**: a channel that has begun to lie
stops agreeing with the corroborated consensus of the others. Information-theoretic mutual
information (MI) — and one level up, **Partial Information Decomposition (PID)**, the
decomposition of the multivariate MI into redundant, unique, and synergistic atoms — is an
attractive, fashionable instrument for measuring that agreement.

This paper asks the disciplined question that method-fashion usually skips: **when is MI/PID
actually worth its cost over a one-line correlation check, and when is using it merely
forced?** On linear-Gaussian sensor residuals — the regime that dominates kinematic fusion —
the Gaussian MI is a *monotone function of the Pearson correlation*, so an MI-threshold and a
`|ρ|`-threshold detector share an identical ROC; and because *every* PID atom of a jointly-
Gaussian distribution is a function of its covariance matrix, the whole decomposition carries
nothing beyond `ρ` either. There, MI/PID is **forced** — no accuracy to gain at full decoupling,
and, across the detection boundary (a decoupling-strength sweep, §5.5), *strictly worse*, because
the nonparametric KSG estimator's variance makes it lose AUC faster than the efficient sample `|ρ|`
exactly where the effect is small — all while it costs **~100× the compute** at our deployed
configuration. We then delimit,
on **canonical constructions**, the three regimes where MI/PID genuinely earns its cost:
(i) **model-free nonlinear** dependence (MI AUC 1.000 vs a correlation check that reaches
only 0.66, and only via a kurtosis artifact); (ii) **adversarial robustness** under
Kerckhoffs' assumption, which we argue is a defense-in-depth framing of (i) that bites only
off the Gaussian manifold; and (iii) **irreducible synergy**, where correlation *and pairwise
MI alike* are at chance (AUC ≈ 0.54, indistinguishable from 0.5) while a joint-information
measure separates the attack (AUC 1.000). We build **Galadriel's Mirror**, a layered detector
that ships the cheap correlation check as its default and gates the MI/PID engine for exactly
those regimes, and evaluate it on a three-axis basis — **accuracy, detection latency, and
compute cost** — against a non-adaptive, single-channel adversary. The system is open-source,
`#![forbid(unsafe_code)]` Rust, and every result is a `cargo` command.

---

## 1. Introduction

Autonomous air-defense and embodied-agent systems fuse heterogeneous sensors — electro-
optical/IR cameras, radar, acoustic direction-of-arrival (DOA) arrays, lidar, RF — into a
single track estimate that drives decisions with real consequences (an interceptor cue, an
evasive maneuver). The fusion filter is a high-value target: an adversary does not need to
defeat the whole system, only to make *one* channel report a plausible lie that the filter
will trust. This is a **false-data injection** attack [Liu2011, Mo2010], and against a
kinematic tracker it is well within reach — GPS/GNSS spoofing of UAVs is demonstrated and
portable [Humphreys2008], and adversarial patches, phantom acoustic bearings, and spoofed
radar returns are the sensor-domain analogues.

The magnitude defenses a tracker already carries — a per-channel **Normalized Innovation
Squared (NIS)** χ² gate [BarShalom2001] — catch the *loud* attacks (a large bias, a jam)
but are, by construction, blind to a **moment-matched** spoof that keeps each channel's
innovation inside its own covariance. Catching that requires looking *across* channels: an
honest sensor and a lying one stop *agreeing*. The obvious instrument for "agreement" is
statistical dependence, and the fashionable instrument for dependence is information-
theoretic — mutual information and, one level up, **Partial Information Decomposition**
[WilliamsBeer2010, Timme2014], which resolves the information two or more sources carry about
a target into **redundant**, **unique**, and **synergistic** atoms.

The temptation is to reach for this machinery because it is powerful and general. The
discipline this paper insists on is to ask whether that power is *needed*. Our central finding
is a **negative result made precise**, and it is the paper's main contribution:

> On the linear-Gaussian residuals that dominate kinematic sensor fusion, **mutual information
> is a monotone function of the correlation** — and, since every PID atom of a jointly-Gaussian
> distribution is a function of its covariance, the whole decomposition adds nothing over `ρ`
> either. MI/PID and a one-line correlation check are the **same detector** there; using MI/PID
> is forced by fashion, not need, and (§5.3) it costs ~100× more to be no better.

We then make the positive case symmetric and precise — the three regimes where MI/PID *is*
justified, demonstrated on canonical constructions — and build a system around the discipline.

**Contributions.**
1. A closed-form + empirical demonstration that on linear-Gaussian couplings, MI-threshold and
   `|ρ|`-threshold detectors have identical ROC, extended from MI to the full decomposition via
   the observation that all Gaussian PID atoms are functions of the covariance (§4.1) — with a
   compute measurement of the ~100× price of using MI/PID anyway (§5.3).
2. A precise characterization, on **canonical constructions** (not counter-UAS-instantiated),
   of the three regimes where MI/PID is justified: model-free nonlinearity, adversarial
   robustness, and irreducible synergy — the last of which defeats *pairwise* MI as well as
   correlation (§4.2).
3. **Galadriel's Mirror**, a layered detector — a cheap NIS ⊕ correlation default with a gated
   MI/PID escalation, unified under one source-agnostic fusion — that operationalizes the
   discipline (§3).
4. A **three-axis evaluation** methodology (accuracy × latency × cost) and an open,
   `cargo`-reproducible artifact (§5).

We do not claim that MI/PID beats cheaper statistics in general. We claim the opposite for the
common case, and we say exactly where the claim flips.

---

## 2. Threat model and problem statement

**System.** A tracker fuses $C$ sensor channels for a target. At each fusion frame $t$,
channel $c$ produces a measurement $z_{c,t}$ and, against the *a priori* (predicted,
pre-update) state $\hat{x}^-_t$, an **innovation** $y_{c,t} = z_{c,t} - H_c \hat{x}^-_t$ with
covariance $S_{c,t}$. Under a correct model, $\mathrm{NIS}_{c,t} = y_{c,t}^\top S_{c,t}^{-1}
y_{c,t} \sim \chi^2(d)$ [BarShalom2001].

**Adversary and its scope.** We assume an **honest majority** of channels: the security
argument rests on enough uncompromised sensors remaining *mutually corroborating* to define a
consensus (effectively fewer than $C/2$ compromised, and at least two honest channels). We
evaluate **single-channel compromise** by a **non-adaptive** adversary — one who injects a
fixed attack, *not* one who optimizes against the deployed detector. This scope is a genuine
limitation, made explicit here rather than buried: a colluding $2$-of-$3$ compromise can invert
the consensus and cause the detector to accuse the honest channel, and a threshold-aware
adaptive adversary is not modeled (§6). We consider three canonical attacks:
- **Loud spoof:** a large constant bias on one channel — inflates its NIS, preserves structure.
- **Broadband jam:** a correlated inflation of every channel — inflates all NIS (denial).
- **Moment-matched stealthy spoof:** the adversary-optimal move *against the magnitude gate
  alone* (it is pessimal against the deployed magnitude ⊕ consistency detector). The channel is
  decoupled onto an independent latent of the *same variance*, so its marginal NIS stays
  $\chi^2(d)$ — the χ² gate is blind by construction — while its cross-channel dependence breaks.

**Defender's question.** Detect the stealthy spoof (the one the magnitude gate misses) without
excess false alarms, with the *cheapest sufficient* instrument. The detector is **advisory**
($\texttt{calibrated\_posterior} = \texttt{false}$): it authenticates statistical consistency,
not truth, and softens/attributes rather than vetoing a control path. A spoof that *also* matches
the cross-channel dependence — a ground-truth-aware, statistics-matching FDI — defeats any
consistency detector; raising the adversary's bar to *that* capability is the honest statement
of what cross-sensor consistency buys (§6).

---

## 3. Method: Galadriel's Mirror

The detector is layered so that cost is paid only where accuracy demands it.

**3.1 The magnitude baseline (NIS χ²).** Per channel, a sliding window of NIS is tested for χ²
consistency (the windowed sum is $\sim \chi^2(n d)$; an improbably high sum flags an inflated
channel), backed by a two-sided CUSUM [Page1954]. This is the cheap magnitude yardstick every
downstream detector must beat, and it owns the loud/jam attacks outright.

**3.2 The correlation consistency default.** For each channel we compute its **best pairwise
$|\rho|$** with any peer over a window (its *corroboration* score). A channel is flagged
**decoupled** when its corroboration falls below `decouple_ratio` × the strongest corroboration
in the group, and only when that strongest clears a floor `corr_floor` (there is a genuine linear
consensus to have decoupled *from*). Defaults: window 128 frames, `min_samples` 64,
`decouple_ratio` 0.4, `corr_floor` 0.15. This costs tens of microseconds and, fused with the
baseline (§3.4), forms a **complete detector with no heavy dependency**. (Note: this is
best-pairwise Pearson $|\rho|$, not *partial* correlation — it does not condition out the other
channels.)

**3.3 The MI/PID escalation.** The optional engine replaces $|\rho|$ with geometry-gated
**pairwise Kraskov–Stögbauer–Grassberger (KSG) mutual information** [Kraskov2004] as the
corroboration score, and reports the $I^{sx}$ **redundancy** atom (shared-exclusions
redundancy [Makkeh2021]) alongside. Synergy, when needed, is the top atom of the Williams–Beer
lattice [WilliamsBeer2010], obtained by Möbius inversion — distinct from $I^{sx}$, which is a
*redundancy* measure. A geometry gate (intrinsic-dimension and distance-concentration checks)
fails the estimator *closed* to `InsufficientEvidence` when the window is too short/high-
dimensional for KSG to be trustworthy.

**3.4 Source-agnostic fusion.** A single 2×2 rule combines the baseline's per-channel elevation
with *any* consistency detector's decoupled set into one verdict:

| | structure intact | consistency decoupling |
|---|---|---|
| **NIS in-covariance** | `Nominal` | `Spoof {stealthy}` |
| **one channel's NIS inflated** | `Spoof` | `Spoof` |
| **all channels' NIS inflated** | `Jam` | `Spoof` |

Because the fusion is source-agnostic, the correlation default and the MI/PID escalation emit
the *same* verdict type; an operator can run both and treat their **divergence** as itself
informative (a structure-preserving, MI-visible anomaly is the adversarial case of §4.2).

---

## 4. When is MI/PID justified — and when is it forced?

This section is the paper's methodological core. We measure MI against correlation head-to-head
as anomaly detectors — ROC-AUC at separating a *coupled* channel pair from a *decoupled*
(independence-null) one, a permutation null that holds the marginal fixed so the comparison
isolates dependence. The coupling study uses **300 trials/class, $n = 400$**; the synergy study
(§4.2(3)) uses **250 trials/class, $n = 600$**. AUCs carry **percentile-bootstrap 95 % CIs**
(1000 resamples); information quantities are in **nats** for the MI/KSG columns and **bits** for
the discrete XOR synergy.

### 4.1 The trap: on linear-Gaussian data, MI is a monotone function of correlation

For jointly-Gaussian variables the *population* mutual information is a closed-form **monotone**
function of the Pearson correlation [CoverThomas2006]:
$$ \mathrm{MI}(X,Y) = -\tfrac{1}{2}\ln(1-\rho^2)\ \text{(nats)}. $$
A monotone transform of a score leaves its ROC unchanged, so a *plug-in* Gaussian-MI detector
(computing $-\tfrac12\ln(1-\hat\rho^2)$) and a $|\hat\rho|$ detector are **identical**.
The KSG estimator we actually benchmark only *approximates* this and carries its own finite-
sample variance; that is why in §5.1 it scores 0.999, marginally below the exact 1.000, rather
than exactly equal. Crucially, the point extends past MI: for a **jointly-Gaussian** joint
distribution, *every* PID atom (redundancy, unique, synergy) is a deterministic function of the
covariance matrix, hence of the pairwise correlations — so the whole decomposition carries no
information beyond $\rho$. Empirically:

```
coupling            | |rho| mn | corr AUC [95% CI]      | MI AUC [95% CI]
------------------------------------------------------------------------
linear  (Y = X + e) |   0.894  | 1.000 [1.000, 1.000]  | 1.000 [1.000, 1.000]
```
(The KSG MI mean is 0.814 nats, ~0.012 above the closed-form $-\tfrac12\ln(1-0.894^2)=0.80$ — the
known positive finite-sample bias of KSG.) **Correlation and MI are tied at AUC 1.000 (identical,
degenerate CIs); using KSG mutual information here is forced** — it cannot improve on a detector
that is already perfect, and §5.3 shows it costs ~100× more to be no better.

### 4.2 The three regimes where MI/PID *is* justified (canonical constructions)

These are illustrative constructions establishing *where* MI/PID would earn its cost, not
counter-UAS-instantiated results.

**(1) Model-free nonlinear dependence.** Where the coupling is nonlinear, the *population*
correlation is $0$ even though the variables are strongly dependent. On a random per-sample sign
flip $Y = \pm X + \varepsilon$:

```
nonlinear (Y=+-X+e) |   0.067  | 0.662 [0.617, 0.707]  | 1.000 [1.000, 1.000]
```

MI is decisive (AUC 1.000) while correlation reaches only 0.662 [0.617, 0.707] — and even that is
**not linear signal**: the population $\rho$ is $0$, but the *sample* correlation's variance is
inflated by the kurtosis of $X$ (a fourth-moment effect, $\mathrm{Var}(\hat\rho)$ scaling with
$\mathbb{E}[X^4]/\mathrm{Var}(X)^2$), and a $|\hat\rho|$ detector rides that variance artifact to
0.66. (The correlation CI excludes 0.5, so the artifact is real but bounded; MI's CI excludes
correlation's entirely, so the ~0.34 gap is not sampling noise.) The precise reason to use MI is
that it catches a **correlation-preserving** attack that breaks a nonlinear dependence, without the
defender knowing the attack's form in advance.

**(2) Adversarial robustness (Kerckhoffs) — a framing of (1), not an independent reason.**
Under Kerckhoffs [Kerckhoffs1883] the adversary knows the detector and may craft an injection
that *preserves $\rho$ while breaking higher-order structure* — invisible to correlation, visible
to MI. We are careful about the load this carries: on the linear-Gaussian residuals that §4.3
says are the deployment regime, $\rho$ and MI are functionally locked (§4.1), so such an attack
is **impossible there** — it exists only off the Gaussian manifold, where it reduces to reason
(1). Moreover, its natural cheap counter is a Gaussianity/kurtosis test, not necessarily KSG. We
therefore present (2) as a defense-in-depth *framing* of (1), not a separate justification, and
give no benchmark for it.

**(3) Irreducible synergy.** For a target carried *only jointly* by two or more sources, no
pairwise statistic suffices. On $T = A \oplus B$ for independent bits $A, B$ — where
$\mathrm{MI}(A;T) = \mathrm{MI}(B;T) = 0$ *exactly* — we measure the joint-information contrast
$Q = \mathrm{MI}(A,B;T) - \max(\mathrm{MI}(A;T),\mathrm{MI}(B;T))$. This $Q = \mathrm{Syn} +
\min(U_A, U_B)$ is an **upper bound** on the Williams–Beer synergy atom, tight for XOR (both
unique atoms vanish, so $Q = \mathrm{Syn}$); it is a joint-MI test, not the $I^{sx}$
decomposition itself.

```
detector                 |  AUC   [95% CI]        (bits target)
---------------------------------------------------------------
correlation (pairwise)   | 0.544  [0.496, 0.592]  <- CI brackets 0.5: chance
mutual info (pairwise)   | 0.544  [0.496, 0.594]  <- CI brackets 0.5: chance
synergy contrast Q       | 1.000  [1.000, 1.000]  (0.997 bits)
```

Correlation **and pairwise MI alike** are at chance — both AUC 0.544 with CIs that **bracket
0.5**, so neither is distinguishable from chance (note that on binary variables discrete MI is a
monotone function of the sample correlation $\phi$, so their identical AUC is *expected*, not
independent corroboration) — while only the joint measure separates the attack (1.000 [1.000,
1.000]). **No pairwise statistic can see synergy; a joint-information (or PID)
measure can.** This is the one regime where a joint measure is a necessity, not a choice. We
*hypothesize* — but do not evaluate here — that this regime dominates for neural fusion policies
(e.g. the vision-language-action analysis in the sibling `prisoma` project); the claim is left
to future work.

### 4.3 Verdict for the sensor-fusion case

Galadriel's core input — kinematic innovation residuals — is essentially linear-Gaussian, so by
§4.1 **correlation is the right default and MI/PID is forced there**. MI/PID is gated behind the
three §4.2 situations: a correlation-aware adversary (off the Gaussian manifold), genuinely
nonlinear modalities (acoustic energy vs radar cross-section; a learned fusion feature), or
synergistic fusion. The disciplined position: *MI/PID where it is irreducible, correlation where
it is not.* Honestly, in the pure kinematic-Gaussian deployment none of the three obtains, so the
residual security value over a correlation check is to **raise the adversary's bar to a
ground-truth-aware, statistics-matching FDI** (§6) — the escalation's accuracy payoff appears only
when a modality or fusion stage leaves the Gaussian manifold.

---

## 5. Evaluation

We evaluate on a shared Monte-Carlo bench (`galadriel-eval`), χ²(3) channels {visual, radar,
acoustic}, $\rho = 0.7$, 300 frames, attack onset at frame 100, 128-frame analysis window. The
**accuracy** study (§5.1) uses **200 trials/regime**; the **latency** study (§5.2) uses **50
trials/regime** with a **4-frame prefix step** (so latencies are quantized to ±4 frames). All are
single-realization point estimates.

### 5.1 Accuracy

```
regime            | base det | corr det | PID det | fused det | base AUC | corr AUC | PID AUC
---------------------------------------------------------------------------------------------
loud bias spoof   |   1.000  |   1.000  |  0.000  |   1.000   |  1.000   |  0.500   |  0.500
stealthy          |   0.020  |   1.000  |  0.965  |   0.965   |  0.547   |  1.000   |  0.999
broadband jam     |   1.000  |   1.000  |  0.000  |   1.000   |  1.000   |  0.500   |  0.500
```
False-alarm rate (clean): baseline 0.030, correlation 0.030, PID 0.000, fused 0.030.

**Reading the columns (they are not all like-for-like).** The `det` columns bundle differently:
`corr det` is the **fused** NIS ⊕ $|\rho|$ detector (so it reads 1.000 on loud/jam *via its NIS
component*), while `PID det` is the PID consistency verdict **alone**, with no NIS baseline (so it
reads 0.000 on the magnitude attacks — correctly, a bias/scale attack preserves cross-channel
structure). A reader must not infer from `corr det 1.000` vs `PID det 0.000` that correlation
beats PID on magnitude attacks; that is a bundling artifact. **The only apples-to-apples
comparison of the two consistency scores is the AUC pair** (`corr AUC`, `PID AUC`), which share
the identical decoupling-depth score.

On that fair comparison, on the stealthy spoof the magnitude baseline is at chance while both
cross-sensor detectors recover it. A bootstrap (2000 resamples) makes this precise:

```
Bootstrap 95% CIs — stealthy spoof (200 trials)
  baseline (NIS χ²)      AUC 0.547  [0.490, 0.603]   <- brackets 0.5: at chance
  correlation default    AUC 1.000  [1.000, 1.000]
  PID (KSG-MI)           AUC 0.999  [0.999, 1.000]
  corr − PID (paired)   ΔAUC +0.001  [+0.000, +0.001] <- ≤0.001: a TIE
```

The baseline's CI **brackets 0.5** (not distinguishable from chance, *as its construction
guarantees*); the two cross-sensor detectors sit at 1.000/0.999 with a **paired** AUC difference of at
most **0.001** (95 % CI lower bound at 0) — a magnitude so small we read it as a statistical tie
rather than an ordering. We do **not** claim correlation
"beats" PID; the ~100×-costlier estimator buys nothing here. On the magnitude attacks the ordering
flips (baseline 1.000, consistency scores at chance): the baseline owns that half of the space.
These results are against a non-adaptive, single-channel adversary (§2).

### 5.2 Detection latency (time-to-detect)

Median frames from attack onset to first alarm over growing prefixes (reach = fraction of the 50
trials that ever alarmed; medians for low-reach cells rest on few samples):

```
regime            |   baseline  | corr default |     PID
---------------------------------------------------------
loud bias spoof   |   4f (100%) |    4f (100%) |  — (0%)
stealthy          |  40f ( 30%) |   80f (100%) | 52f (100%)
broadband jam     |   4f (100%) |    4f (100%) |  — (0%)
```

Magnitude attacks are caught in **~4 frames / 0.4 s**; the stealthy spoof carries an **intrinsic
window-fill latency** (52–80 frames, 5–8 s) because the consistency window must accumulate enough
post-onset decoupled frames — caught reliably (100 % reach) but not instantly. Two honesty notes.
(a) The `corr default` and `PID` columns are **not** measured under the same wiring — `corr` is the
fused NIS ⊕ correlation detector, `PID` the standalone engine — so the 80f-vs-52f difference
conflates the estimator swap with two fusion architectures; we report it descriptively, not as an
ordering, and its ±4-frame quantization and low sample counts preclude a fine claim. (b) The
baseline's 30 % "reach" on the stealthy spoof is occasional **chance NIS excursions** of the
phantom latent, not reliable detection (its final detection rate is 0.020, §5.1). **Security
caveat:** time-to-*detect* is not time-to-*damage*; the security-relevant quantity is how far the
fused track is pulled before detection (and the maximum bias injectable while staying below
`decouple_ratio`), which we do not measure here (§6).

### 5.3 Compute cost

A criterion micro-benchmark prices each detector per full-stream assessment (release; absolute
numbers hardware-dependent, ratios are the point; single configuration):

```
detector                       | time/assessment | vs default
--------------------------------------------------------------
baseline (NIS chi2)            |         ~19 us  |    0.9x
correlation default (NIS+|rho|)|         ~22 us  |    1.0x   (reference)
PID engine (KSG-MI)            |       ~2160 us  |    ~99x
fused (NIS + PID)              |       ~2180 us  |   ~100x
```

The correlation default is **essentially free** (~15 % over the bare baseline). The KSG estimator
(a k-NN search per channel pair) is **~100×** slower *at this configuration* (128-frame window,
3 channels, scalar projection). This ratio is configuration-dependent: KSG scales super-linearly
in window samples while $|\rho|$ is linear, so it grows with window length; and the *isolated*
consistency-check ratio (KSG vs the few-µs $|\rho|$ pass over the shared baseline) is larger still
(~$700\times$). On the linear-Gaussian spoof — where §5.1 shows MI delivers the *same* AUC — this
is ~100× compute for zero accuracy gain: the compute face of §4.1.

### 5.4 The three axes together

On the linear stealthy spoof the correlation default **ties PID's accuracy, at ~1/100th the cost,
with comparable order-of-magnitude latency**. PID's premium buys nothing here — and would buy
decisive accuracy in the §4.2 regimes *on the canonical constructions demonstrated there*, where
correlation's accuracy collapses to chance. A single-axis (accuracy-only) evaluation would have
hidden the cost verdict and over-sold PID; the three-axis view is what makes the "correlation by
default, MI/PID on escalation" recommendation defensible.

### 5.5 The detection boundary (decoupling sweep)

§5.1 evaluated the *fully* decoupled spoof (the easiest instance). To trace the operating
**boundary**, we sweep the spoof's decoupling strength $d\in[0,1]$: the compromised channel tracks
$\sqrt{1-d}\,m + \sqrt{d}\,p$ (shared truth $m$, phantom $p$), which keeps its marginal variance —
so it stays moment-matched at every $d$ — while its correlation with honest channels scales as
$\sqrt{1-d}$. $d=1$ is full decoupling (easiest); $d\to0$ is an undetectable non-attack. AUC of the
two consistency scores, with per-detector bootstrap CIs *and* the **paired** corr−PID $\Delta$AUC CI
(the powerful, §5.1-consistent test; 200 trials, 2000 resamples; `*` = $\Delta$AUC CI wholly above 0):

```
   d  |  corr AUC [95% CI]     |  PID AUC [95% CI]     | Δ(corr−PID) [95% CI]
----------------------------------------------------------------------------
 1.00 |  1.000 [1.000, 1.000]  |  0.999 [0.998, 1.000] | +0.001 [+0.000, +0.001]
 0.80 |  1.000 [1.000, 1.000]  |  0.979 [0.964, 0.992] | +0.021 [+0.008, +0.037] *
 0.60 |  1.000 [0.999, 1.000]  |  0.908 [0.874, 0.938] | +0.092 [+0.062, +0.127] *
 0.40 |  0.959 [0.938, 0.977]  |  0.767 [0.718, 0.811] | +0.192 [+0.146, +0.239] *
 0.30 |  0.879 [0.843, 0.911]  |  0.702 [0.648, 0.750] | +0.176 [+0.116, +0.230] *
 0.20 |  0.710 [0.658, 0.760]  |  0.636 [0.578, 0.688] | +0.074 [+0.004, +0.142] *
 0.10 |  0.550 [0.490, 0.606]  |  0.522 [0.465, 0.574] | +0.028 [−0.049, +0.104]
 0.05 |  0.512 [0.453, 0.567]  |  0.475 [0.419, 0.529] | +0.038 [−0.036, +0.113]
```

Both detectors degrade smoothly to chance as the decoupling weakens (the boundary is graceful, not a
cliff). The sharper finding — **correlation does not merely tie PID off the best case; through the
*mid*-boundary $d\in[0.2,0.8]$ it strictly beats it**, the paired $\Delta$AUC CI lying wholly above 0
at every one of those strengths (e.g. $d=0.6$: $\Delta$AUC $+0.092$, CI $[+0.062,+0.127]$). At the two
extremes the two are a statistical tie: at $d=1$ ($\Delta$AUC $\le 0.001$, as §5.1) and at $d\le0.1$,
where both have collapsed to chance and the $\Delta$AUC CI includes 0. The mechanism is estimator
statistics: sample $|\rho|$ is the *efficient* dependence statistic for Gaussian data, whereas KSG
mutual information is a nonparametric $k$-NN estimator carrying extra finite-sample variance. At full
decoupling both saturate at AUC 1.0 and the variance is invisible; through the mid-boundary KSG's
variance dominates and PID loses AUC faster. **So on linear-Gaussian residuals MI/PID is not merely
*forced* (§4.1, no better at full decoupling) — through the discriminable mid-boundary, the regime
that matters most operationally, it is strictly *worse*.** This is the strongest form of the paper's
thesis, and it answers the "best-case-only" objection directly.

### 5.6 Where consistency itself breaks: the honest-majority failure

Everything above assumes an **honest majority** (§2). We now demonstrate the failure when that
assumption is violated: **two of three** channels collude, decoupling onto *one shared* phantom
(radar and acoustic track the same lie), while visual stays honest. The two liars now mutually
corroborate and become the false "consensus"; the honest channel is the one that decouples from it.
Over 200 trials:

```
Colluding compromise (2 of 3) — radar+acoustic share a phantom; visual honest  (Wilson 95% CIs)
  correlation flags the HONEST channel:  1.000 [0.981, 1.000]   (it fires: 1.000)
  PID         flags the HONEST channel:  0.975 [0.943, 0.989]
```

The detector **inverts**: it fires reliably, but points at the *innocent* channel — correlation on
**every** trial (Wilson CI $[0.981,1.000]$), PID on 97.5 % ($[0.943,0.989]$). Crucially this is
**structural**, not an estimator artifact: consensus-based consistency has no way to tell a true
majority from a colluding one, so *neither* correlation nor MI/PID escapes it (PID's decomposition
offers no protection here either). This is the honest boundary of the whole approach: cross-sensor
consistency needs $f < C/2$ compromised channels, and where that cannot be guaranteed the backstop is
structural, not statistical — cryptographic channel authentication (per-plane ACL / mTLS) against an
*external* spoofer, and, for a genuinely owned/credentialed sensor (which passes authentication),
hardware attestation or physical/vendor diversity. Reporting this failure is part of stating honestly
what the method does and does not buy.

### 5.7 The adaptive (threshold-hugging) adversary

§4.2(2) argued that MI's supposed *adversarial-robustness* advantage bites only off the Gaussian
manifold. We test it directly. A Kerckhoffs-aware adversary knows the gate and injects the *largest*
decoupling that stays below it (maximizing the pull it sneaks past). To compare the two detectors
fairly we hold the operating point fixed — each is thresholded to the **same 5 % false-alarm rate**
(their arbitrary default gates sit at different FARs, which would confound evasion with threshold
placement). Detection rate vs decoupling $d$, and the **evasion ceiling** (the largest $d$ a detector
still misses, detection $\le 0.5$ — the most the adversary injects undetected):

```
   d  | corr detect | PID detect        (200 trials, matched 5% FAR)
--------------------------------------
 1.00 |    1.000    |    0.995
 0.60 |    1.000    |    0.755
 0.40 |    0.825    |    0.445
 0.20 |    0.290    |    0.165
 0.10 |    0.130    |    0.095

Evasion ceiling (max undetected d):  correlation 0.20   PID 0.40
```

At a matched operating point correlation detects **more at every strength**, so its evasion ceiling is
*lower* (0.20 vs 0.40): the adaptive adversary must retain *more* correlation with the honest channels
— inject *less* — to slip past correlation than to slip past PID. **The Kerckhoffs-aware adversary does
not favour PID; if anything correlation is the harder detector to evade**, exactly as its dominant ROC
(§5.5) predicts. This closes reason (2) empirically: MI's adversarial-robustness argument buys nothing
on the linear-Gaussian manifold — it bites only where the coupling is genuinely nonlinear (reason (1)).
(Caveat: the ceiling measures undetected *decoupling*, a proxy for injectable track pull; the true
fused-track displacement needs the downstream filter and is out of scope here.)

### 5.8 Non-stationary false alarms (a benign maneuver)

The stationary sim reports FAR on a *clean, stationary* stream; real innovations spike and
decorrelate under a target maneuver, a false-positive source the consistency check cannot, by
itself, distinguish from a spoof. We inject a **benign** stress-test maneuver — a shared 12σ
triangular ramp over 90 frames (onset at frame 100, so its tail extends into the last-128
analysis window) — with a **per-channel lag** (`lag_step` × the modality's enum discriminant, a
first-order proxy for heterogeneous sensor dynamics; so radar is the most-lagged channel, and at
large `lag_step` a channel's lagged ramp falls partly outside the 300-frame capture — itself a
form of extreme asymmetry). We count the consistency **false-decoupling** rate (isolated from the
NIS/jam alarm a coherent maneuver legitimately raises):

```
 lag_step | corr FAR | PID FAR      (200 trials, benign 12σ / 90-frame maneuver)
--------------------------------------
    0     |  0.000   |  0.000       (synchronized)
    8     |  0.000   |  0.005
   16     |  0.000   |  0.185       (PID starts false-alarming; correlation robust)
   32     |  0.235   |  0.210
   64     |  0.375   |  0.180
```

Three honest findings. **(i) A synchronized maneuver does not false-alarm** (0.000): a *common-mode*
ramp is a strong shared signal that, if anything, *raises* inter-channel correlation — it cannot
produce the *asymmetric* decoupling (one channel against the consensus) the detector keys off. This
holds regardless of how much of the ramp lands in the analysis window, so coherent non-stationarity
is invisible to the check by construction.
**(ii) Strongly heterogeneous (large-lag) maneuvers do false-alarm** (up to ~0.24–0.38) — a real,
disclosed benign false-positive limit: sufficiently divergent per-channel dynamics *are*
indistinguishable from a decoupling. **(iii) Correlation is again the more robust of the two**
through the moderate-lag regime (at lag 16, corr FAR 0.000 vs PID 0.185): the nonparametric KSG
estimator false-alarms *earlier* under benign non-stationarity, consistent with §5.5/§5.7. The
practical **mitigation** is already in the architecture: a real maneuver spikes every channel's
NIS *together*, which the §3.4 fusion routes to `Jam` (degradation), not a per-channel `Spoof` —
so a maneuver, even one that decorrelates, is far more likely to be read as denial than as a
false accusation of a sensor. (Caveat: the per-channel-lag model is a first-order proxy; real
maneuver dynamics — and the fusion filter's own maneuver response — are richer.)

### 5.9 Attacker success: the undetected track pull is bounded

Detection reach (§5.1) and time-to-detect (§5.2) say *whether* and *when* a spoof is caught, not
*how far it moves the fused track* first — the operationally decisive quantity §5.2 flagged as
unmeasured. galadriel consumes innovations, not the fused state, so the true displacement needs the
downstream filter; but we can bound the *per-frame* impact with the **simplest sound fusion** — the
inverse-variance weighted mean of the channels' innovations (the ML static estimate of the common
deviation), where a decoupled channel's pull is a well-grounded $1/C$ fraction, not an arbitrary
filter gain. Measuring the injected bias against the *same seed's* clean stream isolates the spoof's
contribution (200 trials, σ units, shipped operating point):

```
   d  | fused bias (σ) | corr detect
 1.00 |     0.391      |    1.000
 0.80 |     0.291      |    0.275
 0.60 |     0.237      |    0.025
 0.40 |     0.186      |    0.020
 0.20 |     0.127      |    0.025
 0.10 |     0.089      |    0.030
```

Read the two columns together. The injected bias grows with the decoupling (0.06σ at $d=0.05$ to
0.39σ at full decoupling), but so does detection — and the two are **coupled**: to inject more bias
the adversary must decouple more, which is more detectable. At the shipped operating point the
largest bias injectable while detection stays $\le 0.5$ is $\approx$ **0.29σ per frame** ($d=0.8$);
pushing to the 0.39σ of full decoupling is caught every time. So the detector **bounds the
undetected per-frame pull** — the security payoff, and the missing half of the §5.7 evasion story:
**evasion and impact trade off against each other.** Two honest caveats: this is the *memoryless*
static-fusion bias (a tracker with memory *accumulates* it over the undetected window, §5.2), and a
more sensitive operating point — §5.7's matched-FAR threshold, where correlation flags each $d$ more
readily — tightens the bound further (the shipped default `decouple_ratio` is deliberately lenient).

---

## 6. Discussion and limitations

- **Non-adaptive, single-channel adversary.** Every detection number is against a fixed attack on
  one channel. A threshold-aware adaptive adversary optimizing injected bias subject to staying
  above the gate is now evaluated (§5.7: at matched FAR the adaptive adversary's *evasion ceiling* is
  lower against correlation than PID, so it does not favour PID). The **colluding $2$-of-$3$** failure
  is demonstrated in §5.6 (the detector inverts, correlation 100 % / PID 97.5 %). What remains open is
  the true **fused-track displacement** an evading adversary induces — the evasion ceiling is a proxy
  for it, but the actual pull needs the downstream filter (crebain), out of scope here.
- **Interval estimates: partial.** AUCs now carry percentile-bootstrap 95 % CIs (with a paired
  corr-vs-PID bootstrap), which is what backs the "tie" and "at chance" claims. Detection rates
  and latencies are still bare point estimates; extending Wilson/bootstrap CIs to them, and adding
  DeLong CIs alongside the bootstrap, is remaining work.
- **Attack instance.** §5.5 sweeps decoupling strength (the AUC-degradation curve), so the accuracy
  result is no longer best-case-only — correlation dominates the whole boundary. What remains is
  *multi-channel* compromise (a colluding subset), which the single-channel sweep does not cover.
- **Attacker success — per-frame, not integrated.** §5.9 bounds the *per-frame* fused-innovation
  bias an undetected spoof injects (≈0.29σ at the shipped operating point) under memoryless static
  fusion; the *integrated* track displacement over the undetected window needs the downstream
  filter's dynamics (crebain) and is not modelled here.
- **Single-configuration cost.** The ~100× cost ratio is one (window, channels, dimension) point;
  §5.3 states its scaling but does not sweep it.
- **Consistency, not truth; synthetic sim.** A statistics-matching FDI (an adversary who knows the
  true track and fakes cross-channel consistency) defeats consistency detection entirely — a
  fundamental limit; raising the bar to *that* capability is the honest security claim. §5.8 now
  measures FAR under a benign maneuver (synchronized maneuvers are robust; strongly heterogeneous
  ones do false-alarm, and are routed to `Jam` not `Spoof` by the fusion) — but the maneuver model
  is a first-order per-channel-lag proxy, real innovations are non-Gaussian, and precision under a
  near-zero spoof base rate is unbounded here.
- **Advisory attribution.** A decoupling is equally consistent with a spoof, a genuinely *unique*
  true detection, or an estimator artifact. Cryptographic bus controls and a safety governor are
  the enforcement layer; galadriel is instrumentation on top.

---

## 7. Related work

**Sensor-fusion and estimator attacks.** False-data injection against state estimation is studied
in power systems [Liu2011] and control [Mo2010]; GNSS spoofing of UAVs is demonstrated
[Humphreys2008]. Our contribution is not a new attack but a disciplined, cost-aware
*detector-selection* result for the cross-sensor consistency defense.

**Innovation-based fault/attack detection.** NIS/χ² gating and CUSUM are classical [BarShalom2001,
Page1954]; they are our magnitude baseline, and the stealthy spoof is their designed blind spot.

**Information decomposition.** The redundancy lattice and PID framework are due to Williams & Beer
[WilliamsBeer2010]; redundancy/synergy measures are surveyed in [Timme2014]; the $I^{sx}$
shared-exclusions redundancy we report is due to Makkeh, Gutknecht & Wibral [Makkeh2021]; KSG
[Kraskov2004] is our MI back-end. We contribute a security-motivated, cost-aware account of *when*
this machinery is warranted over second-order statistics — grounded in the Gaussian MI–correlation
identity [CoverThomas2006] and extended to the full Gaussian decomposition — not a new measure.

---

## 8. Conclusion

Reaching for mutual information or its decomposition because it is powerful is not the same as
needing it. We showed, precisely and reproducibly, that for the linear-Gaussian residuals of
kinematic sensor fusion, MI is a monotone function of correlation — and, since every Gaussian PID
atom is a function of the covariance, the whole decomposition adds nothing over `ρ` — so MI/PID
there is forced, ~100× more expensive for no gain, and (§5.5) *strictly worse across the detection
boundary*, where the nonparametric estimator's variance penalty bites. We delimited, on canonical
constructions,
the three regimes (nonlinearity, adversarial robustness, irreducible synergy) where it genuinely
earns its cost, the last of which no pairwise statistic can match. Galadriel's Mirror
operationalizes this as a layered detector: cheap correlation by default, gated MI/PID escalation,
one shared verdict. The broader lesson generalizes beyond counter-UAS: **evaluate a fashionable
method on accuracy, latency, *and* cost, quantify its assumptions, and be willing to publish the
regime where the cheap baseline wins.**

---

## Reproducibility

Everything in this paper is a command against the open-source artifact:

```bash
cargo run   -p galadriel-eval    --release      # §5.1 accuracy + §5.2 latency tables
cargo bench -p galadriel-eval    --bench detectors   # §5.3 cost
cargo run   -p galadriel-justify --release      # §4 justification studies
cargo test  --workspace                          # the hypotheses as assertions
```

The detector rationale is in `docs/JUSTIFICATION.md`; the full evaluation in `docs/EVALUATION.md`.
(The 10-lens design review lives in the sibling `haldir` planning repository.)

## References

- **[BarShalom2001]** Y. Bar-Shalom, X.-R. Li, T. Kirubarajan. *Estimation with Applications to Tracking and Navigation.* Wiley, 2001.
- **[CoverThomas2006]** T. M. Cover, J. A. Thomas. *Elements of Information Theory,* 2nd ed. Wiley, 2006.
- **[Humphreys2008]** T. E. Humphreys et al. "Assessing the Spoofing Threat: Development of a Portable GPS Civilian Spoofer." *Proc. ION GNSS,* 2008.
- **[Kerckhoffs1883]** A. Kerckhoffs. "La cryptographie militaire." *Journal des sciences militaires,* 1883.
- **[Kraskov2004]** A. Kraskov, H. Stögbauer, P. Grassberger. "Estimating mutual information." *Phys. Rev. E* 69, 066138, 2004.
- **[Liu2011]** Y. Liu, P. Ning, M. K. Reiter. "False data injection attacks against state estimation in electric power grids." *ACM TISSEC* 14(1), 2011.
- **[Makkeh2021]** A. Makkeh, A. J. Gutknecht, M. Wibral. "Introducing a differentiable measure of pointwise shared information." *Phys. Rev. E* 103, 032149, 2021.
- **[Mo2010]** Y. Mo, B. Sinopoli. "False data injection attacks in control systems." *Proc. 1st Workshop on Secure Control Systems,* 2010.
- **[Page1954]** E. S. Page. "Continuous inspection schemes." *Biometrika* 41(1/2), 1954.
- **[Timme2014]** N. Timme, W. Alford, B. Flecker, J. M. Beggs. "Synergy, redundancy, and multivariate information measures: an experimentalist's perspective." *J. Comput. Neurosci.* 36, 2014.
- **[WilliamsBeer2010]** P. L. Williams, R. D. Beer. "Nonnegative Decomposition of Multivariate Information." *arXiv:1004.2515,* 2010.
