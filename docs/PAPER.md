# Forced or Justified? Mutual Information vs. Correlation for Cross-Sensor Spoof Detection in Counter-UAS Fusion

**Sepehr Mahmoudian**
*sepahead — [github.com/sepahead/galadriel](https://github.com/sepahead/galadriel)*

*Working paper / preprint — v0.2, 2026. Artifact: the `galadriel` repository. The
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
nothing beyond `ρ` either. There, MI/PID is **forced** — no accuracy to gain — while the
KSG-MI engine costs **~100× the compute** at our deployed configuration. We then delimit,
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
  corr − PID (paired)   ΔAUC +0.001  [+0.000, +0.001] <- reaches 0: a TIE
```

The baseline's CI **brackets 0.5** (not distinguishable from chance, *as its construction
guarantees*); the two cross-sensor detectors sit at 1.000/0.999 with a **paired** AUC difference
of at most **0.001** whose CI reaches 0 — a statistical tie. We do **not** claim correlation
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

---

## 6. Discussion and limitations

- **Non-adaptive, single-channel adversary.** Every detection number is against a fixed attack on
  one channel. A threshold-aware adaptive adversary optimizing injected bias subject to staying
  above `decouple_ratio × reference` (a boundary-hugging attack that pulls the track while flagged
  nominal) is not evaluated, and a colluding $2$-of-$3$ compromise can invert the consensus and
  cause the detector to accuse the honest channel. Characterizing the maximum undetectable bias,
  and the honest-majority assumption's failure mode, is the primary open item.
- **Interval estimates: partial.** AUCs now carry percentile-bootstrap 95 % CIs (with a paired
  corr-vs-PID bootstrap), which is what backs the "tie" and "at chance" claims. Detection rates
  and latencies are still bare point estimates; extending Wilson/bootstrap CIs to them, and adding
  DeLong CIs alongside the bootstrap, is remaining work.
- **Best-case attack instance.** The accuracy study exercises full decoupling (phantom latent
  correlation ≈ 0) on 1 of 3 channels. A sweep of decoupling strength (partial `ρ` retention → an
  AUC-degradation curve) and multi-channel compromise, which show where consistency detection
  *fails*, are future work.
- **Detection reach, not attacker success.** §5.2 measures whether an attack is eventually
  detected, not the induced track displacement before detection — the operationally decisive
  quantity for an interceptor cue.
- **Single-configuration cost.** The ~100× cost ratio is one (window, channels, dimension) point;
  §5.3 states its scaling but does not sweep it.
- **Consistency, not truth; synthetic sim.** A statistics-matching FDI (an adversary who knows the
  true track and fakes cross-channel consistency) defeats consistency detection entirely — a
  fundamental limit; raising the bar to *that* capability is the honest security claim. FAR is
  reported only on a clean, stationary Gaussian sim; real innovations are non-Gaussian and
  non-stationary under maneuver, maneuver-induced decoupling is a false-positive source the check
  cannot distinguish from a spoof, and precision under a near-zero spoof base rate is unbounded here.
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
there is forced, and ~100× more expensive for no gain. We delimited, on canonical constructions,
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
