# Related work, competing approaches, and how to compare them

Galadriel's Mirror is **one detector in a crowded, layered field.** Spoof- and fault-detection for
multi-sensor systems has a fifty-year literature, and honest positioning demands that we say
precisely what else exists, what each alternative can and cannot see, and how a fair head-to-head
would be run. This document does four things:

1. **§1 — a map of the field:** where, in the sensing-to-state pipeline, each detector family
   operates, and why that layer decides which attacks it can even observe.
2. **§2 — the competing and related families**, each with its threat model, strengths, honest
   limits, cited sources, and its relation to galadriel.
3. **§3 — a head-to-head comparison table** across the dimensions that matter.
4. **§4 — how they could be compared:** a concrete benchmark methodology (axes, a shared attack
   ontology, a matched operating point, metrics) — most of which galadriel's own evaluation harness
   (`docs/EVALUATION.md`) already instantiates, and the parts a genuine *cross-approach* benchmark
   would still need.
5. **§5 — competing vs complementary:** the layered-defense picture, and where galadriel truly
   competes rather than composes.

This complements — and does not repeat — the compact related-work paragraph in
[`PAPER.md` §7](PAPER.md) and the real-world threat grounding in [`MOTIVATION.md`](MOTIVATION.md).

---

## 1. A map of the field: where does detection happen?

Every spoof/fault detector observes the world at *some* layer of the sensing-to-state pipeline, and
that choice is the single most important fact about it — it determines what data the detector needs,
what attacks are visible to it *in principle*, and what it is structurally blind to. Reading an
attack at the wrong layer is not a tuning problem; it is an observability problem.

| Layer | What is observed | Example detectors | What only this layer can see |
|---|---|---|---|
| **L0 · Signal / RF** | Raw IQ, carrier power, AGC, C/N₀, angle-of-arrival, Doppler | GNSS power/AGC monitoring, multi-antenna DOA, spreading-code auth | An external transmitter *before* it captures the receiver; single-source geometry |
| **L1 · Measurement** | Pseudoranges, detections, ranges, bearings | RAIM (pseudorange residuals), cryptographic message auth (OSNMA) | Redundancy *within one modality*; forged vs. authentic message content |
| **L2 · Innovation / residual** | Per-channel filter innovations (NIS), cross-channel residual dependence | Innovation χ²/CUSUM gating; **galadriel**; GNSS/INS coupling | A channel that has stopped agreeing with the corroborated consensus of the others |
| **L3 · State estimate** | The fused state and its error-correcting structure | Secure/resilient state estimation; Byzantine-robust fusion | Provable state recovery under a bounded corruption budget |
| **L4 · Perception feature** | Neural fusion features, object/occupancy semantics | Cross-modal plausibility, temporal-consistency checks for MSF-AV | Nonlinear, synergistic cross-modal structure a learned stack fuses |

**Galadriel lives at L2, cross-modality.** It reads the innovations that a fusion filter already
produces — no raw RF, no shared measurement model, no state-space dynamics assumption, no training —
and asks whether the channels still *agree* the way independent views of one true world should. Its
central methodological result (`PAPER.md` §4) is about *which* dependence statistic to spend at this
layer: a one-line correlation check by default, an information-theoretic (MI/PID) escalation only
when the coupling genuinely leaves the Gaussian manifold. Everything below is calibrated against that
position.

A single attack often touches several layers at once (a GNSS spoof is an L0 RF event, an L1
pseudorange fault, and an L2 innovation anomaly simultaneously), which is exactly why a *layered*
defense — not a single detector — is the right frame (§5).

---

## 2. Competing and related approaches

Each subsection: **what it is**, its **layer**, its **threat model**, its **honest limit**, and its
**relation to galadriel**, with cited sources.

### 2.1 Signal-level GNSS anti-spoofing (L0)

**What.** A mature taxonomy of receiver-side checks on the physical signal: received-power and AGC
monitoring, carrier-to-noise (C/N₀) anomalies, **direction-of-arrival** via antenna arrays or a
rotating antenna (authentic satellites arrive from *many* directions; a spoofer from *one*), Doppler
and clock-consistency tests
([*A Survey of GNSS Spoofing and Anti-Spoofing Technology*, Remote Sensing 14(19):4826, 2022](https://www.mdpi.com/2072-4292/14/19/4826);
[spatial-processing detection, NAVIGATION 68(2):243](https://navi.ion.org/content/68/2/243)).

**Threat model.** An *external* transmitter injecting counterfeit RF. DOA methods are considered
among the most effective because they need no key infrastructure.

**Honest limit.** Power/AGC methods work mainly during the initial *capture* phase and are blind
once a spoofer has smoothly taken over the tracking loops; DOA needs extra antenna hardware; all of
it is **GNSS-specific** and does nothing for a compromised *non-RF* modality (a lying radar track, a
poisoned acoustic bearing).

**Relation to galadriel.** Different observation layer (L0 vs. L2) and a strictly narrower modality
scope. Signal-level GNSS defenses catch the *external RF* spoof that never reaches galadriel's
residual layer as an inconsistency; galadriel catches the *insider/post-capture* channel that a
signal-level check has already been fooled by. **Complementary, stacked — not competing.**

### 2.2 Cryptographic authentication (L0/L1)

**What.** Make forgery cryptographically hard rather than statistically detectable: Galileo's
**OSNMA** (Open Service Navigation Message Authentication) signs the navigation message with data
unpredictable to an attacker; spreading-code authentication protects the ranging code; at the fusion
*bus*, per-node mTLS / signed messages authenticate the sensor's identity
([survey, Remote Sensing 14(19):4826, 2022](https://www.mdpi.com/2072-4292/14/19/4826)).

**Threat model.** An external party who cannot produce valid signatures/keys.

**Honest limit.** Authentication proves *who sent it*, not *whether it is true*. A **compromised but
authenticated** sensor — the correct key, lying data — sails through every signature check. That
insider is precisely galadriel's target.

**Relation to galadriel.** This is the **enforcement layer galadriel explicitly defers to**
(`MOTIVATION.md` §4b): per-plane ACL / mTLS on the NCP bus is the real fix for *impersonation*;
galadriel is instrumentation for *dishonest-but-authenticated* content. **Orthogonal and
complementary** — they defeat disjoint attacker capabilities.

### 2.3 RAIM — Receiver Autonomous Integrity Monitoring (L1) *(the closest classical analog)*

**What.** The aviation-grade integrity monitor and galadriel's nearest intellectual ancestor.
**Residual-based RAIM** forms the sum-of-squares of the pseudorange residuals as a χ² test statistic
and flags an inconsistency; **solution-separation RAIM** compares full-set vs. subset position
solutions; both then perform **fault detection and exclusion (FDE)** to identify and drop the
offending satellite
([Parkinson & Axelrad, "Autonomous GPS Integrity Monitoring Using the Pseudorange Residual," *NAVIGATION* 35(2):255–274, 1988](https://www.ion.org/publications/abstract.cfm?articleID=100547);
survey: [*A survey of GNSS RAIM: research status and opportunities*, Frontiers in Physics, 2025](https://www.frontiersin.org/journals/physics/articles/10.3389/fphy.2025.1567301/full);
robust extension: [modified residual-based RAIM, *Sensors* 2020](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7570696/)).

**Threat model.** A single (classically) faulty measurement, under a **known geometry matrix** and a
**known measurement model**; extensions handle multiple simultaneous faults and use robust
estimators.

**Honest limit.** RAIM is **intra-modality** — it exploits the redundancy of many satellites within
*one* GNSS receiver, and it needs the linearized observation geometry. It has no notion of a
*heterogeneous* cross-sensor check, and classical single-fault RAIM inverts under a colluding
majority (the same structural failure galadriel discloses in `EVALUATION.md` §5.6).

**Relation to galadriel.** Galadriel is the **model-free, cross-modality generalization of RAIM's
core idea** — "residual consistency + identify and exclude the outlier" — moved from *pseudorange
residuals under a known geometry matrix* to *innovation residuals across heterogeneous modalities
under no shared model*, using statistical dependence (|ρ|, or MI/PID) in place of the geometry
matrix. The forced-vs-justified selection question galadriel answers is one RAIM never posed, because
RAIM's residual test is fixed by the (linear-Gaussian) measurement model — which, tellingly, is
exactly the regime where galadriel proves correlation is *sufficient*. **The most directly comparable
prior art; galadriel is a strict conceptual superset for the multi-sensor case.**

### 2.4 Innovation-based fault/attack detection (L2) *(galadriel's own baseline)*

**What.** The classical Kalman-filter consistency test: **normalized innovation squared (NIS)** as a
χ² statistic for magnitude faults, and **CUSUM** sequential detection for slow drifts
([Bar-Shalom, Li & Kirubarajan, *Estimation with Applications to Tracking and Navigation*, 2001](https://www.wiley.com/en-us/Estimation+with+Applications+to+Tracking+and+Navigation-p-9780471221272);
[Page, "Continuous inspection schemes," *Biometrika* 41, 1954](https://doi.org/10.1093/biomet/41.1-2.100)).

**Threat model.** A channel whose innovation grows in *magnitude* beyond noise.

**Honest limit.** A **magnitude** test on a single channel. A **moment-matched** spoof — same
variance, wrong dependence — passes straight through it. That blind spot is the entire reason
galadriel adds a *cross-channel* layer.

**Relation to galadriel.** This is **`galadriel-core`'s own baseline** (the NIS ⊕ correlation
default), *and* the honest comparison floor every evaluation table is run against. Galadriel does not
replace it — it fuses it (`fusion::combine`) with the cross-sensor test so the loud attacks it *does*
catch cost nothing extra. **A component, and the baseline galadriel must beat to justify itself
(`EVALUATION.md` §5.1: baseline at chance 0.547 on the stealthy spoof; cross-sensor recovers 1.000).**

### 2.5 Cross-sensor / cross-modal consistency (L2/L4) *(galadriel's family)*

**What.** Compare an untrusted channel against the corroborated consensus of independent ones. The
established instance is **GNSS/INS/odometer coupling**: detect a GNSS spoof by checking the satellite
solution against a self-contained inertial/odometer solution over an observation window
([Broumandan & Lachapelle, *Sensors* 18(5):1305, 2018](https://www.mdpi.com/1424-8220/18/5/1305)).
At L4, surveys of robotic-vehicle security name *cross-sensor consistency checks and spatio-temporal
anomaly detection* as the standard defensive toolkit
([Ren et al., "SoK: Rethinking Sensor Spoofing Attacks," IEEE EuroS&P 2023](https://arxiv.org/abs/2205.04662)),
and cross-modal plausibility / temporal-consistency checks are the defenses discussed alongside the
MSF perception attacks ([Cao et al., IEEE S&P 2021](https://arxiv.org/abs/2106.09249);
[Hallyburton et al., USENIX Security 2022](https://arxiv.org/abs/2106.07098)).

**Threat model.** A minority of channels that stop agreeing with the physical world the others see.

**Honest limit.** Defeated by a **statistics-matching false-data injection** that *preserves*
cross-sensor consistency — the **frustum attack** is exactly this, "stealthy … because it preserves
consistencies between camera and LiDAR" [Hallyburton2022]. This is galadriel's disclosed honest
boundary (`PAPER.md` §6), i.e. its limit *is* the current state-of-the-art attack.

**Relation to galadriel.** **This is galadriel's family** — it is the multi-sensor generalization of
Broumandan's pairwise GNSS-vs-INS check to an $N$-channel test, differentiated by (a) the
forced-vs-justified *detector-selection* result the consistency-check literature never asked, (b)
advisory per-channel **attribution** rather than a single accept/reject, and (c) zero training or
model assumptions. **Truly competing prior art — differentiated on the selection discipline and
attribution, not on the base idea.**

### 2.6 Secure / resilient state estimation (L3) *(guarantee-based)*

**What.** Reconstruct the *true state* despite a bounded number of arbitrarily corrupted sensors, via
an error-correction-over-the-reals / compressed-sensing formulation
([Fawzi, Tabuada & Diggavi, "Secure Estimation and Control for CPS under Adversarial Attacks," IEEE TAC 59(6), 2014](https://arxiv.org/abs/1205.5073);
noisy extension: Mishra et al., IEEE TCNS 2017; distributed/Byzantine observers:
[Byzantine-Resilient Distributed Observers, 2018](https://arxiv.org/abs/1802.09651)).

**Threat model.** Up to *p* of *2p+1* sensors adversarial, under a **known LTI dynamics model** and
an observability/redundancy condition.

**Honest limit.** Needs a system model and satisfied redundancy bounds; it **estimates *through*** the
attack rather than *flagging* it (weaker attribution / operator signal); and it inherits the same
honest-majority ceiling — corrupt more than *p* and the guarantee is void.

**Relation to galadriel.** A **stronger guarantee at a higher assumption cost.** Where a validated LTI
model and the corruption bound hold, resilient estimation *provably recovers the state* — more than
galadriel's advisory flag. Where they don't (heterogeneous modalities, no clean dynamics model, an
operator who wants *attribution* not silent correction), galadriel's model-free advisory test
applies. **Complementary along the guarantee/assumption trade-off; a natural L3 partner to galadriel's
L2 flag.**

### 2.7 Byzantine-robust / redundancy-voting fusion (L3)

**What.** Make the *estimate* survive a corrupted minority by construction: median / trimmed-mean /
RANSAC fusion, weighted majority, robust M-estimators
([*A Secure Sensor Fusion Framework for CAVs under Sensor Attacks*, 2021](https://arxiv.org/abs/2103.00883)).

**Threat model.** A minority of outlying channels.

**Honest limit.** Robust fusion *masks* the attack to protect the estimate — it does not necessarily
*surface* it, so an operator may never learn a sensor was compromised; and a colluding majority
defeats the vote.

**Relation to galadriel.** **Robustness-by-design vs. detect-and-attribute.** Robust fusion keeps the
number good under attack; galadriel tells the operator *which* channel to distrust and *how
stealthily*. They compose cleanly: robust fusion for continuity, galadriel for situational awareness
and forensics. **Complementary.**

### 2.8 Learning-based anomaly detection (L2/L4)

**What.** Autoencoders, LSTM/temporal predictors, one-class SVMs on sensor streams, and ML
jam/spoof/meaconing classifiers over multi-sensor features
([ML-based jamming/meaconing/spoofing detection, 2025](https://anavs.com/wp-content/uploads/2025/10/Detection_and_Mitigation_of_Jamming_Meaconing_and_Spoofing_based_on_Machine_Learning_and_Multi_Sensor_Data.pdf)).

**Threat model.** Anomalies (including nonlinear ones) that deviate from a *learned* normal.

**Honest limit.** Needs representative training data, degrades under distribution shift, is hard to
certify for safety-critical use, and typically gives weak **attribution** and interpretability.

**Relation to galadriel.** Overlaps galadriel's **PID-escalation regime** — genuinely
*nonlinear/synergistic* cross-channel structure that correlation misses (`PAPER.md` §4.2). Galadriel
stays **nonparametric and training-free** (KSG-MI / PID, geometry-gated), trading the raw capacity of
a trained model for zero training data, a stated cost model, and per-channel attribution. **Competes
in the nonlinear regime; differentiated on training-freeness, cost transparency, and attribution.**

### 2.9 Active challenge-response / physical probing (L0)

**What.** Instead of passively watching, *actively* perturb the physical channel with a randomized
challenge an attacker cannot predict, and verify the response — **PyCRA** (physical challenge-response
authentication for active sensors)
([Shoukry et al., "PyCRA," ACM CCS 2015](https://dl.acm.org/doi/10.1145/2810103.2813679)).

**Threat model.** A spoofer of an *active* sensor (radar, lidar, ultrasonic) that cannot respond
correctly to an unpredictable probe.

**Honest limit.** Requires **actuation authority** over the sensor and only applies to active sensors;
adds emissions and complexity; nothing for passive modalities.

**Relation to galadriel.** **Active vs. passive.** PyCRA changes the physical interrogation to make
spoofing detectable at the source; galadriel is purely observational on residuals already produced.
Where actuation is available they stack. **Complementary.**

---

## 3. Head-to-head comparison

**Table A — the landscape.** ("Insider" = a compromised-but-authenticated sensor emitting false data;
"external" = an unauthenticated injector.)

| Approach | Layer | Modality scope | Primary threat | Guarantee | Key assumptions | Extra cost/hardware |
|---|---|---|---|---|---|---|
| Signal-level GNSS (§2.1) | L0 | GNSS only | External RF spoof | Detect (pre-capture) | RF front-end access; array for DOA | Antenna array / rotating antenna |
| Crypto auth / OSNMA (§2.2) | L0/L1 | Per-signal / per-node | External forgery | **Prevent** impersonation | Key infrastructure | Key management |
| RAIM (§2.3) | L1 | GNSS (intra-modality) | Faulty/spoofed satellite | Detect + exclude | Known geometry + measurement model | None (compute) |
| Innovation NIS/CUSUM (§2.4) | L2 | Per channel | Magnitude fault | Detect | Filter innovations available | Negligible |
| **Cross-sensor consistency — galadriel (§2.5)** | **L2** | **N heterogeneous** | **Insider that breaks agreement** | **Detect + attribute (advisory)** | **Innovations; ≥3 channels** | **~1× (corr) / ~100× (PID)** |
| Resilient state estimation (§2.6) | L3 | N (modeled) | ≤p corrupted sensors | **Recover state** (provable) | Known LTI model + redundancy bound | Compute (optimization) |
| Byzantine-robust fusion (§2.7) | L3 | N | Corrupted minority | **Tolerate** (mask) | Honest majority | Negligible |
| Learning-based (§2.8) | L2/L4 | N | Learned-normal anomaly | Detect (statistical) | Representative training data | Training + inference |
| Challenge-response / PyCRA (§2.9) | L0 | Active sensors | Active-sensor spoof | Detect at source | Actuation authority | Probe emissions |

**Table B — positioning against the two attacks that define galadriel.** The moment-matched insider
spoof is galadriel's *target*; the statistics-matching FDI (frustum-class) is its disclosed *blind
spot*. A "✗ / partial" is not a criticism — it names the layer each method is built for.

| Approach | Sees the moment-matched insider spoof (galadriel's target)? | Sees the statistics-matching FDI (galadriel's blind spot)? | Sees the external RF spoof (galadriel can't at L2)? |
|---|---|---|---|
| Signal-level GNSS | ✗ (post-capture) | ✗ | **✓** |
| Crypto auth / OSNMA | ✗ (valid key) | ✗ | **✓** (external forger) |
| RAIM | partial (GNSS-only, single-fault) | ✗ | ✓ (as pseudorange fault) |
| Innovation NIS/CUSUM | ✗ (moment-matched) | ✗ | partial (if loud) |
| **galadriel** | **✓** | **✗ (honest limit, §6)** | ✗ (not at L2) |
| Resilient state estimation | ✓ (if within budget + model) | partial (if it moves the state) | ✓ (as bad measurement) |
| Byzantine-robust fusion | masks, doesn't surface | masks if minority | masks if minority |
| Learning-based | partial (if unlike training normal) | partial (if off-manifold) | partial |
| Challenge-response | ✗ (passive-data insider) | ✗ | ✓ (active-sensor source) |

The lesson of Table B is the thesis of §5: **no single row covers all three columns.** The columns
are covered by *composing* rows, not by picking a winner.

---

## 4. How they could be compared: a benchmark methodology

Comparing these approaches fairly is harder than tabulating ROC curves, because they observe
different layers, assume different infrastructure, and offer different *kinds* of guarantee. A
credible cross-approach benchmark needs four ingredients. Galadriel's own harness
(`docs/EVALUATION.md`, `crates/galadriel-eval`) already instantiates most of them *within the L2
consistency family*; the remainder is what a broader benchmark would still have to build.

### 4.1 The comparison axes

Report every method on all of these — scoring only the first two is the classic mistake galadriel was
built to correct:

1. **Accuracy** — ROC-AUC / detection rate, with confidence intervals.
2. **Latency** — time-to-detect (frames/seconds from attack onset).
3. **Compute cost** — wall-clock / FLOPs relative to the cheapest baseline, *and* how it scales with
   window length and channel count.
4. **Adaptive robustness** — performance against a **Kerckhoffs-aware** adversary who knows the
   detector and hugs its threshold (§4.3).
5. **Attribution** — does it identify *which* channel, or only that *something* is wrong?
6. **Assumptions as a first-class output** — what must be true for it to run at all (model? geometry?
   training data? honest majority? key infrastructure? actuation authority?). Two methods with equal
   AUC are not equivalent if one needs a validated dynamics model and the other needs nothing.

Galadriel's three-axis synthesis (accuracy × latency × cost, `EVALUATION.md` §5.4) plus its adaptive
(§5.7), non-stationary-FAR (§5.8), and attacker-gain (§5.9) studies already report axes 1–4 and 6;
its per-channel verdict supplies axis 5.

### 4.2 A shared attack ontology

Every method must be run against the **same** attack suite, and each attack tagged with the layer(s)
it touches (so an L0 method is not unfairly scored on an attack that is only visible at L2, and vice
versa). Galadriel's suite is a reusable starting point:

| Attack | Layer(s) touched | What it probes |
|---|---|---|
| Loud bias spoof | L1/L2 | Magnitude sensitivity (the NIS baseline's home turf) |
| Broadband jam | L0/L2 | Correlated all-channel denial; jam-vs-spoof disambiguation |
| **Moment-matched stealthy spoof** | L2 | The consistency detector's reason to exist |
| Colluding 2-of-3 majority | L2/L3 | Honest-majority failure (structural, §5.6) |
| Adaptive threshold-hugging | L2 | Kerckhoffs-aware evasion ceiling at matched FAR (§5.7) |
| Non-stationary maneuver | L2 | False-alarm robustness to benign dynamics (§5.8) |
| Statistics-matching FDI (frustum-class) | L2/L4 | The **disclosed blind spot** — the honest ceiling everyone shares |

A cross-approach benchmark would extend this with **L0/L1 attacks** (RF power takeover, DOA
single-source, forged unauthenticated message) so signal-level and cryptographic methods have
attacks they can actually see — and would then report, per method, *which attacks are in-scope for its
layer at all.*

### 4.3 The matched operating point (why raw ROC is misleading)

Detectors with different score distributions cannot be compared at a single threshold. The fair
comparison fixes a **common false-alarm rate** and reads detection (or the adversary's evasion
ceiling) *there*. Galadriel's adaptive study does exactly this — at **matched FAR**, correlation's
evasion ceiling (0.20) is *lower* than PID's (0.40), reversing the naive intuition that the fancier
detector is harder to evade (`EVALUATION.md` §5.7). Any cross-approach table must pin the operating
point the same way, or it is comparing thresholds, not detectors.

### 4.4 Metrics, precisely

- **Detection:** AUC (Mann-Whitney, ties = 0.5) with a **percentile-bootstrap 95% CI**; for two
  detectors on the *same* scenarios, a **paired** bootstrap of the AUC *difference* (galadriel's
  `auc_diff_ci`) — the only honest way to call a "tie" or a "strictly beats."
- **Rates:** detection/false-alarm as **Wilson intervals**, not bare fractions.
- **Latency:** median frames-to-detect from onset.
- **Cost:** relative to the cheapest baseline, with a window/channel scaling curve.
- **Adaptive:** evasion ceiling (max undetected attack strength) at matched FAR.
- **Attacker success:** the *bounded* undetected state-pull (galadriel's §5.9) — how far an adversary
  can move the estimate while staying under the detector.

### 4.5 What galadriel's harness already provides — and what it does not

**Provides (reusable today, within the L2 family):** shared synthetic scenarios with a known
ground-truth attack; a matched-FAR comparison; paired-bootstrap CIs; the seven-attack suite above;
and the full accuracy/latency/cost/adaptive/FAR/attacker-gain axis set — all as reproducible `cargo`
commands.

**Does not yet provide (what a true cross-approach benchmark still needs):**
1. **Multi-layer data** — the same scenario emitted at L0 (RF/IQ), L1 (measurements), and L2
   (innovations), so signal-level, RAIM, and consistency detectors run on *one* ground truth.
2. **Real (non-synthetic) traces** — galadriel's study is Gaussian and non-adaptive by construction
   (`PAPER.md` §6); a benchmark that ranks methods for deployment needs field data.
3. **Assumption accounting** — a standard way to report each method's prerequisites (§4.1, axis 6) as
   part of its score, so a model-free advisory flag and a model-based provable recovery are not
   compared as if they answered the same question.

Naming these gaps *is* the honest contribution: galadriel benchmarks rigorously **within its own
family and layer**, and the cross-family comparison is scoped, not overclaimed.

### 4.6 Pitfalls to avoid

- **Layer mismatch:** scoring an L0 detector on an L2-only attack (or vice versa) manufactures a
  false winner. Tag attacks by layer (§4.2).
- **Unmatched thresholds:** comparing AUC-optimal points of differently-shaped score distributions.
  Fix the FAR (§4.3).
- **Assumption laundering:** hiding that method A needed a validated dynamics model (or labeled
  training data, or an extra antenna) while method B needed nothing. Report assumptions as a first-
  class result (§4.1).
- **Ignoring the shared ceiling:** *every* consistency-family method — galadriel included — is
  defeated by the statistics-matching FDI. A benchmark that omits that attack flatters the whole
  family.

---

## 5. Competing vs. complementary: the layered-defense picture

The single most important conclusion of this survey is that **most of these approaches are not
galadriel's rivals — they are its neighbors in a stack.** They defeat *disjoint* attacker
capabilities at *different* layers:

```
  L0  RF/signal      →  signal-level GNSS AS  +  crypto/OSNMA  +  PyCRA (active probing)
  L1  measurement    →  RAIM (intra-GNSS FDE)  +  message authentication
  L2  residual       →  innovation NIS/CUSUM  ⊕  GALADRIEL (cross-sensor consistency + attribution)
  L3  state          →  resilient estimation (recover)  +  Byzantine-robust fusion (tolerate)
  L4  perception     →  cross-modal plausibility / temporal-consistency checks
  ——  enforcement    →  per-plane ACL / mTLS on the NCP bus  +  safety governor
```

Read down the stack: an attacker who beats the L0 signal checks and holds a valid key (beating L1
crypto) still has to keep a *compromised sensor's residuals consistent with the others* to beat L2 —
that is the bar galadriel raises. An attacker who *can* do that (the frustum-class statistics-matching
FDI) has reached the state of the art, and defeats the whole L2/L4 consistency family at once — which
is why the enforcement layer (crypto identity + safety governor) is the real backstop, and galadriel
is honestly labeled *advisory instrumentation on top* (`MOTIVATION.md` §4b).

**Where galadriel genuinely competes** (rather than composes) is a short, well-defined list:

- **Other cross-sensor consistency detectors (§2.5)** — same family, same layer. Galadriel's
  differentiators: the forced-vs-justified *detector-selection* result (correlation by default, MI/PID
  only off the Gaussian manifold), per-channel **attribution**, and zero model/training assumptions.
- **Learning-based anomaly detectors (§2.8)** in the nonlinear regime — galadriel's PID escalation
  targets the same synergistic structure, but training-free, cost-transparent, and attributive.
- **Classical single-modality RAIM (§2.3)** as the conceptual ancestor — galadriel is the model-free,
  multi-modality generalization of its residual-consistency + exclusion principle.

Against everything else — signal-level GNSS, cryptographic authentication, resilient state estimation,
Byzantine-robust fusion, active challenge-response — galadriel is **complementary**, and the right
deployment posture is *all of them, layered*, not a bake-off. That posture, and the discipline of
knowing **which detector to pay for at which layer against which attack**, is the contribution this
project exists to make.

---

## References for this document

Reuses the citation keys of [`PAPER.md` §References](PAPER.md#references) where they overlap
([Cao2021], [Hallyburton2022], [Ren2022], [Broumandan2018], [BarShalom2001], [Page1954],
[Barrett2015], [Kraskov2004], [Humphreys2012], [Liu2011], [Mo2010]) and adds:

- **[ParkinsonAxelrad1988]** B. W. Parkinson, P. Axelrad. "Autonomous GPS Integrity Monitoring Using the Pseudorange Residual." *NAVIGATION* **35**(2):255–274, 1988. [ION](https://www.ion.org/publications/abstract.cfm?articleID=100547).
- **[RAIMsurvey2025]** "A survey of GNSS receiver autonomous integrity monitoring: research status and opportunities." *Frontiers in Physics,* 2025. [link](https://www.frontiersin.org/journals/physics/articles/10.3389/fphy.2025.1567301/full).
- **[GNSSspoofSurvey2022]** "A Survey of GNSS Spoofing and Anti-Spoofing Technology." *Remote Sensing* **14**(19):4826, 2022. [MDPI](https://www.mdpi.com/2072-4292/14/19/4826).
- **[SpatialProcessing2021]** "GNSS spoofing detection through spatial processing." *NAVIGATION: J. Inst. Navigation* **68**(2):243, 2021. [link](https://navi.ion.org/content/68/2/243).
- **[Fawzi2014]** H. Fawzi, P. Tabuada, S. Diggavi. "Secure Estimation and Control for Cyber-Physical Systems Under Adversarial Attacks." *IEEE Trans. Automatic Control* **59**(6):1454–1467, 2014. [arXiv:1205.5073](https://arxiv.org/abs/1205.5073).
- **[Mishra2017]** S. Mishra, Y. Shoukry, N. Karamchandani, S. Diggavi, P. Tabuada. "Secure State Estimation Against Sensor Attacks in the Presence of Noise." *IEEE Trans. Control of Network Systems,* 2017.
- **[ByzantineObservers2018]** "Byzantine-Resilient Distributed Observers for LTI Systems." 2018. [arXiv:1802.09651](https://arxiv.org/abs/1802.09651).
- **[SecureFusionCAV2021]** "A Secure Sensor Fusion Framework for Connected and Automated Vehicles Under Sensor Attacks." 2021. [arXiv:2103.00883](https://arxiv.org/abs/2103.00883).
- **[Shoukry2015]** Y. Shoukry, P. Martin, Y. Yona, S. N. Diggavi, M. B. Srivastava. "PyCRA: Physical Challenge-Response Authentication For Active Sensors Under Spoofing Attacks." *ACM CCS,* pp. 1004–1015, 2015. [ACM](https://dl.acm.org/doi/10.1145/2810103.2813679).
- **[MLspoof2025]** "Detection and Mitigation of Jamming, Meaconing, and Spoofing based on Machine Learning and Multi-Sensor Data." 2025. [PDF](https://anavs.com/wp-content/uploads/2025/10/Detection_and_Mitigation_of_Jamming_Meaconing_and_Spoofing_based_on_Machine_Learning_and_Multi_Sensor_Data.pdf).
