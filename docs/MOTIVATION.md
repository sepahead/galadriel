# Why galadriel: the real problem, with evidence

galadriel is not a solution in search of a problem. Sensor spoofing of autonomous and
counter-UAS systems is a **demonstrated, current, high-stakes** threat; multi-sensor fusion is
the standard defense against it; that defense is itself defeated by attacks that **fake
cross-sensor agreement**; and **cross-sensor consistency checking** — exactly what galadriel
implements — is a recognized countermeasure. This document lays out the evidence and cites its
sources, then states honestly where galadriel does and does not help.

> **Evidence status (2026-07 audit).** The threat and literature citations below motivate
> the research question; they do not validate this implementation. Galadriel's current
> detector evidence is synthetic. The bundled crebain capture proves parsing and baseline
> smoke behavior only: normal captures omit research fields, modalities use mixed residual
> frames, sequential updates do not share a frozen prior, and gating censors misses. The
> cross-channel result for that fixture is therefore `InsufficientEvidence`.

---

## 1. The threat is real, and it is current

**Spoofing a UAV's navigation is a demonstrated attack, not a hypothetical.** In June 2012, a
University of Texas at Austin team led by Todd Humphreys — invited by the U.S. Department of
Homeland Security — commandeered a GPS-guided UAV over the White Sands, New Mexico missile range
from a half-mile standoff using a purpose-built civil-GPS spoofer, inducing the drone to dive
toward the ground. The equipment cost on the order of $1,000
([EurekAlert / UT Austin](https://www.eurekalert.org/news-releases/524632);
[GPS World, "Drone Hack"](https://www.gpsworld.com/drone-hack/);
[Humphreys, congressional testimony](https://rnl.ae.utexas.edu/images/stories/files/papers/Testimony-Humphreys.pdf)).

**A decade later, GNSS spoofing and jamming are a theatre-wide reality.** In the war in Ukraine,
navigation-signal denial and deception have been continuous and area-wide since 2022. Ukraine has
fielded networked electronic-warfare systems (e.g. *Pokrova*) that spoof incoming drones' satellite
navigation to
make them deviate or fall
([Defense One, 2024](https://www.defenseone.com/technology/2024/09/group-ukraine-testing-newest-weapon-against-gps-jammers-cell-phones/399952/);
[The Record](https://therecord.media/ukraine-anti-drone-gps-spoofing-affects-civilian-mobile-phones);
[RNTF / New Scientist](https://rntfnd.org/2024/02/03/ukraine-will-spoof-gps-across-the-country-to-stop-russian-drones-new-scientist/)).
The interference is no longer confined to the battlefield: Poland logged **thousands** of GNSS
interference events in a single month, and GNSS disruption around conflict zones has become a
recognized civil-aviation safety concern
([Jerusalem Post](https://www.jpost.com/defense-and-tech/article-894907)).

The takeaway: an adversary who can make a sensor **lie plausibly** — report a false position,
bearing, or return — is a live, low-cost, and militarily significant capability. That is the
threat galadriel's ecosystem sibling **crebain** (the tactical counter-UAS fuser) must survive,
and the threat galadriel exists to *flag*.

## 2. Multi-sensor fusion is the standard defense — and it is attackable

The textbook mitigation for a single lying sensor is **redundancy**: fuse several modalities
(camera, radar, acoustic DOA, lidar, RF) so that no one channel can dominate. Production
autonomous systems adopt exactly this multi-sensor-fusion (MSF) design for robustness.

The security literature has shown that MSF's redundancy is **not** a free guarantee, because an
attacker can **fabricate cross-sensor consistency**:

- **Cao et al., "Invisible for both Camera and LiDAR" (IEEE S&P 2021)** — the first study of MSF
  perception security — builds a *physical-world* adversarial object (`MSF-ADV`) that fools a
  camera-**and**-LiDAR fusion stack simultaneously into missing a front obstacle
  ([arXiv:2106.09249](https://arxiv.org/abs/2106.09249);
  [code](https://github.com/ASGuard-UCI/MSF-ADV)).
- **Hallyburton et al., "Security Analysis of Camera-LiDAR Fusion" (USENIX Security 2022)** —
  introduces the **frustum attack**, which defeats camera-LiDAR fusion and is *"stealthy to
  existing defenses against LiDAR spoofing as it preserves consistencies between camera and
  LiDAR semantics"*
  ([USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton);
  [arXiv:2106.07098](https://arxiv.org/abs/2106.07098)).

This is the crux, and it is **exactly the boundary galadriel draws for itself** (paper §6): a
consistency detector catches a spoof that *breaks* cross-channel agreement, but is defeated by a
**statistics-matching false-data injection** that *preserves* it. The frustum attack is that
adversary demonstrated in a research system. galadriel does not claim to beat it. The
example identifies a boundary for consistency monitoring; no current field evidence
quantifies how much galadriel raises an operational adversary's cost.

## 3. Cross-sensor consistency detection is a recognized countermeasure

galadriel's approach — flag the channel that has stopped agreeing with the corroborated consensus
of the others — is not invented here; it is a named defense in this space. The security literature
systematizes these sensor-spoofing attacks against multi-sensor robotic vehicles ([Xu et al.,
"SoK: Rethinking Sensor Spoofing Attacks against Robotic Vehicles from a Systematic View," IEEE
EuroS&P 2023, arXiv:2205.04662](https://arxiv.org/abs/2205.04662)). Cross-sensor **consistency
checking** — flagging a channel that stops agreeing with the corroborated majority — is a
recognized countermeasure whose canonical academic form is exactly this comparison: Broumandan &
Lachapelle detect GNSS spoofing by a **consistency check between the GNSS solution and a
self-contained INS/odometer** over an observation window
([*Sensors* 18(5):1305, 2018](https://www.mdpi.com/1424-8220/18/5/1305)), and the MSF attack
papers in §2 discuss cross-modal plausibility and consistency checks as the corresponding
defenses.

galadriel explores an **N-channel generalization** of that established idea. It is a
tested research implementation, not a field-validated reference detector. Its current
producer integration does not yet provide comparable cross-modal residuals.

## 4. Where galadriel fits — and the sharper contribution

Two things make galadriel more than "another consistency check":

**(a) It maps the method choice onto the real attack classes.** The paper's central result is that
*information-theoretic* consistency (mutual information / Partial Information Decomposition)
adds no population information over covariance when the registered cross-channel model is
linear-Gaussian. It becomes a research candidate when a documented estimand is nonlinear,
joint, or adversarially structured. Whether either regime describes field data is empirical:

- **An ideal linear-Gaussian tracker model** makes MI a monotone transform of correlation.
  In that model, MI/PID adds no population-level discrimination and correlation is the
  appropriate cheaper statistic. Whether recorded counter-UAS innovations fit that model
  is an open empirical question, not an established property of current crebain output.
- **Learned-perception MSF attacks** (`MSF-ADV`, the frustum attack) act on a nonlinear
  neural fusion stack — the kind of regime §4.2 motivates studying, where a
  joint-information measure *could in principle* see structure a correlation check on that feature
  cannot. Two honest caveats keep this short of a claim that the escalation *beats* these attacks:
  galadriel consumes an attested projection of kinematic residuals, not that fusion feature (so this argues *where*
  escalation would pay off, it is not a galadriel result); and the frustum attack is *defined* by
  preserving cross-sensor consistency (§2), which by construction defeats **every** consistency
  detector — correlation and MI/PID alike. The escalation's payoff is confined to couplings that are
  nonlinear/synergistic yet still leave a dependence signature; a statistics-matching FDI is the
  whole family's shared blind spot, and the paper leaves the neural-fusion mapping itself to future
  work.

So the disciplined recommendation is signed correlation by default and PID only as
additive, sign-invariant evidence when validated geometry and a nonlinear estimand justify it.

**(b) It is scrupulously honest about scope.** galadriel is **advisory**
(`calibrated_posterior = false`): it authenticates statistical *consistency*, not *truth*; it
cannot see a statistics-matching spoof (§2); and its evaluation is synthetic,
non-adaptive study whose limits are stated in the paper's §6. The real enforcement layer is
cryptographic (per-plane ACL / mTLS on the NCP bus) plus a safety governor; galadriel is
instrumentation on top.

---

## 5. The methodological foundations (verified)

The information-theoretic machinery is standard and correctly attributed:

- **KSG mutual information** — A. Kraskov, H. Stögbauer, P. Grassberger, "Estimating mutual
  information," *Phys. Rev. E* **69**, 066138 (2004)
  ([APS](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.69.066138)).
- **Partial Information Decomposition** — P. L. Williams, R. D. Beer, "Nonnegative Decomposition of
  Multivariate Information," [arXiv:1004.2515](https://arxiv.org/abs/1004.2515) (2010).
- **The `I^sx` shared-exclusions redundancy** — A. Makkeh, A. J. Gutknecht, M. Wibral,
  "Introducing a differentiable measure of pointwise shared information," *Phys. Rev. E* **103**,
  032149 (2021) ([APS](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.103.032149)) — a
  pointwise redundancy measure with a Möbius inversion on the redundancy lattice, exactly as
  used here; its **continuous-variable formulation and the kNN estimator galadriel actually
  runs** are D. A. Ehrlich, K. Schick-Poland, A. Makkeh, F. Lanfermann, P. Wollstadt,
  M. Wibral, "Partial information decomposition for continuous variables based on shared
  exclusions," *Phys. Rev. E* **110**, 014115 (2024)
  ([arXiv:2311.06373](https://arxiv.org/abs/2311.06373)); the part-whole/formal-logic
  foundation is Gutknecht, Wibral & Makkeh, *Proc. R. Soc. A* **477**:20210110 (2021)
  ([arXiv:2008.09535](https://arxiv.org/abs/2008.09535)).

The observation that on jointly-Gaussian data the *entire* decomposition is fixed by the covariance —
so PID adds nothing over correlation there — needs no deep theorem: a zero-mean Gaussian is
completely parameterized by its covariance, so *any* PID functional of it (any measure, the
reported `I^sx` included) is a function of the correlations. What **Barrett** proved is the
sharper, measure-collapsing statement: for jointly-Gaussian sources and a *univariate* target,
every PID whose redundant/unique atoms depend only on the pairwise source–target marginals
(I_min, BROJA, and the other pre-2015 proposals) reduces to the minimum-mutual-information
redundancy (A. B. Barrett, *Phys. Rev. E* **91**, 052802, 2015,
[arXiv:1411.2832](https://arxiv.org/abs/1411.2832)); Venkatesh & Schamberg confirm that
reduction for scalar targets and show it does **not** extend to multivariate targets
([ISIT 2022](https://arxiv.org/abs/2105.00769)). The reported `I^sx` is *outside* Barrett's
class (it reads the full joint and permits negative atoms; on Gaussians its redundancy is a
different function of the covariance than MMI). It is still determined by the covariance,
but that fact alone does not establish finite-sample estimator equivalence. The finite-sample
behaviour of the KSG estimator we escalate to splits across three sources: its dimension-dependent
bias in the high-dimensional / short-window regime our geometry gate rejects is characterised by
[Gao, Oh & Viswanath (IEEE Trans. IT 2018)](https://arxiv.org/abs/1604.03006); its tendency to
*underestimate* mutual information under strong dependence at feasible sample sizes is due to
[Gao, Ver Steeg & Galstyan (AISTATS 2015)](https://arxiv.org/abs/1411.2003); and the sign of its
bias is regime-dependent in general
([Holmes & Nemenman, PRE 2019](https://arxiv.org/abs/1903.09280)).

---

## Sources

- UT Austin / Humphreys 2012 UAV GPS-spoofing demonstration — [EurekAlert](https://www.eurekalert.org/news-releases/524632), [GPS World](https://www.gpsworld.com/drone-hack/), [Humphreys testimony (PDF)](https://rnl.ae.utexas.edu/images/stories/files/papers/Testimony-Humphreys.pdf)
- Ukraine / counter-UAS electronic warfare — [Defense One](https://www.defenseone.com/technology/2024/09/group-ukraine-testing-newest-weapon-against-gps-jammers-cell-phones/399952/), [The Record](https://therecord.media/ukraine-anti-drone-gps-spoofing-affects-civilian-mobile-phones), [RNTF/New Scientist](https://rntfnd.org/2024/02/03/ukraine-will-spoof-gps-across-the-country-to-stop-russian-drones-new-scientist/), [Jerusalem Post](https://www.jpost.com/defense-and-tech/article-894907)
- Cao et al., IEEE S&P 2021, *Invisible for both Camera and LiDAR* — [arXiv:2106.09249](https://arxiv.org/abs/2106.09249), [code](https://github.com/ASGuard-UCI/MSF-ADV)
- Hallyburton et al., USENIX Security 2022, *frustum attack* — [USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton), [arXiv:2106.07098](https://arxiv.org/abs/2106.07098)
- Xu et al., "SoK: Rethinking Sensor Spoofing Attacks against Robotic Vehicles from a Systematic View," IEEE EuroS&P 2023 — [arXiv:2205.04662](https://arxiv.org/abs/2205.04662)
- Kraskov–Stögbauer–Grassberger 2004 — [Phys. Rev. E 69, 066138](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.69.066138)
- Williams–Beer 2010 — [arXiv:1004.2515](https://arxiv.org/abs/1004.2515)
- Makkeh–Gutknecht–Wibral 2021 — [Phys. Rev. E 103, 032149](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.103.032149)
