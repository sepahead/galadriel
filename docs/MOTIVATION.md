# Why galadriel: the real problem, with evidence

galadriel is not a solution in search of a problem. Sensor spoofing of autonomous and
counter-UAS systems is a **demonstrated, current, high-stakes** threat; multi-sensor fusion is
the standard defense against it; that defense is itself defeated by attacks that **fake
cross-sensor agreement**; and **cross-sensor consistency checking** — exactly what galadriel
implements — is a recognized countermeasure. This document lays out the evidence and cites its
sources, then states honestly where galadriel does and does not help.

---

## 1. The threat is real, and it is current

**Spoofing a UAV's navigation is a demonstrated attack, not a hypothetical.** In June 2012, a
University of Texas at Austin team led by Todd Humphreys — invited by the U.S. Department of
Homeland Security — commandeered a GPS-guided UAV over the White Sands, New Mexico missile range
from a half-mile standoff using a purpose-built civil-GPS spoofer, inducing the drone to dive
toward the ground. The equipment cost on the order of $1,000
([EurekAlert / UT Austin](https://www.eurekalert.org/pub_releases/2012-06/uota-uot062912.php);
[GPS World, "Drone Hack"](https://www.gpsworld.com/drone-hack/);
[Humphreys, congressional testimony](https://rnl.ae.utexas.edu/images/stories/files/papers/Testimony-Humphreys.pdf)).

**A decade later, GNSS spoofing and jamming are a theatre-wide reality.** In the war in Ukraine,
navigation-signal denial and deception have been continuous and area-wide since 2022, and drone
strike accuracy is reported to fall below 10 % under heavy jamming; Ukraine has fielded networked
electronic-warfare systems (e.g. *Pokrova*) that spoof incoming drones' satellite navigation to
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
  existing defenses **because it preserves consistencies** between camera and LiDAR semantics"*
  ([USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton);
  [arXiv:2106.07098](https://arxiv.org/abs/2106.07098)).

This is the crux, and it is **exactly the boundary galadriel draws for itself** (paper §6): a
consistency detector catches a spoof that *breaks* cross-channel agreement, but is defeated by a
**statistics-matching false-data injection** that *preserves* it. The frustum attack is that
adversary, in the wild, at the state of the art. galadriel does not claim to beat it — it claims
to raise the adversary's bar *to* that capability, and says so plainly.

## 3. Cross-sensor consistency detection is a recognized countermeasure

galadriel's approach — flag the channel that has stopped agreeing with the corroborated consensus
of the others — is not invented here; it is a named defense in this space. Surveys of MSF and
robotic-vehicle security list **"sensor fusion consistency checks, redundancy across modalities,
and anomaly detection leveraging temporal and spatial correlations"** as the defensive toolkit
([SoK: sensor-spoofing of robotic vehicles, arXiv:2205.04662](https://arxiv.org/abs/2205.04662)).
In the GNSS setting specifically, spoofing "is detected and rejected by **comparing GPS data to
visual or inertial position data**" — cross-sensor consistency by another name
([Defense One, 2024](https://www.defenseone.com/technology/2024/09/group-ukraine-testing-newest-weapon-against-gps-jammers-cell-phones/399952/)).

galadriel is a clean, tested, honestly-scoped **reference implementation** of that idea, plus the
methodological result in §4 below.

## 4. Where galadriel fits — and the sharper contribution

Two things make galadriel more than "another consistency check":

**(a) It maps the method choice onto the real attack classes.** The paper's central result is that
*information-theoretic* consistency (mutual information / Partial Information Decomposition) is
**forced, not justified,** over a one-line correlation check when the cross-channel dependence is
linear-Gaussian — and is *justified* only when the dependence is genuinely nonlinear, synergistic,
or adversarially structured. This dichotomy is not academic; it partitions the real threat:

- **GNSS / kinematic spoofing** (the counter-UAS tracker case) produces **linear-Gaussian**
  innovation residuals. Here MI/PID is forced — a correlation check is provably sufficient, ~100×
  cheaper, and (near the detection boundary) strictly better. Use the cheap detector.
- **Learned-perception MSF attacks** (the frustum attack, `MSF-ADV`) act on a **nonlinear,
  synergistic** neural fusion feature — exactly the regime where the paper shows correlation
  collapses and a joint-information measure is the *only* thing that can see the structure. Here
  the escalation earns its cost.

So the disciplined recommendation ("correlation by default, PID on escalation") is a *map* from the
attack you face to the detector you should pay for.

**(b) It is scrupulously honest about scope.** galadriel is **advisory**
(`calibrated_posterior = false`): it authenticates statistical *consistency*, not *truth*; it
cannot see a statistics-matching spoof (§2); and its evaluation is a synthetic, Gaussian,
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
  redundancy measure with a Möbius inversion on the redundancy lattice, exactly as used here.

The claim that on jointly-Gaussian data the *entire* decomposition is fixed by the covariance
(so PID adds nothing over correlation there) is consistent with recent closed-form Gaussian-PID
results ([arXiv:2605.09919](https://arxiv.org/abs/2605.09919)).

---

## Sources

- UT Austin / Humphreys 2012 UAV GPS-spoofing demonstration — [EurekAlert](https://www.eurekalert.org/pub_releases/2012-06/uota-uot062912.php), [GPS World](https://www.gpsworld.com/drone-hack/), [Humphreys testimony (PDF)](https://rnl.ae.utexas.edu/images/stories/files/papers/Testimony-Humphreys.pdf)
- Ukraine / counter-UAS electronic warfare — [Defense One](https://www.defenseone.com/technology/2024/09/group-ukraine-testing-newest-weapon-against-gps-jammers-cell-phones/399952/), [The Record](https://therecord.media/ukraine-anti-drone-gps-spoofing-affects-civilian-mobile-phones), [RNTF/New Scientist](https://rntfnd.org/2024/02/03/ukraine-will-spoof-gps-across-the-country-to-stop-russian-drones-new-scientist/), [Jerusalem Post](https://www.jpost.com/defense-and-tech/article-894907)
- Cao et al., IEEE S&P 2021, *Invisible for both Camera and LiDAR* — [arXiv:2106.09249](https://arxiv.org/abs/2106.09249), [code](https://github.com/ASGuard-UCI/MSF-ADV)
- Hallyburton et al., USENIX Security 2022, *frustum attack* — [USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton), [arXiv:2106.07098](https://arxiv.org/abs/2106.07098)
- SoK on sensor spoofing of robotic vehicles — [arXiv:2205.04662](https://arxiv.org/abs/2205.04662)
- Kraskov–Stögbauer–Grassberger 2004 — [Phys. Rev. E 69, 066138](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.69.066138)
- Williams–Beer 2010 — [arXiv:1004.2515](https://arxiv.org/abs/1004.2515)
- Makkeh–Gutknecht–Wibral 2021 — [Phys. Rev. E 103, 032149](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.103.032149)
