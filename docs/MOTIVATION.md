# Why Galadriel exists

Galadriel addresses a documented problem.
Sensor spoofing of autonomous and counter-unmanned-aircraft systems is a demonstrated, current, and high-stakes threat.
Multi-sensor fusion is a standard defense against this threat.
Attacks that create false cross-sensor agreement can defeat that defense.
Cross-sensor consistency checking is a recognized countermeasure.
Galadriel implements that type of check.

This document presents the supporting evidence and cites its sources.
It also states where Galadriel can and cannot help.

> **Evidence status after the 2026-07 audit.** The citations motivate the research question.
> They do not validate this implementation.
> Galadriel's current detector evidence is synthetic.
> The bundled Crebain capture proves parsing and baseline smoke behavior only.
> It contains native research fields but no attested common projection.
> Its modalities use mixed residual frames, and its sequential updates do not share a frozen prior.
>
> Gating also censors misses.
> The fixture's cross-channel result is `InsufficientEvidence`.
> The retained historical opt-in producer fixture does not qualify a current reciprocal integration.
> No accepted recorded study exists.

## 1. The threat is real and current

Researchers have demonstrated attacks against unmanned aerial vehicle (UAV) navigation.
In June 2012, a University of Texas at Austin team demonstrated one attack.
Todd Humphreys led the team at the invitation of the United States Department of Homeland Security.
The test occurred at the White Sands, New Mexico missile range.

The team attacked a Global Positioning System (GPS) guided UAV from a half-mile distance.
It used a purpose-built civil-GPS spoofer.
The spoof caused the UAV to dive toward the ground.
The equipment cost was approximately $1,000.
See [GPS World, “Drone Hack”](https://www.gpsworld.com/drone-hack/) and [Humphreys' congressional testimony](https://rnl.ae.utexas.edu/images/stories/files/papers/Testimony-Humphreys.pdf).

By 2022, Global Navigation Satellite System (GNSS) spoofing and jamming affected a theater-wide area.
Navigation-signal denial and deception have been continuous and area-wide in the war in Ukraine since 2022.
Ukraine has deployed networked electronic-warfare systems such as *Pokrova*.
These systems spoof satellite navigation for incoming UAVs and cause them to deviate or fall.

Sources include [Defense One, 2024](https://www.defenseone.com/technology/2024/09/group-ukraine-testing-newest-weapon-against-gps-jammers-cell-phones/399952/), [The Record](https://therecord.media/ukraine-anti-drone-gps-spoofing-affects-civilian-mobile-phones), and [RNTF/New Scientist](https://rntfnd.org/2024/02/03/ukraine-will-spoof-gps-across-the-country-to-stop-russian-drones-new-scientist/).

The interference also affects areas outside the battlefield.
Poland recorded **thousands** of GNSS interference events in one month.
GNSS disruption near conflict areas is also a recognized civil-aviation safety concern.
See the [Jerusalem Post](https://www.jpost.com/defense-and-tech/article-894907).

An adversary can make a sensor report a plausible false position, bearing, or return.
This capability is current, inexpensive, and militarily significant.
Crebain is the fusion project for counter-unmanned aircraft systems (counter-UAS).
It must tolerate this threat.
Galadriel exists to flag applicable evidence of it.

## 2. Multi-sensor fusion is a standard defense, and attackers can defeat it

Redundancy is the standard mitigation for one false sensor.
A system can combine camera, radar, acoustic direction-of-arrival, lidar, and radio-frequency (RF) modalities.
Then, no single channel can dominate.
Production autonomous systems use this multi-sensor fusion (MSF) design for robustness.

Security research shows that redundancy does not give an unconditional guarantee.
An attacker can create false cross-sensor consistency.

- **Cao et al., “Invisible for both Camera and LiDAR” (IEEE S&P 2021)** presented the first MSF perception security study.
  It created a physical-world adversarial object called `MSF-ADV`.
  The object caused a camera-and-LiDAR fusion stack to miss a front obstacle.
  See [arXiv:2106.09249](https://arxiv.org/abs/2106.09249) and the [source code](https://github.com/ASGuard-UCI/MSF-ADV).
- **Hallyburton et al., “Security Analysis of Camera-LiDAR Fusion” (USENIX Security 2022)** introduced the frustum attack.
  The attack defeats camera-LiDAR fusion.
  It remains “stealthy to existing defenses against LiDAR spoofing as it preserves consistencies between camera and LiDAR semantics.”
  See [USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton) and [arXiv:2106.07098](https://arxiv.org/abs/2106.07098).

This attack class defines the Galadriel boundary.
A consistency detector can identify a spoof that breaks cross-channel agreement.
A statistics-matching false-data injection (FDI) can preserve that agreement and defeat the detector.
The frustum attack demonstrates this class in a research system.

Galadriel does not claim to defeat this attack.
The example identifies a boundary for consistency monitoring.
No current field evidence measures how much Galadriel increases an operational adversary's cost.

## 3. Cross-sensor consistency detection is a recognized countermeasure

Galadriel flags a channel that stops agreeing with a corroborated consensus.
This method is a named defense in the security literature.

Xu et al. systematized sensor-spoofing attacks against multi-sensor robotic vehicles.
See [“SoK: Rethinking Sensor Spoofing Attacks against Robotic Vehicles from a Systematic View,” IEEE EuroS&P 2023](https://arxiv.org/abs/2205.04662).

Cross-sensor consistency checking is a recognized countermeasure.
It identifies a channel that stops agreeing with a corroborated majority.
Broumandan and Lachapelle present a canonical academic example.
They detect GNSS spoofing by checking consistency between a GNSS solution and a self-contained inertial navigation system (INS) or odometer.
Their check uses an observation window.
See [*Sensors* 18(5):1305, 2018](https://www.mdpi.com/1424-8220/18/5/1305).

The MSF attack papers in section 2 also discuss cross-modal plausibility and consistency checks.

Galadriel explores an **N-channel generalization** of this established idea.
It is a tested research implementation, not a field-validated reference detector.
Its consumer contract accepts registered and comparable cross-modal projections.
A retained historical producer fixture exercised that shape.

Current reciprocal integration is `NOT_CLAIMED`.
No accepted recorded field study establishes calibration or detection performance.

## 4. Galadriel's role and specific contribution

Two characteristics distinguish Galadriel from a general consistency check.

### 4.1 It maps method choice to attack classes

The paper gives one central result.
Information-theoretic consistency adds no population information over covariance for a registered linear-Gaussian cross-channel model.
The information-theoretic methods are mutual information and Partial Information Decomposition (MI/PID).

MI/PID becomes a research candidate for a documented nonlinear, joint, or adversarially structured estimand.
Field data must determine whether either regime applies.

- **An ideal linear-Gaussian tracker model** makes MI a monotone transform of correlation.
  In that model, MI/PID adds no population discrimination.
  Correlation is the applicable and less expensive statistic.
  It remains unknown whether recorded counter-UAS innovations fit that model.
  Recorded Crebain data has not established this property.
- **Learned-perception MSF attacks** operate on a nonlinear neural fusion stack.
  Examples include `MSF-ADV` and the frustum attack.
  This regime motivates the research in section 4.2.
  A joint-information measure could, in principle, detect structure that a correlation check on the same feature misses.

Two limits prevent a claim that this escalation defeats those attacks.
First, Galadriel consumes an attested projection of kinematic residuals.
It does not consume the neural fusion feature.
This distinction identifies a possible research target, not a Galadriel result.

Second, the frustum attack preserves cross-sensor consistency by definition.
It defeats each consistency detector, including correlation and MI/PID.
Escalation can help only when nonlinear or synergistic coupling leaves a dependence signature.
A statistics-matching FDI remains the shared blind spot of the detector family.
The paper leaves neural-fusion mapping for future work.

Thus, the disciplined recommendation uses signed correlation by default.
Use PID only as additive and sign-invariant evidence.
Validated geometry and a nonlinear estimand must justify that use.

### 4.2 It states its scope

Galadriel is advisory and sets `calibrated_posterior = false`.
It reports statistical consistency, not truth.
It cannot identify a statistics-matching spoof.
Its evaluation uses a synthetic, non-adaptive study.
Section 6 of the paper states those limits.

The enforcement layer uses cryptographic controls.
These controls include per-plane access control lists (ACLs) and mutual Transport Layer Security (mTLS) on the NCP bus.
A safety governor is also part of that layer.
Galadriel supplies instrumentation above those controls.

## 5. Methodological foundations

The project uses these established methods:

- **Kraskov–Stögbauer–Grassberger (KSG) mutual information.** A. Kraskov, H. Stögbauer, and P. Grassberger, “Estimating mutual information,” *Phys. Rev. E* **69**, 066138 (2004).
  See [APS](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.69.066138).
- **Partial Information Decomposition.** P. L. Williams and R. D. Beer, “Nonnegative Decomposition of Multivariate Information,” 2010.
  See [arXiv:1004.2515](https://arxiv.org/abs/1004.2515).
- **The `I^sx` shared-exclusions redundancy.** A. Makkeh, A. J. Gutknecht, and M. Wibral published the pointwise measure in 2021.
  The method uses a Möbius inversion on the redundancy lattice.
  See [*Phys. Rev. E* **103**, 032149](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.103.032149).

D. A. Ehrlich et al. define the continuous-variable formulation and the k-nearest-neighbor estimator that Galadriel uses.
See [“Partial information decomposition for continuous variables based on shared exclusions,” *Phys. Rev. E* **110**, 014115 (2024)](https://arxiv.org/abs/2311.06373).
Gutknecht, Wibral, and Makkeh define the part-whole and formal-logic foundation.

See [*Proc. R. Soc. A* **477**:20210110 (2021)](https://arxiv.org/abs/2008.09535).

For jointly Gaussian data, covariance fixes the complete decomposition.
A zero-mean Gaussian distribution is completely parameterized by its covariance.
Thus, each PID functional of that distribution is a function of the correlations.
This statement includes the reported `I^sx`.

Barrett proved a more specific measure-collapsing result.
For jointly Gaussian sources and a univariate target, some PID measures reduce to minimum-mutual-information redundancy.
The result applies when redundant and unique atoms depend only on pairwise source-to-target marginals.
It includes I_min, BROJA, and other pre-2015 proposals.

See A. B. Barrett, *Phys. Rev. E* **91**, 052802, 2015, [arXiv:1411.2832](https://arxiv.org/abs/1411.2832).

Venkatesh and Schamberg confirm that reduction for scalar targets.
They show that it does **not** extend to multivariate targets.
See [ISIT 2022](https://arxiv.org/abs/2105.00769).

The reported `I^sx` is outside Barrett's class.
It reads the complete joint distribution and permits negative atoms.
For Gaussian data, its redundancy is a different covariance function than minimum mutual information (MMI).
It is still determined by covariance.
This fact alone does not establish finite-sample estimator equivalence.

Three sources characterize finite-sample KSG behavior.
[Gao, Oh, and Viswanath (IEEE Trans. IT 2018)](https://arxiv.org/abs/1604.03006) describe dimension-dependent bias.
This bias affects the high-dimensional, short-window regime that the geometry gate rejects.
[Gao, Ver Steeg, and Galstyan (AISTATS 2015)](https://arxiv.org/abs/1411.2003) describe underestimation under strong dependence at feasible sample sizes.
[Holmes and Nemenman, PRE 2019](https://arxiv.org/abs/1903.09280) show that the bias sign depends on the regime.

## Sources

- UT Austin and Humphreys 2012 UAV GPS-spoofing demonstration: [GPS World](https://www.gpsworld.com/drone-hack/) and [Humphreys testimony](https://rnl.ae.utexas.edu/images/stories/files/papers/Testimony-Humphreys.pdf)
- Ukraine and counter-UAS electronic warfare: [Defense One](https://www.defenseone.com/technology/2024/09/group-ukraine-testing-newest-weapon-against-gps-jammers-cell-phones/399952/), [The Record](https://therecord.media/ukraine-anti-drone-gps-spoofing-affects-civilian-mobile-phones), [RNTF/New Scientist](https://rntfnd.org/2024/02/03/ukraine-will-spoof-gps-across-the-country-to-stop-russian-drones-new-scientist/), and [Jerusalem Post](https://www.jpost.com/defense-and-tech/article-894907)
- Cao et al., IEEE S&P 2021, *Invisible for both Camera and LiDAR*: [arXiv:2106.09249](https://arxiv.org/abs/2106.09249) and [code](https://github.com/ASGuard-UCI/MSF-ADV)
- Hallyburton et al., USENIX Security 2022, *frustum attack*: [USENIX](https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton) and [arXiv:2106.07098](https://arxiv.org/abs/2106.07098)
- Xu et al., “SoK: Rethinking Sensor Spoofing Attacks against Robotic Vehicles from a Systematic View,” IEEE EuroS&P 2023: [arXiv:2205.04662](https://arxiv.org/abs/2205.04662)
- Kraskov–Stögbauer–Grassberger 2004: [Phys. Rev. E 69, 066138](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.69.066138)
- Williams–Beer 2010: [arXiv:1004.2515](https://arxiv.org/abs/1004.2515)
- Makkeh–Gutknecht–Wibral 2021: [Phys. Rev. E 103, 032149](https://journals.aps.org/pre/abstract/10.1103/PhysRevE.103.032149)
