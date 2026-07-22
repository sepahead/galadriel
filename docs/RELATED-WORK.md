# Related work and comparison methods

## Abbreviations

| Short form | Meaning |
|---|---|
| ACM | Association for Computing Machinery |
| AS | anti-spoofing |
| CAVs | connected and automated vehicles |
| CCS | Conference on Computer and Communications Security |
| CPS | cyber-physical systems |
| `et al.` | and others |
| EuroS&P | European Symposium on Security and Privacy |
| FAR | false-alarm rate |
| FDI | false-data injection |
| GPS | Global Positioning System |
| IEEE | Institute of Electrical and Electronics Engineers |
| ION | Institute of Navigation |
| J. Inst. | Journal of the Institute |
| KSG | Kraskov-Stögbauer-Grassberger |
| LiDAR | light detection and ranging |
| MDPI | Multidisciplinary Digital Publishing Institute |
| NCP | Neuro-Cybernetic Protocol |
| PDF | Portable Document Format |
| pp. | pages |
| RANSAC | random sample consensus |
| S&P | Symposium on Security and Privacy |
| TAC | Transactions on Automatic Control |
| TCNS | Transactions on Control of Network Systems |
| Trans. | Transactions |

Galadriel's Mirror is one detector in a large and layered field.
Spoof and fault detection for multi-sensor systems has a fifty-year literature.
Accurate positioning requires clear statements about each alternative.
It also requires a fair comparison method.

This document has five purposes:

1. Section 1 maps detector families to their sensing pipeline layers.
2. Section 2 describes competing and related families, their threat models, strengths, limits, and relation to Galadriel.
3. Section 3 compares the families across applicable dimensions.
4. Section 4 defines a benchmark method with common axes, attacks, operating points, and metrics.
5. Section 5 distinguishes competing methods from complementary methods.

The Galadriel synthetic harness implements part of the proposed benchmark.
See [`EVALUATION.md`](EVALUATION.md).
A cross-approach benchmark still needs the other parts.

This document complements the research argument in [`PAPER.md`](PAPER.md).
It also complements the threat evidence in [`MOTIVATION.md`](MOTIVATION.md).

> **Evidence status after the 2026-07 audit.** This document is a taxonomy and comparison proposal.
> It is not a deployment ranking.
> Galadriel's current performance evidence is synthetic.
> The bundled historical Crebain output lacks comparable cross-modal residuals.
> It lacks a common frame and common frozen prior.
> Association and gating cause selection bias.
>
> The output proves parsing and baseline smoke behavior only.
> A retained historical opt-in producer revision implemented the contract shape.
> It does not qualify a current reciprocal integration.
> No accepted field or calibration result exists.

## 1. Detection layers

Each spoof or fault detector observes one layer of the sensing-to-state pipeline.
This choice determines the required data and the visible attacks.
It also determines structural blind spots.
An attack at a different layer can be unobservable.
Tuning cannot correct an observability problem.

| Layer | Observed data | Example detectors | Distinct visibility |
|---|---|---|---|
| **L0 · Signal or radio frequency (RF)** | Raw in-phase and quadrature data, carrier power, automatic gain control, carrier-to-noise ratio, angle of arrival, Doppler | Global Navigation Satellite System (GNSS) power or automatic gain control (AGC) monitoring, multi-antenna direction of arrival, spreading-code authentication | An external transmitter before receiver capture. Single-source geometry. |
| **L1 · Measurement** | Pseudoranges, detections, ranges, bearings | Receiver Autonomous Integrity Monitoring (RAIM) pseudorange residuals, cryptographic Open Service Navigation Message Authentication (OSNMA) | Redundancy in one modality. Forged versus authentic message content. |
| **L2 · Innovation or residual** | Per-channel filter innovations, Normalized Innovation Squared (NIS), cross-channel residual dependence | Innovation chi-square or cumulative sum (CUSUM) gating, **Galadriel**, GNSS and inertial navigation system (INS) coupling | A channel that no longer agrees with a corroborated consensus. |
| **L3 · State estimate** | The fused state and its error-correcting structure | Secure or resilient state estimation, Byzantine-robust fusion | Provable state recovery under a bounded corruption budget. |
| **L4 · Perception feature** | Neural fusion features, object semantics, occupancy semantics | Cross-modal plausibility and temporal-consistency checks for multi-sensor fusion (MSF) autonomous vehicles | Nonlinear and synergistic cross-modal structure used by a learned stack. |

Galadriel operates across modalities at L2.
It reads NIS and an optional producer-attested common residual projection.
It does not need raw RF or training data.
It tests whether channels still agree.
It never compares modality-native innovations directly.

This method requires a producer contract.
The producer must supply one track, exact sequence alignment, and matching frame and context identifiers.
It must supply one common frozen-prior identifier for each sequence.
It must also supply explicit lifecycle and missingness information.

The central result in `PAPER.md` section 4 selects a dependence statistic at this layer.
The default uses a low-cost correlation check.
Mutual information or Partial Information Decomposition (MI/PID) is an escalation.
The coupling must leave the Gaussian manifold to justify that escalation.

One attack can affect several layers.
For example, a GNSS spoof is an L0 RF event.
It can also be an L1 pseudorange fault and an L2 innovation anomaly.
Thus, a layered defense is more applicable than one detector.
Section 5 describes this structure.

## 2. Competing and related methods

Each subsection states the method, layer, threat model, limit, and relation to Galadriel.

### 2.1 Signal-level GNSS anti-spoofing at L0

**Method.** Receiver-side checks observe the physical signal.
They include received-power and automatic gain control (AGC) monitoring.
They also include carrier-to-noise ratio (C/N₀) anomalies and direction of arrival (DOA).
DOA systems use an antenna array or rotating antenna.
Authentic satellites arrive from many directions, while one spoofer arrives from one direction.
Other checks use Doppler and clock consistency.

See [*A Survey of GNSS Spoofing and Anti-Spoofing Technology*, Remote Sensing 14(19):4826, 2022](https://www.mdpi.com/2072-4292/14/19/4826).
Also see [spatial-processing detection, NAVIGATION 68(2):243](https://navi.ion.org/content/68/2/243).

**Threat model.** The attacker is an external transmitter that injects counterfeit RF.
DOA methods are among the most effective methods because they do not need key infrastructure.

**Limit.** Power and AGC methods operate mainly during initial capture.
They can miss a spoofer after smooth tracking-loop takeover.
DOA requires more antenna hardware.
All these methods are GNSS-specific.
They do not identify a false non-RF modality, such as radar or acoustic bearing.

**Relation to Galadriel.** These methods use L0, while Galadriel uses L2.
They also have a narrower modality scope.
A signal-level GNSS defense can stop an external RF spoof before residual generation.
Galadriel can flag some insider or post-capture inconsistencies that an L0 check cannot observe.
Neither method gives a guarantee outside its assumptions.

### 2.2 Cryptographic authentication at L0 or L1

**Method.** Cryptography makes forgery difficult instead of detecting it statistically.
Galileo Open Service Navigation Message Authentication (OSNMA) authenticates the navigation message.
It uses data that an attacker cannot predict.
Spreading-code authentication protects the ranging code.
On the fusion bus, per-node mutual Transport Layer Security (mTLS) or signed messages authenticate sensor identity.
See the [2022 survey](https://www.mdpi.com/2072-4292/14/19/4826).

**Threat model.** The attacker is an external party that cannot produce valid signatures or keys.

**Limit.** Authentication identifies the sender.
It does not establish that the content is true.
A compromised sensor can have a valid key and send false data.
Each signature check will accept the valid identity.
Galadriel can assess inconsistent authenticated content.
A consistency-preserving insider remains outside its scope.

**Relation to Galadriel.** Cryptographic authentication is an enforcement layer.
Galadriel explicitly defers to it in `MOTIVATION.md` section 4.2.
Per-plane access control lists (ACLs) and mTLS on the NCP bus address impersonation.
Galadriel supplies instrumentation for dishonest authenticated content.
The methods are complementary because they address different attacker capabilities.

### 2.3 Receiver Autonomous Integrity Monitoring at L1

Receiver Autonomous Integrity Monitoring (RAIM) is the closest classical analog to Galadriel.

**Method.** Residual-based RAIM forms a sum of squared pseudorange residuals.
It uses this value as a chi-square test statistic and flags inconsistency.
Solution-separation RAIM compares full-set and subset position solutions.
Both methods then use fault detection and exclusion (FDE) to identify and remove the faulty satellite.

See [Parkinson and Axelrad, “Autonomous GPS Integrity Monitoring Using the Pseudorange Residual,” *NAVIGATION* 35(2):255–274, 1988](https://www.ion.org/publications/abstract.cfm?articleID=100323).
See the [2025 GNSS RAIM survey](https://www.frontiersin.org/journals/physics/articles/10.3389/fphy.2025.1567301/full).
See the [modified residual-based RAIM extension, *Sensors* 2020](https://pmc.ncbi.nlm.nih.gov/articles/PMC7570696/).

**Threat model.** Classical RAIM assumes one faulty measurement.
It uses a known geometry matrix and known measurement model.
Extensions cover multiple simultaneous faults and use robust estimators.

**Limit.** RAIM works within one GNSS receiver and modality.
It uses redundancy from multiple satellites.
It requires the linearized observation geometry.
It does not define a heterogeneous cross-sensor check.
Classical single-fault RAIM can invert under a colluding majority.
Galadriel discloses the same structural limit in `PAPER.md` section 2 and `EVALUATION.md` section 5.

**Relation to Galadriel.** Galadriel applies residual consistency and outlier attribution to heterogeneous modalities.
It replaces a shared geometry matrix with a registered statistical-dependence contract.
It uses signed correlation and optional additive MI/PID.
Galadriel is not a strict RAIM superset.
RAIM has model-specific integrity semantics that the Galadriel advisory prototype does not have.

### 2.4 Innovation-based fault and attack detection at L2

**Method.** This is the classical Kalman-filter consistency test.
NIS is a chi-square magnitude statistic.
CUSUM supplies sequential detection for slow drifts.

See [Bar-Shalom, Li, and Kirubarajan, *Estimation with Applications to Tracking and Navigation*, 2001](https://www.wiley.com/en-us/Estimation+with+Applications+to+Tracking+and+Navigation-p-9780471221272).
See [Page, “Continuous inspection schemes,” *Biometrika* 41, 1954](https://doi.org/10.1093/biomet/41.1-2.100).

**Threat model.** A channel has innovation magnitude that increases beyond noise.

**Limit.** This test uses one channel and its magnitude.
A moment-matched spoof has the same variance but different dependence.
It can pass the test.
This blind spot motivates the Galadriel cross-channel layer.

**Relation to Galadriel.** This method is the `galadriel-core` magnitude baseline.
It is also the comparison floor for the synthetic harness.
Galadriel preserves this evidence.
It adds a separate signed cross-sensor assessment.

### 2.5 Cross-sensor or cross-modal consistency at L2 or L4

**Method.** This method compares an untrusted channel with a corroborated consensus.
An established example combines GNSS, an inertial navigation system (INS), and an odometer.
It checks the satellite solution against a self-contained INS or odometer over an observation window.
See [Broumandan and Lachapelle, *Sensors* 18(5):1305, 2018](https://www.mdpi.com/1424-8220/18/5/1305).

At L4, research systematizes spoof attacks against multi-sensor systems.
See [Xu et al., IEEE EuroS&P 2023](https://arxiv.org/abs/2205.04662).
Cross-modal plausibility and temporal-consistency checks accompany MSF perception defenses.
See [Cao et al., IEEE S&P 2021](https://arxiv.org/abs/2106.09249) and [Hallyburton et al., USENIX Security 2022](https://arxiv.org/abs/2106.07098).

**Threat model.** A minority of channels stops agreeing with the physical world observed by the other channels.

**Limit.** A statistics-matching FDI preserves cross-sensor consistency and defeats this method.
The frustum attack has this property.
It is “stealthy to existing defenses against LiDAR spoofing as it preserves consistencies between camera and LiDAR semantics” [Hallyburton2022].
This is the disclosed Galadriel limit in `PAPER.md` sections 2 and 7.
The limit includes a current state-of-the-art attack.

**Relation to Galadriel.** This is the Galadriel detector family.
Galadriel generalizes Broumandan's pairwise GNSS and INS check to an $N$-channel test.
It asks whether an information-theoretic statistic is forced or justified.
It also supplies advisory per-channel attribution instead of one accept or reject result.
It does not need a training set.
It does require strong producer geometry and timing contracts.

This family is genuinely competing prior art.
Galadriel differs in selection discipline and attribution, not in the basic consistency concept.

### 2.6 Secure or resilient state estimation at L3

**Method.** These methods reconstruct the true state with a bounded number of arbitrarily corrupted sensors.
They use error correction over real numbers or a compressed-sensing formulation.

See [Fawzi, Tabuada, and Diggavi, “Secure Estimation and Control for CPS under Adversarial Attacks,” IEEE TAC 59(6), 2014](https://arxiv.org/abs/1205.5073).
Mishra et al., IEEE TCNS 2017, describe a noisy extension.
See [Byzantine-Resilient Distributed Observers, 2018](https://arxiv.org/abs/1802.09651) for distributed observers.

**Threat model.** At most *p* of *2p+1* sensors are adversarial.
The method requires a known linear time-invariant (LTI) dynamics model.
It also requires an observability and redundancy condition.

**Limit.** The method needs a system model and satisfied redundancy bounds.
It estimates through the attack instead of flagging it.
Thus, it gives weaker attribution or operator information.
The method also has an honest-majority limit.
Its guarantee does not apply when more than *p* sensors are corrupt.

**Relation to Galadriel.** Resilient estimation gives a stronger guarantee with stronger assumptions.
It can provably recover state when a validated LTI model and corruption bound apply.
That result is stronger than a Galadriel advisory flag.

Galadriel can apply when the model assumptions do not apply.
Examples include heterogeneous modalities or absence of a clean dynamics model.
It can also apply when an operator needs attribution instead of silent correction.
Its residual-registration contract must still hold.
The two methods are complementary along the guarantee and assumption trade-off.
A resilient estimator is a natural L3 partner for the Galadriel L2 flag.

### 2.7 Byzantine-robust or redundancy-voting fusion at L3

**Method.** These methods protect the estimate from a corrupted minority.
Examples include median, trimmed-mean, RANSAC, weighted-majority, and robust M-estimator fusion.
See [*A Secure Sensor Fusion Framework for CAVs under Sensor Attacks*, 2021](https://arxiv.org/abs/2103.00883).

**Threat model.** A minority of channels produces outliers.

**Limit.** Robust fusion masks the attack to protect the estimate.
It does not always expose the attack.
Thus, an operator might not learn that a sensor was compromised.
A colluding majority also defeats the vote.

**Relation to Galadriel.** Robust fusion supplies robustness by design.
Galadriel detects and attributes applicable evidence.
Robust fusion can maintain the estimate during an attack.
Galadriel can identify a channel and describe the evidence.
The methods can combine cleanly.
Robust fusion supports continuity, while Galadriel supports awareness and forensics.

### 2.8 Learning-based anomaly detection at L2 or L4

**Method.** Methods include autoencoders, long short-term memory (LSTM) predictors, and one-class support vector machines.
They use sensor streams.
Other methods classify jamming, spoofing, and meaconing from multi-sensor features.
See [*Detection and Mitigation of Jamming, Meaconing, and Spoofing based on Machine Learning and Multi-Sensor Data*, 2025](https://anavs.com/wp-content/uploads/2025/10/Detection_and_Mitigation_of_Jamming_Meaconing_and_Spoofing_based_on_Machine_Learning_and_Multi_Sensor_Data.pdf).

**Threat model.** An anomaly differs from a learned normal pattern.
The anomaly can be nonlinear.

**Limit.** The method requires representative training data.
Distribution shift can reduce its performance.
Safety-critical certification is difficult.
Attribution and interpretation are typically weak.

**Relation to Galadriel.** This method overlaps the nonlinear-dependence question in `PAPER.md` section 5.
The current Galadriel runtime verdict uses geometry-gated pairwise KSG-MI.
Its PID atoms are diagnostic.
They do not implement a pure-synergy classifier.
Galadriel does not need training data.
This fact does not imply broader capacity or field validity than a trained model.

### 2.9 Active challenge-response or physical probing at L0

**Method.** This method actively perturbs a physical channel.
It uses a randomized challenge that an attacker cannot predict.
The system then verifies the response.
Physical Challenge-Response Authentication for active sensors (PyCRA) is one example.
See [Shoukry et al., “PyCRA,” ACM CCS 2015](https://dl.acm.org/doi/10.1145/2810103.2813679).

**Threat model.** The attacker spoofs an active radar, lidar, or ultrasonic sensor.
The attacker cannot respond correctly to an unpredictable probe.

**Limit.** The method requires actuation authority over the sensor.
It applies only to active sensors.
It adds emissions and complexity.
It does not protect passive modalities.

**Relation to Galadriel.** PyCRA changes physical interrogation to identify spoofing at the source.
Galadriel passively observes residuals that another component produced.
The methods can combine when actuation is available.

## 3. Direct comparison

Table A summarizes the field.
An insider is a compromised but authenticated sensor that sends false data.
An external attacker is an unauthenticated injector.

| Approach | Layer | Modality scope | Primary threat | Guarantee | Key assumptions | Extra cost or hardware |
|---|---|---|---|---|---|---|
| Signal-level GNSS, section 2.1 | L0 | GNSS only | External RF spoof | Detect before capture | RF front-end access. Array for DOA. | Antenna array or rotating antenna |
| Cryptographic authentication or OSNMA, section 2.2 | L0/L1 | Per signal or node | External forgery | **Prevent** impersonation | Key infrastructure | Key management |
| RAIM, section 2.3 | L1 | GNSS, one modality | Faulty or spoofed satellite | Detect and exclude | Known geometry and measurement model | Compute only |
| Innovation NIS/CUSUM, section 2.4 | L2 | Per channel | Magnitude fault | Detect | Filter innovations available | Negligible |
| **Cross-sensor consistency and Galadriel, section 2.5** | **L2** | **N heterogeneous channels** | **Insider that breaks agreement** | **Detect and attribute, advisory** | **Comparable innovations. Unique strict majority.** | **Low for correlation. Higher for PID and benchmark-dependent.** |
| Resilient state estimation, section 2.6 | L3 | N modeled channels | At most p corrupted sensors | **Recover state**, provable | Known LTI model and redundancy bound | Optimization compute |
| Byzantine-robust fusion, section 2.7 | L3 | N channels | Corrupted minority | **Tolerate** by masking | Honest majority | Negligible |
| Learning-based, section 2.8 | L2/L4 | N channels | Learned-normal anomaly | Detect statistically | Representative training data | Training and inference |
| Challenge-response or PyCRA, section 2.9 | L0 | Active sensors | Active-sensor spoof | Detect at source | Actuation authority | Probe emissions |

Table B compares the two attacks that define the Galadriel scope.
The moment-matched insider spoof is the Galadriel target.
The statistics-matching FDI is the disclosed blind spot.
A partial or negative result identifies the observation layer.
It is not a general criticism of the method.

| Approach | Detects the moment-matched insider spoof? | Detects the statistics-matching FDI? | Detects the external RF spoof? |
|---|---|---|---|
| Signal-level GNSS | ✗ after capture | ✗ | **✓** |
| Cryptographic authentication or OSNMA | ✗ with a valid key | ✗ | **✓** for an external forger |
| RAIM | Partial, GNSS-only and single-fault | ✗ | ✓ as a pseudorange fault |
| Innovation NIS/CUSUM | ✗ when moment-matched | ✗ | Partial when loud |
| **Galadriel** | **Synthetic only. Recorded validation is pending.** | **✗, disclosed limit** | ✗ because it is not at L0 |
| Resilient state estimation | ✓ when the model and budget apply | Partial when it changes state | ✓ as a bad measurement |
| Byzantine-robust fusion | Masks the attack and does not expose it | Masks it when it is a minority | Masks it when it is a minority |
| Learning-based | Partial when it differs from training normal | Partial when it is off-manifold | Partial |
| Challenge-response | ✗ for a passive-data insider | ✗ | ✓ for an active-sensor source |

No single row covers all three attack columns.
A system must combine applicable rows.

## 4. Benchmark method

Methods at different layers require a careful comparison.
They observe different data, assume different infrastructure, and offer different types of guarantees.
A credible cross-approach benchmark needs these elements.

The Galadriel synthetic harness covers part of this design within the L2 consistency family.
See `docs/EVALUATION.md` and `crates/galadriel-eval`.
A broader benchmark must implement the remaining elements.

### 4.1 Comparison axes

Report each method on these axes:

1. **Accuracy.** Report receiver operating characteristic area under the curve (ROC-AUC) and detection rate with confidence intervals.
2. **Latency.** Report frames or seconds from attack onset to detection.
3. **Compute cost.** Report wall-clock time or floating-point operations relative to the least expensive baseline.
   Also report scaling with window length and channel count.
4. **Adaptive robustness.** Test an adversary that knows the detector and stays near its threshold.
   This is a Kerckhoffs-aware adversary.
5. **Attribution.** State whether the method identifies a channel or only identifies a general fault.
6. **Assumptions.** Report each prerequisite as an output.
   Examples include model, geometry, training data, honest majority, key infrastructure, and actuation authority.

Accuracy and latency alone do not make a sufficient comparison.
Equal AUC does not make methods equivalent when their assumptions differ.
One can require a validated dynamics model.
Another can require a common-frame and common-prior residual contract.

The Galadriel harness includes accuracy, latency, cost, adaptive, non-stationary, and attribution experiments.
No complete post-audit comparative report exists for the revised detector.
The published streaming artifact is a narrower vertical slice.
Its synthetic injected-bias proxy does not measure downstream state displacement.

### 4.2 Shared attack ontology

Run each method against the same applicable attack suite.
Tag each attack with its affected layers.
This rule prevents an unfair score for a method that cannot observe an attack at its layer.

The Galadriel suite is a reusable starting point:

| Attack | Affected layers | Purpose |
|---|---|---|
| Loud bias spoof | L1/L2 | Magnitude sensitivity, which is the NIS baseline's applicable case |
| Broadband jam | L0/L2 | Correlated all-channel denial and localized-versus-broad degradation evidence |
| **Moment-matched stealthy spoof** | L2 | The reason for a consistency detector |
| Colluding 2-of-3 majority | L2/L3 | Structural honest-majority failure |
| Adaptive threshold-hugging | L2 | Kerckhoffs-aware evasion ceiling at matched FAR |
| Non-stationary maneuver | L2 | False-alarm robustness to benign dynamics |
| Statistics-matching FDI, frustum class | L2/L4 | The disclosed shared blind spot of consistency methods |

A cross-approach benchmark must add L0 and L1 attacks.
Examples include RF power takeover, a single-source DOA, and a forged unauthenticated message.
These attacks give signal-level and cryptographic methods applicable tests.
The report must identify the in-scope attacks for each method and layer.

### 4.3 Matched operating point

Raw ROC comparison can be misleading.
Different detectors can have different score distributions.
Do not compare them at one arbitrary threshold.

A fair comparison fixes a common false-alarm rate (FAR).
It then measures detection or the adversary's evasion ceiling at that point.
The Galadriel synthetic harness includes this design.
No complete post-audit comparative results exist for the revised detector.
The published streaming artifact does not answer this comparison.
Each cross-approach table must use the same operating-point rule.

Otherwise, it compares thresholds instead of detectors.

### 4.4 Exact metrics

- **Detection.** Use AUC with Mann-Whitney ranking and ties equal to 0.5.
  Use a paired interval for the AUC difference when two detectors use the same scenarios.
  Parameter-grid claims also require multiplicity control.
- **Rates.** Report detection, false-alarm, error, and inconclusive fractions with intervals.
- **Latency.** Measure time from onset to detection.
  Exclude and separately report pre-onset alarms.
- **Cost.** Report cost relative to the least expensive baseline.
  Include a scaling curve for window and channel count.
- **Adaptive robustness.** Report the maximum undetected attack strength at the matched FAR.
- **Attacker success.** Report downstream state displacement, not only synthetic injected bias.

### 4.5 Current harness scope

The harness provides these research functions within the L2 family:

- shared synthetic scenarios with known labels
- a matched-operating-point design
- paired bootstrap utilities
- reproducible `cargo` commands for accuracy, latency, and cost experiments

The broader suite still needs regenerated exact results after the audit.
`post-audit-v1` covers a separate streaming vertical slice.

A complete cross-approach benchmark still needs:

1. **Multi-layer data.** One scenario must emit L0 RF or in-phase and quadrature data.
   It must also emit L1 measurements and L2 innovations.
   Then signal-level, RAIM, and consistency detectors can use one ground truth.
2. **Recorded traces.** The Galadriel study uses controlled simulator models.
   A deployment ranking requires field data.
3. **Assumption accounting.** A standard result must list each method's prerequisites.
   It must not treat a model-light advisory flag and model-based provable recovery as the same question.

The current harness is useful synthetic scaffolding within its family and layer.
It is not a rigorous cross-family or recorded-data benchmark.

### 4.6 Comparison pitfalls

- **Layer mismatch.** Do not score an L0 detector on an L2-only attack.
  Tag attacks by layer.
- **Unmatched thresholds.** Do not compare AUC-optimal points from different score distributions.
  Fix the FAR.
- **Hidden assumptions.** Report each required model, training set, antenna, frame, and prior contract.
  Treat assumptions as a result.
- **Omitted shared limit.** Each consistency method can fail against a statistics-matching FDI.
  A benchmark that omits this attack favors the complete family.

## 5. Competing and complementary methods

Most methods in this survey occupy different layers.
They address different attacker capabilities.
This stack shows the relationship:

```
  L0  RF/signal      →  signal-level GNSS AS  +  crypto/OSNMA  +  PyCRA (active probing)
  L1  measurement    →  RAIM (intra-GNSS FDE)  +  message authentication
  L2  residual       →  innovation NIS/CUSUM  ⊕  GALADRIEL (cross-sensor consistency + attribution)
  L3  state          →  resilient estimation (recover)  +  Byzantine-robust fusion (tolerate)
  L4  perception     →  cross-modal plausibility / temporal-consistency checks
  ——  enforcement    →  per-plane ACL / mTLS on the NCP bus  +  safety governor
```

An attacker can pass L0 signal checks and hold a valid L1 key.
The attacker must still keep a compromised sensor's residuals consistent with other channels to pass L2.
Galadriel raises that requirement.

A frustum-class statistics-matching FDI can preserve this consistency.
It defeats the L2 and L4 consistency family.
Thus, cryptographic identity and a safety governor remain the enforcement backstop.
Galadriel remains advisory instrumentation.
See `MOTIVATION.md` section 4.2.

Galadriel directly competes with these methods:

- **Other cross-sensor consistency detectors in section 2.5.** They use the same family and layer.
  Galadriel uses signed correlation by default.
  It uses additive MI/PID only for a validated nonlinear estimand.
  It also supplies per-channel attribution.
  It does not need training data, but it still needs producer assumptions.
- **Learning-based anomaly detectors in section 2.8.** They overlap in the nonlinear regime.
  Galadriel supplies training-free pairwise-MI evidence and diagnostic PID atoms.
  This difference does not establish a field-performance advantage.
- **Classical single-modality RAIM in section 2.3.** RAIM is a conceptual ancestor.
  Galadriel explores a multi-modality residual-consistency principle.
  It does not inherit the RAIM integrity guarantee.

Galadriel complements signal-level GNSS and cryptographic authentication.
It also complements resilient state estimation, Byzantine-robust fusion, and active challenge-response.
A system can combine these methods.
This taxonomy is not a deployment ranking.

## References for this document

Most sources appear inline.
[`PAPER.md` references](PAPER.md#references) defines the shared key [Hallyburton2022].
This document also defines these references:

- **[ParkinsonAxelrad1988]** B. W. Parkinson, P. Axelrad. “Autonomous GPS Integrity Monitoring Using the Pseudorange Residual.” *NAVIGATION* **35**(2):255–274, 1988. [ION](https://www.ion.org/publications/abstract.cfm?articleID=100323).
- **[RAIMsurvey2025]** “A survey of GNSS receiver autonomous integrity monitoring: research status and opportunities.” *Frontiers in Physics,* 2025. [Link](https://www.frontiersin.org/journals/physics/articles/10.3389/fphy.2025.1567301/full).
- **[GNSSspoofSurvey2022]** “A Survey of GNSS Spoofing and Anti-Spoofing Technology.” *Remote Sensing* **14**(19):4826, 2022. [MDPI](https://www.mdpi.com/2072-4292/14/19/4826).
- **[SpatialProcessing2021]** “GNSS spoofing detection through spatial processing.” *NAVIGATION: J. Inst. Navigation* **68**(2):243, 2021. [Link](https://navi.ion.org/content/68/2/243).
- **[Fawzi2014]** H. Fawzi, P. Tabuada, S. Diggavi. “Secure Estimation and Control for Cyber-Physical Systems Under Adversarial Attacks.” *IEEE Trans. Automatic Control* **59**(6):1454–1467, 2014. [arXiv:1205.5073](https://arxiv.org/abs/1205.5073).
- **[Mishra2017]** S. Mishra, Y. Shoukry, N. Karamchandani, S. Diggavi, P. Tabuada. “Secure State Estimation Against Sensor Attacks in the Presence of Noise.” *IEEE Trans. Control of Network Systems,* 2017.
- **[ByzantineObservers2018]** “Byzantine-Resilient Distributed Observers for LTI Systems.” 2018. [arXiv:1802.09651](https://arxiv.org/abs/1802.09651).
- **[SecureFusionCAV2021]** “A Secure Sensor Fusion Framework for Connected and Automated Vehicles Under Sensor Attacks.” 2021. [arXiv:2103.00883](https://arxiv.org/abs/2103.00883).
- **[Shoukry2015]** Y. Shoukry, P. Martin, Y. Yona, S. N. Diggavi, M. B. Srivastava. “PyCRA: Physical Challenge-Response Authentication For Active Sensors Under Spoofing Attacks.” *ACM CCS,* pp. 1004–1015, 2015. [ACM](https://dl.acm.org/doi/10.1145/2810103.2813679).
- **[MLspoof2025]** “Detection and Mitigation of Jamming, Meaconing, and Spoofing based on Machine Learning and Multi-Sensor Data.” 2025. [PDF](https://anavs.com/wp-content/uploads/2025/10/Detection_and_Mitigation_of_Jamming_Meaconing_and_Spoofing_based_on_Machine_Learning_and_Multi_Sensor_Data.pdf).
