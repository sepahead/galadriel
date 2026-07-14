# Forced or Justified? Mutual Information vs. Correlation for Cross-Sensor Spoof Detection

## Abstract

Cross-sensor consistency can expose a compromised sensor that stops agreeing with an
honest majority, but the statistic chosen for that comparison matters. For jointly
Gaussian scalar variables, mutual information is a monotone function of correlation
magnitude, so a nonparametric MI estimator adds cost and finite-sample uncertainty without
adding population information. Nonlinear and synergistic dependence can justify MI or
Partial Information Decomposition (PID), but only when the deployed data and target define
that estimand.

Galadriel is a pre-1.0 research implementation of this selection discipline. Its default
combines per-channel NIS/CUSUM magnitude evidence with signed, family-wise-significant
cross-channel correlation and unique strict-majority consensus. An optional path adds
sign-invariant KSG-MI and shared-exclusions PID evidence. Invalid input returns an error;
missing or geometrically insufficient evidence remains inconclusive.

The implementation has synthetic tests and studies, not field validation. A 2026-07 audit
found that the available historical Crebain captures do not support the cross-modal
estimand: they omit the producer-attested common projection, mix native coordinate frames,
use sequential priors, and censor rejected measurements. The bundled fixture therefore
proves parsing and baseline smoke behavior; its cross-channel and fused result is correctly
`InsufficientEvidence`. A retained historical opt-in Crebain revision implemented the
required frozen-prior, Cartesian, lifecycle-complete producer shape, but it does not qualify
a current reciprocal integration and no accepted recorded study exists.

## 1. Problem statement

A tracker receives measurements from several modalities. For modality `c` and frame `t`,
let an innovation be

\[
y_{c,t} = z_{c,t} - h_c(\hat{x}^{-}_t),
\]

with innovation covariance `S`. Under a valid filter model, the Normalized Innovation
Squared

\[
\mathrm{NIS}_{c,t}=y_{c,t}^{\mathsf T}S_{c,t}^{-1}y_{c,t}
\]

has a chi-square reference with the stated degrees of freedom [BarShalom2001]. NIS is a
per-channel magnitude statistic. A moment-matched dependence change can preserve that
marginal while changing how modalities relate to each other.

Cross-channel dependence is not computed from `y` directly. The producer must also attest
a common signed projection

\[
r_{c,t}=g_{c,f,k}(z_{c,t})-\pi_{f,k}(\hat{x}^{-}_{p,t}),
\]

where `g` maps that modality's measurement into the registered common Cartesian frame and
`π` maps the frozen predicted track state into the same frame, axes, and units. This ordering
is material for nonlinear sensors: a polar radar measurement is Cartesianized before the
common-frame subtraction; Galadriel does not subtract mixed-unit native coordinates and then
project the result. Every modality at sequence `t` shares physical-frame identifier `f`,
projection/calibration-context identifier `k`, and frozen-prior identifier `p`. The wire
field is a fixed three-value buffer with an explicit active dimension. Galadriel rejects
contradictory provenance, rejects reuse of one prior identifier at another sequence, and
never substitutes modality-native innovations when this projection is absent.

The defender's question is not merely "can dependence be measured?" It is:

1. What physical/statistical quantity is shared across modalities?
2. Are observations comparable at the same track, frame, coordinate system, and prior?
3. What is the cheapest statistic that observes the expected relation?
4. When is there enough coherent evidence to attribute an outlier?
5. What outcome represents invalid or insufficient evidence?

Galadriel answers the last question fail-closed: errors are errors, and absent evidence is
not nominal evidence.

## 2. Threat model

The attribution model assumes a unique strict majority of mutually corroborating channels.
It can identify a minority that decouples from that majority. It does not establish why
the channel decoupled and does not recover the true state.

In scope:

- a per-channel magnitude shift;
- a common-mode magnitude inflation;
- a minority dependence change that breaks a valid positive consensus;
- synthetic nonlinear/synergistic regimes used to study optional MI/PID evidence.

Out of scope:

- a consistency-preserving attacker;
- a colluding majority or ambiguous clique;
- truth/authenticity, cryptographic identity, or state recovery;
- a silent control-path veto;
- all-modal silence without an external heartbeat.

The frustum attack [Hallyburton2022] is a concrete consistency-preserving attack. Its
existence is not a corner case to tune away; it defines a fundamental boundary of this
detector family.

## 3. Required producer contract

Cross-channel residual comparison is meaningful only when all samples refer to:

- one track and exact sequence;
- one documented coordinate frame;
- one common frozen pre-update prior;
- compatible dimensions and covariance semantics;
- an explicit observation lifecycle, including misses and rejections;
- a stable session and schema version.

Historical/default `CREBAIN_PID_JSONL` output violates several of these requirements.
Radar's EKF innovation is polar while visual/acoustic residuals are Cartesian. Updates
occur sequentially, and the stream contains only associated, accepted, successfully
applied updates. A conforming separately gated operational producer must fix the evidence
boundary by snapshotting the immutable predicted state before association, computing
registered Cartesian projections, and reporting misses/rejections on the monitor route.

`PidObservation::consistency_projection` represents the consumer-side contract, but the
available historical Crebain captures do not populate it. Their native innovation fields therefore
remain baseline diagnostics only and produce no cross-channel columns.

Consequently, the bundled Crebain data may be used for bounded parsing and cautious NIS smoke
checks, but not as evidence that production cross-modal correlation or PID works.

## 4. Method

### 4.1 Validated magnitude evidence

The streaming `Mirror` owns bounded state per track and modality. It rejects invalid or
non-finite observations, non-increasing sequence numbers, changed degrees of freedom, and
configuration outside documented domains. NIS windows and CUSUM evidence are assessed only
for configured, fresh modalities. The assessment-level significance budget is divided
across channels.

Magnitude evidence distinguishes:

- a minority high-direction anomaly (`AttributedInconsistency`, spoof-like evidence with
  cause unclassified);
- broad high-direction inflation (`BroadDegradation`, jam-like evidence with cause
  unclassified);
- positive but non-attributable/lower-direction evidence (`UnclassifiedAnomaly`);
- insufficient freshness/readiness (`InsufficientEvidence`);
- fully ready and consistent evidence (`Nominal`).

### 4.2 Signed correlation and consensus

Scalar channel series come only from the attested common projection and are formed by
exact sequence intersection for one track. Unequal, duplicate, non-finite, degenerate,
or provenance-incompatible channels fail validation. Legacy native innovations do not
enter this path.

The default uses **signed** Pearson correlation. Candidate positive edges must clear both
a configured floor and a family-wise Fisher-transform significance threshold. Attribution
requires one unique positive-consensus clique containing strictly more than half the
channels. This prevents three old failure modes:

- a negative/sign-flipped channel appearing corroborated through `|rho|`;
- a best-peer dyad creating an apparent consensus;
- a convenient pair hiding a failed third channel.

No unique strict majority means `InsufficientEvidence`.

The fused entry points analyze every active projection axis. Correlation's family budget
is split across axes and channel pairs. A coordinate-specific anomaly may leave other axes
nominal, but different positive channel attributions across axes—or a positive axis beside
an insufficient axis—remain `UnclassifiedAnomaly` rather than a selected
`AttributedInconsistency`.

### 4.3 Optional MI/PID evidence

For jointly Gaussian scalar variables [CoverThomas2006],

\[
I(X;Y)=-\tfrac{1}{2}\log(1-\rho^2).
\]

MI and correlation magnitude therefore encode the same population ranking in that model.
KSG [Kraskov2004] is justified only when validated data contain dependence that signed
linear correlation cannot represent. Its geometry, sample size, declared additive
observation-noise model, and bootstrap configuration must be validated — its finite-sample
and dimension-dependent bias are characterized by [Gao2018] — and failure is not replaced
by an optimistic point estimate.

Partial information decomposition [WilliamsBeer2010], in its shared-exclusions form
[Makkeh2021, Ehrlich2024], can describe redundant, unique, and synergistic information for
a documented source/target construction. Its atoms are
advisory and can legitimately be negative. They are neither probabilities nor calibrated
attack confidence.

MI/PID is sign-invariant and additive. It cannot override contradictory signed geometry,
repair a missing modality, or create majority attribution from a dyad.

### 4.4 Fusion

Magnitude and consistency evidence are combined without discarding either source. A
consistency result that is unavailable cannot turn a magnitude-nominal window into a
fully fused nominal result. Positive anomaly evidence is not erased merely because peer
geometry is insufficient. `Result` APIs separate invalid computation from a valid but
inconclusive report.

## 5. Why MI/PID can still be justified

Three canonical cases motivate research beyond correlation:

1. **Nonlinear dependence.** One variable can constrain another while linear covariance
   is zero.
2. **Adversarial structure.** An attacker may target a known second-order statistic while
   leaving detectable higher-order dependence.
3. **Irreducible synergy.** A source pair can jointly constrain a target even though each
   source alone is uninformative, as in XOR/sign-parity constructions.

These constructions show possibility, not prevalence. A synthetic separation demonstrates
that an estimator can observe the constructed model. It does not demonstrate that the
same target/source relation exists in a deployed fusion system.

Pointwise local information may also support sequential change detection [Page1954,
Moustakides1986]. That is a research direction requiring a validated clean reference and
stream-level false-alarm calibration; it is not the current runtime streaming mode.

## 6. Evaluation discipline

The harness evaluates explicit synthetic models along accuracy, latency, and cost axes.
After the correctness audit, exact pre-audit values were removed. They must not be cited as
current results because sequence alignment, signed consensus, family-wise thresholds,
validation, PID observation-noise modeling, bootstrap handling, and fusion semantics changed.

A regenerated report must disclose:

- commit, Rust toolchain, hardware, build profile, and full configuration;
- trial and seed policy;
- errors and inconclusive outcomes as separate rates;
- paired uncertainty for detector differences;
- pre-onset false alarms when measuring time to detect;
- multiplicity for parameter-grid claims;
- synthetic status in every result summary.

The recorded-data gate is stronger: producer common-prior/common-frame semantics, explicit
miss events, heartbeat, sessions, and schema must exist before an operational claim is
possible. See [`EVALUATION.md`](EVALUATION.md).

## 7. Limitations

- **Consistency is not truth.** Decoupling can mean attack, benign uniqueness, frame
  mismatch, filter error, or timing error.
- **Honest-majority boundary.** A colluding majority can invert attribution; an ambiguous
  topology remains inconclusive.
- **Selection bias.** Association and gating can hide attacks as missing data.
- **Temporal calibration.** The Fisher-z correlation significance floor assumes the windowed
  residual pairs are i.i.d. bivariate normal. Same-sign within-window autocorrelation in two
  independent residual series lowers the effective sample size below the window length, so a
  single assessment's significance is anti-conservative; opposite-sign autocorrelation can
  instead be conservative. The canonical autocorrelation-null study in `galadriel-justify`
  quantifies the equal-positive-persistence case at the default window. A Bartlett
  effective-sample-size correction
  [Bartlett1935] improves moderate-persistence calibration but is conservative when high
  persistence leaves a small effective sample (`JUSTIFICATION.md` §5); the runtime floor
  intentionally remains uncorrected until phi estimation and finite-sample calibration are
  registered. Note that a
  correctly tuned filter's *native*
  innovations are approximately white, but the attested common-frozen-prior consistency
  residual is not one filter's innovation and carries no such guarantee. Separately, even a
  well-calibrated per-assessment significance does not by itself guarantee a stream-level
  false-alarm rate under overlapping windows and repeated looks.
- **Below-target magnitude shifts.** The windowed NIS test is right-tailed, and at the fusion
  core's `dof = 3` with the default symmetric CUSUM slack the below-target CUSUM arm is inert
  (see `DetectorConfig::cusum_slack`). A moment-*shrinking* channel — an over-conservative
  filter, or a replay/frozen sensor whose innovations match the prediction too closely — is
  therefore not flagged by the magnitude layer at that operating point.
- **Synthetic evidence.** Current studies do not represent field prevalence, base rates,
  maneuvers, or operator outcomes.
- **Liveness.** The operational receiver expects an independent producer heartbeat and fails
  closed on silence. Historical replay files have no live-liveness claim, and no current
  reciprocal producer pin or retained external deployment campaign demonstrates the
  heartbeat across the real router and certificate boundary.
- **Transport prototype.** A retained historical Crebain revision contained a gated
  two-route publisher baseline, while Galadriel implements a strict, bounded two-route
  receiver. That historical pair does not qualify the current candidate. The generated
  profile fixes mTLS, exact-epoch ACLs, and a 128 KiB transport receive ceiling, but
  component and in-process tests do not prove that a remote router loaded or enforced
  those files. The pinned Zenoh 1.9 client also trusts built-in public WebPKI roots in
  addition to the configured deployment CA; exclusive router pinning requires the
  runbook's private-name/controlled-resolution mitigation or an external exact-certificate/
  SPKI enforcement layer and is not supplied by local profile validation. The pinned
  `ncp-zenoh` callback
  materializes payload bytes before Galadriel's application size gate, so the transport
  ceiling remains mandatory. New sequence streams fail closed at capacity instead of
  evicting replay high-water marks; authenticated ACLs and a fresh deployment-supplied
  epoch remain operational requirements rather than detector features.
- **Advisory only.** The verdict is not a calibrated posterior or enforcement command.

## 8. Roadmap to a defensible claim

1. **Implemented locally:** Galadriel's versioned strict schemas, pinned-registry
   capability, bounded two-route assembler/receiver, typed lifecycle transitions, and
   exact-epoch secure configuration procedure.
2. **Historical fixture only:** Crebain
   `4c311900ade5668200a48d56fb191be1916b884a` and Galadriel
   `81437d807ca83b66b45c8353968948e540072d97` recorded an earlier
   epoch/registry/common-projection compatibility pair. They do not pin or qualify this
   candidate.
3. **Not claimed:** a current reciprocal producer pin and final cross-repository
   qualification.
4. **External evidence required:** execute the real multi-process allow/deny and
   wrong/no-certificate campaign against exact current binaries.
5. **Recorded evidence required:** collect pre-gate streams, characterize selection
   effects, and evaluate maneuvers, lifecycle changes, and attacks independently of
   threshold fitting.
6. **Publication boundary:** retain `publish = false` and the research classification;
   this source release does not promote any crate or adapter to an operational API.

## 9. Conclusion

The central selection rule survives the audit: do not pay for an information-theoretic
estimator when a validated cheaper statistic observes the same estimand. Use signed
correlation for a valid positive linear consensus; add MI/PID only where recorded evidence
demonstrates a nonlinear or synergistic question. When geometry or evidence is absent,
remain inconclusive.

Galadriel currently implements and tests that discipline as a research prototype. Its
consumer contract defines the required stream, but a current reciprocal producer
qualification and an accepted recorded field study remain `NOT_CLAIMED`.

## Reproducibility

```bash
cargo run -p galadriel-eval --release -- 200
cargo run -p galadriel-justify --release
cargo bench -p galadriel-eval --bench detectors
cargo test --workspace --all-features --locked
```

Numeric output is local synthetic evidence. Record provenance before reporting it and do
not translate it into an operational detection or false-alarm rate.

## References

- **[BarShalom2001]** Y. Bar-Shalom, X.-R. Li, T. Kirubarajan. *Estimation with Applications to Tracking and Navigation.* Wiley, 2001.
- **[Bartlett1935]** M. S. Bartlett. "Some Aspects of the Time-Correlation Problem in Regard to Tests of Significance." *Journal of the Royal Statistical Society* 98(3), 536–543, 1935.
- **[CoverThomas2006]** T. M. Cover, J. A. Thomas. *Elements of Information Theory,* 2nd ed. Wiley, 2006.
- **[Ehrlich2024]** D. A. Ehrlich et al. "Partial information decomposition for continuous variables based on shared exclusions." *Phys. Rev. E* 110, 014115, 2024. [arXiv:2311.06373](https://arxiv.org/abs/2311.06373).
- **[Gao2018]** W. Gao, S. Oh, P. Viswanath. "Demystifying Fixed k-Nearest Neighbor Information Estimators." *IEEE Transactions on Information Theory* 64(8), 2018. [arXiv:1604.03006](https://arxiv.org/abs/1604.03006).
- **[Hallyburton2022]** R. S. Hallyburton et al. "Security Analysis of Camera-LiDAR Fusion Against Black-Box Attacks on Autonomous Vehicles." *USENIX Security,* 2022. [arXiv:2106.07098](https://arxiv.org/abs/2106.07098).
- **[Kraskov2004]** A. Kraskov, H. Stögbauer, P. Grassberger. "Estimating mutual information." *Phys. Rev. E* 69, 066138, 2004.
- **[Makkeh2021]** A. Makkeh, A. J. Gutknecht, M. Wibral. "Introducing a differentiable measure of pointwise shared information." *Phys. Rev. E* 103, 032149, 2021. [arXiv:2002.03356](https://arxiv.org/abs/2002.03356).
- **[Moustakides1986]** G. V. Moustakides. "Optimal Stopping Times for Detecting Changes in Distributions." *Annals of Statistics* 14(4), 1986.
- **[Page1954]** E. S. Page. "Continuous inspection schemes." *Biometrika* 41(1/2), 1954.
- **[WilliamsBeer2010]** P. L. Williams, R. D. Beer. "Nonnegative Decomposition of Multivariate Information." [arXiv:1004.2515](https://arxiv.org/abs/1004.2515), 2010.
