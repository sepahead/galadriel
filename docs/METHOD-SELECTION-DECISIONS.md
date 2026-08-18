# Method and profile decision record

## Status and use

This document records why Galadriel selects each statistical object in the
unpublished 0.9 source candidate. It also records alternatives, non-selections,
assumptions, failure behavior, and evidence limits. It is a design record, not a
field-calibration report.

| Publication field | Bound value |
|---|---|
| Record state | **Proposed. Human acceptance and publication review remain open.** |
| Evidence cut | 2026-08-18. Galadriel PR 47 candidate head `883b36aec0c97fb09602cc138e7d165a80daad0a`, tree `fe94613eb8934a6d578d2c54b985a3ac1f1fdf04`. This proposed record is a later working-copy addition and is not evidence that the bound candidate contained it. |
| Evaluator cut | `pid-core` 0.9.0 at `bc3aa80fb6025e709c2906a08bce25a4fac40578`, as selected by `ECO-018`. |
| Downstream cut | Haldir signed review commit `c19f9011e4919a5bc67fab5f90d6c8eefed4455b`, as recorded by [`ECO-019`](ECOSYSTEM-CONNECTIONS.md#haldir-connection). It is not merged Haldir `main` or an implemented adapter. |
| Decision owner | Galadriel project owner. A method or profile change requires an owner-approved successor record and profile identity. |
| Review state | Code-contract red team completed. Independent qualified statistical and PID review is still required. |
| Acceptance gate | Commit this record with its classifier tests, regenerate living audit artifacts, and obtain green exact-head CI and required deep-quality evidence. Until then, crosslinks identify a proposal rather than an accepted release decision. |

The governing rule is question first:

> Select the least complex object that observes the declared estimand. Keep a
> more expressive object separate until evidence shows that it adds information
> on the same admitted rows.

This rule prevents three category errors. A magnitude test is not an association
test. An association statistic is not a target-information allocation. A
descriptive graph is not an authority decision.

![Question-first method decision map. It separates selected default routes, research companions, deferred alternatives, evidence ceilings, and the authority non-edge.](../assets/method-selection-decision-map.svg)

**Figure 1. Question-first decision map.** The layout places the registered
question before the selected object. Alternatives stay visible beside each
selection. The bottom barrier makes the missing evidence-to-authority edge
explicit. Pattern, label, color, and line grammar carry the same state so the
figure does not depend on color alone.

The exact wire and validation contracts remain normative in
[`STATISTICAL-CONTRACT.md`](STATISTICAL-CONTRACT.md) and
[`CONFIGURATION-CONTRACT.md`](CONFIGURATION-CONTRACT.md). This record explains
the choices behind those contracts. If code, a contract, and this rationale
disagree, the candidate must abstain from release until the disagreement is
reviewed and resolved.

## Abbreviations

| Term | Meaning in this record |
|---|---|
| BROJA | The Bertschinger–Rauh–Olbrich–Jost–Ay two-source unique-information construction. |
| CUSUM | Cumulative sum sequential change statistic. |
| EWMA | Exponentially weighted moving average. |
| GLR | Generalized likelihood-ratio change detector. |
| HSIC | Hilbert–Schmidt independence criterion. |
| KSG | Kraskov–Stögbauer–Grassberger mutual-information estimator. |
| MGW | Makkeh–Gutknecht–Wibral shared-exclusions functional. |
| MI | Mutual information, reported in nats. |
| NIS | Normalized Innovation Squared. |
| PID | Partial information decomposition. |
| SPRT | Sequential probability-ratio test. |

## Decision taxonomy

Each decision has one of four states.

| State | Meaning |
|---|---|
| **Selected** | The named 0.9 profile executes this object for its stated question. |
| **Companion** | The object executes only in a separate research path and cannot change the default verdict. |
| **Deferred** | The object is plausible, but no accepted evidence supports selecting it for this release profile. |
| **Rejected for this estimand** | The object answers a different question or violates an input, support, authority, or evidence constraint. |

These states are not universal method rankings. A method rejected for one
estimand can be correct for another estimand.

## Decision map

| ID | Question | Selected object | Why selected | Main alternatives | Release effect |
|---|---|---|---|---|---|
| GLD-MSD-001 | Did one admitted channel's normalized residual magnitude show upper-tail or sustained change? | Windowed right-tail NIS plus a two-arm tabular CUSUM | NIS tests the declared chi-square upper tail. The CUSUM supplies ordered sequential evidence. Its lower arm is inert on the fusion core's `dof=3` route but can move for admitted `dof>=4`. This dimension dependence is a disclosed profile limitation. | NIS alone, Shewhart, EWMA, GLR, SPRT | Default magnitude evidence |
| GLD-MSD-002 | Do comparable channels retain the expected positive linear relation? | Signed Pearson correlation with one-sided Fisher-z screening | Pearson preserves direction and matches the registered positive-linear consensus question. Fisher-z supplies an explicit conditional reference under the declared row model. | Absolute correlation, Spearman, Kendall, robust correlation, partial correlation, mutual information | Default consistency evidence |
| GLD-MSD-003 | How is multiplicity controlled within one assessment? | Bonferroni splits `nis_alpha` across known or expected channels and `family_alpha` across active axes and channel pairs | It is transparent, deterministic, and easy to bind to the exact family size. It needs valid or conservative constituent p-values, but it does not additionally require independence among them. | No correction, Sidak, Holm, Hochberg, max-statistic resampling | Default per-assessment evidence only |
| GLD-MSD-004 | Which channels form corroborated positive consensus? | One unique largest all-pairs clique whose size is a strict majority | It blocks tied largest explanations and bridge ambiguity while stating the project's exact fault-tolerance ceiling. | Best-peer score, connected component, largest clique with arbitrary tie break, spectral clustering | Default consistency evidence |
| GLD-MSD-005 | Is there pairwise dependence that signed Pearson can miss? | Report-first KSG MI behind geometry, support, resource, and stability gates | KSG targets continuous dependence without fitting a parametric response curve. The report-first route retains assumptions, warnings, and failure state. | Distance correlation, HSIC, copula MI, kernel-density MI, neural MI | Non-fused companion only |
| GLD-MSD-006 | How should one target's information be allocated over ordered categorical sources? | Categorical MGW shared-exclusions PID | The registered question requests pointwise and averaged redundant, unique, and synergistic coordinates for an atomic law. MGW supplies that named signed allocation. | Joint contrast, `I_min`, BROJA, co-information, O-information | Offline study only |
| GLD-MSD-007 | How should one target's information be allocated for an eligible continuous law? | Ehrlich and colleagues' experimental restricted-domain shared-exclusions functional and estimator | This is the named continuous construction exposed by the pinned evaluator for a narrowly declared eligible law. It preserves a distinct functional, gauge, support, and estimator identity without implying general continuous validity. | Quantize then use categorical PID, Gaussian closed-form special cases, kernel PID, general measure-theoretic construction without this evaluator | Offline study only |
| GLD-MSD-008 | Can any MI or PID result alter a verdict or downstream authority? | No | These objects do not have calibrated security semantics. Galadriel keeps them outside `FusedVerdict`. At the exact `ECO-019` cut, Haldir has no implemented PID adapter or decision input. | Fuse the score, use PID to deny or restrict, let an operator infer authority from a chart | Explicit non-edge |
| GLD-MSD-009 | How is error controlled across overlapping repeated assessments? | No stream-level correction is selected | Per-assessment Bonferroni control does not establish a sequential false-alarm guarantee. A temporal model and repeated-look procedure must be registered first. | Alpha spending, anytime-valid inference, block/max-statistic resampling, calibrated run-length design | Open calibration decision. No stream-level error claim. |

## GLD-MSD-001: NIS plus two-arm CUSUM

### Estimand and mathematics

For a correctly declared innovation model with \(d\) degrees of freedom, NIS has
the chi-square reference \(\chi^2_d\). The selected window test uses the right
tail and therefore detects excess magnitude, not suppressed magnitude. It does
not ask whether two channels covary.

The CUSUM path scales both the NIS value and its null mean by
\(\sqrt{2d}\). Under the chi-square reference, \(2d\) is the variance. The scale
therefore expresses the tabular CUSUM slack and threshold in comparable
null-standard-deviation units across supported dimensions. The implementation
retains upper and lower accumulator fields and fails on non-finite input. The
configuration fixes the slack but accepts validated `dof` values from 1 through
255. On the fusion core's `dof=3` route, the scaled mean equals the slack. Since
NIS is nonnegative, the lower recurrence remains zero. For `dof>=4`, the scaled
mean exceeds the fixed slack, so a sufficiently small normalized NIS value can
increase the lower arm. The selected object is therefore two-arm over its full
admitted domain, while the fusion-core route supplies effective upper-arm
sensitivity only.

### Why this pair was selected

NIS is the model-aligned magnitude statistic already produced by the admitted
filter contract. It uses the stated degrees of freedom and has a direct reference
law. The upper CUSUM arm adds memory for sustained inflation that a window tail
test can detect late. The lower arm retains dimension-dependent response to small
normalized NIS values. It is inert for the fusion core's `dof=3` route and can
move for admitted `dof>=4`. The system does not relabel either CUSUM arm as a
p-value.

### Alternatives and disposition

| Alternative | Disposition | Reason |
|---|---|---|
| NIS alone | Rejected for this estimand as the complete magnitude lane | It discards ordered evidence about sustained drift. It remains a constituent. |
| Shewhart threshold | Rejected for this estimand as a replacement | It emphasizes isolated excursions and adds no accumulated drift state. |
| EWMA | Deferred | It is a valid sequential smoother, but selecting its decay and control limits needs a separate run-length calibration. |
| Generalized likelihood ratio | Deferred | It can target unknown change points and effects, but it requires a more specific likelihood and a larger bounded search contract. |
| SPRT | Deferred | It requires explicit pre-change and post-change hypotheses. The current profile does not have a qualified post-change law. |
| One-sided CUSUM | Rejected as a general replacement. Deferred for a `dof=3`-only successor. | The selected route admits degrees of freedom above three, where the lower arm can move. A one-sided upper CUSUM would describe the fusion-core `dof=3` computation more directly, but only after the producer contract restricts that route and a reviewed profile and schema change binds the restriction. |

### Numeric profile decision

`StandaloneAdvisoryV0_9` fixes a detector window of 64, readiness at 32 samples,
`nis_alpha=0.01`, slack \(3/\sqrt6\), threshold \(15/\sqrt6\), and broad-event
fraction 0.6. The division by \(\sqrt6\) matches the `dof=3` fusion-core scale
used when the profile was formed. The profile does not restrict `dof`. The source
rescales NIS by \(\sqrt{2d}\) at runtime and retains the same fixed slack and
threshold. This makes the arm response dimension-dependent and prevents a
dimension-free detection-sensitivity claim.

These constants select a deterministic and bounded research operating point.
They are not an estimated optimum. No retained field corpus justifies their
false-alarm or detection-delay performance. The candidate therefore preserves
the exact values for reproducibility and labels deployment calibration
`NOT_CLAIMED`. The correct alternative is a preregistered calibration study with
run-length, repeated-look, autocorrelation, maneuver, and base-rate analysis. It
is not undocumented retuning.

| Profile coordinate | Selection rationale | Rejected or deferred alternative |
|---|---|---|
| Window `64` | A fixed power-of-two window gives bounded state and a stable candidate identity. It is long enough to reach the selected 32-sample readiness point with retained history. | Other windows are **deferred** to false-alert, delay, and autocorrelation studies. No theorem makes `64` optimal. |
| Readiness `32` | The profile withholds a verdict through the first half-window and then permits the declared chi-square aggregate. | Earlier readiness is **rejected for this profile**. Later readiness is **deferred** to latency calibration. |
| `nis_alpha=0.01` | It supplies a conservative per-assessment family input that is divided by the number of known or expected channels, including an absent expected channel. | Other alpha values are **deferred**. This value does not control repeated looks. |
| Slack `3/sqrt(6)` | It preserves the profile's original fusion-core `dof=3` scaling and exact identity. The lower arm is inert for `dof<=3` and can move for admitted `dof>=4`. | A dimension-specific slack or a producer-level `dof` restriction is **deferred** until run-length calibration. |
| Threshold `15/sqrt(6)` | It preserves a finite, tested sequential boundary in the same scaled units as the slack. | Other thresholds are **deferred** to average-run-length and delay qualification. |
| Broad fraction `0.6` | It requires at least two high-direction channel events whose count meets the configured fraction before the broad-degradation branch wins fusion precedence. | A different fraction is **deferred** to channel-count and fault-prevalence analysis. It is not a calibrated attack probability. |

### Failure and evidence ceiling

Invalid configuration or non-finite input is an error. Missing, stale, short, or
incompatible evidence is insufficient. A magnitude event locates statistical
evidence. It does not identify spoofing, jamming, fault, intent, or ground truth.

## GLD-MSD-002: signed Pearson correlation and Fisher screening

### Estimand and mathematics

The default consistency question assumes an expected positive linear relation
between comparable common-projection residuals. Pearson correlation estimates
that signed linear relation. A candidate edge must clear the maximum of the
absolute project floor, the relative separation floor, and the one-sided
Fisher-z reference threshold.

The Fisher reference is conditional. Its conventional standard error uses
\(1/\sqrt{n-3}\) for independent and identically distributed bivariate-normal
rows. Galadriel records this assumption and does not infer it from a finite
window.

### Why Pearson was selected

Direction is part of the registered consensus. A sign-flipped channel must not
become corroborated merely because its association is strong. Pearson is cheap,
deterministic, interpretable in the declared linear model, and aligned with the
Gaussian relation between correlation magnitude and mutual information. It also
provides a transparent baseline that a more complex dependence statistic must
beat on identical admitted rows.

### Alternatives and disposition

| Alternative | Disposition | Reason |
|---|---|---|
| Absolute Pearson correlation | Rejected for this estimand | It turns strong negative relation into positive corroboration. |
| Spearman or Kendall correlation | Deferred | These rank objects are more robust to monotone nonlinear transforms, but they answer a different dependence question and need tie and null-calibration contracts. |
| Robust or winsorized correlation | Deferred | Robustness can help under heavy tails. It also changes the estimand and requires a declared contamination model and tuning rule. |
| Partial correlation | Rejected for this estimand | It conditions on a named variable set. The current producer contract does not supply a qualified conditioning graph. |
| Pairwise KSG MI | Companion | MI is symmetric and direction-free. A signed finite-sample estimate is not a direction label. It cannot replace the default sign check. |

### Numeric profile decision

The named profile fixes a 128-row correlation window, 64-row readiness,
`corr_floor=0.15`, `decouple_ratio=0.4`, and `family_alpha=0.01`. These values
provide one closed, identity-bound candidate profile. They have boundary and
hostile tests. They do not have field calibration. The larger window relative to
the NIS window gives the pair statistic more admitted rows, but it also increases
latency and overlap. This tradeoff remains a profile choice rather than a theorem.

Alternatives such as a lower floor, a shorter window, or an estimated effective
sample size must be compared on a frozen stream corpus. The comparison must
report false consensus, missed decoupling, latency, and the effect of serial
dependence. Until then, changing a number creates a new profile and cannot be
described as a correction.

| Profile coordinate | Selection rationale | Rejected or deferred alternative |
|---|---|---|
| Window `128` | Pairwise association needs a common aligned row tail. The fixed larger window trades more observations for more latency and overlap. | Other windows are **deferred** to same-stream comparison. |
| Minimum `64` | It withholds correlation and Fisher screening below the registered minimum. | A smaller minimum is **rejected for this profile**. A larger one is **deferred** to power and latency analysis. |
| `corr_floor=0.15` | It creates an absolute positive-edge floor so a nearly zero strongest pair cannot define consensus. | Other floors are **deferred**. `0.15` is not a universal minimum useful correlation. |
| `decouple_ratio=0.4` | It adds a scale-relative edge floor against the strongest admitted positive pair. | Absolute-only and differently scaled rules are **deferred** to a frozen graph study. |
| `family_alpha=0.01` | It is divided by active axes and pairs to make the per-assessment family explicit. | Other alpha values and stepwise corrections are **deferred**. Serial repeated-look control remains absent. |

### Failure and evidence ceiling

A finite degenerate column makes the estimand unavailable. It does not create a
zero edge. A rejected or ambiguous graph returns insufficient evidence. Pearson
evidence does not authenticate producer labels, prove truth, or identify cause.

## GLD-MSD-003: Bonferroni family control

### Why it was selected

The magnitude lane divides `nis_alpha` by the number of known or expected
channels, including an absent expected channel. The
correlation lane divides `family_alpha` by active axes and channel pairs.
Bonferroni controls a family without an additional independence assumption only
when each constituent p-value is valid or conservative under its declared null.
It cannot repair an invalid chi-square reference or the disclosed Fisher-z
approximation failure under serial dependence. Its rule is deterministic,
monotone, and directly reviewable from the exact family size. Those properties
matter more here than asymptotic power because the release profile is an
uncalibrated advisory candidate.

### Alternatives and disposition

| Alternative | Disposition | Reason |
|---|---|---|
| No multiplicity correction | Rejected for this estimand | It lets the assessment false-edge opportunity grow with the number of axes and pairs. |
| Sidak correction | Deferred | It is less conservative under suitable independence structure. The current overlapping pair family does not declare that structure. |
| Holm step-down | Deferred | It can dominate Bonferroni for family-wise error, but it needs a complete ordered p-value family and a new graph identity and verification path. |
| Hochberg step-up | Deferred | It requires stronger dependence conditions than the current contract supplies. |
| Permutation or max-statistic calibration | Deferred. Preferred future comparison. | It can represent dependence and repeated processing more directly, but it needs exchangeability, a frozen resampling unit, bounded work, and a representative corpus. |

Bonferroni does not solve repeated looks across overlapping windows. That is a
separate stream-level calibration problem.

### GLD-MSD-009: no selected stream-level repeated-look correction

The runtime repeatedly evaluates overlapping windows. A per-assessment family
split therefore does not imply a stream false-alarm probability, average run
length, or anytime-valid error bound. The candidate makes none of those claims.

| Alternative | State | Why it is not selected now |
|---|---|---|
| Alpha-spending or group-sequential boundary | Deferred | It needs a registered look schedule and dependence model. The current receiver can evaluate on a stream-dependent schedule. |
| Anytime-valid p-values, e-values, or confidence sequences | Deferred | They can support optional continuation, but require a different statistic and proof under the admitted temporal law. |
| Block or max-statistic resampling | Deferred | It can represent dependence only after the episode or block resampling unit and exchangeability conditions are fixed. |
| Empirical run-length calibration | Deferred. Preferred operational study. | It needs a frozen representative stream corpus, preregistered scenarios, and explicit false-alert and delay targets. |

The absence of a selected stream procedure is deliberate disclosure, not a
claim that repeated looks are harmless. Deployment calibration remains blocked.

## GLD-MSD-004: unique strict-majority all-pairs consensus

### Why it was selected

Attribution needs more than one high-scoring neighbor. The selected graph rule
requires one unique largest clique whose size is greater than half of the
requested channels. Every pair inside that clique must clear the threshold.
Smaller subcliques are expected and do not create ambiguity. A minority channel
is attributable only when it has no threshold-clearing bridge that makes the
explanation ambiguous.

This rule encodes a clear fault ceiling. A dyad is the complete graph when two
channels are requested. It can support minority attribution only when exactly
three channels are requested. The implementation admits that 2-of-3 case when it
is the unique largest unbridged clique. A dyad is not a strict majority when four
or more channels are requested. A tied largest clique does not trigger an
arbitrary winner. A connected path does not substitute for all-pairs agreement.

### Alternatives and disposition

| Alternative | Disposition | Reason |
|---|---|---|
| Best-peer or average-peer score | Rejected for this estimand | One convenient pair can hide a failed third channel. |
| Largest connected component | Rejected for this estimand | Transitive connectivity does not prove pairwise corroboration. |
| Largest clique with deterministic tie break | Rejected for this estimand | Determinism would not make a tied scientific explanation identifiable. |
| Spectral or community clustering | Deferred | It adds tuning, stochastic or numerical sensitivity, and no current security-error theorem. |
| Robust state estimation | Companion. Complementary, not a substitute. | It can provide model-specific recovery guarantees at another layer. Galadriel's graph is advisory consistency evidence. |

The rule cannot identify a colluding majority. No threshold can repair that
structural limit.

## GLD-MSD-005: report-first KSG mutual information companion

### Why KSG was selected

KSG estimates continuous mutual information directly from neighbor geometry. It
does not require a parametric response curve or a fixed kernel bandwidth. The
pinned pid-core route returns a typed report with its support declaration,
diagnostics, warnings, estimator identity, and resource estimate. Galadriel uses
the explicit single-thread budget route. It rejects exact ties and screened
geometry instead of adding noise.

The companion keeps the complete pair graph outside the default verdict. This
placement makes the scientific comparison honest. KSG must demonstrate added
value over signed Pearson on the same admitted rows before it can motivate any
larger role.

### Alternatives and disposition

| Alternative | Disposition | Reason |
|---|---|---|
| Distance correlation | Deferred | It is a useful general dependence measure with different finite-sample and null-calibration behavior. No accepted adapter or comparison exists here. |
| HSIC | Deferred | It needs a kernel and bandwidth selection contract and a calibrated test or descriptive interpretation. |
| Copula MI | Deferred | It changes preprocessing and tie behavior and needs an explicit marginal-transform contract. |
| Kernel-density MI | Deferred | Bandwidth and boundary handling become load-bearing estimand and estimator choices. |
| Neural MI estimator | Rejected for this estimand | Training, optimizer, architecture, stopping, and lower-bound bias would create a much larger stochastic evidence contract. |
| Added jitter before KSG | Rejected for this estimand as a generic repair | Noise changes the estimand. A valid observation-noise model must be stated and reported separately. |

### Project-defined graph profile

The profile fixes a 128-row window, a 64-row point-estimate minimum, and an
eight-row exhaustive deletion block. The complete stability route therefore
requires 72 admitted rows before execution. It also fixes geometry `k=5`, KSG `k=3`, an
intrinsic-dimension mean range `[1.5, 3.0]`, local-estimate median minimum 1.30,
`cv_min=0.01`, `nn_ratio_max=0.999`, `mi_floor_nats=0.03`, relative separation
0.4, and exhaustive circular deletion of blocks of eight rows.

These are conservative abstention and sensitivity boundaries exercised against
fixed controls. They are project-defined. They do not prove regular population
support, estimator consistency, a null false-alarm rate, or optimal separation.
The eight-row deletion enumerates a bounded perturbation family. It is not a
bootstrap, confidence interval, or p-value.

The per-call KSG budget fixes one thread, one GiB, a maximum-window
pairwise-distance ceiling of \(4\binom{512}{2}=523{,}264\), and an operation hint
of \(10^{10}\). The exact pairwise ceiling comes from pid-core's conservative
maximum-window preflight. A one-unit-smaller hostile budget must reject that
call. This is a checked call boundary, not a proof of end-to-end study memory.

### Exact KSG and graph-profile choices

None of the following constants is claimed to be field-optimal. The release
reason is either constitutive estimator identity, a checked finite resource
boundary, or preservation of fixed synthetic controls. A different value creates
a successor profile and requires same-row comparison.

| Choice | Why selected | Alternative and disposition | Evidence ceiling |
|---|---|---|---|
| KSG-1 | The pinned stable report route explicitly identifies the Algorithm-1-style product-small-ball estimand and has exact backend parity and retained provenance. | KSG-2 is **deferred** until a named evaluator, bias comparison, and source-compatible report contract exist. | Selection does not establish KSG-1 as universally lower-bias or lower-variance. |
| KSG neighbor count `k=3` | It is the tested profile identity exposed to every point and deletion fit. A small fixed neighbor count preserves locality and makes the comparison reproducible. | Other `k` values are **deferred** to a frozen bias, variance, geometry, and stability study. | No data or theorem in Galadriel makes `3` optimal. |
| Chebyshev max metric | It is constitutive of the selected KSG-1 joint-radius and marginal shell-count construction and matches both exact upstream backends. | Euclidean or learned metrics are **rejected for this estimand** because they would define a different estimator route. | Exact backend agreement is implementation evidence, not support validation. |
| Exact ties and `tie_epsilon=0` | The declared continuous law requires unrounded continuous observations. Rejecting ties preserves that estimand. | Jitter is **rejected for this estimand** because added noise changes the law. Quantized or atomic data must use another estimand. | A tie identifies an incompatible observation, not its physical cause. |
| `NegativeHandling::Allow` | Finite-sample KSG estimates can be signed. Retaining them avoids a hidden nonlinear transform and preserves later algebra and threshold auditing. | Clamping is **rejected for this estimand**. | A negative estimate is not negative population MI and is not directional correlation. |
| Geometry `k=5` | A separately fixed neighborhood probes sample geometry without reusing the estimator's `k=3` identity. It is exercised by fixed controls. | Other geometry neighborhoods are **deferred** to sensitivity analysis. | Galadriel has no proof that `5` maximizes diagnostic power. |
| Intrinsic-dimension mean `[1.5, 3.0]` and local median `>=1.30` | These project screens reject materially one-dimensional or implausibly high sample geometry while retaining the fixed scalar-pair Gaussian controls. | Wider limits are **deferred** to same-law controls. | Passing does not prove full-dimensional population support. |
| Distance coefficient of variation `>=0.01` | It rejects near-collapsed distance clouds in which neighbor geometry has little resolving scale. | Zero or smaller floors are **rejected for this profile** because they admit the tested collapse boundary. | The floor has no null-calibration theorem. |
| Nearest/farthest distance ratio `<=0.999` | It rejects near-equal-distance concentration at the declared finite precision. | A different cutoff is **deferred** to dimension and sample-size calibration. | Passing does not establish estimator consistency. |
| MI floor `0.03` nats | It prevents a very small signed estimate from becoming a graph edge solely through a relative rule. | Zero floor is **rejected for this profile**. Other floors are **deferred** to frozen-corpus calibration. | `0.03` is not a significance threshold or minimum operational effect. |
| Separation ratio `0.4` | It requires an edge to retain a fixed fraction of the strongest admitted pair, which makes the project-defined graph scale-relative. | Absolute-only and differently scaled graphs are **deferred**. | The ratio is uncalibrated and cannot identify cause or an honest majority. |
| Circular deletion block `8` | The exhaustive profile removes every eight-row circular block and requires identical graph disposition. At minimum input it leaves the registered 64-row point-fit population. | Bootstrap intervals are **rejected as a description of this route**. Other block lengths are **deferred** to a temporal-unit study. | This is bounded deterministic sensitivity, not resampling inference. |
| One execution thread | It removes host `available_parallelism()` from the scientific route and makes the retained preflight and call use one explicit budget. | Ambient or multi-thread execution is **deferred** until bit identity and resource evidence are retained for that profile. | One thread bounds concurrency, not wall-clock duration. |
| Custom-config maximum window `512` | It is a hard API admission ceiling used to derive the maximum per-report preflight. The named 0.9 profile still uses `128`. | Larger custom windows are **rejected before work**. | The ceiling is denial-of-service policy, not evidence that KSG is accurate at 512 rows or every dimension. |

## GLD-MSD-006: categorical MGW shared-exclusions PID

### Why this functional was selected

The registered categorical question asks for pointwise and averaged allocation
over named ordered sources. MGW shared exclusions supplies a local informative
and misinformative decomposition, a Williams–Beer antichain lattice, and signed
net atoms. It applies directly to the finite atomic law without fitting a
continuous estimator or quantizer.

The selection does not claim that MGW is the uniquely correct PID. It binds one
named functional so the result is reproducible and falsifiable. The independent
COPY identity-axiom witness and the known multivariate consistency limits remain
part of the result's caveat graph.

### Alternatives and disposition

| Alternative | Disposition | Reason |
|---|---|---|
| Joint contrast \(Q\) | Rejected for this estimand as PID | It can detect joint-only structure but does not define redundancy-lattice atoms. |
| Williams–Beer `I_min` | Companion. Eligible comparator, not substituted. | It is a different redundancy functional and can assign different atoms. Silent fallback would change the question. |
| BROJA two-source PID | Companion. Eligible only for a separately registered PID2 comparison. | It defines a different optimization-based bivariate object and does not supply the exploratory PID3 route used here. |
| Co-information | Companion. Separate diagnostic. | Its sign mixes redundancy and synergy and does not provide a complete nonnegative or signed PID allocation by itself. The exact variable tuple and sign convention must be registered. |
| O-information | Companion. Separate system diagnostic. | It is symmetric in a named variable tuple and has no predictor-target allocation. The tuple must be registered. |
| Quantized continuous PID | Rejected for this estimand | The law is already categorical. Fitting a quantizer would add an unnecessary transform. |

The detailed CREBAIN fixture choice and its exact result are in
[`CREBAIN-DRONE-MGW-STUDY.md`](CREBAIN-DRONE-MGW-STUDY.md).

## GLD-MSD-007: continuous shared-exclusions PID

The continuous offline study uses the feature-gated experimental
restricted-domain functional and estimator of Ehrlich and colleagues. It is not the categorical MGW evaluator
with real-valued inputs. It is also not the general measure-theoretic construction
of Schick-Poland and colleagues.

Galadriel selects this route because the pinned evaluator exposes the named
functional, gauge, KSG constituents, and PID2 atom construction required by the
registered study. A successful `Pid2Report` retains experimental status,
assumptions, warnings, constituent reports, and atom reconstruction. Failure is a
typed `PidError` that aborts the study. There is no numeric fallback and no claim
that an error is a produced estimate. The study
fixes identity coordinates with no fitted preprocessing, both source gauges, the
target coordinate, row relation, and support declaration because those choices
are constitutive, not presentation details.

Quantization is deferred when the scientific target is a continuous law because
binning changes the estimand. Gaussian closed forms remain valuable oracles for
special laws but do not replace the selected functional on arbitrary eligible
continuous distributions. A kernel or neural PID would need its own defining
functional, estimator, tuning, and validation record.

No current result establishes a general continuous PID3 implementation, pointwise
certification, or field validity.

### Offline continuous-study resource choice

The offline justification path fixes one thread, one GiB, at most 1.2 billion
constituent pair-distance evaluations, and an operation hint of \(10^{10}\).
These limits were selected as a finite envelope that admits the registered study
fixtures and their separately counted KSG constituents. They are project resource
policy, not constants from the Ehrlich paper and not evidence that the study needs
that much work. Ambient pid-core defaults are rejected because they would make
host parallelism and generic ceilings part of the execution identity. Smaller
limits are preferable when a narrower registered study can prove admission.
Larger limits require a successor contract and denial-of-service review. The
preflight bounds counted work and memory categories. An independent scheduler or
platform deadline must bound elapsed wall time.

## GLD-MSD-008: advisory-only authority boundary

Galadriel does not fuse MI or PID into its accepted default. The reason is not
that the numbers are uninteresting. The reason is that their present contracts
do not define calibrated security, causal, control, or authorization semantics.

The selected design preserves the accepted default NIS, CUSUM, and
signed-correlation report. Research objects can be stored and audited beside it.
They cannot grant, revoke, restrict, deny, change trusted state, or issue a plant
command. At the exact [`ECO-019`](ECOSYSTEM-CONNECTIONS.md#haldir-connection)
cut, Haldir signed review commit
`c19f9011e4919a5bc67fab5f90d6c8eefed4455b` has no implemented PID adapter or
decision input. It documents only a prospective record-only seam. If such an
adapter is implemented, changes to PID record state must leave authorization,
`TrustedStateSnapshot`, and plant-command bytes identical for fixed admitted
authority input.

Alternatives that directly fuse a PID atom, use it as a deny signal, or invite an
operator to treat it as attack confidence are rejected. They would assign a
decision meaning that the estimator and present evidence do not support.

## CREBAIN exact-law fixture decisions

### Why uniform AND2 and AND3

The fixture enumerates all eight ordered binary source cells with equal mass. It
uses \(T_H=V\land R\) and \(T_V=V\land R\land A\). This law was selected as a
positive conformance control because every cell is present, source order is
observable, the target maps are closed, exact mutual-information identities are
available, and the categorical PID has nontrivial redundancy, uniqueness, and
synergy coordinates.

XOR would emphasize pure joint-only structure in its pairwise Shannon terms and
has a different, not generally narrower, MGW atom pattern. It already exists as a
separate Galadriel justification fixture and is not the producer-declared drone
target. COPY is essential as an axiomatic counterexample but is not the declared
drone-target map. OR is isomorphic to AND under bit complementation for the
balanced binary law and would add little independent coverage. A stochastic law
would be more realistic, but it would mix estimator uncertainty with the first
custody and adapter conformance rung. Those alternatives belong in later,
separately registered controls.

### Why the fixed thresholds

The 1 m visual-North, 50 m radar-East, and 1 m acoustic-Up thresholds are part of
the frozen producer fixture. They create two explicit latent cells on each axis
and make the source reconstruction predicate independently testable. Galadriel
does not claim that these are operational sensor tolerances. Changing them would
change the fixture and target law, so the consumer validates rather than tunes
them.

### Why eight repeats per cell

One row from each cell is sufficient to define the equal-weight categorical law.
Eight repeats retain the producer's fresh-engine, bounded-summary repetition and
make the 64-row artifact useful for custody and ordering tests. The repeats add no
independent information and no inferential precision. Collapsing to eight cells
would preserve the PID law but discard the producer repetition evidence. Treating
all 64 rows as independent flights is rejected.

### Why 80-digit Decimal arithmetic

The dependency-disjoint oracle uses 80-digit Decimal arithmetic to make its
rounding margin negligible relative to the binary64 comparison tolerance and to
retain readable exact-law diagnostics. Exact symbolic logarithms would give the
strongest algebraic representation for PID2 and are retained where compact.
Arbitrary-precision interval arithmetic would give outward enclosures and remains
a stronger future assurance route. Plain binary64 alone is rejected as the only
oracle because it would share the candidate evaluator's number format.

The Decimal route checks 66 averaged atom components, ten mutual informations,
and the named negative control. It does not check every retained pointwise atom
and it is not independent human replication.

### Why the categorical study uses a separate per-call budget

Every one of the nine primary and theorem-control evaluator calls uses one
explicit budget: 64 MiB, one nominal pair-distance unit, \(10^8\) operation-hint
units, and one thread. The discrete evaluator reports no continuous pair-distance
work, so the positive distance field is a schema-compatible ceiling rather than
a claim that a distance pass occurs. The 64 MiB and \(10^8\) values are finite
admission envelopes that comfortably admit the fixed 64-row laws. They are not
measured peaks, optimal limits, or paper-defined constants. One thread removes
ambient parallelism from the evidence route. The nine retained preflights prove
each call is individually admitted. They do not sum to an end-to-end memory or
wall-time bound. A future aggregate composition API should replace informal
whole-study reasoning when available.

## Twenty-lens review checklist

This checklist applies before a method or profile change is accepted.

| Lens | Required question | Fail-closed disposition |
|---:|---|---|
| 1 | Is the problem stated before the method? | Reject a method-first proposal. |
| 2 | Is the estimand named with units and coordinates? | Abstain until it is fixed. |
| 3 | Is method origin separated from project composition? | Correct the catalog and prose before release. |
| 4 | Are population, observation, and sampling assumptions explicit? | Return unavailable when a required declaration is absent. |
| 5 | Does support match the evaluator? | Route to a matching estimand. Do not add silent jitter. |
| 6 | Are transforms, scale, gauge, and source order fixed? | Bind them or abstain. |
| 7 | Is target construction independent of accepted result and authority output? | Reject leakage. |
| 8 | Are competing objects kept role-distinct? | Remove aliases and silent fallbacks. |
| 9 | Does each numeric profile state whether it is calibrated? | Label an uncalibrated profile and block deployment claims. |
| 10 | Are multiplicity, repeated looks, and dependence handled separately? | Do not present one-assessment control as stream control. |
| 11 | Are invalid, unavailable, resource-rejected, and unstable outcomes distinct? | Preserve typed status. |
| 12 | Do hostile controls isolate the intended predicate? | Redesign overlapping mutants. |
| 13 | Are estimator cardinality, memory, counted work, and threads preflighted, and is any wall-time deadline supplied independently by the execution platform? | Reject estimator work above its typed budget. Do not misstate a work estimate as an elapsed-time guarantee. |
| 14 | Are deterministic ordering and binary64 rules fixed? | Reject nondeterministic serialization or aggregation. |
| 15 | Are algebraic identities and signed negative values preserved? | Fail on reconstruction drift or clamping. |
| 16 | Is software identity separated from compatibility and attestation? | Narrow the claim and reconcile exact selected source. |
| 17 | Is the machine schema closed and candidate-bound? | Reject unknown, missing, or cross-document-inconsistent fields. |
| 18 | Is the authority path explicit? | Keep advisory evidence outside verdict and control. |
| 19 | Are evidence ceilings stated beside positive results? | Add the missing ceiling before publication. |
| 20 | Are alternatives, deferrals, owners, gates, and reopen conditions recorded? | Keep the decision open and do not imply closure. |

## Reopen conditions

Reopen a selected decision when any of these conditions occurs:

- The producer changes its coordinate, prior, lifecycle, or row relation.
- A representative frozen corpus shows material nonlinear dependence that signed
  Pearson misses.
- Field or high-fidelity replay evidence supports calibration of windows,
  thresholds, or repeated-look behavior.
- A competing method is evaluated on the same admitted rows, question, units,
  and failure policy.
- The pid-core functional, estimator, support contract, or software identity
  changes.
- A downstream consumer proposes any authority effect.
- A hostile test, mutation gate, schema gate, or exact-head qualification fails.

Reopening does not authorize silent replacement. It starts a new decision record,
new accepted profile identity, and new evidence cut.

## Primary references and local authorities

- Pearson, [“Note on regression and inheritance in the case of two parents,”](https://doi.org/10.1098/rspl.1895.0041)
  *Proceedings of the Royal Society of London* 58, 1895.
- Fisher, [“On the probable error of a coefficient of correlation deduced from a
  small sample,”](http://hdl.handle.net/2440/15169) *Metron* 1, 1921.
- Page, [“Continuous inspection schemes,”](https://doi.org/10.1093/biomet/41.1-2.100)
  *Biometrika* 41, 1954.
- Roberts, [“Control chart tests based on geometric moving averages,”](https://doi.org/10.1080/00401706.1959.10489860)
  *Technometrics* 1, 1959.
- Wald, [“Sequential tests of statistical hypotheses,”](https://doi.org/10.1214/aoms/1177731118)
  *Annals of Mathematical Statistics* 16, 1945.
- Willsky and Jones, [“A generalized likelihood ratio approach to the detection
  and estimation of jumps in linear systems,”](https://doi.org/10.1109/TAC.1976.1101146)
  *IEEE Transactions on Automatic Control* 21, 1976.
- Bonferroni, “Teoria statistica delle classi e calcolo delle probabilità,”
  *Pubblicazioni del R. Istituto Superiore di Scienze Economiche e Commerciali
  di Firenze* 8, 1936.
- Šidák, [“Rectangular confidence regions for the means of multivariate normal
  distributions,”](https://doi.org/10.1080/01621459.1967.10482935) *Journal of
  the American Statistical Association* 62, 1967.
- Holm, [“A simple sequentially rejective multiple test procedure,”](https://doi.org/10.2307/4615733)
  *Scandinavian Journal of Statistics* 6, 1979.
- Hochberg, [“A sharper Bonferroni procedure for multiple tests of
  significance,”](https://doi.org/10.1093/biomet/75.4.800) *Biometrika* 75, 1988.
- Kraskov, Stögbauer, and Grassberger, [“Estimating mutual information,”](https://doi.org/10.1103/PhysRevE.69.066138)
  *Physical Review E* 69, 066138, 2004.
- Gretton, Bousquet, Smola, and Schölkopf, [“Measuring statistical dependence
  with Hilbert–Schmidt norms,”](https://doi.org/10.1007/11564089_7) in
  *Algorithmic Learning Theory*, 2005.
- Székely, Rizzo, and Bakirov, [“Measuring and testing dependence by correlation
  of distances,”](https://doi.org/10.1214/009053607000000505) *Annals of
  Statistics* 35, 2007.
- Williams and Beer, [“Nonnegative decomposition of multivariate
  information,”](https://arxiv.org/abs/1004.2515) 2010.
- Bertschinger, Rauh, Olbrich, Jost, and Ay, [“Quantifying unique
  information,”](https://doi.org/10.3390/e16042161) *Entropy* 16, 2014.
- Makkeh, Gutknecht, and Wibral, [“Introducing a differentiable measure of
  pointwise shared information,”](https://doi.org/10.1103/PhysRevE.103.032149)
  *Physical Review E* 103, 032149, 2021.
- Schick-Poland, Makkeh, Gutknecht, Wollstadt, Sturm, and Wibral,
  [“A partial information decomposition for discrete and continuous variables,”](https://arxiv.org/abs/2106.12393)
  2021.
- Ehrlich, Schick-Poland, Makkeh, Lanfermann, Wollstadt, and Wibral,
  [“Partial information decomposition for continuous variables based on shared
  exclusions,”](https://doi.org/10.1103/PhysRevE.110.014115) *Physical Review E*
  110, 014115, 2024.
- [`CONFIGURATION-CONTRACT.md`](CONFIGURATION-CONTRACT.md) for exact accepted
  values and resource bounds.
- [`STATISTICAL-CONTRACT.md`](STATISTICAL-CONTRACT.md) for exact output and failure
  semantics.
- [`CREBAIN-DRONE-MGW-STUDY.md`](CREBAIN-DRONE-MGW-STUDY.md) for the exact-law
  categorical case.
- [`RELATED-WORK.md`](RELATED-WORK.md) for cross-layer alternatives and benchmark
  requirements.
