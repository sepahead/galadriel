# CREBAIN drone categorical shared-exclusions study

## Status and claim boundary

This document specifies one grounded, executable offline study connecting a
physically parameterized **synthetic** three-sensor fixture in CREBAIN to
Galadriel's exact pinned categorical partial information decomposition (PID)
evaluator.

It is a **deterministic categorical conformance law**, not a statistical study of
recorded flights. Its information-theoretic object is the uniform canonical
AND2/AND3 logic-gate law. It establishes that the declared row definition, source
order, synthetic latent-truth targets, fixture custody, categorical
Makkeh–Gutknecht–Wibral (MGW) shared-exclusions evaluation, and algebraic
reconstruction agree on that one bounded law. CREBAIN generated each repeated row
with a fresh engine, but the compact artifact retains only a bounded fusion summary.
The repeats therefore test bounded-summary fresh-instance reproducibility—not
complete software-state isolation—and create neither confidence intervals nor a
sample of 64 independent flights.

PID remains advisory research evidence. It does not enter `FusedVerdict`, classify
an attack, or determine sensor trust. For fixed admitted authority input, PID
record state leaves Haldir authorization, trusted-state policy, and plant-command
outputs identical. The audit record may vary. This software-path contract makes no
claim about later operator behavior.

[![Synthetic latent ENU targets, ordered pre-fusion sensor variables, exact fixture validation, categorical MGW evaluation, algebra checks, and the Haldir record-only firewall](../assets/crebain-drone-mgw-pipeline.svg)](../assets/crebain-drone-mgw-pipeline.svg)

**System and estimand pipeline.** A preregistered synthetic East–North–Up (ENU)
cell parameterizes the row. The producer constructs sensor-observation objects and
source symbols, then derives the target from the latent cell, and only then runs
fusion. The target calculation does not read serialized source fields, sensor
projections, fusion output, a Galadriel verdict, or a PID result. The target is
therefore dataflow-independent of those objects and external to fusion, Galadriel,
and PID, but it is neither temporally prior to sensor-object construction nor
producer-independent field ground truth. Three pre-fusion observations define the
ordered categorical source tuple. The compact row retains one prior timestamp, one
observation timestamp, a unique episode identifier, and a six-field fusion summary.
It does not retain per-sensor clocks, complete engine state, or a replayable fusion
result. Galadriel checks the exact fixture and manifest digests, reconstructs each
source and target from the declared geometry, and calls only the reviewed, budgeted
pid-core PID2/PID3 routes. The bottom barrier combines Galadriel's implemented
advisory-only boundary with a documented Haldir non-edge:
PID cannot affect a verdict, authorization decision, or plant command.

[Open the system figure at full size.](../assets/crebain-drone-mgw-pipeline.svg)

## 1. The problem before the method

Galadriel's operational question is whether admitted sensors remain consistent.
Normalized innovation squared (NIS), the selected two-arm CUSUM, lifecycle evidence, and
signed correlation are designed for that question. PID answers a different
question:

> Given a target defined independently of fusion and PID, and an ordered set of
> source variables, how does one named PID functional allocate target information
> into redundant, unique, and synergistic coordinates?

PID is useful only if this allocation is itself scientifically relevant. A joint
statistic can detect a multivariate dependency without supplying a PID allocation.
For example,

\[
Q = I(S_1,S_2;T)-\max\{I(S_1;T),I(S_2;T)\}
\]

can reveal joint-only structure, but `Q` is a project-defined contrast rather than
a PID synergy atom. Conversely, pairwise mutual information can detect nonlinear
association but cannot allocate one target's information over a multivariate
redundancy lattice. PID earns its complexity here because the allocation—rather
than detection alone—is the registered question.

[![Question-first method selection, exact PID2 component chart, interpretation firewall, and eligibility matrix](../assets/crebain-mgw-method-map.svg)](../assets/crebain-mgw-method-map.svg)

**Method selection and exact primary result.** The upper row separates operational
consistency, pairwise continuous dependence, and target-information allocation as
parallel questions. The `OR` badges are a choice of estimand, not an escalation
or fallback chain. The middle chart shows the exact categorical MGW PID2
components. The lower matrix states applicability for this fixture, not a
universal method ranking, and gives `I_min`, BROJA, co-/O-information, NIS,
the two-arm CUSUM, and signed correlation separate rows. None of those objects is
evaluated by this fixture. KSG and the continuous Ehrlich construction are
ineligible and are not executed because these rows form an atomic categorical
law. Infomorphic objectives
retain their own downstream meaning.

[Open the method figure at full size.](../assets/crebain-mgw-method-map.svg)

### Why this conformance law was selected

The first executable bridge needs a law whose custody, source order, target map,
and algebra can be checked without statistical ambiguity. The uniform binary
AND2/AND3 law meets that need. All eight ordered source cells are present. Its
target maps are closed. Its mutual informations have compact analytic forms. Its
PID contains nontrivial redundant, unique, and synergistic coordinates.

XOR would make joint-only structure especially visible in its pairwise Shannon
terms, but its MGW atom pattern is different rather than generally narrower. It
already exists as a separate Galadriel justification fixture and is not the
producer-declared drone-target map. COPY is retained as an axiomatic counterexample rather
than used as the drone-target map. Balanced OR is isomorphic to balanced AND
under bit complementation. A stochastic or noisy law would be more realistic,
but it would mix estimator uncertainty with the first custody and adapter check.
The exact-law fixture is therefore the analytic conformance rung. It is not the grounding
rung.

The 1 m, 50 m, and 1 m thresholds are immutable producer coordinates. They form
two explicit latent cells on each axis and make source reconstruction testable.
They are not proposed operational sensor tolerances. Eight repeats per cell keep
the producer's fresh-engine bounded-summary evidence and create hostile ordering
controls. They add no independent units and no information-theoretic precision.

The complete selection record, alternatives, and reopen conditions are in
[`METHOD-SELECTION-DECISIONS.md`](METHOD-SELECTION-DECISIONS.md).

## 2. Frozen synthetic row contract

The canonical frame is `map_enu`, with truth position

\[
\mathbf p_{\mathrm{truth}}=(E,N,U).
\]

The ordered pre-fusion sources are synthetic threshold symbols:

\[
\begin{aligned}
V &= \mathbf 1[N_{\mathrm{visual}}\le 1\ \mathrm m],\\
R &= \mathbf 1[E_{\mathrm{radar}}\le 50\ \mathrm m],\\
A &= \mathbf 1[U_{\mathrm{acoustic}}\le 1\ \mathrm m].
\end{aligned}
\]

The source order is permanently `(V,R,A)`. Neither a fused verdict, a PID output,
nor a target-derived feature is a source. After constructing the sensor-observation
objects and source symbols, the same synthetic producer derives the targets from
the latent cell before fusion, without reading those objects or any projection:

\[
T_H=\mathbf 1[E\le50\ \land\ N\le1],\qquad
T_V=T_H\,\mathbf 1[U\le1].
\]

`T_H` is horizontal incursion and `T_V` is volumetric incursion. This construction
prevents leakage from Galadriel's accepted result. It does not turn synthetic
producer state into independently measured field truth.

Every retained row has:

- A unique episode ID.
- The common prior at 1,000 ms.
- One row-level observation timestamp at 1,100 ms.
- Pre-fusion synthetic measurements, latent ENU coordinates, sources, and targets.
- A six-field fusion summary: common-projection-prior identifier, input count,
  legacy `projection_count`, expected count, degraded flag, and truncated flag.
- Values requiring input count three, legacy `projection_count` three, expected
  count three, common-projection-prior identifier two, and both flags false.

The legacy name is misleading. CREBAIN populates `projection_count` from the
number of admitted PID observations, so its value three does **not** prove that
three non-`None` consistency projections existed. The common-prior identifier
proves that at least one projection existed and that every projection that was
present used prior two. The fixture does not prove that every admitted observation
carried a projection.

The pinned CREBAIN producer says that it instantiated a fresh engine for each row
and synchronized all three source observations. The compact fixture itself cannot
reconstruct full engine state, independently prove per-sensor timing, or replay the
complete fusion result. Claims here stop at row-window and bounded-summary custody.

The exact producer object is CREBAIN commit
`6ef60fabbf8c8a8008e7a77304d3e095b6b9e91d`, path
`src-tauri/tests/fixtures/crebain_drone_mgw_v1.json`, 64,218 bytes, SHA-256
`82a837415b56c3646386a5c3e6fe28a492906c164edc461249bab7844aa4ebda`.
Its recursively key-sorted analysis-manifest SHA-256 is
`4b0381beee855e7d624066ab04cfdc07920c6182951315b65ba48d99c1e86f90`.

### Append-only producer-source errata

The fixture and preregistration are immutable evidence, so Galadriel does not edit
their bytes. Instead, the study output carries a typed three-entry errata receipt.
It first matches each frozen literal, then attaches the reviewed correction and its
impact. A mismatch fails closed.

| Frozen surface | Frozen literal or field | Reviewed correction | Consequence |
|---|---|---|---|
| Analysis manifest `/target_origin` | “externally generated fixture truth in canonical ENU before sensor projection and before fusion” | CREBAIN revision `6ef60f…`, `src-tauri/src/sensor_fusion.rs:7618-7649`, constructs sensor objects and source symbols before deriving the target. Target derivation still reads neither serialized source fields, projections, fusion, verdict, nor PID. | Corrects temporal and producer-independence wording. The categorical law and numbers do not change. |
| Analysis manifest `/method_exclusions/nis_and_correlation` | “separate operational association diagnostics” | Galadriel's magnitude lane has two distinct objects: NIS and a two-arm CUSUM. On the fusion core's `dof=3` route, the CUSUM lower arm is inert. Other admitted degrees of freedom retain the general recurrence. Signed Pearson correlation is a third, directional association object. None is evaluated here. | Restores the omitted CUSUM object. No PID result changes. |
| Every row's `fusion_receipt` | `projection_count=3`, `common_projection_prior_id=2` | CREBAIN revision `6ef60f…`, `src-tauri/src/sensor_fusion.rs:7664-7707`, derives the legacy count from admitted observations. The prior field proves at least one projection and prior-two agreement only among projections that are present. | Narrows custody to a bounded three-observation summary. It does not prove three projections or full fusion replay. |

This is append-only provenance, not permission to reinterpret arbitrary frozen
fields. Source symbols and targets used by PID do not depend on the legacy fusion
summary fields, so these corrections leave the declared empirical laws and all PID
values unchanged.

The 64 rows implement the equal-weight finite law

\[
p(V=v,R=r,A=a)=\frac18,
\quad v,r,a\in\{0,1\},
\]

with each of the eight cells repeated eight times. Collapsing repeated categorical
rows leaves the same empirical probability mass function. Repetition checks the
retained fresh-instance summaries. It adds no information-theoretic or statistical
precision and does not establish unobserved state isolation.

## 3. Exact MGW object and equations

For an observed source realization \(s\), target realization \(t\), a source set
\(a\), and an antichain \(\alpha\), define

\[
E_a(s)=\bigcap_{i\in a}\{S_i=s_i\},\qquad
U_\alpha(s)=\bigcup_{a\in\alpha}E_a(s).
\]

The MGW pointwise informative and misinformative shared-exclusions terms are

\[
i_{\cap}^{\mathrm{sx},+}(t:\alpha)=-\log p\!\left(U_\alpha(s)\right),
\]

\[
i_{\cap}^{\mathrm{sx},-}(t:\alpha)=
\log\frac{p(T=t)}{p\!\left(T=t, U_\alpha(s)\right)}.
\]

Their probability-weighted averages are cumulative lattice quantities. Möbius
inversion on the antichain order gives partial atoms:

\[
I_{\cap}^{\mathrm{sx},\pm}(\alpha;T)
=\sum_{\beta\preceq\alpha}\Pi_\beta^{\pm},
\qquad
\Pi_\beta=\Pi_\beta^+-\Pi_\beta^-.
\]

All logarithms are natural. Every reported quantity is in nats. In exact
arithmetic, informative and misinformative atoms are non-negative by construction,
but their signed difference may be negative. Binary64 values at a theoretical zero
remain subject to the declared numerical tolerance. Galadriel preserves negative
net atoms and never clamps them.

The functional is the categorical pointwise shared-exclusions construction of
Makkeh, Gutknecht, and Wibral, not a generic “Wibral PID.” The Williams–Beer work
supplies the original antichain lattice. Galadriel does not thereby evaluate the
Williams–Beer `I_min` functional. Gutknecht, Wibral, and Makkeh supply a
role-distinct part-whole/formal-logic derivation. The continuous construction of
Ehrlich and colleagues and the general construction of Schick-Poland and
colleagues are related but different objects.

### Axiomatic scope

Successful evaluation does not settle which redundancy axioms should be preferred.
For the independent two-bit COPY distribution, the identity criterion discussed by
[Harder, Salge, and Polani](https://doi.org/10.1103/PhysRevE.87.012130) requires
zero redundancy, whereas categorical shared exclusions assigns \(\ln(4/3)\) nats.
That is a substantive normative difference, not a numerical defect to hide.
[Rauh and colleagues](https://doi.org/10.1109/ISIT.2014.6875230) show that natural
multivariate desiderata involving identity and local positivity cannot all be
assumed to coexist on the Williams–Beer lattice.
[Lyu, Clark, and Raviv](https://doi.org/10.1103/8rzp-w5z1) further document
consistency limits and descriptor collisions in multivariate PID. This AND-law
fixture neither adjudicates those choices nor converts successful PID3 computation
into a general multivariate assurance result.

### Why MGW was selected for this registered allocation

The question asks for pointwise and averaged target-information allocation over
named ordered categorical sources. MGW shared exclusions directly defines that
object on a finite atomic law. It retains informative, misinformative, and signed
net coordinates and requires no fitted quantizer or continuous-support model.

This is a functional selection, not a claim that MGW is uniquely correct.
`I_min` is a different Williams–Beer redundancy functional. BROJA defines a
different two-source optimization object and does not supply this PID3 lattice.
Co-information and O-information are role-distinct diagnostics that require an
exact variable tuple and sign convention. The project-defined joint contrast
`Q` can detect joint-only structure but is not a PID atom allocation. Silent
fallback to any of these alternatives would change the registered question. The
selected evaluator therefore returns an error and aborts the study on failure.
It does not substitute another functional or emit a numeric sentinel.

The continuous Ehrlich route is also rejected for this fixture because repeated
binary rows have atomic support. Adding noise would change the estimand. Fitting
a quantizer would add a transform to data that is already categorical.

## 4. Exact questions

| Question | Ordered sources | Target dataflow-independent of projection/fusion/verdict/PID | Actual route | Claim tier |
|---|---|---|---|---|
| Horizontal allocation | visual `V`, radar `R` | `T_H = V R` on this declared law | `pid_core::stable::categorical::discrete_sxpid2_with_budget` | primary deterministic conformance |
| Volumetric allocation | visual `V`, radar `R`, acoustic `A` | `T_V = V R A` on this declared law | `pid_core::stable::categorical::discrete_sxpid3_with_budget` | Exploratory. Not 108-coordinate assurance closure. |

Two identities are intentionally retained:

- CREBAIN's immutable producer manifest preregistered pid-rs revision
  `1cd2424f7967e1752dcc8e53859e8fdad3566f51` and the unbudgeted
  `discrete_sxpid2` / `discrete_sxpid3` route names.
- Galadriel actually executes pid-core 0.9.0 at clean, remote-reachable,
  read-only revision `bc3aa80fb6025e709c2906a08bce25a4fac40578` through the
  explicit `*_with_budget` routes.

This is a documented post-preregistration evaluator adaptation, not a rewrite of
the frozen manifest. Review found the same categorical MGW functional, empirical
probability laws, ordered sources, targets, lattice coordinates, natural-log
units, signed components, and inclusion of pointwise output. Every one of the nine
executed evaluator/control calls is separately preflighted against Galadriel's
fixed resource ceiling. Per-call admission is not a proof of aggregate peak memory
for the whole study, retained results, or serialization. No alternative method is
substituted if a pid-core call fails.

## 5. Closed-form mutual-information checks

Let \(h(p)=-p\log p-(1-p)\log(1-p)\). Since
\(P(T_H=1)=1/4\),

\[
I(V,R;T_H)=h(1/4)=0.562335144619,
\]

\[
I(V;T_H)=I(R;T_H)=h(1/4)-\tfrac12\log2
=0.215761554339.
\]

Since \(P(T_V=1)=1/8\),

\[
I(V,R,A;T_V)=h(1/8)=0.376770161256,
\]

\[
I(V;T_V)=h(1/8)-\tfrac12h(1/4)=0.095602588947,
\]

and every two-source subset has

\[
I(V,R;T_V)=h(1/8)-\tfrac14\log2=0.203483366116.
\]

The implementation checks these expressions directly, all PID2 self-redundancy
and joint identities, and all seven PID3 down-set identities.

## 6. Primary PID2 result

For \(V,R\overset{\mathrm{ind}}{\sim}\operatorname{Bernoulli}(1/2)\) and
\(T_H=V\land R\), the exact MGW components are

\[
\begin{aligned}
\Pi_{\mathrm{red}}^+ &= \ln\frac43,
&\Pi_{\mathrm{red}}^- &= \frac12\ln\frac32,
&\Pi_{\mathrm{red}} &= \ln\frac43-\frac12\ln\frac32,\\
\Pi_{V}^+=\Pi_R^+ &= \ln\frac32,
&\Pi_{V}^-=\Pi_R^- &= \frac14\ln 3,
&\Pi_V=\Pi_R &= \ln\frac32-\frac14\ln 3,\\
\Pi_{\mathrm{syn}}^+ &= \ln\frac43,
&\Pi_{\mathrm{syn}}^- &= \frac14\ln\frac43,
&\Pi_{\mathrm{syn}} &= \frac34\ln\frac43.
\end{aligned}
\]

Consequently,

\[
\Pi_{\mathrm{red}}+\Pi_V+\Pi_R+\Pi_{\mathrm{syn}}
=h\!\left(\frac14\right)
=-\frac14\ln\frac14-\frac34\ln\frac34
=\ln4-\frac34\ln3.
\]

| MGW coordinate | Informative \(\Pi^+\) | Misinformative \(\Pi^-\) | Net \(\Pi\) |
|---|---:|---:|---:|
| Redundancy `{{V},{R}}` | 0.287682072 | 0.202732554 | 0.084949518 |
| Unique visual `{{V}}` | 0.405465108 | 0.274653072 | 0.130812036 |
| Unique radar `{{R}}` | 0.405465108 | 0.274653072 | 0.130812036 |
| Synergy `{{V,R}}` | 0.287682072 | 0.071920518 | 0.215761554 |

The four net atoms sum to
\(I(V,R;T_H)=h(1/4)=0.562335145\) nats. Under categorical
MGW, the largest net coordinate is synergy. This says that the selected functional
allocates a substantial part of the target information to the joint source event.
It does **not** say that a causal “synergy mechanism” exists, that either sensor is
trustworthy, or that an attack occurred. A joint contrast can detect the AND
structure. PID adds the measure-relative allocation.

Because the finite law is symmetric in `V` and `R`, swapping only their labels can
leave the PID2 numbers unchanged. Numerical equality therefore cannot protect
source identity. Exact fixture bytes, declared-geometry reconstruction,
source-order fields, and the row-order digest provide that protection.

## 7. Exploratory PID3 result

The antichain notation concatenates source collections. For example, `{V}{R,A}`
means the antichain containing the singleton visual collection and the joint
radar–acoustic collection.

| Antichain coordinate | Informative \(\Pi^+\) | Misinformative \(\Pi^-\) | Net \(\Pi\) |
|---|---:|---:|---:|
| `{V}` | 0.223143551 | 0.191559609 | 0.031583942 |
| `{R}` | 0.223143551 | 0.191559609 | 0.031583942 |
| `{A}` | 0.223143551 | 0.191559609 | 0.031583942 |
| `{V,R}` | 0.117783036 | 0.094851777 | 0.022931259 |
| `{V,A}` | 0.117783036 | 0.094851777 | 0.022931259 |
| `{R,A}` | 0.117783036 | 0.094851777 | 0.022931259 |
| `{V,R,A}` | 0.169899037 | 0.084949518 | 0.084949518 |
| `{V}{R}` | 0.154150680 | 0.133219808 | 0.020930872 |
| `{V}{A}` | 0.154150680 | 0.133219808 | 0.020930872 |
| `{V}{R,A}` | 0.028170877 | 0.023932357 | 0.004238520 |
| `{R}{A}` | 0.154150680 | 0.133219808 | 0.020930872 |
| `{R}{V,A}` | 0.028170877 | 0.023932357 | 0.004238520 |
| `{V,R}{A}` | 0.028170877 | 0.023932357 | 0.004238520 |
| `{V,R}{V,A}` | 0.064538521 | 0.053647704 | 0.010890817 |
| `{V,R}{R,A}` | 0.064538521 | 0.053647704 | 0.010890817 |
| `{V,A}{R,A}` | 0.064538521 | 0.053647704 | 0.010890817 |
| `{V}{R}{A}` | 0.133531393 | 0.115613010 | 0.017918383 |
| `{V,R}{V,A}{R,A}` | 0.012651118 | 0.010475087 | 0.002176030 |

The table lists each of the 18 canonical antichains exactly once. Together they
reconstruct every non-empty source-subset mutual information. The
largest absolute observed reconstruction error is
\(1.11\times10^{-16}\) nats. A separate 80-digit implementation evaluates the
MGW event-union equations and solves a separately constructed Möbius incidence
system without importing or executing pid-rs. It compares exactly 66
**empirical-PMF-averaged atom components**—\((4+18)\times3\)—and ten subset mutual
informations. The largest observed Rust/Decimal atom difference is below
\(1.97\times10^{-16}\) nats. The production result also retains pointwise PID2 and
PID3 outputs and internally reconstructs their weighted averages, but the Decimal
route does not separately recompute those pointwise records. This is separate
computational corroboration, not independent human peer review and not a general
validation theorem.

The dependency-disjoint averaged-output route is retained as
`repo_work/check_crebain_mgw_decimal_oracle.py`. It uses only the Python standard
library, 80-digit `Decimal` arithmetic, the exact fixture bytes, explicit event
unions, and a separately constructed antichain incidence order. Its canonical
60-place result has SHA-256
`5aa7a1d92d4aaad9c056ede8a75bdc40abc1fa76634b02bba20aac5cc3913c19`.
Reproduce it with:

```text
python3 -B -E -s -S repo_work/check_crebain_mgw_decimal_oracle.py
```

Compare the separately computed averaged values with the actual Rust study
object with:

```text
cargo run --locked -p galadriel-justify --bin galadriel-crebain-mgw \
  > /tmp/galadriel-crebain-mgw-v2.json
python3 -B -E -s -S repo_work/check_crebain_mgw_decimal_oracle.py \
  --rust-json /tmp/galadriel-crebain-mgw-v2.json
```

Before comparing the 66 averaged components and ten mutual informations, the
comparison binds the exact Rust input bytes, study/fixture/producer identifiers,
selected pid-core version, revision, and source-state coordinates, source order,
targets, method-object order, selected estimand-graph identifiers, cardinalities,
and validation flags, interpretation/algebra pass flags, the nine-call ledger's
cardinality/pass flags, and the negative control. It does not independently
validate every graph label, resource estimate, method description, software-
identity field, or pointwise value. The closed schema and Rust semantic guards
cover those separate obligations.

The complete JSON wire shape is separately governed by the closed Draft 2020-12
[`crebain-drone-mgw-study-v2.schema.json`](../crates/galadriel-justify/schemas/crebain-drone-mgw-study-v2.schema.json).
Every object is closed, every declared property is required, and cardinalities
and enum spellings are explicit. Its standard-library checker also rejects
duplicate keys, non-finite or oversized numeric values, unknown schema keywords,
unresolved references, and disagreement with the serialized schema receipt:

```text
python3 -B -E -s -S repo_work/check_crebain_mgw_schema.py \
  /tmp/galadriel-crebain-mgw-v2.json
```

The schema proves wire-shape conformance. It does not replace Rust semantic,
custody, algebra, resource, or interpretation guards, nor the separate Decimal
numerical route.

Exact candidate qualification composes the binary, schema, and Decimal checks
without a shell pipeline and emits a retained receipt containing the exact Rust
JSON digest and byte count:

```text
python3 -B -E -s -S repo_work/check_crebain_mgw_candidate.py
```

That receipt does not publish the raw JSON bytes. The eventual publication
bundle must preserve those bytes under the exact candidate/toolchain identity.

The stable three-source evaluator makes this bounded fixture possible. It does not
close pid-rs's separate open 108-coordinate formal-assurance program:

\[
18\ \text{antichains}\times
2\ \text{levels (cumulative and atom)}\times
3\ \text{components (informative, misinformative, net)}=108.
\]

Those are averaged cumulatives and averaged atoms, not “108 signed coordinates.”
The defense should present PID3 as exploratory unless that wider assurance and
qualified review are complete before thesis freeze.

## 8. Fixed-source informative invariant

For fixed source law \(p(S)\), the pointwise informative term depends only on
source-event union probabilities. Averaging over the target collapses back to the
same source marginal. Möbius inversion is linear. Therefore, changing only the
target relation while retaining the exact source rows preserves every informative
partial atom. Misinformative and net atoms may change.

The implementation rotates each target column by one row, recomputes PID2 and
PID3, and checks all 22 informative atoms. The maximum observed difference is
zero in binary64. The rotated PID3 control also produces a minimum net atom of
\(-0.02148473827972453\) nats at singleton acoustic antichain `{A}` (bit mask
`[4]`). The value is retained, not clamped. This proves that the exercised path
can carry a legitimate negative net atom. It is not a claim about the primary
AND3 table, a permutation p-value, a null distribution, or scientific novelty.

## 9. Eligibility matrix: no aliases and no fallbacks

Applicability is local to this exact fixture. “Inapplicable” means the declared
support does not meet the method's contract. “Not requested” means a potentially
eligible but separately defined object was outside the preregistered question.
“Not evaluated” means availability elsewhere creates no result here. A failure in
one row never selects another row.

| Object | Kind | Execution here | Output and distinct role | Boundary |
|---|---|---|---|---|
| Categorical MGW shared exclusions | paper-defined functional | produced | pointwise cumulatives and Möbius atoms, plus empirical-PMF averages | The registered allocation. Not synonymous with pid-core software. |
| pid-core raw-row MGW PID2 plug-in | evaluator | produced, primary | pointwise and averaged four-atom result on ordered `(V,R)` | Exact `discrete_sxpid2_with_budget` route. No fallback. |
| pid-core raw-row MGW PID3 plug-in | evaluator | produced, exploratory | pointwise and averaged 18-antichain result on ordered `(V,R,A)` | Exact `discrete_sxpid3_with_budget` route. Does not close 108-coordinate assurance. |
| Williams–Beer `I_min` | different categorical functional | not requested | another redundancy definition and therefore another atom allocation | Comparator only. Never an MGW alias or fallback. |
| BROJA | different two-source functional | not requested | unique information from a constrained family of distributions | Requires external implementation identity, feasibility, and residual reporting. No PID3 route is implied. |
| Schick-Poland general PID | general measure-theoretic construction | not evaluated | a construction spanning discrete and continuous variables | neither MGW nor Ehrlich is presented as its generic evaluator |
| Continuous Ehrlich shared exclusions | continuous functional | inapplicable | continuous redundancy and derived PID2 atoms at a fixed source gauge | the repeated atomic law has the wrong support |
| Ehrlich nearest-neighbor route | estimator for the continuous functional | inapplicable | continuous shared-exclusions estimate with KSG MI constituents | Support fails. No noise or quantization “repair” is substituted. |
| Pairwise KSG MI | continuous estimator, not PID | inapplicable | Symmetric pairwise dependence. Its finite-sample estimate may be signed, but that sign is not correlation direction and it allocates no PID atoms. | Repeated atomic support is ineligible. Added noise changes the estimand. |
| Co-information | invariant/diagnostic | not requested | signed interaction under a declared sign convention | not a PID atom |
| O-information | system-level diagnostic | not requested | balance of redundancy- and synergy-dominated high-order dependence | not a redundancy-lattice allocation |
| NIS | operational diagnostic | not evaluated | per-channel innovation magnitude under a separate covariance/lifecycle contract | this fixture contains no lifecycle-qualified NIS report |
| Two-arm CUSUM | operational sequential diagnostic | not evaluated | Persistent sequential evidence derived in Galadriel's magnitude lane. On the fusion core's `dof=3` route only the upper arm can move. Other admitted degrees of freedom retain the general recurrence. [Page (1954)](https://doi.org/10.1093/biomet/41.1-2.100) supplies the sequential-change foundation. | Galadriel's two-arm composition/lifecycle contract is project-defined and distinct from NIS, correlation, MI, and PID. This fixture contains no CUSUM state or alarm report. |
| Signed Pearson correlation | operational association diagnostic | not evaluated | Direction-sensitive linear consistency under a separate lifecycle contract. | This fixture contains no qualified correlation report. PID cannot override it. |
| PNAS bivariate infomorphic objective | downstream objective composition | not evaluated | two-input learning objective composed from named PID atoms | an objective does not define a PID functional or evaluator |
| ICLR three-input-class objective | downstream objective composition | not evaluated | role-distinct three-input-class local-objective design | not evidence for this fixture and not the PNAS object |

The BROJA contribution elsewhere in the thesis need not be discarded. A
model-family Blackwell/garbling argument and its resulting closed-form comparator
can remain a distinct analytical result. It must not be generalized into a claim
that BROJA equals minimum-mutual-information PID outside the proved family, and it
must not be used as an MGW fallback. Likewise, NIS, the selected two-arm CUSUM, and signed
correlation remain three distinct Galadriel operational objects. This exact-law
PID run evaluates none of them and cannot strengthen or weaken their verdict.

## 10. Authority and ecosystem effect

### Galadriel

PID gives Galadriel a defensible offline answer to a target-allocation question
that NIS, the selected two-arm CUSUM, signed correlation, and pairwise MI do not answer. It
also supplies a strong exact-law hostile control for source/target lineage and
lattice algebra.
It does not strengthen an operational verdict merely by being more complex.

The new evaluator is a standalone `galadriel-justify` binary:

```text
cargo run --locked -p galadriel-justify --bin galadriel-crebain-mgw
cargo run --locked -p galadriel-justify --bin galadriel-crebain-mgw -- --format markdown
```

The default JSON is the schema-defined machine-readable study object. The Markdown
view is a human rendering. Neither is yet a publication bundle: a citable execution
still needs the exact Galadriel commit/tree, toolchain, build profile, executable
digest, host identity, and preserved output bytes. The per-call resource ledger is
also not an aggregate peak-memory proof for the whole process.

### CREBAIN

CREBAIN supplies the physically parameterized synthetic rows. For each factorial
cell it retains a fresh episode identifier, row timestamps, three pre-fusion
measurements, latent coordinates, categorical variables, and a bounded six-field
fusion summary. It does not retain a complete fusion replay or prove isolation of
unserialized engine state. CREBAIN does not run PID, consume PID, or accept
Galadriel conclusions. The relationship is an offline fixture edge, not a Cargo
dependency or live feedback loop.

### Haldir

Haldir may eventually record a versioned advisory evidence reference for audit.
That proposed edge is **record-only**, including for unfavorable or unavailable
PID results. For every Haldir input state \(x\) and PID evidence record \(e\), the
required noninterference contract is

\[
\operatorname{Authorize}(x,e)=\operatorname{Authorize}(x),\qquad
\operatorname{TrustedState}(x,e)=\operatorname{TrustedState}(x),\qquad
\operatorname{PlantCommand}(x,e)=\operatorname{PlantCommand}(x).
\]

The audit-record projection may vary with (e). This contract covers the software
decision path, not later operator behavior. A different future Haldir policy would
be a new integration, not this record path, and would require separate admission
and qualification. There is no current runtime PID route into Haldir.

### Prisoma

Prisoma remains a prospective offline consumer and method-selection authority.
Its provenance/estimand graph should identify this exact categorical law as one
consumer question while keeping MGW, `I_min`, BROJA, KSG, continuous Ehrlich,
invariants, and infomorphic objectives distinct. Shared use of pid-rs does not
constitute independent implementation replication.

## 11. Evidence ladder toward reality

The exact fixture answers a software-and-mathematics question. It does not answer
field-performance questions. Advancement requires separate evidence cuts:

1. **Exact finite law:** current 8-cell synthetic fixture, declared-geometry
   reconstruction, bounded-summary custody, exact MGW outputs, and
   algebraic/80-digit controls.
2. **Stochastic simulator:** physically plausible sensor noise, bias, occlusion,
   latency, association failures, and platform dynamics. Independent episodes and
   external ground truth.
3. **Software in the loop:** flight-stack timing, realistic message ordering,
   dropouts, coordinate transforms, and episode boundaries.
4. **Hardware in the loop:** actual sensor drivers, clocks, calibration drift,
   compute budgets, and restart behavior.
5. **Recorded replay:** immutable multi-flight datasets with calibration/train,
   validation, and evaluation episodes separated before analysis.
6. **Field study:** preregistered operational scenarios, safety review, human
   oversight, missingness accounting, and independent replication.

Success at one level does not promote the next. Frames within one flight are
dependent and never become independent samples by being numerous. Splits,
permutations, bootstraps, and uncertainty summaries must operate at the episode or
mission unit appropriate to the registered target.

If continuous scores are categorized for MGW, the categorizer must be a declared
physical symbol or fitted on separate calibration episodes and then frozen. The
result is a categorical or quantized estimand—not continuous PID. Continuous
Ehrlich PID is eligible only for an independently justified continuous tuple law,
fixed source gauge, and supported estimator regime.

## 12. Twenty-lens hostile review

| Lens | Question | Current disposition | Remaining risk or action |
|---:|---|---|---|
| 1 | Is the scientific quantity stated before the method? | yes: allocation about `T_H` or `T_V` | preserve question IDs across dependency upgrades |
| 2 | Is target leakage excluded? | Yes relative to fusion/Galadriel/PID. Targets are reconstructed from preregistered synthetic latent ENU without reading source symbols, projections, fusion, verdict, or PID. | The target is not producer-independent field truth. Future truth generation and synchronization need qualification. |
| 3 | Are sources named, ordered, and grounded? | Yes. `(V,R,A)` and synthetic coordinate-derived bits. | Physical labels do not add external validity. Symmetric laws require provenance because numbers may not reveal swaps. |
| 4 | Is the sampling unit honest? | Yes. Eight fresh-instance rows per law cell. No `n=64` inference claim. | The compact artifact does not prove complete state isolation. Future data must split and resample by independent episode. |
| 5 | Does support match the estimand? | yes: finite categorical empirical PMF | do not route atomic rows to KSG/Ehrlich |
| 6 | Is the functional exact and unambiguous? | yes: categorical MGW shared exclusions | never say generic “Wibral PID” |
| 7 | Are functional and evaluator distinct? | yes: paper-defined functional, pinned pid-core empirical evaluator | review any later API identity change separately |
| 8 | Are units explicit and consistent? | yes: nats throughout this study | never inherit bit labels from a different aggregate schema |
| 9 | Are signed atoms preserved? | yes: informative, misinformative, and net retained | negative future results must not be clamped or hidden |
| 10 | Does the lattice reconstruct its marginals/joint? | yes: PID2 plus seven PID3 down-set identities | retain fail-closed tolerance and complete-coordinate tests |
| 11 | Is there a dependency-disjoint calculation separate from the production route? | Yes for 66 averaged atom components and ten subset MIs: separate 80-digit event-union/Möbius calculation. | The same fixture/spec/repository means this is not independent human or organizational replication. Pointwise results are not Decimal-recomputed. |
| 12 | Are hostile controls predicate-isolating? | Yes for bytes, rows, sources, targets, bounded summaries, time, order, and algebra. The bounded gate binds a 149-mutant selected set with 146 caught and three exact compile-unviable substitutions in the local repair reference. | Rerun the gate on the final exact candidate. Expand it with each new field or transform and preserve all non-target predicates in each mutation. |
| 13 | Are methods kept semantically separate? | yes: 16 functional/evaluator/estimator/diagnostic/objective rows, with no fallback | preregister any future comparator and report its own failures |
| 14 | Are causal/mechanistic claims blocked? | Yes. Atoms are associational, statistical, and measure-relative. | Defense language must not call atoms causal mechanisms. |
| 15 | Is authority absent by construction? | yes: no PID-to-verdict or PID-to-Haldir effect path | a future record adapter must prove authorization and plant-command invariance for favorable, adverse, missing, stale, and malformed records |
| 16 | Are software identity and custody sufficient? | fixture, manifest, CREBAIN revision, pid-core revision bound | publication run still needs Galadriel commit, build, toolchain, host, output digest |
| 17 | Are errors, abstentions, and missingness visible? | Typed fixture/pid-core failure. Method abstentions explicit. | Future episode studies need per-episode produced/unavailable/error records. |
| 18 | Is external validity stated honestly? | Yes. Synthetic deterministic conformance only. No drone-performance claim. | Stochastic simulator, SITL, HIL, replay, and field evidence remain open. |
| 19 | Is the artifact reproducible and readable? | exact CLI, JSON, Markdown, SVGs, equations, hashes | freeze exact output bundle only after final candidate commit |
| 20 | Are human ownership and AI assistance handled? | this audit records computational provenance, not human expertise | candidate must derive/check the theorem and tables, preserve AI provenance, follow university disclosure rules, and obtain qualified human review before a load-bearing defense claim |

## 13. Complete to-do list

### Exact-law implementation and current candidate

- [x] Freeze the synthetic canonical row contract before selecting a PID method.
- [x] Use three ordered pre-fusion sources and targets generated without reading source symbols, projections, fusion, verdict, or PID. State that these are not producer-independent field truth.
- [x] Generate all eight source cells with eight fresh-engine repeats and limit the claim to bounded-summary fresh-instance reproducibility.
- [x] Bind the exact CREBAIN commit, path, byte count, fixture digest, and manifest digest.
- [x] Vendor the fixture byte-for-byte into `galadriel-justify` without adding a cross-repository build dependency.
- [x] Add a typed append-only errata receipt for target-origin wording, omitted CUSUM, and legacy fusion-summary semantics. Validate the frozen literals and retain the fixture bytes unchanged.
- [x] Reconstruct every source bit and both targets from the declared synthetic geometry.
- [x] Validate episode IDs, row-window timestamps, cell balance, and bounded six-field fusion summaries.
- [x] Evaluate primary categorical MGW PID2 through pinned pid-core 0.9.0 `discrete_sxpid2_with_budget`.
- [x] Evaluate exploratory categorical MGW PID3 through pinned pid-core 0.9.0 `discrete_sxpid3_with_budget`.
- [x] Preserve pointwise and averaged informative, misinformative, and net outputs in nats.
- [x] Check all PID2 identities and all seven PID3 down-set identities.
- [x] Add the fixed-source target-rotation informative-atom canary.
- [x] Add closed-form AND-law mutual-information controls.
- [x] Check all 66 averaged atom components and ten subset MIs against a separate 80-digit event-union/Möbius calculation.
- [x] State explicitly that pointwise outputs are retained and internally reconstructed but not separately Decimal-recomputed.
- [x] Preserve the averaged-output calculation as a standard-library oracle with canonical SHA-256 `5aa7a1d92d4aaad9c056ede8a75bdc40abc1fa76634b02bba20aac5cc3913c19`.
- [x] Encode the functional, evaluator, PMF, pointwise/averaged outputs, validation receipts, and advisory sink as distinct typed graph objects.
- [x] Publish a 16-row eligibility matrix that separates every functional, evaluator, estimator, diagnostic, including NIS, the selected two-arm CUSUM, and signed correlation, from every downstream objective. Define no fallback route.
- [x] Add exact JSON and publication-oriented Markdown output with BrokenPipe-safe CLI behavior.
- [x] Add accessible, renderer-verified system and method SVGs.
- [x] Add a cargo-mutants 27.1.0/Rust 1.89 exact-head gate for the seven CREBAIN contract functions. Bind the 149-mutant normalized multiset, 146 caught results, and three exact compile-unviable substitutions.
- [ ] Run the complete Galadriel local release, security, documentation, Rust, Python, public-API, and mutation matrix on the final exact source bytes.
- [ ] Build a separate candidate-bound PID evidence bundle with Galadriel commit/tree, toolchain, build profile, executable hash, host identity, fixture hash, output hash, and typed failure inventory.
- [ ] Regenerate living release ledgers/manifests and public API evidence last. Do not rewrite historical signed artifacts.
- [ ] Sign the exact Galadriel candidate commit, promote through the protected review path without squash, require terminal hosted CI and deep-quality results on the exact promoted SHA, then delete the review ref and confirm one clean main worktree.

### pid-rs adaptation and future evolution (pid-rs remains read-only here)

- [x] Select clean, remote-reachable pid-core 0.9.0 revision `bc3aa80fb6025e709c2906a08bce25a4fac40578`. Consume no dirty-worktree-only feature.
- [x] Retain CREBAIN's immutable `1cd2424…` preregistration and record the post-preregistration revision/API adaptation instead of rewriting history.
- [x] Review the relevant public API and method-catalog identities. Preserve the functional, law, source order, targets, units, signed atoms, and pointwise inclusion.
- [x] Route all nine production/control calls through explicit `*_with_budget` evaluators and retain their individual preflights.
- [x] Reconcile the compiled pid-core software identity to the selected clean package-subtree revision before producing a study result.
- [ ] Adopt an upstream specified-rational-law or sparse-count receipt only after a clean published API exists. Require raw-row/count/rational agreement before using the stronger claim.
- [ ] Adopt checked aggregate resource composition if upstream supplies it. Do not treat nine per-call preflights as a whole-process peak bound.
- [ ] Keep stable PID3 availability separate from the open 108-coordinate assurance program.
- [ ] Re-run the 66-averaged-component/ten-MI oracle, all hostile controls, full Galadriel qualification, and publication bundle after any pin change.

### Grounded stochastic, SITL, HIL, replay, and field program

- [ ] Write and hash the analysis manifest before viewing PID results: episode definition, source order, target, time window, categorizer, exclusions, method routes, seeds, split, stopping rule, accepted outputs, and abstentions.
- [ ] Define independent flight/mission episodes and synchronized windows. Retain row IDs and pre-fusion lineage.
- [ ] Model physically plausible noise, bias, occlusion, drift, clock offset, dropouts, association failures, and maneuvers.
- [ ] Keep simulator truth external to sensor projection, Galadriel fusion, and PID.
- [ ] If continuous scores are quantized, fit the categorizer on calibration episodes only, freeze it, and call the result a quantized estimand.
- [ ] Split calibration/train, validation, and evaluation at episode level. Never split frames from one episode across arms.
- [ ] Use episode-level permutation/bootstrap schedules that cannot splice missions. Publish effective episode counts and missingness.
- [ ] Record every method as produced, unavailable, inapplicable, resource-rejected, or error—never silently drop failures.
- [ ] Compare NIS, the selected two-arm CUSUM, signed correlation, categorical MGW, optional `I_min`, optional two-source BROJA, KSG, continuous Ehrlich, and co-/O-information only in separately eligible columns.
- [ ] Advance through stochastic simulation, SITL, HIL, immutable replay, and field studies as distinct claim tiers.
- [ ] Test compute budgets, deadlines, restarts, corrupt inputs, missing modalities, and adversarial timing on target hardware.
- [ ] Obtain qualified human PID review and an independent reproduction before treating novel PID interpretation as defense-critical.

### Haldir and ecosystem boundary

- [ ] Define a versioned record-only Haldir advisory reference with exact Galadriel evidence identity, freshness, and explicit non-authority semantics.
- [ ] Prove `Authorize(x,e)=Authorize(x)` and `PlantCommand(x,e)=PlantCommand(x)` for every PID record state. The record path may change only the audit record.
- [ ] Test stale, missing, malformed, replayed, favorable, unfavorable, negative-atom, and unavailable PID records cannot cause allow, deny, restriction, restoration, or a plant command.
- [ ] Update Haldir explanatory documents that still describe rotating/leave-one-out PID targets. Retain archived non-normative history clearly labeled.
- [ ] Reconcile Prisoma's method-selection/provenance graph against the exact published Galadriel and pid-rs commits. Keep dirty drafts advisory until committed.
- [ ] Preserve all useful review/prototype bytes until their publication commit is verified reachable from remote `main` and retrieval succeeds. Delete temporary refs/worktrees only at the very end.

### Defense ownership and contingency

- [ ] Candidate personally derives the MGW event equations, Möbius reconstruction, AND-law MI values, and at least the load-bearing PID2 table.
- [ ] Candidate reproduces the exact fixture and output from a clean checkout and records the result independently of this AI-assisted audit.
- [ ] Preserve council/AI assistance provenance and follow the university's disclosure rules. Correlated agent agreement is not independent replication.
- [ ] Ask qualified human reviewers to challenge functional identity, target construction, episode independence, signed-atom interpretation, and comparator boundaries.
- [ ] If outward-rounded reproduction and qualified human review are incomplete by thesis/slide freeze, keep PID3 and the exact atom tables in an exploratory appendix. Base the load-bearing defense on the target's independence from fusion/PID, finite-law equations, closed-form MI, algebraic checks, and honest limitations.

## 14. Primary references

- Abdullah Makkeh, Aaron J. Gutknecht, and Michael Wibral, “Introducing a
  differentiable measure of pointwise shared information,” *Physical Review E*
  103, 032149 (2021),
  [doi:10.1103/PhysRevE.103.032149](https://doi.org/10.1103/PhysRevE.103.032149).
- Aaron J. Gutknecht, Michael Wibral, and Abdullah Makkeh, “Bits and Pieces:
  Understanding Information Decomposition from Part-whole Relationships and
  Formal Logic,” *Proceedings of the Royal Society A* 477, 20210110 (2021),
  [doi:10.1098/rspa.2021.0110](https://doi.org/10.1098/rspa.2021.0110).
- Paul L. Williams and Randall D. Beer, “Nonnegative Decomposition of
  Multivariate Information” (2010),
  [arXiv:1004.2515](https://arxiv.org/abs/1004.2515).
- Malte Harder, Christoph Salge, and Daniel Polani, “Bivariate Measure of
  Redundant Information,” *Physical Review E* 87, 012130 (2013),
  [doi:10.1103/PhysRevE.87.012130](https://doi.org/10.1103/PhysRevE.87.012130).
- Johannes Rauh, Nils Bertschinger, Eckehard Olbrich, and Jürgen Jost,
  “Reconsidering Unique Information: Towards a Multivariate Information
  Decomposition” (2014),
  [doi:10.1109/ISIT.2014.6875230](https://doi.org/10.1109/ISIT.2014.6875230).
- Aobo Lyu, Andrew Clark, and Netanel Raviv, “Multivariate Partial Information
  Decomposition: Constructions, Inconsistencies, and Alternative Measures”
  (2026),
  [doi:10.1103/8rzp-w5z1](https://doi.org/10.1103/8rzp-w5z1).
- David A. Ehrlich, Kyle Schick-Poland, Abdullah Makkeh, Felix Lanfermann,
  Patricia Wollstadt, and Michael Wibral, “Partial Information Decomposition for
  Continuous Variables based on Shared Exclusions: Analytical Formulation and
  Estimation,” *Physical Review E* 110, 014115 (2024),
  [doi:10.1103/PhysRevE.110.014115](https://doi.org/10.1103/PhysRevE.110.014115).
- Kyle Schick-Poland, Abdullah Makkeh, Aaron J. Gutknecht, Patricia Wollstadt,
  Anja Sturm, and Michael Wibral, “A partial information decomposition for
  discrete and continuous variables” (2021),
  [arXiv:2106.12393](https://arxiv.org/abs/2106.12393).
- Alexander Kraskov, Harald Stögbauer, and Peter Grassberger, “Estimating mutual
  information,” *Physical Review E* 69, 066138 (2004),
  [doi:10.1103/PhysRevE.69.066138](https://doi.org/10.1103/PhysRevE.69.066138).
- Nils Bertschinger, Johannes Rauh, Eckehard Olbrich, Jürgen Jost, and Nihat
  Ay, “Quantifying Unique Information,” *Entropy* 16, 2161–2183 (2014),
  [doi:10.3390/e16042161](https://doi.org/10.3390/e16042161).
- William J. McGill, “Multivariate Information Transmission,” *Psychometrika*
  19, 97–116 (1954),
  [doi:10.1007/BF02289159](https://doi.org/10.1007/BF02289159).
- Fernando E. Rosas, Pedro A. M. Mediano, Michael Gastpar, and Henrik J.
  Jensen, “Quantifying High-order Interdependencies via Multivariate
  Extensions of the Mutual Information,” *Physical Review E* 100, 032305
  (2019),
  [doi:10.1103/PhysRevE.100.032305](https://doi.org/10.1103/PhysRevE.100.032305).
- E. S. Page, “Continuous Inspection Schemes” (1954),
  [doi:10.1093/biomet/41.1-2.100](https://doi.org/10.1093/biomet/41.1-2.100).
- Abdullah Makkeh, Marcel Graetz, Andreas C. Schneider, David A. Ehrlich, Viola
  Priesemann, and Michael Wibral, “A general framework for interpretable neural
  learning based on local information-theoretic goal functions,” *PNAS* 122,
  e2408125122 (2025),
  [doi:10.1073/pnas.2408125122](https://doi.org/10.1073/pnas.2408125122).
- Andreas C. Schneider, Valentin Neuhaus, David A. Ehrlich, Abdullah Makkeh,
  Alexander S. Ecker, Viola Priesemann, and Michael Wibral, “What Should a
  Neuron Aim For? Designing Local Objective Functions Based on Information
  Theory,” *ICLR 2025*,
  [OpenReview:CLE09ESvul](https://openreview.net/forum?id=CLE09ESvul).

The PNAS work establishes the earlier bivariate/two-input infomorphic framework.
The ICLR work develops a three-input-class local-objective design. They are
role-distinct papers and are not implementation evidence for this Galadriel
fixture.
