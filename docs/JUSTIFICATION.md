# When is PID actually justified? (and when is it forced?)

**The demand.** Don't use Partial Information Decomposition / mutual information because
it's fashionable. Use it only where there is a **precise, defensible reason** that it
adds value a cheaper method cannot. This document establishes that reason — and, just
as importantly, the regime where PID is **not** justified and a cheap correlation check
is the right call.

Reproduce every number here with `cargo run -p galadriel-justify --release`.

---

## 1. The trap: on linear-Gaussian data, MI *is* correlation

For jointly-Gaussian variables the mutual information is a closed-form, **monotone**
function of the Pearson correlation:

```
MI(X, Y) = −½ ln(1 − ρ²)
```

A monotone transform of a score does not change its ROC. So an MI-threshold detector
and a `|ρ|`-threshold detector are the **same detector** on linear-Gaussian data — MI
adds exactly nothing. Galadriel's original stealthy-spoof fixture (a channel decoupling
to an independent Gaussian latent) is *linear-Gaussian*. **On that fixture, using KSG
mutual information instead of a one-line correlation is forcing the method.** This is
the honest weakness the design review (`galadriels-mirror.md`, lens 04) flagged, made
concrete.

## 2. The reason: MI is a *model-free* dependence detector

MI earns its cost only where the dependence is **nonlinear** — there `|ρ| ≈ 0` even
though the variables are strongly dependent, so a linear check is blind to structure
that MI still sees. The `galadriel-justify` study measures both detectors head-to-head:
ROC-AUC at separating a **coupled** `(X, Y)` pair from a **decoupled** one (a
permutation null — same marginal, dependence destroyed), under two couplings.

```
Is PID/MI justified over correlation?  300 trials/class · n=400 samples/pair
Detector ROC-AUC at separating a coupled pair from a decoupled one:

coupling                  | |rho| mn | corr AUC [95% CI]      | MI AUC [95% CI]
------------------------------------------------------------------------------
linear     (Y = X + e)    |    0.894 | 1.000 [1.000, 1.000]  | 1.000 [1.000, 1.000]
nonlinear  (Y = +/-X + e) |    0.067 | 0.662 [0.617, 0.707]  | 1.000 [1.000, 1.000]
```

- **Linear** (`Y = X + ε`): `|ρ| = 0.89`, and **corr AUC = MI AUC = 1.000**. Correlation
  is free and just as good — **PID is forced; ship correlation.**
- **Nonlinear** (`Y = ±X + ε`, a random per-sample sign flip): `|ρ| = 0.07` — the linear
  signal is gone — yet `|Y| ≈ |X|`, a strong magnitude dependence. **Correlation is weak
  (AUC 0.662, and only via a residual higher-moment/kurtosis artifact), while MI is
  decisive (AUC 1.000)** — a **ΔAUC ≈ 0.34** advantage. **This is the good reason: MI
  catches an attack that preserves linear correlation while breaking the dependence,
  without the defender having to know the attack's nonlinear form in advance.**

The sign-flip construction is deliberately a hard honest case: its *population* `corr = 0`,
so the linear signal is genuinely gone. The `|ρ|` detector still reaches AUC 0.662 — but
**only via an artifact**: the *sample* correlation's variance is inflated by the kurtosis of
`X` (a fourth-moment effect), and a `|ρ|`-threshold rides that inflation, not any linear
dependence. MI, seeing the magnitude dependence directly, wins by ≈ 0.34 AUC over that
artifact (≈ 0.5 over true chance).

## 3. The good reasons, stated precisely

PID / mutual information is justified — over correlation, NIS, or any second-order
statistic — for **one or more** of these concrete reasons:

1. **Model-free (attack-form-agnostic) dependence detection.** MI catches *any*
   cross-channel dependence — linear, nonlinear, or higher-order — without a hand-picked
   feature. A correlation or parity check only catches the specific relationship it was
   built for. §2 quantifies the gap: ΔAUC 0.34 on a nonlinear coupling correlation
   cannot see.
2. **Adversarial robustness (Kerckhoffs) — only off the Gaussian manifold.** Assume the
   adversary knows the detector. A correlation-aware attacker can craft an injection that
   **preserves `ρ` while breaking higher-order structure** — invisible to correlation,
   visible to MI. But on *linear-Gaussian* residuals `ρ` and MI are functionally locked, so
   this is impossible there — and indeed the adaptive threshold-hugging adversary study
   (`EVALUATION.md` §2.5, matched-FAR evasion ceiling) shows correlation is the *harder*
   detector to evade on the linear manifold, so MI buys **no** adversarial robustness there.
   This reason is therefore a defense-in-depth *framing of reason 1*: it bites only where the
   coupling is genuinely nonlinear, not as an independent justification.
3. **The decomposition itself is irreducible.** A **synergy** measure detects structure
   carried *only* jointly by two or more channels (an XOR/parity-like relationship): all
   pairwise correlations **and** all pairwise MIs are ≈ 0, yet the channels are dependent.
   (`I^sx` is the *redundancy* atom [Makkeh–Gutknecht–Wibral 2021]; the synergy atom is the
   top of the Williams–Beer lattice, obtained by Möbius inversion — distinct from `I^sx`.)
   **No pairwise statistic of any kind can see synergy** — only a joint-information measure
   can. Where an attack targets synergistic fusion, a joint/PID measure is not merely
   better, it is the *only* option. It also gives per-channel **attribution** (which channel
   decoupled) that a single scalar cannot. **Confirmed empirically** by the
   `galadriel-justify` synergy study, which uses the joint-information contrast
   `Q = MI(A,B;T) − max(MI(A;T),MI(B;T))` (an upper bound on the synergy atom, tight for
   XOR) — on `T = A⊕B` (independent bits `A`, `B`):

   ```
   detector                   |  AUC   [95% CI]        (bits target)
   correlation (pairwise)     | 0.544  [0.496, 0.592]  <- CI brackets 0.5: at chance
   mutual info (pairwise)     | 0.544  [0.496, 0.594]  <- CI brackets 0.5: at chance
   synergy contrast Q (joint) | 1.000  [1.000, 1.000]  <- only a joint measure (0.997 bits)
   ```

   Even *pairwise mutual information* is at chance: it is specifically a **joint** measure
   that is required. (On binary variables discrete MI is a monotone function of the sample
   correlation `φ`, so pairwise MI and `|ρ|` returning the *same* 0.544 is expected, not
   independent corroboration.) This is the one regime where a joint/PID measure is not a
   choice but a necessity — no pairwise statistic of any kind suffices.

## 4. Honest verdict for *galadriel*

Galadriel's core input is the **innovation residual** `y = z − Hx̂⁻` of each sensor
against a shared tracked target. For position/kinematic residuals, the cross-channel
relationship is essentially **linear-Gaussian** — so, per §1, **PID does not beat a
cheap best-pairwise `|ρ|` / parity check for galadriel's primary spoof-detection job.**
Using it there is forced.

PID is justified in galadriel **only** in these specific situations, and the honest
recommendation is to gate it behind them rather than run it by default:

- **A correlation-aware adversary** (§3.2): keep MI as the model-free backstop the
  attacker must also beat.
- **Genuinely nonlinear modalities**: where the shared information is a *magnitude/energy*
  quantity (acoustic SPL vs radar cross-section), or a **learned fusion feature**, the
  coupling is nonlinear and §2 applies directly.
- **Synergistic fusion** (§3.3): if fusion combines channels nonlinearly such that the
  target information is synergistic, only the decomposition sees an attack on it.

**Where PID is unambiguously justified in the ecosystem:** [`prisoma`](https://github.com/sepahead/prisoma)'s
Vision-Language-Action analysis. A neural policy's dependence between vision, language,
and action is nonlinear and synergistic by construction — exactly §2/§3 territory —
which is why prisoma is built on PID and galadriel's sensor-fusion case is the harder
sell.

### Recommendation (drives the roadmap)

1. Ship a **cheap correlation/parity cross-sensor detector** as galadriel's default
   consistency check — it is provably sufficient for the linear-Gaussian residual case.
2. Keep the **MI/PID engine as an opt-in escalation** for the three situations above,
   and report *both* so an operator sees when they diverge (divergence is itself
   information: a correlation-preserving, MI-visible anomaly is the adversarial case).
3. Never present MI results as beating the baseline *in general* — only in the regimes
   §2–§3 name. The evaluation (`EVALUATION.md`) must be read with this scope.

This is the disciplined position: **PID where it is irreducible, correlation where it
is not.**

---

## 5. Reproduce

```bash
cargo run -p galadriel-justify --release        # the §2 table
cargo test -p galadriel-justify                 # asserts: linear corr≈MI; nonlinear MI≫corr
```
