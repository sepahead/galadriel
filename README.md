<p align="center">
  <img src="assets/galadriel-logo.svg" alt="Galadriel's Mirror — a cross-sensor consistency monitor: several sensor channels corroborate one track while one channel decouples in red." width="200" height="200" />
</p>

<h1 align="center">galadriel</h1>

<p align="center"><strong>Galadriel's Mirror</strong> — an information-theoretic cross-sensor consistency &amp; spoof detector for multi-sensor fusion.</p>

<p align="center">
  <a href="https://github.com/sepahead/galadriel/actions/workflows/ci.yml"><img src="https://github.com/sepahead/galadriel/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0">
  <img src="https://img.shields.io/badge/rust-1.80%2B-orange.svg" alt="Rust 1.80+">
  <img src="https://img.shields.io/badge/status-experimental%20(pre--1.0)-orange.svg" alt="status: experimental">
  <img src="https://img.shields.io/badge/unsafe-forbidden-success.svg" alt="unsafe forbidden">
</p>

---

Several sensors — vision, radar, acoustic DOA, lidar — should **corroborate** each
other about one tracked target. When one channel starts *lying* (a spoof / false-data
injection: a phantom acoustic bearing, an adversarial patch poisoning one camera),
it stops agreeing with the consensus of the others. **galadriel is the mirror that
catches that decoupling** and tells an operator *which* channel to distrust — before
the fused track pulls an interceptor off the real inbound.

It is the security/guardian sibling of [**crebain**](https://github.com/sepahead/crebain)
(the tactical ARAS fuser), and it uses the information-theoretic estimators of
[**pid-rs**](https://github.com/sepahead/pid-rs). It rides the
[**NCP**](https://github.com/sepahead/NCP) bus's read-only observation plane.

> **The one honest sentence.** galadriel shows that a channel has stopped agreeing
> with the corroborated consensus of the others — it *cannot* prove that channel is
> lying, *cannot* see a spoof that preserves cross-channel agreement, and is
> **advisory** (`calibrated_posterior = false`): it softens and attributes, it never
> silently vetoes a control path.

## Quickstart

```bash
cargo run --bin galadriel -- demo
```

```text
═══ GALADRIEL'S MIRROR · cross-sensor consistency monitor ═══
    NIS χ² baseline — the cheap yardstick the PID engine must beat

┌─ CLEAN — corroborated airspace picture
│  visual          ▁▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂  μ=  2.81  ● consistent
│  radar           ▁▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂  μ=  2.85  ● consistent
│  acoustic        ▁▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂  μ=  3.25  ● consistent
└▷ VERDICT: NOMINAL   3 channels corroborate; NIS consistent with χ²

┌─ PHANTOM DOA — targeted single-channel spoof (acoustic)
│  acoustic        ▁▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▃▄▅▆▇██████████████████  μ= 61.04  ● ANOMALOUS
└▷ VERDICT: SPOOF [acoustic]   1 of 3 channels decoupled (acoustic) — targeted injection

┌─ BROADBAND JAM — correlated all-channel denial
└▷ VERDICT: JAM   3/3 channels inflated together — correlated denial
```

## How it works

galadriel consumes a stream of `PidObservation` records — one per associated
measurement — carrying the **Normalized Innovation Squared** `NIS = yᵀ S⁻¹ y ~ χ²(dof)`
formed against the *a priori* (pre-update) track state. In the ecosystem these are
emitted by crebain's fusion `update_track`; here they are transport-agnostic data.

**The baseline (this release).** Per channel, a sliding window of NIS is tested for
χ² consistency (the window sum is `~ χ²(n·dof)`; an improbably high sum flags an
inflated channel), backed by a two-sided CUSUM for sustained shifts. The per-channel
flags fold into a **fail-closed jam-vs-spoof** verdict:

| observation | verdict |
|---|---|
| all channels consistent with χ²(dof) | `Nominal` |
| **one** channel inflated, others corroborate | `Spoof { channels }` — targeted injection |
| **most/all** channels inflated together | `Jam` — correlated denial |
| too few samples / channels | `InsufficientEvidence` — **fail closed** |

**The engine (roadmap, feature `pid`).** The cheap baseline is a *yardstick*. The
optional cross-sensor PID engine compares each channel's innovation against a
**leave-one-out consensus** (never the fused state), gated by a mandatory geometry
check and block-subsample CIs, to separate a moment-matched spoof (one channel
decouples in *information structure* while its NIS stays in-covariance) from benign
decorrelation — something the NIS baseline alone cannot do. It ships only if it
**beats the baseline** on the fixtures — and it does: on a moment-matched stealthy
spoof the baseline is at chance (ROC-AUC 0.547) while PID reaches **0.999** at a 0%
false-alarm rate ([`docs/EVALUATION.md`](docs/EVALUATION.md)). Full design:
`galadriels-mirror.md`.

## Architecture

```
crates/
  galadriel-core   pure: PidObservation/Modality, NIS window, χ², baseline, CUSUM, decision
  galadriel-sim    pure: synthetic χ²(3) scenarios + phantom-DOA / broadband-jam injections
  galadriel-cli    the `galadriel demo` driver
  galadriel-pid    (planned, feature `pid`)  cross-sensor PID engine over pid-core
  galadriel-ncp    (planned, feature `ncp`)  PidObservation ingest over ncp-core
```

The **default build is pure and light** (serde, thiserror, rand, clap). Heavier
integrations are additive, off-by-default features:

| feature | pulls | adds |
|---|---|---|
| *(default)* | — | pure core + sim + demo |
| `pid` | `pid-core` | the cross-sensor PID engine |
| `ncp` | `ncp-core` (serde-only) | `PidObservation` JSONL ingest |
| `ncp-live` | `ncp-zenoh` + `tokio` | live Zenoh observation-plane tap |

> **On NCP.** `ncp-core` is light (serde only) and usable as-is for the wire types;
> `ncp-zenoh` pulls the full Zenoh stack, so the live tap is strictly feature-gated.
> galadriel's `PidObservation` rides a **non-wire sidecar key** (never a proto
> variant, so it can't trip NCP's `CONTRACT_HASH`); the MVP ingest path is plain
> JSONL, no network.

## Building & testing

```bash
cargo test --workspace          # unit + integration tests
cargo clippy --all-targets      # lint (CI enforces -D warnings)
cargo fmt --all --check         # formatting
cargo build -p galadriel-core --no-default-features   # pure-core smoke
```

MSRV is **1.80** for the default build (rising to 1.88 with the `pid`/`ncp`
features). Every crate is `#![forbid(unsafe_code)]`.

## Honest limitations

- **Consistency, not truth.** A signed frame of a dazzled scene, or a moment-matched
  spoof kept inside each channel's own covariance, passes the baseline.
- **Attribution is advisory.** A redundancy collapse is equally consistent with a
  spoof, a genuinely-unique *true* detection, or an estimator artifact.
- **Not the enforcement layer.** The real bus remedies are cryptographic (per-plane
  ACL + mTLS) and the safety governor; galadriel is instrumentation on top.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option. Part of the [`sepahead`](https://github.com/sepahead) ecosystem.
