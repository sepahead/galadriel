# Galadriel fuzz targets

These targets exercise fail-closed parser and temporal-state boundaries.
They also exercise projection provenance and assessment-scope terminal coordinates.
The structured lifecycle target drives both evidence routes through the assembler.
It passes each complete frame to the lifecycle detector.
Tracked seeds enter each parser, detector, assembler, and lifecycle boundary.
Library canaries bind each raw-byte seed to its intended semantic path.
Each retained campaign also uses one fixed pseudorandom seed.
Lifecycle canaries prove one commit and two exact fail-closed paths.
They stay outside the primary workspace because they use nightly compiler instrumentation.

The following block is a bounded developer reproduction.
It does not create retained qualification evidence.
Qualification copies each runner to a private mode-`0500` snapshot before execution.

```bash
set -euo pipefail
rustup toolchain install nightly-2026-06-16
cargo fetch --locked --manifest-path fuzz/Cargo.toml
cargo +nightly-2026-06-16 test \
  --manifest-path fuzz/Cargo.toml --lib --locked --offline
cargo +nightly-2026-06-16 check \
  --manifest-path fuzz/Cargo.toml --all-targets --locked --offline
fuzz_target="$(rustc +nightly-2026-06-16 -vV | sed -n 's/^host: //p')"
case "$fuzz_target" in
  aarch64-apple-darwin|x86_64-unknown-linux-gnu) ;;
  *) exit 1 ;;
esac
export ASAN_OPTIONS=detect_odr_violation=0
export RUSTFLAGS='-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cllvm-args=-simplifycfg-branch-fold-threshold=0 -Zsanitizer=address -Cdebug-assertions -Ccodegen-units=1'
cargo +nightly-2026-06-16 build \
  --manifest-path fuzz/Cargo.toml \
  --target "$fuzz_target" \
  --release \
  --config 'profile.release.debug="line-tables-only"' \
  --bins \
  --locked \
  --offline
fuzz_root="$(mktemp -d)"
trap 'rm -rf -- "$fuzz_root"' EXIT
mkdir -p \
  "$fuzz_root/corpus/ncp_decode" \
  "$fuzz_root/corpus/detector_boundaries" \
  "$fuzz_root/corpus/lifecycle_state" \
  "$fuzz_root/artifacts/ncp_decode" \
  "$fuzz_root/artifacts/detector_boundaries" \
  "$fuzz_root/artifacts/lifecycle_state"
runner_root="fuzz/target/$fuzz_target/release"
"$runner_root/ncp_decode" \
  -runs=5000 -max_len=131072 -seed=900090001 \
  "-artifact_prefix=$fuzz_root/artifacts/ncp_decode/" \
  "$fuzz_root/corpus/ncp_decode" fuzz/seeds/ncp_decode
"$runner_root/detector_boundaries" \
  -runs=5000 -max_len=131072 -seed=900090002 \
  "-artifact_prefix=$fuzz_root/artifacts/detector_boundaries/" \
  "$fuzz_root/corpus/detector_boundaries" fuzz/seeds/detector_boundaries
"$runner_root/lifecycle_state" \
  -runs=5000 -max_len=131072 -seed=900090003 \
  "-artifact_prefix=$fuzz_root/artifacts/lifecycle_state/" \
  "$fuzz_root/corpus/lifecycle_state" fuzz/seeds/lifecycle_state
cargo fetch --locked
cargo deny --offline --all-features --locked check
cargo deny --offline --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```

For a shorter bounded run, replace `-runs=5000` with `-runs=1000`.
A crash corpus alone is not evidence of a vulnerability.
Reproduce the minimized input with the standard workspace build and its resource limits.
