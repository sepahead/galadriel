# Galadriel fuzz targets

These targets exercise fail-closed parser, temporal-state, and projection-provenance boundaries.
They stay outside the primary workspace because `cargo-fuzz` uses nightly compiler instrumentation.

```bash
rustup toolchain install nightly-2026-06-16
cargo +nightly-2026-06-16 install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-06-16 fuzz run ncp_decode -- -max_len=131072
cargo +nightly-2026-06-16 fuzz run detector_boundaries -- -max_len=131072
cargo fetch --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml
cargo deny --offline --all-features --locked check
cargo deny --offline --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```

For a bounded smoke run, append `-runs=10000`.
A crash corpus alone is not evidence of a vulnerability.
Reproduce the minimized input with the standard workspace build and its resource limits.
