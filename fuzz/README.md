# Galadriel fuzz targets

These targets exercise fail-closed parser, temporal-state, and projection-provenance
boundaries. They intentionally live outside the production workspace because
`cargo-fuzz` uses nightly compiler instrumentation.

```bash
cargo install cargo-fuzz --locked
cargo +nightly fuzz run ncp_decode -- -max_len=131072
cargo +nightly fuzz run detector_boundaries -- -max_len=131072
```

For a bounded smoke run, append `-runs=10000`. A crash corpus is not evidence of a
vulnerability until the minimized input has been reproduced against the ordinary
workspace build and its resource limits.
