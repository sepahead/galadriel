# Qualification dependency policy

**GLD-090-PIN-001:** Every Git dependency used for qualification **SHALL** name a
full 40-hex `rev`, and Cargo.lock **SHALL** resolve that same commit. Branch-only,
tag-only, abbreviated, floating-main and local sibling-path substitutions **SHALL
NOT** qualify a release.

**GLD-090-PIN-002:** Registry dependencies **SHALL** be resolved through the
committed Cargo.lock with registry checksums and every qualification command
**SHALL** use `--locked`. The manifest's compatible version requirements support
maintenance resolution; they are not the qualification identity.

**GLD-090-PIN-003:** The Rust compiler **SHALL** be the exact channel in
`rust-toolchain.toml`; CI actions **SHALL** be commit-SHA pinned; generated artifacts
**SHALL** record tool versions and exact repository/dependency identities.

**GLD-090-PIN-004:** An upstream version declaration without a signed/released tag
or artifact **SHALL NOT** be represented as a released integration. The optional
pid-rs revision is immutable component input but upstream pid-rs 1.x release
qualification remains `NOT_CLAIMED`. NCP qualification is explicitly limited to
the selected public v0.8.0 commit, not NCP 1.0.

The release verifier rejects a Git lock source without a terminal full revision.
`cargo deny` rejects unknown sources and wildcard requirements. Any dependency
change invalidates the public-API snapshot, supply-chain reports, test evidence and
release manifest until regenerated against the new lockfile.
