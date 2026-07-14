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
pid-rs revision selected by this lockfile is an older immutable experimental
component input whose manifest declares `1.0.0`; it is not the identity of current
pid-rs `main`, and upstream pid-rs release qualification remains `NOT_CLAIMED`.
NCP qualification is explicitly limited to the commit selected by the public
annotated `v0.8.0` tag, not NCP 1.0 or current NCP `main`. GitHub reports both the
tag object and its target commit as unsigned, so the immutable 40-hex revision and
Cargo lock entry provide identity but not upstream signature assurance.

**GLD-090-PIN-005:** Yanked registry releases **SHALL** fail dependency review by
default. A temporary exception **SHALL** name the exact package, owner, reason, and
expiry. The only 0.9.0 exceptions are `spin` 0.9.8 and 0.10.0, selected transitively
by the exact NCP 0.8/Zenoh 1.9 graph; neither has a RustSec advisory in the checked
database. They expire on 2026-10-01 and shall be removed during the reviewed
NCP/Zenoh migration. The separate ignored `RUSTSEC-2026-0041` entry has the same
owner/expiry and is admissible only while CI proves Zenoh transport compression is
absent from the complete all-feature graph.

**GLD-090-PIN-006:** The production workspace and isolated fuzz workspace **SHALL**
use separate least-privilege license/source policies. `deny.toml` admits only
licenses and Git sources encountered by the production graph. `fuzz/deny.toml`
additionally admits NCSA solely because `libfuzzer-sys` combines it with MIT or
Apache-2.0, and admits no Git source except the exact NCP dependency. Both locked
checks are release gates.

**GLD-090-PIN-007:** Informational dependency advisories **SHALL** be retained as
release risks even when policy limits enforcement to workspace-owned packages.
The locked Zenoh 1.9 graph transitively contains unmaintained `paste` 1.0.15
(`RUSTSEC-2024-0436`) through `token-cell` and `rustls-pemfile` 2.2.0
(`RUSTSEC-2025-0134`) through the TLS link. Galadriel does not call either crate
directly and cannot replace them without changing the pinned NCP/Zenoh graph.
`cargo audit` must continue to report these notices, and the reviewed NCP/Zenoh
migration must remove or re-evaluate them. They are not vulnerability-free or
maintenance-assurance claims.

The release verifier rejects a Git lock source without a terminal full revision.
`cargo deny` rejects unknown sources and wildcard requirements. Any dependency
change invalidates the public-API snapshot, supply-chain reports, test evidence and
release manifest until regenerated against the new lockfile.

The exact checks are:

```bash
cargo deny --all-features --locked check
cargo deny --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```
