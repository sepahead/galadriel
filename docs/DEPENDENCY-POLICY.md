# Qualification dependency policy

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| CI | continuous integration |
| NCP | Neuro-Cybernetic Protocol |
| SHA | Secure Hash Algorithm |
| TLS | Transport Layer Security |

**GLD-090-PIN-001:** Every Git dependency used for qualification **SHALL** name a
full 40-hex `rev`. Cargo.lock **SHALL** resolve the same commit. A branch-only,
tag-only, abbreviated, floating-main, or local sibling-path substitution
**SHALL NOT** qualify a release.

**GLD-090-PIN-002:** Registry dependencies **SHALL** resolve through the committed
Cargo.lock with registry checksums. Every qualification command **SHALL** use
`--locked`. The compatible version requirements in the manifest support
maintenance resolution. They are not the qualification identity.

**GLD-090-PIN-003:** The Rust compiler **SHALL** use the exact channel in
`rust-toolchain.toml`. CI actions **SHALL** use commit-SHA pins. Generated
artifacts **SHALL** record tool versions and exact repository and dependency
identities.

**GLD-090-PIN-004:** An upstream version declaration is not a released
integration without a signed or released tag or artifact. It **SHALL NOT** be
described as one.

The lockfile selects an older and immutable optional pid-rs revision. Its manifest
declares `1.0.0`. This revision is an experimental component input. It is not the
identity of current pid-rs `main`. Upstream pid-rs release qualification remains
`NOT_CLAIMED`.

NCP qualification applies only to the commit selected by the public annotated
`v0.8.0` tag. It does not apply to NCP 1.0 or current NCP `main`. GitHub reports
that the tag object and target commit are unsigned. The immutable 40-hex revision
and Cargo lock entry give identity. They do not give upstream signature
assurance.

**GLD-090-PIN-005:** Yanked registry releases **SHALL** fail dependency review by
default. A temporary exception **SHALL** name the exact package, owner, reason,
and expiry.

The only 0.9.0 exceptions are `spin` 0.9.8 and 0.10.0. The exact NCP 0.8 and
Zenoh 1.9 graph selects them transitively. Neither package has a RustSec advisory
in the checked database. The exceptions expire on 2026-10-01. The reviewed
NCP/Zenoh migration shall remove them.

The separate ignored `RUSTSEC-2026-0041` entry has the same owner and expiry. It
is admissible only while CI proves that the complete all-feature graph excludes
Zenoh transport compression.

**GLD-090-PIN-006:** The production and isolated fuzz workspaces **SHALL** use
separate least-privilege license and source policies. `deny.toml` admits only the
licenses and Git sources in the production graph.

`fuzz/deny.toml` also admits NCSA for one reason. `libfuzzer-sys` combines it with
MIT or Apache-2.0. This policy admits no other Git source except the exact NCP
dependency. Both locked checks are release gates.

**GLD-090-PIN-007:** Informational dependency advisories **SHALL** remain visible
as release risks. This requirement applies when policy limits enforcement to
workspace-owned packages.

The locked Zenoh 1.9 graph contains two unmaintained transitive dependencies:

- `paste` 1.0.15 (`RUSTSEC-2024-0436`) through `token-cell`
- `rustls-pemfile` 2.2.0 (`RUSTSEC-2025-0134`) through the TLS link

Galadriel does not call either crate directly. It cannot replace them without a
change to the pinned NCP and Zenoh graph. `cargo audit` must continue to report
these notices. The reviewed NCP/Zenoh migration must remove or reevaluate them.
These facts do not claim vulnerability-free code or maintenance assurance.

The release verifier rejects a Git lock source without a terminal full revision.
`cargo deny` rejects unknown sources and wildcard requirements. A dependency
change invalidates this release material:

- public-API snapshot
- supply-chain reports
- test evidence
- release manifest

Regenerate this material against the new lockfile after a dependency change.

Run these exact checks:

```bash
cargo deny --all-features --locked check
cargo deny --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```
