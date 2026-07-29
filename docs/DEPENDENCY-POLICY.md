# Qualification dependency policy

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| CI | continuous integration |
| CPU | central processing unit |
| JSON | JavaScript Object Notation |
| JSONL | JavaScript Object Notation Lines |
| NCP | Neuro-Cybernetic Protocol |
| SBOM | software bill of materials |
| SHA | Secure Hash Algorithm |
| SHA-256 | Secure Hash Algorithm 256 |
| TLS | Transport Layer Security |
| URL | Uniform Resource Locator |

**GLD-090-PIN-001:** Every Git dependency used for qualification **SHALL** name a
full 40-hex `rev`. `Cargo.lock` **SHALL** resolve the same commit. A branch-only,
tag-only, abbreviated, floating-main, or local sibling-path substitution
**SHALL NOT** qualify a release.

**GLD-090-PIN-002:** Registry dependencies **SHALL** resolve through the committed
`Cargo.lock` with registry checksums. Every qualification command **SHALL** use
`--locked`. The compatible version requirements in the manifest support
maintenance resolution. They are not the qualification identity.

Qualification uses this exact 16-key base environment:

- `CARGO_HOME`
- `CARGO_INCREMENTAL`
- `CARGO_TARGET_DIR`
- `CARGO_TERM_COLOR`
- `GIT_ATTR_NOSYSTEM`
- `GIT_CONFIG_GLOBAL`
- `GIT_CONFIG_NOSYSTEM`
- `GIT_OPTIONAL_LOCKS`
- `GIT_TERMINAL_PROMPT`
- `HOME`
- `LC_ALL`
- `PATH`
- `RUSTUP_HOME`
- `SOURCE_DATE_EPOCH`
- `TMPDIR`
- `TZ`

The signed contract identifies `HOME`, `PATH`, and `RUSTUP_HOME` as host tool
inputs.
If `RUSTUP_HOME` is absent, the qualifier derives it from the host `HOME` value.
The candidate `HOME` value remains isolated.
The resulting `PATH` and `RUSTUP_HOME` values can contain host paths.
These values MUST NOT contain credentials.

The qualifier creates isolated `HOME`, `CARGO_HOME`, `CARGO_TARGET_DIR`, and
`TMPDIR` directories.
It sets the fixed values in the signed environment contract.
The documentation command adds the frozen `RUSTDOCFLAGS=-D warnings` override.
No other ambient credential, proxy, wrapper, loader, or compiler variable enters
a candidate command.

Critical host Git and SSH commands do not trust `PATH` resolution.
They bind fixed root-owned regular executables through no-follow descriptors.
They capture each executable digest and file identity before execution.
They require the same identity after execution.

The fixed Git and SSH paths are:

- `/Applications/Xcode.app/Contents/Developer/usr/bin/git`, when present
- `/Library/Developer/CommandLineTools/usr/bin/git`, as the second Git choice
- `/usr/bin/ssh-add`
- `/usr/bin/ssh-keygen`

The qualification record handles `sandbox-exec` separately.
It pins the invoked and resolved paths to `/usr/bin/sandbox-exec`.
It records the SHA-256 value, size, owner, group, and mode.
Finalization requires the expected SHA-256 value and size.

The host environment removes dynamic-loader and toolchain-selection variables from these commands.
This control does not attest the operating system or compiler supply chain.

The qualifier rejects every file-system entry at `.cargo/config` or
`.cargo/config.toml`.
It also rejects a `.cargo` search path that is not a direct directory.
It checks the command directory, each ancestor, and the isolated Cargo home.
It checks before and after each retained command.

It fetches the locked workspace graph and the locked fuzz graph.
Both fetches use the declared network-enabled dependency-fetch sandbox.
They complete before the offline metadata and dependency-policy gates.

Qualification requires an independently obtained `--allowed-signers` file.
The file **MUST** be outside the repository and qualification output.
The candidate-tracked signer file is comparison metadata only.
It does not authenticate the candidate or a qualification bundle.

Qualification also requires a clean external RustSec advisory database clone.
The release input pins this database identity at the 2026-07-23 inspection cut.
The clone has this exact identity:

- origin: `https://github.com/RustSec/advisory-db`
- commit: `f981d991604f3e7d4a0eb94e559cb3e5a94a6dc2`
- tree: `26bea0ac10667f826b5522a828a27861ae4b5287`
- inventory entries: `1187`
- inventory SHA-256: `bfc26634ed164598c75c91fc462f0fa527b73634859faeb9476f2631bf529619`
- Cargo deny directory: `advisory-db-3157b0e258782691`

The qualifier rejects a dirty clone or another origin, commit, or tree.
It also rejects Git replacement references.
It installs detached copies in the isolated Cargo home.
The candidate sandbox denies read access to the original external clone.
Candidate commands can read only the installed detached copies.

The vulnerability commands use those copies without a network fetch.
A qualification result remains bound to that pinned input.
A new candidate can select a later database through a reviewed input change.

The source-archive command uses the same base environment.
It disables Git replacement objects.
It sets `tar.umask=0022` and `core.attributesFile=/dev/null` on the command line.
The validator compares each archive type, mode, owner, time, and content with the
exact Git tree.

## Mutation command containment

Exact mutation receipts use environment schema `galadriel.mutation-environment.v2`.
Each mutation host command uses Linux candidate-tree containment.
The runner requires the Linux process file system (`procfs`), process file descriptors, and child-subreaper control.
It also requires exclusive, single-threaded ownership of the process-local subreaper state.
It fails before process creation when a required control is absent.

The command starts behind a stop-before-exec gate.
The runner tracks the root, its original process group, and children adopted by the subreaper.
It reaps the root only after the tracked candidate tree becomes extinct.
Each containment checkpoint verifies the default disposition of the child-status signal (`SIGCHLD`).
It also verifies the active child-subreaper state.
A control change poisons the process and prevents verified success.
The runner cleans a stable process file descriptor (`pidfd`) identity when it can prove extinction.
It cannot signal an identity that escaped before stable capture during a subreaper control gap.
A control change that starts and ends between checkpoints is not observable.
The contract therefore requires exclusive single-threaded ownership by the trusted runner.
An uninterruptible process can outlive the stop deadline.
This result fails closed and prevents reuse of the uncertain containment state.

This control is process cleanup.
It is not a control group, container, or deployment-isolation boundary.
It cannot attribute work that an existing external service performs.

## Qualification artifact contract

`qualification.json` uses schema `galadriel.candidate-qualification.v3`.
It records exactly 22 auxiliary command receipts:

- one Cargo metadata receipt
- two source-archive receipts
- fourteen package-archive receipts
- two SBOM batch receipts
- one license-inventory receipt
- one license-report receipt
- one vulnerability-report receipt

Each receipt binds the exact argument vector and working directory.
It also binds the sandbox policy, exit status, log, and stream digests.
A passing signed qualification manifest **MUST** bind every retained receipt and
artifact byte.

The evidence command **MUST** create exactly six flat regular files.
These files are `SHA256SUMS`, `config.json`, `manifest.json`, `report.md`,
`summary.json`, and `trials.jsonl`.
Each file has a 1 GiB limit.
The complete set has a 4 GiB limit.
The host walk does not follow links or open blocking special files.
It rejects a missing, extra, nested, linked, or special entry.

The host streams the set into a private snapshot.
It compares source, snapshot, quarantine, and installed identities.
It fails closed on size or digest drift.
It uses only bounded bytes captured from the verified snapshot.
Only a run that uses `--deep` can have qualification status `PASS`.

The candidate evidence runner uses a separate build and execution sequence.
The build command is `cargo build --release --locked -p galadriel-eval --bin galadriel-evidence`.
The host copies the built executable into a private mode-`0700` directory.
The executable copy has mode `0500`.
The copy uses no-follow descriptors and a bounded byte count.
The host then executes that exact snapshot directly.
The runner digest in `manifest.json` must match the direct executable identity.

The exact evidence profiles are:

- `galadriel.evidence.summary.v3`
- `galadriel.evidence.manifest.v3`
- `galadriel-0.9-frozen-acceptance-metrics-v3`
- `splitmix64-rejection-group-metric-v1`

The last profile uses SplitMix64 with unbiased rejection sampling over complete tracks.

After the byte snapshot, the host replays the complete six-file semantics.
It validates every ordered trial record through a bounded JSONL stream.
It independently rebuilds `summary.json` and `report.md`.
It verifies `manifest.json`, `config.json`, and the exact checksum document.
It binds all input identities to the candidate commit and tree.
It then evaluates acceptance from the rebuilt holdout summary.
Finalization repeats the same replay against the signed outer inventory.

This replay can produce a schema-valid candidate acceptance result with `status=FAIL`.
That result does not change a passing executable qualification status.
When the executable gates pass and acceptance fails, qualification uses `NARROWED_REVIEW_REQUIRED`.
Only a later signed human decision can select `NARROWED_GO` or `NO_GO`.
`GO` is prohibited while an acceptance criterion fails.

Each command starts behind a stop-before-exec launch gate.
The command receives fixed CPU, core-file, output-file, open-file, and 64 MiB
stream limits.
The host requires macOS `kqueue` and `/usr/bin/sandbox-exec`.
It fails before candidate execution if either control is absent.

The qualifier installs one mode-0500 dispatch for 19 required command names.
It verifies every dispatch target before and after each bounded process.
The dispatch binds direct Apple developer Git and the matching developer tools.
It also binds the running `CPython 3.14.6` executable.
The sandbox denies direct execution of `/usr/bin/git` and `/usr/bin/python3`.
It denies signal operations by default.
It permits a candidate process to signal only itself or its children.
Thus, candidate code cannot signal an unrelated external process through the sandbox policy.

The macOS tracker observes process groups.
It also scans for the inherited sandbox identity.
It signals only the original group while the root identity remains waitable.
It does not send a signal to an escaped numeric process identifier.
An observed escaped sandbox identity fails the run.
After root reap, it performs only read-only extinction checks.

macOS does not provide atomic recursive descendant tracking.
A short-lived reparented process can exit between scans.
The sandbox-identity scan detects an active detached process that retains that identity.

The inherited sandbox and resource limits apply before candidate execution.
A sandboxed process can request work from an existing external service.
The process scan cannot attribute that external service work.

Generic trusted host commands cover the root and original process group only.
They do not track a descendant that creates another session.
Candidate-controlled commands MUST use the platform-specific candidate containment mode.

The resolved Cargo metadata validator binds the locked all-feature graph.
The validated graph contains 437 packages and seven workspace packages.

The qualifier makes 15 two-run byte comparisons.
One comparison covers the source archive.
Seven comparisons cover unpublished package archives.
Seven comparisons cover CycloneDX 1.5 SBOM documents.
These comparisons show same-host reproduction under the recorded command
contract.
They do not show independent or cross-platform reproduction.

Each package validator receives the exact tracked file map for its crate.
The map renames tracked `Cargo.toml` to `Cargo.toml.orig`.
The validator compares every mapped member byte and mode.
It requires the exact member set.
Only generated `Cargo.toml` and `.cargo_vcs_info.json` can be additional members.
The package artifacts remain unpublished and do not prove a crates.io release.

Each SBOM validator closes root, target, package, dependency, and graph fields.
It compares those fields with validated Cargo metadata and `Cargo.lock`.
It rejects null or mismatched authors.
It rejects hidden nested components and extra identity fields.
It rejects conflicting package URLs, licenses, references, checksums, scopes, or
graph edges.

In a passing qualification, the SBOMs describe the qualified source graph.
They do not identify a deployed binary or target environment.

The license inventory uses scope `CARGO_DENY_HOST_FILTERED_GRAPH`.
It contains the exact 382-package host-filtered subset of the validated
437-package graph.
It contains exactly 707 license assignments.
Its sorted package-identity set has this SHA-256 value:
`5d4cc699506276347efb798c206893da68caa9c9e45f650c08b4a48ffbbab1ce`.
Its canonical package-and-license content has this SHA-256 value:
`0d74d13996da359c9aaffe01978b1bd5e58b1188ff63026ce7d4347da734a0e3`.
The supply-chain CI job rebuilds this inventory from locked metadata.
It verifies both exact digests.

The digest calculation normalizes each workspace package identity.
The exact identity form is `workspace+crates/{name}#{name}@{version}`.
This inventory does not describe another host or target graph.

The license-policy summary requires zero errors and zero warnings.
It also requires 375 accepted help records and seven skipped notes.
The vulnerability report requires the pinned database and exact `Cargo.lock`.
It retains the two declared unmaintained-package warnings.
These checks do not prove vulnerability-free code or maintenance assurance.

**GLD-090-PIN-003:** The Rust compiler **SHALL** use the exact channel in
`rust-toolchain.toml`. CI actions **SHALL** use commit-SHA pins. Generated
artifacts **SHALL** record tool versions and exact repository and dependency
identities.

Qualification pins Apple Git 2.50.1 for source-archive and repository
verification.
The workspace gate uses Rust and Cargo 1.89.0.
The current-stable compatibility gate uses Rust and Cargo 1.97.1.
It runs all-target, all-feature Clippy and all-feature workspace tests.

**GLD-090-PIN-004:** An upstream version declaration is not a released
integration without a signed or released tag or artifact. It **SHALL NOT** be
described as one.

The default build excludes pid-rs.
The PID, evaluation, and justification paths require the immutable pid-rs revision
`1cd2424f7967e1752dcc8e53859e8fdad3566f51`.
Its manifest declares `1.0.0`.
This revision is an experimental component input.
It is not the identity of current pid-rs `main`.
Upstream pid-rs release qualification remains `NOT_CLAIMED`.

NCP qualification applies only to the commit selected by the public annotated
`v0.8.0` tag.
The exact NCP revision is `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`.
This qualification does not apply to NCP 1.0 or current NCP `main`.
GitHub reports that the tag object and target commit are unsigned.
The immutable 40-hex revision and Cargo lock entry give identity.
They do not give upstream signature assurance.

**GLD-090-PIN-005:** Yanked registry releases **SHALL** fail dependency review by
default. A temporary exception **SHALL** name the exact package, owner, reason,
and expiry.

The only 0.9.0 exceptions are `spin` 0.9.8 and 0.10.0. The exact NCP 0.8 and
Zenoh 1.9 graph selects them transitively. Neither package has a RustSec advisory
in the checked database. The exceptions expire on 2026-10-01.
The reviewed NCP and Zenoh migration **SHALL** remove them.

The separate ignored `RUSTSEC-2026-0041` entry has the same owner and expiry. It
is admissible only while CI proves that the complete all-feature graph excludes
Zenoh transport compression.

The resolved metadata gate requires one crates.io `zenoh-transport` 1.9.0 package.
It also requires one matching node.
It requires exactly `shared-memory`, `transport_tcp`, `transport_tls`,
`transport_udp`, and `zenoh-shm`.
It rejects a missing, duplicate, or additional package, node, or feature.
It also rejects another source or version.

**GLD-090-PIN-006:** The primary and isolated fuzz workspaces **SHALL** use
separate least-privilege license and source policies. `deny.toml` admits only the
licenses and Git sources in the primary graph.

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
change to the pinned NCP and Zenoh graph. `cargo audit` **MUST** continue to report
these notices. The reviewed NCP and Zenoh migration **MUST** remove or reevaluate
them.
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
cargo fetch --locked
cargo fetch --locked --manifest-path fuzz/Cargo.toml
cargo deny --offline --all-features --locked check
cargo deny --offline --manifest-path fuzz/Cargo.toml --all-features --locked check --config fuzz/deny.toml
```
