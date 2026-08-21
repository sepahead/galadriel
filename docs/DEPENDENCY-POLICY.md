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
lockfile with registry checksums. Each dependency-resolving Cargo invocation
**SHALL** use `--locked`. A retained build **MUST NOT** use a tool that starts
Cargo without forwarding `--locked`. The compatible manifest requirements support
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
The sandbox does not grant read access to the complete `RUSTUP_HOME` tree.
It grants only the exact Rustup settings file and selected runtime roots.

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

The release audit binds each frozen focused mutant to its tracked source span.
Before each focused run, pinned cargo-mutants enumerates the complete selected set.
The runner rejects a source-span, transformation, or set difference before mutation execution.

Deep quality has one additional bounded gate for the CREBAIN MGW scientific
contract. It uses cargo-mutants 27.1.0 and Rust 1.89.0. It selects only
`crebain_mgw.rs` functions matched by the frozen seven-name expression. A
non-executing listing must contain exactly 155 mutants and match canonical
line-insensitive multiset digest
`31fa7f1288a1bb23d63065515ea2789dfdc1da46c5339d789fd4689167b2b269` before
execution starts. The executed result must contain 152 caught mutants and three
exact compile-unviable `Ok(Default::default())` function-return substitutions.
It permits no missed, timed-out, or surviving mutant. The gate validates each
full descriptor and exact Cargo phase command. Its receipt binds the candidate
commit, tree, toolchain, command, outcome bytes, and GitHub run.

The signed version 5 mutation assembler retains its established 13 artifacts.
The CREBAIN receipt is a separate required exact-head workflow artifact until a
reviewed mutation-evidence schema revision admits it. Do not silently add it to
the version 5 count or omit its deep-quality result.

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
Qualification tests all four feature-isolated CLI profiles.
These tests execute feature-disabled assertions.
An all-feature test cannot reach those assertions.
The deep run tests and checks the complete fuzz workspace.
It runs 5,000 cases for each declared fuzz target.
Each target reads tracked semantic seeds.
Each target uses one fixed pseudorandom seed.
Each target writes mutations only under the private `TMPDIR`.
One direct Cargo command builds all fuzz binaries with `--locked` and `--offline`.
The command uses the pinned nightly compiler and the frozen sanitizer flags.
The host copies each binary into a private mode-`0500` runner directory.
It validates each Mach-O load command and run path before and after the copy.
It requires `LC_LOAD_DYLIB` for all four declared libraries.
It requires one `/usr/lib/dyld` `LC_LOAD_DYLINKER` command.
It rejects lazy, weak, re-exported, and upward library loads.
Each campaign executes its exact snapshot directly.
The record binds both `Cargo.lock` files and the pinned AddressSanitizer runtime.
The finalizer rejects a declared fuzz binary that has no retained campaign.

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
Completion is on time only when the host first observes the root exit before the
monotonic deadline.
A root exit first observed at or after the deadline records `timed_out=true`.
This rule also applies when the process has exit status zero.
Cleanup that starts for another recorded failure keeps that primary classification.
The host requires macOS `kqueue` and `/usr/bin/sandbox-exec`.
It fails before candidate execution if either control is absent.

The qualifier installs one mode-0500 dispatch for 19 required command names.
It verifies every dispatch target before and after each bounded process.
The dispatch binds direct Apple developer Git and the matching developer tools.
The `cc` and `clang` entries resolve to one private mode-`0500` driver.
The driver executes the pinned Clang and appends the fixed SDK selector after caller arguments.
The qualifier binds the SDK root link and `SDKSettings.json` around each bounded process.
This binding does not attest every SDK file or the complete Apple compiler supply chain.
It binds three executable files in the `CPython 3.14.6` runtime inventory.
It binds the complete 4,098-entry CPython version tree before and after qualification.
It binds the six non-system dynamic libraries loaded by that CPython framework.
The operator starts release Python through `repo_work/verify_release_python_runtime.sh`.
The native launcher uses privileged Bash startup and root-owned macOS tools.
It binds the same runtime tree and then replaces itself with the pinned interpreter.
It removes its private verification state before it replaces itself.
It restores the caller's umask before Python starts.
It prevents a changed startup module from running before the first tree measurement.
It verifies all three executable files and six libraries around each bounded process.
Each retained Python command uses `-B -E -s -S`.
The `-B` flag prevents Python from writing `.pyc` files when it imports source modules.
The CI workflow rejects any remaining import bytecode cache after the governance test suite.
The `-E` flag ignores Python environment selectors.
The `-s` and `-S` flags disable site initialization.
The Homebrew version tree contains one outward `site-packages` link.
That target remains outside the sandbox read allowlist and outside `sys.path`.
The qualifier binds the exact Rustup settings file before and after qualification.
It also binds `bin`, `lib`, and `libexec` for each selected Rust toolchain.
The selected toolchains are `1.89.0`, `1.97.1`, and `nightly-2026-06-16`.
The three runtime inventories contain 81, 108, and 174 entries, respectively.
The sandbox grants only those runtime roots under `RUSTUP_HOME`.
It does not grant the `etc` or `share` roots.
Retained commands do not use those excluded roots.
An added runtime read outside the declared roots fails closed in the sandbox.

These inventories detect a change that persists to a checkpoint.
They do not make the user-owned Homebrew or Rustup trees immutable.
A concurrent process under the same operating-system user can replace a path between checkpoints.
The sandbox prevents candidate writes but does not control that external process.
Use a separately protected, read-only toolchain for stronger execution-byte assurance.

The operator supplies the exact `pkgconf 3.0.3` executable through `--pkg-config`.
The value must use the fixed absolute path in the release input.
The qualifier verifies the 74,928-byte executable and its SHA-256 identity.
It verifies mode `0555` and repeats the file check after each bounded process.
It does not select `pkg-config` from ambient `PATH`.
The dispatch retains CMake and pkgconf as required named entries.
The candidate sandbox denies execution of both entries.
Neither exact locked graph declares their Cargo helper package.
A future dependency that needs either tool fails closed until its inputs are bound.
The sandbox does not grant a read binding for either execution-denied tool.
This rule removes the Anaconda read surface from candidate commands.
The sandbox grants the CPython version root and exact external library paths.
It grants the three byte-inventoried Rust runtime root sets.
It grants each other non-system tool as an exact file or dispatch directory.
It does not grant the full Homebrew prefix.
It permits process execution for the pinned launcher and application trampoline.
The launcher uses that exact trampoline to start the interpreter.
The sandbox denies direct execution of the framework runtime file.
The sandbox denies each same-name tool shim in the four system `PATH` roots.
It permits the exact selected target after these same-name denials.
It does not deny every differently named executable in an allowed operating-system or runtime root.
Those executables and external-service behavior remain trusted host inputs.
The candidate file, write, network, and signal restrictions still apply.
It denies signal operations by default.
It permits a candidate process to signal only itself or its children.
Thus, candidate code cannot signal an unrelated external process through the sandbox policy.

This inventory binds declared non-system runtime inputs.
It does not prove universal runtime closure.
It excludes operating-system loader state and data-dependent dynamic loads.
It also excludes transitive operations performed by candidate-built code.
It also excludes external services and unobserved crash-path helpers.

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
The validated graph contains 436 packages and seven workspace packages.

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
It contains the exact 381-package host-filtered subset of the validated
436-package graph.
It contains exactly 705 license assignments.
Its sorted package-identity set has this SHA-256 value:
`272dc6ab496ff2c0c9a43991c01b8b2d5a9ce1004afcc15adbea6c25908ab280`.
Its canonical package-and-license content has this SHA-256 value:
`bcc6f05fe91eaecf62f74db821453b6d35d01fbf7fe94245e7c74ecc9ed24822`.
The supply-chain CI job rebuilds this inventory from locked metadata.
It verifies both exact digests.

The digest calculation normalizes each workspace package identity.
The exact identity form is `workspace+crates/{name}#{name}@{version}`.
This inventory does not describe another host or target graph.

The license-policy summary requires zero errors and zero warnings.
It also requires 374 accepted help records and seven skipped notes.
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
The dependence, evaluation, and offline justification paths require the immutable pid-rs revision
`bc3aa80fb6025e709c2906a08bce25a4fac40578`.
Its `pid-core` manifest declares `0.9.0`.
This revision is an experimental component input.
It is not the identity of current pid-rs `main`.
No resolved Galadriel feature profile contains `pid-runlog`. The dependence
adapter uses `ksg_mi_report_with_budget`. Its retained estimate and its executed
report use the same explicit single-thread `ResourceBudget`. Revision
`1cd2424f7967e1752dcc8e53859e8fdad3566f51` is a historical input retained by
the immutable CREBAIN producer preregistration and the migration record, not a
second active dependency pin.
Upstream pid-rs release qualification remains `NOT_CLAIMED`.

NCP qualification applies only to the commit selected by the public annotated
`v0.8.0` tag.
The exact NCP revision is `2f5bd586d4bb20c90362bb6f5698b7f64057ba4e`.
The 2026-08-03 NCP status inspection is bound to
[commit `1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd`](https://github.com/sepahead/NCP/commit/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd).
That commit is the unreleased and release-blocked `1.0.0-rc.1` candidate.
It uses wire `1.0` and compact `CONTRACT_HASH` `163acc57d8a62b66`.
The local wire-0.8 qualification does not apply to that candidate or to NCP 1.0.
Galadriel has no native-1.0 migration or compatibility evidence.

The pinned [NCP task ledger](https://github.com/sepahead/NCP/blob/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd/evidence/implementation/task-ledger.v1.json)
records `G03` as `OPEN`.
`G03` depends on `X02`, which is also `OPEN`, so `G03` is not dependency-ready.
The `Galadriel NCP observer` and `Galadriel raw-advisory publisher` external
qualifications have no exact evidence and remain **NOT RUN**.

The pinned [NCP ecosystem blueprint](https://github.com/sepahead/NCP/blob/1bcfb190d4d9a2e0032f44e634854ff9ed19a0bd/docs/handoff/NCP_V1_0_ECOSYSTEM_FINALIZATION_BLUEPRINT.md)
defines the release-facing publisher as the `Galadriel assessor` surface.
The observer requires a read-only principal and an exact bounded grant.
The assessor requires a separate principal and a default-off push-only path.
Its payload contains raw verdict and evidence provenance with an optional
non-authoritative requested effect.
It cannot reuse observer credentials, self-admit, derive `StateUnusable`, grant
or widen authority, or encode an authoritative effect, `ALLOW`, or command.
No native-1.0 raw-advisory publisher exists.
Galadriel 0.9 records native-1.0 integration as `NOT_CLAIMED`.
That claim tier is separate from NCP's external **NOT RUN** gate state.
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
