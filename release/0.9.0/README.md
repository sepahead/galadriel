# Galadriel 0.9.0 source release record

## Abbreviations

| Short form | Meaning |
|---|---|
| API | application programming interface |
| DOI | digital object identifier |
| HTML | Hypertext Markup Language |
| JSON | JavaScript Object Notation |
| NCP | Neuro-Cybernetic Protocol |
| PID | partial information decomposition |
| ROS | Robot Operating System |
| SHA-256 | Secure Hash Algorithm 256 |
| SSH | Secure Shell |
| URL | Uniform Resource Locator |
| ZIP | ZIP archive format |

This directory contains the auditable source release record for Galadriel's Mirror 0.9.0.
The release author is **Sepehr Mahmoudian**.
The intended publication channel is a review-gated GitHub research source release.
Source preparation state for this tree: `UNPUBLISHED_CANDIDATE` with no candidate release date.
It does not claim crates.io publication, a DOI, or a Zenodo record.

[`handoff-source.json`](handoff-source.json) identifies the current external handoff.
It records the exact archive and task-ledger digests.
The repository does not contain the superseded handoff copy.
Inherited prose supplies provenance.
It does not supply new evidence.

[`tasks.json`](tasks.json) contains the current 116-task projection.
[`VERSION-ADAPTATION.md`](VERSION-ADAPTATION.md) maps the 1.0 design target to version 0.9.0.
This adaptation does not weaken a technical, safety, or evidence obligation.

The immutable handoff projection calls T055 through T059 the "Optional PID
adapter" and names `crates/galadriel-pid/**`. Those strings are historical source
vocabulary, not the current package or scientific identity. In this candidate they
map to `galadriel-dependence`: a target-free pairwise-MI companion that cannot
alter the accepted verdict. Real PID is confined to fixed-target offline studies.
The projection bytes remain unchanged so the repository does not rewrite the
handoff record after the fact.

**GLD-090-AUD-001:** The release **SHALL** generate a canonical audit manifest.
The manifest **SHALL** cover each qualification input in these groups:

- repositories
- toolchains
- Git dependencies
- datasets, fixtures, and evidence
- normative documents
- external sources

The audit manifest uses schema `galadriel.release-audit-manifest.v2`.
Each local artifact **SHALL** record its path, Git mode, blob identifier, byte length, purpose, and SHA-256 value.
A mutable or abbreviated repository identity **SHALL NOT** qualify.

The generator captures the relevant stage-zero index one time.
It fetches and authenticates all indexed blobs in one bounded batch.
All semantic checks use those captured bytes.
One held-root transaction compares each worktree regular file with the same index identity.

The audit manifest excludes only itself from its tracked-file inventory.
A file cannot contain its own cryptographic digest.
The generator records and enforces this exact exclusion.
It includes `requirements-ledger.json` and all other tracked paths.
The signed full-source archive separately binds the audit manifest bytes.

**GLD-090-LED-001:** The requirement ledger **SHALL** contain exactly T000 through T115.
It **SHALL** keep dependency order.
A `COMPLETE` task **SHALL** have normative `SHALL` requirements and retained evidence.
It **SHALL** also have all twenty handoff lenses and a residual-risk disposition.
Prose alone **SHALL NOT** close a task.

## Append-only CLM-018 assurance extension

[`clm-018-assurance.json`](clm-018-assurance.json) governs the CREBAIN
categorical-MGW study added after the immutable T000-through-T115 handoff
projection. It is an append-only claim-assurance extension: it does not insert a
task into `tasks.json`, change any historical task byte, manufacture a historical
disposition, or mark post-commit candidate evidence complete. The extension binds
the SHA-256 identities of the historical task projection, closure plan, and empty
candidate-disposition interface so that this separation fails closed.

**GLD-090-CLM-018:** Claim `CLM-018` **SHALL** remain an `IMPLEMENTED` claim about
one physically parameterized **synthetic categorical conformance law**. It **SHALL
NOT** be described as physical validation, recorded-flight evidence, complete
producer state isolation, 64 independent experimental units, continuous-PID
validity, closure of pid-rs's separate 108-coordinate assurance program, field
or deployment performance, or control authority. The eight repeats per source
cell establish only bounded-summary fresh-instance reproducibility.

The assurance extension separates the immutable producer fixture source, the
producer's historical pid-rs preregistration, the actual clean pid-core
implementation revision, and the candidate build identity. It retains the producer fixture bytes
and records three append-only corrections: target construction occurs after sensor
objects and source symbols are built. NIS, the two-arm CUSUM with an inert lower
arm on the fusion core's `dof=3` route, and signed Pearson correlation are distinct
non-PID operational diagnostics. The legacy
`projection_count=3` field counts admitted observations rather than proving three
present projections.

Every exact candidate **SHALL** run and retain all five named gates in the
extension:

1. The Rust fixture, algebra, source-identity, resource, errata, and metamorphic
   contract tests.
2. The bounded closed-world Draft 2020-12 schema hostile-test suite.
3. The separately implemented 80-digit Decimal oracle hostile-test suite.
4. The end-to-end wrapper test, which runs the actual offline Rust binary through
   the exact formal schema and Decimal route.
5. The candidate qualifier's direct execution of that wrapper, which retains one
   canonical receipt containing the exact Rust output SHA-256 value and byte size,
   schema identity, Decimal-oracle identity, comparison counts, error, tolerance,
   and separate schema/Decimal pass states.

Schema conformance and numerical agreement are separate gates. The Decimal route
does not call pid-rs, but it remains law-specific software corroboration rather
than independent experimental evidence. It does not independently recompute the
retained pointwise atoms. The extension applies all twenty release-review lenses,
with a counterexample, control or claim removal, exact evidence, and remaining
risk for each lens. Its closure is deliberately limited to the bounded source
claim. Candidate-bound execution, qualified independent human review, and
independent clean-room reproduction remain outstanding.

## Release records

- `RELEASE-NOTES.md` contains the tracked body text for the review-gated GitHub release.
  It preserves each unavailable deployment, integration, archival, and policy-use claim.
- `audit-inputs.json` contains the retained release-input inventory.
  Its `audit_date` is the maintainer-local calendar date of the latest audit-input update.
  It cannot precede any retained inspection or observation date at its declared precision.
  Its peer objects form a separate audit-input cut.
  They do not claim each mutable peer head on the audit date.
  `audit-manifest.json` is the generated repository inventory.
  It uses schema `galadriel.release-audit-manifest.v2`.
  Its artifact rows bind Git modes and blob identifiers.
- The active signed audit-input manifest uses schema `galadriel.frozen-audit-inputs.v2`.
  It binds each release-input path, Git mode, blob identifier, SHA-256 value, and size.
  It derives source semantics and release-tool coverage from one bounded index capture.
  It also binds each external handoff regular-file mode.
- The unversioned signed version 1 pair is a historical record.
  It is not the active pair.
- `claims.json` separates implemented, validated, deployment-qualified, and unclaimed behavior.
  Version 0.9.0 has no deployment-qualified claim.
- `clm-018-assurance.json` is the append-only assurance and twenty-lens evidence map
  for the bounded synthetic CREBAIN categorical-MGW claim. It does not modify or
  retroactively close the immutable 116-task projection.
- `handoff-source.json` identifies the immutable source package.
  `tasks.json` contains the current task-index projection.
- `task-closure-plan.json` records the required task closure.
  `task-dispositions.json` and `requirements-ledger.json` record its source state.
  These records do not represent future review as complete.
- `ecosystem-cut.json` records the dated peer observations and each relationship direction.
  It records build and runtime optionality, the graph rationale, and the acyclic boundary.
  It records the immutable 2026-08-03 NCP release-status snapshot separately
  from the wire-0.8 dependency pin.
  It also records the Haldir supersession and dated Paper2Brain observation.
  Paper2Brain remains an explicit integration non-edge.
  Mutable heads record provenance only.
  The two Cargo revisions are the only dependency pins.
  [`docs/ECOSYSTEM-CONNECTIONS.md`](../../docs/ECOSYSTEM-CONNECTIONS.md)
  cross-references the separate retained audit-input objects.
- `local-convergence-schema.json` adapts the supplied convergence schema to version 0.9.0.
  Finalization creates a signed exact-candidate `LOCAL-CONVERGENCE.json` file.
  Creation occurs only after all 116 dispositions and ten wave acceptances pass.
  Complete file review and all retained artifacts must also pass.
  The record must state the fixed local cross-repository requirements.
- The release process locally qualifies the exact pid-rs and NCP pin graphs.
- Crebain remains an optional reference producer.
- Haldir remains a prospective record-only consumer.
- Prisoma remains a prospective immutable offline consumer.
- Engram, Paper2Brain, ROS, and external authority remain absent edges.
- Reciprocal and deployed relationships remain absent or unclaimed.
- If reciprocal reconciliation starts, it can use `LOCAL-CONVERGENCE.json` as an entry point.
  The record does not prove acceptance by another repository.
- `repo_work/package_release_assets.py` creates two deterministic path-preserving tar files.
  It also creates a canonical asset map and detached `galadriel-release-assets` signature.
  The signed map binds both tar byte identities to the exact candidate and tree.
  It binds the signed tag object and target, the author, and null DOI and Zenodo fields.
  Verification enforces the exact four-file upload set.
- `api/` contains the public source API baseline and accepted 0.9.0 surface.
- `evidence/` contains complete command output instead of pass or fail summaries.
- `reviews/` contains the phase record, review method, and incomplete comment template.
  The final twenty-lens review is a separately signed post-commit input.
- `reviews/REVIEW-COMMENTS.md` is an incomplete comment interface bound to the eventual exact candidate.
  It does not claim that an external person reviewed or approved the release.

Generate and verify deterministic audit artifacts with these commands:

```console
python3 -B -E -s -S scripts/release_audit.py generate
python3 -B -E -s -S scripts/release_audit.py verify
```

## Candidate qualification

Create the exact signed source commit before qualification.
Run qualification from that immutable commit.
Use a new output directory outside the checkout.

The mutation evidence contains exactly 13 artifacts.
These artifacts are seven outcome files, five run receipts, and one retained `git.diff`.
Each of the four broad outcome files has one broad shard receipt.
The three focused outcome files share one focused receipt.
All four broad shards and all three focused outcomes are exact-candidate gates.

Deep quality also requires one separate bounded CREBAIN MGW gate on the same
exact head. It enumerates 149 selected mutants and requires 146 caught, three
exact compile-unviable function-return substitutions, and no missed, timed-out,
or surviving mutant. The dedicated `crebain-mgw-mutation` job uploads its
candidate-bound receipt and outcome as `crebain-mgw-mutation-results`.
The signed version 5 assembler does not add these two files to its established
13-artifact set. Retain and verify the separate workflow artifact until a
reviewed mutation-evidence schema revision admits it.

Each exact mutation command uses environment schema `galadriel.mutation-environment.v2`.
It requires the Linux process file system (`procfs`), process file descriptors, and serialized child-subreaper ownership.
It starts behind a stop-before-exec gate.
It reaps the root only after the tracked candidate tree becomes extinct.
It fails before process creation when a required host control is unavailable.
An uninterruptible process can outlive the stop deadline and causes a failed run.
This cleanup control is not a control group, container, or deployment-isolation boundary.

The observational mutation-baseline job is residual evidence.
It is not a successful release gate.
The acceptance-estimation scope has exactly 26 mutants.
It requires 23 caught mutants and three exact compile-unviable replacements.
It permits no missed, timed-out, or surviving mutant.

The qualifier fetches the locked workspace graph and the locked fuzz graph.
Both fetches complete before the offline metadata and dependency-policy gates.
It uses the exact 16-key base environment in `docs/DEPENDENCY-POLICY.md`.
It isolates home, Cargo, target, and temporary state in the private qualification root.
It does not pass ambient credentials, proxies, wrappers, loader variables, or compiler flags.
It rejects a file, directory, or link at each Cargo configuration path.

It checks before and after each retained command.

The signed qualification record binds this environment policy.

The qualifier refreshes public `main` before each candidate comparison.
It repeats the refresh before it returns.
It uses the literal public repository URL and exact `main` refspec.
It rejects local Git settings that can redirect or weaken the fetch.

The evidence command must create exactly six flat regular files.
These files are `SHA256SUMS`, `config.json`, `manifest.json`, `report.md`, `summary.json`, and `trials.jsonl`.
Each file has a 1 GiB limit.
The complete set has a 4 GiB limit.
The host snapshots the set without following links.
It compares source, quarantine, snapshot, and installed bytes.

The summary uses schema `galadriel.evidence.summary.v3`.
The manifest uses schema `galadriel.evidence.manifest.v3`.
Acceptance uses profile `galadriel-0.9-frozen-acceptance-metrics-v3`.
Bootstrap uses profile `splitmix64-rejection-group-metric-v1`.

The qualifier builds the release runner before it executes evidence.
It creates a private directory with mode `0700`.
It copies the runner into that directory through no-follow descriptors with mode `0500`.
It executes that exact runner snapshot directly.
The evidence manifest binds the runner digest and exact candidate commit and tree.

The host parses only bounded bytes from the verified snapshot.
It streams each trial record in exact order.
It independently rebuilds the complete summary and report.
It verifies the accepted configuration, manifest, and exact checksum document.
It evaluates acceptance from the rebuilt holdout summary.
Finalization repeats the complete replay against the signed outer inventory.
Only a run that uses `--deep` can have qualification status `PASS`.
Qualification tests all four feature-isolated CLI profiles.
The deep run tests and checks the complete fuzz workspace.
It runs 5,000 cases for each of the three fuzz targets.
Each target reads tracked semantic seeds.
Each target uses one fixed pseudorandom seed.
It writes mutations only to the private qualification root.
One direct Cargo command builds all fuzz binaries with `--locked` and `--offline`.
The host validates and copies each binary to a private mode-`0500` path.
The verifier requires `LC_LOAD_DYLIB` for each library and one `/usr/lib/dyld` linker command.
It rejects lazy, weak, re-exported, and upward library loads.
Each campaign executes its exact snapshot directly.
The record binds both lockfiles and the pinned AddressSanitizer runtime.

The qualification record uses schema `galadriel.candidate-qualification.v3`.
The run needs these external inputs:

- an agent-backed Ed25519 public-key handle
- an independently obtained allowed-signers file
- the exact pinned external RustSec advisory database
- the signed exact-candidate mutation pair
- the tracked evidence configuration

```console
repo_work/verify_release_python_runtime.sh \
  -B -E -s -S repo_work/qualify_candidate.py \
  --repo . \
  --expected "$(git rev-parse HEAD)" \
  --require-branch main \
  --out /new/path/galadriel-0.9.0-qualification \
  --signing-key "$(git config --get user.signingkey)" \
  --allowed-signers /independent/path/ALLOWED_SIGNERS \
  --advisory-db /independent/path/advisory-db \
  --pkg-config /opt/homebrew/Cellar/pkgconf/3.0.3/bin/pkgconf \
  --mutation-evidence /path/to/exact-candidate-mutation.json \
  --mutation-evidence-signature /path/to/exact-candidate-mutation.json.sig \
  --evidence-config evidence/galadriel-0.9-candidate.json \
  --deep --keep-going
```

A passing tier must retain exactly 22 auxiliary command receipts.
It must compare one source archive, seven package archives, and seven software bills of materials twice.
These 15 comparisons require byte-identical results.

Each command uses a stop-before-exec gate and fixed resource limits.
Critical host Git and SSH operations bind direct Apple developer Git, `/usr/bin/ssh-add`, and `/usr/bin/ssh-keygen`.
The host verifies each root-owned no-follow file identity before and after use.
It pins `sandbox-exec` to `/usr/bin/sandbox-exec` and its expected byte identity.
It records the resolved path, owner, group, and mode.
The `cc` and `clang` entries resolve to one private mode-`0500` driver.
The driver executes the pinned Clang and applies the fixed SDK after caller arguments.
The qualifier binds the SDK root link and `SDKSettings.json` around each process.
It does not attest every SDK file or the complete Apple compiler supply chain.
The dispatch binds three executable files in the `CPython 3.14.6` runtime inventory.
It binds the complete CPython version tree before and after qualification.
The native launcher binds that tree and then replaces itself with pinned Python.
It removes its private verification state before it replaces itself.
It restores the caller's umask before Python starts.
It verifies all three executable files and six non-system libraries around each process.
Retained Python commands use `-B -E -s -S`.
The `-B` flag prevents Python from writing `.pyc` files when it imports source modules.
The outward Homebrew `site-packages` link remains unreadable and outside `sys.path`.
It binds the exact Rustup settings file before and after qualification.
It binds `bin`, `lib`, and `libexec` for each selected Rust toolchain.
The sandbox grants those roots instead of the complete Rustup home.
It excludes the unused Rust `etc` and `share` roots from candidate reads.

These inventories detect a change that persists to a checkpoint.
They do not make the user-owned Homebrew or Rustup trees immutable.
A concurrent process under the same operating-system user can replace a path between checkpoints.
The sandbox prevents candidate writes but does not control that external process.
Use a separately protected, read-only toolchain for stronger execution-byte assurance.

The sandbox does not grant read bindings for execution-denied CMake or pkgconf.
It does not grant the complete Homebrew or Anaconda prefix.
It permits the pinned launcher and application trampoline under Homebrew.
It denies the framework file as a direct process target.
It denies each same-name tool shim in the four system `PATH` roots.
It permits the exact selected target after these same-name denials.
It does not deny every differently named executable in an allowed operating-system or runtime root.
Those executables and external-service behavior remain trusted host inputs.
The candidate file, write, network, and signal restrictions still apply.
It retains CMake and pkgconf as named entries but denies their execution.
Neither exact locked graph declares their Cargo helper package.
The runtime record binds declared non-system inputs only.
It does not prove universal runtime closure.
It does not bind transitive operations performed by candidate-built code.

The candidate sandbox denies signal operations by default.
It permits signals only to self and children.
The qualifier signals the original process group before it reaps the root.
After root reap, it uses only read-only extinction checks.
macOS does not provide atomic recursive descendant tracking.
A short-lived reparented process can exit between scans.
The sandbox-identity scan detects an active detached process that retains that identity.

The inherited sandbox and resource limits apply before candidate execution.
A sandboxed process can request work from an existing external service.
The process scan cannot attribute that external service work.

The license inventory covers the exact 381-package `CARGO_DENY_HOST_FILTERED_GRAPH` scope.
It does not cover all 436 packages for every target.

The frozen 100-track evidence design has two structural acceptance failures.
`GLD-090-ACC-001` needs at least 369 tracks under its zero-event Garwood bound.
`GLD-090-ACC-006` needs at least 738 tracks under its Hoeffding bound.
The frozen condition grid and observation ceiling permit at most 248 holdout tracks.

Executable qualification can therefore pass while acceptance fails.
That result uses `release_gate=NARROWED_REVIEW_REQUIRED`.
The qualifier does not select a publication disposition.
A signed human decision must select `NARROWED_GO` or `NO_GO`.
It must preserve each failed criterion and residual risk.
It must map each failed criterion to removed claim `CLM-007`.
`GO` is prohibited while an acceptance criterion fails.

The release input pins the external RustSec database identity at the 2026-07-23 inspection cut.
The inventory contains 1,187 entries.
Its SHA-256 value is `bfc26634ed164598c75c91fc462f0fa527b73634859faeb9476f2631bf529619`.
A qualification result remains bound to that pinned input.

Use this exact post-commit evidence order:

1. Sign the final twenty-lens review.
2. Create and sign the candidate-bound version 3 release decision.
3. Bind that decision to the review and its signature.
4. Create and sign the ordered task dispositions.
5. Cite the retained review and decision for tasks T114 and T115.

`repo_work/finalize_release.py` verifies and copies the exact input bytes.
It stages the complete closure and flushes it.
It publishes the closure with one atomic, no-replace, same-parent rename.
These records remain outside the candidate checkout.
Their creation cannot change the source identity.

A pre-publication failure leaves the requested output absent.
Use `--snapshot-dir` to select an existing non-link directory outside the repository and qualification tier.
Restrict directory access to the release operator.
The bounded qualification snapshot can use up to 8 GiB plus review inputs.
Use an agent-backed Ed25519 public-key handle.

Keep the handle outside the repository, qualification tier, output, and snapshot root.
Require the handle to match the independently obtained allowed-signers file.

The finalizer snapshots only the canonical public fields.
It never snapshots private signing material.

The rename is the commit point.
Status 3 means that the rename committed a complete output.
It means that the tool did not confirm one or more items: durability, the result report, or cleanup.
An independent verifier must check that bundle before use.

Status 4 means that the rename completed without confirmed destination identity or tree completeness.
Do not describe the requested path as a complete output.
Preserve the parent directory and stop publication.

## Publication assets

Create the signed annotated `v0.9.0` tag after finalization.
Publish exactly these four assurance assets:

- `galadriel-0.9.0-qualification.tar`
- `galadriel-0.9.0-closure.tar`
- `galadriel-0.9.0-release-asset-map.json`
- `galadriel-0.9.0-release-asset-map.json.sig`

Build these files only with `repo_work/package_release_assets.py build`.
Download all four files before publication verification.
Use an independently obtained allowed-signers trust root.
Verify the complete four-file set with the same tool.

Use `extract` and `reconstruct` to recover the original tier roots.
These actions do not trust an archive path.
Build, verification, and reconstruction authenticate both internal tier signatures.
They bind each tier to the expected candidate commit and tree.
They verify each complete signed inventory and `SHA256SUMS` file.
Verify `LOCAL-CONVERGENCE.json` against the exact candidate.

GitHub creates source ZIP and tar archives automatically.
Use them only as convenience snapshots.
They are not members of the signed asset map.
They do not replace either evidence tar file.
`RELEASE-RUNBOOK.md` contains the normative draft-first procedure.

The internal tier signatures use principal `sepmhn@gmail.com`.
They use these literal SSH namespaces:

- `galadriel-qualification-manifest`
- `galadriel-closure-manifest`

The outer asset-map namespace is `galadriel-release-assets`.
The runbook gives the exact independent-trust-root commands.

## Public verification

Post-publication verification resolves all six immutable release-body `blob` links.
It compares each raw file with the applicable tagged Git blob.
It also checks schema `$id` URLs for these schemas:

- local convergence
- historically named PID observation envelope
- monitor envelope

The verifier compares schema bytes with their tagged Git blobs.
It does not represent an HTML `blob` response as source bytes.

The release title must be `Galadriel 0.9.0`.
The release body must equal the complete tracked `RELEASE-NOTES.md` file.
Do not infer the release body from its Markdown title.

Canonical asset construction, verification, and reconstruction use the audit-pinned `CPython 3.14.6`.
Compare authenticated and anonymous downloads with all four local source files.
This check remains mandatory when GitHub omits an API digest.

The verifier rejects these conditions:

- stale output
- duplicate JSON keys
- mutable Git dependencies
- prose-only task closure
- incomplete twenty-lens reviews
- incorrect author or version metadata
- a project DOI or Zenodo claim
