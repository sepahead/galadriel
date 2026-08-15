# Threat model

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| API | application programming interface |
| CA | certificate authority |
| CPU | central processing unit |
| DOI | digital object identifier |
| JSON | JavaScript Object Notation |
| mTLS | mutual Transport Layer Security |
| NCP | Neuro-Cybernetic Protocol |
| NIS | normalized innovation squared |
| PID | partial information decomposition |
| SBOM | software bill of materials |
| SPKI | Subject Public Key Info |
| TTL | time to live |
| URL | Uniform Resource Locator |
| WebPKI | Web Public Key Infrastructure |

This threat model covers the Galadriel 0.9.0 advisory monitor. It includes
evidence inputs, optional transport adapters, release artifacts, and downstream
use. It complements the deployment-specific ACL and mTLS model. It does not
replace that model.

## Register lifecycle

The machine-readable threat register remains `LIVING_UNTIL_CANDIDATE_FREEZE` during implementation.
Only the release operator can set it to `FROZEN_AT_CANDIDATE`.
The active signed audit-input pair and next signed commit complete that transition.
A later tracked change reopens the freeze and requires new candidate evidence.

## Assets and trust boundaries

The model protects these assets:

- integrity and availability of observation evidence
- provenance identities
- detector state and configuration
- report interpretation
- release evidence
- independence of the actual control and safety path

Trust crosses boundaries at the physical sensor, estimator or producer, NCP
transport, Galadriel decoder, detector core, evidence archive, and downstream
consumer.

The physical scene, sensor, and estimator are not trusted to be honest. A
producer-declared frame or prior is only a claim. A deployment must bind the
claim to an authenticated producer.

A strict local configuration file does not make the transport trusted. Galadriel
never receives controller, lease, plant, or authorization credentials.

An `AssessmentScope` is a validated provenance label.
The core binds it to the ordered observations and accepted release suite.
This binding does not authenticate the caller or producer.
The operational NCP adapter reduces this risk by deriving the scope from admitted
lifecycle state.
Transport authentication remains a separate boundary.

**GLD-090-THR-001:** Invalid, stale, missing, replayed, contradictory,
incomparable, or resource-excess evidence **SHALL NOT** become `Nominal`. It **SHALL**
produce a typed error, explicit insufficiency, unclassified evidence, or bounded
rejection.

**GLD-090-THR-002:** Galadriel **SHALL NOT** grant authority or authenticate
physical truth. It **SHALL NOT** infer malicious intent or replace an independent
safety mechanism. It **SHALL NOT** close a synchronous control feedback loop.

**GLD-090-THR-003:** Every ingestion surface **SHALL** set explicit bounds before
unbounded work or state growth. These bounds cover size, count, identity,
sequence, time, and retained state. The transport must also bound message size
before callback materialization.

## Adversaries and failures

The model includes these adversaries and failures:

- an external spoofer
- one or more compromised sensors
- a compromised or faulty producer
- a publisher with the wrong route, session, or epoch
- a network attacker without a valid credential
- a network attacker with a valid credential
- a replaying or delaying broker
- a malicious fixture or configuration author
- a direct library caller that supplies false lifecycle labels
- an accidental operator
- a downstream consumer that misinterprets advisory output

The model also covers ordinary faults, drift, clock errors, scheduler delays,
missing data, and overload. The evidence can make these events
indistinguishable from attacks.

| Threat | Required behavior | Residual risk or non-claim |
|---|---|---|
| Single-sensor spoof or fault | Magnitude and common-projection dependence evidence can localize inconsistency. The cause remains unclassified. | A bias inside the covariance model can evade detection. Association censoring can also hide it. |
| Correlated or coordinated compromise | Axis disagreement and broad magnitude changes fail closed. The report retains signed geometry. | A coordinated statistics-preserving attack can remain nominal. Galadriel does not claim truth. |
| Moment-matched spoof | Report only the observed statistics. | A spoof that preserves NIS and an evaluated dependence statistic can defeat both checks. |
| Association or gate missingness | Operational lifecycle evidence represents updates, rejections, misses, and heartbeats. Absence never becomes a healthy sample. | Historical successful-update-only captures have selection bias. They cannot validate cross-modal claims. |
| Partial sensor silence | Expected modalities remain unready or stale. They block nominal evidence. | All-modal silence needs a separate producer heartbeat and deadline. No input call advances detector time. |
| Timestamp freeze or regression | Reject the input as malformed. Do not change accepted state. | Authenticated but false producer time remains a producer-compromise case. |
| Excessive gap, skew, or reorder | Reset or abstain under the explicit epoch and window rules. Never align unequal tails by ordinal position. | Loss can cause prolonged abstention. It is a denial-of-service lever. |
| Replay or prior reuse | Reject duplicate or regressing identities. Reject cross-sequence frozen-prior reuse in the bounded operational assembler. | Lifetime replay protection requires epoch rollover before bounded ledgers become full. |
| Route/session/producer confusion | Check the exact realm, route, schema, session, producer, registry, and version. Reject or terminate wrong provenance. | Payload identity is not authenticated without transport identity and ACL binding. |
| Assessment-scope mislabeling | Bind producer, session, epoch, stream, generation, terminal sequence, terminal timestamp, and clock domain. The operational NCP adapter derives them from the admitted producer and position. Receipt verification requires evaluated reports to match that position. | A direct core caller can supply false labels. An explicit positioned caller supplies some control provenance. A digest verifies internal consistency, not identity or physical truth. |
| Router or server substitution | Use a private router hostname that cannot receive a public certificate. Control name resolution. Otherwise, an external layer must enforce the exact certificate or SPKI. Retain the presented certificate. | Zenoh 1.9 trusts built-in public WebPKI roots and the deployment CA. The local profile does not exclusively pin the router. This exclusivity is `NOT_CLAIMED`. |
| Malformed, duplicate-key, or oversized JSON | Bound size before parsing when the API permits this. Reject duplicate keys and non-exact integers. Retain typed fault counters. | Zenoh can allocate transport bytes before the application size gate. Broker bounds are mandatory. |
| Advisory replay or staleness | A future consumer must authenticate the advisory independently. It must bind profile digest, session, and time. Invalid input has no effect. | Live CLI records and lifecycle receipts are unsigned and not durable. Galadriel 0.9.0 has no qualified signed advisory publisher or consumer. |
| Verdict-induced authority widening | The core non-widening validator rejects authority increases. It covers deny-to-allow changes, limits, TTL values, leases, watchdog changes, and record-only changes. | A consumer that bypasses the validator is outside the claim. |
| Restriction abuse | Record-only is the only initial mode. A future restriction needs independent calibration, bounded effect, dwell, hysteresis, and recovery. | Restrict-only evidence is still a denial-of-service input. No such profile is qualified. |
| Feedback oscillation | Do not connect a verdict to control in the same epoch. | Offline joins can have confounding. Causal claims are excluded. |
| State or memory exhaustion | Cap tracks, windows, payloads, lines, records, queues, registry entries, join state, and estimator work. | Sustained valid traffic can force drops or abstention. Availability is not guaranteed. |
| CPU denial of service | Validate work bounds before pairwise MI, exhaustive-deletion, PID-study, or bootstrap work. Keep optional heavy features off by default. | Platform-specific deadlines need independent benchmarks and admission control. |
| Callback race or shutdown fault | Serialize ingress state. Retain the first terminal fault. Bound queues, account for drops, and test close and reset interleavings. | Operating-system, network, and actual-binary deployment timing remain unqualified. |
| Configuration substitution | Validate strict closed schemas and canonical digests. Bind profile, registry, and credential identities. | A privileged operator can replace local artifacts without deployment signing or attestation. |
| Candidate self-authentication | Authenticate the candidate and qualification tier with an independently obtained allowed-signers file. Treat the candidate-tracked signer file as metadata only. | Trust-root acquisition and signing-key protection remain operator responsibilities. A compromised independent trust root can authenticate false evidence. |
| Stale or redirected public `main` | Refresh the literal public URL and exact `main` refspec before candidate comparisons. Repeat the refresh before return or publication. Reject local Git settings that can redirect or weaken the operation. | A compromised public repository can still supply a false object. Public availability is not permanent preservation. |
| Dependency or source substitution | Require `Cargo.lock`, exact Git revisions, and pinned tool identities. Use the 16-key qualification environment. Use Rust and Cargo 1.97.1 only for the current-stable gate. Reject every Cargo configuration path before and after each command. | Registry compromise and compiler trust need external supply-chain controls. |
| Critical host-tool substitution | Pin direct Apple developer Git and fixed `/usr/bin` SSH tools. Require root-owned no-follow regular-file identities before and after execution. Pin `/usr/bin/sandbox-exec` to its exact path and expected byte identity. Record its owner, group, and mode. Remove loader and toolchain selectors from the host environment. | The qualifier does not hold a no-follow descriptor for `sandbox-exec` across candidate execution. These checks do not attest the operating system distribution or trusted tool correctness. |
| Advisory database substitution | Require a clean external RustSec clone at the exact origin, commit, and tree. Install detached copies in isolated tool state. Prohibit network fetches during report generation. | The pinned database can omit a defect. A qualification result remains bound to the pinned input. |
| Package or source-archive substitution | Compare the source archive with the exact Git tree. Compare every package member byte and mode with the tracked crate-file map. Permit only the two declared generated package files. | Package evidence describes unpublished source artifacts. It does not prove crates.io publication or deployed-binary content. |
| SBOM substitution or hidden component | Close every SBOM root, target, package, dependency, identity, license, checksum, scope, and edge against validated Cargo metadata and `Cargo.lock`. Reject hidden nested components and null authors. | In a passing qualification, the SBOMs describe the qualified source graph. They do not identify a deployed target environment. |
| Host or target license-scope confusion | Require the exact 382-package `CARGO_DENY_HOST_FILTERED_GRAPH` subset of the validated 437-package graph. Bind its exact package and license semantic digests. | This inventory does not describe another host or target graph. It is not an all-target license inventory. |
| Artifact-generation result substitution | Require qualification schema v3 and exactly 22 auxiliary command receipts. Bind commands, sandboxes, exits, logs, streams, and artifacts. Retain 15 two-run source, package, and SBOM comparisons. | The comparisons are author-operated on one recorded host. They do not prove independent or cross-platform reproduction. |
| Candidate-evidence substitution | Build the runner separately. Put the mode-`0500` snapshot in a private mode-`0700` directory. Execute that snapshot directly. Require `galadriel.evidence.summary.v3` and `galadriel.evidence.manifest.v3`. Require acceptance profile `galadriel-0.9-frozen-acceptance-metrics-v3`. Require bootstrap profile `splitmix64-rejection-group-metric-v1`. Stream every trial. Rebuild the summary, report, checksums, and candidate acceptance result. Bind the exact commit, tree, inputs, and runner executable. | Host semantic replay checks agreement with the frozen contract. It does not prove model validity, field calibration, or independent replication. |
| Acceptance-result laundering | Preserve every failed criterion. Set `NARROWED_REVIEW_REQUIRED` when executable qualification passes but acceptance fails. Require a signed human `NARROWED_GO` or `NO_GO` decision with exact failure dispositions. Prohibit `GO` for a failed criterion. | A human can still make an incorrect risk decision. Signed provenance does not make that judgment correct. |
| Mutation descendant escape | Require the Linux process file system (`procfs`), process file descriptors, and serialized child-subreaper ownership. Arm a stop-before-exec gate. Verify the process-global controls at each checkpoint. Require exclusive single-threaded trusted-runner ownership. Track adopted children. Reap the root last. | An uninterruptible process can outlive the stop deadline. A subreaper gap can lose an identity before stable capture. A control change that starts and ends between checkpoints is not observable. This control is not a control group, container, or deployment-isolation boundary. It cannot attribute external-service work. |
| Qualification descendant escape | Require macOS `kqueue` and `/usr/bin/sandbox-exec`. Deny candidate signal operations by default. Permit signals only to self and children. Arm a stop-before-exec gate. Track the original process group. Scan for the inherited sandbox identity. Signal only the bound group before root reap. Use read-only post-reap checks. | The qualifier does not signal an escaped numeric process identifier. macOS process discovery is not atomic. A short-lived reparented process can exit between scans. The scan cannot attribute external-service work. |
| Evidence tampering or cherry-picking | Retain complete logs, checksums, exact commits, toolchains, seeds, status ledger, and residual risks. Retain all 13 signed mutation artifacts. Bind candidate, tree, and tag in the signed four-asset release map. Reconstruct against an independent trust root. | Galadriel 0.9.0 has no independent archive or DOI. GitHub availability is not permanent preservation. |
| Valid outer map with invalid inner tier | Authenticate both internal tier signatures during build, verification, and reconstruction. Bind both manifests to the expected candidate and tree. Verify each complete signed inventory and checksum file. | The same independent trust root authenticates the outer and inner layers. Trust-root compromise remains an external risk. |

## Fail-closed states

Malformed representation is an error. Statistical non-identifiability is
`InsufficientEvidence`. Positive but non-localizable evidence is
`UnclassifiedAnomaly`. A transport or assembler integrity fault stops the
affected epoch.

Resource pressure causes a documented bounded rejection or drop. Health
accounting records this action. None of these states becomes `Nominal`. None of
them directly commands a plant.

## Deployment security acceptance boundary

Component tests can establish parsing, state, and policy invariants. Deployment
qualification also requires an actual multi-process router campaign. The campaign
must retain this evidence:

- correct-certificate allow results
- wrong-certificate and no-certificate denials
- wrong-route denials
- replay and stale behavior
- saturation and resource measurements
- the router certificate that the test observed
- the server-authentication mitigation
- independent configuration identities

This evidence does not exist for 0.9.0.
Thus, multi-process deployment security qualification remains `NOT_CLAIMED`.
