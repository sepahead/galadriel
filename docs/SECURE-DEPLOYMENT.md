# Secure operational receiver runbook

## Abbreviations

| Short form | Meaning |
|---|---|
| ASCII | American Standard Code for Information Interchange |
| CN | certificate common name |
| JSON | JavaScript Object Notation |
| JSON5 | JavaScript Object Notation 5 |
| NCP | Neuro-Cybernetic Protocol |
| PEM | Privacy-Enhanced Mail |
| SHA-256 | Secure Hash Algorithm 256 |
| TLS | Transport Layer Security |
| WebPKI | Web Public Key Infrastructure |

Status: runnable component implementation and external evidence procedure.

The repository supplies checked configuration artifacts, a secure observer command, and bounded receiver components.
The repository does not claim deployment of the example identities.
Continuous integration (CI) loopback tests do not prove remote mutual Transport Layer Security (mTLS) authorization.
A current reciprocal Crebain pin remains `NOT_CLAIMED`.
Current cross-repository qualification also remains `NOT_CLAIMED`.

## Identity and epoch handoff

Before either application opens a route, an operator fixes this operational join key:

```text
(realm, epoch, producer_id)
  -> exact observation key
  -> exact monitor key
  -> producer certificate CN
  -> observer certificate CN
  -> one pinned registry digest
```

The `epoch` identifies a producer process.
It does not identify an NCP control session.
The `epoch` and `producer_id` use the Galadriel core identity grammar.

Each value contains 1 through 64 ASCII bytes.
Each identity starts and ends with a letter or digit.
Each identity can contain letters, digits, hyphens, underscores, periods, and colons.
Galadriel rejects other generic NCP segment forms, such as Unicode text or `+`.

Before any sequence, replay, or prior-identity reset, create a new epoch.
Never reuse an epoch.

The Galadriel sidecar schema version 1.0 has no wildcard discovery protocol.
Before startup, an operator or deployment orchestrator must distribute the exact epoch out of band.
Then, render the access control list (ACL) for that epoch.
Start the producer and receiver with the same epoch.
If a value differs, startup or payload validation must fail.
An ACL change to `session/*` is not a recovery method.

The profile `producer_id` controls application validation.
The exact producer certificate common name (CN) controls transport authorization.
Zenoh does not inspect the JavaScript Object Notation (JSON) claim.
Thus, the deployment requires both checks.

The router can accept a client certificate from its configured client-authentication certificate authority (CA).
If that certificate has the profile CN, its client can write the two routes.
Galadriel rejects an envelope when `producer_id` differs from the configured value.
The ACL does not bind one leaf fingerprint.
The certificate authority must reserve each role CN.
It must prevent unintended duplicate issuance.

It must record each authorized leaf serial and fingerprint.

The profile also records `registry_canonical_sha256`.
The router ACL does not contain this value because the router cannot interpret application registry semantics.
The value is part of the deployment handoff.
It must match the intended producer registry pin.
It must match Galadriel `--registry-sha256`.
It must also match each frame summary.

The generated nonsecret `galadriel-handoff.json` binds the digest to the realm, epoch, producer identifier, and both client CNs.
`SHA256SUMS` includes the handoff digest.

## Configuration procedure

Follow [`deploy/README.md`](../deploy/README.md) to render the router, two clients, and application handoff.
Before use, verify `SHA256SUMS`.
Review all four generated artifacts.

The security invariants follow:

| Boundary | Required state |
| --- | --- |
| Router transport | One explicit TLS listener. Mutual TLS enabled. Discovery off. No upstream connection. Fail on a listen error. |
| Producer authority | Send `put` ingress only. Two exact realm and epoch sensor keys. One exact producer certificate CN. |
| Observer authority | Send `declare_subscriber` ingress and receive matching `put` egress only. Use the same two exact keys. Use a distinct exact observer certificate CN. |
| Default behavior | Deny. Grant no wildcard epoch or sensor. Grant no command, action, lease, query, remote procedure call (RPC), delete, or control operation. |
| Client transport | Exactly one bare `tls/` router endpoint. No endpoint-local `#` configuration. No `?` metadata suffix. Enable connector-side mTLS and client-certificate presentation. Disable listeners and discovery. Enable hostname checks and certificate-expiration closure. Use built-in public WebPKI roots plus the configured deployment CA. |
| Receive allocation | A 131,072-byte Zenoh message limit applies to the router and both clients. The 65,536-byte application envelope limits remain active. |

### TLS server-authentication limitation

The pinned Zenoh 1.9 client initializes its server-authentication root store from public `webpki_roots`.
Then, it adds `root_ca_certificate`.
Thus, the deployment CA is one more trust anchor.
It is not an exclusive router-CA pin.

A built-in public root can issue a time-valid certificate for the exact router hostname.
That certificate can satisfy client-side server authentication without the deployment CA.
Hostname and expiration verification still apply.
The configured client-authentication CA and ACL still constrain producer and observer certificates at the router.

The pinned dependency has no Galadriel configuration switch that removes the built-in roots.
`SecureZenohCapability` proves the checked local profile.
It does not prove an exclusive router-certificate or Subject Public Key Info (SPKI) pin.
That exclusivity is `NOT_CLAIMED`.

Until the dependency supplies an exclusive-root mode, use a private router hostname.
The hostname must not qualify for public CA issuance.
Keep its name resolution under deployment control.
Alternatively, add an external connection layer that enforces the exact router certificate or SPKI.
Record the presented fingerprint as evidence.
The record does not enforce a pin.

The 128 KiB transport value permits bounded frame overhead around a maximum 64 KiB application envelope.
An increase changes the security profile and intentionally breaks the checker.
Before a decrease, record an interoperability test with all maximum valid envelopes.

The renderer requires regular files that exist at absolute deployment paths.
It rejects relative paths, inline PEM material, and inline base64 material.
It rejects duplicate JSON keys at each JSON object depth.
It canonicalizes each path.
It rejects textual, symbolic-link, case-folded, and hard-link aliases.

On `Portable Operating System Interface (POSIX)` systems, each private key must permit owner reads.
The key must not permit execution.
The key must not permit group or other access.
On Unix systems, the runtime observer repeats device-and-inode alias checks before it opens Zenoh.
It also repeats the private-mode checks.
On each platform, the renderer requires absolute canonical paths to regular files that exist.

Keep the profile and configurations outside locations with broad read access.

The committed references use strict JSON.
Strict JSON is also valid JSON5.
Thus, review and digest calculation do not depend on a permissive parser.

The runtime secure opener accepts only a standalone regular-file configuration.
Before parsing, it reads no more than 262,144 bytes, inclusive.
It requires strict JSON content when the filename uses the Zenoh `.json5` convention.
At each JSON object depth, it rejects a `__config__` external-include key.

At validation time, each configured CA, public certificate, and private key has an inclusive limit of 1,048,576 bytes.
One byte above either limit causes a typed startup error.
These checks bound the local read before open.
They also reject unreviewed include expansion.
They do not remove a credential-file replacement race after validation.

Runtime validation returns a typed `SecureConfigError` and an opaque `SecureZenohCapability`.
Only the foreign bus-open boundary maps that error to a Zenoh type.

Endpoint discovery stops when it finds a second connect endpoint.
It also stops when it finds a listen endpoint.
Each recursive endpoint extraction has a limit of 256 JSON nodes and depth 16.

The sole connect endpoint rejects a Zenoh `#` endpoint-local configuration.
It also rejects a `?` metadata suffix.
Fragment configuration merges after the validated global TLS settings and can weaken those settings.
Query metadata can change transport behavior, such as reliability.
Thus, the secure profile requires the exact bare endpoint.
It does not maintain another allowlist for the Zenoh endpoint grammar.

The capability identity binds the validated endpoint and allocation ceiling.
It also binds the canonical credential-path strings.
It does not hash credential contents or freeze file-system state after validation.
It does not remove credential-file replacement races.
It does not attest the remote router.
Deployment evidence must record leaf fingerprints and serials.

The deployment must protect the credential directory separately.

## Startup and health sequence

1. Before startup, record the Galadriel commit identifier.
2. Record the selected external-producer commit identifier.
3. Record the registry SHA-256, profile digest, handoff digest, and generated configuration digests.
4. Record the endpoint hostname, name-resolution control, and leaf certificate serial and fingerprint metadata.
5. If public CA issuance is possible for the hostname, record the external pin control.
6. Start the secure Zenoh router.
7. Confirm that the router loaded mTLS and access control.
8. Record the router certificate that each client received.
9. Start the Galadriel observer for the exact realm, epoch, producer, and pinned registry.
10. For acceptance evidence, use the explicit secure client path.
11. Within the 30 s first-heartbeat grace period, start the selected external producer.
12. Supply the exact deployment epoch and producer identity to that producer.
13. Require monitor heartbeat progression before you treat traffic as live.
14. Surface the first terminal tap or assembler fault.
15. Surface bounded queue depth, drops, reorder state, gap state, heartbeat age, incomplete frames, and registry mismatch.
16. Surface epoch-lifetime prior and observation-stream capacity.
17. Before a replay-protection map reaches its fixed cap, rotate to a coordinated new epoch.

A library on a caller-supplied bus inherits that bus security.
Receiver activation starts the finite 30 s first-heartbeat grace period.
The producer and receiver must use the same exact epoch.
An orchestrator can make this handoff atomic.

If the producer starts before the exact ACL exists, an initial prefix can remain unobserved.
The acceptance process does not accept this condition.
Observation traffic alone does not prove lifecycle completeness.
A heartbeat after a fault cannot repair an expired deadline or sequence gap.
Replay-protection maps never evict within an epoch.
Ambiguous evidence remains ineligible for `Nominal`.

The repository command-line interface uses the explicit secure path.
It uses the receiver fixed v1 defaults.
The first-heartbeat grace period is 30 s.
Then, the producer heartbeat interval is 1 s, and its receipt deadline is 3 s.
The reorder deadline is 1 s, and the frame deadline is 5 s.

```bash
export NCP_ZENOH_CONFIG=/secure/config/galadriel-epoch/zenoh-observer.json5
cargo run --locked --features ncp-live --bin galadriel -- observe \
  --realm engram/ncp \
  --epoch "$GALADRIEL_DEPLOYMENT_EPOCH" \
  --producer-id "$GALADRIEL_PRODUCER_ID" \
  --registry "$GALADRIEL_REGISTRY_PATH" \
  --registry-sha256 "$GALADRIEL_REGISTRY_DIGEST"
```

The command requires the epoch as input.
It does not create the epoch.
Before either application starts, put the exact epoch in the router ACL and producer environment.

Each Galadriel secure live path loads the configuration one time.
It validates connector-side mTLS and the other strict client invariants.
Then, it opens that same parsed value.
This sequence prevents a configuration reparse mismatch.
It does not freeze external credential files.
Only the external drills can identify the credentials that the producer, observer, and router used.

They can show that the remote router loaded and enforced its policy.

## Authorization and fault drill

Run each drill from a separate process.
Retain timestamps and router and client logs.
If necessary, remove sensitive paths from the records.
Never retain keys or credential bytes.

| Drill | Expected result |
| --- | --- |
| Correct producer CN, both exact keys | Valid bounded envelopes reach the matching taps. |
| Correct producer CN, other epoch or sensor name | The router denies publication. |
| Correct producer CN, command, action, lease, or RPC key | The router denies the operation. |
| Observer CN subscribes to both exact keys | The subscription succeeds. |
| Observer CN puts either exact key or any control key | The router denies the operation. |
| Untrusted, wrong-CN, missing, or expired client certificate | The TLS connection or authorization fails. |
| Router certificate has the wrong hostname, is expired, or chains to neither configured nor built-in roots | Client TLS fails. |
| Exact-hostname router certificate chains only to a built-in public root | The pinned Zenoh client can accept it. Do not record this result as exclusive custom-CA authentication. |
| Payload identity differs from configured producer or session | The receiver rejects it, even after transport delivery. |
| Message exceeds 128 KiB transport cap | The transport drops or rejects it before application decode allocation. |
| Connect endpoint carries a `#` configuration or `?` metadata suffix | Local secure-configuration validation rejects it before Zenoh opens. |
| Envelope exceeds 64 KiB application cap | The tap rejects it and latches a visible fault. |
| Duplicate, gap, excessive reorder, queue overflow, or frame deadline | The receiver invalidates the affected frame or suffix. The result is never `Nominal`. |
| Heartbeats stop | A liveness fault occurs at the configured monotonic receipt-time deadline. |
| Producer restarts with the same epoch | A protocol fault occurs. The receiver does not reset state or recover silently. |
| Producer restarts with a fresh coordinated epoch | Old subscription and state retire under a bounded handoff. New state starts empty. |

The in-process Zenoh tests validate exact keys, bounded handoff, codec behavior, and sequence behavior.
They do not replace the certificate and ACL tests in the table.
An isolated loopback session has no external router principal to attest.

The configured deployment CA controls router-side client authentication.
The public and deployment root set controls client-side router authentication.
The profile checks expiration.
It does not configure a certificate revocation list (CRL) or Online Certificate Status Protocol (OCSP) mechanism.

Do not claim rejection of a revoked but unexpired leaf without an external control.
The deployment must add and record that revocation or CA-rotation control.
It must also test the control.

## Evidence interpretation

A complete frame can enter the statistical detector only after all route checks agree.
The checks cover identity, sequence, projection context, prior context, registry, outcome counts, and deadline.
Transport authentication establishes who could publish.
It does not establish physical truth.
It does not make a verdict a calibrated posterior.
Galadriel remains advisory and must not directly widen or exercise a control authorization.

The v1 frame summary does not list the pre-association track set.
It also does not contain a digest of that set.
Thus, even a complete v1 join cannot independently prove the full track-by-modality opportunity cardinality from receiver data alone.
Treat this condition as a declared evidence limitation and a v2 schema gate.
Do not infer success from this condition.
