# Secure operational receiver runbook

Status: runnable component implementation and external evidence procedure. The
repository supplies checked configuration artifacts, a secure observer command,
and bounded receiver components; it does not claim that the example identities
have been deployed or that CI loopback tests prove remote mTLS authorization.

## Identity and epoch handoff

The operational join key is fixed before either application opens a route:

```text
(realm, epoch, producer_id)
  -> exact observation key
  -> exact monitor key
  -> producer certificate CN
  -> observer certificate CN
  -> one pinned registry digest
```

`epoch` is a producer-process identifier, not an NCP control-session claim. It must
be freshly minted before sequence, replay, or prior-identity state is reset and may
never be reused. Galadriel v1 deliberately has no wildcard discovery protocol. An
operator or deployment orchestrator must distribute the exact epoch out of band,
render the ACL for it, then start the producer and receiver with that same value.
If any value disagrees, startup or payload validation must fail; widening the ACL
to `session/*` is not a recovery mechanism.

The profile's `producer_id` binds application validation, while its exact producer
certificate CN binds transport authorization. Zenoh does not inspect the JSON
claim, so both checks are required: any certificate accepted by the configured CA
and carrying the profiled CN can write the two routes, while Galadriel rejects an
envelope whose `producer_id` does not equal the configured expectation. The ACL does
not bind a unique leaf fingerprint. The issuing CA must reserve each role CN, prevent
unintended duplicate issuance, and record every authorized leaf serial/fingerprint.

The profile also records `registry_canonical_sha256`. It is not rendered into the
router ACL, because the router cannot interpret application registry semantics; it
is the deployment handoff value that must exactly match Crebain's registry pin,
Galadriel's `--registry-sha256`, and every frame summary. The generated nonsecret
`galadriel-handoff.json` binds that digest to the realm, epoch, producer ID, and both
client CNs; its digest is included in `SHA256SUMS`.

## Configuration procedure

Follow [`deploy/README.md`](../deploy/README.md) to render the router, two clients,
and application handoff. Verify `SHA256SUMS` and review all four generated artifacts
before use. The security invariants are:

| Boundary | Required state |
| --- | --- |
| Router transport | one explicit TLS listener, mutual TLS enabled, discovery off, no upstream connection, fail-on-listen error |
| Producer authority | send `put` ingress only; two exact realm/epoch sensor keys; one exact producer certificate CN |
| Observer authority | send `declare_subscriber` ingress and receive matching `put` egress only; the same two exact keys; a distinct exact observer certificate CN |
| Default behavior | deny; no wildcard epoch/sensor grant and no command, action, lease, query/RPC, delete, or control grant |
| Client transport | explicit TLS router, connector-side mTLS/client-certificate presentation enabled, no listeners/discovery, hostname verification and certificate-expiration closure enabled |
| Receive allocation | 131,072-byte Zenoh message limit on router and both clients; 65,536-byte application envelope limits remain active |

The 128 KiB transport value allows bounded framing overhead around a maximum 64 KiB
application envelope. Increasing it is a security-profile change and intentionally
breaks the checker. Decreasing it requires a recorded interoperability test showing
that all maximum valid envelopes still pass.

The renderer requires existing regular files at absolute production paths, rejects relative
or inline PEM/base64 material and duplicate JSON keys at any nesting depth, canonicalizes
those paths, and refuses textual, symlink, case-folded, or hard-link aliases. On POSIX it
also requires every private key to be owner-readable, non-executable, and inaccessible to
group/other; the runtime observer repeats these credential-file checks before opening
Zenoh. Keep the profile/configs outside broadly readable locations. The committed references
are strict JSON (and therefore valid JSON5) so review and digest calculation do not depend
on a permissive parser.

## Startup and health sequence

1. Record the Galadriel and Crebain commit IDs, registry SHA-256, profile digest,
   handoff digest, generated config digests, and leaf certificate serial/fingerprint
   metadata.
2. Start the secure Zenoh router and confirm that it loaded mTLS and access control.
3. Start the Galadriel observer for the exact realm/epoch/producer and pinned
   registry. A library opened on a caller-provided bus inherits that bus's security;
   use the explicit secure client path for acceptance evidence. Receiver activation
   starts a finite 30 s first-heartbeat grace period.
4. Start Crebain with the exact deployment-supplied epoch and producer identity within
   that grace period (or use an orchestrator that makes the handoff atomic).
   Starting Crebain before the exact ACL exists risks an unobservable initial
   prefix and is not accepted.
5. Require monitor heartbeat progression before treating traffic as live. Observation
   traffic alone does not prove lifecycle completeness. A later heartbeat cannot
   repair an earlier expired deadline or sequence gap.
6. Surface the first terminal tap/assembler fault, bounded queue depth, drops,
   reorder/gap state, heartbeat age, incomplete frames, registry mismatch, and
   epoch-lifetime prior/observation-stream capacity to operators. Rotate to a newly
   coordinated epoch before either replay-protection map reaches its fixed cap; those
   maps deliberately never evict within an epoch. Any ambiguity remains ineligible for
   `Nominal` evidence.

The repository CLI uses the explicit secure path and the receiver's fixed v1
defaults (30 s first-heartbeat grace, then a 1 s producer heartbeat interval and 3 s
receipt deadline, plus a 1 s reorder deadline and 5 s frame deadline):

```bash
export NCP_ZENOH_CONFIG=/secure/config/galadriel-epoch/zenoh-observer.json5
cargo run --locked --features ncp-live --bin galadriel -- observe \
  --realm engram/ncp \
  --epoch "$CREBAIN_GALADRIEL_EPOCH" \
  --producer-id "$CREBAIN_GALADRIEL_PRODUCER_ID" \
  --registry "$CREBAIN_GALADRIEL_REGISTRY_PATH" \
  --registry-sha256 "$CREBAIN_GALADRIEL_REGISTRY_DIGEST"
```

The epoch is required input, not minted by this command. The same exact value must
be present in the router ACL and producer environment before either application
starts. Every Galadriel secure live path loads the configuration once, validates
connector-side mTLS plus the other strict client invariants, and opens that same parsed
value; only the external drills below can show that the remote router loaded and
enforced its policy.

## Authorization and fault drill

Run the following from separate processes and retain timestamps plus router/client
logs. Redact paths if necessary; never retain keys or credential bytes.

| Drill | Expected result |
| --- | --- |
| Correct producer CN, both exact keys | valid bounded envelopes reach the matching taps |
| Correct producer CN, other epoch or sensor name | router denies publication |
| Correct producer CN, command/action/lease/RPC key | router denies operation |
| Observer CN subscribes to both exact keys | subscription succeeds |
| Observer CN puts either exact key or any control key | router denies operation |
| Untrusted, wrong-CN, missing, or expired client certificate | TLS connection/authorization fails |
| Payload identity differs from configured producer/session | receiver rejects it even if transport delivery occurred |
| Message exceeds 128 KiB transport cap | transport drops/rejects before application decode allocation |
| Envelope exceeds 64 KiB application cap | tap rejects it and latches a visible fault |
| Duplicate, gap, excessive reorder, queue overflow, or frame deadline | affected frame/suffix is invalidated; never `Nominal` |
| Heartbeats stop | liveness fault occurs at the configured monotonic receipt-time deadline |
| Producer restarts with the same epoch | protocol fault; no state reset or silent recovery |
| Producer restarts with a fresh coordinated epoch | old subscription/state retires under a bounded handoff; new state starts empty |

The repository's in-process Zenoh tests validate exact keys, bounded handoff, and
codec/sequence behavior. They do not replace the wrong-cert/no-cert/ACL tests above,
because an isolated loopback session has no external router principal to attest.

This profile configures CA trust and certificate-expiration handling, but no CRL or
OCSP revocation mechanism. Do not claim a revoked-yet-unexpired leaf is rejected unless
the deployment adds and records an external revocation/CA-rotation control and tests it.

## Evidence interpretation

A complete frame may feed the statistical detector only after observation and
monitor routes agree on identity, sequence, projection/prior context, registry,
outcome accounting, and deadline. Transport authentication establishes who could
publish; it does not establish physical truth or make a verdict a calibrated
posterior. Galadriel remains advisory and must not directly widen or exercise a
control authorization.

The v1 frame summary does not enumerate the pre-association track set or a digest of
that set. Therefore, even a complete v1 join cannot independently prove the full
track-by-modality opportunity cardinality from receiver data alone. Treat that as a
declared evidence limitation and a v2 schema gate, not as an inferred success.
