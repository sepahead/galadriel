# Galadriel secure deployment profile

## Abbreviations

| Short form | Meaning |
|---|---|
| ACL | access control list |
| ASCII | American Standard Code for Information Interchange |
| CA | certificate authority |
| CN | certificate common name |
| JSON | JavaScript Object Notation |
| mTLS | mutual Transport Layer Security |
| NCP | Neuro-Cybernetic Protocol |
| POSIX | Portable Operating System Interface |
| RPC | remote procedure call |
| SHA-256 | Secure Hash Algorithm 256 |
| TLS | Transport Layer Security |
| UTF-8 | 8-bit Unicode Transformation Format |

This directory contains a deterministic, fail-closed Zenoh deployment profile.
The profile applies to one Galadriel producer process epoch.
It is narrower than the generic NCP sensor ACL.
The epoch and producer identity use the Galadriel core identity grammar.
A generic NCP segment is not sufficient for these two fields.

- One authenticated producer CN can send `put` ingress only on two exact keys.
  The keys are `.../session/{epoch}/sensor/galadriel-{pid,monitor}`.
- One different authenticated observer CN can send `declare_subscriber` ingress on the same keys.
  It can receive the matching `put` egress only on those keys.
- No subject receives a wildcard epoch or `sensor/**` permission.
  No subject receives delete, command, action, lease, query/RPC, or other control-plane permission.
- The router is default-deny and mTLS-only.
  It has no upstream connection. It disables multicast discovery and gossip discovery.
- Both clients use TLS only. They do not listen and do not use discovery.
  They enable connector-side mTLS so Zenoh presents their certificates.
  They require router hostname verification.
- Each receive-side Zenoh defragmentation limit is 128 KiB.
  This limit applies before the frozen 64 KiB application payload gates.

Zenoh uses the certificate common name as the ACL subject.
It does not use a leaf fingerprint as the subject.
If the configured CA accepts a certificate with an authorized exact CN, that certificate receives that CN's permissions.
The issuing CA must reserve each permitted CN and prevent unintended duplicate issuance.
Keep certificate serial and fingerprint evidence for every rotation.

The publication permissions are directional.
A router evaluates a forwarded `put` on ingress from the producer.
It evaluates the `put` again on egress to the observer.
The [Zenoh ACL flow model](https://zenoh.io/docs/manual/access-control/) describes this behavior.
One combined subject rule could deny valid delivery or grant publication authority to the observer.

The committed `.example.json` and `reference/` outputs use `.example.invalid` identities.
They use placeholder certificate paths and an example epoch.
They are inert review fixtures. They are not credentials or a production deployment.

## Render one deployment epoch

1. Mint a process epoch before the producer starts. Never reuse this epoch.
   Give the exact value to the producer, router profile, and receiver subscription.
   Persist or otherwise coordinate the value.
   Do not use `session/*` to avoid this coordination requirement.
2. Put the externally pinned canonical registry SHA-256 in `registry_canonical_sha256`.
   Give the same value to the authorized producer and Galadriel.
   The field is deployment coordination evidence. It is not a Zenoh ACL input.
3. Issue separate keys and certificates for the router, producer, and observer.
   Put each client leaf's exact common name in its profile field.
   The renderer rejects CNs that look like wildcards.
   It also rejects reused certificate and key paths.

   Each deployment credential path must identify a regular file that exists.
   Each path must be absolute.
   The renderer rejects textual, symbolic-link, case-folded, and hard-link aliases.
   On POSIX, make each private key readable by its owner.
   Do not make a private key executable or accessible to a group or other users.

   Only `check` accepts the committed relative placeholders. The renderer does not accept them.

   Protect issuance so no other CA-valid leaf can get either authorized CN.
4. Copy `galadriel-security-profile.example.json` outside the source tree.
   Replace every example value and certificate *path*.
   Render the profile:

   ```bash
   python3 scripts/secure_deployment.py render \
     --profile /secure/config/galadriel-profile.json \
     --output-dir /secure/config/galadriel-epoch
   ```

   The renderer does not replace output files that exist unless you specify `--force`.
   Before a no-force render, the renderer checks every target before it writes a file.
   It writes each of the three Zenoh configurations atomically with owner-only permissions.
   It applies the same controls to the nonsecret `galadriel-handoff.json`.
   `SHA256SUMS` binds all four files.
   The directory is not a transactional unit.

   Verify the complete set after `--force`, a copy operation, or an interrupted render:

   ```bash
   cd /secure/config/galadriel-epoch || exit 1
   sha256sum --check SHA256SUMS
   ```

   The handoff binds `profile_version`, realm, epoch, producer identifier, and canonical registry digest.
   It also binds both exact client CNs. It contains no credential material.
5. Start the router with the generated `zenoh-router.json5`.
   Start the authorized contract-conforming producer with `zenoh-producer.json5`.
   Start Galadriel with `zenoh-observer.json5`.
   Configure both applications with the exact epoch from the handoff.
   Also use its `producer_id` and registry digest.

   Crebain is an optional reference producer.
   A deployment does not require Crebain.

   Galadriel accepts the JSON claim only when its route, session, and producer validators agree.
   The transport ACL separately requires a CA-valid connection with the authorized CN.
6. Retain the sanitized profile, handoff, and digest as deployment evidence.
   Retain configuration digests, software revisions, certificate fingerprints and serials, and authorization-test results.
   Never copy private-key bytes or credentials into logs or evidence bundles.

The renderer and checker use strict UTF-8 JSON.
They reject duplicate object members and nonstandard constants before profile validation.
They also reject non-finite floats and floats with overflow or nonzero underflow.
They reject integer tokens that exceed the fixed resource bound.
Each profile field must then satisfy its closed type, identity, path, endpoint, and size domain.

Run the reference fixture and maintained security regression suite with this command:

```bash
python3 scripts/secure_deployment.py check
```

The static check is necessary.
It does not prove that a specific router runs these files.
Before operational acceptance, exercise a real multi-process router over mTLS.
Record at least these cases:

- A CA-valid certificate with the configured producer CN can publish both exact routes.
- The router denies an untrusted, wrong-CN, expired, or missing producer certificate.
- The router denies the configured producer on a different epoch and every other sensor key.
- The router denies the configured producer on command, action, lease, and RPC routes.
- The observer can subscribe to both exact routes.
- The observer cannot publish either route or use a control or RPC path.
- The router rejects oversized transport messages.
- Valid application-bounded envelopes pass.

Zenoh client construction alone cannot attest to the active ACL on the remote router.
It also cannot attest to the authenticated peer principal.
These live results remain a separate deployment evidence gate.
See [the secure deployment runbook](../docs/SECURE-DEPLOYMENT.md).
