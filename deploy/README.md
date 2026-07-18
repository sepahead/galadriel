# Galadriel secure deployment profile

This directory contains a deterministic, fail-closed Zenoh deployment profile for
one Galadriel producer process epoch. It is narrower than NCP's generic sensor ACL:

- one authenticated producer CN may send `put` ingress only on the two exact
  `.../session/{epoch}/sensor/galadriel-{pid,monitor}` keys;
- one different authenticated observer CN may send `declare_subscriber` ingress
  and receive the matching `put` egress only on those same two keys;
- no subject receives a wildcard epoch, `sensor/**`, delete, command, action,
  lease, query/RPC, or other control-plane permission;
- the router is default-deny, mTLS-only, has no upstream connection, and disables
  multicast and gossip discovery;
- both clients are TLS-only, non-listening, discovery-disabled, explicitly enable
  connector-side mTLS so Zenoh presents their certificates, and require router
  hostname verification; and
- every receive-side Zenoh defragmentation limit is 128 KiB, ahead of the frozen
  64 KiB application payload gates.

Zenoh's ACL subject is the certificate common name, not a leaf fingerprint. Any
certificate accepted by the configured CA and carrying an authorized exact CN receives
that CN's permissions. The issuing CA must reserve each role CN, prevent unintended
duplicate issuance, and keep certificate serial/fingerprint evidence for every rotation.

The publication permissions are deliberately directional. A router evaluates a
forwarded `put` once on ingress from the producer and again on egress to the
observer, as described by the [Zenoh ACL flow model](https://zenoh.io/docs/manual/access-control/).
Combining both directions in one subject rule would either deny valid delivery or
grant the observer publication authority.

The committed `.example.json` and `reference/` outputs use `.example.invalid`
identities, placeholder certificate paths, and an example epoch. They are inert
review fixtures, not credentials or a production deployment.

## Render one deployment epoch

1. Mint a never-reused process epoch before the producer starts. Persist or
   otherwise coordinate it so the exact same value is passed to the producer,
   router profile, and receiver subscription. Do not use `session/*` to avoid this
   coordination requirement.
2. Put the externally pinned canonical registry SHA-256 in
   `registry_canonical_sha256`, and pass that same value to Crebain and Galadriel.
   The field is deployment coordination evidence; it is intentionally not a Zenoh
   ACL input.
3. Issue separate router, producer, and observer keys/certificates. Put each client
   leaf's exact common name in its corresponding profile field; wildcard-looking CNs
   and reused certificate/key paths are rejected. Every production credential path
   must be an existing regular file at an absolute path; textual, symlink, case-folded,
   and hard-link aliases are rejected. On POSIX, every private key must be owner-readable,
   non-executable, and inaccessible to group/other. The committed relative placeholders
   are accepted only by `check` and cannot be rendered. Protect issuance so no other
   CA-valid leaf can acquire either authorized CN.
4. Copy `galadriel-security-profile.example.json` outside the source tree, replace
   every example value and certificate *path*, and render it:

   ```bash
   python3 scripts/secure_deployment.py render \
     --profile /secure/config/galadriel-profile.json \
     --output-dir /secure/config/galadriel-epoch
   ```

   Existing output files are not replaced unless `--force` is explicit, and every
   target is preflighted before a no-force render writes anything. The three Zenoh
   configs and nonsecret `galadriel-handoff.json` are each written atomically with
   owner-only permissions; `SHA256SUMS` binds all four. The directory is not a
   transactional unit, so after `--force`, copying, or an interrupted render, verify
   the complete set before use:

   ```bash
   cd /secure/config/galadriel-epoch
   sha256sum --check SHA256SUMS
   ```

   The handoff binds `profile_version`, realm, epoch, producer ID, canonical registry
   digest, and both exact client CNs. It contains no credential material.
5. Start the router with the generated `zenoh-router.json5`, the Crebain producer
   with `zenoh-producer.json5`, and Galadriel with `zenoh-observer.json5`. Configure
   both applications from the handoff's exact epoch, `producer_id`, and registry
   digest. The JSON claim is accepted only when Galadriel's route/session/producer
   validators agree; the transport ACL separately requires a CA-valid connection to
   present the authorized CN.
6. Retain the sanitized profile, handoff and digest, config digests, software revisions,
   certificate fingerprints/serials, and authorization-test results as deployment evidence.
   Never copy private-key bytes or credentials into logs or evidence bundles.

The renderer and checker use strict UTF-8 JSON. Duplicate object members, nonstandard
constants, non-finite/overflowing or nonzero-underflowing floats, and integer tokens above
the fixed resource bound are rejected before profile validation. Each profile field then
passes its own closed type, identity, path, endpoint, and size domain.

The reference fixture and 67 security regression checks are exercised with:

```bash
python3 scripts/secure_deployment.py check
```

That static check is necessary, but it does not prove that a particular router is
running the files. Before operational acceptance, exercise a real multi-process
router over mTLS and record at least these cases:

- a CA-valid certificate carrying the configured producer CN can publish both exact routes;
- an untrusted, wrong-CN, expired, or missing producer certificate is denied;
- the configured producer is denied on a different epoch, every other sensor key,
  command/action/lease routes, and RPC;
- the observer can subscribe to both exact routes but cannot publish either route
  or invoke a control/RPC path; and
- oversized transport messages are rejected while valid, application-bounded
  envelopes pass.

Zenoh client construction alone cannot attest to the remote router's active ACL or
the authenticated peer principal. Those live results remain a separate deployment
evidence gate. See [the secure deployment runbook](../docs/SECURE-DEPLOYMENT.md).
