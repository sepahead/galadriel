## Change

Describe the requirement and the smallest coherent change.
Identify all affected public claims.

## Evidence

- [ ] Record the exact base commit and all affected requirement identifiers.
- [ ] Add positive, boundary, malformed-input, and regression tests for the change.
- [ ] Run `cargo fmt`, locked all-target and all-feature Clippy, tests, and rustdoc. Confirm that all commands pass.
- [ ] Update the release audit and generated artifacts when the change affects them.
- [ ] Make documentation, migrations, schemas, examples, and residual risks consistent.
- [ ] Exclude credentials, private keys, generated secrets, and undisclosed vulnerabilities.
- [ ] List Sepehr Mahmoudian as the commit author. Do not list an assistant as an author or co-author.

## Scope and rollback

State each deliberate non-claim.
Explain how to withdraw the change safely.
