# SAPPHON-102 — Custody Receipt Acknowledgements & Ancestry Audit

**Phase VII: 6/8 · 75%**

## Deliverables
- `tools/sapphon_102_receipts.cjs` verifies Ed25519-signed custody receipts against the exact SAPPHON-101 anchor digest, ledger head and count.
- Custodian identity, key ID, declared ancestry root and unique receipt serial are bound to the signature; the verifier requires a separately supplied custodian trust registry.
- Revoked and unknown keys, altered signed fields, anchor substitutions, replayed receipt serials, duplicate custodian keys and false independent-retention or UTC declarations fail closed.
- `tools/test_sapphon_102_receipts.cjs` exercises synthetic tests with disposable keys.
- `docs/sapphon/phase-vii/102/index.html` renders the original three neon pumps, eight sectors, four logical clock registers and read-only custody-verification examples.
- The CI workflow also runs inherited fork-detection and enrollment tests, and rechecks all 11 frozen Phase VI file hashes.

## Strict evidence boundaries
A successful Ed25519 signature verifies possession of the signing key registered to the claimed custodian. **A custody-root string cannot prove independent organizational custody.** Multiple keys from one controlling organization remain one source ancestry even if their signatures differ. The software deliberately reports `independently_authenticated_custodians: 0` and `independent_custody_confirmed: false` until independently authenticated custody enrollment is implemented.

No real external custodian has been connected. The anchors are custody-request exports, not acknowledged real-world storage. The preserved SAPPHON clock readings are eight unsigned synthetic observations. No physical time source or UTC authority has been authenticated.

## Next natural bound
**SAPPHON-103 — Custodian root enrollment and out-of-band challenge evidence.** Require a separately provisioned custodian trust anchor, response to a binding challenge, and explicit provenance checks before treating organizational custody as corroboration.

`.dlw`
