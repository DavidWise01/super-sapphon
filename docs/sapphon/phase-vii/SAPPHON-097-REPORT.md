# SAPPHON-097 · Phase VII / 1 of 8
## Source authentication versus time truth

The Phase VI software freeze remains unchanged. Phase VII adds a separate provenance verifier and a companion browser laboratory.

### Delivered
- Ed25519 source-envelope verification with strict explicit field sets and canonical signed payload.
- Key ID, claimed source identity and permitted source role are bound together.
- Key revocation flag and unknown signer fail closed.
- Exact historical record hashes and predecessor identity appear in the signed payload.
- Tests use fresh ephemeral signing keys generated in CI; **no private signing key is published or stored in the repository**.
- A separate GitHub Pages phase-vii clock page preserves three R/G/B physical pump rings, eight phases, four logical address registers, and the original read-only archive.

### Evidence boundaries
A signature proves possession of the private key corresponding to the trusted public key, not correct observation, correct clock time, trusted source governance or independent witness ancestry. The current archive has no signed event envelope, so the browser correctly labels it unauthenticated synthetic evidence. The verifier's signed tests are cryptographic demonstrations rather than a physical authenticated clock source.

### Acceptance
Run `node tools/test_sapphon_097_auth.cjs`; 16 positive and negative checks. The CI workflow performs the same checks along with HTML syntax inspection, and writes no clock readings or authorization decisions.

### Next natural bound
SAPPHON-098: signed-chain continuity, key rotation, cross-key ancestry and key lifecycle discipline. Authenticate source roots before claiming independent corroboration.

`.dlw`
