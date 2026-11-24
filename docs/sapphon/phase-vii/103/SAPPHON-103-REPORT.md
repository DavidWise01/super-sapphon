# SAPPHON-103 — Custodian Enrollment & Out-of-Band Challenge Gate

**Phase VII:** 7/8 · 87.5%  
**CI verification:** 21/21 challenge and enrollment tests; 18/18 inherited custody-receipt checks; 15/15 inherited anchor/fork checks; 11/11 frozen Phase VI source hashes.

## Implementation
- `tools/sapphon_103_challenge.cjs`: checks a separately supplied custodian enrollment record, an Ed25519 public-key fingerprint, exact anchor digest, custodian identity, signing key, session identifier, and cryptographically random 256-bit challenge nonce.
- A response must be signed by the enrolled key. The previously defined SAPPHON-102 receipt must also verify against the same anchor and enrolled identity before the nonce is consumed.
- `tools/test_sapphon_103_challenge.cjs`: verifies successful synthetic key possession and rejects replayed nonces, forged responses, altered signatures, substituted keys, false ancestry claims, altered anchors, mismatched sessions, invalid receipt signatures, and unrecognized enrollment channels.
- `docs/sapphon/phase-vii/103/index.html`: read-only neon explanatory laboratory preserving three red/green/blue physical pump rings, eight phases, center `{{i}}`, four clock registers, and unchanged synthetic archived evidence.
- `.github/workflows/sapphon-103-challenge.yml`: blocking GitHub Actions acceptance suite and Phase VI hash regression.

## What is — and is not — verified
The successful tests prove software-enforced signing-key possession for an enrollment entry marked **test-fixture**, in a fresh simulated challenge session. They **do not** establish an independently trusted out-of-band enrollment ceremony, the physical location of stored evidence, an independently verified organization, or a real retained external checkpoint.

The replay store is supplied to the verification function; a production verifier must persist that store across processes and enforce nonce expiry and challenge issuance provenance, not only compare signatures. The test registry is generated within the same CI ownership boundary.

The existing clock feed is still eight **unsigned synthetic** archival records, with no authenticated physical clock, no independently certified UTC reading, and no new clock authorization. Software changes are separate from the frozen Phase VI source files.

## Next natural bound
**SAPPHON-104 — Phase VII Final Acceptance, Durable Replay Registry & Evidence Freeze.** Extend the challenge mechanism with durable consumed-nonce tracking and expiry, test browser presentation, and seal the complete Phase VII software baseline. Declare physical qualification and independent organizational custody as HOLD until supported by external evidence.

`.dlw`
