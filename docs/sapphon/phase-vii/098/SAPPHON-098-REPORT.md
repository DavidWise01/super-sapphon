# SAPPHON-098 — Signed-Chain Continuity, Key Rotation & Ancestry

**Phase VII milestone 2/8 · 25%**  
**CI:** 22/22 chain and rotation checks passed; 16/16 inherited Ed25519 checks passed; 11/11 Phase VI frozen file hashes unchanged.

## Implementation

- `tools/sapphon_098_chain.cjs`: validates sequential Ed25519-signed record batches against the source's active signing key, exact generation, predecessor record hash, non-repeating record identities, and monotonic sequence boundary.
- A rotation certificate is signed by the currently active key, identifies the replacement public-key fingerprint, binds its source ID and unchanged ancestry root, and names the exact effective sequence and next generation.
- Revoked or unknown keys fail closed. Previous keys cannot sign new records after rotation.
- A source root remains one root across key rotation: **two signing keys do not constitute two independent sources**.
- Both the chain state and key-rotation record are copy-on-write; rejected operations do not advance the accepted history.

## Demonstration

The test-only archive is split into three signed batches (0–3 under key A; 4–5 under key A; 6–7 under key B) with a rotation at sequence 6, generation 1. Test key pairs are generated ephemerally in GitHub Actions. No private key is committed, and the archived clock records are not retroactively represented as genuinely signed observations.

The companion neon page is at `docs/sapphon/phase-vii/098/index.html`. It visualizes the preserved three R/G/B physical pump rings, eight sectors, `{{i}}`, four logical registers, and the illustrative key lifecycle.

## Limits

Key possession is not physical clock truth, UTC accuracy, independence of observation roots, or authorization to mint new clock readings. The provenance root in this synthetic demonstration is a declared relation, not independently attested real-world origin. An actual producer would require separately provisioned keys, authenticated enrollment, revocation governance and external audit evidence.

## Next natural bound

**SAPPHON-099 — Authenticated source enrollment and revocation ledger.** Keep source-key enrollment explicit, with key-compromise and rekey history preserved separately from the immutable clock records.

`.dlw`
