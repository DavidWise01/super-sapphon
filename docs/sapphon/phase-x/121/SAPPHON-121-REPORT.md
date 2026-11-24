# SAPPHON-121 — Trusted Monotonic Anchor Interface & Custodian Qualification Contract

**Phase X:** 1/8 · 12.5%.  
**GitHub Actions:** 29/29 new custodian tests, 26/26 SAPPHON-120 adversarial recovery tests, 28/28 SAPPHON-118 signed-checkpoint tests. All four prior source freezes remain intact: Phase VI (11), VII (45), VIII (42), IX (42) = 140/140 byte+SHA-256 matches.

## Delivered
- `tools/sapphon_121_custodian.cjs`: exact-schema synthetic custodian enrollment, pinned Ed25519 public-key digest, signing-key registry and revocation checks; canonical signed attestation over the receiver ID, receiver revision, exact SHA-256 state digest, checkpoint digest, and previous checkpoint chain link.
- Multiple credential keys sharing an ancestry root cannot be counted as independent custodian roots. The verifier also rejects any declared custody ancestry overlapping the source owner ancestry, including the repository owner and its mirrored corpus. Claimed roots are unique names in the fixture, not independently verified real organizations.
- The assessment returns `decision:"HOLD"`, `ancestry_independence_authenticated:false`, `external_retention_authenticated:false`, `hardware_monotonicity_authenticated:false` and `utc_authority:false`, even with three cryptographically valid, disjoint *declared* fixture roots.
- `tools/test_sapphon_121_custodian.cjs`: 29 deterministic acceptance and negative tests, including source self-custody overlap, shared custodian ancestry, duplicate signer, revoked signer, forged key/signature, tampered checkpoint binding, fabricated physical-authority claims and empty or malformed evidence sets.
- `docs/sapphon/phase-x/121/index.html`: read-only neon RGB three-pump synthetic clock lab, eight phases, center `{{i}}`, four registers and observation-only verification explanations.
- `.github/workflows/sapphon-121-custodian.yml`: blocking new and inherited tests, neon script parsing, and immutable checksum verification of all 140 frozen files.

## Qualifications and limitations
This is an **interface and synthetic fixture verification**, not an authenticated third-party custody trial. Ancestry is declared by fixture enrollment and can be falsely declared by a dishonest actor. Identifying ancestry collision is a necessary gate but not sufficient to prove independence; even multiple disjoint names do not authenticate real-world control.

The checkpoint envelope is bound to the format inherited from SAPPHON-118. External monotonicity, real physical-retention proof, hardware attestation, independent organizational identity, distributed finality and authenticated UTC are unverified. No real external evidence has been acquired.

**Independent external custody: HOLD · Global anti-rollback: HOLD · Physical clock and UTC: HOLD.**

## Next natural bound
**SAPPHON-122 — Custodian Enrollment Origin Proof & Operator-Control Separation.** Require independently checkable organizational ownership and origin evidence, prove fixture key ancestry cannot self-issue its own authority, test compromised enrollment and key rotation, and preserve HOLD until genuine independent provenance exists.

`.dlw`
