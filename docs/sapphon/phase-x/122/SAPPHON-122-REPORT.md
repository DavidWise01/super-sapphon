# SAPPHON-122 — Enrollment Origin & Operator-Control Separation

**Phase X:** 2/8 · 25%.  
**Acceptance:** 28/28 SAPPHON-122 enrollment origin and key-rotation tests; 29/29 SAPPHON-121 signed custodian ancestry checks; 26/26 SAPPHON-120 adversarial recovery tests. All four inherited software freezes preserved: Phase VI (11), Phase VII (45), Phase VIII (42), Phase IX (42) = 140/140 SHA-256 and byte-size matches.

## Implemented
- `tools/sapphon_122_origin.cjs` adds an exact-schema origin-certificate interface binding custodian ID, custody root, operator root, issuer ID/root, signing-key ID, public key SHA-256, monotonic generation and preceding certificate digest.
- Enrollment certificates use Ed25519 signatures verified against a pinned issuer registry. The operator registry separately records its *declared* control group and custodian root.
- The gate rejects unknown or revoked issuers/operators, issuer signing-key substitutions, invalid signatures, source-root self issuance, overlap of custodian lineage with source/operator/issuer lineage, claimed shared operator/issuer controller, stale or forked rotation generations and re-used prior signing keys.
- `tools/test_sapphon_122_origin.cjs` runs 28 synthetic fixture tests, including revoked and forged signer credentials, compromised issuer-key substitution, two-generation rotation, altered predecessor links, attempts to assert physical qualification and malformed trust-source claims.
- `docs/sapphon/phase-x/122/index.html` retains the three neon R/G/B pump rings, eight synthetic phases, center `{{i}}`, four historical clock registers and observation-only controls.
- `.github/workflows/sapphon-122-origin.yml` verifies the new gate, inherited custodian and recovery tests, viewer JavaScript syntax, and all 140 frozen file hashes.

## Trust and qualification boundary
All keys, operator roots and issuer roots are generated or declared within software fixtures. Distinct control-group identifiers are **claims**, not independently authenticated organizational-control evidence. A dishonest or compromised issuer could invent a disjoint operator and ancestry. The checker cannot prove that a named organization exists or that its actual people and key custodians are outside the source owner's authority.

Generation fencing uses a caller-supplied history: the engine rejects a missing, stale or forked predecessor against that history, but a jointly rolled-back history and origin certificate can remain internally consistent without an independent external high-water mark. Real key compromise detection, outside hardware attestation, trusted remote clock, custody and UTC have not been tested.

**Independent operator identity: HOLD · External custody: HOLD · Global anti-rollback: HOLD · Physical clock and UTC: HOLD.**

## Next natural bound

**SAPPHON-123 — External Custodian Challenge–Response & Split-Control Credential Revocation.** Require separately pinned issuer and operator challenge signatures bound to a fresh canonical nonce; test replay, partial revocation and ancestor-control convergence. Keep any fixture approvals observation-only.

`.dlw`
