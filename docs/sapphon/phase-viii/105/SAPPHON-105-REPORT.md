# SAPPHON-105 — Phase VIII External Evidence Intake Gate

**Phase VIII:** 1/8 · 12.5%  
**GitHub Actions acceptance:** 18/18 new signed intake checks; 21/21 inherited custodian challenge checks; 18/18 receipt checks; 15/15 anchor/fork checks. Both immutable baselines remain intact (Phase VI: 11 files; Phase VII: 45 files).

## Delivered

- `tools/sapphon_105_intake.cjs` accepts strictly scoped Ed25519-signed synthetic evidence intake envelopes for two source kinds: external custodian and physical clock.
- The source identity is bound to its provisioned signing key, ownership domain, exact evidence digest, and calibration reference for physical-clock claims.
- Ancestry collisions with the owned GitHub/Pages domain are exposed. Multiple envelopes repeating the same source root are rejected.
- Missing physical calibration fields, extra unauthorized clock fields, forged signatures, changed declarations, revoked keys, and key substitutions fail closed.
- A **source signature, URL, or self-declared independence does not establish real-world independence or a calibrated physical time source**.
- `docs/sapphon/phase-viii/105/index.html` retains the three neon physical pumps (red/hot/H; green/neutral/O; blue/cold/N), eight phase positions, nested `{{i}}`, four clock address registers and a read-only display of the archived synthetic clock.
- `.github/workflows/sapphon-105-intake.yml` gates source changes on signed-intake tests, the inherited custodian/receipt/anchor tests, browser script syntax, and all previous frozen hashes.

## Qualification decision

| Gate | Status |
|---|---|
| Synthetic signed evidence intake software | PASS |
| Actual independent external custodian | HOLD |
| Actual physical-clock measurement calibration | HOLD |
| Independent source ancestry roots | HOLD |
| Real UTC authority | HOLD |

This intake engine does not issue real clock observations or convert synthetic test keys into external authorities. It is deliberately a qualification *screen*, not a production admission gate: external review status fields remain untrusted assertions until independent documents and custody controls exist.

## Next natural bound

**SAPPHON-106 — Real Source Admission Manifest & Calibration Evidence Requirements.** Define the minimum verifiable third-party enrollment artifacts, observation timing evidence, custody controls, and reference-clock calibration contract for a non-synthetic source while retaining operational HOLD until those artifacts actually exist.

`.dlw`
