# SAPPHON-123 — Dual-Role Challenge–Response, Replay Fencing & Partial Revocation

**Phase X:** 3/8 · 37.5% software progress.  
**Verified CI:** 37/37 SAPPHON-123 challenge tests; 28/28 SAPPHON-122 origin and rotation tests; 29/29 SAPPHON-121 custodial ancestry tests; 140/140 immutable prior-phase SHA-256 and byte-length checks (11 + 45 + 42 + 42).

## Delivered
- `tools/sapphon_123_challenge.cjs` defines an exact-schema challenge binding a 256-bit nonce, custodian, issuer and operator identities, checkpoint SHA-256, rotation generation, and bounded logical-tick interval.
- The issuer and operator separately sign role-specific bytes derived from the *same* canonical challenge digest. Verification requires two separately pinned Ed25519 public keys, rejects role swapping, signature forgery, revoked issuer or operator, and missing trust pins.
- A single local fsynced nonce journal, protected by an exclusive directory lock, grants one challenge issuance and one successful consumption. Reissued and consumed nonces are denied. The store rejects corruption and local logical-clock regression.
- Ancestry/control checks reject the declared convergence of issuer, operator and custodian roots, declared source-root overlap, and identical claimed control groups.
- `tools/test_sapphon_123_challenge.cjs` exercises 37 real local-file checks: fresh and expired challenge boundaries, replay, missing issuer/operator, independently revoked roles, swapped signatures, altered checkpoint digest, fixture ancestry collision and corrupt/locked journal. A test-fixture sequencing error was corrected after the initial failed CI run; the next full run passed.
- `docs/sapphon/phase-x/123/index.html` retains the three R/G/B neon pump rings, eight synthetic clock positions, center `{{i}}`, four archived clock registers and clickable observation-only role/replay explanations.
- `.github/workflows/sapphon-123-challenge.yml` gates the new and inherited tests, parses the viewer's JavaScript, and re-verifies the 140 frozen files.

## Evidence boundary
All issuer and operator keys are synthetic fixture keys, and control groups and ancestry roots are **declared**, not independently proven. A pair of signatures establishes test key possession, not real independent control. Logical ticks are supplied by the test, not independently trusted UTC or a physical clock. A privileged attacker who can revert the entire local nonce journal can replay an earlier state in the absence of externally preserved monotonic evidence.

A successful synthetic test consumes a nonce but returns `decision:"HOLD"`, `external_custody_authenticated:false`, `physical_clock_qualified:false` and `utc_authority:false`. No cross-host nonce authority or outside organizational custody was verified.

**External custody: HOLD · Genuine independent operator control: HOLD · Global replay protection: HOLD · Physical clock and UTC: HOLD.**

## Next natural bound
**SAPPHON-124 — Revocation Propagation & Delayed Split-Control Responses.** Model a signer revoked between challenge issuance and response verification, require current revocation state at consumption, and test out-of-order signatures across changing generation/role credentials. Keep externally unqualified outcomes on HOLD.

`.dlw`
