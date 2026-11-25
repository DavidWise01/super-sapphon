# SAPPHON-124 — Revocation Propagation & Delayed Split-Control Responses

**Phase X:** 4/8 · 50% software milestone.  
**Verified GitHub Actions:** 41/41 new SAPPHON-124 tests; 37/37 inherited SAPPHON-123 tests; 28/28 inherited SAPPHON-122 tests; 140/140 hashes and exact bytes from the four immutable Phase VI–IX freeze manifests (11 + 45 + 42 + 42).

## Delivered

- `tools/sapphon_124_revocation.cjs` introduces a standalone, durable local role-state journal. Under one exclusive directory lock, it persists both roles' current pinned Ed25519 signing keys, generation numbers, revocation flags, active challenge digests, issuance generations, consumed nonces, and credential-change events.
- The challenge is bound to the two exact credential generations at issuance. On completion, the verifier rereads and validates the **current stored role state**, not a previously supplied approval, and denies if either role has been revoked or rotated since issuance.
- Each response is role-domain-separated and signs a canonical checkpoint-challenge SHA-256 plus its role generation. Signatures with changed role, digest or generation fail. New challenges can use newly rotated signer keys and generations; old outstanding challenges do not silently inherit that authority.
- A successful fixture response is atomically recorded as `CONSUMED` in the same journal so its nonce cannot be reused. Expired challenges, caller logical-tick regression, conflicting role ancestry, source-root overlap, tampered journal state and local lock contention all fail closed.
- Revocation is terminal within this fixture: reactivating a revoked role through implicit key rotation is rejected. Any later re-enrollment requires a separately governed process, not a mutation of the old record.
- `tools/test_sapphon_124_revocation.cjs` runs 41 checks including issuer-only and operator-only revocations after issuance, pre-rotation responses arriving late, stale generation relabeling, out-of-order signatures, newer valid key issuance, replay, unsigned/forged metadata, corrupted journals and persistent nonce exhaustion.
- `docs/sapphon/phase-x/124/index.html` retains three R/G/B neon pumps, eight synthetic phases, center `{{i}}`, four historical clock registers, and read-only response explanations.
- `.github/workflows/sapphon-124-revocation.yml` verifies the SAPPHON-124, 123 and 122 test suites, neon viewer JavaScript parsing, and every SHA-256/byte-size invariant in the four prior frozen phases.

## Critical evidence boundary

All role identities, source roots, signer keys and revocation events are **locally generated or declared synthetic test fixtures**. Checks prove that the verifier enforces the *latest local role state* at the moment of local challenge consumption. They do not prove timely delivery of a real remote revocation, authenticated physical time, independent issuer/operator control, or a globally linearizable credential registry.

A compromised operator capable of rolling back the complete credential journal can revive a previous logical state without an external monotonic authority. Logical ticks are not trusted UTC.

**Independent external custody: HOLD · Global revocation propagation: HOLD · Physical clock and authenticated UTC: HOLD.**

## Next natural bound

**SAPPHON-125 — Revocation Publication Lag & Cross-Replica High-Water Fencing.** Model separately delivered revocation-state digests and delayed replicas; test a disconnected verifier's stale authorization and require a trusted high-water mark before any authority-sensitive action. Keep externally unqualified outcomes on HOLD.

`.dlw`
