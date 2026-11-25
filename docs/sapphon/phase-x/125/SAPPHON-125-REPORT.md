# SAPPHON-125 — Revocation Publication Lag & Cross-Replica High-Water Fencing

**Phase X:** 5/8 · 62.5% software milestone.

**Verified GitHub Actions:** 39/39 new high-water/replica checks; 41/41 SAPPHON-124 delayed revocation tests; 37/37 SAPPHON-123 two-role challenge tests. All four parent software freezes preserved: VI (11), VII (45), VIII (42), IX (42) = 140/140 SHA-256 and byte-size matches.

## Implemented
- `tools/sapphon_125_replica.cjs` implements a separate local credential replica with pinned Ed25519-signed high-water snapshots containing publication generation, issuer/operator key generations, revocation flags and prior snapshot digest.
- The verifier rejects missing/untrusted high-water reference, a reference older than its locally stored generation, a supplied high-water generation ahead of the stale replica, a same-generation digest fork, a missing predecessor, skipped generations and any rollback of credential generations or resurrection of revoked roles.
- The gate compares the most recent local replica state against a separately supplied *trusted-by-fixture* high-water snapshot on **every** test permission. A disconnected/isolated verifier refuses permission, even if its cached signed snapshot was previously valid.
- Successful current-state matching can record one synthetic local permission nonce, but always returns `decision:"HOLD"`, `external_authority:false`, `independent_high_water_authenticated:false` and `utc_authority:false`. No external side effects are authorized.
- `tools/test_sapphon_125_replica.cjs` executes 39 local-file scenarios for delayed revocation delivery, publisher signature/identity spoofing, revoked publisher, stale replica, offline high-water, replayed permission nonce, signed forks, skipped high-water generations, credential-generation mismatch, rollback attempts, corrupt state and local lock contention. The first Actions test fixture reused the same replica directory; that fixture collision was corrected and the next CI run passed.
- `docs/sapphon/phase-x/125/index.html` preserves the three neon RGB pumps, eight synthetic phase positions, center `{{i}}`, four frozen clock registers and observation-only replica examples.
- `.github/workflows/sapphon-125-replica.yml` verifies new and inherited tests, viewer JavaScript parsing and 140 frozen files.

## Trust boundary
The high-water source is **supplied by a local synthetic test**, with fixture-signing keys and a caller-controlled indication of trust. This is neither a real outside monitor nor cryptographic proof of its current freshness or non-rollback. Since the caller can present a previously valid snapshot together with an old but internally consistent replica, **coordinated high-water and replica rollback remains undetectable**. Cross-host revocation delivery latency, genuine organizational custody, physical timing and UTC are not authenticated.

**Independent high-water authority: HOLD · External operator custody: HOLD · Global revocation: HOLD · Physical clock/UTC: HOLD.**

## Next natural bound
**SAPPHON-126 — High-Water Freshness Challenge & Publication Partition Recovery.** Introduce a fresh, verifier-bound signed high-water query protocol; test delayed publisher responses, disconnected periods, historical responses, and publisher key rotation, keeping externally unqualified authority on HOLD.

`.dlw`
