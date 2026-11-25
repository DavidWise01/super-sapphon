# SAPPHON-145 — Signed Anchor Provider and Disaster-Recovery Inspection

**Phase XIII · 1/8 · 12.5% design progression · operational authority HOLD**

## Implemented

`rust/sapphon-liveness/src/anchor145.rs` introduces a read-only Ed25519 anchor envelope bound to a provisioned provider identity, registry sequence, head digest, epoch and monotonic counter. The provisioned provider contains an independently retained minimum counter, sequence and epoch. The verification API rejects revoked keys, invalid signatures, mismatched provider IDs, stale counters and rollback below the externally supplied sequence/epoch floor.

After authenticated signature screening, restart inspection validates the complete local registry transcript against its *separately supplied* local expectation and compares the signed anchor with that history. The result classifies matching, local-ahead, local-behind, and inconsistent evidence, but no result grants lock clearance or checkpoint acceptance.

## Qualification boundary

Signature validation proves possession of the provisioned private key. It does not prove that the provider and its counter floors are external to the owner, that the physical storage is independent, or that UTC and global anti-rollback are authenticated. The Rust code never updates a remote provider, writes a checkpoint, repairs rollback, or removes a lock.

## Tests authored

1. Signed genesis checkpoint remains HOLD.
2. Forged anchor signature is rejected.
3. Revoked/stale provider key or counter is rejected.
4. Corrupt local registry cannot substitute for independently retained anchor.

## Verification requirement

`.github/workflows/sapphon-145-anchor.yml` tests the Rust crate and inherited recovery suites, verifies exact bytes and SHA-256 for all 188 historical frozen files, and checks explicit HOLD invariants. The source commit alone does not prove that GitHub Actions passed or that Pages deployed. Phase XII's software security freeze remains unqualified until a known successful CI run is inspected.

## Next natural bound: SAPPHON-146

Two separately provisioned anchor providers, matching checkpoint ancestry, asynchronous provider disagreements, and anti-equivocation receipts across restarts. Retain HOLD throughout.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
