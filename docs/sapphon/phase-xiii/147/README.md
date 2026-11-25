# SAPPHON-147 — Cross-Provider Ancestry Lineage and Signed Key Rotation

**Phase XIII · 3/8 · 37.5% design progression · operational authority HOLD**

## Implemented source

`rust/sapphon-liveness/src/lineage147.rs` extends the two-provider SAPPHON-146 comparison with **prefix checks against the actual registry transcript**. It requires independently provisioned trusted keys and validates the entire local history against its externally supplied expected sequence/head before comparing both signed anchor claims.

A lagging provider is marked `ProvenPrefixWithLag` only if its signed head equals the head of the actual earlier prefix **and the newer provider's signed head equals the head of the actual later prefix**. Otherwise the result is `ConflictingHistory`. An anchor farther ahead than the observed journal fails closed with `LINEAGE_NEWER_NOT_OBSERVED`.

The new key-rotation record uses a domain-separated message binding provider identity, old/new Ed25519 keys, old/new epochs and counters. Both old and replacement keys must sign the identical record. Old or replacement signatures are checked against the old trusted provider key and externally retained counter/epoch floors. Signature possession does not prove physically independent custody.

## Regression tests authored

1. Actual registry prefix permits a lag classification while retaining HOLD.
2. Divergent older signed prefix is not mislabeled as ordinary lag.
3. Newer checkpoint beyond locally observed history fails closed.
4. Dual signed key rotation validates both public-key identities.
5. Missing replacement-key signature fails closed.
6. Stale rotation counter is rejected.
7. Revoked/disappeared custodian cannot silently be replaced.

## Invariants and limitations

The module never updates a custody trust store, clears a lock, performs remote recovery, or certifies that two signing keys have separate physical ancestry. The signed checkpoint registry, supplied local expected head, and externally retained provider counter floors must be provisioned and authenticated elsewhere. Valid prefix comparison is not global anti-rollback.

The read-only workflow `.github/workflows/sapphon-147-lineage.yml` requires new and inherited Rust regressions, the exact 188 historical frozen hashes, explicit HOLD checks, and a Rust docs build. Until a completed passing Actions run is examined, the tests remain authored but not qualified.

## Next bound — SAPPHON-148

Interrupted key rotation and provider failover: preserve a pending rotation transcript, disallow acceptance of a new key before authenticated continuity and independent custody acknowledgement, and distinguish delayed provider evidence from lost-key recovery. All operational authority remains HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
