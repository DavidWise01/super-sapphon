# SAPPHON-223 — External Checkpoint Continuity and Anti-Rollback HOLD

## Verified predecessor

SAPPHON-222 report-triggered GitHub Actions run [46160572737](https://github.com/DavidWise01/super-sapphon/actions/runs/46160572737) completed **SUCCESS**. That result verifies Ed25519 anchored-key negative controls within GitHub source ancestry. It does not authenticate an externally controlled public key, physical custody, UTC, or rollback state.

The frozen source-owned artifact remains anchored to OCI source run `46154833375`, commit `c167a95a05177e280625fa61613c1b1fa20f75e9` and image TAR SHA-256 `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197`.

## SAPPHON-223 implemented bound

- `tools/sapphon_223_checkpoint.py` computes a deterministic canonical SHA-256 over each complete checkpoint. Requires sequential, non-boolean positive counters; exactly linked predecessor digests; a single custodian root; and exact frozen source/build ancestry.
- Refuses replay, duplicate or forked sequence, altered predecessor, missing counters, changed custodian, source/image substitution, wrong or stale external head, and unbounded checkpoint sets.
- A supplied external head (even when `externally_authenticated: true`) is **not trusted** merely because a JSON value says it is authenticated. Actual external trust roots, authenticated clocks and independently held anti-rollback counters remain unverified.
- `tools/test_sapphon_223_checkpoint.py`: fourteen deterministic tests, including simulated forked histories and false independent-authentication declarations. Fixtures are not external evidence.
- `.github/workflows/sapphon-223-checkpoint.yml`: checks syntax and regressions, then preserves the negative-control `NO_CHECKPOINTS` HOLD verdict in a source-owned artifact.

## Future external acceptance

An independent custodian must hold the anchored signing key and checkpoint head outside GitHub ownership; provide authenticated, monotonic receipts; attest to personally rehashed image content; and demonstrate anti-rollback durability and independent time authority by separately verifiable evidence. Until those checks are externally authenticated, no receipt is an independently authenticated witness.

**Witnesses: 0. Authenticated UTC: FALSE. Global anti-rollback: FALSE. Recovery: HOLD. Lock cleared: FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
