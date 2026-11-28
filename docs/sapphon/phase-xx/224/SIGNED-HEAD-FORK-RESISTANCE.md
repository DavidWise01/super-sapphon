# SAPPHON-224 — Signed Checkpoint-Head Authentication and Fork Resistance

## Completed predecessor

SAPPHON-223 latest [workflow run 46161021446](https://github.com/DavidWise01/super-sapphon/actions/runs/46161021446) completed **SUCCESS**, preserving the source-owned missing-external-checkpoint HOLD report. SAPPHON-223's 14 test cases passed in its hosted workflow.

The frozen original image ancestry remains source run `46154833375`, commit `c167a95a05177e280625fa61613c1b1fa20f75e9`, with OCI image SHA-256 `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197`.

## SAPPHON-224 new source

- `tools/sapphon_224_signed_head.py` verifies actual Ed25519 signatures against a separately supplied PEM key anchor and validates its SHA-256 fingerprint and custodian-name consistency.
- Signed checkpoint heads bind exact image ancestry, a custodian root, an integer counter and a SHA-256 checkpoint digest. A submitted structural chain must match the terminal checkpoint.
- Two validly signed conflicting checkpoint hashes for the **same custodian root and counter** produce `SIGNED_EQUIVOCATION_SAME_COUNTER` regardless of which head appears first.
- Signature mutation, key-fingerprint substitution, root mismatch, nonterminal signed heads, and absent records fail closed.
- `tools/test_sapphon_224_signed_head.py` contains 12 deterministic regression fixtures that create real local Ed25519 signatures. Local signers are not independent custodians.
- `.github/workflows/sapphon-224-signed-head.yml` runs the tests and preserves an explicit missing-external-head verdict.

## Trust and authority boundary

A separately supplied public key, even if it verifies valid signatures, does not establish an independently provisioned trust root. A valid timestamp string is not authenticated UTC; a same-counter fork check is not externally anchored global anti-rollback. GitHub cannot attest independent physical custody of the source-owned image merely by executing a separate job.

**Source-owned bytes: VERIFIED. Independent external witnesses: 0. Authenticated UTC: FALSE. Global anti-rollback: FALSE. Recovery: HOLD. Lock cleared: FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
