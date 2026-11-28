# SAPPHON-227 — Portable Fork Bundle Readback & Signed Custody ACK Gate

## Predecessor verified

SAPPHON-226 hosted report run [46165617650](https://github.com/DavidWise01/super-sapphon/actions/runs/46165617650) completed SUCCESS; its `Run portable fork export regression cases` step passed and its explicitly negative `FORK_TRANSFER_REJECTED_HOLD` artifact was retained as GitHub-owned evidence. The runtime did **not** receive real externally authenticated signed forks or external acknowledgments. The original verified OCI image ancestry remains run `46154833375`, commit `c167a95a05177e280625fa61613c1b1fa20f75e9`, SHA-256 `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197`.

## SAPPHON-227 code

- `tools/sapphon_227_portable_readback.py` rehashes the exported SAPPHON-226 canonical manifest, verifies every indexed signed envelope and both fork branches, then **rebuilds the original SAPPHON-225 signed fork retention from all Ed25519 envelopes** using a separately supplied key anchor and recreates the entire SAPPHON-226 bundle for exact equality. It refuses missing branches, key substitution, altered signatures, changed manifest digests and original image/source swaps.
- A custody ACK may be supplied as a signed Ed25519 envelope binding exact bundle SHA-256, custodian root, source run/commit, fork count, UTC claim, and a transfer nonce. Verification requires a matching separately supplied public-key anchor. This proves **only signature bytes under the provided key**. It does not authenticate that the key really belongs to an independent custodian or that the custodian obtained the bytes.
- `tools/test_sapphon_227_portable_readback.py` contains 13 positive/negative scenarios including signed ACK, malicious bundle changes, missing fork branches, wrong hash, altered signing key, false recovery claim and no witness promotion.
- `.github/workflows/sapphon-227-portable-readback.yml` builds a **source-owned synthetic signed fork** locally and replays the portable export in a new hosted runner. The resulting artifact is a test fixture, **not an external fork receipt**.

## Non-destructive reconciliation

All canonical signed heads are preserved, including the conflicting branch; `reconciliation=NO_WINNER_SELECTED`. No receipt can delete a branch, elect a winner, grant recovery or clear a lock. Missing ACK is explicitly reported as `PORTABLE_BUNDLE_REPLAYED_ACK_HOLD` if the canonical bundle replays correctly; a valid signature over a fully bound ACK reports `SIGNED_ACK_CHECKED_CUSTODY_HOLD`. Every state remains **HOLD** for external independent authentication.

### Required external evidence

An independent custodian must separately authenticate its public key through an out-of-band trust root, obtain the actual evidence bytes and rehash them, issue an independently retained signed acknowledgment, preserve both branches and show independently verifiable time and monotonic anti-rollback checkpoints. A self-issued key and signature in GitHub tests do not satisfy those requirements.

**Original image parity: VERIFIED (source-owned). External witnesses: 0 authenticated. Authenticated UTC: UNVERIFIED. Global anti-rollback: UNVERIFIED. Recovery: HOLD. Lock cleared: FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
