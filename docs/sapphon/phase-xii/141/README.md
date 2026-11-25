# SAPPHON-141 — Witness Equivocation and Monotonic Receipt History

Phase XII · 5/8 · 62.5% design progression · operational authority HOLD.

## Implementation
`rust/sapphon-liveness/src/equivocation141.rs` introduces a versioned receipt history and externally supplied history digest. A receipt is accepted only if its SAPPHON-140 domain-separated Ed25519 signature verifies using a supplied non-revoked witness key and a counter above both key minimum and retained witness counter.

The ledger rejects multiple heads for a single `(witness_id, sequence)`, duplicate checkpoint receipts, revoked keys, forged signatures, and stale counters. It records a deterministic digest of the new history for the caller to retain independently.

## Critical limitation
If the same attacker controls this history and its purported trusted digest, it can replace both. The implementation does NOT establish independent custody, a globally monotonic counter, secure time, physical device independence, or a recovery entitlement. Distinct keys and ancestry labels alone never prove independent source roots.

## Tests authored
1. Two signed receipts remain HOLD.
2. Conflicting heads for same witness and sequence are rejected.
3. Stale counter after reconstructed history is rejected.
4. An altered history anchor is rejected.
5. A revoked key is rejected.
6. A forged signature is rejected.

## Verification
Source and module integration are committed. Test execution and GitHub Pages deployment must be verified separately; the existence of committed tests does not certify their success. The inherited 188 frozen hash gate remains mandatory.

## Next bound — SAPPHON-142
Authenticated append-only evidence export with independent custody acknowledgement receipts, explicit source ancestry, cross-checkpoint disagreement handling, and full CI readback. Preserve all HOLD gates.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
