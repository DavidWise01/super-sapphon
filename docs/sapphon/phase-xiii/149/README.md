# SAPPHON-149 — Disaster Recovery Intent Replay Against Externally Retained Evidence

**Phase XIII · 5/8 · 62.5% design progression · operational authority HOLD**

## Implementation

`rust/sapphon-liveness/src/replay149.rs` introduces a read-only disaster recovery adjudicator. It accepts local registry bytes, optional local rotation-intent bytes, expected intent SHA-256 retained elsewhere, a separately retained prior history digest, a signed checkpoint anchor, and a provisioned verification key/counter floor.

Before reviewing local bytes, it validates the signed anchor using the SAPPHON-145 Ed25519 interface and supplied provider floors. It checks the recovered local intent against the separately supplied expected SHA-256. The local registry must pass the inherited SAPPHON-137 complete hash-chain parser. Its computed local head is used **only as a syntax/chain-validation input**, never as an independently trusted checkpoint.

A valid registry is compared with the signed anchor at the anchor's exact historical position, avoiding a false match to a newer head. The result is observation-only.

## Replay classification

- `MatchedExternalEvidence`: the local chain matches the signed checkpoint and supplied expected intent digest.
- `LocalHistoryRolledBack`: local chain ends before the signed checkpoint sequence.
- `LocalHistoryAheadPending`: the local chain extends beyond a matching signed prefix.
- `ContradictoryLocalHistory`: the local history has a different head at the checkpoint sequence.
- `LocalHistoryCorrupt`: local registry is malformed, truncated or fails inherited chain validation.
- `IntentUnavailable`: intent is absent, modified, or inconsistent with supplied history/provisioned provider.

All results have `independent_custody_proven=false`, `lock_cleared=false`, `replacement_key_accepted=false`, `decision=HOLD`.

## Regression tests authored

Seven tests: valid same-checkpoint replay stays HOLD; erased local transcript reports rollback; modified intent fails digest readback; partial tail quarantined; contradictory signed checkpoint is not promoted; missing intent remains unavailable; forged signed anchor fails verification.

## Qualification limits

This layer does not authenticate that trusted hashes were genuinely retained outside the owner-controlled system, prove physical witness independence, reconstruct a remote copy, install a new key, promote local state, or authorize automatic recovery. A hostile actor controlling the checkpoint signer and all supplied trusted floors can forge a self-consistent story. There is no trusted UTC or global anti-rollback in this code.

The new read-only CI workflow `.github/workflows/sapphon-149-replay.yml` runs all inherited Linux Rust tests and the 188 frozen historical source hash checks. Passing CI and Pages deployment are not claimed without independent run/deployment readback.

## Next natural bound — SAPPHON-150

Externally anchored replay evidence chain with contradictory reconstruction packets and a separately retained monotonic checkpoint floor. Expand adversarial recovery tests to detect simultaneous journal, intent, and provider-registry replacement while preserving HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
