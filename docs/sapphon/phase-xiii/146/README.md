# SAPPHON-146 — Dual Anchor Providers & Cross-Custodian Disagreement

**Phase XIII · 2/8 · 25% design progression · operational authority HOLD**

## Implementation

`rust/sapphon-liveness/src/dual_anchor146.rs` compares two SAPPHON-145 Ed25519-signed checkpoints. Each has a separately provisioned public key, provider ID, counter floor, and claimed custody root. Both signatures must verify before a comparison is returned.

Comparison categories are:
- `SameCheckpoint`: same sequence, head, epoch.
- `ConflictingHeadAtSameSequence`: identical sequence, contradictory signed heads.
- `DifferentSequenceFloors`: checkpoint sequence levels disagree; this is **not automatically equivocation**.
- `DifferentEpochs`: same sequence/head with divergent epochs.

The comparison result includes provider IDs, checkpoint heads, sequences, epochs, a deterministic SHA-256 digest over their ordered payloads, and a permanent `HOLD` decision. Provider ordering does not change the evidence digest.

## Tests authored

Seven Rust tests cover matching signatures remaining HOLD; contradictory heads; lagging provider sequence; shared declared ancestry or signing key; forged second signature; revoked or stale counters; and order-independent results.

## Trust boundary

Two cryptographic keys do not establish two independent physical or organizational witnesses. Claimed ancestry roots and provisioned keys require authentication outside this application. Different sequence floors may reflect ordinary propagation lag or storage rollback; the module preserves that uncertainty and never votes an authority grant. Neither an authenticated signature nor matching content proves external custody, secure UTC, global anti-rollback, recovery entitlement, or actual process exit.

## Publication and CI

The read-only workflow `.github/workflows/sapphon-146-dual-anchor.yml` runs Rust liveness and inherited security suites, checks 188 historically frozen source hashes, checks HOLD invariants, and builds Rust docs. Actions outcome and Pages deployment remain unverified until read back from a completed run.

The Phase XII source freeze remains design-complete but **not CI-certified** where passing workflow evidence is unavailable.

## Next bound — SAPPHON-147

Cross-provider ancestry lineage: bind each signature to a separately retained prior checkpoint, adjudicate asynchronous provider lag and conflicting branches without conflating replicated records with independent testimony. Include adversarial key rotation and provider disappearance tests.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
