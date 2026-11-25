# SAPPHON-140 — Dual-Custodian Checkpoint Receipts & Restart Reconciliation

**Phase XII · 4/8 · 50% design progression · operational authority HOLD**

## New implementation
`rust/sapphon-liveness/src/checkpoint140.rs` introduces a versioned Ed25519 checkpoint receipt and a fail-closed restart reconciler. A receipt signs witness ID, current registry sequence/head, previous sequence/head, and witness counter. The verifier requires key possession, strictly increasing counter relative to a supplied floor, non-revoked key, and distinct declared ancestry roots.

The locally durable `PendingCheckpoint` must not already assert external acknowledgement or lock removal. The reconciler requires an exact one-event extension of a separately supplied prior anchor; validates the previous chain, final event, and full chain; rejects truncated journals and mismatched receipt values.

## Outcome states
1. `LocalDurablePending`: valid local fsync record; fewer than two valid receipts.
2. `DualSignedCustodyPending`: two distinct, valid signed receipts, yet no proven independent custody.
3. `AtSuppliedAnchorHold`: current transcript matches a caller-supplied anchor. The code cannot authenticate where that anchor came from.

All outcomes remain `decision=HOLD`, `lock_cleared=false`, `external_checkpoint_acknowledged=false`, and `global_anti_rollback=false`.

## Regression tests authored
Eight tests: zero receipts; two valid receipts still HOLD; shared ancestry; forged receipt; revoked/stale counters; stale previous anchor; truncated restart tail; current supplied anchor still HOLD.

## Security limits
Distinct keys are not equivalent to independently controlled custodians. The supplied registry, ancestry assignments, monotonic counter floors, and anchors require outside provisioning and authentication. A successful Ed25519 check does not authenticate wall-clock time, secure hardware, external custody, global anti-rollback, or physical process exit. No lock is cleared.

## CI
`.github/workflows/sapphon-140-checkpoints.yml` runs the Linux Rust regressions, inherited recovery tests, historical 188 frozen hashes, and explicit HOLD invariants. A passing run and Pages deployment are not assumed until observed.

## Next natural bound — SAPPHON-141
Authenticated external checkpoint receipts and monotonic custody floors across restart. Test witness equivocation on the same sequence, conflicting heads, and replacement of an externally provisioned key registry. Keep operational authority HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
