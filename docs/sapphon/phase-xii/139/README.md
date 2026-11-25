# SAPPHON-139 — Supervised Append Ownership & Crash-Consistent Handoff

Phase XII · 3/8 (37.5% implementation progression) · operational authority HOLD

## Software boundary
`rust/sapphon-liveness/src/writer139.rs` contains a Linux-only, descriptor-bound supervised writer. It holds an advisory exclusive flock on the original descriptor, checks pathname device/inode identity before and after operation, rejects hardlinked/symlinked or oversized registry paths, and validates the old transcript against a separately supplied sequence/head anchor. It constructs and verifies the complete proposed next record before writing to the held descriptor with positional writes, fsync, and exact readback.

Successful local append yields `PendingCheckpoint` with `local_fsync_observed=true`, `external_checkpoint_acknowledged=false`, `decision=HOLD`, `lock_cleared=false`. It deliberately does not advance a trusted external anchor.

## Tests authored
1. Successful append/readback after simulated restart; still no external acknowledgement.
2. Second cooperative writer rejected by Linux flock.
3. Stale trusted anchor rejected without writing.
4. Incomplete partial record quarantined without silent truncation.
5. Inode/pathname substitution rejected before writing.

## Explicit non-claims
- Tests are authored but require a passing GitHub Actions run for qualification.
- A partial filesystem write can remain after an I/O failure. Reconciliation is fail-closed, not automatic repair.
- flock remains advisory. Hostile uncooperative processes, file replacement races, and adversarial filesystem behaviors remain potential threats.
- External custody, authority to change the checkpoint, secure UTC, and global anti-rollback have not been established.
- Historical 188 immutable source hashes are checked by CI, not asserted passed without readback.

## GitHub Actions
`.github/workflows/sapphon-139-writer.yml` gates inherited Rust tests, new supervised append tests, explicit HOLD invariants, and 188 historical hashes.

## Next natural bound — SAPPHON-140
Dual-custodian checkpoint acknowledgement: require a separately authenticated, monotonic receipt after local fsync, detect a durable-but-unacknowledged state on restart, and never advance authority from local success alone.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
