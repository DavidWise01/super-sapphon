# SAPPHON-131 · Rust Signed Recovery Receipts

**Phase XI 3/8 · 37.5% software milestone.** New Rust crate independent of every earlier frozen source.

A recovery receipt binds a pinned Ed25519 operator key to a local journal byte digest (SHA-256), revision, declared lock-owner process ID, nonce, and coordinator's **declared** process-exit confirmation. The receipt is committed and fsynced **before** the retained journal lock is cleared.

`prepare()` checks the locked journal, verifies a signed operator approval, enforces unique nonces and a hash-linked receipt sequence, and atomically writes `recovery-receipts.json` with temp-file fsync, rename and directory fsync.

`clear()` refuses to remove `.exclusive-lock` unless that exact approval already exists in the durable receipt log, the original journal bytes still match, and the caller possesses the signed approval. Successful cleanup includes parent-directory fsync and returns `LOCK_CLEARED_LOCAL_HOLD`. Replays and lost acknowledgement are handled by local readback; the API never grants an external effect.

**Important limitation:** The `coordinator_confirmed_exit` field is a signed *claim*, not kernel-verified proof that a process is dead. The production lock owner is not authenticated by SAPPHON-129's empty lock directory, so SAPPHON-131 cannot prove the recorded PID owned that lock. Manual operator review, independent process-status evidence, and a trusted signing-key provisioning system are needed before using this as real stale-lock recovery authorization. In particular, a signer with the test key can falsely claim that a live process has exited. This module is a synthetic qualification experiment, **not** a safe unattended lock-removal service.

Source: `rust/sapphon-recovery/src/lib.rs`  
Tests: `rust/sapphon-recovery/tests/receipts.rs`

```bash
cargo test --manifest-path rust/sapphon-recovery/Cargo.toml --all-targets
```

Next: **SAPPHON-132 — Rust Authenticated Lock Ownership & OS Process-Liveness Fencing.** Record authenticated lock-owner identity during acquisition and require direct OS process-death confirmation before operator signature can initiate recovery.

`.dlw`
