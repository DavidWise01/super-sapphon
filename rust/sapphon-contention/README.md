# SAPPHON-130 · Rust Cross-Process Journal Contention

**Phase XI · 2/8 · 25% software milestone.**

A new Rust executable operates against the frozen SAPPHON-129 Rust journal API without changing that API or any previously frozen Phase VI–X source.

## Run

```bash
cargo test --manifest-path rust/sapphon-contention/Cargo.toml --all-targets
cargo run --manifest-path rust/sapphon-contention/Cargo.toml -- init /tmp/sapphon-fixture
cargo run --manifest-path rust/sapphon-contention/Cargo.toml -- append /tmp/sapphon-fixture 0 sample-source false none
cargo run --manifest-path rust/sapphon-contention/Cargo.toml -- inspect /tmp/sapphon-fixture
```

The worker uses a **deterministic Ed25519 test seed**, never a real custodian key. All results remain observation-only.

## Tested

- Eight **independent child processes** attempt the same expected revision concurrently. Exactly one may commit; other processes must fail with `STORE_BUSY` or `REVISION_CONFLICT`.
- Two independent sequential child processes append incompatible signed snapshots without overwriting either signed fork.
- A separate lock-holding Rust process is killed by the test coordinator. The lock directory persists, so subsequent writers fail closed. The coordinator explicitly confirms the exact child has exited before simulating **manual operator lock recovery**.
- A killed staging process leaves incomplete temporary output and the old complete signed journal. Recovery explicitly cleans the orphaned staging artifact; nothing is silently treated as evidence.
- Injected faults before and after rename verify old-state retention and acknowledgement ambiguity. A failure after rename is not proof that the write was rolled back; disk inspection determines the observed local revision.
- Corrupt journal data and stale revisions cannot be accepted by a new process. Duplicate observations are idempotent.

## Boundaries

The process-kill simulations exercise *OS-process termination* and named local fault points. They do **not** simulate a physical power cut, prove filesystem durability under power loss, or authenticate offsite custodian state. The directory lock is a local coordination protocol, not a cross-host or network-filesystem lock. The test operator removes a stale lock only after knowing the exact child process is dead. The engine never steals or auto-deletes an unknown lock.

**Independence HOLD · Global anti-rollback HOLD · Physical time/UTC HOLD · Real effect authority HOLD.**

## Next bound

**SAPPHON-131 · Rust Journal Recovery Receipts & Operator-Fenced Stale Lock Clearance.** Durable, signed evidence of post-crash readback and operator-reviewed recovery decisions, while keeping all previous freezes intact.

`.dlw`
