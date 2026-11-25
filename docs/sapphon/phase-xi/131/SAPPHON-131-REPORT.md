# SAPPHON-131 — Signed Recovery Receipts & Operator-Fenced Lock Clearance

**Phase XI: 3/8 · 37.5% software milestone.**

## Delivered

- `rust/sapphon-recovery/src/lib.rs`: new Rust signed recovery-receipt gate with strict JSON schemas; Ed25519 operator signature over canonical fields; exact SHA-256 of current journal bytes; revision, nonce, declared lock-owner PID, claimed coordinator-confirmed process exit, chain sequence and predecessor receipt digest.
- A dedicated `.recovery-exclusive` lock synchronizes receipt preparation and clearance independently from the intentionally retained `.exclusive-lock` writer lock. Recovery state is persisted to `recovery-receipts.json` with fsync, atomic rename and parent-directory fsync.
- `prepare()` validates the signed operator claim and pinned journal state before preparing a durable receipt. Repeated identical signed approvals are idempotent; nonce reuse with another signed payload and missing predecessor ancestry fail closed.
- `clear()` requires exact previously durable receipt, validates the current journal again, then removes the retained writer lock and fsyncs the directory. A corrupted recovery journal, changed original evidence, forged signature, or missing receipt prevents clearance.
- `rust/sapphon-recovery/tests/receipts.rs`: 18 synthetic local-disk tests of missing lock, forged signer, false exit claim, digest/revision mismatch, idempotent acknowledgment, reused nonce, interrupted history, corrupted receipts, concurrent recovery lock and clearance replay.
- `docs/sapphon/phase-xi/131/index.html`: neon read-only three-pump/four-register viewer inheriting the synthetic clock and displaying the recovery qualification boundary.

## Scope and safety

The operator-signed `coordinator_confirmed_exit` is **not independently verified process death**. The inherited writer lock directory does not identify its owning process. Therefore this synthetic module **must not be deployed for unattended live lock clearance**; a malicious or mistaken holder of the operator signing key could falsely claim that a live owner exited. The Phase XI next bound must add authenticated lock ownership and OS-backed process lifecycle evidence before considering production use.

The issuer, operator and publisher keys in tests are synthetic. Filesystem fsync and receipts cannot authenticate external organizations, globally retained high-water state, real-world UTC or independence.

**External custody: HOLD · Authenticated owner death: HOLD · Global anti-rollback: HOLD · Physical UTC: HOLD · Operational authority: HOLD.**

## Next natural bound

**SAPPHON-132 — Authenticated Rust Lock Ownership & OS Process-Liveness Fencing.** Require lock owner identity issued when the writer acquires the lock, verify a confirmed OS exit rather than accepting a caller-declared boolean, and maintain durable receipt ancestry without changing frozen historical files.

`.dlw`
