# SAPPHON-132 — Rust Linux Lock Ownership & OS Process-Liveness

**Phase XI: 4/8 · 50% software milestone.**

## New Rust module

- `rust/sapphon-liveness/src/lib.rs`: records an observed PID, process start ticks, kernel boot identity, journal-byte SHA-256 and declarative owner label in a fsynced marker within the lock directory.
- The liveness verifier parses Linux `/proc/<pid>/stat` without splitting the process-name field incorrectly. It distinguishes ALIVE (matching PID+start+boot and non-zombie), DEAD (process absent, zombie, or different start ticks), and UNKNOWN (boot ID mismatch or inaccessible process data).
- `rust/sapphon-liveness/src/main.rs`: standalone process fixture creates the actual lock directory and marks identity while holding it, then can be killed or exited to test an OS-observed process lifecycle.
- `rust/sapphon-liveness/tests/owners.rs`: 14 intended tests for independent owner process lifecycle, killed owner, clean exit, concurrent acquisition, journal mutation, fabricated PID, process identity/boot mismatch, parser faults, missing/corrupt marker and strict schema behavior.
- `docs/sapphon/phase-xi/132/index.html`: read-only neon three-pump and four-register viewer with explicit custody HOLD.
- Existing SAPPHON-131 recovery receipt and prior Rust crates remain untouched.

## Critical gap

The local owner marker is *not independently authenticated*. A privileged attacker can forge the PID and make a false dead observation even while the true holder remains alive. Consequently **SAPPHON-132 intentionally does not expose any lock-clearing operation**. The liveness reading is informational; authorization requires a future authenticated kernel-owned lock and provenance-bound operator receipt.

The module does not prove actual third-party custody, independent witnesses, authenticated UTC, physical-clock correctness or global anti-rollback. The tests are Linux OS-process simulations, not remote-site or power-cut qualifications.

**Owner marker authenticity: HOLD · Operational clearance: HOLD · External custody: HOLD · Global anti-rollback: HOLD · Physical UTC: HOLD.**

## Next natural bound

**SAPPHON-133 — Kernel-Owned Advisory Lock & Tamper-Resistant Owner Registration.** Replace the mutable lock-owner marker as an authority source with kernel-held exclusive file locking and a two-stage check that an unknown/old owner cannot be revived by forged metadata. Keep signing and external custody separately qualified.

`.dlw`
