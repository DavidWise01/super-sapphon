# SAPPHON-132 — Rust Linux Lock Ownership & Process-Liveness

**Phase XI: 4/8 · 50% software milestone.**

This new independent Rust crate records the local holder's PID, Linux `/proc/<pid>/stat` start ticks, kernel boot ID, journal-byte SHA-256 and declared owner label when the holder acquires an exclusive directory lock. It fsyncs its owner marker and the containing directories.

`qualify()` reloads the owner marker, checks the journal hash, then uses actual Linux process data—not the SAPPHON-131 caller's `coordinator_confirmed_exit` assertion—to return ALIVE, DEAD, or UNKNOWN. ALIVE and UNKNOWN are ineligible even for operator review. DEAD is only a **candidate for later signed operator review**. No API in this crate clears the retained lock, grants execution authority, or changes the signed recovery receipt ledger.

The test binary starts an independent owner process, confirms the same PID/start identity is alive, kills and reaps the exact process, and confirms the OS no longer reports that identity. Additional cases test process identity reuse detection, boot ID mismatch, malformed stat parsing, changed journal, corrupted marker, spoofed PID, exclusive acquisition, and missing marker.

**Security limitation:** `owner.json` is written on a local mutable filesystem and is *not authenticated cryptographically* to a separate immutable record or an OS-granted lock handle. A privileged attacker who forges its PID may produce an OS DEAD observation even while the actual original holder is alive. That observation alone MUST NEVER permit clearance, and the provided Rust API intentionally has no clearance method. A production-grade lock requires non-forgeable owner registration, kernel-held lock fencing and OS process handle lifecycle checks. Never substitute `qualify()` for that complete system.

Platform scope: Linux /proc only, runner Ubuntu 24.04. This is not a portable or cross-host liveness protocol. Linux process exit does not demonstrate independent custodian consent, physical time, authenticated UTC, or globally monotonic state.

```bash
cargo test --manifest-path rust/sapphon-liveness/Cargo.toml --all-targets
```

**Independent external custody HOLD · OS-backed live observation TEST ONLY · Authenticated lock ownership HOLD · Actual lock clearance HOLD · Global anti-rollback HOLD.**

Next bound: **SAPPHON-133 — Kernel-Owned File Lock & Tamper-Proof Owner Registration**.

`.dlw`
