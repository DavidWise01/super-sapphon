# SAPPHON-130 — Rust Cross-Process Contention & Crash Fault Matrix

**Phase XI · 2/8 · 25% software milestone**

## Delivered

- New `rust/sapphon-contention` Rust crate, independent OS-process worker, and integration tests, depending on SAPPHON-129's already committed durable journal.
- Eight independent child processes race to append at revision zero. Only one may succeed; failed writers must report either `STORE_BUSY` or `REVISION_CONFLICT`. Cross-process signatures are verified against deterministic synthetic test keys.
- A separately spawned lock-holder process is forcibly terminated. Its lock remains in place and blocks writers until the test coordinator confirms that exact child has exited and explicitly performs a simulated manual operator recovery.
- A killed staging process leaves a partial untrusted temporary file and the original journal. Recovery never promotes that incomplete staging artifact to signed evidence.
- Before-rename and after-rename injected faults verify old-journal retention and lost-acknowledgement readback. Concurrent and stale-revision writes are fenced; identical observations are idempotent, and incompatible signed snapshots remain as recorded forks.
- New neon three-pump and four-clock-register Phase XI viewer at `docs/sapphon/phase-xi/130/index.html`.
- GitHub Actions runs the new real subprocess tests, the inherited Rust test suites, viewer syntax check, and SHA-256 readback of all 188 parent frozen files.

## Limits

A forced process termination and injected fault are not hardware power interruption; the local lock protocol has not been verified across network filesystems or distributed machines. Stale-lock recovery is *operator-reviewed* in the fixture; unknown lock owners are not silently cleaned up. Local filesystem sync and journal readback do not prove globally authoritative custody, authentic UTC, or resistance to joint-disk rollback.

**Independent external custody HOLD · Global anti-rollback HOLD · Physical clock/UTC HOLD · Real-world effect authority HOLD.**

## Next natural bound

**SAPPHON-131 — Rust Recovery Receipts & Operator-Fenced Lock Clearance**, with explicit verified post-crash readbacks and provenance-bound recovery decisions, while maintaining the Phase XI and inherited freezes.

`.dlw`
