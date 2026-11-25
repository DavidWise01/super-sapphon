# SAPPHON-129 — Rust Durable Journal

Phase XI · 1/8 · crash-atomic local synthetic observation archive.

This standalone Rust crate depends on `../sapphon-audit` but **does not modify any source frozen in Phase X**. It preserves SAPPHON-125 canonical signed-snapshot verification, SAPPHON-127 equivocation detection and shared GitHub/Pages ancestry, while implementing actual local-disk persistence in Rust.

## Contract

`initialize(root, pins)` creates a new empty journal; existing journals are never overwritten. `inspect(root, pins)` reloads and validates all signed entries and conflict records. `append(root, pins, expected_revision, signed, source_id, ancestry_roots, fault)` acquires a directory lock, reloads, validates, uses compare-and-swap revision fencing, applies one signed observation, writes the entire snapshot to a new file, fsyncs it, atomically renames and fsyncs the parent directory before returning success.

The lock directory is never automatically stolen, even if its owner crashes. After such a crash, manual operator review is required; indiscriminate stale-lock deletion risks concurrent writers. Journal data is bounded to 16 MiB. The per-process temporary filename is exclusively created and cleaned up on failure.

## Crash semantics

`Fault::BeforeRename`: no new committed journal; old valid state remains.

`Fault::AfterRename`: operation returns an injected error, but the new content may be visible and may survive a real crash. Caller **must inspect and reconcile**, not retry blindly at a guessed revision.

`Fault::None`: temp file fsync, rename, and parent-directory fsync are attempted; success means a local software commit, **not remote independent custody**. Guarantees depend on operating system and filesystem behavior; no power-loss hardware qualification is asserted.

## Test

```bash
cargo fmt --manifest-path rust/sapphon-journal/Cargo.toml --all -- --check
cargo test --manifest-path rust/sapphon-journal/Cargo.toml --all-targets
```

Rust tests cover restart readback, both interrupted-commit boundaries, stale revisions, idempotent replay, signed publication fork retention, shared mirror ancestry, lock conflicts, corrupt snapshots, forged signatures, revoked pins and unknown authority metadata.

## HOLD

These tests are synthetic on local files. File replacement and directory sync do **not** establish globally linearizable writes, trusted time, independently owned witnesses or anti-rollback against an attacker who replaces the entire journal and its backup. A real power-cut fault injector, independent monotonic store and cross-host crash recovery are outside this initial Phase XI bound.

`.dlw`
