# SAPPHON-129 — Rust Persistent Journal & Crash-Atomic Append

**Phase XI · 1/8 · 12.5% software milestone**

## Implemented

- `rust/sapphon-journal/Cargo.toml`: new standalone Rust package depending on the already-frozen `sapphon-audit` crate by relative path; no modification of Phase X's frozen Rust source.
- `rust/sapphon-journal/src/lib.rs`: exclusive directory process lock, verified journal readback, expected-revision fencing, canonical signed publication ingestion, temporary file exclusive creation, temp fsync, atomic rename, directory fsync and explicit replay/no-op behavior.
- `rust/sapphon-journal/tests/recovery.rs`: 18 intended recovery tests for cold readback, fault boundaries, acknowledgement ambiguity, stale revisions, replay, fork retention, mirror source ancestry, exclusive lock, corrupt journal, deleted journal, false authority, forged signatures and revoked pins.
- `docs/sapphon/phase-xi/129/index.html`: Phase XI neon Rust persistence viewer; keeps three RGB pumps, center `{{i}}`, four synthetic time registers and observation-only crash-status controls.
- `rust/sapphon-journal/README.md`: persistence and crash-acknowledgement contract.

## Fault semantics

`BeforeRename`: old valid journal remains; no committed observation was installed. `AfterRename`: the caller sees an injected failure and must inspect disk for the actual state; a real crash before directory fsync has platform-specific durability uncertainty. `None`: success requires local temp-file fsync, rename and parent directory fsync. Exclusive lock directories fail closed if unexpectedly present; they are not automatically stolen.

## Verification

The Phase XI GitHub Actions workflow must pass Rust formatting, all new and inherited crate tests, neon viewer verification, and all five prior freeze manifests before this phase is marked source-verified. The five frozen phases VI–X contain 188 source-file hashes (11+45+42+42+48).

## Trust boundary

Local fsync+rename does not prove power-loss hardware correctness, cross-host linearizability, or resistance to an adversary who replaces the whole filesystem snapshot. The pinned Ed25519 identities are synthetic fixtures. A complete local rollback can remain internally consistent without an independently retained high-water mark.

**Real external custody: HOLD · Global anti-rollback: HOLD · Physical/UTC clock authority: HOLD · Real-world effect authority: HOLD.**

## Next natural bound

**SAPPHON-130 — Rust Journal Fault-Matrix & Cross-Process Contention.** Test two independent Rust processes, stale-lock operator recovery, rename boundary crash failures and metadata fsync behavior under retained audit evidence.

`.dlw`
