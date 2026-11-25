# SAPPHON-138 — Descriptor-Bound Registry Checkpoint Fencing

**Phase XII · 2/8 · 25% implementation progression · operational authority HOLD**

## Implementation
- Rust: `rust/sapphon-liveness/src/fence138.rs` (Linux-only)
- CI: `.github/workflows/sapphon-138-fence.yml`
- Retains SAPPHON-137's hash-chained registry journal and exact externally supplied `(sequence, head)` anchor.
- Uses `O_NOFOLLOW` and `O_CLOEXEC` for an opened registry descriptor.
- Requires a single-link regular file no larger than 1 MiB; rejects symlink paths and oversize ledgers.
- Acquires a nonblocking advisory `flock(LOCK_EX | LOCK_NB)` and holds the file descriptor open.
- Verifies device/inode identity of the named path both before and after reading, and validates the transcript against the supplied anchor.
- Uses positional `read_at` to examine the held descriptor without relying on a shared seek offset.

## Adversarial tests authored
1. A symlink substituted for the registry path cannot be opened.
2. Two cooperative writer handles cannot simultaneously acquire the exclusive lock.
3. A renamed/replaced pathname fails identity verification.
4. An incorrect trusted-anchor sequence fails closed, while an empty trusted-genesis checkpoint can be read.

## Residual limitations
- `flock` is advisory; malicious processes or writable filesystem layers can bypass it.
- A mutable file may change without changing inode or final size. Descriptor readback is not a hard guarantee of immutable bytes.
- A trusted external checkpoint service is NOT implemented. A caller-supplied or co-controlled anchor is not independent and cannot establish global anti-rollback.
- Linux-only: no Windows or macOS liveness/fencing qualification.
- This guard is observation-only. No lock clearance, physical authority, external custody, or authenticated UTC.
- CI and deployment are separate verification gates. Committed Rust and authored tests do not alone demonstrate passing tests.

## Next natural bound — SAPPHON-139
Implement a supervised writer primitive that owns the advisory lock while appending, holds the original descriptor, and checks a separately retained checkpoint update without claiming remote independence. Add interruption, crash and uncooperative-writer adversarial tests.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
