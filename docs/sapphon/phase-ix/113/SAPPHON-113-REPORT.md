# SAPPHON-113 — Phase IX Single-Writer Epoch & Partition Fencing

**Phase IX:** 1/8 · 12.5%  
**Verified GitHub Actions:** 28/28 new epoch/partition tests; 20/20 SAPPHON-112 split-brain counterexamples; 23/23 SAPPHON-111 durable capture checks. Phase VI 11 hashes, Phase VII 45 hashes and Phase VIII 42 hashes unchanged.

## Delivered
- `tools/sapphon_113_fence.cjs`: local canonical single-writer lease registry, monotonically increasing writer epoch, nonce minting only for current nonexpired lease, durable rejected-attempt audit, exclusive local mutation lock, bounded resource capacity, and atomic/fsynced source writes.
- A current writer can issue nonces only while its lease is valid. Stale epochs, competing writers, expired leases, repeated nonces and malformed requests fail closed.
- The test API refuses authorization whenever it is explicitly told the central store is unreachable. The registry rejects local clock rollback, corruption and silent reinitialization.
- `tools/test_sapphon_113_fence.cjs` includes 28 tests for lease acquisition, fencing rotation, partition denial, restart history, malicious authority fields and audit preservation.
- `docs/sapphon/phase-ix/113/index.html`: read-only neon Phase IX viewer with the protected R/G/B pumps, eight phase positions, center `{{i}}`, four clock registers and synthetic clock archive.
- `.github/workflows/sapphon-113-fence.yml`: mandatory regression gate and exact byte+SHA-256 recheck of all 98 frozen Phase VI–VIII files.

## Operational limits
This is a **single local canonical-store prototype**, not a deployed distributed single-writer authority. The `reachable` flag is an input supplied to a test API; an untrusted client can falsely assert `reachable:true`. Genuine partition fencing requires the trusted authoritative server to enforce exclusive admission, authenticated writer credentials, real fencing-token validation at every downstream commit, and durable state that cannot be forked or rolled back. Physical clocks and UTC cannot be certified from local test lease timestamps.

Rejected requests made against the reachable local store are durably logged, but requests refused before contacting the central store (including explicit unreachable state) cannot be captured in that store. Filesystem snapshots can still be replayed without external anti-rollback anchoring. These limitations are retained as explicit qualification gates rather than bypassed with simulated quorums.

**Global writer authority: HOLD. External custody: HOLD. Physical clock and UTC: HOLD.**

## Next natural bound
**SAPPHON-114 — Downstream Fencing-Token Enforcement & Atomic Side-Effect Gate.** Require the current epoch at the actual commit destination, reject stale and expired writers even after locally issued tokens, and preserve the observable failure record without using a caller-supplied connectivity assertion as authority.

`.dlw`
