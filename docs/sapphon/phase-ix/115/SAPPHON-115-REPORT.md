# SAPPHON-115 — Crash-Window Recovery & Local Effect Reconciliation

**Phase IX:** 3/8 · 37.5%.  
**Acceptance:** 27/27 new crash-recovery checks, 23/23 SAPPHON-114 destination checks, 28/28 SAPPHON-113 fencing checks, and all 98 inherited frozen files (Phase VI: 11; Phase VII: 45; Phase VIII: 42).

## Delivered

- `tools/sapphon_115_reconcile.cjs` introduces a separate local synthetic effect journal with `PREPARED`, `COMMITTED`, and `ABORTED` states, using the canonical SAPPHON-113 directory lock and the source-of-truth writer registry.
- The PREPARED intent is persisted with atomic rename, file sync, and directory sync *before* the local journal effect is committed. An interruption at this point leaves an inspectable PREPARED record.
- Recovery may complete a PREPARED intent only while its original writer, fencing epoch, issued nonce, and lease remain valid. A stale or expired intent is durably ABORTED and cannot be revived under the same effect ID.
- A synthetic commit that was persisted before a lost client acknowledgement is returned on retry without adding a second effect. The replayed receipt must match original effect ID, epoch, writer, nonce and payload hash.
- The verifier disallows duplicate reserved nonces, conflicting effect identifiers, forged fields, malformed journal state, missing authority stores, lock contention and client-supplied clock rollback.
- `tools/test_sapphon_115_reconcile.cjs` checks real local temporary files, post-prepare and post-commit injected crashes, restart reads, lost acknowledgements, idempotent retries, recovery after lease expiry, and durable rejection history. The test suite initially revealed a fixture nonce collision; the fixture was corrected and the later Actions run passed.
- `docs/sapphon/phase-ix/115/index.html` retains the three R/G/B neon pump rings, eight phases, center `{{i}}`, four frozen clock registers, and interactive observation-only fault explanations.
- `.github/workflows/sapphon-115-reconcile.yml` gates the new test and 51 inherited checks, browser script syntax, and all 98 frozen Phase VI–VIII file hashes.

## Explicit qualification limits

The only “effect” here is a state transition within the local JSON journal. There is **no real external actuator, remote transaction, payment, or physical measurement**. Accordingly, local journal idempotency must not be called universal exactly-once delivery. A real external side effect requires a transactional downstream commit protocol, a receiver-maintained deduplication ledger, or durable outbox/inbox reconciliation. The canonical store remains one local filesystem. A privileged filesystem rollback can reintroduce previously committed effects unless checked against independent immutable external state. Caller-provided local time and synthetic clock evidence are not calibrated UTC.

**Global exactly-once authority: HOLD. Independent external custody: HOLD. Physical clock and UTC: HOLD.**

## Next natural bound

**SAPPHON-116 — Durable Outbox/Inbox & Receiver Idempotency Contract.** Model a separate receiver's durable deduplication record and bounded acknowledgements, test dropped replies and sender restarts, and reject replays at the receiver itself. Retain the original synthetic clock and all prior immutable freezes.

`.dlw`
