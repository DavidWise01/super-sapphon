# SAPPHON-116 — Durable Sender Outbox, Receiver Inbox & Idempotency

**Phase IX:** 4/8 · 50%.  
**Acceptance:** 28/28 new outbox/inbox tests; 27/27 SAPPHON-115 crash-window tests; 23/23 SAPPHON-114 downstream-fencing tests; unchanged immutable Phase VI (11), Phase VII (45), and Phase VIII (42) source hashes.

## Delivered
- `tools/sapphon_116_outbox_inbox.cjs`: separate durable sender-outbox and receiver-inbox journals. Both are written with exclusive local directory locks, temporary-file creation, file fsync, atomic rename, and directory fsync.
- Signed Ed25519 sender envelopes bind the message ID, effect ID, sender, writer, epoch, nonce, and immutable payload SHA-256. The receiver verifies the configured sender public key and its revocation status before accepting the message.
- The sender queues a PENDING message independently from reception. The receiver durably records an identical message at most once, keyed by message ID, effect ID, and nonce, returning the same deterministic receipt on a subsequent authenticated replay.
- The test injects a lost network reply **after receiver commit**, verifies that the sender remains PENDING, repeats the delivery and confirms the receiver's single durable record survives. The sender then accepts a bound receipt and marks its own outbox ACKED; repeated acknowledgements do not add records.
- A changed payload under the original ID, reuse of the effect ID with another nonce, reuse of the nonce with another effect, forged signature, revoked sender, fabricated acknowledgement, corrupted journal, absent receiver and lock contention are rejected.
- `tools/test_sapphon_116_outbox_inbox.cjs`: 28 acceptance and negative cases.
- `docs/sapphon/phase-ix/116/index.html`: three concentric RGB pumps, eight phase positions, center `{{i}}`, four inherited clock registers, and observation-only neon result controls.
- `.github/workflows/sapphon-116-inbox.yml`: verification of new and inherited tests and all 98 frozen file hashes.

## Evidence boundary and limitations
The sender and receiver are separate **local filesystem directories in a deterministic synthetic test**. There is no actual network transport or separate physical custody host. The sender receipt is a deterministic content-derived acknowledgement checked against the receiver's output, not an independently signed third-party retention receipt. This test does not establish external exactly-once processing, a real receiver's downstream transaction, a shared consensus service, secure wall-clock time, independent witnesses, physical optical measurements or authenticated UTC. Sender-key enrollment is injected in test configuration and has not been independently audited.

The receiver's own durable record is the authoritative deduplication record for the modeled synthetic effect. In a real deployment, receiver-side deduplication must be atomic with the externally visible effect, and rollback resistance must be secured separately.

**External receiver qualification: HOLD. Global once-only effects: HOLD. Independent custody: HOLD. Physical clock and UTC: HOLD.**

## Next natural bound
**SAPPHON-117 — Receiver Commit Coupling & Transactional Inbox Reconciliation.** Prove that receiver deduplication and its synthetic effect update are one atomic state transition, including crash-injection and rollback tests, rather than relying on receipt equality alone.

`.dlw`
