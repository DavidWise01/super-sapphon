# SAPPHON-117 — Transactional Receiver Commit Coupling

**Phase IX:** 5/8 · 62.5%.  
**Verified acceptance:** 31/31 new transactional receiver tests; 28/28 SAPPHON-116 outbox/inbox tests; 27/27 SAPPHON-115 local effect recovery checks. Frozen Phase VI 11, Phase VII 45, Phase VIII 42, all unchanged.

## Delivered
- `tools/sapphon_117_transaction.cjs`: a receiver-only local transactional state file. The signed message deduplication record and matching synthetic effect are persisted together in **one validated JSON document** and published with a single atomic filesystem rename under the receiver's exclusive directory lock. A receiver journal missing either member fails closed.
- Ed25519 enrollment, signature verification, sender revocation, message IDs, effect IDs, nonce uniqueness and immutable payload SHA-256 are inherited from the SAPPHON-116 signed envelope contract.
- A crash injected BEFORE_TRANSACTION leaves neither inbox record nor synthetic effect. A crash injected AFTER_TRANSACTION leaves both and loses only the reply. Re-delivery returns the same receipt with `duplicate:true` and makes no additional synthetic effect.
- SAPPHON-117 receipts intentionally preserve the SAPPHON-116 format so the separate durable sender outbox can acknowledge the recorded result.
- `tools/test_sapphon_117_transaction.cjs` exercises 31 tests of atomic coupling, double-consumption rejection, crash windows, sender acknowledgement, persistence across module reload, duplicate payload and nonce conflicts, corruption, lock contention, missing destination and rollback.
- `docs/sapphon/phase-ix/117/index.html` retains three concentric neon R/G/B pumps, eight phase markers, central `{{i}}`, four logical registers and the original synthetic archival source.
- `.github/workflows/sapphon-117-transaction.yml` verifies SAPPHON-117, inherited SAPPHON-116/115 tests, neon viewer script and all 98 frozen source hashes.

## Evidence boundary
The test is **local and synthetic**. Its effect is an entry within the same JSON state object; this does not prove atomicity across a database and a remote physical actuator. Simulated failures occur before or after the final rename, not during all possible operating-system and power-loss conditions.

The negative rollback test copies an old empty receiver journal back over the committed file. Local validation accepts this internally consistent but stale snapshot, demonstrating that **external anti-rollback proof is missing**. Neither the receipt digest nor an additional local signature can prove independent custody. Actual network transport, physical clock qualification, globally linearizable replay authority and trusted UTC remain HOLD.

**Global effect authority: HOLD · Outside custody: HOLD · Physical clock and UTC: HOLD.**

## Next natural bound
**SAPPHON-118 — Independent State Anchors & Anti-Rollback Reconciliation.** Add an externally held monotonic checkpoint contract and test rejection of an old but internally consistent receiver snapshot. Do not mistake a synthetic external checkpoint fixture for real outside custody.

`.dlw`
