# SAPPHON-119 — Cross-Store Checkpoint Handshake & Unacknowledged Commit Resolution

**Phase IX:** 7/8 · 87.5%.  
**Verified GitHub Actions:** 28/28 new handshake tests; 28/28 SAPPHON-118 checkpoint checks; 31/31 SAPPHON-117 transactional receiver checks. Three prior immutable manifests preserved: Phase VI (11), Phase VII (45), Phase VIII (42) = 98/98.

## Delivered

- `tools/sapphon_119_handshake.cjs` wraps actual SAPPHON-117 receiver commit and SAPPHON-118 checkpoint verification with an explicit local third journal. Every receiver revision is tracked as `PENDING_ANCHOR` until a matching signed local checkpoint is confirmed.
- A crash *after receiver commit and before recording the handshake* leaves a visible gap. `status` reports `UNRECORDED_RECEIVER_COMMIT` and does not promote the receiver action; `reconcile` reconstructs a pending record.
- A crash after writing the pending journal but before checkpoint publication remains `PENDING_ANCHOR`.
- A crash after signed checkpoint publication but before acknowledgement is recoverable: `reconcile` compares receiver digest and revision with the checkpoint chain, updates the local handshake state, and does not publish another checkpoint.
- `LOCAL_ANCHOR_CONFIRMED` is an observation of two consistent *synthetic local* stores, NOT external finality. Every status and reconciliation result retains `external_finalized:false` and `decision:"HOLD"`.
- The SAPPHON-117 receiver handles duplicate signed messages without reexecuting effects; the SAPPHON-118 checkpoint anchors use monotonic revisions and linked signatures.
- `tools/test_sapphon_119_handshake.cjs` contains 28 real-file fixture tests, including all three interruption windows, old receiver rollback, forged checkpoint signatures, local lock contention, malformed handshake, and a deliberate joint rollback counterexample.
- `docs/sapphon/phase-ix/119/index.html` retains the neon three-pump R/G/B clock, eight sectors, central `{{i}}`, four frozen clock registers and observation-only diagnostic controls.
- `.github/workflows/sapphon-119-handshake.yml` verifies all new and inherited checks, viewer syntax, and all earlier immutable SHA-256/byte-size baselines.

## Critical qualification boundary

The receiver, handshake journal and checkpoint journal exist in separate **local** directories. Their changes are not one distributed atomic transaction. The receiver may commit while no handshake record exists; the recovery logic deliberately exposes that gap rather than treating it as final. The checkpoint signer and owner root are synthetic fixtures. Joint rollback of receiver and checkpoint state remains undetectable without outside high-water evidence; an attacker who can also rewrite the local handshake journal can further conceal it.

The API signs checkpoints using a fixture private key supplied by the local test harness. No real remote custodian, trust-authorized service, authenticated external acquisition, calibrated clock or UTC has been connected.

**External finalization: HOLD · Independent custody: HOLD · Global exactly-once effects: HOLD · Physical time and UTC: HOLD.**

## Next natural bound

**SAPPHON-120 — Phase IX Final Adversarial Recovery, Chromium Acceptance & Immutable Software Freeze.** Close Phase IX at 8/8. Retest network-like partitions, joint local rollback, skipped unanchored revisions, acknowledgement replay, receiver side-effect count, and stale fencing. Run Chromium against the live neon page and freeze the complete Phase IX software baseline without altering Phases VI–VIII.

`.dlw`
