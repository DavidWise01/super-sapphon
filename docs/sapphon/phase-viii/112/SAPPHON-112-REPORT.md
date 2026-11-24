# SAPPHON-112 — Phase VIII Cross-Host Counterexample & Software Freeze

**Phase VIII:** 8/8 · 100% (software milestone).  
**Evidence authority:** HOLD.

## Final-phase objectives
1. Preserve the immutable Phase VI (11 files) and Phase VII (45 files) baselines exactly.
2. Expose the distributed-system limit of the SAPPHON-111 local durable nonce journal.
3. Exercise the original neon clock in real Chromium with three pump rings, eight phase markers, center `{{i}}`, four clock registers and observation-only controls.
4. Inventory the SAPPHON-105–112 code, tests, workflows, report texts and viewer sources in an SHA-256 freeze manifest.

## Cross-host counterexample
SAPPHON-112's test creates *two independent local journals*, copies the same previously issued challenge into both, and calls the real SAPPHON-111 `consume` against both journals while they are isolated. **Both accept the same challenge.** The subsequent SAPPHON-112 comparison detects `DUAL_CONSUMPTION_SAME_CAPTURE`. If their signed retention digests differ, it detects `DUAL_CONSUMPTION_DIFFERENT_RETENTION`.

A local replay gate remains effective on each host, but that does **not** make independent stores globally linearizable. The counterexample is deliberately preserved instead of claiming two copies constitute a quorum. No aggregate verdict, vote, replicated signature count, or matched-byte hash can substitute for single-writer authority or genuine independently authenticated custody.

Further negative tests cover conflicting issuance hashes, missing and malformed journals, fabricated consumption, duplicate nonces, duplicate snapshot IDs, false UTC claims and source-root double counting. The source auditor does not mutate the compared journals.

## Source freeze
`tools/sapphon_112_freeze.py` creates `docs/sapphon/phase-viii/SAPPHON-112-FREEZE.json` only after the acceptance suite passes in GitHub Actions. Its manifest contains SHA-256 and byte sizes for the Phase VIII code, documentation, tests and workflow; it verifies all Phase VI and Phase VII hashes before emission. The manifest excludes itself to avoid a self-referential digest. It is an inventory/integrity record, not externally signed notarization.

## Unqualified
- The archive has only eight unsigned **synthetic** phase samples.
- The split-brain test runs local files and test keys. It does not establish a multi-host synchronized service or real independent witnesses.
- No independently authenticated physical clock, true UTC, actual TLS packet capture or outside custody receipt has been established.
- A copied or forged filesystem journal may pass ordinary file-hash checks until checked against independent immutable external state. No external notarization was connected.

**Physical clock authority: HOLD. External custody: HOLD. Global cross-host replay protection: HOLD.**

## Next phase
**Phase IX, turn 1/8 — SAPPHON-113: Global Single-Writer Acquisition Authority & Partition Fail-Closed Contract.** Design and test a single-writer lease/epoch gate that refuses to promote disconnected replicas, including stale epoch fencing, with no false independent authority claims. Operational qualification remains HOLD until actual outside evidence and real physical calibration are available.

`.dlw`
