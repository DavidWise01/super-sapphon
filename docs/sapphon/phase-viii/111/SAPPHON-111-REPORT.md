# SAPPHON-111 — Durable Capture Replay and Signed Retention

**Phase VIII:** 7/8 · 87.5%  
**Verified GitHub Actions:** 23/23 durable capture and retention tests; 25/25 SAPPHON-110 capture-agent tests; 26/26 SAPPHON-109 transport-transcript tests; 11/11 Phase VI and 45/45 Phase VII frozen hashes.

## Delivered
- `tools/sapphon_111_durable_capture.cjs` stores issued capture-session challenges and consumed nonces in a dedicated JSON disk journal. Mutations are serialized under an exclusive lock, with `fsync`, atomic rename and directory sync. Missing journal, corrupt state, unavailable lock and unsigned or unissued challenges fail closed.
- Nonces bind a 256-bit challenge to the exact capture-agent identity, acquisition, session and signed transport transcript, and are consumed only after all inherited SAPPHON-110 signature checks and the signed retention acknowledgement pass.
- Bounded local expiry, persisted high-water local time, one-time initialization and an append-preserving bounded record set prevent simple restart replay or silent local reinitialization. The registry refuses rollover after 1,024 records pending an operator-reviewed external archive.
- Synthetic retention acknowledgements bind the exact signed capture payload, challenge digest, custody root and identified custodian signing key. Revoked or unknown custodians, forgeries, cross-root substitutions and conflicting retention claims are rejected.
- `tools/test_sapphon_111_durable_capture.cjs`: 23 synthetic acceptance and negative tests, including forged retention, expiry, replay, lock contention, local clock rollback and corruption.
- `docs/sapphon/phase-viii/111/index.html`: neon read-only viewer retaining three R/G/B pump rings, eight phases, nested `{{i}}`, four frozen clock registers and explicit operational HOLD.
- `.github/workflows/sapphon-111-durable.yml`: continuous acceptance gating across the new and inherited transport and capture suites plus both immutable prior freeze manifests.

## Qualification boundary
The journal is durable in the tested local filesystem sense, but it is not tamper-proof, a distributed consensus ledger or cross-host external retention. Actual cross-host replay protection requires all participating hosts to use the **same authoritative persistent journal**, or independently authenticated, consistent cross-host synchronization. Two independent local journal copies can each accept the same challenge.

Synthetic retention acknowledgements establish signature verification only. They do not demonstrate physical offsite storage, independent ownership or a real network capture. The source transport and capture signatures still originate from synthetic fixture keys.

**Independent capture-agent qualification, external custody, calibrated physical clock and actual UTC: HOLD.**

## Next natural bound
**SAPPHON-112 — Phase VIII Final Qualification, Cross-Host Replay Counterexamples & Immutable Software Freeze.** Verify split-brain journal and hostile storage cases; preserve a reproducible Phase VIII source manifest; execute real Chromium acceptance tests; carry external qualification HOLD to the next phase until authentic third-party evidence is obtained.

`.dlw`
