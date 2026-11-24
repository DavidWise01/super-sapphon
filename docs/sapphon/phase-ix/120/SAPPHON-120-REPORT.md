# SAPPHON-120 — Phase IX Adversarial Recovery, Chromium Acceptance & Software Freeze

**Phase IX:** 8/8 · 100% software milestone.  
**Operational external authority:** HOLD.

## Final scope
- `tools/sapphon_120_audit.cjs` provides an observation-only consistency audit across the receiver transaction journal, pending/confirmed handshake records and signed synthetic checkpoint store.
- It reports `UNTRACKED_RECEIVER_REVISION`, `PENDING_ANCHOR`, `UNANCHORED_ADVANCE`, `RECEIVER_ROLLBACK`, `RECEIVER_DIGEST_CONFLICT` and `ACK_LINK_MISMATCH` without authorizing external effects.
- `tools/test_sapphon_120_audit.cjs` replays crash windows, lost checkpoint acknowledgement, duplicate sender delivery, receiver rollback, changed digest, missing authority store and joint-local-rollback counterexample.
- Real Chromium acceptance tests exercise the three neon R/G/B pumps, eight sectors, center `{{i}}`, four frozen registers, synthetic archive, state explanation controls, and absence of browser JS errors.
- `tools/sapphon_120_freeze.py` inventories SAPPHON-113–120 tools, tests, neon viewer, workflows and phase reports in `docs/sapphon/phase-ix/SAPPHON-120-FREEZE.json`, with SHA-256 and byte lengths.
- Freeze generation verifies all three prior manifests and runs only after the acceptance job succeeds. The new manifest is self-excluding to avoid circular hashing.

## Trust boundaries
All receiver, handshake and checkpoint stores are **local synthetic test files**. Local consistency, signed checkpoints and three copies do not prove independent organizational ancestry, physical custody, network partition tolerance or anti-rollback against a joint snapshot substitution. The latest checkpoint may be rolled back together with the receiver and handshake files; without an externally held monotonic high-water mark, that rollback remains undetectable.

No real network acquisition, outside custodian, third-party verified clock, global consensus, remote side effect, or authenticated UTC was established. Synthetic checkpoints and test fixture credentials must not be upgraded into real witnesses.

**Global effect finality: HOLD · Independent custody: HOLD · Cross-host anti-rollback: HOLD · Physical clock and UTC: HOLD.**

## Next natural bound
**SAPPHON-121 — Phase X, 1/8 · Trusted Monotonic Anchor Interface & External Custodian Qualification Contract.** Specify signed external state evidence, immutable high-water checks and source ancestry enrollment. Keep all claims in HOLD until genuine independent evidence exists.

`.dlw`
