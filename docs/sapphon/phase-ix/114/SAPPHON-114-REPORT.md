# SAPPHON-114 — Downstream Fencing-Token Enforcement & Local Side-Effect Gate

**Phase IX:** 2/8 · 25%  
**Verified CI:** 23/23 new destination enforcement tests; 28/28 SAPPHON-113 epoch fencing tests; 20/20 SAPPHON-112 split-brain counterexample tests. Phase VI: 11 frozen hashes; Phase VII: 45; Phase VIII: 42; all unchanged.

## Delivered

- `tools/sapphon_114_effect.cjs`: a synthetic local side-effect journal that acquires the **same canonical directory lock** as the SAPPHON-113 writer/lease registry, then verifies current epoch, writer ID, lease expiry and an actually issued nonce before committing an effect.
- Destination-side idempotency prevents a committed effect ID or nonce from being used twice. A stale token can no longer perform this local synthetic side effect after epoch rotation, even if it was valid when issued.
- Rejected downstream requests are persisted with a reason code; the effect journal writes using a temporary file, file sync, atomic rename and directory sync.
- Fail-closed tests cover expired leases, changed writers, stale epochs, unissued or duplicate nonces, malformed authorizations, corrupted store data, exclusive lock contention and missing canonical stores.
- `tools/test_sapphon_114_effect.cjs`: 23 acceptance and negative checks.
- `docs/sapphon/phase-ix/114/index.html`: neon viewer retaining the original three R/G/B pump rings, eight sectors, nested `{{i}}`, four clock registers, and synthetic archived observations.
- `.github/workflows/sapphon-114-effect.yml`: blocking acceptance and regression check of the 98 frozen files from previous phases.

## Limits and HOLD

The effect is an **entry in a local synthetic journal**, not an externally performed real-world action. The canonical writer and side-effect destination coordinate through one directory lock on a shared local filesystem; no remote fencing enforcement, distributed lease service or globally consistent consensus has been verified. Local time is caller-provided, not an independently authenticated time source. A malicious client or compromised filesystem authority remains outside the proven boundary. Rejected requests invalid before acquiring the lock are not durably logged; the destination's rejection ledger is a local record, not independent notarization.

**Global single-writer authority: HOLD. Independent external custody: HOLD. Physical-clock calibration and real UTC: HOLD.**

## Next natural bound

**SAPPHON-115 — Commit-Result Reconciliation & Crash-Window Recovery.** Model interrupted writes and ambiguous client acknowledgement, recover journal intent before resubmission, and prove that retry/restart cannot duplicate synthetic downstream effects. Preserve the observer-only, append-preserving principles and all prior frozen phases.

`.dlw`
