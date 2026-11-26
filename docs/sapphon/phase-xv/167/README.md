# SAPPHON-167 — Controlled Lockfile Promotion Review

**Phase XV · bound 7/8 · 87.5% source-design progression · operational authority HOLD**

## Executive summary

SAPPHON-167 introduces a **review-only lock promotion boundary**. It will not edit or replace `package-lock.json` automatically. The committed dependency lock remains the inherited provisional draft because the exact npm registry integrity metadata and SAPPHON-165/166 artifact evidence have not been authenticated in this authoring session.

The new `tools/sapphon_167_promotion_review.py` checks an actual candidate lock against `165-run-summary.json`, `165-registry-candidate-inspection.json`, `166-artifact-intake.json` and `166-candidate-review.json`. It requires exact historical source SHA, run ID, attempt, checksum continuity, clean predecessor review, explicit registry-step success, precise Playwright/Playwright Core 1.65.1 package identity and SHA-512 integrity field shape, a closed dependency set, and persistent HOLD flags. If any input is missing or inconsistent, the review **fails**, generates findings and does not silently promote a candidate.

**Important:** Even a consistent review is only `candidate_review_eligible`. That is not proof that registry archive bytes are independently retained, nor an authorization to mutate a protected source or clear a lock. No source-owned output qualifies as an independent external custodian.

## Committed artifacts

- `tools/sapphon_167_promotion_review.py`: exact-run integrity reconciliation and deterministic HOLD-only output, no source writes.
- `tools/test_sapphon_167_promotion.py`: 13 synthetic Python adversarial cases covering altered SHA/run/attempt, absent artifact, checksum conflict, false authority claims, registry failure, bad predecessor review, unexpected package, missing integrity, and malformed current source SHA.
- `rust/sapphon-liveness/src/promotion167.rs`: Rust source-owned candidate gate and create-only fsynced evidence output. Nine Rust regression tests are authored.
- `rust/sapphon-liveness/src/lib.rs`: append-only module declaration.
- `.github/workflows/sapphon-167-promotion.yml`: attempts exact SAPPHON-165 artifact intake using predecessor tools, executes the 166 candidate review, runs the 167 review, full Rust regression suites, protected 188-file SHA/length checks and four-page GitHub Pages byte parity. Per-step results and evidence are retained on failures, and the final gate is blocking. It explicitly verifies that `package-lock.json` was not changed by the review.
- `docs/sapphon/phase-xv/167/index.html`: standalone neon 4D hypercube visualization of lock-promotion decision states.

## Observations and limitations

The local Node/npm registry lookup failed with `EAI_AGAIN`. The external public metadata URLs were inaccessible, and the GitHub connector could read repository source and combined commit statuses but did not expose a completed push-triggered SAPPHON-166 artifact/run for examination. Therefore a real verified lock candidate could **not** be reviewed or committed in this turn.

Source commits are verified separately after creation. Rust/Python suites and Chromium/Pages parity remain **configured or authored**, not independently verified passing. A missing reported combined status is not evidence of a passing or failing GitHub Actions workflow.

Historical files in the 188 frozen manifest set were not intentionally edited. The workflow retains exact checks of their content lengths and SHA-256 digests, which have not been observed passing from a completed run.

## Phase XV checkpoint

- Source design: **87.5% · 7/8 bounds**.
- Controlled promotion gate: committed to GitHub.
- Verified npm lock candidate: **missing external readback**.
- Committed lockfile: **provisional, unchanged**.
- Actual CI/Chromium/Pages success: **unverified**.
- Key rotation, authenticated UTC, external monotonic floor, global anti-rollback, external physical custody, lock clearance and operational recovery: **HOLD**.

## Next bound — SAPPHON-168

Final Phase XV qualification freeze: inspect actual completed run/attempt and candidate artifact if available, and separate source-design completion from CI, browser, Pages and external-custody qualification. Freeze only the evidence that is actually supported. Keep the dependency lock unqualified until its authentic candidate has been committed and reverified.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
