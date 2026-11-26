# SAPPHON-172 — Failure-Specific Runner Evidence Reconciliation

**Phase XVI · bound 4/8 · 50% source-design progression · operational authority HOLD**

## Executive summary

SAPPHON-172 fixes two code-level observations from SAPPHON-171: its Python log classifier could report source-owned success when a job had `conclusion=success` but a nested step had failed/cancelled, and its log-excerpt redaction bounded the text **before** masking secret-like fields. The classifier now preserves failed child steps even under nominally green parent jobs. The redactor masks the input before limiting output length to 12,000 characters.

A third integration fault was visible: the SAPPHON-171 job collector had a hard-coded SAPPHON-170 commit and workflow, preventing it from querying the intended predecessor SAPPHON-171 run. It now accepts only an explicit allowlist of exact commit/workflow/job combinations, preserving the old default. The SAPPHON-172 workflow uses `sapphon-171-joblogs.yml`, commit `9e7fc8ad8c3b05a3e12f1c3aa0c15b4c99c2e18e` and required job `diagnostics`.

## Changes

- `tools/sapphon_171_job_logs.py`: rejects failed child steps inside a green parent, redacts before bounding, and requires exact allowed GitHub Actions run target ancestry.
- `tools/test_sapphon_171_job_logs.py`: adds five regression cases covering failed/cancelled child steps, redaction near the excerpt boundary, and correct/wrong SAPPHON-171 job binding.
- `tools/sapphon_172_reconcile.py`: deterministic SHA-256 reconciliation of the exact SAPPHON-171 predecessor log finding; checks source SHA, workflow, required job, run ID, attempt, completed status, failed-step evidence, source-owned pass claim and false custody/recovery claims. Always returns operational HOLD.
- `tools/test_sapphon_172_reconcile.py`: ten authored negative-control tests.
- `rust/sapphon-liveness/src/reconcile172.rs` and `lib.rs`: seven authored Rust regression cases plus fail-closed create-only persistent observations; never grant external recovery.
- `.github/workflows/sapphon-172-reconcile.yml`: runs inherited Rust and Python diagnostics and 188 historic frozen-file SHA/length checks, obtains exact SAPPHON-171 job/readback evidence when accessible, checks the known provisional npm lock and four GitHub Pages HTML assets, and uploads all diagnostic outcomes whether successful or failed. Source diagnostic pass is reported separately from full qualification.

## Evidence limits

The GitHub connector lookup for the SAPPHON-171 source commit returned no PR-triggered runs and the combined commit-status endpoint returned an empty status list. This does not tell us whether push-triggered Actions ran. Direct public GitHub Actions and npm registry endpoints were inaccessible in this authoring session. No actual SAPPHON-171 run logs, published npm integrity metadata, Rust compiler outcomes, browser results or Pages parity observations were retrieved as passing.

The code-level defects above were found by source inspection, not from an authenticated failing GitHub runner log. All newly added tests are authored, not independently confirmed executed. The historical 188 files were not altered by this bound.

## Phase XVI ledger

| Criterion | State |
| --- | --- |
| Source design | 4/8 (50%) committed |
| Python green-parent/failed-child status | Source repaired |
| Redaction-before-bounding | Source repaired |
| Predecessor source/workflow/job binding | Source repaired |
| Rust and Python regressions | Authored, not verified passing |
| Historical 188 frozen-file checks | Retained in CI |
| Genuine npm lockfile integrity | Still unqualified |
| Browser / Pages deployment parity | Unverified |
| Authenticated UTC, independent custody, global anti-rollback | HOLD |
| Key rotation, recovery, lock clearance | HOLD |

## Next natural bound — SAPPHON-173

Review the actual SAPPHON-172 run results. If source-owned diagnostics report compiler, Python or historical-file failures, repair the specific observed error; if completed job evidence remains inaccessible, preserve that absence. The provisional lockfile must not be replaced without authentic npm registry metadata.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
