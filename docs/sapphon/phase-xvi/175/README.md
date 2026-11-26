# SAPPHON-175 — Bounded Workflow Readback & Verified Diagnostic Separation

**Phase XVI · bound 7/8 · 87.5% source-design progression · recovery HOLD**

## Executive summary

SAPPHON-175 repairs a concrete source-readback limitation: the job-log collector searched only the first 100 workflow runs. For a pinned older commit, a matching run can be located on later API pages. The previous result `NO_MATCHING_RUN_IN_FIRST_PAGE` could be misread as exhaustive absence. The collector now pages up to 10 × 100 run entries, selects a matching exact-source run when found, distinguishes `NO_MATCHING_RUN_IN_EXHAUSTED_PAGES` from `RUN_SEARCH_INCOMPLETE_PAGE_CAP`, and preserves `READBACK_UNAVAILABLE` when GitHub API access fails.

The allowlist now contains the exact SAPPHON-174 predecessor triple:
- Commit: `185802d4f10b496b899ab09551fe193b9ddd4a0d`
- Workflow: `sapphon-174-outcomes.yml`
- Required job: `source-outcomes`

No GitHub Actions status can certify independent physical custody, external monotonic authority, key rotation, or recovery.

## New and updated artifacts

- `tools/sapphon_171_job_logs.py`: bounded multi-page run discovery, precise query incompleteness and exact workflow/job/source allowlist.
- `tools/test_sapphon_171_job_logs.py`: three authored regression cases covering a match on page 2, exhausted search, and capped incomplete search.
- `tools/sapphon_175_observed.py`: exact SAPPHON-174 source-owned outcome review requiring an observed completed matching run/attempt, unique expected job, successful Python/Rust/188-file steps, and no unresolved child failures. Consistency is not full system qualification.
- `tools/test_sapphon_175_observed.py`: eleven authored Python negative controls for missing/ambiguous run evidence, skipped/failed/duplicate steps and forged external custody claims.
- `rust/sapphon-liveness/src/runner175.rs`: Rust source-evidence verifier with seven authored unit tests and create-only fsynced HOLD report.
- `rust/sapphon-liveness/src/lib.rs`: additive Rust module declaration.
- `.github/workflows/sapphon-175-readback.yml`: source-owned executable Python, Rust and 188-file hash checks independently of predecessor run readback, provisional npm lock review, and four HTML Pages parity checks. Upload diagnostic artifacts even when a stage fails; fail the job when source checks fail. The external recovery gate always remains HOLD.

## Actual readback limitations

The connected GitHub source tool returned repository source and commit status but no PR-associated workflow runs and no combined status entries for SAPPHON-174. These APIs do not prove push-triggered workflow execution did or did not occur. The public GitHub Actions runs endpoint was inaccessible to the current web reader. Thus **no actual SAPPHON-174 run ID, job logs, or successful test results have been independently recovered in this session**.

The 188 historical frozen files have not been intentionally modified. A runner's 188/188 pass remains unverified. The Playwright `package-lock.json` stays provisional and has not been promoted; independently retrieved npm SHA-512 metadata remains unavailable. GitHub Pages deployment and live Chromium acceptance also remain unverified.

## Phase XVI checkpoint

| Dimension | Evidence |
| --- | --- |
| Phase XVI source design | 7/8 = 87.5% source committed |
| Paginated exact-run lookup | Code corrected, tests authored |
| Current source diagnostics | CI configured, execution unverified |
| Historical frozen source checks | CI configured; 188 actual results unverified |
| Authenticated npm candidate | Not observed |
| Live Pages parity and Chromium | Not observed |
| Independent custody, monotonicity, authenticated UTC | HOLD |
| Key rotation, operational recovery, lock clearance | HOLD |

**Source owned GitHub + GitHub Actions + GitHub Pages = one ancestry, not independent witnesses.**

## Next natural bound — SAPPHON-176

Finalize the Phase XVI source-design freeze while retaining distinct evidence statuses. Inspect real SAPPHON-175 runner findings if available; repair only authenticated compiler or runtime errors, and report explicitly any missing readback. Never replace the npm lock without verified registry candidate bytes.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
