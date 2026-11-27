# SAPPHON-185 — Phase XVIII: Observed Runner Failure Isolation

**Phase XVIII · bound 1/8 · 12.5% source-design progress · operational authority HOLD**

## Executive summary

SAPPHON-185 begins Phase XVIII by correcting two concrete false-PASS risks in the inherited GitHub Actions collector and creating an exact SAPPHON-184 runner adjudicator.

The pinned predecessor is commit `edb582df9db3873d2fe308d219ed30b412d1b06d`, workflow `sapphon-184-freeze.yml`, job `final-freeze`. The connected commit-run and combined-status readbacks returned empty PR-associated runs and statuses. These readings do **not** establish whether push-triggered Actions executed, passed, or failed; no actual SAPPHON-184 runner logs were obtained in this authoring session.

## Demonstrated source defect repairs

1. `tools/sapphon_171_job_logs.py` previously reported `EXACT_RUN_OBSERVED` when a matching SHA was present even if every candidate had an invalid run ID or attempt. It now returns `MALFORMED_MATCHING_RUN`, excludes boolean IDs, and never promotes malformed identity to observed evidence.
2. The collector previously requested only the first 100 jobs of an attempt, allowing the required job or a failed child to escape classification. It now paginates through up to ten pages, requires evidence of exhaustion, returns `JOB_PAGE_CAP_REACHED` rather than a partial PASS and records exact job-search state. A source-owned PASS is forbidden unless job pages were exhausted.
3. The exact SAPPHON-184 source/workflow/job tuple was added to the collector's locked allowlist; prior pins were preserved.

## New implementation

- `tools/test_sapphon_185_pagination.py`: ten authored tests for malformed matching runs, page-two matching runs, missing/failed page-two jobs, boolean identities, page caps and incomplete jobs.
- `tools/sapphon_185_observed.py`: exact-run adjudication for the four critical SAPPHON-184 diagnostic steps (Python, Rust, 188 immutable frozen files, and final source inventory). Distinguishes recorded failures, malformed identity and unobserved evidence. Never executes arbitrary job-log commands or grants recovery authority.
- `tools/test_sapphon_185_observed.py`: twelve authored regressions covering missing reads, false PASS, failed Rust step, missing/duplicated critical step, incorrect source, incomplete job pagination and false external custody.
- `rust/sapphon-liveness/src/observed185.rs`: Rust exact source/attempt and four-step classifier, seven authored regression cases, and create-only fsynced HOLD evidence. Additively registered in `lib.rs`.
- `.github/workflows/sapphon-185-observed.yml`: runs current source Python/Rust tests and 188 historical hashes, reads exact SAPPHON-184 job pages when available, preserves error states and findings, uploads diagnostic evidence, and fails on current source or immutable-history execution failures.

## Qualification ledger

| Dimension | State |
| --- | --- |
| Phase XVIII source design | 1/8 = 12.5% committed |
| Python pagination and observed-run regressions | 22 authored, hosted execution unverified |
| Rust observed-run tests | 7 authored, hosted execution unverified |
| Two pre-existing collector false-PASS defects | Source fixes committed, successful CI execution unverified |
| Exact SAPPHON-184 run/attempt/job | Not retrieved in this authoring session |
| Historical 188 immutable records | Read-only verification retained; hosted result unverified |
| Original evidence bytes and artifact consistency | No authentic external readback established |
| npm Playwright SHA-512 registry integrity | Provisional, unchanged |
| GitHub Pages and Chromium | Source publication, live execution unverified |
| External custody, authenticated UTC, global anti-rollback | HOLD |
| Recovery, lock clearance and key rotation | HOLD |

GitHub source, Actions and Pages are one controlled ancestry. More GitHub records do not create independent physical witnesses.

## Next natural bound — SAPPHON-186

**Exhaustive Attempt and Artifact Evidence Coverage.** Validate pagination of runs, jobs and artifacts across all pages for an exact run and attempt, including workflow reruns, missing ZIPs, and required-step duplication. Never infer physical qualification from source-owned PASS.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
