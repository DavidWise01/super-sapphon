# SAPPHON-171 — Exact Job-Log Recovery and Workflow-Bound Adjudication

**Phase XVI · bound 3/8 · 37.5% source-design progression · operational recovery HOLD**

## Executive summary

SAPPHON-171 fixes a concrete predecessor source error: the workflow triage code used the job name `final-freeze` unconditionally, even when querying `sapphon-169-triage.yml` (whose job is `runtime-evidence`). `tools/sapphon_169_run_triage.py` now maps each allowed workflow to its actual required job name, including `sapphon-170-isolation.yml` → `deterministic-diagnostics`. Three new negative-control tests cover correct and wrong job binding.

The phase also adds an exact-SHA SAPPHON-170 job-log intake that selects the latest matching run and attempt, retains failed job/step conclusions, and attempts to retrieve bounded redacted log excerpts. It cannot substitute an unrelated green run. It reports unavailable evidence explicitly instead of claiming tests ran.

## New implementation

- `tools/sapphon_171_job_logs.py`: pins the SAPPHON-170 workflow to source commit `94188aa212cb2ae5d80ddc4c93ba0d71c6b81f2b`, retrieves run jobs from GitHub's Actions API by exact run/attempt, classifies source-owned success/failure and stores up to six failed-job log excerpts with a maximum 12,000-character redacted prefix each. Missing or inaccessible runs retain a distinct status.
- `tools/test_sapphon_171_job_logs.py`: twelve authored offline tests for exact-commit selection, newest attempt, missing or failed job, incomplete run, redaction, output bounds and no inferred success.
- `rust/sapphon-liveness/src/joblog171.rs`: Rust job-log adjudicator with eight authored regression tests and create-only, fsynced HOLD evidence. An observed source-owned pass never becomes authorization to recover or clear locks.
- `.github/workflows/sapphon-171-joblogs.yml`: runs inherited Rust suites and all previous Python controls, verifies the 188 historic frozen SHA-256/size records, independently attempts the SAPPHON-170 run/job log intake, checks the provisional npm lock, compares four GitHub Pages HTML assets to the exact source SHA and uploads diagnostic artifacts even on failures. Executable source checks are assessed independently of unavailable prior logs or known missing npm integrity.

## Verification limits

The connected GitHub workflow-run lookup for commit `94188aa212cb2ae5d80ddc4c93ba0d71c6b81f2b` returned no pull-request-triggered runs and its combined status endpoint returned no statuses. Neither endpoint establishes whether ordinary push-triggered Actions runs executed. No run ID and job logs were actually retrieved in this authoring session; the log collector is therefore committed but **not shown to have captured a real failure**.

No live GitHub Pages deployment/readback, Rust test execution or npm package SHA-512 registry validation has been independently established in this turn. The committed `package-lock.json` remains the provisional draft. The 188 historical entries are checked by CI and have not been modified here, but a successful runner outcome is not established.

Source, Pages and GitHub Actions are all one GitHub-owned ancestry, not three independent custody roots.

## Phase XVI checkpoint

| Criterion | State |
| --- | --- |
| Source design | 3/8 bounds; 37.5% |
| Workflow/job-name binding defect | Source fixed |
| Exact-run log intake, redacted excerpts | Code committed; real output unverified |
| 12 Python + 8 Rust log tests | Authored; runtime pass unverified |
| 188 historical frozen files | CI check configured; passing result unverified |
| Playwright integrity lock | Provisional, unqualified |
| Pages deployment and browser | Unverified |
| External custody, globally monotonic time, recovery and lock clearance | HOLD |

## Next bound — SAPPHON-172

Use the **actual SAPPHON-171 run results and failed-job excerpts** to patch demonstrated compilation, test or Pages failures. Authenticate genuine npm registry candidate bytes before replacing the lock. If the logs cannot be retrieved, preserve a precise `READBACK_UNAVAILABLE` outcome rather than inventing execution.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
