# SAPPHON-174 — Observed Runner Outcomes & Source Qualification Separation

**Phase XVI · bound 6/8 · 75% source design · operational recovery HOLD**

## Evidence statement

The GitHub connector returned no PR-associated workflow runs for SAPPHON-173 commit `7e1be863797ddad3043e03074fc2375b9f760c74` and no legacy combined-status entries. These readbacks **cannot rule out push-triggered Actions runs** and cannot certify actual Python or Rust test execution. No precise completed run ID, attempt or job logs were available through this connector.

SAPPHON-174 therefore advances the diagnostics and source qualification machinery without claiming a completed or successful GitHub Actions run. The known provisional Playwright lockfile remains unchanged and unqualified.

## Changes

- `tools/sapphon_171_job_logs.py` now accepts the exact SAPPHON-173 run triple `7e1be863797ddad3043e03074fc2375b9f760c74` / `sapphon-173-steps.yml` / `critical-step-diagnostics`, rejecting other combinations.
- `tools/sapphon_174_outcomes.py` distinguishes a completed, exact-run and exact-job source observation from **full qualification**. It requires unique passing records for Python, Rust and 188 historical-file checks and rejects missing/duplicate/skipped, failed or unknown required steps.
- `tools/test_sapphon_174_outcomes.py`: 10 authored synthetic negative controls for missing/incorrect runs, false custody, wrong job, absent/skipped/duplicate steps and failed child evidence.
- `rust/sapphon-liveness/src/outcomes174.rs`: Rust source-outcome separation with six authored tests; returns `SOURCE_OUTCOMES_HOLD`, locks all operational flags false and records create-only fsynced evidence.
- `.github/workflows/sapphon-174-outcomes.yml`: executes the inherited Python and Rust regressions and 188 historical hash checks, attempts pinned SAPPHON-173 readback, records npm lock inspection and Pages byte parity as *separate outcomes*, uploads artifacts regardless of partial failures, and blocks executable-source failures without upgrading recovery authority.
- `docs/sapphon/phase-xvi/174/index.html`: neon 4D rotating-tesseract interactive status model. Scenarios are illustrative, not actual runner data.

## Qualification checkpoint

| Dimension | State |
| --- | --- |
| Phase XVI source design | Bound 6/8 · 75% |
| Source commits | Confirm via subsequent GitHub readback |
| Python and Rust tests | Authored; actual execution result not confirmed |
| 188 historical frozen files | Protected by existing check, passing run not witnessed |
| SAPPHON-173 run and job logs | Not observed through current accessible tool |
| Playwright lockfile SHA-512 integrity | Unqualified provisional draft |
| GitHub Pages deployment and browser acceptance | Unverified |
| External independent custody, global anti-rollback and authenticated UTC | HOLD |
| Key rotation, recovery and lock clearance | HOLD |

GitHub source, GitHub Actions and GitHub Pages share one owned-source ancestry and do not establish independent physical custody.

## Next natural bound — SAPPHON-175

Obtain actual completed SAPPHON-174 runner logs and compare Python/Rust and historical hash findings independently of npm and Pages. Repair any specific observed failure, retain precise missing-evidence reports if execution remains inaccessible, and do not promote the provisional lockfile without genuine registry-origin integrity values.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
