# SAPPHON-173 — Critical-Step Completeness & Exact-Run Evidence

**Phase XVI · bound 5/8 · 62.5% source-design progression · operational authority HOLD**

## Executive summary

SAPPHON-173 fixes an evidence-grading weakness: a GitHub Actions job with a green parent conclusion could be treated as a successful source-owned observation even when the required diagnostic step list was missing, a step was skipped, or the expected job appeared more than once.

The existing log collector now requires **one unique required job**, a **nonempty** step list, and no unresolved required steps before reporting a source-owned success. It preserves older behavior as a read-only diagnostic, and adds an exact source/workflow/job allowlist entry for the SAPPHON-172 predecessor: `496dec7bf5410baf031b0b7168ed2ac26311a181` / `sapphon-172-reconcile.yml` / `diagnostic-reconciliation`.

The new `tools/sapphon_173_critical_steps.py` requires three uniquely observed successful diagnostic steps from that exact SAPPHON-172 job: `Execute targeted Python regression suites`, `Run Rust all-target check and inherited test suites` and `Recheck all 188 protected historical file hashes`. A successful parent job cannot override missing, failed, skipped, cancelled, or duplicate critical steps. The gate always returns HOLD and never upgrades any independent custody or operational permissions.

## Committed changes

- `tools/sapphon_171_job_logs.py` and `tools/test_sapphon_171_job_logs.py`: require unique completed expected job with observed eligible steps; three new negative controls for skipped and empty steps and duplicate expected job.
- `tools/sapphon_173_critical_steps.py`: enforce exact predecessor SHA, run ID, attempt, expected job, completed status and three individually completed critical steps, with deterministic evidence digest.
- `tools/test_sapphon_173_critical_steps.py`: 12 synthetic negative-control tests for missing/duplicate/skipped/failed steps, wrong SHA/job, missing attempt, unsupported authority and stale success.
- `rust/sapphon-liveness/src/steps173.rs` and module declaration: seven authored Rust negative-control tests; write-new-only, fsynced HOLD evidence.
- `.github/workflows/sapphon-173-steps.yml`: independently runs Python, Rust and 188 historical file checks, attempts exact SAPPHON-172 predecessor readback, assesses critical-step evidence, inspects the provisional npm lockfile and compares four GitHub Pages assets to the workflow's exact source commit. Diagnostic pass is reported separately from full qualification.
- `docs/sapphon/phase-xvi/173/index.html`: synthetic neon 4D critical-step viewer.

## Qualification limitations

The connected GitHub status API returned no commit statuses for SAPPHON-172's final source commit, while the available commit-workflow wrapper returned no PR-triggered runs. Neither endpoint establishes whether push-triggered runs exist or have completed. **No completed SAPPHON-172 job log or actual Rust/Python test outcome was retrieved in this authoring session.**

The historical 188-file freezes were not intentionally changed. The existing npm lockfile still lacks independently verified registry SHA-512 integrity metadata and was not promoted. The GitHub Pages source URL exists as a repository path, but live deployment and browser execution remain unverified.

GitHub source, Actions and Pages are a **single source-controlled ancestry**, not independent physical witnesses. Global anti-rollback, external custody, authenticated UTC, key rotation, lock clearance and recovery remain HOLD.

## Next natural bound — SAPPHON-174

Observe actual SAPPHON-173 job outcomes. Distinguish source-execution pass, observed failed critical step, absent predecessor logs and known provisional-lock failure. Where a compiler or test fails, fix the specific demonstrated error and verify a subsequent run, rather than declaring another source-only qualification.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
