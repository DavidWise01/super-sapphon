# SAPPHON-193 — Phase XIX Observed Runner Failure Qualification & Repair

**Phase XIX · Bound 1/8 · 12.5% source-design progress · operational HOLD**

## Executive summary

SAPPHON-193 begins Phase XIX by demanding real evidence for the frozen SAPPHON-192 runner rather than assuming the suite passed. The exact predecessor is commit `9c3734c78bab40690ca1f5f9b65e29362193a1bf`, workflow `sapphon-192-freeze.yml`, required job `final-source-freeze`.

Connected GitHub commit-level workflow and status lookups returned empty lists for that commit. These observations cover PR-linked runs and commit statuses, not an exhaustive proof that no push-triggered run exists. **There is no verified successful SAPPHON-192 hosted test execution or actual runner log at authoring time.**

## Demonstrable source-level defect repaired

The existing `tools/sapphon_171_job_logs.py` had no allowlist tuple for the SAPPHON-192 predecessor. Its exit-condition check also failed to reject some exact-run observations where the required job or child steps had failed: a structured diagnostic could record failure but return exit code zero. Both conditions are now corrected without modifying Phase XVIII's eight frozen Rust sources.

The collector now pins exactly the SAPPHON-192 commit, workflow and job; success exit requires `status == EXACT_RUN_OBSERVED` and the observed job's `source_owned_success_observed == true`. Missing, incomplete or failed source execution remains a nonzero result.

## New bound

- `tools/sapphon_193_triage.py`: fail-closed exact-run triage, four named critical steps (Python, Rust, historical 188-file verification, source inventory), run/attempt identity, bounded pagination completion, failure and missing-evidence distinctions, source-owned success only.
- `tools/test_sapphon_193_triage.py`: 14 authored adversarial tests for absent execution, wrong ancestry, page-cap incompleteness, failed Rust/Python, missing or duplicated required steps, false green parents, malformed attempts and forged custody.
- `rust/sapphon-liveness/src/triage193.rs`: strict Rust four-step state fence with eight authored negative-control tests and create-only fsynced HOLD output. Registered in `lib.rs`.
- `.github/workflows/sapphon-193-triage.yml`: Python/Rust tests, inherited 188 protected-file verification, pinned exact SAPPHON-192 readback with failed job excerpts, fail-closed triage and sanitized diagnosis artifact.
- `docs/sapphon/phase-xix/193/index.html`: animated neon 4D source-execution failure lab. Scenarios are synthetic, not live CI status.

## Final status

| Criterion | Evidence |
| --- | --- |
| Phase XIX source-design progress | **1/8 = 12.5% committed** |
| Collector pinned exact SAPPHON-192 target | Committed |
| False-green exit handling | Source repaired |
| New Python triage regressions | 14 authored; actual hosted execution unverified |
| New Rust triage regressions | 8 authored; actual hosted execution unverified |
| Real SAPPHON-192 run and failure logs | Not retrieved during authoring |
| Historic 188 frozen source paths | Read-only verification retained |
| Phase XVIII frozen Rust modules | No historical module edits |
| Independent custody / authenticated UTC / anti-rollback | HOLD |
| Key rotation, physical recovery, lock clearance | HOLD |

GitHub source, Actions and Pages are one owned ancestry. Source ownership and a successful source runner do not constitute independent witnesses.

## Next natural bound — SAPPHON-194

**Hosted Diagnostic Evidence Acquisition & Actual Failure Replay.** Obtain original SAPPHON-193 run/job/artifact bytes, classify actual failing command output and reproduce only demonstrated faults. If no run is found within the bounded search, retain `NOT_OBSERVED` rather than constructing PASS evidence.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
