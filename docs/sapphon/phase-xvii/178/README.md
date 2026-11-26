# SAPPHON-178 — Verified Job Failure Isolation

**Phase XVII · bound 2/8 · 25% source design · operational authority HOLD**

## Executive summary

SAPPHON-178 adds a source-owned failure-isolation mechanism for the exact SAPPHON-177 workflow. Its pinned predecessor is commit `3053c21609333ea93d74ff2d38aeeed1c27d6084`, workflow `sapphon-177-evidence.yml`, job `executable-diagnostics`. Its three independent diagnostics are the Python regressions, Rust compilation/tests and the 188 immutable historical SHA-256 checks.

The GitHub connector's available PR-associated workflow lookup returned no run for the pinned final source commit and the legacy combined-status endpoint returned no checks. **Neither lookup can establish whether a normal push-triggered Actions run executed.** Consequently no actual failed compiler line, CI test failure, completed run ID or source-owned test pass is asserted here.

## Concrete defect correction

The existing `tools/sapphon_171_job_logs.py` collector classified only `None`, `skipped`, `cancelled`, `timed_out` and `failure` as unresolved required steps. An unexpected or in-progress conclusion could escape that rule. It now requires exactly `success` for every required step and rejects boolean/zero run-attempt identities. The exact SAPPHON-177 commit/workflow/job binding was added without loosening older pins. Three new Python cases cover unknown conclusion, in-progress conclusion and boolean attempt.

## New artifacts

- `tools/sapphon_178_isolate.py`: classifies actual predecessor run data into independent `PYTHON`, `RUST` and `FROZEN` outcomes with exact SHA, run/attempt, job uniqueness and failed-child-step checks. Missing or incomplete observations cannot become success.
- `tools/test_sapphon_178_isolate.py`: eleven authored synthetic/adversarial cases for isolated Rust failures, skipped Python, absent frozen checks, duplicate critical steps, incorrect source or job, missing run identity and unsupported recovery assertions.
- `rust/sapphon-liveness/src/isolation178.rs`: Rust equivalent with seven authored unit tests, create-only fsynced HOLD evidence and no operational actuation. Registered additively in `lib.rs`.
- `.github/workflows/sapphon-178-isolation.yml`: runs inherited Python/Rust tests, rechecks exactly 188 historical frozen files, attempts exact SAPPHON-177 job-log collection, isolates failure conclusions, inspects the provisional npm lock, compares Pages parity and saves all available outcomes. Source-execution failures block the diagnostic job; unavailable predecessor evidence remains explicitly unavailable.
- `docs/sapphon/phase-xvii/178/index.html`: interactive synthetic neon 4D tesseract illustration; not a live GitHub run display.

## Qualification status

| Criterion | Status |
| --- | --- |
| Phase XVII source design | 2/8 = 25% |
| Unknown/in-progress CI step conclusion | Source corrected |
| Exact source/job pin | Committed |
| New Python and Rust tests | Authored, execution not yet established |
| Historical 188 immutable records | CI check retained; passing execution unverified |
| Actual SAPPHON-177 Actions job logs | Not retrieved in this session |
| npm lockfile SHA-512 integrity | Provisional, unchanged |
| Live Pages / Chromium | Unverified |
| Independent external custody, monotonic time, anti-rollback | HOLD |
| Physical recovery, key rotation, lock clearance | HOLD |

The GitHub source repository, Actions runs and Pages publication are all one owned ancestry. Their internal agreement cannot substitute for independent physical witnesses.

## Next bound — SAPPHON-179

**Provenance-Bound Failure Replay:** acquire a completed SAPPHON-178 runner artifact or job log, replay only its demonstrable Python/Rust failures, verify canonical corrections under the same exact test set, and retain precise `READBACK_UNAVAILABLE` when the evidence cannot be obtained.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
