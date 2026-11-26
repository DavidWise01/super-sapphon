# SAPPHON-177 — Phase XVII, Evidence-First CI Recovery

**Phase XVII · bound 1/8 · source design 12.5% · operational authority HOLD**

## Executive summary

SAPPHON-177 prioritizes recovering real runner evidence, rather than treating authored tests and GitHub commits as passing executions. The Phase XVI final commit is pinned to `f17b3d6c437da7f82240fffae703dfbde61a215b`, workflow `sapphon-176-freeze.yml`, required job `final-evidence`.

The available GitHub connector returned zero PR-linked workflow runs and zero combined commit-status entries for that commit. These specific readbacks **do not cover ordinary push-triggered Actions execution**, so no claim is made that a run passed, failed, or did not exist. A real run/job ID remains unavailable through that readback path.

## Concrete source repairs

**SAPPHON-176 Python freeze**: previously, `UNSUPPORTED_STATUS:RUST` could be listed in findings while `phase_design_complete` remained true, and the `source_tests_recorded_pass` calculation did not explicitly reject malformed statuses. The evaluator now refuses to mark design complete or a source-test pass when an outcome status is unsupported. The existing Python negative test asserts both fail-closed results.

**SAPPHON-176 Rust freeze**: previously, any plausible `rust/sapphon-liveness/src/*.rs` path could be assigned to one of the eight bounds. The verifier now requires each bound to use its exact canonical module path; a new Rust regression case rejects source-path substitution. The original eight-source freeze files were not rewritten beyond this specific correctness repair.

## New committed components

- `tools/sapphon_177_evidence.py`: exact-run readback adjudication. Requires correct source commit/workflow/job identity, one valid run and attempt, three explicitly successful required steps, no failed child step, and false external-authority fields. A source-owned pass is not external qualification.
- `tools/test_sapphon_177_evidence.py`: 11 authored Python negative-control tests for missing or wrong run/workflow/SHA, absent, skipped or duplicated critical steps, failed child steps, and false authority.
- `rust/sapphon-liveness/src/evidence177.rs` and its `lib.rs` registration: six authored Rust tests, strict source-run evidence, fail-closed create-only fsynced HOLD record.
- `.github/workflows/sapphon-177-evidence.yml`: executes inherited Rust/Python regression suites and exactly verifies the 188 historical immutable source entries; seeks the pinned SAPPHON-176 run and job outcomes; inspects the provisional lockfile, compares four Pages HTML assets, preserves failure diagnostics, and fails the source-execution gate when real tests or frozen hashes fail.
- `docs/sapphon/phase-xvii/177/index.html`: synthetic animated neon 4D provenance viewer; the UI does not claim live GitHub API readings.

## Source / execution / external qualification

| Dimension | Evidence state |
|---|---|
| Phase XVII source design | 1/8, 12.5%, code and workflow authored |
| Phase XVI source-design freeze | 8/8 committed, historical source unchanged except explicit repairs |
| Actual Python/Rust CI test execution | Not independently confirmed here |
| SAPPHON-176 completed Actions run / logs | No exact result retrieved through available connector |
| Historical 188 protected hashes | Runner check configured; passing execution not confirmed |
| Authentic Playwright package-lock integrity | Provisional, unqualified |
| GitHub Pages deployment / Chromium interaction | Source committed; live execution unverified |
| Independent custody / monotonic external anchor / UTC | HOLD |
| Recovery, lock clearance and key rotation | HOLD |

GitHub source, GitHub Actions and Pages are a shared owned ancestry, not three independent witnesses.

## Next natural bound — SAPPHON-178

Use actual SAPPHON-177 job logs and the evidence artifacts to isolate *demonstrated* Rust/Python or historical hash failures. Fix only reproducible faults, verify corrected test runs at a pinned commit, and maintain external authority HOLD until genuinely independent custody and immutable checkpoints can be authenticated.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
