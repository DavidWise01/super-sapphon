# SAPPHON-194 — Hosted Original Diagnostic Evidence Acquisition

**Phase XIX · Bound 2/8 · 25% source-design progress · operational authority HOLD**

## Executive summary

SAPPHON-194 targets the original GitHub Actions bytes for the completed source-design SAPPHON-193 commit `517959b0c98b65bafefaba5ae5e18065b2e27212`, workflow `sapphon-193-triage.yml`, required job `runner-failure-triage`, named artifact `sapphon-193-exact-run-failure-triage`. It uses bounded, exhaustive discovery of workflow runs, attempt-scoped job listings and run-scoped artifact listings. It hashes original job logs **before** excerpt redaction and hashes original ZIP bytes **before** inspecting their members in memory. No ZIP files are extracted or executed.

Connected GitHub's available commit-run wrapper is PR-scoped, so an empty result cannot rule out a push-triggered workflow run. No actual SAPPHON-193 job, log, or original artifact ZIP was obtained through that wrapper in this authoring session. Therefore no hosted pass or reproduced CI failure is claimed.

## Committed source

- `tools/sapphon_194_acquire.py`: pinned SHA/workflow/job/artifact; up to ten pages × 100 for runs, jobs, and artifacts; strict positive IDs and duplicate rejection; latest matching run and exact attempt; required-job and artifact uniqueness; original log SHA-256, byte length, and bounded redacted excerpt; original ZIP SHA-256, safe member checks and exact embedded source/run/attempt; structured failed child steps; explicit missing evidence.
- `tools/test_sapphon_194_acquire.py`: **14 authored synthetic tests** for exact matching, wrong ZIP attempt, missing log, expired/wrong-ancestry artifact, failed Rust step, duplicate artifact IDs, page cap, duplicate page IDs, wrong commit, raw-log hash vs redacted excerpt, malformed ZIP, duplicate ZIP member, and Boolean attempts.
- `rust/sapphon-liveness/src/acquire194.rs`: Rust source-owned SHA-256 and attempt consistency fence with **8 authored tests**, create-only fsynced HOLD finding, zero external witnesses; additively registered in `lib.rs`.
- `.github/workflows/sapphon-194-acquire.yml`: runs current Python/Rust tests and the inherited 188-file protected history check; uses `GH_TOKEN` to call the original run/job/artifact API; emits source-owned metadata separately from current test results; uploads redacted diagnostic artifact and fails on actual current execution failures.
- `docs/sapphon/phase-xix/194/index.html`: interactive neon 4D diagnostic display, illustrative scenarios only.

## Source and execution evidence boundary

The prior SAPPHON-193 workflow may have failed to produce an artifact even if its job logs exist. A missing artifact is an incomplete-evidence finding, not proof of an absent workflow run; a failed step visible in an original job record is an observed failure, not automatically a reproduced source defect. The probe never executes the remote job's commands and does not rewrite the frozen Phase XVIII source files.

Only one GitHub-owned provenance ancestry is available. Original bytes plus matching SHA-256 establish internal source evidence, not independent custody, authenticated UTC, global anti-rollback, key rotation or physical recovery authority.

## Qualification

| Criterion | State |
| --- | --- |
| Phase XIX source design | **2/8 · 25% committed** |
| New Python acquisition cases | 14 authored, hosted execution unverified |
| New Rust acquisition cases | 8 authored, hosted execution unverified |
| Exact original log/ZIP SHA-256 collection | Source committed, real bytes not obtained during authoring |
| SAPPHON-193 original run/attempt | Not retrieved in authoring |
| Demonstrated hosted failure replay | Not performed without observed log |
| Historical 188 frozen source paths | Read-only check retained |
| Phase XVIII completed Rust modules | Unmodified |
| GitHub Pages/Chromium | Source publication, live execution unverified |
| External custody, authenticated UTC, global anti-rollback | HOLD |
| Recovery and lock clearance | HOLD |

## Next natural bound — SAPPHON-195

**Original Log–Artifact Cross-Verification & Failure Replay Allowlist.** Bind a verified original log digest to an exact workflow job/attempt and artifact SHA, reject mismatched histories and replay only a closed, reviewed command allowlist after a demonstrable failure. Continue to distinguish missing original bytes from actual failing execution; authority stays HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
