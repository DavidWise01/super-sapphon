# SAPPHON-170 — Verified Failure Isolation & Targeted CI Decision Repair

**Phase XVI · bound 2/8 · 25% source design · operational HOLD**

## Executive summary

SAPPHON-170 makes targeted, source-visible repairs to the SAPPHON-169 runtime triage and provides a diagnostic CI workflow that isolates real executable failures without letting the known provisional npm lockfile suppress Rust and Python test information.

**Two demonstrable source defects were corrected.** First, `tools/sapphon_169_run_triage.py` used `any(... successful ...)` over every matching run, meaning an old green attempt could mask a newer failed or incomplete attempt for the same source revision. It now selects the latest matching run and attempt, requires the expected `final-freeze` job, and counts a source-owned success only when that selected attempt and its jobs are completed successfully. Three regression tests were added to the existing test suite for latest-run failure, later-attempt failure and missing required job.

Second, the first SAPPHON-170 workflow draft accidentally queried `sapphon-168-freeze.yml` for the source SHA of `SAPPHON-169`. The source tool and workflow were corrected so the pinned `SAPPHON-169` commit `e9f983e28da437b80b6c22be1107a099df381f38` is queried through `sapphon-169-triage.yml`. This avoids fabricating a missing-run conclusion by looking under the wrong workflow name.

## New source artifacts

- `rust/sapphon-liveness/src/isolate170.rs` provides newest-attempt diagnostic isolation, source-owned pass classification, explicit failure reasons and a create-only fsynced HOLD report. Eight Rust tests are authored for old-green masking, retry failure, missing jobs, incomplete runs, wrong SHA, duplicate evidence and output protection.
- `rust/sapphon-liveness/src/lib.rs` adds the Linux module declaration without altering older ancestry.
- `.github/workflows/sapphon-170-isolation.yml` runs all inherited Rust suites, the expanded Python triage controls, exact SHA-256/length checks against the 188 historical frozen-file entries, predecessor run discovery, committed-lock integrity inspection and four-page GitHub Pages byte parity.
- The workflow records independent outcomes for `PYTHON`, `RUST`, `FROZEN`, `PREDECESSOR`, `LOCK`, and `PARITY`. A failure in Rust, Python or the historic source integrity gate **fails the diagnostic job**. Failures in predecessor readback, the known provisional lockfile, or Pages are retained as blockers in the artifact without suppressing executable source diagnostics. This diagnostic-pass state **must not** be interpreted as full qualification.

## Verification boundary

The GitHub connector confirms committed source changes through readback and commit enumeration. Its available workflow lookup is limited to PR-triggered runs; an empty result there cannot establish whether a push-triggered job passed, failed or ran. In this authoring session, no completed SAPPHON-169 job logs were available, so no real compiler failure or particular CI job outcome has been claimed or repaired.

The npm lockfile still lacks real package SHA-512 integrity values. It was intentionally not edited. GitHub source, GitHub Actions and GitHub Pages belong to the same owned corpus, not three independent custodians. No physical recovery, lock clearance, key rotation, globally monotonic external time or authenticated UTC is established.

## Phase XVI checkpoint

| Dimension | Finding |
|---|---|
| Source design | 2/8 bounds committed, 25% |
| Old-green replay and missing-job triage bugs | Source repaired; runtime test execution pending |
| Target workflow SHA mismatch | Corrected before final freeze |
| New Rust isolation module | Committed; eight tests authored |
| Historical 188 file contents | Frozen checks retained; passing CI unverified |
| npm package integrity | Still provisional and unqualified |
| Chromium / Pages live verification | Not established in this turn |
| External custody, anti-rollback and operational recovery | HOLD |

## Next natural bound — SAPPHON-171

Acquire completed job logs for the corrected SAPPHON-170 workflow; identify actual compiler, Python, browser or Pages errors and fix only demonstrated failures. Authenticate the real npm integrity metadata before any lockfile replacement. If GitHub job logs remain unavailable, retain `READBACK_UNAVAILABLE` instead of inventing test results.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
