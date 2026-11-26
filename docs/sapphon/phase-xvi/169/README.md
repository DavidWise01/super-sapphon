# SAPPHON-169 — Phase XVI Runtime Evidence Priority and CI Triage

**Phase XVI · bound 1 of 8 · 12.5% source-design progression · recovery authority HOLD**

## Executive summary

This bound changes the qualification process from simply authoring additional locks to **identifying actual executable failures**. It supplies a GitHub Actions workflow-run triage tool that distinguishes a missing exact-run result, an unfinished run, a failed job or step, and an observed GitHub-owned success. A successful commit or a missing combined-status response is not a passing workflow. The Python tool is `tools/sapphon_169_run_triage.py`; the Rust counterpart is `rust/sapphon-liveness/src/runtime169.rs`.

The previous Phase XV final source commit is pinned to `9df4a75761d005f8157b713aeff2dc96b61b7079`. The new workflow `.github/workflows/sapphon-169-triage.yml` queries the actual workflow runs of `sapphon-168-freeze.yml` using the authenticated GitHub Actions runner token and fetches attempt-scoped jobs and steps. The exact source SHA is mandatory; a green result from a different commit is not accepted.

## Work performed

- **11 new Python regression tests** for exact-SHA readback, missing/incomplete runs, failing and cancelled steps, missing jobs, duplicate/invalid status handling, attempt propagation and non-promotion of GitHub-owned evidence.
- **8 authored Rust tests** and an append-only Linux module declaration in `rust/sapphon-liveness/src/lib.rs`; the Rust module preserves run identity, incomplete status and failed job observations with a create-only fsynced HOLD report.
- A GitHub Actions workflow running full inherited Rust suites, 188 frozen historical byte/hash checks, prior Python adversarial controls, the present lockfile integrity gate and four GitHub Pages exact-commit HTML comparisons. The workflow uploads observations and fails required gates instead of silently accepting unknown outcomes.

## Observed evidence

The GitHub connector reported no PR-triggered runs on the Phase XV final commit. That API wrapper filters by event type, **so this does not imply that there are no push-triggered runs**. The combined GitHub status readback for the same commit returned no statuses. Public npm registry package metadata was inaccessible from the authoring environment, including the direct Playwright 1.65.1 and Playwright Core 1.65.1 registry endpoints. The committed `package-lock.json` therefore still has no independently verified integrity values. Third-party package pages confirm that Playwright 1.65.1 exists, but do not substitute for the exact `dist.integrity` metadata and archive verification. Consequently, no valid npm lockfile promotion was performed.

These are **observation limits**, not demonstrated Rust compiler failures. The full Rust regression suite and the new CI workflow have not been observed passing. The historical 188-file manifest declarations are still protected in source; a completed SHA-256 verification run is still pending observation.

## Authority and ancestry boundaries

GitHub code, GitHub Actions artifact readback and GitHub Pages share one owned-source ancestry. Even if every GitHub-owned check passes, they do not establish independently authenticated external custody, globally monotonic outside checkpoints, trusted UTC, operational key replacement, lock clearance or recovery. All remain **HOLD**.

## Next natural bound — SAPPHON-170

Read the exact SAPPHON-169 run output and predecessor failed-step diagnostics. Repair only evidenced failures (such as compilation errors, missing artifact fields, actual npm candidate mismatch or deployed Pages drift). Preserve the 188 frozen files and all operational HOLD bits. If no completed job can be observed, explicitly retain `NO_MATCHING_RUN` or `READBACK_UNAVAILABLE` rather than claiming a pass.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
