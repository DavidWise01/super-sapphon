# SAPPHON-161 — Phase XV Reproducible CI Qualification Diagnostics

**Phase XV · 1/8 · 12.5% source-design progression · operational authority HOLD**

## Executive summary

This phase changes priority from serial source-design additions to **actual executable qualification**. The previous Phase XIV source freeze was committed, but no completed passing Actions run or browser deployment was independently confirmed. The SAPPHON-161 workflow tests those assumptions explicitly and writes an outcome record even if one or more steps fail.

### Implemented
- `rust/sapphon-liveness/src/diagnostic161.rs`: deterministic Rust check classifier for Rust type-check, Rust tests, historical hashes, Pages HTTP and browser smoke. Failed, missing, skipped and unknown statuses remain distinguishable. A caller-supplied “pass” claim does not become independently authenticated CI.
- `tools/sapphon_161_probe.py`: a GitHub Pages HTTP probe requiring 200 status, HTML MIME type, bounded response size, expected SAPPHON-160 title and canvas/script markers. Its report mode requires exact repository, commit, run ID and attempt, then records **the actual GitHub Actions step outcomes** as untrusted runner observations with false custody and recovery flags.
- `.github/workflows/sapphon-161-diagnostics.yml`: performs `cargo check`, full liveness and inherited Rust test suites, hash/byte comparison of all 188 historical freeze entries, Pages HTTP inspection, and a Chromium Playwright CLI screenshot. Each test step uses `continue-on-error` to allow an evidence report to be produced even after failure; a final blocking step fails the job if any required step outcome is not `success`. The workflow uploads `161-diagnostic.json` and a screenshot if one was produced.
- Nine authored Rust regression tests for failure retention, missing checks, fake API-readback claims, duplicate/unexpected steps, unsupported statuses, deterministic order, skipped outcomes, malformed commit IDs and create-only evidence output.

### What was actually observed
The GitHub connector confirmed the previous Phase XIV source and workflow files and their expected structures. Five prior historical freeze manifests were inspected earlier and yielded **11 + 45 + 42 + 42 + 48 = 188 entries**. That enumerates declared files; it is not proof that their current bytes match all hashes. The public Actions and Pages URLs could not be opened using the available public web reader, and the GitHub connector does not expose push-triggered runs through its commit-run discovery. Combined commit-status readback on previous final commits reported no statuses, which does **not** establish a pass or failure.

The execution environment used for authoring has no local `cargo` or `rustc` executable. Therefore the Rust tests here have been **authored**, not locally executed. The new Actions workflow must complete and its actual run, job and log readback must be checked before any test is called passed. The browser smoke verifies loading and screenshot generation, not full interactive behavioral parity.

### External authority
Even successful Actions and Pages validation cannot authenticate independent external custody, authenticated physical UTC, a globally monotonic outside checkpoint, operational key replacement, recovery, or lock clearance. Those remain **HOLD**. GitHub source, GitHub Actions, and GitHub Pages are one owned ancestry.

### Next natural bound — SAPPHON-162
Read and triage the specific SAPPHON-161 Actions failure logs (or all passing outcomes), repair any compiler/fixture or Pages-deployment blockers, and add deterministic browser interaction assertions rather than relying only on a screenshot.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
