# SAPPHON-162 — Interactive Chromium Acceptance and CI Failure Triage

**Phase XV · bound 2/8 · 25% source-design progression · operational authority HOLD**

## Qualification change

SAPPHON-161 captured a Chromium screenshot, but an image alone does not verify button handlers, JavaScript error states, canvas pixel initialization or the visible recovery HOLD invariant. SAPPHON-162 creates an explicit interactive browser acceptance harness, rather than claiming that a screenshot proves working browser behavior.

## Committed work

- `tools/sapphon_162_browser.cjs` starts actual Playwright Chromium, visits SAPPHON-160 and SAPPHON-161 Pages, verifies HTTP 200 and expected page titles, inspects the canvas pixel dimensions, clicks **four scenario buttons per page**, asserts the exact resulting DOM status text, requires visible HOLD, checks the browser error stream and records screenshots with SHA-256 digests. The acceptance output `162-browser-acceptance.json` is generated only after the assertions pass.
- `rust/sapphon-liveness/src/triage162.rs` cross-classifies the results of Rust typecheck, Rust tests, 188 inherited frozen hashes, Pages HTTP and interactive browser acceptance. It refuses invalid statuses and duplicate browser cases, preserves failed stages and retains unqualified authority even when every supplied stage says success. Nine Rust unit tests are authored.
- `.github/workflows/sapphon-162-acceptance.yml` runs Rust checks, inherited suites, exact 188 historic checks, installs Playwright Chromium and executes browser interactions. It uses the GitHub API to read back the latest SAPPHON-161 workflow run and job steps where available; absence or API error is explicitly recorded. Evidence is uploaded even on failure, and a required failed or skipped stage makes the final job fail.

## Live-evidence boundary

GitHub connector searches here can verify source commits and source files. Its commit workflow-run discovery is restricted to PR-triggered runs, so absence there does not establish the absence of push-triggered Actions runs. The public web reader could not fetch the target workflow or Pages URL. No completed run ID, successful job log, or deployed Chromium test outcome was independently authenticated in this authoring turn.

As before, **CI configured** and **test authored** are not equivalent to **CI passed**. The GitHub-runner-owned readback and screenshot are one source ancestry, not an independent custodian. Authenticated external checkpoint retention, physical custody, globally monotonic time, automated recovery, key rotation and lock clearance remain HOLD.

## Browser acceptance details

The eight interactions include design freeze, CI uncertainty, signed fork and shared ancestry (SAPPHON-160), plus compiler failure, historic hash failure, browser failure and neutral status (SAPPHON-161). Expected DOM outcomes and screenshots are recorded by the test. The harness does not validate the separate Rust computation through the browser's illustrative controls, and should not be treated as a cryptographic witness.

## Next bound — SAPPHON-163

Fix only failures confirmed by the SAPPHON-162 workflow and its retained job logs. Add repository-pinned browser dependencies and explicit deployed-asset revision checks, then audit preserved historical hashes before any source changes.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
