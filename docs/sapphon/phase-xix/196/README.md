# SAPPHON-196 — Independent Original-Byte Reacquisition & Readback Equivocation

**Phase XIX · bound 4/8 · 50% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-196 implements **a second, separate request for the original SAPPHON-193 log and ZIP bytes**, using SHA-256 claims retrieved from a genuine SAPPHON-195 cross-verification artifact. Here, *independent reacquisition* describes a distinct API fetch and local hash calculation, **not** an independent external custodian: both are within the same GitHub-owned source ancestry.

Pinned source-of-claims: SAPPHON-195 commit `c5496fcaaa28ce37d9dcb43e69223b6566d1a1a3`, workflow `sapphon-195-crossverify.yml`, artifact `sapphon-195-log-artifact-parity`. Pinned original evidence source: SAPPHON-193 commit `517959b0c98b65bafefaba5ae5e18065b2e27212`, workflow `sapphon-193-triage.yml`, job `runner-failure-triage`, artifact `sapphon-193-exact-run-failure-triage`.

The available GitHub commit-run wrapper returned no PR-associated run or combined status for SAPPHON-195. That is not an exhaustive search of push runs. **No original SAPPHON-193 log/ZIP or genuine SAPPHON-195 artifact has been retrieved during this authoring session**, and no successful hosted test run has been demonstrated.

## Committed source

- `tools/sapphon_196_reacquire.py`: bounded complete pagination of SAPPHON-195 workflows/artifacts; strict original ZIP member and predecessor identity checks; imports exact `195-crossverify.json` and `195-summary.json`; rejects unresolved or conflicting ancestry; requests the exact original SAPPHON-193 run ID, attempt-specific jobs, run artifacts, original job-log bytes and original artifact ZIP; checks ZIP member shape/source/run/attempt; calculates **new SHA-256 directly from downloaded original bytes**; compares them to SAPPHON-195 claimed digests; records `GITHUB_OWNED_HASH_MATCH`, `GITHUB_OWNED_READBACK_EQUIVOCATION`, or a precise not-observed/invalid state.
- `tools/test_sapphon_196_reacquire.py`: **16 authored adversarial fixtures** for genuine byte matching, changed log, changed valid ZIP, wrong embedded attempt, artifact expiry, unknown expiry, altered source ancestry, absent original bytes, false replay, malformed digest and duplicate archive members.
- `rust/sapphon-liveness/src/reacquire196.rs`: Rust comparison of fresh/claimed SHA-256 strings with precise provenance and missing-evidence fences; **8 authored regression cases**, create-only fsynced HOLD diagnostics. Registered additively in `lib.rs`.
- `.github/workflows/sapphon-196-reacquire.yml`: Python/Rust regression suites, read-only historical 188-file check, attempted live original-byte reacquisition using read-only `GH_TOKEN`, sanitized original-byte hash comparison artifact and explicitly separate source-check status.
- `docs/sapphon/phase-xix/196/index.html`: interactive neon 4D shadow lab, **synthetic scenarios**, not live GitHub Actions reporting.

## Evidence interpretation

A matching log and ZIP on two requests is **source-owned content consistency**. It does not prove external custody, original issuance time, real-world clock accuracy, physically independent observers or recovery authority. A hash difference for the same source/run/attempt and original evidence identity is **GitHub-owned readback equivocation**, not automatically external maliciousness. An unavailable or expired original artifact must never be labeled as a hash mismatch.

The imported SAPPHON-195 ZIP carries *previous digest claims*, whereas the new log/ZIP SHA-256 fields originate from **newly fetched original SAPPHON-193 bytes**. The report explicitly distinguishes those roles. The probe has no shell replay and does not persist or publish raw secret-bearing logs.

The completed Phase XVIII eight-module source freeze and protected 188 historical source files remain untouched.

## Qualification checkpoint

| Criterion | State |
| --- | --- |
| Phase XIX source-design progress | **4/8 = 50% committed** |
| Python reacquisition regressions | 16 authored; hosted execution unverified |
| Rust hash-parity regressions | 8 authored; hosted execution unverified |
| Genuine SAPPHON-195 artifact | Not retrieved during authoring |
| Fresh original SAPPHON-193 log / ZIP | Not retrieved during authoring |
| Actual 193-vs-195 SHA-256 comparison | **Not yet observed** |
| Historical 188 protected paths | Read-only check retained |
| Hosted CI pass and live Pages | Unverified |
| Independent external witnesses | **0 verified** |
| Authenticated UTC, anti-rollback, npm registry integrity | HOLD |
| Key rotation, lock clearance, physical recovery | HOLD |

## Next natural bound — SAPPHON-197

**Cross-Readback Monotonic Evidence & Fork Attribution.** Compare multiple *actual* original-byte readbacks for one pinned source/run/attempt, establish source-owned monotonic sequence records, classify changed bytes independently of deleted/expired history, and refuse to turn GitHub-owned copies into independent witnesses.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
