# SAPPHON-202 — Hosted Compiler/Regression Failure Reproduction With Verified Ancestry

**Phase XX · Bound 2/8 · 25% source-design progress · recovery HOLD**

## Executive summary

SAPPHON-202 checks the **original SAPPHON-201 Actions job, log bytes and artifact ZIP**, tying observed failures to one immutable source commit and exact run attempt. It does not run remote log commands; only exact, reviewed diagnostic command arrays may be proposed as **PLAN_ONLY**.

Pinned predecessor: `b5ddf7f7d7d51a282c0109276dc37310f56eb240`, workflow `sapphon-201-runner.yml`, job `observed-hosted-qualification`, artifact `sapphon-201-observed-hosted-qualification`.

Available GitHub PR-linked commit workflow and combined-status results were empty. These results do not exhaust push-triggered Actions. No actual SAPPHON-201 hosted job, original log, or original artifact was acquired during authoring. Consequently no compiler or test failure has been **observed or reproduced**, and no speculative frozen-source repair was made.

## New code

- `tools/sapphon_202_reproduce.py`: bounded complete original workflow-run, attempt-job and artifact listings; exact predecessor ancestry; original SHA-256 of logs and ZIP; safe in-memory archive member checks; report/summary cross-consistency; four named critical steps; observed failure classification; reviewed Python, Rust and immutable-history **argv** replay plans, never executable log fragments.
- `tools/test_sapphon_202_reproduce.py`: **17 authored synthetic tests** for exact source/attempt mismatch, omitted logs, duplicate or missing job steps, corrupted ZIP, false green parent and contradictory child outcome, expired artifacts, remote log injection and plan-only behavior.
- `rust/sapphon-liveness/src/replay202.rs`: Rust original-byte hashes and run/attempt ancestry gate with **9 authored tests**, fixed diagnostic IDs and create-only fsynced HOLD output; additively registered in `lib.rs`.
- `.github/workflows/sapphon-202-reproduce.yml`: current 202 Python/Rust regressions and inherited Phase XIX checks, the read-only 188-file protection check, exact SAPPHON-201 original-byte acquisition, sanitized artifact upload and separation of prior failure observations from current source execution.
- `docs/sapphon/phase-xx/202/index.html`: animated neon four-dimensional diagnostic lab, illustrative, not live source-run data.

## Evidence boundary

The GitHub source tree, owned Actions runner and hosted artifacts share one ancestry. If exact original bytes show a failed Rust or Python step, the verifier can propose a closed, predetermined local diagnostic command array. The proposed command is **never executed by this workflow**; a later explicit bounded replay must confirm the failure without creating new source authority. An observed acquisition-step failure is not eligible for arbitrary shell replay.

The completed Phase XIX source-design freeze and earlier historical 188 protected files are not changed. Authenticated UTC, global anti-rollback, independent keys/witnesses, physical recovery and lock clearance remain **HOLD**.

| Checkpoint | State |
| --- | --- |
| Phase XX source-design progress | **2/8 = 25% committed** |
| Python 202 negative controls | 17 authored; hosted execution unverified |
| Rust 202 negative controls | 9 authored; hosted execution unverified |
| Genuine SAPPHON-201 run and artifact | Not retrieved in authoring |
| Verified/reproduced actual compiler failure | Not observed |
| Source-owned original-byte replay plan | Committed, **PLAN_ONLY** |
| Historical 188-file verification | Retained read-only |
| Live GitHub Pages/Chromium and hosted CI | Unverified |
| Independent witnesses | **0 verified** |
| Authenticated UTC / external custody / physical recovery | **HOLD** |

## Next natural bound — SAPPHON-203

**Sandboxed Diagnostic Command Reproduction & Original Log Lineage.** Reacquire an actual failure and run **only** the fixed, reviewed diagnostic command on a pinned read-only checkout in a bounded subprocess, recording observed exit code and output hashes while preserving every original source and provenance label. If no real failure exists, do not invent one.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
