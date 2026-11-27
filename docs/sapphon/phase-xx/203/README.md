# SAPPHON-203 — Sandboxed Diagnostic Reproduction & Original Log Lineage

**Phase XX · Bound 3 of 8 · 37.5% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-203 creates a real, bounded **Docker-isolated diagnostic reproduction path**, but it only executes when **two source-owned readbacks agree**: (1) the exact SAPPHON-202 original artifact's reported SAPPHON-201 failure and (2) a fresh API reacquisition of the original SAPPHON-201 logs/ZIP and their SHA-256 digests. Both must bind the same original run, attempt, failed step, original log hash and ZIP hash. A missing predecessor remains a refusal, not an invented run.

Pinned SAPPHON-202 commit: `e3053b2b52317fc5d5cf1f2546b1e1f0efcc2c6f`; workflow `sapphon-202-reproduce.yml`; artifact `sapphon-202-hosted-failure-ancestry`. Pinned diagnostic source checkout: SAPPHON-201 `b5ddf7f7d7d51a282c0109276dc37310f56eb240`. These are one GitHub-controlled ancestry, **not independent external witnesses**.

The connected GitHub PR-associated workflow lookup and combined commit-status check for the SAPPHON-202 source returned no associated entries. Those calls are not exhaustive for push-triggered workflows. Neither the original 202 artifact nor the fresh SAPPHON-201 log/ZIP was observed in this authoring turn. Consequently no command was actually executed by the gated replay, and no compiler or source failure was reproduced.

## Committed implementation

- `tools/sapphon_203_isolated_replay.py`: import the exact original SAPPHON-202 ZIP, enforce uniqueness/safe members/source-run-attempt ancestry, require original SAPPHON-201 failure record, freshly reacquire SAPPHON-201 via SAPPHON-202's verifier, demand identical run/attempt and original byte SHA-256 evidence; refuse if no genuine failure or an unsupported command is requested.
- `tools/test_sapphon_203_isolated_replay.py`: **17 authored adversarial cases** for missing or contradictory original bytes, unsupported Docker commands, foreign code, previous attempt substitutions, injection, duplicate plans, missing isolation and replay-not-executed safeguards.
- `rust/sapphon-liveness/src/sandbox203.rs`: Rust exact source/hash/attempt isolation gate; **10 authored tests**; create-only fsynced HOLD findings, registered additively in `lib.rs`.
- `.github/workflows/sapphon-203-isolation.yml`: checks out the pinned SAPPHON-201 revision without persisting credentials, verifies SHA, runs current Python/Rust source tests and immutable 188-file checks, then tries the original-byte-gated Docker reproduction and uploads only SHA-256 and execution summaries.
- `docs/sapphon/phase-xx/203/index.html`: interactive neon rotating 4D lab showing isolation gates and result states; **synthetic**, not a live GitHub Actions dashboard.

## Replay execution boundary

Allowed replay IDs are **`python`** and **`frozen`**; they resolve to fixed command argument arrays that are present in source. Untrusted original job-log content never becomes shell code, arguments, environment variables or scripts. Rust/Cargo replay is **not eligible** in this bound because an offline-pinned dependency image is not yet qualified. An observed Rust failure remains recorded without arbitrary execution.

The runner uses Docker with `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, a source `readonly` bind mount, unprivileged UID/GID, bounded CPU/memory/PIDs, `/tmp` tmpfs, and a 90-second command deadline. It hashes original command output rather than uploading possibly sensitive logs. A replay failure matching an original observed failure is evidence of a **local reproduced diagnostic result**, not permission to modify historical files or authorize physical recovery.

## Qualification snapshot

| Criterion | State |
| --- | --- |
| Phase XX source design | **3/8 = 37.5% committed** |
| New Python adversarial cases | 17 authored; CI execution unverified |
| New Rust cases | 10 authored; CI execution unverified |
| Genuine SAPPHON-202 artifact | Not retrieved during authoring |
| Fresh original SAPPHON-201 log and ZIP | Not retrieved during authoring |
| Sandboxed replay execution | Implemented, **not executed in authoring** |
| Actual source failure reproduced | **None verified** |
| Historical Phase XIX freeze and 188 protected paths | Unmodified / read-only checks retained |
| GitHub Pages / Chromium | Source committed, live deployment unverified |
| Independent custody / UTC / anti-rollback | **HOLD** |
| Recovery and lock clearance | **HOLD** |

## Next natural bound — SAPPHON-204

**Offline-Pinned Rust Reproduction and Diagnostic Artifact Parity.** Build and verify a dependency-complete, immutable Rust replay image, then permit one exact failing Rust command to execute network-disabled against the pinned checkout, preserving observed stdout/stderr hashes and the original source revision. Until an actual failed Rust step and both original byte readbacks exist, replay remains HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
