# SAPPHON-199 — Immutable Parent-Custody Replay & Bounded Retention Pressure

**Phase XIX · Bound 7/8 · 87.5% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-199 checks the **actual original SAPPHON-198 ZIP** against its pinned source commit, run, attempt and inherited 197 parent. It recomputes the complete SAPPHON-197-compatible hash chain embedded in the SAPPHON-198 archive, independently replays the parent prefix, verifies the exact parent tip, append count and fork inheritance, and classifies unavailable or expired data without fabricating a deletion or rollback conclusion.

Pinned predecessor: `16aebb4fc9551e505ec7f461b7db05db6f340d86`, workflow `sapphon-198-import.yml`, artifact `sapphon-198-cross-run-ledger-tip`.

Available PR-associated GitHub workflow and combined commit-status lookups returned no runs/checks. This is not an exhaustive search of push-triggered Actions. No actual SAPPHON-198 original artifact was obtained during authoring; no hosted PASS, genuine parent verification, or live GitHub Pages deployment has been observed.

## Implemented source

- `tools/sapphon_199_retention.py`: bounded exact workflow-run and artifact discovery; original ZIP SHA-256; safe in-memory ZIP member inspection; embedded run/attempt/source validation; recompute entire source-owned ledger and independently recompute prefix tip; compare `198-import.json`, `198-adjudication.json`, `198-summary.json`; ensure exactly one append and inherited fork preservation.
- `tools/test_sapphon_199_retention.py`: 15 authored adversarial cases: successful synthetic parent replay, missing/expired metadata, changed parent tip, absent 197 ancestry, wrong attempt, prior fork retention and attempted erasure, modified chain bytes, duplicate/unexpected ZIP entries, invalid boundary, false recovery.
- `rust/sapphon-liveness/src/retention199.rs`: Rust source-owned immutable-parent, full SHA-256 format, fork non-erasure and expiration/deletion separation gate; eight authored tests; fsynced create-only HOLD output. Registered in `lib.rs`.
- `.github/workflows/sapphon-199-retention.yml`: new and inherited Python/Rust tests, 188 protected historical-file verification, exact SAPPHON-198 original artifact readback and sanitized outcome upload; source tests and required original-parent acquisition fail closed.
- `docs/sapphon/phase-xix/199/index.html`: neon interactive 4D source-owned retention and parent-fork lab, illustrative only.

## Retention evidence distinctions

A missing artifact name in a bounded listing is not evidence of deletion. An incomplete listing is not evidence that any artifact was absent. A GitHub API `expired` metadata flag is an **expiration claim**, not proof of a verified deletion event. SAPPHON-199 deliberately does **not** infer deletion from expiration, a missing listing, an unavailable download or an absent source run.

A rebuilt source-owned chain with a matching parent tip establishes only **internal provenance consistency**. Even a true original-archive readback remains within the same GitHub-controlled evidence ancestry. Authenticated UTC, third-party durable custody and global anti-rollback stay unqualified.

## Qualification ledger

| Criterion | State |
| --- | --- |
| Phase XIX source design | **7/8 = 87.5% committed** |
| Original SAPPHON-198 source ZIP | Source acquisition implemented; real bytes not retrieved during authoring |
| Parent-tip and one-append replay | Implemented, real hosted observation pending |
| Fork inheritance and retention separation | Implemented |
| New Python negative cases | 15 authored, hosted execution unverified |
| New Rust negative cases | 8 authored, hosted execution unverified |
| 188 historical frozen files | Read-only checks retained |
| Live Pages / Chromium and successful hosted CI | Unverified |
| Independent witnesses | **0 verified** |
| Authenticated UTC, anti-rollback, custody | HOLD |
| Physical recovery and lock clearance | HOLD |

## Next natural bound — SAPPHON-200

**Phase XIX Final Source Freeze & Observed Retention Evidence Inventory.** Freeze the eight Phase XIX source-design bounds (193–200), record their exact source digests and observed-vs-authored status, inspect source-owned original retention failures if any can actually be retrieved, and avoid upgrading any missing evidence to a successful runner result or independent custody.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
