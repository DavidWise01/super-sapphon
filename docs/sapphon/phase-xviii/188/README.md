# SAPPHON-188 — Cross-Run Ledger Import & Ancestry Continuity

**Phase XVIII · Bound 4/8 · 50% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-188 makes previous-run ledger continuity an explicit source-owned acquisition problem. The importer searches the exact SAPPHON-187 commit `f404ed9e4c60558d82116cf86348304f17daed81`, workflow `sapphon-187-retention.yml`, and named artifact `sapphon-187-retention-evidence`. It requires a completed run with a specific attempt, an unexpired artifact, a matching source-owned ZIP summary, an intact SAPPHON-187 hash chain, and exact equality between the recomputed chain tip and the prior adjudication record.

GitHub's commit-level PR-run readback for the SAPPHON-187 publication commit returned an empty list; combined statuses were also empty. Those particular endpoints cannot rule out push-triggered runs. **No genuine prior ledger ZIP or independently verified SAPPHON-187 CI run has been obtained during this authoring session.**

## Confirmed source defect repair

The Rust source registry included **two identical `pub mod retention187;` declarations**, a concrete Rust compile-time redefinition error. SAPPHON-188 removed the duplicate and registered the new `continuity188` module once. Passing compiler execution has not been independently observed.

## New source

- `tools/sapphon_188_import.py` — bounded 10-page run/artifact discovery; exact run/attempt/source ancestry; original artifact ZIP inspected in memory with no file extraction, path traversal or executable content; verifies `187-summary.json`, `187-adjudication.json`, `187-observation.json` and optional historical `187-evidence-ledger.jsonl`. Missing ledger is `PREDECESSOR_LEDGER_NOT_PRESENT`, not broken-chain evidence.
- When a genuine prior ledger exists, recomputes each earlier SHA-256 link using the inherited SAPPHON-187 verifier and checks the prior adjudication's entry count and final tip. A valid import emits **one new cross-run transition record** binding prior source, run, attempt, original ZIP digest, ledger bytes digest, entry count and tip. It never rewrites original history.
- `tools/test_sapphon_188_import.py` — twelve authored synthetic tests for valid owned import, missing history, tampered history, wrong attempt, changed tip, wrong count, duplicate archive member, expired/missing artifact, incomplete pages and source substitution.
- `rust/sapphon-liveness/src/continuity188.rs` — Rust cross-run evidence-tip and attempt gate with seven authored negative controls, create-only fsynced HOLD output and explicit rejection of custody claims.
- `.github/workflows/sapphon-188-import.yml` — runs Python/Rust and immutable 188-file checks independently of the original ZIP readback, records the exact missing/tampered/imported state and uploads only source-owned metadata and findings.
- `docs/sapphon/phase-xviii/188/index.html` — interactive neon 4D tesseract for import, missing history, changed digest and ancestry scenarios. This is a synthetic viewer, not a live Actions monitor.

## Critical provenance boundary

The imported original artifact and its reported ledger are still both controlled by GitHub. Even a complete chain and a matching SHA-256 tip demonstrate **source-owned structural continuity only**; they do not establish an independently retained witness, independently authenticated UTC, global anti-rollback, registry authenticity or authority to clear a lock.

The preceding SAPPHON-187 workflow creates a ledger on its runner **only when it has a source-owned observation**. A new runner does not inherit that file. Its absence must remain `PREDECESSOR_LEDGER_NOT_PRESENT` (or artifact unavailable), never an invented genesis or fraudulent PASS.

## Qualification ledger

| Criterion | Current state |
| --- | --- |
| Phase XVIII source design | **4/8 = 50% committed** |
| Prior Phase XVII 8/8 source freeze | Protected; not rewritten |
| Duplicate Rust module declaration | Source fix committed; compile verification pending |
| New Python regression cases | 12 authored; hosted execution unverified |
| New Rust regression cases | 7 authored; hosted execution unverified |
| Actual SAPPHON-187 original artifact and ledger | Not retrieved during authoring |
| Historical cross-run continuity | Not yet observed |
| 188 frozen historical files | CI read-only verifier retained |
| npm SHA-512 lockfile integrity | Provisional, unchanged |
| Live GitHub Pages and Chromium | Source committed; deployment unverified |
| External custody, authenticated UTC, anti-rollback | HOLD |
| Key rotation, physical recovery, lock clearance | HOLD |

## Next natural bound — SAPPHON-189

**Custody-Rooted Cross-Run Fork Detection.** Compare multiple independently retrieved copies of a previous source-owned ledger root, detect conflicting histories with the same lineage identifiers, and record unavailable external custody separately from matching GitHub mirrors. Do not treat two GitHub endpoints as two independent witnesses.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
