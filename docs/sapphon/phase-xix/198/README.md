# SAPPHON-198 — Durable Cross-Run Ledger Tip Import & Fork Preservation

**Phase XIX · Bound 6/8 · 75% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-198 moves the original-byte evidence chain across source-owned CI runs **only when an original SAPPHON-197 ledger ZIP is genuinely available**. It verifies the ZIP's exact run/attempt and source SHA, recomputes every SHA-256 ledger link, checks the published adjudication's entry count, tip, missing evidence and fork list, and then appends one more observation. It never manufactures a genesis to conceal an unavailable predecessor.

Pinned SAPPHON-197 predecessor: commit `9bddb4491893ee121f71821b61692685508adae6`; workflow `sapphon-197-monotonic.yml`; artifact `sapphon-197-monotonic-readback-evidence`. The underlying original evidence remains SAPPHON-193 commit `517959b0c98b65bafefaba5ae5e18065b2e27212`.

The currently available GitHub commit-level status and PR-run lookups return empty arrays for SAPPHON-197. These lookups are not exhaustive for push-triggered runs. **No genuine predecessor SAPPHON-197 artifact, original SAPPHON-193 log, or ZIP was retrieved during authoring.** Hosted execution and GitHub Pages deployment are also unverified.

## New source

- `tools/sapphon_198_import.py`: bounded, exhaustive exact SAPPHON-197 run/artifact API listing; ZIP member safety and uniqueness; original ZIP SHA-256; run/attempt verification; full inherited ledger SHA-256 hash-chain verification using the frozen SAPPHON-197 format; published adjudication and summary parity. A genuine original ZIP must be present for successful return.
- `tools/sapphon_198_extend.py`: validates actual inherited chain entries, tip, and fork list against the original import receipt; rejects missing or forged parents; creates a new ledger by appending a single observed/unavailable event; retains the entire inherited fork and missing-evidence ancestry; creates output files without overwriting predecessors.
- `tools/test_sapphon_198_import.py`: 15 authored synthetic tests covering ZIP tampering, substituted attempts, forged tips, changed chain bytes, missing source, absent parent, inherited/new fork preservation, source-owned witness isolation and contradictory summaries.
- `rust/sapphon-liveness/src/import198.rs`: Rust exact source/run/attempt and tip comparison; immutable-parent and ZIP digest gates; eight authored tests; create-only fsynced HOLD diagnostic. Registered in `lib.rs`.
- `.github/workflows/sapphon-198-import.yml`: Python/Rust regression suites, inherited 188-file historical verification, read-only genuine predecessor import, fresh original-byte observation, verified-parent-only append, sanitized evidence upload and fail-closed parent checks.
- `docs/sapphon/phase-xix/198/index.html`: interactive neon rotating 4D provenance lab. Scenarios are synthetic; the viewer is not a live CI monitor.

## Qualification boundaries

The ledger's sequential order is the order in which this source-owned process records events. An authenticated independent clock, separately held archival custody, and global anti-rollback are still absent. A successful source-owned original import would establish *a particular GitHub artifact's internal chain continuity*, not durable, independent third-party ownership.

The workflow cannot assert continuity when the previous ZIP is inaccessible. An unavailable predecessor is **NO_VERIFIED_PREDECESSOR** rather than a synthetic PASS, and the source gate fails. A historically recorded fork is never cleared by appending later events. No archive content is executed or extracted.

| Criterion | Status |
| --- | --- |
| Phase XIX source design | **6/8 · 75% committed** |
| Python new negative controls | 15 authored; hosted execution unverified |
| Rust negative controls | 8 authored; hosted execution unverified |
| Genuine inherited SAPPHON-197 artifact | Not retrieved during authoring |
| Cross-run ledger chain continuity | Source implemented; genuine verification pending |
| Historical source freezes | 188 protected files; read-only checks retained |
| Completed Phase XVIII Rust freeze | Unmodified |
| Live Pages and hosted Actions | Unverified |
| Independent witnesses and authenticated UTC | **0 / HOLD** |
| Global anti-rollback and recovery | **HOLD** |

## Next natural bound — SAPPHON-199

**Immutable Parent-Custody Replay & Bounded Retention Pressure.** Reacquire exact original SAPPHON-198 ledger bytes, require an unmodified inherited tip, inspect artifact retention gaps and source-owned parent forks, and refuse to infer deletion or anti-rollback from missing GitHub data. Recovery and lock clearance remain HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
