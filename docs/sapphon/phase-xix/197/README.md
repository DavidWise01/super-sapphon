# SAPPHON-197 — Cross-Readback Monotonic Evidence & Fork Attribution

**Phase XIX · Bound 5/8 · 62.5% source-design progress · operational authority HOLD**

## Executive summary

SAPPHON-197 builds an append-only, sequence-numbered, SHA-256-linked **GitHub-owned evidence ledger** for original SAPPHON-193 job-log and artifact readbacks. It distinguishes identical byte hashes, conflicting byte hashes for the **same run and attempt**, and missing/expired originals. It never infers a fork from an absent artifact, nor promotes different GitHub API requests into independent external witnesses.

The predecessor is SAPPHON-196 final source commit `56d66ad2390063f08e33872299eebe6c8d78a8fe`, workflow `sapphon-196-reacquire.yml`, artifact `sapphon-196-original-byte-comparison`. The underlying original is SAPPHON-193 commit `517959b0c98b65bafefaba5ae5e18065b2e27212`.

The available PR-scoped GitHub workflow and combined status lookups for the predecessor returned no associated run/check. This does **not** rule out push-triggered workflows. No genuine predecessor artifact or original SAPPHON-193 log/ZIP has been obtained in this authoring session.

## New source

- `tools/sapphon_197_ledger.py`: strictly defined original source SHA, workflow, run/attempt, state and digests; max 10,000 source-owned records; monotonic integer sequence; canonical SHA-256 record links; tamper and parent mismatch rejection; exact source-run/attempt byte fork classification; create-only ledger output (never rewrite previous ledger).
- `tools/test_sapphon_197_ledger.py`: **17 authored tests** for matching/changed hashes, distinct attempts, missing/expired evidence, history alteration, nonmonotonic parent, forged external witness, false recovery and unknown fields.
- `tools/sapphon_197_import.py`: bounded, exhaustive read-only acquisition of the exact original SAPPHON-196 diagnostic ZIP; checks artifact/run ancestry, safe unique ZIP members and embedded source/run/attempt; exports only the genuinely observed report. If no report exists, leaves the previous observation explicitly unavailable.
- `rust/sapphon-liveness/src/monotonic197.rs`: Rust monotonic SHA-256 chain, source-owned fork findings and create-only fsynced HOLD diagnostics; **8 authored tests**. Registered in `lib.rs`.
- `.github/workflows/sapphon-197-monotonic.yml`: regression checks and inherited immutable 188-file verification, exact SAPPHON-196 report retrieval, fresh SAPPHON-193 original-byte readback, two ordered append operations, fork findings and sanitized artifact upload.
- `docs/sapphon/phase-xix/197/index.html`: neon interactive 4D laboratory. Synthetic scenarios only; not a live Actions monitor.

## Provenance boundaries

The sequence count is **local append order**, not authenticated UTC or global anti-rollback. Although the generated ledger is protected by a hash chain and the current output is created without overwriting older files, there is no separately authenticated durable cross-run store. **Cross-run chain continuity remains unverified** until a previously retained ledger can be independently retrieved and its inherited tip validated.

The workflow can import one historical SAPPHON-196 readback result and perform one fresh source-owned readback. If the prior artifact was not accessible, the ledger begins with an explicit `READBACK_UNAVAILABLE` event—not invented historical success. If a fresh readback is absent, that too is recorded separately.

An observed `GITHUB_OWNED_READBACK_EQUIVOCATION` means original byte observations conflict within the pinned GitHub-owned ancestry; it is not, by itself, proof of independent tampering, third-party custody, or physical conditions.

## Qualification

| Criterion | State |
| --- | --- |
| Phase XIX source-design progress | **5/8 = 62.5% committed** |
| New Python negative controls | 17 authored; hosted execution unverified |
| New Rust negative controls | 8 authored; hosted execution unverified |
| Genuine prior SAPPHON-196 report | Not retrieved in authoring |
| Fresh original SAPPHON-193 bytes | Not retrieved in authoring |
| Historical cross-run ledger custody | **Unverified** |
| Immutable historical 188-file check | Retained read-only |
| Completed Phase XVIII Rust freeze | Unmodified |
| Live Pages/Chromium and hosted CI | Unverified |
| Independent witnesses, authenticated UTC, anti-rollback | **0 / HOLD** |
| Key rotation, physical recovery, lock clearance | **HOLD** |

## Next natural bound — SAPPHON-198

**Durable Cross-Run Ledger Tip Import & Original Source Equivocation Recovery.** Re-import the *actual SAPPHON-197 ledger artifact* from an exact prior source run, validate its last SHA-256 tip, append a new real observation only after provenance checks, and preserve all fork/absence findings without rewriting history. No source-owned copy becomes an independent witness.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
