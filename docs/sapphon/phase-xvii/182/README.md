# SAPPHON-182 — Archive Entry Provenance & Cross-File Consistency

**Phase XVII · bound 6/8 · 75% source design · operational recovery HOLD**

## Executive summary

SAPPHON-182 upgrades the SAPPHON-181 original ZIP inspection to a **three-record cross-file evidence gate**, inspecting original ZIP bytes in memory and requiring all three diagnostic files: `180-summary.json`, `180-binding.json`, and `180-predecessor.json`.

The verifier binds the SAPPHON-180 source commit `dd1d778c522aa18fb399c052958f05c4f5b02dd9`, `sapphon-180-binding.yml`, job `artifact-binding`, and named artifact `sapphon-180-byte-binding`. The internal predecessor must trace to SAPPHON-179 commit `d07203a254678fdf7df05a75c1d144c7a8337f87`.

The available GitHub commit-run wrapper returned no PR-associated runs and its combined status endpoint returned no checks for SAPPHON-181. These narrow responses do **not** prove absence or failure of push-triggered Actions. No genuine SAPPHON-180 original bytes were retrieved by this authoring session.

## New implementation

- `tools/sapphon_182_crossfile.py`: bounded ZIP input (64 MiB), maximum 48 members, 2 MiB per member, 12 MiB total uncompressed, path/symlink/encryption/traversal/duplicate checks, exact three-file set requirement, digest validation, JSON parsing in memory only and semantic cross-file checks.
- `tools/test_sapphon_182_crossfile.py`: 14 authored adversarial checks for missing/duplicate files, wrong SHA/attempt, false Rust pass, forged recovery, predecessor ancestry mismatch, unknown binding status, tampered ZIP and structurally complete versus evidence-complete distinction.
- `rust/sapphon-liveness/src/crossfile182.rs`: Rust evidence-finding adjudication with 7 authored tests, create-only fsynced output and no actuation; registered in `lib.rs`.
- `.github/workflows/sapphon-182-crossfile.yml`: independently runs Python, Rust and historical 188-file checks, uses the SAPPHON-181 read-only collector to seek original SAPPHON-180 bytes, runs cross-file verification only when actual ZIP bytes are available, preserves explicit unavailability findings, cleans the temporary original bytes, uploads only metadata and diagnostics and retains HOLD.

## Three-record ancestry rules

**180-summary.json** must declare the exact SAPPHON-180 source commit and match the artifact's run ID and attempt. A claimed source-test pass is rejected unless Python, Rust and frozen historical checks are all `success`. Any full qualification or recovery claim is rejected.

**180-binding.json** may be an exact SAPPHON-179 source-owned binding report or the explicit `ORIGINAL_BYTES_NOT_SUPPLIED` result. Incorrect schema, mismatched source ancestry, false PASS with nonempty failures, or unsupported authority are rejected. An unavailable binding can be *structurally consistent* but cannot be *complete evidence*.

**180-predecessor.json** must identify the pinned SAPPHON-179 commit and `sapphon-179-replay.yml`. A reported exact observed run must carry that same SHA and positive run/attempt. Missing predecessor execution remains an explicit nonqualified state rather than a fabricated pass.

The verifier records two **different booleans**: `archive_records_structurally_consistent` and `complete_predecessor_and_raw_byte_evidence`. Even true for both means agreement among GitHub-owned records, not an independently anchored external witness.

## Qualification ledger

| Criterion | State |
| --- | --- |
| Phase XVII source design | 6/8 = 75% committed |
| Python cross-file negative tests | 14 authored; hosted execution unverified |
| Rust source adjudication tests | 7 authored; hosted execution unverified |
| Three ZIP member provenance/ancestry checks | Source implemented |
| SAPPHON-180 original ZIP | Not retrieved in this authoring session |
| Historical 188 frozen records | Read-only check retained; hosted pass unverified |
| Actual GitHub Actions CI and live Pages | Unverified |
| Provisional npm lock | Not modified or qualified |
| External custody, monotonic witness, authenticated UTC | HOLD |
| Key rotation, lock clearance, physical recovery | HOLD |

## Next natural bound — SAPPHON-183

**Completed-Run Evidence and Contradiction Adjudication.** Retrieve genuine SAPPHON-182 acquisition outcomes, distinguish source-owned pass from actual full evidence completeness, and reconcile contradictions across acquisition, archive, runner job steps and source artifact roots. Keep all independent authority gated.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
