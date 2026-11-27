# SAPPHON-181 — Original-Byte Acquisition and Safe Artifact Inspection

**Phase XVII · bound 5/8 · 62.5% source-design progress · recovery HOLD**

## Executive summary

SAPPHON-181 adds a read-only source-owned acquisition path and safe original-artifact ZIP inspection. The source is pinned to SAPPHON-180 final commit `dd1d778c522aa18fb399c052958f05c4f5b02dd9`, workflow `sapphon-180-binding.yml`, required job `artifact-binding` and named artifact `sapphon-180-byte-binding`.

The connected GitHub commit-run reader returned no PR-associated Actions runs for this source and no combined commit statuses. That reader is not exhaustive for push-triggered workflows. Consequently **no actual SAPPHON-180 run/job/artifact identifiers or original bytes were independently obtained in this session**.

## Added source

- `tools/sapphon_181_acquire.py`: on the hosted GitHub runner, use the authenticated `gh api` command to find an exact source/workflow run across up to 1,000 workflow entries, bind newest attempt, require one expected job and artifact, reject expired artifacts, and acquire original job-log and artifact ZIP bytes. Distinct unavailability reasons remain explicit. On success, record SHA-256 and identifiers without generating synthetic bytes.
- `tools/sapphon_181_zip.py`: inspect ZIP entries **in memory only**, with no extraction or code execution. Reject unsafe and absolute paths, path traversal, Windows paths, duplicate names, symlinks, encrypted entries, invalid ZIPs, too many entries, individual file size over 2 MiB and total uncompressed size over 12 MiB. Verify ZIP SHA-256 against supplied metadata and inspect expected `180-summary.json` identity and HOLD fields. No archive content becomes executable instructions.
- `tools/test_sapphon_181_zip.py`: twelve authored negative-control regression cases covering path traversal, duplicates, tampering, unknown identity, expired artifacts, missing summary, invalid ZIP, oversize entry and authority forgery.
- `rust/sapphon-liveness/src/archive181.rs`: independent Rust finding adjudicator with six authored tests and a create-only, fsynced HOLD record. It consumes inspected metadata, not untrusted archive code; registered in `lib.rs`.
- `.github/workflows/sapphon-181-acquisition.yml`: runs Python/Rust and frozen-file integrity diagnostics, attempts exact original-byte acquisition, safely inspects the ZIP, removes temporary original bytes, and uploads only source-owned summaries and diagnostics.

## Limits and provenance

The GitHub API download endpoints are susceptible to expired artifacts, authentication failures, redirect/download issues or missing job IDs. The acquisition code fails closed on these; it does not substitute redacted excerpts or fabricated fixtures. Hash agreement proves consistency to **the supplied GitHub metadata**, not independent physical custody.

An uploaded artifact may include source-owned JSON even when no external witness exists. GitHub source, Actions and Pages remain one ancestry. Original unredacted logs or ZIP payloads are not included in the workflow's uploaded diagnostic files.

The existing 188 historical frozen source paths remain immutable. The provisional npm lockfile remains unchanged and unqualified. No key rotation, operational recovery, lock clearance or source-authority promotion is performed.

## Qualification ledger

| Criterion | Status |
| --- | --- |
| Phase XVII source design | 5/8 · 62.5% committed |
| Python safe-ZIP tests | 12 authored; hosted execution unverified |
| Rust adjudicator tests | 6 authored; hosted execution unverified |
| 188 historical frozen records | Read-only regression retained; run unverified |
| Original SAPPHON-180 job log | Not retrieved here |
| Original SAPPHON-180 artifact ZIP | Not retrieved here |
| ZIP summary run/attempt verification | Implemented in source; not yet executed on genuine bytes |
| GitHub Pages and Chromium | Source publication; live result unverified |
| npm registry integrity | Provisional |
| Independent custody and recovery | **HOLD** |

## Next natural bound — SAPPHON-182

**Archive Entry Provenance and Cross-File Consistency.** Verify all expected 180 summary, inspection and predecessor diagnostic records against the exact run/attempt and commit, detect mismatched source ancestries inside the archive, and verify successful source checks separately from independent custody. Require real evidence to move observational state.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
