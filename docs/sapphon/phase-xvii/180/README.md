# SAPPHON-180 — Raw Job-Log and Artifact Byte Binding

**Phase XVII · bound 4/8 · 50% source-design progression · recovery HOLD**

## Executive summary

SAPPHON-180 separates SHA-256 consistency of **original raw job-log bytes** and an **original workflow artifact ZIP** from weaker evidence such as a redacted excerpt, Actions metadata alone, or a synthetic fixture. Original evidence remains unavailable in this authoring session.

The connected GitHub run lookup for SAPPHON-179 commit `d07203a254678fdf7df05a75c1d144c7a8337f87` returned no PR-associated runs and the combined-status endpoint returned no status records. Neither reading decides whether push-triggered Actions ran.

## Committed implementation

- `tools/sapphon_180_bind.py`: validates exact SAPPHON-179 source SHA, workflow `sapphon-179-replay.yml`, job `replay-diagnostics`, positive run/attempt/job/artifact IDs, completed run, named artifact `sapphon-179-provenance-replay`, original byte kinds, SHA-256 values, expiry and parent/job consistency. Rejects empty logs, oversize bytes, changed digests, excerpt substitution and false authority.
- `tools/test_sapphon_180_bind.py`: twelve authored offline tamper and negative-control tests. Fixtures are synthetic and prove only classifier behavior if executed.
- `rust/sapphon-liveness/src/binding180.rs`: Rust equivalent with six authored regression cases and a create-only fsynced HOLD record, additively exported in `lib.rs`.
- `tools/sapphon_171_job_logs.py`: exact SAPPHON-179 workflow/commit/job allowlist pair.
- `.github/workflows/sapphon-180-binding.yml`: independent Python/Rust/historical 188-file checks and source-run observation, plus an original-byte binding stage. If raw bytes and metadata are not separately supplied, it writes `ORIGINAL_BYTES_NOT_SUPPLIED` and never invents them. It excludes raw unredacted log files and ZIPs from uploaded diagnostic artifacts.

## Important provenance boundary

A digest match against metadata supplied by the same GitHub-controlled source **does not prove independently authenticated metadata**. It establishes consistency of the bytes and claimed digest only. SHA-256 cannot turn an owned source into an independent custodian. Also, the older log collector retains only a bounded, redacted excerpt hash; this must never be substituted for the original raw job-log hash.

The source workflow does not silently acquire original job logs or ZIPs. Their absence remains unqualified. No npm integrity values, lockfile promotion, key rotation, lock clearance, operational recovery, or physical external actuation occurs.

## Qualification status

| Criterion | Observation |
| --- | --- |
| Phase XVII source design | 4/8 · 50% |
| Python raw-byte binding regressions | 12 authored; hosted run unverified |
| Rust byte-binding regressions | 6 authored; hosted run unverified |
| Historical 188 frozen records | Read-only check retained; pass unverified |
| SAPPHON-179 original job logs | Not retrieved |
| SAPPHON-179 original artifact ZIP | Not retrieved |
| Authenticated external metadata | Not established |
| npm dependency lock | Provisional, unchanged |
| Live GitHub Pages and Chromium | Deployment and execution unverified |
| Independent custody, anti-rollback, UTC and recovery | HOLD |

## Next bound — SAPPHON-181

**Original-Byte Acquisition and Artifact Manifest Verification.** Acquire real source-owned job-log bytes and artifact ZIP bytes for a fully identified run/attempt/job/artifact, verify original SHA-256 values, record download errors precisely, and prove the ZIP contains the expected diagnostic files without executing archive content. No authority promotion.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
