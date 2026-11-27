# SAPPHON-187 — Cross-Attempt Artifact Equivocation & Retention Fencing

**Phase XVIII · Bound 3/8 · 37.5% source-design progress · operational HOLD**

## Executive summary

SAPPHON-187 adds a bounded, append-only hash-linked ledger for source-owned GitHub Actions artifact observations. An observation is tied to an exact source SHA, workflow, run ID and run attempt. Two different original artifact identities for the **same run and attempt** trigger `SAME_ATTEMPT_ARTIFACT_EQUIVOCATION`. Different ZIP contents from distinct rerun attempts are not, by themselves, evidence of equivocation.

The pinned source is SAPPHON-186 commit `a18115b4099c0eac6bef1c624efd73573aaffe8e`, workflow `sapphon-186-attempts.yml`, artifact `sapphon-186-exhaustive-attempt-findings`.

At authoring time the connected GitHub wrapper returned no PR-associated workflow runs or combined status entries for the SAPPHON-186 final commit. These interfaces do not exhaustively cover push-triggered runs. No original SAPPHON-186 artifact bytes were retrieved; **actual hosted test pass and original-byte acquisition remain unverified**.

## Committed implementation

- `tools/sapphon_187_ledger.py`: strict observation schema; six distinct `OBSERVED`, `EXPIRED`, `DELETED_OBSERVED`, `READBACK_UNAVAILABLE`, `NOT_FOUND_IN_EXHAUSTED_LISTING`, and `LISTING_INCOMPLETE` states; 10,000-record bound; SHA-256 previous-record link and per-record digest; fail-closed mismatch detection. `DELETED_OBSERVED` requires an explicitly confirmed deletion endpoint and known artifact ID: a missing listing alone cannot establish deletion. API timestamps are untrusted metadata. Its CLI appends a new record, not a rewritten historical ledger.
- `tools/test_sapphon_187_ledger.py`: 17 authored negative-control cases for same-attempt equivocation, distinct attempts, changed historical hashes, broken ancestry, unconfirmed deletion, expiration, unsupported authority and falsely claimed bytes.
- `tools/sapphon_187_acquire.py`: uses the inherited exhaustive GitHub run/artifact pagination, selects the pinned run/attempt, separates expired, absent, unresolved and incomplete artifact states, and inspects the SAPPHON-186 ZIP for exact embedded run/attempt/source identity without extracting archive contents or running archive code. Missing or malformed metadata cannot become an observed ZIP.
- `tools/test_sapphon_187_acquire.py`: eight authored mocked acquisition controls for expired, absent, ambiguous or stale-attempt artifacts.
- `rust/sapphon-liveness/src/retention187.rs`: strict bounded Rust attempt-hash ledger with eight authored tests, create-only fsynced HOLD report and non-authorizing custody fields, registered additively in `lib.rs`.
- `.github/workflows/sapphon-187-retention.yml`: current Python, Rust and historical 188-file diagnostics; read-only SAPPHON-186 attempt acquisition; append observed event to a runner-local ledger; upload sanitized findings and the ledger when available; fail current source diagnostics on actual errors.

## Critical limitations

The ledger is **append-only within its particular retained file and run**. A fresh GitHub-hosted runner does not automatically inherit prior runs' ledger files. No durable cross-run monotonic continuity is established until a previous ledger is explicitly acquired and validated. GitHub's own artifacts may expire or be deleted, so the source-owned chain is not a physically independent anti-rollback system.

`EXPIRED` means the API explicitly reports expiration; `NOT_FOUND_IN_EXHAUSTED_LISTING` means an exhausted source-owned listing omitted the artifact; `READBACK_UNAVAILABLE` means insufficient evidence. None individually proves a physical deletion. GitHub API timestamps do not constitute independently authenticated UTC.

The historical 188 frozen source paths are not rewritten. Provisional npm dependency integrity, independent custody, external UTC, global anti-rollback and operational recovery remain **HOLD**.

## Qualification ledger

| Criterion | Status |
| --- | --- |
| Phase XVIII source design | 3/8 = 37.5% committed |
| Python evidence and acquisition tests | 25 authored; hosted execution unverified |
| Rust retention tests | 8 authored; hosted execution unverified |
| Attempt-linked local append-only ledger | Source committed |
| Historical cross-run chain continuity | Not established |
| Real SAPPHON-186 job and artifact bytes | Not obtained during authoring |
| GitHub source / Pages | Source committed; live deployment unverified |
| 188 inherited immutable historical sources | Read-only check retained |
| npm integrity, external custody, authenticated UTC, anti-rollback | HOLD |
| Key rotation, lock clearance, physical recovery | HOLD |

## Next natural bound — SAPPHON-188

**Cross-Run Ledger Import & Ancestry Continuity.** Explicitly acquire the prior genuine ledger artifact, verify its exact hash-chain tip and source ancestry, and append exactly one new observation without rewriting previous records. Separate missing historical custody from genuine ledger tampering, and keep GitHub-owned continuity distinct from independent external witnesses.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
