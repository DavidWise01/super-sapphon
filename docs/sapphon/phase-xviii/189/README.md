# SAPPHON-189 — Custody-Rooted Cross-Run Fork Detection

**Phase XVIII · Bound 5/8 · 62.5% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-189 introduces a root-claim comparator which detects disagreements between SHA-256 ledger roots that carry the **same source SHA, run ID, attempt and lineage ID**. Different roots from distinct attempts are not automatically equivocation. All claims are explicitly classified as **one GitHub-owned ancestry**. Multiple GitHub APIs, GitHub Pages and GitHub Actions must not be counted as independent custodians.

Pinned predecessor: SAPPHON-188 commit `011ad7d5623d7d5db8ec2183bcf7207a0e8ec42c`, workflow `sapphon-188-import.yml`, artifact `sapphon-188-ancestry-continuity`.

The accessible commit-level GitHub lookup returned no PR-associated runs and no combined checks for the predecessor. These results are not an exhaustive push-run search. No genuine SAPPHON-188 original archive, independent custody receipt or verified CI PASS was obtained during authoring.

## Source implementation

- `tools/sapphon_189_forks.py` — bounded maximum 64 claims; fixed source/workflow/artifact identities; positive run/attempt; literal `github-owned` custodian; declared GitHub surfaces only; SHA-256 root validation; missing evidence with no fictional digests; exact-lineage fork detection; zero independent witnesses; no recovery or lock clearance.
- `tools/test_sapphon_189_forks.py` — 16 authored synthetic cases: matching mirrors, conflicting roots, distinct attempts, missing/unavailable hashes, duplicate surface entries, forged custody and malformed identities.
- `tools/sapphon_189_acquire.py` — read-only GitHub Actions API discovery using bounded complete pagination, exact predecessor SHA, original ZIP read in memory, ZIP member and attempt identity checks. Compares `188-import.json` against `188-transition.json` within the same archive and rejects an internal root conflict. Emits **one** owned GitHub claim at most, not two fabricated witnesses.
- `tools/test_sapphon_189_acquire.py` — 9 authored mocked cases for missing and expired originals, wrong attempts, changed roots, forged authority, absent transition and duplicate ZIP members.
- `rust/sapphon-liveness/src/forks189.rs` — Rust same-lineage root comparator, 7 authored negative controls, create-only fsynced HOLD record, integrated additively in `lib.rs`.
- `.github/workflows/sapphon-189-forks.yml` — Python and Rust regression checks, read-only historical 188-file verifier, actual original-artifact attempt and fork adjudication, and sanitized GitHub-owned metadata uploads.

## Evidence hierarchy

Matching two copies of a ledger root is useful for detecting corruption or inconsistency *within the ancestry that owns both copies*. It cannot prove independent external custody. A self-declared external name, duplicate GitHub endpoints, or a displayed Pages rendering cannot establish a third-party witness. A missing original ZIP is `NOT_OBSERVED`, not a fork and not PASS.

Root conflict within one original ZIP is classified separately as `INTRA_ARTIFACT_ROOT_CONFLICT`. It is not falsely described as two independent witnesses.

## Qualification ledger

| Dimension | State |
| --- | --- |
| Phase XVIII source design | **5/8 · 62.5% committed** |
| Python fork + acquisition cases | 25 authored; hosted run unverified |
| Rust fork-detection cases | 7 authored; hosted run unverified |
| Exact source/run/attempt root comparator | Source implemented |
| Actual SAPPHON-188 predecessor artifact | Not obtained during authoring |
| Independent witness count established | **0** |
| Historical 188 frozen files | Read-only verifier retained |
| Successful hosted CI | Unverified |
| GitHub Pages/Chromium | Source publication; live deployment unverified |
| npm lock integrity, authenticated UTC, global anti-rollback | HOLD |
| Physical recovery and key rotation | HOLD |

## Next natural bound — SAPPHON-190

**Independent Custody Enrollment & Receipt Ancestry.** Define an independently held, externally authenticated custody receipt with a real verifying key and proof-of-possession boundary; detect replayed, self-issued and colluding custody claims. Until a genuinely independent receipt is supplied and verified, the witness count remains zero and all authority HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
