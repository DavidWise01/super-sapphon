# SAPPHON-156 — Independent Evidence Retention and Dual-Source Readback

**Phase XIV · 4/8 · 50% source-design progression · operational authority HOLD**

## Implemented

The Linux Rust module `rust/sapphon-liveness/src/custody156.rs` compares two allegedly separate acquisition receipts against one separately supplied, expected artifact SHA-256. Each receipt records an acquisition ID, acquisition operator, claimed custody root, source-ancestry fingerprint, artifact digest, Git repository, commit, run ID and attempt.

Classification includes matching but unqualified claims, shared ancestry, reused acquisitions/operators, conflicting artifact digests and conflicts against an externally claimed digest. Contradictory run ID, attempt, repository, or commit cause a hard error. A batch gate rejects repeated acquisition identities; identical readback records cannot acquire new independence just by changing display labels.

A byte-for-byte agreement across two receipts means only that their claimed digests match. **It does not prove the receipts were independently retrieved, genuinely witnessed, physically separated, or retained against rollback.** A GitHub Pages copy and a GitHub Actions artifact belong to the same owned-source ancestry unless an external, authenticated custodian genuinely provides a distinct root.

## Nine Rust regressions authored

1. Two matching, different claimed roots remain HOLD.
2. Distinct labels but equal ancestry fingerprint are not independent.
3. Same declared GitHub custody root is detected.
4. Divergent artifact digests are recorded.
5. Both matching each other but not matching the externally retained digest are rejected.
6. Replayed acquisition ID cannot count twice.
7. Different run attempts fail closed.
8. Reordering receipts preserves deterministic report digest.
9. Create-only report output denies overwrite.

## GitHub Actions

`.github/workflows/sapphon-156-custody.yml` runs all liveness and inherited Rust tests, 188 historical frozen-source hash assertions, HOLD source invariants and Rust documentation. It creates a run-scoped GitHub observation artifact carrying the exact GitHub commit, run ID, attempt and a **single GitHub source ancestry label**. It deliberately does **not** manufacture a second independent custodian.

The immutable receipt claim requires an external SHA-256 retention and authentication mechanism. File-system `create_new` and `fsync` do not constitute a physical append-only/WORM vault.

## Qualification state

The GitHub source, integration, workflow and viewer are committed. Completed Rust tests, the historical freeze run, artifact upload and deployed Pages runtime are not independently verified from current available API results. Independent custody and anti-rollback are HOLD. No key promotion, lock clearance, or recovery occurs.

## Next natural bound — SAPPHON-157

Externally held receipt acceptance: define a clearly separated custody enrollment ceremony, verify independent readback signatures and provenance roots against outside-retained keys, and refuse operator-owned substitute witnesses. Real physical custody qualification remains HOLD until such external observations are authenticated.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
