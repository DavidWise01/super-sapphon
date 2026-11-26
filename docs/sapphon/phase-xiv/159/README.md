# SAPPHON-159 — Externally Pinned Nonce-Consumption Ledger & Fork Detection

**Phase XIV · Bound 7/8 · 87.5% source-design progression · operational authority HOLD**

## Executive summary

A Linux Rust module, `rust/sapphon-liveness/src/nonce159.rs`, adds signed, domain-separated nonce-consumption events chained from a deterministic genesis, with exact historical-prefix comparison against a **separately supplied** checkpoint sequence/head and retained counter floor. The module verifies each event's Ed25519 signature against the supplied provisioned key, requires strictly increasing sequence and counter, and rejects repeated nonce digests, transcript substitutions, forged signatures and rollback below the supplied floor.

**Important:** the module does not authenticate that its supplied floor, provider key or challenge history was actually retained outside GitHub, nor that the signing key has a physically independent owner. Only an external trusted service can establish those facts.

## Fork analysis

Two individually valid histories must share the same supplied trusted floor before comparison. Same height + different authenticated event heads is classified `EquivocationAtSameSequence`. Same height + same head is `MatchingHead`. Different heights are `DifferentUnqualifiedHeights`: asynchronous observation alone is not proof of a fork. Same-height discrepancy is a structural signed-history conflict, not proof of independent external custody.

A create-only JSON review can be fsynced and SHA-256 addressed, but it does not constitute WORM external storage or global anti-rollback.

## Ten Rust tests authored

1. A valid signed consumption chain remains HOLD.
2. Repeated nonce rejected.
3. Reused counter rejected.
4. Forged event signature rejected.
5. Truncation below trusted sequence rejected.
6. Replacement of signed historical prefix detected.
7. Two conflicting signed heads at the same sequence detected.
8. Unequal observation heights are not automatically equivocation.
9. Valid extension beyond a supplied pinned historical prefix accepted for **inspection only**.
10. Create-only fork review refuses overwrite.

## Publication and qualification

The module is integrated into `rust/sapphon-liveness/src/lib.rs`. The read-only workflow `.github/workflows/sapphon-159-nonce-ledger.yml` runs the Rust liveness crate and inherited recovery, contention, journal and audit suites, checks the historical 188 frozen source files, applies HOLD source assertions and builds API documentation. Any CI artifact is explicitly labeled as a single GitHub-origin observation lacking authenticated external custody.

Rust tests are **authored**, not demonstrated passed. A committed workflow is not a successful completed run. GitHub Pages is published as source HTML, but successful deployment and live Chromium execution require separate confirmation.

## Persisting HOLD barriers

Externally retained and authenticated floor/key/counter, independent custodian provenance, genuine WORM/monotonic facilities, authenticated UTC, global anti-rollback, key promotion, lock clearance and operational recovery remain HOLD.

## Next natural bound — SAPPHON-160, Phase XIV bound 8/8

Final Phase XIV evidence reconciliation: verify actual GitHub Actions and Pages deployment outcomes; preserve all origin, chronology and custody limitations; assemble a frozen cross-module qualification manifest; conclude design only, not physical authority, until independently authenticated external evidence exists.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
