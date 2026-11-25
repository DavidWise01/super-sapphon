# SAPPHON-127 — Publication Equivocation & Source-Ancestry Cross-Check

**Phase X:** 7/8 · 87.5% software milestone.  
**Verified CI:** 32/32 SAPPHON-127 equivocation tests; 38/38 SAPPHON-126 freshness and publication partition tests; 39/39 SAPPHON-125 replica/high-water tests. All frozen prior-phase software hashes preserved: VI 11, VII 45, VIII 42, IX 42 = 140/140.

## Delivered

- `tools/sapphon_127_equivocation.cjs` implements an append-only-in-semantics local audit journal for signed publisher snapshots and their observed provenance. Each signed SAPPHON-125 snapshot is verified against a pinned Ed25519 publisher key before admission.
- Two distinct valid signed payloads from **the same publisher ID at the same generation** constitute publication equivocation. The journal preserves both snapshots and creates a conflict record rather than selecting either as authoritative.
- One publisher snapshot seen through different surfaces (e.g., the repository and its GitHub Pages mirror) is recorded with separate observation paths but the **same declared ancestry**. The report indicates shared ancestry and does not inflate the independent-witness count.
- The journal validates conflict evidence links: deleting the conflict ledger while the two signed forks remain triggers `MISSING_EQUIVOCATION_RECORD`; removing a retained observation referenced by a conflict triggers `JOURNAL_CORRUPT`. Each local write uses an exclusive directory lock and temp-file fsync+rename+directory-fsync.
- `tools/test_sapphon_127_equivocation.cjs` runs 32 local-file checks covering multiple signed forks, same-source mirrors, publisher-key forgery, revoked/unknown publisher, inconsistent local journal state, ancestry claims, duplicate observations and absence of actual external authority.
- `docs/sapphon/phase-x/127/index.html` retains three R/G/B neon pump rings, eight synthetic archive positions, central `{{i}}`, four clock registers and observation-only equivocation and ancestry explanations.
- `.github/workflows/sapphon-127-equivocation.yml` gates the new suite, inherited SAPPHON-126 and 125 suites, JavaScript parse verification and all four frozen phase manifests.

## Trust and qualification boundary

Signed publication conflicts prove only that the enrolled test signing key signed incompatible claims, **conditional on the pinned key and the retained journal**. The record is locally writable, not an authenticated outside append-only witness. A privileged attacker with access to both journal and publisher signing key can remove or rewrite history absent real external custody. Even when multiple distinct ancestry root labels appear, their actual organizational independence has not been proven.

Github and GitHub Pages are one source ancestry for this corpus. Source duplication, copied signed evidence and separate URLs are not independent witnesses. This test deliberately never chooses a winner or upgrades a quorum of artificial sources into outside authority.

**Independent publisher custody: HOLD · Outside high-water history: HOLD · Global publication truth: HOLD · Physical clock and UTC: HOLD.**

## Next natural bound
**SAPPHON-128 — Phase X Final Byzantine Publication Audit, Real Chromium Acceptance & Immutable Software Freeze.** Finish Phase X (8/8); run adversarial cases for forked snapshots, correlated mirrors, stale signer keys, off-line counterfeit freshness and altered conflict ledgers. Verify the interactive viewer in real Chromium and SHA-256 freeze Phase X source files, without modifying any inherited frozen phase.

`.dlw`
