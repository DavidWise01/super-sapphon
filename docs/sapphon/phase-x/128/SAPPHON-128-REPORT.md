# SAPPHON-128 — Phase X Rust-first Adversarial Closure and Software Freeze

**Milestone:** Phase X, 8/8 · 100% software milestone, contingent on final workflow acceptance and SHA-256 freeze publication.

## Rust-primary closure
- `rust/sapphon-audit/src/lib.rs` authenticates synthetic SAPPHON-125 signed snapshot payloads with Ed25519 in the established canonical JavaScript field-array order, validates all retained conflict records and traces declared ancestry.
- `rust/sapphon-audit/src/phase_x.rs` extends the Rust audit across generations: publication equivocation by publisher/generation, missing predecessor links, skipped publication generations, revoked-role resurrection, correlated source ancestry and fail-closed journal validation.
- `rust/sapphon-audit/tests/audit.rs` and `rust/sapphon-audit/tests/phase_x.rs` form the Rust regression suite (15 baseline cases and 12 adversarial Phase X closure tests).
- `tools/test_sapphon_128_browser.cjs` executes the final neon page in an actual Chromium browser and asserts three RGB pumps, four frozen clock registers, diagnostics and zero uncaught JavaScript errors.
- `docs/sapphon/phase-x/128/index.html` provides the final read-only Phase X laboratory with links to the Rust implementation.
- `.github/workflows/sapphon-128-freeze.yml` gates the 27 Rust cases, inherited SAPPHON-121–127 JavaScript tests, real Chromium, viewer safety status and all 140 earlier immutable source hashes. Only after those pass does it generate and commit `docs/sapphon/phase-x/SAPPHON-128-FREEZE.json` from the complete phase source list.
- `tools/sapphon_128_freeze.py` generates deterministic file SHA-256 and exact byte lengths, checks the parent manifests, and excludes the final manifest itself to avoid circular hashing.

## Evidence caveats
Rust Phase X is an **observation-only in-memory / read-only software audit**, not a replacement for all earlier JavaScript execution or a globally transactional provenance service. The Rust audit does not yet reproduce the previous JavaScript fsync/rename file persistence layer, cross-process locking, credential freshness, publisher rotation and remote custodian enrollment. The JavaScript lineage remains available for regression and is never silently replaced.

The synthetic issuer/custodian roots, declared ancestry and test signer keys cannot prove real organizational independence. A correctly signed fresh nonce or snapshot can be supplied by a lying owner; a privileged actor might jointly roll back a local journal and its claimed high-water evidence. Cross-generation anomalies are flags for review, not proof that another source was truthful.

**External custody: HOLD · Independent third-party witness: HOLD · Global anti-rollback: HOLD · Physical clock/UTC: HOLD · Real-world effect authority: HOLD.**

## Next bound

**SAPPHON-129 — Phase XI, 1/8 · Rust Persistent Journal & Crash-Atomic Append Protocol.** Add durable fsync+rename journal writes, exclusive process fencing, hostile restart/replay fixtures and a Rust/JavaScript equivalence regression against the frozen Phase X observations.

`.dlw`
