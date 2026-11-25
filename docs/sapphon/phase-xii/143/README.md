# SAPPHON-143 — Blind Ancestry Screening and Conflict Quarantine

**Phase XII · 7/8 · 87.5% design progression · operational authority HOLD**

## Source
- Rust implementation: `rust/sapphon-liveness/src/quarantine143.rs`
- CI workflow: `.github/workflows/sapphon-143-quarantine.yml`
- Neon evidence viewer: `docs/sapphon/phase-xii/143/index.html`

## Boundary
This phase creates a **quarantine** evidence artifact separate from the clean SAPPHON-142 export. When the same witness submits different heads for the same sequence, both raw receipt claims remain in the quarantine packet together with a structured `BATCH_EQUIVOCATION` or `CONFLICTING_HEAD` finding.

Blind ancestry screening compares registry ancestry roots, public key fingerprints, and claim relationships without using friendly display names or relying on matching content as independent testimony. It flags shared declared ancestry and reused public keys. Since the registry fields are provided by the caller, the detector cannot authenticate custodial independence.

The artifact is deterministic JSON, SHA-256 addressed, create-only, and fsynced on creation. Repeated attempts to write the same path are rejected. The digest must be retained outside the writable archive to make tampering detection meaningful.

## Tests authored
1. Conflicting heads in the same batch remain visible and cause a quarantine finding.
2. Matching content with shared ancestry is not counted as independent evidence.
3. Deterministic packet digest and tampering detection.
4. Prior history digest mismatch fails closed.
5. Previously created packet cannot be overwritten.

## Explicit limits
The packet marks cryptographic authentication `NOT_PERFORMED`: capturing a raw receipt is not a signature check. Contradictions are documented, not settled. No quarantine output asserts independent custody, independent witness count, global anti-rollback, secure UTC, or recovery authority. `AUTHORITY = HOLD` always.

GitHub Actions includes inherited Rust regressions and the 188 historical hash freezes. Test success and Pages deployment require independent run readback; source publication alone does not qualify them.

## Next natural bound — SAPPHON-144
Phase XII evidence freeze: verify all Rust security regressions in CI, ensure quarantine evidence remains append-only, test conflicting packets from common source ancestry, and produce a no-authority final report. An independent custody root is still required before any operational qualification.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
