# SAPPHON-142 — Deterministic Evidence Export & Cross-Checkpoint Disagreement

Phase XII · 6/8 · 75% design progression · operational authority HOLD

## Scope
`rust/sapphon-liveness/src/export142.rs` assembles an exact-versioned evidence bundle with registry sequence/head, old and new witness-history digests, sorted Ed25519 receipts, witness ancestry and custodian declarations, and explicit conflict findings.

It verifies the prior history against a supplied SHA-256 digest, checks the supplied registry transcript against its sequence/head, screens duplicate declared ancestry/custody roots, checks receipts using SAPPHON-141's signature and monotonic-counter validation, and refuses an export if conflicting checkpoint heads are found. Records are exported with deterministic JSON encoding and SHA-256 digests.

The create-only writer fsyncs a new export and its directory. It never overwrites an existing evidence file. Re-reading with the expected export digest detects ordinary byte tampering.

## Six Rust tests authored
- Deterministic export and permanent HOLD
- Shared declared ancestry rejection
- Conflict with retained witness history
- Tampered export digest rejection
- Create-only evidence preservation
- Incorrect trusted history anchor rejection

## Limitations
This code makes claims about *supplied* ancestry fields. It cannot authenticate independent organizational or physical custody. Two keys, mirrored GitHub pages, and two copied receipts are not independently witnessed evidence. A co-controlled registry, history and anchor could be replaced together. Filesystem hostile-writer or crash guarantees are not independently qualified. The export does not authorize recovery, certify UTC, provide global anti-rollback, or modify a checkpoint acceptance floor.

The new CI workflow `.github/workflows/sapphon-142-export.yml` runs the crate tests, inherited Rust security suites, the 188 historical frozen hashes, and explicit HOLD assertions. Source publication alone does not prove execution or deployment.

## Next natural bound — SAPPHON-143
Cross-source ancestry adjudication: bind custody claims to independently provisioned trust roots, preserve contradictory packets, and run blinded adversarial tests without promoting matching content to independent testimony.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
