# SAPPHON-107 — Evidence Retrieval Integrity & Cross-Document Traceability

**Phase VIII:** 3/8 · 37.5%  
**Verified GitHub Actions:** 20/20 new actual-file and cross-document tests; 23/23 inherited source-admission tests; 18/18 inherited evidence-intake tests; 11/11 Phase VI frozen hashes; 45/45 Phase VII frozen hashes.

## Delivery
- `tools/sapphon_107_evidence.cjs` reads eleven **actual local JSON evidence files** from a caller-provided directory and compares SHA-256 over the exact raw bytes, not only strings in a claimed manifest.
- Strict evidence roles: custody receipt, retained anchor, calibration report, traceability chain, observation, measurement series, custody bundle, calibration bundle, measurement bundle, chain-of-custody record, and verification record.
- The verifier links those records to the SAPPHON-106 signed dossier and checks source identity, custody root, anchor identity, calibration reference, uncertainty, capture interval, time scale, measurement series, and dependent bundle digests.
- Validation refuses missing files, symlink path escape, directories pretending to be files, malformed JSON, oversized files, mutated bytes, and correct-digest but **contradictory** source/custody/calibration documents.
- `tools/test_sapphon_107_evidence.cjs` assembles its own 11-file deterministic synthetic fixture at runtime, including real SHA-256 calculations and negative cases in which a changed document's digest is updated but its meaning contradicts the rest of the dossier.
- `docs/sapphon/phase-viii/107/index.html` displays a neon explanatory audit with the original three R/G/B pump rings, eight phase positions, nested `{{i}}`, four frozen registers, and preservation of the synthetic archived clock.
- `.github/workflows/sapphon-107-evidence.yml` blocks CI on test failure and re-verifies both sealed software phases.

## Trust boundary
The verifier operates on local files supplied by the runner. It does **not** fetch or authenticate a real external custodian, confirm physical measurement acquisition, independently attest the provenance of the JSON documents, or verify true UTC. A file digest establishes only that the file bytes match the claimed digest. The synthetic fixtures remain one owned evidence ancestry. **Physical-clock authority and external custody qualification remain HOLD.**

## Next natural bound
**SAPPHON-108 — Cross-Origin Acquisition Receipts & Independent Byte Witnesses.** Define source-transport acquisition receipts, independently anchored download references, and safeguards against two mirror URLs being mistaken for independent acquisition evidence. Require actual externally supplied data before claiming external corroboration.

`.dlw`
