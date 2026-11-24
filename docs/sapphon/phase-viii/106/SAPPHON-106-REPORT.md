# SAPPHON-106 — Physical Source Admission Manifest & Calibration Evidence

**Phase VIII milestone:** 2 of 8 · 25%.

## Delivered
- `tools/sapphon_106_admission.cjs`: signed physical-source intake envelope validation, strict source-custody admission schema, calibration-reference and measurement-digest binding, explicit uncertainty floors, bounded measurement time windows, and source ancestry checking.
- `tools/test_sapphon_106_admission.cjs`: positive structural acceptance plus negative trials for missing custody receipts, invalid reference report hashes, unsupported uncertainty claims, forged signer declarations, wrong ownership, missing evidence digests and shared root ancestry.
- `docs/sapphon/phase-viii/106/index.html`: interactive neon explanatory laboratory preserving three red/green/blue physical pump rings, eight phases, center `{{i}}`, and four frozen clock registers.
- `.github/workflows/sapphon-106-admission.yml`: blocks project qualification when source admission tests fail; checks both Phase VI and Phase VII freeze manifests.

## Required real-source admission package
1. Enrolled source public key, immutable root identity, and independently authenticated ownership.
2. External custodian identity, signed custody receipt, independently retained anchor, and an independent verifier's authenticated identity.
3. Traceable calibration reference, report digest, calibration-chain digest, validity interval, and uncertainty budget.
4. Timestamp observation and measurement-series digests, capture interval, supported time scale (UTC or TAI), measured uncertainty, and documented comparison method.
5. Source lineage with independently corroborated ancestry; the same root or ancestor cannot be reused as an independent verifier.
6. Separately retained calibration, custody, observation, chain-of-custody and verification evidence bundles.

## Evidence interpretation
A structurally complete package is not a physically verified source. Hash strings establish only asserted identifiers until the referenced documents and their provenance are actually retrieved and authenticated; source time and uncertainty remain claims. The current exercise uses synthetic signatures and invented fixture references. It does not attest actual UTC or certify any independent organization.

**Admission decision: HOLD** until externally obtained custody credentials and independently verified physical clock measurements exist. The original eight synthetic clock observations and both frozen phases remain unchanged.

## Next natural bound
**SAPPHON-107 — Evidence Retrieval Integrity & Cross-Document Traceability.** Verify supplied bundle bytes against admission-manifest SHA-256 identifiers, check exact cross-document lineage and calibration references, and reject missing or contradictory evidence. Physical authority remains gated.

`.dlw`
