# SAPPHON-126 — High-Water Freshness Challenge & Publication Partition Recovery

**Phase X:** 6/8 · 75% software milestone.  
**CI success:** 38/38 new SAPPHON-126 freshness and partition checks; 39/39 SAPPHON-125 replica/high-water checks; 41/41 SAPPHON-124 current-credential revocation checks. All 140 frozen source files from Phases VI, VII, VIII and IX preserve their original SHA-256 hashes and byte lengths (11 + 45 + 42 + 42).

## Delivered
- `tools/sapphon_126_freshness.cjs` adds a durable local freshness-verifier journal. A canonical challenge binds the verifier ID, publisher ID, unique 256-bit nonce, minimum requested high-water generation, issuance logical tick, and bounded expiration tick.
- The pinned publisher signs a response binding that exact nonce, verifier, publisher, signing-key generation, snapshot SHA-256, and snapshot generation. Admission checks both the response signature against the **current local pinned publisher key** and the referenced SAPPHON-125 snapshot's Ed25519 signature.
- A publisher-key rotation increments the current local pin generation. Delayed signatures from the old key are rejected by `PUBLISHER_ROTATION_FENCE`; the newest key can answer a pending synthetic challenge if it also supplies a valid snapshot under the new current key.
- The verifier fails closed for unavailable publisher connection, absent snapshot, expired response, changed verifier ID or nonce, mismatched snapshot digest or generation, stale snapshot below requested high-water generation, corrupted journal, lock contention and reused nonce. Successful test consumption is durably recorded once.
- `tools/test_sapphon_126_freshness.cjs` exercises 38 acceptance and adversarial scenarios. Two early CI runs exposed test-fixture construction errors in forged-signature and rotated-key scenarios; after correcting those fixture paths, full GitHub Actions acceptance passed.
- `docs/sapphon/phase-x/126/index.html` preserves the three neon R/G/B pump rings, eight synthetic phase positions, center `{{i}}`, four inherited archive clock registers and observation-only freshness, partition and rotation diagnostics.
- `.github/workflows/sapphon-126-freshness.yml` executes the new freshness suite, the inherited SAPPHON-125/124 suites, viewer JavaScript parsing and the 140 inherited immutable hashes.

## Qualification boundary
The signed fresh-nonce response demonstrates **possession of the presently pinned synthetic publisher key**, bound to the verifier challenge, with local logical-tick expiry. It does **not** establish that a remote signer is really live, that a signed snapshot reflects the latest global revocation, that an outside custodian independently retains the high-water mark, or that the publisher's clock is truthful.

The fixture's issuer, publisher keys and signing history remain under local test control. A dishonest publisher with an active signing key can still sign an obsolete high-water snapshot in answer to a fresh challenge unless a genuinely independent monotonic publication authority is also verified. Joint rollback of the verifier journal, publisher pins and authority records likewise remains beyond this model's detection.

**Real external freshness: HOLD · Independent custody: HOLD · Globally authoritative revocation: HOLD · Physical clock and UTC: HOLD.**

## Next natural bound
**SAPPHON-127 — Publication Equivocation & Independent High-Water Cross-Check.** Present two incompatible, validly signed snapshots from the same source; record conflicting publisher claims without manufacturing independent witnesses, and make all conflicting freshness claims fail closed.

`.dlw`
