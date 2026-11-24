# SAPPHON-099 — Source Enrollment & Revocation Ledger

**Phase VII:** 3/8 · 37.5%  
**Verified:** 22/22 source lifecycle checks, 22/22 inherited signed-chain checks, 16/16 inherited Ed25519 checks. Eleven Phase VI freeze file hashes still match.

## Delivered

- `tools/sapphon_099_enrollment.cjs`: software-governed, Ed25519-signed append-only source enrollment, revocation, and re-enrollment.
- The ledger preserves predecessor hashes, event indexes, key identity, generations and immutable historical entries.
- Enrollment and revocation are signed by a dedicated *test governance key*, separate from the source's observation key.
- Re-enrollment after revocation requires a new key identity, a different key, the correct next generation and **the same ancestry root**.
- A revoked key cannot be returned by the active trust store; it cannot sign future accepted events.
- Failed validation does not mutate previously accepted ledger entries.
- A second declared source identity is not assumed to have independent ancestry.

## Synthetic demonstration

CI creates temporary Ed25519 governance and source keypairs and executes: **ENROLL Key A → REVOKE Key A → REENROLL Key B**, with one shared source root. This is an authenticated *test ledger*, not independently attested source enrollment in the real world. No private key is committed to GitHub.

## Risks and limitations

GitHub Actions validates the software and synthetic signatures. It does **not** grant physical clock authority, prove UTC, or authenticate governance identity outside the test. SHA-256 chaining detects changes relative to an available trusted head; a fully rewritten ledger and replaced trust root require an external anchor to detect. Lifecycle operations are not yet integrated into a production clock producer. The existing Phase VI clock observations remain archived, unsigned synthetic events.

## Interface

The HTML page at `docs/sapphon/phase-vii/099/index.html` shows the three physical R/G/B pumps with eight positions, nested center `{{i}}`, four original logical clock registers and a selectable lifecycle timeline.

## Next natural bound

**SAPPHON-100 — Independent enrollment audit and signed ledger checkpoint exports.** Add read-only export and independent head verification while ensuring source ownership and witness independence are not conflated.

`.dlw`
