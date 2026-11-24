# SAPPHON-108 — Cross-Origin Acquisition Receipts & Independent Byte Witnesses

**Phase VIII:** 4/8 · 50%  
**Verified CI:** 26/26 new acquisition checks; 20/20 SAPPHON-107 byte and cross-document checks; 23/23 SAPPHON-106 physical admission checks; 18/18 SAPPHON-105 signed intake checks. Both frozen baselines remain intact: Phase VI 11 files; Phase VII 45 files.

## Implementation
- `tools/sapphon_108_acquisition.cjs` accepts signed acquisition receipts over exact local evidence bytes, with Ed25519 transport-key verification, byte count, SHA-256, a strict HTTPS source URL, a declared source root and bounded parent ancestry.
- The canonical known-owned group includes `github.com/DavidWise01/super-sapphon`, `raw.githubusercontent.com/DavidWise01/super-sapphon`, and `davidwise01.github.io/super-sapphon`. These are the **same underlying owned project lineage**, not independent witnesses.
- Transport signing keys must be explicitly present in a supplied trust registry, not revoked, and bound to the claimed source root. Reused acquisition identifiers and signing keys fail closed.
- Separately declared roots can be counted as **declared root categories**, but the verifier reports **zero independently authenticated external roots** until independently acquired, externally trusted custody evidence is present.
- `tools/test_sapphon_108_acquisition.cjs` tests actual file reads and negative cases for byte tampering, forged signatures, mirror relabeling, parent-ancestry collisions, duplicate receipts, malformed URL formats and nonexistent byte sources.
- `docs/sapphon/phase-viii/108/index.html` illustrates source ancestry in the original neon three-pump clock viewer, retaining eight sector positions, the central `{{i}}`, and four frozen logical registers.
- `.github/workflows/sapphon-108-acquisition.yml` blocks regression on failures and checks both sealed phases.

## Evidence boundaries

The synthetic fixtures are acquired from local test byte buffers and files, **not from external servers**. The URL stored on a test receipt is a declared identifier, not proof that those bytes were downloaded from that URL. No real independent custodian, externally authenticated acquisition agent, physical clock, or UTC calibration is established. The result is therefore **HOLD** for physical-clock authority and external custody.

A second cryptographic transport signature is independent as a signing event only; without genuinely independent source ancestry and custody, it cannot provide independent confirmation of the underlying observation.

## Next natural bound

**SAPPHON-109 — Independent Transport Provenance & Acquisition Transcript Binding.** Require request/response transcript evidence, pinned transport peer identity, acquisition session isolation and origin-root comparison. Fail closed on replay, redirects to shared ownership, and unverified transport assertions. Keep operational clock qualification on HOLD.

`.dlw`
