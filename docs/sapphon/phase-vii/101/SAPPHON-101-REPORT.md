# SAPPHON-101 — External Anchor Export & Historical Fork Detection

**Phase VII:** 5/8 · 62.5%  
**State:** Executable verification and externally retainable *custody-request* anchor. No independent custodian is connected or claimed.

## Delivered
- `tools/sapphon_101_anchor.cjs`: verifies the governance-signed enrollment checkpoint from SAPPHON-100, fixes its SHA-256 ledger head, exact sequence length, checkpoint signature, and trusted public-key fingerprint.
- Compares later signed ledger histories against the retained historical prefix, rejecting altered past events even when a replacement branch is re-signed with the same governance key.
- Rejects rollback, truncated histories, same-height re-signed forks, longer forks, altered pinned heads, public-key substitution, false independent-retention declarations, and fabricated UTC claims.
- `tools/sapphon_101_export.cjs`: produces a new JSON anchor for separately managed custody. The file is deliberately marked `independently_retained: false`. This tool does not establish external trust; it only makes the checkpoint transferable.
- `tools/test_sapphon_101_anchor.cjs`: isolated proof scenarios using temporary Ed25519 governance and source keys.
- `docs/sapphon/phase-vii/101/index.html`: neon three-pump and four-register visualization, with illustrated fork, rollback, and valid continuation states.
- GitHub Actions runs tests and checks all 11 frozen Phase VI file hashes.

## Operator export contract

```sh
node tools/sapphon_101_export.cjs audit.json trusted-public.pem governance-key-id /path/outside-repo/anchor.json
```

For a later checkpoint, pass the previous audit and previously retained anchor as additional arguments. The trusted public key and retained anchor must originate outside the current untrusted submission, otherwise verification is circular.

## Critical distinction

A checkpoint stored in the **same GitHub repository** as the ledger is an owned mirror, not an independent witness or external custody anchor. The runnable tests demonstrate how comparison *would* detect a rewritten ledger if an earlier trusted head was independently retained. Real independent storage and cryptographic custody acknowledgement have not yet been implemented. The archived eight synthetic clock records remain unsigned; no physical clock authority or UTC truth has been inferred.

## Next natural bound

**SAPPHON-102 — Custody acknowledgement schema and receipt verification.** Record independently signed custodian receipts for exported anchors, validating signatures and non-overlapping ownership ancestry before treating them as externally held.

`.dlw`
