# SAPPHON-231 — Externally Anchored Session-Fork Evidence & Durable Reconciliation HOLD

## Verified predecessor
SAPPHON-230 GitHub Actions run [46169915203](https://github.com/DavidWise01/super-sapphon/actions/runs/46169915203) completed SUCCESS. The hosted `signed-competing-heads` job passed its 16-case step and preserved two synthetic signed competing-session histories. Its corresponding workflow source SHA was `3cbbe16b3d9dd67723aa456fff85d00c1354d4bb`. This is *source-owned* qualification, not independent custody.

## SAPPHON-231 implementation
- `tools/sapphon_231_custody_reconciliation.py` verifies Ed25519 custody-receipt signatures over canonical payloads that bind a candidate session-set digest, terminal branch head, monotonically numbered receipt, predecessor receipt digest and retention identifier.
- The verifier preserves the *complete* signed receipts, both competing heads and the entire predecessor SAPPHON-230 report digest. Duplicate sequence, unanchored prefix, predecessor mismatch, reused retention identifiers, modified signatures, unmatched candidates, forged predecessor digest, and excessive inventory are documented as blockers.
- `tools/test_sapphon_231_custody_reconciliation.py` defines 12 synthetic adversarial scenarios. The dedicated Actions workflow runs them and archives the synthetic receipts, tagged explicitly as source-owned evidence.
- No source-provided custodian name, public key, retention identifier or signature proves third-party administration, physical retention, independently authenticated time, or global anti-rollback.
- No receipt is allowed to elect a signed branch, erase a competing history, certify a witness, clear a lock or authorize recovery.

## Independent custody acceptance contract (not yet satisfied)
An actual independently operated custodian must (1) retain the checkpoint and complete conflicting evidence outside the repository owner's control; (2) authenticate the custody key using an independently established trust anchor; (3) demonstrate durable retention and retrieval of both complete histories; (4) present an independently maintained monotonic sequence or anti-rollback log; and (5) provide an authenticated adjudication procedure that never silently deletes a competing signed history. A self-submitted receipt cannot satisfy these conditions.

## Status
| Criterion | Status |
|---|---|
| SAPPHON-230 hosted regression | VERIFIED SUCCESS |
| Signed custody-receipt verification source | COMMITTED |
| Twelve synthetic custody regressions | AUTHORED; HOSTED EXECUTION TO VERIFY |
| Independent custody witness | 0 VERIFIED |
| Durable external retention | HOLD |
| Trusted global highwater | HOLD |
| Authenticated UTC | HOLD |
| Recovery and lock clearance | HOLD |

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`

**Past observes. Present deserves. Future reserves. Forks remain preserved.**
