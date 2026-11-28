# SAPPHON-232 — Three-Witness Readback & Monotonic Checkpoint Qualification (HOLD)

## Predecessor verified
SAPPHON-231 regression [46173226487](https://github.com/DavidWise01/super-sapphon/actions/runs/46173226487) completed SUCCESS on commit `2730d7bc24511cb1aa59517c305c6b0e2a2a67d7`; its [Pages deployment](https://github.com/DavidWise01/super-sapphon/actions/runs/46173226070) also succeeded. These validate source-owned code and deployment, not external custodians.

## Implemented
- `tools/sapphon_232_three_witness_readback.py` checks signed Ed25519 witness attestations, exact bounded readback bytes, canonical checkpoint bodies, receipt ancestry, candidate branch/session digests and locally monotonic checkpoint chains.
- Rejects forged signatures, altered readback hashes, readback body substitution, invalid ancestry, reused witness identity, duplicate public keys, duplicate operator-domain *claims*, unanchored counter prefixes, malformed attestations and inventory overflow.
- Retains all complete local attestations, including competing signed histories. The synthetic workflow exports the verification record as a source-owned artifact.
- `tools/test_sapphon_232_three_witness_readback.py` defines 13 adversarial synthetic cases.
- Three locally signed matching attestations **never** become three independently authenticated witnesses. One process can generate all signatures and readback bytes.

## Independence acceptance gate (not satisfied)
A qualifying readback must be fetched from a separately administered retention system, using a trust anchor established outside this repository's unilateral control; each of three actual witnesses needs independently demonstrated control and ancestry, and an independently checkable monotonic highwater, not a self-asserted identifier. Authentication and custody of one mirrored source do not count as independent corroboration. The operating authority also needs an explicit, authenticated reconciliation policy for retaining and adjudicating both competing branches. Authenticated UTC is not supplied here.

## Status
| Gate | State |
|---|---|
| SAPPHON-231 CI | VERIFIED SUCCESS |
| SAPPHON-231 Pages | VERIFIED SUCCESS |
| SAPPHON-232 readback verifier | COMMITTED |
| 13 adversarial synthetic tests | AUTHORED; CI PENDING |
| Three independent external witnesses | 0 VERIFIED |
| Monotonic external checkpoint | HOLD |
| Real out-of-band durable readback | HOLD |
| Authenticated UTC | HOLD |
| Winner selection / recovery / lock clearance | HOLD |

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`

**Three locally valid signatures do not establish three custodians.**
