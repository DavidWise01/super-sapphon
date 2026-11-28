# SAPPHON-234 — Custodian Challenge–Response, Retention Claim & Replay Resistance HOLD

## Verified predecessor
SAPPHON-233 final Actions run [46175864554](https://github.com/DavidWise01/super-sapphon/actions/runs/46175864554) completed SUCCESS on commit `f6a5d876425b87366e7de154f225def244b260df`. Its final [Pages deployment](https://github.com/DavidWise01/super-sapphon/actions/runs/46175863641) also completed SUCCESS. The live owner-corpus readback from SAPPHON-233 remains one source ancestry, not independent custody.

## SAPPHON-234 source qualification
- `tools/sapphon_234_challenge_response.py` verifies nonce-bound Ed25519 challenge responses over a canonical signed payload containing requested and claimed readback digests, witness identifier, replay epoch, and previous response digest.
- Rejects repeated nonces in a batch or supplied prior nonce ledger, wrong requested hashes, response substitution, signature modification, missing responses, unanchored nonzero epochs, duplicate witnesses, and broken or stale local response ancestry.
- Each accepted response generates a proposed replay ledger update. The report explicitly sets `replay_state_committed=false`. Source-owned files do not prove independently durable nonce history.
- `tools/test_sapphon_234_challenge_response.py` provides 14 synthetic cryptographic and adversarial tests.
- `.github/workflows/sapphon-234-challenge-response.yml` runs the tests and retains three synthetic locally signed challenge-response records. This is source-owned test evidence, not remote custodian participation.

## Unmet authority conditions
A real external custodian must receive a fresh verifier-generated challenge over a separately authenticated and independently administered transport, retrieve and return independently held evidence bytes, and provide a signature verifiable against an independently provisioned custody key. A durable, independently read-back nonce/sequence ledger must prevent replay and rollback across sessions and across verifier restarts. The custodian must show that historical competing signed branches remain retained. One locally supplied signature, URL, operator label, or replay proposal cannot establish these conditions.

## Qualification
| Criterion | State |
|---|---|
| SAPPHON-233 Actions | VERIFIED SUCCESS |
| SAPPHON-233 Pages | VERIFIED SUCCESS |
| SAPPHON-234 nonce-bound verifier | COMMITTED |
| 14 adversarial regression scenarios | AUTHORED; HOSTED RESULT TO VERIFY |
| Locally created synthetic signed responses | CONFIGURED |
| Independent witness authentication | 0 VERIFIED |
| External durable retention / replay store | HOLD |
| External monotonic highwater | HOLD |
| Global anti-rollback / authenticated UTC | HOLD |
| Recovery authorization / lock clearance | HOLD |

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`

**Nonce freshness qualifies one interaction; durable independent custody remains separate evidence.**
