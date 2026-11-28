# SAPPHON-235 — Persistent Nonce Highwater, Restart-Safe Replay & Local Fork HOLD

## Verified predecessor
SAPPHON-234 final [Actions run 46176613110](https://github.com/DavidWise01/super-sapphon/actions/runs/46176613110) and [Pages run 46176612641](https://github.com/DavidWise01/super-sapphon/actions/runs/46176612641) both completed SUCCESS at commit `965c2e729846aadf99c78263d7dc9918a98fe5af`. This validates source-owned qualification and deployment, not independently durable custody.

## SAPPHON-235 implementation
- `tools/sapphon_235_local_highwater.py` provides a POSIX local append-only JSON-lines nonce ledger. Each row binds sequence, unique nonce, witness ID, witness epoch, predecessor row hash and its own SHA-256. A cooperating writer takes an advisory `flock`, validates the entire existing chain, appends one line, and `fsync`s the file before returning.
- A new process reopens the ledger and refuses a consumed nonce, a stale witness epoch, malformed or torn tail, broken digest, sequence gap or ancestry mismatch. At a bounded capacity, the ledger refuses further writes instead of overwriting history.
- `compare` preserves two otherwise valid diverging histories and reports their first conflicting sequence. Identical and prefix-related histories remain **HOLD**, too.
- `tools/test_sapphon_235_local_highwater.py` includes 15 cases, including an actual subprocess-restart replay test, forged edits, torn tail, divergent branches and monotonic local epochs.
- `.github/workflows/sapphon-235-local-highwater.yml` runs the 15 cases and archives a synthetic two-branch conflict record.

## Explicit limits
A local POSIX journal, advisory lock and `fsync` provide limited crash and cooperating-writer protection. They do not provide independent custody, a tamper-resistant disk, protection from a privileged replacement of the full journal, network-wide replay protection, authenticated UTC, or protection from coordinated snapshots being rolled back. A directory durability guarantee is not asserted. The retained JSON alone is source-owned evidence.

An independent custodian would need to authenticate a checkpoint outside repository-owner control, retain the current highwater and historical forks, and verify remote readback after a process and machine restart. Distinct URLs or self-reported operator identities cannot satisfy that condition.

## Qualification
| Gate | State |
|---|---|
| SAPPHON-234 hosted qualification | VERIFIED SUCCESS |
| SAPPHON-234 Pages | VERIFIED SUCCESS |
| POSIX append-only nonce journal | COMMITTED |
| 15 restart and fork regressions | AUTHORED; HOSTED STATUS TO VERIFY |
| External monotonic highwater | HOLD |
| Independently authenticated witnesses | 0 |
| External durability / UTC | HOLD |
| Branch reconciliation winner | NONE |
| Recovery authorization / lock clearance | HOLD |

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`

**Past observes. Present persists. Future reserves. Local memory is not external authority.**
