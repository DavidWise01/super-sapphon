# SAPPHON-179 — Provenance-Bound Failure Replay

**Phase XVII · bound 3/8 · 37.5% source-design progress · operational HOLD**

## What is new

SAPPHON-179 requires actual pinned evidence before producing a targeted diagnostic replay plan. The predecessor is commit `71931a8602229cecad921297aabe633e810fb211`, workflow `sapphon-178-isolation.yml`, expected job `failure-isolation`.

The GitHub connector's PR-run and legacy commit-status readbacks returned empty collections for this commit. That cannot establish what happened with push-triggered Actions. **No actual SAPPHON-178 job log or compiler failure was obtained in this authoring turn.** Missing evidence is not a failed test.

A local Python implementation was executed with **13/13 synthetic regression cases passing** before the corresponding code and tests were committed. Those cases establish classifier behavior, not actual hosted Actions execution.

## Changes committed

- `tools/sapphon_179_replay.py`: bounded 1 MiB evidence input, optional exact SHA-256 digest comparison over original bytes, fixed source/workflow/job/run/attempt checks, distinct required Python/Rust/historical step outcomes, rejection of forged authority and contradictions, and a fixed allowlist of review-only diagnostic commands. Never runs arbitrary evidence-derived commands.
- `tools/test_sapphon_179_replay.py`: 13 adversarial tests covering tampering, missing or wrong ancestry, missing/boolean attempts, duplicated/unknown steps, green parent with failed child, genuine failure-plan isolation, and a clean success with no replay plan.
- `tools/sapphon_179_verify_frozen.py`: standalone read-only verifier for the exact 188 protected historical paths, lengths and SHA-256 records.
- `rust/sapphon-liveness/src/replay179.rs` and module declaration: Rust failure-plan classifier with six authored tests and create-only fsynced HOLD evidence.
- `.github/workflows/sapphon-179-replay.yml`: executes current source checks independently of predecessor API access, acquires exact pinned SAPPHON-178 evidence when available, creates a non-executing replay plan, inspects the unchanged provisional lockfile, uploads all findings and fails on current source diagnostic failures.

## Evidence ledger

| Criterion | Result |
| --- | --- |
| Phase XVII source design | 3/8 = 37.5% |
| Local Python replay classifier | 13/13 synthetic tests executed and passed |
| Hosted Rust / Python CI | Not confirmed passing |
| SAPPHON-178 pinned job log | Not retrieved |
| Historical 188 frozen files | Read-only verification configured; hosted outcome pending |
| Original-byte SHA-256 evidence pin | Supported; requires supplied digest |
| Playwright npm lock integrity | Provisional; not modified |
| Live Pages / browser | Source publication only; deployment unverified |
| External custody / global anti-rollback / authenticated UTC | HOLD |
| Recovery / lock clearance | HOLD |

GitHub source, Actions, and Pages are a single owned ancestry, not three independent external witnesses.

## Next natural bound — SAPPHON-180

**Authenticated Failure-Artifact Replay:** obtain real failed-job log bytes and artifact digests, cross-check against exact run/attempt, reproduce only the matching deterministic test locally or on a pinned hosted runner, and preserve explicit unavailable-evidence outcomes rather than inventing success.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
