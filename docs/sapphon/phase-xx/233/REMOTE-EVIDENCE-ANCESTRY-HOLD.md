# SAPPHON-233 — Out-of-Band Witness Acquisition, Remote Bytes & Ancestry (HOLD)

## Predecessor verified
SAPPHON-232 hosted run [46174340509](https://github.com/DavidWise01/super-sapphon/actions/runs/46174340509) completed SUCCESS on `a7fc00f4f7c0e03d75a70897aa9c813c1b273f54`. [Pages deployment 46174340207](https://github.com/DavidWise01/super-sapphon/actions/runs/46174340207) also completed SUCCESS. This proves hosted source qualification, not third-party storage.

## SAPPHON-233 actual acquisition implementation
- `tools/sapphon_233_remote_acquisition.py`: bounded, TLS-verified HTTPS GET (no redirects), public-host/DNS checks, remote-byte SHA-256, source-declared ancestry grouping, explicit missing/mismatched evidence classification, deterministic evidence-digest report. Limits: 12 target URLs, 1 MiB/readback, 12-second timeout; no credentials or permission to mutate a custodian.
- `qualification/sapphon-233-targets.json`: one immutable-commit URL for the existing SAPPHON-232 report in the owner's GitHub repository. The workflow attempts live network acquisition from `raw.githubusercontent.com`; the acquisition result is captured by the run, not presumed from source configuration.
- `tools/test_sapphon_233_remote_acquisition.py`: 16 fully mocked regressions covering byte equality/mismatch, network failure, private network rejection, duplicate targets, target bounds and ancestry collisions.
- `.github/workflows/sapphon-233-remote-acquisition.yml`: execute regressions; fetch the actual pinned owner-corpus bytes, fail if absent; preserve source-owned acquisition JSON even on failure.

## Trust classification
The pinned endpoint is a GitHub-hosted mirror of the same owned source: **one ancestry**, not an independent witness. Distinct hostnames, public keys, transport sessions or declared operator names do not establish independence. A successful GET is evidence of observed bytes and response status at check time; it is neither authenticated external custody nor durable retention. Cross-session rollback, authenticated UTC and physical custody are unverified. No competing branch is selected, erased or released.

## Qualification states
| Gate | State |
|---|---|
| SAPPHON-232 hosted test | VERIFIED SUCCESS |
| SAPPHON-232 Pages | VERIFIED SUCCESS |
| Remote HTTPS retrieval code | COMMITTED |
| 16 mocked regressions | AUTHORED; HOSTED EXECUTION TO VERIFY |
| Pinned owner GitHub readback | ACQUISITION CONFIGURED; LIVE RESULT TO VERIFY |
| Independent source ancestry | 0 VERIFIED |
| Third-party durable custody | HOLD |
| Global monotonic anti-rollback | HOLD |
| Authenticated UTC | HOLD |
| Recovery and lock clearance | HOLD |

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`

**Observed HTTPS bytes are not independent custody. Past observes; present verifies; future reserves.**
