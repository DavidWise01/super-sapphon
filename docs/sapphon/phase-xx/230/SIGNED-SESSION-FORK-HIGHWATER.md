# SAPPHON-230 — Competing Signed Session Heads & Externally Anchored Highwater HOLD

## Verified predecessor

SAPPHON-229 final regression run [46168553616](https://github.com/DavidWise01/super-sapphon/actions/runs/46168553616), source commit `512706f920368eb0b8f57903daf71737b8b96abc`, completed **SUCCESS**. Its final 17 regression cases included malformed terminal head rejection. GitHub Pages deployment for that commit completed **SUCCESS**. Its evidence artifact `15273225033` records source-owned structural session parity and a deliberately rejected truncated history. The original frozen source-owned OCI image continues to bind to run `46154833375`, source SHA `c167a95a05177e280625fa61613c1b1fa20f75e9`, and image TAR SHA-256 `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197`.

## SAPPHON-230 implementation

- `tools/sapphon_230_competing_sessions.py` independently re-verifies each submitted full-session ACK history and its terminal Ed25519-signed head using the SAPPHON-229 gate.
- An append-only source-owned evidence body retains every complete candidate, every signature, session-set digest, counter and head digest, including both conflicting candidates for the same recorded count.
- Differing valid terminal hashes at the same count become `SIGNED_SESSION_FORK_PRESERVED_HOLD`, not a selected winner. A separately supplied signed external head is reverified against the supplied public-key anchor and each candidate. If it matches one candidate, the other signed branch remains preserved; no supplied head can unilaterally resolve the fork.
- Rejects stale or modified head, changed original source bundle, missing session history, duplicate candidate identities, malformed candidate inventory, or excessive candidate count (limit 16).
- `tools/test_sapphon_230_competing_sessions.py` provides 16 locally signed regression scenarios, including competing branch preservation, digest alteration, head-key mismatch, stale external head, candidate substitution, and no witness promotion.
- `.github/workflows/sapphon-230-session-fork.yml` independently executes the regression suite in GitHub Actions and retains two **synthetic** complete competing-session evidence records. Neither is an external witness.

## Trust boundary

Cryptographic validity proves a key signed a claimed head, not that its identity or external custody was independently authenticated. An externally labeled head supplied through this GitHub pipeline is not a separately controlled monotonic clock, independent custody store or global anti-rollback authority. Across disconnected sessions, global rollback is still possible without a physically independently held, authenticated checkpoint. The original conflict is observation-only: **no signed candidate is erased, elected, released or reclassified as authoritative**.

**GitHub-owned image and source parity verified · Signed competing sessions test implemented · Independent witnesses 0 · Authenticated UTC unverified · Global anti-rollback unverified · Recovery HOLD · Lock cleared FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
