# SAPPHON-229 — Cross-Session Signed ACK History, Replay & Highwater Qualification

## Verified source-owned predecessor

SAPPHON-228 GitHub Actions [run 46166461387](https://github.com/DavidWise01/super-sapphon/actions/runs/46166461387) completed **SUCCESS** at commit `c4e52a26e23d560b4ef0f1fa5fcb8f8799827c2a`. Fourteen ACK history, nonce replay and signature-regression cases passed, including the hosted repeated-ACK admission rejection. The GitHub Pages deployment for that commit also completed successfully. These are GitHub-controlled executions, not independently authenticated witnesses.

## SAPPHON-229 implementation

- `tools/sapphon_229_cross_session.py` re-verifies the **entire signed ACK history** in every submitted session, checking signatures, original image ancestry, digest-linked history rows, counters and duplicate nonces.
- Requires each successive session to contain the exact preceding session's immutable record prefix, append at least one new row and declare the exact prior head digest. It rejects empty-session resets, truncated history, forked or modified record prefixes, replayed receipts, reused nonces, duplicate session identifiers, and invalid or stale highwater claims.
- An optional checkpoint head is verified with Ed25519 against a separately supplied public key and checks exact source run/commit, session identity, terminal record count and digest. The *signing key's independent provenance is unverified*. A valid head signature reports **structural byte agreement only**, never externally authenticated global monotonicity.
- The source-owned report is deterministically SHA-256-bound and always retains `independently_authenticated_witnesses=0`, `recovery_authorized=false`, `lock_cleared=false`, and `decision=HOLD`.
- `tools/test_sapphon_229_cross_session.py` authors 16 positive and adversarial fixture tests; `.github/workflows/sapphon-229-cross-session.yml` tests the implementation on a separate hosted runner and archives both structurally matching and deliberately truncated **synthetic** session examples.

## Limitations and external boundary

Two complete-looking session snapshots can still represent an entirely rewritten GitHub-owned history if an external monotonic anchor is absent. Signed bytes prove that a key signed them, not that a separate organization holds the key, retained the original 730 MB image ZIP, witnessed the real transfer, or maintained independent time and anti-rollback counters. Never count repeated GitHub workflows as independent witnesses.

The frozen OCI source image still binds to run `46154833375`, source commit `c167a95a05177e280625fa61613c1b1fa20f75e9`, image TAR SHA-256 `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197`.

**Source-owned original image parity VERIFIED · Source-owned cross-session history implemented · Independent external custody NOT VERIFIED · Authenticated UTC NOT VERIFIED · Global anti-rollback NOT VERIFIED · Recovery HOLD.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
