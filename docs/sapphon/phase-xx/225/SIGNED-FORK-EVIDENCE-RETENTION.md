# SAPPHON-225 — Signed-Fork Evidence Retention Without Winner Selection

## Verified predecessor

SAPPHON-224 GitHub Actions [run 46162029983](https://github.com/DavidWise01/super-sapphon/actions/runs/46162029983) completed **SUCCESS** on `799559901fb9b098cb0da3447e19e0c7b5bb300a`. Its signed-head regression step and explicit no-external-head HOLD qualification passed. That is source-owned GitHub evidence, not an external custodian.

## New bounded evidence engine

- `tools/sapphon_225_fork_retention.py` accepts up to 64 complete signed-head envelopes, checks the supplied PEM anchor fingerprint and actual Ed25519 signatures, and binds all candidate heads to the frozen source run `46154833375`, commit `c167a95a05177e280625fa61613c1b1fa20f75e9`, and OCI image SHA-256 `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197`.
- Retains **both** validly signed sides of any same-custodian, same-sequence conflicting checkpoint digest; categorizes the event `SIGNED_EQUIVOCATION_REQUIRES_EXTERNAL_RECONCILIATION` without choosing an authoritative winner.
- Every submitted envelope, including invalid or duplicate entries, remains represented in a canonical JSON retention record; a digest of the complete evidence body is emitted. This does **not** preserve the uploaded file's original whitespace or byte envelope, nor does a GitHub artifact provide immutable external custody.
- Invalid signatures never create a proven fork. Replayed identical envelopes are duplicate evidence, not two independent witnesses. Missing anchor, malformed ancestry, invalid counter, oversized input or no external signed heads remain HOLD.
- `tools/test_sapphon_225_fork_retention.py` supplies 12 real locally signed Ed25519 regression cases. All fixture keys are generated inside the job, not externally provisioned.
- `.github/workflows/sapphon-225-fork-retention.yml` runs the regression suite and emits an explicit no-external-head HOLD verdict for archival.

## Reconciliation boundary

The evidence ledger is **observation-only**. Contradictory signed checkpoints must remain intact until an independently authenticated custodian resolves ancestry, signatures, external monotonic counter/clock and chain reconciliation through separately controlled channels. The local source must not delete either branch, clear a lock, release authority or count a duplicate GitHub source as an independent witness.

**Source-owned OCI image bytes verified · Independent external witnesses 0 · Authenticated UTC unverified · Global anti-rollback unverified · Recovery HOLD · Lock cleared FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
