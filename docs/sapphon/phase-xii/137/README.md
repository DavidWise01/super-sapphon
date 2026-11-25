# SAPPHON-137 — Phase XII: Local Registry Journal & Trusted Anchor Boundary

**Phase XII · 1/8 · 12.5% design progression · operational authority HOLD**

## Scope
- Rust module: `rust/sapphon-liveness/src/registry137.rs`
- Visualization: `docs/sapphon/phase-xii/137/index.html`
- CI: `.github/workflows/sapphon-137-registry.yml`

## Implementation
The registry is an append-only JSONL transcript of `register`, `advance`, and `revoke` events. Every event binds its predecessor's SHA-256, a sequential index, witness ID, ancestry label, public key, and monotonically advancing counter floor. Revocation is sticky and cannot be undone by a subsequent registry event.

Verification demands BOTH an expected sequence and exact head digest independently supplied by the caller. Missing or mismatched anchors fail closed. A local digest does not establish global anti-rollback. The registry can be reconstructed across process restarts from the committed transcript only when its external anchor is trustworthy.

The local append helper verifies the transcript and candidate transition, checks the current file before appending, writes and fsyncs. It assumes exclusive writer ownership supplied by the caller; it is not safe against hostile concurrent filesystem substitution, rogue symlinks, or an attacker able to replace both the registry and its anchor. The filesystem writer and external anchor must be separately hardened before operational use.

## Tests
Four Rust tests are authored: restart and rollback transcript checks; sticky revocation and monotonic floor; truncated/tampered entry rejection; local append durability and stale-counter rejection. The full inherited Rust test suites and 188 previously frozen hashes are gated by GitHub Actions.

## Authority HOLD
- The module never removes a lock, issues a recovery authorization, or authenticates UTC.
- Keys provisioned into the registry do not independently establish their owners' identity or independence.
- Revocation is checked only relative to an authenticated monotonic anchor that is **not implemented** in this module.
- Independent external custody, physical time, global anti-rollback, and secure federation remain HOLD.
- GitHub Actions passing status and Pages deployment must be observed separately; a source commit is not CI certification.

## Next natural bound: SAPPHON-138
Bind registry anchors to an independently verifiable custody witness, qualify restart/recovery against protected checkpoints, and add adversarial symlink and concurrent-writer tests. Preserve HOLD throughout.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
