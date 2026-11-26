# SAPPHON-158 — Out-of-Band Challenge Binding & Receipt Replay Rejection

**Phase XIV · Bound 6 of 8 · 75% design progression · operational authority HOLD**

## Executive summary

The Linux Rust module `rust/sapphon-liveness/src/challenge158.rs` adds a read-only anti-replay review for externally provisioned custodian receipt claims. It checks the inherited domain-separated Ed25519 enrollment signature and externally supplied provider key, counter floors and revocation status, and compares a pinned challenge to the signed nonce digest, artifact digest, custodian identity and source ancestry. It separately checks the nonce against a caller-supplied prior nonce history, refusing duplicate or reused entries.

**Threat boundary:** the local caller cannot manufacture independent physical custody merely by supplying a new challenge or nonce-history list. Real replay resistance across restarts requires the challenge and the used-nonce ledger to be durably retained and authenticated outside the repository owner’s control. The software cannot prove those facts. An apparent fresh receipt is `CHALLENGE_HOLD`, never an automatic recovery authorization.

## Twelve authored Rust regression tests

Fresh valid receipt remains unqualified; repeated nonce rejected; substituted expected challenge nonce rejected; changed artifact digest rejected; modified signed nonce signature rejected; stale counter rejected; revoked key rejected; mismatched signed ancestry rejected; mutated signed artifact requires a new signature; duplicated prior nonce history rejected; re-signed nonce still must match the independently pinned challenge; create-only report resists overwrite.

## Source integration and CI

The module is wired into `rust/sapphon-liveness/src/lib.rs`. `.github/workflows/sapphon-158-challenge.yml` runs inherited liveness, recovery, contention, journal and audit suites; verifies 188 historical immutable source hashes; enforces HOLD assertions; and builds Rust API docs. Its report artifact explicitly records that external nonce retention and physical custody are **not authenticated**.

The workflow has been committed, but CI pass and newest GitHub Pages deployment require separate completed-run and browser readback evidence. GitHub hosted source, runner artifacts and Pages are one owned ancestry, not independent custodians.

## Remaining HOLD barriers

External challenge issuance, independently authenticated nonce consumption history, out-of-band key provisioning, authenticated custody provenance, global monotonic anti-rollback, authenticated UTC, lock clearance and automatic recovery remain HOLD.

## Next natural bound — SAPPHON-159

Externally retained nonce-consumption ledger and fork detection: compare signed receipt transitions against previously pinned external head/counter, detect duplicated/forked challenge consumption, and preserve independent custodian qualification as HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
