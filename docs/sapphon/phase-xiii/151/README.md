# SAPPHON-151 — Blinded Cross-Custody Replacement Challenge

**Phase XIII · 7/8 · 87.5% design progression · operational authority HOLD**

## Executive summary
The Linux Rust module `rust/sapphon-liveness/src/blind151.rs` compares evidence packets from up to 32 alleged custodians. It uses provisioned Ed25519 trust keys to verify each signed SAPPHON-145 checkpoint before issuing any cross-source finding. User-facing display names have no role in the ancestry or checkpoint comparisons.

## Evidence findings
- `SHARED_ANCESTRY`: identical declared origin used as multiple purported witnesses.
- `COPIED_RECEIPT_ANCESTRY`: identical origin fingerprint attached to two packets.
- `MIRRORED_STATE`: exact registry, intent and provider digests replicated.
- `SHARED_SIGNER` and `SHARED_PUBLIC_KEY`: duplicate identities or reused signing credentials.
- `SIGNED_EQUIVOCATION`: same signer, same sequence, conflicting authenticated heads.
- `CROSS_PROVIDER_CONFLICT`: different keys, same sequence, different signed heads.
- `ASYNC_SEQUENCE`: different sequence numbers; not by itself evidence of equivocation.

Findings are sorted deterministically and the report is create-only on write with a SHA-256 digest. An existing evidence path cannot be overwritten without an explicit external filesystem operation. The output preserves claimed-root count, observed evidence and signature count, but **never declares physical or organizational independence**.

## Seven authored regression tests
Shared ancestry and copied receipt detection; two valid contradictory checkpoint signatures; display-name/order invariance; forged-signature rejection; missing trusted provider; asynchronous sequence categorization; create-only report preservation.

## Limits
The provenance fingerprints, claimed ancestry roots and trust-registry entries are supplied by callers. A malicious operator can assign distinct ancestry labels to copied information, and the software cannot authenticate physical custody. Even verified signatures, two names, and copied hashes cannot prove two witnesses. This phase performs a blind structural audit, not an operational security certification or proof of global anti-rollback.

All challenge decisions are HOLD; recovery authorization, key acceptance, external custody qualification and lock clearance remain false.

## CI
`.github/workflows/sapphon-151-blind.yml` executes the liveness and inherited Rust suites, validates the 188 historical frozen source hashes, checks HOLD invariants and builds documentation. Source committed is not CI passed; Pages deployment is also independently unverified until readback.

## Next natural bound — SAPPHON-152
Phase XIII final qualification and evidence freeze: execute tests, inspect Actions outcomes, reconcile external custody gaps, and issue a no-authority final report. Do not infer independent custody from matching copies or signature counts.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
