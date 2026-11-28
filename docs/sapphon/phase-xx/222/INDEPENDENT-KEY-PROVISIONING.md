# SAPPHON-222 — Independent Key Provisioning, Custody Ancestry and Authenticated Checkpoint Intake

## Observed predecessor

SAPPHON-221 GitHub Actions [run 46159398175](https://github.com/DavidWise01/super-sapphon/actions/runs/46159398175) completed **SUCCESS** on commit `9d6ed30d5a4e0bb32845bef507d91080042c456d`. This establishes source-owned Ed25519 validation behavior and negative-control tests, not external physical custody.

SAPPHON-220's digest-bound manifest traces the previously verified source-owned image TAR from original build run `46154833375`. The cryptographically verified signature itself is not proof of independent identity, physical custody, authenticated UTC or global anti-rollback.

## New bounded intake

- `tools/sapphon_222_external_anchor.py`: separates an operator-supplied public-key anchor from the receipt's `public_key_pem`. The Ed25519 signature is checked with the supplied anchor key, not silently trusted from the receipt. The key's SHA-256 fingerprint, stated custodian root and stated provisioning channel must match.
- The previous receipt link is checked for non-genesis sequences: exact predecessor counter, custodian root and SHA-256, with an explicitly *claimed* authenticated predecessor.
- All self-supplied fingerprints, provisioning channel labels, counters, receipt signatures and claimed time remain **untrusted as external provenance**. GitHub cannot independently establish key ownership or external chain custody by reading user-provided metadata.
- `tools/test_sapphon_222_external_anchor.py`: twelve signed fixtures and negative controls: swapped key, mutated signature payload, unknown anchor, mismatched fingerprint, GitHub-root provenance, spoofed custodian, invalid genesis predecessor, counter confusion, unverified predecessor, and false witness claims.
- `.github/workflows/sapphon-222-external-anchor.yml`: runs source tests and archives an explicit no-external-receipt HOLD decision; no operational release action.

## External qualification required

An actual external custodian must independently provision and authenticate signing-key identity **outside the GitHub source ancestry**; independently obtain or rehash the frozen image bytes; produce durable counter/head checkpoints in externally controlled append-only storage; authenticate UTC independently; and provide independently verified evidence of those operations. No string in an externally submitted JSON receipt can substitute for this trust channel.

**Independently authenticated witnesses: 0. Authenticated UTC: unverified. Global anti-rollback: unverified. Recovery: HOLD. Lock cleared: FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
