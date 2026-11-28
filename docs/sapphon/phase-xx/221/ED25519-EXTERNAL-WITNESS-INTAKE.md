# SAPPHON-221 — Ed25519 Witness Intake Without Custody Promotion

## Verified predecessor

The SAPPHON-220 hosted workflow [46158907134](https://github.com/DavidWise01/super-sapphon/actions/runs/46158907134) completed **SUCCESS**. The source-owned handoff artifact `15268632362` was downloaded and its ZIP SHA-256 independently recomputed: `d0d0d71d1d083e16529f3e2d43c996f6a0b5030dd83d01ccf95a36ade4aeefa4`, matching the GitHub receipt. The enclosed `220-handoff.json` binds exact source run `46154833375`, attempt 1 and commit `c167a95a05177e280625fa61613c1b1fa20f75e9`, as well as the three frozen file digests and `manifest_sha256=3ac20185c7e4bb6933f9bcfe3e6ba91eeaa25a91904ca3c3f7aefd92ff7e6836`.

## New bound

`tools/sapphon_221_attestation.py` validates an Ed25519 signature over canonical JSON payload using OpenSSL, and rejects mutated manifest SHA, exact-run mismatch, incorrect image digest, invalid claimed roots, missing or malformed signature, invalid counter/previous-receipt link and unsupported authority claims. It reports explicit signature validity separately from custody authenticity.

**A valid signature proves only control of the key supplied with the receipt.** The supplied public key is not independently authenticated. A plausible custodial name, claimed UTC timestamp or linked predecessor digest is not proof of physical independence, trusted clock or independently anchored anti-rollback. Even a signature-valid receipt remains `CRYPTOGRAPHIC_SIGNATURE_VALID_CUSTODY_HOLD` with zero authenticated witnesses and no recovery.

Nine local tests passed using actual Ed25519 key generation/signing through OpenSSL, including mutations and negative controls. A new GitHub Actions workflow runs those regressions and tests an absent receipt as an expected **rejected HOLD**, never as a success to promote.

## Known limits and next requirements

1. Independently provision a trusted public-key fingerprint and custody ancestry outside the GitHub-owned source tree; establish authenticity via an external trusted channel, not receipt-provided labels.
2. Bind external time evidence to an authenticated, non-caller-controlled clock with auditable authority.
3. Bind sequence and previous checkpoint to an independent append-only anti-rollback custodian.
4. Only after all three are externally verifiable can distinct independent evidence *be considered*. This module deliberately has no witness-promotion or operational release path.

Current state: **Independent authenticated witnesses 0 · UTC HOLD · Anti-rollback HOLD · Recovery HOLD · Lock cleared FALSE**.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
