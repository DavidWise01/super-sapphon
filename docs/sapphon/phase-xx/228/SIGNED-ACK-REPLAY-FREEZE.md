# SAPPHON-228 — Signed Custody ACK Replay, Nonce Reuse & Source-Owned Freeze

## Verified predecessor

The SAPPHON-227 report-triggered workflow [46165945563](https://github.com/DavidWise01/super-sapphon/actions/runs/46165945563) completed **SUCCESS** on source SHA `71e01f156553ae00c3f13d7bff832d86b3a6d0c4`. Its 13 Ed25519 portable fork-bundle, manifest readback and acknowledgment fixtures passed. It preserved a synthetic two-branch conflict in source-owned evidence; no actual external custodian or authenticated witness was obtained. Evidence artifact `15271079606`, ZIP metadata digest `sha256:3939751056cc46558f4247524444f520199c12ea5e58c2c9bdebc2c83d9d32d0`.

## New SAPPHON-228 source

`tools/sapphon_228_ack_ledger.py` creates a bounded, deterministic, append-only **source-owned** acknowledgment history. Before admission, it re-verifies each historical signed Ed25519 ACK against its included public-key anchor and the exact frozen fork manifest. Each entry binds an exact integer counter, its preceding entry digest, the full signed acknowledgment, and its supplied key anchor. The entire record is SHA-256-bound with a deterministic canonical representation.

The admission gate rejects a reused `(custodian_root, transfer_nonce)`, an identical signed acknowledgment replay, overwritten/tampered historical evidence, counter gaps, altered predecessors, a forged signature, wrong source bundle, missing acknowledgment and capacity overflow (128 entries). A rejected candidate is never appended and earlier rows are not replaced. Receipt signing keys and ACKs can be validly verified while still remaining untrusted as *external custody* evidence.

`tools/test_sapphon_228_ack_ledger.py` adds 14 deterministic positive and negative regression cases. `.github/workflows/sapphon-228-ack-ledger.yml` runs those tests and produces two explicitly **synthetic** source-owned evidence records: first signed ACK admitted into a test ledger, identical ACK re-submitted and rejected by nonce and receipt replay checks. Neither contains an external independent witness.

## Scope and unavoidable limits

The history is append-only **within the tested execution state**. GitHub artifact retention does not by itself create globally durable immutable external storage. A reused nonce in a *different disconnected ledger* or a rewind to a different fork of the whole ledger cannot be ruled out without independently anchored monotonic custody. An earlier GitHub snapshot is not global anti-rollback. User-supplied witness flags and UTC strings cannot authenticate external keys, custody or time.

The original source-owned OCI image remains bound to run `46154833375`, source commit `c167a95a05177e280625fa61613c1b1fa20f75e9`, exact image TAR SHA-256 `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197`.

**Both original fork branches retained · No winner selected · Independent external witnesses 0 · Authenticated UTC unverified · Global anti-rollback unverified · Recovery HOLD · Lock cleared FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
