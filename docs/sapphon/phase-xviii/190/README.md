# SAPPHON-190 — Independent Custody Enrollment & Receipt Ancestry

**Phase XVIII · Bound 6/8 · 75% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-190 adds a **cryptographic receipt-verification boundary** without pretending that a valid signature proves independent custody. Rust verifies Ed25519 signatures against an explicit domain-separated, length-prefixed receipt message. The Python preflight checks schema, exact source/workflow ancestry, receipt identity, key fingerprints, nonce replay and predecessor digest shape. Crucially, **neither module accepts an artifact-supplied key as trusted external enrollment**.

The pinned predecessor source is SAPPHON-189 commit `8dfc2f0851df7bc02ac29977529bafe9c0b2101e`, workflow `sapphon-189-forks.yml`. The available commit-level readback returned no PR-associated runs and no combined checks, which does not exhaustively establish push workflow execution. No genuine externally signed receipt, independently enrolled key or verified hosted test result was obtained in this authoring session.

## New source

- `tools/sapphon_190_enrollment.py` — bounded receipt preflight (64 records); exact ancestor SHA/workflow, positive run/attempt/sequence, SHA-256 root, strict 32-byte Ed25519 public key and 64-byte signature encoding, key fingerprint agreement, 256-bit nonce, nonce+sequence replay rejection, previous digest and key registration validation. Python checks *shape only*, not cryptographic verification.
- `tools/test_sapphon_190_enrollment.py` — 16 authored adversarial tests for replay, substituted ancestry, boolean attempt, forged recovery, malformed key/signature, unverified enrollment claims, changed root and unknown fields.
- `rust/sapphon-liveness/src/custody190.rs` — actual Ed25519 verification using the existing `ed25519-dalek` and `base64` dependencies. Message bytes use an explicit domain label and length-prefixed fields, to avoid ambiguous concatenations. Seven authored Rust tests include cryptographically valid test-key signing, tampered root, mismatched key fingerprint, replay and forged authority.
- `docs/sapphon/phase-xviii/190/key-registry.json` — **explicitly empty** source-owned registry. No invented trusted public key or trust-on-first-use enrollment. This file is a refusal to enroll, not evidence of independently held custody.
- `.github/workflows/sapphon-190-custody.yml` — Python/Rust tests, inherited 188 historical source-file checks, empty-registry preflight and a machine-readable zero-witness/HOLD source result.
- `docs/sapphon/phase-xviii/190/index.html` — neon 4D educational visualization, synthetic scenarios only.

## The critical split

**Cryptographic signature validity** answers whether one private key signed a particular exact message. This can be demonstrated with a deterministic test fixture.

**Independent custody identity** additionally requires a genuine externally held verification key enrolled through a separate authenticated channel, trusted owner verification and independently evidenced source ancestry. A self-issued key, another GitHub-hosted endpoint, or a copied signature is not another witness.

**Operational authority** requires its own still-unmet governance controls, so valid cryptography plus real independent custody would still not automatically authorize key rotation, lock clearance or physical recovery.

## Qualification ledger

| Criterion | State |
| --- | --- |
| Phase XVIII source design | **6/8 = 75% committed** |
| Python receipt controls | 16 authored, hosted execution unverified |
| Rust Ed25519 receipt tests | 7 authored, hosted execution unverified |
| Ed25519 verification implementation | Source committed; compiler execution unverified |
| Independently enrolled keys | **0** |
| Verified independent witnesses | **0** |
| Real external signed custody receipts | Not supplied or retrieved |
| GitHub-owned ancestry fork protection | Prior SAPPHON-189 source retained |
| Historical 188 frozen files | Read-only checks retained |
| Live GitHub Pages and Chromium | Source publication; deployment unverified |
| npm integrity, authenticated UTC, global anti-rollback | HOLD |
| Key rotation, lock clearance, physical recovery | HOLD |

The source test fixture's private key is fixed and intended only for deterministic regression testing. It is not a production credential, is not enrolled, and is not an external custody witness.

## Next natural bound — SAPPHON-191

**Independent Proof-of-Possession Challenge & Receipt Replay Window.** Define independently sourced single-use challenges, bind each external receipt to a unique challenge and source root, reject replay and cross-session substitution, and verify key enrollment from a genuinely separate authenticated channel. Remain at zero trusted witnesses until that source exists.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
