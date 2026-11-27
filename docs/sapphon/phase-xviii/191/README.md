# SAPPHON-191 — Independent Proof-of-Possession Challenge & Replay Window

**Phase XVIII · Bound 7/8 · 87.5% source design · operational authority HOLD**

## Executive summary

SAPPHON-191 binds a one-time proof-of-possession response to an exact source SHA, root SHA-256, workflow run, attempt, session, nonce and Ed25519 key fingerprint. Replaying a consumed challenge, substituting a different root/session/attempt/key, or claiming an authenticated external issuer without evidence fails closed.

The predecessor source is SAPPHON-190 commit `9cdfc47714899d4f1791d7a51be813ba0790eca9` and workflow `sapphon-190-custody.yml`. The current connected GitHub commit-run readback found no PR-associated runs or combined statuses. This is not exhaustive evidence about push-triggered Actions. No genuine external challenge, independent enrolled key, physical custody witness or successful hosted CI execution was established during authoring.

## Implemented bound

- `tools/sapphon_191_challenges.py`: validates source-owned challenge issuance and response structures; limits to 128 each; detects duplicate challenges, repeated nonce consumption, unknown challenges, cross-root/session/attempt/key substitution and forged external authority. Python does **not** claim to verify cryptographic signatures.
- `tools/test_sapphon_191_challenges.py`: 16 authored adversarial regression cases including replay, wrong source root, session, key, run/attempt, unknown nonce, forged issuer and malformed fields.
- `rust/sapphon-liveness/src/challenge191.rs`: real Ed25519 verification using existing `ed25519-dalek`, with length-prefixed, domain-separated message fields binding source, root, run, attempt, session, nonce and key fingerprint. Rust rejects nonce reuse and forged custody claims. Eight authored Rust tests use a deterministic, **test-only** signing key.
- `rust/sapphon-liveness/src/lib.rs`: additively registers the Rust module.
- `.github/workflows/sapphon-191-challenges.yml`: runs Python and Rust tests, 188 historical frozen-file integrity checks, and an explicitly empty external-challenge preflight. Publishes only sanitized source-owned diagnostics, never production keys or external credentials.
- `docs/sapphon/phase-xviii/191/index.html`: illustrative neon 4D challenge/response lab, not a live signature verifier.

## Qualification and provenance

A mathematically correct signature from an internally held test key demonstrates only that a given key signed the bounded message. It **does not** establish that a third party issued the challenge, retained the private key independently, or witnessed physical recovery conditions.

The challenge list in CI is explicitly empty; a source-owned workflow cannot fabricate an independent challenge by generating one internally. A future real enrollment requires an authenticated out-of-band key and issuer provenance, an issuance record carried outside the GitHub source ancestry, and durable prevention of reuse beyond one ephemeral runner. Even that would not itself authorize physical recovery.

| Criterion | Status |
| --- | --- |
| Phase XVIII source design | **7/8 = 87.5% committed** |
| Python challenge regression cases | 16 authored; hosted execution unverified |
| Rust signature and replay tests | 8 authored; hosted execution unverified |
| Single-use nonce and context binding | Source implemented |
| Independently issued challenges | **0 observed** |
| Independently enrolled custody keys | **0** |
| Independent witnesses | **0** |
| 188 inherited historical files | Read-only checks retained |
| npm dependency integrity / authenticated UTC / anti-rollback | HOLD |
| Live Pages / Chromium | Source committed; deployment unverified |
| Physical recovery / key rotation / lock clearance | HOLD |

## Next natural bound — SAPPHON-192

**Phase XVIII Final Challenge & Custody Freeze.** Freeze the phase's eight bounded source designs and exact test inventory, retain observed-vs-authored distinctions, and verify any actual Actions failures before beginning a later phase. No unverified witness count or recovery escalation.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
