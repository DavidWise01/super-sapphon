# SAPPHON-110 — Capture-Agent Registration & Session Challenge Anchors

**Phase VIII:** 6/8 · 75%  
**Verified GitHub Actions:** 25/25 capture-agent checks; 26/26 inherited transport-transcript checks; 26/26 inherited acquisition-byte checks. Phase VI: 11 frozen hashes unchanged. Phase VII: 45 frozen hashes unchanged.

## Delivered
- `tools/sapphon_110_capture.cjs` defines a provisioned Ed25519 capture-agent key fingerprint, explicitly issued 256-bit nonce challenge, signed response-evidence envelope, source ownership root, transport session binding, peer-key fingerprint, byte SHA-256, and an explicit test-only retention reference.
- The verifier requires a trusted supplied agent registry, prior nonce issuance, valid transcript and acquisition receipt, original byte digest, correct transport peer pin, and valid signed capture evidence. The same nonce cannot be consumed twice in the supplied test store.
- It rejects forged capture signatures, substituted keys, revoked or unknown agent keys, mismatched source ancestry, changed bytes, conflicting session/acquisition IDs, transcript substitutions, unissued nonce challenges, repeated sessions and unauthorized UTC fields.
- `tools/test_sapphon_110_capture.cjs` exercises 25 synthetic acceptance and negative tests.
- `docs/sapphon/phase-viii/110/index.html` retains all three neon pump rings (hot red, neutral green, cold blue), eight sectors, central `{{i}}`, four frozen clock registers, and read-only challenge diagnostics.
- `.github/workflows/sapphon-110-capture.yml` gates all new and inherited checks, and compares both sealed manifests against actual repository bytes.

## Evidence boundary
The signed capture records are **synthetic**. No independently authenticated acquisition agent or physical HTTPS capture is connected. A fixture retention identifier does not prove external archival custody. The test challenge is supplied through an in-memory map and consumed-nonce set, not a durable cross-host notary; the earlier SAPPHON-104 local durable replay registry is not yet integrated with this capture step. Separate signing keys do not establish independent source roots. No real TLS handshake capture, remote timestamp witness, or calibrated physical source is authenticated.

**External acquisition, independent custody, physical-clock qualification, and UTC authority: HOLD.**

## Next natural bound
**SAPPHON-111 — Durable Cross-Host Capture Replay & Retention Evidence.** Build a restart-safe capture challenge ledger with replay controls, independently supplied retention-acknowledgement format, and strict source-ancestry reconciliation. Do not upgrade any external evidence qualification without independently obtained custody proof.

`.dlw`
