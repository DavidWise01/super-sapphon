# SAPPHON-100 — Signed Enrollment Checkpoint Export and Independent Software Audit

**Phase VII:** 4/8 · 50%  
**Architecture:** One input; three R/G/B physical pumps; four logical registers; one output. `.dlw`

## Implemented

- `tools/sapphon_100_checkpoint.cjs` signs a checkpoint over the exact SAPPHON-099 governance-enrollment ledger head, event count, trusted governance key ID, and deterministic enrolled-source state.
- `tools/sapphon_100_export.cjs` exports complete signed checkpoint JSON and the corresponding **public** governance key. A production invocation requires a private key supplied externally; it never writes private key bytes into export artifacts. `--test-fixture OUTDIR` produces a temporary, independently reproducible synthetic enrollment → revocation → re-enrollment sample.
- `tools/sapphon_100_verify.py` independently verifies both Ed25519 checkpoint signature and each governance event signature, ledger SHA-256 predecessor chain, sequence, enrollment/revocation/re-enrollment transitions and final active-source projection. Python verification uses the separately supplied public key, not the public key embedded in an untrusted checkpoint.
- `tools/test_sapphon_100_checkpoint.cjs` validates accepted checkpoints, rejects rewritten ledgers and altered source histories, and runs the independent Python verifier on the same evidence.
- GitHub Actions exports a signed **synthetic** checkpoint and public test key as a 30-day run artifact after the software tests pass.
- `docs/sapphon/phase-vii/100/index.html` is a neon observation-only visualization retaining the frozen three-pump clock geometry.

## Actual trust boundary

Two verifiers written in different languages are **not two independent witnesses**. Both use the same software-provided governance public key. A replacement of both the trusted key and the checkpoint by an attacker with distribution control would evade self-contained verification. Neither the synthetic enrollment ledger nor the unsigned archived clock establishes true UTC, a physical clock source, or independently authenticated source ancestry.

The Phase VI frozen source and evidence hash manifest are untouched. Any full external trust anchor is reserved for later work, not claimed here.

## Signed export usage

`node tools/sapphon_100_export.cjs ledger.json governance-private.pem approved-governance-id audit.json governance-public.pem`

`python3 tools/sapphon_100_verify.py audit.json governance-public.pem approved-governance-id`

The governance public key must be distributed through a channel trusted independently of the supplied audit document.

## Next natural bound

**SAPPHON-101 — External anchor registration and historical fork detection.** Persist a checkpoint head beyond the ledger's own ownership boundary and compare subsequent versions against that trusted reference without accepting fabricated clock authorization.

`.dlw`
