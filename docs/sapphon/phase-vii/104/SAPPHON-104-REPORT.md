# SAPPHON-104 — Phase VII Software Freeze and Replay Protection

**Phase VII: 8/8 · 100% (software milestone).**

## Baseline

The frozen SAPPHON-096 Phase VI clock remains unchanged: three red/hot/hydrogen, green/neutral/oxygen and blue/cold/nitrogen physical pumps, eight sectors, nested `{{i}}`, four logical [3] clock registers, and eight synthetic archived phase records. New Phase VII additions are separate.

## Durable replay contract

`tools/sapphon_104_replay.cjs` records issued cryptographic 256-bit nonces, their exact challenge digest, local issuance time, expiration, and consumed status. Records survive process restarts through a dedicated JSON file on a writable volume. Mutations use an exclusive directory lock, a temporary file, `fsync`, atomic rename and directory sync. Missing state, corrupted state or an unavailable lock fails closed. Expired nonces are pruned; absence from the registry cannot be interpreted as new permission. A challenge is consumed only after signing-key verification and its signed custody receipt both pass. A duplicate nonce, expired challenge, substituted session or challenge, key mismatch, false root, or forged signature cannot authorize a new clock observation.

**Limits:** Filesystem atomic rename/locking assumes a suitable local filesystem and one shared durable volume. A stale lock requires supervised recovery, not automatic reset. A caller supplies the local wall-clock reference; rollback is rejected relative to issuance but cross-process persistent clock-quality/monotonicity is not yet guaranteed. This code is a synthetic custody verifier, not a network service or an independent clock. Its disk is not an externally anchored tamper-proof storage service.

## Acceptance and freeze

- `tools/test_sapphon_104_replay.cjs` exercises restart, replay, expiry, corruption, failed-signature non-consumption, issuer constraints and locking.
- `tools/test_sapphon_104_browser.cjs` executes the final viewer under Chromium and checks canvas content, four original registers, display-only controls and page errors.
- Inherited source, receipt, challenge and anchor suites are preserved.
- `tools/sapphon_104_freeze.py` writes `docs/sapphon/phase-vii/SAPPHON-104-FREEZE.json` as a deterministic SHA-256 manifest of Phase VII code, tests, reports, viewer and workflows, while separately validating every existing Phase VI frozen hash.
- A GitHub Actions run must pass before the workflow commits a new freeze manifest.

## Qualification gates

- **Software:** subject to the blocking acceptance workflow.
- **Real independent custodian:** HOLD. No external organization or out-of-band custody receipt verified.
- **Physical clock and UTC:** HOLD. The eight archived clock records are synthetic and unsigned.
- **Independent ancestry roots:** HOLD. Distinct test keys do not constitute independent sources.

## Next phase

Phase VIII begins only with new evidence: an external custodian who can independently attest retention and ownership or an authenticated non-synthetic physical clock feed. Until then, subsequent work remains in engineering qualification rather than claiming physical authority.

`.dlw`
