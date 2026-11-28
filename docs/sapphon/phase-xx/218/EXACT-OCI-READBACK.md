# SAPPHON-218 — Exact OCI archive second-runner readback

## Qualified hosted source-owned build

GitHub Actions [run 46154833375](https://github.com/DavidWise01/super-sapphon/actions/runs/46154833375), source commit `c167a95a05177e280625fa61613c1b1fa20f75e9`, completed SUCCESS. Python, Rust, frozen ancestry, actual vendor archive, immutable base resolution, network-disabled Docker image build/export, image verdict and parity gate all completed successfully. Rust: 549 unit + 14 additional passing.

- Original artifact `15267037687` — `sapphon-207-vendor-and-local-image`.
- GitHub-reported artifact ZIP: `730704125` bytes; SHA-256 `62b7d3dfd7faf3c10a34d5c7e74da434debd0039c2cf3a60173b602d10a27a07`.
- Immutable base selected at runtime: `rust@sha256:75d26c23c24cc6ea1cdabf0714a6bff8fd7bf3248716043fd7ae86dac7f41b94`.
- Hosted verdict: `SOURCE_OWNED_IMAGE_ARCHIVE_VERIFIED`.
- Exact image TAR independently downloaded by assistant: **not yet**. The connected artifact downloader rejects files exceeding **536,870,912 bytes**; the archive is **730,704,125 bytes**. Do not claim an assistant-side ZIP or image TAR rehash.

## Second-runner verification

New `.github/workflows/sapphon-218-image-readback.yml` fetches the exact artifact from original run `46154833375` into an independent **execution runner** still under the same GitHub owner/source ancestry. The `tools/sapphon_218_second_runner.py` verifier streams the extracted TAR and lock bytes, checks recorded hashes against the original run summary, receipt, image report, previous verdict and pinned-base resolver, and checks exact run ID/attempt/source SHA. It records a compact `218-readback.json` report. Five negative/positive regression cases test qualification.

This separate GitHub runner does not independently rehash the ZIP envelope because `actions/download-artifact` extracts the ZIP. It is a second execution context, **not an independent external custodian or witness**.

## Acceptance and authority

- `GITHUB_OWNED_EXTRACTED_BYTES_MATCH` requires actual second-runner success and matching original extracted bytes.
- Any missing file, hash conflict, run/attempt substitution, missing base receipt or operational authority claim yields `READBACK_HOLD`.
- A green unit test is not a green hosted readback. Do not imply hosted completion until the workflow run succeeds and its artifact is read.
- Independent externally authenticated witnesses: **0**.
- Authenticated UTC / global anti-rollback: **unverified**.
- Recovery authorized: **FALSE**. Lock cleared: **FALSE**.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
