# SAPPHON-219 — Cross-Runner Byte Parity and Immutable Source-Owned Freeze

## Observed evidence

The SAPPHON-218 second-runner workflow [46156872306](https://github.com/DavidWise01/super-sapphon/actions/runs/46156872306) completed **SUCCESS**. Its independently executing GitHub runner fetched the extracted original artifact from run `46154833375`, attempt `1`, commit `c167a95a05177e280625fa61613c1b1fa20f75e9` and streamed SHA-256 over three source-owned files.

Artifact `15268320414` (`sapphon-218-second-runner-readback`) is a 629-byte compact ZIP. An additional assistant-side download and independent hash of **that compact ZIP** matched GitHub's SHA-256:
`522a1978ed1af9f7ce9ef1df735f6da81a4e9d90f343420c73b6fae41c682475`.

Extracted `218-readback.json` reported `GITHUB_OWNED_EXTRACTED_BYTES_MATCH`, `blockers: []`, and these **exact hashes**:

| File | SHA-256 |
| --- | --- |
| `207-Cargo.lock` | `2ee90c706c436c450c786e7ecf5a12243c9dd8fc213a39d0ff071737dab6238c` |
| `207-vendor.tar` | `84c024537ba4d52f6892d080b08ed94c9a5a38c666cd1538a932bbfedd90c38e` |
| `207-image.tar` | `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197` |

The original image-bearing artifact ZIP has 730,704,125 bytes; the connected artifact downloader refuses it above 536,870,912 bytes. Consequently the assistant **has not** independently hashed the original large ZIP envelope. Its GitHub-reported digest is `62b7d3dfd7faf3c10a34d5c7e74da434debd0039c2cf3a60173b602d10a27a07`.

## SAPPHON-219 frozen qualification

- `tools/sapphon_219_cross_runner.py` compares original run, attempt, source commit, inventory, three exact SHA-256 digests and all authority guard flags to a fixed frozen reference. A different run/attempt/source or a changed digest fails closed.
- `tools/test_sapphon_219_cross_runner.py` provides ten positive/negative regression checks.
- `.github/workflows/sapphon-219-freeze.yml` re-acquires the **compact original SAPPHON-218 artifact** by its exact originating run and performs a third GitHub-execution readback. This remains **the same owner/ancestry**, not an independent witness.

## Strict authority boundary

`SOURCE_OWNED_IMAGE_BYTE_PARITY_VERIFIED` is the positive *hash-and-ancestry* decision, not permission to clear a lock or perform recovery.

Independent external witnesses: **0**. Authenticated UTC: **unverified**. Global anti-rollback: **unverified**. Recovery: **HOLD**. Lock cleared: **FALSE**. ZIP envelope independently hashed outside GitHub: **FALSE**.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
