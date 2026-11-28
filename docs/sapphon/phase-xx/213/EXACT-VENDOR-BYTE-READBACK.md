# SAPPHON-213 — Exact corrected-run artifact byte readback

**Decision: VENDOR_BYTES_VERIFIED_IMAGE_AND_RECOVERY_HOLD**

This evidence was independently recomputed by the assistant from the GitHub-hosted ZIP bytes downloaded through the connected GitHub artifact interface. It is **a separate readback of source-owned GitHub bytes**, not independent external custody or a second physical witness.

| Field | Observed value |
| --- | --- |
| Corrected source commit | `3f5eae74398eb318f6eecf409ef19e93eaf55e46` |
| Workflow run / attempt | `46096591838` / `1` |
| Artifact ID | `15244050179` |
| ZIP bytes | `4004302` |
| ZIP SHA-256 | `5e23e49fcc1e6bb1a80e747ea058aad634c74504794abd254f0d0ae12e246a7f` |
| Cargo.lock SHA-256 | `2ee90c706c436c450c786e7ecf5a12243c9dd8fc213a39d0ff071737dab6238c` |
| Vendor TAR SHA-256 | `84c024537ba4d52f6892d080b08ed94c9a5a38c666cd1538a932bbfedd90c38e` |
| Canonical vendor tree SHA-256 | `df53074bc71ad69b56add5cf98fd880f64458da5df4a2a856de2836e1948c93d` |
| Vendor files hashed and matched | **1,751 of 1,751** |
| Uncompressed vendor file bytes | `22082124` |
| Original image archive | **Not present**, image step failed because no pinned base digest was configured |
| External independently authenticated witnesses | **0** |
| Recovery and lock clearance | **HOLD** |

## Verification performed

1. SHA-256 of the downloaded ZIP matched the GitHub-reported artifact digest.
2. The ZIP had exactly four unique safe entries: `207-Cargo.lock`, `207-vendor.tar`, `207-vendor.json`, and `207-summary.json`.
3. Summary run, attempt and source SHA matched the corrected workflow's exact identifiers.
4. The Cargo.lock and vendor TAR byte hashes matched the report; both vendor tree hashes matched.
5. All 1,751 TAR entries were regular files, path-safe and unique. Independently hashed entry data matched the ordered manifest, its canonical SHA-256 and its total bytes.
6. Image qualification was **not** promoted from optional step status. All recovery/lock clearance flags remain false.

## Historical ancestry

The original historical source `aea6cb530ed4b23445a489e23099c63b6049854e` and its failed run `46080606762` are retained unchanged. This qualification applies **only** to the corrected-run source `3f5eae74398eb318f6eecf409ef19e93eaf55e46`.

The digest evidence does not authenticate a UTC time authority, an external independent custodian, global anti-rollback, or physical recovery.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
