# SAPPHON-214 — Pinned OCI Base and Offline Image Qualification

## Observed source changes

- The SAPPHON-213 exact corrected-source vendor evidence remains immutable: run 46096591838, artifact 15244050179, 1751 verified vendor files.
- New `tools/sapphon-214.Dockerfile` uses Docker `ADD vendor.tar /src/vendor/` to unpack audited vendored crate bytes. The historical `sapphon-207.Dockerfile` is unchanged.
- The SAPPHON-207 workflow now checks Docker's `RepoDigests` membership against the configured `SAPPHON_RUST_BASE_IMAGE`, and builds using `--network=none --pull=false` plus `--locked --offline`.
- New `tools/test_sapphon_214_image.py` provides five static regression tests, but passing them does not constitute image execution evidence.

## Qualification boundary

| Gate | State |
| --- | --- |
| Exact corrected vendor archive bytes | VERIFIED in SAPPHON-213 |
| Updated Dockerfile and workflow source | COMMITTED |
| Hosted regression run for SAPPHON-214 | PENDING |
| `SAPPHON_RUST_BASE_IMAGE` exact repository@sha256 configured | NOT OBSERVED |
| Verified base image RepoDigest in fresh job | NOT OBSERVED |
| Network-disabled image build | NOT OBSERVED |
| Exported image archive bytes/hash | NOT OBSERVED |
| Independent external witnesses | 0 |
| Recovery / lock clearance | HOLD |

GitHub Actions' top-level success can coexist with an optional image step failure. A `success` workflow conclusion is not a substitute for checking `steps.IMAGE`, the actual image TAR bytes and SHA-256, and the run-bound summary.

## Next bound — SAPPHON-215

Select and configure a **real** registry-resolved image digest that contains the required Rust/Cargo toolchain. Do not invent an image SHA or use a mutable tag. Confirm the digest in Docker's `RepoDigests`; execute a network-disabled build and image export. Separately read back the resulting image archive bytes, matching run, attempt and commit. A source-owned Docker build is never independently authenticated physical custody.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
