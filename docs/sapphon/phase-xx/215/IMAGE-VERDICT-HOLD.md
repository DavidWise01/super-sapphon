# SAPPHON-215 — Observable OCI Image Verdict (source-owned)

**Current result:** Vendor build PASS; no configured `SAPPHON_RUST_BASE_IMAGE`; image **HOLD**; recovery **HOLD**.

## Hosted baseline

- SAPPHON-214 vendor run `46110853479` completed overall SUCCESS, 549 Rust unit tests and 14 additional tests passed, 188 frozen paths checked, vendor/offline check passed.
- The job log explicitly shows `BASE:` empty and `IMAGE: failure` (step is `continue-on-error`). Therefore Docker image qualification did not occur.
- Source-owned ZIP artifact `15249801258` was retained. This is not an image TAR or an independent witness.
- The published SAPPHON-213 verified corrected vendor archive and all 1,751 SHA-256 file entries remain the separate trusted baseline.

## Changes in this bound

- `tools/sapphon_215_image_gate.py`: independent *logical classification* of existing source-owned image report, archive bytes, SHA-256 receipt, immutable base reference, image IDs, and recovery flags.
- `tools/test_sapphon_215_image_gate.py`: seven positive/negative fixture tests. Passing a fixture is **not** a claim of Docker execution.
- `.github/workflows/sapphon-207-vendor.yml`: adds test execution, archives `215-image-verdict.json`, and reports explicit `IMAGE_QUALIFICATION_HOLD` or `SOURCE_OWNED_IMAGE_ARCHIVE_VERIFIED` in the GitHub Actions summary. It does not turn vendor success into image success.

## Next acceptance

The repository workflow variable `SAPPHON_RUST_BASE_IMAGE` must be set to an authentic, registry-resolved Rust/Cargo base in `repository/path@sha256:<64 lowercase hex>` format. Do not use a made-up digest or mutable tag. The hosted runner must prove `RepoDigests` contains it, build using `--network=none --pull=false`, export `207-image.tar`, and independently recompute its SHA-256 against receipt and run/attempt-bound source-owned reports. An additional external custodian and authenticated time/anti-rollback remain independently required for any operational authority.

**Do not clear locks, promote recovery or claim independent witnesses from GitHub-only source ancestry.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
