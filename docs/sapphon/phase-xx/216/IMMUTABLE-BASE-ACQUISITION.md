# SAPPHON-216 — Registry Digest Acquisition and Offline OCI Qualification

**Boundary:** Image source acquisition and build are distinct from physical external custody and recovery authority.

## Changes

1. `tools/sapphon_216_resolve_base.sh` accepts the configured exact `SAPPHON_RUST_BASE_IMAGE` when present. When absent, it uses the official `docker.io/library/rust:1-bookworm` tag **only for discovery**, then extracts an actual observed `RepoDigests` reference, pulls the immutable `repository@sha256:...` address and verifies that it remains in the local image's `RepoDigests`. It never guesses SHA-256.
2. The resolution receipt `216-base-resolution.json` records the selected exact reference, image ID and whether tag discovery was used. Any mutable discovery tag is insufficient for a build; the Docker build receives only the resolved immutable digest.
3. `.github/workflows/sapphon-207-vendor.yml` uses an explicit digest acquisition step before optional network-disabled Docker qualification. The base reference is passed through `GITHUB_ENV` only after digest confirmation. Failure keeps image HOLD.
4. `tools/sapphon_215_image_gate.py` streams image archive SHA-256, avoiding whole-image RAM allocation for large Docker exports.
5. `tools/test_sapphon_216_resolve_base.py` adds five static source regressions. These are not claims of actual OCI execution.

## Ancestry and qualification

- SAPPHON-213 source-owned ZIP, vendor TAR, Cargo.lock and all 1,751 vendored files were independently rehashed.
- SAPPHON-215 run `46111805480` concluded SUCCESS for vendor operations; prior image attempt failed because no base was configured. The historical evidence is retained.
- SAPPHON-216 run must independently show resolver PASS, image build PASS, `207-image.tar` and matching SHA-256 receipt, exact run ID, commit and attempt.
- A successful image step is still **source-owned**; no external physical custody, authenticated UTC, global anti-rollback or recovery/lock authority arises from it.

## Final gate

**Recovery: HOLD. Lock cleared: FALSE. Independent external witnesses: 0.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
