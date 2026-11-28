# SAPPHON-217 — Hosted OCI image evidence readback and verdict parity

## Actual hosted evidence

Run [46153809451](https://github.com/DavidWise01/super-sapphon/actions/runs/46153809451) on commit `c16810a1145d27147c154573f7d5eb49a0c00204` reported:

- immutable base resolution **success**; Docker supplied `rust@sha256:75d26c23c24cc6ea1cdabf0714a6bff8fd7bf3248716043fd7ae86dac7f41b94`
- offline Docker build / image export step **success**
- Rust suite: 549 unit + 14 additional tests passing
- vendor generation and locked offline Cargo check: **success**
- overall workflow: **failure** (Python image-verdict `SyntaxError`; Python regression step also failed)
- uploaded source-owned artifact ID `15267276234`, GitHub-reported ZIP byte size `730703382`, SHA-256 `f32f2100321d8bf05d02fd2595ee9ae531f4a738c3f5b3bbf0fb81fc0a608ed2`

The Docker image step's success does not retroactively make the failed workflow green, nor does GitHub artifact retention mean the large image tar was independently downloaded and rehashed outside GitHub.

## Corrections applied

1. Remove the literal backslash-n causing `SyntaxError` in `tools/sapphon_215_image_gate.py`.
2. Add explicit Python syntax compilation before Python regression tests, so such failures are detected earlier.
3. Generate image archive SHA-256 using streaming `hashlib.file_digest` rather than loading the large image tar into memory.
4. Add a post-verdict parity guard: a successful image step with an unverified artifact verdict fails the workflow. A missing image remains HOLD even if the vendor build succeeds.
5. Retain artifact export, exact run/attempt and digest evidence, and all recovery authority fences.

## Next qualification

Re-run hosted workflow; require image result SUCCESS and `215-image-verdict.json` state `SOURCE_OWNED_IMAGE_ARCHIVE_VERIFIED`. Download artifact ID from *that same run*, recompute ZIP and contained image tar digests, check the receipt, build report, base-resolution record, run ID, attempt and source commit. This is source-owned artifact qualification only, not independently authenticated physical custody.

**External witnesses: 0. Recovery: HOLD. Lock cleared: FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
