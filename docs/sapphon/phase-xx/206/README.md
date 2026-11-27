# SAPPHON-206 — Exact Hosted Lockfile Import & Offline Image Custody

**Phase XX · Bound 6/8 · 75% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-206 acquires the *actual* SAPPHON-205 Actions artifact, if hosted and still available, for the pinned final source commit `a73488b1cbfa353d7a2e0d0bd762f7402f7117ee`. It binds the exact workflow `sapphon-205-lock-genesis.yml`, run ID, attempt number, artifact name `sapphon-205-cargo-lock-and-offline-provenance`, and original ZIP. It requires the raw `Cargo.lock` SHA-256 to agree with both `205-provenance.json` and `205-summary.json`, while rejecting missing or failed lock-generation, vendor, offline, and provenance steps.

During authoring, GitHub's PR-associated workflow-run check and combined commit-status check returned **no entries** for SAPPHON-205. They do not exhaust push-triggered Actions. Direct repository paths for a source lockfile remained absent. No genuine SAPPHON-205 lockfile artifact has been acquired in this authoring session; **no lockfile bytes were committed to Git**.

## Source committed

- `tools/sapphon_206_import_lock.py`: bounded exact GitHub Actions run/artifact listing; original-byte ZIP retrieval; safe unique ZIP members; original run/attempt/source comparison; lockfile SHA-256 parity across report, summary and bytes; create-only source-independent lockfile output; explicit unobserved, expired, missing and conflict states.
- `tools/test_sapphon_206_import_lock.py`: **16 authored regression cases** for wrong attempts, ancestry substitutions, inconsistent hashes, false offline receipts, duplicate/unsafe ZIP members, absent lockfile and forged recovery.
- `rust/sapphon-liveness/src/import206.rs`: Rust source-owned lockfile parity, original vendor/image evidence segregation, **8 authored tests** and create-only fsynced HOLD findings, registered additively in `lib.rs`.
- `.github/workflows/sapphon-206-import.yml`: inherited Python/Rust and 188-file frozen checks; genuine original SAPPHON-205 artifact import; conditional retention of original raw lock bytes and SHA-256; explicit `source_lockfile_committed=false` and `offline_image_qualified=false` until separate verified promotion.
- `docs/sapphon/phase-xx/206/index.html`: animated neon 4D original Cargo source/import image-custody lab; illustrative only.

## Critical provenance distinction

A *matching original lockfile* establishes a limited GitHub-owned lock source provenance result, not an independently authenticated source, Docker image, or Rust failure reproduction.

The SAPPHON-205 workflow uploads `Cargo.lock`, metadata, checks and sanitized reports; it **does not upload the original vendored dependency tree** or an image digest/manifest. Thus SAPPHON-206 cannot derive a reproducible offline container solely from its 205 artifact. Building an immutable image requires an observed, content-addressed vendor bundle and verified image digest; neither can be invented from the lockfile alone.

The original 188 protected paths and completed Phase XIX source freeze are not modified.

## Qualification checkpoint

| Criterion | State |
| --- | --- |
| Phase XX source-design progress | **6/8 · 75% source code committed** |
| New Python adversarial cases | **16 authored**; hosted execution unverified |
| New Rust regression cases | **8 authored**; hosted execution unverified |
| Genuine SAPPHON-205 artifact | Not retrieved during authoring |
| Exact source lockfile SHA-256 | Acquisition code committed, observed bytes pending |
| Source Cargo.lock promotion | **Not performed without original bytes** |
| Original vendored dependency bundle | **Not present in 205 artifact** |
| Verified immutable offline image | **Not established** |
| Original Rust failure reproduced | **No** |
| Hosted CI and live Pages | Unverified |
| Independent witnesses, UTC, anti-rollback | **0 / HOLD** |
| Physical recovery and lock clearance | **HOLD** |

## Next natural bound — SAPPHON-207

**Vendor Bundle Preservation & Immutable Image Build Qualification.** Amend only new Phase XX code to capture the original vendor tree as a bounded archive with independent file hashes, verify that offline locked Cargo commands use that source tree, and record the actual resulting image ID/digest. Source-owned image parity is not independent witness custody. The missing SAPPHON-205 artifact remains missing until genuinely retrieved.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
