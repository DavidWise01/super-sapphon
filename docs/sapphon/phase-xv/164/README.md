# SAPPHON-164 — Dependency Lock, Four-Page Parity and Exact-Run CI Readback

**Phase XV · bound 4 of 8 · 50% source-design progression · operational authority HOLD**

## Executive summary

SAPPHON-164 adds a `package.json`, version-3 `package-lock.json` draft, extended source-to-deployed byte parity for **SAPPHON-160, 161, 162 and 163**, and exact-commit/attempt-scoped GitHub Actions readback. Its CI gate remains strictly HOLD if a required test or integrity check does not pass. No historical frozen files were intentionally changed.

## Important dependency-integrity caveat

Playwright and Playwright Core are declared at exactly `1.65.1`. The initial lockfile was constructed using the conventional npm v3 lockfile structure, because the authoring environment's npm registry request failed with `EAI_AGAIN`. This draft therefore **does not include registry-confirmed integrity hashes**, and must not be described as a verified dependency lock.

The `.github/workflows/sapphon-164-lock.yml` workflow attempts `npm ci`, regenerates lock metadata from the registry, checks that regeneration makes **no changes** and insists on SHA-512 integrity fields for both packages. Accordingly this first revision is expected to be **blocked until the genuine registry-generated lockfile is committed**. The workflow is a diagnostic bridge, not a qualified dependency supply chain. Its failure should be preserved rather than waived or called a pass.

## Executable checks

1. `tools/sapphon_164_pages_parity.py` extends inherited SAPPHON-163 byte parity to the SAPPHON-163 neon viewer. Each Pages file is compared against the corresponding GitHub Contents API file at the **exact workflow commit SHA**. SHA-256, byte length and expected HTML markers must agree.
2. `tools/sapphon_164_actions_readback.py` queries the prior `sapphon-163-parity.yml` Actions workflow; requires the exact pinned source commit `9bda0dfc5887c53223c6093851c39c09de930ac3`, records the attempt-scoped job and step conclusions, and distinguishes matching runs, missing runs and API readback errors. A newer unrelated green run cannot satisfy that commit.
3. The workflow runs full Rust typecheck/inherited tests, 188 historical byte/hash comparisons, and Chromium DOM acceptance. Even if those steps pass, they remain **GitHub-owned observations**, not independent physical custody.
4. The workflow uploads available evidence regardless of failures and finishes with a fail-closed gate for lockfile, Rust, historic hashes, four-page parity and browser interactions.

## Verification limits

GitHub connector source readback verified the previous SAPPHON-163 code and workflow structure, which explicitly installed Playwright without a lockfile. The current environment can run Node/npm but cannot reach npm's registry to generate package integrity fields; Rust Cargo is unavailable locally. A passing runner outcome, deployment parity and independent physical custody have **not** been independently confirmed.

The draft lockfile must be replaced or amended using genuine npm registry metadata on a trusted runner. Do not copy synthetic integrity values or disable the gate to force success.

## Next bound — SAPPHON-165

Capture the actual SAPPHON-164 Actions outcome, incorporate a registry-authenticated npm-generated lockfile without changing preserved historical freezes, and re-run the Rust, browser and deployed-byte parity checks with exact source ancestry.

**DESIGN ADVANCES · LOCK AUTHENTICATION PENDING · OPERATIONAL AUTHORITY HOLD.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
