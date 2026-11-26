# SAPPHON-163 — Pinned Browser Dependency and Deployed-Asset Revision Verification

**Phase XV · bound 3/8 · 37.5% source-design progression · operational authority HOLD**

## Executive summary

SAPPHON-163 addresses a concrete reproducibility gap identified in the SAPPHON-162 workflow: it installed the unpinned `playwright` npm package. The new `.github/workflows/sapphon-163-parity.yml` installs the exact published `playwright@1.65.1` release, asserts the locally installed package version, installs its matching Chromium, and runs the inherited eight interactive SAPPHON-160/161 scenario assertions.

The new `tools/sapphon_163_pages_parity.py` compares deployed Pages HTML bytes against exact GitHub Repository Contents API source bytes at `github.sha`. SAPPHON-160, 161 and 162 are independently requested from the source API and Pages HTTP origin, SHA-256 hashed and compared byte-for-byte, including exact length and expected page label/canvas markers. A missing/deployed-stale HTML asset, API failure, altered content or incorrect source path fails closed. The two fetched surfaces still share GitHub ownership and are not independent custodians.

The new `rust/sapphon-liveness/src/parity163.rs` classifies three matching or mismatched source/deployed asset reports with deterministic digesting; it cannot upgrade source parity into custody. Seven Rust regression tests are authored: matching remains HOLD, one changed hash, missing page, HTTP failure, duplicate asset, order-independent digest and create-only output.

## GitHub Actions

`sapphon-163-parity.yml` runs typecheck and inherited Rust suites, checks all 188 historic frozen files, installs a pinned browser version, runs SAPPHON-162 interactions, checks three Pages HTML assets against pinned SHA and queries the previous SAPPHON-162 workflow's recent run/job metadata using the GitHub Actions token. Required failures are retained in uploaded diagnostic artifacts before the final gate reports failure.

A pinned direct npm dependency is an improvement over an unpinned install, **not** a full transitive-dependency lockfile. Full lockfile or OCI image digest pinning remains future hardening work. An exact GitHub SHA comparison proves source/deployment byte equivalence if the API and HTTP readbacks succeed, but not that a source is independent, physically immutable or that the broader app behaves securely.

## Observed evidence and limits

SAPPHON-162 source and workflow were fetched and inspected. It indeed ran `npm install --no-save playwright` without an exact version. The GitHub connector exposes source and combined statuses, but not a general push-triggered workflow run listing. Both the public Pages and Actions readback endpoints were inaccessible through the available external reader, so **no completed successful SAPPHON-162 job or deployed Pages asset has been directly authenticated in this authoring turn**. Do not reinterpret absent status reports as no jobs or successful jobs.

Rust tests and the browser fixture are authored and committed, not locally executed. GitHub Actions and GitHub Pages are one GitHub-controlled source ancestry, not two physical witnesses.

## Qualification boundaries

- Source assets committed: yes.
- Successful pinned dependency installation: not yet established by a completed CI run.
- Chromium interactive checks: configured, passing result unverified.
- Frozen 188 source hashes: configured, passing result unverified.
- Pages/commit byte parity: configured, match unverified.
- External custody, global anti-rollback, authenticated physical UTC, lock clearance, key promotion and operational recovery: **HOLD**.

## Next natural bound — SAPPHON-164

Make browser and source integrity reproducible with a committed dependency lockfile, add source/Pages parity for the SAPPHON-163 viewer itself, and promote only verified run/job results into an observation ledger. No operational authority elevation.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
