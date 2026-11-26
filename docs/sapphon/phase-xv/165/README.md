# SAPPHON-165 — Registry Lockfile Recovery and CI Qualification Repair

**Phase XV · bound 5/8 · 62.5% source-design progression · operational authority HOLD**

## Executive summary

SAPPHON-165 provides a **real npm registry-based lockfile recovery workflow** rather than inventing missing SHA-512 package digests. The authoring container could not resolve registry.npmjs.org (`EAI_AGAIN`) and does not have Rust/Cargo installed. Web registry fetch also returned inaccessible. The committed SAPPHON-164 lockfile is a provisional, **unqualified draft**; it must not be presented as a complete integrity-attested dependency lockfile.

The new `.github/workflows/sapphon-165-recover.yml` saves the existing provisional lockfile, removes it only inside the ephemeral GitHub runner, regenerates a candidate `package-lock.json` using live npm package metadata, inspects both Playwright 1.65.1 and Playwright Core 1.65.1 `sha512-` fields and their expected registry origins, executes `npm ci` against the regenerated candidate, and retains the exact candidate bytes and SHA-256 digest in the workflow artifact `sapphon-165-registry-lock-candidate`.

**The candidate is not silently committed.** The final job remains blocking while the committed draft fails its lock inspection. Candidate artifacts are source-owned GitHub Actions evidence. Genuine integrity fields are necessary for reproducibility, but their presence alone does not authenticate an independent physical custodian.

## Source changes

- `tools/sapphon_165_lock_inspect.py` checks npm lockfile schema, exact direct/transitive package versions, expected npm registry origins, SHA-512 field shape and dependency linkage. This is structural validation only; actual archive bytes are checked by `npm ci` in GitHub Actions.
- `tools/test_sapphon_165_lock.py` contains eight offline regression tests covering missing/invalid/short integrity fields, substituted registry URLs, wrong versions, tampered dependency linkage, lock schema and nominal field-complete fixture.
- `rust/sapphon-liveness/src/diagnostic161.rs` was minimally repaired: `BTreeSet::contains` now receives the borrowed `&str` correctly for the inherited expected-check scan. This is a source-level repair; compilation has not been witnessed in the authoring environment.
- The new workflow retains complete inherited Rust suites, all 188 historical frozen-file SHA-256 checks, SAPPHON-162's eight real Chromium UI assertions and SAPPHON-164's four exact deployed-HTML asset comparisons. Each stage retains its own outcome. Uploads occur on failure as well as success.

## Qualification states

| Item | State |
| --- | --- |
| Seven new phase commits or more | Verify GitHub readback separately |
| Real registry-origin SHA-512 metadata | Candidate-generation workflow configured; execution pending |
| Committed lockfile | Provisional; expected inspection failure until replaced |
| Inherited Rust borrowed-string repair | Committed; Rust compiler pass unverified |
| Rust regression and browser acceptance | Configured; completed runner result unverified |
| 188 historical frozen-file hashes | CI check configured; passing execution unverified |
| Four Pages assets pinned to workflow commit | CI check configured; parity unverified |
| Global anti-rollback and independent custody | HOLD |
| Operational recovery, key rotation and lock clearance | HOLD |

## Boundaries

A green future candidate workflow is **not** permission to promote a new key or clear locks. Independent external custody and authenticated monotonic checkpoint retention remain unproven. GitHub code, Actions and Pages share a single owned-source ancestry. Exact input/output claims are append-only observations; they do not become physical authority.

## Next natural bound — SAPPHON-166

Read the exact SAPPHON-165 candidate artifact and workflow logs; review and commit only authentic npm-generated integrity values, then rerun `npm ci`, Rust, frozen-hash, Chromium and deployed-asset checks against that exact source revision. If an issue is observed, repair it without changing the protected 188 files.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
