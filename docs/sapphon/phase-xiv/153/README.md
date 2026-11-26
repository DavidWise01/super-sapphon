# SAPPHON-153 — Phase XIV Qualification Evidence Commissioning

**Phase XIV · 1/8 · 12.5% source-design progression · operational authority HOLD**

## Finding from inspection

The GitHub connector's combined commit-status response for the SAPPHON-152 final source commit reported no statuses. A commit-scoped workflow search returned no pull-request-triggered runs, but that search **does not cover ordinary push-triggered runs**. These observations do not certify the CI as passed, failed, or not executed. Attempts to open the workflow and Pages viewer through the available public web reader also failed. Phase XIII must retain `CI_UNVERIFIED` and `PAGES_UNVERIFIED`.

## New Rust qualification boundary

`rust/sapphon-liveness/src/qualification153.rs` defines a five-category observation ledger for Rust CI, 188 historical hash checks, Pages deployment, a custody root, and a monotonic anchor. Each observation can record a claimed run/locator, alleged commit, readback state and claimed independent provenance. The ledger **never interprets caller-supplied success claims as independently verified evidence**; all authority and certification fields remain false. Claims are sorted deterministically and SHA-256 addressed. Reports are create-only and fsynced; external retention of the returned report digest is still required.

Six source tests cover fail-closed authority, spoofed success, duplicate categories, stable ordering, immutable publication, and forged certification flags.

## GitHub Actions evidence production

`.github/workflows/sapphon-153-qualification.yml` runs the Linux Rust liveness tests, inherited recovery/contention/journal/audit suites, exact 188 inherited historical frozen hashes, HOLD assertions and Rust API docs. If those steps complete successfully, the job writes `qualification-artifact/ci-claim.json` containing repository, commit, run ID and attempt, then uploads it using `actions/upload-artifact@v4`.

The GitHub-run artifact is **not** an independent custodian or a passing result by itself: inspect the actual workflow run, its conclusion, the commit SHA, job steps and artifact bytes. A failure in any earlier test prevents the artifact step in this workflow.

## Verification state at publication

| Criterion | Status |
|---|---|
| Rust qualification source | Committed; not execution-certified |
| GitHub Actions workflow | Committed; completed run not verified |
| Historical 188 frozen source check | Configured; not confirmed passed |
| Browser acceptance and Pages live deployment | Unverified |
| Independently provisioned custody root | HOLD |
| Externally held monotonic checkpoints | HOLD |
| Authenticated UTC and global anti-rollback | HOLD |
| Recovery, key replacement, lock clearance | HOLD |

## Next natural bound — SAPPHON-154

CI run readback reconciler: ingest independently fetched GitHub Actions job and artifact information, reject commit/run mismatches, require actual run conclusions and artifact digests, and preserve failures without converting a GitHub-run artifact into external custody.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
