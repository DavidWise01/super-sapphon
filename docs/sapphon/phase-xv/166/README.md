# SAPPHON-166 — Exact-Run Lock Candidate Intake and Evidence Reconciliation

**Phase XV · bound 6 of 8 · 75% source-design progression · operational authority HOLD**

## Outcome

SAPPHON-166 adds a fail-closed intake gate for the exact `SAPPHON-165` GitHub Actions candidate artifact. Its review requires a **specific predecessor Git commit, run ID, run attempt, genuine artifact bytes and exact SHA-256 correspondence**. The phase deliberately does not replace the committed provisional `package-lock.json` in the absence of validated candidate bytes.

Source-owned GitHub evidence and external physical custody are different concepts. A valid GitHub workflow artifact can be consistent, but it does not qualify as an independently controlled custodian.

## Source additions

- `tools/sapphon_166_artifact_intake.py`: reads GitHub Actions runs for `sapphon-165-recover.yml` and selects only completed runs with pinned source commit `f697afc224d9ca7404aad8c33e827abad6f2342b`. Attempts to download the named `sapphon-165-registry-lock-candidate` artifact by run ID and retains status/errors when unavailable. It does not substitute a different commit or fabricated artifact.
- `tools/sapphon_166_candidate_review.py`: validates run-scoped `165-run-summary.json`, registry candidate inspection and `165-registry-candidate-package-lock.json`. Requires the matching source SHA, run ID, attempt, registry step success, recorded SHA-256 and structural Playwright/Playwright Core `1.65.1` SHA-512 fields. Retains the candidate as **uncommitted** with recovery HOLD.
- `tools/test_sapphon_166_candidate.py`: eleven authored synthetic negative controls for changed commit, run, attempt, candidate bytes, missing integrity, failed registry step, false promotion, false custody and broken inspection.
- `rust/sapphon-liveness/src/candidate166.rs`: exact-identity candidate comparison and create-only, fsynced HOLD-only JSON review; eight authored Rust regression tests.
- `.github/workflows/sapphon-166-intake.yml`: performs artifact intake, candidate consistency review, full inherited Rust tests, all 188 frozen historical file checks and four-page exact SHA source/deployed parity. Uploads all possible evidence even if a gate fails, and fails the job if any required check is missing or unsuccessful.
- The new source and viewer are additive. No changes were made to the historic 188 protected files.

## Current evidence limitations

During this turn, public GitHub Actions and npm registry endpoints were inaccessible from the authoring environment. The combined GitHub commit status for the previous bound did not expose a completed workflow. Consequently **no genuine registry-produced lockfile artifact was obtainable**, and the provisional `package-lock.json` remains unchanged.

The Rust and Python tests have been authored, not reported as run successfully. The SAPPHON-166 workflow has been committed, not independently certified as passing; GitHub Actions and GitHub Pages share one owned-source ancestry.

## Explicit qualification state

- Phase XV source design: 6/8 (75%)
- Candidate artifact: not retrieved/validated by this authoring session.
- Committed lockfile: unqualified draft; do not claim registry-backed integrity.
- Rust tests, 188 historical source hash comparisons, and four HTML Pages byte parity: configured in GitHub Actions; completed results require actual job readback.
- Physical custody independence, authenticated monotonic external checkpoints and UTC, key rotation, lock clearance and recovery: **HOLD**.

## Next bound — SAPPHON-167

Review the exact SAPPHON-166 intake and candidate output. If a genuine lockfile exists and matches the pinned artifact's run ID, attempt and digest, commit **only those authenticated bytes**, then run `npm ci`, Rust, Chromium and exact Pages parity from the new pinned source commit. If the candidate remains missing, produce and retain a precise missing-evidence report instead of fabricating integrity values.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
