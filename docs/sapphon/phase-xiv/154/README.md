# SAPPHON-154 — CI Run Readback Reconciliation

**Phase XIV · 2 of 8 · 25% source-design progression · authority HOLD**

## Implemented
The Linux Rust module `rust/sapphon-liveness/src/readback154.rs` reconciles a **supplied** GitHub Actions run snapshot against independently specified repository, workflow path, commit SHA, run ID, attempt, required job names and expected artifact SHA-256.

Identity mismatches are hard errors. Incomplete/unsuccessful runs, missing required jobs and absent/replayed/mismatched artifacts receive distinct findings. Duplicate job names are rejected. Every result has `signature_or_source_authenticated=false`, `run_success_qualified=false`, `external_custody_authenticated=false`, `recovery_authorized=false`, `lock_cleared=false` and `decision=SNAPSHOT_ONLY_HOLD`.

`VerifiedSnapshotConsistent` means only **internally consistent supplied data**; it is **not a validated GitHub success**.

## Ten Rust tests authored
1. Matching supplied snapshot never certifies CI.
2. Wrong commit rejected.
3. Wrong run attempt rejected.
4. Failed job remains failure.
5. Pending run remains pending.
6. Missing artifact not qualified.
7. Artifact replayed from another run detected.
8. Missing required job identified.
9. Duplicate job names rejected.
10. Create-only review export denies overwrite.

## Workflow evidence
`.github/workflows/sapphon-154-readback.yml` runs all liveness and inherited Rust tests, validates the 188 historic freezes, checks HOLD source assertions, and builds documentation. If earlier steps pass, it queries GitHub using `gh run list --workflow sapphon-153-qualification.yml` with the job's GitHub token and saves the returned run metadata as a new artifact.

The workflow artifact reports only **run metadata observations**. It does not inspect individual GitHub job conclusions or the earlier SAPPHON-153 artifact bytes; those still require a separate readback. No populated snapshot should be treated as independently authenticated merely because it was rendered by a website or supplied by a caller.

## Current external qualification
The available GitHub connector exposes committed source and PR-scoped run discovery but did not return a verified completed **push-triggered** SAPPHON-153 workflow run, its job conclusion, or the actual artifact bytes. We cannot conclude that such a run does not exist. Success remains UNVERIFIED.

The GitHub Pages live deployment is not browser-verified; independent physical custody, authenticated UTC, global anti-rollback and operational recovery remain HOLD.

## Next natural bound — SAPPHON-155
Fetch and compare workflow-run jobs and artifact bytes against a pinned commit and expected run attempt, retain a provenance chain for every readback operation, and refuse to elevate a self-published or GitHub-runner-owned artifact into independent custody.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
