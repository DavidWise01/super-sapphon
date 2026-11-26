# SAPPHON-155 — Run-Scoped Artifact Authentication and Readback Provenance

**Phase XIV · bound 3 of 8 · 37.5% source design · operational authority HOLD**

## Evidence boundary

The Rust module `rust/sapphon-liveness/src/artifact155.rs` extends the SAPPHON-154 readback comparison. It requires the exact downloaded JSON entry bytes to hash to an independently supplied SHA-256; checks the JSON schema, repository, commit, run ID, attempt, prior-test claims and HOLD conditions; and compares those against a supplied GitHub run/job/artifact snapshot. Results distinguish matching but **untrusted** snapshots, failed/incomplete jobs, and artifact mismatch. A claim of independently authenticated custody fails.

In particular, a GitHub Actions artifact ZIP hash differs from the SHA-256 of the JSON entry contained inside it. Neither hash proves who retained the reference value.

Seven Rust tests are authored: exact matched bytes remain HOLD; modified bytes rejected; wrong artifact attempt; changed embedded run ID; failed job; missing artifact; and self-asserted independent custody.

## GitHub-sourced readback workflow

`.github/workflows/sapphon-155-artifact.yml` first runs the liveness and inherited Rust suites and all 188 historical source hash checks. If those pass, its GitHub-token step queries recent completed successful `sapphon-153-qualification.yml` runs, fetches job conclusions and a run-scoped named artifact, downloads the ZIP, hashes the ZIP and extracted `ci-claim.json`, and requires exact agreement of the embedded claim with repository, Git commit, run ID and attempt. The resulting `155-observation.json` is uploaded as a workflow artifact.

This mechanism is not an independent custody provider: GitHub Actions code and evidence are part of the same repository/security domain. The workflow examines up to the latest 30 runs and the API first page of up to 100 jobs/artifacts. Failure or absence yields a recorded readback error/absence; it does not promote authority.

The Rust module does not make network calls or authenticate the origin of supplied metadata; that remains a separate evidence and trust requirement.

## Qualification state

- Source module, integration, workflow and report: committed.
- Rust and historical frozen-hash outcomes: not verified by an examined completed Actions run.
- GitHub job/artifact readback: configured, not yet verified by examining live results.
- Browser/Pages deployment: unverified.
- Independent custody, authenticated UTC, global anti-rollback, key acceptance, lock clearance and recovery: HOLD.

## Next bound — SAPPHON-156

Reproducible run custody split: pin artifact and workflow provenance outside the repository-controlled Actions environment and compare two separately acquired observations. Expose claimed vs observed states in the lab without treating two GitHub mirrors as independent roots.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
