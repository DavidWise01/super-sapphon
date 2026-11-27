# SAPPHON-205 — Lockfile Genesis & Controlled Dependency Provenance

**Phase XX · Bound 5 of 8 · 62.5% source-design progress · operational recovery HOLD**

## Executive summary

SAPPHON-205 commits a **real Cargo dependency resolution workflow** rather than a generated-looking placeholder lockfile. The workflow runs Cargo's native resolver against `rust/sapphon-liveness/Cargo.toml`, retains its exact `Cargo.lock` bytes as a GitHub Actions artifact, vendors the locked dependencies, then runs `cargo metadata --locked --offline` and `cargo check --locked --offline` with a source-replacement configuration. The newly created lockfile is retained as *observed output of the runner* if and only if that hosted step executes; it is **not yet committed to the repository source tree**.

The directly inspected source includes `rust/sapphon-liveness/Cargo.toml` and `rust/sapphon-audit/Cargo.toml`. `rust/Cargo.toml`, `rust/Cargo.lock`, `rust/sapphon-liveness/Cargo.lock`, and repository-root `Cargo.lock` were not found in the GitHub paths checked. This means SAPPHON-204's offline qualification blocker was concrete. The new workflow resolves and reports that gap, without inventing a lock digest.

The connected GitHub commit-associated workflow and combined-status lookups for SAPPHON-204 showed no entries. Those APIs are not exhaustive for push-triggered runs. The SAPPHON-205 lock-generation workflow has been committed but successful hosted execution, actual lock bytes, live Pages deployment, immutable image content digest and independent custody are **not yet observed** in this authoring session.

## Source changes

- `tools/sapphon_205_lock_provenance.py`: validates *actual* Cargo.lock TOML syntax, exact target crate, lock format, unique package rows, registry package SHA-256 checksums, parity with Cargo metadata, and truthful completion flags for lock generation, vendoring, offline metadata and offline compilation. Rejects missing files, missing checksums, incompatible metadata and unsupported PASS claims.
- `tools/test_sapphon_205_lock_provenance.py`: **16 authored adversarial tests** for missing lock, inconsistent package graph, malformed checksums, absent vendor/offline steps, and forged source success. Fixture lock contents are synthetic and explicitly not source evidence.
- `rust/sapphon-liveness/src/lock205.rs`: Rust source-owned lock/provenance gate with **10 authored tests** and create-only fsynced HOLD report; registered additively in `lib.rs`.
- `.github/workflows/sapphon-205-lock-genesis.yml`: generate native lock, vendor exact dependencies from the resolver, write a Cargo source-replacement config, attempt offline locked metadata and compile, upload original Cargo.lock and sanitized SHA-256 report, and fail CI when any required check is absent or fails.
- `docs/sapphon/phase-xx/205/index.html`: animated neon 4D dependency provenance lab. Synthetic visual scenarios are not hosted results.

## Controlled boundaries

SAPPHON-205 does **not** auto-commit a lockfile generated from unobserved network resolution. Once an original hosted `Cargo.lock` artifact is acquired and its checksums and offline verification are observed, an exact-byte copy can be added to Git in a later provenance-bound commit. The workflow's GitHub-controlled source and artifacts are one ownership ancestry; neither are independent witnesses.

Cargo registry package SHA-256 checksums attest to package bytes in Cargo's resolution model, not to complete supply-chain trust. The vendor directory and image are **not independently attested**, and Rust/Cargo reproduction of an original SAPPHON-201 failure is **not executed** in this bound.

The original Phase XIX eight-source freeze and all earlier frozen historical paths remain untouched. Existing 188-file read-only checks are preserved.

## Qualification ledger

| Criterion | State |
| --- | --- |
| Phase XX source design | **5/8 = 62.5% committed** |
| Python negative-control cases | 16 authored; hosted execution unverified |
| Rust regression cases | 10 authored; hosted execution unverified |
| Native Cargo.lock generation | Workflow committed, execution unverified |
| Exact Cargo.lock SHA-256 | Pending original hosted bytes |
| Offline vendor metadata and Cargo compilation | Workflow committed, execution unverified |
| Immutable offline Rust container image digest | Not established |
| Original SAPPHON-201 failure reproduction | Not observed / not executed |
| Historical Phase XIX freezes | Preserved |
| Live Pages and hosted CI | Unverified |
| Independent custody / authenticated UTC / anti-rollback | **0 verified / HOLD** |
| Physical recovery and lock clearance | **HOLD** |

## Next natural bound — SAPPHON-206

**Exact Hosted Lockfile Import, Durable Source Pin & Offline Container Qualification.** Acquire the authentic SAPPHON-205 lockfile artifact, independently hash and compare its original bytes to the reported SHA, bind it to the exact hosted run/attempt, and only then commit the verified lockfile and qualify a content-addressed offline Rust container. No speculative image digests, no original-failure replay before evidence.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
