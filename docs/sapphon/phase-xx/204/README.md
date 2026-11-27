# SAPPHON-204 — Offline-Pinned Rust Reproduction & Diagnostic Artifact Parity

**Phase XX · Bound 4/8 · 50% source-design progress · operational HOLD**

## Executive summary

SAPPHON-204 defines fail-closed conditions for running a Rust compiler/test diagnostic in a network-disabled, read-only container. It does **not** execute a Rust replay by default. Original SAPPHON-201 failure evidence and SAPPHON-202/203 source-owned readback ancestry remain prerequisites, alongside a real pinned Cargo.lock, verified immutable Docker image SHA-256, and a complete offline Cargo dependency environment.

A direct GitHub source inspection confirmed `rust/sapphon-liveness/Cargo.toml` exists and contains dependencies including `serde`, `sha2`, `hex`, `ed25519-dalek`, `libc`, and local workspace crates. The inspected paths `rust/sapphon-liveness/Cargo.lock` and repository-root `Cargo.lock` returned not-found. The module additionally checks `rust/Cargo.lock` during execution. A missing lockfile must never be presented as pinned reproducibility, and an unverified Docker image tag must never substitute for a content digest.

The GitHub commit-associated SAPPHON-203 workflow and combined status lookups returned no associated entries. Those lookups are not exhaustive for push-triggered workflows. Neither a genuine original Rust failure nor an offline verified image was observed in authoring.

## Committed implementation

- `tools/sapphon_204_offline_rust.py`: exact source identity; Cargo.lock presence, header, and SHA-256 equality; immutable image digest syntax; original-failure and source-byte ancestry gates; reviewed `cargo test --offline --locked` argument vector; bounded Docker command with `--pull never`, `--network none`, read-only source mount, unprivileged user, isolated tmpfs, dropped privileges, CPU/memory/PID/time limits; output hashing. The workflow invokes **preflight only**; no actual replay is authorized without original failure and independently checked offline dependencies.
- `tools/test_sapphon_204_offline_rust.py`: **16 authored negative controls**, including missing Cargo.lock, forged image tag, incorrect SHA, insufficient evidence, source substitution, no-network and read-only safeguards.
- `rust/sapphon-liveness/src/offline204.rs`: Rust precise provenance and offline image qualification; **10 authored regression tests**, additively registered in `lib.rs`, fsynced create-only HOLD records.
- `.github/workflows/sapphon-204-offline-rust.yml`: checks out historical source commit, runs Python and Rust tests plus 188-file read-only historical verification, records Cargo.lock and image prerequisite state without inventing an immutable replay image or successful reproduction.
- `docs/sapphon/phase-xx/204/index.html`: interactive neon 4D visual lab, purely illustrative.

## Qualification

| Criterion | State |
| --- | --- |
| Phase XX source design | **4/8 · 50% committed** |
| New Python negative controls | **16 authored**, hosted execution unverified |
| New Rust negative controls | **10 authored**, hosted execution unverified |
| Cargo manifest | Observed in GitHub source |
| Pinned Cargo.lock | **Not found in inspected locations**, offline qualification HOLD |
| Verified offline Docker image and cached dependencies | **Not established** |
| Actual original SAPPHON-201 Rust failure | **Not observed** |
| Sandboxed offline Rust replay | Code path proposed; **not executed** |
| Frozen historical sources | Preserved; 188-file read-only check retained |
| Hosted CI / live Pages | Unverified |
| Authenticated UTC / external independent witnesses / global anti-rollback | HOLD / zero verified |
| Physical recovery and lock clearance | HOLD |

## Next natural bound — SAPPHON-205

**Lockfile Genesis With Controlled Dependency Provenance.** Create an actual Cargo.lock from the recognized workspace with source/resolution evidence, pin and hash an immutable image containing the vendored dependencies, and run a **network-none offline lockfile consistency test**. No runtime failure replay until both this check and genuine original failure evidence pass.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
