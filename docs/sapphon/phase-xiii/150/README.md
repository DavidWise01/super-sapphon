# SAPPHON-150 — Total-State Substitution & Contradictory Reconstruction Evidence

**Phase XIII · 6/8 · 75% design progression · operational authority HOLD**

## Executive summary
SAPPHON-150 adds a Linux Rust observation-only review of **three jointly replaceable local surfaces**: the registry transcript, the rotation intent, and the recovered provider trust configuration. Independently supplied expected digests for each surface are treated as required references. The code deliberately uses the **trusted**, separately provided provider key to verify the signed anchor; the recovered provider configuration is never allowed to replace it.

Source: `rust/sapphon-liveness/src/substitution150.rs`.

## Core controls
- Provider configuration fingerprint includes identity, public key and monotonic floor fields. A mismatch against an independently retained fingerprint is recorded as a replacement.
- Local intent bytes must exactly match the externally retained intent digest.
- Local registry bytes must exactly match the externally retained registry digest; when not matching, SAPPHON-149 categorizes rollback, corrupted reconstruction, conflicting signed history, or unanchored advances.
- An apparent match is additionally required to pass complete hash-chain validation and signed-anchor prefix inspection.
- Every review retains the observed digests and the separately supplied expected digests; no review changes state, installs keys or clears a lock.
- Create-only report publication with file/directory fsync and digest verification. This is not physical WORM storage or independent custody.

## Seven Rust regressions authored
1. Exact reconstruction remains `HOLD`.
2. Simultaneous registry, intent and provider replacement is recorded.
3. Missing intent cannot be accepted.
4. Rollback and corrupt-tail reconstruction are distinguished.
5. Forged signed anchor fails independently of recovered provider.
6. Altered trusted provider fingerprint fails.
7. Existing reports cannot be overwritten; modified report bytes fail digest readback.

## Limits and evidence status
These checks cannot prove who controls the external hashes or whether witness keys are physically independent. If an attacker controls the supposed trusted provider and all expected digests, it can present a consistent forgery. The code is not global anti-rollback and it cannot authenticate UTC, OS process exit, or external custody. The result is **HOLD in every case**.

The workflow `.github/workflows/sapphon-150-substitution.yml` is committed with the liveness suite, inherited Rust tests, the 188 frozen hashes, static HOLD assertions and documentation build. Successful execution must be confirmed from Actions; a committed workflow does not establish a pass.

## Next natural bound — SAPPHON-151
Blinded cross-custody replacement challenge, externally retained ledger snapshots, independent-custodian receipts and an adversarial full-state reconstruction matrix. The clean export and quarantine ancestry must be compared without treating common mirrors as separate witnesses.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
