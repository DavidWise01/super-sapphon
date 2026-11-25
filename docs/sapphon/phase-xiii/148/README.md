# SAPPHON-148 — Interrupted Key Rotation and Provider Failover

**Phase XIII · 4/8 · 50% design progression · operational authority HOLD**

## Summary

SAPPHON-148 adds the Linux-only Rust module `rust/sapphon-liveness/src/failover148.rs`. It creates a **durable, create-only rotation intent** linked to a supplied prior-history SHA-256 digest. A restart may read back exactly that intent, provided its expected digest is retained outside the mutable archive. The journal cannot overwrite an earlier intent file. The implementation does not repair interrupted writes.

An interrupted rotation is classified `InterruptedHold`. Even an intact, correctly dual-signed SAPPHON-147 rotation is classified `ContinuityVerifiedCustodyPending`, not accepted. The module never installs a replacement signing key.

## Provider state classification

- `BothPresent`: the two supplied signed anchors agree at the same sequence, or have no immediate same-sequence head contradiction
- `OneDelayed`: a provider has delayed evidence, which is not converted into an absent provider or a timeout override
- `ProviderMissing`: a custodian observation is absent
- `ProviderRevoked`: a custodian was explicitly flagged revoked
- `ConflictingHeads`: two observed signed checkpoints claim the same sequence and differing heads

This is a limited observation-only classification. The function does not verify complete ancestry across differing sequences (SAPPHON-147 does that), and does not authenticate the physical independence of sources. A missing custodian cannot silently be replaced.

## Regression tests authored

Ten Rust tests cover valid dual-signed intent staying pending; interrupted intent HOLD; mismatched history digest; missing custodian; delayed evidence; matching keys still not clearing a lock; deterministic write and anti-overwrite/readback tampering; conflicting provider heads; revoked provider flag; and absent replacement-key signature.

## Important trust limits

The signature verification and history hash make sense only against **trusted keys and monotonic digests provisioned outside the potentially compromised local owner**. A valid self-owned key, self-supplied ancestry label, or local fsync does not prove independent custody. The implementation cannot authenticate UTC, guarantee hostile filesystem crash atomicity, or authorize remote recovery. All outcomes remain HOLD.

## CI and Pages

The read-only `.github/workflows/sapphon-148-failover.yml` runs the liveness crate tests, inherited Rust security suites, all **188 historical frozen hash checks**, HOLD source assertions, and Rust documentation. Passing Actions execution and Pages deployment are not claimed until independently read back.

## Next natural bound — SAPPHON-149

Recovery intent replay under total local-state replacement: compare an externally anchored intent digest against stale, partial, or contradictory local reconstructions, with separate provider continuity and custody evidence. Preserve HOLD.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
