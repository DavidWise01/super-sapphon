# SAPPHON-136 — Phase XI signed-witness qualification and freeze

**Phase XI 8/8 implementation steps; operational authority HOLD.**

## Implemented source
- `rust/sapphon-liveness/src/attest136.rs`: Ed25519 signature checks over a domain-separated exact acquisition digest, witness ID, and monotonic counter.
- `TrustedKey` registry passed in by an external trusted caller. Key registry duplicates, repeated public keys, revoked keys, stale counters, signature mismatches, acquisition conflicts, and shared **declared** ancestry fail closed.
- Six Rust unit tests check valid signatures (still HOLD), invalid signatures, revocation, replay, ancestry collision and acquisition conflict.
- `.github/workflows/sapphon-136-freeze.yml`: read-only CI for Rust tests, formatting, docs, recovery regressions, 188 inherited frozen hashes and HOLD gates.

## Evidence limits
Signatures establish possession of a private key corresponding to a supplied public key. They do NOT prove that the key holder is a separate person, organization, storage device, physical process, or evidence lineage.
The code cannot independently authenticate registry provisioning, revocation updates, the counter floor, physically independent custody, or UTC. Those inputs require separately qualified systems.
The witness code contains no codepath that clears the lock, advances a physical-clock authority, or permits global rollback changes.

## Freeze decision
The Phase XI design sequence is complete, but a security freeze cannot be certified until GitHub Actions reports a passing gate against the exact revision and the inherited hashes are confirmed there.
Global anti-rollback, external independent custody, physical-clock authority, authenticated UTC and operational recovery remain HOLD.

## Next natural bound
SAPPHON-137 — external registry provenance and revocation monotonicity; follow the replay floor across process restarts with independent trust roots. Never infer source independence from signatures alone.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
