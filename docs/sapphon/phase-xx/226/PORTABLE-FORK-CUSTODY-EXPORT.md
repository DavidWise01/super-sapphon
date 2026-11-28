# SAPPHON-226 — Portable Signed-Fork Export & Non-Destructive Custody Handoff

## Verified predecessor

SAPPHON-225 report-triggered GitHub Actions run [46162245572](https://github.com/DavidWise01/super-sapphon/actions/runs/46162245572) completed **SUCCESS**, following run `46162224770` whose twelve regression cases passed. The SAPPHON-225 evidence source preserved both simulated Ed25519-signed conflicting checkpoint heads; the live gate has not received independently authenticated external signed heads.

## New source

- `tools/sapphon_226_fork_export.py` exports a canonical, hash-bound portable evidence bundle containing every head envelope, its canonical SHA-256, both fork branches, exact source run/commit, and the original image digest.
- It detects missing branches, altered envelopes, inconsistent head hashes, changed fork manifests, and claims to clear recovery.
- An optional acknowledgment is checked against the bundle SHA-256 and a stated custodian root. Neither a matching acknowledgment nor a declaration of an external signature proves independent custody. The verifier always retains independent witness count **0** and operational **HOLD**.
- `tools/test_sapphon_226_fork_export.py` provides twelve signed-fixture regression cases. These keys are generated locally and do not represent external witnesses.
- `.github/workflows/sapphon-226-fork-export.yml` executes tests and preserves an explicit missing-external-fork negative-control verdict.

## Structural limitations

The export preserves canonical signed-envelope content, not original uploaded whitespace, transport framing or a physical custody receipt. GitHub artifacts may expire; for actual external custody independent recipients must durably retain and separately hash the transferred bytes, authenticate their keys through a truly independent trust channel, sign a verified receipt, and supply externally anchored sequence and time evidence. A self-declared receipt cannot qualify those properties.

**Original source-owned OCI image byte parity: VERIFIED. Independent external custodian: NOT ESTABLISHED. Authenticated UTC: UNVERIFIED. Anti-rollback authority: UNVERIFIED. Recovery: HOLD. Lock cleared: FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
