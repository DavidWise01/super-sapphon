# SAPPHON-212 — Corrected-Source Vendor Evidence Bound

Status: SOURCE-OWNED VENDOR BUILD OBSERVED; IMAGE/RECOVERY HOLD.

## Ancestry separation

- Historical original SAPPHON-207 source: `aea6cb530ed4b23445a489e23099c63b6049854e`, run `46080606762`, failed. Historical evidence is retained unchanged.
- Corrected source: `3f5eae74398eb318f6eecf409ef19e93eaf55e46`.
- Corrected SAPPHON-207 workflow run `46096591838` completed with conclusion `success`.
- Observed job `140829228025`: Python vendor regressions PASS; Rust provenance regressions PASS (549 unit tests, 14 additional tests); SAPPHON-179 protected paths PASS (188); generated vendor bytes and locked offline Cargo check PASS.
- Source-owned artifact: `15244050179`, `sapphon-207-vendor-and-local-image`, 4,004,302 ZIP bytes, GitHub-reported ZIP SHA-256 `5e23e49fcc1e6bb1a80e747ea058aad634c74504794abd254f0d0ae12e246a7f`.
- Docker image step: failure (optional, continue-on-error), because `SAPPHON_RUST_BASE_IMAGE` is empty. No image tar was qualified.

## Byte boundary

A successful workflow and GitHub-reported ZIP digest do not prove independently recomputed byte digests of the ZIP's contained `207-vendor.tar`, `207-Cargo.lock`, and `207-vendor.json`. This report does not claim that readback. The existing 208 readback is pinned to the earlier failed source; it must not silently relabel evidence from the corrected run as if it came from that historical original.

## Acceptance for SAPPHON-213

1. Select the corrected run by exact run ID, attempt and commit SHA; obtain the original artifact ZIP bytes.
2. Reject duplicate/unsafe ZIP entries; require Cargo.lock, vendor.tar, vendor.json, summary.
3. Recompute SHA-256 for the lock, vendor tree and vendor tar; compare to report and run summary.
4. Preserve source-owned status, optional image absence, external witness count 0, and operational HOLD.
5. Refuse artifact substitutions from the historical failed run and any differing run/attempt.

No independent physical custody, authenticated UTC, global anti-rollback, recovery authority or lock release has been established.

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
