# SAPPHON-220 — Frozen Image Parity and External Custody Handoff

## Confirmed source-owned evidence

SAPPHON-219 hosted adjudication run [46157658571](https://github.com/DavidWise01/super-sapphon/actions/runs/46157658571) completed SUCCESS, with regression, compact artifact acquisition, ancestry adjudication and evidence archival passing.

The output artifact **15268885124** (`sapphon-219-source-owned-parity`) was downloaded, and its 630-byte ZIP was independently hashed to SHA-256 `aee92239ebb2ed1a2f85715b6c663300356b008bf97ace4166265fa0999e6c22`, matching the GitHub artifact receipt.

The enclosed `219-frozen.json` reported `SOURCE_OWNED_IMAGE_BYTE_PARITY_VERIFIED`, an empty blocker list, original source run `46154833375` / attempt `1` / commit `c167a95a05177e280625fa61613c1b1fa20f75e9`, with frozen digests:

| File | SHA-256 |
| --- | --- |
| Cargo.lock | `2ee90c706c436c450c786e7ecf5a12243c9dd8fc213a39d0ff071737dab6238c` |
| Vendor TAR | `84c024537ba4d52f6892d080b08ed94c9a5a38c666cd1538a932bbfedd90c38e` |
| OCI image TAR | `32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197` |

Original large ZIP envelope SHA-256 has **not** been independently recomputed outside GitHub; independent second-runner checks covered its extracted files.

## Handoff implemented

`tools/sapphon_220_custody_handoff.py` emits a canonical SHA-256-bound manifest and accepts a possible external custody receipt for negative-control review. It refuses run/attempt substitution, mismatched digests, missing signature/time/anti-rollback claims and false recovery declarations.

Crucially, self-declared receipts—even with signature strings or labels claiming an external custodian—**cannot authenticate** independently held keys, custody ancestry, trusted time or external anti-rollback. The review always emits **HOLD**, with independently authenticated witnesses set to **0**. No operational release is implemented.

Ten regression cases and a GitHub Actions workflow publish the handoff manifest. They do not pretend to create an external custodian.

## External acceptance boundary

An independent organization/custodian must receive or compute the frozen bytes, authenticate its own identity and signing key through an independent trust channel, sign a checkpoint bound to the full manifest and original source, and provide separately verified time and anti-rollback evidence. Those actions are **not** completed by this GitHub-owned source pipeline. Three GitHub runners remain one owned ancestry, not three witnesses.

**Independent witnesses 0 · Authenticated UTC unverified · Global anti-rollback unverified · Recovery HOLD · Lock cleared FALSE.**

`{r[g(b → 0xyz/.|.\\ )]} · {{i}} · .dlw`
