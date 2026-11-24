# SAPPHON-096 — Phase VI Operational Visualization Freeze

**Scope:** A read-only HTML laboratory for a synthetic three-pump clock, backed by recorded event exports.

## Immutable clock geometry
- Physical pumps: 3, R (hot/H), G (neither/O), B (cold/N).
- Eight indexed phases per pump; shared center `{{i}}`.
- Four logical clock address registers: [year, month, day], [hour, minute, second], [degree, arcminute, arcsecond], [arc, arc-arc, arc-arc-arc].
- A single input and output; no pump or time authority added by the browser.
- Preserved `.dlw` marker.

## Browser acceptance criteria
1. Canvas draws the three-pump representation from published phase records.
2. Four logical address registers display exported values.
3. Playback, scrub and view-only fault injection do not mutate source records.
4. Checkpoint export includes every accepted record, four registers, uncertainty, authorization flags and a SHA-256 content digest.
5. Browser reload checks the saved checkpoint against published history.
6. Changed historical prefix or altered local checkpoint causes fail-closed suspension.
7. Published record sequence and source route are checked before accepting new observations.
8. Python and Node software verifiers cross-check archive, checkpoint and source consistency.
9. The CI workflow runs headless Chromium acceptance before writing the deterministic freeze manifest.

## Evidence boundary
The output reflects eight *synthetic archived* clock records, **not a live physical clock**. A URL, SHA-256 digest or matching route declaration does not attest genuine source independence, prove UTC correctness, or grant new time authorization. An external notarization service is not implemented. A browser checkpoint and the published archive share an ownership ancestry and are not independent observers.

## Fail-closed policy
Historical record mismatch, uncertain checkpoint integrity, malformed source record, or broken stream continuity must not trigger new clock authorization. Rejected source history is preserved for inspection; accepted original evidence is not silently rewritten.

## Baseline and verification
See `SAPPHON-096-FREEZE.json` for the hash of each shipped source file, and the `SAPPHON-096 Phase VI Browser Acceptance & Freeze` GitHub Actions run for the real acceptance result. CI success and GitHub Pages deployment are distinct checks.

## Next phase
Phase VII: source transport provenance, durable independent audit anchors, and authenticated non-synthetic source ingest, without changing the frozen read-only clock geometry.
