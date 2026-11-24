#!/usr/bin/env python3
"""SAPPHON-096 deterministic Phase VI source/evidence manifest.
Manifest hashes the committed software; this is a reproducible local integrity check,
not external notarization, source authenticity, or a signed clock measurement.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "docs/sapphon/index.html",
    "docs/sapphon/monitor.js",
    "docs/sapphon/source/clock.json",
    "docs/sapphon/live/clock.json",
    "tools/sapphon_publish.py",
    "tools/sapphon_verify_checkpoint.py",
    "tools/test_sapphon_monitor.cjs",
    "tools/test_sapphon_checkpoint.cjs",
    "tools/test_sapphon_browser.cjs",
    ".github/workflows/sapphon-publisher.yml",
)
OUT = ROOT / "docs/sapphon/SAPPHON-096-FREEZE.json"

def build():
    files = {}
    for name in FILES:
        data=(ROOT/name).read_bytes()
        files[name]={"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)}
    publication = json.loads((ROOT/"docs/sapphon/live/clock.json").read_text())
    if publication.get("mode") != "static-archive":
        # Freeze is scoped to verified archival evidence only.
        raise ValueError("Refusing to freeze an unreviewed new event stream")
    if publication.get("record_count") != 8:
        raise ValueError("Archival record count changed")
    return {
        "schema":"sapphon-096-phase-vi-freeze-v1",
        "phase":"VI",
        "stage":"8/8",
        "software_baseline":"SAPPHON-096",
        "physical_pumps":3,
        "logical_clock_registers":4,
        "recorded_phase_count":publication["record_count"],
        "source_mode":publication["mode"],
        "capability":"read-only visualization, checked archival replay and local recovery",
        "not_verified":["physical clock","true UTC","source cryptographic attestation",
                        "independent witness roots","live clock producer"],
        "test_strategy":["Node contract tests","Python verifier","Playwright Chromium on GitHub Actions"],
        "files":files,
    }

def main():
    content=json.dumps(build(),indent=2,sort_keys=True)+"\n"
    OUT.write_text(content)
    candidate=json.loads(OUT.read_text())
    for name,entry in candidate["files"].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==entry["sha256"]
    print("PASS: Phase VI freeze",len(candidate["files"]),"source files checked; archived records",candidate["recorded_phase_count"])

if __name__=="__main__":
    main()
