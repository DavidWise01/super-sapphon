#!/usr/bin/env python3
"""SAPPHON-104 deterministic Phase VII source freeze.
Verify old immutable baseline, hash exact new paths, no generated self-reference.
This is a software inventory, not an external evidence notarization.
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
FILES=[
"tools/sapphon_097_auth.cjs","tools/test_sapphon_097_auth.cjs",
"tools/sapphon_098_chain.cjs","tools/test_sapphon_098_chain.cjs",
"tools/sapphon_099_enrollment.cjs","tools/test_sapphon_099_enrollment.cjs",
"tools/sapphon_100_checkpoint.cjs","tools/test_sapphon_100_checkpoint.cjs",
"tools/sapphon_100_verify.py","tools/sapphon_100_export.cjs",
"tools/sapphon_101_anchor.cjs","tools/test_sapphon_101_anchor.cjs",
"tools/sapphon_101_export.cjs",
"tools/sapphon_102_receipts.cjs","tools/test_sapphon_102_receipts.cjs",
"tools/sapphon_103_challenge.cjs","tools/test_sapphon_103_challenge.cjs",
"tools/sapphon_104_replay.cjs","tools/test_sapphon_104_replay.cjs",
"tools/test_sapphon_104_browser.cjs","tools/sapphon_104_freeze.py",
"docs/sapphon/phase-vii/index.html",
"docs/sapphon/phase-vii/SAPPHON-097-REPORT.md",
"docs/sapphon/phase-vii/098/index.html","docs/sapphon/phase-vii/098/SAPPHON-098-REPORT.md",
"docs/sapphon/phase-vii/099/index.html","docs/sapphon/phase-vii/099/SAPPHON-099-REPORT.md",
"docs/sapphon/phase-vii/100/index.html","docs/sapphon/phase-vii/100/SAPPHON-100-REPORT.md",
"docs/sapphon/phase-vii/101/index.html","docs/sapphon/phase-vii/101/SAPPHON-101-REPORT.md",
"docs/sapphon/phase-vii/102/index.html","docs/sapphon/phase-vii/102/SAPPHON-102-REPORT.md",
"docs/sapphon/phase-vii/103/index.html","docs/sapphon/phase-vii/103/SAPPHON-103-REPORT.md",
"docs/sapphon/phase-vii/104/index.html","docs/sapphon/phase-vii/104/SAPPHON-104-REPORT.md",
".github/workflows/sapphon-097-provenance.yml",
".github/workflows/sapphon-098-chain.yml",
".github/workflows/sapphon-099-enrollment.yml",
".github/workflows/sapphon-100-audit.yml",
".github/workflows/sapphon-101-anchor.yml",
".github/workflows/sapphon-102-receipts.yml",
".github/workflows/sapphon-103-challenge.yml",
".github/workflows/sapphon-104-freeze.yml",
]
OUTPUT=ROOT/"docs/sapphon/phase-vii/SAPPHON-104-FREEZE.json"
def sha(name):
    b=(ROOT/name).read_bytes()
    return {"sha256":hashlib.sha256(b).hexdigest(),"bytes":len(b)}
def build():
    old=json.loads((ROOT/"docs/sapphon/SAPPHON-096-FREEZE.json").read_text())
    for name,record in old["files"].items():
        assert sha(name)==record, "Phase VI freeze changed: "+name
    assert len(FILES)==len(set(FILES)), "Duplicate manifest entry"
    result={"schema":"sapphon-104-phase-vii-freeze-v1","phase":"VII","stage":"8/8",
       "software_status":"TESTED_ONLY","external_custody":"HOLD",
       "physical_clock":"HOLD","utc_authority":False,
       "phase_vi_baseline_sha256":hashlib.sha256((ROOT/"docs/sapphon/SAPPHON-096-FREEZE.json").read_bytes()).hexdigest(),
       "phase_vi_file_count":len(old["files"]),
       "files":{name:sha(name) for name in FILES}}
    return result
def main():
    result=build()
    OUTPUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    assert json.loads(OUTPUT.read_text())==build()
    print("PASS Phase VII manifest",len(result["files"]),"files; Phase VI",result["phase_vi_file_count"],"hashes")
if __name__=="__main__": main()
