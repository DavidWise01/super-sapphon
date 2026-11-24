#!/usr/bin/env python3
"""SAPPHON-112 Phase VIII deterministic SOFTWARE freeze.
A source inventory with exact bytes, not a cryptographic third-party attestation.
Never silently modify either existing sealed phase manifest.
"""
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"docs/sapphon/phase-viii/SAPPHON-112-FREEZE.json"
def hexdigest(file):
    data=(ROOT/file).read_bytes()
    return {"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)}
def phase_files():
    paths=[]
    for item in (ROOT/"tools").glob("sapphon_*"):
        if re.fullmatch(r"sapphon_(?:10[5-9]|11[0-2])_[a-z_]+\.(?:cjs|py)",item.name):
            paths.append(item.relative_to(ROOT).as_posix())
    for item in (ROOT/"tools").glob("test_sapphon_*"):
        if re.fullmatch(r"test_sapphon_(?:10[5-9]|11[0-2])_[a-z_]+\.cjs",item.name):
            paths.append(item.relative_to(ROOT).as_posix())
    for item in (ROOT/".github/workflows").glob("sapphon-*.yml"):
        if re.fullmatch(r"sapphon-(?:10[5-9]|11[0-2])-[a-z-]+\.yml",item.name):
            paths.append(item.relative_to(ROOT).as_posix())
    for turn in range(105,113):
        folder=ROOT/f"docs/sapphon/phase-viii/{turn}"
        for filename in ("index.html",f"SAPPHON-{turn}-REPORT.md"):
            entry=folder/filename
            if not entry.is_file():
                raise ValueError(f"Missing final Phase VIII source: {entry}")
            paths.append(entry.relative_to(ROOT).as_posix())
    paths=sorted(set(paths))
    if len(paths)<42:
        raise ValueError("Too few Phase VIII sources for a freeze")
    assert "tools/sapphon_112_freeze.py" in paths
    assert ".github/workflows/sapphon-112-freeze.yml" in paths
    assert "tools/test_sapphon_112_browser.cjs" in paths
    assert "tools/test_sapphon_112_splitbrain.cjs" in paths
    return paths
def build():
    v6=ROOT/"docs/sapphon/SAPPHON-096-FREEZE.json"
    v7=ROOT/"docs/sapphon/phase-vii/SAPPHON-104-FREEZE.json"
    parent=[]
    for file,expected in ((v6,11),(v7,45)):
        original=json.loads(file.read_text())
        assert len(original["files"])==expected
        for name,entry in original["files"].items():
            assert hexdigest(name)==entry, f"FROZEN_PARENT_CHANGED: {name}"
        parent.append({"name":file.relative_to(ROOT).as_posix(),
            "manifest_sha256":hashlib.sha256(file.read_bytes()).hexdigest(),"file_count":expected})
    return {"schema":"sapphon-112-phase-viii-freeze-v1","phase":"VIII","stage":"8/8",
        "software_qualification":"PASS_TESTED_CODE_ONLY",
        "external_custody":"HOLD","physical_clock":"HOLD","utc_authority":False,
        "global_cross_host_replay_authority":False,
        "parent_freezes":parent,"files":{file:hexdigest(file) for file in phase_files()}}
def main():
    content=json.dumps(build(),sort_keys=True,indent=2)+"\n"
    OUT.write_text(content)
    again=json.loads(OUT.read_text())
    assert again==build()
    print("PASS SAPPHON-112 freeze",len(again["files"]),"Phase VIII source hashes; inherited",
          sum(x["file_count"] for x in again["parent_freezes"]),"parent hashes")
if __name__=="__main__":main()
