#!/usr/bin/env python3
"""SAPPHON-120 — Phase IX SOFTWARE freeze only. No real external qualification."""
import hashlib,json,pathlib,re
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/"docs/sapphon/phase-ix/SAPPHON-120-FREEZE.json"
PARENTS=("docs/sapphon/SAPPHON-096-FREEZE.json",
 "docs/sapphon/phase-vii/SAPPHON-104-FREEZE.json",
 "docs/sapphon/phase-viii/SAPPHON-112-FREEZE.json")
def meta(name):
    blob=(ROOT/name).read_bytes()
    return {"sha256":hashlib.sha256(blob).hexdigest(),"bytes":len(blob)}
def source_paths():
    names=[]
    for item in (ROOT/"tools").glob("*.cjs"):
        if re.fullmatch(r"(?:test_)?sapphon_(?:11[3-9]|120)_[a-z_]+\.cjs",item.name):
            names.append(item.relative_to(ROOT).as_posix())
    for item in (ROOT/"tools").glob("*.py"):
        if re.fullmatch(r"sapphon_(?:11[3-9]|120)_[a-z_]+\.py",item.name):
            names.append(item.relative_to(ROOT).as_posix())
    for item in (ROOT/".github/workflows").glob("sapphon-*.yml"):
        if re.fullmatch(r"sapphon-(?:11[3-9]|120)-[a-z-]+\.yml",item.name):
            names.append(item.relative_to(ROOT).as_posix())
    for turn in range(113,121):
        folder=ROOT/f"docs/sapphon/phase-ix/{turn}"
        for item in ("index.html",f"SAPPHON-{turn}-REPORT.md"):
            path=folder/item
            if not path.is_file():raise RuntimeError(f"MISSING_PHASE_IX_SOURCE: {path}")
            names.append(path.relative_to(ROOT).as_posix())
    names=sorted(set(names))
    required=("tools/sapphon_120_audit.cjs","tools/test_sapphon_120_audit.cjs",
     "tools/test_sapphon_120_browser.cjs","tools/sapphon_120_freeze.py",
     ".github/workflows/sapphon-120-freeze.yml")
    for name in required:
        if name not in names:raise RuntimeError(f"MISSING_REQUIRED_SOURCE: {name}")
    if len(names)!=42:raise RuntimeError(f"EXPECTED_42_SOURCES_GOT_{len(names)}")
    return names
def build():
    parents=[];total=0
    for manifest in PARENTS:
        data=json.loads((ROOT/manifest).read_text())
        for name,record in data["files"].items():
            if meta(name)!=record:raise RuntimeError(f"PARENT_FREEZE_CHANGED: {name}")
        count=len(data["files"]);total+=count
        parents.append({"manifest":manifest,"file_count":count,
                        "sha256":hashlib.sha256((ROOT/manifest).read_bytes()).hexdigest()})
    if total!=98:raise RuntimeError("PARENT_FILE_COUNT_MISMATCH")
    return {"schema":"sapphon-120-phase-ix-freeze-v1","phase":"IX","stage":"8/8",
      "software_test_gate":"ACCEPTANCE_REQUIRED","external_custody":"HOLD",
      "physical_clock":"HOLD","global_finality":"HOLD","utc_authority":False,
      "parent_freezes":parents,"files":{p:meta(p) for p in source_paths()}}
def main():
    payload=json.dumps(build(),sort_keys=True,indent=2)+"\n"
    OUT.write_text(payload)
    assert json.loads(OUT.read_text())==build()
    print("PASS SAPPHON-120 freeze",len(json.loads(payload)["files"]),
          "Phase IX source hashes; 98 inherited parent hashes")
if __name__=="__main__":main()
