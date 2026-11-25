#!/usr/bin/env python3
"""SAPPHON-128 Rust-first Phase X SOFTWARE freeze; no external custody claim."""
from __future__ import annotations
import hashlib,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/"docs/sapphon/phase-x/SAPPHON-128-FREEZE.json"
PARENTS=(
 "docs/sapphon/SAPPHON-096-FREEZE.json",
 "docs/sapphon/phase-vii/SAPPHON-104-FREEZE.json",
 "docs/sapphon/phase-viii/SAPPHON-112-FREEZE.json",
 "docs/sapphon/phase-ix/SAPPHON-120-FREEZE.json",
)
ENGINES={
 121:"custodian",122:"origin",123:"challenge",124:"revocation",
 125:"replica",126:"freshness",127:"equivocation"
}
def fingerprint(name):
    blob=(ROOT/name).read_bytes()
    return {"sha256":hashlib.sha256(blob).hexdigest(),"bytes":len(blob)}
def selected():
    names=set()
    for version,slug in ENGINES.items():
        names.add(f"tools/sapphon_{version}_{slug}.cjs")
        names.add(f"tools/test_sapphon_{version}_{slug}.cjs")
    for version in range(121,129):
        folder=f"docs/sapphon/phase-x/{version}"
        names.update((folder+"/index.html",folder+f"/SAPPHON-{version}-REPORT.md"))
    for version,slug in {**ENGINES,128:"freeze"}.items():
        names.add(f".github/workflows/sapphon-{version}-{slug}.yml")
    names.update({
        "tools/sapphon_128_freeze.py",
        "tools/test_sapphon_128_browser.cjs",
        ".github/workflows/sapphon-rust-audit.yml",
        "rust/sapphon-audit/Cargo.toml",
        "rust/sapphon-audit/README.md",
        "rust/sapphon-audit/src/lib.rs",
        "rust/sapphon-audit/src/main.rs",
        "rust/sapphon-audit/src/phase_x.rs",
        "rust/sapphon-audit/tests/audit.rs",
        "rust/sapphon-audit/tests/phase_x.rs",
    })
    if len(names)!=49:raise RuntimeError(f"UNEXPECTED_PHASE_X_SOURCE_COUNT:{len(names)}")
    for name in names:
        if not (ROOT/name).is_file():raise RuntimeError(f"MISSING_PHASE_X_SOURCE:{name}")
    return sorted(names)
def main():
    parent_info=[]
    total=0
    for manifest in PARENTS:
        parsed=json.loads((ROOT/manifest).read_text())
        for name,meta in parsed["files"].items():
            if fingerprint(name)!=meta:raise RuntimeError(f"INHERITED_FREEZE_MODIFIED:{name}")
        count=len(parsed["files"]);total+=count
        parent_info.append({"manifest":manifest,"file_count":count,
          "sha256":hashlib.sha256((ROOT/manifest).read_bytes()).hexdigest()})
    if total!=140:raise RuntimeError("PARENT_FROZEN_FILE_COUNT")
    items={p:fingerprint(p) for p in selected()}
    payload={"schema":"sapphon-128-phase-x-rust-freeze-v1","phase":"X","stage":"8/8",
        "primary_verifier":"rust-sapphon-audit","external_custody":"HOLD",
        "real_utc":"HOLD","global_finality":"HOLD","parent_freezes":parent_info,"files":items}
    OUT.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n")
    if json.loads(OUT.read_text())!=payload:raise RuntimeError("FREEZE_READBACK")
    for file,meta in items.items():
        if fingerprint(file)!=meta:raise RuntimeError(f"SELF_VERIFY_FAILED:{file}")
    print(f"PASS SAPPHON-128 Rust Phase X freeze: {len(items)} source files; {total} inherited hashes verified")
if __name__=="__main__":main()
