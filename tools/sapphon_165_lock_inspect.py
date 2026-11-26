#!/usr/bin/env python3
"""SAPPHON-165 candidate lockfile inspection, never supply-chain certification.

The registry-generated lockfile remains a candidate until separately reviewed,
committed, and verified from that same pinned source revision.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path

PACKAGES=("node_modules/playwright","node_modules/playwright-core")
VERSION="1.65.1"

def inspect(lock, package):
    issues=[]
    if lock.get("lockfileVersion")!=3:
        issues.append("LOCKFILE_V3_REQUIRED")
    root=lock.get("packages",{}).get("",{}).get("devDependencies",{})
    if root.get("playwright")!=VERSION or package.get("devDependencies",{}).get("playwright")!=VERSION:
        issues.append("ROOT_VERSION_MISMATCH")
    for name in PACKAGES:
        item=lock.get("packages",{}).get(name,{})
        if item.get("version")!=VERSION:
            issues.append(name+":VERSION")
        expected="https://registry.npmjs.org/"+name.rsplit("/",1)[-1]+"/-/"+name.rsplit("/",1)[-1]+"-"+VERSION+".tgz"
        if item.get("resolved")!=expected:
            issues.append(name+":REGISTRY_ORIGIN")
        integrity=item.get("integrity","")
        if not integrity.startswith("sha512-"):
            issues.append(name+":MISSING_SHA512")
        else:
            try:
                raw=base64.b64decode(integrity[7:].split()[0],validate=True)
                if len(raw)!=64:issues.append(name+":SHA512_LENGTH")
            except (ValueError,TypeError):
                issues.append(name+":INVALID_SHA512")
    if lock.get("packages",{}).get("node_modules/playwright",{}).get("dependencies",{}).get("playwright-core")!=VERSION:
        issues.append("PLAYWRIGHT_CORE_DEPENDENCY")
    return sorted(set(issues))

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--lock",default="package-lock.json")
    p.add_argument("--package",default="package.json")
    p.add_argument("--out",default="qualification-artifact/165-lock-inspection.json")
    a=p.parse_args()
    lockpath=Path(a.lock)
    raw=lockpath.read_bytes()
    lock=json.loads(raw)
    package=json.loads(Path(a.package).read_text())
    issues=inspect(lock,package)
    report={"schema":"sapphon-165-lock-inspection-v1",
        "lock_sha256":hashlib.sha256(raw).hexdigest(),
        "package_version":VERSION,"issues":issues,
        "candidate_schema_complete":not issues,
        "registry_provenance_independently_authenticated":False,
        "committed_lock_qualified":False,
        "external_custody_authenticated":False,"recovery_authorized":False,
        "decision":"CANDIDATE_LOCK_HOLD"}
    out=Path(a.out)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("LOCK CHECK:", "FIELDS COMPLETE" if not issues else ", ".join(issues))
    if issues:raise SystemExit(1)

if __name__=="__main__":main()
