#!/usr/bin/env python3
"""SAPPHON-179: read-only exact historical freeze verification; no repair."""
import hashlib,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
MANIFESTS=(
 "docs/sapphon/SAPPHON-096-FREEZE.json",
 "docs/sapphon/phase-vii/SAPPHON-104-FREEZE.json",
 "docs/sapphon/phase-viii/SAPPHON-112-FREEZE.json",
 "docs/sapphon/phase-ix/SAPPHON-120-FREEZE.json",
 "docs/sapphon/phase-x/SAPPHON-128-FREEZE.json")
def verify(root=ROOT):
 seen=set()
 for path in MANIFESTS:
  manifest=json.loads((root/path).read_text())["files"]
  for name,meta in manifest.items():
   if name in seen:raise ValueError("DUPLICATE_HISTORICAL_PATH:"+name)
   seen.add(name)
   item=root/name
   data=item.read_bytes()
   if len(data)!=meta["bytes"]:raise ValueError("BYTE_MISMATCH:"+name)
   if hashlib.sha256(data).hexdigest()!=meta["sha256"]:
    raise ValueError("HASH_MISMATCH:"+name)
 if len(seen)!=188:raise ValueError("FROZEN_COUNT_MISMATCH:"+str(len(seen)))
 return len(seen)
if __name__=="__main__":
 try:print("SAPPHON-179 FROZEN SOURCE CHECK PASS",verify())
 except Exception as exc:
  print(type(exc).__name__,str(exc));sys.exit(1)
