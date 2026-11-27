#!/usr/bin/env python3
"""SAPPHON-192: Phase XVIII final eight-bound source-design freeze.

Byte hashes of canonical checked-out Rust modules are source evidence,
not signatures, independent time, runner success, or physical authorization.
"""
import argparse, hashlib, json, pathlib, re, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCES={n:f"rust/sapphon-liveness/src/{name}{n}.rs" for n,name in [
 (185,"observed"),(186,"attempts"),(187,"retention"),(188,"continuity"),
 (189,"forks"),(190,"custody"),(191,"challenge"),(192,"freeze")]}
REQUIRED=("PYTHON","RUST","FROZEN","PREDECESSOR","CHALLENGE","PAGES","NPM_LOCK")
STATES=("success","failure","cancelled","timed_out","skipped","not_observed")
HEX40=re.compile(r"^[0-9a-f]{40}$")
def sha(b):return hashlib.sha256(b).hexdigest()
def freeze(head,modules,outcomes,registry):
 errors=[];records=[]
 if type(head) is not str or not HEX40.fullmatch(head):errors.append("HEAD_INVALID")
 if type(modules) is not dict or set(modules)!=set(SOURCES):errors.append("NONCANONICAL_SOURCE_SET")
 for bound,path in SOURCES.items():
  data=modules.get(bound) if type(modules) is dict else None
  if type(data) is not bytes or not data:errors.append("MISSING_SOURCE:"+str(bound));continue
  records.append({"bound":bound,"path":path,"bytes":len(data),"sha256":sha(data)})
 if type(outcomes) is not dict or set(outcomes)!=set(REQUIRED):
  errors.append("OUTCOME_SET");outcomes={} if type(outcomes) is not dict else outcomes
 for key in REQUIRED:
  if outcomes.get(key) not in STATES:errors.append("OUTCOME_INVALID:"+key)
 if type(registry) is not dict or set(registry)!={"schema","out_of_band_authenticated","keys","authority_source"}:
  errors.append("REGISTRY_INVALID")
 elif (registry["schema"]!="sapphon-190-key-registry-v1" or
       registry["out_of_band_authenticated"] is not False or
       registry["authority_source"]!="none" or registry["keys"]!=[]):
  errors.append("FALSE_EXTERNAL_KEY_ENROLLMENT")
 complete=len(records)==8 and not errors
 return {"schema":"sapphon-192-phase-xviii-freeze-v1",
  "phase":18,"bounds":8,"source_design_complete":complete,
  "source_design_percent":100 if complete else 0,
  "source_head":head,"sources":records,
  "inventory_sha256":sha(json.dumps(records,sort_keys=True,separators=(",",":")).encode()),
  "outcomes":{k:outcomes.get(k,"not_observed") for k in REQUIRED},
  "source_checks_recorded_success":complete and all(outcomes.get(k)=="success" for k in ("PYTHON","RUST","FROZEN")),
  "findings":sorted(set(errors)),
  "successful_hosted_run_independently_verified":False,
  "original_predecessor_artifact_authenticated":False,
  "external_challenge_issued":False,
  "independently_enrolled_keys":0,"independent_witnesses":0,
  "authenticated_utc":False,"npm_registry_integrity_qualified":False,
  "global_anti_rollback_authenticated":False,
  "independent_custody_authenticated":False,
  "key_rotation_authorized":False,"recovery_authorized":False,
  "lock_cleared":False,"decision":"PHASE_XVIII_FINAL_SOURCE_FREEZE_HOLD"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--head",required=True)
 p.add_argument("--root",default=str(ROOT))
 p.add_argument("--outcomes")
 p.add_argument("--out",default="qualification-artifact/192-freeze.json")
 a=p.parse_args()
 root=pathlib.Path(a.root);modules={}
 for n,path in SOURCES.items():
  x=root/path
  if x.is_file():modules[n]=x.read_bytes()
 outcomes={k:"not_observed" for k in REQUIRED}
 if a.outcomes:
  v=json.loads(pathlib.Path(a.outcomes).read_text())
  if v.get("schema")!="sapphon-192-current-run-v1":raise ValueError("OUTCOME_SCHEMA")
  outcomes=v["outcomes"]
 registry=json.loads((root/"docs/sapphon/phase-xviii/190/key-registry.json").read_text())
 result=freeze(a.head,modules,outcomes,registry)
 out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
 out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["decision"],result["findings"],len(result["sources"]))
 if not result["source_design_complete"]:sys.exit(1)
if __name__=="__main__":main()
