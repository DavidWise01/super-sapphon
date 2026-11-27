#!/usr/bin/env python3
"""SAPPHON-184 Phase XVII final source-design freeze (not runtime qualification).

Read actual files; require eight distinct canonical sources and compare their
byte-level SHA256. Missing CI or external custody cannot be filled by assertion.
"""
import argparse,hashlib,json,pathlib,re,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCES={
177:"rust/sapphon-liveness/src/evidence177.rs",
178:"rust/sapphon-liveness/src/isolation178.rs",
179:"rust/sapphon-liveness/src/replay179.rs",
180:"rust/sapphon-liveness/src/binding180.rs",
181:"rust/sapphon-liveness/src/archive181.rs",
182:"rust/sapphon-liveness/src/crossfile182.rs",
183:"rust/sapphon-liveness/src/contradictions183.rs",
184:"rust/sapphon-liveness/src/freeze184.rs"}
CHECKS=("PYTHON","RUST","FROZEN","RUN_READBACK","ARTIFACT_READBACK","CONTRADICTIONS","PAGES","NPM_LOCK")
STATES=("success","failure","skipped","cancelled","timed_out","not_observed")
HEX40=re.compile(r"^[a-f0-9]{40}$")
def sha(b):return hashlib.sha256(b).hexdigest()
def freeze(head,files,outcomes,lock):
 errors=[]
 if not isinstance(head,str) or not HEX40.fullmatch(head):errors.append("INVALID_HEAD")
 if type(files) is not dict or set(files)!=set(SOURCES):
  errors.append("NONCANONICAL_SOURCE_SET")
 records=[]
 for n,path in SOURCES.items():
  raw=files.get(n) if type(files) is dict else None
  if not isinstance(raw,bytes) or not raw:
   errors.append("MISSING_SOURCE:"+str(n));continue
  records.append({"bound":n,"path":path,"bytes":len(raw),"sha256":sha(raw)})
 if type(outcomes) is not dict:
  outcomes={};errors.append("MALFORMED_OUTCOMES")
 if set(outcomes)!=set(CHECKS):errors.append("OUTCOME_KEY_SET")
 for key in CHECKS:
  if outcomes.get(key) not in STATES:errors.append("INVALID_OUTCOME:"+key)
 source_pass=all(outcomes.get(key)=="success" for key in ("PYTHON","RUST","FROZEN"))
 if not isinstance(lock,bytes):
  errors.append("LOCKFILE_NOT_BYTES");lock=b""
 try:
  parsed=json.loads(lock)
  if type(parsed) is not dict or type(parsed.get("packages")) is not dict:
   errors.append("LOCKFILE_SCHEMA")
 except (UnicodeError,ValueError):
  errors.append("LOCKFILE_JSON")
 design_ok=(not errors and len(records)==8)
 return {"schema":"sapphon-184-final-phase-xvii-freeze-v1",
  "phase":17,"design_bounds":8,"design_percent":100 if design_ok else 0,
  "source_head":head,"sources":records,
  "source_inventory_sha256":sha(json.dumps(records,sort_keys=True,separators=(",",":")).encode()),
  "lockfile_sha256":sha(lock),
  "outcomes":{key:outcomes.get(key,"not_observed") for key in CHECKS},
  "source_checks_recorded_pass":source_pass and not errors,
  "source_design_complete":design_ok,
  "findings":sorted(set(errors)),
  "verified_hosted_run":False,
  "original_bytes_independently_authenticated":False,
  "npm_registry_integrity_qualified":False,
  "pages_deployment_verified":False,
  "external_custody_authenticated":False,
  "global_anti_rollback_authenticated":False,
  "authenticated_utc":False,
  "key_rotation_authorized":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"PHASE_XVII_DESIGN_FREEZE_QUALIFICATION_HOLD"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--head",required=True)
 p.add_argument("--outcomes",help="actual runner outcomes file; missing means not_observed")
 p.add_argument("--root",default=str(ROOT))
 p.add_argument("--out",default="qualification-artifact/184-freeze.json")
 a=p.parse_args();root=pathlib.Path(a.root)
 files={n:(root/path).read_bytes() for n,path in SOURCES.items()}
 states={x:"not_observed" for x in CHECKS}
 if a.outcomes:
  record=json.loads(pathlib.Path(a.outcomes).read_text())
  if record.get("schema")!="sapphon-184-runner-outcomes-v1":
   raise ValueError("OUTCOME_SCHEMA_MISMATCH")
  states=record["outcomes"]
 result=freeze(a.head,files,states,(root/"package-lock.json").read_bytes())
 out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(result["decision"],len(result["sources"]),result["findings"])
 if not result["source_design_complete"]:sys.exit(1)
if __name__=="__main__":main()
