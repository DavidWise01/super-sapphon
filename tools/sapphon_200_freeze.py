#!/usr/bin/env python3
"""SAPPHON-200: exact eight-bound Phase XIX source freeze.

Source inventory completion is not a CI PASS, a live Pages deployment,
independent custody, authenticated UTC, or global anti-rollback.
"""
import argparse, hashlib, json, pathlib, re, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCES={
 193:"rust/sapphon-liveness/src/triage193.rs",
 194:"rust/sapphon-liveness/src/acquire194.rs",
 195:"rust/sapphon-liveness/src/crossverify195.rs",
 196:"rust/sapphon-liveness/src/reacquire196.rs",
 197:"rust/sapphon-liveness/src/monotonic197.rs",
 198:"rust/sapphon-liveness/src/import198.rs",
 199:"rust/sapphon-liveness/src/retention199.rs",
 200:"rust/sapphon-liveness/src/freeze200.rs"}
REQUIRED=("PYTHON","RUST","FROZEN","RETENTION","PAGES","BROWSER")
STATES=("success","failure","cancelled","timed_out","skipped","not_observed")
HEX40=re.compile(r"^[0-9a-f]{40}$")
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def freeze(head,modules,outcomes,retention):
 errors=[];inventory=[]
 if type(head) is not str or HEX40.fullmatch(head) is None:errors.append("SOURCE_HEAD_INVALID")
 if type(modules) is not dict or set(modules)!=set(SOURCES):errors.append("EIGHT_SOURCE_SET_INVALID")
 for bound,path in SOURCES.items():
  raw=modules.get(bound) if type(modules) is dict else None
  if type(raw) is not bytes or not raw:
   errors.append("SOURCE_MISSING_OR_EMPTY:"+str(bound));continue
  inventory.append({"bound":bound,"path":path,"bytes":len(raw),"sha256":sha(raw)})
 if type(outcomes) is not dict or set(outcomes)!=set(REQUIRED):
  errors.append("OUTCOME_SET_INVALID");outcomes=outcomes if type(outcomes) is dict else {}
 for key in REQUIRED:
  if outcomes.get(key) not in STATES:errors.append("OUTCOME_INVALID:"+key)
 if type(retention) is not dict or retention.get("schema")!="sapphon-199-retention-v1":
  errors.append("RETENTION_RECORD_UNVERIFIED");retention={}
 if retention.get("recovery_authorized") is not False or retention.get("lock_cleared") is not False:
  errors.append("RETENTION_FALSE_AUTHORITY")
 state=retention.get("state","NOT_OBSERVED")
 if type(state) is not str or len(state)>128:errors.append("RETENTION_STATE_INVALID")
 if retention.get("deletion_confirmed") is not False:errors.append("UNSUPPORTED_DELETION_CLAIM")
 if retention.get("global_anti_rollback_authenticated") is not False:errors.append("FALSE_ANTI_ROLLBACK")
 if retention.get("independent_witnesses")!=0:errors.append("FALSE_INDEPENDENT_WITNESSES")
 design_complete=len(inventory)==8 and not errors
 return {"schema":"sapphon-200-phase-xix-source-freeze-v1",
  "source_head":head,"phase":19,"bounds":8,
  "source_design_complete":design_complete,
  "source_design_percent":100 if design_complete else 0,
  "sources":inventory,"inventory_sha256":sha(canonical(inventory)),
  "observed_outcomes":{k:outcomes.get(k,"not_observed") for k in REQUIRED},
  "inherited_retention_state":state,
  "original_199_parent_observed":retention.get("original_parent_verified") is True,
  "source_tests_observed_success":design_complete and
    all(outcomes.get(k)=="success" for k in ("PYTHON","RUST","FROZEN")),
  "findings":sorted(set(errors)),
  "original_199_artifact_authenticated":False,
  "live_pages_deployment_authenticated":False,
  "successful_hosted_run_independently_verified":False,
  "external_custody_authenticated":False,
  "independent_witnesses":0,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,
  "deletion_independently_verified":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"PHASE_XIX_FINAL_SOURCE_FREEZE_HOLD"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--head",required=True)
 p.add_argument("--root",default=str(ROOT))
 p.add_argument("--outcomes",required=True)
 p.add_argument("--retention",required=True)
 p.add_argument("--out",default="qualification-artifact/200-freeze.json")
 a=p.parse_args()
 root=pathlib.Path(a.root)
 modules={n:(root/path).read_bytes() for n,path in SOURCES.items() if (root/path).is_file()}
 observed=json.loads(pathlib.Path(a.outcomes).read_text())
 if observed.get("schema")!="sapphon-200-outcomes-v1":raise ValueError("OUTCOMES_SCHEMA")
 retention=json.loads(pathlib.Path(a.retention).read_text())
 result=freeze(a.head,modules,observed["outcomes"],retention)
 target=pathlib.Path(a.out);target.parent.mkdir(parents=True,exist_ok=True)
 target.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["decision"],result["findings"],len(result["sources"]))
 if not result["source_design_complete"]:sys.exit(1)
if __name__=="__main__":main()
