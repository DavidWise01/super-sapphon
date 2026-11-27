#!/usr/bin/env python3
"""SAPPHON-185: diagnostic qualification of the exact Phase XVII freeze run.

Never infer a run from an empty PR-linked lookup. Never repair files or grant
physical authority. Preserve real failed step evidence for subsequent replay.
"""
import argparse,hashlib,json,pathlib,sys
SOURCE="edb582df9db3873d2fe308d219ed30b412d1b06d"
WORKFLOW="sapphon-184-freeze.yml"
JOB="final-freeze"
CRITICAL={
 "PYTHON":"Run Phase XVII Python regression tests",
 "RUST":"Rust all-target build and inherited tests",
 "FROZEN":"Verify all 188 protected historical hashes",
 "INVENTORY":"Build exact eight-bound source freeze from real checkout"}
def hash_obj(x):
 return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def assess(record):
 if type(record) is not dict:raise ValueError("READBACK_NOT_OBJECT")
 blockers=[];unobserved=[]
 if record.get("schema")!="sapphon-171-job-log-triage-v1" or record.get("expected_sha")!=SOURCE or record.get("workflow")!=WORKFLOW:
  blockers.append("INVALID_PROVENANCE")
 obs=record.get("observed")
 if record.get("status")!="EXACT_RUN_OBSERVED" or type(obs) is not dict:
  unobserved.append("EXACT_RUN_NOT_OBSERVED")
  obs={}
 if obs:
  if obs.get("head_sha")!=SOURCE or obs.get("expected_job")!=JOB or obs.get("required_job_unique") is not True:
   blockers.append("RUN_OR_JOB_IDENTITY_CONFLICT")
  for key in ("run_id","attempt"):
   if type(obs.get(key)) is not int or obs[key]<=0:blockers.append("INVALID_"+key.upper())
  if obs.get("run_status")!="completed":unobserved.append("RUN_NOT_COMPLETED")
 else:
  unobserved.append("NO_RUN_METADATA")
 if record.get("job_search_state") not in ("JOB_PAGES_EXHAUSTED",) and obs:
  # For older collectors, absence of a pagination marker is insufficient.
  blockers.append("JOBS_NOT_PROVEN_EXHAUSTIVE")
 failures=[]
 steps=obs.get("required_steps") if type(obs) is dict else []
 if not isinstance(steps,list):steps=[];blockers.append("MALFORMED_STEPS")
 outcomes={}
 for key,name in CRITICAL.items():
  hits=[s for s in steps if type(s) is dict and s.get("name")==name]
  if len(hits)!=1:
   outcomes[key]="NOT_OBSERVED_OR_DUPLICATED"
   if obs:blockers.append("CRITICAL_STEP_NOT_UNIQUE:"+key)
  else:
   state=hits[0].get("conclusion")
   outcomes[key]=state if isinstance(state,str) else "NOT_OBSERVED"
   if state in ("failure","timed_out","cancelled"):
    failures.append({"check":key,"step":name,"conclusion":state})
   elif state!="success":unobserved.append("CRITICAL_STEP_INCOMPLETE:"+key)
 if obs.get("failures"):
  failures.extend({"check":"JOB","detail":x} for x in obs["failures"][:25] if type(x) is dict)
 if record.get("independent_custody_authenticated") is not False or record.get("recovery_authorized") is not False:
  blockers.append("UNAUTHORIZED_CUSTODY_OR_RECOVERY")
 source_pass=(bool(obs) and not blockers and not unobserved and not failures and
              all(outcomes.get(k)=="success" for k in CRITICAL) and
              obs.get("source_owned_success_observed") is True and
              obs.get("run_conclusion")=="success")
 if obs.get("run_conclusion")=="success" and failures:blockers.append("GREEN_RUN_WITH_FAILED_CHILD")
 return {"schema":"sapphon-185-observed-run-v1",
  "source_sha":SOURCE,"workflow":WORKFLOW,
  "run_id":obs.get("run_id"),"attempt":obs.get("attempt"),
  "readback_sha256":hash_obj(record),
  "critical_steps":outcomes,"recorded_failures":failures,
  "blockers":sorted(set(blockers)),"unobserved":sorted(set(unobserved)),
  "source_owned_run_pass":source_pass,
  "repaired_code_executed":False,"recovery_authorized":False,
  "independent_custody_authenticated":False,
  "global_anti_rollback_authenticated":False,"authenticated_utc":False,
  "npm_registry_integrity_qualified":False,"lock_cleared":False,
  "decision":"OBSERVED_FAILURE_ISOLATION_HOLD"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--readback",required=True)
 p.add_argument("--out",default="qualification-artifact/185-diagnostic.json")
 args=p.parse_args()
 rec=json.loads(pathlib.Path(args.readback).read_text())
 result=assess(rec)
 dest=pathlib.Path(args.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(result["decision"],result["blockers"],result["unobserved"],len(result["recorded_failures"]))
 if result["blockers"] or result["unobserved"] or result["recorded_failures"]:sys.exit(1)
if __name__=="__main__":main()
