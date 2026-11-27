#!/usr/bin/env python3
"""SAPPHON-193: exact-run source failure adjudication, no inferred CI success.

Read genuine SAPPHON-171 source-owned observations for SAPPHON-192. Separate
failure, absent evidence, and present-but-unproven steps. Never clear locks.
"""
import argparse,hashlib,json,pathlib,sys
SOURCE="9c3734c78bab40690ca1f5f9b65e29362193a1bf"
WORKFLOW="sapphon-192-freeze.yml"
JOB="final-source-freeze"
CRITICAL={
 "PYTHON":"Run eight-bound Python source regression inventory",
 "RUST":"Compile inherited Rust and run exact Phase XVIII regressions",
 "FROZEN":"Verify all 188 immutable historical files",
 "INVENTORY":"Build canonical checked-out final source freeze"
}
def sha(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def diagnose(record):
 if type(record) is not dict:raise ValueError("RECORD_NOT_OBJECT")
 blockers=[];missing=[];failures=[]
 if record.get("schema")!="sapphon-171-job-log-triage-v1" or record.get("repository")!="DavidWise01/super-sapphon":
  blockers.append("READBACK_SCHEMA_OR_REPOSITORY")
 if record.get("expected_sha")!=SOURCE or record.get("workflow")!=WORKFLOW:
  blockers.append("PINNED_SOURCE_ANCESTRY_MISMATCH")
 observed=record.get("observed")
 if record.get("status") not in ("EXACT_RUN_OBSERVED","LATEST_INCOMPLETE") or type(observed) is not dict:
  missing.append("EXACT_RUN_UNOBSERVED");observed={}
 if observed:
  if observed.get("head_sha")!=SOURCE or observed.get("expected_job")!=JOB or observed.get("required_job_unique") is not True:
   blockers.append("JOB_IDENTITY_MISMATCH")
  if type(observed.get("run_id")) is not int or type(observed.get("attempt")) is not int or observed["run_id"]<=0 or observed["attempt"]<=0:
   blockers.append("RUN_IDENTITY_INVALID")
  if record.get("job_search_state")!="JOB_PAGES_EXHAUSTED":
   blockers.append("JOB_PAGINATION_INCOMPLETE")
  if observed.get("run_status")!="completed":
   missing.append("RUN_INCOMPLETE")
 steps=observed.get("required_steps",[])
 if type(steps) is not list:steps=[];blockers.append("REQUIRED_STEPS_MALFORMED")
 results={}
 for key,step in CRITICAL.items():
  found=[x for x in steps if type(x) is dict and x.get("name")==step]
  if len(found)!=1:
   results[key]="NOT_OBSERVED_OR_DUPLICATE"
   if observed:blockers.append("CRITICAL_STEP_UNIQUE:"+key)
  else:
   state=found[0].get("conclusion")
   results[key]=state if type(state) is str else "NOT_OBSERVED"
   if state in ("failure","cancelled","timed_out"):
    failures.append({"kind":"STEP_FAILURE","check":key,"name":step,"state":state})
   elif state!="success":
    missing.append("STEP_INCOMPLETE:"+key)
 reported=observed.get("failures",[])
 if type(reported) is not list:reported=[];blockers.append("FAILED_JOBS_MALFORMED")
 for x in reported[:25]:
  if type(x) is dict:failures.append({"kind":"JOB_OR_CHILD_FAILURE","job_id":x.get("job_id"),"name":x.get("name"),"state":x.get("conclusion")})
 if observed and observed.get("run_conclusion") in ("failure","cancelled","timed_out"):
  failures.append({"kind":"RUN_FAILURE","state":observed["run_conclusion"]})
 if observed and observed.get("run_conclusion")=="success" and failures:
  blockers.append("GREEN_RUN_CONTRADICTS_CHILD_FAILURE")
 if record.get("independent_custody_authenticated") is not False or record.get("recovery_authorized") is not False:
  blockers.append("UNSUPPORTED_AUTHORITY_CLAIM")
 owned_pass=(bool(observed) and not blockers and not missing and not failures
             and observed.get("source_owned_success_observed") is True
             and observed.get("run_conclusion")=="success"
             and all(results.get(k)=="success" for k in CRITICAL))
 return {"schema":"sapphon-193-runner-triage-v1",
  "source_sha":SOURCE,"workflow":WORKFLOW,"required_job":JOB,
  "readback_sha256":sha(record),"run_id":observed.get("run_id"),"attempt":observed.get("attempt"),
  "critical_steps":results,"recorded_failures":failures,
  "blockers":sorted(set(blockers)),"unobserved":sorted(set(missing)),
  "source_owned_critical_steps_pass":owned_pass,
  "successful_hosted_run_independently_verified":False,
  "independent_witnesses":0,"external_custody_authenticated":False,
  "authenticated_utc":False,"global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"PHASE_XIX_OBSERVED_RUNNER_REPAIR_HOLD"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--readback",required=True)
 p.add_argument("--out",default="qualification-artifact/193-triage.json")
 args=p.parse_args()
 r=diagnose(json.loads(pathlib.Path(args.readback).read_text()))
 path=pathlib.Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 print(r["decision"],r["blockers"],r["unobserved"],len(r["recorded_failures"]))
 if not r["source_owned_critical_steps_pass"]:sys.exit(1)
if __name__=="__main__":main()
