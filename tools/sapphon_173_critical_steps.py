#!/usr/bin/env python3
"""SAPPHON-173 exact-run critical-step completeness and anti-replay gate.

This reconciles GitHub-owned run metadata only. It does not perform recovery,
rotate keys, establish outside custody, or authenticate externally anchored time.
"""
import argparse,hashlib,json,pathlib,re,sys
SOURCE_SHA="496dec7bf5410baf031b0b7168ed2ac26311a181"
WORKFLOW="sapphon-172-reconcile.yml"
REQUIRED_JOB="diagnostic-reconciliation"
REQUIRED_STEPS=("Execute targeted Python regression suites",
 "Run Rust all-target check and inherited test suites",
 "Recheck all 188 protected historical file hashes")
BAD={"failure","cancelled","timed_out","skipped",None}
def digest(data):return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def reconcile(payload):
    issues=[]
    if payload.get("schema")!="sapphon-171-job-log-triage-v1":issues.append("SCHEMA_MISMATCH")
    if payload.get("expected_sha")!=SOURCE_SHA:issues.append("SOURCE_PIN_MISMATCH")
    if payload.get("workflow")!=WORKFLOW:issues.append("WORKFLOW_MISMATCH")
    if payload.get("status")!="EXACT_RUN_OBSERVED":issues.append("RUN_NOT_OBSERVED_COMPLETED")
    obs=payload.get("observed") or {}
    if obs.get("head_sha")!=SOURCE_SHA:issues.append("OBSERVED_SOURCE_MISMATCH")
    if not isinstance(obs.get("run_id"),int) or isinstance(obs.get("run_id"),bool) or obs.get("run_id",0)<1:issues.append("RUN_ID_INVALID")
    if not isinstance(obs.get("attempt"),int) or isinstance(obs.get("attempt"),bool) or obs.get("attempt",0)<1:issues.append("ATTEMPT_INVALID")
    if obs.get("expected_job")!=REQUIRED_JOB:issues.append("REQUIRED_JOB_IDENTITY_MISMATCH")
    if obs.get("run_status")!="completed" or obs.get("status")!="EXACT_RUN_OBSERVED":
        issues.append("RUN_NOT_COMPLETE")
    if obs.get("run_conclusion")!="success" or obs.get("source_owned_success_observed") is not True:
        issues.append("NO_SUCCESSFUL_SOURCE_OBSERVATION")
    if obs.get("required_job_present") is not True or obs.get("required_job_unique") is not True:
        issues.append("REQUIRED_JOB_NOT_UNIQUE")
    if obs.get("required_steps_observed") is not True:issues.append("STEP_LIST_MISSING")
    steps=obs.get("required_steps")
    if not isinstance(steps,list):steps=[]
    for expected in REQUIRED_STEPS:
        matches=[s for s in steps if isinstance(s,dict) and s.get("name")==expected]
        if len(matches)!=1:issues.append("STEP_MISSING_OR_DUPLICATED:"+expected)
        elif matches[0].get("conclusion")!="success":issues.append("STEP_NOT_SUCCESS:"+expected)
    if obs.get("unresolved_required_steps"):
        issues.append("UNRESOLVED_REQUIRED_STEP")
    if obs.get("failures"):
        issues.append("FAILED_JOB_OR_CHILD_STEP_PRESENT")
    if payload.get("independent_custody_authenticated") is not False or payload.get("recovery_authorized") is not False:
        issues.append("AUTHORITY_CLAIM_REJECTED")
    return {"schema":"sapphon-173-critical-steps-v1",
      "pinned_commit":SOURCE_SHA,"workflow":WORKFLOW,"required_job":REQUIRED_JOB,
      "observed_run_id":obs.get("run_id"),"observed_attempt":obs.get("attempt"),
      "evidence_sha256":digest(payload),
      "findings":sorted(set(issues)),"source_owned_critical_steps_consistent":not issues,
      "full_qualification":False,"npm_lock_qualified":False,
      "external_custody_authenticated":False,"external_anti_rollback_authenticated":False,
      "recovery_authorized":False,"lock_cleared":False,
      "decision":"CRITICAL_STEPS_REVIEW_HOLD"}
def main():
    a=argparse.ArgumentParser()
    a.add_argument("--input",required=True)
    a.add_argument("--out",default="qualification-artifact/173-critical-steps.json")
    opt=a.parse_args()
    payload=json.loads(pathlib.Path(opt.input).read_text())
    output=reconcile(payload);p=pathlib.Path(opt.out);p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(output,indent=2,sort_keys=True)+"\n")
    print(output["decision"],output["findings"])
    if output["findings"]:sys.exit(1)
if __name__=="__main__":main()
