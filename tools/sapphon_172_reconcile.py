#!/usr/bin/env python3
"""SAPPHON-172 — reconcile exact predecessor job logs with phase-gated outcomes.
Reject contradictory parent/child statuses and missing run identities. GitHub
observations are source-owned, never external physical custody authority.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

COMMIT="9e7fc8ad8c3b05a3e12f1c3aa0c15b4c99c2e18e"
REQUIRED="diagnostics"
GOOD_SHA=re.compile(r"^[0-9a-f]{40}$")
BAD={"failure","timed_out","cancelled"}
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":")).encode()

def reconcile(observation):
    issues=[]
    if observation.get("schema")!="sapphon-171-job-log-triage-v1":
        issues.append("SCHEMA_MISMATCH")
    if observation.get("expected_sha")!=COMMIT:
        issues.append("PINNED_SOURCE_MISMATCH")
    if observation.get("workflow")!="sapphon-171-joblogs.yml":
        issues.append("WORKFLOW_MISMATCH")
    if observation.get("status")!="EXACT_RUN_OBSERVED":
        issues.append("NO_COMPLETED_EVIDENCE")
    observed=observation.get("observed") or {}
    if observed.get("head_sha")!=COMMIT:
        issues.append("OBSERVED_SOURCE_MISMATCH")
    if not isinstance(observed.get("run_id"),int) or observed.get("run_id",0)<=0:
        issues.append("RUN_ID_MISSING")
    if not isinstance(observed.get("attempt"),int) or observed.get("attempt",0)<=0:
        issues.append("ATTEMPT_MISSING")
    if observed.get("expected_job")!=REQUIRED:
        issues.append("REQUIRED_JOB_MISMATCH")
    if observed.get("status")!="EXACT_RUN_OBSERVED" or observed.get("run_status")!="completed":
        issues.append("RUN_INCOMPLETE")
    if observed.get("run_conclusion")!="success":
        issues.append("RUN_NOT_SUCCESS")
    failures=observed.get("failures",[])
    if not isinstance(failures,list):failures=[{"reason":"MALFORMED_FAILURE_LIST"}]
    if failures:issues.append("FAILURE_EVIDENCE_PRESENT")
    if observed.get("required_job_present") is not True:
        issues.append("REQUIRED_JOB_NOT_PRESENT")
    if observed.get("source_owned_success_observed") is not True:
        issues.append("SOURCE_SUCCESS_NOT_ESTABLISHED")
    if observation.get("independent_custody_authenticated") is not False or observation.get("recovery_authorized") is not False:
        issues.append("UNSUPPORTED_AUTHORITY_CLAIM")
    digest=hashlib.sha256(canonical(observation)).hexdigest()
    return {"schema":"sapphon-172-runtime-reconciliation-v1",
      "predecessor_commit":COMMIT,
      "run_id":observed.get("run_id"),"attempt":observed.get("attempt"),
      "observation_sha256":digest,
      "issues":sorted(set(issues)),
      "source_owned_diagnostic_consistent":not issues,
      "npm_lock_qualified":False,
      "pages_deployed_verified":False,
      "external_custody_authenticated":False,
      "global_anti_rollback_authenticated":False,
      "recovery_authorized":False,"lock_cleared":False,
      "decision":"DIAGNOSTIC_RECONCILIATION_HOLD"}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--out",default="qualification-artifact/172-reconciliation.json")
    a=p.parse_args()
    data=json.loads(pathlib.Path(a.input).read_text())
    result=reconcile(data)
    dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("SAPPHON-172",result["decision"],result["issues"])
    if result["issues"]:sys.exit(1)

if __name__=="__main__":main()
