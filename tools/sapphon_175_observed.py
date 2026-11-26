#!/usr/bin/env python3
"""SAPPHON-175: bounded exact-run diagnostic reconciliation.

No run metadata or test verdicts are synthesized. A truncated search never
becomes evidence of a nonexistent Actions run. All authority remains HOLD.
"""
import argparse,hashlib,json,pathlib,sys
SOURCE="185802d4f10b496b899ab09551fe193b9ddd4a0d"
WORKFLOW="sapphon-174-outcomes.yml"
JOB="source-outcomes"
REQUIRED=("Run offline Python regressions","Run inherited Rust regression suites",
          "Verify inherited 188 historical byte and SHA256 constraints")
def assess(payload):
    faults=[]
    if payload.get("schema")!="sapphon-171-job-log-triage-v1":faults.append("BAD_SCHEMA")
    if payload.get("expected_sha")!=SOURCE or payload.get("workflow")!=WORKFLOW:
        faults.append("WRONG_SOURCE_ANCESTRY")
    state=payload.get("status")
    if state!="EXACT_RUN_OBSERVED":faults.append("RUN_READBACK_UNQUALIFIED:"+str(state))
    o=payload.get("observed") or {}
    if o.get("head_sha")!=SOURCE:faults.append("WRONG_OBSERVED_SOURCE")
    if type(o.get("run_id")) is not int or o["run_id"]<1:faults.append("RUN_ID_MISSING")
    if type(o.get("attempt")) is not int or o["attempt"]<1:faults.append("ATTEMPT_MISSING")
    if o.get("expected_job")!=JOB or o.get("required_job_unique") is not True:
        faults.append("EXPECTED_JOB_NOT_UNIQUE")
    if o.get("run_status")!="completed" or o.get("run_conclusion")!="success":
        faults.append("RUN_NOT_COMPLETE_PASS")
    if o.get("source_owned_success_observed") is not True:faults.append("SOURCE_TESTS_NOT_VERIFIED")
    if o.get("failures") or o.get("unresolved_required_steps"):
        faults.append("FAILED_OR_UNRESOLVED_CHILD")
    steps=o.get("required_steps")
    if not isinstance(steps,list):steps=[]
    for name in REQUIRED:
        found=[s for s in steps if isinstance(s,dict) and s.get("name")==name]
        if len(found)!=1:faults.append("MISSING_OR_DUPLICATED:"+name)
        elif found[0].get("conclusion")!="success":
            faults.append("REQUIRED_STEP_NOT_PASS:"+name)
    if payload.get("independent_custody_authenticated") is not False or payload.get("recovery_authorized") is not False:
        faults.append("FORGED_AUTHORITY_CLAIM")
    digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {"schema":"sapphon-175-observed-diagnostics-v1","predecessor_sha":SOURCE,
       "workflow":WORKFLOW,"job":JOB,
       "run_id":o.get("run_id"),"attempt":o.get("attempt"),
       "evidence_sha256":digest,"issues":sorted(set(faults)),
       "source_owned_diagnostics_consistent":not faults,
       "lockfile_qualified":False,"pages_verified":False,
       "externally_authenticated_custody":False,"global_anti_rollback":False,
       "recovery_authorized":False,"lock_cleared":False,
       "decision":"OBSERVED_DIAGNOSTICS_HOLD"}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--out",default="qualification-artifact/175-observed-diagnostics.json")
    a=p.parse_args();data=json.loads(pathlib.Path(a.input).read_text())
    result=assess(data);out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("SAPPHON-175",result["decision"],result["issues"])
    if result["issues"]:sys.exit(1)
if __name__=="__main__":main()
