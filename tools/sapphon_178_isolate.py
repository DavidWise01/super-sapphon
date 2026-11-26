#!/usr/bin/env python3
"""SAPPHON-178: exact SAPPHON-177 runner failure isolation, not proof of execution.

Classify only actual GitHub API observations or explicitly labeled test
fixtures. Missing, partial and failed evidence must never become green.
"""
import argparse,hashlib,json,pathlib,sys
SOURCE="3053c21609333ea93d74ff2d38aeeed1c27d6084"
WORKFLOW="sapphon-177-evidence.yml"
JOB="executable-diagnostics"
REQUIRED={
  "PYTHON":"Python tests, including frozen-source status regressions",
  "RUST":"Rust typecheck and inherited suites",
  "FROZEN":"Recheck 188 immutable historical source files",
}
def review(record):
    out={"schema":"sapphon-178-failure-isolation-v1",
      "source_sha":SOURCE,"workflow":WORKFLOW,
      "status":"NOT_OBSERVED","run_id":None,"attempt":None,
      "gates":{k:"NOT_OBSERVED" for k in REQUIRED},
      "failures":[],"findings":[],
      "source_owned_diagnostics_pass":False,
      "external_custody_authenticated":False,
      "authenticated_utc":False,"global_anti_rollback":False,
      "npm_lock_qualified":False,"pages_verified":False,
      "recovery_authorized":False,"lock_cleared":False,
      "decision":"FAILURE_ISOLATION_HOLD"}
    issues=out["findings"]
    if record.get("schema")!="sapphon-171-job-log-triage-v1":issues.append("SCHEMA_MISMATCH")
    if record.get("expected_sha")!=SOURCE or record.get("workflow")!=WORKFLOW:
        issues.append("SOURCE_ANCESTRY_MISMATCH")
    out["status"]=record.get("status","READBACK_UNAVAILABLE")
    obs=record.get("observed") or {}
    out["run_id"]=obs.get("run_id");out["attempt"]=obs.get("attempt")
    if out["status"]!="EXACT_RUN_OBSERVED" or obs.get("head_sha")!=SOURCE:
        issues.append("RUN_NOT_MATCHED")
    for k in ("run_id","attempt"):
        v=obs.get(k)
        if type(v) is not int or v<1:issues.append("INVALID_"+k.upper())
    if obs.get("expected_job")!=JOB or obs.get("required_job_unique") is not True:
        issues.append("REQUIRED_JOB_NOT_UNIQUE")
    if obs.get("run_status")!="completed":issues.append("RUN_INCOMPLETE")
    if obs.get("run_conclusion")!="success":issues.append("RUN_NOT_SUCCESS")
    steps=obs.get("required_steps",[])
    if not isinstance(steps,list):steps=[]
    for kind,name in REQUIRED.items():
        matches=[s for s in steps if isinstance(s,dict) and s.get("name")==name]
        state="NOT_OBSERVED" if not matches else ("DUPLICATE" if len(matches)!=1 else
             ("PASS" if matches[0].get("conclusion")=="success" else "FAIL_OR_INCOMPLETE"))
        out["gates"][kind]=state
        if state!="PASS":issues.append(kind+":"+state)
    if obs.get("failures"):
        out["failures"]=obs["failures"][:50]
        issues.append("FAILED_JOB_OR_CHILD_STEP")
    if obs.get("unresolved_required_steps"):
        issues.append("UNRESOLVED_STEP_PRESENT")
    if obs.get("source_owned_success_observed") is not True:
        issues.append("SUCCESS_NOT_OBSERVED")
    if record.get("recovery_authorized") is not False or record.get("independent_custody_authenticated") is not False:
        issues.append("FORGED_AUTHORITY_CLAIM")
    out["findings"]=sorted(set(issues))
    out["source_owned_diagnostics_pass"]=not out["findings"]
    out["evidence_sha256"]=hashlib.sha256(json.dumps(record,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return out
def main():
    p=argparse.ArgumentParser();p.add_argument("--input",required=True)
    p.add_argument("--out",default="qualification-artifact/178-isolation.json")
    args=p.parse_args()
    result=review(json.loads(pathlib.Path(args.input).read_text()))
    out=pathlib.Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("SAPPHON-178",result["status"],result["gates"],result["findings"])
    if result["findings"]:sys.exit(1)
if __name__=="__main__":main()
