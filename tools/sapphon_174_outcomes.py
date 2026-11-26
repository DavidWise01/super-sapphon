#!/usr/bin/env python3
"""SAPPHON-174 — source diagnostics vs full-qualification separation.

Observe only supplied GitHub-owned Actions records. Do not conflate missing
predecessor evidence, source tests, Pages parity, or npm integrity.
"""
import argparse,hashlib,json,pathlib,sys

SOURCE_SHA="7e1be863797ddad3043e03074fc2375b9f760c74"
WORKFLOW="sapphon-173-steps.yml"
JOB="critical-step-diagnostics"
NEEDED=("Execute Python critical-step regressions",
        "Run Rust typecheck and inherited test suites",
        "Check 188 inherited frozen source hashes")
STATES=("success","failure","skipped","cancelled","timed_out",None)
def digest(o):
    return hashlib.sha256(json.dumps(o,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def assess(record):
    findings=[]
    if record.get("schema")!="sapphon-171-job-log-triage-v1":
        findings.append("WRONG_SCHEMA")
    if record.get("expected_sha")!=SOURCE_SHA or record.get("workflow")!=WORKFLOW:
        findings.append("WRONG_ANCESTRY")
    observed=record.get("observed") or {}
    if record.get("status")!="EXACT_RUN_OBSERVED" or observed.get("head_sha")!=SOURCE_SHA:
        findings.append("RUN_NOT_OBSERVED")
    for name in ("run_id","attempt"):
        n=observed.get(name)
        if type(n) is not int or n<=0:findings.append("INVALID_"+name.upper())
    if observed.get("expected_job")!=JOB or observed.get("required_job_unique") is not True:
        findings.append("JOB_IDENTITY_INVALID")
    if observed.get("run_status")!="completed":
        findings.append("INCOMPLETE_RUN")
    if observed.get("run_conclusion")!="success" or observed.get("source_owned_success_observed") is not True:
        findings.append("RUN_NOT_SUCCESS")
    steps=observed.get("required_steps")
    if not isinstance(steps,list):steps=[]
    for name in NEEDED:
        matches=[x for x in steps if isinstance(x,dict) and x.get("name")==name]
        if len(matches)!=1:findings.append("MISSING_OR_DUPLICATE:"+name)
        elif matches[0].get("conclusion")!="success":
            findings.append("NON_SUCCESS:"+name)
    if observed.get("failures") or observed.get("unresolved_required_steps"):
        findings.append("FAILED_OR_UNRESOLVED_STEP")
    if record.get("independent_custody_authenticated") is not False or record.get("recovery_authorized") is not False:
        findings.append("FORGED_AUTHORITY")
    ok=not findings
    return {"schema":"sapphon-174-runner-outcome-v1",
      "source_commit":SOURCE_SHA,"expected_workflow":WORKFLOW,
      "run_id":observed.get("run_id"),"attempt":observed.get("attempt"),
      "evidence_sha256":digest(record),"findings":sorted(set(findings)),
      "source_owned_diagnostics_observed_pass":ok,
      "historical_integrity_run_observed_pass":ok,
      "npm_lock_qualified":False,"pages_deployed_verified":False,
      "independent_custody_authenticated":False,
      "global_anti_rollback_authenticated":False,
      "recovery_authorized":False,"lock_cleared":False,
      "full_qualification":False,"decision":"SOURCE_OUTCOMES_SEPARATE_HOLD"}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--out",default="qualification-artifact/174-runner-outcomes.json")
    a=p.parse_args();r=assess(json.loads(pathlib.Path(a.input).read_text()))
    dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
    print(r["decision"],r["findings"])
    if r["findings"]:sys.exit(1)
if __name__=="__main__":main()
