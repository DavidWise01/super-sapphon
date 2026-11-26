#!/usr/bin/env python3
"""SAPPHON-177: classify an actual Phase XVI runner observation, never self-certify.

A source-owned pass is a finding about one exact GitHub Actions run. It is not
an independent custodian or an authorization to recover/replace a lock.
"""
import argparse,hashlib,json,pathlib,sys
SHA="f17b3d6c437da7f82240fffae703dfbde61a215b"
WORKFLOW="sapphon-176-freeze.yml"
JOB="final-evidence"
REQUIRED=("Execute Python adversarial and source-freeze tests",
          "Run all inherited Rust source checks and test suites",
          "Check exact bytes and SHA-256 for 188 inherited frozen sources")
def assess(src):
    errors=[]
    if src.get("schema")!="sapphon-171-job-log-triage-v1":errors.append("SCHEMA")
    if src.get("workflow")!=WORKFLOW or src.get("expected_sha")!=SHA:errors.append("ANCESTRY")
    o=src.get("observed") or {}
    if src.get("status")!="EXACT_RUN_OBSERVED" or o.get("head_sha")!=SHA:
        errors.append("RUN_NOT_OBSERVED")
    if type(o.get("run_id")) is not int or o.get("run_id",0)<=0:errors.append("RUN_ID")
    if type(o.get("attempt")) is not int or o.get("attempt",0)<=0:errors.append("ATTEMPT")
    if o.get("expected_job")!=JOB or o.get("required_job_unique") is not True:errors.append("JOB")
    if o.get("run_status")!="completed" or o.get("run_conclusion")!="success":
        errors.append("RUN_NOT_SUCCESS")
    if o.get("source_owned_success_observed") is not True:errors.append("CLAIMED_SUCCESS_NOT_OBSERVED")
    steps=o.get("required_steps")
    if not isinstance(steps,list):steps=[]
    for name in REQUIRED:
        matched=[x for x in steps if isinstance(x,dict) and x.get("name")==name]
        if len(matched)!=1:errors.append("MISSING_OR_DUPLICATE_STEP:"+name)
        elif matched[0].get("conclusion")!="success":errors.append("NON_SUCCESS_STEP:"+name)
    if o.get("failures") or o.get("unresolved_required_steps"):errors.append("FAILED_CHILD")
    if src.get("independent_custody_authenticated") is not False or src.get("recovery_authorized") is not False:
        errors.append("UNSUPPORTED_AUTHORITY")
    return {"schema":"sapphon-177-evidence-first-v1",
            "predecessor_sha":SHA,"run_id":o.get("run_id"),"attempt":o.get("attempt"),
            "evidence_sha256":hashlib.sha256(json.dumps(src,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
            "findings":sorted(set(errors)),
            "source_owned_pass_consistent":not errors,
            "independent_custody_authenticated":False,
            "global_anti_rollback_authenticated":False,
            "authenticated_utc":False,"npm_lock_qualified":False,
            "pages_verified":False,"recovery_authorized":False,"lock_cleared":False,
            "decision":"EVIDENCE_FIRST_HOLD"}
def main():
    p=argparse.ArgumentParser();p.add_argument("--input",required=True)
    p.add_argument("--out",default="qualification-artifact/177-observation.json")
    a=p.parse_args();r=assess(json.loads(pathlib.Path(a.input).read_text()))
    dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
    print(r["decision"],r["findings"])
    if r["findings"]:sys.exit(1)
if __name__=="__main__":main()
