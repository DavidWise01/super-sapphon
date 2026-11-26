#!/usr/bin/env python3
"""SAPPHON-166: evidence-first candidate lockfile review.

Fail closed on an unavailable source-owned candidate, missing integrity fields,
wrong run/attempt/commit, unexpected lock bytes, or a mismatched SHA-256.
Checking consistency DOES NOT authenticate GitHub Actions or third-party custody.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

ROOT="DavidWise01/super-sapphon"
VERSION="1.65.1"
TARGETS=("node_modules/playwright","node_modules/playwright-core")
HEX40=re.compile(r"^[0-9a-f]{40}$")
HEX64=re.compile(r"^[0-9a-f]{64}$")

def sha(b): return hashlib.sha256(b).hexdigest()
def assess(candidate,summary,record,expected_commit,expected_run,expected_attempt):
    issues=[]
    if not HEX40.fullmatch(expected_commit or ""):issues.append("EXPECTED_COMMIT_INVALID")
    if expected_run<1 or expected_attempt<1:issues.append("RUN_ID_INVALID")
    if summary.get("schema")!="sapphon-165-run-v1":
        issues.append("SOURCE_SUMMARY_SCHEMA")
    if summary.get("source_commit")!=expected_commit:
        issues.append("SOURCE_COMMIT_MISMATCH")
    if str(summary.get("run_id"))!=str(expected_run):
        issues.append("SOURCE_RUN_MISMATCH")
    if str(summary.get("attempt"))!=str(expected_attempt):
        issues.append("SOURCE_ATTEMPT_MISMATCH")
    if summary.get("candidate_lock_committed_to_source") is not False:
        issues.append("CANDIDATE_PROMOTION_CLAIM")
    if summary.get("external_custody_authenticated") is not False or summary.get("recovery_authority")!="HOLD":
        issues.append("SOURCE_AUTHORITY_VIOLATION")
    if summary.get("outcomes",{}).get("REGISTRY")!="success":
        issues.append("REGISTRY_STEP_NOT_SUCCESS")
    if record.get("schema")!="sapphon-165-lock-inspection-v1":
        issues.append("INSPECTION_SCHEMA")
    if record.get("candidate_schema_complete") is not True or record.get("issues"):
        issues.append("INSPECTION_REPORTED_FAILURE")
    if record.get("registry_provenance_independently_authenticated") is not False:
        issues.append("INDEPENDENCE_FALSE_CLAIM")
    if record.get("committed_lock_qualified") is not False:
        issues.append("COMMIT_QUALIFIED_FALSE_CLAIM")
    if record.get("lock_sha256")!=sha(candidate):
        issues.append("CANDIDATE_SHA256_MISMATCH")
    try:
        lock=json.loads(candidate)
    except (ValueError,UnicodeError):
        return sorted(set(issues+["CANDIDATE_INVALID_JSON"]))
    if lock.get("lockfileVersion")!=3:issues.append("LOCKFILE_VERSION")
    if lock.get("packages",{}).get("",{}).get("devDependencies",{}).get("playwright")!=VERSION:
        issues.append("ROOT_VERSION")
    for name in TARGETS:
        p=lock.get("packages",{}).get(name,{})
        short=name.rsplit("/",1)[-1]
        if p.get("version")!=VERSION:
            issues.append(short+":VERSION")
        if p.get("resolved")!="https://registry.npmjs.org/"+short+"/-"+"/"+short+"-"+VERSION+".tgz":
            issues.append(short+":RESOLVED")
        integrity=p.get("integrity","")
        if not isinstance(integrity,str) or not integrity.startswith("sha512-"):
            issues.append(short+":SHA512_MISSING")
        else:
            import base64
            try:
                b=base64.b64decode(integrity[7:],validate=True)
                if len(b)!=64:issues.append(short+":SHA512_LENGTH")
            except (ValueError,TypeError):
                issues.append(short+":SHA512_INVALID")
    if lock.get("packages",{}).get("node_modules/playwright",{}).get("dependencies",{}).get("playwright-core")!=VERSION:
        issues.append("CORE_DEPENDENCY")
    return sorted(set(issues))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--candidate",required=True)
    ap.add_argument("--summary",required=True)
    ap.add_argument("--inspection",required=True)
    ap.add_argument("--commit",required=True)
    ap.add_argument("--run",type=int,required=True)
    ap.add_argument("--attempt",type=int,required=True)
    ap.add_argument("--out",default="qualification-artifact/166-candidate-review.json")
    a=ap.parse_args()
    source=pathlib.Path(a.candidate).read_bytes()
    summary=json.loads(pathlib.Path(a.summary).read_text())
    inspection=json.loads(pathlib.Path(a.inspection).read_text())
    issues=assess(source,summary,inspection,a.commit,a.run,a.attempt)
    report={"schema":"sapphon-166-candidate-review-v1",
      "expected_commit":a.commit,"run_id":a.run,"attempt":a.attempt,
      "candidate_sha256":sha(source),"issues":issues,
      "candidate_consistent_with_supplied_runner_evidence":not issues,
      "candidate_committed":False,
      "github_origin_independently_authenticated":False,
      "external_custody_authenticated":False,
      "global_anti_rollback_authenticated":False,
      "recovery_authorized":False,"lock_cleared":False,
      "decision":"CANDIDATE_REVIEW_HOLD"}
    path=pathlib.Path(a.out);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("SAPPHON-166 candidate verdict:", "CONSISTENT BUT UNQUALIFIED" if not issues else "REJECTED",issues)
    if issues:sys.exit(1)

if __name__=="__main__":main()
