#!/usr/bin/env python3
"""SAPPHON-167 — fail-closed candidate-to-committed-lock reconciliation.

This never modifies package-lock.json. It can generate a reviewer-ready exact
candidate only if run/attempt, signed-off observation fields, registry integrity,
archive sha256, and protected-source baseline all agree.
GitHub-owned CI observations are one ancestry. Operational recovery always HOLD.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SOURCE="f697afc224d9ca7404aad8c33e827abad6f2342b"
REPO="DavidWise01/super-sapphon"
NAMES=("playwright","playwright-core")
COMMIT=re.compile(r"^[0-9a-f]{40}$")
HEX=re.compile(r"^[0-9a-f]{64}$")
def digest(b):return hashlib.sha256(b).hexdigest()

def validate(candidate:bytes,summary:dict,inspection:dict,intake:dict,review:dict,head:str)->list[str]:
    errors=[]
    if not COMMIT.fullmatch(head or ""):errors.append("SOURCE_HEAD_INVALID")
    if intake.get("schema")!="sapphon-166-exact-artifact-intake-v1" or intake.get("status")!="EXACT_RUN_ARTIFACT_OBSERVED":
        errors.append("ARTIFACT_INTAKE_NOT_CONFIRMED")
    if intake.get("expected_commit")!=SOURCE or summary.get("source_commit")!=SOURCE:
        errors.append("SOURCE_COMMIT_MISMATCH")
    if intake.get("run_id")!=summary.get("run_id") and str(intake.get("run_id"))!=str(summary.get("run_id")):
        errors.append("RUN_ID_MISMATCH")
    if str(intake.get("attempt"))!=str(summary.get("attempt")):
        errors.append("ATTEMPT_MISMATCH")
    if intake.get("run_conclusion") not in ("failure","success"):
        errors.append("RUN_NOT_FINISHED")
    if "165-registry-candidate-package-lock.json" not in intake.get("candidate_files_present",[]):
        errors.append("CANDIDATE_FILE_NOT_IN_INTAKE")
    if summary.get("schema")!="sapphon-165-run-v1" or summary.get("outcomes",{}).get("REGISTRY")!="success":
        errors.append("REGISTRY_STEP_NOT_SUCCESS")
    if inspection.get("schema")!="sapphon-165-lock-inspection-v1" or inspection.get("candidate_schema_complete") is not True or inspection.get("issues"):
        errors.append("CANDIDATE_INSPECTION_NOT_CLEAN")
    if review.get("schema")!="sapphon-166-candidate-review-v1" or review.get("issues") or review.get("candidate_consistent_with_supplied_runner_evidence") is not True:
        errors.append("PREDECESSOR_REVIEW_NOT_CLEAN")
    if review.get("expected_commit")!=SOURCE or str(review.get("run_id"))!=str(intake.get("run_id")) or str(review.get("attempt"))!=str(intake.get("attempt")):
        errors.append("REVIEW_RUN_IDENTITY_MISMATCH")
    candidate_hash=digest(candidate)
    if inspection.get("lock_sha256")!=candidate_hash or review.get("candidate_sha256")!=candidate_hash:
        errors.append("CANDIDATE_DIGEST_CONFLICT")
    for item in (intake,summary,inspection,review):
        if item.get("external_custody_authenticated") is True or item.get("recovery_authorized") is True:
            errors.append("FALSE_EXTERNAL_AUTHORITY_CLAIM")
    if summary.get("recovery_authority")!="HOLD" or review.get("decision")!="CANDIDATE_REVIEW_HOLD":
        errors.append("RECOVERY_GATE_NOT_HOLD")
    try:
        j=json.loads(candidate)
        packages=j.get("packages",{})
        if j.get("lockfileVersion")!=3 or packages.get("",{}).get("devDependencies",{}).get("playwright")!="1.65.1":
            errors.append("LOCK_ROOT_MISMATCH")
        if set(packages)!={"","node_modules/playwright","node_modules/playwright-core"}:
            errors.append("UNEXPECTED_LOCK_DEPENDENCY_SET")
        for name in NAMES:
            item=packages.get("node_modules/"+name,{})
            expected=f"https://registry.npmjs.org/{name}/-/{name}-1.65.1.tgz"
            if item.get("version")!="1.65.1" or item.get("resolved")!=expected:
                errors.append("PACKAGE_IDENTITY_MISMATCH:"+name)
            import base64
            integrity=item.get("integrity","")
            try:
                assert integrity.startswith("sha512-") and len(base64.b64decode(integrity[7:],validate=True))==64
            except (AssertionError,ValueError):
                errors.append("INTEGRITY_FIELD_INVALID:"+name)
        if packages.get("node_modules/playwright",{}).get("dependencies",{}).get("playwright-core")!="1.65.1":
            errors.append("PLAYWRIGHT_CORE_LINK_MISMATCH")
    except (ValueError,UnicodeError,TypeError,AttributeError):
        errors.append("CANDIDATE_JSON_INVALID")
    return sorted(set(errors))

def reconcile(candidate,summary,inspection,intake,review,head):
    errors=validate(candidate,summary,inspection,intake,review,head)
    return {
      "schema":"sapphon-167-promotion-review-v1",
      "phase":"XV","bound":167,"source_head":head,
      "candidate_source_commit":SOURCE,"candidate_sha256":digest(candidate),
      "run_id":intake.get("run_id"),"run_attempt":intake.get("attempt"),
      "issues":errors,
      "candidate_review_eligible":not errors,
      "candidate_committed":False,
      "dependency_supply_chain_externally_authenticated":False,
      "independent_custody_authenticated":False,
      "global_anti_rollback_authenticated":False,
      "authenticated_utc":False,
      "recovery_authorized":False,"lock_cleared":False,
      "decision":"LOCK_PROMOTION_REVIEW_HOLD",
    }

def main():
    p=argparse.ArgumentParser()
    for f in ("candidate","summary","inspection","intake","review"):
        p.add_argument("--"+f,required=True)
    p.add_argument("--head",required=True)
    p.add_argument("--out",default="qualification-artifact/167-promotion-review.json")
    args=p.parse_args()
    candidate=Path(args.candidate).read_bytes()
    records=[json.loads(Path(getattr(args,f)).read_text()) for f in ("summary","inspection","intake","review")]
    result=reconcile(candidate,*records,args.head)
    path=Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("SAPPHON-167",result["decision"],"issues:",result["issues"])
    if result["issues"]:sys.exit(1)
    print("Review eligible only; candidate not committed; authority HOLD")
if __name__=="__main__":main()
