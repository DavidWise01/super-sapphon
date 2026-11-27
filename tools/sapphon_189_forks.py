#!/usr/bin/env python3
"""SAPPHON-189: custody-rooted fork detection; no self-attested authority.

Inputs are source-owned custody *claims*. GitHub mirrors, Actions and Pages
share one ancestry. Matching claims never certify external custody.
"""
import argparse, hashlib, json, pathlib, re, sys
SOURCE="011ad7d5623d7d5db8ec2183bcf7207a0e8ec42c"
WORKFLOW="sapphon-188-import.yml"
ARTIFACT="sapphon-188-ancestry-continuity"
SHA40=re.compile(r"^[a-f0-9]{40}$")
SHA64=re.compile(r"^[a-f0-9]{64}$")
MAX_CLAIMS=64
ALLOWED_STATES={"OBSERVED","READBACK_UNAVAILABLE","ARTIFACT_EXPIRED","ARTIFACT_MISSING","PAGE_CAP"}
GITHUB_SURFACES={"github-source","github-actions","github-pages","github-api"}
def pos(x):return type(x) is int and x>0
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def validate(x):
 if type(x) is not dict:raise ValueError("CLAIM_NOT_OBJECT")
 expected={"schema","source_sha","workflow","artifact_name","run_id","attempt",
           "lineage_id","custodian","surface","evidence_state","root_sha256",
           "artifact_sha256","independently_authenticated","recovery_authorized"}
 if set(x)!=expected:raise ValueError("CLAIM_FIELDS")
 if x["schema"]!="sapphon-189-root-claim-v1" or x["source_sha"]!=SOURCE:
  raise ValueError("SOURCE_MISMATCH")
 if x["workflow"]!=WORKFLOW or x["artifact_name"]!=ARTIFACT:
  raise ValueError("WORKFLOW_ARTIFACT_MISMATCH")
 if not pos(x["run_id"]) or not pos(x["attempt"]):raise ValueError("RUN_IDENTITY")
 if type(x["lineage_id"]) is not str or not (1<=len(x["lineage_id"])<=128):
  raise ValueError("LINEAGE_ID")
 if x["custodian"]!="github-owned" or x["surface"] not in GITHUB_SURFACES:
  raise ValueError("UNVERIFIED_CUSTODIAN")
 if x["independently_authenticated"] is not False or x["recovery_authorized"] is not False:
  raise ValueError("FORGED_AUTHORITY")
 if x["evidence_state"] not in ALLOWED_STATES:raise ValueError("EVIDENCE_STATE")
 if x["evidence_state"]=="OBSERVED":
  if not isinstance(x["root_sha256"],str) or not SHA64.fullmatch(x["root_sha256"]):
   raise ValueError("OBSERVED_ROOT_DIGEST")
  if not isinstance(x["artifact_sha256"],str) or not SHA64.fullmatch(x["artifact_sha256"]):
   raise ValueError("OBSERVED_ARTIFACT_DIGEST")
 elif x["root_sha256"] is not None or x["artifact_sha256"] is not None:
  raise ValueError("UNOBSERVED_DIGEST_FABRICATION")
 return dict(x)
def compare(claims):
 if type(claims) is not list or len(claims)>MAX_CLAIMS:raise ValueError("CLAIM_SET")
 cleaned=[validate(c) for c in claims]
 seen=set();by_lineage={};conflicts=[]
 for c in cleaned:
  key=(c["surface"],c["run_id"],c["attempt"],c["lineage_id"])
  if key in seen:raise ValueError("DUPLICATE_SURFACE_CLAIM")
  seen.add(key)
  if c["evidence_state"]=="OBSERVED":
   lineage=(c["source_sha"],c["run_id"],c["attempt"],c["lineage_id"])
   by_lineage.setdefault(lineage,[]).append(c)
 for lineage,items in sorted(by_lineage.items()):
  roots=sorted(set(i["root_sha256"] for i in items))
  if len(roots)>1:
   conflicts.append({"type":"OWNED_ANCESTRY_ROOT_FORK",
     "run_id":lineage[1],"attempt":lineage[2],"lineage_id":lineage[3],
     "conflicting_root_sha256":roots})
 status=("ROOT_FORK_OBSERVED" if conflicts else
         "NO_OBSERVED_ROOTS" if not by_lineage else
         "OWNED_ROOTS_CONSISTENT")
 return {"schema":"sapphon-189-fork-adjudication-v1","source_sha":SOURCE,
  "claims_sha256":digest(cleaned),"claim_count":len(cleaned),
  "observed_root_claims":sum(c["evidence_state"]=="OBSERVED" for c in cleaned),
  "owned_ancestries":1 if cleaned else 0,"independent_witnesses":0,
  "status":status,"forks":conflicts,
  "owned_roots_consistent":bool(by_lineage) and not conflicts,
  "independent_custody_authenticated":False,
  "authenticated_utc":False,"global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"CUSTODY_ROOT_FORK_HOLD"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--claims",required=True)
 p.add_argument("--out",default="qualification-artifact/189-forks.json")
 a=p.parse_args()
 claims=json.loads(pathlib.Path(a.claims).read_text())
 result=compare(claims)
 dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["status"],result["claim_count"],result["forks"])
 if result["forks"]:sys.exit(1)
if __name__=="__main__":main()
