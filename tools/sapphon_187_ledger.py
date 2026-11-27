#!/usr/bin/env python3
"""SAPPHON-187: bounded, append-only, provenance-aware artifact attempt ledger.

Only actual GitHub-owned readbacks can be recorded as observations. The
GitHub API timestamp is metadata, never independent UTC proof.
"""
import argparse,hashlib,json,pathlib,re,sys
SOURCE="a18115b4099c0eac6bef1c624efd73573aaffe8e"
WORKFLOW="sapphon-186-attempts.yml"
ARTIFACT="sapphon-186-exhaustive-attempt-findings"
STATES=("OBSERVED","EXPIRED","DELETED_OBSERVED","READBACK_UNAVAILABLE","NOT_FOUND_IN_EXHAUSTED_LISTING","LISTING_INCOMPLETE")
HEX64=re.compile(r"^[a-f0-9]{64}$")
MAX_RECORDS=10000
def canonical(obj):
 return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def digest(obj):return hashlib.sha256(canonical(obj)).hexdigest()
def positive(value):return type(value) is int and value>0
def normalized(row):
 if type(row) is not dict:raise ValueError("RECORD_NOT_OBJECT")
 if row.get("source_sha")!=SOURCE or row.get("workflow")!=WORKFLOW:
  raise ValueError("SOURCE_ANCESTRY_MISMATCH")
 if not positive(row.get("run_id")) or not positive(row.get("attempt")):
  raise ValueError("INVALID_RUN_ATTEMPT")
 state=row.get("state")
 if state not in STATES:raise ValueError("INVALID_EVIDENCE_STATE")
 artifact_id=row.get("artifact_id")
 zip_sha=row.get("original_zip_sha256")
 if state=="OBSERVED":
  if not positive(artifact_id) or not isinstance(zip_sha,str) or not HEX64.fullmatch(zip_sha):
   raise ValueError("OBSERVED_BYTES_NOT_BOUND")
  if row.get("embedded_run_id")!=row["run_id"] or row.get("embedded_attempt")!=row["attempt"]:
   raise ValueError("EMBEDDED_ATTEMPT_CONFLICT")
  if row.get("artifact_name")!=ARTIFACT:raise ValueError("WRONG_ARTIFACT_NAME")
 elif zip_sha is not None or row.get("embedded_run_id") is not None or row.get("embedded_attempt") is not None:
  raise ValueError("UNOBSERVED_BYTES_FABRICATED")
 if state in ("EXPIRED","DELETED_OBSERVED") and not positive(artifact_id):
  raise ValueError("ARTIFACT_IDENTITY_REQUIRED")
 if state=="DELETED_OBSERVED" and row.get("deletion_endpoint_confirmed") is not True:
  raise ValueError("UNSUPPORTED_DELETION_INFERENCE")
 if row.get("external_custody_authenticated") is not False or row.get("recovery_authorized") is not False:
  raise ValueError("UNSUPPORTED_AUTHORITY")
 # Only these source-owned fields are permitted; no implicit timestamp ordering.
 allowed={"source_sha","workflow","run_id","attempt","state","artifact_id",
  "artifact_name","original_zip_sha256","embedded_run_id","embedded_attempt",
  "deletion_endpoint_confirmed","api_timestamp","external_custody_authenticated",
  "recovery_authorized"}
 if set(row)-allowed:raise ValueError("UNRECOGNIZED_RECORD_FIELDS")
 if row.get("api_timestamp") is not None and (not isinstance(row["api_timestamp"],str)
     or len(row["api_timestamp"])>50):
  raise ValueError("INVALID_UNTRUSTED_TIME")
 return dict(row)
def envelope(number,prev,row):
 return {"schema":"sapphon-187-ledger-envelope-v1","sequence":number,
  "previous_sha256":prev,"observation":normalized(row)}
def chain(records):
 if type(records) is not list or len(records)>MAX_RECORDS:raise ValueError("INVALID_LEDGER_LENGTH")
 previous="0"*64;seen={}
 findings=[];stored=[]
 for index,item in enumerate(records,1):
  if type(item) is not dict or set(item)!={"envelope","sha256"}:
   raise ValueError("MALFORMED_CHAIN_RECORD")
  env=item["envelope"]
  if type(env) is not dict or env.get("schema")!="sapphon-187-ledger-envelope-v1":
   raise ValueError("INVALID_ENVELOPE")
  if env.get("sequence")!=index or env.get("previous_sha256")!=previous:
   raise ValueError("CHAIN_BREAK")
  row=normalized(env.get("observation"))
  if env!=envelope(index,previous,row):raise ValueError("NONCANONICAL_ENVELOPE")
  actual=digest(env)
  if item.get("sha256")!=actual:raise ValueError("CHAIN_DIGEST_MISMATCH")
  key=(row["run_id"],row["attempt"])
  if row["state"]=="OBSERVED":
   identity=(row["artifact_id"],row["original_zip_sha256"])
   if key in seen and seen[key]!=identity:
    findings.append({"type":"SAME_ATTEMPT_ARTIFACT_EQUIVOCATION","run_id":key[0],"attempt":key[1]})
   seen[key]=identity
  stored.append(item);previous=actual
 return {"entries":len(stored),"tip_sha256":previous,
  "equivocations":findings,
  "source_owned_ledger_consistent":not findings,
  "authenticated_utc":False,
  "independent_custody_authenticated":False,
  "global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"CROSS_ATTEMPT_RETENTION_HOLD"}
def append(records,row):
 report=chain(records)
 next_env=envelope(len(records)+1,report["tip_sha256"],row)
 entry={"envelope":next_env,"sha256":digest(next_env)}
 return records+[entry]
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--ledger",required=True)
 p.add_argument("--observation",required=True)
 p.add_argument("--out",default="qualification-artifact/187-adjudication.json")
 args=p.parse_args()
 path=pathlib.Path(args.ledger)
 existing=[json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
 event=json.loads(pathlib.Path(args.observation).read_text())
 updated=append(existing,event)
 result=chain(updated)
 output=pathlib.Path(args.out);output.parent.mkdir(parents=True,exist_ok=True)
 output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 # A standalone invocation may create a new ledger, but must not overwrite an existing one.
 if path.exists():
  with path.open("ab") as file:
   data=canonical(updated[-1])+b"\n"
   file.write(data);file.flush()
   import os
   os.fsync(file.fileno())
 else:
  with path.open("xb") as file:
   file.write(canonical(updated[-1])+b"\n")
   file.flush()
   import os
   os.fsync(file.fileno())
 print(result["decision"],result["entries"],result["equivocations"])
 if result["equivocations"]:sys.exit(1)
if __name__=="__main__":main()
