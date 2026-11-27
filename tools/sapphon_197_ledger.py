#!/usr/bin/env python3
"""SAPPHON-197 append-only monotonic readback evidence.

Each event preserves one *reported* GitHub-owned readback. Only verified
previous-ledger bytes establish parent continuity. Sequence number is a
local append index, not authenticated wall-clock or global anti-rollback.
"""
import argparse,hashlib,json,pathlib,re,sys
SOURCE="56d66ad2390063f08e33872299eebe6c8d78a8fe"
ORIGINAL_SOURCE="517959b0c98b65bafefaba5ae5e18065b2e27212"
ORIGINAL_WORKFLOW="sapphon-193-triage.yml"
HEX=re.compile(r"^[a-f0-9]{64}$")
MAX_RECORDS=10000
STATES={"GITHUB_OWNED_HASH_MATCH","GITHUB_OWNED_READBACK_EQUIVOCATION",
        "193_ARTIFACT_EXPIRED","193_ARTIFACT_EXPIRY_UNKNOWN",
        "193_LOG_DOWNLOAD_FAILED","193_ZIP_DOWNLOAD_FAILED",
        "195_RUN_NOT_FOUND","READBACK_UNAVAILABLE","NOT_OBSERVED"}
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def pos(x):return type(x) is int and x>0
def valid_hash(x):return type(x) is str and HEX.fullmatch(x) is not None
def observation(r):
 if type(r) is not dict or set(r)!={"schema","source_sha","original_source_sha",
     "original_workflow","original_run_id","original_attempt","state",
     "log_sha256","zip_sha256","original_bytes_reacquired",
     "independent_witnesses","external_custody_authenticated",
     "recovery_authorized","lock_cleared"}:raise ValueError("EVENT_FIELDS")
 if r["schema"]!="sapphon-197-observation-v1" or r["source_sha"]!=SOURCE or r["original_source_sha"]!=ORIGINAL_SOURCE or r["original_workflow"]!=ORIGINAL_WORKFLOW:
  raise ValueError("EVENT_ANCESTRY")
 if r["state"] not in STATES:raise ValueError("EVENT_STATE")
 if r["independent_witnesses"]!=0 or r["external_custody_authenticated"] is not False or r["recovery_authorized"] is not False or r["lock_cleared"] is not False:
  raise ValueError("EVENT_AUTHORITY")
 exists=pos(r["original_run_id"]) and pos(r["original_attempt"])
 if r["state"] in ("GITHUB_OWNED_HASH_MATCH","GITHUB_OWNED_READBACK_EQUIVOCATION"):
  if not exists or r["original_bytes_reacquired"] is not True or not valid_hash(r["log_sha256"]) or not valid_hash(r["zip_sha256"]):
   raise ValueError("OBSERVED_ORIGINAL_BYTES_NOT_BOUND")
 else:
  if r["original_bytes_reacquired"] is not False or r["log_sha256"] is not None or r["zip_sha256"] is not None:
   raise ValueError("UNOBSERVED_DIGEST_FABRICATION")
  if (r["original_run_id"] is None)!=(r["original_attempt"] is None) or (r["original_run_id"] is not None and not exists):
   raise ValueError("UNOBSERVED_IDENTITY")
 return dict(r)
def validate(records):
 if type(records) is not list or len(records)>MAX_RECORDS:raise ValueError("LEDGER_LENGTH")
 previous="0"*64;first={};forks=[];missing=[]
 for i,record in enumerate(records,1):
  if type(record) is not dict or set(record)!={"envelope","sha256"}:raise ValueError("RECORD_SHAPE")
  env=record["envelope"]
  if type(env) is not dict or set(env)!={"schema","sequence","previous_sha256","observation"} or env["schema"]!="sapphon-197-ledger-envelope-v1":
   raise ValueError("ENVELOPE_SHAPE")
  if type(env["sequence"]) is not int or env["sequence"]!=i or env["previous_sha256"]!=previous:
   raise ValueError("NONMONOTONIC_HASH_CHAIN")
  row=observation(env["observation"])
  if record["sha256"]!=sha(canonical(env)):raise ValueError("HASH_CHAIN_TAMPERED")
  if row["state"] in ("GITHUB_OWNED_HASH_MATCH","GITHUB_OWNED_READBACK_EQUIVOCATION"):
   key=(row["original_run_id"],row["original_attempt"])
   hashes=(row["log_sha256"],row["zip_sha256"])
   if key in first and first[key]!=hashes:
    forks.append({"type":"SAME_ORIGINAL_ATTEMPT_BYTE_FORK","original_run_id":key[0],
      "original_attempt":key[1],"first_log_sha256":first[key][0],
      "first_zip_sha256":first[key][1],"later_log_sha256":hashes[0],
      "later_zip_sha256":hashes[1],"sequence":i})
   else:first.setdefault(key,hashes)
  else:missing.append({"sequence":i,"state":row["state"]})
  previous=record["sha256"]
 return {"schema":"sapphon-197-readback-adjudication-v1",
  "source_sha":SOURCE,"entries":len(records),"tip_sha256":previous,
  "owned_observed_original_attempts":len(first),
  "forks":forks,"missing_and_expired":missing,
  "owned_chain_consistent":not forks,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,
  "independent_witnesses":0,"independent_custody_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"MONOTONIC_READBACK_EVIDENCE_HOLD"}
def append(previous,event):
 result=validate(previous)
 if len(previous)>=MAX_RECORDS:raise ValueError("LEDGER_FULL")
 env={"schema":"sapphon-197-ledger-envelope-v1","sequence":len(previous)+1,
      "previous_sha256":result["tip_sha256"],"observation":observation(event)}
 return previous+[{"envelope":env,"sha256":sha(canonical(env))}]
def from_reacquisition(result):
 if type(result) is not dict or result.get("schema")!="sapphon-196-original-byte-reacquisition-v1":
  result={"state":"READBACK_UNAVAILABLE"}
 state=result.get("state","READBACK_UNAVAILABLE")
 if state not in STATES:state="NOT_OBSERVED"
 observed=state in ("GITHUB_OWNED_HASH_MATCH","GITHUB_OWNED_READBACK_EQUIVOCATION")
 return {"schema":"sapphon-197-observation-v1","source_sha":SOURCE,
  "original_source_sha":ORIGINAL_SOURCE,"original_workflow":ORIGINAL_WORKFLOW,
  "original_run_id":result.get("original_run_id") if pos(result.get("original_run_id")) else None,
  "original_attempt":result.get("original_attempt") if pos(result.get("original_attempt")) else None,
  "state":state,"log_sha256":result.get("log_sha256") if observed else None,
  "zip_sha256":result.get("zip_sha256") if observed else None,
  "original_bytes_reacquired":observed and result.get("original_bytes_reacquired") is True,
  "independent_witnesses":0,"external_custody_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--previous")
 p.add_argument("--readback",required=True)
 p.add_argument("--ledger-out",default="qualification-artifact/197-ledger.jsonl")
 p.add_argument("--report-out",default="qualification-artifact/197-adjudication.json")
 a=p.parse_args()
 prior=[]
 if a.previous:
  prior=[json.loads(line) for line in pathlib.Path(a.previous).read_bytes().splitlines() if line.strip()]
 current=json.loads(pathlib.Path(a.readback).read_text())
 event=from_reacquisition(current)
 updated=append(prior,event)
 decision=validate(updated)
 # Newly created append-only output; never overwrite a historical file.
 dest=pathlib.Path(a.ledger_out);dest.parent.mkdir(parents=True,exist_ok=True)
 with dest.open("xb") as f:
  for row in updated:f.write(canonical(row)+b"\n")
  f.flush()
  import os
  os.fsync(f.fileno())
 report=pathlib.Path(a.report_out);report.parent.mkdir(parents=True,exist_ok=True)
 report.write_text(json.dumps(decision,indent=2,sort_keys=True)+"\n")
 print(decision["decision"],decision["entries"],len(decision["forks"]))
 if decision["forks"]:sys.exit(1)
if __name__=="__main__":main()
