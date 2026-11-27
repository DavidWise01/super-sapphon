#!/usr/bin/env python3
"""SAPPHON-199 exact 198 parent ZIP import and retention-pressure preflight.

Never infer deletion from empty/limited listings, TTL metadata, or GitHub 404.
Never manufacture an ancestral ledger when the original artifact is absent.
"""
import argparse, hashlib, importlib.util, io, json, pathlib, stat, subprocess, sys, zipfile
ROOT=pathlib.Path(__file__).resolve().parent
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,ROOT/file)
 obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj
api=load("acquire194_199","sapphon_194_acquire.py")
ledger=load("ledger197_199","sapphon_197_ledger.py")
SOURCE="16aebb4fc9551e505ec7f461b7db05db6f340d86"
WORKFLOW="sapphon-198-import.yml"
ARTIFACT="sapphon-198-cross-run-ledger-tip"
MEMBERS={"198-import.json","198-adjudication.json","198-ledger.jsonl","198-summary.json"}
MAX_BYTES=32*1024*1024
def digest(b):return hashlib.sha256(b).hexdigest()
def hold(state,extra=None):
 return {"schema":"sapphon-199-retention-v1","state":state,
 "source_sha":SOURCE,"original_parent_verified":False,
 "parent_tip_sha256":None,"parent_entries":None,"inherited_forks":[],
 "retention_metadata_untrusted":True,"deletion_confirmed":False,
 "global_anti_rollback_authenticated":False,"authenticated_utc":False,
 "external_custody_authenticated":False,"independent_witnesses":0,
 "recovery_authorized":False,"lock_cleared":False,
 "decision":"PARENT_RETENTION_PRESSURE_HOLD",**(extra or {})}
def inspect(raw,run,artifact):
 if type(raw) is not bytes or not raw or len(raw)>MAX_BYTES:return hold("ORIGINAL_ZIP_NOT_OBSERVED")
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   items=z.infolist();names=[x.filename for x in items]
   if set(names)!=MEMBERS or len(names)!=len(set(names)) or any(
      x.is_dir() or x.flag_bits&1 or x.file_size>2*1024*1024 or
      stat.S_ISLNK(x.external_attr>>16) or "/" in x.filename or "\\" in x.filename
      for x in items):return hold("ZIP_MEMBER_CONFLICT")
   rawledger=z.read("198-ledger.jsonl")
   chain=[json.loads(x) for x in rawledger.splitlines() if x.strip()]
   report=json.loads(z.read("198-adjudication.json"))
   summary=json.loads(z.read("198-summary.json"))
   parent=json.loads(z.read("198-import.json"))
 except (zipfile.BadZipFile,ValueError,KeyError,RuntimeError,OverflowError,UnicodeError):
  return hold("ZIP_CORRUPT")
 if (type(summary) is not dict or summary.get("schema")!="sapphon-198-source-owned-outcomes-v1" or
     summary.get("commit")!=SOURCE or str(summary.get("run_id"))!=str(run["id"]) or
     str(summary.get("attempt"))!=str(run["run_attempt"]) or summary.get("recovery_authorized") is not False):
  return hold("SOURCE_RUN_ATTEMPT_CONFLICT")
 if type(report) is not dict or report.get("schema")!="sapphon-198-cross-run-v1" or report.get("recovery_authorized") is not False:
  return hold("ADJUDICATION_INVALID")
 if (type(parent) is not dict or parent.get("schema")!="sapphon-198-import-v1"
     or parent.get("state")!="OWNED_197_CHAIN_IMPORTED"
     or parent.get("source_sha")!="9bddb4491893ee121f71821b61692685508adae6"
     or parent.get("prior_ledger_observed") is not True):
  return hold("197_PARENT_NOT_OBSERVED")
 try:
  complete=ledger.validate(chain)
  n=report["predecessor_entries"]
  if type(n) is not int or n<0 or n>=len(chain):return hold("PARENT_BOUNDARY_INVALID")
  predecessor=ledger.validate(chain[:n])
 except (ValueError,KeyError,TypeError):
  return hold("CHAIN_HASH_INVALID")
 if (report.get("predecessor_tip_sha256")!=predecessor["tip_sha256"] or
     parent.get("prior_tip_sha256")!=predecessor["tip_sha256"] or
     parent.get("chain_entries")!=n or
     report.get("new_entries")!=complete["entries"] or
     report.get("new_tip_sha256")!=complete["tip_sha256"] or
     report.get("all_forks")!=complete["forks"] or
     report.get("inherited_forks")!=predecessor["forks"] or
     summary.get("inherited_forks_preserved")!=len(predecessor["forks"])):
  return hold("PARENT_TIP_OR_FORK_EQUIVOCATION")
 if complete["entries"]!=n+1 or chain[:n]!=chain[:-1]:
  return hold("NON_APPEND_PARENT_REPLAY")
 return {**hold("SOURCE_OWNED_PARENT_REPLAY_VERIFIED"),"original_parent_verified":True,
  "parent_tip_sha256":predecessor["tip_sha256"],"parent_entries":n,
  "new_tip_sha256":complete["tip_sha256"],"inherited_forks":predecessor["forks"],
  "all_forks":complete["forks"],"prior_missing":predecessor["missing_and_expired"],
  "original_zip_sha256":digest(raw),"original_ledger_sha256":digest(rawledger),
  "run_id":run["id"],"attempt":run["run_attempt"],"artifact_id":artifact["id"]}
def acquire(fetch=api.json_api,download=api.api):
 base=f"repos/{api.REPO}/actions"
 rows,state,pages=api.listing(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return hold("RUN_LISTING_"+state,{"pages":pages})
 candidates=[r for r in rows if r.get("head_sha")==SOURCE]
 if not candidates:return hold("EXACT_RUN_NOT_OBSERVED")
 if any(not api.positive(r.get("run_attempt")) for r in candidates):return hold("INVALID_RUN_ATTEMPT")
 run=max(candidates,key=lambda x:(x["id"],x["run_attempt"]))
 artifacts,state,pages=api.listing(f"{base}/runs/{run['id']}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return hold("ARTIFACT_LISTING_"+state,{"pages":pages})
 matches=[a for a in artifacts if a.get("name")==ARTIFACT]
 if len(matches)!=1:return hold("ARTIFACT_NOT_UNIQUE_OR_MISSING")
 artifact=matches[0]
 if artifact.get("expired") is True:return hold("ARTIFACT_METADATA_EXPIRED")
 if artifact.get("expired") is not False:return hold("ARTIFACT_EXPIRY_UNKNOWN")
 assoc=artifact.get("workflow_run") or {}
 if assoc and (assoc.get("id")!=run["id"] or assoc.get("head_sha")!=SOURCE):
  return hold("ARTIFACT_ANCESTRY_CONFLICT")
 try:raw=download(f"{base}/artifacts/{artifact['id']}/zip")
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError):
  return hold("ORIGINAL_DOWNLOAD_UNAVAILABLE")
 return inspect(raw,run,artifact)
def main():
 p=argparse.ArgumentParser();p.add_argument("--out",default="qualification-artifact/199-parent.json")
 a=p.parse_args()
 try:result=acquire()
 except (ValueError,TypeError,KeyError,OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  result=hold("ACQUISITION_ERROR",{"error_type":type(e).__name__})
 target=pathlib.Path(a.out);target.parent.mkdir(parents=True,exist_ok=True)
 target.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(result["state"])
 if not result["original_parent_verified"] or result["inherited_forks"]:sys.exit(1)
if __name__=="__main__":main()
