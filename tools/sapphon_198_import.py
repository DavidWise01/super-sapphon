#!/usr/bin/env python3
"""SAPPHON-198: original ZIP import of exact SAPPHON-197 hash ledger.

All custody remains GitHub-owned. A reconstructed ledger from reports is NOT
accepted: bytes from the exact source-owned 197 artifact are required.
"""
import argparse,hashlib,importlib.util,io,json,pathlib,stat,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
def load(name,path):
 sp=importlib.util.spec_from_file_location(name,ROOT/path)
 obj=importlib.util.module_from_spec(sp);sp.loader.exec_module(obj);return obj
legacy=load("ledger197","sapphon_197_ledger.py")
api194=load("a194","sapphon_194_acquire.py")
SOURCE="9bddb4491893ee121f71821b61692685508adae6"
WORKFLOW="sapphon-197-monotonic.yml"
ARTIFACT="sapphon-197-monotonic-readback-evidence"
MEMBERS={"197-import.json","197-ledger.jsonl","197-adjudication.json","197-summary.json"}
MAX_ZIP=32*1024*1024
def digest(raw):return hashlib.sha256(raw).hexdigest()
def unavailable(state):return {"state":state,"prior_ledger_observed":False,"chain_entries":0,
    "prior_tip_sha256":None,"prior_forks":[],"original_zip_sha256":None,
    "cross_run_continuity_verified":False,"independent_witnesses":0,
    "recovery_authorized":False,"lock_cleared":False}
def inspect(raw,run,artifact):
 if type(raw) is not bytes or not raw or len(raw)>MAX_ZIP:return unavailable("ZIP_MISSING_OR_OVERSIZE")
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   infos=z.infolist();names=[i.filename for i in infos]
   if len(names)!=len(set(names)) or set(names)!=MEMBERS:
    return unavailable("ORIGINAL_MEMBERS_CONFLICT")
   if any(i.is_dir() or i.flag_bits&1 or i.file_size>2*1024*1024 or
          stat.S_ISLNK(i.external_attr>>16) or "/" in i.filename or "\\" in i.filename
          for i in infos):
    return unavailable("ORIGINAL_ZIP_UNSAFE")
   raw_ledger=z.read("197-ledger.jsonl")
   chain=[json.loads(line) for line in raw_ledger.splitlines() if line.strip()]
   adjudication=json.loads(z.read("197-adjudication.json"))
   summary=json.loads(z.read("197-summary.json"))
 except (zipfile.BadZipFile,ValueError,KeyError,UnicodeError,RuntimeError,OverflowError):
  return unavailable("ORIGINAL_ZIP_CORRUPT")
 if type(summary) is not dict or summary.get("schema")!="sapphon-197-owned-run-results-v1" or summary.get("commit")!=SOURCE or str(summary.get("run_id"))!=str(run["id"]) or str(summary.get("attempt"))!=str(run["run_attempt"]) or summary.get("recovery_authorized") is not False:
  return unavailable("RUN_ATTEMPT_SUBSTITUTED")
 if type(adjudication) is not dict or adjudication.get("schema")!="sapphon-197-readback-adjudication-v1" or adjudication.get("recovery_authorized") is not False:
  return unavailable("ADJUDICATION_SCHEMA")
 try:computed=legacy.validate(chain)
 except (ValueError,KeyError,TypeError):
  return unavailable("CHAIN_TAMPER_OR_SCHEMA")
 for k in ("source_sha","entries","tip_sha256","forks","missing_and_expired","owned_chain_consistent"):
  if adjudication.get(k)!=computed.get(k):return unavailable("ADJUDICATION_TIP_CONFLICT")
 if summary.get("source_owned_forks")!=len(computed["forks"]):
  return unavailable("SUMMARY_FORK_CONFLICT")
 if summary.get("ledger_complete") is not True:return unavailable("PREDECESSOR_LEDGER_NOT_COMPLETE")
 return {"state":"OWNED_197_CHAIN_IMPORTED","prior_ledger_observed":True,
   "chain_entries":len(chain),"prior_tip_sha256":computed["tip_sha256"],
   "prior_forks":computed["forks"],"prior_missing":computed["missing_and_expired"],
   "original_zip_sha256":digest(raw),"ledger_bytes_sha256":digest(raw_ledger),
   "run_id":run["id"],"attempt":run["run_attempt"],"artifact_id":artifact["id"],
   "cross_run_continuity_verified":True,
   "independent_witnesses":0,"recovery_authorized":False,"lock_cleared":False,
   "chain":chain}
def acquire(fetch=api194.json_api,download=api194.api):
 base=f"repos/{api194.REPO}/actions"
 runs,state,_=api194.listing(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return unavailable("RUN_LIST_"+state)
 selected=[r for r in runs if r.get("head_sha")==SOURCE]
 if not selected:return unavailable("EXACT_197_RUN_NOT_OBSERVED")
 if any(not api194.positive(r.get("run_attempt")) for r in selected):
  return unavailable("RUN_ATTEMPT_INVALID")
 run=max(selected,key=lambda x:(x["id"],x["run_attempt"]))
 artifacts,state,_=api194.listing(f"{base}/runs/{run['id']}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return unavailable("ARTIFACT_LIST_"+state)
 found=[x for x in artifacts if x.get("name")==ARTIFACT]
 if len(found)!=1:return unavailable("REQUIRED_ARTIFACT_NOT_UNIQUE")
 artifact=found[0]
 if artifact.get("expired") is not False:return unavailable("ARTIFACT_EXPIRED_OR_UNKNOWN")
 association=artifact.get("workflow_run") or {}
 if association and (association.get("id")!=run["id"] or association.get("head_sha")!=SOURCE):
  return unavailable("ARTIFACT_ANCESTRY_CONFLICT")
 try:raw=download(f"{base}/artifacts/{artifact['id']}/zip")
 except (OSError,subprocess.TimeoutExpired,subprocess.CalledProcessError):
  return unavailable("DOWNLOAD_UNAVAILABLE")
 return inspect(raw,run,artifact)
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--out",default="qualification-artifact/198-import.json")
 p.add_argument("--ledger-out",default="qualification-artifact/198-prior-ledger.jsonl")
 a=p.parse_args()
 try:r=acquire()
 except (OSError,ValueError,KeyError,TypeError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  r=unavailable("READBACK_UNAVAILABLE");r["error_type"]=type(e).__name__
 actual=r.get("state")=="OWNED_197_CHAIN_IMPORTED"
 chain=r.pop("chain",None)
 r.update({"schema":"sapphon-198-import-v1","source_sha":SOURCE,
   "independent_custody_authenticated":False,"authenticated_utc":False,
   "global_anti_rollback_authenticated":False,"recovery_authorized":False,"lock_cleared":False})
 path=pathlib.Path(a.out);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 if actual:
  path=pathlib.Path(a.ledger_out)
  with path.open("xb") as out:
   for item in chain:out.write(legacy.canonical(item)+b"\n")
   out.flush()
   import os
   os.fsync(out.fileno())
 print(r["state"])
 if not actual:sys.exit(1)
if __name__=="__main__":main()
