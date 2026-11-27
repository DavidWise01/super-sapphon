#!/usr/bin/env python3
"""SAPPHON-197: exact predecessor SAPPHON-196 artifact import, source owned.

No prior ZIP? Emit a missing-evidence record, never a fabricated observation.
"""
import argparse,importlib.util,io,json,pathlib,stat,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("a194",ROOT/"sapphon_194_acquire.py")
a194=importlib.util.module_from_spec(spec);spec.loader.exec_module(a194)
SHA="56d66ad2390063f08e33872299eebe6c8d78a8fe"
WORKFLOW="sapphon-196-reacquire.yml"
ARTIFACT="sapphon-196-original-byte-comparison"
NAMES={"196-reacquisition.json","196-summary.json"}
def acquire(fetch=a194.json_api,download=a194.api):
 base=f"repos/{a194.REPO}/actions"
 runs,state,_=a194.listing(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return {"state":"RUN_LISTING_"+state}
 matches=[r for r in runs if r.get("head_sha")==SHA]
 if not matches:return {"state":"EXACT_196_RUN_NOT_OBSERVED"}
 if any(not a194.positive(r.get("run_attempt")) for r in matches):
  return {"state":"196_ATTEMPT_INVALID"}
 run=max(matches,key=lambda r:(r["id"],r["run_attempt"]))
 arts,state,_=a194.listing(f"{base}/runs/{run['id']}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return {"state":"196_ARTIFACT_LISTING_"+state}
 found=[a for a in arts if a.get("name")==ARTIFACT]
 if len(found)!=1:return {"state":"196_ARTIFACT_NOT_UNIQUE"}
 a=found[0]
 if a.get("expired") is not False:return {"state":"196_ARTIFACT_EXPIRED_OR_UNKNOWN"}
 assoc=a.get("workflow_run") or {}
 if assoc and (assoc.get("id")!=run["id"] or assoc.get("head_sha")!=SHA):
  return {"state":"196_ARTIFACT_ANCESTRY_CONFLICT"}
 try:raw=download(f"{base}/artifacts/{a['id']}/zip")
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):
  return {"state":"196_ARTIFACT_ZIP_NOT_OBSERVED"}
 if type(raw) is not bytes or not raw or len(raw)>32*1024*1024:
  return {"state":"196_ZIP_OVERSIZE_OR_MISSING"}
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   items=z.infolist();names=[x.filename for x in items]
   if len(names)!=len(set(names)) or set(names)!=NAMES or any(
     x.is_dir() or x.flag_bits&1 or x.file_size>2*1024*1024 or
     stat.S_ISLNK(x.external_attr>>16) or "/" in x.filename or "\\" in x.filename
     for x in items):return {"state":"196_ZIP_MEMBER_CONFLICT"}
   report=json.loads(z.read("196-reacquisition.json"))
   summary=json.loads(z.read("196-summary.json"))
 except (zipfile.BadZipFile,KeyError,ValueError,UnicodeError,RuntimeError,OverflowError):
  return {"state":"196_ZIP_CORRUPT"}
 if (type(summary) is not dict or summary.get("schema")!="sapphon-196-owned-run-results-v1"
     or summary.get("commit")!=SHA or str(summary.get("run_id"))!=str(run["id"])
     or str(summary.get("attempt"))!=str(run["run_attempt"])
     or summary.get("recovery_authorized") is not False):
  return {"state":"196_EMBEDDED_RUN_IDENTITY_CONFLICT"}
 if (type(report) is not dict or report.get("schema")!="sapphon-196-original-byte-reacquisition-v1"
     or summary.get("reacquisition_state")!=report.get("state")
     or summary.get("original_bytes_reacquired")!=(report.get("original_bytes_reacquired") is True)
     or report.get("recovery_authorized") is not False):
  return {"state":"196_SUMMARY_READBACK_CONFLICT"}
 return {"state":"OWNED_196_READBACK_IMPORTED","report":report,
   "run_id":run["id"],"attempt":run["run_attempt"],"artifact_id":a["id"],
   "original_zip_sha256":a194.digest(raw)}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--out",default="qualification-artifact/197-import.json")
 p.add_argument("--readback",default="qualification-artifact/197-prior-196.json")
 a=p.parse_args()
 try:r=acquire()
 except (OSError,ValueError,TypeError,KeyError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  r={"state":"READBACK_UNAVAILABLE","error_type":type(e).__name__}
 observed=r.get("state")=="OWNED_196_READBACK_IMPORTED"
 source=r.pop("report",None)
 r.update({"schema":"sapphon-197-import-v1",
  "external_custody_authenticated":False,"recovery_authorized":False,"lock_cleared":False})
 path=pathlib.Path(a.out);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 if observed:
  pathlib.Path(a.readback).write_text(json.dumps(source,sort_keys=True,indent=2)+"\n")
 print(r["state"])
 if not observed:sys.exit(1)
if __name__=="__main__":main()
