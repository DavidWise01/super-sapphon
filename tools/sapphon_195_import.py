#!/usr/bin/env python3
"""SAPPHON-195: read exact SAPPHON-194 diagnostic artifact, metadata only.

Original 193 job-log and ZIP digests were reported by 194; reading that
report does NOT re-download or independently attest those original bytes.
"""
import argparse,importlib.util,io,json,pathlib,stat,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("a194",ROOT/"sapphon_194_acquire.py")
a194=importlib.util.module_from_spec(spec);spec.loader.exec_module(a194)
SOURCE="c2f237a5065c29a13947657c707d101ff2dca31e"
WORKFLOW="sapphon-194-acquire.yml"
ARTIFACT="sapphon-194-hosted-original-byte-diagnostics"
NAMES={"194-acquisition.json","194-summary.json"}
def acquire(fetch=a194.json_api,download=a194.api):
 base=f"repos/{a194.REPO}/actions"
 runs,state,pages=a194.listing(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return {"state":"RUN_LISTING_"+state}
 matches=[r for r in runs if r.get("head_sha")==SOURCE]
 if not matches:return {"state":"EXACT_RUN_MISSING"}
 if any(not a194.positive(r.get("run_attempt")) for r in matches):
  return {"state":"INVALID_RUN_ATTEMPT"}
 run=max(matches,key=lambda r:(r["id"],r["run_attempt"]))
 arts,state,ap=a194.listing(f"{base}/runs/{run['id']}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return {"state":"ARTIFACT_LISTING_"+state}
 found=[a for a in arts if a.get("name")==ARTIFACT]
 if len(found)!=1:return {"state":"ARTIFACT_NOT_UNIQUE"}
 art=found[0]
 if art.get("expired") is not False:return {"state":"ARTIFACT_EXPIRED_OR_UNKNOWN"}
 assoc=art.get("workflow_run") or {}
 if assoc and (assoc.get("id")!=run["id"] or assoc.get("head_sha")!=SOURCE):
  return {"state":"ARTIFACT_RUN_CONFLICT"}
 try:raw=download(f"{base}/artifacts/{art['id']}/zip")
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError):
  return {"state":"ORIGINAL_ARTIFACT_NOT_OBSERVED"}
 if type(raw) is not bytes or not raw or len(raw)>32*1024*1024:
  return {"state":"ZIP_MISSING_OR_OVERSIZE"}
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   infos=z.infolist();names=[m.filename for m in infos]
   if len(names)!=len(set(names)) or set(names)!=NAMES:
    return {"state":"ZIP_MEMBER_SET_CONFLICT"}
   if any(m.is_dir() or m.flag_bits&1 or m.file_size>2*1024*1024 or
    stat.S_ISLNK(m.external_attr>>16) or
    m.filename.startswith(("/","\\"))
    or ".." in m.filename.split("/") or "\\" in m.filename for m in infos):
    return {"state":"UNSAFE_ZIP_MEMBER"}
   acq=json.loads(z.read("194-acquisition.json"))
   summary=json.loads(z.read("194-summary.json"))
 except (zipfile.BadZipFile,ValueError,KeyError,RuntimeError,UnicodeError):
  return {"state":"CORRUPT_ZIP"}
 if type(summary) is not dict or (summary.get("schema")!="sapphon-194-owned-run-results-v1"
  or summary.get("commit")!=SOURCE or
  str(summary.get("run_id"))!=str(run["id"]) or
  str(summary.get("attempt"))!=str(run["run_attempt"]) or
  summary.get("recovery_authorized") is not False):
  return {"state":"PREDECESSOR_IDENTITY_CONFLICT"}
 return {"state":"SOURCE_OWNED_194_REPORT_OBSERVED","run_id":run["id"],
  "attempt":run["run_attempt"],"artifact_id":art["id"],
  "artifact_zip_sha256":a194.digest(raw),
  "acquisition":acq,"summary":summary}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--out",default="qualification-artifact/195-import.json")
 p.add_argument("--acquisition",default="qualification-artifact/195-194-acquisition.json")
 p.add_argument("--summary",default="qualification-artifact/195-194-summary.json")
 a=p.parse_args()
 try:r=acquire()
 except (OSError,KeyError,ValueError,TypeError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  r={"state":"READBACK_UNAVAILABLE","error_type":type(e).__name__}
 got=r.get("state")=="SOURCE_OWNED_194_REPORT_OBSERVED"
 acq=r.pop("acquisition",None);summary=r.pop("summary",None)
 r.update({"schema":"sapphon-195-import-v1","independent_custody_authenticated":False,
  "original_193_bytes_reread":False,"recovery_authorized":False,"lock_cleared":False})
 out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
 out.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 if got:
  pathlib.Path(a.acquisition).write_text(json.dumps(acq,sort_keys=True,indent=2)+"\n")
  pathlib.Path(a.summary).write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
 print(r["state"])
 if not got:sys.exit(1)
if __name__=="__main__":main()
