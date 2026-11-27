#!/usr/bin/env python3
"""SAPPHON-183: acquire three JSON records from exact SAPPHON-182 Actions artifact.

Never extract ZIP entries or treat GitHub-owned records as independent custody.
Explicit missing-evidence fixtures preserve original absent statuses.
"""
import argparse,hashlib,io,json,pathlib,subprocess,sys,zipfile
REPO="DavidWise01/super-sapphon"
SOURCE="bcc82842d0ebc090db6fb3b32c978a75db3cf9fd"
WORKFLOW="sapphon-182-crossfile.yml"
ARTIFACT="sapphon-182-cross-file-provenance"
FILES=("182-summary.json","182-acquisition.json","182-crossfile.json")
def gh(path):
 return subprocess.run(["gh","api",path],check=True,timeout=45,
   stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
def fetch_json(path):return json.loads(gh(path))
def choose(rows):
 found=[v for v in rows if v.get("head_sha")==SOURCE
  and type(v.get("id")) is int and v["id"]>0
  and type(v.get("run_attempt")) is int and v["run_attempt"]>0]
 found.sort(key=lambda x:(x["id"],x["run_attempt"]),reverse=True)
 return found[0] if found else None
def record_missing(out,status):
 return {"schema":"sapphon-183-acquisition-metadata-v1",
  "status":status,"source_sha":SOURCE,"artifact_observed":False,
  "independent_custody_authenticated":False,"recovery_authorized":False}
def collect(directory):
 directory.mkdir(parents=True,exist_ok=True)
 state=record_missing(directory,"READBACK_UNAVAILABLE")
 try:
  run=None
  for page in range(1,11):
   rows=fetch_json(f"repos/{REPO}/actions/workflows/{WORKFLOW}/runs?per_page=100&page={page}").get("workflow_runs",[])
   run=choose(rows)
   if run:break
   if len(rows)<100:return record_missing(directory,"NO_MATCHING_RUN_IN_EXHAUSTED_PAGES")
  if not run:return record_missing(directory,"RUN_SEARCH_INCOMPLETE_PAGE_CAP")
  rid=run["id"]
  arts=fetch_json(f"repos/{REPO}/actions/runs/{rid}/artifacts?per_page=100").get("artifacts",[])
  hits=[a for a in arts if a.get("name")==ARTIFACT and type(a.get("id")) is int]
  if len(hits)!=1:return record_missing(directory,"ARTIFACT_NOT_UNIQUE")
  art=hits[0]
  if art.get("expired") is not False:return record_missing(directory,"ARTIFACT_EXPIRED")
  raw=gh(f"repos/{REPO}/actions/artifacts/{art['id']}/zip")
  if not raw or len(raw)>64*1024*1024:return record_missing(directory,"ZIP_UNAVAILABLE_OR_OVERSIZE")
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   members=z.infolist()
   if len(members)!=3 or set(x.filename for x in members)!=set(FILES):
    return record_missing(directory,"UNEXPECTED_ARTIFACT_FILES")
   if any(x.file_size>2*1024*1024 or x.flag_bits&1 or x.is_dir()
      or x.filename.startswith("/") for x in members):
    return record_missing(directory,"UNSAFE_ARTIFACT_MEMBER")
   for name in FILES:
    data=z.read(name)
    value=json.loads(data)
    if type(value) is not dict:raise ValueError("NONOBJECT_MEMBER")
    (directory/name).write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
  return {"schema":"sapphon-183-acquisition-metadata-v1",
   "status":"ARTIFACT_JSON_OBSERVED","source_sha":SOURCE,
   "run_id":rid,"attempt":run["run_attempt"],"artifact_id":art["id"],
   "artifact_sha256":hashlib.sha256(raw).hexdigest(),
   "artifact_observed":True,"independent_custody_authenticated":False,
   "recovery_authorized":False}
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError,
         ValueError,KeyError,zipfile.BadZipFile) as exc:
  value=record_missing(directory,"READBACK_UNAVAILABLE")
  value["error_type"]=type(exc).__name__
  return value
def main():
 p=argparse.ArgumentParser();p.add_argument("--directory",required=True)
 p.add_argument("--out",default="qualification-artifact/183-acquisition.json")
 a=p.parse_args();result=collect(pathlib.Path(a.directory))
 path=pathlib.Path(a.out);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(result["status"])
 if not result["artifact_observed"]:sys.exit(1)
if __name__=="__main__":main()
