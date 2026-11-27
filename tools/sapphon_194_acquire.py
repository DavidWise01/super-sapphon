#!/usr/bin/env python3
"""SAPPHON-194: acquire original exact SAPPHON-193 Actions job logs and ZIP bytes.

GitHub-owned evidence only. No synthetic PASS, no archive extraction,
no automatic replay of commands, no operational authority.
"""
import argparse,hashlib,io,json,pathlib,re,subprocess,sys,zipfile,stat
REPO="DavidWise01/super-sapphon"
SHA="517959b0c98b65bafefaba5ae5e18065b2e27212"
WORKFLOW="sapphon-193-triage.yml"
JOB="runner-failure-triage"
ARTIFACT="sapphon-193-exact-run-failure-triage"
MAX_PAGES=10
MAX_ORIGINAL_BYTES=32*1024*1024
MEMBERS={"193-readback.json","193-diagnostic.json","193-summary.json"}
SECRET=re.compile(rb"(?i)(token|authorization|password|secret|api[_-]?key)(\s*[=:]\s*)(\S+)")
def digest(x):return hashlib.sha256(x).hexdigest()
def positive(v):return type(v) is int and v>0
def api(path):
 return subprocess.run(["gh","api",path],check=True,timeout=45,
   stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
def json_api(path):return json.loads(api(path))
def listing(path,key,fetch=json_api):
 output=[];seen=set()
 for page in range(1,MAX_PAGES+1):
  obj=fetch(path+("&" if "?" in path else "?")+f"per_page=100&page={page}")
  rows=obj.get(key) if type(obj) is dict else None
  if type(rows) is not list or len(rows)>100 or any(type(x) is not dict for x in rows):
   return [],"MALFORMED_PAGE",page
  for x in rows:
   if not positive(x.get("id")) or x["id"] in seen:
    return [],"INVALID_OR_DUPLICATE_ID",page
   seen.add(x["id"])
  output.extend(rows)
  if len(rows)<100:return output,"EXHAUSTED",page
 return [],"PAGE_CAP_REACHED",MAX_PAGES
def inspect_zip(raw,run,artifact):
 if type(raw) is not bytes or not raw or len(raw)>MAX_ORIGINAL_BYTES:
  return {"state":"ZIP_UNAVAILABLE_OR_OVERSIZE"}
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   infos=z.infolist();names=[x.filename for x in infos]
   if len(names)!=len(set(names)) or set(names)!=MEMBERS:
    return {"state":"ZIP_MEMBER_SET_CONFLICT"}
   if any(x.is_dir() or x.flag_bits&1 or x.file_size>2*1024*1024 or
     stat.S_ISLNK(x.external_attr>>16) or x.filename.startswith(("/","\\"))
     or ".." in x.filename.split("/") or "\\" in x.filename for x in infos):
    return {"state":"ZIP_MEMBER_UNSAFE"}
   members={name:json.loads(z.read(name)) for name in MEMBERS}
 except (zipfile.BadZipFile,KeyError,ValueError,UnicodeError,RuntimeError,OverflowError):
  return {"state":"ZIP_CORRUPT"}
 summary=members["193-summary.json"]
 if (type(summary) is not dict or summary.get("schema")!="sapphon-193-source-run-v1"
     or summary.get("commit")!=SHA or str(summary.get("run_id"))!=str(run["id"])
     or str(summary.get("attempt"))!=str(run["run_attempt"])
     or summary.get("recovery_authorized") is not False):
  return {"state":"ZIP_RUN_ATTEMPT_CONFLICT"}
 result={"state":"ORIGINAL_ZIP_OBSERVED","sha256":digest(raw),
  "bytes":len(raw),"artifact_id":artifact["id"],
  "members":{name:{"sha256":digest(json.dumps(members[name],sort_keys=True).encode()),
                    "schema":members[name].get("schema") if type(members[name]) is dict else None}
             for name in sorted(MEMBERS)}}
 # No raw body included in the published result.
 return result
def run_acquisition(fetch=json_api,download=api):
 base=f"repos/{REPO}/actions"
 runs,state,pages=listing(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 result={"schema":"sapphon-194-hosted-acquisition-v1","source_sha":SHA,
  "workflow":WORKFLOW,"run_search_state":state,"run_pages_scanned":pages,
  "run_id":None,"attempt":None,"job_search_state":"NOT_OBSERVED",
  "artifact_search_state":"NOT_OBSERVED","job_log":None,"artifact_zip":None,
  "blockers":[],"actual_failed_steps":[],
  "source_owned_original_bytes_complete":False,
  "independent_custody_authenticated":False,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,"recovery_authorized":False,
  "lock_cleared":False,"decision":"HOSTED_ORIGINAL_BYTES_ACQUISITION_HOLD"}
 if state!="EXHAUSTED":
  result["blockers"].append("RUN_SEARCH_"+state);return result
 matches=[r for r in runs if r.get("head_sha")==SHA]
 if not matches:
  result["blockers"].append("EXACT_RUN_NOT_FOUND");return result
 if any(not positive(r.get("run_attempt")) for r in matches):
  result["blockers"].append("MALFORMED_RUN_ATTEMPT");return result
 selected=max(matches,key=lambda r:(r["id"],r["run_attempt"]))
 rid,attempt=selected["id"],selected["run_attempt"]
 result["run_id"]=rid;result["attempt"]=attempt
 jobs,js,jp=listing(f"{base}/runs/{rid}/attempts/{attempt}/jobs","jobs",fetch)
 result["job_search_state"]=js;result["job_pages_scanned"]=jp
 arts,az,ap=listing(f"{base}/runs/{rid}/artifacts","artifacts",fetch)
 result["artifact_search_state"]=az;result["artifact_pages_scanned"]=ap
 if js!="EXHAUSTED" or az!="EXHAUSTED":
  result["blockers"].append("INCOMPLETE_JOB_OR_ARTIFACT_LISTING");return result
 needed=[j for j in jobs if j.get("name")==JOB]
 if len(needed)!=1:
  result["blockers"].append("REQUIRED_JOB_NOT_UNIQUE");return result
 job=needed[0]
 if job.get("run_id") not in (None,rid) or job.get("run_attempt") not in (None,attempt):
  result["blockers"].append("JOB_ATTEMPT_CONFLICT");return result
 result["actual_failed_steps"]=[
  {"name":s.get("name"),"conclusion":s.get("conclusion")}
  for s in job.get("steps",[]) if type(s) is dict and s.get("conclusion") in ("failure","cancelled","timed_out")]
 try:
  raw=download(f"{base}/jobs/{job['id']}/logs")
  if type(raw) is not bytes or not raw or len(raw)>MAX_ORIGINAL_BYTES:raise ValueError("LOG_SIZE")
  bounded=SECRET.sub(rb"\1\2[REDACTED]",raw)[:16000]
  result["job_log"]={"state":"ORIGINAL_LOG_OBSERVED","job_id":job["id"],
   "sha256":digest(raw),"bytes":len(raw),"redacted_excerpt":bounded.decode("utf-8","replace")}
 except (OSError,ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired):
  result["job_log"]={"state":"ORIGINAL_LOG_NOT_OBSERVED"}
 matching=[a for a in arts if a.get("name")==ARTIFACT]
 if len(matching)!=1:
  result["blockers"].append("REQUIRED_ARTIFACT_NOT_UNIQUE");return result
 artifact=matching[0]
 if artifact.get("expired") is not False:
  result["blockers"].append("ARTIFACT_EXPIRED_OR_UNKNOWN");return result
 assoc=artifact.get("workflow_run") or {}
 if assoc and (assoc.get("id")!=rid or assoc.get("head_sha")!=SHA):
  result["blockers"].append("ARTIFACT_ANCESTRY_CONFLICT");return result
 try:result["artifact_zip"]=inspect_zip(download(f"{base}/artifacts/{artifact['id']}/zip"),selected,artifact)
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):
  result["artifact_zip"]={"state":"ORIGINAL_ZIP_NOT_OBSERVED"}
 if result["job_log"]["state"]!="ORIGINAL_LOG_OBSERVED":
  result["blockers"].append("ORIGINAL_JOB_LOG_NOT_OBSERVED")
 if result["artifact_zip"]["state"]!="ORIGINAL_ZIP_OBSERVED":
  result["blockers"].append(result["artifact_zip"]["state"])
 result["source_owned_original_bytes_complete"]=not result["blockers"]
 return result
def main():
 p=argparse.ArgumentParser();p.add_argument("--out",default="qualification-artifact/194-acquisition.json")
 a=p.parse_args()
 try:r=run_acquisition()
 except (ValueError,KeyError,TypeError,OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  r={"schema":"sapphon-194-hosted-acquisition-v1","decision":"HOSTED_ORIGINAL_BYTES_ACQUISITION_HOLD",
   "status":"READBACK_UNAVAILABLE","error_type":type(e).__name__,
   "source_owned_original_bytes_complete":False,"independent_custody_authenticated":False,
   "recovery_authorized":False,"lock_cleared":False}
 f=pathlib.Path(a.out);f.parent.mkdir(parents=True,exist_ok=True)
 f.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print(r.get("status",r.get("run_search_state")),r.get("blockers",[]))
 if not r["source_owned_original_bytes_complete"]:sys.exit(1)
if __name__=="__main__":main()
