#!/usr/bin/env python3
"""SAPPHON-181 owned-GitHub acquisition. No synthetic bytes, no extraction.

Runs only in GitHub Actions with GH_TOKEN. Raw logs/ZIP stay under a temporary
directory outside uploaded artifacts. Failures yield reason-coded JSON.
"""
import argparse,hashlib,json,os,pathlib,subprocess,sys
SOURCE="dd1d778c522aa18fb399c052958f05c4f5b02dd9"
WORKFLOW="sapphon-180-binding.yml"
JOB="artifact-binding"
ARTIFACT="sapphon-180-byte-binding"
REPO="DavidWise01/super-sapphon"
def gh(path):
 return subprocess.run(["gh","api",path],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45).stdout
def get_json(path):return json.loads(gh(path))
def select(runs):
 matches=[r for r in runs if r.get("head_sha")==SOURCE and
   type(r.get("id")) is int and type(r.get("run_attempt")) is int
   and r["id"]>0 and r["run_attempt"]>0]
 matches.sort(key=lambda r:(r["id"],r["run_attempt"]),reverse=True)
 return matches[0] if matches else None
def acquire(directory):
 state={"schema":"sapphon-181-acquisition-v1","source_sha":SOURCE,
        "workflow":WORKFLOW,"job_name":JOB,"status":"READBACK_UNAVAILABLE",
        "source_owned_bytes_observed":False,"recovery_authorized":False}
 directory.mkdir(parents=True,exist_ok=True)
 try:
  run=None
  for page in range(1,11):
   rows=get_json(f"repos/{REPO}/actions/workflows/{WORKFLOW}/runs?per_page=100&page={page}").get("workflow_runs",[])
   run=select(rows)
   if run:break
   if len(rows)<100:
    state["status"]="NO_EXACT_RUN_IN_EXHAUSTED_PAGES"
    return state
  if not run:
   state["status"]="RUN_SEARCH_INCOMPLETE_PAGE_CAP"
   return state
  rid=run["id"];attempt=run["run_attempt"]
  state.update(run_id=rid,attempt=attempt)
  jobs=get_json(f"repos/{REPO}/actions/runs/{rid}/attempts/{attempt}/jobs?per_page=100").get("jobs",[])
  matched=[j for j in jobs if j.get("name")==JOB and type(j.get("id")) is int]
  if len(matched)!=1:
   state["status"]="EXPECTED_JOB_NOT_UNIQUE";return state
  job=matched[0]
  artifacts=get_json(f"repos/{REPO}/actions/runs/{rid}/artifacts?per_page=100").get("artifacts",[])
  found=[a for a in artifacts if a.get("name")==ARTIFACT and type(a.get("id")) is int]
  if len(found)!=1:
   state["status"]="EXPECTED_ARTIFACT_NOT_UNIQUE";return state
  art=found[0]
  if art.get("expired") is not False:
   state["status"]="ARTIFACT_EXPIRED";return state
  raw=gh(f"repos/{REPO}/actions/jobs/{job['id']}/logs")
  zipbytes=gh(f"repos/{REPO}/actions/artifacts/{art['id']}/zip")
  if not raw or len(raw)>8*1024*1024:
   state["status"]="RAW_JOB_LOG_MISSING_OR_OVERSIZE";return state
  if not zipbytes.startswith(b"PK") or len(zipbytes)>64*1024*1024:
   state["status"]="ZIP_DOWNLOAD_MISSING_OR_UNEXPECTED";return state
  (directory/"181-original-job.log").write_bytes(raw)
  (directory/"181-original-artifact.zip").write_bytes(zipbytes)
  manifest={"schema":"sapphon-181-original-byte-manifest-v1",
   "source_sha":SOURCE,"workflow":WORKFLOW,"job_name":JOB,
   "artifact_name":ARTIFACT,"run_id":rid,"attempt":attempt,
   "job_id":job["id"],"artifact_id":art["id"],
   "artifact_expired":False,"run_status":run.get("status"),
   "run_conclusion":run.get("conclusion"),"job_conclusion":job.get("conclusion"),
   "log_kind":"RAW_JOB_LOG","artifact_kind":"ORIGINAL_ZIP",
   "log_sha256":hashlib.sha256(raw).hexdigest(),
   "artifact_sha256":hashlib.sha256(zipbytes).hexdigest(),
   "independent_custody_authenticated":False,"recovery_authorized":False}
  (directory/"181-manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
  state.update(status="ORIGINAL_BYTES_OBSERVED",source_owned_bytes_observed=True,
    job_id=job["id"],artifact_id=art["id"],log_sha256=manifest["log_sha256"],
    artifact_sha256=manifest["artifact_sha256"])
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired,ValueError,KeyError,OSError) as e:
  state["status"]="READBACK_UNAVAILABLE"
  state["error_type"]=type(e).__name__
 return state
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--private-dir",required=True)
 p.add_argument("--out",default="qualification-artifact/181-acquisition.json")
 a=p.parse_args()
 result=acquire(pathlib.Path(a.private_dir))
 out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(result["status"])
 if not result["source_owned_bytes_observed"]:sys.exit(1)
if __name__=="__main__":main()
