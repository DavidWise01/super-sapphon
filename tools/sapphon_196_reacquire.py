#!/usr/bin/env python3
"""SAPPHON-196: independently re-request original 193 GitHub bytes.

Comparison anchor: exact SAPPHON-195 published crossverify report.
Distinct GitHub requests are NOT independently held custodians.
No log execution, ZIP extraction, or recovery authorization.
"""
import argparse,hashlib,importlib.util,io,json,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parent
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path)
 obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj)
 return obj
previous=module("import195","sapphon_195_import.py")
a194=module("acquire194","sapphon_194_acquire.py")
SOURCE_195="c5496fcaaa28ce37d9dcb43e69223b6566d1a1a3"
WORKFLOW_195="sapphon-195-crossverify.yml"
ARTIFACT_195="sapphon-195-log-artifact-parity"
REPORT="195-crossverify.json"
MAX_BYTES=32*1024*1024
def sha(b):return hashlib.sha256(b).hexdigest()
def fail(kind,details=None):
 return {"state":kind,"details":details,"original_bytes_reacquired":False,
         "digests_match":False,"external_custody_authenticated":False,
         "recovery_authorized":False,"lock_cleared":False}
def zip_read(raw):
 if type(raw) is not bytes or not raw or len(raw)>MAX_BYTES:return fail("195_ZIP_UNAVAILABLE")
 try:
  import zipfile,stat
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   items=z.infolist()
   allowed={"195-import.json","195-crossverify.json","195-summary.json"}
   if len(items)!=len(set(m.filename for m in items)) or set(m.filename for m in items)!=allowed:
    return fail("195_ZIP_MEMBER_CONFLICT")
   if any(m.is_dir() or m.flag_bits&1 or m.file_size>2*1024*1024 or
          stat.S_ISLNK(m.external_attr>>16) or
          "/" in m.filename or "\\" in m.filename for m in items):
    return fail("195_ZIP_UNSAFE")
   report=json.loads(z.read(REPORT)); summary=json.loads(z.read("195-summary.json"))
 except (ValueError,KeyError,RuntimeError,UnicodeError,zipfile.BadZipFile,OverflowError):
  return fail("195_ZIP_CORRUPT")
 return {"report":report,"summary":summary,"report_zip_sha256":sha(raw)}
def validate_anchor(report,summary,run):
 if type(report) is not dict or report.get("schema")!="sapphon-195-crossverify-v1":
  return "195_REPORT_INVALID"
 if type(summary) is not dict or summary.get("schema")!="sapphon-195-source-owned-v1":
  return "195_SUMMARY_INVALID"
 if summary.get("commit")!=SOURCE_195 or str(summary.get("run_id"))!=str(run["id"]) or str(summary.get("attempt"))!=str(run["run_attempt"]):
  return "195_SUMMARY_IDENTITY"
 if report.get("source_sha")!="c2f237a5065c29a13947657c707d101ff2dca31e" or report.get("prior_source_sha")!=a194.SHA:
  return "195_SOURCE_CONFLICT"
 if report.get("issues")!=[] or report.get("replay_executed") is not False or report.get("recovery_authorized") is not False:
  return "195_REPORT_NOT_QUALIFIED"
 if report.get("original_log_bytes_reread_in_195") is not False or report.get("original_zip_bytes_reread_in_195") is not False:
  return "195_FALSE_ANCESTRY"
 if type(report.get("original_run_id")) is not int or report["original_run_id"]<=0 or type(report.get("original_attempt")) is not int or report["original_attempt"]<=0:
  return "ORIGINAL_RUN_ATTEMPT_INVALID"
 if not a194.positive(run.get("id")):return "195_RUN_INVALID"
 if any(not isinstance(report.get(k),str) or len(report[k])!=64 or any(c not in "0123456789abcdef" for c in report[k])
        for k in ("original_log_sha256","original_zip_sha256")):
  return "195_ORIGINAL_DIGESTS_INVALID"
 return None
def compare(report,run,art,raw_log,raw_zip):
 """Raw bytes are freshly fetched; artifact and job metadata are separately checked."""
 error=validate_anchor(report,{"schema":"sapphon-195-source-owned-v1","commit":SOURCE_195,"run_id":200,"attempt":1}, {"id":200,"run_attempt":1})
 if error:return fail(error)
 if run.get("head_sha")!=a194.SHA or run.get("id")!=report["original_run_id"] or run.get("run_attempt")!=report["original_attempt"]:
  return fail("193_IDENTITY_MISMATCH")
 if type(art) is not dict or art.get("name")!=a194.ARTIFACT or not a194.positive(art.get("id")):
  return fail("193_ARTIFACT_IDENTITY_MISMATCH")
 if art.get("expired") is True:return fail("193_ARTIFACT_EXPIRED")
 if art.get("expired") is not False:return fail("193_ARTIFACT_EXPIRY_UNKNOWN")
 assoc=art.get("workflow_run") or {}
 if assoc and (assoc.get("id")!=run["id"] or assoc.get("head_sha")!=a194.SHA):
  return fail("193_ARTIFACT_ANCESTRY_MISMATCH")
 if any(type(x) is not bytes or not x or len(x)>MAX_BYTES for x in (raw_log,raw_zip)):
  return fail("193_ORIGINAL_BYTES_MISSING_OR_OVERSIZE")
 observed={"log_sha256":sha(raw_log),"zip_sha256":sha(raw_zip),
           "log_bytes":len(raw_log),"zip_bytes":len(raw_zip)}
 inspected=a194.inspect_zip(raw_zip,run,art)
 if inspected.get("state")!="ORIGINAL_ZIP_OBSERVED":
  return {**fail("193_ORIGINAL_ZIP_IDENTITY_INVALID"),"original_observation":observed,"zip_state":inspected.get("state")}
 matches=(observed["log_sha256"]==report["original_log_sha256"] and
          observed["zip_sha256"]==report["original_zip_sha256"])
 return {"state":"GITHUB_OWNED_HASH_MATCH" if matches else "GITHUB_OWNED_READBACK_EQUIVOCATION",
   "original_bytes_reacquired":True,"digests_match":matches,
   "prior_log_sha256":report["original_log_sha256"],"prior_zip_sha256":report["original_zip_sha256"],
   **observed,"original_run_id":run["id"],"original_attempt":run["run_attempt"],
   "artifact_id":art["id"],"external_custody_authenticated":False,
   "independent_witnesses":0,"recovery_authorized":False,"lock_cleared":False}
def acquire(fetch=a194.json_api,download=a194.api):
 base=f"repos/{a194.REPO}/actions"
 runs,state,_=a194.listing(f"{base}/workflows/{WORKFLOW_195}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return fail("195_RUN_LIST_"+state)
 possible=[r for r in runs if r.get("head_sha")==SOURCE_195]
 if not possible:return fail("195_RUN_NOT_FOUND")
 if any(not a194.positive(r.get("run_attempt")) for r in possible):return fail("195_ATTEMPT_INVALID")
 r195=max(possible,key=lambda r:(r["id"],r["run_attempt"]))
 arts,state,_=a194.listing(f"{base}/runs/{r195['id']}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return fail("195_ARTIFACT_LIST_"+state)
 matching=[x for x in arts if x.get("name")==ARTIFACT_195]
 if len(matching)!=1:return fail("195_ARTIFACT_NOT_UNIQUE")
 meta=matching[0]
 if meta.get("expired") is not False:return fail("195_ARTIFACT_NOT_AVAILABLE")
 association=meta.get("workflow_run") or {}
 if association and (association.get("id")!=r195["id"] or association.get("head_sha")!=SOURCE_195):
  return fail("195_ARTIFACT_ANCESTRY")
 try:anchor=zip_read(download(f"{base}/artifacts/{meta['id']}/zip"))
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):return fail("195_ZIP_DOWNLOAD_FAILED")
 if "report" not in anchor:return anchor
 report=anchor["report"];reason=validate_anchor(report,anchor["summary"],r195)
 if reason:return fail(reason)
 rid,attempt=report["original_run_id"],report["original_attempt"]
 # Require exact source ancestry and original run identity; no latest-run substitution.
 try:r193=fetch(f"{base}/runs/{rid}")
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):return fail("193_RUN_LOOKUP_FAILED")
 if type(r193) is not dict or r193.get("id")!=rid or r193.get("head_sha")!=a194.SHA or r193.get("run_attempt",0)<attempt:
  return fail("193_RUN_SOURCE_OR_ATTEMPT_CONFLICT")
 jobs,state,_=a194.listing(f"{base}/runs/{rid}/attempts/{attempt}/jobs","jobs",fetch)
 if state!="EXHAUSTED":return fail("193_JOB_LIST_"+state)
 job=[j for j in jobs if j.get("name")==a194.JOB]
 if len(job)!=1 or not a194.positive(job[0].get("id")):return fail("193_REQUIRED_JOB_NOT_UNIQUE")
 if job[0].get("run_attempt") not in (None,attempt):return fail("193_JOB_ATTEMPT_CONFLICT")
 artifacts,state,_=a194.listing(f"{base}/runs/{rid}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return fail("193_ARTIFACT_LIST_"+state)
 candidates=[a for a in artifacts if a.get("name")==a194.ARTIFACT]
 if len(candidates)!=1:return fail("193_ARTIFACT_NOT_UNIQUE")
 try:rawlog=download(f"{base}/jobs/{job[0]['id']}/logs")
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):return fail("193_LOG_DOWNLOAD_FAILED")
 try:rawzip=download(f"{base}/artifacts/{candidates[0]['id']}/zip")
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):return fail("193_ZIP_DOWNLOAD_FAILED")
 checked=compare(report,{"id":rid,"run_attempt":attempt,"head_sha":a194.SHA},candidates[0],rawlog,rawzip)
 checked.update({"source_report_zip_sha256":anchor["report_zip_sha256"],
  "report_195_run_id":r195["id"],"report_195_attempt":r195["run_attempt"],
  "source_owned_only":True,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False})
 return checked
def main():
 p=argparse.ArgumentParser();p.add_argument("--out",default="qualification-artifact/196-reacquisition.json")
 a=p.parse_args()
 try:result=acquire()
 except (OSError,ValueError,KeyError,TypeError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  result=fail("REACQUISITION_UNAVAILABLE",type(e).__name__)
 result.update({"schema":"sapphon-196-original-byte-reacquisition-v1",
   "decision":"GITHUB_OWNED_READBACK_HOLD","recovery_authorized":False,"lock_cleared":False})
 path=pathlib.Path(a.out);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["state"])
 if result["state"]!="GITHUB_OWNED_HASH_MATCH":sys.exit(1)
if __name__=="__main__":main()
