#!/usr/bin/env python3
"""SAPPHON-202: original SAPPHON-201 job-log and artifact failure adjudication.

Only an exact 201 run, attempt and original bytes can establish observed
failure. Replay is a fixed argv PLAN_ONLY, never remote log commands.
"""
import argparse,hashlib,importlib.util,io,json,pathlib,stat,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("acquire194_202",ROOT/"sapphon_194_acquire.py")
api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
SOURCE="b5ddf7f7d7d51a282c0109276dc37310f56eb240"
WORKFLOW="sapphon-201-runner.yml"
JOB="observed-hosted-qualification"
ARTIFACT="sapphon-201-observed-hosted-qualification"
MEMBERS={"201-runner.json","201-summary.json"}
STEPS={
 "python":"Execute 201 exact-run and Phase XIX source regressions",
 "rust":"Compile source and run Rust qualifier regressions",
 "frozen":"Recheck historical 188 protected files",
 "acquisition":"Fetch exact SAPPHON-200 workflow, original job logs, and ZIP"}
REPLAY={
 "python":("python3","tools/test_sapphon_201_runner.py"),
 "rust":("cargo","test","--manifest-path","rust/sapphon-liveness/Cargo.toml","--all-targets"),
 "frozen":("python3","tools/sapphon_179_verify_frozen.py")}
MAX_BYTES=32*1024*1024
def sha(raw):return hashlib.sha256(raw).hexdigest()
def hold(state,**kwargs):
 return {"schema":"sapphon-202-replay-adjudication-v1","state":state,
  "pinned_source_sha":SOURCE,"run_id":None,"attempt":None,
  "original_log_sha256":None,"original_artifact_sha256":None,
  "observed_201_failures":[],"original_bytes_complete":False,
  "replay_plan":[],"replay_executed":False,"source_owned_execution_qualified":False,
  "independent_witnesses":0,"external_custody_authenticated":False,
  "authenticated_utc":False,"global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"PHASE_XX_REPRODUCIBLE_FAILURE_HOLD",**kwargs}
def inspect_archive(raw,run,artifact):
 if type(raw) is not bytes or not raw or len(raw)>MAX_BYTES:return {"state":"ZIP_NOT_OBSERVED"}
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   infos=z.infolist();names=[x.filename for x in infos]
   if len(names)!=len(set(names)) or set(names)!=MEMBERS or any(
     x.is_dir() or x.flag_bits&1 or x.file_size>2*1024*1024 or
     stat.S_ISLNK(x.external_attr>>16) or "/" in x.filename or "\\" in x.filename
     for x in infos):return {"state":"ZIP_MEMBER_CONFLICT"}
   report=json.loads(z.read("201-runner.json"))
   summary=json.loads(z.read("201-summary.json"))
 except (zipfile.BadZipFile,ValueError,KeyError,UnicodeError,RuntimeError,OverflowError):
  return {"state":"ZIP_CORRUPT"}
 if (type(summary) is not dict or summary.get("schema")!="sapphon-201-source-owned-run-v1"
   or summary.get("commit")!=SOURCE or str(summary.get("run_id"))!=str(run["id"])
   or str(summary.get("attempt"))!=str(run["run_attempt"])
   or summary.get("recovery_authorized") is not False):
  return {"state":"ZIP_EXACT_ATTEMPT_CONFLICT"}
 if type(report) is not dict or report.get("schema")!="sapphon-201-hosted-qualification-v1" or report.get("source_sha")!="c914d2710192cf0c80e12641dfad82a4a006998d" or report.get("recovery_authorized") is not False:
  return {"state":"ZIP_ORIGINAL_200_SOURCE_CONFLICT"}
 if (summary.get("original_200_run_state")!=report.get("state") or
   summary.get("source_owned_200_runner_pass")!=(report.get("source_owned_runner_pass") is True) or
   summary.get("original_job_and_zip_bytes_observed")!=(report.get("original_bytes_complete") is True) or
   summary.get("original_200_failed_steps")!=report.get("observed_failed_steps")):
  return {"state":"ZIP_200_EVIDENCE_EQUIVOCATION"}
 return {"state":"ZIP_EXACT_SOURCE_OWNED","sha256":sha(raw),"bytes":len(raw),
  "reported_201_steps":summary.get("steps"),
  "reported_source_tests_pass":summary.get("source_tests_pass"),
  "reported_200_failures":report.get("observed_failed_steps",[])}
def inspect(run,job,artifacts,original_log,original_zip):
 if type(run) is not dict or run.get("head_sha")!=SOURCE or not api.positive(run.get("id")) or not api.positive(run.get("run_attempt")):
  return hold("RUN_SOURCE_OR_ATTEMPT_INVALID")
 base=hold("ORIGINAL_BYTES_INCOMPLETE",run_id=run["id"],attempt=run["run_attempt"])
 if type(job) is not dict or job.get("name")!=JOB or not api.positive(job.get("id")):
  return {**base,"state":"JOB_IDENTITY_INVALID"}
 if job.get("run_id") not in (None,run["id"]) or job.get("run_attempt") not in (None,run["run_attempt"]):
  return {**base,"state":"JOB_ATTEMPT_CONFLICT"}
 steps=job.get("steps")
 if type(steps) is not list:return {**base,"state":"JOB_STEPS_UNAVAILABLE"}
 status={};failed=[]
 for key,name in STEPS.items():
  found=[x for x in steps if type(x) is dict and x.get("name")==name]
  if len(found)!=1:return {**base,"state":"CRITICAL_STEP_UNIQUE_MISSING","critical_step":key}
  val=found[0].get("conclusion")
  status[key]=val
  if val in ("failure","cancelled","timed_out"):failed.append({"step":key,"conclusion":val})
 base["observed_201_failures"]=failed;base["observed_201_steps"]=status
 if type(original_log) is bytes and 0<len(original_log)<=MAX_BYTES:
  base["original_log_sha256"]=sha(original_log)
 arts=[x for x in artifacts if type(x) is dict and x.get("name")==ARTIFACT]
 if len(arts)!=1:return {**base,"state":"ORIGINAL_ARTIFACT_NOT_UNIQUE"}
 art=arts[0]
 if art.get("expired") is not False:return {**base,"state":"ARTIFACT_EXPIRED_OR_UNKNOWN"}
 association=art.get("workflow_run") or {}
 if association and (association.get("id")!=run["id"] or association.get("head_sha")!=SOURCE):
  return {**base,"state":"ARTIFACT_ANCESTRY_CONFLICT"}
 zip_result=inspect_archive(original_zip,run,art)
 base["archive_state"]=zip_result["state"]
 if zip_result["state"]=="ZIP_EXACT_SOURCE_OWNED":
  base["original_artifact_sha256"]=zip_result["sha256"]
  reported=zip_result.get("reported_201_steps")
  if type(reported) is not dict or any(reported.get(k.upper())!=v for k,v in status.items()):
   return {**base,"state":"ACTUAL_JOB_VS_ARTIFACT_OUTCOME_CONFLICT"}
  base["reported_200_failures"]=zip_result["reported_200_failures"]
 base["original_bytes_complete"]=bool(base["original_log_sha256"] and base["original_artifact_sha256"])
 if not base["original_bytes_complete"]:return base
 # No reproduction until actual failure is observed; always PLAN_ONLY.
 base["replay_plan"]=[{"id":x["step"],"argv":list(REPLAY[x["step"]]),"mode":"PLAN_ONLY"}
   for x in failed if x["step"] in REPLAY]
 base["source_owned_execution_qualified"]=(run.get("status")=="completed" and
   run.get("conclusion")=="success" and job.get("conclusion")=="success" and not failed and
   all(status[k]=="success" for k in ("python","rust","frozen")))
 base["state"]="OBSERVED_SOURCE_FAILURE" if failed else (
   "SOURCE_OWNED_EXECUTION_OBSERVED" if base["source_owned_execution_qualified"] else "RUN_NOT_QUALIFIED")
 return base
def acquire(fetch=api.json_api,download=api.api):
 root=f"repos/{api.REPO}/actions"
 runs,state,_=api.listing(f"{root}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return hold("RUN_PAGINATION_"+state)
 candidates=[r for r in runs if r.get("head_sha")==SOURCE]
 if not candidates:return hold("EXACT_201_RUN_NOT_FOUND")
 if any(not api.positive(r.get("run_attempt")) for r in candidates):return hold("MALFORMED_ATTEMPT")
 run=max(candidates,key=lambda x:(x["id"],x["run_attempt"]))
 jobs,js,_=api.listing(f"{root}/runs/{run['id']}/attempts/{run['run_attempt']}/jobs","jobs",fetch)
 arts,az,_=api.listing(f"{root}/runs/{run['id']}/artifacts","artifacts",fetch)
 if js!="EXHAUSTED" or az!="EXHAUSTED":return hold("JOB_OR_ARTIFACT_PAGINATION_INCOMPLETE")
 chosen=[x for x in jobs if x.get("name")==JOB]
 if len(chosen)!=1:return hold("REQUIRED_JOB_NOT_UNIQUE")
 artifacts=[x for x in arts if x.get("name")==ARTIFACT]
 log_bytes=None;archive_bytes=None
 try:log_bytes=download(f"{root}/jobs/{chosen[0]['id']}/logs")
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):pass
 if len(artifacts)==1 and artifacts[0].get("expired") is False:
  try:archive_bytes=download(f"{root}/artifacts/{artifacts[0]['id']}/zip")
  except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):pass
 return inspect(run,chosen[0],arts,log_bytes,archive_bytes)
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--out",default="qualification-artifact/202-adjudication.json")
 args=parser.parse_args()
 try:result=acquire()
 except (OSError,KeyError,ValueError,TypeError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  result=hold("API_READBACK_UNAVAILABLE",error_type=type(e).__name__)
 output=pathlib.Path(args.out);output.parent.mkdir(parents=True,exist_ok=True)
 output.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["state"],result.get("observed_201_failures",[]))
 if result["state"] not in ("SOURCE_OWNED_EXECUTION_OBSERVED","OBSERVED_SOURCE_FAILURE"):sys.exit(1)
if __name__=="__main__":main()
