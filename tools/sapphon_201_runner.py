#!/usr/bin/env python3
"""SAPPHON-201 exact SAPPHON-200 run qualification.

Separates real original job logs, exact artifact bytes, missing CI run,
failed source tests and source-owned PASS. Never repairs from guessed logs.
"""
import argparse,hashlib,importlib.util,io,json,pathlib,stat,subprocess,sys,zipfile
P=pathlib.Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location("a194",P/"sapphon_194_acquire.py")
a=importlib.util.module_from_spec(sp);sp.loader.exec_module(a)
SOURCE="c914d2710192cf0c80e12641dfad82a4a006998d"
WORKFLOW="sapphon-200-freeze.yml"
JOB="final-phase-xix-freeze"
ARTIFACT="sapphon-200-phase-xix-final-freeze"
MEMBERS={"200-retention.json","200-outcomes.json","200-freeze.json","200-summary.json"}
CRITICAL={"python":"Run all eight-bound Phase XIX Python negative controls",
 "rust":"Compile all Rust modules and run regression tests",
 "frozen":"Verify 188 protected historical files",
 "freeze":"Build exact eight-source snapshot and observed outcome inventory"}
MAX_BYTES=32*1024*1024
def sha(b):return hashlib.sha256(b).hexdigest()
def hold(reason,details=None):
 return {"schema":"sapphon-201-hosted-qualification-v1","state":reason,
  "source_sha":SOURCE,"run_id":None,"attempt":None,
  "observed_failed_steps":[],"step_states":{},
  "original_job_log_sha256":None,"original_zip_sha256":None,
  "source_owned_runner_pass":False,"original_bytes_complete":False,
  "evidence_observed":False,"independent_witnesses":0,
  "external_custody_authenticated":False,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"PHASE_XX_HOSTED_QUALIFICATION_HOLD",**(details or {})}
def inspect_zip(raw,run,artifact):
 if type(raw) is not bytes or not raw or len(raw)>MAX_BYTES:
  return {"state":"ZIP_NOT_OBSERVED"}
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   info=z.infolist();names=[v.filename for v in info]
   if set(names)!=MEMBERS or len(names)!=len(set(names)) or any(
    v.is_dir() or v.flag_bits&1 or v.file_size>2*1024*1024 or
    stat.S_ISLNK(v.external_attr>>16) or "/" in v.filename or "\\" in v.filename
    for v in info):return {"state":"ZIP_MEMBER_CONFLICT"}
   content={name:json.loads(z.read(name)) for name in MEMBERS}
 except (zipfile.BadZipFile,ValueError,KeyError,RuntimeError,UnicodeError,OverflowError):
  return {"state":"ZIP_CORRUPT"}
 freeze,summary=content["200-freeze.json"],content["200-summary.json"]
 outcomes,retention=content["200-outcomes.json"],content["200-retention.json"]
 if type(freeze) is not dict or freeze.get("schema")!="sapphon-200-phase-xix-source-freeze-v1" or freeze.get("source_head")!=SOURCE or freeze.get("recovery_authorized") is not False:
  return {"state":"PHASE_FREEZE_ANCESTRY_CONFLICT"}
 if type(summary) is not dict or summary.get("schema")!="sapphon-200-source-owned-run-v1" or summary.get("commit")!=SOURCE or str(summary.get("run_id"))!=str(run["id"]) or str(summary.get("attempt"))!=str(run["run_attempt"]) or summary.get("recovery_authorized") is not False:
  return {"state":"SUMMARY_ATTEMPT_CONFLICT"}
 if type(outcomes) is not dict or outcomes.get("schema")!="sapphon-200-outcomes-v1" or not isinstance(outcomes.get("outcomes"),dict):
  return {"state":"OUTCOME_SCHEMA"}
 if type(retention) is not dict or retention.get("schema")!="sapphon-199-retention-v1" or retention.get("deletion_confirmed") is not False:
  return {"state":"RETENTION_AUTHORITY_CONFLICT"}
 if freeze.get("observed_outcomes")!=outcomes["outcomes"]:
  return {"state":"FREEZE_OUTCOME_EQUIVOCATION"}
 if summary.get("source_design_complete")!=(freeze.get("source_design_complete") is True):
  return {"state":"FREEZE_SUMMARY_CONTRADICTION"}
 if summary.get("source_tests_pass")!=all(summary.get("steps",{}).get(k)=="success" for k in ("PYTHON","RUST","FROZEN")):
  return {"state":"FALSE_SOURCE_PASS_CLAIM"}
 return {"state":"EXACT_ORIGINAL_ZIP_OBSERVED","sha256":sha(raw),"bytes":len(raw),
  "artifact_id":artifact["id"],"freeze_design_complete":freeze.get("source_design_complete") is True,
  "summary_step_states":summary["steps"],"retention_state":retention.get("state","NOT_OBSERVED")}
def observe(run,jobs,artifacts,log,zipbytes):
 result=hold("EVIDENCE_NOT_COMPLETE",{"run_id":run.get("id"),"attempt":run.get("run_attempt")})
 if run.get("head_sha")!=SOURCE or run.get("run_attempt") is None or not a.positive(run.get("run_attempt")):
  return hold("RUN_ANCESTRY_CONFLICT")
 if run.get("status")!="completed":return {**result,"state":"RUN_INCOMPLETE"}
 matched=[j for j in jobs if j.get("name")==JOB]
 if len(matched)!=1:return {**result,"state":"REQUIRED_JOB_NOT_UNIQUE"}
 job=matched[0]
 if job.get("run_attempt") not in (None,run["run_attempt"]) or job.get("run_id") not in (None,run["id"]):
  return {**result,"state":"JOB_ATTEMPT_CONFLICT"}
 steps=job.get("steps",[])
 if type(steps) is not list:return {**result,"state":"STEP_ARRAY_INVALID"}
 states={};failed=[]
 for key,name in CRITICAL.items():
  matches=[x for x in steps if type(x) is dict and x.get("name")==name]
  if len(matches)!=1:return {**result,"state":"STEP_MISSING_OR_DUPLICATE","step":key}
  state=matches[0].get("conclusion","NOT_OBSERVED")
  states[key]=state
  if state in ("failure","cancelled","timed_out"):failed.append({"step":key,"state":state})
 result["step_states"]=states;result["observed_failed_steps"]=failed
 if type(log) is bytes and 0<len(log)<=MAX_BYTES:result["original_job_log_sha256"]=sha(log)
 matched=[x for x in artifacts if x.get("name")==ARTIFACT]
 if len(matched)!=1:return {**result,"state":"ARTIFACT_NOT_UNIQUE"}
 artifact=matched[0]
 if artifact.get("expired") is not False:return {**result,"state":"ARTIFACT_EXPIRED_OR_UNKNOWN"}
 association=artifact.get("workflow_run") or {}
 if association and (association.get("id")!=run["id"] or association.get("head_sha")!=SOURCE):
  return {**result,"state":"ARTIFACT_ANCESTRY_CONFLICT"}
 inspected=inspect_zip(zipbytes,run,artifact)
 result["original_zip_state"]=inspected["state"]
 if inspected["state"]=="EXACT_ORIGINAL_ZIP_OBSERVED":
  result["original_zip_sha256"]=inspected["sha256"]
  result["source_owned_freeze_design_complete"]=inspected["freeze_design_complete"]
  result["reported_step_states"]=inspected["summary_step_states"]
  if inspected["summary_step_states"].get("PYTHON")!=states["python"] or inspected["summary_step_states"].get("RUST")!=states["rust"] or inspected["summary_step_states"].get("FROZEN")!=states["frozen"]:
   result["state"]="CHILD_STEP_OUTCOME_CONFLICT";return result
 result["original_bytes_complete"]=bool(result["original_job_log_sha256"] and result["original_zip_sha256"])
 result["evidence_observed"]=result["original_bytes_complete"]
 success=(result["original_bytes_complete"] and not failed and
  all(x=="success" for x in states.values()) and
  run.get("conclusion")=="success" and job.get("conclusion")=="success" and
  inspected.get("freeze_design_complete") is True)
 result["source_owned_runner_pass"]=success
 result["state"]="SOURCE_OWNED_RUN_PASS" if success else ("OBSERVED_FAILURE" if failed else "RUNNER_NOT_QUALIFIED")
 return result
def acquire(fetch=a.json_api,download=a.api):
 base=f"repos/{a.REPO}/actions"
 runs,state,pages=a.listing(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return hold("RUN_LIST_"+state,{"pages_scanned":pages})
 matches=[v for v in runs if v.get("head_sha")==SOURCE]
 if not matches:return hold("EXACT_200_RUN_NOT_OBSERVED")
 if any(not a.positive(v.get("run_attempt")) for v in matches):
  return hold("MALFORMED_ATTEMPT")
 run=max(matches,key=lambda x:(x["id"],x["run_attempt"]))
 jobs,js,_=a.listing(f"{base}/runs/{run['id']}/attempts/{run['run_attempt']}/jobs","jobs",fetch)
 artifacts,az,_=a.listing(f"{base}/runs/{run['id']}/artifacts","artifacts",fetch)
 if js!="EXHAUSTED" or az!="EXHAUSTED":return hold("INCOMPLETE_JOB_OR_ARTIFACT_PAGINATION")
 job=[j for j in jobs if j.get("name")==JOB]
 if len(job)!=1:return hold("REQUIRED_JOB_NOT_UNIQUE")
 try:raw_log=download(f"{base}/jobs/{job[0]['id']}/logs")
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError):raw_log=None
 archive=[x for x in artifacts if x.get("name")==ARTIFACT]
 raw_zip=None
 if len(archive)==1 and archive[0].get("expired") is False:
  try:raw_zip=download(f"{base}/artifacts/{archive[0]['id']}/zip")
  except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError):pass
 return observe(run,jobs,artifacts,raw_log,raw_zip)
def main():
 p=argparse.ArgumentParser();p.add_argument("--out",default="qualification-artifact/201-runner.json")
 args=p.parse_args()
 try:r=acquire()
 except (ValueError,TypeError,KeyError,OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
  r=hold("ACQUISITION_UNAVAILABLE",{"error_type":type(exc).__name__})
 target=pathlib.Path(args.out);target.parent.mkdir(parents=True,exist_ok=True)
 target.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 print(r["state"],r.get("observed_failed_steps",[]))
 if not r["source_owned_runner_pass"]:sys.exit(1)
if __name__=="__main__":main()
