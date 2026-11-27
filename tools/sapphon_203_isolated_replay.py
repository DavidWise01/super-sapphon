#!/usr/bin/env python3
"""SAPPHON-203: fail-closed, Docker-isolated reproduction of real 201 failures.

The *current* SAPPHON-202 acquisition re-fetches actual 201 bytes. A source-
owned previous 202 ZIP supplies a separate claim. Both must agree exactly.
Only reviewed Python read-only diagnostic commands are reproducible here.
Rust/Cargo is deliberately not executed without an offline dependency image.
No source tree mutation, log-derived shell, network, privileged capabilities,
recovery, or lock clearance.
"""
import argparse,hashlib,importlib.util,io,json,pathlib,stat,subprocess,sys,zipfile
P=pathlib.Path(__file__).resolve().parent
def load(n,p):
 s=importlib.util.spec_from_file_location(n,P/p);x=importlib.util.module_from_spec(s);s.loader.exec_module(x);return x
a=load("a194_203","sapphon_194_acquire.py")
prior=load("repro202_203","sapphon_202_reproduce.py")
SOURCE="e3053b2b52317fc5d5cf1f2546b1e1f0efcc2c6f"
WORKFLOW="sapphon-202-reproduce.yml"
ARTIFACT="sapphon-202-hosted-failure-ancestry"
MEMBERS={"202-adjudication.json","202-summary.json"}
REPLAY={"python":("python3","tools/test_sapphon_201_runner.py"),
        "frozen":("python3","tools/sapphon_179_verify_frozen.py")}
DOCKER_IMAGE="python:3.12-slim"
MAX_ZIP=32*1024*1024
def hashbytes(b):return hashlib.sha256(b).hexdigest()
def hold(state,**extra):
 return {"schema":"sapphon-203-isolated-replay-v1","state":state,
  "pinned_202_source":SOURCE,"original_201_source":prior.SOURCE,
  "evidence_consistent":False,"replay_executed":False,"replay_results":[],
  "replay_sandbox":"DOCKER_NETWORK_NONE_READONLY_SOURCE",
  "actual_failure_reproduced":False,"independent_witnesses":0,
  "external_custody_authenticated":False,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,"recovery_authorized":False,
  "lock_cleared":False,"decision":"PHASE_XX_SANDBOXED_REPLAY_HOLD",**extra}
def inspect_zip(raw,run):
 if type(raw) is not bytes or not raw or len(raw)>MAX_ZIP:return hold("PRIOR_ZIP_UNAVAILABLE")
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   infos=z.infolist();names=[i.filename for i in infos]
   if set(names)!=MEMBERS or len(names)!=len(set(names)) or any(
    i.is_dir() or i.flag_bits&1 or i.file_size>2*1024*1024 or
    stat.S_ISLNK(i.external_attr>>16) or "/" in i.filename or "\\" in i.filename
    for i in infos):return hold("PRIOR_ZIP_MEMBER_CONFLICT")
   assessment=json.loads(z.read("202-adjudication.json"))
   summary=json.loads(z.read("202-summary.json"))
 except (zipfile.BadZipFile,ValueError,KeyError,UnicodeError,RuntimeError,OverflowError):
  return hold("PRIOR_ZIP_CORRUPT")
 if (type(summary) is not dict or summary.get("schema")!="sapphon-202-source-results-v1"
    or summary.get("commit")!=SOURCE or str(summary.get("run_id"))!=str(run["id"])
    or str(summary.get("attempt"))!=str(run["run_attempt"])
    or summary.get("replay_executed") is not False
    or summary.get("recovery_authorized") is not False):
  return hold("PRIOR_RUN_ATTEMPT_CONFLICT")
 if (type(assessment) is not dict or assessment.get("schema")!="sapphon-202-replay-adjudication-v1"
    or assessment.get("pinned_source_sha")!=prior.SOURCE
    or assessment.get("recovery_authorized") is not False
    or assessment.get("replay_executed") is not False):
  return hold("PRIOR_ASSESSMENT_CONFLICT")
 if (summary.get("predecessor_source_state")!=assessment.get("state") or
    summary.get("original_bytes_complete")!=(assessment.get("original_bytes_complete") is True)
    or summary.get("predecessor_failed_steps")!=assessment.get("observed_201_failures")
    or summary.get("reviewed_replay_plans")!=assessment.get("replay_plan")):
  return hold("PRIOR_SUMMARY_EQUIVOCATION")
 return {"state":"PRIOR_202_ORIGINAL_ARTIFACT_OBSERVED","artifact_sha256":hashbytes(raw),
  "assessment":assessment,"summary":summary}
def qualify(archived,fresh,head):
 if type(archived) is not dict or archived.get("state")!="PRIOR_202_ORIGINAL_ARTIFACT_OBSERVED":
  return hold("NO_VERIFIED_202_ARTIFACT")
 old=archived["assessment"]
 if type(fresh) is not dict or fresh.get("schema")!="sapphon-202-replay-adjudication-v1":
  return hold("NO_FRESH_201_EVIDENCE")
 if head!=prior.SOURCE:return hold("WRONG_CHECKOUT_SOURCE")
 if old.get("state")!="OBSERVED_SOURCE_FAILURE" or fresh.get("state")!="OBSERVED_SOURCE_FAILURE":
  return hold("NO_OBSERVED_SOURCE_FAILURE")
 keys=("run_id","attempt","original_log_sha256","original_artifact_sha256",
       "observed_201_failures","replay_plan")
 if any(old.get(k)!=fresh.get(k) for k in keys):return hold("201_READBACK_EQUIVOCATION")
 if fresh.get("original_bytes_complete") is not True or fresh.get("replay_executed") is not False:
  return hold("201_ORIGINAL_BYTES_INCOMPLETE")
 plans=fresh.get("replay_plan")
 if type(plans) is not list or not plans:return hold("NO_REVIEWED_REPLAY")
 approved=[]
 for p in plans:
  if type(p) is not dict or set(p)!={"id","argv","mode"}:return hold("UNTRUSTED_REPLAY_SHAPE")
  key=p.get("id")
  if key not in REPLAY:return hold("REPLAY_NOT_ISOLATABLE",blocked_id=key)
  if p.get("mode")!="PLAN_ONLY" or p.get("argv")!=list(REPLAY[key]):
   return hold("REPLAY_COMMAND_SUBSTITUTION")
  if key in approved:return hold("DUPLICATE_REPLAY")
  approved.append(key)
 failures={f.get("step") for f in fresh.get("observed_201_failures",[]) if type(f) is dict}
 if not set(approved).issubset(failures):return hold("REPLAY_WITHOUT_OBSERVED_FAILURE")
 return hold("REVIEWED_REPLAY_ELIGIBLE",evidence_consistent=True,
   original_run_id=fresh["run_id"],original_attempt=fresh["attempt"],
   original_log_sha256=fresh["original_log_sha256"],
   original_artifact_sha256=fresh["original_artifact_sha256"],
   replay_ids=approved,prior_202_artifact_sha256=archived["artifact_sha256"])
def docker_command(source_dir,replay_id):
 if replay_id not in REPLAY:raise ValueError("NOT_REVIEWED")
 return ["docker","run","--rm","--network","none","--read-only",
  "--cap-drop","ALL","--security-opt","no-new-privileges",
  "--pids-limit","64","--memory","512m","--cpus","1",
  "--user","65534:65534","--tmpfs","/tmp:rw,noexec,nosuid,size=32m",
  "--mount","type=bind,source="+str(source_dir)+",target=/src,readonly",
  "--workdir","/src",DOCKER_IMAGE,*REPLAY[replay_id]]
def execute(assessment,checkout,launcher=subprocess.run):
 if not assessment.get("evidence_consistent") or assessment.get("state")!="REVIEWED_REPLAY_ELIGIBLE":
  return {**assessment,"state":"REPLAY_REFUSED"}
 base=pathlib.Path(checkout).resolve(strict=True)
 if not base.is_dir():return {**assessment,"state":"SOURCE_CHECKOUT_NOT_DIRECTORY"}
 # Double-check the source revision; GitHub checkout ref is never accepted by assertion alone.
 try:
  cp=launcher(["git","-C",str(base),"rev-parse","HEAD"],stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,timeout=10,check=False)
 except (OSError,subprocess.TimeoutExpired):return {**assessment,"state":"CHECKOUT_REVISION_UNAVAILABLE"}
 if cp.returncode!=0 or cp.stdout.decode("ascii","replace").strip()!=prior.SOURCE:
  return {**assessment,"state":"CHECKOUT_REVISION_MISMATCH"}
 result={**assessment,"state":"ISOLATED_REPLAY_EXECUTED","replay_executed":True}
 outputs=[]
 for key in assessment["replay_ids"]:
  command=docker_command(base,key)
  try:
   cp=launcher(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
               timeout=90,check=False)
   outputs.append({"id":key,"returncode":cp.returncode,
    "stdout_sha256":hashbytes(cp.stdout),"stderr_sha256":hashbytes(cp.stderr),
    "stdout_bytes":len(cp.stdout),"stderr_bytes":len(cp.stderr),
    "diagnostic_failed_again":cp.returncode!=0})
  except (OSError,subprocess.TimeoutExpired) as exc:
   outputs.append({"id":key,"state":"ISOLATED_RUN_UNAVAILABLE",
    "error_type":type(exc).__name__})
 result["replay_results"]=outputs
 result["actual_failure_reproduced"]=bool(outputs) and all(
    x.get("diagnostic_failed_again") is True for x in outputs)
 return result
def acquire_prior(fetch=a.json_api,download=a.api):
 root=f"repos/{a.REPO}/actions"
 runs,state,_=a.listing(f"{root}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return hold("202_RUN_LIST_"+state)
 matches=[r for r in runs if r.get("head_sha")==SOURCE]
 if not matches:return hold("202_EXACT_RUN_NOT_OBSERVED")
 if any(not a.positive(r.get("run_attempt")) for r in matches):return hold("202_MALFORMED_ATTEMPT")
 run=max(matches,key=lambda r:(r["id"],r["run_attempt"]))
 artifacts,state,_=a.listing(f"{root}/runs/{run['id']}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return hold("202_ARTIFACT_LIST_"+state)
 found=[v for v in artifacts if v.get("name")==ARTIFACT]
 if len(found)!=1:return hold("202_ARTIFACT_NOT_UNIQUE")
 art=found[0]
 if art.get("expired") is not False:return hold("202_ARTIFACT_EXPIRED_OR_UNKNOWN")
 assoc=art.get("workflow_run") or {}
 if assoc and (assoc.get("id")!=run["id"] or assoc.get("head_sha")!=SOURCE):
  return hold("202_ARTIFACT_ANCESTRY")
 try:raw=download(f"{root}/artifacts/{art['id']}/zip")
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):
  return hold("202_ARTIFACT_BYTES_UNAVAILABLE")
 return inspect_zip(raw,run)
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--checkout",required=True)
 p.add_argument("--out",default="qualification-artifact/203-replay.json")
 x=p.parse_args()
 try:
  archived=acquire_prior()
  current=prior.acquire()
  qualified=qualify(archived,current,prior.SOURCE)
  result=execute(qualified,x.checkout) if qualified["evidence_consistent"] else qualified
 except (OSError,ValueError,TypeError,KeyError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  result=hold("INPUT_OR_API_UNAVAILABLE",error_type=type(e).__name__)
 target=pathlib.Path(x.out);target.parent.mkdir(parents=True,exist_ok=True)
 target.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["state"],result["replay_executed"],result["actual_failure_reproduced"])
 if not result["actual_failure_reproduced"]:sys.exit(1)
if __name__=="__main__":main()
