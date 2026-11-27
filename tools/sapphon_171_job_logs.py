#!/usr/bin/env python3
"""SAPPHON-171: exact-SHA job-log diagnostics, no inferred execution.

Captures bounded, redacted excerpts ONLY from failed GitHub Actions jobs.
All GitHub surfaces share the same owned ancestry. No operational authority.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

REPO="DavidWise01/super-sapphon"
EXPECTED="94188aa212cb2ae5d80ddc4c93ba0d71c6b81f2b"
WORKFLOW="sapphon-170-isolation.yml"
REQUIRED="deterministic-diagnostics"
MAX_CHARS=12000
SECRET=re.compile(r"(?i)(token|authorization|password|secret|api[_-]?key)(\s*[=:]\s*)(\S+)")
HEX40=re.compile(r"^[a-f0-9]{40}$")
def redacted(text):
    return SECRET.sub(lambda m:m.group(1)+m.group(2)+"[REDACTED]",text)[:MAX_CHARS]

def choose(rows,sha):
    if not HEX40.fullmatch(sha):raise ValueError("invalid pinned commit")
    selected=[r for r in rows if r.get("head_sha")==sha and isinstance(r.get("id"),int)
              and isinstance(r.get("run_attempt"),int) and not isinstance(r.get("run_attempt"),bool)
              and not isinstance(r.get("id"),bool)
              and r["run_attempt"]>0 and r["id"]>0]
    selected.sort(key=lambda r:(r["id"],r["run_attempt"]),reverse=True)
    return selected[0] if selected else None

def classify(run,jobs,required=REQUIRED):
    out={"status":"EXACT_RUN_OBSERVED","run_id":run["id"],
         "attempt":run["run_attempt"],"head_sha":run["head_sha"],
         "run_status":run.get("status"),"run_conclusion":run.get("conclusion"),
         "expected_job":required,"failures":[]}
    any_failed_step=False
    for j in jobs:
        steps=[{"name":s.get("name"),"conclusion":s.get("conclusion")}
               for s in j.get("steps",[])]
        failed_steps=[s for s in steps if s["conclusion"] in ("failure","cancelled","timed_out")]
        any_failed_step=any_failed_step or bool(failed_steps)
        if j.get("conclusion") in ("failure","cancelled","timed_out") or failed_steps:
            out["failures"].append({"job_id":j.get("id"),"name":j.get("name"),
                 "conclusion":j.get("conclusion"),"failed_steps":failed_steps})
    names=[j.get("name") for j in jobs]
    out["required_job_present"]=required in names
    required_jobs=[j for j in jobs if j.get("name")==required]
    out["required_steps"]=[{"name":step.get("name"),"conclusion":step.get("conclusion")} for j in required_jobs for step in j.get("steps",[])]
    out["required_steps_observed"]=bool(out["required_steps"])
    out["unresolved_required_steps"]=[step for step in out["required_steps"] if step["conclusion"]!="success"]
    out["required_job_unique"]=len(required_jobs)==1
    out["source_owned_success_observed"]=(run.get("status")=="completed"
        and run.get("conclusion")=="success"
        and out["required_job_present"] and out["required_job_unique"]
        and out["required_steps_observed"] and not out["unresolved_required_steps"]
        and bool(jobs) and not any_failed_step
        and all(j.get("conclusion")=="success" for j in jobs))
    out["status"]="LATEST_INCOMPLETE" if run.get("status")!="completed" else out["status"]
    if not out["required_job_present"]:out["status"]="REQUIRED_JOB_MISSING"
    return out

def gh(args):
    return subprocess.run(["gh",*args],check=True,capture_output=True,text=True).stdout

def api(path):
    return json.loads(gh(["api",path]))

def paged_runs(workflow,sha,max_pages=10,api_call=None):
    """Scan up to 1000 recent runs. Report an incomplete search separately."""
    fetch=api_call or api
    for page in range(1,max_pages+1):
        rows=fetch(f"repos/{REPO}/actions/workflows/{workflow}/runs?per_page=100&page={page}").get("workflow_runs",[])
        matches=[x for x in rows if x.get("head_sha")==sha]
        if matches:
            selected=choose(matches,sha)
            if selected is None:
                return None,"MALFORMED_MATCHING_RUN",page
            return selected,"EXACT_RUN_OBSERVED",page
        if len(rows)<100:
            return None,"NO_MATCHING_RUN_IN_EXHAUSTED_PAGES",page
    return None,"RUN_SEARCH_INCOMPLETE_PAGE_CAP",max_pages

def paged_jobs(run_id,attempt,max_pages=10,api_call=None):
    """Collect all jobs, or fail closed if pagination cannot finish."""
    if type(run_id) is not int or type(attempt) is not int or run_id<=0 or attempt<=0:
        return [],"INVALID_RUN_IDENTITY",0
    fetch=api_call or api
    collected=[]
    for page in range(1,max_pages+1):
        payload=fetch(f"repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}")
        rows=payload.get("jobs")
        if not isinstance(rows,list):
            return [],"MALFORMED_JOB_PAGE",page
        collected.extend(rows)
        if len(rows)<100:
            return collected,"JOB_PAGES_EXHAUSTED",page
    return [],"JOB_PAGE_CAP_REACHED",max_pages

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--out",default="qualification-artifact/171-job-log-triage.json")
    p.add_argument("--fixture",help="synthetic input object {runs:[],jobs:[]}")
    p.add_argument("--sha",default=EXPECTED)
    p.add_argument("--workflow",default=WORKFLOW)
    p.add_argument("--required-job",default=REQUIRED)
    a=p.parse_args()
    valid_targets={
      "sapphon-170-isolation.yml":("94188aa212cb2ae5d80ddc4c93ba0d71c6b81f2b","deterministic-diagnostics"),
      "sapphon-171-joblogs.yml":("9e7fc8ad8c3b05a3e12f1c3aa0c15b4c99c2e18e","diagnostics"),
      "sapphon-172-reconcile.yml":("496dec7bf5410baf031b0b7168ed2ac26311a181","diagnostic-reconciliation"),
      "sapphon-173-steps.yml":("7e1be863797ddad3043e03074fc2375b9f760c74","critical-step-diagnostics"),
      "sapphon-174-outcomes.yml":("185802d4f10b496b899ab09551fe193b9ddd4a0d","source-outcomes"),
      "sapphon-175-readback.yml":("134dd02d0d6728abc27264548fed4c91a223e9e4","source-diagnostics"),
      "sapphon-176-freeze.yml":("f17b3d6c437da7f82240fffae703dfbde61a215b","final-evidence"),
      "sapphon-177-evidence.yml":("3053c21609333ea93d74ff2d38aeeed1c27d6084","executable-diagnostics"),
      "sapphon-178-isolation.yml":("71931a8602229cecad921297aabe633e810fb211","failure-isolation"),
      "sapphon-179-replay.yml":("d07203a254678fdf7df05a75c1d144c7a8337f87","replay-diagnostics"),
      "sapphon-182-crossfile.yml":("bcc82842d0ebc090db6fb3b32c978a75db3cf9fd","crossfile-adjudication"),
      "sapphon-183-contradictions.yml":("9745ac2fb25233db2cdd150421b8b5f95ac3e9d7","contradiction-adjudication"),
      "sapphon-184-freeze.yml":("edb582df9db3873d2fe308d219ed30b412d1b06d","final-freeze"),
    }
    if (a.workflow not in valid_targets or
        (a.sha,a.required_job)!=valid_targets[a.workflow]):
        p.error("workflow, commit and required job must match the pinned allowlist")
    out={"schema":"sapphon-171-job-log-triage-v1","repository":REPO,
         "expected_sha":a.sha,"workflow":a.workflow,
         "status":"READBACK_UNAVAILABLE","observed":None,
         "log_excerpts":[],"independent_custody_authenticated":False,
         "global_anti_rollback_authenticated":False,
         "recovery_authorized":False,"lock_cleared":False,
         "decision":"JOB_LOG_OBSERVATION_HOLD"}
    try:
        if a.fixture:
            fixture=json.loads(pathlib.Path(a.fixture).read_text())
            rows=fixture["runs"]
        else:
            target,search_status,pages=paged_runs(a.workflow,a.sha)
            out["pages_scanned"]=pages
        if a.fixture:
            target=choose(rows,a.sha)
            search_status="NO_MATCHING_RUN_IN_FIXTURE" if target is None else "EXACT_RUN_OBSERVED"
        if target is None:
            out["status"]=search_status
        else:
            if a.fixture:jobs=fixture["jobs"]
            else:
                jobs,job_search_state,job_pages=paged_jobs(target["id"],target["run_attempt"])
                out["job_pages_scanned"]=job_pages
                out["job_search_state"]=job_search_state
                if job_search_state!="JOB_PAGES_EXHAUSTED":
                    out["status"]=job_search_state
                    jobs=[]
            out["observed"]=classify(target,jobs,a.required_job)
            out["status"]=out["observed"]["status"]
            if not a.fixture and out.get("job_search_state")!="JOB_PAGES_EXHAUSTED":
                out["observed"]["source_owned_success_observed"]=False
                out["status"]=out["job_search_state"]
            if not a.fixture:
                for failure in out["observed"]["failures"][:6]:
                    jid=failure["job_id"]
                    if not isinstance(jid,int):continue
                    try:
                        raw=gh(["api",f"repos/{REPO}/actions/jobs/{jid}/logs"])
                        excerpt=redacted(raw)
                        out["log_excerpts"].append({"job_id":jid,
                          "excerpt":excerpt,
                          "sha256_of_bounded_redacted_excerpt":hashlib.sha256(excerpt.encode()).hexdigest(),
                          "truncated":len(raw)>MAX_CHARS})
                    except Exception as exc:
                        out["log_excerpts"].append({"job_id":jid,
                             "readback_error":type(exc).__name__+": "+str(exc)[:200]})
    except Exception as exc:
        out["status"]="READBACK_UNAVAILABLE"
        out["error"]=type(exc).__name__+": "+str(exc)[:400]
    dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print("SAPPHON-171",out["status"],"observed failed jobs:",
           len((out.get("observed") or {}).get("failures",[])))
    if out["status"] in ("READBACK_UNAVAILABLE","NO_MATCHING_RUN_IN_EXHAUSTED_PAGES","RUN_SEARCH_INCOMPLETE_PAGE_CAP","MALFORMED_MATCHING_RUN","JOB_PAGE_CAP_REACHED","MALFORMED_JOB_PAGE","INVALID_RUN_IDENTITY","NO_MATCHING_RUN_IN_FIXTURE","REQUIRED_JOB_MISSING"):
        raise SystemExit(1)

if __name__=="__main__":main()
