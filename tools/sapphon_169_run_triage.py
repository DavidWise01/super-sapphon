#!/usr/bin/env python3
"""SAPPHON-169: exact-commit workflow-run and failed-step evidence triage.

This tool only observes GitHub-owned CI. No remote run is invented or treated
as physical custody. A missing run is not a failed run.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

REPO="DavidWise01/super-sapphon"
SHA=re.compile(r"^[a-f0-9]{40}$")
ALLOWED={"success","failure","cancelled","skipped","timed_out","action_required","neutral",None}
def analyze(runs, expected_sha):
    out={"schema":"sapphon-169-run-triage-v1","expected_sha":expected_sha,
         "status":"NO_MATCHING_RUN","runs":[],"failed_jobs":[],"incomplete_runs":[],
         "completed_success_observed":False,"independent_custody_proven":False,
         "global_anti_rollback_proven":False,"recovery_authorized":False,
         "decision":"RUNTIME_EVIDENCE_HOLD"}
    if not SHA.fullmatch(expected_sha):
        raise ValueError("bad pinned SHA")
    matches=[r for r in runs if r.get("head_sha")==expected_sha]
    for r in matches:
        item={"run_id":r.get("id"),"attempt":r.get("run_attempt"),
              "status":r.get("status"),"conclusion":r.get("conclusion"),
              "jobs":[]}
        if not isinstance(item["run_id"],int) or item["run_id"]<1 or not isinstance(item["attempt"],int) or item["attempt"]<1:
            raise ValueError("missing run identity")
        for j in r.get("jobs",[]):
            if j.get("conclusion") not in ALLOWED:
                raise ValueError("unrecognized job conclusion")
            job={"name":j.get("name"),"conclusion":j.get("conclusion"),
                 "status":j.get("status"),"steps":[]}
            for s in j.get("steps",[]):
                if s.get("conclusion") not in ALLOWED:raise ValueError("unrecognized step conclusion")
                step={"name":s.get("name"),"conclusion":s.get("conclusion")}
                job["steps"].append(step)
                if s.get("conclusion") in ("failure","timed_out","cancelled"):
                    out["failed_jobs"].append({"run_id":item["run_id"],
                        "job":job["name"],"step":step})
            if job["conclusion"] in ("failure","timed_out","cancelled") and not any(
                 s["conclusion"] in ("failure","timed_out","cancelled") for s in job["steps"]):
                out["failed_jobs"].append({"run_id":item["run_id"],
                    "job":job["name"],"step":{"name":"JOB_FAILURE_WITHOUT_STEP","conclusion":job["conclusion"]}})
            item["jobs"].append(job)
        if item["status"]!="completed" or item["conclusion"] is None:
            out["incomplete_runs"].append(item["run_id"])
        out["runs"].append(item)
    if not matches:return out
    out["status"]="EXACT_RUN_OBSERVED"
    out["completed_success_observed"]=any(
       r["status"]=="completed" and r["conclusion"]=="success"
       and r["jobs"] and all(j["conclusion"]=="success" for j in r["jobs"])
       for r in out["runs"]
    )
    return out

def gh_api(path):
    proc=subprocess.run(["gh","api",path],text=True,capture_output=True,check=True)
    return json.loads(proc.stdout)

def fetch_runs(repo,workflow,expected_sha):
    results=gh_api(f"repos/{repo}/actions/workflows/{workflow}/runs?per_page=100")
    runs=[]
    for row in results.get("workflow_runs",[]):
        if row.get("head_sha")!=expected_sha:continue
        run={"id":row.get("id"),"run_attempt":row.get("run_attempt",1),
             "head_sha":row.get("head_sha"),"status":row.get("status"),
             "conclusion":row.get("conclusion"),"jobs":[]}
        attempt=run["run_attempt"]
        jobs=gh_api(f"repos/{repo}/actions/runs/{run['id']}/attempts/{attempt}/jobs?per_page=100")
        for j in jobs.get("jobs",[]):
            run["jobs"].append({"name":j.get("name"),"status":j.get("status"),
                "conclusion":j.get("conclusion"),
                "steps":[{"name":s.get("name"),"conclusion":s.get("conclusion")}
                         for s in j.get("steps",[])]})
        runs.append(run)
    return runs

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sha",required=True)
    p.add_argument("--workflow",default="sapphon-168-freeze.yml")
    p.add_argument("--fixture",help="offline JSON input for deterministic diagnostics")
    p.add_argument("--out",default="qualification-artifact/169-run-triage.json")
    a=p.parse_args()
    if a.workflow!="sapphon-168-freeze.yml":p.error("unknown workflow")
    try:
        if a.fixture:
            runs=json.loads(pathlib.Path(a.fixture).read_text())
        else:
            runs=fetch_runs(REPO,a.workflow,a.sha)
        result=analyze(runs,a.sha)
    except Exception as exc:
        result={"schema":"sapphon-169-run-triage-v1","expected_sha":a.sha,
            "status":"READBACK_UNAVAILABLE","error":type(exc).__name__+": "+str(exc)[:500],
            "completed_success_observed":False,"independent_custody_proven":False,
            "global_anti_rollback_proven":False,"recovery_authorized":False,
            "decision":"RUNTIME_EVIDENCE_HOLD"}
    path=pathlib.Path(a.out);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("SAPPHON-169:",result["status"],"successful source-owned run:",result["completed_success_observed"])
    if result["status"]!="EXACT_RUN_OBSERVED":
        raise SystemExit(1)

if __name__=="__main__":main()
