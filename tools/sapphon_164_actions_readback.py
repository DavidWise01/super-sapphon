#!/usr/bin/env python3
"""SAPPHON-164 authenticated GitHub API *transport* readback, not custody proof.

Requires GH_TOKEN, GH_REPO, EXPECTED_COMMIT, WORKFLOW_FILE.
Find the exact workflow run at pinned SHA; never select an unrelated success.
Record all matching runs and their step outcomes, including incomplete status.
"""
import json,os,pathlib,subprocess
def api(path):
    p=subprocess.run(["gh","api",path],capture_output=True,text=True,check=True)
    return json.loads(p.stdout)
def main():
    repo=os.environ["GH_REPO"]
    pinned=os.environ["EXPECTED_COMMIT"]
    workflow=os.environ.get("WORKFLOW_FILE","sapphon-163-parity.yml")
    if repo!="DavidWise01/super-sapphon" or len(pinned)!=40 or any(x not in "0123456789abcdef" for x in pinned):
        raise SystemExit("invalid repository or expected SHA")
    result={"schema":"sapphon-164-workflow-readback-v1",
      "expected_commit":pinned,"workflow":workflow,
      "readback_origin":"github-actions-api",
      "external_custody_authenticated":False,
      "global_anti_rollback_authenticated":False,
      "recovery_authority":"HOLD","matches":[]}
    try:
        runs=api(f"repos/{repo}/actions/workflows/{workflow}/runs?per_page=100")["workflow_runs"]
        matches=[r for r in runs if r.get("head_sha")==pinned]
        for r in matches[:10]:
            item={"run_id":r["id"],"attempt":r.get("run_attempt",1),
                "event":r.get("event"),"status":r.get("status"),
                "conclusion":r.get("conclusion"),"commit_sha":r["head_sha"],"jobs":[]}
            jobs=api(f"repos/{repo}/actions/runs/{r['id']}/attempts/{item['attempt']}/jobs?per_page=100")
            for job in jobs.get("jobs",[]):
                item["jobs"].append({"name":job.get("name"),"id":job.get("id"),
                    "status":job.get("status"),"conclusion":job.get("conclusion"),
                    "steps":[{"name":s.get("name"),"conclusion":s.get("conclusion"),
                              "status":s.get("status")} for s in job.get("steps",[])]})
            result["matches"].append(item)
        result["finding"]="MATCHING_RUNS_OBSERVED" if result["matches"] else "NO_MATCHING_RUN_IN_FIRST_100"
    except Exception as exc:
        result["finding"]="API_READBACK_ERROR"
        result["error"]=type(exc).__name__+": "+str(exc)[:450]
    result["github_run_success_observed"]=any(
        r["status"]=="completed" and r["conclusion"]=="success"
        and r["jobs"] and all(j["conclusion"]=="success" for j in r["jobs"])
        for r in result["matches"]
    )
    result["operational_recovery_authorized"]=False
    out=pathlib.Path("qualification-artifact/164-run-readback.json")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["finding"],"run success observed:",result["github_run_success_observed"])
    # Inability to fetch a matching run is a diagnostic limitation but not
    # a reason to invent a "passed" or "failed" predecessor state.
if __name__=="__main__":main()
