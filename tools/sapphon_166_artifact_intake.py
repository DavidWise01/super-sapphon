#!/usr/bin/env python3
"""Locate exactly the SAPPHON-165 workflow run for a pinned source commit.
GitHub API results are source-owned observations, not independent evidence.
Uses gh CLI with GH_TOKEN; downloads by run ID and artifact name ONLY.
"""
import json
import os
import pathlib
import subprocess
import sys

REPO="DavidWise01/super-sapphon"
EXPECTED="f697afc224d9ca7404aad8c33e827abad6f2342b"
WORKFLOW="sapphon-165-recover.yml"
ARTIFACT="sapphon-165-registry-lock-candidate"

def call(args):
    return subprocess.run(args,capture_output=True,text=True,check=True).stdout

def main():
    dest=pathlib.Path("qualification-artifact/165-intake")
    dest.mkdir(parents=True,exist_ok=True)
    report={"schema":"sapphon-166-exact-artifact-intake-v1",
       "expected_commit":EXPECTED,"workflow":WORKFLOW,
       "origin":"github-actions-owned","status":"NOT_OBSERVED",
       "independent_custody_authenticated":False,
       "recovery_authorized":False,"decision":"INTAKE_HOLD"}
    try:
        runs=json.loads(call(["gh","api",f"repos/{REPO}/actions/workflows/{WORKFLOW}/runs?per_page=100"]))
        exact=[r for r in runs.get("workflow_runs",[]) if r.get("head_sha")==EXPECTED
               and r.get("status")=="completed"]
        exact.sort(key=lambda r:(r.get("run_attempt",0),r.get("id",0)),reverse=True)
        if not exact:raise ValueError("NO_COMPLETED_RUN_FOR_EXACT_COMMIT_IN_FIRST_PAGE")
        for run in exact:
            rid=run["id"];attempt=run.get("run_attempt",1)
            artifacts=json.loads(call(["gh","api",f"repos/{REPO}/actions/runs/{rid}/artifacts?per_page=100"]))
            eligible=[a for a in artifacts.get("artifacts",[]) if a.get("name")==ARTIFACT and not a.get("expired")]
            if not eligible:continue
            selected=eligible[0]
            report.update(status="EXACT_RUN_ARTIFACT_OBSERVED",run_id=rid,
                attempt=attempt,run_conclusion=run.get("conclusion"),
                artifact_id=selected["id"],artifact_size=selected.get("size_in_bytes"))
            # Download into isolated directory with repository + pinned run ID.
            call(["gh","run","download",str(rid),"--repo",REPO,
                  "--name",ARTIFACT,"--dir",str(dest)])
            break
        if report["status"]!="EXACT_RUN_ARTIFACT_OBSERVED":
            raise ValueError("NO_UNEXPIRED_ARTIFACT_FOR_MATCHING_RUN")
        needed=("165-registry-candidate-package-lock.json",
                "165-registry-candidate-inspection.json",
                "165-run-summary.json")
        missing=[n for n in needed if not (dest/n).is_file()]
        if missing:raise ValueError("CANDIDATE_ARTIFACT_MISSING:"+",".join(missing))
        report["candidate_files_present"]=list(needed)
    except Exception as exc:
        report["status"]="READBACK_BLOCKED"
        report["error"]=type(exc).__name__+": "+str(exc)[:500]
    out=pathlib.Path("qualification-artifact/166-artifact-intake.json")
    out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("SAPPHON-166:",report["status"],report.get("error",""))
    if report["status"]!="EXACT_RUN_ARTIFACT_OBSERVED":sys.exit(1)
    print("source-owned artifact observed; outside custody still HOLD")
if __name__=="__main__":main()
