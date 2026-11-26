#!/usr/bin/env python3
"""SAPPHON-179: exact evidence-byte failure replay plan; no arbitrary shell execution."""
import argparse,hashlib,json,pathlib,sys
SOURCE="71931a8602229cecad921297aabe633e810fb211"
WORKFLOW="sapphon-178-isolation.yml"
JOB="failure-isolation"
STEPS={
 "PYTHON":("Python regression diagnostics","python3 tools/test_sapphon_178_isolate.py"),
 "RUST":("Rust compilation and inherited regression tests","cargo test --manifest-path rust/sapphon-liveness/Cargo.toml --all-targets -- --test-threads=1"),
 "FROZEN":("Recheck historical frozen source digests","python3 tools/sapphon_179_verify_frozen.py"),
}
MAX_EVIDENCE=1048576
def sha256(b):return hashlib.sha256(b).hexdigest()
def analyze(raw,expected_digest=None):
 if len(raw)>MAX_EVIDENCE:raise ValueError("EVIDENCE_TOO_LARGE")
 observed_digest=sha256(raw)
 if expected_digest is not None and observed_digest!=expected_digest:
  raise ValueError("EVIDENCE_DIGEST_MISMATCH")
 doc=json.loads(raw)
 if not isinstance(doc,dict):raise ValueError("EVIDENCE_NOT_OBJECT")
 blockers=[]
 if doc.get("schema")!="sapphon-171-job-log-triage-v1":blockers.append("BAD_SCHEMA")
 if doc.get("expected_sha")!=SOURCE or doc.get("workflow")!=WORKFLOW:blockers.append("WRONG_ANCESTRY")
 if doc.get("status")!="EXACT_RUN_OBSERVED":blockers.append("RUN_NOT_OBSERVED")
 run=doc.get("observed") or {}
 if not isinstance(run,dict):run={};blockers.append("MALFORMED_RUN")
 if run.get("head_sha")!=SOURCE:blockers.append("SOURCE_MISMATCH")
 if type(run.get("run_id")) is not int or run["run_id"]<=0:blockers.append("INVALID_RUN_ID")
 if type(run.get("attempt")) is not int or run["attempt"]<=0:blockers.append("INVALID_ATTEMPT")
 if run.get("expected_job")!=JOB or run.get("required_job_unique") is not True:blockers.append("EXPECTED_JOB_NOT_UNIQUE")
 if run.get("run_status")!="completed":blockers.append("INCOMPLETE_RUN")
 if doc.get("independent_custody_authenticated") is not False or doc.get("recovery_authorized") is not False:
  blockers.append("UNSUPPORTED_AUTHORITY")
 steps=run.get("required_steps")
 if not isinstance(steps,list) or len(steps)>100:steps=[];blockers.append("MALFORMED_STEP_LIST")
 plan=[]
 for category,(name,command) in STEPS.items():
  matches=[s for s in steps if isinstance(s,dict) and s.get("name")==name]
  if len(matches)!=1:blockers.append(category+"_STEP_NOT_UNIQUE");continue
  conclusion=matches[0].get("conclusion")
  if conclusion in ("failure","timed_out","cancelled"):
   plan.append({"category":category,"step":name,"observed_conclusion":conclusion,"review_only_command":command})
  elif conclusion!="success":blockers.append(category+"_STEP_UNRESOLVED")
 failed=bool(plan)
 if failed and run.get("run_conclusion")=="success":blockers.append("PARENT_CHILD_CONTRADICTION")
 if not failed and run.get("run_conclusion")!="success":blockers.append("FAILED_PARENT_WITHOUT_REPLAYABLE_STEP")
 invalid={"BAD_SCHEMA","WRONG_ANCESTRY","RUN_NOT_OBSERVED","SOURCE_MISMATCH",
  "INVALID_RUN_ID","INVALID_ATTEMPT","EXPECTED_JOB_NOT_UNIQUE",
  "INCOMPLETE_RUN","UNSUPPORTED_AUTHORITY","MALFORMED_RUN","MALFORMED_STEP_LIST"}
 if invalid.intersection(blockers):plan=[]
 return {"schema":"sapphon-179-replay-plan-v1","expected_sha":SOURCE,"workflow":WORKFLOW,
  "run_id":run.get("run_id"),"attempt":run.get("attempt"),
  "evidence_bytes_sha256":observed_digest,
  "replay_eligible":bool(plan) and not blockers,
  "replay_commands_executed":False,"replay_plan":plan,"blockers":sorted(set(blockers)),
  "independent_custody_authenticated":False,"global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,"decision":"PROVENANCE_BOUND_REPLAY_HOLD"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--evidence",required=True)
 p.add_argument("--sha256")
 p.add_argument("--out",default="qualification-artifact/179-replay.json")
 a=p.parse_args()
 result=analyze(pathlib.Path(a.evidence).read_bytes(),a.sha256)
 dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["decision"],result["blockers"],result["replay_plan"])
 if result["blockers"]:sys.exit(1)
if __name__=="__main__":main()
