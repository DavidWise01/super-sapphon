#!/usr/bin/env python3
"""SAPPHON-195: reconcile owned 194 log and ZIP digests; dry-run replay only.

Requires original-byte acquisition attestation from the 194 diagnostic.
The attestation is GitHub-owned metadata, not a fresh re-download or an
independent witness. Never execute commands derived from remote logs.
"""
import argparse,hashlib,json,pathlib,re,sys
SOURCE="c2f237a5065c29a13947657c707d101ff2dca31e"
PRIOR_SOURCE="517959b0c98b65bafefaba5ae5e18065b2e27212"
PRIOR_WORKFLOW="sapphon-193-triage.yml"
HEX64=re.compile(r"^[a-f0-9]{64}$")
MAX_FAILED_STEPS=64
# Explicit reviewed commands; command data is never used as a shell string.
ALLOWLIST={
 "PYTHON_TRIAGE":("python3","tools/test_sapphon_193_triage.py"),
 "PYTHON_ACQUIRE":("python3","tools/test_sapphon_194_acquire.py"),
 "RUST_TESTS":("cargo","test","--manifest-path","rust/sapphon-liveness/Cargo.toml","--all-targets"),
 "FROZEN_HISTORY":("python3","tools/sapphon_179_verify_frozen.py")
}
def h(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def positive(x):return type(x) is int and x>0
def valid_hash(s):return type(s) is str and HEX64.fullmatch(s) is not None
def reconcile(acquisition,summary):
 issues=[];failures=[];recommendations=[]
 if type(acquisition) is not dict or acquisition.get("schema")!="sapphon-194-hosted-acquisition-v1":
  issues.append("ACQUISITION_SCHEMA");acquisition={}
 if type(summary) is not dict or summary.get("schema")!="sapphon-194-owned-run-results-v1":
  issues.append("SUMMARY_SCHEMA");summary={}
 if acquisition.get("source_sha")!=PRIOR_SOURCE or acquisition.get("workflow")!=PRIOR_WORKFLOW:
  issues.append("ORIGINAL_SOURCE_ANCESTRY")
 for key in ("run_id","attempt"):
  if not positive(acquisition.get(key)):issues.append("ORIGINAL_"+key.upper()+"_MISSING")
 if any(acquisition.get(k)!="EXHAUSTED" for k in ("run_search_state","job_search_state","artifact_search_state")):
  issues.append("INCOMPLETE_PAGINATION")
 if acquisition.get("source_owned_original_bytes_complete") is not True:
  issues.append("ORIGINAL_BYTES_NOT_COMPLETE")
 log=acquisition.get("job_log")
 arc=acquisition.get("artifact_zip")
 if type(log) is not dict or log.get("state")!="ORIGINAL_LOG_OBSERVED" or not valid_hash(log.get("sha256")) or not positive(log.get("job_id")) or not positive(log.get("bytes")):
  issues.append("ORIGINAL_LOG_PROVENANCE")
 if type(arc) is not dict or arc.get("state")!="ORIGINAL_ZIP_OBSERVED" or not valid_hash(arc.get("sha256")) or not positive(arc.get("artifact_id")) or not positive(arc.get("bytes")):
  issues.append("ORIGINAL_ZIP_PROVENANCE")
 if acquisition.get("blockers"):
  issues.append("INHERITED_ACQUISITION_BLOCKERS")
 if type(summary.get("steps")) is not dict or summary.get("recovery_authorized") is not False:
  issues.append("SUMMARY_AUTHORITY_OR_STEPS")
 if summary.get("predecessor_original_bytes_complete") is not True:
  issues.append("SUMMARY_DISAGREES_ABOUT_COMPLETENESS")
 reported=acquisition.get("actual_failed_steps")
 if type(reported) is not list or len(reported)>MAX_FAILED_STEPS:
  issues.append("FAILED_STEP_LIST_INVALID");reported=[]
 summary_failures=summary.get("actual_failed_steps")
 if summary_failures!=reported:issues.append("FAILED_STEP_EQUIVOCATION")
 for entry in reported:
  if type(entry) is not dict or set(entry)!={"name","conclusion"} or entry.get("conclusion") not in ("failure","cancelled","timed_out"):
   issues.append("FAILED_STEP_INVALID");continue
  failures.append({"name":entry["name"],"conclusion":entry["conclusion"]})
 # Fixed diagnostic choice based on exact known step names, never untrusted command strings.
 steps_to_commands={
  "Execute Python exact-run diagnostics and inherited regressions":"PYTHON_TRIAGE",
  "Compile and test Rust runner failure diagnostic":"RUST_TESTS",
  "Verify protected 188 historical immutable files":"FROZEN_HISTORY"}
 for item in failures:
  choice=steps_to_commands.get(item["name"])
  if choice and choice not in recommendations:recommendations.append(choice)
 # No replay without a demonstrated failure and intact source-owned evidence metadata.
 eligible=not issues and bool(failures) and bool(recommendations)
 return {"schema":"sapphon-195-crossverify-v1","source_sha":SOURCE,
  "prior_source_sha":PRIOR_SOURCE,"original_run_id":acquisition.get("run_id"),
  "original_attempt":acquisition.get("attempt"),
  "original_log_sha256":log.get("sha256") if type(log) is dict else None,
  "original_zip_sha256":arc.get("sha256") if type(arc) is dict else None,
  "acquisition_report_sha256":h(acquisition),
  "summary_report_sha256":h(summary),
  "issues":sorted(set(issues)),"observed_failure_steps":failures,
  "replay_allowlist":[{"id":key,"argv":list(ALLOWLIST[key]),"mode":"PLAN_ONLY"}
                     for key in recommendations] if eligible else [],
  "replay_eligible_for_review":eligible,"replay_executed":False,
  "original_log_bytes_reread_in_195":False,
  "original_zip_bytes_reread_in_195":False,
  "independent_witnesses":0,"external_custody_authenticated":False,
  "authenticated_utc":False,"global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"LOG_ARTIFACT_CROSS_VERIFICATION_HOLD"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--acquisition",required=True)
 p.add_argument("--summary",required=True)
 p.add_argument("--out",default="qualification-artifact/195-crossverify.json")
 a=p.parse_args()
 try:
  result=reconcile(json.loads(pathlib.Path(a.acquisition).read_text()),
                   json.loads(pathlib.Path(a.summary).read_text()))
 except (OSError,ValueError,TypeError):
  result={"schema":"sapphon-195-crossverify-v1","issues":["REQUIRED_EVIDENCE_NOT_READABLE"],
    "replay_eligible_for_review":False,"replay_executed":False,
    "independent_witnesses":0,"recovery_authorized":False,"lock_cleared":False,
    "decision":"LOG_ARTIFACT_CROSS_VERIFICATION_HOLD"}
 out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
 out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["decision"],result["issues"])
 if result["issues"]:sys.exit(1)
if __name__=="__main__":main()
