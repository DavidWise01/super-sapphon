#!/usr/bin/env python3
"""SAPPHON-183: completed-run contradiction adjudication, source-owned HOLD.

Compares actual SAPPHON-182 runner results, acquisition and cross-file
findings. Missing evidence stays NOT_OBSERVED. Never infers external custody.
"""
import argparse,hashlib,json,pathlib,sys
SOURCE="bcc82842d0ebc090db6fb3b32c978a75db3cf9fd"
WORKFLOW="sapphon-182-crossfile.yml"
JOB="crossfile-adjudication"
ACQUIRED_SOURCE="dd1d778c522aa18fb399c052958f05c4f5b02dd9"
CHECKS=("PYTHON","RUST","FROZEN","ACQUISITION","CROSSFILE")
SOURCE_CHECKS=("PYTHON","RUST","FROZEN")
RUN_STEPS=("Execute Python archive consistency regression suites",
           "Compile and test Rust provenance modules",
           "Verify the inherited 188 immutable source records")
def sha(obj):
 return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def identity(value):
 return type(value) is int and value>0
def adjudicate(runner,acquisition,crossfile,job_record):
 issues=[];warnings=[]
 if type(runner) is not dict or type(acquisition) is not dict or type(crossfile) is not dict or type(job_record) is not dict:
  raise ValueError("RECORD_NOT_OBJECT")
 if runner.get("schema")!="sapphon-182-owned-outcomes-v1" or runner.get("commit")!=SOURCE:
  issues.append("RUNNER_ANCESTRY_INVALID")
 if not identity(runner.get("run_id")) and not (isinstance(runner.get("run_id"),str) and runner["run_id"].isdigit() and int(runner["run_id"])>0):
  issues.append("RUNNER_ID_INVALID")
 if not identity(runner.get("attempt")) and not (isinstance(runner.get("attempt"),str) and runner["attempt"].isdigit() and int(runner["attempt"])>0):
  issues.append("RUNNER_ATTEMPT_INVALID")
 outcomes=runner.get("outcomes")
 if type(outcomes) is not dict:outcomes={};issues.append("RUNNER_OUTCOMES_INVALID")
 for key in CHECKS:
  if outcomes.get(key) not in ("success","failure","skipped","cancelled","timed_out","not_observed"):
   issues.append("UNRECOGNIZED_STEP_OUTCOME:"+key)
 local_pass=all(outcomes.get(k)=="success" for k in SOURCE_CHECKS)
 if runner.get("source_tests_pass") is not local_pass:
  issues.append("RUNNER_FALSE_SOURCE_TEST_CLAIM")
 if runner.get("full_qualification") is not False or runner.get("recovery_authorized") is not False or runner.get("lock_cleared") is not False:
  issues.append("RUNNER_AUTHORITY_CLAIM")
 if acquisition.get("schema")!="sapphon-181-acquisition-v1" or acquisition.get("source_sha")!=ACQUIRED_SOURCE:
  issues.append("ACQUISITION_ANCESTRY_INVALID")
 observed=acquisition.get("source_owned_bytes_observed") is True
 if observed:
  if acquisition.get("status")!="ORIGINAL_BYTES_OBSERVED":
   issues.append("ACQUISITION_STATUS_CONFLICT")
  for key in ("run_id","attempt","job_id","artifact_id"):
   if not identity(acquisition.get(key)):issues.append("ACQUISITION_ID_INVALID:"+key)
  if outcomes.get("ACQUISITION")!="success":issues.append("ACQUISITION_FALSE_FAILURE")
 elif acquisition.get("status")=="ORIGINAL_BYTES_OBSERVED" or outcomes.get("ACQUISITION")=="success":
  issues.append("ACQUISITION_FALSE_SUCCESS")
 if acquisition.get("recovery_authorized") is not False:issues.append("ACQUISITION_AUTHORITY")
 if crossfile.get("schema")=="sapphon-182-cross-file-v1":
  structural=crossfile.get("archive_records_structurally_consistent") is True
  complete=crossfile.get("complete_predecessor_and_raw_byte_evidence") is True
  if crossfile.get("source_sha")!=ACQUIRED_SOURCE:issues.append("CROSSFILE_ANCESTRY_INVALID")
  if crossfile.get("findings"):issues.append("CROSSFILE_FINDINGS_PRESENT")
  if complete and not structural:issues.append("COMPLETE_WITHOUT_CONSISTENCY")
  if not observed:issues.append("ARCHIVE_REPORTED_WITHOUT_ORIGINAL_BYTES")
  if outcomes.get("CROSSFILE")=="success" and not structural:
   issues.append("CROSSFILE_FALSE_SUCCESS")
  if outcomes.get("CROSSFILE")!="success" and structural:
   issues.append("CROSSFILE_FALSE_FAILURE")
 elif crossfile.get("schema")=="sapphon-182-evidence-unavailable-v1":
  structural=False;complete=False
  if crossfile.get("status")!="ORIGINAL_ARCHIVE_NOT_OBSERVED":
   issues.append("CROSSFILE_UNAVAILABILITY_INVALID")
  if outcomes.get("CROSSFILE")=="success":
   # Workflow emits a successful step when writing an unavailable placeholder.
   warnings.append("STEP_EXECUTED_BUT_ARCHIVE_NOT_OBSERVED")
  if observed:issues.append("ACQUIRED_BYTES_BUT_ARCHIVE_MARKED_MISSING")
 else:
  structural=False;complete=False;issues.append("CROSSFILE_SCHEMA_INVALID")
 if crossfile.get("recovery_authorized") is not False or crossfile.get("lock_cleared") is not False:
  issues.append("CROSSFILE_AUTHORITY")
 if job_record.get("schema")!="sapphon-171-job-log-triage-v1" or job_record.get("expected_sha")!=SOURCE or job_record.get("workflow")!=WORKFLOW:
  issues.append("JOB_READBACK_ANCESTRY")
 status=job_record.get("status")
 jobs=job_record.get("observed") or {}
 exact=status=="EXACT_RUN_OBSERVED" and type(jobs) is dict and jobs.get("head_sha")==SOURCE
 if exact:
  if jobs.get("expected_job")!=JOB or jobs.get("required_job_unique") is not True:
   issues.append("JOB_IDENTITY_NOT_UNIQUE")
  if str(jobs.get("run_id"))!=str(runner.get("run_id")) or str(jobs.get("attempt"))!=str(runner.get("attempt")):
   issues.append("JOB_RUN_ATTEMPT_CONFLICT")
  if jobs.get("run_status")!="completed":issues.append("JOB_NOT_COMPLETED")
  step_records=jobs.get("required_steps") or []
  for key,name in zip(SOURCE_CHECKS,RUN_STEPS):
   found=[v for v in step_records if type(v) is dict and v.get("name")==name]
   if len(found)!=1:issues.append("JOB_REQUIRED_STEP_NOT_UNIQUE:"+key)
   else:
    c=found[0].get("conclusion")
    if outcomes.get(key)=="success" and c!="success":issues.append("JOB_PARENT_CHILD_CONFLICT:"+key)
    if outcomes.get(key)!="success" and c=="success":issues.append("JOB_SOURCE_OUTCOME_CONFLICT:"+key)
  if jobs.get("run_conclusion")=="success" and any(outcomes.get(k)!="success" for k in SOURCE_CHECKS):
   issues.append("GREEN_RUN_WITH_FAILED_SOURCE_TESTS")
 else:warnings.append("EXACT_JOB_READBACK_UNAVAILABLE")
 if job_record.get("recovery_authorized") is not False or job_record.get("independent_custody_authenticated") is not False:
  issues.append("JOB_READBACK_AUTHORITY")
 return {"schema":"sapphon-183-contradiction-v1","source_sha":SOURCE,
  "runner_sha256":sha(runner),"acquisition_sha256":sha(acquisition),
  "crossfile_sha256":sha(crossfile),"job_record_sha256":sha(job_record),
  "source_owned_test_outcomes_consistent":local_pass and not any(x.startswith(("RUNNER_","JOB_SOURCE_OUTCOME","JOB_PARENT_CHILD","GREEN_RUN")) for x in issues),
  "original_archive_observed":observed,
  "archive_structurally_consistent":structural,
  "complete_owned_evidence":complete and observed and exact and not issues,
  "exact_job_observed":exact,"findings":sorted(set(issues)),"limitations":sorted(set(warnings)),
  "external_custody_authenticated":False,"global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"COMPLETED_RUN_CONTRADICTION_HOLD"}
def main():
 p=argparse.ArgumentParser()
 for flag in ("runner","acquisition","crossfile","job"):p.add_argument("--"+flag,required=True)
 p.add_argument("--out",default="qualification-artifact/183-adjudication.json")
 a=p.parse_args()
 objects=[json.loads(pathlib.Path(getattr(a,key)).read_text()) for key in ("runner","acquisition","crossfile","job")]
 result=adjudicate(*objects)
 path=pathlib.Path(a.out);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(result["decision"],result["findings"],result["limitations"])
 if result["findings"]:sys.exit(1)
if __name__=="__main__":main()
