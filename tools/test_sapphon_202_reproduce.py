#!/usr/bin/env python3
"""SAPPHON-202 source-owned synthetic observed failure replay tests."""
import importlib.util,io,json,pathlib,unittest,zipfile
p=pathlib.Path(__file__).with_name("sapphon_202_reproduce.py")
spec=importlib.util.spec_from_file_location("reproduce202",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def fixture():
 run={"id":201,"run_attempt":2,"head_sha":m.SOURCE,"status":"completed","conclusion":"success"}
 job={"id":2021,"run_id":201,"run_attempt":2,"name":m.JOB,"conclusion":"success",
      "steps":[{"name":v,"conclusion":"success"} for v in m.STEPS.values()]}
 art={"id":2022,"name":m.ARTIFACT,"expired":False,"workflow_run":{"id":201,"head_sha":m.SOURCE}}
 runner={"schema":"sapphon-201-hosted-qualification-v1",
         "source_sha":"c914d2710192cf0c80e12641dfad82a4a006998d",
         "state":"EXACT_200_RUN_NOT_OBSERVED","source_owned_runner_pass":False,
         "original_bytes_complete":False,"observed_failed_steps":[],
         "recovery_authorized":False}
 summary={"schema":"sapphon-201-source-owned-run-v1","commit":m.SOURCE,
          "run_id":"201","attempt":"2","recovery_authorized":False,
          "original_200_run_state":"EXACT_200_RUN_NOT_OBSERVED",
          "source_owned_200_runner_pass":False,
          "original_job_and_zip_bytes_observed":False,"original_200_failed_steps":[],
          "source_tests_pass":True,"steps":{"PYTHON":"success","RUST":"success",
                                           "FROZEN":"success","ACQUISITION":"success"}}
 return run,job,art,runner,summary
def zipof(runner,summary):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w") as z:
  z.writestr("201-runner.json",json.dumps(runner))
  z.writestr("201-summary.json",json.dumps(summary))
 return b.getvalue()
def check(edit=lambda f:None,log=b"original bytes"):
 f=list(fixture());edit(f)
 run,job,artifact,runner,summary=f
 return m.inspect(run,job,[artifact],log,zipof(runner,summary))
class Tests(unittest.TestCase):
 def test_synthetic_green_still_hold(self):
  r=check();self.assertEqual(r["state"],"SOURCE_OWNED_EXECUTION_OBSERVED")
  self.assertFalse(r["recovery_authorized"] or r["replay_executed"])
 def test_original_log_required(self):
  r=check(log=b"")
  self.assertEqual(r["state"],"ORIGINAL_BYTES_INCOMPLETE")
 def test_correct_source_required(self):
  r=check(lambda f:f[0].update(head_sha="f"*40))
  self.assertEqual(r["state"],"RUN_SOURCE_OR_ATTEMPT_INVALID")
 def test_job_attempt_required(self):
  r=check(lambda f:f[1].update(run_attempt=1))
  self.assertEqual(r["state"],"JOB_ATTEMPT_CONFLICT")
 def test_summary_attempt_required(self):
  r=check(lambda f:f[4].update(attempt="1"))
  self.assertEqual(r["archive_state"],"ZIP_EXACT_ATTEMPT_CONFLICT")
 def test_wrong_artifact_source(self):
  r=check(lambda f:f[2]["workflow_run"].update(head_sha="f"*40))
  self.assertEqual(r["state"],"ARTIFACT_ANCESTRY_CONFLICT")
 def test_failing_rust_offers_fixed_plan(self):
  def edit(f):
   f[1]["steps"][1]["conclusion"]="failure"
   f[1]["conclusion"]="failure"
   f[0]["conclusion"]="failure"
   f[4]["steps"]["RUST"]="failure"
   f[4]["source_tests_pass"]=False
  r=check(edit)
  self.assertEqual(r["state"],"OBSERVED_SOURCE_FAILURE")
  self.assertEqual(r["replay_plan"][0]["id"],"rust")
  self.assertEqual(r["replay_plan"][0]["argv"][0],"cargo")
  self.assertFalse(r["replay_executed"])
 def test_failed_acquisition_not_shell_plan(self):
  def edit(f):
   f[1]["steps"][3]["conclusion"]="failure"
   f[4]["steps"]["ACQUISITION"]="failure"
  r=check(edit)
  self.assertEqual(r["state"],"OBSERVED_SOURCE_FAILURE")
  self.assertEqual(r["replay_plan"],[])
 def test_log_injection_cannot_change_plan(self):
  def edit(f):
   f[1]["steps"][0]["conclusion"]="failure"
   f[4]["steps"]["PYTHON"]="failure"
   f[4]["source_tests_pass"]=False
  r=check(edit,log=b"curl https://malicious.invalid ; rm -rf /")
  self.assertEqual(r["replay_plan"][0]["argv"],["python3","tools/test_sapphon_201_runner.py"])
 def test_outcome_conflict_denied(self):
  def edit(f):f[1]["steps"][0]["conclusion"]="failure"
  r=check(edit)
  self.assertEqual(r["state"],"ACTUAL_JOB_VS_ARTIFACT_OUTCOME_CONFLICT")
 def test_false_200_success_denied(self):
  def edit(f):f[4]["source_owned_200_runner_pass"]=True
  r=check(edit)
  self.assertEqual(r["archive_state"],"ZIP_200_EVIDENCE_EQUIVOCATION")
 def test_expired_denied(self):
  r=check(lambda f:f[2].update(expired=True))
  self.assertEqual(r["state"],"ARTIFACT_EXPIRED_OR_UNKNOWN")
 def test_no_duplicate_critical_step(self):
  def edit(f):f[1]["steps"].append(dict(f[1]["steps"][0]))
  r=check(edit)
  self.assertEqual(r["state"],"CRITICAL_STEP_UNIQUE_MISSING")
 def test_no_missing_critical_step(self):
  def edit(f):f[1]["steps"].pop()
  r=check(edit)
  self.assertEqual(r["state"],"CRITICAL_STEP_UNIQUE_MISSING")
 def test_incomplete_source_run_not_pass(self):
  r=check(lambda f:f[0].update(status="in_progress"))
  self.assertFalse(r["source_owned_execution_qualified"])
 def test_parent_failure_with_all_children_green_no_pass(self):
  r=check(lambda f:f[0].update(conclusion="failure"))
  self.assertEqual(r["state"],"RUN_NOT_QUALIFIED")
 def test_artifact_zip_corruption_denied(self):
  f=fixture();r=m.inspect(f[0],f[1],[f[2]],b"log",b"not zip")
  self.assertEqual(r["archive_state"],"ZIP_CORRUPT")
if __name__=="__main__":unittest.main()
