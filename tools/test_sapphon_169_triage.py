#!/usr/bin/env python3
"""SAPPHON-169 synthetic workflow-readback regression controls."""
import importlib.util,pathlib,unittest,copy
p=pathlib.Path(__file__).with_name("sapphon_169_run_triage.py")
s=importlib.util.spec_from_file_location("sapphon169",p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
SHA="a"*40
def run(status="completed",conclusion="success",job="success",step="success"):
 return [{"id":169,"run_attempt":1,"head_sha":SHA,
   "status":status,"conclusion":conclusion,
   "jobs":[{"name":"final-freeze","status":status,"conclusion":job,
      "steps":[{"name":"Rust typecheck","conclusion":step}]}]}]
class Tests(unittest.TestCase):
 def test_completed_pass_is_owned_only(self):
  x=m.analyze(run(),SHA)
  self.assertTrue(x["completed_success_observed"])
  self.assertFalse(x["recovery_authorized"])
  self.assertFalse(x["independent_custody_proven"])
 def test_unrelated_green_run_not_accepted(self):
  r=run();r[0]["head_sha"]="b"*40
  self.assertEqual(m.analyze(r,SHA)["status"],"NO_MATCHING_RUN")
 def test_failed_step_remains_visible(self):
  r=run(conclusion="failure",job="failure",step="failure")
  x=m.analyze(r,SHA)
  self.assertFalse(x["completed_success_observed"])
  self.assertEqual(x["failed_jobs"][0]["step"]["name"],"Rust typecheck")
 def test_failed_job_without_step(self):
  x=m.analyze(run(conclusion="failure",job="failure"),SHA)
  self.assertEqual(x["failed_jobs"][0]["step"]["name"],"JOB_FAILURE_WITHOUT_STEP")
 def test_in_progress_not_success(self):
  x=m.analyze(run(status="in_progress",conclusion=None,job=None,step=None),SHA)
  self.assertFalse(x["completed_success_observed"])
  self.assertEqual(x["incomplete_runs"],[169])
 def test_empty_jobs_cannot_pass(self):
  r=run();r[0]["jobs"]=[]
  self.assertFalse(m.analyze(r,SHA)["completed_success_observed"])
 def test_missing_run_is_not_a_failed_run(self):
  x=m.analyze([],SHA)
  self.assertEqual(x["failed_jobs"],[])
  self.assertEqual(x["status"],"NO_MATCHING_RUN")
 def test_invalid_sha_rejected(self):
  with self.assertRaises(ValueError):m.analyze(run(),"oops")
 def test_invalid_conclusion_rejected(self):
  with self.assertRaises(ValueError):m.analyze(run(job="miracle"),SHA)
 def test_exact_attempt_preserved(self):
  r=run();r[0]["run_attempt"]=3
  self.assertEqual(m.analyze(r,SHA)["runs"][0]["attempt"],3)
 def test_cancelled_step_retained(self):
  x=m.analyze(run(conclusion="cancelled",job="cancelled",step="cancelled"),SHA)
  self.assertEqual(x["failed_jobs"][0]["step"]["conclusion"],"cancelled")
if __name__=="__main__":unittest.main()
