#!/usr/bin/env python3
"""SAPPHON-193 synthetic exact-run failure-isolation regressions."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_193_triage.py")
spec=importlib.util.spec_from_file_location("triage193",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def fixture():
 return {"schema":"sapphon-171-job-log-triage-v1","repository":"DavidWise01/super-sapphon",
  "expected_sha":m.SOURCE,"workflow":m.WORKFLOW,"status":"EXACT_RUN_OBSERVED",
  "job_search_state":"JOB_PAGES_EXHAUSTED",
  "independent_custody_authenticated":False,"recovery_authorized":False,
  "observed":{"run_id":192,"attempt":1,"head_sha":m.SOURCE,"expected_job":m.JOB,
    "required_job_unique":True,"run_status":"completed","run_conclusion":"success",
    "source_owned_success_observed":True,"failures":[],
    "required_steps":[{"name":n,"conclusion":"success"} for n in m.CRITICAL.values()]}}
class Tests(unittest.TestCase):
 def case(self,fn=lambda d:None):
  d=fixture();fn(d);return m.diagnose(d)
 def test_owned_green_remains_hold(self):
  r=self.case();self.assertTrue(r["source_owned_critical_steps_pass"])
  self.assertFalse(r["recovery_authorized"])
 def test_missing_exact_run_denied(self):
  r=self.case(lambda d:d.update(status="NO_MATCHING_RUN_IN_EXHAUSTED_PAGES",observed=None))
  self.assertIn("EXACT_RUN_UNOBSERVED",r["unobserved"])
 def test_wrong_pinned_sha_denied(self):
  r=self.case(lambda d:d.update(expected_sha="a"*40))
  self.assertIn("PINNED_SOURCE_ANCESTRY_MISMATCH",r["blockers"])
 def test_job_pages_incomplete_denied(self):
  r=self.case(lambda d:d.update(job_search_state="JOB_PAGE_CAP_REACHED"))
  self.assertIn("JOB_PAGINATION_INCOMPLETE",r["blockers"])
 def test_failing_rust_step(self):
  r=self.case(lambda d:d["observed"]["required_steps"][1].update(conclusion="failure"))
  self.assertEqual(r["recorded_failures"][0]["check"],"RUST")
 def test_failing_python_step(self):
  r=self.case(lambda d:d["observed"]["required_steps"][0].update(conclusion="failure"))
  self.assertEqual(r["recorded_failures"][0]["check"],"PYTHON")
 def test_missing_frozen_step_denied(self):
  r=self.case(lambda d:d["observed"]["required_steps"].pop(2))
  self.assertIn("CRITICAL_STEP_UNIQUE:FROZEN",r["blockers"])
 def test_duplicate_inventory_step_denied(self):
  def edit(d):
   s=d["observed"]["required_steps"];s.append(dict(s[3]))
  r=self.case(edit)
  self.assertIn("CRITICAL_STEP_UNIQUE:INVENTORY",r["blockers"])
 def test_false_parent_green_denied(self):
  r=self.case(lambda d:d["observed"].update(failures=[{"job_id":1,"name":"child","conclusion":"failure"}]))
  self.assertIn("GREEN_RUN_CONTRADICTS_CHILD_FAILURE",r["blockers"])
 def test_invalid_attempt_denied(self):
  r=self.case(lambda d:d["observed"].update(attempt=True))
  self.assertIn("RUN_IDENTITY_INVALID",r["blockers"])
 def test_unfinished_run_denied(self):
  r=self.case(lambda d:d["observed"].update(run_status="in_progress"))
  self.assertIn("RUN_INCOMPLETE",r["unobserved"])
 def test_green_but_not_reported_success_denied(self):
  r=self.case(lambda d:d["observed"].update(source_owned_success_observed=False))
  self.assertFalse(r["source_owned_critical_steps_pass"])
 def test_forged_external_custody_denied(self):
  r=self.case(lambda d:d.update(independent_custody_authenticated=True))
  self.assertIn("UNSUPPORTED_AUTHORITY_CLAIM",r["blockers"])
 def test_job_failure_denied(self):
  r=self.case(lambda d:d["observed"].update(run_conclusion="failure"))
  self.assertIn("RUN_FAILURE",str(r["recorded_failures"]))
if __name__=="__main__":unittest.main()
