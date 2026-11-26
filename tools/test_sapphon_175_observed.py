#!/usr/bin/env python3
"""SAPPHON-175 synthetic negative controls, no live-result claims."""
import importlib.util,pathlib,unittest
f=pathlib.Path(__file__).with_name("sapphon_175_observed.py")
s=importlib.util.spec_from_file_location("obs175",f)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def fixture():
 return {"schema":"sapphon-171-job-log-triage-v1","expected_sha":m.SOURCE,
   "workflow":m.WORKFLOW,"status":"EXACT_RUN_OBSERVED",
   "independent_custody_authenticated":False,"recovery_authorized":False,
   "observed":{"head_sha":m.SOURCE,"run_id":175,"attempt":1,
      "expected_job":m.JOB,"required_job_unique":True,
      "run_status":"completed","run_conclusion":"success",
      "source_owned_success_observed":True,"failures":[],
      "unresolved_required_steps":[],
      "required_steps":[{"name":x,"conclusion":"success"} for x in m.REQUIRED]}}
class T(unittest.TestCase):
 def check(self,mutate=lambda d:None):
  d=fixture();mutate(d);return m.assess(d)
 def test_consistent_still_hold(self):
  r=self.check();self.assertTrue(r["source_owned_diagnostics_consistent"])
  self.assertFalse(r["recovery_authorized"])
 def test_exhausted_search_not_a_pass(self):
  r=self.check(lambda d:d.update(status="NO_MATCHING_RUN_IN_EXHAUSTED_PAGES"))
  self.assertFalse(r["source_owned_diagnostics_consistent"])
 def test_pagination_cap_not_a_pass(self):
  r=self.check(lambda d:d.update(status="RUN_SEARCH_INCOMPLETE_PAGE_CAP"))
  self.assertTrue(any("UNQUALIFIED" in x for x in r["issues"]))
 def test_wrong_source(self):
  self.assertIn("WRONG_SOURCE_ANCESTRY",self.check(lambda d:d.update(expected_sha="a"*40))["issues"])
 def test_failed_rust(self):
  r=self.check(lambda d:d["observed"]["required_steps"][1].update(conclusion="failure"))
  self.assertTrue(any("STEP_NOT_PASS" in x for x in r["issues"]))
 def test_skipped_frozen(self):
  r=self.check(lambda d:d["observed"]["required_steps"][2].update(conclusion="skipped"))
  self.assertTrue(any("STEP_NOT_PASS" in x for x in r["issues"]))
 def test_duplicate_python(self):
  def change(d):
   x=d["observed"]["required_steps"];x.append(x[0].copy())
  self.assertTrue(any("DUPLICATED" in x for x in self.check(change)["issues"]))
 def test_missing_run(self):
  self.assertIn("RUN_ID_MISSING",self.check(lambda d:d["observed"].update(run_id=None))["issues"])
 def test_wrong_job(self):
  self.assertIn("EXPECTED_JOB_NOT_UNIQUE",self.check(lambda d:d["observed"].update(expected_job="other"))["issues"])
 def test_false_custody(self):
  self.assertIn("FORGED_AUTHORITY_CLAIM",self.check(lambda d:d.update(independent_custody_authenticated=True))["issues"])
 def test_failed_child(self):
  self.assertIn("FAILED_OR_UNRESOLVED_CHILD",self.check(lambda d:d["observed"].update(failures=[{"step":"Rust"}]))["issues"])
if __name__=="__main__":unittest.main()
