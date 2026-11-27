#!/usr/bin/env python3
"""SAPPHON-185 observed runner classifier regression controls."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_185_observed.py")
s=importlib.util.spec_from_file_location("observe185",p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def fixture():
 return {"schema":"sapphon-171-job-log-triage-v1",
 "expected_sha":m.SOURCE,"workflow":m.WORKFLOW,
 "status":"EXACT_RUN_OBSERVED","job_search_state":"JOB_PAGES_EXHAUSTED",
 "independent_custody_authenticated":False,"recovery_authorized":False,
 "observed":{"head_sha":m.SOURCE,"expected_job":m.JOB,
 "required_job_unique":True,"run_id":184,"attempt":1,
 "run_status":"completed","run_conclusion":"success",
 "source_owned_success_observed":True,"failures":[],
 "required_steps":[{"name":n,"conclusion":"success"} for n in m.CRITICAL.values()]}}
class Tests(unittest.TestCase):
 def check(self,edit=lambda d:None):
  d=fixture();edit(d);return m.assess(d)
 def test_complete_owned_pass_still_hold(self):
  r=self.check();self.assertTrue(r["source_owned_run_pass"])
  self.assertFalse(r["recovery_authorized"])
 def test_empty_readback_not_pass(self):
  r=self.check(lambda d:d.update(status="READBACK_UNAVAILABLE",observed=None))
  self.assertFalse(r["source_owned_run_pass"])
  self.assertIn("EXACT_RUN_NOT_OBSERVED",r["unobserved"])
 def test_wrong_commit_not_pass(self):
  r=self.check(lambda d:d.update(expected_sha="a"*40))
  self.assertIn("INVALID_PROVENANCE",r["blockers"])
 def test_page_cap_not_pass(self):
  r=self.check(lambda d:d.update(job_search_state="JOB_PAGE_CAP_REACHED"))
  self.assertIn("JOBS_NOT_PROVEN_EXHAUSTIVE",r["blockers"])
 def test_missing_page_scope_not_pass(self):
  r=self.check(lambda d:d.pop("job_search_state"))
  self.assertFalse(r["source_owned_run_pass"])
 def test_missing_rust_not_pass(self):
  r=self.check(lambda d:d["observed"]["required_steps"].pop(1))
  self.assertIn("CRITICAL_STEP_NOT_UNIQUE:RUST",r["blockers"])
 def test_rust_failed_step_isolated(self):
  r=self.check(lambda d:d["observed"]["required_steps"][1].update(conclusion="failure"))
  self.assertEqual(r["recorded_failures"][0]["check"],"RUST")
  self.assertFalse(r["source_owned_run_pass"])
 def test_duplicate_python_rejected(self):
  def edit(d):
   a=d["observed"]["required_steps"];a.append(a[0].copy())
  r=self.check(edit)
  self.assertIn("CRITICAL_STEP_NOT_UNIQUE:PYTHON",r["blockers"])
 def test_invalid_attempt_rejected(self):
  r=self.check(lambda d:d["observed"].update(attempt=True))
  self.assertIn("INVALID_ATTEMPT",r["blockers"])
 def test_in_progress_source_not_pass(self):
  r=self.check(lambda d:d["observed"]["required_steps"][2].update(conclusion="in_progress"))
  self.assertIn("CRITICAL_STEP_INCOMPLETE:FROZEN",r["unobserved"])
 def test_forged_custody_rejected(self):
  r=self.check(lambda d:d.update(independent_custody_authenticated=True))
  self.assertIn("UNAUTHORIZED_CUSTODY_OR_RECOVERY",r["blockers"])
 def test_green_parent_failed_child_rejected(self):
  r=self.check(lambda d:d["observed"].update(failures=[{"name":"rust"}]))
  self.assertIn("GREEN_RUN_WITH_FAILED_CHILD",r["blockers"])
if __name__=="__main__":unittest.main()
