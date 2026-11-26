#!/usr/bin/env python3
"""SAPPHON-177 isolated source-owned evidence regression controls."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_177_evidence.py")
sp=importlib.util.spec_from_file_location("e177",p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def fixture():
 return {"schema":"sapphon-171-job-log-triage-v1","workflow":m.WORKFLOW,
 "expected_sha":m.SHA,"status":"EXACT_RUN_OBSERVED",
 "independent_custody_authenticated":False,"recovery_authorized":False,
 "observed":{"head_sha":m.SHA,"run_id":176,"attempt":1,"expected_job":m.JOB,
 "required_job_unique":True,"run_status":"completed","run_conclusion":"success",
 "source_owned_success_observed":True,"failures":[],"unresolved_required_steps":[],
 "required_steps":[{"name":n,"conclusion":"success"} for n in m.REQUIRED]}}
class Tests(unittest.TestCase):
 def call(self,mutate=lambda o:None):
  r=fixture();mutate(r);return m.assess(r)
 def test_source_pass_not_authority(self):
  x=self.call();self.assertTrue(x["source_owned_pass_consistent"])
  self.assertFalse(x["recovery_authorized"])
 def test_missing_run(self):
  self.assertIn("RUN_NOT_OBSERVED",self.call(lambda d:d.update(status="READBACK_UNAVAILABLE"))["findings"])
 def test_wrong_workflow(self):
  self.assertIn("ANCESTRY",self.call(lambda d:d.update(workflow="other"))["findings"])
 def test_wrong_sha(self):
  self.assertIn("ANCESTRY",self.call(lambda d:d.update(expected_sha="a"*40))["findings"])
 def test_missing_rust(self):
  self.assertTrue(any("MISSING_OR_DUPLICATE" in v for v in self.call(lambda d:d["observed"]["required_steps"].pop(1))["findings"]))
 def test_skipped_python(self):
  self.assertTrue(any("NON_SUCCESS" in v for v in self.call(lambda d:d["observed"]["required_steps"][0].update(conclusion="skipped"))["findings"]))
 def test_duplicate_historical(self):
  def mutate(d):d["observed"]["required_steps"].append(d["observed"]["required_steps"][2].copy())
  self.assertTrue(any("MISSING_OR_DUPLICATE" in v for v in self.call(mutate)["findings"]))
 def test_unverified_claim(self):
  self.assertIn("CLAIMED_SUCCESS_NOT_OBSERVED",self.call(lambda d:d["observed"].update(source_owned_success_observed=False))["findings"])
 def test_failed_child(self):
  self.assertIn("FAILED_CHILD",self.call(lambda d:d["observed"].update(failures=[{"step":"cargo"}]))["findings"])
 def test_forged_authority(self):
  self.assertIn("UNSUPPORTED_AUTHORITY",self.call(lambda d:d.update(recovery_authorized=True))["findings"])
 def test_missing_attempt(self):
  self.assertIn("ATTEMPT",self.call(lambda d:d["observed"].update(attempt=None))["findings"])
if __name__=="__main__":unittest.main()
