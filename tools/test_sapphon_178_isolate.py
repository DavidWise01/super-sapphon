#!/usr/bin/env python3
"""SAPPHON-178 offline regression controls: no invented runner observations."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_178_isolate.py")
spec=importlib.util.spec_from_file_location("s178",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def fixture():
 return {"schema":"sapphon-171-job-log-triage-v1","expected_sha":m.SOURCE,
  "workflow":m.WORKFLOW,"status":"EXACT_RUN_OBSERVED",
  "recovery_authorized":False,"independent_custody_authenticated":False,
  "observed":{"head_sha":m.SOURCE,"run_id":177,"attempt":1,
    "expected_job":m.JOB,"required_job_unique":True,
    "run_status":"completed","run_conclusion":"success",
    "source_owned_success_observed":True,"failures":[],"unresolved_required_steps":[],
    "required_steps":[{"name":name,"conclusion":"success"} for name in m.REQUIRED.values()]}}
class Tests(unittest.TestCase):
 def run_case(self,edit=lambda x:None):
  x=fixture();edit(x);return m.review(x)
 def test_all_owned_passes_still_hold(self):
  x=self.run_case();self.assertTrue(x["source_owned_diagnostics_pass"])
  self.assertFalse(x["recovery_authorized"])
 def test_missing_run_not_success(self):
  x=self.run_case(lambda r:r.update(status="READBACK_UNAVAILABLE"))
  self.assertFalse(x["source_owned_diagnostics_pass"])
 def test_wrong_commit(self):
  x=self.run_case(lambda r:r.update(expected_sha="a"*40))
  self.assertIn("SOURCE_ANCESTRY_MISMATCH",x["findings"])
 def test_rust_failure_isolated(self):
  x=self.run_case(lambda r:r["observed"]["required_steps"][1].update(conclusion="failure"))
  self.assertEqual(x["gates"]["RUST"],"FAIL_OR_INCOMPLETE")
  self.assertEqual(x["gates"]["PYTHON"],"PASS")
 def test_python_skipped(self):
  x=self.run_case(lambda r:r["observed"]["required_steps"][0].update(conclusion="skipped"))
  self.assertEqual(x["gates"]["PYTHON"],"FAIL_OR_INCOMPLETE")
 def test_missing_historical(self):
  x=self.run_case(lambda r:r["observed"]["required_steps"].pop(2))
  self.assertEqual(x["gates"]["FROZEN"],"NOT_OBSERVED")
 def test_duplicate_python(self):
  def edit(r):
   a=r["observed"]["required_steps"];a.append(a[0].copy())
  x=self.run_case(edit);self.assertEqual(x["gates"]["PYTHON"],"DUPLICATE")
 def test_failed_child(self):
  x=self.run_case(lambda r:r["observed"].update(failures=[{"name":"cargo","conclusion":"failure"}]))
  self.assertIn("FAILED_JOB_OR_CHILD_STEP",x["findings"])
 def test_boolean_attempt(self):
  x=self.run_case(lambda r:r["observed"].update(attempt=True))
  self.assertIn("INVALID_ATTEMPT",x["findings"])
 def test_incomplete_run(self):
  x=self.run_case(lambda r:r["observed"].update(run_status="in_progress"))
  self.assertIn("RUN_INCOMPLETE",x["findings"])
 def test_forged_recovery(self):
  x=self.run_case(lambda r:r.update(recovery_authorized=True))
  self.assertIn("FORGED_AUTHORITY_CLAIM",x["findings"])
if __name__=="__main__":unittest.main()
