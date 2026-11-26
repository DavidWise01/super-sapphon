#!/usr/bin/env python3
"""SAPPHON-174 offline source-outcome regression controls."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_174_outcomes.py")
spec=importlib.util.spec_from_file_location("outcomes174",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def sample():
    steps=[{"name":n,"conclusion":"success"} for n in m.NEEDED]
    return {"schema":"sapphon-171-job-log-triage-v1",
      "expected_sha":m.SOURCE_SHA,"workflow":m.WORKFLOW,
      "status":"EXACT_RUN_OBSERVED",
      "independent_custody_authenticated":False,"recovery_authorized":False,
      "observed":{"head_sha":m.SOURCE_SHA,"run_id":173,"attempt":1,
        "expected_job":m.JOB,"required_job_unique":True,
        "run_status":"completed","run_conclusion":"success",
        "source_owned_success_observed":True,
        "required_steps":steps,"unresolved_required_steps":[],"failures":[]}}
class Tests(unittest.TestCase):
    def check(self,change=lambda r:None):
        r=sample();change(r);return m.assess(r)
    def test_source_pass_not_full_qualification(self):
        r=self.check()
        self.assertTrue(r["source_owned_diagnostics_observed_pass"])
        self.assertFalse(r["full_qualification"])
        self.assertFalse(r["recovery_authorized"])
    def test_missing_run(self):
        self.assertIn("RUN_NOT_OBSERVED",self.check(lambda r:r.update(status="READBACK_UNAVAILABLE"))["findings"])
    def test_wrong_sha(self):
        self.assertIn("WRONG_ANCESTRY",self.check(lambda r:r.update(expected_sha="a"*40))["findings"])
    def test_wrong_job(self):
        self.assertIn("JOB_IDENTITY_INVALID",self.check(lambda r:r["observed"].update(expected_job="other"))["findings"])
    def test_missing_rust_step(self):
        self.assertTrue(any("MISSING_OR_DUPLICATE" in s for s in self.check(lambda r:r["observed"]["required_steps"].pop(1))["findings"]))
    def test_skipped_historical_step(self):
        self.assertTrue(any("NON_SUCCESS" in s for s in self.check(lambda r:r["observed"]["required_steps"][2].update(conclusion="skipped"))["findings"]))
    def test_duplicated_step(self):
        self.assertTrue(any("MISSING_OR_DUPLICATE" in s for s in self.check(lambda r:r["observed"]["required_steps"].append(r["observed"]["required_steps"][0].copy()))["findings"]))
    def test_failed_child_step(self):
        self.assertIn("FAILED_OR_UNRESOLVED_STEP",self.check(lambda r:r["observed"].update(failures=[{"step":"cargo"}]))["findings"])
    def test_invalid_attempt(self):
        self.assertIn("INVALID_ATTEMPT",self.check(lambda r:r["observed"].update(attempt=0))["findings"])
    def test_forged_custody(self):
        self.assertIn("FORGED_AUTHORITY",self.check(lambda r:r.update(independent_custody_authenticated=True))["findings"])
if __name__=="__main__":unittest.main()
