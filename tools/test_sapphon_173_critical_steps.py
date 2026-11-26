#!/usr/bin/env python3
"""SAPPHON-173 deterministic required-step negative controls."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_173_critical_steps.py")
spec=importlib.util.spec_from_file_location("critical173",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def fixture():
    steps=[{"name":n,"conclusion":"success"} for n in m.REQUIRED_STEPS]
    return {"schema":"sapphon-171-job-log-triage-v1",
      "expected_sha":m.SOURCE_SHA,"workflow":m.WORKFLOW,"status":"EXACT_RUN_OBSERVED",
      "independent_custody_authenticated":False,"recovery_authorized":False,
      "observed":{"head_sha":m.SOURCE_SHA,"run_id":173,"attempt":2,
        "expected_job":m.REQUIRED_JOB,"run_status":"completed",
        "status":"EXACT_RUN_OBSERVED","run_conclusion":"success",
        "source_owned_success_observed":True,"required_job_present":True,
        "required_job_unique":True,"required_steps_observed":True,
        "required_steps":steps,"unresolved_required_steps":[],"failures":[]}}
class Tests(unittest.TestCase):
    def case(self,mutation=lambda d:None):
        d=fixture();mutation(d);return m.reconcile(d)
    def test_consistent_only_source_observation(self):
        r=self.case();self.assertTrue(r["source_owned_critical_steps_consistent"])
        self.assertFalse(r["recovery_authorized"])
    def test_missing_python_step(self):
        r=self.case(lambda d:d["observed"]["required_steps"].pop(0))
        self.assertTrue(any("STEP_MISSING" in x for x in r["findings"]))
    def test_skipped_rust_step(self):
        r=self.case(lambda d:d["observed"]["required_steps"][1].update(conclusion="skipped"))
        self.assertTrue(any("STEP_NOT_SUCCESS" in x for x in r["findings"]))
    def test_failed_historic_hash_step(self):
        r=self.case(lambda d:d["observed"]["required_steps"][2].update(conclusion="failure"))
        self.assertTrue(any("STEP_NOT_SUCCESS" in x for x in r["findings"]))
    def test_duplicate_step(self):
        r=self.case(lambda d:d["observed"]["required_steps"].append(d["observed"]["required_steps"][0].copy()))
        self.assertTrue(any("STEP_MISSING_OR_DUPLICATED" in x for x in r["findings"]))
    def test_wrong_source(self):
        self.assertIn("OBSERVED_SOURCE_MISMATCH",self.case(lambda d:d["observed"].update(head_sha="a"*40))["findings"])
    def test_failed_child(self):
        self.assertIn("FAILED_JOB_OR_CHILD_STEP_PRESENT",self.case(lambda d:d["observed"].update(failures=[{"step":"Rust"}]))["findings"])
    def test_wrong_job(self):
        self.assertIn("REQUIRED_JOB_IDENTITY_MISMATCH",self.case(lambda d:d["observed"].update(expected_job="wrong"))["findings"])
    def test_no_step_list(self):
        self.assertIn("STEP_LIST_MISSING",self.case(lambda d:d["observed"].update(required_steps_observed=False))["findings"])
    def test_false_authority(self):
        self.assertIn("AUTHORITY_CLAIM_REJECTED",self.case(lambda d:d.update(recovery_authorized=True))["findings"])
    def test_duplicate_job(self):
        self.assertIn("REQUIRED_JOB_NOT_UNIQUE",self.case(lambda d:d["observed"].update(required_job_unique=False))["findings"])
    def test_invalid_attempt(self):
        self.assertIn("ATTEMPT_INVALID",self.case(lambda d:d["observed"].update(attempt=0))["findings"])
if __name__=="__main__":unittest.main()
