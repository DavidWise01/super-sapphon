#!/usr/bin/env python3
"""SAPPHON-183: offline source-run/acquisition contradictions."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_183_contradictions.py")
sp=importlib.util.spec_from_file_location("c183",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def samples():
 r={"schema":"sapphon-182-owned-outcomes-v1","commit":m.SOURCE,
    "run_id":"182","attempt":"1",
    "outcomes":{k:"success" for k in m.CHECKS},
    "source_tests_pass":True,"full_qualification":False,
    "recovery_authorized":False,"lock_cleared":False}
 a={"schema":"sapphon-181-acquisition-v1","source_sha":m.ACQUIRED_SOURCE,
    "status":"ORIGINAL_BYTES_OBSERVED","source_owned_bytes_observed":True,
    "run_id":180,"attempt":2,"job_id":3,"artifact_id":4,"recovery_authorized":False}
 c={"schema":"sapphon-182-cross-file-v1","source_sha":m.ACQUIRED_SOURCE,
    "archive_records_structurally_consistent":True,
    "complete_predecessor_and_raw_byte_evidence":True,
    "findings":[],"recovery_authorized":False,"lock_cleared":False}
 j={"schema":"sapphon-171-job-log-triage-v1","expected_sha":m.SOURCE,
    "workflow":m.WORKFLOW,"status":"EXACT_RUN_OBSERVED",
    "recovery_authorized":False,"independent_custody_authenticated":False,
    "observed":{"head_sha":m.SOURCE,"run_id":182,"attempt":1,
       "expected_job":m.JOB,"required_job_unique":True,
       "run_status":"completed","run_conclusion":"success",
       "required_steps":[{"name":n,"conclusion":"success"} for n in m.RUN_STEPS]}}
 return r,a,c,j
class Tests(unittest.TestCase):
 def check(self,fn=lambda v:None):
  values=list(samples());fn(values);return m.adjudicate(*values)
 def test_consistent_complete_still_hold(self):
  x=self.check();self.assertEqual(x["findings"],[])
  self.assertTrue(x["complete_owned_evidence"])
  self.assertFalse(x["recovery_authorized"])
 def test_wrong_runner_sha(self):
  x=self.check(lambda v:v[0].update(commit="a"*40))
  self.assertIn("RUNNER_ANCESTRY_INVALID",x["findings"])
 def test_false_python_pass(self):
  def edit(v):v[0]["outcomes"]["RUST"]="failure"
  x=self.check(edit);self.assertIn("RUNNER_FALSE_SOURCE_TEST_CLAIM",x["findings"])
 def test_job_run_mismatch(self):
  x=self.check(lambda v:v[3]["observed"].update(attempt=2))
  self.assertIn("JOB_RUN_ATTEMPT_CONFLICT",x["findings"])
 def test_predecessor_acquisition_missing(self):
  def edit(v):
   v[1].update(status="READBACK_UNAVAILABLE",source_owned_bytes_observed=False)
   v[0]["outcomes"]["ACQUISITION"]="failure"
  x=self.check(edit);self.assertIn("ARCHIVE_REPORTED_WITHOUT_ORIGINAL_BYTES",x["findings"])
 def test_acquisition_false_success(self):
  x=self.check(lambda v:v[1].update(status="READBACK_UNAVAILABLE",source_owned_bytes_observed=False))
  self.assertIn("ACQUISITION_FALSE_SUCCESS",x["findings"])
 def test_crossfile_false_success(self):
  x=self.check(lambda v:v[2].update(archive_records_structurally_consistent=False))
  self.assertIn("CROSSFILE_FALSE_SUCCESS",x["findings"])
 def test_crossfile_false_failure(self):
  x=self.check(lambda v:v[0]["outcomes"].update(CROSSFILE="failure"))
  self.assertIn("CROSSFILE_FALSE_FAILURE",x["findings"])
 def test_wrong_archive_ancestry(self):
  x=self.check(lambda v:v[2].update(source_sha="b"*40))
  self.assertIn("CROSSFILE_ANCESTRY_INVALID",x["findings"])
 def test_missing_job_is_not_qualified(self):
  x=self.check(lambda v:v[3].update(status="READBACK_UNAVAILABLE",observed=None))
  self.assertFalse(x["complete_owned_evidence"])
  self.assertIn("EXACT_JOB_READBACK_UNAVAILABLE",x["limitations"])
 def test_unavailable_archive_placeholder_is_not_complete(self):
  def edit(v):
   v[1].update(status="READBACK_UNAVAILABLE",source_owned_bytes_observed=False)
   v[0]["outcomes"]["ACQUISITION"]="failure"
   v[2]={"schema":"sapphon-182-evidence-unavailable-v1",
     "status":"ORIGINAL_ARCHIVE_NOT_OBSERVED","recovery_authorized":False,"lock_cleared":False}
  x=self.check(edit);self.assertFalse(x["complete_owned_evidence"])
  self.assertIn("STEP_EXECUTED_BUT_ARCHIVE_NOT_OBSERVED",x["limitations"])
 def test_green_job_conflicting_child(self):
  def edit(v):
   v[3]["observed"]["required_steps"][1]["conclusion"]="failure"
  x=self.check(edit);self.assertIn("JOB_PARENT_CHILD_CONFLICT:RUST",x["findings"])
 def test_authority_claim_denied(self):
  x=self.check(lambda v:v[2].update(recovery_authorized=True))
  self.assertIn("CROSSFILE_AUTHORITY",x["findings"])
if __name__=="__main__":unittest.main()
