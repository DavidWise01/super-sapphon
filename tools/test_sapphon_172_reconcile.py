#!/usr/bin/env python3
"""SAPPHON-172 offline evidence reconciliation negative controls."""
import importlib.util,pathlib,unittest,copy
path=pathlib.Path(__file__).with_name("sapphon_172_reconcile.py")
spec=importlib.util.spec_from_file_location("recon172",path)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
def fixture():
 return {"schema":"sapphon-171-job-log-triage-v1","expected_sha":mod.COMMIT,
  "workflow":"sapphon-171-joblogs.yml","status":"EXACT_RUN_OBSERVED",
  "independent_custody_authenticated":False,"recovery_authorized":False,
  "observed":{"head_sha":mod.COMMIT,"run_id":171,"attempt":2,
    "status":"EXACT_RUN_OBSERVED","run_status":"completed",
    "run_conclusion":"success","expected_job":"diagnostics",
    "required_job_present":True,"source_owned_success_observed":True,
    "failures":[]}}
class Tests(unittest.TestCase):
 def test_consistent_does_not_authorize(self):
  r=mod.reconcile(fixture())
  self.assertTrue(r["source_owned_diagnostic_consistent"])
  self.assertFalse(r["recovery_authorized"])
 def test_wrong_run_source(self):
  d=fixture();d["observed"]["head_sha"]="b"*40
  self.assertIn("OBSERVED_SOURCE_MISMATCH",mod.reconcile(d)["issues"])
 def test_wrong_workflow(self):
  d=fixture();d["workflow"]="other"
  self.assertIn("WORKFLOW_MISMATCH",mod.reconcile(d)["issues"])
 def test_missing_run_id(self):
  d=fixture();d["observed"]["run_id"]=None
  self.assertIn("RUN_ID_MISSING",mod.reconcile(d)["issues"])
 def test_wrong_required_job(self):
  d=fixture();d["observed"]["expected_job"]="final-freeze"
  self.assertIn("REQUIRED_JOB_MISMATCH",mod.reconcile(d)["issues"])
 def test_failed_step_block(self):
  d=fixture();d["observed"]["failures"]=[{"step":"cargo test"}]
  self.assertIn("FAILURE_EVIDENCE_PRESENT",mod.reconcile(d)["issues"])
 def test_incomplete_run(self):
  d=fixture();d["observed"]["run_status"]="in_progress"
  self.assertIn("RUN_INCOMPLETE",mod.reconcile(d)["issues"])
 def test_false_authority_claim(self):
  d=fixture();d["recovery_authorized"]=True
  self.assertIn("UNSUPPORTED_AUTHORITY_CLAIM",mod.reconcile(d)["issues"])
 def test_unknown_status(self):
  d=fixture();d["status"]="READBACK_UNAVAILABLE"
  self.assertIn("NO_COMPLETED_EVIDENCE",mod.reconcile(d)["issues"])
 def test_missing_success_cannot_be_assumed(self):
  d=fixture();d["observed"]["source_owned_success_observed"]=False
  self.assertIn("SOURCE_SUCCESS_NOT_ESTABLISHED",mod.reconcile(d)["issues"])
if __name__=="__main__":unittest.main()
