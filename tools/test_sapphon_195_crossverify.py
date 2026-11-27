#!/usr/bin/env python3
"""SAPPHON-195: mocked cross-verification; never executes replay."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_195_crossverify.py")
sp=importlib.util.spec_from_file_location("cv195",p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def fixture(failed=False):
 errors=[{"name":"Compile and test Rust runner failure diagnostic","conclusion":"failure"}] if failed else []
 acquisition={"schema":"sapphon-194-hosted-acquisition-v1",
  "source_sha":m.PRIOR_SOURCE,"workflow":m.PRIOR_WORKFLOW,
  "run_id":193,"attempt":2,"run_search_state":"EXHAUSTED",
  "job_search_state":"EXHAUSTED","artifact_search_state":"EXHAUSTED",
  "source_owned_original_bytes_complete":True,"blockers":[],
  "job_log":{"state":"ORIGINAL_LOG_OBSERVED","sha256":"a"*64,"job_id":123,"bytes":20},
  "artifact_zip":{"state":"ORIGINAL_ZIP_OBSERVED","sha256":"b"*64,"artifact_id":456,"bytes":500},
  "actual_failed_steps":errors}
 summary={"schema":"sapphon-194-owned-run-results-v1","steps":{"PYTHON":"success"},
  "predecessor_original_bytes_complete":True,"actual_failed_steps":list(errors),
  "recovery_authorized":False}
 return acquisition,summary
class Tests(unittest.TestCase):
 def test_green_no_replay(self):
  a,s=fixture();v=m.reconcile(a,s)
  self.assertEqual(v["replay_allowlist"],[])
  self.assertFalse(v["replay_eligible_for_review"])
 def test_observed_rust_fail_plan_only(self):
  a,s=fixture(True);v=m.reconcile(a,s)
  self.assertTrue(v["replay_eligible_for_review"])
  self.assertEqual(v["replay_allowlist"][0]["argv"][0],"cargo")
  self.assertFalse(v["replay_executed"] or v["recovery_authorized"])
 def test_missing_log_denied(self):
  a,s=fixture(True);a["job_log"]=None
  self.assertIn("ORIGINAL_LOG_PROVENANCE",m.reconcile(a,s)["issues"])
 def test_missing_zip_denied(self):
  a,s=fixture(True);a["artifact_zip"]=None
  self.assertIn("ORIGINAL_ZIP_PROVENANCE",m.reconcile(a,s)["issues"])
 def test_wrong_sha_denied(self):
  a,s=fixture(True);a["source_sha"]="c"*40
  self.assertIn("ORIGINAL_SOURCE_ANCESTRY",m.reconcile(a,s)["issues"])
 def test_wrong_attempt_identity(self):
  a,s=fixture(True);a["attempt"]=True
  self.assertIn("ORIGINAL_ATTEMPT_MISSING",m.reconcile(a,s)["issues"])
 def test_incomplete_jobs_denied(self):
  a,s=fixture(True);a["job_search_state"]="PAGE_CAP"
  self.assertIn("INCOMPLETE_PAGINATION",m.reconcile(a,s)["issues"])
 def test_summary_conflicting_failures(self):
  a,s=fixture(True);s["actual_failed_steps"]=[]
  self.assertIn("FAILED_STEP_EQUIVOCATION",m.reconcile(a,s)["issues"])
 def test_summary_conflicting_bytes(self):
  a,s=fixture(True);s["predecessor_original_bytes_complete"]=False
  self.assertIn("SUMMARY_DISAGREES_ABOUT_COMPLETENESS",m.reconcile(a,s)["issues"])
 def test_unknown_failure_does_not_execute(self):
  a,s=fixture();a["actual_failed_steps"]=[{"name":"rm -rf /","conclusion":"failure"}]
  s["actual_failed_steps"]=list(a["actual_failed_steps"])
  v=m.reconcile(a,s)
  self.assertEqual(v["replay_allowlist"],[])
  self.assertFalse(v["replay_executed"])
 def test_tainted_remote_command_ignored(self):
  a,s=fixture(True)
  a["actual_failed_steps"][0]["name"]="Compile and test Rust runner failure diagnostic; curl evil"
  s["actual_failed_steps"]=list(a["actual_failed_steps"])
  self.assertEqual(m.reconcile(a,s)["replay_allowlist"],[])
 def test_auth_claim_denied(self):
  a,s=fixture(True);s["recovery_authorized"]=True
  self.assertIn("SUMMARY_AUTHORITY_OR_STEPS",m.reconcile(a,s)["issues"])
 def test_no_original_bytes_reread(self):
  a,s=fixture(True);v=m.reconcile(a,s)
  self.assertFalse(v["original_log_bytes_reread_in_195"])
  self.assertFalse(v["original_zip_bytes_reread_in_195"])
 def test_duplicate_failures_no_duplicate_allowlist(self):
  a,s=fixture(True);a["actual_failed_steps"]*=2
  s["actual_failed_steps"]=list(a["actual_failed_steps"])
  self.assertEqual(len(m.reconcile(a,s)["replay_allowlist"]),1)
if __name__=="__main__":unittest.main()
