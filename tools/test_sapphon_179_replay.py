#!/usr/bin/env python3
"""SAPPHON-179 offline tests: no executable instructions sourced from logs."""
import importlib.util,json,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_179_replay.py")
spec=importlib.util.spec_from_file_location("s179",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def sample():
 return {"schema":"sapphon-171-job-log-triage-v1","expected_sha":m.SOURCE,
  "workflow":m.WORKFLOW,"status":"EXACT_RUN_OBSERVED",
  "independent_custody_authenticated":False,"recovery_authorized":False,
  "observed":{"head_sha":m.SOURCE,"run_id":178,"attempt":1,
   "expected_job":m.JOB,"required_job_unique":True,"run_status":"completed",
   "run_conclusion":"failure","required_steps":[{"name":name,
   "conclusion":"failure" if cat=="RUST" else "success"}
   for cat,(name,_) in m.STEPS.items()]}}
def review(d,digest=None):return m.analyze(json.dumps(d,sort_keys=True).encode(),digest)
class ReplayTests(unittest.TestCase):
 def test_exact_failed_rust_plan(self):
  x=review(sample());self.assertTrue(x["replay_eligible"])
  self.assertEqual([v["category"] for v in x["replay_plan"]],["RUST"])
  self.assertFalse(x["replay_commands_executed"])
 def test_digest(self):
  raw=json.dumps(sample()).encode()
  self.assertEqual(m.analyze(raw,m.sha256(raw))["evidence_bytes_sha256"],m.sha256(raw))
 def test_tampering_denied(self):
  with self.assertRaisesRegex(ValueError,"DIGEST_MISMATCH"):review(sample(),"0"*64)
 def test_wrong_commit(self):
  d=sample();d["expected_sha"]="a"*40
  x=review(d);self.assertFalse(x["replay_plan"]);self.assertIn("WRONG_ANCESTRY",x["blockers"])
 def test_no_run(self):
  d=sample();d["status"]="READBACK_UNAVAILABLE"
  self.assertEqual(review(d)["replay_plan"],[])
 def test_missing_job(self):
  d=sample();d["observed"]["expected_job"]="other"
  self.assertEqual(review(d)["replay_plan"],[])
 def test_boolean_attempt(self):
  d=sample();d["observed"]["attempt"]=True
  self.assertEqual(review(d)["replay_plan"],[])
 def test_duplicate_step(self):
  d=sample();d["observed"]["required_steps"].append(d["observed"]["required_steps"][1].copy())
  self.assertIn("RUST_STEP_NOT_UNIQUE",review(d)["blockers"])
 def test_unknown_step_conclusion(self):
  d=sample();d["observed"]["required_steps"][1]["conclusion"]="queued"
  self.assertIn("RUST_STEP_UNRESOLVED",review(d)["blockers"])
 def test_green_parent_red_child(self):
  d=sample();d["observed"]["run_conclusion"]="success"
  self.assertIn("PARENT_CHILD_CONTRADICTION",review(d)["blockers"])
 def test_unsupported_authority(self):
  d=sample();d["recovery_authorized"]=True
  self.assertEqual(review(d)["replay_plan"],[])
 def test_clean_pass_no_plan(self):
  d=sample();d["observed"]["run_conclusion"]="success"
  d["observed"]["required_steps"][1]["conclusion"]="success"
  x=review(d);self.assertFalse(x["replay_eligible"]);self.assertFalse(x["blockers"])
 def test_oversize_rejected(self):
  with self.assertRaisesRegex(ValueError,"TOO_LARGE"):m.analyze(b"x"*(m.MAX_EVIDENCE+1))
if __name__=="__main__":unittest.main()
