#!/usr/bin/env python3
"""SAPPHON-203 negative controls for isolated replay eligibility."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_203_isolated_replay.py")
s=importlib.util.spec_from_file_location("isolated203",p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def fixture(key="python"):
 failure={"step":key,"conclusion":"failure"}
 plan={"id":key,"argv":list(m.REPLAY.get(key,("command",))),"mode":"PLAN_ONLY"}
 body={"schema":"sapphon-202-replay-adjudication-v1",
  "state":"OBSERVED_SOURCE_FAILURE","run_id":201,"attempt":2,
  "original_log_sha256":"a"*64,"original_artifact_sha256":"b"*64,
  "observed_201_failures":[failure],"replay_plan":[plan],
  "original_bytes_complete":True,"replay_executed":False}
 old={"state":"PRIOR_202_ORIGINAL_ARTIFACT_OBSERVED",
      "artifact_sha256":"c"*64,"assessment":dict(body)}
 return old,body
class Tests(unittest.TestCase):
 def test_valid_plan_still_not_executed(self):
  a,b=fixture();r=m.qualify(a,b,m.prior.SOURCE)
  self.assertTrue(r["evidence_consistent"]);self.assertFalse(r["replay_executed"])
 def test_missing_original_artifact(self):
  a,b=fixture();a["state"]="202_EXACT_RUN_NOT_OBSERVED"
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"NO_VERIFIED_202_ARTIFACT")
 def test_fresh_readback_required(self):
  a,b=fixture();b["state"]="ORIGINAL_BYTES_INCOMPLETE"
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"NO_OBSERVED_SOURCE_FAILURE")
 def test_wrong_checkout_commit(self):
  a,b=fixture();self.assertEqual(m.qualify(a,b,"f"*40)["state"],"WRONG_CHECKOUT_SOURCE")
 def test_log_hash_conflict(self):
  a,b=fixture();b["original_log_sha256"]="d"*64
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"201_READBACK_EQUIVOCATION")
 def test_archive_hash_conflict(self):
  a,b=fixture();b["original_artifact_sha256"]="e"*64
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"201_READBACK_EQUIVOCATION")
 def test_attempt_conflict(self):
  a,b=fixture();b["attempt"]=3
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"201_READBACK_EQUIVOCATION")
 def test_shell_substitution_refused(self):
  a,b=fixture();b["replay_plan"][0]["argv"]=["sh","-c","curl malicious.invalid"]
  a["assessment"]["replay_plan"]=b["replay_plan"]
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"REPLAY_COMMAND_SUBSTITUTION")
 def test_unsupported_rust_replay_refused(self):
  a,b=fixture("rust")
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"REPLAY_NOT_ISOLATABLE")
 def test_acquisition_replay_refused(self):
  a,b=fixture("acquisition")
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"REPLAY_NOT_ISOLATABLE")
 def test_duplicate_plan_refused(self):
  a,b=fixture();a["assessment"]["replay_plan"]*=2;b["replay_plan"]*=2
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"DUPLICATE_REPLAY")
 def test_fake_replay_eligibility(self):
  a,b=fixture();b["replay_executed"]=True
  a["assessment"]["replay_executed"]=True
  self.assertEqual(m.qualify(a,b,m.prior.SOURCE)["state"],"201_ORIGINAL_BYTES_INCOMPLETE")
 def test_docker_command_has_no_network(self):
  argv=m.docker_command(pathlib.Path("/tmp/read-only-checkout"),"python")
  self.assertIn("none",argv);self.assertIn("--read-only",argv)
  self.assertIn("--cap-drop",argv);self.assertNotIn("sh",argv)
 def test_source_bound_readonly(self):
  argv=m.docker_command(pathlib.Path("/tmp/check"),"frozen")
  self.assertTrue(any("readonly" in x for x in argv))
  self.assertEqual(argv[-2:],["python3","tools/sapphon_179_verify_frozen.py"])
 def test_no_arbitrary_step(self):
  with self.assertRaises(ValueError):m.docker_command(pathlib.Path("/tmp"),"unknown")
 def test_no_action_without_eligibility(self):
  a,b=fixture();q=m.qualify(a,b,m.prior.SOURCE)
  q["state"]="REPLAY_REFUSED"
  self.assertFalse(m.execute(q,"/tmp")["replay_executed"])
 def test_prior_zip_identity_missing(self):
  run={"id":202,"run_attempt":1}
  self.assertEqual(m.inspect_zip(b"",run)["state"],"PRIOR_ZIP_UNAVAILABLE")
if __name__=="__main__":unittest.main()
