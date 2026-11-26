#!/usr/bin/env python3
"""SAPPHON-171 isolated synthetic log triage negative controls."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_171_job_logs.py")
sp=importlib.util.spec_from_file_location("logs171",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
SHA=m.EXPECTED
def row(status="completed",conclusion="success",attempt=1):
 return {"id":170,"run_attempt":attempt,"head_sha":SHA,
         "status":status,"conclusion":conclusion}
def job(name="deterministic-diagnostics",result="success"):
 return {"id":1000,"name":name,"conclusion":result,
    "steps":[{"name":"cargo test","conclusion":result}]}
class T(unittest.TestCase):
 def test_select_exact_sha(self):
  r=m.choose([row(),dict(row(),head_sha="b"*40,id=171)],SHA)
  self.assertEqual(r["id"],170)
 def test_newest_failure_selected(self):
  latest=dict(row(conclusion="failure"),id=171)
  self.assertEqual(m.choose([row(),latest],SHA)["id"],171)
 def test_new_attempt_selected(self):
  self.assertEqual(m.choose([row(),row(attempt=2)],SHA)["run_attempt"],2)
 def test_empty_run_unobserved(self):
  self.assertIsNone(m.choose([],SHA))
 def test_success_owned_only(self):
  x=m.classify(row(),[job()])
  self.assertTrue(x["source_owned_success_observed"])
 def test_missing_job_blocks(self):
  x=m.classify(row(),[job(name="other")])
  self.assertEqual(x["status"],"REQUIRED_JOB_MISSING")
 def test_failed_job_retains_step(self):
  x=m.classify(row(conclusion="failure"),[job(result="failure")])
  self.assertEqual(x["failures"][0]["failed_steps"][0]["name"],"cargo test")
 def test_incomplete_not_pass(self):
  x=m.classify(row(status="in_progress",conclusion=None),[job()])
  self.assertFalse(x["source_owned_success_observed"])
 def test_empty_jobs_no_success(self):
  self.assertFalse(m.classify(row(),[])["source_owned_success_observed"])
 def test_secret_redaction(self):
  self.assertNotIn("something",m.redacted("Authorization: something"))
 def test_invalid_sha(self):
  with self.assertRaises(ValueError):m.choose([],"invalid")
 def test_excerpt_bounded(self):
  self.assertLessEqual(len(m.redacted("a"*40000)),m.MAX_CHARS)
 def test_green_job_with_failed_step_denied(self):
  j=job()
  j["steps"][0]["conclusion"]="failure"
  result=m.classify(row(),[j])
  self.assertFalse(result["source_owned_success_observed"])
  self.assertEqual(result["failures"][0]["failed_steps"][0]["name"],"cargo test")
 def test_secret_entire_input_redacted_before_bounding(self):
  original="A"*(m.MAX_CHARS-15)+" Authorization: SECRET123_AFTER_EDGE"
  red=m.redacted(original)
  self.assertNotIn("SECRET123_AFTER_EDGE",red)
  self.assertLessEqual(len(red),m.MAX_CHARS)
 def test_green_run_with_cancelled_step_denied(self):
  j=job();j["steps"][0]["conclusion"]="cancelled"
  self.assertFalse(m.classify(row(),[j])["source_owned_success_observed"])
 def test_phase_xvi_171_required_job(self):
  observed=m.classify(row(),[job(name="diagnostics")],"diagnostics")
  self.assertTrue(observed["source_owned_success_observed"])
  self.assertEqual(observed["expected_job"],"diagnostics")
 def test_wrong_required_job_fails(self):
  observed=m.classify(row(),[job(name="deterministic-diagnostics")],"diagnostics")
  self.assertFalse(observed["source_owned_success_observed"])
  self.assertEqual(observed["status"],"REQUIRED_JOB_MISSING")
if __name__=="__main__":unittest.main()
