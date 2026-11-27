#!/usr/bin/env python3
"""SAPPHON-194 mocked acquisition tests; no hosted-run PASS assertion."""
import importlib.util,io,json,pathlib,unittest,zipfile
p=pathlib.Path(__file__).with_name("sapphon_194_acquire.py")
spec=importlib.util.spec_from_file_location("a194",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def fixture():
 run={"id":193,"run_attempt":2,"head_sha":m.SHA,"status":"completed"}
 jobs=[{"id":1901,"run_id":193,"run_attempt":2,"name":m.JOB,
        "conclusion":"success","steps":[{"name":"Run Python","conclusion":"success"}]}]
 arts=[{"id":1902,"name":m.ARTIFACT,"expired":False,
        "workflow_run":{"id":193,"head_sha":m.SHA}}]
 summary={"schema":"sapphon-193-source-run-v1","commit":m.SHA,"run_id":"193",
          "attempt":"2","recovery_authorized":False}
 return run,jobs,arts,summary
def zipof(summary):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w") as z:
  for name in sorted(m.MEMBERS):
   data=summary if name=="193-summary.json" else {"schema":"synthetic"}
   z.writestr(name,json.dumps(data))
 return b.getvalue()
def acquire(run,jobs,arts,summary,logs=b"sample hosted log"):
 zipbytes=zipof(summary)
 def fetch(path):
  if "/workflows/" in path:return {"workflow_runs":[run]}
  if "/jobs?" in path:return {"jobs":jobs}
  if "/artifacts?" in path:return {"artifacts":arts}
  raise ValueError(path)
 def download(path):
  if "/logs" in path:return logs
  return zipbytes
 return m.run_acquisition(fetch,download)
class Tests(unittest.TestCase):
 def test_valid_owned_bytes_are_not_independent(self):
  run,jobs,arts,summary=fixture();r=acquire(run,jobs,arts,summary)
  self.assertTrue(r["source_owned_original_bytes_complete"])
  self.assertFalse(r["recovery_authorized"])
  self.assertEqual(r["attempt"],2)
 def test_wrong_zip_attempt_denied(self):
  run,jobs,arts,summary=fixture();summary["attempt"]="1"
  self.assertEqual(acquire(run,jobs,arts,summary)["artifact_zip"]["state"],"ZIP_RUN_ATTEMPT_CONFLICT")
 def test_missing_original_log_denied(self):
  run,jobs,arts,summary=fixture()
  r=acquire(run,jobs,arts,summary,logs=b"")
  self.assertIn("ORIGINAL_JOB_LOG_NOT_OBSERVED",r["blockers"])
 def test_expired_artifact_denied(self):
  run,jobs,arts,summary=fixture();arts[0]["expired"]=True
  self.assertIn("ARTIFACT_EXPIRED_OR_UNKNOWN",acquire(run,jobs,arts,summary)["blockers"])
 def test_wrong_artifact_ancestry(self):
  run,jobs,arts,summary=fixture();arts[0]["workflow_run"]["id"]=9
  self.assertIn("ARTIFACT_ANCESTRY_CONFLICT",acquire(run,jobs,arts,summary)["blockers"])
 def test_actual_failed_rust_step_preserved(self):
  run,jobs,arts,summary=fixture()
  jobs[0]["steps"]=[{"name":"Rust source regression","conclusion":"failure"}]
  r=acquire(run,jobs,arts,summary)
  self.assertEqual(r["actual_failed_steps"],[{"name":"Rust source regression","conclusion":"failure"}])
 def test_duplicate_artifact_rejected(self):
  run,jobs,arts,summary=fixture();arts.append(dict(arts[0],id=1999))
  self.assertIn("REQUIRED_ARTIFACT_NOT_UNIQUE",acquire(run,jobs,arts,summary)["blockers"])
 def test_page_cap_denied(self):
  items,state,page=m.listing("path","jobs",fetch=lambda _:{"jobs":[{"id":x} for x in range(1,101)]})
  self.assertEqual((items,state,page),([],"PAGE_CAP_REACHED",10))
 def test_duplicate_page_id_denied(self):
  items,state,page=m.listing("path","jobs",fetch=lambda _:{"jobs":[{"id":1},{"id":1}]})
  self.assertEqual(state,"INVALID_OR_DUPLICATE_ID")
 def test_wrong_sha_denied(self):
  run,jobs,arts,summary=fixture();run["head_sha"]="b"*40
  r=acquire(run,jobs,arts,summary)
  self.assertIn("EXACT_RUN_NOT_FOUND",r["blockers"])
 def test_log_sha_is_original_bytes(self):
  run,jobs,arts,summary=fixture()
  raw=b"Authorization: secret-value\nPASS"
  r=acquire(run,jobs,arts,summary,raw)
  self.assertEqual(r["job_log"]["sha256"],m.digest(raw))
  self.assertNotIn("secret-value",r["job_log"]["redacted_excerpt"])
 def test_malformed_zip_denied(self):
  run,jobs,arts,summary=fixture()
  self.assertEqual(m.inspect_zip(b"not a zip",run,arts[0])["state"],"ZIP_CORRUPT")
 def test_duplicate_zip_member_denied(self):
  run,jobs,arts,summary=fixture()
  b=io.BytesIO()
  with zipfile.ZipFile(b,"w") as z:
   for name in m.MEMBERS:z.writestr(name,json.dumps(summary))
   z.writestr("193-summary.json","{}")
  self.assertEqual(m.inspect_zip(b.getvalue(),run,arts[0])["state"],"ZIP_MEMBER_SET_CONFLICT")
 def test_boolean_attempt_denied(self):
  run,jobs,arts,summary=fixture();run["run_attempt"]=True
  self.assertIn("MALFORMED_RUN_ATTEMPT",acquire(run,jobs,arts,summary)["blockers"])
if __name__=="__main__":unittest.main()
