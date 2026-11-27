#!/usr/bin/env python3
"""SAPPHON-186 bounded exhaustive pagination and attempt ancestry controls."""
import importlib.util,io,json,pathlib,unittest,zipfile
p=pathlib.Path(__file__).with_name("sapphon_186_attempts.py")
sp=importlib.util.spec_from_file_location("a186",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def records(attempt=2):
 run={"id":185,"head_sha":m.SOURCE,"run_attempt":attempt,"status":"completed","conclusion":"success"}
 job={"id":851,"name":m.JOB,"run_id":185,"run_attempt":attempt,"conclusion":"success"}
 artifact={"id":861,"name":m.ARTIFACT,"expired":False,"workflow_run":{"id":185,"head_sha":m.SOURCE}}
 summary={"schema":"sapphon-185-current-run-v1","commit":m.SOURCE,"run_id":"185",
  "attempt":str(attempt),"source_owned_tests_pass":True,"recovery_authorized":False,
  "lock_cleared":False}
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as z:
  for name in m.MEMBERS:
   z.writestr(name,json.dumps(summary if name=="185-summary.json" else {"status":"NOT_OBSERVED"}))
 return run,job,artifact,b.getvalue()
class Tests(unittest.TestCase):
 def test_matching_zip_still_hold(self):
  run,job,art,raw=records()
  r=m.review([run],[job],[art],raw)
  self.assertTrue(r["source_owned_evidence_consistent"])
  self.assertFalse(r["recovery_authorized"])
 def test_wrong_attempt_inside_zip(self):
  run,job,art,raw=records(1);new,_,_,_=records(2)
  r=m.review([new],[dict(job,run_attempt=2)],[art],raw)
  self.assertIn("ATTEMPT_IDENTITY_MISMATCH",r["findings"])
 def test_job_attempt_mismatch(self):
  run,job,art,raw=records()
  self.assertIn("JOB_ATTEMPT_CONFLICT",m.review([run],[dict(job,run_attempt=1)],[art],raw)["findings"])
 def test_artifact_wrong_run(self):
  run,job,art,raw=records();art["workflow_run"]["id"]=900
  self.assertIn("ARTIFACT_RUN_OR_SOURCE_CONFLICT",m.review([run],[job],[art],raw)["findings"])
 def test_duplicate_named_artifact(self):
  run,job,art,raw=records()
  self.assertIn("REQUIRED_ARTIFACT_NOT_UNIQUE",m.review([run],[job],[art,dict(art,id=1002)],raw)["findings"])
 def test_artifact_expired(self):
  run,job,art,raw=records();art["expired"]=True
  self.assertIn("ARTIFACT_INVALID_OR_EXPIRED",m.review([run],[job],[art],raw)["findings"])
 def test_no_original_zip(self):
  run,job,art,_=records()
  r=m.review([run],[job],[art])
  self.assertIn("ORIGINAL_ARTIFACT_ZIP_UNAVAILABLE",r["limitations"])
 def test_malformed_exact_run(self):
  run,_,_,_=records();run["run_attempt"]=True
  self.assertEqual(m.choose_run([run])[1],"MALFORMED_EXACT_RUN")
 def test_missing_run(self):
  self.assertEqual(m.choose_run([])[1],"EXACT_RUN_NOT_FOUND")
 def test_page_two_artifact(self):
  def call(path):
   if "page=1" in path:return {"artifacts":[{"id":i+1} for i in range(100)]}
   return {"artifacts":[{"id":101,"name":m.ARTIFACT}]}
  a,status,pages=m.paginate("dummy","artifacts",call)
  self.assertEqual((len(a),status,pages),(101,"EXHAUSTED",2))
 def test_page_cap_fail_closed(self):
  a,status,_=m.paginate("dummy","jobs",lambda _:{"jobs":[{"id":i+1} for i in range(100)]},limit=2)
  self.assertEqual(a,[])
  self.assertEqual(status,"PAGE_LIMIT_REACHED")
 def test_duplicate_page_ids_fail(self):
  def call(path):
   return {"jobs":[{"id":1},{"id":1}]}
  self.assertEqual(m.paginate("dummy","jobs",call)[1],"INVALID_OR_DUPLICATE_JOBS_ID")
 def test_malformed_page(self):
  self.assertEqual(m.paginate("dummy","jobs",lambda _:{"jobs":None})[1],"MALFORMED_JOBS_PAGE")
 def test_zip_missing_member(self):
  run,job,art,_=records()
  b=io.BytesIO()
  with zipfile.ZipFile(b,"w") as z:z.writestr("185-summary.json","{}")
  self.assertIn("ZIP_MEMBER_SET_MISMATCH",m.review([run],[job],[art],b.getvalue())["findings"])
 def test_two_runs_select_latest_attempt(self):
  first,job,art,raw=records(1)
  second=dict(first,run_attempt=2)
  self.assertEqual(m.choose_run([first,second])[0]["run_attempt"],2)
 def test_incomplete_run_not_selected(self):
  first,_,_,_=records();first["status"]="in_progress"
  self.assertEqual(m.choose_run([first])[1],"EXACT_RUN_INCOMPLETE")
if __name__=="__main__":unittest.main()
