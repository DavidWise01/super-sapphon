#!/usr/bin/env python3
"""SAPPHON-185 synthetic regression controls for bounded job pagination.

These tests are authored source, not proof of Actions execution.
"""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_171_job_logs.py")
s=importlib.util.spec_from_file_location("j185",p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
SHA="edb582df9db3873d2fe308d219ed30b412d1b06d"
def run(run_id=184):
 return {"id":run_id,"head_sha":SHA,"run_attempt":1,"status":"completed","conclusion":"success"}
class Tests(unittest.TestCase):
 def test_exact_matching_run(self):
  picked,state,page=m.paged_runs("sapphon-184-freeze.yml",SHA,api_call=lambda _:{"workflow_runs":[run()]})
  self.assertEqual((picked["id"],state,page),(184,"EXACT_RUN_OBSERVED",1))
 def test_invalid_matching_run_is_not_observed(self):
  for candidate in (dict(run(),id=True),dict(run(),run_attempt=0),dict(run(),id=None)):
   picked,state,_=m.paged_runs("sapphon-184-freeze.yml",SHA,api_call=lambda _,c=candidate:{"workflow_runs":[c]})
   self.assertIsNone(picked)
   self.assertEqual(state,"MALFORMED_MATCHING_RUN")
 def test_valid_run_paged_second_page(self):
  def api(path):
   if "page=1" in path:return {"workflow_runs":[run(i+1)|{"head_sha":"b"*40} for i in range(100)]}
   return {"workflow_runs":[run()]}
  picked,state,pages=m.paged_runs("sapphon-184-freeze.yml",SHA,api_call=api)
  self.assertEqual((picked["id"],state,pages),(184,"EXACT_RUN_OBSERVED",2))
 def test_second_page_job_is_present(self):
  def api(path):
   if "page=1" in path:return {"jobs":[{"id":i+1,"name":"unrelated"} for i in range(100)]}
   return {"jobs":[{"id":101,"name":"final-freeze","conclusion":"failure"}]}
  jobs,status,pages=m.paged_jobs(184,1,api_call=api)
  self.assertEqual(status,"JOB_PAGES_EXHAUSTED")
  self.assertEqual(pages,2)
  self.assertEqual(len(jobs),101)
  self.assertEqual(jobs[-1]["name"],"final-freeze")
 def test_page_cap_not_green(self):
  jobs,status,page=m.paged_jobs(184,1,max_pages=2,
   api_call=lambda _:{"jobs":[{"id":i+1} for i in range(100)]})
  self.assertEqual((jobs,status,page),([],"JOB_PAGE_CAP_REACHED",2))
 def test_invalid_page_not_green(self):
  jobs,status,_=m.paged_jobs(184,1,api_call=lambda _:{"jobs":None})
  self.assertEqual((jobs,status),([],"MALFORMED_JOB_PAGE"))
 def test_boolean_run_id_rejected(self):
  jobs,status,_=m.paged_jobs(True,1)
  self.assertEqual((jobs,status),([],"INVALID_RUN_IDENTITY"))
 def test_boolean_attempt_rejected(self):
  jobs,status,_=m.paged_jobs(184,True)
  self.assertEqual((jobs,status),([],"INVALID_RUN_IDENTITY"))
 def test_failed_child_on_page_two_rejects_green_parent(self):
  def api(path):
   if "page=1" in path:return {"jobs":[{"id":i+1,"name":"other","conclusion":"success","steps":[{"name":"ok","conclusion":"success"}]} for i in range(100)]}
   return {"jobs":[{"id":101,"name":"final-freeze","conclusion":"failure","steps":[{"name":"Rust all-target build and inherited tests","conclusion":"failure"}]}]}
  jobs,status,_=m.paged_jobs(184,1,api_call=api)
  finding=m.classify(run(),jobs,"final-freeze")
  self.assertEqual(status,"JOB_PAGES_EXHAUSTED")
  self.assertFalse(finding["source_owned_success_observed"])
  self.assertTrue(finding["failures"])
 def test_not_found_after_exhaustion(self):
  picked,status,pages=m.paged_runs("sapphon-184-freeze.yml",SHA,
   api_call=lambda _:{"workflow_runs":[]})
  self.assertEqual((picked,status,pages),(None,"NO_MATCHING_RUN_IN_EXHAUSTED_PAGES",1))
if __name__=="__main__":unittest.main()
