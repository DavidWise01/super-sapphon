#!/usr/bin/env python3
"""SAPPHON-201 deterministic fixtures: never claim original hosted execution."""
import importlib.util,io,json,pathlib,unittest,zipfile
p=pathlib.Path(__file__).with_name("sapphon_201_runner.py")
sp=importlib.util.spec_from_file_location("runner201",p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def fixture():
 run={"id":200,"head_sha":m.SOURCE,"run_attempt":2,"status":"completed","conclusion":"success"}
 names=list(m.CRITICAL.values())
 steps=[{"name":name,"conclusion":"success"} for name in names]
 job={"id":2011,"run_id":200,"run_attempt":2,"name":m.JOB,
      "conclusion":"success","steps":steps}
 artifact={"id":2012,"name":m.ARTIFACT,"expired":False,
           "workflow_run":{"id":200,"head_sha":m.SOURCE}}
 states={"PYTHON":"success","RUST":"success","FROZEN":"success",
         "RETENTION":"failure","PAGES":"not_observed","BROWSER":"not_observed"}
 freeze={"schema":"sapphon-200-phase-xix-source-freeze-v1",
         "source_head":m.SOURCE,"source_design_complete":True,
         "observed_outcomes":states,"recovery_authorized":False}
 summary={"schema":"sapphon-200-source-owned-run-v1","commit":m.SOURCE,
          "run_id":"200","attempt":"2","recovery_authorized":False,
          "source_design_complete":True,"source_tests_pass":True,
          "steps":{"PYTHON":"success","RUST":"success","FROZEN":"success",
                   "RETENTION":"failure","FREEZE":"success"}}
 contents={"200-freeze.json":freeze,"200-summary.json":summary,
           "200-outcomes.json":{"schema":"sapphon-200-outcomes-v1","outcomes":states},
           "200-retention.json":{"schema":"sapphon-199-retention-v1",
              "state":"EXACT_RUN_NOT_OBSERVED","deletion_confirmed":False}}
 return run,job,artifact,contents
def archive(contents):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w") as z:
  for name,value in contents.items():z.writestr(name,json.dumps(value))
 return b.getvalue()
def inspect(edit=lambda x:None):
 f=list(fixture());edit(f)
 run,job,art,content=f
 return m.observe(run,[job],[art],b"original hosted log",archive(content))
class Tests(unittest.TestCase):
 def test_source_owned_green_not_custody(self):
  x=inspect();self.assertEqual(x["state"],"SOURCE_OWNED_RUN_PASS")
  self.assertTrue(x["source_owned_runner_pass"])
  self.assertFalse(x["recovery_authorized"])
 def test_missing_original_log(self):
  r,j,a,c=fixture()
  x=m.observe(r,[j],[a],None,archive(c))
  self.assertFalse(x["original_bytes_complete"])
 def test_missing_zip(self):
  r,j,a,c=fixture()
  x=m.observe(r,[j],[a],b"log",None)
  self.assertEqual(x["original_zip_state"],"ZIP_NOT_OBSERVED")
 def test_rust_failure_is_observed(self):
  def edit(f):
   f[1]["steps"][1]["conclusion"]="failure"
   f[3]["200-summary.json"]["steps"]["RUST"]="failure"
   f[3]["200-summary.json"]["source_tests_pass"]=False
   f[3]["200-outcomes.json"]["outcomes"]["RUST"]="failure"
   f[3]["200-freeze.json"]["observed_outcomes"]["RUST"]="failure"
  x=inspect(edit);self.assertEqual(x["state"],"OBSERVED_FAILURE")
  self.assertEqual(x["observed_failed_steps"][0]["step"],"rust")
 def test_wrong_source_sha(self):
  x=inspect(lambda f:f[0].update(head_sha="a"*40))
  self.assertEqual(x["state"],"RUN_ANCESTRY_CONFLICT")
 def test_wrong_attempt(self):
  x=inspect(lambda f:f[1].update(run_attempt=4))
  self.assertEqual(x["state"],"JOB_ATTEMPT_CONFLICT")
 def test_duplicate_named_step(self):
  def edit(f):f[1]["steps"].append(dict(f[1]["steps"][0]))
  self.assertEqual(inspect(edit)["state"],"STEP_MISSING_OR_DUPLICATE")
 def test_missing_named_step(self):
  def edit(f):f[1]["steps"].pop()
  self.assertEqual(inspect(edit)["state"],"STEP_MISSING_OR_DUPLICATE")
 def test_false_green_parent_with_child_failure(self):
  def edit(f):
   f[1]["steps"][0]["conclusion"]="failure"
   f[3]["200-summary.json"]["steps"]["PYTHON"]="failure"
   f[3]["200-summary.json"]["source_tests_pass"]=False
   f[3]["200-outcomes.json"]["outcomes"]["PYTHON"]="failure"
   f[3]["200-freeze.json"]["observed_outcomes"]["PYTHON"]="failure"
  x=inspect(edit);self.assertFalse(x["source_owned_runner_pass"])
 def test_expired_artifact_denied(self):
  x=inspect(lambda f:f[2].update(expired=True))
  self.assertEqual(x["state"],"ARTIFACT_EXPIRED_OR_UNKNOWN")
 def test_wrong_artifact_ancestry(self):
  x=inspect(lambda f:f[2]["workflow_run"].update(id=12))
  self.assertEqual(x["state"],"ARTIFACT_ANCESTRY_CONFLICT")
 def test_forced_source_pass_claim_denied(self):
  x=inspect(lambda f:f[3]["200-summary.json"].update(source_tests_pass=False))
  self.assertEqual(x["original_zip_state"],"FALSE_SOURCE_PASS_CLAIM")
 def test_forged_retention_deletion_denied(self):
  x=inspect(lambda f:f[3]["200-retention.json"].update(deletion_confirmed=True))
  self.assertEqual(x["original_zip_state"],"RETENTION_AUTHORITY_CONFLICT")
 def test_wrong_freeze_sha_denied(self):
  x=inspect(lambda f:f[3]["200-freeze.json"].update(source_head="f"*40))
  self.assertEqual(x["original_zip_state"],"PHASE_FREEZE_ANCESTRY_CONFLICT")
 def test_conflicting_steps_denied(self):
  def edit(f):
   f[3]["200-summary.json"]["steps"]["RUST"]="failure"
   f[3]["200-summary.json"]["source_tests_pass"]=False
   f[3]["200-outcomes.json"]["outcomes"]["RUST"]="failure"
   f[3]["200-freeze.json"]["observed_outcomes"]["RUST"]="failure"
  x=inspect(edit);self.assertEqual(x["state"],"CHILD_STEP_OUTCOME_CONFLICT")
 def test_incomplete_job_no_pass(self):
  x=inspect(lambda f:f[0].update(status="in_progress"))
  self.assertEqual(x["state"],"RUN_INCOMPLETE")
if __name__=="__main__":unittest.main()
