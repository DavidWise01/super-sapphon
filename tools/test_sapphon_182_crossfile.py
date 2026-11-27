#!/usr/bin/env python3
"""SAPPHON-182: in-memory cross-file archive negative controls."""
import importlib.util,io,json,pathlib,unittest,zipfile
p=pathlib.Path(__file__).with_name("sapphon_182_crossfile.py")
sp=importlib.util.spec_from_file_location("s182",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def fixture():
 summary={"schema":"sapphon-180-owned-source-evidence-v1",
  "commit":m.SOURCE,"run_id":"180","attempt":"2",
  "source_owned_diagnostics_pass":True,
  "steps":{"PYTHON":"success","RUST":"success","FROZEN":"success"},
  "full_qualification":False,"recovery_authorized":False,"lock_cleared":False}
 binding={"schema":"sapphon-180-evidence-unavailable-v1",
  "status":"ORIGINAL_BYTES_NOT_SUPPLIED","binding_qualified":False,
  "recovery_authorized":False}
 preced={"schema":"sapphon-171-job-log-triage-v1",
  "expected_sha":m.PREDECESSOR,"workflow":"sapphon-179-replay.yml",
  "status":"READBACK_UNAVAILABLE","recovery_authorized":False,
  "independent_custody_authenticated":False}
 records=dict(zip(m.FILES,(summary,binding,preced)))
 meta={"source_sha":m.SOURCE,"workflow":m.WORKFLOW,
   "job_name":m.JOB,"artifact_name":m.ARTIFACT,
   "run_id":180,"attempt":2,"job_id":9,"artifact_id":11,
   "artifact_expired":False,"recovery_authorized":False}
 return records,meta
def encode(records):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w",compression=zipfile.ZIP_DEFLATED) as z:
  for name,v in records.items():z.writestr(name,json.dumps(v))
 return b.getvalue()
def evaluate(records=None,meta=None):
 if records is None or meta is None:
  a,b=fixture()
  if records is None:records=a
  if meta is None:meta=b
 body=encode(records);meta=dict(meta,artifact_sha256=m.sha(body))
 return m.verify(body,meta)
class CrossFile(unittest.TestCase):
 def test_complete_set_structurally_consistent_but_missing_evidence(self):
  r=evaluate();self.assertTrue(r["archive_records_structurally_consistent"])
  self.assertFalse(r["complete_predecessor_and_raw_byte_evidence"])
  self.assertFalse(r["recovery_authorized"])
 def test_missing_binding(self):
  d,x=fixture();d.pop("180-binding.json")
  self.assertIn("REQUIRED_FILE_SET_MISMATCH",evaluate(d,x)["findings"])
 def test_wrong_summary_commit(self):
  d,x=fixture();d["180-summary.json"]["commit"]="a"*40
  self.assertIn("SUMMARY_IDENTITY_CONFLICT",evaluate(d,x)["findings"])
 def test_wrong_attempt(self):
  d,x=fixture();x["attempt"]=3
  self.assertIn("SUMMARY_IDENTITY_CONFLICT",evaluate(d,x)["findings"])
 def test_false_test_pass(self):
  d,x=fixture();d["180-summary.json"]["steps"]["RUST"]="failure"
  self.assertIn("SUMMARY_FALSE_PASS",evaluate(d,x)["findings"])
 def test_forged_summary_authority(self):
  d,x=fixture();d["180-summary.json"]["recovery_authorized"]=True
  self.assertIn("SUMMARY_AUTHORITY_CONFLICT",evaluate(d,x)["findings"])
 def test_wrong_predecessor_sha(self):
  d,x=fixture();d["180-predecessor.json"]["expected_sha"]="b"*40
  self.assertIn("PREDECESSOR_ANCESTRY_CONFLICT",evaluate(d,x)["findings"])
 def test_invalid_predecessor_observation(self):
  d,x=fixture();d["180-predecessor.json"].update(status="EXACT_RUN_OBSERVED",observed={"head_sha":"a"*40,"run_id":5,"attempt":1})
  self.assertIn("PREDECESSOR_RUN_CONFLICT",evaluate(d,x)["findings"])
 def test_unknown_binding_schema(self):
  d,x=fixture();d["180-binding.json"]["schema"]="made-up"
  self.assertIn("BINDING_SCHEMA",evaluate(d,x)["findings"])
 def test_inconsistent_binding_claim(self):
  d,x=fixture();d["180-binding.json"]["binding_qualified"]=True
  self.assertIn("BINDING_UNAVAILABILITY_CONFLICT",evaluate(d,x)["findings"])
 def test_zip_traversal(self):
  d,x=fixture();d["../evil.json"]={}
  self.assertIn("UNSAFE_ARCHIVE_PATH",evaluate(d,x)["findings"])
 def test_duplicate_member(self):
  d,x=fixture();b=io.BytesIO()
  with zipfile.ZipFile(b,"w") as z:
   for n,v in d.items():z.writestr(n,json.dumps(v))
   z.writestr("180-summary.json","{}")
  x["artifact_sha256"]=m.sha(b.getvalue())
  self.assertIn("DUPLICATE_ARCHIVE_PATH",m.verify(b.getvalue(),x)["findings"])
 def test_wrong_digest(self):
  d,x=fixture();b=encode(d);x["artifact_sha256"]="0"*64
  self.assertIn("ARTIFACT_DIGEST_MISMATCH",m.verify(b,x)["findings"])
 def test_successful_predecessor_and_binding_can_have_complete_source_owned_evidence(self):
  d,x=fixture()
  d["180-binding.json"]={"schema":"sapphon-180-artifact-binding-v1",
   "source_sha":m.PREDECESSOR,"workflow":"sapphon-179-replay.yml",
   "source_owned_binding_consistent":True,"findings":[],
   "recovery_authorized":False,"lock_cleared":False}
  d["180-predecessor.json"].update(status="EXACT_RUN_OBSERVED",
   observed={"head_sha":m.PREDECESSOR,"run_id":179,"attempt":1})
  r=evaluate(d,x)
  self.assertTrue(r["complete_predecessor_and_raw_byte_evidence"])
  self.assertFalse(r["independent_custody_authenticated"])
if __name__=="__main__":unittest.main()
