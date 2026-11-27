#!/usr/bin/env python3
"""SAPPHON-187 acquisition fixtures only; not GitHub execution claims."""
import importlib.util,pathlib,io,json,zipfile,unittest
p=pathlib.Path(__file__).with_name("sapphon_187_acquire.py")
sp=importlib.util.spec_from_file_location("acq187",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def sample():
 r={"id":186,"head_sha":m.l187.SOURCE,"run_attempt":2,"status":"completed"}
 a={"id":187,"name":m.l187.ARTIFACT,"expired":False}
 b=io.BytesIO()
 summary={"schema":"sapphon-186-source-diagnostics-v1",
  "commit":m.l187.SOURCE,"run_id":"186","attempt":"2",
  "recovery_authorized":False,"lock_cleared":False}
 with zipfile.ZipFile(b,"w") as z:
  z.writestr("186-summary.json",json.dumps(summary))
  z.writestr("186-attempts.json",json.dumps({"recovery_authorized":False}))
 return r,a,b.getvalue()
def inspect(runs,arts,raw):
 def call(path):
  if "/workflows/" in path:return {"workflow_runs":runs}
  if "/artifacts" in path:return {"artifacts":arts}
  raise ValueError(path)
 return m.observe(call,lambda _:raw)
class Tests(unittest.TestCase):
 def test_matching_attempt_observed_not_external(self):
  r,a,raw=sample();x=inspect([r],[a],raw)
  self.assertEqual(x["status"],"SOURCE_OWNED_BYTES_OBSERVED")
  self.assertEqual(x["event"]["embedded_attempt"],2)
  self.assertFalse(x["event"]["recovery_authorized"])
 def test_expired_not_deleted(self):
  r,a,raw=sample();a["expired"]=True
  x=inspect([r],[a],raw)
  self.assertEqual(x["event"]["state"],"EXPIRED")
 def test_not_found_not_deleted(self):
  r,a,raw=sample();x=inspect([r],[],raw)
  self.assertEqual(x["event"]["state"],"NOT_FOUND_IN_EXHAUSTED_LISTING")
 def test_wrong_attempt_zip_denied(self):
  r,a,raw=sample();r["run_attempt"]=3
  self.assertEqual(inspect([r],[a],raw)["status"],"ZIP_ATTEMPT_MISMATCH")
 def test_missing_run_is_not_deleted(self):
  r,a,raw=sample()
  self.assertEqual(inspect([],[a],raw)["status"],"NO_MATCHING_RUN_IN_EXHAUSTED_LISTING")
 def test_duplicate_named_artifact_rejected(self):
  r,a,raw=sample()
  self.assertEqual(inspect([r],[a,dict(a,id=188)],raw)["status"],"AMBIGUOUS_ARTIFACT")
 def test_unknown_expiry_unverified(self):
  r,a,raw=sample();a.pop("expired")
  self.assertEqual(inspect([r],[a],raw)["event"]["state"],"READBACK_UNAVAILABLE")
 def test_wrong_source_run_ignored(self):
  r,a,raw=sample();r["head_sha"]="b"*40
  self.assertEqual(inspect([r],[a],raw)["status"],"NO_MATCHING_RUN_IN_EXHAUSTED_LISTING")
if __name__=="__main__":unittest.main()
