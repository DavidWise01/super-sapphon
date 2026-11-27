#!/usr/bin/env python3
"""SAPPHON-189: mocked genuine-artifact parsing; no invented hosted PASS."""
import importlib.util,io,json,pathlib,unittest,zipfile
path=pathlib.Path(__file__).with_name("sapphon_189_acquire.py")
spec=importlib.util.spec_from_file_location("acquire189",path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def fixture():
 r={"id":188,"run_attempt":2,"head_sha":m.SOURCE,"status":"completed"}
 a={"id":189,"name":m.ARTIFACT,"expired":False}
 imp={"schema":"sapphon-188-import-result-v1","status":"IMPORTED_OWNED_SOURCE_CHAIN",
  "prior_tip_sha256":"a"*64,"prior_records":1}
 summary={"schema":"sapphon-188-owned-outcomes-v1","commit":m.SOURCE,
  "run_id":"188","attempt":"2","recovery_authorized":False,
  "external_custody_authenticated":False}
 trans={"schema":"sapphon-188-import-transition-v1",
  "prior_ledger_tip_sha256":"a"*64,"prior_ledger_entries":1,
  "independent_custody_authenticated":False,"recovery_authorized":False}
 return r,a,{"188-summary.json":summary,"188-import.json":imp,"188-transition.json":trans}
def zipped(items):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w") as z:
  for k,v in items.items():z.writestr(k,json.dumps(v))
 return b.getvalue()
class Tests(unittest.TestCase):
 def test_consistent_owned_root_not_independent(self):
  r,a,items=fixture();o=m.inspect(zipped(items),r,a)
  self.assertEqual(o["status"],"ONE_OWNED_ROOT_OBSERVED")
  self.assertFalse(o["claims"][0]["independently_authenticated"])
 def test_conflicting_roots_rejected(self):
  r,a,items=fixture();items["188-import.json"]["prior_tip_sha256"]="b"*64
  self.assertEqual(m.inspect(zipped(items),r,a)["status"],"INTRA_ARTIFACT_ROOT_CONFLICT")
 def test_wrong_attempt_rejected(self):
  r,a,items=fixture();r["run_attempt"]=3
  self.assertEqual(m.inspect(zipped(items),r,a)["status"],"ATTEMPT_SUBSTITUTION")
 def test_missing_transition_rejected(self):
  r,a,items=fixture();items.pop("188-transition.json")
  self.assertEqual(m.inspect(zipped(items),r,a)["status"],"MISSING_TRANSITION")
 def test_missing_predecessor_does_not_create_root(self):
  r,a,items=fixture();items.pop("188-transition.json")
  items["188-import.json"]["status"]="PRIOR_ARTIFACT_EXPIRED"
  o=m.inspect(zipped(items),r,a)
  self.assertEqual(o["status"],"PREDECESSOR_IMPORT_NOT_OBSERVED")
  self.assertEqual(o["claims"],[])
 def test_forged_summary_custody_rejected(self):
  r,a,items=fixture();items["188-summary.json"]["external_custody_authenticated"]=True
  self.assertEqual(m.inspect(zipped(items),r,a)["status"],"FORGED_SUMMARY_AUTHORITY")
 def test_bad_source_rejected(self):
  r,a,items=fixture();items["188-summary.json"]["commit"]="b"*40
  self.assertEqual(m.inspect(zipped(items),r,a)["status"],"RUN_SOURCE_CONFLICT")
 def test_duplicate_archive_member_rejected(self):
  r,a,items=fixture();b=io.BytesIO()
  with zipfile.ZipFile(b,"w") as z:
   for k,v in items.items():z.writestr(k,json.dumps(v))
   z.writestr("188-summary.json","{}")
  self.assertEqual(m.inspect(b.getvalue(),r,a)["status"],"UNEXPECTED_ZIP_FILES")
 def test_expired_artifact_stays_missing(self):
  r,a,items=fixture();a["expired"]=True
  def get(path):return {"workflow_runs":[r]} if "/workflows/" in path else {"artifacts":[a]}
  self.assertEqual(m.acquire(get,lambda _:zipped(items))["status"],"ARTIFACT_EXPIRED")
if __name__=="__main__":unittest.main()
