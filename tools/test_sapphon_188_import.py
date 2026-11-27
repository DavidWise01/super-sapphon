#!/usr/bin/env python3
"""SAPPHON-188: synthetic in-memory prior-ledger import and provenance tests."""
import importlib.util,io,json,pathlib,unittest,zipfile
p=pathlib.Path(__file__).with_name("sapphon_188_import.py")
sp=importlib.util.spec_from_file_location("i188",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def fixture():
 row={"source_sha":m.legacy.SOURCE,"workflow":m.legacy.WORKFLOW,
  "run_id":186,"attempt":1,"state":"OBSERVED","artifact_id":186,
  "artifact_name":m.legacy.ARTIFACT,"original_zip_sha256":"a"*64,
  "embedded_run_id":186,"embedded_attempt":1,
  "external_custody_authenticated":False,"recovery_authorized":False}
 ledger=m.legacy.append([],row)
 chain=m.legacy.chain(ledger)
 summary={"schema":"sapphon-187-owned-run-v1","commit":m.SOURCE,
  "run_id":"187","attempt":"2","cross_run_continuity_verified":False,
  "recovery_authorized":False}
 adjudication=dict(chain,schema="sapphon-187-adjudication-v1")
 contents={"187-summary.json":summary,
  "187-adjudication.json":adjudication,"187-observation.json":{"status":"SOURCE_OWNED_BYTES_OBSERVED"},
  "187-evidence-ledger.jsonl":m.canonical(ledger[0]).decode()+"\n"}
 run={"id":187,"run_attempt":2,"head_sha":m.SOURCE,"status":"completed"}
 artifact={"id":188,"name":m.ARTIFACT,"expired":False}
 return contents,run,artifact
def zipof(contents):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as z:
  for name,value in contents.items():z.writestr(name,value if isinstance(value,str) else json.dumps(value))
 return b.getvalue()
class Tests(unittest.TestCase):
 def test_matching_previous_ledger_is_owned_only(self):
  c,r,a=fixture();x=m.inspect(zipof(c),r,a)
  self.assertEqual(x["status"],"IMPORTED_OWNED_SOURCE_CHAIN")
  self.assertFalse(x["transition"]["independent_custody_authenticated"])
 def test_prior_artifact_missing_ledger(self):
  c,r,a=fixture();c.pop("187-evidence-ledger.jsonl")
  self.assertEqual(m.inspect(zipof(c),r,a)["status"],"PREDECESSOR_LEDGER_NOT_PRESENT")
 def test_tampered_history_rejected(self):
  c,r,a=fixture();x=json.loads(c["187-evidence-ledger.jsonl"])
  x["envelope"]["observation"]["artifact_id"]=999
  c["187-evidence-ledger.jsonl"]=json.dumps(x)+"\n"
  self.assertEqual(m.inspect(zipof(c),r,a)["status"],"PREDECESSOR_CHAIN_INVALID")
 def test_substituted_run_rejected(self):
  c,r,a=fixture();r["run_attempt"]=3
  self.assertEqual(m.inspect(zipof(c),r,a)["status"],"PREDECESSOR_ANCESTRY_OR_ATTEMPT_MISMATCH")
 def test_wrong_chain_tip_rejected(self):
  c,r,a=fixture();c["187-adjudication.json"]["tip_sha256"]="b"*64
  self.assertEqual(m.inspect(zipof(c),r,a)["status"],"PREDECESSOR_TIP_OR_COUNT_MISMATCH")
 def test_wrong_count_rejected(self):
  c,r,a=fixture();c["187-adjudication.json"]["entries"]=42
  self.assertEqual(m.inspect(zipof(c),r,a)["status"],"PREDECESSOR_TIP_OR_COUNT_MISMATCH")
 def test_unauthorized_summary_rejected(self):
  c,r,a=fixture();c["187-summary.json"]["recovery_authorized"]=True
  self.assertEqual(m.inspect(zipof(c),r,a)["status"],"UNAUTHORIZED_PREDECESSOR_CLAIM")
 def test_duplicate_zip_member_rejected(self):
  c,r,a=fixture();b=io.BytesIO()
  with zipfile.ZipFile(b,"w") as z:
   for n,v in c.items():z.writestr(n,v if isinstance(v,str) else json.dumps(v))
   z.writestr("187-summary.json","{}")
  self.assertEqual(m.inspect(b.getvalue(),r,a)["status"],"DUPLICATE_ZIP_MEMBER")
 def test_expired_not_authenticated_deletion(self):
  c,r,a=fixture();a["expired"]=True
  def fetch(path):
   if "/workflows/" in path:return {"workflow_runs":[r]}
   return {"artifacts":[a]}
  self.assertEqual(m.acquire(fetch,lambda _:zipof(c))["status"],"PRIOR_ARTIFACT_EXPIRED")
 def test_missing_artifact_not_chain_tampering(self):
  c,r,a=fixture()
  def fetch(path):
   if "/workflows/" in path:return {"workflow_runs":[r]}
   return {"artifacts":[]}
  self.assertEqual(m.acquire(fetch,lambda _:zipof(c))["status"],"PRIOR_ARTIFACT_MISSING_OR_AMBIGUOUS")
 def test_incomplete_run_page(self):
  c,r,a=fixture()
  self.assertEqual(m.acquire(lambda _:{"workflow_runs":[{"id":i+1} for i in range(100)]})["status"],"RUN_LISTING_PAGE_CAP")
 def test_wrong_artifact_ancestry(self):
  c,r,a=fixture();a["workflow_run"]={"id":987,"head_sha":m.SOURCE}
  def fetch(path):
   if "/workflows/" in path:return {"workflow_runs":[r]}
   return {"artifacts":[a]}
  self.assertEqual(m.acquire(fetch,lambda _:zipof(c))["status"],"ARTIFACT_SOURCE_CONFLICT")
if __name__=="__main__":unittest.main()
