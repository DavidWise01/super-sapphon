#!/usr/bin/env python3
"""SAPPHON-181 tests: safe ZIP inspection, never extraction."""
import importlib.util,io,json,pathlib,unittest,zipfile
p=pathlib.Path(__file__).with_name("sapphon_181_zip.py")
spec=importlib.util.spec_from_file_location("z181",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def makezip(items):
 b=io.BytesIO()
 with zipfile.ZipFile(b,"w",compression=zipfile.ZIP_DEFLATED) as f:
  for name,body in items:f.writestr(name,body)
 return b.getvalue()
def fixture():
 summary={"schema":"sapphon-180-owned-source-evidence-v1",
  "commit":m.SOURCE,"run_id":"180","attempt":"1",
  "recovery_authorized":False,"lock_cleared":False}
 zipbytes=makezip([("180-summary.json",json.dumps(summary))])
 metadata={"source_sha":m.SOURCE,"workflow":m.WORKFLOW,"job_name":m.JOB,
  "artifact_name":m.ARTIFACT,"run_id":180,"attempt":1,"job_id":777,
  "artifact_id":888,"artifact_expired":False,"recovery_authorized":False,
  "artifact_sha256":m.sha(zipbytes)}
 return zipbytes,metadata
class Tests(unittest.TestCase):
 def test_consistent_zip_still_hold(self):
  b,d=fixture();r=m.inspect_zip(b,d)
  self.assertTrue(r["source_owned_zip_consistent"])
  self.assertFalse(r["recovery_authorized"])
  self.assertFalse(r["bytes_extracted_to_disk"])
 def test_digest_tamper(self):
  b,d=fixture();d["artifact_sha256"]="0"*64
  self.assertIn("ORIGINAL_ZIP_HASH_MISMATCH",m.inspect_zip(b,d)["findings"])
 def test_wrong_source(self):
  b,d=fixture();d["source_sha"]="a"*40
  self.assertIn("WRONG_SOURCE_WORKFLOW_JOB",m.inspect_zip(b,d)["findings"])
 def test_wrong_attempt(self):
  b,d=fixture();d["attempt"]=2
  self.assertIn("SUMMARY_IDENTITY_MISMATCH",m.inspect_zip(b,d)["findings"])
 def test_zip_traversal(self):
  b,d=fixture();b=makezip([("../unsafe",b"a"),("180-summary.json",b"{}")]);d["artifact_sha256"]=m.sha(b)
  self.assertIn("UNSAFE_PATH_OR_DIRECTORY",m.inspect_zip(b,d)["findings"])
 def test_absolute_path(self):
  b,d=fixture();b=makezip([("/tmp/evil",b"x")]);d["artifact_sha256"]=m.sha(b)
  self.assertIn("UNSAFE_PATH_OR_DIRECTORY",m.inspect_zip(b,d)["findings"])
 def test_duplicate_entry(self):
  b,d=fixture();b=makezip([("180-summary.json",b"{}"),("180-summary.json",b"{}")]);d["artifact_sha256"]=m.sha(b)
  self.assertIn("DUPLICATE_ENTRY",m.inspect_zip(b,d)["findings"])
 def test_missing_summary(self):
  b,d=fixture();b=makezip([("something.json",b"{}")]);d["artifact_sha256"]=m.sha(b)
  self.assertIn("SUMMARY_NOT_UNIQUE",m.inspect_zip(b,d)["findings"])
 def test_invalid_zip(self):
  b,d=fixture();b=b"bad";d["artifact_sha256"]=m.sha(b)
  self.assertTrue(any("ZIP_DECODE_FAILURE" in x for x in m.inspect_zip(b,d)["findings"]))
 def test_oversized_entry(self):
  b,d=fixture();b=makezip([("too-large",b"x"*(m.MAX_ITEM+1))]);d["artifact_sha256"]=m.sha(b)
  self.assertIn("ITEM_TOO_LARGE",m.inspect_zip(b,d)["findings"])
 def test_expired(self):
  b,d=fixture();d["artifact_expired"]=True
  self.assertIn("ARTIFACT_EXPIRED_UNKNOWN",m.inspect_zip(b,d)["findings"])
 def test_forged_recovery(self):
  b,d=fixture();d["recovery_authorized"]=True
  self.assertIn("FORGED_AUTHORITY",m.inspect_zip(b,d)["findings"])
if __name__=="__main__":unittest.main()
