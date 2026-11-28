#!/usr/bin/env python3
"""SAPPHON-220 negative controls: declaration != independent evidence."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_220_custody_handoff.py")
s=importlib.util.spec_from_file_location("s220",p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def fixture():
 return {"schema":"sapphon-220-external-receipt-v1","manifest_sha256":m.handoff()["manifest_sha256"],"source_run":m.RUN,"source_attempt":"1","source_commit":m.COMMIT,"sha256":m.HASHES.copy(),"custodian_root":"external-origin","signature":"unverified","authenticated_utc_evidence":"unverified","external_anti_rollback_evidence":"unverified","recovery_authorized":False,"lock_cleared":False}
class Cases(unittest.TestCase):
 def test_manifest_deterministic(self):
  x=m.handoff().copy();h=x.pop("manifest_sha256");self.assertEqual(m.hash_obj(x),h)
 def test_missing_receipt_hold(self):self.assertEqual(m.review({})["decision"],"HOLD")
 def test_full_declared_receipt_not_a_witness(self):
  x=m.review(fixture());self.assertEqual(x["independently_authenticated_witnesses"],0);self.assertEqual(x["blockers"],["EXTERNAL_AUTHENTICATION_UNVERIFIED"])
 def test_wrong_run(self):
  x=fixture();x["source_run"]="1";self.assertIn("RUN_ANCESTRY",m.review(x)["blockers"])
 def test_wrong_image_hash(self):
  x=fixture();x["sha256"]["207-image.tar"]="0"*64;self.assertIn("FILE_HASH_PARITY",m.review(x)["blockers"])
 def test_wrong_manifest(self):
  x=fixture();x["manifest_sha256"]="0"*64;self.assertIn("MANIFEST_DIGEST",m.review(x)["blockers"])
 def test_owned_custodian_cannot_claim_independence(self):
  x=fixture();x["custodian_root"]="GitHub";self.assertIn("CUSTODIAN_ANCESTRY",m.review(x)["blockers"])
 def test_signature_absence(self):
  x=fixture();x.pop("signature");self.assertIn("MISSING_SIGNATURE",m.review(x)["blockers"])
 def test_utc_absence(self):
  x=fixture();x.pop("authenticated_utc_evidence");self.assertIn("MISSING_AUTHENTICATED_UTC_EVIDENCE",m.review(x)["blockers"])
 def test_recovery_claim(self):
  x=fixture();x["recovery_authorized"]=True;self.assertIn("UNSAFE_AUTHORITY_CLAIM",m.review(x)["blockers"])
if __name__=="__main__":unittest.main()
