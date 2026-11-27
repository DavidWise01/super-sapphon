#!/usr/bin/env python3
"""SAPPHON-190 adversarial enrollment preflight; synthetic receipt only."""
import importlib.util,pathlib,base64,hashlib,unittest
path=pathlib.Path(__file__).with_name("sapphon_190_enrollment.py")
spec=importlib.util.spec_from_file_location("e190",path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def registry():return {"schema":"sapphon-190-key-registry-v1",
 "out_of_band_authenticated":False,"keys":[],"authority_source":"none"}
def receipt():
 key=b"k"*32
 return {"schema":"sapphon-190-custody-receipt-v1","source_sha":m.SOURCE,
  "workflow":m.WORKFLOW,"run_id":189,"attempt":1,"root_sha256":"a"*64,
  "custodian_id":"external-claim","public_key_b64":base64.b64encode(key).decode(),
  "key_fingerprint_sha256":hashlib.sha256(key).hexdigest(),"nonce_hex":"b"*64,
  "sequence":1,"signature_b64":base64.b64encode(b"s"*64).decode(),
  "previous_receipt_sha256":"0"*64,"recovery_authorized":False}
class Tests(unittest.TestCase):
 def test_empty_is_zero_independents(self):
  r=m.verify([],registry());self.assertEqual(r["independent_witnesses"],0)
  self.assertFalse(r["external_custody_authenticated"])
 def test_valid_shape_not_authentication(self):
  r=m.verify([receipt()],registry())
  self.assertEqual(r["findings"],["UNENROLLED_KEY:0"])
  self.assertFalse(r["cryptographic_signatures_verified"])
 def test_self_issued_key_rejected(self):
  reg=registry();reg["keys"]=[{"public_key_b64":receipt()["public_key_b64"]}]
  with self.assertRaisesRegex(ValueError,"EXTERNAL_ENROLLMENT_NOT_AUTHORIZED"):m.verify([receipt()],reg)
 def test_forged_out_of_band_rejected(self):
  reg=registry();reg["out_of_band_authenticated"]=True
  with self.assertRaisesRegex(ValueError,"UNVERIFIED_EXTERNAL_AUTHENTICATION"):m.verify([],reg)
 def test_replayed_nonce_rejected(self):
  r=m.verify([receipt(),receipt()],registry())
  self.assertIn("REPLAYED_RECEIPT:1",r["findings"])
 def test_new_signature_same_nonce_still_replay(self):
  x=receipt();y=receipt();y["signature_b64"]=base64.b64encode(b"t"*64).decode()
  self.assertIn("REPLAYED_RECEIPT:1",m.verify([x,y],registry())["findings"])
 def test_wrong_root_rejected(self):
  x=receipt();x["root_sha256"]="n"*64
  self.assertIn("ROOT_DIGEST:0",m.verify([x],registry())["findings"])
 def test_invalid_key_rejected(self):
  x=receipt();x["public_key_b64"]="not-base64"
  self.assertIn("KEY_OR_SIGNATURE_SHAPE:0",m.verify([x],registry())["findings"])
 def test_wrong_fingerprint_rejected(self):
  x=receipt();x["key_fingerprint_sha256"]="c"*64
  self.assertIn("KEY_FINGERPRINT:0",m.verify([x],registry())["findings"])
 def test_wrong_source_rejected(self):
  x=receipt();x["source_sha"]="a"*40
  self.assertIn("ANCESTRY:0",m.verify([x],registry())["findings"])
 def test_boolean_attempt_rejected(self):
  x=receipt();x["attempt"]=True
  self.assertIn("IDENTITY:0",m.verify([x],registry())["findings"])
 def test_forged_recovery_rejected(self):
  x=receipt();x["recovery_authorized"]=True
  self.assertIn("FORGED_RECOVERY:0",m.verify([x],registry())["findings"])
 def test_nonce_missing_rejected(self):
  x=receipt();x["nonce_hex"]=""
  self.assertIn("NONCE_INVALID:0",m.verify([x],registry())["findings"])
 def test_wrong_predecessor_digest_rejected(self):
  x=receipt();x["previous_receipt_sha256"]="bad"
  self.assertIn("PREDECESSOR_DIGEST:0",m.verify([x],registry())["findings"])
 def test_unknown_field_rejected(self):
  x=receipt();x["independent_witnesses"]=3
  self.assertIn("FIELDS:0",m.verify([x],registry())["findings"])
 def test_key_surface_cannot_be_called_external(self):
  x=receipt();reg=registry();reg["authority_source"]="github"
  with self.assertRaisesRegex(ValueError,"INVALID_AUTHORITY_SOURCE"):m.verify([x],reg)
if __name__=="__main__":unittest.main()
