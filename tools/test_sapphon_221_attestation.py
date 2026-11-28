#!/usr/bin/env python3
"""SAPPHON-221 signed fixture checks. Local signer is NOT external witness."""
import base64,pathlib,subprocess,tempfile,unittest
import sapphon_221_attestation as m
def fixture():
 p={"schema":"sapphon-221-custody-attestation-v1","manifest_sha256":m.MANIFEST_SHA,
    "source_run":m.SOURCE_RUN,"source_attempt":m.SOURCE_ATTEMPT,
    "source_commit":m.SOURCE_COMMIT,"custodian_root":"external-root-one",
    "sequence":1,"previous_receipt_sha256":None,"claimed_utc":"2026-11-28T10:00:00Z",
    "observed_image_sha256":m.EXPECTED_IMAGE_SHA}
 return {"payload":p,"public_key_pem":"","signature_base64":"",
         "recovery_authorized":False,"lock_cleared":False}
def sign(r):
 with tempfile.TemporaryDirectory() as d:
  x=pathlib.Path(d);key=x/"key.pem";pub=x/"pub.pem";data=x/"data";sig=x/"sig"
  subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(key)],check=True,stdout=subprocess.DEVNULL)
  subprocess.run(["openssl","pkey","-in",str(key),"-pubout","-out",str(pub)],check=True,stdout=subprocess.DEVNULL)
  data.write_bytes(m.canonical(r["payload"]))
  subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(key),"-rawin","-in",str(data),"-out",str(sig)],check=True)
  r["public_key_pem"]=pub.read_text()
  r["signature_base64"]=base64.b64encode(sig.read_bytes()).decode()
 return r
class Tests(unittest.TestCase):
 def test_signed_receipt_still_hold(self):
  r=m.assess(sign(fixture()))
  self.assertTrue(r["signature_valid"])
  self.assertEqual(r["state"],"CRYPTOGRAPHIC_SIGNATURE_VALID_CUSTODY_HOLD")
  self.assertEqual(r["independently_authenticated_witnesses"],0)
  self.assertFalse(r["recovery_authorized"])
 def test_mutated_manifest_signature_fails(self):
  r=sign(fixture());r["payload"]["manifest_sha256"]="0"*64
  self.assertFalse(m.assess(r)["signature_valid"])
 def test_mutated_counter_signature_fails(self):
  r=sign(fixture());r["payload"]["sequence"]=2
  self.assertFalse(m.assess(r)["signature_valid"])
 def test_missing_signature_fails(self):
  self.assertFalse(m.assess(fixture())["signature_valid"])
 def test_wrong_source_denied(self):
  r=sign(fixture());r["payload"]["source_run"]="4"
  self.assertIn("SOURCE_ANCESTRY_MISMATCH",m.assess(r)["blockers"])
 def test_false_recovery_claim_denied(self):
  r=sign(fixture());r["recovery_authorized"]=True
  self.assertIn("UNSAFE_AUTHORITY_CLAIM",m.assess(r)["blockers"])
 def test_bogus_root_denied(self):
  r=fixture();r["payload"]["custodian_root"]="github";r=sign(r)
  self.assertIn("CLAIMED_CUSTODIAN_ROOT_INVALID",m.assess(r)["blockers"])
 def test_claimed_utc_does_not_authenticate_time(self):
  self.assertFalse(m.assess(sign(fixture()))["authenticated_utc"])
 def test_rollback_link_not_authenticated(self):
  self.assertFalse(m.assess(sign(fixture()))["global_anti_rollback_authenticated"])
if __name__=="__main__":unittest.main()
