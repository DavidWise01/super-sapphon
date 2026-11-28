#!/usr/bin/env python3
"""SAPPHON-222 signer/anchor fixtures never count as independent witnesses."""
import base64,hashlib,importlib.util,pathlib,subprocess,tempfile,unittest
import sapphon_221_attestation as signed
p=pathlib.Path(__file__).with_name("sapphon_222_external_anchor.py")
s=importlib.util.spec_from_file_location("s222",p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def sample():
 payload={"schema":"sapphon-221-custody-attestation-v1",
 "manifest_sha256":signed.MANIFEST_SHA,"source_run":signed.SOURCE_RUN,
 "source_attempt":signed.SOURCE_ATTEMPT,"source_commit":signed.SOURCE_COMMIT,
 "custodian_root":"external-demo-1","sequence":1,"previous_receipt_sha256":None,
 "claimed_utc":"2026-11-28T12:00:00Z","observed_image_sha256":signed.EXPECTED_IMAGE_SHA}
 with tempfile.TemporaryDirectory() as tmp:
  d=pathlib.Path(tmp);priv=d/"key";pub=d/"pub";data=d/"msg";sig=d/"sig"
  subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(priv)],check=True,stdout=subprocess.DEVNULL)
  subprocess.run(["openssl","pkey","-in",str(priv),"-pubout","-out",str(pub)],check=True,stdout=subprocess.DEVNULL)
  data.write_bytes(signed.canonical(payload))
  subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(priv),"-rawin","-in",str(data),"-out",str(sig)],check=True,stdout=subprocess.DEVNULL)
  pem=pub.read_text()
  receipt={"payload":payload,"public_key_pem":pem,
    "signature_base64":base64.b64encode(sig.read_bytes()).decode(),
    "recovery_authorized":False,"lock_cleared":False}
  anchor={"public_key_pem":pem,"key_sha256":hashlib.sha256(pem.encode()).hexdigest(),
    "custodian_root":"external-demo-1","provisioning_channel":"out-of-band-declared"}
 return receipt,anchor
class Tests(unittest.TestCase):
 def test_anchored_signature_is_still_hold(self):
  r,a=sample();v=m.assess(r,a)
  self.assertTrue(v["anchored_signature_valid"])
  self.assertEqual(v["independently_authenticated_witnesses"],0)
  self.assertFalse(v["recovery_authorized"])
 def test_missing_anchor(self):
  r,_=sample();self.assertIn("EXTERNAL_KEY_ANCHOR_MISSING_OR_MISMATCH",m.assess(r)["blockers"])
 def test_incorrect_anchor_hash(self):
  r,a=sample();a["key_sha256"]="0"*64
  self.assertIn("EXTERNAL_KEY_ANCHOR_MISSING_OR_MISMATCH",m.assess(r,a)["blockers"])
 def test_github_provisioning_not_independent(self):
  r,a=sample();a["provisioning_channel"]="github"
  self.assertIn("EXTERNAL_KEY_ANCHOR_MISSING_OR_MISMATCH",m.assess(r,a)["blockers"])
 def test_other_custodian_rejected(self):
  r,a=sample();a["custodian_root"]="external-demo-2"
  self.assertIn("EXTERNAL_KEY_ANCHOR_MISSING_OR_MISMATCH",m.assess(r,a)["blockers"])
 def test_key_swap_rejected(self):
  r,a=sample();r["public_key_pem"]="forged"
  self.assertIn("RECEIPT_KEY_DIFFERS_FROM_ANCHOR",m.assess(r,a)["blockers"])
 def test_signature_mutation_rejected(self):
  r,a=sample();r["payload"]["observed_image_sha256"]="0"*64
  self.assertFalse(m.assess(r,a)["anchored_signature_valid"])
 def test_genesis_prev_hash_denied(self):
  r,a=sample();r["payload"]["previous_receipt_sha256"]="a"*64
  self.assertIn("GENESIS_PREVIOUS_HASH_NOT_NULL",m.assess(r,a)["blockers"])
 def test_counter_boolean_denied(self):
  r,a=sample();r["payload"]["sequence"]=True
  self.assertIn("COUNTER_INVALID",m.assess(r,a)["blockers"])
 def test_untrusted_predecessor_denied(self):
  r,a=sample();r["payload"]["sequence"]=2;r["payload"]["previous_receipt_sha256"]="b"*64
  self.assertIn("EXTERNAL_PREDECESSOR_NOT_AUTHENTICATED",m.assess(r,a)["blockers"])
 def test_unverified_utc_is_held(self):
  r,a=sample();self.assertIn("AUTHENTICATED_UTC_UNVERIFIED",m.assess(r,a)["blockers"])
 def test_self_asserted_anchor_not_a_witness(self):
  r,a=sample();a["externally_authenticated"]=True
  self.assertEqual(m.assess(r,a)["independently_authenticated_witnesses"],0)
if __name__=="__main__": unittest.main()
