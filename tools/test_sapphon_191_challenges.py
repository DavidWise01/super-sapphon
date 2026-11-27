#!/usr/bin/env python3
"""SAPPHON-191 offline challenges; no external witness simulation as real evidence."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_191_challenges.py")
s=importlib.util.spec_from_file_location("c191",p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def fixture():
 c={"schema":"sapphon-191-challenge-v1","source_sha":m.SOURCE,
 "workflow":m.WORKFLOW,"run_id":190,"attempt":1,"root_sha256":"a"*64,
 "challenge_nonce_hex":"b"*64,"session_id":"session-one","key_fingerprint_sha256":"c"*64,
 "issuer":"unverified-source","external_issuer_authenticated":False,"recovery_authorized":False}
 r={"schema":"sapphon-191-challenge-response-v1","source_sha":m.SOURCE,
 "run_id":190,"attempt":1,"root_sha256":"a"*64,"challenge_nonce_hex":"b"*64,
 "session_id":"session-one","key_fingerprint_sha256":"c"*64,
 "signature_b64":"synthetic-not-cryptographically-verified","recovery_authorized":False}
 return c,r
class Tests(unittest.TestCase):
 def test_empty_never_grants_authority(self):
  x=m.check([],[]);self.assertEqual(x["independent_witnesses"],0)
  self.assertFalse(x["recovery_authorized"])
 def test_syntactically_bound_but_not_trusted(self):
  c,r=fixture();x=m.check([c],[r])
  self.assertFalse(x["findings"]);self.assertEqual(x["consumed_challenges"],1)
  self.assertFalse(x["cryptographic_signatures_verified"])
 def test_replay_denied(self):
  c,r=fixture();x=m.check([c],[r,r])
  self.assertIn("REPLAYED_CHALLENGE_RESPONSE:1",x["findings"])
 def test_duplicate_nonce_denied(self):
  c,r=fixture();x=m.check([c,c],[r])
  self.assertIn("REUSED_CHALLENGE_NONCE:1",x["findings"])
 def test_wrong_root_denied(self):
  c,r=fixture();r["root_sha256"]="d"*64
  self.assertIn("CROSS_SESSION_OR_ROOT_SUBSTITUTION:0:root_sha256",m.check([c],[r])["findings"])
 def test_wrong_session_denied(self):
  c,r=fixture();r["session_id"]="another"
  self.assertIn("CROSS_SESSION_OR_ROOT_SUBSTITUTION:0:session_id",m.check([c],[r])["findings"])
 def test_wrong_run_denied(self):
  c,r=fixture();r["run_id"]=191
  self.assertIn("CROSS_SESSION_OR_ROOT_SUBSTITUTION:0:run_id",m.check([c],[r])["findings"])
 def test_wrong_attempt_denied(self):
  c,r=fixture();r["attempt"]=2
  self.assertIn("CROSS_SESSION_OR_ROOT_SUBSTITUTION:0:attempt",m.check([c],[r])["findings"])
 def test_key_substitution_denied(self):
  c,r=fixture();r["key_fingerprint_sha256"]="e"*64
  self.assertIn("CROSS_SESSION_OR_ROOT_SUBSTITUTION:0:key_fingerprint_sha256",m.check([c],[r])["findings"])
 def test_unissued_nonce_denied(self):
  c,r=fixture();r["challenge_nonce_hex"]="f"*64
  self.assertIn("UNISSUED_CHALLENGE:0",m.check([c],[r])["findings"])
 def test_claimed_external_issuer_denied(self):
  c,r=fixture();c["external_issuer_authenticated"]=True
  self.assertIn("CHALLENGE_UNTRUSTED_AUTHORITY:0",m.check([c],[r])["findings"])
 def test_forged_recovery_denied(self):
  c,r=fixture();r["recovery_authorized"]=True
  self.assertIn("RESPONSE_AUTHORITY:0",m.check([c],[r])["findings"])
 def test_boolean_attempt_denied(self):
  c,r=fixture();c["attempt"]=True
  self.assertIn("CHALLENGE_RUN:0",m.check([c],[r])["findings"])
 def test_bad_hash_denied(self):
  c,r=fixture();c["root_sha256"]="invalid"
  self.assertIn("CHALLENGE_DIGEST:0",m.check([c],[r])["findings"])
 def test_unknown_field_denied(self):
  c,r=fixture();c["authorized"]=True
  self.assertIn("CHALLENGE_SCHEMA:0",m.check([c],[r])["findings"])
 def test_bounded(self):
  with self.assertRaisesRegex(ValueError,"BOUNDED_INPUT"):
   m.check([fixture()[0]]*(m.MAX_CHALLENGES+1),[])
if __name__=="__main__":unittest.main()
