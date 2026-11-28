#!/usr/bin/env python3
"""SAPPHON-224 Ed25519 fixtures do not establish independent custody."""
import base64,hashlib,json,pathlib,subprocess,tempfile,unittest
import sapphon_224_signed_head as m
import sapphon_223_checkpoint as chain
def sample():
 c={"schema":"sapphon-223-custody-checkpoint-v1","sequence":1,
 "previous_sha256":chain.GENESIS,"custodian_root":"external-demo-one",
 "source_run":chain.SOURCE_RUN,"source_commit":chain.SOURCE_COMMIT,
 "image_sha256":chain.IMAGE_SHA,"claimed_utc":"2026-11-28T14:00:00Z",
 "key_fingerprint_sha256":"a"*64}
 p={"schema":"sapphon-224-signed-head-v1","sequence":1,
 "checkpoint_sha256":chain.sha(c),"custodian_root":c["custodian_root"],
 "source_run":chain.SOURCE_RUN,"source_commit":chain.SOURCE_COMMIT,
 "image_sha256":chain.IMAGE_SHA,"claimed_utc":c["claimed_utc"]}
 with tempfile.TemporaryDirectory() as temp:
  d=pathlib.Path(temp);private=d/"priv";public=d/"pub"
  subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(private)],check=True,stdout=subprocess.DEVNULL)
  subprocess.run(["openssl","pkey","-in",str(private),"-pubout","-out",str(public)],check=True,stdout=subprocess.DEVNULL)
  pem=public.read_text()
  def sign(payload):
   (d/"message").write_bytes(m.canonical(payload))
   subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(private),"-rawin","-in",str(d/"message"),"-out",str(d/"signature")],check=True,stdout=subprocess.DEVNULL)
   return {"payload":payload,"signature_base64":base64.b64encode((d/"signature").read_bytes()).decode()}
  anchor={"public_key_pem":pem,"key_sha256":hashlib.sha256(pem.encode()).hexdigest(),"custodian_root":c["custodian_root"]}
  good=sign(p)
  altered={**p,"checkpoint_sha256":"f"*64}
  fork=sign(altered)
 return [c],anchor,good,fork
class Tests(unittest.TestCase):
 def test_signed_matching_head_is_only_structural(self):
  records,anchor,head,_=sample();x=m.inspect([head],anchor,records)
  self.assertEqual(x["state"],"SIGNED_HEAD_STRUCTURAL_MATCH_CUSTODY_HOLD")
  self.assertEqual(x["signatures_valid"],1)
  self.assertFalse(x["recovery_authorized"])
  self.assertEqual(x["independently_authenticated_witnesses"],0)
 def test_two_valid_signatures_fork_counter(self):
  records,anchor,a,b=sample();x=m.inspect([a,b],anchor,records)
  self.assertIn("SIGNED_EQUIVOCATION_SAME_COUNTER",x["blockers"])
 def test_signature_modified(self):
  records,anchor,a,_=sample();a["payload"]["checkpoint_sha256"]="e"*64
  self.assertIn("HEAD_SIGNATURE_INVALID",m.inspect([a],anchor,records)["blockers"])
 def test_anchor_fingerprint_wrong(self):
  records,anchor,a,_=sample();anchor["key_sha256"]="f"*64
  self.assertIn("ANCHOR_KEY_HASH_INVALID",m.inspect([a],anchor,records)["blockers"])
 def test_custodian_swapped(self):
  records,anchor,a,_=sample();anchor["custodian_root"]="fake-root"
  self.assertIn("ANCHOR_ROOT_MISMATCH",m.inspect([a],anchor,records)["blockers"])
 def test_source_substitution(self):
  records,anchor,a,_=sample();a["payload"]["source_run"]="unexpected"
  self.assertIn("SOURCE_ANCESTRY_CONFLICT",m.inspect([a],anchor,records)["blockers"])
 def test_missing_anchor(self):
  records,_,a,_=sample()
  self.assertIn("ANCHOR_KEY_HASH_INVALID",m.inspect([a],None,records)["blockers"])
 def test_missing_records(self):
  _,anchor,a,_=sample()
  self.assertIn("RECORDS_MISSING",m.inspect([a],anchor,[])["blockers"])
 def test_zero_heads(self):
  records,anchor,_,_=sample()
  self.assertIn("HEAD_SET_EMPTY_OR_UNBOUNDED",m.inspect([],anchor,records)["blockers"])
 def test_false_time_authority(self):
  records,anchor,a,_=sample();v=m.inspect([a],anchor,records)
  self.assertIn("AUTHENTICATED_UTC_UNVERIFIED",v["blockers"])
  self.assertFalse(v["authenticated_utc"])
 def test_duplicate_identical_heads_not_two_witnesses(self):
  records,anchor,a,_=sample();v=m.inspect([a,a],anchor,records)
  self.assertEqual(v["independently_authenticated_witnesses"],0)
 def test_nonterminal_signed_head(self):
  records,anchor,_,fork=sample()
  self.assertIn("SIGNED_HEAD_NOT_TERMINAL",m.inspect([fork],anchor,records)["blockers"])
if __name__=="__main__":unittest.main()
