#!/usr/bin/env python3
"""SAPPHON-223: fixture-based checkpoint continuity tests; no external witness."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_223_checkpoint.py")
spec=importlib.util.spec_from_file_location("s223",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def chain():
 def record(n,prev):
  return {"schema":"sapphon-223-custody-checkpoint-v1","sequence":n,
    "previous_sha256":prev,"custodian_root":"external-demo-one",
    "source_run":m.SOURCE_RUN,"source_commit":m.SOURCE_COMMIT,
    "image_sha256":m.IMAGE_SHA,"claimed_utc":"2026-11-28T10:00:00Z",
    "key_fingerprint_sha256":"a"*64}
 a=record(1,m.GENESIS);b=record(2,m.sha(a))
 return [a,b],{"checkpoint_sha256":m.sha(b),"sequence":2,
   "custodian_root":"external-demo-one","externally_authenticated":True}
class Tests(unittest.TestCase):
 def test_two_records_structure_but_not_custody(self):
  c,h=chain();r=m.adjudicate(c,h)
  self.assertEqual(r["state"],"STRUCTURAL_CHAIN_MATCH_CUSTODY_HOLD")
  self.assertIn("HEAD_TRUST_ROOT_NOT_INDEPENDENTLY_VERIFIED",r["blockers"])
  self.assertEqual(r["independently_authenticated_witnesses"],0)
  self.assertFalse(r["recovery_authorized"])
 def test_missing_external_head(self):
  c,_=chain()
  self.assertIn("INDEPENDENT_EXTERNAL_HEAD_MISSING",m.adjudicate(c)["blockers"])
 def test_counter_replay(self):
  c,h=chain();c[1]["sequence"]=1
  self.assertIn("DUPLICATE_OR_FORKED_SEQUENCE",m.adjudicate(c,h)["blockers"])
 def test_forked_sequence(self):
  c,h=chain();fork=dict(c[0]);fork["claimed_utc"]="2026-11-28T11:00:00Z"
  self.assertIn("FORKED_CHECKPOINT",m.adjudicate(c+[fork],h)["blockers"])
 def test_wrong_predecessor(self):
  c,h=chain();c[1]["previous_sha256"]="b"*64
  self.assertIn("PREDECESSOR_DIGEST_CONFLICT",m.adjudicate(c,h)["blockers"])
 def test_gap(self):
  c,h=chain();c[1]["sequence"]=3
  self.assertIn("COUNTER_REPLAY_OR_GAP",m.adjudicate(c,h)["blockers"])
 def test_stale_external_head(self):
  c,h=chain();h["sequence"]=1
  self.assertIn("HEAD_ROLLBACK_OR_CONFLICT",m.adjudicate(c,h)["blockers"])
 def test_head_digest_fork(self):
  c,h=chain();h["checkpoint_sha256"]="f"*64
  self.assertIn("HEAD_ROLLBACK_OR_CONFLICT",m.adjudicate(c,h)["blockers"])
 def test_changed_custodian(self):
  c,h=chain();c[1]["custodian_root"]="other-custodian"
  self.assertIn("CUSTODIAN_ANCESTRY_CHANGED",m.adjudicate(c,h)["blockers"])
 def test_changed_image(self):
  c,h=chain();c[1]["image_sha256"]="f"*64
  self.assertIn("SOURCE_ANCESTRY_CONFLICT",m.adjudicate(c,h)["blockers"])
 def test_empty(self):
  self.assertIn("NO_CHECKPOINTS",m.adjudicate([],None)["blockers"])
 def test_oversize(self):
  c,h=chain();x=m.adjudicate(c*2050,h)
  self.assertIn("RECORD_SET_INVALID_OR_TOO_LARGE",x["blockers"])
 def test_claimed_external_authentication_not_a_witness(self):
  c,h=chain();r=m.adjudicate(c,h)
  self.assertFalse(r["global_anti_rollback_authenticated"])
  self.assertEqual(r["decision"],"HOLD")
 def test_boolean_counter_denied(self):
  c,h=chain();c[1]["sequence"]=True
  self.assertIn("COUNTER_INVALID",m.adjudicate(c,h)["blockers"])
if __name__=="__main__":unittest.main()
