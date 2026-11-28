#!/usr/bin/env python3
"""SAPPHON-228: signed ACK replay, duplicate and predecessor tests."""
import unittest
import sapphon_228_ack_ledger as ledger
from test_sapphon_227_portable_readback import sample,make_ack

def seed():
 bundle,anchor=sample()
 ack,ack_anchor=make_ack(bundle)
 return bundle,anchor,ack,ack_anchor
class Tests(unittest.TestCase):
 def test_valid_first_append_is_still_hold(self):
  b,a,x,k=seed();v=ledger.adjudicate([],b,a,x,k)
  self.assertTrue(v["candidate_accepted"])
  self.assertEqual(v["record_count"],1)
  self.assertFalse(v["recovery_authorized"])
  self.assertEqual(v["independently_authenticated_witnesses"],0)
  self.assertEqual(v["reconciliation"],"NO_WINNER_SELECTED")
 def test_identical_ack_replay_rejected(self):
  b,a,x,k=seed();one=ledger.adjudicate([],b,a,x,k)
  two=ledger.adjudicate(one["records"],b,a,x,k)
  self.assertFalse(two["candidate_accepted"])
  self.assertIn("SIGNED_ACK_ALREADY_RECORDED",two["blockers"])
  self.assertEqual(two["records"],one["records"])
 def test_nonce_reuse_with_new_signature_rejected(self):
  b,a,x,k=seed();one=ledger.adjudicate([],b,a,x,k)
  # Mutation cannot pass signature, but nonce reuse must still be detected.
  new=dict(x);new["payload"]={**x["payload"],"claimed_utc":"2026-11-29T00:00:00Z"}
  two=ledger.adjudicate(one["records"],b,a,new,k)
  self.assertIn("TRANSFER_NONCE_ALREADY_USED",two["blockers"])
  self.assertEqual(two["records"],one["records"])
 def test_wrong_history_digest_rejected(self):
  b,a,x,k=seed();one=ledger.adjudicate([],b,a,x,k)
  one["records"][0]["entry_sha256"]="0"*64
  v=ledger.adjudicate(one["records"],b,a)
  self.assertIn("HISTORY_ENTRY_HASH_CHANGED",v["blockers"])
 def test_reversed_or_skipped_counter_rejected(self):
  b,a,x,k=seed();one=ledger.adjudicate([],b,a,x,k)
  one["records"][0]["sequence"]=4
  v=ledger.adjudicate(one["records"],b,a)
  self.assertIn("HISTORY_COUNTER_GAP_OR_REPLAY",v["blockers"])
 def test_predecessor_conflict_rejected(self):
  b,a,x,k=seed();one=ledger.adjudicate([],b,a,x,k)
  one["records"][0]["previous_sha256"]="f"*64
  v=ledger.adjudicate(one["records"],b,a)
  self.assertIn("HISTORY_PREDECESSOR_MISMATCH",v["blockers"])
 def test_history_signed_ack_invalid_rejected(self):
  b,a,x,k=seed();one=ledger.adjudicate([],b,a,x,k)
  one["records"][0]["ack"]["signature_base64"]="bad"
  v=ledger.adjudicate(one["records"],b,a)
  self.assertIn("HISTORY_ACK_CRYPTOGRAPHICALLY_INVALID",v["blockers"])
 def test_wrong_source_bundle_rejected(self):
  b,a,x,k=seed();b["manifest_sha256"]="0"*64
  v=ledger.adjudicate([],b,a,x,k)
  self.assertIn("NEW_ACK_SIGNATURE_OR_BUNDLE_INVALID",v["blockers"])
 def test_wrong_anchor_rejected(self):
  b,a,x,k=seed();k["key_sha256"]="0"*64
  v=ledger.adjudicate([],b,a,x,k)
  self.assertFalse(v["candidate_accepted"])
 def test_empty_history_missing_ack_is_hold(self):
  b,a,_,_=seed();v=ledger.adjudicate([],b,a)
  self.assertEqual(v["state"],"ACK_REPLAY_OR_INTAKE_REJECTED_HOLD")
  self.assertIn("NEW_SIGNED_ACK_NOT_PROVIDED",v["blockers"])
 def test_history_bounded(self):
  b,a,x,k=seed();v=ledger.adjudicate([{}]*129,b,a,x,k)
  self.assertIn("HISTORY_ABSENT_OR_UNBOUNDED",v["blockers"])
  self.assertFalse(v["candidate_accepted"])
 def test_deterministic_evidence_hash(self):
  b,a,x,k=seed();v=ledger.adjudicate([],b,a,x,k)
  h=v.pop("evidence_sha256")
  self.assertEqual(h,ledger.sha(v))
 def test_false_self_declared_external_witness_never_promoted(self):
  b,a,x,k=seed();k["externally_authenticated"]=True
  v=ledger.adjudicate([],b,a,x,k)
  self.assertEqual(v["independently_authenticated_witnesses"],0)
  self.assertEqual(v["decision"],"HOLD")
 def test_boolean_history_counter_invalid(self):
  b,a,x,k=seed();one=ledger.adjudicate([],b,a,x,k)
  one["records"][0]["sequence"]=True
  v=ledger.adjudicate(one["records"],b,a)
  self.assertIn("HISTORY_COUNTER_GAP_OR_REPLAY",v["blockers"])
if __name__=="__main__":unittest.main()
