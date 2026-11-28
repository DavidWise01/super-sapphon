#!/usr/bin/env python3
"""SAPPHON-226: signed fork export fixtures, still one GitHub ancestry."""
import unittest
import sapphon_226_fork_export as m
import sapphon_225_fork_retention as prior
from test_sapphon_225_fork_retention import fixture
def sample():
 anchor,a,b=fixture()
 return prior.adjudicate([a,b],anchor)
class Tests(unittest.TestCase):
 def test_both_branches_exported_without_selection(self):
  bundle,v=m.export(sample())
  self.assertEqual(v["state"],"PORTABLE_FORK_EVIDENCE_READY_HOLD")
  self.assertEqual(len(bundle["heads"]),2)
  self.assertEqual(len(bundle["forks"]),1)
  self.assertEqual(bundle["reconciliation"],"NO_WINNER_SELECTED")
  self.assertFalse(v["recovery_authorized"])
 def test_export_reproducible(self):
  a=sample()
  self.assertEqual(m.export(a)[0],m.export(a)[0])
 def test_fork_branch_removed_rejected(self):
  a=sample();a["heads_retained"].pop()
  self.assertEqual(m.export(a)[1]["state"],"FORK_TRANSFER_REJECTED_HOLD")
 def test_fork_digest_altered_rejected(self):
  a=sample();a["signed_forks"][0]["conflicting_checkpoint_sha256"]=["a"*64]
  self.assertIn("FORK_BRANCHES_INVALID",m.export(a)[1]["blockers"])
 def test_mutated_envelope_rejected(self):
  a=sample();a["heads_retained"][0]["canonical_envelope"]["signature_base64"]="forged"
  self.assertIn("HEAD_EVIDENCE_CONFLICT",m.export(a)[1]["blockers"])
 def test_wrong_report_hash_rejected(self):
  a=sample();a["evidence_sha256"]="0"*64
  self.assertIn("REPORT_HASH_MISMATCH",m.export(a)[1]["blockers"])
 def test_missing_input_hold(self):
  self.assertEqual(m.export(None)[1]["state"],"FORK_TRANSFER_REJECTED_HOLD")
 def test_ack_declares_transfer_not_authenticated(self):
  a=sample();manifest,_=m.export(a)
  receipt={"manifest_sha256":manifest["manifest_sha256"],"custodian_root":"external-demo",
    "recovery_authorized":False,"lock_cleared":False,
    "signature":"self-declared","externally_authenticated":True}
  v=m.export(a,receipt)[1]
  self.assertEqual(v["state"],"PORTABLE_FORK_EVIDENCE_READY_HOLD")
  self.assertEqual(v["independently_authenticated_witnesses"],0)
 def test_wrong_ack_manifest_denied(self):
  a=sample()
  x=m.export(a,{"manifest_sha256":"0"*64,"custodian_root":"external-demo",
    "recovery_authorized":False,"lock_cleared":False})[1]
  self.assertIn("CUSTODY_ACK_MANIFEST_CONFLICT",x["blockers"])
 def test_github_ack_denied(self):
  a=sample();v=m.export(a,{"custodian_root":"GitHub",
    "recovery_authorized":False,"lock_cleared":False})[1]
  self.assertIn("CUSTODY_ACK_ROOT_INVALID",v["blockers"])
 def test_recovery_ack_denied(self):
  a=sample();v=m.export(a,{"custodian_root":"external-demo",
    "recovery_authorized":True,"lock_cleared":False})[1]
  self.assertIn("CUSTODY_ACK_UNSAFE_AUTHORITY",v["blockers"])
 def test_single_branch_not_fork(self):
  a=sample();a["signed_forks"]=[];a["fork_count"]=0
  self.assertIn("FORK_COUNT_OR_MISSING_BRANCH",m.export(a)[1]["blockers"])
if __name__=="__main__":unittest.main()
