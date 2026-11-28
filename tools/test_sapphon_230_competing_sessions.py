#!/usr/bin/env python3
"""SAPPHON-230 adversarial signed, competing-session head fixtures."""
import hashlib,unittest
import sapphon_230_competing_sessions as m
import sapphon_228_ack_ledger as ledger
from test_sapphon_229_cross_session import sample_sessions,signed_head,sign

def sample_competitors():
    sessions,bundle,anchor=sample_sessions()
    first=sessions[0]
    original=sessions[1]
    # Create a valid alternate second ACK on the same preserved first entry.
    from test_sapphon_227_portable_readback import make_ack
    ack0,ack_anchor=make_ack(bundle)
    payload={**ack0["payload"],"transfer_nonce":"synthetic-other-branch-0002"}
    key,sig=sign(payload)
    alt_ack={"payload":payload,"public_key_pem":key,"signature_base64":sig,
             "recovery_authorized":False,"lock_cleared":False}
    alt_anchor={"public_key_pem":key,"key_sha256":hashlib.sha256(key.encode()).hexdigest(),
                "custodian_root":payload["custodian_root"]}
    alternate=ledger.adjudicate(first["records"],bundle,anchor,alt_ack,alt_anchor)
    assert alternate["candidate_accepted"],alternate["blockers"]
    other={"session_id":"session-alternate","records":alternate["records"],
           "declared_prior_head":first["records"][-1]["entry_sha256"]}
    variants=[{"candidate_id":"branch-alpha","sessions":[first,original]},
              {"candidate_id":"branch-beta","sessions":[first,other]}]
    for candidate in variants:
        head,head_anchor=signed_head(candidate["sessions"])
        candidate["signed_head"]=head
        candidate["head_anchor"]=head_anchor
    return variants,bundle,anchor
class Tests(unittest.TestCase):
 def test_two_valid_fork_branches_preserved(self):
    c,b,a=sample_competitors();v=m.assess(c,b,a)
    self.assertEqual(v["state"],"SIGNED_SESSION_FORK_PRESERVED_HOLD")
    self.assertEqual(v["fork_count"],1)
    self.assertEqual(v["candidate_count"],2)
    self.assertEqual(len(v["forks_retained"][0]["conflicting_head_sha256"]),2)
    self.assertEqual(v["reconciliation"],"NO_WINNER_SELECTED")
    self.assertEqual(v["independently_authenticated_witnesses"],0)
 def test_reverse_candidate_order_still_detects_fork(self):
    c,b,a=sample_competitors()
    self.assertEqual(m.assess(list(reversed(c)),b,a)["fork_count"],1)
 def test_identical_head_not_a_fork(self):
    c,b,a=sample_competitors()
    same={**c[0],"candidate_id":"branch-copy"}
    self.assertEqual(m.assess([c[0],same],b,a)["fork_count"],0)
 def test_duplicate_candidate_id_rejected(self):
    c,b,a=sample_competitors();c[1]["candidate_id"]=c[0]["candidate_id"]
    self.assertIn("CANDIDATE_ID_DUPLICATE_OR_INVALID",m.assess(c,b,a)["blockers"])
 def test_missing_branch_rejected_if_mutated(self):
    c,b,a=sample_competitors();c[1]["sessions"][-1]["records"].pop()
    self.assertIn("CANDIDATE_HISTORY_OR_HEAD_REJECTED",m.assess(c,b,a)["blockers"])
 def test_signed_head_changed_rejected(self):
    c,b,a=sample_competitors();c[1]["signed_head"]["payload"]["head_sha256"]="f"*64
    self.assertIn("CANDIDATE_HISTORY_OR_HEAD_REJECTED",m.assess(c,b,a)["blockers"])
 def test_source_bundle_modified_rejected(self):
    c,b,a=sample_competitors();b["manifest_sha256"]="0"*64
    self.assertIn("CANDIDATE_HISTORY_OR_HEAD_REJECTED",m.assess(c,b,a)["blockers"])
 def test_external_signed_head_matches_one_branch_without_authority(self):
    c,b,a=sample_competitors()
    v=m.assess(c,b,a,c[0]["signed_head"],c[0]["head_anchor"])
    self.assertTrue(v["signed_external_head_bytes_match"])
    self.assertIn("EXTERNAL_HEAD_CANNOT_SELECT_FORK_WINNER",v["blockers"])
    self.assertEqual(v["fork_count"],1)
    self.assertFalse(v["global_anti_rollback_authenticated"])
 def test_stale_external_head_rejected(self):
    c,b,a=sample_competitors()
    h={**c[0]["signed_head"],"payload":{**c[0]["signed_head"]["payload"],
       "head_sha256":"0"*64}}
    self.assertIn("EXTERNAL_SIGNED_HEAD_NOT_MATCHED",
                  m.assess(c,b,a,h,c[0]["head_anchor"])["blockers"])
 def test_no_candidates_rejected(self):
    _,b,a=sample_competitors()
    self.assertEqual(m.assess([],b,a)["state"],"SESSION_FORK_OR_HIGHWATER_REJECTED_HOLD")
 def test_malformed_candidate_retained_as_fault(self):
    c,b,a=sample_competitors()
    self.assertIn("CANDIDATE_SCHEMA_INVALID",m.assess(c+[{}],b,a)["blockers"])
 def test_bounded_candidates(self):
    c,b,a=sample_competitors()
    self.assertIn("CANDIDATE_INVENTORY_MISSING_OR_UNBOUNDED",
                  m.assess(c*9,b,a)["blockers"])
 def test_single_history_no_external_head_still_hold(self):
    c,b,a=sample_competitors()
    v=m.assess(c[:1],b,a)
    self.assertEqual(v["state"],"STRUCTURAL_SESSIONS_HELD_NO_EXTERNAL_HEAD")
    self.assertFalse(v["recovery_authorized"])
 def test_deterministic_digest(self):
    c,b,a=sample_competitors()
    v=m.assess(c,b,a);h=v.pop("evidence_sha256")
    self.assertEqual(h,m.sha(v))
 def test_all_original_signed_heads_remain_in_report(self):
    c,b,a=sample_competitors();v=m.assess(c,b,a)
    self.assertEqual(v["candidates_retained"][0]["complete_candidate"],c[0])
    self.assertEqual(v["candidates_retained"][1]["complete_candidate"],c[1])
 def test_claimed_external_authentication_not_witness(self):
    c,b,a=sample_competitors();k=dict(c[0]["head_anchor"],externally_authenticated=True)
    v=m.assess(c,b,a,c[0]["signed_head"],k)
    self.assertEqual(v["independently_authenticated_witnesses"],0)
    self.assertFalse(v["authenticated_utc"])
if __name__=="__main__":unittest.main()
