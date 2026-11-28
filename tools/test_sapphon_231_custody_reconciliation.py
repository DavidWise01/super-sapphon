#!/usr/bin/env python3
"""SAPPHON-231 synthetic, signed custody-claim regressions."""
import base64
import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import sapphon_231_custody_reconciliation as m
import sapphon_230_competing_sessions as prior
from test_sapphon_230_competing_sessions import sample_competitors

def fixture():
    c,b,a=sample_competitors()
    return prior.assess(c,b,a)

def receipt(report,idx=0,custodian="outside-a",seq=0,prior_receipt=None):
    private=Ed25519PrivateKey.generate()
    c=report["candidates_retained"][idx]
    payload={"schema":"sapphon-231-custody-receipt-v1","custodian_id":custodian,
             "custody_domain":"synthetic-test-domain","sequence":seq,
             "branch_head_sha256":c["head_sha256"],
             "session_set_sha256":c["session_set_sha256"],
             "prior_receipt_sha256":prior_receipt,"retention_id":"test-retention-"+str(seq)}
    key=private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode()
    sig=base64.b64encode(private.sign(m.canonical(payload))).decode()
    return {"payload":payload,"public_key_pem":key,"signature_base64":sig}

class Tests(unittest.TestCase):
    def test_empty_receipts_still_hold(self):
        v=m.assess(fixture(),[])
        self.assertFalse(v["recovery_authorized"])
        self.assertEqual(v["independently_authenticated_witnesses"],0)
    def test_signed_both_branches_preserved(self):
        f=fixture()
        v=m.assess(f,[receipt(f,0),receipt(f,1,"outside-b")])
        self.assertEqual(v["matched_signed_receipts"],2)
        self.assertEqual(len(v["candidate_heads_retained"]),2)
        self.assertEqual(v["reconciliation"],"NO_WINNER_SELECTED")
    def test_signature_tampering_rejected(self):
        f=fixture();r=receipt(f);r["payload"]["custodian_id"]="tampered"
        self.assertIn("RECEIPT_SIGNATURE_INVALID",m.assess(f,[r])["blockers"])
    def test_wrong_branch_rejected(self):
        f=fixture();r=receipt(f)
        r["payload"]["branch_head_sha256"]="0"*64
        self.assertEqual(m.assess(f,[r])["matched_signed_receipts"],0)
    def test_predecessor_digest_tampering_rejected(self):
        f=fixture();f["candidate_count"]=25
        self.assertIn("PREDECESSOR_DIGEST_INVALID",m.assess(f,[])["blockers"])
    def test_duplicate_sequence_rejected(self):
        f=fixture();v=m.assess(f,[receipt(f),receipt(f,1,seq=0)])
        self.assertIn("CUSTODIAN_SEQUENCE_REUSED_OR_ROLLBACK",v["blockers"])
    def test_missing_predecessor_rejected(self):
        f=fixture();v=m.assess(f,[receipt(f,seq=1)])
        self.assertIn("UNANCHORED_CUSTODIAN_PREFIX",v["blockers"])
    def test_reused_retention_id_rejected(self):
        f=fixture();v=m.assess(f,[receipt(f),receipt(f,1)])
        self.assertIn("RETENTION_ID_REUSED",v["blockers"])
    def test_receipt_count_bound(self):
        f=fixture();v=m.assess(f,[{}]*33)
        self.assertIn("RECEIPT_INVENTORY_INVALID",v["blockers"])
    def test_receipt_digest_is_deterministic(self):
        f=fixture();v=m.assess(f,[receipt(f)])
        h=v.pop("evidence_sha256")
        self.assertEqual(h,m.digest(v))
    def test_claimed_external_id_does_not_promote(self):
        f=fixture();r=receipt(f,custodian="third-party")
        v=m.assess(f,[r])
        self.assertFalse(v["lock_cleared"])
        self.assertIn("INDEPENDENT_CUSTODY_NOT_ESTABLISHED",v["blockers"])
    def test_malformed_schema_rejected(self):
        f=fixture();v=m.assess(f,[{"receipt":"bad"}])
        self.assertIn("RECEIPT_SCHEMA_INVALID",v["blockers"])
if __name__=="__main__":unittest.main()
