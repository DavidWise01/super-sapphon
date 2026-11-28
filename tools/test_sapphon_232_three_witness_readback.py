#!/usr/bin/env python3
"""SAPPHON-232 synthetic three-witness qualification tests."""
import base64
import copy
import hashlib
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import sapphon_232_three_witness_readback as m
import sapphon_231_custody_reconciliation as previous
from test_sapphon_231_custody_reconciliation import fixture,receipt

def predecessor():
    f=fixture()
    return previous.assess(f,[receipt(f,0),receipt(f,1,"outside-b")])

def make_att(pre,i=0,branch=0,seq=0,prev=None):
    source=pre["receipts_retained"][branch]["receipt"]["payload"]
    raw=m.canonical({"branch_head_sha256":source["branch_head_sha256"],
                     "session_set_sha256":source["session_set_sha256"],
                     "custody_receipt_sha256":pre["receipts_retained"][branch]["receipt_sha256"]})
    p={"schema":"sapphon-232-readback-v1","witness_id":f"witness-{i}",
       "operator_domain":f"synthetic-operator-{i}","sequence":seq,
       "previous_checkpoint_sha256":prev,
       "branch_head_sha256":source["branch_head_sha256"],
       "session_set_sha256":source["session_set_sha256"],
       "custody_receipt_sha256":pre["receipts_retained"][branch]["receipt_sha256"],
       "readback_sha256":hashlib.sha256(raw).hexdigest(),
       "readback_base64":base64.b64encode(raw).decode()}
    p["checkpoint_sha256"]=m.sha({k:p[k] for k in ("witness_id","operator_domain",
       "sequence","previous_checkpoint_sha256","branch_head_sha256","session_set_sha256",
       "custody_receipt_sha256","readback_sha256")})
    key=Ed25519PrivateKey.generate()
    public=key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode()
    return {"payload":p,"public_key_pem":public,
            "signature_base64":base64.b64encode(key.sign(m.canonical(p))).decode()}

def three(pre):
    return [make_att(pre,i,branch=i%2) for i in range(3)]

class Tests(unittest.TestCase):
    def test_three_local_readbacks_do_not_authorize(self):
        p=predecessor();v=m.assess(p,three(p))
        self.assertEqual(v["locally_valid_readbacks"],3)
        self.assertEqual(v["independently_authenticated_witnesses"],0)
        self.assertFalse(v["recovery_authorized"])
    def test_three_preserve_competing_heads(self):
        p=predecessor();v=m.assess(p,three(p))
        self.assertEqual(v["reconciliation"],"NO_WINNER_SELECTED")
        self.assertEqual(len({r["complete_attestation"]["payload"]["branch_head_sha256"] for r in v["attestations_retained"]}),2)
    def test_tampered_signature_rejected(self):
        p=predecessor();a=three(p);a[0]["payload"]["witness_id"]="altered"
        self.assertIn("WITNESS_SIGNATURE_INVALID",m.assess(p,a)["blockers"])
    def test_mismatched_readback_bytes(self):
        p=predecessor();a=three(p);a[0]["payload"]["readback_base64"]=base64.b64encode(b"lie").decode()
        self.assertIn("READBACK_BYTES_DIGEST_MISMATCH",m.assess(p,a)["blockers"])
    def test_reused_key(self):
        p=predecessor();a=three(p);a.append(copy.deepcopy(a[0]))
        self.assertIn("WITNESS_KEY_REUSED",m.assess(p,a)["blockers"])
    def test_reused_witness_identity(self):
        p=predecessor();a=three(p);a.append(copy.deepcopy(a[0]))
        self.assertIn("WITNESS_ID_REUSED",m.assess(p,a)["blockers"])
    def test_duplicate_operator_claim(self):
        p=predecessor();a=three(p);a.append(copy.deepcopy(a[0]))
        self.assertIn("OPERATOR_DOMAIN_CLAIM_REUSED",m.assess(p,a)["blockers"])
    def test_unanchored_counter(self):
        p=predecessor();a=[make_att(p,0,seq=10)]
        self.assertIn("CHECKPOINT_PREFIX_NOT_INDEPENDENTLY_ANCHORED",m.assess(p,a)["blockers"])
    def test_predecessor_mutation(self):
        p=predecessor();p["matched_signed_receipts"]=99
        self.assertIn("PREDECESSOR_DIGEST_INVALID",m.assess(p,[])["blockers"])
    def test_malformed_witness(self):
        p=predecessor()
        self.assertIn("WITNESS_SCHEMA_INVALID",m.assess(p,[{}])["blockers"])
    def test_bounded_inventory(self):
        p=predecessor()
        self.assertIn("WITNESS_INVENTORY_INVALID",m.assess(p,[{}]*13)["blockers"])
    def test_single_is_not_three(self):
        p=predecessor()
        self.assertIn("THREE_VALID_READBACKS_NOT_ESTABLISHED",m.assess(p,[make_att(p)])["blockers"])
    def test_deterministic_report_digest(self):
        p=predecessor();v=m.assess(p,three(p));h=v.pop("evidence_sha256")
        self.assertEqual(h,m.sha(v))
if __name__=="__main__": unittest.main()
