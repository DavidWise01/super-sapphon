#!/usr/bin/env python3
"""SAPPHON-225: signed fork retention fixtures never establish custody."""
import base64
import hashlib
import pathlib
import subprocess
import tempfile
import unittest

import sapphon_225_fork_retention as m
import sapphon_223_checkpoint as chain

def fixture():
    with tempfile.TemporaryDirectory() as tmp:
        d=pathlib.Path(tmp)
        private=d/"private.pem";public=d/"public.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(private)],
                       check=True,stdout=subprocess.DEVNULL)
        subprocess.run(["openssl","pkey","-in",str(private),"-pubout","-out",str(public)],
                       check=True,stdout=subprocess.DEVNULL)
        pem=public.read_text()
        anchor={"public_key_pem":pem,"key_sha256":hashlib.sha256(pem.encode()).hexdigest(),
                "custodian_root":"external-demo-one"}
        def sign(digest,seq=1,root="external-demo-one"):
            payload={"schema":"sapphon-224-signed-head-v1","sequence":seq,
              "checkpoint_sha256":digest,"custodian_root":root,
              "source_run":chain.SOURCE_RUN,"source_commit":chain.SOURCE_COMMIT,
              "image_sha256":chain.IMAGE_SHA,"claimed_utc":"2026-11-28T14:00:00Z"}
            (d/"message").write_bytes(m.canonical(payload))
            subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(private),
                           "-rawin","-in",str(d/"message"),"-out",str(d/"signature")],
                           check=True,stdout=subprocess.DEVNULL)
            return {"payload":payload,
                    "signature_base64":base64.b64encode((d/"signature").read_bytes()).decode()}
        a=sign("a"*64);b=sign("b"*64)
    return anchor,a,b

class Tests(unittest.TestCase):
    def test_valid_fork_retains_both(self):
        anchor,a,b=fixture()
        v=m.adjudicate([a,b],anchor)
        self.assertEqual(v["state"],"SIGNED_FORK_PRESERVED_HOLD")
        self.assertEqual(v["fork_count"],1)
        self.assertEqual(v["verified_signature_count"],2)
        self.assertEqual(len(v["heads_retained"]),2)
        self.assertEqual(v["reconciliation"],"NO_WINNER_SELECTED")
        self.assertFalse(v["recovery_authorized"])
        self.assertEqual(v["independently_authenticated_witnesses"],0)
    def test_reverse_order_preserves_fork(self):
        anchor,a,b=fixture()
        v=m.adjudicate([b,a],anchor)
        self.assertEqual(v["fork_count"],1)
        self.assertEqual(v["signed_forks"][0]["conflicting_checkpoint_sha256"],["a"*64,"b"*64])
    def test_duplicate_is_not_fork(self):
        anchor,a,_=fixture()
        v=m.adjudicate([a,a],anchor)
        self.assertEqual(v["fork_count"],0)
        self.assertIn("DUPLICATED_SIGNED_ENVELOPE",v["blockers"])
    def test_invalid_signature_does_not_prove_fork(self):
        anchor,a,b=fixture()
        b["signature_base64"]=a["signature_base64"]
        v=m.adjudicate([a,b],anchor)
        self.assertEqual(v["fork_count"],0)
        self.assertIn("INVALID_OR_UNVERIFIED_SIGNED_HEAD",v["blockers"])
        self.assertEqual(v["head_count"],2)
    def test_wrong_anchor_does_not_prove_fork(self):
        anchor,a,b=fixture()
        anchor["key_sha256"]="0"*64
        v=m.adjudicate([a,b],anchor)
        self.assertEqual(v["fork_count"],0)
        self.assertIn("TRUST_ANCHOR_ABSENT_OR_HASH_MISMATCH",v["blockers"])
    def test_source_substitution_denied(self):
        anchor,a,b=fixture()
        b["payload"]["source_run"]="other"
        v=m.adjudicate([a,b],anchor)
        self.assertEqual(v["fork_count"],0)
        self.assertEqual(v["head_count"],2)
    def test_bad_counter_denied(self):
        anchor,a,b=fixture()
        b["payload"]["sequence"]=True
        self.assertEqual(m.adjudicate([a,b],anchor)["fork_count"],0)
    def test_missing_input_fails_closed(self):
        v=m.adjudicate(None,None)
        self.assertEqual(v["state"],"SIGNED_HEAD_INTAKE_HOLD")
        self.assertIn("NO_SIGNED_HEADS_PROVIDED",v["blockers"])
    def test_many_records_bounded(self):
        anchor,a,_=fixture()
        v=m.adjudicate([a]*65,anchor)
        self.assertEqual(v["head_count"],0)
        self.assertIn("INVALID_OR_UNBOUNDED_HEAD_SET",v["blockers"])
    def test_deterministic_manifest_hash(self):
        anchor,a,b=fixture()
        v=m.adjudicate([a,b],anchor)
        original=v.pop("evidence_sha256")
        self.assertEqual(original,m.sha(m.canonical(v)))
    def test_no_timestamp_promotion(self):
        anchor,a,b=fixture()
        v=m.adjudicate([a,b],anchor)
        self.assertFalse(v["authenticated_utc"])
        self.assertFalse(v["global_anti_rollback_authenticated"])
    def test_single_head_no_reconciliation(self):
        anchor,a,_=fixture()
        v=m.adjudicate([a],anchor)
        self.assertEqual(v["state"],"NO_FORK_OBSERVED_CUSTODY_HOLD")
        self.assertEqual(v["reconciliation"],"NO_WINNER_SELECTED")

if __name__=="__main__":
    unittest.main()
