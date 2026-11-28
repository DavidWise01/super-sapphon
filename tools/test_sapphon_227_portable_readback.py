#!/usr/bin/env python3
"""SAPPHON-227 deterministic signed fork and custody acknowledgment fixtures."""
import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

import sapphon_225_fork_retention as signed
import sapphon_226_fork_export as portable
import sapphon_227_portable_readback as readback
from test_sapphon_225_fork_retention import fixture

def sample():
    anchor,a,b=fixture()
    original=signed.adjudicate([a,b],anchor)
    bundle,verdict=portable.export(original)
    assert verdict["state"]=="PORTABLE_FORK_EVIDENCE_READY_HOLD"
    return bundle,anchor

def make_ack(bundle):
    with tempfile.TemporaryDirectory() as temp:
        d=pathlib.Path(temp)
        priv=d/"private";pub=d/"public";msg=d/"payload";sig=d/"signature"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(priv)],
                       check=True,stdout=subprocess.DEVNULL)
        subprocess.run(["openssl","pkey","-in",str(priv),"-pubout","-out",str(pub)],
                       check=True,stdout=subprocess.DEVNULL)
        pem=pub.read_text()
        payload={"schema":"sapphon-227-custody-transfer-ack-v1",
                 "manifest_sha256":bundle["manifest_sha256"],
                 "custodian_root":"external-declared-custodian",
                 "source_run":signed.chain.SOURCE_RUN,
                 "source_commit":signed.chain.SOURCE_COMMIT,
                 "fork_count":len(bundle["forks"]),
                 "claimed_utc":"2026-11-28T17:00:00Z",
                 "transfer_nonce":"synthetic-nonce-0001"}
        msg.write_bytes(readback.canon(payload))
        subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(priv),"-rawin",
                        "-in",str(msg),"-out",str(sig)],check=True,stdout=subprocess.DEVNULL)
        ack={"payload":payload,"signature_base64":base64.b64encode(sig.read_bytes()).decode(),
             "public_key_pem":pem,"recovery_authorized":False,"lock_cleared":False}
        anchor={"public_key_pem":pem,"key_sha256":hashlib.sha256(pem.encode()).hexdigest(),
                "custodian_root":payload["custodian_root"]}
    return ack,anchor

class Tests(unittest.TestCase):
    def test_full_export_roundtrip_no_ack(self):
        bundle,anchor=sample()
        result=readback.adjudicate(bundle,anchor)
        self.assertEqual(result["state"],"PORTABLE_BUNDLE_REPLAYED_ACK_HOLD")
        self.assertEqual(result["heads_preserved"],2)
        self.assertEqual(result["forks_preserved"],1)
        self.assertEqual(result["independently_authenticated_witnesses"],0)
        self.assertFalse(result["recovery_authorized"])
    def test_cryptographic_ack_still_hold(self):
        bundle,anchor=sample();ack,ack_anchor=make_ack(bundle)
        result=readback.adjudicate(bundle,anchor,ack,ack_anchor)
        self.assertEqual(result["state"],"SIGNED_ACK_CHECKED_CUSTODY_HOLD")
        self.assertTrue(result["ack_signature_valid"])
        self.assertIn("PHYSICAL_CUSTODY_UNVERIFIED",result["blockers"])
        self.assertFalse(result["lock_cleared"])
    def test_missing_branch_rejected(self):
        bundle,anchor=sample();bundle["heads"].pop()
        self.assertEqual(readback.adjudicate(bundle,anchor)["state"],"TRANSFER_REJECTED_HOLD")
    def test_manifest_mutation_rejected(self):
        bundle,anchor=sample();bundle["manifest_sha256"]="0"*64
        self.assertIn("BUNDLE_MANIFEST_INVALID",readback.adjudicate(bundle,anchor)["blockers"])
    def test_signature_mutation_rejected(self):
        bundle,anchor=sample()
        bundle["heads"][0]["envelope"]["signature_base64"]="forged"
        self.assertIn("RETAINED_ENVELOPE_HASH_CONFLICT",readback.adjudicate(bundle,anchor)["blockers"])
    def test_fork_metadata_mutation_rejected(self):
        bundle,anchor=sample()
        bundle["forks"][0]["conflicting_checkpoint_sha256"]=["a"*64]
        self.assertIn("FORK_REPLAY_OR_SIGNATURE_CONFLICT",readback.adjudicate(bundle,anchor)["blockers"])
    def test_bad_source_anchor_rejected(self):
        bundle,anchor=sample();anchor["key_sha256"]="0"*64
        self.assertIn("FORK_REPLAY_OR_SIGNATURE_CONFLICT",readback.adjudicate(bundle,anchor)["blockers"])
    def test_ack_wrong_manifest_rejected(self):
        bundle,anchor=sample();ack,ack_anchor=make_ack(bundle)
        ack["payload"]["manifest_sha256"]="0"*64
        self.assertIn("ACK_PAYLOAD_OR_BINDING_INVALID",readback.adjudicate(bundle,anchor,ack,ack_anchor)["blockers"])
    def test_ack_signature_swap_rejected(self):
        bundle,anchor=sample();ack,ack_anchor=make_ack(bundle)
        ack["signature_base64"]=base64.b64encode(b"f"*64).decode()
        self.assertIn("ACK_SIGNATURE_UNVERIFIED",readback.adjudicate(bundle,anchor,ack,ack_anchor)["blockers"])
    def test_ack_key_anchor_mismatch_rejected(self):
        bundle,anchor=sample();ack,ack_anchor=make_ack(bundle)
        ack_anchor["key_sha256"]="f"*64
        self.assertIn("ACK_ANCHOR_MISMATCH",readback.adjudicate(bundle,anchor,ack,ack_anchor)["blockers"])
    def test_ack_recovery_claim_rejected(self):
        bundle,anchor=sample();ack,ack_anchor=make_ack(bundle)
        ack["recovery_authorized"]=True
        self.assertIn("UNSAFE_ACK_AUTHORITY",readback.adjudicate(bundle,anchor,ack,ack_anchor)["blockers"])
    def test_absent_bundle_fail_closed(self):
        self.assertEqual(readback.adjudicate(None)["state"],"TRANSFER_REJECTED_HOLD")
    def test_source_owned_ack_cannot_be_witness(self):
        bundle,anchor=sample();ack,ack_anchor=make_ack(bundle)
        ack_anchor["externally_authenticated"]=True
        r=readback.adjudicate(bundle,anchor,ack,ack_anchor)
        self.assertEqual(r["independently_authenticated_witnesses"],0)
        self.assertFalse(r["authenticated_utc"])
        self.assertFalse(r["global_anti_rollback_authenticated"])

if __name__=="__main__":
    unittest.main()
