#!/usr/bin/env python3
"""SAPPHON-234 14 synthetic challenge/response and replay tests."""
import base64
import copy
import secrets
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import sapphon_234_challenge_response as m

def pair(witness="synthetic-a",nonce=None,requested="a"*64,epoch=0,prior=None):
    challenge={"witness_id":witness,"challenge_nonce":nonce or secrets.token_hex(32),
               "requested_sha256":requested,"previous_response_sha256":prior,"epoch":epoch}
    p=dict(challenge,schema=m.SCHEMA,readback_sha256=requested)
    key=Ed25519PrivateKey.generate()
    response={"payload":p,"public_key_pem":key.public_key().public_bytes(
              Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode(),
              "signature_base64":base64.b64encode(key.sign(m.canon(p))).decode()}
    return challenge,response

class Tests(unittest.TestCase):
    def test_valid_local_pair_still_hold(self):
        c,r=pair();v=m.verify([c],[r])
        self.assertEqual(v["locally_valid_responses"],1)
        self.assertFalse(v["recovery_authorized"])
        self.assertFalse(v["replay_state_committed"])
    def test_three_locally_valid_not_independent(self):
        pairs=[pair("operator-"+str(i)) for i in range(3)]
        v=m.verify([x[0] for x in pairs],[x[1] for x in pairs])
        self.assertEqual(v["locally_valid_responses"],3)
        self.assertEqual(v["independently_authenticated_witnesses"],0)
    def test_changed_nonce_rejected(self):
        c,r=pair();r["payload"]["challenge_nonce"]="b"*64
        v=m.verify([c],[r])
        self.assertIn("CHALLENGE_RESPONSE_BINDING_MISMATCH",v["blockers"])
    def test_tampered_signature_rejected(self):
        c,r=pair();r["payload"]["requested_sha256"]="c"*64
        self.assertIn("RESPONSE_SIGNATURE_INVALID",m.verify([c],[r])["blockers"])
    def test_replayed_nonce_from_previous(self):
        c,r=pair()
        previous={"schema":"sapphon-234-replay-state-v1","used_nonces":[c["challenge_nonce"]],"last_by_witness":{}}
        self.assertIn("CHALLENGE_NONCE_ALREADY_USED",m.verify([c],[r],previous)["blockers"])
    def test_duplicate_nonce_within_batch(self):
        nonce=secrets.token_hex(32)
        c1,r1=pair("a",nonce);c2,r2=pair("b",nonce)
        self.assertIn("CHALLENGE_NONCE_DUPLICATE",m.verify([c1,c2],[r1,r2])["blockers"])
    def test_wrong_readback_digest(self):
        c,r=pair();r["payload"]["readback_sha256"]="0"*64
        self.assertIn("REMOTE_BYTE_DIGEST_MISMATCH",m.verify([c],[r])["blockers"])
    def test_duplicate_response(self):
        c,r=pair()
        self.assertIn("DUPLICATE_WITNESS_RESPONSE",m.verify([c],[r,r])["blockers"])
    def test_missing_response(self):
        c,r=pair()
        self.assertIn("CHALLENGE_RESPONSE_SET_INCOMPLETE",m.verify([c],[])["blockers"])
    def test_unanchored_prefix(self):
        c,r=pair(epoch=1)
        self.assertIn("UNANCHORED_WITNESS_PREFIX",m.verify([c],[r])["blockers"])
    def test_stale_epoch_chain(self):
        c,r=pair(epoch=2,prior="b"*64)
        previous={"schema":"sapphon-234-replay-state-v1","used_nonces":[],
                  "last_by_witness":{c["witness_id"]:{"epoch":2,"response_sha256":"b"*64}}}
        self.assertIn("WITNESS_CHAIN_REWIND_OR_FORK",m.verify([c],[r],previous)["blockers"])
    def test_proposal_requires_external_commit(self):
        c,r=pair();v=m.verify([c],[r])
        self.assertIn(c["challenge_nonce"],v["replay_state_proposal"]["used_nonces"])
        self.assertFalse(v["replay_state_committed"])
    def test_invalid_previous_state(self):
        c,r=pair()
        self.assertIn("REPLAY_STATE_INVALID",m.verify([c],[r],{})["blockers"])
    def test_canonical_digest(self):
        c,r=pair();v=m.verify([c],[r]);h=v.pop("evidence_sha256")
        self.assertEqual(m.sha(v),h)
if __name__=="__main__":unittest.main()
