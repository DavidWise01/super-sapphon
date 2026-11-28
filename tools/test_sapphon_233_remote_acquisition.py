#!/usr/bin/env python3
"""SAPPHON-233 remote acquisition tests; all network calls mocked."""
import copy
import hashlib
import unittest
import sapphon_233_remote_acquisition as m

def target(id="a",url="https://raw.githubusercontent.com/example/repo/main/evidence.json",
           ancestry="repo-owner/repo"):
    return {"id":id,"url":url,"ancestry_root":ancestry,
            "expected_sha256":None,"claimed_operator":"unverified-operator"}

def remote(url):
    return {"status":200,"bytes":b"frozen-test-evidence","content_type":"application/octet-stream"}

class Tests(unittest.TestCase):
    def test_bytes_observed_no_external_witness(self):
        o=m.assess([target()],remote)
        self.assertEqual(o["observed_count"],1)
        self.assertEqual(o["independently_authenticated_witnesses"],0)
        self.assertFalse(o["recovery_authorized"])
    def test_one_root_three_urls_not_three_witnesses(self):
        ts=[target(str(i),"https://raw.githubusercontent.com/a/b/"+str(i)) for i in range(3)]
        o=m.assess(ts,remote)
        self.assertEqual(len(o["declared_ancestry_groups"]),1)
        self.assertEqual(o["observed_count"],3)
        self.assertEqual(o["independently_authenticated_witnesses"],0)
    def test_three_claimed_roots_still_zero_witnesses(self):
        o=m.assess([target(str(i),"https://raw.githubusercontent.com/a/b/"+str(i),str(i)) for i in range(3)],remote)
        self.assertEqual(len(o["declared_ancestry_groups"]),3)
        self.assertEqual(o["independently_authenticated_witnesses"],0)
    def test_expected_digest_match(self):
        t=target();t["expected_sha256"]=hashlib.sha256(b"frozen-test-evidence").hexdigest()
        self.assertEqual(m.assess([t],remote)["observed_count"],1)
    def test_expected_digest_mismatch(self):
        t=target();t["expected_sha256"]="0"*64
        self.assertIn("EXPECTED_DIGEST_MISMATCH",m.assess([t],remote)["blockers"])
    def test_private_ip_rejected(self):
        self.assertEqual(m.assess([target(url="https://127.0.0.1/test")],remote)["observed_count"],0)
    def test_http_rejected(self):
        self.assertIn("HTTPS_URL_REQUIRED",m.assess([target(url="http://example.com")],remote)["blockers"])
    def test_userinfo_rejected(self):
        self.assertIn("HTTPS_URL_REQUIRED",m.assess([target(url="https://a:b@example.com/x")],remote)["blockers"])
    def test_local_hostname_rejected(self):
        self.assertIn("HOST_NOT_PUBLIC",m.assess([target(url="https://metadata.local/")],remote)["blockers"])
    def test_bad_schema(self):
        self.assertIn("TARGET_SCHEMA_INVALID",m.assess([{}],remote)["blockers"])
    def test_duplicate_target(self):
        self.assertIn("TARGET_ID_DUPLICATE",m.assess([target(),target()],remote)["blockers"])
    def test_bounded_target_inventory(self):
        self.assertIn("TARGET_INVENTORY_INVALID",m.assess([target(str(i)) for i in range(13)],remote)["blockers"])
    def test_oversize_bytes(self):
        def huge(u):return {"status":200,"bytes":b"x"*(m.MAX_BYTES+1)}
        self.assertEqual(m.assess([target()],huge)["observed_count"],0)
    def test_missing_remote(self):
        def missing(u):raise OSError("network unavailable")
        self.assertIn("FETCH_FAILED_OSError",m.assess([target()],missing)["blockers"])
    def test_unexpected_status(self):
        def bad(u):return {"status":404,"bytes":b""}
        self.assertEqual(m.assess([target()],bad)["observed_count"],0)
    def test_digest_deterministic(self):
        result=m.assess([target()],remote)
        h=result.pop("evidence_sha256")
        self.assertEqual(h,m.sha(result))
if __name__=="__main__":unittest.main()
