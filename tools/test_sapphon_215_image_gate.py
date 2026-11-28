#!/usr/bin/env python3
"""SAPPHON-215 image evidence policy regression tests."""
import importlib.util
from pathlib import Path
import hashlib
import unittest

p=Path(__file__).with_name("sapphon_215_image_gate.py")
spec=importlib.util.spec_from_file_location("s215",p)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def sample():
    b=b"owned-image-archive-fixture"
    h=hashlib.sha256(b).hexdigest()
    image_id="sha256:"+"b"*64
    report={"schema":"sapphon-207-local-image-v1",
            "base_ref":"docker.io/library/rust@sha256:"+"a"*64,
            "base_local_id":"sha256:"+"c"*64,
            "built_image_local_id":image_id,
            "archive_sha256":h,"recovery_authorized":False,"lock_cleared":False}
    summary={"schema":"sapphon-207-source-owned-run-v1",
             "steps":dict.fromkeys(("PYTHON","RUST","FROZEN","VENDOR","IMAGE"),"success"),
             "built_image_local_id":image_id,
             "built_image_archive_sha256":h,
             "recovery_authorized":False,"lock_cleared":False}
    return summary,report,b,h+"  207-image.tar\n"

class ImageGateTests(unittest.TestCase):
    def test_missing_image_stays_hold(self):
        summary,_,_,_=sample()
        summary["steps"]["IMAGE"]="failure"
        result=m.assess(summary)
        self.assertEqual(result["state"],"IMAGE_QUALIFICATION_HOLD")
        self.assertIn("IMAGE_STEP_NOT_SUCCESS",result["blockers"])
    def test_consistent_owned_artifact_never_grants_recovery(self):
        result=m.assess(*sample())
        self.assertEqual(result["state"],"SOURCE_OWNED_IMAGE_ARCHIVE_VERIFIED")
        self.assertFalse(result["recovery_authorized"])
        self.assertEqual(result["external_witnesses"],0)
    def test_mutated_archive_denied(self):
        summary,report,raw,receipt=sample()
        result=m.assess(summary,report,raw+b"tampered",receipt)
        self.assertIn("IMAGE_ARCHIVE_HASH_NOT_MATCHED",result["blockers"])
    def test_mutable_tag_denied(self):
        summary,report,raw,receipt=sample()
        report["base_ref"]="rust:latest"
        result=m.assess(summary,report,raw,receipt)
        self.assertIn("IMMUTABLE_BASE_REF_UNVERIFIED",result["blockers"])
    def test_false_authority_denied(self):
        summary,report,raw,receipt=sample()
        report["recovery_authorized"]=True
        result=m.assess(summary,report,raw,receipt)
        self.assertIn("UNSAFE_IMAGE_AUTHORITY_CLAIM",result["blockers"])
    def test_image_success_without_bytes_denied(self):
        summary,report,_,_=sample()
        result=m.assess(summary,report,None,None)
        self.assertIn("ORIGINAL_IMAGE_ARCHIVE_UNAVAILABLE",result["blockers"])
    def test_wrong_image_id_denied(self):
        summary,report,raw,receipt=sample()
        summary["built_image_local_id"]="sha256:"+"d"*64
        self.assertIn("IMAGE_ID_CONFLICT",m.assess(summary,report,raw,receipt)["blockers"])

if __name__=="__main__":
    unittest.main()
