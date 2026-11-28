#!/usr/bin/env python3
"""SAPPHON-219 compact evidence adjudication fixtures (not third-party custody)."""
import importlib.util
import pathlib
import unittest
p=pathlib.Path(__file__).with_name("sapphon_219_cross_runner.py")
spec=importlib.util.spec_from_file_location("s219",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def fixture():
    return {
        "schema":"sapphon-218-second-runner-artifact-readback-v1",
        "state":"GITHUB_OWNED_EXTRACTED_BYTES_MATCH",
        "source_run_id":m.SOURCE_RUN,
        "source_attempt":m.SOURCE_ATTEMPT,
        "source_commit":m.SOURCE_COMMIT,
        "blockers":[],
        "file_sha256":m.CHECKS.copy(),
        "external_custody_authenticated":False,
        "independent_witnesses":0,
        "zip_envelope_sha256_independently_read":False,
        "recovery_authorized":False,
        "lock_cleared":False,
        "decision":"HOLD"
    }
class Tests(unittest.TestCase):
    def test_complete_source_owned_parity_still_hold(self):
        result=m.adjudicate(fixture())
        self.assertEqual(result["state"],"SOURCE_OWNED_IMAGE_BYTE_PARITY_VERIFIED")
        self.assertEqual(result["decision"],"HOLD")
        self.assertFalse(result["recovery_authorized"])
    def test_other_run_denied(self):
        x=fixture();x["source_run_id"]="46154833376"
        self.assertIn("EXACT_SOURCE_ANCESTRY_MISMATCH",m.adjudicate(x)["blockers"])
    def test_other_attempt_denied(self):
        x=fixture();x["source_attempt"]="2"
        self.assertIn("EXACT_SOURCE_ANCESTRY_MISMATCH",m.adjudicate(x)["blockers"])
    def test_other_commit_denied(self):
        x=fixture();x["source_commit"]="0"*40
        self.assertIn("EXACT_SOURCE_ANCESTRY_MISMATCH",m.adjudicate(x)["blockers"])
    def test_image_hash_mutation_denied(self):
        x=fixture();x["file_sha256"]["207-image.tar"]="a"*64
        self.assertIn("HASH_MISMATCH_207-image.tar",m.adjudicate(x)["blockers"])
    def test_extra_file_denied(self):
        x=fixture();x["file_sha256"]["extra"]="f"*64
        self.assertIn("FILE_INVENTORY_MISMATCH",m.adjudicate(x)["blockers"])
    def test_false_witness_denied(self):
        x=fixture();x["independent_witnesses"]=1
        self.assertIn("UNSUPPORTED_AUTHORITY_OR_ZIP_CLAIM",m.adjudicate(x)["blockers"])
    def test_zip_envelope_not_claimed(self):
        x=fixture();x["zip_envelope_sha256_independently_read"]=True
        self.assertIn("UNSUPPORTED_AUTHORITY_OR_ZIP_CLAIM",m.adjudicate(x)["blockers"])
    def test_recovery_flag_denied(self):
        x=fixture();x["recovery_authorized"]=True
        self.assertIn("UNSUPPORTED_AUTHORITY_OR_ZIP_CLAIM",m.adjudicate(x)["blockers"])
    def test_blockers_not_ignored(self):
        x=fixture();x["blockers"]=["unexpected"]
        self.assertIn("ORIGINAL_READBACK_NOT_CLEAN",m.adjudicate(x)["blockers"])
if __name__=="__main__": unittest.main()
