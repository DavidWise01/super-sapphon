#!/usr/bin/env python3
"""SAPPHON-166 offline, synthetic negative-control tests."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest
p=Path(__file__).with_name("sapphon_166_candidate_review.py")
spec=importlib.util.spec_from_file_location("review166",p)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
COMMIT="a"*40
HASH="sha512-"+base64.b64encode(b"x"*64).decode()
def fixture():
    lock={"name":"sapphon-browser-acceptance","version":"1.0.0","lockfileVersion":3,"packages":{
      "":{"devDependencies":{"playwright":"1.65.1"}},
      "node_modules/playwright":{"version":"1.65.1","integrity":HASH,
        "resolved":"https://registry.npmjs.org/playwright/-/playwright-1.65.1.tgz",
        "dependencies":{"playwright-core":"1.65.1"}},
      "node_modules/playwright-core":{"version":"1.65.1","integrity":HASH,
        "resolved":"https://registry.npmjs.org/playwright-core/-/playwright-core-1.65.1.tgz"}
    }}
    candidate=json.dumps(lock,sort_keys=True).encode()
    summary={"schema":"sapphon-165-run-v1","source_commit":COMMIT,"run_id":"123",
        "attempt":"2","candidate_lock_committed_to_source":False,
        "external_custody_authenticated":False,"recovery_authority":"HOLD",
        "outcomes":{"REGISTRY":"success"}}
    inspection={"schema":"sapphon-165-lock-inspection-v1",
        "candidate_schema_complete":True,"issues":[],"lock_sha256":mod.sha(candidate),
        "registry_provenance_independently_authenticated":False,
        "committed_lock_qualified":False}
    return candidate,summary,inspection

class ReviewTests(unittest.TestCase):
    def issues(self,changes=lambda b,s,i:None):
        b,s,i=fixture();changes(b,s,i)
        return mod.assess(b,s,i,COMMIT,123,2)
    def test_consistent_candidate_still_not_authority(self):
        self.assertEqual(self.issues(),[])
    def test_wrong_commit(self):
        self.assertIn("SOURCE_COMMIT_MISMATCH",self.issues(lambda b,s,i:s.update(source_commit="b"*40)))
    def test_wrong_attempt(self):
        self.assertIn("SOURCE_ATTEMPT_MISMATCH",self.issues(lambda b,s,i:s.update(attempt="3")))
    def test_wrong_run(self):
        self.assertIn("SOURCE_RUN_MISMATCH",self.issues(lambda b,s,i:s.update(run_id="124")))
    def test_registry_failed(self):
        self.assertIn("REGISTRY_STEP_NOT_SUCCESS",self.issues(lambda b,s,i:s["outcomes"].update(REGISTRY="failure")))
    def test_candidate_byte_tampering(self):
        self.assertIn("CANDIDATE_SHA256_MISMATCH",self.issues(lambda b,s,i:i.update(lock_sha256="0"*64)))
    def test_integrity_missing(self):
        b,s,i=fixture();bad=json.loads(b);del bad["packages"]["node_modules/playwright"]["integrity"]
        b=json.dumps(bad).encode();i["lock_sha256"]=mod.sha(b)
        self.assertIn("playwright:SHA512_MISSING",mod.assess(b,s,i,COMMIT,123,2))
    def test_unqualified_claim_cannot_promote(self):
        self.assertIn("CANDIDATE_PROMOTION_CLAIM",self.issues(lambda b,s,i:s.update(candidate_lock_committed_to_source=True)))
    def test_external_custody_claim_rejected(self):
        self.assertIn("SOURCE_AUTHORITY_VIOLATION",self.issues(lambda b,s,i:s.update(external_custody_authenticated=True)))
    def test_inspection_failure_cannot_be_silenced(self):
        self.assertIn("INSPECTION_REPORTED_FAILURE",self.issues(lambda b,s,i:i.update(issues=["unverified"])))
    def test_missing_candidate_json_rejected(self):
        b,s,i=fixture()
        self.assertIn("CANDIDATE_INVALID_JSON",mod.assess(b"invalid",s,i,COMMIT,123,2))
if __name__=="__main__":unittest.main()
