#!/usr/bin/env python3
"""SAPPHON-180 offline original-byte binding negative controls."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_180_bind.py")
spec=importlib.util.spec_from_file_location("binding180",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
LOG=b"authentic source-owned job log bytes"
ZIP=b"PK\x03\x04synthetic ZIP-shaped bytes"
def fixture():
 return {"schema":"sapphon-180-evidence-manifest-v1","source_sha":m.SOURCE,
 "workflow":m.WORKFLOW,"job_name":m.JOB,
 "run_id":179,"attempt":2,"job_id":9001,"artifact_id":8001,
 "run_status":"completed","run_conclusion":"failure","job_conclusion":"failure",
 "artifact_name":"sapphon-179-provenance-replay","artifact_expired":False,
 "log_kind":"RAW_JOB_LOG","artifact_kind":"ORIGINAL_ZIP",
 "log_sha256":m.sha(LOG),"artifact_sha256":m.sha(ZIP),
 "independent_custody_authenticated":False,"recovery_authorized":False}
class Tests(unittest.TestCase):
 def test_exact_bytes_consistent_still_hold(self):
  x=m.classify(fixture(),LOG,ZIP)
  self.assertTrue(x["bytes_match_supplied_metadata"])
  self.assertFalse(x["external_metadata_authenticity_verified"])
  self.assertFalse(x["recovery_authorized"])
 def test_altered_log_denied(self):
  self.assertIn("MISMATCH_LOG_SHA256",m.classify(fixture(),LOG+b"!",ZIP)["findings"])
 def test_altered_artifact_denied(self):
  self.assertIn("MISMATCH_ARTIFACT_SHA256",m.classify(fixture(),LOG,ZIP+b"!")["findings"])
 def test_wrong_source_denied(self):
  d=fixture();d["source_sha"]="a"*40
  self.assertIn("WRONG_SOURCE_OR_WORKFLOW",m.classify(d,LOG,ZIP)["findings"])
 def test_wrong_job_denied(self):
  d=fixture();d["job_name"]="other"
  self.assertIn("WRONG_SOURCE_OR_WORKFLOW",m.classify(d,LOG,ZIP)["findings"])
 def test_boolean_attempt_denied(self):
  d=fixture();d["attempt"]=True
  self.assertIn("INVALID_ATTEMPT",m.classify(d,LOG,ZIP)["findings"])
 def test_excerpt_not_raw_denied(self):
  d=fixture();d["log_kind"]="REDACTED_EXCERPT"
  self.assertIn("LOG_NOT_RAW",m.classify(d,LOG,ZIP)["findings"])
 def test_expired_artifact_denied(self):
  d=fixture();d["artifact_expired"]=True
  self.assertIn("ARTIFACT_EXPIRED_OR_UNKNOWN",m.classify(d,LOG,ZIP)["findings"])
 def test_missing_artifact_denied(self):
  self.assertIn("ARTIFACT_BYTES_MISSING_OR_OVERSIZE",m.classify(fixture(),LOG,b"")["findings"])
 def test_unknown_hash_denied(self):
  d=fixture();d["artifact_sha256"]="not-a-sha"
  self.assertIn("MISMATCH_ARTIFACT_SHA256",m.classify(d,LOG,ZIP)["findings"])
 def test_success_parent_failed_job_denied(self):
  d=fixture();d["run_conclusion"]="success"
  self.assertIn("PARENT_JOB_CONTRADICTION",m.classify(d,LOG,ZIP)["findings"])
 def test_false_recovery_denied(self):
  d=fixture();d["recovery_authorized"]=True
  self.assertIn("UNSUPPORTED_AUTHORITY",m.classify(d,LOG,ZIP)["findings"])
if __name__=="__main__":unittest.main()
