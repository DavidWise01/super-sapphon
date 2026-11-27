#!/usr/bin/env python3
"""SAPPHON-189 fork detection negative controls; synthetic inputs only."""
import importlib.util,pathlib,unittest
path=pathlib.Path(__file__).with_name("sapphon_189_forks.py")
spec=importlib.util.spec_from_file_location("fork189",path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def claim(surface="github-actions",root="a"*64,state="OBSERVED",attempt=1):
 return {"schema":"sapphon-189-root-claim-v1","source_sha":m.SOURCE,
  "workflow":m.WORKFLOW,"artifact_name":m.ARTIFACT,
  "run_id":188,"attempt":attempt,"lineage_id":"original-188",
  "custodian":"github-owned","surface":surface,"evidence_state":state,
  "root_sha256":root if state=="OBSERVED" else None,
  "artifact_sha256":"c"*64 if state=="OBSERVED" else None,
  "independently_authenticated":False,"recovery_authorized":False}
class Tests(unittest.TestCase):
 def test_matching_mirrors_still_zero_witnesses(self):
  result=m.compare([claim("github-api"),claim("github-actions")])
  self.assertTrue(result["owned_roots_consistent"])
  self.assertEqual(result["independent_witnesses"],0)
  self.assertFalse(result["recovery_authorized"])
 def test_same_lineage_conflicting_roots(self):
  result=m.compare([claim("github-api"),claim("github-pages","b"*64)])
  self.assertEqual(result["status"],"ROOT_FORK_OBSERVED")
  self.assertEqual(result["forks"][0]["type"],"OWNED_ANCESTRY_ROOT_FORK")
 def test_different_attempt_not_fork(self):
  result=m.compare([claim("github-api"),claim("github-actions","b"*64,attempt=2)])
  self.assertEqual(result["status"],"OWNED_ROOTS_CONSISTENT")
 def test_missing_and_observed_not_fork(self):
  result=m.compare([claim("github-api"),claim("github-actions",state="READBACK_UNAVAILABLE")])
  self.assertEqual(result["status"],"OWNED_ROOTS_CONSISTENT")
 def test_all_missing_not_consistent(self):
  result=m.compare([claim(state="READBACK_UNAVAILABLE")])
  self.assertEqual(result["status"],"NO_OBSERVED_ROOTS")
  self.assertFalse(result["owned_roots_consistent"])
 def test_claiming_independent_custody_denied(self):
  x=claim();x["independently_authenticated"]=True
  with self.assertRaisesRegex(ValueError,"FORGED_AUTHORITY"):m.compare([x])
 def test_external_custodian_not_accepted_as_genuine(self):
  x=claim();x["custodian"]="unverified-external"
  with self.assertRaisesRegex(ValueError,"UNVERIFIED_CUSTODIAN"):m.compare([x])
 def test_wrong_commit_denied(self):
  x=claim();x["source_sha"]="b"*40
  with self.assertRaisesRegex(ValueError,"SOURCE_MISMATCH"):m.compare([x])
 def test_wrong_artifact_denied(self):
  x=claim();x["artifact_name"]="not-this-one"
  with self.assertRaisesRegex(ValueError,"WORKFLOW_ARTIFACT_MISMATCH"):m.compare([x])
 def test_boolean_attempt_denied(self):
  x=claim();x["attempt"]=True
  with self.assertRaisesRegex(ValueError,"RUN_IDENTITY"):m.compare([x])
 def test_duplicate_surface_denied(self):
  with self.assertRaisesRegex(ValueError,"DUPLICATE_SURFACE_CLAIM"):
   m.compare([claim(),claim()])
 def test_fake_missing_hash_denied(self):
  x=claim(state="ARTIFACT_EXPIRED");x["root_sha256"]="a"*64
  with self.assertRaisesRegex(ValueError,"UNOBSERVED_DIGEST_FABRICATION"):m.compare([x])
 def test_missing_hash_on_observed_denied(self):
  x=claim();x["root_sha256"]=None
  with self.assertRaisesRegex(ValueError,"OBSERVED_ROOT_DIGEST"):m.compare([x])
 def test_new_unknown_field_denied(self):
  x=claim();x["custody_granted"]=True
  with self.assertRaisesRegex(ValueError,"CLAIM_FIELDS"):m.compare([x])
 def test_empty_set_not_pass(self):
  r=m.compare([])
  self.assertEqual(r["status"],"NO_OBSERVED_ROOTS")
  self.assertEqual(r["independent_witnesses"],0)
 def test_capped_set(self):
  with self.assertRaisesRegex(ValueError,"CLAIM_SET"):m.compare([claim()]*(m.MAX_CLAIMS+1))
if __name__=="__main__":unittest.main()
