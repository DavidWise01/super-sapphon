#!/usr/bin/env python3
"""SAPPHON-187: adversarial retention/equivocation controls (synthetic)."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_187_ledger.py")
spec=importlib.util.spec_from_file_location("ledger187",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def obs(attempt=1,artifact_id=10,digest="a"*64,state="OBSERVED"):
 return {"source_sha":m.SOURCE,"workflow":m.WORKFLOW,
   "run_id":186,"attempt":attempt,"state":state,"artifact_id":artifact_id,
   "artifact_name":m.ARTIFACT,
   "original_zip_sha256":digest if state=="OBSERVED" else None,
   "embedded_run_id":186 if state=="OBSERVED" else None,
   "embedded_attempt":attempt if state=="OBSERVED" else None,
   "external_custody_authenticated":False,"recovery_authorized":False}
class Tests(unittest.TestCase):
 def test_single_observation_hold(self):
  x=m.chain(m.append([],obs()))
  self.assertTrue(x["source_owned_ledger_consistent"])
  self.assertFalse(x["recovery_authorized"])
 def test_distinct_attempts_not_equivocation(self):
  a=m.append([],obs());b=m.append(a,obs(attempt=2,artifact_id=11,digest="b"*64))
  self.assertEqual(m.chain(b)["equivocations"],[])
 def test_same_attempt_conflict_is_equivocation(self):
  a=m.append([],obs());b=m.append(a,obs(artifact_id=11,digest="b"*64))
  self.assertEqual(m.chain(b)["equivocations"][0]["type"],"SAME_ATTEMPT_ARTIFACT_EQUIVOCATION")
 def test_duplicate_same_bytes_not_equivocation(self):
  a=m.append([],obs());b=m.append(a,obs())
  self.assertEqual(m.chain(b)["equivocations"],[])
 def test_modified_previous_record_rejected(self):
  x=m.append([],obs());x[0]["envelope"]["observation"]["run_id"]=999
  with self.assertRaisesRegex(ValueError,"CHAIN_DIGEST_MISMATCH"):m.chain(x)
 def test_previous_hash_rejected(self):
  x=m.append(m.append([],obs()),obs(attempt=2,artifact_id=11))
  x[1]["envelope"]["previous_sha256"]="f"*64
  with self.assertRaisesRegex(ValueError,"CHAIN_BREAK"):m.chain(x)
 def test_unverified_deletion_rejected(self):
  row=obs(state="DELETED_OBSERVED");row["deletion_endpoint_confirmed"]=False
  with self.assertRaisesRegex(ValueError,"UNSUPPORTED_DELETION_INFERENCE"):m.append([],row)
 def test_confirmed_deletion_is_not_owned_zip(self):
  row=obs(state="DELETED_OBSERVED");row["deletion_endpoint_confirmed"]=True
  ledger=m.append([],row)
  self.assertFalse(m.chain(ledger)["recovery_authorized"])
 def test_expired_is_not_content(self):
  row=obs(state="EXPIRED")
  self.assertTrue(m.chain(m.append([],row))["source_owned_ledger_consistent"])
 def test_missing_zip_cannot_have_hash(self):
  row=obs(state="READBACK_UNAVAILABLE");row["original_zip_sha256"]="a"*64
  with self.assertRaisesRegex(ValueError,"UNOBSERVED_BYTES_FABRICATED"):m.append([],row)
 def test_incomplete_listing_not_deletion(self):
  row=obs(state="LISTING_INCOMPLETE")
  self.assertEqual(m.append([],row)[0]["envelope"]["observation"]["state"],"LISTING_INCOMPLETE")
 def test_wrong_source_rejected(self):
  row=obs();row["source_sha"]="b"*40
  with self.assertRaisesRegex(ValueError,"SOURCE_ANCESTRY_MISMATCH"):m.append([],row)
 def test_boolean_attempt_rejected(self):
  row=obs();row["attempt"]=True
  with self.assertRaisesRegex(ValueError,"INVALID_RUN_ATTEMPT"):m.append([],row)
 def test_forged_custody_rejected(self):
  row=obs();row["external_custody_authenticated"]=True
  with self.assertRaisesRegex(ValueError,"UNSUPPORTED_AUTHORITY"):m.append([],row)
 def test_api_time_is_not_trusted_time(self):
  row=obs();row["api_timestamp"]="2099-01-01T00:00:00Z"
  assert not m.chain(m.append([],row))["authenticated_utc"]
 def test_unrecognized_field_rejected(self):
  row=obs();row["delete_old_history"]=True
  with self.assertRaisesRegex(ValueError,"UNRECOGNIZED_RECORD_FIELDS"):m.append([],row)
 def test_max_entries_is_bounded(self):
  with self.assertRaisesRegex(ValueError,"INVALID_LEDGER_LENGTH"):m.chain([None]*(m.MAX_RECORDS+1))
if __name__=="__main__":unittest.main()
