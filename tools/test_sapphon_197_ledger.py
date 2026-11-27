#!/usr/bin/env python3
"""SAPPHON-197 negative controls: source-owned history only."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_197_ledger.py")
sp=importlib.util.spec_from_file_location("ledger197",p)
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def event(state="GITHUB_OWNED_HASH_MATCH",log="a"*64,ziphash="b"*64,run=193,attempt=2):
 observed=state.startswith("GITHUB_OWNED_")
 return {"schema":"sapphon-197-observation-v1","source_sha":m.SOURCE,
  "original_source_sha":m.ORIGINAL_SOURCE,"original_workflow":m.ORIGINAL_WORKFLOW,
  "original_run_id":run,"original_attempt":attempt,"state":state,
  "log_sha256":log if observed else None,"zip_sha256":ziphash if observed else None,
  "original_bytes_reacquired":observed,"independent_witnesses":0,
  "external_custody_authenticated":False,"recovery_authorized":False,"lock_cleared":False}
class Tests(unittest.TestCase):
 def test_first_genuine_owned_event_hold(self):
  r=m.validate(m.append([],event()))
  self.assertEqual(r["entries"],1);self.assertFalse(r["recovery_authorized"])
 def test_same_attempt_matching_bytes_no_fork(self):
  records=m.append(m.append([],event()),event())
  self.assertEqual(m.validate(records)["forks"],[])
 def test_same_attempt_changed_log_fork(self):
  records=m.append(m.append([],event()),event(log="c"*64))
  self.assertEqual(m.validate(records)["forks"][0]["type"],"SAME_ORIGINAL_ATTEMPT_BYTE_FORK")
 def test_same_attempt_changed_zip_fork(self):
  records=m.append(m.append([],event()),event(ziphash="d"*64))
  self.assertEqual(len(m.validate(records)["forks"]),1)
 def test_distinct_run_attempt_not_fork(self):
  records=m.append(m.append([],event()),event(attempt=3,log="c"*64))
  self.assertEqual(m.validate(records)["forks"],[])
 def test_missing_and_expired_not_fork(self):
  records=m.append([],event())
  records=m.append(records,event(state="193_ARTIFACT_EXPIRED"))
  self.assertEqual(len(m.validate(records)["missing_and_expired"]),1)
  self.assertEqual(len(m.validate(records)["forks"]),0)
 def test_missing_must_have_no_digests(self):
  x=event(state="READBACK_UNAVAILABLE");x["log_sha256"]="a"*64
  with self.assertRaisesRegex(ValueError,"UNOBSERVED_DIGEST"):m.append([],x)
 def test_observed_must_have_both_digests(self):
  with self.assertRaisesRegex(ValueError,"OBSERVED_ORIGINAL"):m.append([],event(ziphash=None))
 def test_forged_external_witness_rejected(self):
  x=event();x["independent_witnesses"]=1
  with self.assertRaisesRegex(ValueError,"EVENT_AUTHORITY"):m.append([],x)
 def test_forged_recovery_rejected(self):
  x=event();x["recovery_authorized"]=True
  with self.assertRaisesRegex(ValueError,"EVENT_AUTHORITY"):m.append([],x)
 def test_tampered_history_rejected(self):
  items=m.append([],event());items[0]["envelope"]["observation"]["log_sha256"]="d"*64
  with self.assertRaisesRegex(ValueError,"HASH_CHAIN_TAMPERED"):m.validate(items)
 def test_broken_parent_rejected(self):
  items=m.append(m.append([],event()),event());items[1]["envelope"]["previous_sha256"]="0"*64
  with self.assertRaisesRegex(ValueError,"NONMONOTONIC_HASH_CHAIN"):m.validate(items)
 def test_missing_source_rejected(self):
  x=event();x["source_sha"]="d"*40
  with self.assertRaisesRegex(ValueError,"EVENT_ANCESTRY"):m.append([],x)
 def test_unknown_field_rejected(self):
  x=event();x["trusted_utc"]=True
  with self.assertRaisesRegex(ValueError,"EVENT_FIELDS"):m.append([],x)
 def test_empty_chain_holds(self):
  r=m.validate([]);self.assertEqual(r["tip_sha256"],"0"*64)
  self.assertFalse(r["recovery_authorized"])
 def test_conversion_unverified_is_not_observed(self):
  x=m.from_reacquisition({"schema":"sapphon-196-original-byte-reacquisition-v1","state":"195_RUN_NOT_FOUND"})
  self.assertEqual(x["state"],"195_RUN_NOT_FOUND");self.assertIsNone(x["log_sha256"])
 def test_conversion_observed_requires_true_flag(self):
  x=m.from_reacquisition({"schema":"sapphon-196-original-byte-reacquisition-v1",
   "state":"GITHUB_OWNED_HASH_MATCH","original_run_id":193,"original_attempt":2,
   "log_sha256":"a"*64,"zip_sha256":"b"*64,"original_bytes_reacquired":False})
  with self.assertRaisesRegex(ValueError,"OBSERVED_ORIGINAL"):m.append([],x)
if __name__=="__main__":unittest.main()
