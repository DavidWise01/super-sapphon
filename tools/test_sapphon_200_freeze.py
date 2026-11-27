#!/usr/bin/env python3
"""SAPPHON-200 synthetic final source freeze regressions, zero custody claims."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_200_freeze.py")
s=importlib.util.spec_from_file_location("f200",p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def fixture():
 return ["a"*40,{n:("rust source "+str(n)).encode() for n in m.SOURCES},
  {k:"not_observed" for k in m.REQUIRED},
  {"schema":"sapphon-199-retention-v1","state":"EXACT_RUN_NOT_OBSERVED",
   "original_parent_verified":False,"deletion_confirmed":False,
   "global_anti_rollback_authenticated":False,"independent_witnesses":0,
   "recovery_authorized":False,"lock_cleared":False}]
class Tests(unittest.TestCase):
 def check(self,edit=lambda x:None):
  f=fixture();edit(f);return m.freeze(*f)
 def test_eight_bounds_design_complete_but_hold(self):
  x=self.check()
  self.assertTrue(x["source_design_complete"])
  self.assertEqual([v["bound"] for v in x["sources"]],list(range(193,201)))
  self.assertFalse(x["recovery_authorized"])
 def test_missing_193(self):
  x=self.check(lambda f:f[1].pop(193))
  self.assertIn("SOURCE_MISSING_OR_EMPTY:193",x["findings"])
 def test_missing_200(self):
  x=self.check(lambda f:f[1].pop(200))
  self.assertIn("SOURCE_MISSING_OR_EMPTY:200",x["findings"])
 def test_extra_bound(self):
  x=self.check(lambda f:f[1].update({201:b"unauthorized"}))
  self.assertIn("EIGHT_SOURCE_SET_INVALID",x["findings"])
 def test_wrong_source_head(self):
  x=self.check(lambda f:f.__setitem__(0,"bad"))
  self.assertIn("SOURCE_HEAD_INVALID",x["findings"])
 def test_byte_change_changes_inventory_digest(self):
  f=fixture();a=m.freeze(*f)["inventory_sha256"]
  f[1][199]=b"changed"
  self.assertNotEqual(m.freeze(*f)["inventory_sha256"],a)
 def test_unknown_outcome(self):
  x=self.check(lambda f:f[2].update(RUST="CERTIFIED"))
  self.assertIn("OUTCOME_INVALID:RUST",x["findings"])
 def test_missing_outcome(self):
  x=self.check(lambda f:f[2].pop("PAGES"))
  self.assertIn("OUTCOME_SET_INVALID",x["findings"])
 def test_green_source_not_external_witness(self):
  x=self.check(lambda f:f[2].update({k:"success" for k in ("PYTHON","RUST","FROZEN")}))
  self.assertTrue(x["source_tests_observed_success"])
  self.assertEqual(x["independent_witnesses"],0)
 def test_missing_199_record(self):
  x=self.check(lambda f:f.__setitem__(3,{}))
  self.assertIn("RETENTION_RECORD_UNVERIFIED",x["findings"])
 def test_retention_with_false_recovery(self):
  x=self.check(lambda f:f[3].update(recovery_authorized=True))
  self.assertIn("RETENTION_FALSE_AUTHORITY",x["findings"])
 def test_retention_with_false_deletion(self):
  x=self.check(lambda f:f[3].update(deletion_confirmed=True))
  self.assertIn("UNSUPPORTED_DELETION_CLAIM",x["findings"])
 def test_retention_with_forged_rollback(self):
  x=self.check(lambda f:f[3].update(global_anti_rollback_authenticated=True))
  self.assertIn("FALSE_ANTI_ROLLBACK",x["findings"])
 def test_retention_with_forged_witness(self):
  x=self.check(lambda f:f[3].update(independent_witnesses=1))
  self.assertIn("FALSE_INDEPENDENT_WITNESSES",x["findings"])
 def test_missing_parent_not_pass(self):
  x=self.check()
  self.assertFalse(x["original_199_parent_observed"])
  self.assertFalse(x["successful_hosted_run_independently_verified"])
 def test_green_everything_still_no_recovery(self):
  x=self.check(lambda f:f[2].update({k:"success" for k in m.REQUIRED}))
  self.assertFalse(x["recovery_authorized"])
  self.assertFalse(x["global_anti_rollback_authenticated"])
if __name__=="__main__":unittest.main()
