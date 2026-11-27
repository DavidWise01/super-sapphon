#!/usr/bin/env python3
"""SAPPHON-192 synthetic fail-closed eight-source freeze tests."""
import importlib.util,json,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_192_freeze.py")
spec=importlib.util.spec_from_file_location("f192",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def fixture():
 return ["a"*40,{n:("rust source "+str(n)).encode() for n in m.SOURCES},
  {k:"not_observed" for k in m.REQUIRED},
  {"schema":"sapphon-190-key-registry-v1","out_of_band_authenticated":False,
   "keys":[],"authority_source":"none"}]
class Tests(unittest.TestCase):
 def case(self,edit=lambda x:None):
  f=fixture();edit(f);return m.freeze(*f)
 def test_all_eight_design_but_hold(self):
  x=self.case();self.assertTrue(x["source_design_complete"])
  self.assertEqual([v["bound"] for v in x["sources"]],list(range(185,193)))
  self.assertFalse(x["recovery_authorized"])
 def test_missing_185_rejected(self):
  x=self.case(lambda f:f[1].pop(185))
  self.assertIn("MISSING_SOURCE:185",x["findings"])
 def test_missing_192_rejected(self):
  x=self.case(lambda f:f[1].pop(192))
  self.assertIn("MISSING_SOURCE:192",x["findings"])
 def test_extra_module_rejected(self):
  x=self.case(lambda f:f[1].update({193:b"bad"}))
  self.assertIn("NONCANONICAL_SOURCE_SET",x["findings"])
 def test_invalid_commit_rejected(self):
  x=self.case(lambda f:f.__setitem__(0,"bad"))
  self.assertIn("HEAD_INVALID",x["findings"])
 def test_changed_bytes_change_digest(self):
  f=fixture();a=m.freeze(*f);f[1][190]=b"altered"
  self.assertNotEqual(a["inventory_sha256"],m.freeze(*f)["inventory_sha256"])
 def test_invalid_outcome_rejected(self):
  x=self.case(lambda f:f[2].update(RUST="CERTIFIED"))
  self.assertIn("OUTCOME_INVALID:RUST",x["findings"])
 def test_missing_outcome_rejected(self):
  x=self.case(lambda f:f[2].pop("PAGES"))
  self.assertIn("OUTCOME_SET",x["findings"])
 def test_passing_source_tests_no_external_authority(self):
  def edit(f):
   for k in ("PYTHON","RUST","FROZEN"):f[2][k]="success"
  x=self.case(edit)
  self.assertTrue(x["source_checks_recorded_success"])
  self.assertEqual(x["independent_witnesses"],0)
 def test_forged_registry_denied(self):
  x=self.case(lambda f:f[3].update(out_of_band_authenticated=True))
  self.assertIn("FALSE_EXTERNAL_KEY_ENROLLMENT",x["findings"])
 def test_nonempty_registry_denied(self):
  x=self.case(lambda f:f[3].update(keys=[{"key":"self-issued"}]))
  self.assertIn("FALSE_EXTERNAL_KEY_ENROLLMENT",x["findings"])
 def test_source_design_percentage_not_ci(self):
  x=self.case();self.assertEqual(x["source_design_percent"],100)
  self.assertFalse(x["successful_hosted_run_independently_verified"])
 def test_all_green_still_recovery_hold(self):
  x=self.case(lambda f:f[2].update({k:"success" for k in m.REQUIRED}))
  self.assertFalse(x["recovery_authorized"])
  self.assertFalse(x["npm_registry_integrity_qualified"])
 def test_invalid_registry_schema(self):
  x=self.case(lambda f:f[3].update(schema="wrong"))
  self.assertIn("FALSE_EXTERNAL_KEY_ENROLLMENT",x["findings"])
if __name__=="__main__":unittest.main()
