#!/usr/bin/env python3
"""SAPPHON-184 immutable eight-bound source-design negative controls."""
import importlib.util,pathlib,json,unittest
p=pathlib.Path(__file__).with_name("sapphon_184_freeze.py")
s=importlib.util.spec_from_file_location("f184",p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def inputs():
 return ["a"*40,{n:("module "+str(n)).encode() for n in m.SOURCES},
         {n:"not_observed" for n in m.CHECKS},
         json.dumps({"packages":{}}).encode()]
class Tests(unittest.TestCase):
 def case(self,change=lambda v:None):
  a=inputs();change(a);return m.freeze(*a)
 def test_design_complete_does_not_certify_runtime(self):
  r=self.case();self.assertTrue(r["source_design_complete"])
  self.assertFalse(r["verified_hosted_run"])
  self.assertFalse(r["recovery_authorized"])
 def test_exact_eight_canonical_modules(self):
  r=self.case();self.assertEqual([x["bound"] for x in r["sources"]],list(range(177,185)))
 def test_missing_module_fails(self):
  r=self.case(lambda v:v[1].pop(181))
  self.assertFalse(r["source_design_complete"])
 def test_extra_source_fails(self):
  r=self.case(lambda v:v[1].update({185:b"unexpected"}))
  self.assertIn("NONCANONICAL_SOURCE_SET",r["findings"])
 def test_missing_head_fails(self):
  r=self.case(lambda v:v.__setitem__(0,"bad"))
  self.assertIn("INVALID_HEAD",r["findings"])
 def test_invalid_outcome_fails(self):
  r=self.case(lambda v:v[2].update(RUST="PASS_CERTIFIED"))
  self.assertFalse(r["source_design_complete"])
  self.assertFalse(r["source_checks_recorded_pass"])
 def test_boolean_outcome_fails(self):
  r=self.case(lambda v:v[2].update(PYTHON=True))
  self.assertIn("INVALID_OUTCOME:PYTHON",r["findings"])
 def test_missing_outcome_fails(self):
  r=self.case(lambda v:v[2].pop("PAGES"))
  self.assertIn("OUTCOME_KEY_SET",r["findings"])
 def test_source_pass_still_not_external_custody(self):
  def setpasses(v):
   for n in ("PYTHON","RUST","FROZEN"):v[2][n]="success"
  r=self.case(setpasses)
  self.assertTrue(r["source_checks_recorded_pass"])
  self.assertFalse(r["external_custody_authenticated"])
 def test_missing_lock_json_fails(self):
  r=self.case(lambda v:v.__setitem__(3,b"not json"))
  self.assertIn("LOCKFILE_JSON",r["findings"])
 def test_lock_schema_fails(self):
  r=self.case(lambda v:v.__setitem__(3,b"{}"))
  self.assertIn("LOCKFILE_SCHEMA",r["findings"])
 def test_modified_byte_changes_digest(self):
  v=inputs();a=m.freeze(*v);v[1][181]=b"modified"
  b=m.freeze(*v)
  self.assertNotEqual(a["sources"][4]["sha256"],b["sources"][4]["sha256"])
 def test_no_recovery_even_all_outcomes_success(self):
  r=self.case(lambda v:v[2].update({key:"success" for key in m.CHECKS}))
  self.assertFalse(r["recovery_authorized"])
  self.assertFalse(r["npm_registry_integrity_qualified"])
if __name__=="__main__":unittest.main()
