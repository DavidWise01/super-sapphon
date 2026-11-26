#!/usr/bin/env python3
"""SAPPHON-176 synthetic source-freeze negative controls."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_176_freeze.py")
spec=importlib.util.spec_from_file_location("freeze176",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def inputs():
 files={n:("source:"+str(n)).encode() for n in m.SOURCES}
 lock=b'{"packages":{"node_modules/playwright":{"integrity":"sha512-mock"},"node_modules/playwright-core":{"integrity":"sha512-mock"}}}'
 records={k:"not_observed" for k in m.CHECKS}
 return ["a"*40,records,files,lock]
class FreezeTests(unittest.TestCase):
 def case(self,change=lambda x:None):
  x=inputs();change(x);return m.evaluate(*x)
 def test_design_complete_without_ci(self):
  r=self.case();self.assertTrue(r["phase_design_complete"])
  self.assertFalse(r["ci_success_independently_verified"])
  self.assertFalse(r["recovery_authorized"])
 def test_eight_sources_hashed(self):
  self.assertEqual(len(self.case()["sources"]),8)
 def test_source_missing_denies_complete(self):
  r=self.case(lambda x:x[2].pop(174))
  self.assertFalse(r["phase_design_complete"])
 def test_wrong_head_denies_complete(self):
  r=self.case(lambda x:x.__setitem__(0,"bad"))
  self.assertFalse(r["phase_design_complete"])
 def test_passed_owned_tests_still_hold(self):
  def fill(x):
   for n in ("PYTHON","RUST","FROZEN"):x[1][n]="success"
  r=self.case(fill)
  self.assertTrue(r["source_tests_recorded_pass"])
  self.assertFalse(r["independent_external_custody"])
 def test_skipped_rust_not_pass(self):
  r=self.case(lambda x:x[1].update(RUST="skipped"))
  self.assertFalse(r["source_tests_recorded_pass"])
 def test_unsupported_status_rejected(self):
  r=self.case(lambda x:x[1].update(RUST="verified by magic"))
  self.assertIn("UNSUPPORTED_STATUS:RUST",r["findings"])
  self.assertFalse(r["phase_design_complete"])
  self.assertFalse(r["source_tests_recorded_pass"])
 def test_missing_integrity_visible(self):
  r=self.case(lambda x:x.__setitem__(3,b'{"packages":{}}'))
  self.assertIn("COMMITTED_NPM_LOCK_INTEGRITY_MISSING",r["findings"])
 def test_corrupt_lock_visible(self):
  r=self.case(lambda x:x.__setitem__(3,b'not json'))
  self.assertIn("COMMITTED_LOCK_INVALID_JSON",r["findings"])
 def test_changed_source_changes_digest(self):
  x=inputs();a=m.evaluate(*x)
  x[2][174]=b"changed"
  b=m.evaluate(*x)
  self.assertNotEqual(a["sources"][5]["sha256"],b["sources"][5]["sha256"])
 def test_missing_evidence_not_misreported_failed(self):
  r=self.case()
  self.assertEqual(r["recorded_outcomes"]["RUST"],"not_observed")
 def test_invariant_custody_never_promoted(self):
  r=self.case(lambda x:x[1].update({k:"success" for k in m.CHECKS}))
  self.assertFalse(r["recovery_authorized"])
  self.assertFalse(r["lock_cleared"])
if __name__=="__main__":unittest.main()
