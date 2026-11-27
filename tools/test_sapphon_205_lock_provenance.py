#!/usr/bin/env python3
"""SAPPHON-205 synthetic lock/metadata checks (not hosted evidence)."""
import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name("sapphon_205_lock_provenance.py")
s=importlib.util.spec_from_file_location("lock205",p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
MANIFEST=b'[package]\nname = "sapphon-liveness"\nversion = "0.1.0"\n'
LOCK=b'version = 4\n[[package]]\nname = "sapphon-liveness"\nversion = "0.1.0"\n[[package]]\nname = "sha2"\nversion = "0.10.9"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "'+b'a'*64+b'"\n'
META={"packages":[{"name":"sapphon-liveness","version":"0.1.0"},{"name":"sha2","version":"0.10.9"}]}
CHECKS={"lock_generation":True,"vendor":True,"offline_metadata":True,"offline_check":True}
class Tests(unittest.TestCase):
 def runcheck(self,lock=LOCK,metadata=META,checks=CHECKS,manifest=MANIFEST):
  return m.inspect(manifest,lock,metadata,checks)
 def test_valid_fixture_owned_only(self):
  r=self.runcheck();self.assertEqual(r["state"],"GITHUB_OWNED_OFFLINE_DEPENDENCY_CHECK")
  self.assertTrue(r["offline_verified"]);self.assertFalse(r["image_digest_verified"])
 def test_missing_lock(self):
  self.assertEqual(self.runcheck(lock=b"")["state"],"LOCK_BYTES_NOT_OBSERVED")
 def test_wrong_package(self):
  self.assertEqual(self.runcheck(manifest=b'[package]\nname="wrong"\n')["state"],"WRONG_CRATE")
 def test_invalid_lock(self):
  self.assertEqual(self.runcheck(lock=b"not=toml??")["state"],"LOCK_NOT_TOML")
 def test_version(self):
  self.assertEqual(self.runcheck(lock=LOCK.replace(b"version = 4",b"version = 2",1))["state"],"LOCK_VERSION_INVALID")
 def test_duplicate_package(self):
  rest=LOCK[LOCK.index(b'[[package]]\nname = "sha2"'):]
  self.assertEqual(self.runcheck(lock=LOCK+rest)["state"],"LOCK_PACKAGE_DUPLICATED")
 def test_bad_registry_checksum(self):
  self.assertEqual(self.runcheck(lock=LOCK.replace(b"a"*64,b"bad"))["state"],"REGISTRY_PACKAGE_CHECKSUM_INVALID")
 def test_missing_target(self):
  self.assertEqual(self.runcheck(lock=b'version=4\n[[package]]\nname="sha2"\nversion="0.10.9"\n')["state"],"TARGET_PACKAGE_MISSING")
 def test_missing_metadata(self):
  self.assertEqual(self.runcheck(metadata={})["state"],"CARGO_METADATA_UNAVAILABLE")
 def test_wrong_metadata(self):
  self.assertEqual(self.runcheck(metadata={"packages":[META["packages"][0]]})["state"],"LOCK_METADATA_PACKAGE_CONFLICT")
 def test_no_generation(self):
  c=dict(CHECKS,lock_generation=False)
  self.assertEqual(self.runcheck(checks=c)["state"],"LOCK_GENERATION_NOT_OBSERVED")
 def test_no_vendor(self):
  c=dict(CHECKS,vendor=False)
  self.assertEqual(self.runcheck(checks=c)["state"],"VENDOR_NOT_OBSERVED")
 def test_no_offline_metadata(self):
  c=dict(CHECKS,offline_metadata=False)
  self.assertEqual(self.runcheck(checks=c)["state"],"OFFLINE_METADATA_NOT_OBSERVED")
 def test_no_offline_check(self):
  c=dict(CHECKS,offline_check=False)
  self.assertEqual(self.runcheck(checks=c)["state"],"OFFLINE_CHECK_NOT_OBSERVED")
 def test_unknown_outcome(self):
  c=dict(CHECKS,source_ok=True)
  self.assertEqual(self.runcheck(checks=c)["state"],"CHECK_SET_INCOMPLETE")
 def test_no_authority_even_valid(self):
  r=self.runcheck();self.assertFalse(r["recovery_authorized"])
  self.assertEqual(r["independent_witnesses"],0)
if __name__=="__main__":unittest.main()
