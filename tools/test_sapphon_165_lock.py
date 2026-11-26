#!/usr/bin/env python3
"""SAPPHON-165 deterministic offline lock-schema and adversarial tests."""
import base64
import importlib.util
import json
import pathlib
import unittest
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("inspect165",ROOT/"sapphon_165_lock_inspect.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class LockTests(unittest.TestCase):
    def setUp(self):
        fake=base64.b64encode(b"x"*64).decode()
        self.package={"devDependencies":{"playwright":"1.65.1"}}
        self.lock={"lockfileVersion":3,"packages":{
            "":{"devDependencies":{"playwright":"1.65.1"}},
            "node_modules/playwright":{"version":"1.65.1",
              "integrity":"sha512-"+fake,
              "resolved":"https://registry.npmjs.org/playwright/-/playwright-1.65.1.tgz",
              "dependencies":{"playwright-core":"1.65.1"}},
            "node_modules/playwright-core":{"version":"1.65.1",
              "integrity":"sha512-"+fake,
              "resolved":"https://registry.npmjs.org/playwright-core/-/playwright-core-1.65.1.tgz"}
        }}
    def test_complete_fields_not_authority(self):
        self.assertEqual(module.inspect(self.lock,self.package),[])
    def test_missing_integrity_fails(self):
        del self.lock["packages"]["node_modules/playwright"]["integrity"]
        self.assertIn("node_modules/playwright:MISSING_SHA512",module.inspect(self.lock,self.package))
    def test_wrong_version_fails(self):
        self.lock["packages"]["node_modules/playwright-core"]["version"]="1.0.0"
        self.assertIn("node_modules/playwright-core:VERSION",module.inspect(self.lock,self.package))
    def test_wrong_registry_fails(self):
        self.lock["packages"]["node_modules/playwright"]["resolved"]="https://unknown.invalid/tar"
        self.assertIn("node_modules/playwright:REGISTRY_ORIGIN",module.inspect(self.lock,self.package))
    def test_invalid_sha512_fails(self):
        self.lock["packages"]["node_modules/playwright"]["integrity"]="sha512-!!!!!!"
        self.assertIn("node_modules/playwright:INVALID_SHA512",module.inspect(self.lock,self.package))
    def test_short_hash_fails(self):
        self.lock["packages"]["node_modules/playwright"]["integrity"]="sha512-"+base64.b64encode(b"x"*32).decode()
        self.assertIn("node_modules/playwright:SHA512_LENGTH",module.inspect(self.lock,self.package))
    def test_dependency_replaced_fails(self):
        self.lock["packages"]["node_modules/playwright"]["dependencies"]["playwright-core"]="0.0.0"
        self.assertIn("PLAYWRIGHT_CORE_DEPENDENCY",module.inspect(self.lock,self.package))
    def test_lockfile_version_fails(self):
        self.lock["lockfileVersion"]=2
        self.assertIn("LOCKFILE_V3_REQUIRED",module.inspect(self.lock,self.package))
if __name__=="__main__":unittest.main()
