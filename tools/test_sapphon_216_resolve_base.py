#!/usr/bin/env python3
"""SAPPHON-216: source-only regression tests; not actual registry execution."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent.parent
SCRIPT=(ROOT/"tools/sapphon_216_resolve_base.sh").read_text()
WORKFLOW=(ROOT/".github/workflows/sapphon-207-vendor.yml").read_text()
IMAGE=(ROOT/"tools/sapphon_215_image_gate.py").read_text()

class Tests(unittest.TestCase):
    def test_discovery_tag_only_then_digest(self):
        self.assertIn('docker pull "$discovery_tag"',SCRIPT)
        self.assertIn('docker pull "$candidate"',SCRIPT)
        self.assertIn('ref not in (item.get("RepoDigests") or [])',SCRIPT)
        self.assertIn('printf \'BASE=%s\\n\' "$candidate" >> "$GITHUB_ENV"',SCRIPT)
    def test_no_generated_digest_or_mutable_build(self):
        self.assertIn("PINNED_BASE_DIGEST_NOT_IN_LOCAL_REPODIGESTS",SCRIPT)
        self.assertIn("REGISTRY_TAG_DISCOVERY_PINNED_IN_RUN",SCRIPT)
        self.assertIn('docker build --network=none --pull=false',WORKFLOW)
        self.assertIn('--build-arg "BASE=$BASE"',WORKFLOW)
    def test_image_gated_on_resolution(self):
        self.assertIn("steps.base.outcome == 'success'",WORKFLOW)
        self.assertIn("bash tools/sapphon_216_resolve_base.sh",WORKFLOW)
        self.assertIn("216-base-resolution.json",WORKFLOW)
    def test_large_archive_hashed_streamingly(self):
        self.assertIn('hashlib.file_digest(f, "sha256")',IMAGE)
    def test_no_operational_authority(self):
        self.assertIn('"recovery_authorized":False',SCRIPT)
        self.assertIn('"lock_cleared":False',SCRIPT)
        self.assertIn('"independent_witnesses":0',SCRIPT)
if __name__=="__main__":
    unittest.main()
