#!/usr/bin/env python3
"""SAPPHON-214: static constraints for source-owned offline OCI build.

These tests check source/config only, not successful Docker execution,
pinned image provenance, or independently witnessed custody.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "tools" / "sapphon-214.Dockerfile"
WORKFLOW = ROOT / ".github" / "workflows" / "sapphon-207-vendor.yml"

class OfflineImageTests(unittest.TestCase):
    def test_tar_unpacked_for_cargo(self):
        lines = DOCKERFILE.read_text().splitlines()
        self.assertIn("ADD vendor.tar /src/vendor/", lines)
        self.assertNotIn("COPY vendor.tar /src/vendor/", lines)

    def test_base_is_build_argument_and_digested(self):
        content = DOCKERFILE.read_text()
        self.assertRegex(content, r"(?m)^ARG BASE$")
        self.assertRegex(content, r"(?m)^FROM \\?\$\{BASE\}$")
        workflow = WORKFLOW.read_text()
        self.assertIn("SAPPHON_RUST_BASE_IMAGE",workflow)
        self.assertIn("PINNED_BASE_REPODIGEST_NOT_OBSERVED",workflow)
        self.assertIn("docker pull \"$BASE\"",workflow)

    def test_no_online_cargo(self):
        content = DOCKERFILE.read_text()
        self.assertIn("ENV CARGO_NET_OFFLINE=true",content)
        self.assertIn("--locked --offline --all-targets",content)
        workflow = WORKFLOW.read_text()
        self.assertIn("docker build --network=none --pull=false",workflow)
        self.assertIn("-f tools/sapphon-214.Dockerfile",workflow)

    def test_no_authority_promoted(self):
        content = DOCKERFILE.read_text()
        self.assertNotIn("recovery_authorized=true", content.lower())
        workflow = WORKFLOW.read_text()
        self.assertIn("'recovery_authorized':False",workflow)
        self.assertIn("'lock_cleared':False",workflow)
        self.assertIn("'independent_witnesses':0",workflow)

    def test_base_regex_rejects_mutable_tags(self):
        pat = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
        self.assertIsNone(pat.fullmatch("rust:latest"))
        self.assertIsNone(pat.fullmatch("docker.io/library/rust@sha256:bad"))
        self.assertIsNotNone(pat.fullmatch("docker.io/library/rust@sha256:"+"a"*64))

if __name__ == "__main__":
    unittest.main()
