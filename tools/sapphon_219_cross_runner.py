#!/usr/bin/env python3
"""SAPPHON-219 — verify a compact second-runner readback against frozen ancestry.

No external custody, UTC authentication, global anti-rollback, or operational
authority can be inferred from two GitHub-owned execution environments.
"""
import argparse
import json
import pathlib
import re
import sys

SOURCE_RUN = "46154833375"
SOURCE_ATTEMPT = "1"
SOURCE_COMMIT = "c167a95a05177e280625fa61613c1b1fa20f75e9"
CHECKS = {
    "207-Cargo.lock":"2ee90c706c436c450c786e7ecf5a12243c9dd8fc213a39d0ff071737dab6238c",
    "207-vendor.tar":"84c024537ba4d52f6892d080b08ed94c9a5a38c666cd1538a932bbfedd90c38e",
    "207-image.tar":"32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197",
}
EXPECTED_KEYS=set(CHECKS)
HEX64=re.compile(r"^[0-9a-f]{64}$")

def adjudicate(report):
    blockers=[]
    if type(report) is not dict:
        report={}
        blockers.append("INVALID_REPORT")
    if report.get("schema")!="sapphon-218-second-runner-artifact-readback-v1":
        blockers.append("SCHEMA_MISMATCH")
    if (str(report.get("source_run_id"))!=SOURCE_RUN or
        str(report.get("source_attempt"))!=SOURCE_ATTEMPT or
        report.get("source_commit")!=SOURCE_COMMIT):
        blockers.append("EXACT_SOURCE_ANCESTRY_MISMATCH")
    if report.get("state")!="GITHUB_OWNED_EXTRACTED_BYTES_MATCH" or report.get("blockers")!=[]:
        blockers.append("ORIGINAL_READBACK_NOT_CLEAN")
    hashes=report.get("file_sha256")
    if type(hashes) is not dict or set(hashes)!=EXPECTED_KEYS:
        blockers.append("FILE_INVENTORY_MISMATCH")
    else:
        for name,expected in CHECKS.items():
            actual=hashes.get(name)
            if type(actual) is not str or not HEX64.fullmatch(actual) or actual!=expected:
                blockers.append("HASH_MISMATCH_"+name)
    if (report.get("external_custody_authenticated") is not False or
        report.get("independent_witnesses")!=0 or
        report.get("recovery_authorized") is not False or
        report.get("lock_cleared") is not False or
        report.get("decision")!="HOLD" or
        report.get("zip_envelope_sha256_independently_read") is not False):
        blockers.append("UNSUPPORTED_AUTHORITY_OR_ZIP_CLAIM")
    return {
        "schema":"sapphon-219-cross-runner-frozen-adjudication-v1",
        "state":"SOURCE_OWNED_IMAGE_BYTE_PARITY_VERIFIED" if not blockers else "CROSS_RUNNER_HOLD",
        "source_run_id":SOURCE_RUN,
        "source_attempt":SOURCE_ATTEMPT,
        "source_commit":SOURCE_COMMIT,
        "file_sha256":CHECKS.copy(),
        "blockers":sorted(set(blockers)),
        "external_custody_authenticated":False,
        "independent_witnesses":0,
        "zip_envelope_sha256_independently_read":False,
        "recovery_authorized":False,
        "lock_cleared":False,
        "decision":"HOLD"
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",required=True)
    p.add_argument("--out",required=True)
    args=p.parse_args()
    try:
        report=json.loads(pathlib.Path(args.input).read_text())
    except (OSError, ValueError):
        report={}
    result=adjudicate(report)
    path=pathlib.Path(args.out)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["state"], ",".join(result["blockers"]))
    return 0 if not result["blockers"] else 1

if __name__=="__main__":
    sys.exit(main())
