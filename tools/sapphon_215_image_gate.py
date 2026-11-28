#!/usr/bin/env python3
"""SAPPHON-215 source-owned Docker image result: fail closed, never grant recovery.

A successful vendor workflow is *not* evidence that the optional Docker image
was built. Image qualification requires a run-bound source-owned report and
actual archive SHA-256. This gate never establishes independent custody.
"""
import argparse
import hashlib
import json
import pathlib
import re

SHA = re.compile(r"^[0-9a-f]{64}$")
BASE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")

def assess(summary, image_report=None, image_bytes=None, receipt=None):
    blockers = []
    if not isinstance(summary, dict) or summary.get("schema") != "sapphon-207-source-owned-run-v1":
        blockers.append("SOURCE_OWNED_SUMMARY_INVALID")
        summary = {}
    steps = summary.get("steps") or {}
    if any(steps.get(k) != "success" for k in ("PYTHON", "RUST", "FROZEN", "VENDOR")):
        blockers.append("SOURCE_OR_VENDOR_GATE_FAILED")
    if steps.get("IMAGE") != "success":
        blockers.append("IMAGE_STEP_NOT_SUCCESS")
    if not isinstance(image_report, dict) or image_report.get("schema") != "sapphon-207-local-image-v1":
        blockers.append("IMAGE_REPORT_UNAVAILABLE")
        image_report = {}
    if not BASE.fullmatch(str(image_report.get("base_ref", ""))):
        blockers.append("IMMUTABLE_BASE_REF_UNVERIFIED")
    for field in ("base_local_id", "built_image_local_id"):
        value = str(image_report.get(field, ""))
        if not (value.startswith("sha256:") and SHA.fullmatch(value[7:])):
            blockers.append(field.upper() + "_INVALID")
    observed = (image_bytes if isinstance(image_bytes, str) and SHA.fullmatch(image_bytes) else
                hashlib.sha256(image_bytes).hexdigest() if isinstance(image_bytes, bytes) and image_bytes else None)
    if observed is None:
        blockers.append("ORIGINAL_IMAGE_ARCHIVE_UNAVAILABLE")
    if observed is None or image_report.get("archive_sha256") != observed or summary.get("built_image_archive_sha256") != observed:
        blockers.append("IMAGE_ARCHIVE_HASH_NOT_MATCHED")
    if observed is None or not isinstance(receipt, str) or receipt.split()[:1] != [observed]:
        blockers.append("IMAGE_RECEIPT_NOT_MATCHED")
    if summary.get("built_image_local_id") != image_report.get("built_image_local_id"):
        blockers.append("IMAGE_ID_CONFLICT")
    if summary.get("recovery_authorized") is not False or summary.get("lock_cleared") is not False:
        blockers.append("UNSAFE_AUTHORITY_CLAIM")
    if image_report.get("recovery_authorized") is not False or image_report.get("lock_cleared") is not False:
        blockers.append("UNSAFE_IMAGE_AUTHORITY_CLAIM")
    return {
        "schema": "sapphon-215-image-source-owned-gate-v1",
        "state": "SOURCE_OWNED_IMAGE_ARCHIVE_VERIFIED" if not blockers else "IMAGE_QUALIFICATION_HOLD",
        "blockers": sorted(set(blockers)),
        "image_archive_sha256": observed,
        "external_witnesses": 0,
        "independent_custody_authenticated": False,
        "authenticated_utc": False,
        "global_anti_rollback_authenticated": False,
        "recovery_authorized": False,
        "lock_cleared": False,
        "decision": "RECOVERY_HOLD",
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--directory", default="qualification-artifact")
    p.add_argument("--out", default="qualification-artifact/215-image-verdict.json")
    a = p.parse_args()
    d = pathlib.Path(a.directory)
    def read_json(name):
        try:
            return json.loads((d/name).read_text())
        except (OSError, ValueError):
            return None
    def read_bytes(name):
        try:
            return (d/name).read_bytes()
        except OSError:
            return None
    try:
        receipt = (d/"207-image.sha256").read_text()
    except OSError:
        receipt = None
    image_path = d/"207-image.tar"
    image_hash = None
    if image_path.is_file() and image_path.stat().st_size > 0:
        with image_path.open("rb") as f:
            image_hash = hashlib.file_digest(f, "sha256").hexdigest()
    result = assess(read_json("207-summary.json"), read_json("207-image-report.json"),
                    image_hash, receipt)
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(result["state"], ",".join(result["blockers"]))
    return 0  # HOLD is recorded as an observation; not a green image claim.

if __name__ == "__main__":
    raise SystemExit(main())
