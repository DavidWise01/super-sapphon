#!/usr/bin/env python3
"""SAPPHON-180: bind exact-run job-log and artifact bytes to a sealed manifest.

Read-only verification. No HTTP, shell commands, promotion, or recovery.
SHA-256 proves byte consistency against supplied metadata, not independent
authenticity of that metadata. A redacted excerpt is NOT the raw log.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

SOURCE="d07203a254678fdf7df05a75c1d144c7a8337f87"
WORKFLOW="sapphon-179-replay.yml"
JOB="replay-diagnostics"
HEX64=re.compile(r"^[0-9a-f]{64}$")
MAX_LOG=8*1024*1024
MAX_ZIP=64*1024*1024

def sha(data):
    return hashlib.sha256(data).hexdigest()

def classify(meta,log,artifact):
    findings=[]
    if not isinstance(meta,dict):raise ValueError("MANIFEST_NOT_OBJECT")
    if meta.get("schema")!="sapphon-180-evidence-manifest-v1":
        findings.append("WRONG_MANIFEST_SCHEMA")
    if meta.get("source_sha")!=SOURCE or meta.get("workflow")!=WORKFLOW or meta.get("job_name")!=JOB:
        findings.append("WRONG_SOURCE_OR_WORKFLOW")
    for field in ("run_id","attempt","job_id","artifact_id"):
        n=meta.get(field)
        if type(n) is not int or n<=0:findings.append("INVALID_"+field.upper())
    if meta.get("run_status")!="completed" or meta.get("run_conclusion") not in ("success","failure"):
        findings.append("RUN_INCOMPLETE_OR_UNKNOWN")
    if meta.get("job_conclusion") not in ("success","failure"):
        findings.append("JOB_CONCLUSION_UNRESOLVED")
    if meta.get("artifact_name")!="sapphon-179-provenance-replay":
        findings.append("WRONG_ARTIFACT_NAME")
    if meta.get("artifact_expired") is not False:
        findings.append("ARTIFACT_EXPIRED_OR_UNKNOWN")
    if meta.get("log_kind")!="RAW_JOB_LOG":
        findings.append("LOG_NOT_RAW")
    if meta.get("artifact_kind")!="ORIGINAL_ZIP":
        findings.append("ARTIFACT_NOT_ORIGINAL_ZIP")
    if not isinstance(log,bytes) or not log or len(log)>MAX_LOG:
        findings.append("LOG_BYTES_MISSING_OR_OVERSIZE")
    if not isinstance(artifact,bytes) or not artifact or len(artifact)>MAX_ZIP:
        findings.append("ARTIFACT_BYTES_MISSING_OR_OVERSIZE")
    log_hash=sha(log) if isinstance(log,bytes) else None
    artifact_hash=sha(artifact) if isinstance(artifact,bytes) else None
    for name,actual in (("log_sha256",log_hash),("artifact_sha256",artifact_hash)):
        specified=meta.get(name)
        if not isinstance(specified,str) or not HEX64.fullmatch(specified) or specified!=actual:
            findings.append("MISMATCH_"+name.upper())
    # A self-reported id is insufficient; binding remains source-owned only.
    if meta.get("independent_custody_authenticated") is not False or meta.get("recovery_authorized") is not False:
        findings.append("UNSUPPORTED_AUTHORITY")
    if len(findings)==0 and meta.get("run_conclusion")=="success" and meta.get("job_conclusion")!="success":
        findings.append("PARENT_JOB_CONTRADICTION")
    return {"schema":"sapphon-180-artifact-binding-v1",
        "source_sha":SOURCE,"workflow":WORKFLOW,
        "run_id":meta.get("run_id"),"attempt":meta.get("attempt"),
        "job_id":meta.get("job_id"),"artifact_id":meta.get("artifact_id"),
        "raw_job_log_sha256":log_hash,"original_artifact_zip_sha256":artifact_hash,
        "bytes_match_supplied_metadata":not findings,
        "source_owned_binding_consistent":not findings,
        "findings":sorted(set(findings)),
        "external_metadata_authenticity_verified":False,
        "independent_custody_authenticated":False,
        "global_anti_rollback_authenticated":False,
        "recovery_authorized":False,"lock_cleared":False,
        "decision":"RAW_EVIDENCE_BINDING_HOLD"}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",required=True)
    p.add_argument("--raw-log",required=True)
    p.add_argument("--artifact-zip",required=True)
    p.add_argument("--out",default="qualification-artifact/180-binding.json")
    args=p.parse_args()
    metadata=json.loads(pathlib.Path(args.manifest).read_text())
    log=pathlib.Path(args.raw_log).read_bytes()
    artifact=pathlib.Path(args.artifact_zip).read_bytes()
    result=classify(metadata,log,artifact)
    out=pathlib.Path(args.out)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(result["decision"],result["findings"])
    if result["findings"]:sys.exit(1)

if __name__=="__main__":main()
