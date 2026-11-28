#!/usr/bin/env python3
"""SAPPHON-218: second-runner readback of exact GitHub-owned artifact files.

The archive must be extracted by actions/download-artifact from an exact run.
This verifier cannot prove external physical custody or hash the original ZIP
envelope, which is distinct from the extracted image and vendor file hashes.
"""
import argparse, hashlib, json, pathlib, re, sys
HEX=re.compile(r"^[a-f0-9]{64}$")
REF=re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$")
REQUIRED=["207-Cargo.lock","207-vendor.tar","207-vendor.json","207-summary.json",
          "207-image.tar","207-image.sha256","207-image-report.json",
          "215-image-verdict.json","216-base-resolution.json"]
def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file,"sha256").hexdigest()
def assess(root,run,attempt,commit):
    root=pathlib.Path(root)
    blockers=[]
    missing=[p for p in REQUIRED if not (root/p).is_file()]
    if missing: blockers.append("REQUIRED_FILES_MISSING")
    def read(name):
        try:return json.loads((root/name).read_text())
        except (OSError,ValueError):return {}
    summary=read("207-summary.json")
    vendor=read("207-vendor.json")
    image=read("207-image-report.json")
    verdict=read("215-image-verdict.json")
    base=read("216-base-resolution.json")
    if summary.get("schema")!="sapphon-207-source-owned-run-v1" or str(summary.get("run_id"))!=str(run) or str(summary.get("attempt"))!=str(attempt) or summary.get("commit")!=commit:
        blockers.append("EXACT_RUN_ATTEMPT_COMMIT_MISMATCH")
    steps=summary.get("steps",{})
    if any(steps.get(k)!="success" for k in ("PYTHON","RUST","FROZEN","VENDOR","IMAGE")):
        blockers.append("HOSTED_REQUIRED_STEP_NOT_SUCCESS")
    if verdict.get("state")!="SOURCE_OWNED_IMAGE_ARCHIVE_VERIFIED":
        blockers.append("ORIGINAL_VERDICT_NOT_VERIFIED")
    if base.get("pinned_base_ref")!=image.get("base_ref") or not REF.fullmatch(str(base.get("pinned_base_ref",""))):
        blockers.append("PINNED_BASE_CONFLICT")
    if base.get("local_image_id")!=image.get("base_local_id"):
        blockers.append("BASE_IMAGE_ID_CONFLICT")
    if summary.get("built_image_local_id")!=image.get("built_image_local_id"):
        blockers.append("BUILT_IMAGE_ID_CONFLICT")
    observed={}
    for name in ("207-Cargo.lock","207-vendor.tar","207-image.tar"):
        if name not in missing:
            observed[name]=digest(root/name)
    def matches(name, *refs):
        h=observed.get(name)
        if h is None or not HEX.fullmatch(h) or any(v!=h for v in refs):
            blockers.append(name.upper().replace("-","_").replace(".","_")+"_HASH_MISMATCH")
    matches("207-Cargo.lock",vendor.get("lock_sha256"))
    matches("207-vendor.tar",vendor.get("archive_sha256"),summary.get("vendor_archive_sha256"))
    matches("207-image.tar",image.get("archive_sha256"),summary.get("built_image_archive_sha256"),
            verdict.get("image_archive_sha256"))
    try:
        receipt=(root/"207-image.sha256").read_text().split()
        if len(receipt)!=2 or receipt[0]!=observed.get("207-image.tar") or receipt[1]!="207-image.tar":
            blockers.append("IMAGE_RECEIPT_CONFLICT")
    except OSError: blockers.append("IMAGE_RECEIPT_MISSING")
    if vendor.get("tree_sha256")!=summary.get("vendor_tree_sha256"):
        blockers.append("VENDOR_TREE_HASH_CONFLICT")
    for obj in (summary,image,verdict,base):
        if obj.get("recovery_authorized") is not False or obj.get("lock_cleared") is not False:
            blockers.append("OPERATIONAL_AUTHORITY_CLAIM")
    if verdict.get("external_witnesses")!=0 or base.get("independent_witnesses")!=0:
        blockers.append("UNSUPPORTED_INDEPENDENT_WITNESS")
    return {"schema":"sapphon-218-second-runner-artifact-readback-v1",
            "source_run_id":str(run),"source_attempt":str(attempt),"source_commit":commit,
            "state":"GITHUB_OWNED_EXTRACTED_BYTES_MATCH" if not blockers else "READBACK_HOLD",
            "blockers":sorted(set(blockers)),"file_sha256":observed,
            "zip_envelope_sha256_independently_read":False,
            "external_custody_authenticated":False,"independent_witnesses":0,
            "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",required=True)
    p.add_argument("--run",required=True)
    p.add_argument("--attempt",required=True)
    p.add_argument("--commit",required=True)
    p.add_argument("--out",required=True)
    a=p.parse_args()
    result=assess(a.root,a.run,a.attempt,a.commit)
    out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(result["state"],",".join(result["blockers"]))
    return 0 if not result["blockers"] else 1
if __name__=="__main__":sys.exit(main())
