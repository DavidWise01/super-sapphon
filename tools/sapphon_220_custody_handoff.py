#!/usr/bin/env python3
"""SAPPHON-220: issue digest-bound custody handoff; receipts cannot grant authority."""
import argparse,hashlib,json,pathlib
RUN="46154833375"
COMMIT="c167a95a05177e280625fa61613c1b1fa20f75e9"
HASHES={"207-Cargo.lock":"2ee90c706c436c450c786e7ecf5a12243c9dd8fc213a39d0ff071737dab6238c","207-vendor.tar":"84c024537ba4d52f6892d080b08ed94c9a5a38c666cd1538a932bbfedd90c38e","207-image.tar":"32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197"}
def hash_obj(obj):
 return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()
def handoff():
 body={"schema":"sapphon-220-external-handoff-v1","origin":"GitHub-owned-source-only","source_run":RUN,"source_attempt":"1","source_commit":COMMIT,"sha256":HASHES,"freeze_artifact_id":"15268885124","freeze_zip_sha256":"aee92239ebb2ed1a2f85715b6c663300356b008bf97ace4166265fa0999e6c22","recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
 return {**body,"manifest_sha256":hash_obj(body)}
def review(receipt):
 m=handoff();b=[]
 if type(receipt) is not dict:receipt={};b.append("MISSING_RECEIPT")
 if receipt.get("schema")!="sapphon-220-external-receipt-v1":b.append("RECEIPT_SCHEMA")
 if receipt.get("manifest_sha256")!=m["manifest_sha256"]:b.append("MANIFEST_DIGEST")
 if (str(receipt.get("source_run"))!=RUN or str(receipt.get("source_attempt"))!="1" or receipt.get("source_commit")!=COMMIT):b.append("RUN_ANCESTRY")
 if receipt.get("sha256")!=HASHES:b.append("FILE_HASH_PARITY")
 if receipt.get("custodian_root") in (None,"","github","GitHub","DavidWise01/super-sapphon"):b.append("CUSTODIAN_ANCESTRY")
 for field in ("signature","authenticated_utc_evidence","external_anti_rollback_evidence"):
  if not isinstance(receipt.get(field),str) or not receipt[field]:b.append("MISSING_"+field.upper())
 if receipt.get("recovery_authorized") is not False or receipt.get("lock_cleared") is not False:b.append("UNSAFE_AUTHORITY_CLAIM")
 # Claimed signatures, ancestry and clocks have not been authenticated outside GitHub.
 b.append("EXTERNAL_AUTHENTICATION_UNVERIFIED")
 return {"schema":"sapphon-220-custody-review-v1","state":"EXTERNAL_CUSTODY_HOLD","receipt_sha256":hash_obj(receipt),"blockers":sorted(set(b)),"independently_authenticated_witnesses":0,"authenticated_utc":False,"global_anti_rollback_authenticated":False,"recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--out",required=True);p.add_argument("--receipt");p.add_argument("--review-out");a=p.parse_args()
 if bool(a.receipt)!=bool(a.review_out):p.error("--receipt and --review-out must be paired")
 out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(handoff(),sort_keys=True,indent=2)+"\n")
 if a.receipt:
  try:r=json.loads(pathlib.Path(a.receipt).read_text())
  except (ValueError,OSError):r={}
  v=review(r);p=pathlib.Path(a.review_out);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,sort_keys=True,indent=2)+"\n")
 print("SAPPHON_220_SOURCE_OWNED_HANDOFF_PREPARED__RECOVERY_HOLD")
if __name__=="__main__":main()
