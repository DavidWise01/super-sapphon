#!/usr/bin/env python3
"""SAPPHON-190: external custody enrollment preflight; no trust on first use.

A valid signature alone is not independent custody. The trusted key registry
must be provisioned out of band; GitHub-only key claims are source-owned.
This module validates shapes, ancestry, replay and nonce uniqueness, and
always keeps independent authority HOLD.
"""
import argparse,base64,hashlib,json,pathlib,re,sys
SOURCE="8dfc2f0851df7bc02ac29977529bafe9c0b2101e"
WORKFLOW="sapphon-189-forks.yml"
MAX_RECEIPTS=64
HEX64=re.compile(r"^[0-9a-f]{64}$")
HEX40=re.compile(r"^[0-9a-f]{40}$")
def canonical(data):return json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def hash_obj(data):return hashlib.sha256(canonical(data)).hexdigest()
def positive(x):return type(x) is int and x>0
def fixed_b64(data,n):
 if type(data) is not str:return False
 try: return len(base64.b64decode(data,validate=True))==n
 except (ValueError,base64.binascii.Error):return False
def verify(receipts,registry):
 if type(receipts) is not list or len(receipts)>MAX_RECEIPTS:raise ValueError("RECEIPT_LIST_INVALID")
 if type(registry) is not dict or set(registry)!={"schema","out_of_band_authenticated","keys","authority_source"}:
  raise ValueError("REGISTRY_SCHEMA")
 if registry["schema"]!="sapphon-190-key-registry-v1" or type(registry["keys"]) is not list:
  raise ValueError("REGISTRY_SCHEMA")
 if registry["authority_source"]!="external-pinned" and registry["authority_source"]!="none":
  raise ValueError("INVALID_AUTHORITY_SOURCE")
 if registry["out_of_band_authenticated"] is not False:
  raise ValueError("UNVERIFIED_EXTERNAL_AUTHENTICATION")
 if registry["keys"]:raise ValueError("EXTERNAL_ENROLLMENT_NOT_AUTHORIZED")
 findings=[];seen=set();claimed_keys=set()
 for i,receipt in enumerate(receipts):
  if type(receipt) is not dict:
   findings.append("RECEIPT_NOT_OBJECT:"+str(i));continue
  required={"schema","source_sha","workflow","run_id","attempt","root_sha256",
   "custodian_id","public_key_b64","key_fingerprint_sha256","nonce_hex",
   "sequence","signature_b64","previous_receipt_sha256","recovery_authorized"}
  if set(receipt)!=required:findings.append("FIELDS:"+str(i));continue
  if receipt["schema"]!="sapphon-190-custody-receipt-v1" or receipt["source_sha"]!=SOURCE or receipt["workflow"]!=WORKFLOW:
   findings.append("ANCESTRY:"+str(i))
  if not positive(receipt["run_id"]) or not positive(receipt["attempt"]) or not positive(receipt["sequence"]):
   findings.append("IDENTITY:"+str(i))
  if not isinstance(receipt["root_sha256"],str) or not HEX64.fullmatch(receipt["root_sha256"]):
   findings.append("ROOT_DIGEST:"+str(i))
  if not fixed_b64(receipt["public_key_b64"],32) or not fixed_b64(receipt["signature_b64"],64):
   findings.append("KEY_OR_SIGNATURE_SHAPE:"+str(i))
  else:
   actual=hashlib.sha256(base64.b64decode(receipt["public_key_b64"])).hexdigest()
   if actual!=receipt["key_fingerprint_sha256"]:findings.append("KEY_FINGERPRINT:"+str(i))
   claimed_keys.add(actual)
  if (not isinstance(receipt["nonce_hex"],str) or len(receipt["nonce_hex"])!=64 or
      not HEX64.fullmatch(receipt["nonce_hex"])):
   findings.append("NONCE_INVALID:"+str(i))
  replay=(receipt["custodian_id"],receipt["nonce_hex"],receipt["sequence"])
  if replay in seen:findings.append("REPLAYED_RECEIPT:"+str(i))
  seen.add(replay)
  if (type(receipt["custodian_id"]) is not str or not (1<=len(receipt["custodian_id"])<=100)):
   findings.append("CUSTODIAN_ID:"+str(i))
  if (receipt["previous_receipt_sha256"]!="0"*64 and
      (not isinstance(receipt["previous_receipt_sha256"],str) or
       not HEX64.fullmatch(receipt["previous_receipt_sha256"]))):
   findings.append("PREDECESSOR_DIGEST:"+str(i))
  if receipt["recovery_authorized"] is not False:
   findings.append("FORGED_RECOVERY:"+str(i))
  findings.append("UNENROLLED_KEY:"+str(i))
 return {"schema":"sapphon-190-custody-preflight-v1","source_sha":SOURCE,
  "receipt_count":len(receipts),"claimed_keys":len(claimed_keys),
  "receipt_set_sha256":hash_obj(receipts),
  "findings":sorted(set(findings)),
  "cryptographic_signatures_verified":False,
  "out_of_band_key_enrollment_verified":False,
  "independent_witnesses":0,"external_custody_authenticated":False,
  "authenticated_utc":False,"global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"INDEPENDENT_CUSTODY_ENROLLMENT_HOLD"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--receipts",required=True)
 p.add_argument("--registry",required=True)
 p.add_argument("--out",default="qualification-artifact/190-preflight.json")
 a=p.parse_args()
 result=verify(json.loads(pathlib.Path(a.receipts).read_text()),
               json.loads(pathlib.Path(a.registry).read_text()))
 dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["decision"],result["findings"])
 if result["findings"]:sys.exit(1)
if __name__=="__main__":main()
