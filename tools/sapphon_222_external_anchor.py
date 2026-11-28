#!/usr/bin/env python3
"""SAPPHON-222 independently provisioned key gate: never promote claims to custody.

An externally authenticated key must arrive by a trust channel independent of
the submitted receipt. An operator-supplied anchor can verify signing-key parity,
but its provenance itself is NOT verified by this GitHub-owned process.
"""
import argparse,hashlib,json,pathlib,re,sys
import sapphon_221_attestation as signed

HEX=re.compile(r"^[0-9a-f]{64}$")
def sha(b): return hashlib.sha256(b).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def assess(receipt,anchor=None,prior=None):
 base=signed.assess(receipt)
 blockers=list(base["blockers"])
 receipt=receipt if isinstance(receipt,dict) else {}
 anchor=anchor if isinstance(anchor,dict) else {}
 prior=prior if isinstance(prior,dict) else {}
 payload=receipt.get("payload") if isinstance(receipt.get("payload"),dict) else {}
 key=anchor.get("public_key_pem")
 source=anchor.get("provisioning_channel")
 independent_key=bool(
   isinstance(key,str) and key and len(key)<4096 and
   isinstance(anchor.get("key_sha256"),str) and
   anchor["key_sha256"]==sha(key.encode()) and
   source not in (None,"","github","receipt","source-owned") and
   anchor.get("custodian_root")==payload.get("custodian_root") and
   anchor.get("custodian_root") not in (None,"","GitHub","github")
 )
 if not independent_key:blockers.append("EXTERNAL_KEY_ANCHOR_MISSING_OR_MISMATCH")
 if isinstance(key,str) and key!=receipt.get("public_key_pem"):
    blockers.append("RECEIPT_KEY_DIFFERS_FROM_ANCHOR")
 anchor_sig=bool(independent_key and isinstance(receipt.get("signature_base64"),str)
                 and signed.verify_crypto(signed.canonical(payload),receipt["signature_base64"],key))
 if not anchor_sig:blockers.append("ANCHORED_SIGNATURE_NOT_VERIFIED")
 sequence=payload.get("sequence")
 previous=payload.get("previous_receipt_sha256")
 # The latest receipt head must come from an independently verified source.
 if not isinstance(sequence,int) or isinstance(sequence,bool) or sequence<1:
    blockers.append("COUNTER_INVALID")
 elif sequence==1:
    if previous is not None:blockers.append("GENESIS_PREVIOUS_HASH_NOT_NULL")
 else:
    if not isinstance(previous,str) or not HEX.fullmatch(previous):
      blockers.append("PREDECESSOR_HASH_INVALID")
    if prior.get("externally_authenticated") is not True:
      blockers.append("EXTERNAL_PREDECESSOR_NOT_AUTHENTICATED")
    if prior.get("custodian_root")!=payload.get("custodian_root") or prior.get("sequence")!=sequence-1:
      blockers.append("PREDECESSOR_CHAIN_CONFLICT")
    if prior.get("receipt_sha256")!=previous:
      blockers.append("PREDECESSOR_DIGEST_CONFLICT")
 # The external provenance of the anchor, clock and ledger is not established
 # by a GitHub-side artifact, a self-assertion or these negative tests.
 blockers.extend(["ANCHOR_PROVISIONING_NOT_INDEPENDENTLY_AUTHENTICATED",
                  "PHYSICAL_CUSTODY_UNVERIFIED","AUTHENTICATED_UTC_UNVERIFIED",
                  "EXTERNAL_ANTI_ROLLBACK_UNVERIFIED"])
 return {"schema":"sapphon-222-external-key-ancestry-gate-v1",
   "state":"ANCHORED_SIGNATURE_CHECKED_CUSTODY_HOLD" if anchor_sig
           and not any(x in blockers for x in ("EXTERNAL_KEY_ANCHOR_MISSING_OR_MISMATCH",
           "RECEIPT_KEY_DIFFERS_FROM_ANCHOR","EXTERNAL_PREDECESSOR_NOT_AUTHENTICATED",
           "PREDECESSOR_CHAIN_CONFLICT","PREDECESSOR_DIGEST_CONFLICT",
           "PREDECESSOR_HASH_INVALID","GENESIS_PREVIOUS_HASH_NOT_NULL")) 
           else "EXTERNAL_ANCHOR_REJECTED_HOLD",
   "receipt_sha256":sha(canonical(receipt)),
   "anchored_signature_valid":anchor_sig,
   "blockers":sorted(set(blockers)),
   "independently_authenticated_witnesses":0,"authenticated_utc":False,
   "global_anti_rollback_authenticated":False,"recovery_authorized":False,
   "lock_cleared":False,"decision":"HOLD"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--receipt",required=True);p.add_argument("--anchor")
 p.add_argument("--prior");p.add_argument("--out",required=True)
 a=p.parse_args()
 def read(path):
  try:return json.loads(pathlib.Path(path).read_text()) if path else None
  except (OSError,ValueError):return None
 result=assess(read(a.receipt),read(a.anchor),read(a.prior))
 dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["state"],"witnesses",result["independently_authenticated_witnesses"])
 return 0 if result["anchored_signature_valid"] else 1
if __name__=="__main__":sys.exit(main())
