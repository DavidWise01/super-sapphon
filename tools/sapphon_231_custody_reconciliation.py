#!/usr/bin/env python3
"""SAPPHON-231: evaluate signed external custody *claims* without self-attestation.

An externally signed receipt is not proof of independently administered custody.
No output from this source-owned process can clear the recovery lock.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_RECEIPTS = 32
MAX_INPUT = 4 * 1024 * 1024

def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def digest(x):
    return hashlib.sha256(canonical(x)).hexdigest()

def valid_sha(x):
    return isinstance(x,str) and len(x)==64 and all(c in "0123456789abcdef" for c in x)

def verify_receipt(r):
    if not isinstance(r,dict) or set(r)!={"payload","public_key_pem","signature_base64"}:
        return False,"RECEIPT_SCHEMA_INVALID"
    p=r["payload"]
    required={"schema","custodian_id","custody_domain","sequence","branch_head_sha256",
              "session_set_sha256","prior_receipt_sha256","retention_id"}
    if not isinstance(p,dict) or set(p)!=required or p["schema"]!="sapphon-231-custody-receipt-v1":
        return False,"RECEIPT_PAYLOAD_INVALID"
    if any(not isinstance(p[k],str) or not 1<=len(p[k])<=128 for k in
           ("custodian_id","custody_domain","retention_id")):
        return False,"RECEIPT_ID_INVALID"
    if type(p["sequence"]) is not int or not 0<=p["sequence"]<=2**63-1:
        return False,"RECEIPT_SEQUENCE_INVALID"
    if not valid_sha(p["branch_head_sha256"]) or not valid_sha(p["session_set_sha256"]):
        return False,"RECEIPT_HEAD_INVALID"
    if p["prior_receipt_sha256"] is not None and not valid_sha(p["prior_receipt_sha256"]):
        return False,"RECEIPT_PREDECESSOR_INVALID"
    try:
        key=load_pem_public_key(r["public_key_pem"].encode())
        if not isinstance(key,Ed25519PublicKey):
            return False,"RECEIPT_KEY_TYPE_INVALID"
        sig=base64.b64decode(r["signature_base64"],validate=True)
        key.verify(sig,canonical(p))
    except (ValueError,TypeError,KeyError,AttributeError):
        return False,"RECEIPT_SIGNATURE_INVALID"
    except Exception:
        return False,"RECEIPT_SIGNATURE_INVALID"
    return True,"SIGNED_RECEIPT_BYTES_VERIFIED"

def assess(fork_report,receipts):
    blockers=[]
    if not isinstance(fork_report,dict) or fork_report.get("schema")!="sapphon-230-competing-sessions-v1":
        blockers.append("PREDECESSOR_SCHEMA_INVALID")
        candidates=[]
    else:
        expected=fork_report.get("evidence_sha256")
        body={k:v for k,v in fork_report.items() if k!="evidence_sha256"}
        if expected!=digest(body):
            blockers.append("PREDECESSOR_DIGEST_INVALID")
        candidates=fork_report.get("candidates_retained",[])
        if not isinstance(candidates,list): candidates=[];blockers.append("PREDECESSOR_INVENTORY_INVALID")
    if not isinstance(receipts,list) or len(receipts)>MAX_RECEIPTS:
        blockers.append("RECEIPT_INVENTORY_INVALID")
        receipts=[]
    heads={}
    for c in candidates:
        if not isinstance(c,dict) or not c.get("verified_structure"): continue
        h=c.get("head_sha256");s=c.get("session_set_sha256")
        if valid_sha(h) and valid_sha(s):
            heads.setdefault((h,s),[]).append(c.get("candidate_id"))
    retained=[]
    by_custodian={}
    retention_ids=set()
    for i,r in enumerate(receipts):
        ok,reason=verify_receipt(r)
        p=r.get("payload",{}) if isinstance(r,dict) else {}
        if not isinstance(p,dict): p={}
        key=(p.get("branch_head_sha256"),p.get("session_set_sha256"))
        match=heads.get(key,[]) if ok else []
        if ok and not match: reason="RECEIPT_UNMATCHED_CANDIDATE";blockers.append(reason)
        if not ok: blockers.append(reason)
        cid=p.get("custodian_id") if ok else None
        rid=(cid,p.get("retention_id")) if ok else None
        if rid is not None:
            if rid in retention_ids: blockers.append("RETENTION_ID_REUSED")
            retention_ids.add(rid)
        if ok: by_custodian.setdefault(cid,[]).append((p["sequence"],digest(r),p["prior_receipt_sha256"],key))
        retained.append({"index":i,"receipt_sha256":digest(r),"receipt":r,
                         "signature_valid":ok,"matching_candidates":sorted(match),"check":reason})
    for cid,history in by_custodian.items():
        history.sort(key=lambda x:(x[0],x[1]))
        for j,(seq,cur,prev,key) in enumerate(history):
            if j and seq<=history[j-1][0]: blockers.append("CUSTODIAN_SEQUENCE_REUSED_OR_ROLLBACK")
            if j and prev!=history[j-1][1]: blockers.append("CUSTODIAN_PREDECESSOR_MISMATCH")
            if not j and seq==0 and prev is not None: blockers.append("GENESIS_PREDECESSOR_INVALID")
            if not j and seq>0: blockers.append("UNANCHORED_CUSTODIAN_PREFIX")
    # A source-owned ledger cannot assert that named custodians are distinct
    # legal operators, physically durable stores or independent witnesses.
    blockers.extend(["INDEPENDENT_CUSTODY_NOT_ESTABLISHED",
                     "CUSTODIAN_KEY_PROVISIONING_UNVERIFIED",
                     "DURABLE_RETENTION_NOT_ATTESTED",
                     "AUTHENTICATED_UTC_UNVERIFIED",
                     "GLOBAL_ANTI_ROLLBACK_UNVERIFIED"])
    if fork_report.get("fork_count",0)>0:
        blockers.append("SIGNED_FORK_NO_AUTOMATIC_WINNER")
    result={"schema":"sapphon-231-custody-reconciliation-v1",
            "predecessor_evidence_sha256":fork_report.get("evidence_sha256"),
            "state":"SIGNED_CUSTODY_CLAIMS_PRESERVED_HOLD",
            "receipts_retained":retained,"receipt_count":len(retained),
            "matched_signed_receipts":sum(bool(x["signature_valid"] and x["matching_candidates"]) for x in retained),
            "candidate_heads_retained":sorted({h for h,s in heads}),
            "blockers":sorted(set(blockers)),
            "reconciliation":"NO_WINNER_SELECTED",
            "independently_authenticated_witnesses":0,
            "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
    result["evidence_sha256"]=digest(result)
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--fork-report",required=True)
    ap.add_argument("--receipts",required=True)
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    def read(path):
        f=Path(path)
        if f.stat().st_size>MAX_INPUT: raise ValueError("input exceeds bound")
        return json.loads(f.read_text())
    result=assess(read(args.fork_report),read(args.receipts))
    dest=Path(args.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["state"],"matched",result["matched_signed_receipts"])
if __name__=="__main__":main()
