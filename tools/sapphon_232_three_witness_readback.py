#!/usr/bin/env python3
"""SAPPHON-232: three-witness readback and monotonic checkpoint *qualification*.

Local signed responses establish only key control, byte match, and ancestry syntax.
Independent custody, actual remote readback and monotonic authority require separately
authenticated out-of-band evidence. This module never releases recovery.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

MAX_BYTES=4*1024*1024
MAX_WITNESSES=12
REQUIRED={"schema","witness_id","operator_domain","sequence","previous_checkpoint_sha256",
          "checkpoint_sha256","branch_head_sha256","session_set_sha256","custody_receipt_sha256",
          "readback_sha256","readback_base64"}
def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()
def hex64(value):
    return type(value) is str and len(value)==64 and all(c in "0123456789abcdef" for c in value)
def assess(predecessor,attestations):
    blockers=[]
    if type(predecessor) is not dict or predecessor.get("schema")!="sapphon-231-custody-reconciliation-v1":
        blockers.append("PREDECESSOR_SCHEMA_INVALID")
        predecessor={}
    elif predecessor.get("evidence_sha256")!=sha({k:v for k,v in predecessor.items() if k!="evidence_sha256"}):
        blockers.append("PREDECESSOR_DIGEST_INVALID")
    receipts=predecessor.get("receipts_retained",[])
    if type(receipts) is not list: receipts=[];blockers.append("PREDECESSOR_RECEIPTS_INVALID")
    receipt_map={}
    for item in receipts:
        if type(item) is not dict: continue
        r=item.get("receipt")
        if type(r) is not dict or not item.get("signature_valid"): continue
        p=r.get("payload")
        if type(p) is not dict: continue
        key=(p.get("branch_head_sha256"),p.get("session_set_sha256"))
        if type(key[0]) is str and type(key[1]) is str and item.get("receipt_sha256")==sha(r):
            receipt_map.setdefault(key,set()).add(item["receipt_sha256"])
    if type(attestations) is not list or len(attestations)>MAX_WITNESSES:
        blockers.append("WITNESS_INVENTORY_INVALID")
        attestations=[]
    retained=[]
    sequences={}
    ids=set()
    keys=set()
    domains=set()
    for i,att in enumerate(attestations):
        issues=[]
        if type(att) is not dict or set(att)!={"payload","public_key_pem","signature_base64"}:
            issues.append("WITNESS_SCHEMA_INVALID")
            retained.append({"index":i,"attestation_sha256":sha(att),"checks":issues})
            blockers.extend(issues)
            continue
        p=att["payload"]
        if type(p) is not dict or set(p)!=REQUIRED or p.get("schema")!="sapphon-232-readback-v1":
            issues.append("WITNESS_PAYLOAD_INVALID")
        else:
            if any(type(p[k]) is not str or not 1<=len(p[k])<=128 for k in ("witness_id","operator_domain")):
                issues.append("WITNESS_ID_INVALID")
            if type(p["sequence"]) is not int or not 0<=p["sequence"]<=2**63-1:
                issues.append("WITNESS_SEQUENCE_INVALID")
            if any(not hex64(p[k]) for k in ("checkpoint_sha256","branch_head_sha256",
                    "session_set_sha256","custody_receipt_sha256","readback_sha256")):
                issues.append("WITNESS_DIGEST_INVALID")
            if p["previous_checkpoint_sha256"] is not None and not hex64(p["previous_checkpoint_sha256"]):
                issues.append("WITNESS_PREDECESSOR_INVALID")
            try:
                raw=base64.b64decode(p["readback_base64"],validate=True)
                if len(raw)>MAX_BYTES: issues.append("READBACK_OVERSIZE")
                if hashlib.sha256(raw).hexdigest()!=p["readback_sha256"]:
                    issues.append("READBACK_BYTES_DIGEST_MISMATCH")
                # Canonical readback body binds the exact branch/session/receipt
                # claimed in the signed attestation. It is still locally supplied.
                if raw!=canonical({"branch_head_sha256":p["branch_head_sha256"],
                                   "session_set_sha256":p["session_set_sha256"],
                                   "custody_receipt_sha256":p["custody_receipt_sha256"]}):
                    issues.append("READBACK_BODY_MISMATCH")
            except (ValueError,TypeError,KeyError):
                issues.append("READBACK_INVALID")
            key=(p["branch_head_sha256"],p["session_set_sha256"])
            if p["custody_receipt_sha256"] not in receipt_map.get(key,set()):
                issues.append("RECEIPT_ANCESTRY_MISMATCH")
            checkpoint_body={k:p[k] for k in ("witness_id","operator_domain","sequence",
                "previous_checkpoint_sha256","branch_head_sha256","session_set_sha256",
                "custody_receipt_sha256","readback_sha256")}
            if sha(checkpoint_body)!=p["checkpoint_sha256"]:
                issues.append("CHECKPOINT_DIGEST_MISMATCH")
            if p["witness_id"] in ids: issues.append("WITNESS_ID_REUSED")
            ids.add(p["witness_id"])
            if p["operator_domain"] in domains: issues.append("OPERATOR_DOMAIN_CLAIM_REUSED")
            domains.add(p["operator_domain"])
            try:
                public_key=load_pem_public_key(att["public_key_pem"].encode())
                if not isinstance(public_key,Ed25519PublicKey): raise ValueError("not Ed25519")
                fp=hashlib.sha256(att["public_key_pem"].encode()).hexdigest()
                if fp in keys: issues.append("WITNESS_KEY_REUSED")
                keys.add(fp)
                signature=base64.b64decode(att["signature_base64"],validate=True)
                public_key.verify(signature,canonical(p))
            except Exception:
                issues.append("WITNESS_SIGNATURE_INVALID")
            sequences.setdefault(p["witness_id"],[]).append((p["sequence"],p["checkpoint_sha256"],p["previous_checkpoint_sha256"]))
        blockers.extend(issues)
        retained.append({"index":i,"attestation_sha256":sha(att),"complete_attestation":att,"checks":sorted(set(issues))})
    for history in sequences.values():
        history.sort()
        for i,(seq,current,previous) in enumerate(history):
            if i and seq<=history[i-1][0]: blockers.append("CHECKPOINT_COUNTER_REUSE_OR_ROLLBACK")
            if i and previous!=history[i-1][1]: blockers.append("CHECKPOINT_PREDECESSOR_MISMATCH")
            if i==0 and seq>0: blockers.append("CHECKPOINT_PREFIX_NOT_INDEPENDENTLY_ANCHORED")
            if i==0 and seq==0 and previous is not None: blockers.append("CHECKPOINT_GENESIS_INVALID")
    clean=sum(not record["checks"] for record in retained)
    if clean<3: blockers.append("THREE_VALID_READBACKS_NOT_ESTABLISHED")
    # All attestations may originate from a single actor and input surface.
    blockers.extend(["WITNESS_CONTROL_INDEPENDENCE_UNVERIFIED",
        "OUT_OF_BAND_READBACK_UNVERIFIED","DURABLE_EXTERNAL_BYTES_UNVERIFIED",
        "EXTERNAL_MONOTONIC_AUTHORITY_UNVERIFIED","AUTHENTICATED_UTC_UNVERIFIED"])
    result={"schema":"sapphon-232-three-witness-readback-v1",
            "state":"READBACK_ANCESTRY_QUALIFIED_RECOVERY_HOLD",
            "predecessor_evidence_sha256":predecessor.get("evidence_sha256"),
            "attestations_retained":retained,"attestation_count":len(retained),
            "locally_valid_readbacks":clean,
            "independently_authenticated_witnesses":0,
            "blockers":sorted(set(blockers)),"reconciliation":"NO_WINNER_SELECTED",
            "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
    result["evidence_sha256"]=sha(result)
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--predecessor",required=True)
    ap.add_argument("--attestations",required=True)
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    def read(path):
        f=Path(path)
        if f.stat().st_size>MAX_BYTES: raise ValueError("bounded input exceeded")
        return json.loads(f.read_text())
    result=assess(read(args.predecessor),read(args.attestations))
    dest=Path(args.out)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["state"],"local_readbacks",result["locally_valid_readbacks"])
if __name__=="__main__": main()
