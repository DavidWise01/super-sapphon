#!/usr/bin/env python3
"""SAPPHON-228: bounded append-only source-owned custody ACK ledger.

Each ACK is cryptographically rechecked, including all historical entries.
No external trust root, physical custody, monotonic storage or UTC is authenticated.
"""
import argparse,hashlib,json,pathlib,sys
import sapphon_227_portable_readback as intake

LIMIT=128
def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(x):
    return hashlib.sha256(canonical(x)).hexdigest()
def check_history(records,bundle,source_anchor):
    errors=[]
    if type(records) is not list or len(records)>LIMIT:
        return ["HISTORY_ABSENT_OR_UNBOUNDED"],set(),set(),None
    seen_nonces=set()
    seen_receipts=set()
    prior=None
    for n,entry in enumerate(records,1):
        if type(entry) is not dict or set(entry)!={"sequence","previous_sha256",
           "ack","ack_anchor","entry_sha256"}:
            errors.append("HISTORY_ENTRY_SCHEMA");break
        content={k:v for k,v in entry.items() if k!="entry_sha256"}
        if entry["entry_sha256"]!=sha(content):
            errors.append("HISTORY_ENTRY_HASH_CHANGED")
        if type(entry["sequence"]) is not int or entry["sequence"]!=n:
            errors.append("HISTORY_COUNTER_GAP_OR_REPLAY")
        if entry["previous_sha256"]!=prior:
            errors.append("HISTORY_PREDECESSOR_MISMATCH")
        verdict=intake.adjudicate(bundle,source_anchor,entry["ack"],entry["ack_anchor"])
        if verdict["state"]!="SIGNED_ACK_CHECKED_CUSTODY_HOLD" or not verdict["ack_signature_valid"]:
            errors.append("HISTORY_ACK_CRYPTOGRAPHICALLY_INVALID")
        ack=entry["ack"]
        if type(ack) is not dict or type(ack.get("payload")) is not dict:
            errors.append("HISTORY_ACK_SCHEMA");break
        key=(ack["payload"].get("custodian_root"),ack["payload"].get("transfer_nonce"))
        digest=sha(ack)
        if key in seen_nonces:errors.append("HISTORY_NONCE_REUSED")
        if digest in seen_receipts:errors.append("HISTORY_RECEIPT_REPLAYED")
        seen_nonces.add(key)
        seen_receipts.add(digest)
        prior=entry.get("entry_sha256")
    return sorted(set(errors)),seen_nonces,seen_receipts,prior

def adjudicate(records,bundle,source_anchor,ack=None,ack_anchor=None):
    errors,nonces,receipts,prior=check_history(records,bundle,source_anchor)
    records=records if type(records) is list and len(records)<=LIMIT else []
    new_records=list(records)
    if len(records)>=LIMIT:errors.append("LEDGER_CAPACITY_REACHED")
    if ack is None:
        errors.append("NEW_SIGNED_ACK_NOT_PROVIDED")
    else:
        verdict=intake.adjudicate(bundle,source_anchor,ack,ack_anchor)
        if verdict["state"]!="SIGNED_ACK_CHECKED_CUSTODY_HOLD" or not verdict["ack_signature_valid"]:
            errors.append("NEW_ACK_SIGNATURE_OR_BUNDLE_INVALID")
        if type(ack) is dict and type(ack.get("payload")) is dict:
            payload=ack["payload"]
            token=(payload.get("custodian_root"),payload.get("transfer_nonce"))
            if token in nonces:errors.append("TRANSFER_NONCE_ALREADY_USED")
            if sha(ack) in receipts:errors.append("SIGNED_ACK_ALREADY_RECORDED")
        else:
            errors.append("NEW_ACK_MALFORMED")
    accepted=not errors
    if accepted:
        content={"sequence":len(records)+1,"previous_sha256":prior,
                 "ack":ack,"ack_anchor":ack_anchor}
        new_records.append({**content,"entry_sha256":sha(content)})
    # Re-validate the entire retained history, including candidate, before
    # reporting a structural acceptance.
    if accepted:
        verify,_,_,_=check_history(new_records,bundle,source_anchor)
        if verify:
            errors.extend(verify)
            accepted=False
            new_records=list(records)
    final_head=new_records[-1]["entry_sha256"] if new_records else None
    evidence={"schema":"sapphon-228-custody-ack-replay-ledger-v1",
       "state":"SOURCE_OWNED_ACK_APPENDED_CUSTODY_HOLD" if accepted
               else "ACK_REPLAY_OR_INTAKE_REJECTED_HOLD",
       "records":new_records,"record_count":len(new_records),"head_sha256":final_head,
       "candidate_accepted":accepted,"blockers":sorted(set(errors+[
           "EXTERNAL_CUSTODY_NOT_AUTHENTICATED","INDEPENDENT_KEY_ROOT_UNVERIFIED",
           "AUTHENTICATED_UTC_UNVERIFIED","GLOBAL_ANTI_ROLLBACK_UNVERIFIED"])),
       "fork_branches_unmodified":True,"reconciliation":"NO_WINNER_SELECTED",
       "independently_authenticated_witnesses":0,"recovery_authorized":False,
       "lock_cleared":False,"decision":"HOLD"}
    evidence["evidence_sha256"]=sha(evidence)
    return evidence

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--history",required=True);p.add_argument("--bundle",required=True)
    p.add_argument("--source-anchor",required=True);p.add_argument("--ack")
    p.add_argument("--ack-anchor");p.add_argument("--out",required=True)
    a=p.parse_args()
    def read(name):
        try:
            path=pathlib.Path(name)
            if path.stat().st_size>4*1024*1024:return None
            return json.loads(path.read_text())
        except (OSError,ValueError):return None
    v=adjudicate(read(a.history),read(a.bundle),read(a.source_anchor),
                 read(a.ack) if a.ack else None,
                 read(a.ack_anchor) if a.ack_anchor else None)
    out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(v,sort_keys=True,indent=2)+"\n")
    print(v["state"],"records",v["record_count"])
    return 0 if v["candidate_accepted"] else 1
if __name__=="__main__":sys.exit(main())
