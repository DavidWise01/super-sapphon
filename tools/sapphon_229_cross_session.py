#!/usr/bin/env python3
"""SAPPHON-229: cross-session prefix parity and signed-head byte checks.

All input and keys remain source/user supplied. Valid signatures and matching
snapshots cannot authenticate physical custody or global anti-rollback.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

import sapphon_221_attestation as crypto
import sapphon_228_ack_ledger as ledger
import sapphon_223_checkpoint as frozen

MAX_SESSIONS=16
MAX_JSON_BYTES=4*1024*1024
HEAD_FIELDS={"schema","source_run","source_commit","session_id",
             "record_count","head_sha256","claimed_utc"}

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(x):
    return hashlib.sha256(canonical(x)).hexdigest()
def verify_signed_head(checkpoint,anchor,last):
    failures=[]
    if type(checkpoint) is not dict or set(checkpoint)!={"payload","signature_base64","public_key_pem"}:
        return False,["SIGNED_HIGHWATER_ENVELOPE_INVALID"]
    p=checkpoint["payload"]
    if type(p) is not dict or set(p)!=HEAD_FIELDS or p.get("schema")!="sapphon-229-signed-session-head-v1":
        return False,["SIGNED_HIGHWATER_PAYLOAD_INVALID"]
    if (p.get("source_run")!=frozen.SOURCE_RUN or
        p.get("source_commit")!=frozen.SOURCE_COMMIT or
        p.get("session_id")!=last.get("session_id") or
        type(p.get("record_count")) is not int or
        p.get("record_count")!=len(last.get("records",[])) or
        p.get("head_sha256")!=(last["records"][-1]["entry_sha256"] if last.get("records") else None)):
        failures.append("SIGNED_HIGHWATER_NOT_CURRENT_SESSION")
    if type(p.get("claimed_utc")) is not str or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",p["claimed_utc"]):
        failures.append("SIGNED_HIGHWATER_UTC_SYNTAX")
    pem=checkpoint.get("public_key_pem")
    if (type(anchor) is not dict or type(pem) is not str
        or anchor.get("public_key_pem")!=pem
        or anchor.get("key_sha256")!=hashlib.sha256(pem.encode()).hexdigest()
        or anchor.get("custodian_root") in (None,"","github","GitHub")):
        failures.append("SIGNED_HIGHWATER_ANCHOR_MISMATCH")
    if (type(checkpoint.get("signature_base64")) is not str or type(pem) is not str
        or not crypto.verify_crypto(canonical(p),checkpoint["signature_base64"],pem)):
        failures.append("SIGNED_HIGHWATER_SIGNATURE_INVALID")
    return not failures,failures

def audit(sessions,bundle,source_anchor,checkpoint=None,head_anchor=None):
    errors=[]
    valid_session_count=0
    if type(sessions) is not list or not 1<=len(sessions)<=MAX_SESSIONS:
        sessions=[];errors.append("SESSIONS_MISSING_OR_UNBOUNDED")
    previous=None
    seen_ids=set()
    readback=[]
    for index,s in enumerate(sessions):
        if (type(s) is not dict or set(s)!={"session_id","records","declared_prior_head"}
            or type(s.get("session_id")) is not str
            or not re.fullmatch(r"[A-Za-z0-9_-]{4,80}",s["session_id"])
            or s["session_id"] in seen_ids):
            errors.append("SESSION_SCHEMA_OR_ID_CONFLICT")
            continue
        seen_ids.add(s["session_id"])
        records=s.get("records")
        if type(records) is not list or not records or len(records)>ledger.LIMIT:
            errors.append("SESSION_HISTORY_MISSING_OR_UNBOUNDED")
            continue
        history_errors,_,_,head=ledger.check_history(records,bundle,source_anchor)
        if history_errors:
            errors.extend("SESSION_"+e for e in history_errors)
        if index==0:
            if s["declared_prior_head"] is not None:
                errors.append("GENESIS_PRIOR_HEAD_NOT_NULL")
        else:
            if previous is None:
                errors.append("PRIOR_SESSION_NOT_VERIFIED")
            else:
                prev_records=previous["records"]
                if len(records)<=len(prev_records):
                    errors.append("SESSION_HISTORY_TRUNCATED_OR_NOT_ADVANCED")
                if records[:len(prev_records)]!=prev_records:
                    errors.append("SESSION_HISTORY_REWRITTEN_OR_FORKED")
                if s["declared_prior_head"]!=previous["records"][-1]["entry_sha256"]:
                    errors.append("DECLARED_PRIOR_HEAD_CONFLICT")
        readback.append({"session_id":s["session_id"],"record_count":len(records),
                         "head_sha256":head,"session_digest":sha(s)})
        valid_session_count+=1
        previous=s
    if len(readback)!=len(sessions):
        errors.append("SESSION_INVENTORY_INCOMPLETE")
    signed_valid=False
    if checkpoint is None:
        errors.append("EXTERNAL_SIGNED_HIGHWATER_MISSING")
    elif previous is None:
        errors.append("SIGNED_HIGHWATER_WITHOUT_SESSION")
    else:
        signed_valid,problems=verify_signed_head(checkpoint,head_anchor,previous)
        errors.extend(problems)
    hard=[x for x in errors if x!="EXTERNAL_SIGNED_HIGHWATER_MISSING"]
    state=("CROSS_SESSION_SIGNED_HEAD_BYTES_MATCH_HOLD" if not hard and signed_valid
           else "CROSS_SESSION_PREFIX_MATCH_HEAD_MISSING_HOLD" if not hard and checkpoint is None and readback
           else "CROSS_SESSION_REJECTED_HOLD")
    report={"schema":"sapphon-229-cross-session-ack-continuity-v1",
       "state":state,"session_count":valid_session_count,"sessions":readback,
       "signed_head_bytes_verified":signed_valid,
       "blockers":sorted(set(errors+["EXTERNAL_SIGNING_KEY_PROVENANCE_UNVERIFIED",
            "GLOBAL_MONOTONIC_HIGHWATER_UNVERIFIED","PHYSICAL_CUSTODY_UNVERIFIED",
            "AUTHENTICATED_UTC_UNVERIFIED"])),
       "fork_branches_unmodified":True,"reconciliation":"NO_WINNER_SELECTED",
       "independently_authenticated_witnesses":0,"authenticated_utc":False,
       "global_anti_rollback_authenticated":False,"recovery_authorized":False,
       "lock_cleared":False,"decision":"HOLD"}
    report["evidence_sha256"]=sha(report)
    return report

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--sessions",required=True);p.add_argument("--bundle",required=True)
    p.add_argument("--source-anchor",required=True);p.add_argument("--signed-head")
    p.add_argument("--head-anchor");p.add_argument("--out",required=True)
    args=p.parse_args()
    def load(path):
        if not path:return None
        try:
            x=pathlib.Path(path)
            if x.stat().st_size>MAX_JSON_BYTES:return None
            return json.loads(x.read_text())
        except (ValueError,OSError):return None
    result=audit(load(args.sessions),load(args.bundle),load(args.source_anchor),
                 load(args.signed_head),load(args.head_anchor))
    out=pathlib.Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(result["state"],"sessions",result["session_count"])
    return 0 if result["state"] in ("CROSS_SESSION_PREFIX_MATCH_HEAD_MISSING_HOLD",
                                   "CROSS_SESSION_SIGNED_HEAD_BYTES_MATCH_HOLD") else 1
if __name__=="__main__":sys.exit(main())
