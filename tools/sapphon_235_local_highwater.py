#!/usr/bin/env python3
"""SAPPHON-235: local append-only nonce highwater, restart replay and fork detection.

This is a source-owned *local* POSIX journal. A privileged actor can replace or
roll back the entire file. Neither fsync nor a hash chain creates independent
external custody. Every output keeps recovery forbidden.
"""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import re

SCHEMA="sapphon-235-local-highwater-v1"
MAX_ROWS=100000
MAX_BYTES=16*1024*1024
HEX=re.compile(r"^[0-9a-f]{64}$")
def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()
def hex64(value):
    return type(value) is str and HEX.fullmatch(value) is not None
def row_hash(row):
    return digest({k:v for k,v in row.items() if k!="row_sha256"})
def audit_rows(rows):
    faults=[];used=set();heads={}
    if type(rows) is not list or len(rows)>MAX_ROWS:
        return {"valid":False,"faults":["ROW_INVENTORY_INVALID"],"rows":0,
                "highwater":None,"used_nonces":[],"witness_epochs":{}}
    previous=None
    for i,row in enumerate(rows):
        if type(row) is not dict or set(row)!={"schema","sequence","nonce","witness_id",
            "witness_epoch","previous_row_sha256","row_sha256"}:
            faults.append("ROW_SCHEMA_INVALID");break
        if row["schema"]!=SCHEMA or type(row["sequence"]) is not int or row["sequence"]!=i:
            faults.append("SEQUENCE_GAP_OR_ROLLBACK");break
        if not hex64(row["nonce"]) or type(row["witness_id"]) is not str or not 1<=len(row["witness_id"])<=128:
            faults.append("NONCE_OR_WITNESS_INVALID");break
        if type(row["witness_epoch"]) is not int or row["witness_epoch"]<0:
            faults.append("EPOCH_INVALID");break
        if row["nonce"] in used:
            faults.append("NONCE_REPLAY");break
        if row["previous_row_sha256"]!=previous:
            faults.append("PREDECESSOR_LINK_INVALID");break
        if not hex64(row["row_sha256"]) or row["row_sha256"]!=row_hash(row):
            faults.append("ROW_DIGEST_INVALID");break
        wid=row["witness_id"]
        if wid in heads and row["witness_epoch"]<=heads[wid]:
            faults.append("WITNESS_EPOCH_REWIND");break
        heads[wid]=row["witness_epoch"]
        used.add(row["nonce"]);previous=row["row_sha256"]
    return {"valid":not faults,"faults":faults,"rows":len(rows),"highwater":previous,
            "used_nonces":sorted(used),"witness_epochs":heads}

def read_rows(path):
    path=pathlib.Path(path)
    if not path.exists():return []
    if path.stat().st_size>MAX_BYTES:raise ValueError("JOURNAL_SIZE_BOUND")
    blob=path.read_bytes()
    if blob and not blob.endswith(b"\n"):raise ValueError("TORN_JOURNAL_TAIL")
    rows=[]
    for line in blob.splitlines():
        if not line:raise ValueError("EMPTY_JOURNAL_LINE")
        rows.append(json.loads(line))
        if len(rows)>MAX_ROWS:raise ValueError("JOURNAL_ROW_BOUND")
    return rows

def append(path,nonce,witness_id,epoch):
    if not hex64(nonce) or type(witness_id) is not str or not 1<=len(witness_id)<=128 or type(epoch) is not int or epoch<0:
        raise ValueError("INVALID_APPEND_INPUT")
    dest=pathlib.Path(path)
    dest.parent.mkdir(parents=True,exist_ok=True)
    # Advisory flock serializes cooperating writers on POSIX. Not an
    # authenticated cross-machine lock or defence against hostile file owners.
    with open(dest,"a+b",buffering=0) as file:
        fcntl.flock(file,fcntl.LOCK_EX)
        file.seek(0)
        blob=file.read(MAX_BYTES+1)
        if len(blob)>MAX_BYTES:raise ValueError("JOURNAL_SIZE_BOUND")
        if blob and not blob.endswith(b"\n"):raise ValueError("TORN_JOURNAL_TAIL")
        rows=[json.loads(line) for line in blob.splitlines()]
        audit=audit_rows(rows)
        if not audit["valid"]:raise ValueError("INVALID_ANCESTRY:"+",".join(audit["faults"]))
        if len(rows)>=MAX_ROWS:raise ValueError("ROW_BOUND")
        if nonce in audit["used_nonces"]:raise ValueError("NONCE_REPLAY")
        old= audit["witness_epochs"].get(witness_id)
        if (old is None and epoch!=0) or (old is not None and epoch<=old):
            raise ValueError("WITNESS_EPOCH_NOT_MONOTONIC")
        row={"schema":SCHEMA,"sequence":len(rows),"nonce":nonce,
             "witness_id":witness_id,"witness_epoch":epoch,
             "previous_row_sha256":audit["highwater"]}
        row["row_sha256"]=row_hash(row)
        line=canonical(row)+b"\n"
        if len(blob)+len(line)>MAX_BYTES:raise ValueError("JOURNAL_SIZE_BOUND")
        file.seek(0,os.SEEK_END)
        written=file.write(line)
        if written!=len(line):raise OSError("SHORT_APPEND")
        os.fsync(file.fileno())
        return row

def compare(left,right):
    a=audit_rows(left);b=audit_rows(right)
    faults=sorted(set(a["faults"]+b["faults"]))
    first=None
    for i in range(min(len(left),len(right))):
        if left[i]!=right[i]:
            first=i;break
    if not a["valid"] or not b["valid"]:state="INVALID_HISTORY_HOLD"
    elif first is not None:state="CONFLICTING_VALID_HISTORIES_HOLD"
    elif len(left)==len(right):state="SAME_LOCAL_HISTORY_HOLD"
    else:state="PREFIX_RELATED_HISTORIES_HOLD"
    out={"schema":"sapphon-235-history-comparison-v1","state":state,
         "left_highwater":a["highwater"],"right_highwater":b["highwater"],
         "left_rows":len(left),"right_rows":len(right),"first_conflict_index":first,
         "faults":faults,
         "external_highwater_authenticated":False,
         "independently_authenticated_witnesses":0,
         "reconciliation":"NO_WINNER_SELECTED","recovery_authorized":False,
         "lock_cleared":False,"decision":"HOLD"}
    out["evidence_sha256"]=digest(out)
    return out

def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="command",required=True)
    add=sub.add_parser("append")
    add.add_argument("--journal",required=True)
    add.add_argument("--nonce",required=True)
    add.add_argument("--witness",required=True)
    add.add_argument("--epoch",type=int,required=True)
    check=sub.add_parser("audit")
    check.add_argument("--journal",required=True)
    cross=sub.add_parser("compare")
    cross.add_argument("--left",required=True);cross.add_argument("--right",required=True)
    args=ap.parse_args()
    if args.command=="append":result=append(args.journal,args.nonce,args.witness,args.epoch)
    elif args.command=="audit":result=audit_rows(read_rows(args.journal))
    else:result=compare(read_rows(args.left),read_rows(args.right))
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
