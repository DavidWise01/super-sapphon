#!/usr/bin/env python3
"""SAPPHON-100 independent Python audit of a signed enrollment checkpoint.
Requires cryptography. Governance root supplied separately by the verifier.
A second implementation does NOT create an independent evidence source.
"""
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

FIELDS=["type","source_id","ancestry_root","role","key_id","public_key_pem","reason","generation","index","prev_event_hash"]
SOURCE_FIELDS=["source_id","ancestry_root","role","key_id","generation","status"]
HEX=re.compile(r"[a-f0-9]{64}\Z")
ID=re.compile(r"[a-z0-9-]{4,64}\Z")
def insist(ok,msg):
    if not ok: raise ValueError(msg)
def compact(a):
    return json.dumps(a,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode("utf-8")
def event_bytes(e):
    insist(type(e)==dict and set(e)==set(FIELDS),"EVENT_FIELDS")
    insist(e["type"] in ("ENROLL","REVOKE","REENROLL"),"EVENT_TYPE")
    insist(all(type(e[k])==str and ID.fullmatch(e[k]) for k in ("source_id","ancestry_root","key_id")),"EVENT_ID")
    insist(e["role"]=="synthetic-test","EVENT_ROLE")
    insist(type(e["index"])==int and e["index"]>=0 and type(e["generation"])==int and e["generation"]>=0,"EVENT_INDEX")
    insist((e["index"]==0 and e["prev_event_hash"] is None) or
           (e["index"]>0 and type(e["prev_event_hash"])==str and HEX.fullmatch(e["prev_event_hash"])),"EVENT_PREV")
    if e["type"]=="REVOKE":
        insist(e["public_key_pem"] is None and type(e["reason"])==str and 0<len(e["reason"].strip())<=256,"REVOCATION_REASON")
    else:
        insist(e["reason"] is None and type(e["public_key_pem"])==str,"KEY_FIELDS")
        load_pem_public_key(e["public_key_pem"].encode())
    return compact([e[k] for k in FIELDS])
def decode_signature(s):
    insist(type(s)==str and re.fullmatch(r"[A-Za-z0-9+/]{86}==",s),"SIGNATURE_ENCODING")
    return base64.b64decode(s,validate=True)
def verify(doc,public_pem,expected_key_id):
    insist(type(doc)==dict and set(doc)=={"entries","checkpoint"},"DOCUMENT_FIELDS")
    cp=doc["checkpoint"]
    insist(type(cp)==dict and set(cp)=={"payload","signature"},"CHECKPOINT_FIELDS")
    payload=cp["payload"]
    insist(type(payload)==dict and set(payload)=={"schema","head","count","governance_key_id","sources"},"PAYLOAD_FIELDS")
    insist(payload["schema"]=="sapphon-enrollment-checkpoint-v1","SCHEMA")
    insist(payload["governance_key_id"]==expected_key_id,"GOVERNANCE_ROOT_MISMATCH")
    insist(type(payload["count"])==int and 1<=payload["count"]<=4096,"COUNT")
    insist(type(payload["head"])==str and HEX.fullmatch(payload["head"]),"HEAD")
    insist(type(payload["sources"])==list,"SOURCES")
    pub=load_pem_public_key(public_pem.encode())
    source_rows=[]
    for s in payload["sources"]:
        insist(type(s)==dict and set(s)==set(SOURCE_FIELDS),"SOURCE_FIELDS")
        insist(type(s["generation"])==int and s["generation"]>=0 and s["status"] in ("ACTIVE","REVOKED"),"SOURCE_STATE")
        source_rows.append([s[k] for k in SOURCE_FIELDS])
    message=compact([payload["schema"],payload["head"],payload["count"],payload["governance_key_id"],source_rows])
    try:pub.verify(decode_signature(cp["signature"]),message)
    except InvalidSignature: raise ValueError("CHECKPOINT_SIGNATURE")
    entries=doc["entries"]
    insist(type(entries)==list and len(entries)==payload["count"],"COUNT_MISMATCH")
    head=None
    sources={}
    used_keys=set()
    for idx,item in enumerate(entries):
        insist(type(item)==dict and set(item)=={"event","signature"},"ENTRY_FIELDS")
        e=item["event"]
        eb=event_bytes(e)
        insist(e["index"]==idx and e["prev_event_hash"]==head,"LEDGER_CHAIN")
        rawsig=decode_signature(item["signature"])
        try:pub.verify(rawsig,eb)
        except InvalidSignature:raise ValueError("EVENT_SIGNATURE")
        sid=e["source_id"]
        prior=sources.get(sid)
        if e["type"]=="ENROLL":
            insist(prior is None and e["generation"]==0 and e["key_id"] not in used_keys,"ENROLL_CONFLICT")
            sources[sid]={"source_id":sid,"ancestry_root":e["ancestry_root"],"role":e["role"],
                "key_id":e["key_id"],"generation":0,"status":"ACTIVE","public_key_pem":e["public_key_pem"]}
            used_keys.add(e["key_id"])
        elif e["type"]=="REVOKE":
            insist(prior is not None and prior["status"]=="ACTIVE" and e["key_id"]==prior["key_id"] and
                   e["generation"]==prior["generation"] and e["ancestry_root"]==prior["ancestry_root"],"REVOKE_CONFLICT")
            prior["status"]="REVOKED"
        else:
            insist(prior is not None and prior["status"]=="REVOKED" and
                   e["ancestry_root"]==prior["ancestry_root"] and e["generation"]==prior["generation"]+1 and
                   e["key_id"] not in used_keys and
                   e["public_key_pem"]!=prior["public_key_pem"],"REENROLL_CONFLICT")
            prior.update(key_id=e["key_id"],generation=e["generation"],status="ACTIVE",public_key_pem=e["public_key_pem"])
            used_keys.add(e["key_id"])
        head=hashlib.sha256(b"SAPPHON099\x00"+eb+rawsig).hexdigest()
    insist(head==payload["head"],"HEAD_MISMATCH")
    actual=[{k:v[k] for k in SOURCE_FIELDS} for _,v in sorted(sources.items())]
    insist(actual==payload["sources"],"SOURCE_STATE_MISMATCH")
    return {"status":"VALID_SAME_GOVERNANCE_ROOT","events":len(entries),
        "roots":len(set(s["ancestry_root"] for s in actual)),
        "clock_authority":False,"independent_witnesses_verified":False}
if __name__=="__main__":
    try:
        if len(sys.argv)!=4:raise ValueError("usage: verifier audit.json root-public.pem key-id")
        doc=json.loads(Path(sys.argv[1]).read_text())
        root=Path(sys.argv[2]).read_text()
        print(json.dumps(verify(doc,root,sys.argv[3]),sort_keys=True))
    except Exception as e:
        print("FAIL:",e,file=sys.stderr)
        sys.exit(1)
