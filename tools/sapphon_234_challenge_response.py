#!/usr/bin/env python3
"""SAPPHON-234: nonce-bound signed custody challenges, observation-only.

This verifier cannot authenticate independent operator control, durable custody,
authenticated UTC, or rollback authority. It never authorizes recovery.
"""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA="sapphon-234-challenge-response-v1"
MAX_ITEMS=16
MAX_INPUT=1024*1024
HEX64=re.compile(r"^[0-9a-f]{64}$")
def canon(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(x):
    return hashlib.sha256(canon(x)).hexdigest()
def valid_hash(x):
    return type(x) is str and HEX64.fullmatch(x) is not None

def verify(challenges,responses,previous=None):
    faults=[]
    if type(challenges) is not list or not 1<=len(challenges)<=MAX_ITEMS:
        faults.append("CHALLENGE_INVENTORY_INVALID");challenges=[]
    if type(responses) is not list or len(responses)>MAX_ITEMS:
        faults.append("RESPONSE_INVENTORY_INVALID");responses=[]
    if previous is None: previous={"schema":"sapphon-234-replay-state-v1","used_nonces":[],"last_by_witness":{}}
    if type(previous) is not dict or set(previous)!={"schema","used_nonces","last_by_witness"} or previous.get("schema")!="sapphon-234-replay-state-v1" or type(previous.get("used_nonces")) is not list or type(previous.get("last_by_witness")) is not dict:
        faults.append("REPLAY_STATE_INVALID")
        previous={"schema":"sapphon-234-replay-state-v1","used_nonces":[],"last_by_witness":{}}
    old_nonces=previous["used_nonces"]
    if len(old_nonces)>100000 or any(not valid_hash(n) for n in old_nonces) or len(set(old_nonces))!=len(old_nonces):
        faults.append("REPLAY_STATE_NONCES_INVALID")
        old_nonces=[]
    old=set(old_nonces)
    current=set()
    requests={}
    for c in challenges:
        if type(c) is not dict or set(c)!={"witness_id","challenge_nonce","requested_sha256","previous_response_sha256","epoch"}:
            faults.append("CHALLENGE_SCHEMA_INVALID");continue
        witness=c["witness_id"]
        if type(witness) is not str or not 1<=len(witness)<=128 or not valid_hash(c["challenge_nonce"]) or not valid_hash(c["requested_sha256"]) or (c["previous_response_sha256"] is not None and not valid_hash(c["previous_response_sha256"])) or type(c["epoch"]) is not int or c["epoch"]<0:
            faults.append("CHALLENGE_FIELDS_INVALID");continue
        nonce=c["challenge_nonce"]
        if nonce in old: faults.append("CHALLENGE_NONCE_ALREADY_USED")
        if nonce in current: faults.append("CHALLENGE_NONCE_DUPLICATE")
        current.add(nonce)
        if witness in requests: faults.append("CHALLENGE_WITNESS_REUSED")
        requests[witness]=c
        prior=previous["last_by_witness"].get(witness)
        if prior is None and (c["previous_response_sha256"] is not None or c["epoch"]!=0):
            faults.append("UNANCHORED_WITNESS_PREFIX")
        if prior is not None:
            if type(prior) is not dict or not valid_hash(prior.get("response_sha256")) or type(prior.get("epoch")) is not int:
                faults.append("PRIOR_WITNESS_STATE_INVALID")
            elif c["previous_response_sha256"]!=prior["response_sha256"] or c["epoch"]<=prior["epoch"]:
                faults.append("WITNESS_CHAIN_REWIND_OR_FORK")
    retained=[]
    updated={k:v for k,v in previous["last_by_witness"].items()}
    accepted_witnesses=set()
    for i,response in enumerate(responses):
        errors=[]
        if type(response) is not dict or set(response)!={"payload","public_key_pem","signature_base64"}:
            errors.append("RESPONSE_SCHEMA_INVALID")
        else:
            p=response["payload"]
            keys={"schema","witness_id","challenge_nonce","requested_sha256","readback_sha256","previous_response_sha256","epoch"}
            if type(p) is not dict or set(p)!=keys or p.get("schema")!=SCHEMA:
                errors.append("RESPONSE_PAYLOAD_INVALID")
            else:
                witness=p["witness_id"]
                c=requests.get(witness)
                if c is None: errors.append("UNSOLICITED_RESPONSE")
                else:
                    for name in ("witness_id","challenge_nonce","requested_sha256","previous_response_sha256","epoch"):
                        if p.get(name)!=c[name]: errors.append("CHALLENGE_RESPONSE_BINDING_MISMATCH");break
                if not valid_hash(p.get("readback_sha256")) or p.get("readback_sha256")!=p.get("requested_sha256"):
                    errors.append("REMOTE_BYTE_DIGEST_MISMATCH")
                if witness in accepted_witnesses: errors.append("DUPLICATE_WITNESS_RESPONSE")
                try:
                    public=load_pem_public_key(response["public_key_pem"].encode())
                    if not isinstance(public,Ed25519PublicKey): raise ValueError("non Ed25519")
                    public.verify(base64.b64decode(response["signature_base64"],validate=True),canon(p))
                except Exception:
                    errors.append("RESPONSE_SIGNATURE_INVALID")
                if not errors:
                    accepted_witnesses.add(witness)
                    updated[witness]={"epoch":p["epoch"],"response_sha256":sha(response)}
        faults.extend(errors)
        retained.append({"index":i,"response_sha256":sha(response),"complete_response":response,
                         "checks":sorted(set(errors))})
    if len(accepted_witnesses)!=len(requests):
        faults.append("CHALLENGE_RESPONSE_SET_INCOMPLETE")
    # No local response is an externally independently authenticated witness.
    faults.extend(["INDEPENDENT_OPERATOR_CONTROL_UNVERIFIED",
                   "OUT_OF_BAND_RESPONSE_TRANSPORT_UNVERIFIED",
                   "DURABLE_REMOTE_RETENTION_UNVERIFIED",
                   "TRUSTED_MONOTONIC_HIGHWATER_UNVERIFIED",
                   "AUTHENTICATED_UTC_UNVERIFIED"])
    clean=not any(x for x in faults if x not in {
        "INDEPENDENT_OPERATOR_CONTROL_UNVERIFIED","OUT_OF_BAND_RESPONSE_TRANSPORT_UNVERIFIED",
        "DURABLE_REMOTE_RETENTION_UNVERIFIED","TRUSTED_MONOTONIC_HIGHWATER_UNVERIFIED",
        "AUTHENTICATED_UTC_UNVERIFIED"})
    # A replay-state update is only a proposal; actual append-only external
    # persistence must be independently observed before accepting it.
    proposal={"schema":"sapphon-234-replay-state-v1",
              "used_nonces":old_nonces+sorted(current) if clean else old_nonces,
              "last_by_witness":updated if clean else previous["last_by_witness"]}
    result={"schema":"sapphon-234-verification-v1",
            "state":"SIGNED_CHALLENGES_LOCAL_ONLY_RECOVERY_HOLD",
            "responses_retained":retained,"locally_valid_responses":len(accepted_witnesses),
            "replay_state_proposal":proposal,"replay_state_committed":False,
            "independently_authenticated_witnesses":0,
            "blockers":sorted(set(faults)),"reconciliation":"NO_WINNER_SELECTED",
            "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
    result["evidence_sha256"]=sha(result)
    return result

def main():
    a=argparse.ArgumentParser()
    for name in ("challenges","responses","out"): a.add_argument("--"+name,required=True)
    a.add_argument("--previous")
    args=a.parse_args()
    def read(p):
        if p is None:return None
        f=Path(p)
        if f.stat().st_size>MAX_INPUT:raise ValueError("oversize input")
        return json.loads(f.read_text())
    report=verify(read(args.challenges),read(args.responses),read(args.previous))
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(report["state"],"locally_valid_responses",report["locally_valid_responses"])
if __name__=="__main__":main()
