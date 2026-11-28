#!/usr/bin/env python3
"""SAPPHON-227: replay portable fork bundle and cryptographic ACK, remain HOLD.

The supplied signer keys and custody claims are *not* externally authenticated.
A valid Ed25519 signature proves possession of a signing key only.
"""
import argparse
import hashlib
import json
import pathlib
import sys

import sapphon_221_attestation as crypto
import sapphon_225_fork_retention as retained
import sapphon_226_fork_export as portable

MAX_BUNDLE_BYTES=4*1024*1024
ACK_FIELDS={"schema","manifest_sha256","custodian_root","source_run",
            "source_commit","fork_count","claimed_utc","transfer_nonce"}
def canon(x):return portable.canonical(x)
def sha(x):return hashlib.sha256(canon(x)).hexdigest()
def key_matches(pem,anchor):
    return (type(anchor) is dict and type(pem) is str and 0<len(pem)<=4096
            and anchor.get("public_key_pem")==pem
            and anchor.get("key_sha256")==hashlib.sha256(pem.encode()).hexdigest())
def adjudicate(bundle,source_anchor=None,ack=None,ack_anchor=None):
    errors=[]
    if type(bundle) is not dict or len(canon(bundle))>MAX_BUNDLE_BYTES:
        bundle={}
        errors.append("BUNDLE_MISSING_OR_UNBOUNDED")
    h=bundle.get("manifest_sha256")
    body={k:v for k,v in bundle.items() if k!="manifest_sha256"}
    if (type(h) is not str or h!=sha(body)
        or bundle.get("schema")!="sapphon-226-portable-fork-export-v1"):
        errors.append("BUNDLE_MANIFEST_INVALID")
    heads=bundle.get("heads")
    forks=bundle.get("forks")
    if type(heads) is not list or type(forks) is not list or not forks or len(heads)>retained.LIMIT:
        heads=[];forks=[]
        errors.append("BUNDLE_BRANCH_INVENTORY_INVALID")
    envelopes=[]
    for idx,item in enumerate(heads):
        if (type(item) is not dict or item.get("index")!=idx
            or type(item.get("envelope")) is not dict
            or item.get("sha256")!=sha(item["envelope"])):
            errors.append("RETAINED_ENVELOPE_HASH_CONFLICT")
            continue
        envelopes.append(item["envelope"])
    if len(envelopes)!=len(heads):
        errors.append("RETAINED_ENVELOPE_MISSING")
    # Independently reconstruct source retention from all signatures, branches
    # and the supplied anchor. Never rely only on a self-hashed report.
    source=retained.adjudicate(envelopes,source_anchor)
    reconstructed,old_verdict=portable.export(source)
    if (source["state"]!="SIGNED_FORK_PRESERVED_HOLD"
        or source["verified_signature_count"]!=len(heads)
        or reconstructed!=bundle
        or old_verdict["state"]!="PORTABLE_FORK_EVIDENCE_READY_HOLD"):
        errors.append("FORK_REPLAY_OR_SIGNATURE_CONFLICT")
    if (bundle.get("source_evidence_sha256")!=source.get("evidence_sha256")
        or bundle.get("source_image_sha256")!=retained.chain.IMAGE_SHA
        or bundle.get("source_commit")!=retained.chain.SOURCE_COMMIT
        or bundle.get("source_run")!=retained.chain.SOURCE_RUN):
        errors.append("SOURCE_ANCESTRY_CONFLICT")
    if (bundle.get("independent_witnesses")!=0 or
        bundle.get("recovery_authorized") is not False
        or bundle.get("lock_cleared") is not False
        or bundle.get("reconciliation")!="NO_WINNER_SELECTED"
        or bundle.get("decision")!="HOLD"):
        errors.append("AUTHORITY_OR_RECONCILIATION_VIOLATION")
    ack_valid=False
    if ack is None:
        errors.append("SIGNED_CUSTODY_ACK_MISSING")
    elif type(ack) is not dict or set(ack)!={"payload","signature_base64","public_key_pem",
                                           "recovery_authorized","lock_cleared"}:
        errors.append("ACK_ENVELOPE_INVALID")
    else:
        payload=ack["payload"]
        if (type(payload) is not dict or set(payload)!=ACK_FIELDS
            or payload.get("schema")!="sapphon-227-custody-transfer-ack-v1"
            or payload.get("manifest_sha256")!=h
            or payload.get("source_run")!=retained.chain.SOURCE_RUN
            or payload.get("source_commit")!=retained.chain.SOURCE_COMMIT
            or type(payload.get("fork_count")) is not int
            or payload.get("fork_count")!=len(forks)
            or not isinstance(payload.get("transfer_nonce"),str)
            or len(payload["transfer_nonce"])<16
            or not isinstance(payload.get("claimed_utc"),str)
            or not isinstance(payload.get("custodian_root"),str)
            or payload["custodian_root"] in ("","GitHub","github")):
            errors.append("ACK_PAYLOAD_OR_BINDING_INVALID")
        pem=ack.get("public_key_pem")
        if not key_matches(pem,ack_anchor):
            errors.append("ACK_ANCHOR_MISMATCH")
        if (type(ack_anchor) is not dict or
            type(payload) is not dict or
            ack_anchor.get("custodian_root")!=payload.get("custodian_root")):
            errors.append("ACK_CUSTODIAN_MISMATCH")
        if (ack.get("recovery_authorized") is not False
            or ack.get("lock_cleared") is not False):
            errors.append("UNSAFE_ACK_AUTHORITY")
        ack_valid=bool(
            not errors and type(ack.get("signature_base64")) is str and
            crypto.verify_crypto(canon(payload),ack["signature_base64"],pem))
        if not ack_valid:
            errors.append("ACK_SIGNATURE_UNVERIFIED")
    # No hosted source-owned process authenticates external key provisioning,
    # transport receipt, trusted UTC or global monotonic storage.
    blocks=sorted(set(errors+["EXTERNAL_KEY_PROVENANCE_UNVERIFIED",
           "PHYSICAL_CUSTODY_UNVERIFIED","AUTHENTICATED_UTC_UNVERIFIED",
           "GLOBAL_ANTI_ROLLBACK_UNVERIFIED"]))
    structure_ok=not any(e not in {"SIGNED_CUSTODY_ACK_MISSING"} for e in errors)
    state=("SIGNED_ACK_CHECKED_CUSTODY_HOLD" if structure_ok and ack_valid else
           "PORTABLE_BUNDLE_REPLAYED_ACK_HOLD" if structure_ok and ack is None else
           "TRANSFER_REJECTED_HOLD")
    return {"schema":"sapphon-227-transfer-readback-v1","state":state,
      "source_manifest_sha256":h,"source_evidence_sha256":source.get("evidence_sha256"),
      "heads_preserved":len(envelopes),"forks_preserved":len(forks),
      "ack_signature_valid":ack_valid,
      "reconciliation":"NO_WINNER_SELECTED",
      "blockers":blocks,"independently_authenticated_witnesses":0,
      "authenticated_utc":False,"global_anti_rollback_authenticated":False,
      "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
def main():
    p=argparse.ArgumentParser()
    for key in ("bundle","source-anchor","out"):p.add_argument("--"+key,required=True)
    p.add_argument("--ack");p.add_argument("--ack-anchor")
    a=p.parse_args()
    def read(path):
        try:
            path=pathlib.Path(path)
            if path.stat().st_size>MAX_BUNDLE_BYTES:return None
            return json.loads(path.read_text())
        except (ValueError,OSError):return None
    result=adjudicate(read(a.bundle),read(a.source_anchor),
                      read(a.ack) if a.ack else None,
                      read(a.ack_anchor) if a.ack_anchor else None)
    dst=pathlib.Path(a.out);dst.parent.mkdir(parents=True,exist_ok=True)
    dst.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(result["state"],",".join(result["blockers"]))
    return 0 if result["state"] in ("PORTABLE_BUNDLE_REPLAYED_ACK_HOLD",
                                   "SIGNED_ACK_CHECKED_CUSTODY_HOLD") else 1
if __name__=="__main__":sys.exit(main())
