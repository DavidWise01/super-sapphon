#!/usr/bin/env python3
"""SAPPHON-224: anchored Ed25519 checkpoint heads and equivocation detection.

Verifies bytes and signature with separately supplied public key. Neither a
provided key nor signatures establish independent custody or a trusted clock.
"""
import argparse,hashlib,json,pathlib,re,sys
import sapphon_221_attestation as ed
import sapphon_223_checkpoint as chain
HEX=re.compile(r"^[0-9a-f]{64}$")
FIELDS={"schema","sequence","checkpoint_sha256","custodian_root","source_run","source_commit","image_sha256","claimed_utc"}
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()
def inspect(heads,anchor,records):
    failures=[]
    if type(heads) is not list or not (1<=len(heads)<=64):
        heads=[];failures.append("HEAD_SET_EMPTY_OR_UNBOUNDED")
    if type(anchor) is not dict:anchor={}
    key=anchor.get("public_key_pem")
    key_ok=(type(key) is str and len(key)<4096 and
         hashlib.sha256(key.encode()).hexdigest()==anchor.get("key_sha256"))
    if not key_ok:failures.append("ANCHOR_KEY_HASH_INVALID")
    observed={}
    valid=0
    for item in heads:
        if type(item) is not dict or set(item)!={"payload","signature_base64"}:
            failures.append("HEAD_ENVELOPE_INVALID");continue
        p=item.get("payload")
        if type(p) is not dict or set(p)!=FIELDS or p.get("schema")!="sapphon-224-signed-head-v1":
            failures.append("HEAD_SCHEMA_INVALID");continue
        if (type(p.get("sequence")) is not int or p["sequence"]<1 or
            type(p.get("checkpoint_sha256")) is not str or not HEX.fullmatch(p["checkpoint_sha256"]) or
            type(p.get("custodian_root")) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{4,128}",p["custodian_root"])):
            failures.append("HEAD_COUNTER_OR_DIGEST_INVALID");continue
        if p["source_run"]!=chain.SOURCE_RUN or p["source_commit"]!=chain.SOURCE_COMMIT or p["image_sha256"]!=chain.IMAGE_SHA:
            failures.append("SOURCE_ANCESTRY_CONFLICT");continue
        if not isinstance(p.get("claimed_utc"),str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",p["claimed_utc"]):
            failures.append("CLAIMED_UTC_INVALID");continue
        if p["custodian_root"]!=anchor.get("custodian_root"):
            failures.append("ANCHOR_ROOT_MISMATCH");continue
        if not key_ok or not isinstance(item["signature_base64"],str) or not ed.verify_crypto(canonical(p),item["signature_base64"],key):
            failures.append("HEAD_SIGNATURE_INVALID");continue
        valid+=1
        ident=(p["custodian_root"],p["sequence"])
        prev=observed.get(ident)
        if prev is not None and prev!=p["checkpoint_sha256"]:
            failures.append("SIGNED_EQUIVOCATION_SAME_COUNTER")
        observed[ident]=p["checkpoint_sha256"]
    if type(records) is not list or not records or len(records)>chain.MAX_RECORDS:
        failures.append("RECORDS_MISSING")
    else:
        # All submitted signed heads must refer to the same terminal
        # checkpoint; a minority conflicting head is never ignored.
        structure=chain.adjudicate(records,{"sequence":len(records),
          "checkpoint_sha256":chain.sha(records[-1]),"custodian_root":records[-1].get("custodian_root"),
          "externally_authenticated":True})
        if structure["state"]!="STRUCTURAL_CHAIN_MATCH_CUSTODY_HOLD":
            failures.append("CHECKPOINT_CHAIN_INVALID")
        terminal=chain.sha(records[-1])
        for root_counter,hash_value in observed.items():
            if root_counter!=(records[-1].get("custodian_root"),len(records)) or hash_value!=terminal:
                failures.append("SIGNED_HEAD_NOT_TERMINAL")
    if valid==0:failures.append("NO_VERIFIED_SIGNED_HEAD")
    return {"schema":"sapphon-224-signed-head-fork-gate-v1",
        "state":"SIGNED_HEAD_STRUCTURAL_MATCH_CUSTODY_HOLD" if not failures else "SIGNED_HEAD_REJECTED_HOLD",
        "signed_heads_checked":len(heads),"signatures_valid":valid,
        "blockers":sorted(set(failures+["ANCHOR_PROVENANCE_NOT_EXTERNAL_AUTHENTICATED",
          "INDEPENDENT_HEAD_CUSTODY_UNVERIFIED","AUTHENTICATED_UTC_UNVERIFIED",
          "EXTERNAL_ANTI_ROLLBACK_UNVERIFIED"])),
        "independently_authenticated_witnesses":0,"authenticated_utc":False,
        "global_anti_rollback_authenticated":False,"recovery_authorized":False,
        "lock_cleared":False,"decision":"HOLD"}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--heads",required=True);p.add_argument("--anchor",required=True)
    p.add_argument("--records",required=True);p.add_argument("--out",required=True)
    a=p.parse_args()
    def read(file):
        try:return json.loads(pathlib.Path(file).read_text())
        except (OSError,ValueError):return None
    out=inspect(read(a.heads),read(a.anchor),read(a.records))
    dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")
    print(out["state"],",".join(out["blockers"]))
    return 0 if out["state"]=="SIGNED_HEAD_STRUCTURAL_MATCH_CUSTODY_HOLD" else 1
if __name__=="__main__":sys.exit(main())
