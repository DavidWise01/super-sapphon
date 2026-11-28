#!/usr/bin/env python3
"""SAPPHON-223: deterministic checkpoint chain and rollback/fork detection.

Input evidence is caller-owned unless an *independent* custody channel
authenticates it. Passing structural tests never grants witness authority.
"""
import argparse, hashlib, json, pathlib, re, sys

HEX64=re.compile(r"^[0-9a-f]{64}$")
MAX_RECORDS=4096
GENESIS="0"*64
SOURCE_RUN="46154833375"
SOURCE_COMMIT="c167a95a05177e280625fa61613c1b1fa20f75e9"
IMAGE_SHA="32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197"
FIELDS={"schema","sequence","previous_sha256","custodian_root","source_run",
        "source_commit","image_sha256","claimed_utc","key_fingerprint_sha256"}
def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()
def validate(record):
    if type(record) is not dict or set(record)!=FIELDS: return "RECORD_SCHEMA"
    if record["schema"]!="sapphon-223-custody-checkpoint-v1": return "RECORD_SCHEMA"
    if type(record["sequence"]) is not int or record["sequence"]<1: return "COUNTER_INVALID"
    if type(record["previous_sha256"]) is not str or not HEX64.fullmatch(record["previous_sha256"]):
        return "PREVIOUS_DIGEST_INVALID"
    if type(record["custodian_root"]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{4,128}",record["custodian_root"]):
        return "CUSTODIAN_ROOT_INVALID"
    if record["source_run"]!=SOURCE_RUN or record["source_commit"]!=SOURCE_COMMIT or record["image_sha256"]!=IMAGE_SHA:
        return "SOURCE_ANCESTRY_CONFLICT"
    if type(record["claimed_utc"]) is not str or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",record["claimed_utc"]):
        return "CLAIMED_UTC_SYNTAX"
    if type(record["key_fingerprint_sha256"]) is not str or not HEX64.fullmatch(record["key_fingerprint_sha256"]):
        return "KEY_FINGERPRINT_INVALID"
    return None
def adjudicate(records,head=None):
    blockers=[]
    if type(records) is not list or len(records)>MAX_RECORDS:
        records=[];blockers.append("RECORD_SET_INVALID_OR_TOO_LARGE")
    previous=GENESIS
    custodian=None
    hashes=[]
    seen_sequence={}
    seen_hashes=set()
    expected_sequence=1
    for index,item in enumerate(records):
        problem=validate(item)
        if problem:
            blockers.append(problem)
            continue
        sequence=item["sequence"]
        digest=sha(item)
        if sequence in seen_sequence:
            blockers.append("DUPLICATE_OR_FORKED_SEQUENCE")
            if seen_sequence[sequence]!=digest:blockers.append("FORKED_CHECKPOINT")
        else:
            seen_sequence[sequence]=digest
        if digest in seen_hashes:blockers.append("DUPLICATE_CHECKPOINT")
        seen_hashes.add(digest)
        if sequence!=expected_sequence:
            blockers.append("COUNTER_REPLAY_OR_GAP")
        if item["previous_sha256"]!=previous:
            blockers.append("PREDECESSOR_DIGEST_CONFLICT")
        if custodian is None:custodian=item["custodian_root"]
        elif item["custodian_root"]!=custodian:blockers.append("CUSTODIAN_ANCESTRY_CHANGED")
        previous=digest
        hashes.append(digest)
        expected_sequence+=1
    if not hashes:blockers.append("NO_CHECKPOINTS")
    # A caller-declared head is not an independent anti-rollback authority.
    if type(head) is not dict:
        blockers.append("INDEPENDENT_EXTERNAL_HEAD_MISSING")
    else:
        if head.get("checkpoint_sha256")!=previous or head.get("sequence")!=expected_sequence-1:
            blockers.append("HEAD_ROLLBACK_OR_CONFLICT")
        if head.get("custodian_root")!=custodian:
            blockers.append("HEAD_CUSTODIAN_CONFLICT")
        if head.get("externally_authenticated") is not True:
            blockers.append("EXTERNAL_HEAD_NOT_AUTHENTICATED")
        # Even the boolean above is only a claim when supplied through GitHub.
        blockers.append("HEAD_TRUST_ROOT_NOT_INDEPENDENTLY_VERIFIED")
    blockers.extend(("INDEPENDENT_KEY_PROVISIONING_UNVERIFIED",
                     "AUTHENTICATED_UTC_UNVERIFIED",
                     "EXTERNAL_ANTI_ROLLBACK_UNVERIFIED",
                     "PHYSICAL_CUSTODY_UNVERIFIED"))
    structural=set(blockers).isdisjoint({
       "RECORD_SET_INVALID_OR_TOO_LARGE","RECORD_SCHEMA","COUNTER_INVALID",
       "PREVIOUS_DIGEST_INVALID","CUSTODIAN_ROOT_INVALID","SOURCE_ANCESTRY_CONFLICT",
       "CLAIMED_UTC_SYNTAX","KEY_FINGERPRINT_INVALID","DUPLICATE_OR_FORKED_SEQUENCE",
       "FORKED_CHECKPOINT","DUPLICATE_CHECKPOINT","COUNTER_REPLAY_OR_GAP",
       "PREDECESSOR_DIGEST_CONFLICT","CUSTODIAN_ANCESTRY_CHANGED","NO_CHECKPOINTS",
       "HEAD_ROLLBACK_OR_CONFLICT","HEAD_CUSTODIAN_CONFLICT"})
    return {"schema":"sapphon-223-checkpoint-continuity-verdict-v1",
      "state":"STRUCTURAL_CHAIN_MATCH_CUSTODY_HOLD" if structural else "CHECKPOINT_CHAIN_REJECTED_HOLD",
      "records_checked":len(records),"last_digest":previous if hashes else None,
      "blockers":sorted(set(blockers)),
      "independently_authenticated_witnesses":0,
      "authenticated_utc":False,"global_anti_rollback_authenticated":False,
      "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--records",required=True);p.add_argument("--head")
    p.add_argument("--out",required=True)
    a=p.parse_args()
    def load(path):
        try:return json.loads(pathlib.Path(path).read_text()) if path else None
        except (OSError, ValueError):return None
    result=adjudicate(load(a.records),load(a.head))
    out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["state"],",".join(result["blockers"]))
    return 0 if result["state"]=="STRUCTURAL_CHAIN_MATCH_CUSTODY_HOLD" else 1
if __name__=="__main__":sys.exit(main())
