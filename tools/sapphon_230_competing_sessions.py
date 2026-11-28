#!/usr/bin/env python3
"""SAPPHON-230: preserve competing complete ACK-session histories and signed heads.

All externally labeled inputs are untrusted until authenticated outside GitHub.
Neither signatures nor a matching declared highwater grants custody or recovery.
"""
import argparse,hashlib,json,pathlib,sys
import sapphon_229_cross_session as prior
import sapphon_228_ack_ledger as ledger

MAX_CANDIDATES=16
MAX_JSON_BYTES=4*1024*1024
def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(x):
    return hashlib.sha256(canonical(x)).hexdigest()
def assess(candidates,bundle,source_anchor,external_head=None,external_anchor=None):
    faults=[]
    if type(candidates) is not list or not 1<=len(candidates)<=MAX_CANDIDATES:
        candidates=[];faults.append("CANDIDATE_INVENTORY_MISSING_OR_UNBOUNDED")
    entries=[]
    groups={}
    seen_ids=set()
    for i,item in enumerate(candidates):
        if type(item) is not dict or set(item)!={"candidate_id","sessions","signed_head","head_anchor"}:
            faults.append("CANDIDATE_SCHEMA_INVALID");continue
        ident=item["candidate_id"]
        if type(ident) is not str or not 4<=len(ident)<=80 or ident in seen_ids:
            faults.append("CANDIDATE_ID_DUPLICATE_OR_INVALID");continue
        seen_ids.add(ident)
        sessions=item["sessions"]
        original=prior.audit(sessions,bundle,source_anchor,item["signed_head"],item["head_anchor"])
        valid=original["state"]=="CROSS_SESSION_SIGNED_HEAD_BYTES_MATCH_HOLD"
        if not valid:faults.append("CANDIDATE_HISTORY_OR_HEAD_REJECTED")
        record_count=0
        records=[]
        if type(sessions) is list and sessions and type(sessions[-1]) is dict:
            records=sessions[-1].get("records",[])
            if type(records) is list:record_count=len(records)
            else:records=[]
        terminal=records[-1].get("entry_sha256") if records and type(records[-1]) is dict else None
        descriptor={"candidate_id":ident,"input_index":i,"verified_structure":valid,
            "record_count":record_count,"head_sha256":terminal,
            "session_set_sha256":sha(sessions),"signed_head_sha256":sha(item["signed_head"]),
            "complete_candidate":item}
        entries.append(descriptor)
        if valid:
            groups.setdefault(record_count,{}).setdefault(terminal,[]).append(ident)
    forks=[]
    for counter,heads in sorted(groups.items()):
        if len(heads)>1:
            forks.append({"record_count":counter,
               "conflicting_head_sha256":sorted(heads),
               "candidate_ids_by_head":{h:sorted(v) for h,v in sorted(heads.items())},
               "disposition":"RETAIN_ALL_NO_SELECTION"})
    # Distinguish at-least-one signed fork from an externally authenticated fork.
    if forks:faults.append("SIGNED_SESSION_FORK_REQUIRES_EXTERNAL_RECONCILIATION")
    if len(entries)!=len(candidates):faults.append("INCOMPLETE_CANDIDATE_INVENTORY")
    external_matched=False
    if external_head is None:
        faults.append("EXTERNAL_HIGHWATER_MISSING")
    elif not entries:
        faults.append("EXTERNAL_HIGHWATER_WITHOUT_CANDIDATE")
    else:
        matches=[]
        for item in candidates:
            if type(item) is not dict:continue
            s=item.get("sessions")
            if type(s) is not list or not s or type(s[-1]) is not dict:continue
            verified,problems=prior.verify_signed_head(external_head,external_anchor,s[-1])
            if verified:matches.append(item.get("candidate_id"))
        external_matched=bool(matches)
        if not external_matched:faults.append("EXTERNAL_SIGNED_HEAD_NOT_MATCHED")
        # An unauthenticated highwater does not resolve a fork even if it
        # happens to match one branch.
        if forks:faults.append("EXTERNAL_HEAD_CANNOT_SELECT_FORK_WINNER")
    hard=set(faults)-{"SIGNED_SESSION_FORK_REQUIRES_EXTERNAL_RECONCILIATION",
        "EXTERNAL_HIGHWATER_MISSING","EXTERNAL_HEAD_CANNOT_SELECT_FORK_WINNER"}
    state=("SIGNED_SESSION_FORK_PRESERVED_HOLD" if forks and not hard else
           "SOURCE_OWNED_HIGHWATER_BYTES_MATCH_HOLD" if not hard and external_matched else
           "STRUCTURAL_SESSIONS_HELD_NO_EXTERNAL_HEAD" if not hard and entries else
           "SESSION_FORK_OR_HIGHWATER_REJECTED_HOLD")
    report={"schema":"sapphon-230-competing-sessions-v1","state":state,
      "candidates_retained":entries,"candidate_count":len(entries),
      "forks_retained":forks,"fork_count":len(forks),
      "signed_external_head_bytes_match":external_matched,
      "blockers":sorted(set(faults+["INDEPENDENT_HEAD_CUSTODY_UNVERIFIED",
        "EXTERNAL_KEY_PROVISIONING_UNVERIFIED","PHYSICAL_CUSTODY_UNVERIFIED",
        "AUTHENTICATED_UTC_UNVERIFIED","GLOBAL_ANTI_ROLLBACK_UNVERIFIED"])),
      "reconciliation":"NO_WINNER_SELECTED","independently_authenticated_witnesses":0,
      "authenticated_utc":False,"global_anti_rollback_authenticated":False,
      "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
    report["evidence_sha256"]=sha(report)
    return report
def main():
    p=argparse.ArgumentParser()
    for name in ("candidates","bundle","source-anchor","out"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--external-head");p.add_argument("--external-anchor")
    a=p.parse_args()
    def read(path):
        if not path:return None
        try:
            q=pathlib.Path(path)
            if q.stat().st_size>MAX_JSON_BYTES:return None
            return json.loads(q.read_text())
        except (ValueError,OSError):return None
    result=assess(read(a.candidates),read(a.bundle),read(a.source_anchor),
                  read(a.external_head),read(a.external_anchor))
    out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(result["state"],"forks",result["fork_count"])
    return 0 if result["state"]!="SESSION_FORK_OR_HIGHWATER_REJECTED_HOLD" else 1
if __name__=="__main__":sys.exit(main())
