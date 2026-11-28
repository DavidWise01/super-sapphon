#!/usr/bin/env python3
"""SAPPHON-226 — portable hash-bound fork export and no-promotion custody intake.

Source-owned transfer package. Never asserts external custody, authenticated
clock, anti-rollback or recovery authorization.
"""
import argparse,hashlib,json,pathlib,sys
import sapphon_225_fork_retention as prior

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()
def export(report,receipt=None):
    issues=[]
    if type(report) is not dict:
        report={};issues.append("REPORT_ABSENT")
    held=report.get("heads_retained")
    forks=report.get("signed_forks")
    original_hash=report.get("evidence_sha256")
    if type(held) is not list or type(forks) is not list or len(held)>prior.LIMIT:
        held=[];forks=[];issues.append("REPORT_SHAPE")
    remainder={k:v for k,v in report.items() if k!="evidence_sha256"}
    if type(original_hash) is not str or digest(remainder)!=original_hash:
        issues.append("REPORT_HASH_MISMATCH")
    for field,value in (("schema","sapphon-225-fork-evidence-retention-v1"),
                        ("state","SIGNED_FORK_PRESERVED_HOLD"),
                        ("reconciliation","NO_WINNER_SELECTED"),
                        ("decision","HOLD")):
        if report.get(field)!=value:issues.append("REPORT_"+field.upper())
    if report.get("fork_count")!=len(forks) or not forks or report.get("head_count")!=len(held):
        issues.append("FORK_COUNT_OR_MISSING_BRANCH")
    if (report.get("recovery_authorized") is not False or
        report.get("lock_cleared") is not False or
        report.get("independently_authenticated_witnesses")!=0):
        issues.append("UNSAFE_SOURCE_AUTHORITY")
    observed={}
    retained=[]
    for index,entry in enumerate(held):
        if type(entry) is not dict or type(entry.get("canonical_envelope")) is not dict:
            issues.append("HEAD_ENVELOPE_INVALID");continue
        envelope=entry["canonical_envelope"]
        h=digest(envelope)
        if (entry.get("input_index")!=index or
            entry.get("canonical_envelope_sha256")!=h or
            entry.get("canonical_envelope_hex_bytes")!=len(canonical(envelope)) or
            entry.get("signature_verified_against_supplied_key") is not True):
            issues.append("HEAD_EVIDENCE_CONFLICT")
        payload=envelope.get("payload") if type(envelope.get("payload")) is dict else {}
        key=(payload.get("custodian_root"),payload.get("sequence"),payload.get("checkpoint_sha256"))
        observed.setdefault(str(key),[]).append(h)
        retained.append({"index":index,"sha256":h,"envelope":envelope})
    referenced=set()
    for fork in forks:
        if type(fork) is not dict or fork.get("disposition")!="PRESERVE_BOTH_NO_SELECTION":
            issues.append("FORK_DISPOSITION_INVALID");continue
        groups=fork.get("retained_signed_envelopes_by_checkpoint")
        hashes=fork.get("conflicting_checkpoint_sha256")
        if type(groups) is not dict or type(hashes) is not list or len(set(hashes))<2 or set(groups)!=set(hashes):
            issues.append("FORK_BRANCHES_INVALID");continue
        for checkpoint,identifiers in groups.items():
            if type(identifiers) is not list or not identifiers:
                issues.append("FORK_BRANCH_EMPTY");continue
            actual=observed.get(str((fork.get("custodian_root"),fork.get("sequence"),checkpoint)),[])
            if sorted(identifiers)!=sorted(actual):
                issues.append("FORK_BRANCH_HASH_CONFLICT")
            referenced.update(identifiers)
    if not referenced or not referenced.issubset({h["sha256"] for h in retained}):
        issues.append("FORK_EVIDENCE_INCOMPLETE")
    manifest={"schema":"sapphon-226-portable-fork-export-v1",
      "source_evidence_sha256":original_hash,
      "source_image_sha256":prior.chain.IMAGE_SHA,
      "source_commit":prior.chain.SOURCE_COMMIT,
      "source_run":prior.chain.SOURCE_RUN,
      "heads":retained,
      "forks":forks,
      "reconciliation":"NO_WINNER_SELECTED",
      "independent_witnesses":0,
      "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
    manifest["manifest_sha256"]=digest(manifest)
    receipt=receipt if type(receipt) is dict else {}
    if receipt:
        if receipt.get("manifest_sha256")!=manifest["manifest_sha256"]:
            issues.append("CUSTODY_ACK_MANIFEST_CONFLICT")
        if receipt.get("custodian_root") in (None,"","github","GitHub"):
            issues.append("CUSTODY_ACK_ROOT_INVALID")
        if receipt.get("recovery_authorized") is not False or receipt.get("lock_cleared") is not False:
            issues.append("CUSTODY_ACK_UNSAFE_AUTHORITY")
    issues.extend(["EXTERNAL_CUSTODY_ACK_UNAUTHENTICATED",
                   "EXTERNAL_TIMESTAMP_UNVERIFIED","EXTERNAL_ANTI_ROLLBACK_UNVERIFIED"])
    verdict={"schema":"sapphon-226-custody-transfer-verdict-v1",
        "state":"PORTABLE_FORK_EVIDENCE_READY_HOLD" if set(issues)=={
            "EXTERNAL_CUSTODY_ACK_UNAUTHENTICATED","EXTERNAL_TIMESTAMP_UNVERIFIED",
            "EXTERNAL_ANTI_ROLLBACK_UNVERIFIED"} else "FORK_TRANSFER_REJECTED_HOLD",
        "blockers":sorted(set(issues)),"manifest_sha256":manifest["manifest_sha256"],
        "independently_authenticated_witnesses":0,"recovery_authorized":False,
        "lock_cleared":False,"decision":"HOLD"}
    return manifest,verdict
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True);p.add_argument("--receipt")
    p.add_argument("--bundle-out",required=True);p.add_argument("--verdict-out",required=True)
    a=p.parse_args()
    def load(name):
        try:return json.loads(pathlib.Path(name).read_text()) if name else None
        except (OSError,ValueError):return None
    bundle,verdict=export(load(a.source),load(a.receipt))
    for path,obj in ((a.bundle_out,bundle),(a.verdict_out,verdict)):
        path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n")
    print(verdict["state"],",".join(verdict["blockers"]))
    return 0 if verdict["state"]=="PORTABLE_FORK_EVIDENCE_READY_HOLD" else 1
if __name__=="__main__":sys.exit(main())
