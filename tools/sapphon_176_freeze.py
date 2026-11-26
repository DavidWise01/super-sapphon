#!/usr/bin/env python3
"""SAPPHON-176 Phase XVI source-design freeze, not runtime certification.

Real source files are hashed from the checked-out tree; independent execution
evidence is never fabricated. Writes a HOLD-only report and never edits lockfile.
"""
import argparse,hashlib,json,pathlib,re,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCES={
169:"rust/sapphon-liveness/src/runtime169.rs",
170:"rust/sapphon-liveness/src/isolate170.rs",
171:"rust/sapphon-liveness/src/joblog171.rs",
172:"rust/sapphon-liveness/src/reconcile172.rs",
173:"rust/sapphon-liveness/src/steps173.rs",
174:"rust/sapphon-liveness/src/outcomes174.rs",
175:"rust/sapphon-liveness/src/runner175.rs",
176:"rust/sapphon-liveness/src/freeze176.rs",
}
CHECKS=("PYTHON","RUST","FROZEN","PREDECESSOR","REVIEW","LOCK","PAGES")
SHA40=re.compile(r"^[0-9a-f]{40}$")
def digest(b):return hashlib.sha256(b).hexdigest()
def evaluate(head,records,files,lock):
    findings=[]
    if not SHA40.fullmatch(head):findings.append("BAD_HEAD")
    if set(files)!=set(SOURCES):findings.append("MISSING_BOUND")
    source=[]
    for bound,path in SOURCES.items():
        body=files.get(bound)
        if not isinstance(body,bytes) or not body:findings.append("MISSING_SOURCE:"+str(bound));continue
        source.append({"bound":bound,"path":path,"bytes":len(body),"sha256":digest(body),"ancestry":"github-owned-source"})
    for k in CHECKS:
        v=records.get(k)
        if v not in ("success","failure","skipped","cancelled","timed_out","not_observed"):
            findings.append("UNSUPPORTED_STATUS:"+k)
    source_pass=all(records.get(k)=="success" for k in ("PYTHON","RUST","FROZEN"))
    if any(records.get(k)=="not_observed" for k in CHECKS):findings.append("INCOMPLETE_RUN_READBACK")
    try:
        parsed=json.loads(lock)
        packages=parsed["packages"]
        integrity_present=all(packages.get("node_modules/"+name,{}).get("integrity","").startswith("sha512-")
          for name in ("playwright","playwright-core"))
    except (ValueError,KeyError,TypeError,AttributeError):
        integrity_present=False
        findings.append("COMMITTED_LOCK_INVALID_JSON")
    if not integrity_present:findings.append("COMMITTED_NPM_LOCK_INTEGRITY_MISSING")
    return {"schema":"sapphon-176-phase-xvi-source-freeze-v1",
        "phase":16,"design_bounds":8,"design_percent":100,
        "source_head":head,"sources":source,
        "source_ancestry_roots":1,"source_tests_recorded_pass":source_pass,
        "recorded_outcomes":{k:records.get(k,"not_observed") for k in CHECKS},
        "committed_lock_sha256":digest(lock),"committed_lock_integrity_present":integrity_present,
        "findings":sorted(set(findings)),
        "phase_design_complete":len(source)==8 and "BAD_HEAD" not in findings,
        "ci_success_independently_verified":False,
        "npm_lock_qualified":False,"pages_verified":False,
        "independent_external_custody":False,"global_anti_rollback_authenticated":False,
        "authenticated_utc":False,"key_rotation_authorized":False,
        "recovery_authorized":False,"lock_cleared":False,
        "decision":"PHASE_XVI_DESIGN_COMPLETE_QUALIFICATION_HOLD"}
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--head",required=True)
    ap.add_argument("--out",default="qualification-artifact/176-freeze.json")
    ap.add_argument("--outcomes",help="optional exact-run outcomes; missing means not_observed")
    ap.add_argument("--root",default=str(ROOT))
    args=ap.parse_args();base=pathlib.Path(args.root)
    entries={bound:(base/path).read_bytes() for bound,path in SOURCES.items()}
    lock=(base/"package-lock.json").read_bytes()
    records={k:"not_observed" for k in CHECKS}
    if args.outcomes:
        supplied=json.loads(pathlib.Path(args.outcomes).read_text())
        records.update(supplied["outcomes"])
    result=evaluate(args.head,records,entries,lock)
    path=pathlib.Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["decision"],"bounds",len(result["sources"]),"findings",result["findings"])
    if not result["phase_design_complete"]:sys.exit(1)
if __name__=="__main__":main()
