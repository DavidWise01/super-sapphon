#!/usr/bin/env python3
"""SAPPHON-186: exact workflow run/attempt and exhaustive job/artifact pagination.

GitHub artifacts are run-scoped, not attempt-scoped. A ZIP must independently
contain a matching run_id+attempt; metadata alone cannot prove rerun ancestry.
No shell execution, archive extraction, or recovery authority.
"""
import argparse, hashlib, io, json, pathlib, re, stat, subprocess, sys, zipfile

REPO="DavidWise01/super-sapphon"
SOURCE="ae117baf57dd18ca3d4adade9700705faff9db1c"
WORKFLOW="sapphon-185-observed.yml"
JOB="observed-diagnostics"
ARTIFACT="sapphon-185-observed-run-diagnostics"
MEMBERS=("185-summary.json","185-predecessor.json","185-diagnostic.json")
PAGE_SIZE=100
PAGE_LIMIT=10
MAX_ZIP=64*1024*1024
MAX_MEMBER=2*1024*1024
HEX64=re.compile(r"^[a-f0-9]{64}$")

def sha(data):return hashlib.sha256(data).hexdigest()
def positive(x):return type(x) is int and x>0
def api(path):
    result=subprocess.run(["gh","api",path],stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,check=True,timeout=45)
    return result.stdout
def fetch(path):return json.loads(api(path))
def paginate(base,key,call=fetch,limit=PAGE_LIMIT):
    """Never certify a partial listing or silently accept malformed pages."""
    data=[]; seen=set()
    for page in range(1,limit+1):
        response=call(f"{base}{'&' if '?' in base else '?'}per_page={PAGE_SIZE}&page={page}")
        if type(response) is not dict or type(response.get(key)) is not list:
            return [],"MALFORMED_"+key.upper()+"_PAGE",page
        batch=response[key]
        if len(batch)>PAGE_SIZE or any(type(x) is not dict for x in batch):
            return [],"MALFORMED_"+key.upper()+"_PAGE",page
        for record in batch:
            rid=record.get("id")
            if not positive(rid) or rid in seen:
                return [],"INVALID_OR_DUPLICATE_"+key.upper()+"_ID",page
            seen.add(rid)
        data.extend(batch)
        if len(batch)<PAGE_SIZE:
            return data,"EXHAUSTED",page
    return [],"PAGE_LIMIT_REACHED",limit

def choose_run(rows):
    matches=[r for r in rows if r.get("head_sha")==SOURCE]
    if any(not positive(r.get("id")) or not positive(r.get("run_attempt")) for r in matches):
        return None,"MALFORMED_EXACT_RUN"
    matches.sort(key=lambda r:(r["id"],r["run_attempt"]),reverse=True)
    if not matches:return None,"EXACT_RUN_NOT_FOUND"
    chosen=matches[0]
    if chosen.get("status")!="completed":return None,"EXACT_RUN_INCOMPLETE"
    return chosen,"EXACT_RUN_SELECTED"

def inspect_zip(raw,run_id,attempt):
    errors=[];payload={}
    if not isinstance(raw,bytes) or not raw or len(raw)>MAX_ZIP:
        return None,["ZIP_MISSING_OR_OVERSIZE"]
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            members=z.infolist()
            if len(members)!=len(MEMBERS) or {m.filename for m in members}!=set(MEMBERS):
                return None,["ZIP_MEMBER_SET_MISMATCH"]
            if len({m.filename for m in members})!=len(members):
                return None,["DUPLICATE_ZIP_MEMBER"]
            for m in members:
                if (m.is_dir() or m.flag_bits&1 or m.file_size>MAX_MEMBER
                    or stat.S_ISLNK(m.external_attr>>16) or m.filename.startswith(("/","\\"))
                    or ".." in m.filename.split("/") or "\\" in m.filename):
                    errors.append("UNSAFE_ZIP_MEMBER")
            if errors:return None,errors
            for name in MEMBERS:
                obj=json.loads(z.read(name))
                if type(obj) is not dict:return None,["NONOBJECT_ZIP_MEMBER"]
                payload[name]=obj
    except (zipfile.BadZipFile,RuntimeError,ValueError,KeyError,UnicodeError,OverflowError) as exc:
        return None,["ZIP_DECODE_"+type(exc).__name__]
    summary=payload["185-summary.json"]
    if summary.get("schema")!="sapphon-185-current-run-v1" or summary.get("commit")!=SOURCE:
        errors.append("SUMMARY_SOURCE_MISMATCH")
    if str(summary.get("run_id"))!=str(run_id) or str(summary.get("attempt"))!=str(attempt):
        errors.append("ATTEMPT_IDENTITY_MISMATCH")
    if summary.get("recovery_authorized") is not False or summary.get("lock_cleared") is not False:
        errors.append("UNAUTHORIZED_SUMMARY")
    return payload,errors

def review(runs,jobs,artifacts,raw=None):
    errors=[];limits=[]
    run,state=choose_run(runs)
    if run is None:errors.append(state)
    run_id=run.get("id") if run else None
    attempt=run.get("run_attempt") if run else None
    job=None;artifact=None
    if run:
        choices=[j for j in jobs if j.get("name")==JOB]
        if len(choices)!=1:errors.append("REQUIRED_JOB_NOT_UNIQUE")
        else:
            job=choices[0]
            if not positive(job.get("id")):errors.append("INVALID_JOB_ID")
            if job.get("run_id") not in (None,run_id):errors.append("JOB_RUN_CONFLICT")
            if job.get("run_attempt") not in (None,attempt):errors.append("JOB_ATTEMPT_CONFLICT")
        choices=[a for a in artifacts if a.get("name")==ARTIFACT]
        if len(choices)!=1:errors.append("REQUIRED_ARTIFACT_NOT_UNIQUE")
        else:
            artifact=choices[0]
            if not positive(artifact.get("id")) or artifact.get("expired") is not False:
                errors.append("ARTIFACT_INVALID_OR_EXPIRED")
            attached=artifact.get("workflow_run") or {}
            if attached and (attached.get("id")!=run_id or attached.get("head_sha")!=SOURCE):
                errors.append("ARTIFACT_RUN_OR_SOURCE_CONFLICT")
    decoded=None
    if raw is None:limits.append("ORIGINAL_ARTIFACT_ZIP_UNAVAILABLE")
    elif run and not errors:
        decoded,ziperrors=inspect_zip(raw,run_id,attempt)
        errors.extend(ziperrors)
    else:limits.append("ZIP_NOT_EVALUATED_INVALID_METADATA")
    if decoded is not None and not errors:
        if decoded["185-summary.json"].get("source_owned_tests_pass") is not True:
            limits.append("SOURCE_TEST_PASS_NOT_RECORDED")
    return {"schema":"sapphon-186-attempt-artifact-v1",
      "source_sha":SOURCE,"workflow":WORKFLOW,"run_id":run_id,"attempt":attempt,
      "job_id":job.get("id") if job else None,
      "artifact_id":artifact.get("id") if artifact else None,
      "artifact_zip_sha256":sha(raw) if isinstance(raw,bytes) else None,
      "findings":sorted(set(errors)),"limitations":sorted(set(limits)),
      "source_owned_evidence_consistent":bool(decoded) and not errors and not limits,
      "original_bytes_present":raw is not None,
      "independent_custody_authenticated":False,
      "authenticated_utc":False,"global_anti_rollback_authenticated":False,
      "recovery_authorized":False,"lock_cleared":False,
      "decision":"EXHAUSTIVE_ATTEMPT_ARTIFACT_HOLD"}

def acquire(call=fetch,download=api):
    base=f"repos/{REPO}/actions"
    runs,rs,rp=paginate(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",call)
    if rs!="EXHAUSTED":return {"status":"RUN_"+rs,"pages_scanned":rp}
    run,state=choose_run(runs)
    if run is None:return {"status":state}
    rid,attempt=run["id"],run["run_attempt"]
    jobs,js,jp=paginate(f"{base}/runs/{rid}/attempts/{attempt}/jobs","jobs",call)
    arts,az,ap=paginate(f"{base}/runs/{rid}/artifacts","artifacts",call)
    if js!="EXHAUSTED" or az!="EXHAUSTED":
        return {"status":"INCOMPLETE_PAGINATION","job_search":js,"artifact_search":az,
                "job_pages":jp,"artifact_pages":ap}
    matches=[a for a in arts if a.get("name")==ARTIFACT]
    raw=None
    if len(matches)==1 and positive(matches[0].get("id")) and matches[0].get("expired") is False:
        try:raw=download(f"{base}/artifacts/{matches[0]['id']}/zip")
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError):
            pass
    result=review(runs,jobs,arts,raw)
    result["status"]="OBSERVED" if result["source_owned_evidence_consistent"] else "UNQUALIFIED"
    result["run_search"]="EXHAUSTED";result["job_search"]=js;result["artifact_search"]=az
    result["job_pages"]=jp;result["artifact_pages"]=ap
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument("--out",default="qualification-artifact/186-attempts.json")
    a=p.parse_args()
    try:result=acquire()
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired,ValueError,OSError,KeyError) as exc:
        result={"status":"READBACK_UNAVAILABLE","error_type":type(exc).__name__}
    result.update({"recovery_authorized":False,"lock_cleared":False,
                   "independent_custody_authenticated":False})
    out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result.get("status"),result.get("findings",[]),result.get("limitations",[]))
    if result.get("status")!="OBSERVED":sys.exit(1)
if __name__=="__main__":main()
