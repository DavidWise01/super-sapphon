#!/usr/bin/env python3
"""SAPPHON-187 read-only GitHub attempt observation; never infer deletion.

A missing run/artifact in a bounded listing is not a confirmed deletion.
Source-owned timestamps are metadata, not authenticated UTC.
"""
import argparse,importlib.util,json,pathlib,subprocess,sys
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("attempt186",HERE/"sapphon_186_attempts.py")
a186=importlib.util.module_from_spec(spec);spec.loader.exec_module(a186)
spec2=importlib.util.spec_from_file_location("ledger187",HERE/"sapphon_187_ledger.py")
l187=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(l187)
REPO=l187.SOURCE
def empty(run_id,attempt,state,artifact_id=None):
 return {"source_sha":l187.SOURCE,"workflow":l187.WORKFLOW,
 "run_id":run_id,"attempt":attempt,"state":state,"artifact_id":artifact_id,
 "artifact_name":l187.ARTIFACT,"original_zip_sha256":None,
 "embedded_run_id":None,"embedded_attempt":None,
 "external_custody_authenticated":False,"recovery_authorized":False}
def observe(call=a186.fetch,download=a186.api):
 base=f"repos/{a186.REPO}/actions"
 runs,run_status,_=a186.paginate(
  f"{base}/workflows/{l187.WORKFLOW}/runs","workflow_runs",call)
 if run_status!="EXHAUSTED":
  return {"status":"RUN_LISTING_"+run_status,"event":None}
 matches=[r for r in runs if r.get("head_sha")==l187.SOURCE]
 if not matches:
  return {"status":"NO_MATCHING_RUN_IN_EXHAUSTED_LISTING","event":None}
 if any(not a186.positive(r.get("id")) or not a186.positive(r.get("run_attempt")) for r in matches):
  return {"status":"MALFORMED_MATCHING_RUN","event":None}
 chosen=max(matches,key=lambda r:(r["id"],r["run_attempt"]))
 rid,attempt=chosen["id"],chosen["run_attempt"]
 arts,art_status,_=a186.paginate(f"{base}/runs/{rid}/artifacts","artifacts",call)
 if art_status!="EXHAUSTED":
  return {"status":"ARTIFACT_LISTING_"+art_status,
  "event":empty(rid,attempt,"LISTING_INCOMPLETE")}
 found=[a for a in arts if a.get("name")==l187.ARTIFACT]
 if not found:
  return {"status":"NOT_FOUND_IN_EXHAUSTED_LISTING",
  "event":empty(rid,attempt,"NOT_FOUND_IN_EXHAUSTED_LISTING")}
 if len(found)!=1 or not a186.positive(found[0].get("id")):
  return {"status":"AMBIGUOUS_ARTIFACT","event":None}
 item=found[0];aid=item["id"]
 if item.get("expired") is True:
  return {"status":"EXPIRED","event":empty(rid,attempt,"EXPIRED",aid)}
 if item.get("expired") is not False:
  return {"status":"EXPIRY_UNRESOLVED","event":empty(rid,attempt,"READBACK_UNAVAILABLE",aid)}
 try:
  raw=download(f"{base}/artifacts/{aid}/zip")
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError):
  return {"status":"DOWNLOAD_UNAVAILABLE","event":empty(rid,attempt,"READBACK_UNAVAILABLE",aid)}
 # Reuse in-memory ZIP safety checks; SAPPHON-186 expects a different file set.
 import hashlib,io,zipfile
 if not isinstance(raw,bytes) or not raw or len(raw)>a186.MAX_ZIP:
  return {"status":"ZIP_BYTES_UNAVAILABLE","event":empty(rid,attempt,"READBACK_UNAVAILABLE",aid)}
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   members=z.infolist()
   if len(members)!=2 or set(x.filename for x in members)!={"186-summary.json","186-attempts.json"}:
    return {"status":"ZIP_MEMBER_SET_INVALID","event":None}
   if any(x.file_size>2*1024*1024 or x.flag_bits&1 or x.is_dir() for x in members):
    return {"status":"ZIP_MEMBER_UNSAFE","event":None}
   summary=json.loads(z.read("186-summary.json"))
   attempt_report=json.loads(z.read("186-attempts.json"))
 except (zipfile.BadZipFile,ValueError,KeyError,RuntimeError,UnicodeError):
  return {"status":"ZIP_CORRUPT","event":None}
 if not isinstance(summary,dict) or summary.get("schema")!="sapphon-186-source-diagnostics-v1":
  return {"status":"SUMMARY_SCHEMA_MISMATCH","event":None}
 if summary.get("commit")!=l187.SOURCE or str(summary.get("run_id"))!=str(rid) or str(summary.get("attempt"))!=str(attempt):
  return {"status":"ZIP_ATTEMPT_MISMATCH","event":None}
 if summary.get("recovery_authorized") is not False or summary.get("lock_cleared") is not False:
  return {"status":"ZIP_UNSUPPORTED_AUTHORITY","event":None}
 if not isinstance(attempt_report,dict) or attempt_report.get("recovery_authorized") is not False:
  return {"status":"ZIP_ATTEMPT_REPORT_INVALID","event":None}
 row=empty(rid,attempt,"OBSERVED",aid)
 row.update(original_zip_sha256=hashlib.sha256(raw).hexdigest(),embedded_run_id=rid,embedded_attempt=attempt)
 return {"status":"SOURCE_OWNED_BYTES_OBSERVED","event":row}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--ledger",default="qualification-artifact/187-evidence-ledger.jsonl")
 p.add_argument("--out",default="qualification-artifact/187-observation.json")
 args=p.parse_args()
 try:result=observe()
 except (OSError,ValueError,KeyError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  result={"status":"READBACK_UNAVAILABLE","error_type":type(e).__name__,"event":None}
 out=pathlib.Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
 out.write_text(json.dumps({"schema":"sapphon-187-acquisition-v1",**result,
  "independent_custody_authenticated":False,"recovery_authorized":False},indent=2,sort_keys=True)+"\n")
 event=result.get("event")
 if event is not None:
  src=out.with_name("187-pending-event.json")
  src.write_text(json.dumps(event,sort_keys=True,indent=2)+"\n")
  from sapphon_187_ledger import main as _unused
  # The ledger CLI is invoked separately in CI, after acquisition.
 print(result["status"])
 if result["status"]!="SOURCE_OWNED_BYTES_OBSERVED":sys.exit(1)
if __name__=="__main__":main()
