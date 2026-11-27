#!/usr/bin/env python3
"""SAPPHON-188: import a real prior GitHub-owned ledger and bind one new transition.

Original ZIP is read in-memory, never extracted. A missing prior ledger, a
broken hash chain, and a substituted source/attempt are distinct outcomes.
GitHub custody is owned-source, not an external trusted clock or witness.
"""
import argparse,hashlib,importlib.util,io,json,pathlib,stat,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("retention187",ROOT/"sapphon_187_ledger.py")
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
SOURCE="f404ed9e4c60558d82116cf86348304f17daed81"
WORKFLOW="sapphon-187-retention.yml"
ARTIFACT="sapphon-187-retention-evidence"
REPO="DavidWise01/super-sapphon"
MAX_ZIP=64*1024*1024
MAX_ITEM=2*1024*1024
MEMBERS={"187-observation.json","187-adjudication.json","187-summary.json"}
def hashbytes(v):return hashlib.sha256(v).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def positive(x):return type(x) is int and x>0
def gh(path):
 return subprocess.run(["gh","api",path],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       check=True,timeout=45).stdout
def paged(path,key,fetch):
 allrows=[];seen=set()
 for page in range(1,11):
  data=fetch(path+("&" if "?" in path else "?")+f"per_page=100&page={page}")
  rows=data.get(key) if type(data) is dict else None
  if type(rows) is not list or len(rows)>100 or any(type(r) is not dict for r in rows):
   return [],"MALFORMED_PAGE"
  for r in rows:
   if not positive(r.get("id")) or r["id"] in seen:return [],"DUPLICATE_OR_INVALID_ID"
   seen.add(r["id"])
  allrows.extend(rows)
  if len(rows)<100:return allrows,"EXHAUSTED"
 return [],"PAGE_CAP"
def inspect(raw,run,artifact):
 if not isinstance(raw,bytes) or not raw or len(raw)>MAX_ZIP:
  return {"status":"ZIP_BYTES_MISSING_OR_OVERSIZE"}
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   infos=z.infolist()
   names=[i.filename for i in infos]
   if len(names)!=len(set(names)):return {"status":"DUPLICATE_ZIP_MEMBER"}
   if set(names) not in (MEMBERS,MEMBERS|{"187-evidence-ledger.jsonl"}):
    return {"status":"ZIP_MEMBER_SET_MISMATCH"}
   if any(i.is_dir() or i.flag_bits&1 or i.file_size>MAX_ITEM or
          stat.S_ISLNK(i.external_attr>>16) or i.filename.startswith(("/","\\"))
          or ".." in i.filename.split("/") or "\\" in i.filename for i in infos):
    return {"status":"UNSAFE_ZIP_MEMBER"}
   docs={name:json.loads(z.read(name)) for name in MEMBERS}
   ledger_bytes=z.read("187-evidence-ledger.jsonl") if "187-evidence-ledger.jsonl" in names else None
 except (zipfile.BadZipFile,ValueError,KeyError,RuntimeError,UnicodeError,OverflowError) as e:
  return {"status":"ZIP_DECODE_"+type(e).__name__}
 summary=docs["187-summary.json"]
 if (type(summary) is not dict or summary.get("schema")!="sapphon-187-owned-run-v1"
     or summary.get("commit")!=SOURCE or str(summary.get("run_id"))!=str(run["id"])
     or str(summary.get("attempt"))!=str(run["run_attempt"])):
  return {"status":"PREDECESSOR_ANCESTRY_OR_ATTEMPT_MISMATCH"}
 if summary.get("recovery_authorized") is not False or summary.get("cross_run_continuity_verified") is not False:
  return {"status":"UNAUTHORIZED_PREDECESSOR_CLAIM"}
 if ledger_bytes is None or not ledger_bytes.strip():
  return {"status":"PREDECESSOR_LEDGER_NOT_PRESENT"}
 if len(ledger_bytes)>MAX_ITEM:return {"status":"LEDGER_BYTES_OVERSIZE"}
 try:
  records=[json.loads(line) for line in ledger_bytes.splitlines() if line.strip()]
  validation=legacy.chain(records)
 except (ValueError,TypeError,KeyError,UnicodeError) as e:
  return {"status":"PREDECESSOR_CHAIN_INVALID","error_type":type(e).__name__}
 if not validation["source_owned_ledger_consistent"]:
  return {"status":"PREDECESSOR_EQUIVOCATION","prior_tip":validation["tip_sha256"]}
 adjudication=docs["187-adjudication.json"]
 if (type(adjudication) is not dict or
     adjudication.get("schema")!="sapphon-187-ledger-envelope-v1" and
     adjudication.get("decision")!="CROSS_ATTEMPT_RETENTION_HOLD"):
  return {"status":"PREDECESSOR_ADJUDICATION_INVALID"}
 if adjudication.get("tip_sha256")!=validation["tip_sha256"] or adjudication.get("entries")!=len(records):
  return {"status":"PREDECESSOR_TIP_OR_COUNT_MISMATCH"}
 transition={"schema":"sapphon-188-import-transition-v1",
  "prior_source_sha":SOURCE,"prior_workflow":WORKFLOW,
  "prior_run_id":run["id"],"prior_attempt":run["run_attempt"],
  "prior_artifact_id":artifact["id"],"prior_artifact_sha256":hashbytes(raw),
  "prior_ledger_bytes_sha256":hashbytes(ledger_bytes),
  "prior_ledger_tip_sha256":validation["tip_sha256"],
  "prior_ledger_entries":len(records),
  "new_observation_type":"OWNED_PREDECESSOR_IMPORT",
  "independent_custody_authenticated":False,"recovery_authorized":False}
 return {"status":"IMPORTED_OWNED_SOURCE_CHAIN","transition":transition,
  "transition_sha256":hashbytes(canonical(transition)),
  "prior_records":len(records),"prior_tip_sha256":validation["tip_sha256"]}
def acquire(fetch=None,download=None):
 if fetch is None:fetch=lambda p:json.loads(gh(p))
 if download is None:download=gh
 base=f"repos/{REPO}/actions"
 runs,state=paged(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return {"status":"RUN_LISTING_"+state}
 candidates=[r for r in runs if r.get("head_sha")==SOURCE]
 if not candidates:return {"status":"EXACT_PREDECESSOR_RUN_NOT_FOUND"}
 if any(not positive(r.get("run_attempt")) for r in candidates):
  return {"status":"MALFORMED_PREDECESSOR_ATTEMPT"}
 run=max(candidates,key=lambda r:(r["id"],r["run_attempt"]))
 if run.get("status")!="completed":return {"status":"PREDECESSOR_RUN_INCOMPLETE"}
 arts,state=paged(f"{base}/runs/{run['id']}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return {"status":"ARTIFACT_LISTING_"+state}
 found=[a for a in arts if a.get("name")==ARTIFACT]
 if len(found)!=1:return {"status":"PRIOR_ARTIFACT_MISSING_OR_AMBIGUOUS"}
 art=found[0]
 if art.get("expired") is True:return {"status":"PRIOR_ARTIFACT_EXPIRED"}
 if art.get("expired") is not False:return {"status":"PRIOR_EXPIRY_UNKNOWN"}
 metadata=art.get("workflow_run") or {}
 if metadata and (metadata.get("id")!=run["id"] or metadata.get("head_sha")!=SOURCE):
  return {"status":"ARTIFACT_SOURCE_CONFLICT"}
 try:raw=download(f"{base}/artifacts/{art['id']}/zip")
 except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError):
  return {"status":"ORIGINAL_ZIP_DOWNLOAD_UNAVAILABLE"}
 return inspect(raw,run,art)
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--out",default="qualification-artifact/188-import.json")
 p.add_argument("--transition",default="qualification-artifact/188-transition.json")
 a=p.parse_args()
 try:result=acquire()
 except (ValueError,KeyError,TypeError,OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  result={"status":"READBACK_UNAVAILABLE","error_type":type(e).__name__}
 report={k:v for k,v in result.items() if k!="transition"}
 report.update({"schema":"sapphon-188-import-result-v1",
  "cross_run_source_continuity_observed":result.get("status")=="IMPORTED_OWNED_SOURCE_CHAIN",
  "independent_custody_authenticated":False,"global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"CROSS_RUN_IMPORT_HOLD"})
 dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
 if "transition" in result:
  transition_path=pathlib.Path(a.transition);transition_path.parent.mkdir(parents=True,exist_ok=True)
  with transition_path.open("x") as f:
   json.dump(result["transition"],f,sort_keys=True,indent=2);f.write("\n")
 print(report["status"])
 if report["status"]!="IMPORTED_OWNED_SOURCE_CHAIN":sys.exit(1)
if __name__=="__main__":main()
