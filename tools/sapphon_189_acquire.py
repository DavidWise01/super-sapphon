#!/usr/bin/env python3
"""SAPPHON-189: read a genuine SAPPHON-188 workflow artifact as one GitHub ancestry.

Never manufacture an independent witness. Root disagreements within one ZIP
are contradictions, not corroboration. No extraction or actuation.
"""
import argparse,hashlib,io,json,pathlib,stat,subprocess,sys,zipfile
SOURCE="011ad7d5623d7d5db8ec2183bcf7207a0e8ec42c"
WORKFLOW="sapphon-188-import.yml"
ARTIFACT="sapphon-188-ancestry-continuity"
REPO="DavidWise01/super-sapphon"
def gh(path):
 return subprocess.run(["gh","api",path],check=True,timeout=45,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
def api(path):return json.loads(gh(path))
def positive(x):return type(x) is int and x>0
def pages(path,key,get):
 result=[];ids=set()
 for page in range(1,11):
  r=get(path+("&" if "?" in path else "?")+f"per_page=100&page={page}")
  rows=r.get(key) if type(r) is dict else None
  if type(rows) is not list or len(rows)>100 or any(type(x) is not dict for x in rows):
   return [],"MALFORMED_PAGE"
  for item in rows:
   if not positive(item.get("id")) or item["id"] in ids:return [],"DUPLICATE_OR_INVALID_ID"
   ids.add(item["id"])
  result.extend(rows)
  if len(rows)<100:return result,"EXHAUSTED"
 return [],"PAGE_CAP"
def inspect(raw,run,artifact):
 if not isinstance(raw,bytes) or not raw or len(raw)>64*1024*1024:return {"status":"ZIP_MISSING_OR_OVERSIZE"}
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   infos=z.infolist();names=[i.filename for i in infos]
   allowed={"188-import.json","188-summary.json"}
   if set(names) not in (allowed,allowed|{"188-transition.json"}) or len(names)!=len(set(names)):
    return {"status":"UNEXPECTED_ZIP_FILES"}
   if any(i.is_dir() or i.flag_bits&1 or i.file_size>2*1024*1024 or
     stat.S_ISLNK(i.external_attr>>16) or i.filename.startswith(("/","\\"))
     or ".." in i.filename.split("/") or "\\" in i.filename for i in infos):
    return {"status":"UNSAFE_ZIP_MEMBER"}
   d={n:json.loads(z.read(n)) for n in names}
 except (ValueError,KeyError,RuntimeError,UnicodeError,zipfile.BadZipFile):
  return {"status":"ZIP_READBACK_CORRUPT"}
 summary=d["188-summary.json"];imp=d["188-import.json"];transition=d.get("188-transition.json")
 if type(summary) is not dict or summary.get("schema")!="sapphon-188-owned-outcomes-v1" or summary.get("commit")!=SOURCE:
  return {"status":"RUN_SOURCE_CONFLICT"}
 if str(summary.get("run_id"))!=str(run["id"]) or str(summary.get("attempt"))!=str(run["run_attempt"]):
  return {"status":"ATTEMPT_SUBSTITUTION"}
 if summary.get("recovery_authorized") is not False or summary.get("external_custody_authenticated") is not False:
  return {"status":"FORGED_SUMMARY_AUTHORITY"}
 if type(imp) is not dict or imp.get("schema")!="sapphon-188-import-result-v1":
  return {"status":"IMPORT_SCHEMA_CONFLICT"}
 if imp.get("status")!="IMPORTED_OWNED_SOURCE_CHAIN":
  return {"status":"PREDECESSOR_IMPORT_NOT_OBSERVED","claims":[]}
 if type(transition) is not dict or transition.get("schema")!="sapphon-188-import-transition-v1":
  return {"status":"MISSING_TRANSITION"}
 root=transition.get("prior_ledger_tip_sha256")
 if imp.get("prior_tip_sha256")!=root or imp.get("prior_records")!=transition.get("prior_ledger_entries"):
  return {"status":"INTRA_ARTIFACT_ROOT_CONFLICT"}
 if not isinstance(root,str) or len(root)!=64 or any(c not in "0123456789abcdef" for c in root):
  return {"status":"MALFORMED_ROOT"}
 if transition.get("independent_custody_authenticated") is not False or transition.get("recovery_authorized") is not False:
  return {"status":"FORGED_TRANSITION_AUTHORITY"}
 claim={"schema":"sapphon-189-root-claim-v1","source_sha":SOURCE,"workflow":WORKFLOW,
  "artifact_name":ARTIFACT,"run_id":run["id"],"attempt":run["run_attempt"],
  "lineage_id":"sapphon-187-ledger","custodian":"github-owned",
  "surface":"github-actions","evidence_state":"OBSERVED","root_sha256":root,
  "artifact_sha256":hashlib.sha256(raw).hexdigest(),
  "independently_authenticated":False,"recovery_authorized":False}
 return {"status":"ONE_OWNED_ROOT_OBSERVED","claims":[claim],
   "artifact_id":artifact["id"],"original_zip_sha256":claim["artifact_sha256"]}
def acquire(get=api,download=gh):
 base=f"repos/{REPO}/actions"
 runs,state=pages(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",get)
 if state!="EXHAUSTED":return {"status":"RUN_LISTING_"+state,"claims":[]}
 matching=[r for r in runs if r.get("head_sha")==SOURCE]
 if not matching:return {"status":"EXACT_RUN_NOT_OBSERVED","claims":[]}
 if any(not positive(r.get("run_attempt")) for r in matching):
  return {"status":"INVALID_RUN_ATTEMPT","claims":[]}
 run=max(matching,key=lambda r:(r["id"],r["run_attempt"]))
 if run.get("status")!="completed":return {"status":"RUN_INCOMPLETE","claims":[]}
 arts,state=pages(f"{base}/runs/{run['id']}/artifacts","artifacts",get)
 if state!="EXHAUSTED":return {"status":"ARTIFACT_LISTING_"+state,"claims":[]}
 found=[a for a in arts if a.get("name")==ARTIFACT]
 if len(found)!=1:return {"status":"REQUIRED_ARTIFACT_NOT_UNIQUE","claims":[]}
 a=found[0]
 if a.get("expired") is True:return {"status":"ARTIFACT_EXPIRED","claims":[]}
 if a.get("expired") is not False:return {"status":"EXPIRY_NOT_OBSERVED","claims":[]}
 if a.get("workflow_run") and (a["workflow_run"].get("id")!=run["id"] or a["workflow_run"].get("head_sha")!=SOURCE):
  return {"status":"ARTIFACT_ANCESTRY_CONFLICT","claims":[]}
 try:raw=download(f"{base}/artifacts/{a['id']}/zip")
 except (subprocess.TimeoutExpired,subprocess.CalledProcessError,OSError):
  return {"status":"DOWNLOAD_UNAVAILABLE","claims":[]}
 result=inspect(raw,run,a)
 result.setdefault("claims",[])
 return result
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--out",default="qualification-artifact/189-acquisition.json")
 p.add_argument("--claims",default="qualification-artifact/189-claims.json")
 a=p.parse_args()
 try:r=acquire()
 except (OSError,ValueError,KeyError,TypeError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
  r={"status":"READBACK_UNAVAILABLE","error_type":type(e).__name__,"claims":[]}
 out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
 claims=r.pop("claims",[])
 pathlib.Path(a.claims).write_text(json.dumps(claims,sort_keys=True,indent=2)+"\n")
 r.update({"schema":"sapphon-189-acquisition-v1","observed_claims":len(claims),
   "independent_custody_authenticated":False,"recovery_authorized":False,"lock_cleared":False})
 out.write_text(json.dumps(r,sort_keys=True,indent=2)+"\n")
 print(r["status"])
 if r["status"]!="ONE_OWNED_ROOT_OBSERVED":sys.exit(1)
if __name__=="__main__":main()
