#!/usr/bin/env python3
"""SAPPHON-182: read-only, fail-closed cross-file provenance of original ZIP bytes.

Accept no archive extraction or executable content. Archive consistency is
owned-source evidence only: never independent custody or recovery authority.
"""
import argparse,hashlib,io,json,pathlib,re,stat,sys,zipfile
SOURCE="dd1d778c522aa18fb399c052958f05c4f5b02dd9"
PREDECESSOR="d07203a254678fdf7df05a75c1d144c7a8337f87"
WORKFLOW="sapphon-180-binding.yml"
JOB="artifact-binding"
ARTIFACT="sapphon-180-byte-binding"
FILES=("180-summary.json","180-binding.json","180-predecessor.json")
MAX_ARCHIVE=64*1024*1024
MAX_ITEM=2*1024*1024
MAX_TOTAL=12*1024*1024
MAX_ENTRIES=48
HEX64=re.compile(r"^[0-9a-f]{64}$")
def sha(b):return hashlib.sha256(b).hexdigest()
def integer(v):return type(v) is int and v>0
def verify(zipbytes,manifest):
 issues=[];records={};entries=[];total=0
 if type(manifest) is not dict:raise ValueError("MANIFEST_NOT_OBJECT")
 for key,expected in (("source_sha",SOURCE),("workflow",WORKFLOW),
                      ("job_name",JOB),("artifact_name",ARTIFACT)):
  if manifest.get(key)!=expected:issues.append("MANIFEST_"+key.upper())
 for key in ("run_id","attempt","job_id","artifact_id"):
  if not integer(manifest.get(key)):issues.append("INVALID_"+key.upper())
 if manifest.get("artifact_expired") is not False:issues.append("ARTIFACT_EXPIRED_OR_UNKNOWN")
 if manifest.get("recovery_authorized") is not False:issues.append("MANIFEST_AUTHORITY")
 if not isinstance(zipbytes,bytes) or not zipbytes or len(zipbytes)>MAX_ARCHIVE:
  issues.append("ARCHIVE_MISSING_OR_OVERSIZE")
 digest=sha(zipbytes) if isinstance(zipbytes,bytes) else None
 if not isinstance(manifest.get("artifact_sha256"),str) or not HEX64.fullmatch(manifest["artifact_sha256"]) or manifest["artifact_sha256"]!=digest:
  issues.append("ARTIFACT_DIGEST_MISMATCH")
 if "ARCHIVE_MISSING_OR_OVERSIZE" not in issues:
  try:
   with zipfile.ZipFile(io.BytesIO(zipbytes)) as z:
    infos=z.infolist()
    if not (1<=len(infos)<=MAX_ENTRIES):issues.append("ENTRY_COUNT")
    names=set()
    for item in infos:
     name=item.filename;parts=name.replace("\\","/").split("/")
     if (not name or name.startswith(("/","\\")) or "\\" in name
         or re.match(r"^[A-Za-z]:",name)
         or any(part in ("",".","..") for part in parts) or item.is_dir()):
      issues.append("UNSAFE_ARCHIVE_PATH");continue
     if name in names:issues.append("DUPLICATE_ARCHIVE_PATH")
     names.add(name)
     if stat.S_ISLNK(item.external_attr>>16):issues.append("SYMLINK_ENTRY")
     if item.flag_bits&1:issues.append("ENCRYPTED_ENTRY")
     if item.file_size>MAX_ITEM or item.compress_size>MAX_ARCHIVE:issues.append("ITEM_LIMIT")
     total+=item.file_size
     if total>MAX_TOTAL:issues.append("EXPANSION_LIMIT")
     entries.append({"name":name,"size":item.file_size,"crc32":f"{item.CRC:08x}"})
    if set(names)!=set(FILES):issues.append("REQUIRED_FILE_SET_MISMATCH")
    if not issues:
     for name in FILES:
      payload=z.read(name)
      if len(payload)>MAX_ITEM:issues.append("ITEM_LIMIT");break
      obj=json.loads(payload)
      if type(obj) is not dict:issues.append("NONOBJECT:"+name)
      else:records[name]=obj
  except (zipfile.BadZipFile,RuntimeError,ValueError,KeyError,UnicodeError,OverflowError,MemoryError) as ex:
   issues.append("ARCHIVE_DECODE:"+type(ex).__name__)
 if len(records)==len(FILES):
  summary,binding,preced=(records[x] for x in FILES)
  if summary.get("schema")!="sapphon-180-owned-source-evidence-v1":issues.append("SUMMARY_SCHEMA")
  if summary.get("commit")!=SOURCE or str(summary.get("run_id"))!=str(manifest.get("run_id")) or str(summary.get("attempt"))!=str(manifest.get("attempt")):
   issues.append("SUMMARY_IDENTITY_CONFLICT")
  if summary.get("recovery_authorized") is not False or summary.get("lock_cleared") is not False or summary.get("full_qualification") is not False:
   issues.append("SUMMARY_AUTHORITY_CONFLICT")
  if summary.get("source_owned_diagnostics_pass") is True:
   steps=summary.get("steps") or {}
   if any(steps.get(s)!="success" for s in ("PYTHON","RUST","FROZEN")):
    issues.append("SUMMARY_FALSE_PASS")
  schema=binding.get("schema")
  if schema=="sapphon-180-artifact-binding-v1":
   if binding.get("source_sha")!=PREDECESSOR or binding.get("workflow")!="sapphon-179-replay.yml":
    issues.append("BINDING_ANCESTRY_CONFLICT")
   if binding.get("recovery_authorized") is not False or binding.get("lock_cleared") is not False:
    issues.append("BINDING_AUTHORITY_CONFLICT")
   if binding.get("source_owned_binding_consistent") is True and binding.get("findings"):
    issues.append("BINDING_FALSE_PASS")
  elif schema=="sapphon-180-evidence-unavailable-v1":
   if binding.get("status")!="ORIGINAL_BYTES_NOT_SUPPLIED" or binding.get("binding_qualified") is not False:
    issues.append("BINDING_UNAVAILABILITY_CONFLICT")
  else:issues.append("BINDING_SCHEMA")
  if preced.get("schema")!="sapphon-171-job-log-triage-v1" or preced.get("expected_sha")!=PREDECESSOR or preced.get("workflow")!="sapphon-179-replay.yml":
   issues.append("PREDECESSOR_ANCESTRY_CONFLICT")
  if preced.get("recovery_authorized") is not False or preced.get("independent_custody_authenticated") is not False:
   issues.append("PREDECESSOR_AUTHORITY_CONFLICT")
  observed=preced.get("observed") or {}
  if preced.get("status")=="EXACT_RUN_OBSERVED":
   if observed.get("head_sha")!=PREDECESSOR or not integer(observed.get("run_id")) or not integer(observed.get("attempt")):
    issues.append("PREDECESSOR_RUN_CONFLICT")
  elif preced.get("status") not in ("READBACK_UNAVAILABLE","NO_MATCHING_RUN_IN_EXHAUSTED_PAGES",
    "RUN_SEARCH_INCOMPLETE_PAGE_CAP","LATEST_INCOMPLETE","REQUIRED_JOB_MISSING"):
   issues.append("PREDECESSOR_UNSUPPORTED_STATUS")
 missing_evidence=(binding.get("schema")=="sapphon-180-evidence-unavailable-v1"
   or preced.get("status")!="EXACT_RUN_OBSERVED")
 else:missing_evidence=True
 return {"schema":"sapphon-182-cross-file-v1","source_sha":SOURCE,
   "artifact_sha256":digest,"entries":entries,
   "record_sha256":{n:sha(json.dumps(records[n],sort_keys=True,separators=(",",":")).encode()) for n in records},
   "findings":sorted(set(issues)),
   "archive_records_structurally_consistent":not issues,
   "complete_predecessor_and_raw_byte_evidence":not issues and not missing_evidence,
   "disk_extraction_performed":False,"archive_code_executed":False,
   "independent_custody_authenticated":False,"global_anti_rollback_authenticated":False,
   "recovery_authorized":False,"lock_cleared":False,
   "decision":"CROSS_FILE_PROVENANCE_HOLD"}
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--zip",required=True);p.add_argument("--manifest",required=True)
 p.add_argument("--out",default="qualification-artifact/182-crossfile.json")
 a=p.parse_args();result=verify(pathlib.Path(a.zip).read_bytes(),json.loads(pathlib.Path(a.manifest).read_text()))
 dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["decision"],result["findings"],"complete",result["complete_predecessor_and_raw_byte_evidence"])
 if result["findings"]:sys.exit(1)
if __name__=="__main__":main()
