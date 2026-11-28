#!/usr/bin/env python3
"""SAPPHON-208 final Phase XX source freeze and original 207 artifact readback.

Never promote an authored fixture, a missing artifact or a local Docker image
to verified external custody. All acquired artifacts share GitHub ancestry.
"""
import argparse,hashlib,importlib.util,io,json,pathlib,re,stat,subprocess,sys,zipfile
P=pathlib.Path(__file__).resolve().parent
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,P/file)
 mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
api=load("a194_208","sapphon_194_acquire.py")
vendor=load("vendor207_208","sapphon_207_vendor.py")
SOURCE="aea6cb530ed4b23445a489e23099c63b6049854e"
WORKFLOW="sapphon-207-vendor.yml"
ARTIFACT="sapphon-207-vendor-and-local-image"
MODULES={n:f"rust/sapphon-liveness/src/{name}.rs" for n,name in [
 (201,"runner201"),(202,"replay202"),(203,"sandbox203"),(204,"offline204"),
 (205,"lock205"),(206,"import206"),(207,"vendor207"),(208,"freeze208")]}
REQUIRED={"207-Cargo.lock","207-vendor.tar","207-vendor.json","207-summary.json"}
IMAGE_FILES={"207-image.tar","207-image-report.json","207-image.sha256"}
MAX_ARCHIVE=768*1024*1024
def sha(b):return hashlib.sha256(b).hexdigest()
def hold(state,**values):
 return {"schema":"sapphon-208-final-phase-xx-v1","state":state,
 "pinned_207_source":SOURCE,"phase":20,"source_bound_count":8,
 "source_design_complete":False,"source_inventory":[],
 "source_inventory_sha256":None,"original_207_run_observed":False,
 "vendor_archive_verified":False,"image_archive_verified":False,
 "external_witnesses":0,"authenticated_utc":False,
 "global_anti_rollback_authenticated":False,"recovery_authorized":False,
 "lock_cleared":False,"decision":"PHASE_XX_FINAL_FREEZE_HOLD",**values}
def freeze_sources(root):
 root=pathlib.Path(root)
 rows=[]
 for n,path in MODULES.items():
  file=root/path
  if not file.is_file():return hold("SOURCE_MODULE_NOT_FOUND",missing_bound=n)
  b=file.read_bytes()
  if not b or len(b)>8*1024*1024:return hold("SOURCE_MODULE_BYTES_INVALID",bound=n)
  rows.append({"bound":n,"path":path,"bytes":len(b),"sha256":sha(b)})
 encoded=vendor.canonical(rows)
 return hold("EIGHT_SOURCE_MODULES_INVENTORIED",source_design_complete=True,
   source_inventory=rows,source_inventory_sha256=sha(encoded))
def inspect_artifact(raw,run):
 if type(raw) is not bytes or not raw or len(raw)>MAX_ARCHIVE:
  return hold("ORIGINAL_ZIP_UNAVAILABLE_OR_OVERSIZE")
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as zipf:
   members=zipf.infolist();names=[v.filename for v in members]
   if len(names)!=len(set(names)) or any(
    not f.filename or f.is_dir() or f.flag_bits&1 or "/" in f.filename or
    "\\" in f.filename or stat.S_ISLNK(f.external_attr>>16) or
    f.file_size>MAX_ARCHIVE for f in members):
    return hold("UNSAFE_OR_DUPLICATE_ARTIFACT")
   if not REQUIRED.issubset(set(names)):
    return hold("ORIGINAL_REQUIRED_VENDOR_FILES_MISSING",missing_files=sorted(REQUIRED-set(names)))
   present=set(names)&IMAGE_FILES
   if present and present!=IMAGE_FILES:return hold("PARTIAL_IMAGE_ARCHIVE")
   report=json.loads(zipf.read("207-vendor.json"))
   summary=json.loads(zipf.read("207-summary.json"))
   lock=zipf.read("207-Cargo.lock")
   archive=zipf.read("207-vendor.tar")
   image_report=json.loads(zipf.read("207-image-report.json")) if present else None
   image=zipf.read("207-image.tar") if present else None
   image_receipt=zipf.read("207-image.sha256").decode("utf-8") if present else None
 except (zipfile.BadZipFile,KeyError,ValueError,UnicodeError,OverflowError,RuntimeError,MemoryError):
  return hold("ARCHIVE_CORRUPT")
 if type(summary) is not dict or summary.get("schema")!="sapphon-207-source-owned-run-v1":
  return hold("ORIGINAL_SUMMARY_INVALID")
 if (summary.get("commit")!=SOURCE or str(summary.get("run_id"))!=str(run.get("id"))
  or str(summary.get("attempt"))!=str(run.get("run_attempt"))
  or summary.get("recovery_authorized") is not False):
  return hold("ORIGINAL_RUN_ATTEMPT_CONFLICT")
 if (summary.get("steps",{}).get("VENDOR")!="success" or
  summary.get("offline_check_observed") is not True):
  return hold("OFFLINE_VENDOR_EXECUTION_NOT_OBSERVED")
 if sha(lock)!=report.get("lock_sha256"):return hold("LOCKFILE_BYTES_CONFLICT")
 if report.get("tree_sha256")!=summary.get("vendor_tree_sha256") or report.get("archive_sha256")!=summary.get("vendor_archive_sha256"):
  return hold("REPORT_SUMMARY_CONFLICT")
 verified=vendor.verify_archive(archive,report)
 if verified.get("state")!="ORIGINAL_VENDOR_ARCHIVE_MATCH":
  return hold("VENDOR_ARCHIVE_"+verified.get("state","INVALID"))
 result=hold("ORIGINAL_GITHUB_VENDOR_BYTES_VERIFIED",
   original_207_run_observed=True,vendor_archive_verified=True,
   run_id=run["id"],attempt=run["run_attempt"],
   zip_sha256=sha(raw),lockfile_sha256=sha(lock),
   vendor_tar_sha256=sha(archive),vendor_tree_sha256=report["tree_sha256"],
   vendor_files=verified["files"])
 if present:
  if (type(image_report) is not dict or image_report.get("schema")!="sapphon-207-local-image-v1"
   or image_report.get("recovery_authorized") is not False or
   image_report.get("archive_sha256")!=sha(image) or
   summary.get("built_image_archive_sha256")!=sha(image) or
   summary.get("built_image_local_id")!=image_report.get("built_image_local_id") or
   summary.get("steps",{}).get("IMAGE")!="success"):
   return {**result,"state":"ORIGINAL_IMAGE_EVIDENCE_CONFLICT"}
  receipt=image_receipt.split()
  if not receipt or receipt[0]!=sha(image):
   return {**result,"state":"ORIGINAL_IMAGE_RECEIPT_CONFLICT"}
  result.update({"state":"ORIGINAL_GITHUB_VENDOR_AND_LOCAL_IMAGE_BYTES_VERIFIED",
    "image_archive_verified":True,"image_tar_sha256":sha(image),
    "image_local_id":image_report.get("built_image_local_id")})
 elif summary.get("steps",{}).get("IMAGE")=="success":
  return {**result,"state":"MISSING_ORIGINAL_IMAGE_FOR_SUCCESS_CLAIM"}
 return result
def acquire(fetch=api.json_api,download=api.api):
 base=f"repos/{api.REPO}/actions"
 rows,state,_=api.listing(f"{base}/workflows/{WORKFLOW}/runs","workflow_runs",fetch)
 if state!="EXHAUSTED":return hold("RUN_LIST_"+state)
 found=[r for r in rows if r.get("head_sha")==SOURCE]
 if not found:return hold("ORIGINAL_207_RUN_NOT_OBSERVED")
 if any(not api.positive(r.get("run_attempt")) for r in found):
  return hold("RUN_ATTEMPT_INVALID")
 run=max(found,key=lambda r:(r["id"],r["run_attempt"]))
 artifacts,state,_=api.listing(f"{base}/runs/{run['id']}/artifacts","artifacts",fetch)
 if state!="EXHAUSTED":return hold("ARTIFACT_LIST_"+state)
 found=[x for x in artifacts if x.get("name")==ARTIFACT]
 if len(found)!=1:return hold("ORIGINAL_ARTIFACT_NOT_UNIQUE_OR_MISSING")
 art=found[0]
 if art.get("expired") is not False:return hold("ARTIFACT_EXPIRED_OR_UNKNOWN")
 link=art.get("workflow_run") or {}
 if link and (link.get("id")!=run["id"] or link.get("head_sha")!=SOURCE):
  return hold("ARTIFACT_SOURCE_ANCESTRY_CONFLICT")
 try:raw=download(f"{base}/artifacts/{art['id']}/zip")
 except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired):
  return hold("ORIGINAL_ZIP_DOWNLOAD_UNAVAILABLE")
 return inspect_artifact(raw,run)
def main():
 parser=argparse.ArgumentParser()
 parser.add_argument("--root",default=str(P.parent))
 parser.add_argument("--out",default="qualification-artifact/208-final.json")
 args=parser.parse_args()
 frozen=freeze_sources(args.root)
 try:old=acquire()
 except (OSError,TypeError,ValueError,KeyError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
  old=hold("ACQUISITION_UNAVAILABLE",error_type=type(exc).__name__)
 report={**frozen,"original_207_evidence_state":old["state"],
  "original_207_run_observed":old["original_207_run_observed"],
  "vendor_archive_verified":old["vendor_archive_verified"],
  "image_archive_verified":old["image_archive_verified"],
  "original_207_zip_sha256":old.get("zip_sha256"),
  "original_vendor_tree_sha256":old.get("vendor_tree_sha256"),
  "original_image_tar_sha256":old.get("image_tar_sha256"),
  "state":"PHASE_XX_SOURCE_FREEZE_WITH_"+old["state"] if frozen["source_design_complete"] else frozen["state"]}
 out=pathlib.Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
 out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(report["state"])
 if not frozen["source_design_complete"]:sys.exit(1)
if __name__=="__main__":main()
