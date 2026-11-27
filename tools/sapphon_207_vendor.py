#!/usr/bin/env python3
"""SAPPHON-207: deterministic, byte-hashed cargo vendor archive.

Inventories an ACTUAL vendor directory. Unsafe symlinks, hidden files that
escape the root, duplicate paths, unbounded files and mutation are rejected.
The original bytes and artifact provenance stay GitHub-owned.
"""
import argparse,hashlib,io,json,os,pathlib,re,stat,sys,tarfile
MAX_FILES=20000
MAX_FILE_BYTES=32*1024*1024
MAX_TOTAL_BYTES=512*1024*1024
SHA=re.compile(r"^[0-9a-f]{64}$")
IMAGE=re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def hold(state,**kwargs):
 return {"schema":"sapphon-207-vendor-evidence-v1","state":state,
  "files":0,"tree_sha256":None,"archive_sha256":None,"lock_sha256":None,
  "offline_check_observed":False,"image_digest_verified":False,
  "independent_witnesses":0,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,
  "recovery_authorized":False,"lock_cleared":False,
  "decision":"PHASE_XX_VENDOR_IMAGE_HOLD",**kwargs}
def files_under(root):
 root=pathlib.Path(root).resolve(strict=True)
 if not root.is_dir():raise ValueError("VENDOR_NOT_DIRECTORY")
 files=[];total=0
 for base,dirs,names in os.walk(root,followlinks=False):
  for name in dirs+names:
   p=pathlib.Path(base)/name
   if p.is_symlink():raise ValueError("SYMLINK_NOT_ALLOWED")
  for name in names:
   p=pathlib.Path(base)/name
   rel=p.relative_to(root).as_posix()
   if not rel or rel.startswith("/") or ".." in pathlib.PurePosixPath(rel).parts:
    raise ValueError("UNSAFE_RELATIVE_PATH")
   size=p.stat().st_size
   if not p.is_file() or size>MAX_FILE_BYTES:raise ValueError("OVERSIZE_OR_NONREGULAR")
   total+=size
   if total>MAX_TOTAL_BYTES or len(files)>=MAX_FILES:raise ValueError("VENDOR_LIMIT")
   data=p.read_bytes()
   if len(data)!=size:raise ValueError("FILE_CHANGED_DURING_READ")
   files.append((rel,data))
 files.sort(key=lambda x:x[0])
 if not files or len({name for name,_ in files})!=len(files):
  raise ValueError("EMPTY_OR_DUPLICATE_VENDOR")
 return files,total
def inventory(root,lock_bytes,offline_verified):
 if type(lock_bytes) is not bytes or not lock_bytes or len(lock_bytes)>8*1024*1024:
  return hold("ORIGINAL_LOCK_MISSING"),None
 if offline_verified is not True:return hold("OFFLINE_COMPILATION_NOT_OBSERVED"),None
 try:
  files,total=files_under(root)
 except (OSError,ValueError) as e:
  return hold("VENDOR_BYTES_INVALID",error_type=type(e).__name__),None
 entries=[{"path":p,"bytes":len(b),"sha256":sha(b)} for p,b in files]
 tree=sha(canonical(entries))
 result=hold("SOURCE_OWNED_VENDOR_TREE_VERIFIED",files=len(entries),
  total_bytes=total,lock_sha256=sha(lock_bytes),tree_sha256=tree,
  offline_check_observed=True,entries=entries)
 return result,files
def pack(files):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode="w",format=tarfile.USTAR_FORMAT) as tar:
  for name,data in files:
   info=tarfile.TarInfo(name=name)
   info.size=len(data);info.mtime=0;info.mode=0o644;info.uid=0;info.gid=0
   info.uname="";info.gname=""
   tar.addfile(info,io.BytesIO(data))
 return out.getvalue()
def verify_archive(raw,report):
 if type(raw) is not bytes or not raw or len(raw)>MAX_TOTAL_BYTES+4*1024*1024:
  return hold("ARCHIVE_BYTES_NOT_OBSERVED")
 if type(report) is not dict or report.get("schema")!="sapphon-207-vendor-evidence-v1" or report.get("state")!="SOURCE_OWNED_VENDOR_TREE_VERIFIED":
  return hold("VENDOR_REPORT_NOT_QUALIFIED")
 if report.get("archive_sha256")!=sha(raw):return hold("ARCHIVE_SHA_CONFLICT")
 try:
  with tarfile.open(fileobj=io.BytesIO(raw),mode="r:") as tar:
   members=tar.getmembers()
   if len(members)>MAX_FILES or len(members)!=report.get("files"):
    return hold("ARCHIVE_FILE_COUNT_CONFLICT")
   entries=[];seen=set();total=0
   for member in members:
    name=member.name
    if not member.isfile() or name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts or name in seen:
     return hold("ARCHIVE_MEMBER_UNSAFE")
    seen.add(name)
    if member.size>MAX_FILE_BYTES:return hold("ARCHIVE_MEMBER_OVERSIZE")
    total+=member.size
    if total>MAX_TOTAL_BYTES:return hold("ARCHIVE_TOTAL_OVERSIZE")
    handle=tar.extractfile(member)
    if handle is None:return hold("ARCHIVE_MEMBER_UNREADABLE")
    content=handle.read()
    entries.append({"path":name,"bytes":len(content),"sha256":sha(content)})
 except (OSError,ValueError,tarfile.TarError,EOFError):
  return hold("ARCHIVE_CORRUPT")
 if entries!=report.get("entries") or sha(canonical(entries))!=report.get("tree_sha256"):
  return hold("TREE_SHA_CONFLICT")
 return hold("ORIGINAL_VENDOR_ARCHIVE_MATCH",files=len(entries),
  total_bytes=total,tree_sha256=report["tree_sha256"],
  archive_sha256=sha(raw),lock_sha256=report.get("lock_sha256"),
  offline_check_observed=True)
def image_gate(image,inspect_data,archive_result):
 if type(archive_result) is not dict or archive_result.get("state")!="ORIGINAL_VENDOR_ARCHIVE_MATCH":
  return hold("VENDOR_ARCHIVE_NOT_VERIFIED")
 if type(image) is not str or not IMAGE.fullmatch(image):
  return hold("IMAGE_REFERENCE_NOT_PINNED")
 if type(inspect_data) is not dict or inspect_data.get("Id") is None or not isinstance(inspect_data["Id"],str):
  return hold("IMAGE_INSPECTION_MISSING")
 if not SHA.fullmatch(inspect_data["Id"].removeprefix("sha256:")):
  return hold("IMAGE_LOCAL_ID_INVALID")
 digests=inspect_data.get("RepoDigests")
 if type(digests) is not list or image not in digests:
  return hold("IMAGE_REPOSITORY_DIGEST_NOT_OBSERVED")
 return hold("SOURCE_OWNED_IMAGE_CONTENT_PINNED",
   files=archive_result["files"],tree_sha256=archive_result["tree_sha256"],
   archive_sha256=archive_result["archive_sha256"],
   lock_sha256=archive_result["lock_sha256"],
   offline_check_observed=True,image_digest_verified=True,
   image_digest=image,image_local_id=inspect_data["Id"])
def main():
 p=argparse.ArgumentParser();p.add_argument("--vendor",required=True)
 p.add_argument("--lock",required=True);p.add_argument("--offline-check-observed",action="store_true")
 p.add_argument("--report-out",default="qualification-artifact/207-vendor.json")
 p.add_argument("--tar-out",default="qualification-artifact/207-vendor.tar")
 args=p.parse_args()
 try:r,files=inventory(args.vendor,pathlib.Path(args.lock).read_bytes(),
   args.offline_check_observed)
 except OSError:r,files=hold("SOURCE_INPUT_UNAVAILABLE"),None
 out=pathlib.Path(args.report_out);out.parent.mkdir(parents=True,exist_ok=True)
 if files is not None:
  tar=pack(files)
  r["archive_sha256"]=sha(tar)
  check=verify_archive(tar,r)
  if check["state"]!="ORIGINAL_VENDOR_ARCHIVE_MATCH":
   r=hold("ARCHIVE_SELF_CHECK_FAILED",reason=check["state"])
  else:
   with pathlib.Path(args.tar_out).open("xb") as f:
    f.write(tar);f.flush();os.fsync(f.fileno())
 out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
 print(r["state"],r.get("files"),r.get("tree_sha256"))
 if r["state"]!="SOURCE_OWNED_VENDOR_TREE_VERIFIED":sys.exit(1)
if __name__=="__main__":main()
