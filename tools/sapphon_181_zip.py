#!/usr/bin/env python3
"""SAPPHON-181: inspect original GitHub Actions artifact ZIP in memory only.

Never extract entries, follow paths, import modules from archive, or execute files.
Archive byte/digest checks are GitHub-owned provenance, not external custody.
"""
import argparse, hashlib, io, json, pathlib, re, stat, sys, zipfile

SOURCE="dd1d778c522aa18fb399c052958f05c4f5b02dd9"
WORKFLOW="sapphon-180-binding.yml"
JOB="artifact-binding"
ARTIFACT="sapphon-180-byte-binding"
MAX_ZIP=64*1024*1024
MAX_FILES=48
MAX_ITEM=2*1024*1024
MAX_TOTAL=12*1024*1024
SHA64=re.compile(r"^[a-f0-9]{64}$")
EXPECTED="180-summary.json"
def sha(data):return hashlib.sha256(data).hexdigest()
def inspect_zip(data, metadata):
    issues=[]; entries=[]
    if type(metadata) is not dict:raise ValueError("BAD_METADATA")
    if metadata.get("source_sha")!=SOURCE or metadata.get("workflow")!=WORKFLOW or metadata.get("job_name")!=JOB:
        issues.append("WRONG_SOURCE_WORKFLOW_JOB")
    if metadata.get("artifact_name")!=ARTIFACT:issues.append("ARTIFACT_NAME_MISMATCH")
    for key in ("run_id","attempt","job_id","artifact_id"):
        val=metadata.get(key)
        if type(val) is not int or val<=0:issues.append("INVALID_"+key.upper())
    if metadata.get("artifact_expired") is not False:issues.append("ARTIFACT_EXPIRED_UNKNOWN")
    if metadata.get("recovery_authorized") is not False:issues.append("FORGED_AUTHORITY")
    actual=sha(data)
    claimed=metadata.get("artifact_sha256")
    if not isinstance(claimed,str) or not SHA64.fullmatch(claimed) or claimed!=actual:
        issues.append("ORIGINAL_ZIP_HASH_MISMATCH")
    if not data or len(data)>MAX_ZIP:issues.append("ZIP_MISSING_OR_OVERSIZE")
    summary=None
    if "ZIP_MISSING_OR_OVERSIZE" not in issues:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos=z.infolist()
                if not infos or len(infos)>MAX_FILES:issues.append("INVALID_ENTRY_COUNT")
                seen=set();uncompressed=0
                for info in infos:
                    name=info.filename
                    parts=name.replace("\\","/").split("/")
                    if (not name or name.startswith(("/", "\\")) or
                        re.match(r"^[a-zA-Z]:",name) or "\\" in name or
                        any(p in ("","..",".") for p in parts) or
                        info.is_dir()):
                        issues.append("UNSAFE_PATH_OR_DIRECTORY");continue
                    if name in seen:issues.append("DUPLICATE_ENTRY")
                    seen.add(name)
                    mode=info.external_attr >> 16
                    if stat.S_ISLNK(mode):issues.append("SYMLINK_ENTRY")
                    if info.flag_bits & 1:issues.append("ENCRYPTED_ENTRY")
                    if info.file_size>MAX_ITEM or info.compress_size>MAX_ZIP:
                        issues.append("ITEM_TOO_LARGE")
                    uncompressed+=info.file_size
                    if uncompressed>MAX_TOTAL:issues.append("EXPANSION_LIMIT")
                    entries.append({"name":name,"bytes":info.file_size,"crc32":f"{info.CRC:08x}"})
                matches=[x for x in infos if x.filename==EXPECTED]
                if len(matches)!=1:issues.append("SUMMARY_NOT_UNIQUE")
                if not issues:
                    content=z.read(matches[0])
                    summary=json.loads(content)
                    if type(summary) is not dict or summary.get("schema")!="sapphon-180-owned-source-evidence-v1":
                        issues.append("SUMMARY_SCHEMA")
                    elif (summary.get("commit")!=SOURCE or
                          str(summary.get("run_id"))!=str(metadata.get("run_id")) or
                          str(summary.get("attempt"))!=str(metadata.get("attempt"))):
                        issues.append("SUMMARY_IDENTITY_MISMATCH")
                    elif (summary.get("recovery_authorized") is not False or
                          summary.get("lock_cleared") is not False):
                        issues.append("SUMMARY_AUTHORITY_CLAIM")
        except (zipfile.BadZipFile, RuntimeError, ValueError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
            issues.append("ZIP_DECODE_FAILURE:"+type(exc).__name__)
    return {"schema":"sapphon-181-safe-zip-inspection-v1",
        "source_sha":SOURCE,"run_id":metadata.get("run_id"),"attempt":metadata.get("attempt"),
        "artifact_id":metadata.get("artifact_id"),"original_zip_sha256":actual,
        "entries":entries,"findings":sorted(set(issues)),
        "source_owned_zip_consistent":not issues,
        "bytes_extracted_to_disk":False,"archive_code_executed":False,
        "external_metadata_authenticated":False,"independent_custody_authenticated":False,
        "recovery_authorized":False,"lock_cleared":False,
        "decision":"ORIGINAL_ZIP_INSPECTION_HOLD"}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--artifact-zip",required=True);p.add_argument("--metadata",required=True)
    p.add_argument("--out",default="qualification-artifact/181-archive-inspection.json")
    a=p.parse_args()
    data=pathlib.Path(a.artifact_zip).read_bytes()
    meta=json.loads(pathlib.Path(a.metadata).read_text())
    result=inspect_zip(data,meta)
    out=pathlib.Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["decision"],result["findings"])
    if result["findings"]:sys.exit(1)
if __name__=="__main__":main()
