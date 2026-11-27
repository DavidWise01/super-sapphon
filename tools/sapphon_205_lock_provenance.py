#!/usr/bin/env python3
"""SAPPHON-205: attest *observed* Cargo lock genesis and offline vendor check.

Never assert that a Cargo.lock was committed or verified from a Cargo.toml.
This tool consumes real Cargo outputs, rejects incomplete or inconsistent
records, and retains the GitHub-owned provenance boundary.
"""
import argparse,hashlib,json,pathlib,re,sys,tomllib
SOURCE="50680b739378147d626c4822862d73306acc26bf"
MANIFEST="rust/sapphon-liveness/Cargo.toml"
HEX=re.compile(r"^[0-9a-f]{64}$")
def digest(b):return hashlib.sha256(b).hexdigest()
def hold(state,**kw):
 return {"schema":"sapphon-205-cargo-provenance-v1","state":state,
  "source_sha":SOURCE,"manifest_path":MANIFEST,
  "lockfile_sha256":None,"manifest_sha256":None,
  "packages":0,"registry_checksums":0,"offline_verified":False,
  "image_digest_verified":False,"replay_executed":False,
  "independent_witnesses":0,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,"recovery_authorized":False,
  "lock_cleared":False,"decision":"PHASE_XX_DEPENDENCY_PROVENANCE_HOLD",**kw}
def inspect(manifest,lock_bytes,metadata,checks):
 if type(manifest) is not bytes or not manifest:return hold("MANIFEST_BYTES_UNOBSERVED")
 if type(lock_bytes) is not bytes or len(lock_bytes)>8*1024*1024 or not lock_bytes:
  return hold("LOCK_BYTES_NOT_OBSERVED")
 try:manifest_toml=tomllib.loads(manifest.decode("utf-8"))
 except (UnicodeError,tomllib.TOMLDecodeError):return hold("MANIFEST_NOT_TOML")
 if manifest_toml.get("package",{}).get("name")!="sapphon-liveness":
  return hold("WRONG_CRATE")
 try:lock=tomllib.loads(lock_bytes.decode("utf-8"))
 except (UnicodeError,tomllib.TOMLDecodeError):return hold("LOCK_NOT_TOML")
 if lock.get("version") not in (3,4):return hold("LOCK_VERSION_INVALID")
 packages=lock.get("package")
 if type(packages) is not list or not packages:return hold("LOCK_PACKAGES_MISSING")
 unique=set();registry=0
 for p in packages:
  if type(p) is not dict or type(p.get("name")) is not str or type(p.get("version")) is not str:
   return hold("LOCK_PACKAGE_INVALID")
  key=(p["name"],p["version"],p.get("source",""))
  if key in unique:return hold("LOCK_PACKAGE_DUPLICATED")
  unique.add(key)
  if p.get("source","").startswith("registry+"):
   if type(p.get("checksum")) is not str or not HEX.fullmatch(p["checksum"]):
    return hold("REGISTRY_PACKAGE_CHECKSUM_INVALID")
   registry+=1
 if not any(p["name"]=="sapphon-liveness" for p in packages):return hold("TARGET_PACKAGE_MISSING")
 if type(metadata) is not dict or type(metadata.get("packages")) is not list:
  return hold("CARGO_METADATA_UNAVAILABLE")
 pkg_metadata={(p.get("name"),p.get("version")) for p in metadata["packages"] if type(p) is dict}
 if not all((p["name"],p["version"]) in pkg_metadata for p in packages):
  return hold("LOCK_METADATA_PACKAGE_CONFLICT")
 if type(checks) is not dict or set(checks)!={"lock_generation","vendor","offline_metadata","offline_check"}:
  return hold("CHECK_SET_INCOMPLETE")
 if checks["lock_generation"] is not True:return hold("LOCK_GENERATION_NOT_OBSERVED")
 if checks["vendor"] is not True:return hold("VENDOR_NOT_OBSERVED")
 if checks["offline_metadata"] is not True:return hold("OFFLINE_METADATA_NOT_OBSERVED")
 if checks["offline_check"] is not True:return hold("OFFLINE_CHECK_NOT_OBSERVED")
 return hold("GITHUB_OWNED_OFFLINE_DEPENDENCY_CHECK",
  lockfile_sha256=digest(lock_bytes),manifest_sha256=digest(manifest),
  packages=len(packages),registry_checksums=registry,
  offline_verified=True)
def main():
 p=argparse.ArgumentParser()
 p.add_argument("--manifest",required=True);p.add_argument("--lock",required=True)
 p.add_argument("--metadata",required=True);p.add_argument("--checks",required=True)
 p.add_argument("--out",default="qualification-artifact/205-provenance.json")
 x=p.parse_args()
 try:
  result=inspect(pathlib.Path(x.manifest).read_bytes(),
    pathlib.Path(x.lock).read_bytes(),
    json.loads(pathlib.Path(x.metadata).read_text()),
    json.loads(pathlib.Path(x.checks).read_text()))
 except (OSError,ValueError,TypeError,KeyError,UnicodeError) as e:
  result=hold("DEPENDENCY_EVIDENCE_UNAVAILABLE",error_type=type(e).__name__)
 dest=pathlib.Path(x.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(result["state"],result["lockfile_sha256"])
 if not result["offline_verified"]:sys.exit(1)
if __name__=="__main__":main()
