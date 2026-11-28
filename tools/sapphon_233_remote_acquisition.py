#!/usr/bin/env python3
"""SAPPHON-233 — bounded remote byte acquisition and source ancestry inventory.

A successful HTTPS GET proves reachable bytes at acquisition time, not independent
custody, authenticated publication identity, permanence or permission to recover.
No URL, hostname, signature, or separate transport is promoted to a witness.
"""
import argparse
import hashlib
import ipaddress
import json
import pathlib
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

MAX_TARGETS=12
MAX_BYTES=1024*1024
MAX_INPUT=64*1024
TIMEOUT=12
def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def sha(x):
    return hashlib.sha256(canonical(x)).hexdigest()
def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None

def public_url(url):
    if not isinstance(url,str) or len(url)>2048: return False,"URL_INVALID"
    try:
        p=urllib.parse.urlsplit(url)
        if p.scheme!="https" or not p.hostname or p.username or p.password or p.fragment or p.port not in (None,443):
            return False,"HTTPS_URL_REQUIRED"
        host=p.hostname
        if host.endswith(".local") or host=="localhost" or "." not in host:
            return False,"HOST_NOT_PUBLIC"
        try:
            ipaddress.ip_address(host)
            return False,"IP_LITERAL_FORBIDDEN"
        except ValueError: pass
        return True,"URL_SHAPE_OK"
    except ValueError:
        return False,"URL_INVALID"

def fetch_https(url,timeout=TIMEOUT):
    valid,reason=public_url(url)
    if not valid: raise ValueError(reason)
    host=urllib.parse.urlsplit(url).hostname
    # Reject DNS answers leading into private, loopback, reserved and link-local space.
    answers=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
    addresses={a[4][0] for a in answers}
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("DNS_NONPUBLIC_ADDRESS")
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request=urllib.request.Request(url,headers={"User-Agent":"sapphon-233-observation-only/1","Accept":"application/octet-stream"})
    with opener.open(request,timeout=timeout) as response:
        status=response.getcode()
        if status!=200: raise ValueError("HTTP_STATUS_"+str(status))
        data=response.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES: raise ValueError("READBACK_OVERSIZE")
        return {"status":status,"bytes":data,"content_type":response.headers.get("Content-Type","")}

def assess(targets,fetcher=fetch_https):
    faults=[]
    if not isinstance(targets,list) or len(targets)>MAX_TARGETS:
        faults.append("TARGET_INVENTORY_INVALID");targets=[]
    acquisitions=[]
    seen=set()
    for index,t in enumerate(targets):
        record={"index":index,"state":"NOT_ACQUIRED","http_status":None,
                "byte_count":None,"sha256":None}
        if not isinstance(t,dict) or set(t)!={"id","url","ancestry_root","expected_sha256","claimed_operator"}:
            record["reason"]="TARGET_SCHEMA_INVALID";faults.append(record["reason"])
            acquisitions.append(record);continue
        record.update({k:t[k] for k in ("id","url","ancestry_root","claimed_operator")})
        if any(not isinstance(t[k],str) or not 1<=len(t[k])<=160 for k in ("id","ancestry_root","claimed_operator")):
            record["reason"]="TARGET_ID_INVALID"
        elif t["id"] in seen:
            record["reason"]="TARGET_ID_DUPLICATE"
        elif t["expected_sha256"] is not None and (not isinstance(t["expected_sha256"],str) or
             len(t["expected_sha256"])!=64 or any(c not in "0123456789abcdef" for c in t["expected_sha256"])):
            record["reason"]="EXPECTED_DIGEST_INVALID"
        else:
            seen.add(t["id"])
            good,why=public_url(t["url"])
            if not good: record["reason"]=why
            else:
                try:
                    result=fetcher(t["url"])
                    payload=result["bytes"]
                    if type(payload) is not bytes or len(payload)>MAX_BYTES:
                        raise ValueError("READBACK_SIZE_OR_TYPE_INVALID")
                    if result["status"]!=200: raise ValueError("HTTP_STATUS_NOT_200")
                    h=sha_bytes(payload)
                    record.update({"http_status":result["status"],"sha256":h,
                                   "byte_count":len(payload),"content_type":result.get("content_type","")})
                    if t["expected_sha256"] is not None and t["expected_sha256"]!=h:
                        record["reason"]="EXPECTED_DIGEST_MISMATCH"
                    else:
                        record["state"]="REMOTE_BYTES_OBSERVED"
                        record["reason"]="HTTPS_BYTES_HASHED_NOT_CUSTODY_ATTESTED"
                except (ValueError,OSError,urllib.error.URLError,ssl.SSLError,TimeoutError,KeyError) as exc:
                    record["reason"]="FETCH_FAILED_"+type(exc).__name__
        if record.get("state")!="REMOTE_BYTES_OBSERVED": faults.append(record["reason"])
        acquisitions.append(record)
    seen_roots={}
    for record in acquisitions:
        if record["state"]=="REMOTE_BYTES_OBSERVED":
            seen_roots.setdefault(record["ancestry_root"],[]).append(record["id"])
    # Root strings are caller-declared. Distinct strings do not establish
    # independent origin/control. A retrieved mirror is not a witness.
    blockers=sorted(set(faults+["INDEPENDENT_SOURCE_ANCESTRY_UNVERIFIED",
         "INDEPENDENT_OPERATOR_CONTROL_UNVERIFIED","DURABLE_EXTERNAL_RETENTION_UNVERIFIED",
         "REMOTE_MONOTONIC_HIGHWATER_UNVERIFIED","AUTHENTICATED_UTC_UNVERIFIED",
         "THREE_INDEPENDENT_WITNESSES_UNVERIFIED"]))
    out={"schema":"sapphon-233-remote-acquisition-v1","state":"REMOTE_ACQUISITION_OBSERVATION_ONLY_HOLD",
         "acquisitions":acquisitions,"observed_count":sum(x["state"]=="REMOTE_BYTES_OBSERVED" for x in acquisitions),
         "declared_ancestry_groups":seen_roots,"independently_authenticated_witnesses":0,
         "blockers":blockers,"reconciliation":"NO_WINNER_SELECTED",
         "recovery_authorized":False,"lock_cleared":False,"decision":"HOLD"}
    out["evidence_sha256"]=sha(out)
    return out

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--targets",required=True)
    a.add_argument("--out",required=True)
    args=a.parse_args()
    q=pathlib.Path(args.targets)
    if q.stat().st_size>MAX_INPUT: raise ValueError("target manifest exceeds bound")
    targets=json.loads(q.read_text())
    out=assess(targets)
    dest=pathlib.Path(args.out)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(out["state"],"remote_observed",out["observed_count"])
if __name__=="__main__":main()
