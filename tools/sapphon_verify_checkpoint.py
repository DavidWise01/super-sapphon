#!/usr/bin/env python3
"""SAPPHON-095 standalone checkpoint verifier.
Independently recomputes the browser checkpoint projection with Python hashlib,
then compares its retained prefix to an independently supplied published JSON file.
This does not establish third-party provenance or external time truth.
"""
import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path

REGISTERS = ("ymd", "hms", "degree_arcminute_arcsecond", "arc_arc_arc")
FLAGS = ("second", "minute", "day")
PIN = "sapphon-082-frozen-synthetic-export"

def reject(message):
    raise ValueError(message)

def projection(record, index):
    if type(record) is not dict or type(record.get("seq")) is not int or record["seq"] != index:
        reject("Invalid sequence at "+str(index))
    if type(record.get("sector")) is not int or record["sector"] != index % 8:
        reject("Invalid sector")
    h = record.get("hash")
    if not isinstance(h,str) or not re.fullmatch("[0-9a-f]{64}", h):
        reject("Invalid recorded hash")
    if any(type(record.get(k)) is not bool for k in FLAGS):
        reject("Invalid authorization field")
    e, u = record.get("estimate"), record.get("uncertainty")
    if type(e) not in (int,float) or not math.isfinite(e):
        reject("Invalid time estimate")
    if u is not None and (type(u) not in (int,float) or not math.isfinite(u) or u < 0):
        reject("Invalid uncertainty")
    a = record.get("address")
    if type(a) is not dict or any(k not in a for k in REGISTERS):
        reject("Missing register")
    blocks=[]
    for k in REGISTERS:
        x=a[k]
        if type(x) is not list or len(x)!=3 or any(type(v) is not int for v in x):
            reject("Malformed register "+k)
        blocks.append(x)
    return [index,record["sector"],h,e,u,*[record[k] for k in FLAGS],*blocks]

def projection_text(rows):
    if type(rows) is not list or not 1 <= len(rows) <= 100000:
        reject("Invalid history size")
    canonical=[projection(r,i) for i,r in enumerate(rows)]
    # JS JSON.stringify used by browser writes floats using shortest JSON number form.
    # For this integer-dominated archived corpus, Python's serialization matches;
    # if exotic numeric forms appear, verification must explicitly refuse mismatches.
    return json.dumps(canonical,ensure_ascii=False,separators=(",",":"),allow_nan=False)

def verify(checkpoint,published):
    if not isinstance(checkpoint,dict) or checkpoint.get("schema")!="sapphon-browser-checkpoint-v1":
        reject("Unrecognized checkpoint schema")
    rows=checkpoint.get("records")
    raw=projection_text(rows)
    if type(checkpoint.get("last_seq")) is not int or checkpoint["last_seq"]!=len(rows)-1:
        reject("Checkpoint boundary mismatch")
    declared=checkpoint.get("digest")
    digest=hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if declared!=digest:
        reject("Local checkpoint fingerprint mismatch")
    if not isinstance(published,dict) or published.get("schema")!="sapphon-clock-records-v1":
        reject("Invalid published format")
    if published.get("source_root")!=PIN or published.get("clock_origin")!="synthetic-export":
        reject("Unexpected source declaration")
    public_rows=published.get("records")
    projection_text(public_rows)
    if len(public_rows)<len(rows):
        reject("Published history shorter than checkpoint")
    for index,old in enumerate(rows):
        if projection(old,index)!=projection(public_rows[index],index):
            reject("Published historical prefix differs at "+str(index))
    return {
        "status":"PASS",
        "checkpoint_digest":digest,
        "checkpoint_last_seq":len(rows)-1,
        "published_last_seq":len(public_rows)-1,
        "continuation_records":len(public_rows)-len(rows),
        "scope":"software content and declared source consistency; not time authenticity",
    }

def run_tests(path):
    import copy
    source=json.loads(path.read_text())
    rows=source["records"]
    template={"schema":"sapphon-browser-checkpoint-v1","last_seq":len(rows)-1,
        "records":copy.deepcopy(rows),
        "digest":hashlib.sha256(projection_text(rows).encode()).hexdigest()}
    count=0
    def passed(check):
        nonlocal count
        if not check: raise AssertionError("Assertion failed")
        count+=1
    passed(verify(template,source)["status"]=="PASS")
    def rejects(change,publication=False):
        nonlocal count
        ck, pub=copy.deepcopy(template), copy.deepcopy(source)
        change(pub if publication else ck)
        try:verify(ck,pub)
        except ValueError: count+=1
        else:raise AssertionError("Forged checkpoint accepted")
    rejects(lambda x:x["records"][0].update(day=True))
    rejects(lambda x:x["records"][3]["address"]["hms"].__setitem__(0,7))
    rejects(lambda x:x.update(last_seq=11))
    rejects(lambda x:x["records"].pop())
    rejects(lambda x:x["records"][4].update(uncertainty=-1))
    rejects(lambda x:x["records"][2].update(hash="ab"))
    rejects(lambda x:x["records"][2].update(day=False),True)
    rejects(lambda x:x.update(source_root="other"),True)
    rejects(lambda x:x["records"].pop(),True)
    # Prefix shorter than publication is valid continuation.
    shorter=copy.deepcopy(template);shorter["records"]=shorter["records"][:-1]
    shorter["last_seq"]-=1
    shorter["digest"]=hashlib.sha256(projection_text(shorter["records"]).encode()).hexdigest()
    passed(verify(shorter,source)["continuation_records"]==1)
    print("PASS:",count,"independent checkpoint verification tests")
    return count

if __name__=="__main__":
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("checkpoint",nargs="?",type=Path)
    cli.add_argument("--published",type=Path,default=Path("docs/sapphon/live/clock.json"))
    cli.add_argument("--test",action="store_true")
    args=cli.parse_args()
    try:
        if args.test:run_tests(args.published)
        else:
            if args.checkpoint is None:cli.error("Checkpoint JSON path required")
            print(json.dumps(verify(json.loads(args.checkpoint.read_text()),
                                   json.loads(args.published.read_text())),indent=2))
    except (ValueError,KeyError,TypeError,AssertionError) as e:
        print("FAIL:",e,file=sys.stderr)
        sys.exit(1)
