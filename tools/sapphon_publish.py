#!/usr/bin/env python3
"""SAPPHON-092. Read-only exported clock event publisher.
No new timestamps, clocks, or authorizations are calculated by this program.
The bounded local pin is a deployment configuration, NOT an independent credential.
"""
import argparse
import copy
import hashlib
import json
import math
import re
from pathlib import Path

REGS = ("ymd", "hms", "degree_arcminute_arcsecond", "arc_arc_arc")
FLAGS = ("second", "minute", "day")
SCHEMA = "sapphon-clock-records-v1"
PIN = "sapphon-082-frozen-synthetic-export"  # owned deployment route, NOT proof of independence

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def validate_record(r, sequence):
    if not isinstance(r, dict) or type(r.get("seq")) is not int or r["seq"] != sequence:
        raise ValueError("Sequence gap or non-integer sequence")
    if type(r.get("sector")) is not int or r["sector"] != sequence % 8:
        raise ValueError("Eight-sector mismatch")
    h = r.get("hash")
    if not isinstance(h, str) or re.fullmatch("[a-f0-9]{64}", h) is None:
        raise ValueError("Invalid recorded identity")
    a = r.get("address")
    if not isinstance(a, dict) or set(a) != set(REGS):
        raise ValueError("Must preserve four registers")
    for k in REGS:
        if not isinstance(a[k], list) or len(a[k]) != 3 or any(type(v) is not int for v in a[k]):
            raise ValueError("Malformed clock register")
    if type(r.get("estimate")) not in (int,float) or not math.isfinite(r["estimate"]):
        raise ValueError("Invalid estimate")
    u = r.get("uncertainty")
    if u is not None and (type(u) not in (int,float) or not math.isfinite(u) or u < 0):
        raise ValueError("Invalid uncertainty")
    for k in FLAGS:
        if type(r.get(k)) is not bool:
            raise ValueError("Authorization must come from recorded engine")
    return h

def validate_archive(doc):
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or doc.get("mode") != "static-archive":
        raise ValueError("Invalid frozen archive contract")
    records = doc.get("records")
    if not isinstance(records, list) or not 1 <= len(records) <= 100000:
        raise ValueError("Invalid archive size")
    unique = set()
    for n, r in enumerate(records):
        h = validate_record(r, n)
        if h in unique: raise ValueError("Reused event identity")
        unique.add(h)
    return records

def reconcile(frozen, incoming=None):
    """Atomic full-archive + optional suffix reconciliation; never reauthorizes records."""
    history = copy.deepcopy(validate_archive(frozen))
    if incoming is None:
        return history, "static-archive"
    if not isinstance(incoming, dict) or incoming.get("schema") != SCHEMA or incoming.get("mode") != "recorded-stream":
        raise ValueError("Unsupported incoming stream")
    if incoming.get("source_root") != PIN:
        raise ValueError("Unpinned source route")
    if incoming.get("clock_origin") != "synthetic-export":
        raise ValueError("Unknown observation origin")
    start = incoming.get("start_seq")
    if type(start) is not int or not 0 <= start <= len(history):
        raise ValueError("Incoming gap or invalid start")
    rows = incoming.get("records")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100000:
        raise ValueError("Invalid incoming batch")
    if len(history) + len(rows) > 100000:
        raise ValueError("Bounded retention exceeded")
    if start == 0:
        if incoming.get("prev_hash") is not None: raise ValueError("Genesis hash mismatch")
    elif incoming.get("prev_hash") != history[start-1]["hash"]:
        raise ValueError("Predecessor identity mismatch")
    identities = {x["hash"] for x in history}
    for offset, row in enumerate(rows):
        i = start + offset
        h = validate_record(row, i)
        if i < len(history):
            if encode(row) != encode(history[i]):
                raise ValueError("Conflicting immutable overlap")
        else:
            if h in identities: raise ValueError("Duplicate identity reused for new sequence")
            history.append(copy.deepcopy(row))
            identities.add(h)
    if len(history) == len(frozen["records"]):
        return history, "static-archive"
    return history, "recorded-stream"

def publish(archive_file, output_file, incoming_file):
    original = archive_file.read_bytes()
    frozen = json.loads(original)
    incoming = json.loads(incoming_file.read_bytes()) if incoming_file.is_file() else None
    records, mode = reconcile(frozen, incoming)
    out = {
        "schema": SCHEMA,
        "mode": mode,
        "clock_origin": "synthetic-export",
        "source_root": PIN,
        "source_sha256": hashlib.sha256(original).hexdigest(),
        "record_count": len(records),
        "note": "Recorded synthetic clock data only; source declarations are not cryptographic attestation.",
        "records": records,
    }
    output_file.parent.mkdir(parents=True,exist_ok=True)
    output_file.write_text(json.dumps(out,sort_keys=True,indent=2,allow_nan=False)+"\n")
    return out

def tests(source):
    orig = json.loads(source.read_text())
    rows = validate_archive(orig)
    count = 0
    def check(condition, label):
        nonlocal count
        assert condition, label
        count += 1
    check(len(rows) >= 8, "archive size")
    check(len(reconcile(orig)[0]) == len(rows), "baseline")
    def batch(rows_new, start=None, prev=None, root=PIN):
        start = len(rows) if start is None else start
        return {"schema":SCHEMA,"mode":"recorded-stream","source_root":root,
                "clock_origin":"synthetic-export","start_seq":start,
                "prev_hash": rows[start-1]["hash"] if prev is None and start else prev,
                "records":rows_new}
    extension = copy.deepcopy(rows[-1])
    extension["seq"]=len(rows)
    extension["sector"]=len(rows)%8
    extension["hash"]=hashlib.sha256(b"test-only-new-record").hexdigest()
    extension["day"]=False
    accepted, mode = reconcile(orig,batch([extension]))
    check(len(accepted)==len(rows)+1 and mode=="recorded-stream","append")
    overlapped,_=reconcile(orig,batch([rows[-1],extension],start=len(rows)-1))
    check(encode(overlapped)==encode(accepted),"overlap retry")
    check(reconcile(orig,batch([rows[-1]],start=len(rows)-1))[1]=="static-archive","replay")
    def rejects(update,label):
        nonlocal count
        b=batch([copy.deepcopy(extension)])
        update(b)
        try: reconcile(orig,b)
        except (ValueError,TypeError,KeyError):
            count+=1
            return
        raise AssertionError("Accepted "+label)
    rejects(lambda b:b.update(start_seq=len(rows)+1),"gap")
    rejects(lambda b:b.update(prev_hash="0"*64),"wrong predecessor")
    rejects(lambda b:b.update(source_root="unrecognized"),"unregistered route")
    rejects(lambda b:b["records"][0].update(day="true"),"invented flag type")
    rejects(lambda b:b["records"][0].update(sector=7),"wrong rotor phase")
    rejects(lambda b:b["records"][0].update(hash=rows[0]["hash"]),"duplicate digest")
    rejects(lambda b:b["records"][0].update(uncertainty=-1),"bad uncertainty")
    rejects(lambda b:b.update(start_seq=len(rows)-1,records=[copy.deepcopy(extension)]),"conflicting overlap")
    rejects(lambda b:b.update(clock_origin="hardware-utc"),"false hardware label")
    rejects(lambda b:b.update(mode="live-utc"),"unsupported mode")
    print("PASS:",count,"continuity, provenance, replay and rejection checks")
    return count

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,default=Path("docs/sapphon/source/clock.json"))
    p.add_argument("--incoming",type=Path,default=Path("docs/sapphon/source/incoming.json"))
    p.add_argument("--output",type=Path,default=Path("docs/sapphon/live/clock.json"))
    p.add_argument("--test",action="store_true")
    a=p.parse_args()
    if a.test: tests(a.source)
    else:
        r=publish(a.source,a.output,a.incoming)
        print("PASS:",r["mode"],r["record_count"],"recorded events; zero synthesized authority")
