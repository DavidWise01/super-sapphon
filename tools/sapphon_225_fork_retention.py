#!/usr/bin/env python3
"""SAPPHON-225 — retain both signed heads of a fork, never select a winner.

Retention is deterministic content-addressed evidence inside GitHub's owned
ancestry. It is not an independent custody witness or original-byte archive.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys
from collections import defaultdict

import sapphon_221_attestation as ed
import sapphon_223_checkpoint as chain

LIMIT = 64
HEAD_FIELDS = {"schema", "sequence", "checkpoint_sha256", "custodian_root",
               "source_run", "source_commit", "image_sha256", "claimed_utc"}
ENVELOPE_FIELDS = {"payload", "signature_base64"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROOT = re.compile(r"^[A-Za-z0-9_-]{4,128}$")

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def adjudicate(heads, anchor=None):
    problems = []
    if type(heads) is not list or len(heads) > LIMIT:
        problems.append("INVALID_OR_UNBOUNDED_HEAD_SET")
        heads = []
    if type(anchor) is not dict:
        anchor = {}
    pem = anchor.get("public_key_pem")
    key_ready = (type(pem) is str and 0 < len(pem) <= 4096
                 and sha(pem.encode()) == anchor.get("key_sha256"))
    if not key_ready:
        problems.append("TRUST_ANCHOR_ABSENT_OR_HASH_MISMATCH")
    retained = []
    by_counter = defaultdict(list)
    seen = set()
    for index, envelope in enumerate(heads):
        # Canonical serialization is for deterministic second-order evidence,
        # not a claim to have saved original uploaded JSON whitespace/bytes.
        raw = canonical(envelope)
        receipt_hash = sha(raw)
        if receipt_hash in seen:
            problems.append("DUPLICATED_SIGNED_ENVELOPE")
        seen.add(receipt_hash)
        payload = envelope.get("payload") if type(envelope) is dict else None
        signature = envelope.get("signature_base64") if type(envelope) is dict else None
        valid_shape = (
            type(envelope) is dict and set(envelope) == ENVELOPE_FIELDS
            and type(payload) is dict and set(payload) == HEAD_FIELDS
            and payload.get("schema") == "sapphon-224-signed-head-v1"
            and type(payload.get("sequence")) is int and payload["sequence"] > 0
            and type(payload.get("checkpoint_sha256")) is str
            and HEX64.fullmatch(payload["checkpoint_sha256"])
            and type(payload.get("custodian_root")) is str
            and ROOT.fullmatch(payload["custodian_root"])
            and type(payload.get("claimed_utc")) is str
            and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",payload["claimed_utc"])
            and payload.get("source_run") == chain.SOURCE_RUN
            and payload.get("source_commit") == chain.SOURCE_COMMIT
            and payload.get("image_sha256") == chain.IMAGE_SHA
        )
        valid_sig = bool(
            valid_shape and key_ready
            and anchor.get("custodian_root") == payload["custodian_root"]
            and type(signature) is str
            and ed.verify_crypto(canonical(payload), signature, pem)
        )
        entry = {
            "input_index": index,
            "canonical_envelope_sha256": receipt_hash,
            "canonical_envelope_hex_bytes": len(raw),
            "signature_verified_against_supplied_key": valid_sig,
            "custodian_root": payload.get("custodian_root") if type(payload) is dict else None,
            "sequence": payload.get("sequence") if type(payload) is dict else None,
            "checkpoint_sha256": payload.get("checkpoint_sha256") if type(payload) is dict else None,
            "canonical_envelope": envelope,
        }
        retained.append(entry)
        if not valid_sig:
            problems.append("INVALID_OR_UNVERIFIED_SIGNED_HEAD")
        else:
            by_counter[(payload["custodian_root"], payload["sequence"])].append(entry)
    forks = []
    for (root, counter), entries in sorted(by_counter.items()):
        groups = defaultdict(list)
        for e in entries:
            groups[e["checkpoint_sha256"]].append(e["canonical_envelope_sha256"])
        if len(groups) > 1:
            hashes = sorted(groups)
            forks.append({
                "custodian_root": root,
                "sequence": counter,
                "conflicting_checkpoint_sha256": hashes,
                "retained_signed_envelopes_by_checkpoint": {
                    h: sorted(groups[h]) for h in hashes
                },
                "disposition": "PRESERVE_BOTH_NO_SELECTION"
            })
    if not retained:
        problems.append("NO_SIGNED_HEADS_PROVIDED")
    if forks:
        problems.append("SIGNED_EQUIVOCATION_REQUIRES_EXTERNAL_RECONCILIATION")
    # Retain all received heads in deterministic input order; the summary is
    # independently hashable, but GitHub custody is still the same source root.
    body = {
        "schema": "sapphon-225-fork-evidence-retention-v1",
        "state": ("SIGNED_FORK_PRESERVED_HOLD" if forks else
                  "NO_FORK_OBSERVED_CUSTODY_HOLD" if retained and not problems
                  else "SIGNED_HEAD_INTAKE_HOLD"),
        "head_count": len(retained),
        "verified_signature_count": sum(e["signature_verified_against_supplied_key"] for e in retained),
        "heads_retained": retained,
        "signed_forks": forks,
        "fork_count": len(forks),
        "blockers": sorted(set(problems + [
            "EXTERNAL_KEY_PROVISIONING_UNAUTHENTICATED",
            "INDEPENDENT_CUSTODY_UNVERIFIED",
            "AUTHENTICATED_UTC_UNVERIFIED",
            "EXTERNAL_ANTI_ROLLBACK_UNVERIFIED"
        ])),
        "reconciliation": "NO_WINNER_SELECTED",
        "independently_authenticated_witnesses": 0,
        "authenticated_utc": False,
        "global_anti_rollback_authenticated": False,
        "recovery_authorized": False,
        "lock_cleared": False,
        "decision": "HOLD",
    }
    body["evidence_sha256"] = sha(canonical(body))
    return body

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--heads", required=True)
    p.add_argument("--anchor")
    p.add_argument("--out", required=True)
    args = p.parse_args()
    def load(name):
        try:
            return json.loads(pathlib.Path(name).read_text()) if name else None
        except (OSError, ValueError):
            return None
    result = adjudicate(load(args.heads), load(args.anchor))
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
    print(result["state"], "forks", result["fork_count"], "witnesses", 0)
    # A valid signed fork is retained as evidence, not cause to fail the audit.
    return 0 if result["fork_count"] and result["verified_signature_count"] >= 2 else 1

if __name__ == "__main__":
    sys.exit(main())
