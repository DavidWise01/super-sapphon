#!/usr/bin/env python3
"""SAPPHON-221: verify Ed25519 receipt signature, never infer independent custody.

An arbitrary receipt can carry its own valid public key. Therefore a valid
signature is NOT independent identity, physical custody, trusted time,
anti-rollback, an external witness, or recovery authorization.
"""
import argparse,base64,hashlib,json,pathlib,re,subprocess,sys,tempfile
MANIFEST_SHA="3ac20185c7e4bb6933f9bcfe3e6ba91eeaa25a91904ca3c3f7aefd92ff7e6836"
SOURCE_RUN="46154833375"
SOURCE_COMMIT="c167a95a05177e280625fa61613c1b1fa20f75e9"
SOURCE_ATTEMPT="1"
HEX64=re.compile(r"^[0-9a-f]{64}$")
REQUIRED=("schema","manifest_sha256","source_run","source_attempt","source_commit","custodian_root","sequence","previous_receipt_sha256","claimed_utc","observed_image_sha256")
EXPECTED_IMAGE_SHA="32da27a2e9fee90e9773a1b33eb59e0b1483223dc29d2161c0dfa05f1a8ed197"
def canonical(payload):
    return json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def verify_crypto(message, signature_base64, pubkey_pem):
    try:
        sig=base64.b64decode(signature_base64,validate=True)
        if len(sig)!=64 or len(pubkey_pem)>4096: return False
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            (p/"key.pem").write_text(pubkey_pem)
            (p/"sig").write_bytes(sig)
            (p/"message").write_bytes(message)
            result=subprocess.run(
                ["openssl","pkeyutl","-verify","-pubin","-inkey",str(p/"key.pem"),
                 "-rawin","-in",str(p/"message"),"-sigfile",str(p/"sig")],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8,check=False)
            return result.returncode==0
    except (ValueError,TypeError,OSError,subprocess.TimeoutExpired):
        return False
def assess(receipt):
    bad=[]
    if type(receipt) is not dict: receipt={};bad.append("RECEIPT_INVALID")
    payload=receipt.get("payload")
    if type(payload) is not dict or set(payload)!=set(REQUIRED):
        bad.append("PAYLOAD_SCHEMA_OR_FIELDS")
        payload={}
    if payload.get("schema")!="sapphon-221-custody-attestation-v1":
        bad.append("ATTESTATION_SCHEMA")
    if payload.get("manifest_sha256")!=MANIFEST_SHA:
        bad.append("HANDOFF_MANIFEST_MISMATCH")
    if (str(payload.get("source_run"))!=SOURCE_RUN or
        str(payload.get("source_attempt"))!=SOURCE_ATTEMPT or
        payload.get("source_commit")!=SOURCE_COMMIT):
        bad.append("SOURCE_ANCESTRY_MISMATCH")
    if payload.get("observed_image_sha256")!=EXPECTED_IMAGE_SHA:
        bad.append("IMAGE_HASH_MISMATCH")
    if type(payload.get("custodian_root")) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{4,128}",payload["custodian_root"]) or payload["custodian_root"].lower() in ("github","davidwise01","super-sapphon"):
        bad.append("CLAIMED_CUSTODIAN_ROOT_INVALID")
    if type(payload.get("sequence")) is not int or payload["sequence"]<1:
        bad.append("COUNTER_INVALID")
    if not (payload.get("previous_receipt_sha256") is None or
            type(payload.get("previous_receipt_sha256")) is str and HEX64.fullmatch(payload["previous_receipt_sha256"])):
        bad.append("PREVIOUS_RECEIPT_INVALID")
    if type(payload.get("claimed_utc")) is not str or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",payload["claimed_utc"]):
        bad.append("CLAIMED_UTC_SYNTAX")
    pub=receipt.get("public_key_pem")
    sig=receipt.get("signature_base64")
    signature_valid=type(pub) is str and type(sig) is str and verify_crypto(canonical(payload),sig,pub)
    if not signature_valid:bad.append("SIGNATURE_INVALID_OR_MISSING")
    if receipt.get("recovery_authorized") is not False or receipt.get("lock_cleared") is not False:
        bad.append("UNSAFE_AUTHORITY_CLAIM")
    bad.append("INDEPENDENT_KEY_PROVISIONING_UNVERIFIED")
    bad.append("PHYSICAL_CUSTODY_UNVERIFIED")
    bad.append("AUTHENTICATED_UTC_UNVERIFIED")
    bad.append("EXTERNAL_ANTI_ROLLBACK_UNVERIFIED")
    return {"schema":"sapphon-221-cryptographic-intake-v1",
      "state":"CRYPTOGRAPHIC_SIGNATURE_VALID_CUSTODY_HOLD" if signature_valid and
                 len(bad)==4 else "RECEIPT_REJECTED_HOLD",
      "signature_valid":bool(signature_valid),
      "payload_sha256":hashlib.sha256(canonical(payload)).hexdigest(),
      "blockers":sorted(set(bad)),
      "independently_authenticated_witnesses":0,"authenticated_utc":False,
      "global_anti_rollback_authenticated":False,"recovery_authorized":False,
      "lock_cleared":False,"decision":"HOLD"}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--receipt",required=True)
    p.add_argument("--out",required=True)
    a=p.parse_args()
    try:r=json.loads(pathlib.Path(a.receipt).read_text())
    except (OSError,ValueError):r={}
    v=assess(r);q=pathlib.Path(a.out);q.parent.mkdir(parents=True,exist_ok=True)
    q.write_text(json.dumps(v,indent=2,sort_keys=True)+"\n")
    print(v["state"],"signature_valid="+str(v["signature_valid"]))
    return 0 if v["signature_valid"] else 1
if __name__=="__main__":
    sys.exit(main())
