#!/usr/bin/env python3
"""SAPPHON-191: source-owned proof-of-possession challenge ledger.

No trust on first use, no fabricated externally issued nonce or trusted UTC.
The registry is empty; valid formats never become external custody.
"""
import argparse,hashlib,json,pathlib,re,sys
SOURCE="9cdfc47714899d4f1791d7a51be813ba0790eca9"
WORKFLOW="sapphon-190-custody.yml"
HEX64=re.compile(r"^[0-9a-f]{64}$")
MAX_CHALLENGES=128
def h(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def pos(x):return type(x) is int and x>0
def check(challenges,responses):
 if type(challenges) is not list or type(responses) is not list or len(challenges)>MAX_CHALLENGES or len(responses)>MAX_CHALLENGES:raise ValueError("BOUNDED_INPUT")
 checks={};issues=[];consumed=set();observations=[]
 fields={"schema","source_sha","workflow","run_id","attempt","root_sha256","challenge_nonce_hex",
  "session_id","key_fingerprint_sha256","issuer","external_issuer_authenticated",
  "recovery_authorized"}
 for i,c in enumerate(challenges):
  if type(c) is not dict or set(c)!=fields:issues.append("CHALLENGE_SCHEMA:"+str(i));continue
  if c["schema"]!="sapphon-191-challenge-v1" or c["source_sha"]!=SOURCE or c["workflow"]!=WORKFLOW:issues.append("CHALLENGE_ANCESTRY:"+str(i))
  if not pos(c["run_id"]) or not pos(c["attempt"]):issues.append("CHALLENGE_RUN:"+str(i))
  if any(type(c.get(k)) is not str or not HEX64.fullmatch(c[k]) for k in ("root_sha256","challenge_nonce_hex","key_fingerprint_sha256")):issues.append("CHALLENGE_DIGEST:"+str(i))
  if type(c.get("session_id")) is not str or not (1<=len(c["session_id"])<=128):issues.append("SESSION_INVALID:"+str(i))
  if c.get("issuer")!="unverified-source" or c.get("external_issuer_authenticated") is not False or c.get("recovery_authorized") is not False:issues.append("CHALLENGE_UNTRUSTED_AUTHORITY:"+str(i))
  nonce=c["challenge_nonce_hex"]
  if nonce in checks:issues.append("REUSED_CHALLENGE_NONCE:"+str(i))
  else:checks[nonce]=c
 response_fields={"schema","challenge_nonce_hex","source_sha","run_id","attempt","root_sha256","session_id","key_fingerprint_sha256","signature_b64","recovery_authorized"}
 for i,r in enumerate(responses):
  if type(r) is not dict or set(r)!=response_fields:issues.append("RESPONSE_SCHEMA:"+str(i));continue
  if r["schema"]!="sapphon-191-challenge-response-v1" or r["recovery_authorized"] is not False:issues.append("RESPONSE_AUTHORITY:"+str(i))
  nonce=r.get("challenge_nonce_hex");c=checks.get(nonce)
  if c is None:issues.append("UNISSUED_CHALLENGE:"+str(i));continue
  if nonce in consumed:issues.append("REPLAYED_CHALLENGE_RESPONSE:"+str(i));continue
  consumed.add(nonce)
  for key in ("source_sha","run_id","attempt","root_sha256","session_id","key_fingerprint_sha256"):
   if r.get(key)!=c[key]:issues.append("CROSS_SESSION_OR_ROOT_SUBSTITUTION:"+str(i)+":"+key)
  if type(r.get("signature_b64")) is not str or len(r["signature_b64"])>256:issues.append("SIGNATURE_FORMAT:"+str(i))
  observations.append({"challenge_sha256":h(c),"response_sha256":h(r),"status":"SOURCE_ONLY_UNTRUSTED"})
 return {"schema":"sapphon-191-challenge-adjudication-v1",
  "source_sha":SOURCE,"challenge_count":len(challenges),"response_count":len(responses),
  "consumed_challenges":len(consumed),"findings":sorted(set(issues)),
  "observations":observations,"cryptographic_signatures_verified":False,
  "challenge_issuer_independently_authenticated":False,
  "independent_witnesses":0,"authenticated_utc":False,
  "global_anti_rollback_authenticated":False,"recovery_authorized":False,
  "lock_cleared":False,"decision":"CHALLENGE_PROOF_OF_POSSESSION_HOLD"}
def main():
 p=argparse.ArgumentParser();p.add_argument("--challenges",required=True);p.add_argument("--responses",required=True)
 p.add_argument("--out",default="qualification-artifact/191-challenges.json")
 a=p.parse_args()
 data=check(json.loads(pathlib.Path(a.challenges).read_text()),json.loads(pathlib.Path(a.responses).read_text()))
 dest=pathlib.Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")
 print(data["decision"],data["findings"])
 if data["findings"]:sys.exit(1)
if __name__=="__main__":main()
