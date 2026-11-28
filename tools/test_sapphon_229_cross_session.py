#!/usr/bin/env python3
"""SAPPHON-229 regression fixtures: two sessions, signed highwater and resets."""
import base64,hashlib,pathlib,subprocess,tempfile,unittest
import sapphon_229_cross_session as m
import sapphon_228_ack_ledger as ledger
from test_sapphon_227_portable_readback import sample,make_ack

def sign(payload):
 with tempfile.TemporaryDirectory() as tmp:
  d=pathlib.Path(tmp);priv=d/"key";pub=d/"pub";msg=d/"message";sig=d/"sig"
  subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(priv)],check=True,stdout=subprocess.DEVNULL)
  subprocess.run(["openssl","pkey","-in",str(priv),"-pubout","-out",str(pub)],check=True,stdout=subprocess.DEVNULL)
  pem=pub.read_text()
  msg.write_bytes(m.canonical(payload))
  subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(priv),"-rawin","-in",str(msg),"-out",str(sig)],
                 check=True,stdout=subprocess.DEVNULL)
  signature=base64.b64encode(sig.read_bytes()).decode()
 return pem,signature

def sample_sessions():
 bundle,source_anchor=sample()
 ack1,key1=make_ack(bundle)
 first=ledger.adjudicate([],bundle,source_anchor,ack1,key1)
 assert first["candidate_accepted"],first["blockers"]
 second_payload={**ack1["payload"],"transfer_nonce":"synthetic-nonce-2222"}
 second_pem,second_sig=sign(second_payload)
 ack2={"payload":second_payload,"public_key_pem":second_pem,"signature_base64":second_sig,
       "recovery_authorized":False,"lock_cleared":False}
 key2={"public_key_pem":second_pem,"key_sha256":hashlib.sha256(second_pem.encode()).hexdigest(),
       "custodian_root":second_payload["custodian_root"]}
 second=ledger.adjudicate(first["records"],bundle,source_anchor,ack2,key2)
 assert second["candidate_accepted"],second["blockers"]
 sessions=[{"session_id":"session-one","records":first["records"],"declared_prior_head":None},
           {"session_id":"session-two","records":second["records"],
            "declared_prior_head":first["head_sha256"]}]
 return sessions,bundle,source_anchor

def signed_head(sessions):
 latest=sessions[-1]
 p={"schema":"sapphon-229-signed-session-head-v1","source_run":m.frozen.SOURCE_RUN,
    "source_commit":m.frozen.SOURCE_COMMIT,"session_id":latest["session_id"],
    "record_count":len(latest["records"]),
    "head_sha256":latest["records"][-1]["entry_sha256"],
    "claimed_utc":"2026-11-28T17:00:00Z"}
 pem,signature=sign(p)
 return ({"payload":p,"public_key_pem":pem,"signature_base64":signature},
         {"public_key_pem":pem,"key_sha256":hashlib.sha256(pem.encode()).hexdigest(),
          "custodian_root":"external-demo-not-verified"})

class Tests(unittest.TestCase):
 def test_complete_two_sessions_without_external_head(self):
  ss,b,a=sample_sessions();v=m.audit(ss,b,a)
  self.assertEqual(v["state"],"CROSS_SESSION_PREFIX_MATCH_HEAD_MISSING_HOLD")
  self.assertEqual(v["session_count"],2)
  self.assertFalse(v["recovery_authorized"])
 def test_signed_head_matches_but_not_external(self):
  ss,b,a=sample_sessions();h,k=signed_head(ss)
  v=m.audit(ss,b,a,h,k)
  self.assertEqual(v["state"],"CROSS_SESSION_SIGNED_HEAD_BYTES_MATCH_HOLD")
  self.assertTrue(v["signed_head_bytes_verified"])
  self.assertEqual(v["independently_authenticated_witnesses"],0)
 def test_cross_session_truncated_history(self):
  ss,b,a=sample_sessions();ss[1]["records"]=ss[1]["records"][:1]
  self.assertIn("SESSION_HISTORY_TRUNCATED_OR_NOT_ADVANCED",m.audit(ss,b,a)["blockers"])
 def test_rewrite_first_record(self):
  ss,b,a=sample_sessions()
  ss[1]["records"][0]={"sequence":1,"entry_sha256":"a"*64}
  self.assertIn("SESSION_HISTORY_REWRITTEN_OR_FORKED",m.audit(ss,b,a)["blockers"])
 def test_changed_prior_head(self):
  ss,b,a=sample_sessions();ss[1]["declared_prior_head"]="f"*64
  self.assertIn("DECLARED_PRIOR_HEAD_CONFLICT",m.audit(ss,b,a)["blockers"])
 def test_duplicate_session_id(self):
  ss,b,a=sample_sessions();ss[1]["session_id"]="session-one"
  self.assertIn("SESSION_SCHEMA_OR_ID_CONFLICT",m.audit(ss,b,a)["blockers"])
 def test_second_session_replays_nonce(self):
  ss,b,a=sample_sessions()
  ss[1]["records"][1]["ack"]=ss[0]["records"][0]["ack"]
  self.assertIn("SESSION_HISTORY_NONCE_REUSED",m.audit(ss,b,a)["blockers"])
 def test_second_session_replays_receipt(self):
  ss,b,a=sample_sessions()
  ss[1]["records"][1]["ack"]=ss[0]["records"][0]["ack"]
  self.assertIn("SESSION_HISTORY_RECEIPT_REPLAYED",m.audit(ss,b,a)["blockers"])
 def test_stale_signed_head(self):
  ss,b,a=sample_sessions();h,k=signed_head(ss)
  h["payload"]["record_count"]=1
  self.assertIn("SIGNED_HIGHWATER_NOT_CURRENT_SESSION",m.audit(ss,b,a,h,k)["blockers"])
 def test_bad_signed_head_signature(self):
  ss,b,a=sample_sessions();h,k=signed_head(ss)
  h["signature_base64"]="broken"
  self.assertIn("SIGNED_HIGHWATER_SIGNATURE_INVALID",m.audit(ss,b,a,h,k)["blockers"])
 def test_wrong_head_key(self):
  ss,b,a=sample_sessions();h,k=signed_head(ss)
  k["key_sha256"]="0"*64
  self.assertIn("SIGNED_HIGHWATER_ANCHOR_MISMATCH",m.audit(ss,b,a,h,k)["blockers"])
 def test_malformed_empty_session(self):
  ss,b,a=sample_sessions();ss[1]["records"]=[]
  self.assertIn("SESSION_HISTORY_MISSING_OR_UNBOUNDED",m.audit(ss,b,a)["blockers"])
 def test_full_sessions_are_bounded(self):
  ss,b,a=sample_sessions();v=m.audit(ss*9,b,a)
  self.assertIn("SESSIONS_MISSING_OR_UNBOUNDED",v["blockers"])
 def test_no_session_rejected(self):
  ss,b,a=sample_sessions();v=m.audit([],b,a)
  self.assertEqual(v["state"],"CROSS_SESSION_REJECTED_HOLD")
 def test_deterministic_evidence(self):
  ss,b,a=sample_sessions();v=m.audit(ss,b,a)
  h=v.pop("evidence_sha256");self.assertEqual(h,m.sha(v))
 def test_boolean_signed_head_count_rejected(self):
  ss,b,a=sample_sessions();h,k=signed_head(ss)
  h["payload"]["record_count"]=True
  self.assertIn("SIGNED_HIGHWATER_NOT_CURRENT_SESSION",m.audit(ss,b,a,h,k)["blockers"])

 def test_missing_terminal_digest_fails_closed(self):
  ss,b,a=sample_sessions();h,k=signed_head(ss)
  missing={"session_id":ss[-1]["session_id"],"records":[{"sequence":2}]}
  valid,errors=m.verify_signed_head(h,k,missing)
  self.assertFalse(valid)
  self.assertIn("SIGNED_HIGHWATER_NOT_CURRENT_SESSION",errors)
if __name__=="__main__":unittest.main()
