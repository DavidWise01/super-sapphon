#!/usr/bin/env python3
"""SAPPHON-199 source-owned retention and immutable-parent negative cases."""
import importlib.util,io,json,pathlib,unittest,zipfile
P=pathlib.Path(__file__).parent
def load(n,f):
 sp=importlib.util.spec_from_file_location(n,P/f);x=importlib.util.module_from_spec(sp);sp.loader.exec_module(x);return x
m=load("r199","sapphon_199_retention.py")
l=m.ledger
def event(state="GITHUB_OWNED_HASH_MATCH",log="a"*64):
 data={"schema":"sapphon-196-original-byte-reacquisition-v1",
  "state":state,"original_run_id":193,"original_attempt":2,
  "log_sha256":log,"zip_sha256":"b"*64,"original_bytes_reacquired":True}
 return l.from_reacquisition(data)
def base(fork=False):
 prior=l.append([],event())
 if fork:prior=l.append(prior,event(log="c"*64))
 updated=l.append(prior,event(state="NOT_OBSERVED"))
 p=l.validate(prior);v=l.validate(updated);n=len(prior)
 report={"schema":"sapphon-198-cross-run-v1",
  "predecessor_entries":n,"predecessor_tip_sha256":p["tip_sha256"],
  "new_entries":len(updated),"new_tip_sha256":v["tip_sha256"],
  "inherited_forks":p["forks"],"all_forks":v["forks"],"recovery_authorized":False}
 parent={"schema":"sapphon-198-import-v1","source_sha":"9bddb4491893ee121f71821b61692685508adae6",
  "state":"OWNED_197_CHAIN_IMPORTED","prior_ledger_observed":True,
  "chain_entries":n,"prior_tip_sha256":p["tip_sha256"]}
 summary={"schema":"sapphon-198-source-owned-outcomes-v1","commit":m.SOURCE,
  "run_id":"198","attempt":"2","recovery_authorized":False,
  "inherited_forks_preserved":len(p["forks"])}
 return updated,report,parent,summary
def archive(data):
 chain,report,parent,summary=data;b=io.BytesIO()
 with zipfile.ZipFile(b,"w") as z:
  z.writestr("198-ledger.jsonl",b"".join(l.canonical(x)+b"\n" for x in chain))
  z.writestr("198-adjudication.json",json.dumps(report))
  z.writestr("198-import.json",json.dumps(parent))
  z.writestr("198-summary.json",json.dumps(summary))
 return b.getvalue()
def run():return {"id":198,"run_attempt":2}
def artifact():return {"id":199}
class Tests(unittest.TestCase):
 def test_exact_parent(self):
  x=m.inspect(archive(base()),run(),artifact())
  self.assertTrue(x["original_parent_verified"])
  self.assertFalse(x["recovery_authorized"])
 def test_missing_original_not_deletion(self):
  x=m.hold("EXACT_RUN_NOT_OBSERVED")
  self.assertFalse(x["deletion_confirmed"])
 def test_expired_metadata_not_deletion(self):
  x=m.hold("ARTIFACT_METADATA_EXPIRED")
  self.assertFalse(x["deletion_confirmed"])
 def test_parent_changed(self):
  v=list(base());v[1]=dict(v[1],predecessor_tip_sha256="f"*64)
  self.assertEqual(m.inspect(archive(v),run(),artifact())["state"],"PARENT_TIP_OR_FORK_EQUIVOCATION")
 def test_parent_missing(self):
  v=list(base());v[2]=dict(v[2],prior_ledger_observed=False)
  self.assertEqual(m.inspect(archive(v),run(),artifact())["state"],"197_PARENT_NOT_OBSERVED")
 def test_different_attempt_rejected(self):
  v=list(base());v[3]=dict(v[3],attempt="3")
  self.assertEqual(m.inspect(archive(v),run(),artifact())["state"],"SOURCE_RUN_ATTEMPT_CONFLICT")
 def test_fork_retained(self):
  x=m.inspect(archive(base(True)),run(),artifact())
  self.assertTrue(x["original_parent_verified"])
  self.assertEqual(len(x["inherited_forks"]),1)
 def test_fork_erasure_rejected(self):
  v=list(base(True));v[1]=dict(v[1],inherited_forks=[])
  self.assertEqual(m.inspect(archive(v),run(),artifact())["state"],"PARENT_TIP_OR_FORK_EQUIVOCATION")
 def test_tamper_chain(self):
  data=archive(base());buffer=io.BytesIO()
  with zipfile.ZipFile(io.BytesIO(data)) as original:
   entries={name:original.read(name) for name in original.namelist()}
  chain=[json.loads(line) for line in entries["198-ledger.jsonl"].splitlines()]
  chain[0]["sha256"]="f"*64
  entries["198-ledger.jsonl"]=b"".join(l.canonical(x)+b"\\n" for x in chain)
  with zipfile.ZipFile(buffer,"w") as out:
   for name,body in entries.items():out.writestr(name,body)
  self.assertEqual(m.inspect(buffer.getvalue(),run(),artifact())["state"],"CHAIN_HASH_INVALID")
 def test_duplicate_zip_entry_rejected(self):
  b=io.BytesIO()
  with zipfile.ZipFile(b,"w") as z:
   for name in m.MEMBERS:z.writestr(name,"{}")
   z.writestr("198-summary.json","{}")
  self.assertEqual(m.inspect(b.getvalue(),run(),artifact())["state"],"ZIP_MEMBER_CONFLICT")
 def test_no_zip_rejected(self):
  self.assertEqual(m.inspect(b"",run(),artifact())["state"],"ORIGINAL_ZIP_NOT_OBSERVED")
 def test_unexpected_archive_file_rejected(self):
  b=io.BytesIO()
  with zipfile.ZipFile(b,"w") as z:
   for name in m.MEMBERS:z.writestr(name,"{}")
   z.writestr("extra.sh","contents")
  self.assertEqual(m.inspect(b.getvalue(),run(),artifact())["state"],"ZIP_MEMBER_CONFLICT")
 def test_nonappend_record_denied(self):
  v=list(base());v[1]=dict(v[1],predecessor_entries=len(v[0]))
  self.assertEqual(m.inspect(archive(v),run(),artifact())["state"],"PARENT_BOUNDARY_INVALID")
 def test_forged_recovery_in_summary(self):
  v=list(base());v[3]=dict(v[3],recovery_authorized=True)
  self.assertEqual(m.inspect(archive(v),run(),artifact())["state"],"SOURCE_RUN_ATTEMPT_CONFLICT")
 def test_missing_is_not_fork(self):
  x=m.inspect(archive(base()),run(),artifact())
  self.assertEqual(x["all_forks"],[])
  self.assertEqual(len(x["prior_missing"]),0)
if __name__=="__main__":unittest.main()
